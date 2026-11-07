//! The Shadowsocks AEAD stream under `SHADOWSOCKS-OSSH`: a salt, then sealed
//! length/payload chunks, carrying the OSSH seed and SSH session unchanged.

use ferrox_core::shadowsocks::{Cipher, MasterKey, Method, LENGTH_LEN, MAX_CHUNK, TAG_LEN};
use std::io::{self, IoSlice, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

const METHOD: Method = Method::Chacha20Poly1305;
const SALT_LEN: usize = 32;
const HEAD_LEN: usize = LENGTH_LEN + TAG_LEN;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Write a chunk's sealed length and tag, returning where its body starts.
#[inline]
fn seal_head(wire: &mut Vec<u8>, cipher: &mut Cipher, len: usize) -> io::Result<usize> {
    let mut length = u16::try_from(len)
        .map_err(|_| invalid("shadowsocks chunk"))?
        .to_be_bytes();
    let tag = cipher
        .seal_piece_in_place(&mut length)
        .ok_or_else(|| invalid("shadowsocks length seal"))?;
    wire.extend_from_slice(&length);
    wire.extend_from_slice(&tag);
    Ok(wire.len())
}

struct Reader {
    master: MasterKey,
    cipher: Option<Cipher>,
    salt: [u8; SALT_LEN],
    salt_len: usize,
    head: [u8; HEAD_LEN],
    head_len: usize,
    size: Option<usize>,
    body: Vec<u8>,
    body_len: usize,
    plain_at: usize,
    opened: bool,
    done: bool,
}

impl Reader {
    fn new(key: &str) -> Self {
        Self {
            master: MasterKey::new(key, METHOD.key_len()),
            cipher: None,
            salt: [0; SALT_LEN],
            salt_len: 0,
            head: [0; HEAD_LEN],
            head_len: 0,
            size: None,
            body: Vec::new(),
            body_len: 0,
            plain_at: 0,
            opened: false,
            done: false,
        }
    }

    fn read(&mut self, io: &mut impl Read, out: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.opened {
                if self.plain_at < self.size.unwrap_or(0) {
                    let take = (self.size.unwrap_or(0) - self.plain_at).min(out.len());
                    out[..take].copy_from_slice(&self.body[self.plain_at..self.plain_at + take]);
                    self.plain_at += take;
                    return Ok(take);
                }
                self.opened = false;
                self.size = None;
                self.head_len = 0;
                self.body_len = 0;
                self.plain_at = 0;
                continue;
            }
            if self.done {
                return Ok(0);
            }
            if self.cipher.is_none() {
                self.fill_salt(io)?;
                continue;
            }
            if self.size.is_none() {
                self.fill_head(io)?;
                continue;
            }
            self.fill_body(io)?;
            self.open_body()?;
        }
    }

    fn fill_salt(&mut self, io: &mut impl Read) -> io::Result<()> {
        while self.salt_len < SALT_LEN {
            let read = io.read(&mut self.salt[self.salt_len..])?;
            if read == 0 {
                if self.salt_len != 0 {
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                }
                self.done = true;
                return Ok(());
            }
            self.salt_len += read;
        }
        self.cipher = Some(
            Cipher::from_master_key(METHOD, &self.master, &self.salt)
                .ok_or_else(|| invalid("shadowsocks salt"))?,
        );
        Ok(())
    }

    fn fill_head(&mut self, io: &mut impl Read) -> io::Result<()> {
        while self.head_len < HEAD_LEN {
            let read = io.read(&mut self.head[self.head_len..])?;
            if read == 0 {
                if self.head_len == 0 {
                    self.done = true;
                    return Ok(());
                }
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            self.head_len += read;
        }
        let cipher = self
            .cipher
            .as_mut()
            .ok_or_else(|| invalid("shadowsocks cipher"))?;
        if cipher.open_in_place(&mut self.head) != Some(LENGTH_LEN) {
            return Err(invalid("shadowsocks length"));
        }
        let size = usize::from(u16::from_be_bytes([self.head[0], self.head[1]]));
        if size > MAX_CHUNK {
            return Err(invalid("shadowsocks chunk"));
        }
        if self.body.is_empty() {
            self.body.resize(MAX_CHUNK + TAG_LEN, 0);
        }
        self.body_len = 0;
        self.size = Some(size);
        Ok(())
    }

    fn fill_body(&mut self, io: &mut impl Read) -> io::Result<()> {
        let end = self.size.unwrap_or(0) + TAG_LEN;
        while self.body_len < end {
            let read = io.read(&mut self.body[self.body_len..end])?;
            if read == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            self.body_len += read;
        }
        Ok(())
    }

    fn open_body(&mut self) -> io::Result<()> {
        let size = self.size.ok_or_else(|| invalid("shadowsocks body"))?;
        let cipher = self
            .cipher
            .as_mut()
            .ok_or_else(|| invalid("shadowsocks cipher"))?;
        if cipher.open_in_place(&mut self.body[..size + TAG_LEN]) != Some(size) {
            return Err(invalid("shadowsocks tag"));
        }
        self.plain_at = 0;
        self.opened = true;
        Ok(())
    }
}

struct Writer {
    master: MasterKey,
    cipher: Option<Cipher>,
    prefix: Vec<u8>,
    wire: Vec<u8>,
    failed: bool,
}

impl Writer {
    fn new(key: &str, prefix: &[u8]) -> Self {
        Self {
            master: MasterKey::new(key, METHOD.key_len()),
            cipher: None,
            prefix: prefix.to_vec(),
            wire: Vec::new(),
            failed: false,
        }
    }

    fn start(&mut self, io: &mut impl Write) -> io::Result<()> {
        if self.cipher.is_some() {
            return Ok(());
        }
        let mut salt = [0u8; SALT_LEN];
        let prefix = self.prefix.len().min(SALT_LEN);
        salt[..prefix].copy_from_slice(&self.prefix[..prefix]);
        getrandom::fill(&mut salt[prefix..])
            .map_err(|error| io::Error::other(error.to_string()))?;
        io.write_all(&salt)?;
        self.cipher = Some(
            Cipher::from_master_key(METHOD, &self.master, &salt)
                .ok_or_else(|| invalid("shadowsocks key"))?,
        );
        Ok(())
    }

    fn write(&mut self, io: &mut impl Write, buf: &[u8]) -> io::Result<()> {
        self.write_slices(io, &[IoSlice::new(buf)]).map(|_| ())
    }

    /// Seal the caller's slices in one wire write.
    fn write_vectored(&mut self, io: &mut impl Write, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.write_slices(io, bufs)
    }

    /// Seal the slices and latch a failure so later writes fail.
    fn write_slices(&mut self, io: &mut impl Write, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "shadowsocks write failed",
            ));
        }
        let result = self.seal_slices(io, bufs);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Seal the concatenated slices as the same `MAX_CHUNK` frames the contiguous
    /// writer makes, taking each chunk's bytes straight from the caller's buffers.
    fn seal_slices(&mut self, io: &mut impl Write, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.start(io)?;
        let cipher = self
            .cipher
            .as_mut()
            .ok_or_else(|| invalid("shadowsocks cipher"))?;
        let total: usize = bufs.iter().map(|buf| buf.len()).sum();
        self.wire.clear();
        self.wire
            .reserve(total + (total / MAX_CHUNK + 1) * HEAD_LEN);
        if total == 0 {
            io.write_all(&self.wire)?;
            return Ok(0);
        }
        if total <= MAX_CHUNK {
            let body = seal_head(&mut self.wire, cipher, total)?;
            for buffer in bufs {
                self.wire.extend_from_slice(buffer);
            }
            cipher
                .seal_tail_in_place(&mut self.wire, body)
                .ok_or_else(|| invalid("shadowsocks body seal"))?;
            io.write_all(&self.wire)?;
            return Ok(total);
        }
        let mut left = total;
        let mut index = 0;
        let mut at = 0;
        while left > 0 {
            let chunk = left.min(MAX_CHUNK);
            let body = seal_head(&mut self.wire, cipher, chunk)?;
            let mut need = chunk;
            while need > 0 {
                let buffer = &bufs[index];
                if at == buffer.len() {
                    index += 1;
                    at = 0;
                    continue;
                }
                let take = need.min(buffer.len() - at);
                self.wire.extend_from_slice(&buffer[at..at + take]);
                at += take;
                need -= take;
            }
            cipher
                .seal_tail_in_place(&mut self.wire, body)
                .ok_or_else(|| invalid("shadowsocks body seal"))?;
            left -= chunk;
        }
        io.write_all(&self.wire)?;
        Ok(total)
    }
}

/// One Shadowsocks stream. Clones share the two cipher directions and split the
/// socket, because SSH reads and writes on independent halves.
pub(crate) struct Stream<T> {
    io: T,
    reader: Arc<Mutex<Reader>>,
    writer: Arc<Mutex<Writer>>,
}

impl<T: Read + Write> Stream<T> {
    fn new(io: T, key: &str, prefix: &[u8]) -> Self {
        Self {
            io,
            reader: Arc::new(Mutex::new(Reader::new(key))),
            writer: Arc::new(Mutex::new(Writer::new(key, prefix))),
        }
    }
}

impl Stream<TcpStream> {
    pub(crate) fn connect(io: TcpStream, key: &str, prefix: Option<&[u8]>) -> Self {
        Self::new(io, key, prefix.unwrap_or_default())
    }

    /// Clone the underlying stream.
    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            io: self.io.try_clone()?,
            reader: Arc::clone(&self.reader),
            writer: Arc::clone(&self.writer),
        })
    }

    /// Forward the timeout to the underlying stream.
    pub(crate) fn set_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.io
            .set_read_timeout(timeout)
            .and_then(|()| self.io.set_write_timeout(timeout))
    }

    /// Forward the read timeout to the underlying stream.
    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.io.set_read_timeout(timeout)
    }

    /// Shut down the underlying stream.
    pub(crate) fn shutdown(&self) -> io::Result<()> {
        self.io.shutdown(Shutdown::Both)
    }
}

impl Stream<crate::psiphon_fragment::FragmentStream> {
    /// Dial through the proxy and fragment the first writes beneath it.
    pub(crate) fn connect_fragment(
        io: crate::psiphon_fragment::FragmentStream,
        key: &str,
        prefix: Option<&[u8]>,
    ) -> Self {
        Self::new(io, key, prefix.unwrap_or_default())
    }

    /// Clone the underlying stream and its fragment plan.
    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            io: self.io.try_clone()?,
            reader: Arc::clone(&self.reader),
            writer: Arc::clone(&self.writer),
        })
    }

    /// Forward the timeout to the underlying stream.
    pub(crate) fn set_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.io
            .set_read_timeout(timeout)
            .and_then(|()| self.io.set_write_timeout(timeout))
    }

    /// Forward the read timeout to the underlying stream.
    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.io.set_read_timeout(timeout)
    }

    /// Shut down the underlying stream.
    pub(crate) fn shutdown(&self) -> io::Result<()> {
        self.io.shutdown(std::net::Shutdown::Both)
    }
}

impl Stream<crate::psiphon_webrtc::WebRtcStream> {
    pub(crate) fn connect_webrtc(
        io: crate::psiphon_webrtc::WebRtcStream,
        key: &str,
        prefix: Option<&[u8]>,
    ) -> Self {
        Self::new(io, key, prefix.unwrap_or_default())
    }

    pub(crate) fn try_clone(&self) -> Self {
        Self {
            io: self.io.clone(),
            reader: Arc::clone(&self.reader),
            writer: Arc::clone(&self.writer),
        }
    }

    pub(crate) fn set_timeout(&self, timeout: Option<Duration>) {
        self.io.set_timeout(timeout);
    }

    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) {
        self.io.set_read_timeout(timeout);
    }

    pub(crate) fn shutdown(&self) {
        self.io.shutdown();
    }
}

impl<T: Read + Write> Read for Stream<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        lock(&self.reader).read(&mut self.io, buf)
    }
}

impl<T: Read + Write> Write for Stream<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        lock(&self.writer).write(&mut self.io, buf)?;
        Ok(buf.len())
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let total: usize = bufs.iter().map(|buf| buf.len()).sum();
        if total == 0 {
            return Ok(0);
        }
        lock(&self.writer).write_vectored(&mut self.io, bufs)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.io.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Wire {
        input: Vec<u8>,
        at: usize,
        output: Vec<u8>,
    }

    impl Read for Wire {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let take = (self.input.len() - self.at).min(buf.len());
            buf[..take].copy_from_slice(&self.input[self.at..self.at + take]);
            self.at += take;
            Ok(take)
        }
    }

    impl Write for Wire {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_stream_round_trips_chunks_and_a_tail() {
        let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let mut writer = Stream::new(
            Wire {
                input: Vec::new(),
                at: 0,
                output: Vec::new(),
            },
            key,
            &[],
        );
        let payload: Vec<u8> = (0..=255u8).cycle().take(MAX_CHUNK * 2 + 17).collect();
        writer.write_all(&payload).expect("writes");
        let wire = writer.io.output;

        let mut reader = Stream::new(
            Wire {
                input: wire,
                at: 0,
                output: Vec::new(),
            },
            key,
            &[],
        );
        let mut got = vec![0u8; payload.len()];
        reader.read_exact(&mut got).expect("reads");
        assert_eq!(got, payload);
    }

    #[test]
    fn a_configured_prefix_leads_the_salt() {
        let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let mut writer = Stream::new(
            Wire {
                input: Vec::new(),
                at: 0,
                output: Vec::new(),
            },
            key,
            b"\x16\x03\x01",
        );
        writer.write_all(b"hello").expect("writes");
        assert!(writer.io.output.starts_with(b"\x16\x03\x01"));
    }

    #[test]
    fn a_truncated_salt_is_an_error() {
        let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let mut reader = Stream::new(
            Wire {
                input: vec![0u8; 10],
                at: 0,
                output: Vec::new(),
            },
            key,
            &[],
        );
        let mut got = [0u8; 4];
        assert_eq!(
            reader.read(&mut got).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    /// A writer whose salt is fixed, so two writes can be compared byte for byte.
    fn sealed_writer(key: &str) -> Writer {
        let mut writer = Writer::new(key, &[]);
        let cipher =
            Cipher::from_master_key(METHOD, &writer.master, &[0x42; SALT_LEN]).expect("cipher");
        writer.cipher = Some(cipher);
        writer
    }

    #[test]
    fn vectored_frames_are_the_contiguous_frames() {
        let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let payload: Vec<u8> = (0..=255u8).cycle().take(MAX_CHUNK * 2 + 17).collect();
        let mut contiguous = sealed_writer(key);
        let mut sink = Wire {
            input: Vec::new(),
            at: 0,
            output: Vec::new(),
        };
        contiguous
            .write_slices(&mut sink, &[IoSlice::new(&payload)])
            .expect("writes");
        let expected = sink.output;
        for cut in [
            0,
            1,
            HEAD_LEN,
            MAX_CHUNK - 1,
            MAX_CHUNK,
            MAX_CHUNK + 1,
            payload.len() - 1,
        ] {
            let parts = [IoSlice::new(&payload[..cut]), IoSlice::new(&payload[cut..])];
            let mut writer = sealed_writer(key);
            let mut sink = Wire {
                input: Vec::new(),
                at: 0,
                output: Vec::new(),
            };
            writer.write_slices(&mut sink, &parts).expect("writes");
            assert_eq!(sink.output, expected, "cut {cut}");
        }
    }

    #[test]
    fn a_vectored_write_allocates_only_the_wire_buffer() {
        let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let payload = vec![0x5a; MAX_CHUNK * 2 + 17];
        let ((), contiguous) = ferrox_core::alloc_count::measure(|| {
            let mut writer = sealed_writer(key);
            let mut sink = Wire {
                input: Vec::new(),
                at: 0,
                output: Vec::new(),
            };
            writer
                .write_slices(&mut sink, &[IoSlice::new(&payload)])
                .expect("writes");
        });
        let ((), vectored) = ferrox_core::alloc_count::measure(|| {
            let mut writer = sealed_writer(key);
            let mut sink = Wire {
                input: Vec::new(),
                at: 0,
                output: Vec::new(),
            };
            let parts = [
                IoSlice::new(&payload[..3]),
                IoSlice::new(&payload[3..MAX_CHUNK + 5]),
                IoSlice::new(&payload[MAX_CHUNK + 5..]),
            ];
            writer.write_slices(&mut sink, &parts).expect("writes");
        });
        assert_eq!(
            (vectored.allocs, vectored.bytes),
            (contiguous.allocs, contiguous.bytes),
            "a vectored write reserves only the wire buffer the contiguous one reserves"
        );
    }

    struct Discard(usize);

    impl Write for Discard {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    const PROBE_HEAD: [u8; 14] = [0x11; 14];
    const PROBE_BODY: [u8; 1024] = [0x22; 1024];
    const PROBE_PAD: [u8; 16] = [0x33; 16];
    const PROBE_TAG: [u8; 32] = [0x44; 32];

    #[inline(never)]
    fn direct_write_probe() -> usize {
        let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let mut writer = sealed_writer(key);
        let mut sink = Discard(0);
        let slices = [
            IoSlice::new(&PROBE_HEAD),
            IoSlice::new(&PROBE_BODY),
            IoSlice::new(&PROBE_PAD),
            IoSlice::new(&PROBE_TAG),
        ];
        for _ in 0..4096 {
            writer.write_slices(&mut sink, &slices).expect("writes");
        }
        sink.0
    }

    #[inline(never)]
    fn flattened_write_probe() -> usize {
        let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let mut writer = sealed_writer(key);
        let mut sink = Discard(0);
        let slices = [
            IoSlice::new(&PROBE_HEAD),
            IoSlice::new(&PROBE_BODY),
            IoSlice::new(&PROBE_PAD),
            IoSlice::new(&PROBE_TAG),
        ];
        let mut plain = Vec::new();
        for _ in 0..4096 {
            plain.clear();
            for slice in &slices {
                plain.extend_from_slice(slice);
            }
            writer
                .write_slices(&mut sink, &[IoSlice::new(&plain)])
                .expect("writes");
        }
        sink.0
    }

    #[test]
    fn the_direct_write_costs_the_seal_and_nothing_else() {
        assert!(direct_write_probe() > 0);
    }

    #[test]
    fn the_flattened_write_costs_the_copy() {
        assert!(flattened_write_probe() > 0);
    }

    #[test]
    fn vectored_slices_round_trip_as_one_stream() {
        let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let mut writer = Stream::new(
            Wire {
                input: Vec::new(),
                at: 0,
                output: Vec::new(),
            },
            key,
            &[],
        );
        let slices = [
            IoSlice::new(b"abc"),
            IoSlice::new(b"def"),
            IoSlice::new(b""),
        ];
        assert_eq!(writer.write_vectored(&slices).expect("writes"), 6);
        let wire = writer.io.output;

        let mut reader = Stream::new(
            Wire {
                input: wire,
                at: 0,
                output: Vec::new(),
            },
            key,
            &[],
        );
        let mut got = [0u8; 6];
        reader.read_exact(&mut got).expect("reads");
        assert_eq!(&got, b"abcdef");
    }

    #[test]
    fn a_failed_write_stays_failed() {
        struct Drip {
            left: usize,
            output: Vec<u8>,
        }

        impl Read for Drip {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Ok(0)
            }
        }

        impl Write for Drip {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                if self.left == 0 {
                    return Err(io::Error::from(io::ErrorKind::BrokenPipe));
                }
                let take = self.left.min(buf.len());
                self.output.extend_from_slice(&buf[..take]);
                self.left -= take;
                Ok(take)
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let mut writer = Stream::new(
            Drip {
                left: 16,
                output: Vec::new(),
            },
            key,
            &[],
        );
        assert!(writer.write_all(b"hello").is_err());
        let written = writer.io.output.len();
        assert!(writer.write_all(b"hello").is_err());
        assert_eq!(writer.io.output.len(), written);
    }

    #[test]
    fn a_forged_tag_is_rejected() {
        let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let mut writer = Stream::new(
            Wire {
                input: Vec::new(),
                at: 0,
                output: Vec::new(),
            },
            key,
            &[],
        );
        writer.write_all(b"hello").expect("writes");
        let mut wire = writer.io.output;
        let last = wire.len() - 1;
        wire[last] ^= 0xff;

        let mut reader = Stream::new(
            Wire {
                input: wire,
                at: 0,
                output: Vec::new(),
            },
            key,
            &[],
        );
        let mut got = [0u8; 5];
        assert_eq!(
            reader.read_exact(&mut got).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}

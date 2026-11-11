use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex, OnceLock};

use crate::conn::Connection;
use base64::Engine as _;
use ferrox_core::transport::url_decode_parts;

pub(crate) const HEAD_LIMIT: usize = 64 * 1024;
/// One chunk per relay window: a promoted read leaves as one chunked frame, not as a 16 KiB chunk per quarter of it.
const CHUNK: usize = crate::proxy::RELAY_BUFFER;
/// A whole body plus the longest size line that can precede it and both bytes that close the body, so one framing read opens and finishes it.
const FRAMING_READ: usize = CHUNK + 131;
const HEX: &[u8; 16] = b"0123456789ABCDEF";

fn path_covers(configured: &str, requested: &str) -> bool {
    if configured == "/" {
        return requested.starts_with('/');
    }
    let configured = match configured.strip_suffix('/') {
        Some(stripped) if !stripped.is_empty() => stripped,
        _ => configured,
    };
    requested == configured
        || requested
            .strip_prefix(configured)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn bare_path(target: &str) -> &str {
    target.split_once('?').map_or(target, |(base, _)| base)
}

/// The head, the octets that arrived with it, and where the head ends: this read consumes what it proves, so a body pipelined behind the head is already in hand.
fn read_head(stream: &mut Connection) -> Option<(Vec<u8>, usize)> {
    crate::proxy::read_http_head_kept(stream, HEAD_LIMIT, crate::budgets::head_arrival())
}

fn size_line(n: usize, out: &mut [u8; 7]) -> usize {
    debug_assert!((1..=CHUNK).contains(&n));
    if n < 16 {
        out[0] = HEX[n & 0xf];
        out[1] = b'\r';
        out[2] = b'\n';
        3
    } else if n < 256 {
        out[0] = HEX[(n >> 4) & 0xf];
        out[1] = HEX[n & 0xf];
        out[2] = b'\r';
        out[3] = b'\n';
        4
    } else if n < 4096 {
        out[0] = HEX[(n >> 8) & 0xf];
        out[1] = HEX[(n >> 4) & 0xf];
        out[2] = HEX[n & 0xf];
        out[3] = b'\r';
        out[4] = b'\n';
        5
    } else if n < 0x1_0000 {
        out[0] = HEX[(n >> 12) & 0xf];
        out[1] = HEX[(n >> 8) & 0xf];
        out[2] = HEX[(n >> 4) & 0xf];
        out[3] = HEX[n & 0xf];
        out[4] = b'\r';
        out[5] = b'\n';
        6
    } else {
        out[0] = HEX[(n >> 16) & 0xf];
        out[1] = HEX[(n >> 12) & 0xf];
        out[2] = HEX[(n >> 8) & 0xf];
        out[3] = HEX[(n >> 4) & 0xf];
        out[4] = HEX[n & 0xf];
        out[5] = b'\r';
        out[6] = b'\n';
        7
    }
}

fn take_into<R: Read>(read: &mut R, reads: &mut usize, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        *reads += 1;
        match read.read(buf) {
            Err(error)
                if crate::proxy::is_timeout(&error) && !crate::proxy::relay_step_owns_poll() =>
            {
                if crate::proxy::body_deadline()
                    .is_some_and(|until| std::time::Instant::now() >= until)
                {
                    return Err(error);
                }
                std::thread::sleep(crate::budgets::RELAY_POLL);
            }
            other => return other,
        }
    }
}

fn read_line_into(
    reader: &mut Reader<impl Read>,
    out: &mut [u8; 130],
) -> std::io::Result<Option<usize>> {
    loop {
        if let Some(end_pos) = reader.line_in_prefix(out) {
            return Ok(Some(end_pos));
        }
        if reader.prefix.len() - reader.at >= 129 {
            return Ok(None);
        }
        if reader.at >= reader.prefix.len() {
            reader.prefix.clear();
            reader.at = 0;
        } else if reader.at > 0 {
            reader.prefix.drain(..reader.at);
            reader.at = 0;
        }
        match reader.fill(FRAMING_READ) {
            Ok(n) if n > 0 => {}
            Err(error) if crate::proxy::is_timeout(&error) => return Err(error),
            _ => return Ok(None),
        }
    }
}

fn chunk_size(line: &[u8]) -> Option<usize> {
    let mut size = 0usize;
    let mut i = 0;
    while i < line.len() {
        let v = CHUNK_LINE_LUT[line[i] as usize];
        if v == 16 {
            return if i == 0 { None } else { Some(size) };
        }
        if v == 255 {
            return None;
        }
        if i == 16 {
            return None;
        }
        size = (size << 4) | v as usize;
        i += 1;
    }
    if i == 0 {
        return None;
    }
    Some(size)
}

/// One pass over the size line: 0..=15 is a hex nibble, 16 marks a terminator (any of `;`, space, tab, CR, LF), 255 marks a byte that can be neither.
const CHUNK_LINE_LUT: [u8; 256] = {
    let mut t = [255u8; 256];
    let mut i = 0;
    while i < 10 {
        t[b'0' as usize + i] = i as u8;
        i += 1;
    }
    let mut i = 0;
    while i < 6 {
        t[b'a' as usize + i] = 10 + i as u8;
        t[b'A' as usize + i] = 10 + i as u8;
        i += 1;
    }
    t[b';' as usize] = 16;
    t[b' ' as usize] = 16;
    t[b'\t' as usize] = 16;
    t[b'\r' as usize] = 16;
    t[b'\n' as usize] = 16;
    t
};

/// Generic over the underlying `Read` so a test can drive it from an in-memory stream and count the reads, the way `WsReader` counts its own; `reads` is that counter and the read-syscall row is measured from it.
#[derive(Debug)]
pub(crate) struct Reader<R> {
    read: R,
    prefix: Vec<u8>,
    at: usize,
    left: usize,
    ended: bool,
    reads: usize,
    pending_head: bool,
    head_progress: Option<Arc<AtomicU64>>,
    /// Where the chunked framing stands: a body's bytes are being delivered, its closing CRLF is still unread, or the zero-size chunk ran and only trailer lines are left until an empty one ends the body.
    chunk: Chunk,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Chunk {
    Body,
    Crlf,
    Trailers,
}

pub(crate) type XhttpReader = Reader<Connection>;

/// A live stream with sniffed bytes pushed back in front, so a transport decision made on the first bytes does not eat them.
pub(crate) struct ChainReader<R> {
    prefix: Vec<u8>,
    at: usize,
    read: R,
}

impl<R: Read> ChainReader<R> {
    pub(crate) fn new(prefix: Vec<u8>, read: R) -> Self {
        Self {
            prefix,
            at: 0,
            read,
        }
    }
    /// Put the bytes that rode in with the last request but belong to the next one back on the front.
    fn set_carry(&mut self, carry: Vec<u8>) {
        self.prefix = carry;
        self.at = 0;
    }
}

impl<R: crate::proxy::RelayPoll> crate::proxy::RelayPoll for ChainReader<R> {
    fn arm_relay_poll(&mut self) {
        self.read.arm_relay_poll();
    }

    fn arm_head_poll(&mut self) {
        self.read.arm_head_poll();
    }
}

impl<R: Read> Read for ChainReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.at < self.prefix.len() {
            let n = (self.prefix.len() - self.at).min(buf.len());
            buf[..n].copy_from_slice(&self.prefix[self.at..self.at + n]);
            self.at += n;
            return Ok(n);
        }
        self.read.read(buf)
    }
}

impl Reader<Connection> {
    /// Arm or clear the poll quantum on the socket this reader reads through; a duplicated socket inherits no read timeout on Windows.
    pub(crate) fn set_poll(&mut self, every: Option<std::time::Duration>) {
        let _ = self.read.set_read_timeout(every);
    }
}

impl<R> Reader<R> {
    /// Tie the first answer head to the upload pump, so a server that waits for payload cannot end the head at a fixed clock.
    pub(crate) fn set_head_progress(&mut self, progress: Arc<AtomicU64>) {
        self.head_progress = Some(progress);
    }
}

impl<R: Read + crate::proxy::RelayPoll> crate::proxy::RelayPoll for Reader<R> {
    fn arm_relay_poll(&mut self) {
        self.read.arm_relay_poll();
    }

    fn arm_head_poll(&mut self) {
        self.read.arm_head_poll();
    }
}

impl<R: Read> Reader<R> {
    /// Every read that reaches the stream, counted where it happens. A relay's poll timeout comes
    /// back to the lane instead of being retried here: the chunk stays where it broke.
    fn take(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        take_into(&mut self.read, &mut self.reads, buf)
    }

    /// One read past the framing into the buffer holding what it proved: xray's 8 KiB chunks otherwise cost a framing syscall each.
    fn fill(&mut self, want: usize) -> std::io::Result<usize> {
        let base = self.prefix.len();
        crate::proxy::grow_scratch(&mut self.prefix, base + want);
        match take_into(&mut self.read, &mut self.reads, &mut self.prefix[base..]) {
            Ok(n) => {
                self.prefix.truncate(base + n);
                Ok(n)
            }
            Err(error) => {
                self.prefix.truncate(base);
                Err(error)
            }
        }
    }

    /// The syscall counter, read by `a_chunk_costs_two_reads_not_three` and `a_real_socket_drains_the_same_bytes`.
    #[cfg_attr(not(test), expect(dead_code, reason = "only the gate reads it"))]
    #[must_use]
    pub(crate) fn reads(&self) -> usize {
        self.reads
    }
}

impl<R: Read> Reader<R> {
    /// The answer head is read on the first read, not at the dial: the reference dialer returns once the socket is up and lets the first body byte pull the response (client.go:97), and a hub that flushes only past the request body would otherwise deadlock the dial.
    fn parse_head(&mut self) -> std::io::Result<()> {
        if !self.pending_head {
            return Ok(());
        }
        self.pending_head = false;
        let progress = self.head_progress.take();
        let head = match progress.as_deref() {
            Some(progress) => crate::proxy::read_exact_head_deferred(
                &mut self.read,
                HEAD_LIMIT,
                crate::budgets::head_arrival(),
                progress,
            ),
            None => crate::proxy::read_exact_head(
                &mut self.read,
                HEAD_LIMIT,
                crate::budgets::head_arrival(),
            ),
        };
        let Some((head, at)) = head else {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        };
        if check_response(&head[..at]).is_none() {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        }
        self.prefix = head;
        self.at = at;
        Ok(())
    }

    fn body(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.at < self.prefix.len() {
            let n = (self.prefix.len() - self.at).min(buf.len());
            buf[..n].copy_from_slice(&self.prefix[self.at..self.at + n]);
            self.at += n;
            return Ok(n);
        }
        self.take(buf)
    }

    /// Walk the framing until a body is open or the body ends: `left` says how much is owed, and a poll timeout inside a pair or a size line leaves it where it broke.
    fn open(&mut self) -> std::io::Result<()> {
        self.parse_head()?;
        while !self.ended && self.left == 0 {
            if self.chunk == Chunk::Crlf {
                // Both bytes or neither: a poll timeout inside the CRLF leaves the pair unread, so the next read resumes on the same two bytes.
                while self.prefix.len() - self.at < 2 {
                    self.prefix.drain(..self.at);
                    self.at = 0;
                    // One promoted window instead of a two-byte read: the bytes past the CRLF are the next size lines and bodies.
                    let n = self.fill(CHUNK)?;
                    if n == 0 {
                        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
                    }
                }
                if &self.prefix[self.at..self.at + 2] != b"\r\n" {
                    return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
                }
                self.at += 2;
                self.chunk = Chunk::Body;
            }
            if self.chunk == Chunk::Trailers {
                let mut trailer = [0u8; 130];
                let len = read_line_into(self, &mut trailer)?
                    .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
                if len == 0 {
                    self.chunk = Chunk::Body;
                    self.ended = true;
                    return Ok(());
                }
                continue;
            }
            let mut line = [0u8; 130];
            let len = read_line_into(self, &mut line)?
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            let size = chunk_size(&line[..len])
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            if size == 0 {
                self.chunk = Chunk::Trailers;
                continue;
            }
            if size > 64 * 1024 * 1024 {
                return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
            }
            self.left = size;
        }
        Ok(())
    }

    /// A size or trailer line already in `prefix`; `None` leaves `at` where it was for [`Self::open`] to fill.
    fn line_in_prefix(&mut self, out: &mut [u8; 130]) -> Option<usize> {
        let start = self.at;
        let end = self.prefix.len().min(start + 130);
        let mut i = start;
        while i + 1 < end {
            if self.prefix[i] == b'\r' && self.prefix[i + 1] == b'\n' {
                let end_pos = i - start;
                if end_pos > 127 {
                    return None;
                }
                out[..end_pos].copy_from_slice(&self.prefix[start..i]);
                self.at = i + 2;
                return Some(end_pos);
            }
            i += 1;
        }
        None
    }

    /// Framing that is already in `prefix` and nowhere else: `true` leaves a body open, `false` says the next chunk needs a read or the body ended.
    fn try_open_prefix(&mut self) -> std::io::Result<bool> {
        loop {
            if self.ended {
                return Ok(false);
            }
            if self.left > 0 {
                return Ok(true);
            }
            if self.chunk == Chunk::Crlf {
                if self.prefix.len() - self.at < 2 {
                    return Ok(false);
                }
                if &self.prefix[self.at..self.at + 2] != b"\r\n" {
                    return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
                }
                self.at += 2;
                self.chunk = Chunk::Body;
            }
            if self.chunk == Chunk::Trailers {
                let mut trailer = [0u8; 130];
                match self.line_in_prefix(&mut trailer) {
                    Some(0) => {
                        self.chunk = Chunk::Body;
                        self.ended = true;
                        return Ok(false);
                    }
                    Some(_) => continue,
                    None => {
                        if self.prefix.len() - self.at >= 129 {
                            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
                        }
                        return Ok(false);
                    }
                }
            }
            let mut line = [0u8; 130];
            let Some(len) = self.line_in_prefix(&mut line) else {
                if self.prefix.len() - self.at >= 129 {
                    return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
                }
                return Ok(false);
            };
            let Some(size) = chunk_size(&line[..len]) else {
                return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
            };
            if size == 0 {
                self.chunk = Chunk::Trailers;
                continue;
            }
            if size > 64 * 1024 * 1024 {
                return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
            }
            self.left = size;
            return Ok(true);
        }
    }
}

/// The stream a session writes through after `accept_core` split it: HTTP/2 frames on a negotiated
/// h2 stream, HTTP/3 frames on a QUIC stream. The carrier above it only asks whether the body is raw.
#[derive(Debug, Clone)]
pub(crate) enum StreamOut {
    H2(crate::xhttp_h2::H2StreamOut),
    H3(crate::xhttp_h3::H3StreamOut),
}

impl StreamOut {
    pub(crate) fn data(&self, payload: &[u8]) -> bool {
        match self {
            Self::H2(out) => out.data(payload),
            Self::H3(out) => out.data(payload),
        }
    }

    pub(crate) fn bind_session(&self, sid: &str) {
        match self {
            Self::H2(out) => out.bind_session(sid),
            Self::H3(_) => crate::xhttp_h3::H3StreamOut::bind_session(sid),
        }
    }

    pub(crate) fn bind_upload(&self, sid: &str) {
        match self {
            Self::H2(out) => out.bind_upload(sid),
            Self::H3(_) => crate::xhttp_h3::H3StreamOut::bind_upload(sid),
        }
    }

    pub(crate) fn end(&self) {
        match self {
            Self::H2(out) => out.end(),
            Self::H3(out) => out.end(),
        }
    }

    pub(crate) fn reset(&self) {
        match self {
            Self::H2(out) => out.reset(),
            Self::H3(out) => out.reset(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct XhttpWriter {
    shared: Arc<Shared>,
    stream: OnceLock<StreamOut>,
    lease: Option<Arc<crate::xmux::Lease>>,
}

/// A carrier byte stream the packet frame also reads, so a POST's answer is consumed before the next shares the connection.
trait FrameStream: crate::proxy::FrameWrite + Read {}

impl<T: crate::proxy::FrameWrite + Read> FrameStream for T {}

enum Body {
    Stream(Mutex<Box<dyn crate::proxy::FrameWrite + Send>>),
    Packets(Box<Packets>),
}

/// The packet-up upload: one POST per queued batch, each with its own seq, the answer drained before the next.
struct Packets {
    up: Arc<Packer>,
    poster: Mutex<Option<std::thread::JoinHandle<()>>>,
}

/// One POST's transport: the H1 dial writes a request head and drains its answer, the H2 dial opens
/// a stream per packet on the connection both directions already share.
pub(crate) trait PacketPost: Send {
    fn post(&mut self, seq: u64, piece: &[u8]) -> bool;
}

struct Packer {
    transport: Mutex<Box<dyn PacketPost + Send>>,
    queue: Mutex<Vec<u8>>,
    cv: Condvar,
    closed: AtomicBool,
    failed: AtomicBool,
    settings: XhttpSettings,
    seq: AtomicU64,
    last: Mutex<Option<std::time::Instant>>,
}

impl Packets {
    fn new(up: Arc<Packer>, poster: Option<std::thread::JoinHandle<()>>) -> Self {
        if poster.is_none() {
            up.failed.store(true, Ordering::SeqCst);
            up.cv.notify_all();
        }
        Self {
            up,
            poster: Mutex::new(poster),
        }
    }

    fn send(&self, data: &[u8]) -> bool {
        let mut at = 0;
        while at < data.len() {
            match self.up.push(&data[at..]) {
                crate::proxy::Push::Took(n) => at += n,
                crate::proxy::Push::Parked => {
                    let Ok(mut queue) = self.up.queue.lock() else {
                        return false;
                    };
                    while queue.len() >= self.up.max()
                        && !self.up.failed.load(Ordering::SeqCst)
                        && !self.up.closed.load(Ordering::SeqCst)
                    {
                        queue = self
                            .up
                            .cv
                            .wait(queue)
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                    }
                }
                crate::proxy::Push::Lost => return false,
            }
        }
        !self.up.failed.load(Ordering::SeqCst)
    }

    fn push(&self, data: &[u8]) -> crate::proxy::Push {
        self.up.push(data)
    }

    fn finish(&self) -> bool {
        self.up.closed.store(true, Ordering::SeqCst);
        self.up.cv.notify_all();
        let poster = self.poster.lock().ok().and_then(|mut poster| poster.take());
        if let Some(poster) = poster {
            let _ = poster.join();
        }
        !self.up.failed.load(Ordering::SeqCst)
    }
}

impl Drop for Packets {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

impl Packer {
    fn max(&self) -> usize {
        self.settings.sc_max_each_post.max(1)
    }

    /// The reference's pipe batches every write that lands while a POST is in flight (`dialer.go:489`), so a full pipe becomes one POST instead of one POST per relay window.
    /// A full queue parks the caller instead of waiting in it, so a paced upload cannot pin the lane other flows need.
    fn push(&self, data: &[u8]) -> crate::proxy::Push {
        if data.is_empty() {
            return crate::proxy::Push::Took(0);
        }
        if self.closed.load(Ordering::SeqCst) {
            return crate::proxy::Push::Lost;
        }
        let max = self.max();
        let Ok(mut queue) = self.queue.lock() else {
            return crate::proxy::Push::Lost;
        };
        if self.failed.load(Ordering::SeqCst) {
            return crate::proxy::Push::Lost;
        }
        let room = max.saturating_sub(queue.len());
        if room == 0 {
            return crate::proxy::Push::Parked;
        }
        let take = room.min(data.len());
        queue.extend_from_slice(&data[..take]);
        self.cv.notify_all();
        crate::proxy::Push::Took(take)
    }

    fn pump(&self) {
        let mut spare = Vec::new();
        loop {
            let Ok(mut queue) = self.queue.lock() else {
                self.failed.store(true, Ordering::SeqCst);
                return;
            };
            while queue.is_empty() && !self.closed.load(Ordering::SeqCst) {
                queue = self
                    .cv
                    .wait(queue)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            if queue.is_empty() {
                return;
            }
            let take = queue.len().min(self.max());
            let piece = if take == queue.len() {
                std::mem::replace(&mut *queue, std::mem::take(&mut spare))
            } else {
                let rest = queue.split_off(take);
                std::mem::replace(&mut *queue, rest)
            };
            self.cv.notify_all();
            drop(queue);
            let Ok(mut transport) = self.transport.lock() else {
                self.failed.store(true, Ordering::SeqCst);
                return;
            };
            if !self.post(&mut **transport, &piece) {
                self.failed.store(true, Ordering::SeqCst);
                self.cv.notify_all();
                return;
            }
            spare = piece;
            spare.clear();
        }
    }

    fn post(&self, transport: &mut dyn PacketPost, piece: &[u8]) -> bool {
        let Ok(mut last) = self.last.lock() else {
            return false;
        };
        // The reference paces the posts from the second one (`dialer.go:520`), gated on the range's `from`.
        if let Some(since) = *last {
            let (from, to) = self.settings.sc_min_posts_interval_ms;
            if from > 0 {
                let want = std::time::Duration::from_millis(
                    u64::try_from(random_between(from as usize, to as usize)).unwrap_or(0),
                );
                if let Some(pause) = want.checked_sub(since.elapsed()) {
                    std::thread::sleep(pause);
                }
            }
        }
        *last = Some(std::time::Instant::now());
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        transport.post(seq, piece)
    }
}

/// The H1 packet transport: one request head, its body, and the answer read back off the same stream.
struct H1Post {
    stream: Box<dyn FrameStream + Send>,
    host: String,
    settings: XhttpSettings,
    session: String,
    answer: Vec<u8>,
}

impl PacketPost for H1Post {
    fn post(&mut self, seq: u64, piece: &[u8]) -> bool {
        let (head, body) = packet_head(&self.host, &self.settings, &self.session, seq, piece);
        let wrote = match body {
            Some(body) => self.stream.write_slices(&[head.as_bytes(), body]),
            None => self.stream.write_all(head.as_bytes()).is_ok(),
        };
        wrote && drain_answer(&mut *self.stream, &mut self.answer)
    }
}

/// The H2 packet transport: the stream is the packet, opened and retired on the session's connection.
struct H2Post {
    client: Arc<crate::xhttp_h2::H2Client>,
    host: String,
    settings: XhttpSettings,
    session: String,
    _owner: Arc<crate::xhttp_h2::ClientOwner>,
}

impl PacketPost for H2Post {
    fn post(&mut self, seq: u64, piece: &[u8]) -> bool {
        self.client
            .packet(&self.host, &self.settings, &self.session, seq, piece)
    }
}

/// A packet-up POST answers 200 with no body; anything else is a dead upload.
fn drain_answer(stream: &mut dyn Read, head: &mut Vec<u8>) -> bool {
    let Some((got, at)) = crate::proxy::read_exact_head_into(
        stream,
        HEAD_LIMIT,
        crate::budgets::head_arrival(),
        std::mem::take(head),
    ) else {
        return false;
    };
    *head = got;
    let Ok(text) = std::str::from_utf8(&head[..at]) else {
        return false;
    };
    if !ok_status_text(text) {
        return false;
    }
    let mut left = content_length(text).unwrap_or(0);
    let mut sink = [0u8; 256];
    while left > 0 {
        let want = left.min(sink.len());
        match stream.read(&mut sink[..want]) {
            Ok(0) | Err(_) => return false,
            Ok(n) => left -= n,
        }
    }
    true
}

struct Shared {
    body: Body,
    finished: AtomicBool,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl<R: Read> Read for Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.open()?;
        if self.ended {
            return Ok(0);
        }
        let n = self.left.min(buf.len());
        let got = self.body(&mut buf[..n])?;
        if got == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        self.left -= got;
        if self.left == 0 {
            // The pair is taken on the next call, so a poll timeout after these bytes cannot lose them.
            self.chunk = Chunk::Crlf;
        }
        Ok(got)
    }
}

impl<R: Read> crate::proxy::WindowRead for Reader<R> {
    fn set_head_progress(&mut self, progress: Arc<AtomicU64>) {
        Reader::set_head_progress(self, progress);
    }

    fn awaits_head(&self) -> bool {
        self.pending_head
    }

    /// Every body the prefix already holds, as spans of it: the relay writes them in one gather without moving them again.
    fn read_window(&mut self) -> std::io::Result<crate::proxy::Window<'_>> {
        self.open()?;
        let mut spans = [(0, 0); crate::proxy::WINDOW_PARTS];
        let mut len = 0;
        loop {
            if self.ended {
                break;
            }
            if self.at == self.prefix.len() {
                if len == 0 {
                    self.prefix.clear();
                    self.at = 0;
                    if self.fill(CHUNK)? == 0 {
                        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
                    }
                    continue;
                }
                break;
            }
            let n = self.left.min(self.prefix.len() - self.at);
            if n == 0 {
                break;
            }
            spans[len] = (self.at, n);
            len += 1;
            self.at += n;
            self.left -= n;
            if self.left == 0 {
                self.chunk = Chunk::Crlf;
            }
            if len == crate::proxy::WINDOW_PARTS {
                break;
            }
            let before = (self.at, self.left, self.chunk, self.ended);
            match self.try_open_prefix() {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => {
                    // The body already gathered still belongs to this read; `Read` reports the bad framing on the next call, and so does this.
                    self.at = before.0;
                    self.left = before.1;
                    self.chunk = before.2;
                    self.ended = before.3;
                    if len == 0 {
                        return Err(error);
                    }
                    break;
                }
            }
        }
        if len == 0 {
            return Ok(crate::proxy::Window::empty());
        }
        Ok(crate::proxy::Window::new(&self.prefix, spans, len))
    }
}

impl XhttpWriter {
    pub(crate) fn new<W: crate::proxy::FrameWrite + Send + 'static>(w: W) -> Self {
        Self {
            shared: Arc::new(Shared {
                body: Body::Stream(Mutex::new(
                    Box::new(w) as Box<dyn crate::proxy::FrameWrite + Send>
                )),
                finished: AtomicBool::new(false),
            }),
            stream: OnceLock::new(),
            lease: None,
        }
    }
    fn packets<W: crate::proxy::FrameWrite + Read + Send + 'static>(
        w: W,
        host: &str,
        settings: &XhttpSettings,
        session: String,
    ) -> Self {
        let post = H1Post {
            stream: Box::new(w),
            host: host.to_owned(),
            settings: settings.clone(),
            session,
            answer: Vec::new(),
        };
        Self::packets_with(Box::new(post), settings)
    }
    pub(crate) fn packets_h2(
        client: Arc<crate::xhttp_h2::H2Client>,
        host: &str,
        settings: &XhttpSettings,
        session: String,
        owner: Arc<crate::xhttp_h2::ClientOwner>,
    ) -> Self {
        let post = H2Post {
            client,
            host: host.to_owned(),
            settings: settings.clone(),
            session,
            _owner: owner,
        };
        Self::packets_with(Box::new(post), settings)
    }
    pub(crate) fn packets_h3(
        client: Arc<crate::xhttp_h3::H3Client>,
        host: &str,
        settings: &XhttpSettings,
        session: String,
    ) -> Self {
        crate::xhttp_h3::packets(client, host, settings, session)
    }
    pub(crate) fn packets_with(post: Box<dyn PacketPost + Send>, settings: &XhttpSettings) -> Self {
        let up = Arc::new(Packer {
            transport: Mutex::new(post),
            queue: Mutex::new(Vec::new()),
            cv: Condvar::new(),
            closed: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            settings: settings.clone(),
            seq: AtomicU64::new(0),
            last: Mutex::new(None),
        });
        let poster = {
            let up = Arc::clone(&up);
            std::thread::Builder::new()
                .name("xhttp-packet-up".to_owned())
                .spawn(move || up.pump())
                .ok()
        };
        Self {
            shared: Arc::new(Shared {
                body: Body::Packets(Box::new(Packets::new(up, poster))),
                finished: AtomicBool::new(false),
            }),
            stream: OnceLock::new(),
            lease: None,
        }
    }
    pub(crate) fn hold(&mut self, lease: Arc<crate::xmux::Lease>) {
        self.lease = Some(lease);
    }
    pub(crate) fn set_stream(&self, out: StreamOut) {
        let _ = self.stream.set(out);
    }
    pub(crate) fn set_h2(&self, out: crate::xhttp_h2::H2StreamOut) {
        self.set_stream(StreamOut::H2(out));
    }
    pub(crate) fn send(&self, data: &[u8]) -> bool {
        if let Some(stream) = self.stream.get() {
            return stream.data(data);
        }
        let stream = match &self.shared.body {
            Body::Stream(stream) => stream,
            Body::Packets(packets) => return packets.send(data),
        };
        let Ok(mut stream) = stream.lock() else {
            return false;
        };
        for piece in data.chunks(CHUNK) {
            if piece.is_empty() {
                continue;
            }
            let mut line = [0u8; 7];
            let len = size_line(piece.len(), &mut line);
            if !stream.write_slices(&[&line[..len], piece, b"\r\n"]) {
                return false;
            }
        }
        true
    }
    /// The session refused the request: the response ends and, on h2, the request is reset so its
    /// unread body is not credited for the connection's life.
    pub(crate) fn abort(&self) {
        if let Some(stream) = self.stream.get() {
            if self.shared.finished.swap(true, Ordering::SeqCst) {
                return;
            }
            stream.reset();
            return;
        }
        self.finish();
    }

    pub(crate) fn finish(&self) {
        if self.shared.finished.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some(stream) = self.stream.get() {
            stream.end();
            return;
        }
        match &self.shared.body {
            Body::Stream(stream) => {
                let Ok(mut stream) = stream.lock() else {
                    return;
                };
                let _ = stream.write_all(b"0\r\n\r\n");
            }
            Body::Packets(packets) => {
                let _ = packets.finish();
            }
        }
    }
}

impl Write for XhttpWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.send(data) {
            Ok(data.len())
        } else {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn split(read: Connection, prefix: Vec<u8>, at: usize) -> Option<(XhttpReader, XhttpWriter)> {
    let Ok(write) = read.try_clone() else {
        return None;
    };
    Some(split_halves(read, write, prefix, at))
}

// The same split over halves that cannot clone: `prefix` is the buffer the head read left, with `at` already past the head.
fn split_halves<R: Read, W: crate::proxy::FrameWrite + 'static>(
    read: R,
    write: W,
    prefix: Vec<u8>,
    at: usize,
) -> (Reader<R>, XhttpWriter) {
    let reader = Reader {
        read,
        prefix,
        at,
        left: 0,
        ended: false,
        reads: 0,
        pending_head: false,
        head_progress: None,
        chunk: Chunk::Body,
    };
    let writer = XhttpWriter {
        shared: Arc::new(Shared {
            body: Body::Stream(Mutex::new(
                Box::new(write) as Box<dyn crate::proxy::FrameWrite + Send>
            )),
            finished: AtomicBool::new(false),
        }),
        stream: OnceLock::new(),
        lease: None,
    };
    (reader, writer)
}

fn has_chunked(value: &str) -> bool {
    value
        .as_bytes()
        .windows(7)
        .any(|w| w.eq_ignore_ascii_case(b"chunked"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum XhttpMode {
    StreamOne,
    StreamUp,
    PacketUp,
}

impl XhttpMode {
    fn parse_mode(s: &str) -> Option<XhttpMode> {
        match s {
            "stream-one" | "streamone" => Some(XhttpMode::StreamOne),
            "stream-up" => Some(XhttpMode::StreamUp),
            "packet-up" => Some(XhttpMode::PacketUp),
            _ => None,
        }
    }

    // Missing/`auto` resolve the way the reference's dialer.go:332 does.
    fn auto_mode(settings: &crate::json::Json, xhttp: &crate::json::Json) -> XhttpMode {
        let reality = settings
            .get("security")
            .and_then(crate::json::Json::as_str)
            .is_some_and(|s| s == "reality");
        if reality {
            if xhttp.get("downloadSettings").is_some() {
                XhttpMode::StreamUp
            } else {
                XhttpMode::StreamOne
            }
        } else {
            XhttpMode::PacketUp
        }
    }
}

/// Whether the config wrote a mode down. The reference hub gates a shape only on a stated mode (`hub.go:154`), so `Auto` names a dialer default rather than a limit on what may arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModeSource {
    Stated,
    Auto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Placement {
    Path,
    Query,
    Header,
    Cookie,
    Body,
    Auto,
    QueryInHeader,
}

impl Placement {
    fn parse(s: &str) -> Option<Placement> {
        Some(match s {
            "path" => Placement::Path,
            "query" => Placement::Query,
            "header" => Placement::Header,
            "cookie" => Placement::Cookie,
            "body" => Placement::Body,
            "auto" => Placement::Auto,
            "queryInHeader" => Placement::QueryInHeader,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PadMethod {
    RepeatX,
    Tokenish,
}

/// The `xmux` bounds (`transport_method.go:299`): the reference grows an H2 connection pool from them,
/// and `xmux::Manager` steers the REALITY stream-one pool by the same six fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub(crate) struct Xmux {
    pub max_concurrency: (i32, i32),
    pub max_connections: (i32, i32),
    pub c_max_reuse_times: (i32, i32),
    pub h_max_request_times: (i32, i32),
    pub h_max_reusable_secs: (i32, i32),
    pub h_keep_alive_period: i64,
}

impl Xmux {
    /// `SplitHTTPConfig.Build` (`transport_method.go:458`): the two bounds exclude each other, and a block
    /// that names none of its six fields takes the reference's pool defaults. The flag says whether the
    /// config wrote the block at all, which is what the one-line notice keys on.
    fn from_json(node: Option<&crate::json::Json>) -> Option<(Self, bool)> {
        let mut out = Self::default();
        let stated = match node {
            None | Some(crate::json::Json::Null) => false,
            Some(node @ crate::json::Json::Obj(_)) => {
                let field = |name: &str| -> Option<(i32, i32)> {
                    match node.get(name) {
                        Some(value) => i32_range(value),
                        None => Some((0, 0)),
                    }
                };
                out.max_concurrency = field("maxConcurrency")?;
                out.max_connections = field("maxConnections")?;
                out.c_max_reuse_times = field("cMaxReuseTimes")?;
                out.h_max_request_times = field("hMaxRequestTimes")?;
                out.h_max_reusable_secs = field("hMaxReusableSecs")?;
                out.h_keep_alive_period = match node.get("hKeepAlivePeriod") {
                    None | Some(crate::json::Json::Null) => 0,
                    Some(value) => value.as_i64()?,
                };
                true
            }
            Some(_) => return None,
        };
        if out.max_connections.1 > 0 && out.max_concurrency.1 > 0 {
            eprintln!("maxConnections cannot be specified together with maxConcurrency");
            return None;
        }
        if out == Self::default() {
            out.max_connections = (3, 3);
            out.h_max_request_times = (600, 900);
            out.h_max_reusable_secs = (1800, 3000);
        }
        Some((out, stated))
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct XhttpSettings {
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub mode: XhttpMode,
    pub mode_source: ModeSource,
    /// Dial the cleartext carrier with the HTTP/2 preface instead of an H1 head; the hub answers both.
    pub h2c: bool,
    pub session_placement: Placement,
    pub session_key: String,
    pub seq_placement: Placement,
    pub seq_key: String,
    pub uplink_data_placement: Placement,
    pub uplink_data_key: String,
    pub uplink_chunk: (usize, usize),
    pub uplink_method: String,
    pub session_id_length: (usize, usize),
    pub session_id_table: String,
    pub x_padding_bytes: (u32, u32),
    pub x_padding_obfs: bool,
    pub x_padding_placement: Placement,
    pub x_padding_key: String,
    pub x_padding_header: String,
    pub x_padding_method: PadMethod,
    pub sc_max_each_post: usize,
    pub sc_max_buffered: usize,
    pub sc_min_posts_interval_ms: (u64, u64),
    pub no_sse: bool,
    pub no_grpc_header: bool,
    /// The bounds a written `xmux` block states with the reference's defaults filled in; `None` when it wrote none.
    pub xmux: Option<Xmux>,
}

impl XhttpSettings {
    /// `GenerateSessionID` (config.go:511): a named or literal table at a positive length draws the id, and anything else mints the UUID the reference's default uses.
    pub(crate) fn session_id(&self) -> String {
        let table = match self.session_id_table.as_str() {
            "ALPHABET" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "Alphabet" => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "BASE36" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "Base62" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "HEX" => "0123456789ABCDEF",
            "alphabet" => "abcdefghijklmnopqrstuvwxyz",
            "base36" => "0123456789abcdefghijklmnopqrstuvwxyz",
            "hex" => "0123456789abcdef",
            "number" => "0123456789",
            other => other,
        };
        let length = random_between(self.session_id_length.0, self.session_id_length.1);
        if table.is_empty() || length == 0 {
            return uuid_v4();
        }
        let mut raw = vec![0u8; length];
        getrandom::fill(&mut raw).unwrap_or_default();
        raw.iter()
            .map(|byte| table.as_bytes()[usize::from(*byte) % table.len()] as char)
            .collect()
    }

    pub(crate) fn stream_one() -> Self {
        Self {
            path: "/".to_owned(),
            query: String::new(),
            headers: Vec::new(),
            mode: XhttpMode::StreamOne,
            mode_source: ModeSource::Auto,
            h2c: false,
            session_placement: Placement::Path,
            session_key: String::new(),
            seq_placement: Placement::Path,
            seq_key: String::new(),
            uplink_data_placement: Placement::Body,
            uplink_data_key: String::new(),
            uplink_chunk: (1_000_000, 1_000_000),
            uplink_method: "POST".to_owned(),
            session_id_length: (0, 0),
            session_id_table: String::new(),
            x_padding_bytes: (100, 1000),
            x_padding_obfs: false,
            x_padding_placement: Placement::Header,
            x_padding_key: "x_padding".to_owned(),
            x_padding_header: "X-Padding".to_owned(),
            x_padding_method: PadMethod::RepeatX,
            sc_max_each_post: 1_000_000,
            sc_max_buffered: 30,
            sc_min_posts_interval_ms: (30, 30),
            no_sse: false,
            no_grpc_header: false,
            xmux: None,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "straight-line config parse, one block per knob; splitting hides defaults"
    )]
    pub(crate) fn from_json(settings: Option<&crate::json::Json>) -> Option<XhttpSettings> {
        let settings = settings?;
        let Some(xhttp) = settings
            .get("xhttpSettings")
            .or_else(|| settings.get("splithttpSettings"))
        else {
            // A bare xhttp network carries no settings block and means defaults; any other network means this parser does not apply.
            return match settings.get("network").and_then(crate::json::Json::as_str) {
                Some("xhttp" | "splithttp") => Some(XhttpSettings::stream_one()),
                _ => None,
            };
        };
        let mut out = XhttpSettings::stream_one();
        // The path is a path plus the query that rode with it (`config.go:20`, `:38`): a session or seq segment still lands under the path, and the query rides on every dial head.
        let raw_path = xhttp
            .get("path")
            .and_then(crate::json::Json::as_str)
            .unwrap_or("/");
        let (path, query) = raw_path.split_once('?').unwrap_or((raw_path, ""));
        query.clone_into(&mut out.query);
        path.clone_into(&mut out.path);
        if !out.path.starts_with('/') {
            out.path.insert(0, '/');
        }
        let raw = xhttp
            .get("mode")
            .and_then(crate::json::Json::as_str)
            .unwrap_or("");
        out.mode_source = if raw.is_empty() || raw == "auto" {
            ModeSource::Auto
        } else {
            ModeSource::Stated
        };
        out.mode = if out.mode_source == ModeSource::Stated {
            XhttpMode::parse_mode(raw)?
        } else {
            XhttpMode::auto_mode(settings, xhttp)
        };
        // Xray's `SplitHTTPConfig.Build` replaces every knob below but host, path and mode with the `extra` block a link carries, which arrives either as an object or as the JSON string the link query holds.
        let extra = xhttp.get("extra");
        let owned: Option<crate::json::Json> = match extra {
            Some(crate::json::Json::Str(text)) => crate::json::parse(text.as_str()).ok(),
            _ => None,
        };
        let xhttp: &crate::json::Json = match extra {
            None | Some(crate::json::Json::Null) => xhttp,
            Some(node @ crate::json::Json::Obj(_)) => node,
            Some(crate::json::Json::Str(_)) => match owned.as_ref() {
                Some(node @ crate::json::Json::Obj(_)) => node,
                _ => return None,
            },
            Some(_) => return None,
        };
        out.h2c = xhttp
            .get("h2c")
            .and_then(crate::json::Json::as_bool)
            .unwrap_or(false);
        out.headers = crate::config::masquerade_headers(xhttp.get("headers"));
        out.session_placement = placement_or(
            xhttp.get("sessionIDPlacement"),
            Placement::Path,
            &[
                Placement::Path,
                Placement::Cookie,
                Placement::Header,
                Placement::Query,
            ],
        )?;
        out.seq_placement = placement_or(
            xhttp.get("seqPlacement"),
            Placement::Path,
            &[
                Placement::Path,
                Placement::Cookie,
                Placement::Header,
                Placement::Query,
            ],
        )?;
        out.session_key = key_or(
            xhttp.get("sessionIDKey"),
            out.session_placement,
            "x_session",
            "X-Session",
        );
        out.seq_key = key_or(xhttp.get("seqKey"), out.seq_placement, "x_seq", "X-Seq");
        out.uplink_data_placement = placement_or(
            xhttp.get("uplinkDataPlacement"),
            Placement::Body,
            &[
                Placement::Body,
                Placement::Cookie,
                Placement::Header,
                Placement::Auto,
            ],
        )?;
        if matches!(
            out.uplink_data_placement,
            Placement::Cookie | Placement::Header
        ) && out.mode != XhttpMode::PacketUp
        {
            return None;
        }
        // `AnalogConfig`'s uplinkData key defaults (`config.go:65-97`): `x_data` on cookies, `X-Data` on headers.
        let data_key = match out.uplink_data_placement {
            Placement::Cookie => "x_data",
            Placement::Header | Placement::Auto => "X-Data",
            _ => "",
        };
        xhttp
            .get("uplinkDataKey")
            .and_then(crate::json::Json::as_str)
            .unwrap_or(data_key)
            .clone_into(&mut out.uplink_data_key);
        let mut method = xhttp
            .get("uplinkHTTPMethod")
            .and_then(crate::json::Json::as_str)
            .unwrap_or("POST")
            .to_ascii_uppercase();
        if method.is_empty() {
            "POST".clone_into(&mut method);
        }
        if method == "GET" && out.mode != XhttpMode::PacketUp {
            return None;
        }
        out.uplink_method = method;
        out.x_padding_bytes = match xhttp.get("xPaddingBytes") {
            None => (100, 1000),
            Some(node) => {
                let (from, to) = parse_range(node)?;
                if from == 0 && to == 0 {
                    (100, 1000)
                } else if from == 0 || to == 0 {
                    return None;
                } else {
                    (from, to)
                }
            }
        };
        out.x_padding_obfs = xhttp
            .get("xPaddingObfsMode")
            .and_then(crate::json::Json::as_bool)
            .unwrap_or(false);
        xhttp
            .get("xPaddingKey")
            .and_then(crate::json::Json::as_str)
            .unwrap_or("x_padding")
            .clone_into(&mut out.x_padding_key);
        xhttp
            .get("xPaddingHeader")
            .and_then(crate::json::Json::as_str)
            .unwrap_or("X-Padding")
            .clone_into(&mut out.x_padding_header);
        out.x_padding_placement = placement_or(
            xhttp.get("xPaddingPlacement"),
            Placement::QueryInHeader,
            &[
                Placement::Cookie,
                Placement::Header,
                Placement::Query,
                Placement::QueryInHeader,
            ],
        )?;
        out.x_padding_method = match xhttp
            .get("xPaddingMethod")
            .and_then(crate::json::Json::as_str)
            .unwrap_or("repeat-x")
        {
            "repeat-x" => PadMethod::RepeatX,
            "tokenish" => PadMethod::Tokenish,
            _ => return None,
        };
        out.no_grpc_header = xhttp
            .get("noGRPCHeader")
            .and_then(crate::json::Json::as_bool)
            .unwrap_or(false);
        out.no_sse = xhttp
            .get("noSSEHeader")
            .and_then(crate::json::Json::as_bool)
            .unwrap_or(false);
        // `GenerateSessionID` (config.go:511) draws from this table at this length, or mints a UUID when either is absent.
        out.session_id_length = xhttp
            .get("sessionIDLength")
            .and_then(parse_range)
            .map_or((0, 0), |(from, to)| (from as usize, to as usize));
        xhttp
            .get("sessionIDTable")
            .and_then(crate::json::Json::as_str)
            .unwrap_or("")
            .clone_into(&mut out.session_id_table);
        out.sc_max_each_post = xhttp
            .get("scMaxEachPostBytes")
            .and_then(parse_range)
            .map_or(1_000_000, |(_, to)| to as usize);
        if out.sc_max_each_post == 0 {
            out.sc_max_each_post = 1_000_000;
        }
        // `GetNormalizedUplinkChunkSize` (config.go:181) draws from a placement-sized range by default and floors a written `from` at 64.
        out.uplink_chunk = match xhttp.get("uplinkChunkSize").and_then(parse_range) {
            Some((from, to)) if to > 0 => {
                if from < 64 {
                    (64, usize::try_from(to).unwrap_or(usize::MAX).max(64))
                } else {
                    (from as usize, to as usize)
                }
            }
            _ => match out.uplink_data_placement {
                Placement::Cookie => (2 * 1024, 3 * 1024),
                Placement::Header => (3 * 1000, 4 * 1000),
                _ => (out.sc_max_each_post, out.sc_max_each_post),
            },
        };
        out.sc_max_buffered = xhttp
            .get("scMaxBufferedPosts")
            .and_then(crate::json::Json::as_u32)
            .filter(|n| *n > 0)
            .map_or(30, |n| n as usize);
        out.sc_min_posts_interval_ms = xhttp
            .get("scMinPostsIntervalMs")
            .and_then(parse_range)
            .map_or((30, 30), |(from, to)| (u64::from(from), u64::from(to)));
        if out.sc_min_posts_interval_ms.1 == 0 {
            out.sc_min_posts_interval_ms = (30, 30);
        }
        let (xmux, stated) = Xmux::from_json(xhttp.get("xmux"))?;
        out.xmux = stated.then_some(xmux);
        Some(out)
    }
}

fn placement_or(
    node: Option<&crate::json::Json>,
    default: Placement,
    allowed: &[Placement],
) -> Option<Placement> {
    let Some(node) = node else {
        return Some(default);
    };
    let value = Placement::parse(node.as_str()?)?;
    allowed.contains(&value).then_some(value)
}

fn key_or(
    node: Option<&crate::json::Json>,
    placement: Placement,
    query_default: &str,
    header_default: &str,
) -> String {
    if let Some(key) = node.and_then(crate::json::Json::as_str) {
        return key.to_owned();
    }
    match placement {
        Placement::Cookie | Placement::Query => query_default.to_owned(),
        Placement::Header => header_default.to_owned(),
        _ => String::new(),
    }
}

fn parse_range(node: &crate::json::Json) -> Option<(u32, u32)> {
    if let Some(n) = node.as_u32() {
        return Some((n, n));
    }
    let (a, b) = node.as_str()?.split_once('-')?;
    let (a, b) = (a.parse::<u32>().ok()?, b.parse::<u32>().ok()?);
    Some((a.min(b), a.max(b)))
}

/// `Int32Range` (`common.go:295`): an integer, or a string holding one, `a-b`, an empty string, or the
/// signed forms `-a-b` and `-a--b`, ordered so the low bound is first. `null` is the zero range.
fn i32_range(node: &crate::json::Json) -> Option<(i32, i32)> {
    let (left, right) = match node {
        crate::json::Json::Null => (0, 0),
        crate::json::Json::Num(n)
            if n.fract() == 0.0 && (-2_147_483_648.0..=2_147_483_647.0).contains(n) =>
        {
            (*n as i32, *n as i32)
        }
        crate::json::Json::Str(text) => i32_range_string(text)?,
        _ => return None,
    };
    Some((left.min(right), left.max(right)))
}

/// `ParseRangeString` (`common.go:364`): the reference's `Atoi` on each half, and its `int32(...)` cast,
/// which wraps rather than refusing a half that outgrew an `i32`.
fn i32_range_string(text: &str) -> Option<(i32, i32)> {
    let narrow = |part: &str| part.parse::<i64>().ok().map(|value| value as i32);
    if let Some(value) = narrow(text) {
        return Some((value, value));
    }
    if text.is_empty() {
        return Some((0, 0));
    }
    // `splitFromSecondDash` splits on the dash that separates the bounds, not on the sign.
    let (left, right) = match text.strip_prefix('-') {
        Some(body) => {
            let at = body.find('-')?;
            (&text[..=at], &body[at + 1..])
        }
        None => text.split_once('-')?,
    };
    Some((narrow(left)?, narrow(right)?))
}

const HUFFMAN_CODE_LEN: [u8; 256] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22,
    23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22,
    21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20,
    22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19,
    21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22,
    22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
];

fn huffman_len(s: &[u8]) -> usize {
    s.iter()
        .map(|&b| HUFFMAN_CODE_LEN[b as usize] as usize)
        .sum::<usize>()
        .div_ceil(8)
}

fn generate_tokenish(target_huffman_bytes: usize) -> String {
    let n = (target_huffman_bytes * 10).div_ceil(8);
    // The draw fills every byte, so the zero pass in front of it was work thrown away; a draw that fails still leaves the pad it always did.
    let mut raw = crate::proxy::unfilled(n.max(1));
    if getrandom::fill(&mut raw).is_err() {
        raw.fill(0);
    }
    tokenish_adjust(&raw, target_huffman_bytes)
}

/// Maps the random bytes into base62 and walks the padding to its target, but carries the code-length sum instead of re-scanning the whole string on every one of the 150 adjust steps: only the end the loop touches moves the sum.
fn tokenish_adjust(raw: &[u8], target_huffman_bytes: usize) -> String {
    const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const ADJUST_STEPS: usize = 150;
    // One buffer for the pad and the steps it can grow by, so no push past the decoded length moves it.
    let mut s = String::with_capacity(raw.len() + ADJUST_STEPS);
    s.extend(raw.iter().map(|&b| BASE62[(b as usize) % 62] as char));
    let mut bits: usize = s
        .bytes()
        .map(|b| usize::from(HUFFMAN_CODE_LEN[usize::from(b)]))
        .sum();
    for iter in 0..ADJUST_STEPS {
        let cur = bits.div_ceil(8);
        if cur.abs_diff(target_huffman_bytes) <= 2 {
            return s;
        }
        if cur < target_huffman_bytes {
            let added = if iter % 2 == 0 { b'X' } else { b'Z' };
            bits += usize::from(HUFFMAN_CODE_LEN[usize::from(added)]);
            s.push(added as char);
        } else if s.len() > 1 {
            let last = s.as_bytes()[s.len() - 1];
            s.pop();
            bits -= usize::from(HUFFMAN_CODE_LEN[usize::from(last)]);
        } else {
            return s;
        }
    }
    s
}

fn pad_value(method: PadMethod, len: usize) -> String {
    match method {
        PadMethod::RepeatX => "X".repeat(len),
        PadMethod::Tokenish => generate_tokenish(len),
    }
}

fn pad_target_len(settings: &XhttpSettings) -> usize {
    let (from, to) = settings.x_padding_bytes;
    if to <= from {
        return from as usize;
    }
    let mut raw = [0u8; 4];
    getrandom::fill(&mut raw).unwrap_or_default();
    from as usize + (u32::from_le_bytes(raw) as usize % (to as usize - from as usize + 1))
}

fn padding_valid(value: &str, from: u32, to: u32, method: PadMethod) -> bool {
    if value.is_empty() {
        return false;
    }
    match method {
        PadMethod::RepeatX => {
            let n = value.len() as u32;
            n >= from && n <= to
        }
        PadMethod::Tokenish => {
            let n = huffman_len(value.as_bytes()) as u32;
            n >= from.saturating_sub(2) && n <= to + 2
        }
    }
}

fn query_param<'a>(target: &'a str, key: &str) -> Option<&'a str> {
    let q = target.split_once('?')?.1;
    for part in q.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            if k == key {
                return Some(v);
            }
        }
    }
    None
}

fn header_cookie<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        if k.eq_ignore_ascii_case("cookie") {
            for part in v.trim().split(';') {
                let Some((n, val)) = part.trim().split_once('=') else {
                    continue;
                };
                if n == name {
                    return Some(val);
                }
            }
        }
    }
    None
}

/// The head's field lines after the request line, up to the first line without a colon — where a field lookup stops.
fn head_fields(text: &str) -> Vec<(&str, &str)> {
    let mut fields = Vec::with_capacity(8);
    for line in text.split("\r\n").skip(1) {
        let Some((key, value)) = line.split_once(':') else {
            break;
        };
        fields.push((key.trim(), value.trim()));
    }
    fields
}

/// Every cookie pair in the head, in the order a name lookup walks them.
fn cookie_pairs(text: &str) -> Vec<(&str, &str)> {
    let mut pairs = Vec::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.eq_ignore_ascii_case("cookie") {
            for part in value.trim().split(';') {
                if let Some((name, value)) = part.trim().split_once('=') {
                    pairs.push((name, value));
                }
            }
        }
    }
    pairs
}

/// The canonical decimal `index` a name spells for `key`, or `None` when it names another key, a non-canonical decimal, or no part. Header names fold case, cookie names do not.
fn part_index(name: &str, key: &str, sep: u8, fold: bool) -> Option<usize> {
    let name = name.as_bytes();
    let key = key.as_bytes();
    if name.len() <= key.len() {
        return None;
    }
    let head = &name[..key.len()];
    let matches = if fold {
        head.eq_ignore_ascii_case(key)
    } else {
        head == key
    };
    if !matches {
        return None;
    }
    let rest = &name[key.len()..];
    if rest.first() != Some(&sep) {
        return None;
    }
    let digits = &rest[1..];
    if digits.is_empty() || (digits[0] == b'0' && digits.len() > 1) {
        return None;
    }
    let mut index = 0usize;
    for &byte in digits {
        if !byte.is_ascii_digit() {
            return None;
        }
        index = index
            .checked_mul(10)?
            .checked_add(usize::from(byte - b'0'))?;
    }
    Some(index)
}

/// The packet the data parts carry: one walk of the head answers every part name, and the parts decode as their join because the six-bit window crosses the cut.
fn data_parts(text: &str, settings: &XhttpSettings) -> Option<Vec<u8>> {
    const INLINE: usize = 512;
    let (key, sep, fields, fold) = match settings.uplink_data_placement {
        Placement::Header => (
            if settings.uplink_data_key.is_empty() {
                "X-Data"
            } else {
                settings.uplink_data_key.as_str()
            },
            b'-',
            head_fields(text),
            true,
        ),
        Placement::Cookie => (
            if settings.uplink_data_key.is_empty() {
                "x_data"
            } else {
                settings.uplink_data_key.as_str()
            },
            b'_',
            cookie_pairs(text),
            false,
        ),
        _ => return None,
    };
    let mut slots: Vec<&str> = vec![""; fields.len()];
    let mut inline = [0u64; INLINE / 64];
    let mut overflow: Vec<bool> = Vec::new();
    if fields.len() > INLINE {
        overflow = vec![false; fields.len()];
    }
    for &(name, value) in &fields {
        let Some(index) = part_index(name, key, sep, fold) else {
            continue;
        };
        if index >= slots.len() {
            continue;
        }
        let bit = 1u64 << (index % 64);
        let present = if index < INLINE {
            inline[index / 64] & bit != 0
        } else {
            overflow[index]
        };
        if present {
            continue;
        }
        slots[index] = value;
        if index < INLINE {
            inline[index / 64] |= bit;
        } else {
            overflow[index] = true;
        }
    }
    let mut len = 0;
    while len < slots.len() {
        let present = if len < INLINE {
            inline[len / 64] & (1u64 << (len % 64)) != 0
        } else {
            overflow[len]
        };
        if !present {
            break;
        }
        len += 1;
    }
    slots.truncate(len);
    url_decode_parts(&slots)
}

fn extract_padding<'a>(
    text: &'a str,
    target: &'a str,
    settings: &XhttpSettings,
) -> Option<&'a str> {
    if !settings.x_padding_obfs {
        if let Some(remark) = crate::proxy::header_value_in(text, "referer") {
            if let Some(v) = query_param(remark, "x_padding") {
                return Some(v);
            }
        }
        return query_param(target, "x_padding");
    }
    if let Some(cookie) = header_cookie(text, &settings.x_padding_key) {
        return Some(cookie);
    }
    if let Some(value) = crate::proxy::header_value_in(text, &settings.x_padding_header) {
        if settings.x_padding_placement == Placement::Header {
            return Some(value);
        }
        if let Some(v) = query_param(value, &settings.x_padding_key) {
            return Some(v);
        }
    }
    query_param(target, &settings.x_padding_key)
}

/// Reads the session id and packet sequence from one request target.
pub(crate) fn extract_meta<'a>(
    text: &'a str,
    target: &'a str,
    settings: &XhttpSettings,
) -> (Option<&'a str>, Option<&'a str>) {
    // A `Path` placement asks for its segment by position, so the path is scanned rather than collected.
    let segment = |n: usize| -> Option<&'a str> {
        let rest = target.strip_prefix(settings.path.as_str()).unwrap_or("");
        rest.split_once('?')
            .map_or(rest, |(r, _)| r)
            .split('/')
            .filter(|s| !s.is_empty())
            .nth(n)
    };
    let mut sid = None;
    let mut seq = None;
    if settings.session_placement == Placement::Path {
        sid = segment(0);
    }
    if settings.seq_placement == Placement::Path {
        seq = segment(usize::from(settings.session_placement == Placement::Path));
    }
    if settings.session_placement == Placement::Query {
        sid = query_param(target, &settings.session_key);
    }
    if settings.session_placement == Placement::Header {
        sid = crate::proxy::header_value_in(text, &settings.session_key);
    }
    if settings.session_placement == Placement::Cookie {
        sid = header_cookie(text, &settings.session_key);
    }
    if settings.seq_placement == Placement::Query {
        seq = query_param(target, &settings.seq_key);
    }
    if settings.seq_placement == Placement::Header {
        seq = crate::proxy::header_value_in(text, &settings.seq_key);
    }
    if settings.seq_placement == Placement::Cookie {
        seq = header_cookie(text, &settings.seq_key);
    }
    (sid, seq)
}

struct Session {
    state: Mutex<SessionState>,
    cv: Condvar,
    id: String,
}

struct DeferredResponse {
    at: std::time::Instant,
    write: Box<dyn FnOnce() + Send>,
}

#[allow(clippy::struct_excessive_bools)]
struct SessionState {
    upload: Option<Box<dyn crate::proxy::WindowRead + Send>>,
    upload_attached: bool,
    upload_done: bool,
    upload_fd: Option<crate::proxy::WaitFd>,
    packets: BTreeMap<u64, Vec<u8>>,
    next_seq: u64,
    ended: bool,
    downlink: bool,
    last_seen: std::time::Instant,
    /// The 200 a plain H1 POST owed, written by whichever half ends the session.
    response: Option<DeferredResponse>,
}

type Sessions = Mutex<HashMap<String, Arc<Session>>>;

fn sessions() -> &'static Sessions {
    static CELL: LazyLock<Sessions> = LazyLock::new(|| Mutex::new(HashMap::new()));
    &CELL
}

struct Expiry {
    generation: Mutex<u64>,
    cv: Condvar,
}

fn expiry() -> &'static Expiry {
    static CELL: LazyLock<Expiry> = LazyLock::new(|| Expiry {
        generation: Mutex::new(0),
        cv: Condvar::new(),
    });
    &CELL
}

fn ensure_expiry_worker() {
    static CELL: OnceLock<()> = OnceLock::new();
    CELL.get_or_init(|| crate::proxy::spawn_carried(expiry_loop));
}

fn wake_expiry() {
    let mut generation = expiry().generation.lock().expect("expiry lock");
    *generation = generation.wrapping_add(1);
    expiry().cv.notify_one();
}

fn expiry_loop() {
    let mut seen = 0u64;
    loop {
        let (expired, next) = sweep_expiring();
        for session in expired {
            close_session(&session);
        }
        let mut generation = expiry().generation.lock().expect("expiry lock");
        if *generation != seen {
            seen = *generation;
            drop(generation);
            continue;
        }
        generation = match next {
            Some(deadline) => {
                expiry()
                    .cv
                    .wait_timeout(
                        generation,
                        deadline.saturating_duration_since(std::time::Instant::now()),
                    )
                    .expect("expiry lock")
                    .0
            }
            None => expiry().cv.wait(generation).expect("expiry lock"),
        };
        seen = *generation;
    }
}

fn sweep_expiring() -> (Vec<Arc<Session>>, Option<std::time::Instant>) {
    let now = std::time::Instant::now();
    let mut map = sessions().lock().expect("sessions lock");
    let mut due = Vec::new();
    let mut next = None;
    let mut remove = Vec::new();
    for (id, session) in map.iter() {
        let state = session.state.lock().expect("session lock");
        if state.ended || state.downlink {
            continue;
        }
        let Some(response) = state.response.as_ref() else {
            continue;
        };
        if response.at <= now {
            remove.push(id.clone());
        } else {
            next = Some(next.map_or(response.at, |next: std::time::Instant| {
                next.min(response.at)
            }));
        }
    }
    for id in remove {
        if let Some(session) = map.remove(&id) {
            due.push(session);
        }
    }
    (due, next)
}

/// A session with no downlink that has been silent past the relay stall.
fn is_stalled(session: &Session, budget: std::time::Duration) -> bool {
    let state = session.state.lock().expect("session lock");
    !state.downlink && state.last_seen.elapsed() >= budget
}

#[cfg(test)]
thread_local! {
    static SWEEPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

static LAST_SWEEP: Mutex<Option<std::time::Instant>> = Mutex::new(None);

/// A live lookup only sweeps once the table has gone a stall budget without one.
fn sweep_due(budget: std::time::Duration) -> bool {
    let mut last = LAST_SWEEP.lock().expect("sweep lock");
    let now = std::time::Instant::now();
    if last.is_some_and(|last| now.duration_since(last) < budget) {
        return false;
    }
    *last = Some(now);
    true
}

fn sweep_stalled_sessions(
    map: &mut HashMap<String, Arc<Session>>,
    budget: std::time::Duration,
) -> Vec<Arc<Session>> {
    #[cfg(test)]
    SWEEPS.with(|sweeps| sweeps.set(sweeps.get() + 1));
    let stale: Vec<String> = map
        .iter()
        .filter(|(_, session)| is_stalled(session, budget))
        .map(|(id, _)| id.clone())
        .collect();
    stale.into_iter().filter_map(|id| map.remove(&id)).collect()
}

fn get_or_create_session(id: &str) -> Arc<Session> {
    let mut map = sessions().lock().expect("sessions lock");
    let budget = crate::budgets::relay_stall();
    let due = sweep_due(budget);
    let mut stalled = Vec::new();
    match map
        .get(id)
        .map(|session| (Arc::clone(session), is_stalled(session, budget)))
    {
        Some((session, false)) => {
            if due {
                stalled.extend(sweep_stalled_sessions(&mut map, budget));
            }
            drop(map);
            // The owed answers run after the map lock, so a peer that stops reading cannot block a session lookup.
            for session in stalled {
                close_session(&session);
            }
            return session;
        }
        Some((_, true)) => {
            if let Some(session) = map.remove(id) {
                stalled.push(session);
            }
        }
        None => {}
    }
    if due {
        stalled.extend(sweep_stalled_sessions(&mut map, budget));
    }
    let session = map
        .entry(id.to_owned())
        .or_insert_with(|| {
            Arc::new(Session {
                state: Mutex::new(SessionState {
                    upload: None,
                    upload_attached: false,
                    upload_done: false,
                    upload_fd: None,
                    packets: BTreeMap::new(),
                    next_seq: 0,
                    ended: false,
                    downlink: false,
                    last_seen: std::time::Instant::now(),
                    response: None,
                }),
                cv: Condvar::new(),
                id: id.to_owned(),
            })
        })
        .clone();
    drop(map);
    // The owed answers run after the map lock, so a peer that stops reading cannot block a session lookup.
    for session in stalled {
        close_session(&session);
    }
    session
}

fn close_session(s: &Arc<Session>) {
    let response = {
        let mut st = s.state.lock().expect("session lock");
        st.ended = true;
        s.cv.notify_all();
        st.response.take()
    };
    if let Some(response) = response {
        (response.write)();
    }
}

fn remove_session_if_owned(id: &str, session: &Session) {
    let mut map = sessions().lock().expect("sessions lock");
    if map
        .get(id)
        .is_some_and(|carried| std::ptr::eq(Arc::as_ptr(carried), session))
    {
        map.remove(id);
    }
}

// Drop is the only other way a session ends, and a waiter parked before a reader exists has no Drop to run.
pub(crate) fn end_session(id: &str) {
    let carried = sessions().lock().expect("sessions lock").remove(id);
    if let Some(carried) = carried {
        close_session(&carried);
    }
}

#[cfg(test)]
pub(crate) fn start_session_for_probe(id: &str) {
    let _ = get_or_create_session(id);
}

#[cfg(test)]
pub(crate) fn session_is_carried(id: &str) -> bool {
    sessions().lock().expect("sessions lock").contains_key(id)
}

/// An h2 connection owns the sessions its streams opened, so its death can end them; a bare H1 request has no carrier to bind to.
fn bound_session(sid: &str, stream: Option<&StreamOut>, downlink: bool) -> Arc<Session> {
    let session = get_or_create_session(sid);
    if downlink {
        let mut st = session.state.lock().expect("session lock");
        st.downlink = true;
        session.cv.notify_all();
    }
    if let Some(stream) = stream {
        if downlink {
            stream.bind_session(sid);
        } else {
            stream.bind_upload(sid);
        }
    }
    session
}

impl Session {
    /// Test seam: attaches a copied reader through the windowed upload slot.
    #[cfg(test)]
    fn set_upload(&self, reader: Box<dyn Read + Send>, fd: Option<crate::proxy::WaitFd>) -> bool {
        self.set_upload_window(Box::new(crate::proxy::Copied::new(reader)), fd)
    }

    /// One stream-up body per session, the reference's `uploadQueue.Push`: a second reader is
    /// refused so the caller can answer 409 before its bytes are promised.
    fn set_upload_window(
        &self,
        reader: Box<dyn crate::proxy::WindowRead + Send>,
        fd: Option<crate::proxy::WaitFd>,
    ) -> bool {
        let mut st = self.state.lock().expect("session lock");
        if st.upload_attached || st.ended {
            return false;
        }
        st.upload_attached = true;
        st.upload = Some(reader);
        st.upload_fd = fd;
        st.last_seen = std::time::Instant::now();
        self.cv.notify_all();
        true
    }
    fn push_packet(&self, seq: u64, payload: Vec<u8>, cap: usize) -> bool {
        let mut st = self.state.lock().expect("session lock");
        if st.packets.len() >= cap {
            return false;
        }
        st.packets.insert(seq, payload);
        st.last_seen = std::time::Instant::now();
        self.cv.notify_all();
        true
    }
    /// The 200 an H1 POST owes: written by whichever half ends the session, so the POST keeps no thread.
    fn defer_response(&self, response: Box<dyn FnOnce() + Send>) {
        let at = std::time::Instant::now()
            .checked_add(crate::budgets::relay_stall())
            .unwrap_or_else(std::time::Instant::now);
        self.defer_response_at(at, response);
    }
    fn defer_response_at(&self, at: std::time::Instant, response: Box<dyn FnOnce() + Send>) {
        let mut response = Some(DeferredResponse {
            at,
            write: response,
        });
        let stored = {
            let mut st = self.state.lock().expect("session lock");
            if st.ended {
                false
            } else {
                st.response = response.take();
                true
            }
        };
        if stored {
            ensure_expiry_worker();
            wake_expiry();
        } else if let Some(response) = response {
            (response.write)();
        }
    }
    fn wait_ended(&self) {
        self.wait_ended_for(crate::budgets::relay_stall());
    }
    fn wait_ended_for(&self, idle: std::time::Duration) {
        let started = std::time::Instant::now();
        let mut expired = false;
        let mut st = self.state.lock().expect("session lock");
        while !st.ended {
            if st.downlink {
                st = self.cv.wait(st).expect("session lock");
                continue;
            }
            let remaining = idle.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                st.ended = true;
                expired = true;
                self.cv.notify_all();
                break;
            }
            let (next, wait) = self.cv.wait_timeout(st, remaining).expect("session lock");
            st = next;
            if wait.timed_out() && !st.ended && !st.downlink && started.elapsed() >= idle {
                st.ended = true;
                expired = true;
                self.cv.notify_all();
                break;
            }
        }
        let response = st.response.take().map(|response| response.write);
        drop(st);
        if expired {
            remove_session_if_owned(&self.id, self);
        }
        if let Some(response) = response {
            response();
        }
    }
}

struct SessionReader {
    session: Arc<Session>,
    id: String,
    cur: Vec<u8>,
    cur_at: usize,
    upload: Option<Box<dyn crate::proxy::WindowRead + Send>>,
    upload_fd: Option<crate::proxy::WaitFd>,
}

impl SessionReader {
    fn new(session: Arc<Session>, id: String) -> Self {
        Self {
            session,
            id,
            cur: Vec::new(),
            cur_at: 0,
            upload: None,
            upload_fd: None,
        }
    }

    fn touch(&self) {
        self.session.state.lock().expect("session lock").last_seen = std::time::Instant::now();
    }

    /// Moves the session's upload into this reader once, refusing a second or finished one.
    fn take_upload(&mut self) -> bool {
        let mut st = self.session.state.lock().expect("session lock");
        if st.ended || st.upload_done {
            self.upload = None;
            return false;
        }
        if self.upload.is_none() {
            self.upload = st.upload.take();
            if self.upload.is_some() {
                self.upload_fd = st.upload_fd;
            }
        }
        self.upload.is_some()
    }

    /// The upload reached its own end, so the reader reports EOF but the session keeps the downlink
    /// it is still relaying: a hard read error still ends the whole session instead.
    fn finish_upload(&mut self) {
        note_upload_done(&self.session);
        self.upload = None;
    }

    fn upload_error(&mut self, error: std::io::Error) -> std::io::Error {
        map_upload_error(&self.session, self.upload_fd, error)
    }
}

/// A timeout on the upload's own socket is the lane's poll, not the session's end: the lane parks
/// on that descriptor and the client's next byte wakes it, so an idle upload holds no relay worker.
fn map_upload_error(
    session: &Session,
    fd: Option<crate::proxy::WaitFd>,
    error: std::io::Error,
) -> std::io::Error {
    let mapped = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<ferrox_core::tls::TlsError>())
        .is_some_and(|mapped| matches!(mapped, ferrox_core::tls::TlsError::Timeout));
    let pending = cfg!(windows) && error.raw_os_error() == Some(997);
    if ferrox_core::tls::TlsError::is_timeout(&error) {
        if let Some(fd) = fd {
            crate::proxy::note_wait_fd(fd);
            return std::io::Error::from(std::io::ErrorKind::WouldBlock);
        }
        if mapped || pending {
            return error;
        }
    }
    if poll_grain(&error) {
        return error;
    }
    session.state.lock().expect("session lock").ended = true;
    session.cv.notify_all();
    error
}

/// Records that the upload ended without ending the session's downlink.
fn note_upload_done(session: &Session) {
    session.state.lock().expect("session lock").upload_done = true;
    session.cv.notify_all();
}

/// A poll grain is the reader's own wake-up, not a socket deadline, so it ends no session.
fn poll_grain(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::WouldBlock && error.raw_os_error().is_none()
}

impl Read for SessionReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.cur_at < self.cur.len() {
                let avail = &self.cur[self.cur_at..];
                let n = avail.len().min(buf.len());
                buf[..n].copy_from_slice(&avail[..n]);
                self.cur_at += n;
                if self.cur_at == self.cur.len() {
                    self.cur.clear();
                    self.cur_at = 0;
                }
                self.touch();
                return Ok(n);
            }
            if self.take_upload() {
                let got = self.upload.as_mut().expect("upload").read(buf);
                return match got {
                    Ok(0) => {
                        self.finish_upload();
                        Ok(0)
                    }
                    Ok(n) => {
                        self.touch();
                        Ok(n)
                    }
                    Err(e) => Err(self.upload_error(e)),
                };
            }
            let mut st = self.session.state.lock().expect("session lock");
            if let Some(pkt) = {
                let seq = st.next_seq;
                st.packets.remove(&seq)
            } {
                st.next_seq += 1;
                st.last_seen = std::time::Instant::now();
                if pkt.len() <= buf.len() {
                    buf[..pkt.len()].copy_from_slice(&pkt);
                    return Ok(pkt.len());
                }
                self.cur = pkt;
                self.cur_at = buf.len();
                buf.copy_from_slice(&self.cur[..buf.len()]);
                return Ok(buf.len());
            }
            if st.ended || st.upload_done {
                eprintln!("t-trace: reader-end {} {}", self.session.id, st.ended);
                return Ok(0);
            }
            if !st.upload_attached && st.last_seen.elapsed() >= crate::budgets::relay_stall() {
                st.ended = true;
                self.session.cv.notify_all();
                return Ok(0);
            }
            let (guard, wait) = self
                .session
                .cv
                .wait_timeout(st, crate::budgets::RELAY_POLL)
                .expect("session lock");
            st = guard;
            if wait.timed_out() {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
        }
    }
}

impl crate::proxy::WindowRead for SessionReader {
    /// Returns the next packet or upload frame as a window, copying only packet storage.
    fn read_window(&mut self) -> std::io::Result<crate::proxy::Window<'_>> {
        loop {
            if self.cur_at < self.cur.len() {
                let start = self.cur_at;
                self.cur_at = self.cur.len();
                self.touch();
                return Ok(crate::proxy::Window::one(&self.cur[start..]));
            }
            if self.take_upload() {
                let session = Arc::clone(&self.session);
                let upload_fd = self.upload_fd;
                let window = {
                    let upload = self.upload.as_mut().expect("upload");
                    upload.read_window()
                };
                match window {
                    Ok(window) if window.is_empty() => {
                        note_upload_done(&session);
                        return Ok(crate::proxy::Window::empty());
                    }
                    Ok(window) => {
                        session.state.lock().expect("session lock").last_seen =
                            std::time::Instant::now();
                        return Ok(window);
                    }
                    Err(error) => return Err(map_upload_error(&session, upload_fd, error)),
                }
            }
            let mut st = self.session.state.lock().expect("session lock");
            if let Some(pkt) = {
                let seq = st.next_seq;
                st.packets.remove(&seq)
            } {
                st.next_seq += 1;
                st.last_seen = std::time::Instant::now();
                drop(st);
                self.cur = pkt;
                self.cur_at = self.cur.len();
                return Ok(crate::proxy::Window::one(&self.cur));
            }
            if st.ended || st.upload_done {
                return Ok(crate::proxy::Window::empty());
            }
            if !st.upload_attached && st.last_seen.elapsed() >= crate::budgets::relay_stall() {
                st.ended = true;
                self.session.cv.notify_all();
                return Ok(crate::proxy::Window::empty());
            }
            let (guard, wait) = self
                .session
                .cv
                .wait_timeout(st, crate::budgets::RELAY_POLL)
                .expect("session lock");
            st = guard;
            if wait.timed_out() {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
        }
    }

    fn parks_on_timeout(&self) -> bool {
        true
    }
}

impl Drop for SessionReader {
    fn drop(&mut self) {
        if !self.id.is_empty() {
            remove_session_if_owned(&self.id, self.session.as_ref());
        }
        close_session(&self.session);
    }
}

/// The answer head, opened once for the bytes it holds: the padding can be a kilobyte, so growing
/// a seventeen-byte buffer into it cost a reallocation per doubling and a `String` for the
/// downlink header that only ever got copied in.
fn padded_response(stream: &mut impl Write, settings: &XhttpSettings, padded: &str, framing: &str) {
    const OK: &str = "HTTP/1.1 200 OK\r\n";
    const CRLF: &str = "\r\n";
    const ACCEL: &str = "X-Accel-Buffering: no\r\n";
    const CACHE: &str = "Cache-Control: no-store\r\n";
    const SSE: &str = "Content-Type: text/event-stream\r\n";
    const PAD: &str = "X-Padding: ";
    let downlink = if settings.no_sse { "" } else { SSE };
    let padding_line = if settings.x_padding_obfs {
        match settings.x_padding_placement {
            Placement::Header => {
                settings.x_padding_header.len() + ": ".len() + padded.len() + CRLF.len()
            }
            Placement::Cookie => {
                "Set-Cookie: ".len()
                    + settings.x_padding_key.len()
                    + "=".len()
                    + padded.len()
                    + "; Path=/\r\n".len()
            }
            _ => PAD.len() + padded.len() + CRLF.len(),
        }
    } else {
        PAD.len() + padded.len() + CRLF.len()
    };
    let mut head = String::with_capacity(
        OK.len() + padding_line + ACCEL.len() + CACHE.len() + downlink.len() + framing.len(),
    );
    head.push_str(OK);
    if settings.x_padding_obfs {
        match settings.x_padding_placement {
            Placement::Header => {
                head.push_str(&settings.x_padding_header);
                head.push_str(": ");
                head.push_str(padded);
                head.push_str(CRLF);
            }
            Placement::Cookie => {
                head.push_str("Set-Cookie: ");
                head.push_str(&settings.x_padding_key);
                head.push('=');
                head.push_str(padded);
                head.push_str("; Path=/\r\n");
            }
            _ => {
                head.push_str(PAD);
                head.push_str(padded);
                head.push_str(CRLF);
            }
        }
    } else {
        head.push_str(PAD);
        head.push_str(padded);
        head.push_str(CRLF);
    }
    head.push_str(ACCEL);
    head.push_str(CACHE);
    head.push_str(downlink);
    head.push_str(framing);
    let _ = stream.write_all(head.as_bytes());
}

fn sse_ok(stream: &mut impl Write, settings: &XhttpSettings, padded: &str) {
    padded_response(
        stream,
        settings,
        padded,
        "Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n",
    );
}

fn plain_ok(stream: &mut impl Write, settings: &XhttpSettings, padded: &str) {
    padded_response(
        stream,
        settings,
        padded,
        "Content-Length: 0\r\nConnection: keep-alive\r\n\r\n",
    );
}

/// Whether the head's status line is the `200 OK` this carrier writes and expects.
fn ok_status_text(text: &str) -> bool {
    text.lines()
        .next()
        .is_some_and(|l| l.starts_with("HTTP/1.1 200 OK"))
}

fn check_response(head: &[u8]) -> Option<()> {
    let text = std::str::from_utf8(head).ok()?;
    if !ok_status_text(text) {
        return None;
    }
    if !crate::proxy::header_value_in(text, "transfer-encoding").is_some_and(has_chunked) {
        return None;
    }
    Some(())
}

fn emit_404(stream: &mut impl Write) {
    let _ = stream
        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
}
fn emit_400(stream: &mut impl Write) {
    let _ = stream
        .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
}
fn emit_405(stream: &mut impl Write) {
    let _ = stream.write_all(
        b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
}
fn emit_409(stream: &mut impl Write) {
    let _ = stream
        .write_all(b"HTTP/1.1 409 Conflict\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
}
fn emit_413(stream: &mut impl Write) {
    let _ = stream.write_all(
        b"HTTP/1.1 413 Request Entity Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
}

fn emit_500(stream: &mut impl Write) {
    let _ = stream.write_all(
        b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
}

fn content_length(text: &str) -> Option<usize> {
    crate::proxy::header_value_in(text, "content-length").and_then(|v| v.trim().parse().ok())
}

// --- Server ------------------------------------------------------------------

#[cfg(test)]
pub(crate) fn accept(stream: Connection, path: &str) -> Option<(XhttpReader, XhttpWriter)> {
    let mut read = stream;
    let (head, at) = read_head(&mut read)?;
    check_request(&head[..at], path)?;
    read.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\n\r\n").ok()?;
    split(read, head, at)
}

#[cfg(test)]
fn check_request(head: &[u8], path: &str) -> Option<()> {
    let text = std::str::from_utf8(head).ok()?;
    let mut parts = text.split("\r\n").next()?.split_ascii_whitespace();
    if parts.next()? != "POST" {
        return None;
    }
    let target = parts.next()?;
    if !path_covers(path, bare_path(target)) {
        return None;
    }
    if !crate::proxy::header_value_in(text, "transfer-encoding").is_some_and(has_chunked) {
        return None;
    }
    Some(())
}

// The same accept over halves that cannot peek: pipelined bytes arrive as a prefix. One connection serves requests until a session takes it or a request ends it, so a packet-up uplink does not pay a new connection per POST.
pub(crate) fn accept_split_with_settings<
    R: Read + Send + 'static + crate::proxy::RelayPoll,
    W: crate::proxy::FrameWrite + Send + 'static,
>(
    read: R,
    write: W,
    settings: &XhttpSettings,
    fd: Option<crate::proxy::WaitFd>,
) -> Option<(Box<dyn crate::proxy::WindowRead + Send>, XhttpWriter)> {
    let mut read = ChainReader::new(Vec::new(), read);
    let mut write = write;
    loop {
        // The head's own clock, because nothing arms the socket before the first read: a partial head that stops must end at its budget.
        crate::proxy::RelayPoll::arm_head_poll(&mut read);
        let (mut head, at) = match crate::proxy::read_exact_head(
            &mut read,
            HEAD_LIMIT,
            crate::budgets::head_arrival(),
        ) {
            Some(v) => v,
            None => {
                eprintln!("t-trace: head-fail");
                return None;
            }
        };
        // The loop hands `accept_core` a head it parses and a tail it keeps, so this is the one reader whose tail still needs its own owner.
        let prefix = head.split_off(at);
        // The session lands in a boxed window whose own arm is a no-op, so the socket gets its poll quantum here, once the head is in.
        crate::proxy::RelayPoll::arm_relay_poll(&mut read);
        match accept_core(&head, prefix, Upload::Read(read), write, settings, None, fd) {
            Served::Session(reader, writer) => return Some((reader, writer)),
            Served::Again(next, next_write, carry) => {
                read = next;
                write = next_write;
                read.set_carry(carry);
            }
            Served::Closed => {
                eprintln!("t-trace: closed");
                return None;
            }
        }
    }
}

fn writer_for<W: crate::proxy::FrameWrite + Send + 'static>(
    write: W,
    stream: Option<StreamOut>,
) -> XhttpWriter {
    let writer = XhttpWriter::new(write);
    if let Some(out) = stream {
        writer.set_stream(out);
    }
    writer
}

/// The bytes an accepted request reads next: an H2 stream can hand its frame window over without a copy, while an H1 socket is wrapped in the chunked reader the session already used.
pub(crate) enum Upload<R> {
    Read(R),
    Window(Box<dyn crate::proxy::WindowRead + Send>),
}

impl<R: Read + Send + 'static> Upload<R> {
    /// Borrows the body through the ordinary `Read` path.
    fn as_read(&mut self) -> &mut dyn Read {
        match self {
            Self::Read(read) => read,
            Self::Window(window) => window,
        }
    }

    /// The body as a windowed reader: an H1 source is framed, an H2 source is the frame it already owns.
    fn into_window(self, prefix: Vec<u8>) -> Box<dyn crate::proxy::WindowRead + Send> {
        match self {
            Self::Read(read) => Box::new(Reader {
                read,
                prefix,
                at: 0,
                left: 0,
                ended: false,
                reads: 0,
                pending_head: false,
                head_progress: None,
                chunk: Chunk::Body,
            }),
            Self::Window(window) => window,
        }
    }

    /// Returns the H1 reader, or `None` when the body is a window that cannot rewind to the socket.
    fn into_h1(self) -> Option<R> {
        match self {
            Self::Read(read) => Some(read),
            Self::Window(_) => None,
        }
    }
}

/// What one request leaves the connection to. `Session` hands both halves to a session that owns them for as long as the stream lives; `Again` gives them back, with the bytes that came with this request but belong to the next; `Closed` is the end of the connection.
pub(crate) enum Served<R, W> {
    Session(Box<dyn crate::proxy::WindowRead + Send>, XhttpWriter),
    Again(R, W, Vec<u8>),
    Closed,
}

/// Whether the client means to keep this connection: HTTP/1.1 keeps alive unless the request says otherwise, HTTP/1.0 only when it does.
fn keeps_alive(text: &str) -> bool {
    let mut lines = text.lines();
    let mut keep = !lines
        .next()
        .unwrap_or_default()
        .trim_end()
        .ends_with("HTTP/1.0");
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("connection") {
            continue;
        }
        keep = value
            .split(',')
            .any(|part| part.trim().eq_ignore_ascii_case("keep-alive"))
            && !value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("close"));
    }
    keep
}

/// A body's arrival window: an idle budget each byte moves out, inside a hard cap no byte moves, so a drip cannot hold an unauthenticated handler.
struct BodyArrival {
    budget: std::time::Duration,
    idle: std::time::Instant,
    hard: std::time::Instant,
}

impl BodyArrival {
    /// Open the window: the first read is due inside `budget`, the whole body inside a relay stall.
    fn new(budget: std::time::Duration) -> Self {
        let now = std::time::Instant::now();
        let arrival = Self {
            budget,
            idle: now + budget,
            hard: now + crate::budgets::relay_stall(),
        };
        arrival.publish();
        arrival
    }

    /// Hand the nearer of the two deadlines to the reads that enforce it.
    fn publish(&self) {
        crate::proxy::set_body_deadline(Some(self.idle.min(self.hard)));
    }

    /// A byte landed: move the idle deadline out, leaving the hard cap where it is.
    fn advanced(&mut self) {
        self.idle = std::time::Instant::now() + self.budget;
        self.publish();
    }

    /// Whether the body has outlived either deadline.
    fn passed(&self) -> bool {
        let now = std::time::Instant::now();
        now >= self.idle || now >= self.hard
    }
}

impl Drop for BodyArrival {
    fn drop(&mut self) {
        crate::proxy::set_body_deadline(None);
    }
}

/// The body of `n` bytes, and how much of the bytes already read as the head it used; the rest of those belong to the next request on this connection.
fn read_body<R: Read>(
    read: &mut R,
    prefix: &[u8],
    n: usize,
    budget: std::time::Duration,
) -> Option<(Vec<u8>, usize)> {
    let mut buf = crate::proxy::unfilled(n);
    let pre = prefix.len().min(n);
    buf[..pre].copy_from_slice(&prefix[..pre]);
    let mut at = pre;
    let mut arrival = BodyArrival::new(budget);
    while at < n {
        match read.read(&mut buf[at..]) {
            Err(error) if crate::proxy::is_timeout(&error) => {
                if arrival.passed() {
                    return None;
                }
            }
            Ok(0) | Err(_) => return None,
            Ok(r) => {
                at += r;
                if at < n {
                    arrival.advanced();
                    if arrival.passed() {
                        return None;
                    }
                }
            }
        }
    }
    Some((buf, pre))
}

/// The bytes behind the body — the next request's head — moved down inside the head's own buffer, so the reuse keeps that room instead of paying a second allocation and a copy into it.
fn carry_tail(mut prefix: Vec<u8>, pre: usize) -> Vec<u8> {
    prefix.copy_within(pre.., 0);
    prefix.truncate(prefix.len() - pre);
    prefix
}

/// How reading a body that ends only when its stream ends turned out.
enum Drained {
    Done(Vec<u8>),
    Over,
    Broken,
}

/// The body until the stream ends, with `Over` naming a payload past the per-request cap.
fn drain_body(read: &mut dyn Read, cap: usize, budget: std::time::Duration) -> Drained {
    let mut body = Vec::new();
    let mut buf = [0u8; 8192];
    let mut arrival = BodyArrival::new(budget);
    loop {
        match read.read(&mut buf) {
            Err(error) if crate::proxy::is_timeout(&error) => {
                if arrival.passed() {
                    return Drained::Broken;
                }
            }
            Ok(0) => return Drained::Done(body),
            Ok(n) => {
                body.extend_from_slice(&buf[..n]);
                if body.len() > cap {
                    return Drained::Over;
                }
                arrival.advanced();
                if arrival.passed() {
                    return Drained::Broken;
                }
            }
            Err(_) => return Drained::Broken,
        }
    }
}

/// Dispatches one parsed request to the session or connection shape it names.
#[allow(
    clippy::too_many_lines,
    reason = "one arm per method and session shape; the dispatch is the function"
)]
pub(crate) fn accept_core<
    R: Read + Send + 'static,
    W: crate::proxy::FrameWrite + Send + 'static,
>(
    head: &[u8],
    prefix: Vec<u8>,
    mut upload: Upload<R>,
    mut write: W,
    settings: &XhttpSettings,
    h2: Option<StreamOut>,
    fd: Option<crate::proxy::WaitFd>,
) -> Served<R, W> {
    let Ok(text) = std::str::from_utf8(head) else {
        return Served::Closed;
    };
    let Some(first) = text.lines().next() else {
        return Served::Closed;
    };
    let mut parts = first.split_ascii_whitespace();
    let Some(method) = parts.next() else {
        return Served::Closed;
    };
    let Some(target) = parts.next() else {
        return Served::Closed;
    };

    if !path_covers(settings.path.as_str(), bare_path(target)) {
        eprintln!("t-trace: 404 {first}");
        emit_404(&mut write);
        return Served::Closed;
    }

    let padded = pad_value(settings.x_padding_method, pad_target_len(settings));

    if method == "OPTIONS" {
        let alive = keeps_alive(text);
        let mut resp = String::from("HTTP/1.1 200 OK\r\n");
        if !settings.x_padding_obfs {
            let _ = write!(resp, "X-Padding: {padded}\r\n");
        }
        resp.push_str("Access-Control-Allow-Methods: *\r\nAccess-Control-Allow-Headers: *\r\nAccess-Control-Allow-Origin: *\r\n");
        resp.push_str("Content-Length: 0\r\nConnection: keep-alive\r\n\r\n");
        let _ = write.write_all(resp.as_bytes());
        if h2.is_none() && alive {
            if let Some(read) = upload.into_h1() {
                return Served::Again(read, write, prefix);
            }
        }
        return Served::Closed;
    }

    let pad_ok = match extract_padding(text, target, settings) {
        Some(v) => padding_valid(
            v,
            settings.x_padding_bytes.0,
            settings.x_padding_bytes.1,
            settings.x_padding_method,
        ),
        None => false,
    };
    if !pad_ok {
        eprintln!("t-trace: 400 pad {first}");
        emit_400(&mut write);
        return Served::Closed;
    }
    let (sid, seq) = extract_meta(text, target, settings);

    match (sid, seq) {
        (None, None) => {
            if settings.mode_source == ModeSource::Stated
                && !matches!(settings.mode, XhttpMode::StreamOne | XhttpMode::StreamUp)
            {
                emit_400(&mut write);
                return Served::Closed;
            }
            if method == "GET" {
                eprintln!("t-trace: none-none get");
                sse_ok(&mut write, settings, &padded);
                let writer = writer_for(write, h2);
                let session = get_or_create_session("__none__");
                session.state.lock().expect("session lock").ended = true;
                return Served::Session(
                    Box::new(SessionReader::new(session, String::new())),
                    writer,
                );
            }
            if method == settings.uplink_method.as_str() {
                if h2.is_none()
                    && !crate::proxy::header_value_in(text, "transfer-encoding")
                        .is_some_and(has_chunked)
                {
                    emit_400(&mut write);
                    return Served::Closed;
                }
                eprintln!("t-trace: none-none post {first}");
                sse_ok(&mut write, settings, &padded);
                let reader = upload.into_window(prefix);
                let writer = writer_for(write, h2);
                return Served::Session(reader, writer);
            }
            emit_405(&mut write);
            Served::Closed
        }
        (Some(sid), None) => {
            if method == "GET" {
                if settings.mode == XhttpMode::StreamOne
                    && settings.mode_source == ModeSource::Stated
                {
                    emit_400(&mut write);
                    return Served::Closed;
                }
                eprintln!("t-trace: sid get {sid} {first}");
                let session = bound_session(sid, h2.as_ref(), true);
                sse_ok(&mut write, settings, &padded);
                let writer = writer_for(write, h2);
                return Served::Session(
                    Box::new(SessionReader::new(session, sid.to_owned())),
                    writer,
                );
            }
            if settings.mode != XhttpMode::StreamUp && settings.mode_source == ModeSource::Stated {
                emit_400(&mut write);
                return Served::Closed;
            }
            if !crate::proxy::header_value_in(text, "transfer-encoding").is_some_and(has_chunked)
                && h2.is_none()
            {
                emit_400(&mut write);
                return Served::Closed;
            }
            let session = bound_session(sid, None, false);
            if !session.set_upload_window(upload.into_window(prefix), fd) {
                emit_409(&mut write);
                return Served::Closed;
            }
            if let Some(h2) = h2.as_ref() {
                h2.bind_upload(sid);
            }
            // Go writes the 200 only when the handler returns; a stream-up POST hands that answer to its session so no accepted thread waits out the download, and the other shapes keep the inline wait.
            if h2.is_none() && settings.mode == XhttpMode::StreamUp {
                let settings = settings.clone();
                session.defer_response(Box::new(move || plain_ok(&mut write, &settings, &padded)));
                return Served::Closed;
            }
            session.wait_ended();
            plain_ok(&mut write, settings, &padded);
            Served::Closed
        }
        (Some(sid), Some(seq)) => {
            if settings.mode != XhttpMode::PacketUp {
                emit_400(&mut write);
                return Served::Closed;
            }
            let Ok(seq_num) = seq.parse::<u64>() else {
                emit_500(&mut write);
                return Served::Closed;
            };
            let session = bound_session(sid, h2.as_ref(), false);
            // The body arrives whatever the placement carries the packet in: an unread one would leave the next request's head sitting in its bytes.
            let mut body = Vec::new();
            let mut carry = Vec::new();
            let mut resumable = true;
            if let Some(n) = content_length(text) {
                if n > settings.sc_max_each_post {
                    emit_413(&mut write);
                    return Served::Closed;
                }
                let Some((buf, pre)) = read_body(
                    &mut upload.as_read(),
                    &prefix,
                    n,
                    crate::budgets::head_arrival(),
                ) else {
                    return Served::Closed;
                };
                carry = carry_tail(prefix, pre);
                body = buf;
            } else if crate::proxy::header_value_in(text, "transfer-encoding")
                .is_some_and(has_chunked)
            {
                // A chunked body leaves no length behind that the next request's head could be found after.
                resumable = false;
                let mut chain = ChainReader::new(prefix, upload.as_read());
                let drained = if h2.is_some() {
                    drain_body(
                        &mut chain,
                        settings.sc_max_each_post,
                        crate::budgets::head_arrival(),
                    )
                } else {
                    let mut framed = Reader {
                        read: &mut chain,
                        prefix: Vec::new(),
                        at: 0,
                        left: 0,
                        ended: false,
                        reads: 0,
                        pending_head: false,
                        head_progress: None,
                        chunk: Chunk::Body,
                    };
                    drain_body(
                        &mut framed,
                        settings.sc_max_each_post,
                        crate::budgets::head_arrival(),
                    )
                };
                match drained {
                    Drained::Done(buf) => body = buf,
                    Drained::Over => {
                        emit_413(&mut write);
                        return Served::Closed;
                    }
                    Drained::Broken => return Served::Closed,
                }
            } else {
                carry = prefix;
            }
            let payload = match settings.uplink_data_placement {
                Placement::Header | Placement::Cookie => data_parts(text, settings),
                _ => Some(body),
            };
            let Some(payload) = payload else {
                crate::proxy::echo_trace("serve packet undecodable");
                emit_400(&mut write);
                return Served::Closed;
            };
            if payload.len() > settings.sc_max_each_post {
                emit_413(&mut write);
                return Served::Closed;
            }
            if !session.push_packet(seq_num, payload, settings.sc_max_buffered) {
                // A refused packet is a lost one — the reader waits on strict sequence — so the session is over; keeping it alive would park its reader on a sequence that can never arrive.
                end_session(sid);
                emit_500(&mut write);
                return Served::Closed;
            }
            plain_ok(&mut write, settings, &padded);
            if resumable && h2.is_none() && keeps_alive(text) {
                if let Some(read) = upload.into_h1() {
                    return Served::Again(read, write, carry);
                }
            }
            Served::Closed
        }
        (None, Some(_)) => {
            emit_405(&mut write);
            Served::Closed
        }
    }
}

thread_local! {
    /// The dial's head, staged once per dialling thread and refilled in place by every later dial on it.
    static DIAL_HEAD: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

// The stream-one dial: one POST, chunked framing both ways, staged in the thread's own room.
fn send_dial_head<W: crate::proxy::FrameWrite>(
    write: &mut W,
    host: &str,
    target: &str,
    headers: &[(String, String)],
    pad: &str,
) -> Option<()> {
    const BEFORE_PATH: &str = "POST ";
    const BEFORE_HOST: &str = " HTTP/1.1\r\nHost: ";
    const BEFORE_REFERER: &str = "\r\nReferer: http://";
    const BEFORE_PADDING: &str = "?x_padding=";
    // The reference dialer disables keep-alives (dialer.go:272), and a chunked request whose first chunk waits on the 200 hangs a peer that drains the body before it flushes.
    const TAIL: &str = "Transfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n";
    // The default padding's longest shape stays in the room, so a configured pad only grows it when it exceeds the default's ceiling.
    const PADDING_ROOM: usize = 1000;
    let referer = target.split_once('?').map_or(target, |(path, _)| path);
    let room = pad.len().max(PADDING_ROOM);
    let headers_len = crate::headers::masked_len(headers, crate::headers::FETCH);
    DIAL_HEAD.with(|cell| {
        let mut head = cell.borrow_mut();
        head.clear();
        // The room is the head's longest shape, so the allocator is entered once and a default padding never grows it.
        head.reserve(
            BEFORE_PATH.len()
                + target.len()
                + BEFORE_HOST.len()
                + host.len()
                + BEFORE_REFERER.len()
                + host.len()
                + referer.len()
                + BEFORE_PADDING.len()
                + room
                + 2
                + headers_len
                + TAIL.len(),
        );
        head.extend_from_slice(BEFORE_PATH.as_bytes());
        head.extend_from_slice(target.as_bytes());
        head.extend_from_slice(BEFORE_HOST.as_bytes());
        head.extend_from_slice(host.as_bytes());
        head.extend_from_slice(BEFORE_REFERER.as_bytes());
        head.extend_from_slice(host.as_bytes());
        head.extend_from_slice(referer.as_bytes());
        head.extend_from_slice(BEFORE_PADDING.as_bytes());
        head.extend_from_slice(pad.as_bytes());
        head.extend_from_slice(b"\r\n");
        crate::headers::write_masked(&mut head, headers, crate::headers::FETCH);
        head.extend_from_slice(TAIL.as_bytes());
        write.write_all(&head).ok()
    })
}

/// The regular fields a stream-one dial sends, in the H1 head's order: the configured set, the
/// padded referer, and the body's type. H2 encodes the same fields as HEADERS.
pub(crate) fn dial_fields(host: &str, settings: &XhttpSettings) -> Vec<(String, String)> {
    let mut fields = Vec::new();
    for line in crate::headers::masked(&settings.headers, crate::headers::FETCH).split("\r\n") {
        if let Some((name, value)) = line.split_once(": ") {
            fields.push((name.to_owned(), value.to_owned()));
        }
    }
    fields.push((
        "referer".to_owned(),
        format!(
            "http://{host}{}?x_padding={}",
            normalized_path(settings),
            referer_pad_value(settings)
        ),
    ));
    fields.push((
        "content-type".to_owned(),
        "application/octet-stream".to_owned(),
    ));
    fields
}

// The reference's `appendToPath` (config.go:529): a segment lands under the trailing slash, never beside it.
fn append_segment(path: &mut String, value: &str) {
    if !path.ends_with('/') {
        path.push('/');
    }
    path.push_str(value);
}

fn push_param(query: &mut String, key: &str, value: &str) {
    if !query.is_empty() {
        query.push('&');
    }
    query.push_str(key);
    query.push('=');
    query.push_str(value);
}

/// The reference's `ApplyMetaToRequest` (config.go:264): a session and seq ride the path unless the config names another placement.
fn meta_request(
    settings: &XhttpSettings,
    session: &str,
    seq: Option<u64>,
    target: &mut String,
    query: &mut String,
    extra: &mut String,
) {
    if !session.is_empty() {
        match settings.session_placement {
            Placement::Path => append_segment(target, session),
            Placement::Query => push_param(query, &settings.session_key, session),
            Placement::Header => {
                let _ = write!(extra, "{}: {session}\r\n", settings.session_key);
            }
            Placement::Cookie => {
                let _ = write!(extra, "Cookie: {}={session}\r\n", settings.session_key);
            }
            Placement::Auto | Placement::Body | Placement::QueryInHeader => {}
        }
    }
    if let Some(seq) = seq {
        let seq = seq.to_string();
        match settings.seq_placement {
            Placement::Path => append_segment(target, &seq),
            Placement::Query => push_param(query, &settings.seq_key, &seq),
            Placement::Header => {
                let _ = write!(extra, "{}: {seq}\r\n", settings.seq_key);
            }
            Placement::Cookie => {
                let _ = write!(extra, "Cookie: {}={seq}\r\n", settings.seq_key);
            }
            Placement::Auto | Placement::Body | Placement::QueryInHeader => {}
        }
    }
}

fn target_of(path: &str, query: &str) -> String {
    if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    }
}

/// The same target from a path the caller already owns, so a per-packet head does not copy it twice.
fn combine_target(mut path: String, query: &str) -> String {
    if !query.is_empty() {
        path.push('?');
        path.push_str(query);
    }
    path
}

/// The reference's `GetNormalizedPath` (config.go:20): a path segment needs its trailing slash when the session or seq rides it.
fn normalized_path(settings: &XhttpSettings) -> String {
    let mut path = settings.path.clone();
    if (settings.session_placement == Placement::Path || settings.seq_placement == Placement::Path)
        && !path.ends_with('/')
    {
        path.push('/');
    }
    path
}

/// The request target a dial writes: the normalized path and the query that rode in with it (`config.go:20`).
pub(crate) fn dial_path(settings: &XhttpSettings) -> String {
    target_of(&normalized_path(settings), &settings.query)
}

/// The packet-up and stream-up dial's POST: one POST, chunked framing, the session under the head's own placement. `Connection: close` is the reference dialer's `DisableKeepAlives` (dialer.go:272).
pub(crate) fn dial_head(
    host: &str,
    settings: &XhttpSettings,
    session: &str,
    seq: Option<u64>,
) -> String {
    let mut target = normalized_path(settings);
    let mut query = settings.query.clone();
    let mut extra = String::new();
    meta_request(settings, session, seq, &mut target, &mut query, &mut extra);
    let target = target_of(&target, &query);
    let content_type = if settings.no_grpc_header {
        "application/octet-stream"
    } else {
        "application/grpc"
    };
    let headers = crate::headers::masked(&settings.headers, crate::headers::FETCH);
    format!("{} {target} HTTP/1.1\r\nHost: {host}\r\n{headers}{extra}Referer: http://{host}{}?x_padding={}\r\nTransfer-Encoding: chunked\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n", settings.uplink_method, normalized_path(settings), referer_pad_value(settings))
}

/// The downlink a packet-up or stream-up dial opens beside its upload (dialer.go:411).
pub(crate) fn downlink_head(host: &str, settings: &XhttpSettings, session: &str) -> String {
    let mut target = normalized_path(settings);
    let mut query = settings.query.clone();
    let mut extra = String::new();
    meta_request(settings, session, None, &mut target, &mut query, &mut extra);
    let target = target_of(&target, &query);
    let headers = crate::headers::masked(&settings.headers, crate::headers::FETCH);
    format!("GET {target} HTTP/1.1\r\nHost: {host}\r\n{headers}{extra}Referer: http://{host}{}?x_padding={}\r\nConnection: close\r\n\r\n", normalized_path(settings), referer_pad_value(settings))
}

/// The referer's pad the dial-side heads draw: a run in the configured range and method, the shape the hub's own check validates (`xpadding.go`'s `MakeXPadding`).
pub(crate) fn referer_pad_value(settings: &XhttpSettings) -> String {
    pad_value(settings.x_padding_method, pad_target_len(settings))
}

/// One packet-up POST. The packet rides the body by default, or `X-Data-{i}` headers / `x_data_{i}` cookies when `uplinkDataPlacement` says so: the reference encodes the whole packet as base64url and splits that one string at `uplinkChunkSize` points (`config.go:65-97`), so the hub joins the parts before it decodes.
pub(crate) fn packet_head<'a>(
    host: &str,
    settings: &XhttpSettings,
    session: &str,
    seq: u64,
    piece: &'a [u8],
) -> (String, Option<&'a [u8]>) {
    let mut target = normalized_path(settings);
    let mut query = settings.query.clone();
    let mut extra = String::new();
    meta_request(
        settings,
        session,
        Some(seq),
        &mut target,
        &mut query,
        &mut extra,
    );
    let target = combine_target(target, &query);
    let method = settings.uplink_method.as_str();
    let pad = referer_pad_value(settings);
    match settings.uplink_data_placement {
        Placement::Header | Placement::Cookie => {
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(piece);
            let header = settings.uplink_data_placement == Placement::Header;
            let separator = if header { "-" } else { "_" };
            if header {
                let mut at = 0;
                for i in 0.. {
                    if at >= encoded.len() {
                        break;
                    }
                    let size = random_between(settings.uplink_chunk.0, settings.uplink_chunk.1)
                        .min(encoded.len() - at);
                    let _ = write!(
                        extra,
                        "{}{separator}{i}: {}\r\n",
                        settings.uplink_data_key,
                        &encoded[at..at + size]
                    );
                    at += size;
                }
            } else {
                let _ = write!(extra, "Cookie: ");
                let mut at = 0;
                for i in 0.. {
                    if at >= encoded.len() {
                        break;
                    }
                    if i > 0 {
                        extra.push_str("; ");
                    }
                    let size = random_between(settings.uplink_chunk.0, settings.uplink_chunk.1)
                        .min(encoded.len() - at);
                    let _ = write!(
                        extra,
                        "{}{separator}{i}={}",
                        settings.uplink_data_key,
                        &encoded[at..at + size]
                    );
                    at += size;
                }
                extra.push_str("\r\n");
            }
            // Go writes `Content-Length: 0` for a bodyless POST, and no length at all for a bodyless GET (`shouldSendContentLength`).
            let zero = if matches!(method, "GET" | "HEAD") {
                ""
            } else {
                "Content-Length: 0\r\n"
            };
            let headers = crate::headers::masked(&settings.headers, crate::headers::FETCH);
            (
                format!(
                    "{method} {target} HTTP/1.1\r\nHost: {host}\r\n{headers}{extra}Referer: http://{host}{}?x_padding={pad}\r\n{zero}Connection: keep-alive\r\n\r\n",
                    settings.path
                ),
                None,
            )
        }
        _ => {
            let headers = crate::headers::masked(&settings.headers, crate::headers::FETCH);
            (
            format!(
                "{method} {target} HTTP/1.1\r\nHost: {host}\r\n{headers}{extra}Content-Length: {}\r\nReferer: http://{host}{}?x_padding={pad}\r\nConnection: keep-alive\r\n\r\n",
                piece.len(),
                settings.path
            ),
            Some(piece),
            )
        }
    }
}

fn pad_raw() -> [u8; 4] {
    let mut raw = [0u8; 4];
    getrandom::fill(&mut raw).unwrap_or_default();
    raw
}

/// The reference redraws the part size per part (`GetNormalizedUplinkChunkSize().rand()`).
fn random_between(from: usize, to: usize) -> usize {
    let raw = pad_raw();
    let span = to.saturating_sub(from);
    from + (u32::from_le_bytes(raw) as usize % span.max(1))
}

/// The reference mints a UUID when no length or table is written (`GenerateSessionID`, config.go:511).
fn uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).unwrap_or_default();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let mut out = String::with_capacity(36);
    for (i, byte) in bytes.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push(b"0123456789abcdef"[usize::from(byte >> 4)] as char);
        out.push(b"0123456789abcdef"[usize::from(byte & 0xf)] as char);
    }
    out
}

/// The packet-up and stream-up dial: a GET downlink beside the upload half, both under one session id (dialer.go:411).
pub(crate) fn connect_dual(
    down: Connection,
    up: Connection,
    host: &str,
    settings: &XhttpSettings,
) -> Option<(XhttpReader, XhttpWriter)> {
    let down_write = down.try_clone().ok()?;
    connect_dual_split(down, down_write, up, host, settings)
}

pub(crate) fn connect_dual_split<
    DR: Read,
    DW: Write,
    UW: crate::proxy::FrameWrite + Read + Send + 'static,
>(
    down: DR,
    mut down_write: DW,
    mut up: UW,
    host: &str,
    settings: &XhttpSettings,
) -> Option<(Reader<DR>, XhttpWriter)> {
    let session = settings.session_id();
    down_write
        .write_all(downlink_head(host, settings, &session).as_bytes())
        .ok()?;
    let writer = if settings.mode == XhttpMode::PacketUp {
        XhttpWriter::packets(up, host, settings, session)
    } else {
        up.write_all(dial_head(host, settings, &session, None).as_bytes())
            .ok()?;
        XhttpWriter::new(up)
    };
    let reader = Reader {
        read: down,
        prefix: Vec::new(),
        at: 0,
        left: 0,
        ended: false,
        reads: 0,
        pending_head: true,
        head_progress: None,
        chunk: Chunk::Body,
    };
    Some((reader, writer))
}

pub(crate) fn connect(
    stream: Connection,
    host: &str,
    path: &str,
    headers: &[(String, String)],
    pad: &str,
) -> Option<(XhttpReader, XhttpWriter)> {
    let mut read = stream;
    send_dial_head(&mut read, host, path, headers, pad)?;
    let (head, at) = read_head(&mut read)?;
    check_response(&head[..at])?;
    split(read, head, at)
}

// The same connect over halves that cannot peek: pipelined bytes arrive as a prefix.
pub(crate) fn connect_split<R: Read, W: crate::proxy::FrameWrite + 'static>(
    mut read: R,
    mut write: W,
    host: &str,
    path: &str,
    headers: &[(String, String)],
    pad: &str,
) -> Option<(Reader<R>, XhttpWriter)> {
    send_dial_head(&mut write, host, path, headers, pad)?;
    let (head, at) =
        crate::proxy::read_exact_head(&mut read, HEAD_LIMIT, crate::budgets::head_arrival())?;
    check_response(&head[..at])?;
    Some(split_halves(read, write, head, at))
}

impl crate::proxy::CarrierSink for XhttpWriter {
    #[inline]
    fn send(&self, bytes: &[u8]) -> bool {
        self.send(bytes)
    }
    #[inline]
    fn push(&self, bytes: &[u8]) -> crate::proxy::Push {
        if let Some(stream) = self.stream.get() {
            return if stream.data(bytes) {
                crate::proxy::Push::Took(bytes.len())
            } else {
                crate::proxy::Push::Lost
            };
        }
        match &self.shared.body {
            Body::Stream(_) => {
                if self.send(bytes) {
                    crate::proxy::Push::Took(bytes.len())
                } else {
                    crate::proxy::Push::Lost
                }
            }
            Body::Packets(packets) => packets.push(bytes),
        }
    }
    #[inline]
    fn close(&self) {
        self.finish();
    }
    #[inline]
    fn upload_done(&self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    /// The tokenish adjust as it was — the whole string re-summed on every one of the 150 steps — kept as the oracle the carried sum is compared against.
    fn tokenish_recompute(raw: &[u8], target: usize) -> String {
        const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        let mut s: String = raw
            .iter()
            .map(|&b| BASE62[(b as usize) % 62] as char)
            .collect();
        for iter in 0..150 {
            let cur = huffman_len(s.as_bytes());
            if cur.abs_diff(target) <= 2 {
                return s;
            }
            if cur < target {
                s.push(if iter % 2 == 0 { 'X' } else { 'Z' });
            } else if s.len() > 1 {
                s.pop();
            } else {
                return s;
            }
        }
        s
    }

    #[test]
    fn tokenish_carry_matches_the_recompute_on_every_probe() {
        let mut targets: Vec<usize> = (0..=64).collect();
        targets.extend([251, 997, 1500]);
        for target in targets {
            let n = ((target * 10).div_ceil(8)).max(1);
            let mut runs: Vec<Vec<u8>> = vec![vec![0u8; n], vec![255u8; n], vec![61u8; n]];
            let mut state = 0x2545_F491_4F6C_DD1Du64;
            let mut raw = Vec::with_capacity(n);
            for _ in 0..n {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                raw.push((state >> 33) as u8);
            }
            runs.push(raw);
            for raw in runs {
                assert_eq!(
                    tokenish_adjust(&raw, target),
                    tokenish_recompute(&raw, target),
                    "target {target} raw {raw:?}"
                );
            }
        }
    }

    /// The pad's buffer is opened once and drawn without a zero pass: `collect` reserved only the
    /// decoded length, so the first adjust push moved the whole pad, and the draw overwrites every
    /// byte of a buffer that was zeroed first.
    #[cfg_attr(miri, ignore = "uses the OS random source")]
    #[test]
    fn a_tokenish_pad_is_one_buffer_drawn_without_zeroing() {
        let raw = [0x5au8; 900];
        let (pad, counts) = ferrox_core::alloc_count::measure(|| tokenish_adjust(&raw, 700));
        assert_eq!(
            counts.allocs, 1,
            "the pad string and nothing else: {counts:?}"
        );
        assert_eq!(pad, tokenish_recompute(&raw, 700), "the same pad");
        let (drawn, counts) = ferrox_core::alloc_count::measure(|| generate_tokenish(700));
        assert_ne!(drawn, "");
        assert_eq!(counts.zeroed, 0, "the draw fills every byte: {counts:?}");
    }

    /// The same drain over a real socket asserts the *bytes* and nothing else: a socket may segment, so its read count moves with the scheduler and cannot gate a number — that claim belongs to `a_chunk_costs_two_reads_not_three`, on an in-memory stream that answers the whole buffer. The peer paces its sends 2048 bytes at a time, which segments the kernel's delivery the way load alone used to do at random.
    #[test]
    fn a_real_socket_drains_the_same_bytes() {
        let count = 16usize;
        let mut wire = Vec::new();
        for _ in 0..count {
            wire.extend_from_slice(format!("{CHUNK:X}\r\n").as_bytes());
            wire.extend(std::iter::repeat_n(0x5Au8, CHUNK));
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let h = thread::spawn(move || {
            const VANE: usize = 2048;
            let (mut sock, _) = listener.accept().expect("accepts");
            let mut head = [0u8; 4096];
            let n = sock.read(&mut head).expect("reads the request");
            assert!(n > 0);
            sock.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .expect("replies");
            for burst in wire.chunks(VANE) {
                sock.write_all(burst).expect("sends");
                thread::sleep(Duration::from_millis(2));
            }
            sock.shutdown(std::net::Shutdown::Write).ok();
        });
        let sock = Connection::connect(("127.0.0.1", port)).expect("connects");
        let pad = "X".repeat(500);
        let (mut reader, _w) = connect(sock, "h", "/share", &[], &pad).expect("dials");
        let mut buf = vec![0u8; CHUNK];
        let mut got = 0usize;
        loop {
            let n = reader.read(&mut buf).expect("reads");
            if n == 0 {
                break;
            }
            got += n;
        }
        h.join().expect("joins");
        assert_eq!(got, CHUNK * count, "the payload must be byte-identical");
    }

    #[test]
    fn size_lines_match_format_without_allocating() {
        for n in [
            1usize, 9, 10, 15, 16, 255, 256, 4096, 16384, 65535, 65536, CHUNK,
        ] {
            let mut line = [0u8; 7];
            let len = size_line(n, &mut line);
            assert_eq!(&line[..len], format!("{n:X}\r\n").as_bytes());
        }
    }

    /// The sink frames one relay window once: `one_window_is_one_chunked_frame` counts the `write_slices` calls and reassembles their bytes, because a socket sees the bytes and not how many calls carried them.
    #[test]
    fn one_window_is_one_chunked_frame() {
        #[derive(Default)]
        struct Frames {
            calls: usize,
            bytes: Vec<u8>,
        }
        struct Counting(Arc<Mutex<Frames>>);
        impl Write for Counting {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("sink").bytes.extend_from_slice(data);
                Ok(data.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl crate::proxy::FrameWrite for Counting {
            fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
                let mut seen = self.0.lock().expect("sink");
                seen.calls += 1;
                for part in parts {
                    seen.bytes.extend_from_slice(part);
                }
                true
            }
        }
        let log = Arc::new(Mutex::new(Frames::default()));
        let writer = XhttpWriter::new(Counting(Arc::clone(&log)));
        let payload = vec![0x5Au8; CHUNK];
        assert!(writer.send(&payload), "the window is framed");
        let seen = log.lock().expect("sink");
        assert_eq!(
            seen.calls, 1,
            "a promoted window left as {} chunked frames",
            seen.calls
        );
        let head = format!("{CHUNK:X}\r\n");
        assert_eq!(seen.bytes.len(), head.len() + CHUNK + 2);
        assert_eq!(&seen.bytes[..head.len()], head.as_bytes());
        assert_eq!(&seen.bytes[head.len()..head.len() + CHUNK], &payload[..]);
        assert_eq!(&seen.bytes[head.len() + CHUNK..], b"\r\n");
    }

    #[test]
    fn paths_cover_prefixes_without_crossing_names() {
        assert!(path_covers("/service", "/service"));
        assert!(path_covers("/service", "/service/session"));
        assert!(path_covers("/", "/anything"));
        assert!(!path_covers("/service", "/service-evil"));
        assert!(path_covers("/up/", "/up/sess-01"));
        assert!(path_covers("/up/", "/up/"));
        assert!(!path_covers("/up/", "/up-evil"));
    }

    #[test]
    fn chunked_matches_case_insensitive_contains() {
        for (value, want) in [
            ("chunked", true),
            ("Chunked", true),
            ("CHUNKED", true),
            ("gzip, chunked", true),
            ("chunked, gzip", true),
            ("mychunked", true),
            ("chunkedx", true),
            ("chu", false),
            ("", false),
            ("gzip", false),
            ("identity", false),
        ] {
            assert_eq!(has_chunked(value), want, "{value}");
        }
    }

    /// The two-pass form kept as the oracle for the fused rewrite: same None-when-invalid, same Some for every accepted size line.
    fn chunk_size_two_pass(line: &[u8]) -> Option<usize> {
        let mut end = line.len();
        for (i, &b) in line.iter().enumerate() {
            if b == b';' || b == b' ' || b == b'\t' || b == b'\r' || b == b'\n' {
                end = i;
                break;
            }
        }
        if end == 0 || end > 16 {
            return None;
        }
        let mut size = 0usize;
        for &b in &line[..end] {
            let digit = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => 10 + (b - b'a'),
                b'A'..=b'F' => 10 + (b - b'A'),
                _ => return None,
            } as usize;
            size = size * 16 + digit;
        }
        Some(size)
    }

    /// Bit-identity for the fused `chunk_size`: for every length 0..=20 and every probe byte at every position (with the rest filled by `1`, a hex digit), the fused loop and the two-pass reference agree. The full-window cases (length 16 with and without a terminator) and the length that overruns the cap (17) are the ones the fused rewrite could have moved, so they are covered explicitly.
    #[test]
    fn chunk_size_fused_matches_two_pass_on_every_probe() {
        let probes: [u8; 18] = [
            b'0', b'1', b'9', b'a', b'f', b'A', b'F', b';', b' ', b'\t', b'\r', b'\n', b'g', b'/',
            b':', b'@', b'`', 0xff,
        ];
        for len in 0..=20usize {
            let base = vec![b'1'; len];
            assert_eq!(
                chunk_size(&base),
                chunk_size_two_pass(&base),
                "all-hex len={len}"
            );
            for i in 0..len {
                for &probe in &probes {
                    let mut line = base.clone();
                    line[i] = probe;
                    assert_eq!(
                        chunk_size(&line),
                        chunk_size_two_pass(&line),
                        "len={len} pos={i} probe={probe:#04x}"
                    );
                }
            }
        }
        for prefix in [
            "",
            ";",
            " ;",
            "\t;",
            "\r\n",
            "f",
            "ff",
            "Ff",
            "1234567890abcdef",
            "1234567890abcdef;",
            "1234567890abcdef\r\n",
            "1234567890abcdefg",
            "1234567890abcdefg;",
            "1234567890abcdef0",
            "1234567890abcdef0;",
            "ffffffffffffffff",
            "fffffffffffffffff",
            "0",
            "0;",
            "00000",
        ] {
            assert_eq!(
                chunk_size(prefix.as_bytes()),
                chunk_size_two_pass(prefix.as_bytes()),
                "prefix={prefix:?}"
            );
        }
    }

    #[test]
    fn exchange_carries_an_echo_over_loopback() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, writer) = accept(stream, "/share").expect("serves");
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
            assert!(writer.send(b"pong"));
            writer.finish();
        });
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        let pad = "X".repeat(500);
        let (mut reader, writer) =
            connect(stream, "oracle.example", "/share", &[], &pad).expect("dials");
        assert!(writer.send(b"ping"));
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"pong");
        server.join().expect("joins");
    }

    /// Reads are driven with a fixed CHUNK buffer, the way `relay_ordered` drives them, so the count is the reader's and not `read_to_end`'s buffer growth; `reads` is the counter that says so.
    #[test]
    fn a_chunk_costs_two_reads_not_three() {
        for count in [1usize, 2, 4, 8, 16] {
            let chunks: Vec<usize> = std::iter::repeat_n(CHUNK, count).collect();
            let payload: Vec<u8> = vec![0x5Au8; CHUNK * count];
            let mut reader = Reader {
                read: std::io::Cursor::new(framed(&chunks)),
                prefix: Vec::new(),
                at: 0,
                left: 0,
                ended: false,
                reads: 0,
                pending_head: false,
                head_progress: None,
                chunk: Chunk::Body,
            };
            let mut got = Vec::new();
            let mut buf = vec![0u8; CHUNK];
            loop {
                let n = reader.read(&mut buf).expect("reads");
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            assert_eq!(got, payload, "{count} chunks: the bytes must be unchanged");
            // A size line now rides in the same window as the body it opens, so only the body's tail is a second read; the terminal line shares the last window. The old shape read the line and the two-byte CRLF on their own, so it cost three per chunk.
            assert_eq!(
                reader.reads(),
                count * 2 - 1,
                "{count} chunks: the framing read must not ask for a line alone"
            );
        }
    }

    /// xray writes 8 KiB per chunk, a quarter of the relay window; the framing read must cover several of them.
    #[test]
    fn a_peer_chunk_smaller_than_the_window_amortises_its_framing() {
        const PEER: usize = 8 * 1024;
        let count = 16;
        let chunks: Vec<usize> = std::iter::repeat_n(PEER, count).collect();
        let payload: Vec<u8> = vec![0x5Au8; PEER * count];
        let mut reader = Reader {
            read: std::io::Cursor::new(framed(&chunks)),
            prefix: Vec::new(),
            at: 0,
            left: 0,
            ended: false,
            reads: 0,
            pending_head: false,
            head_progress: None,
            chunk: Chunk::Body,
        };
        let mut got = Vec::new();
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = reader.read(&mut buf).expect("reads");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, payload, "the bytes must be unchanged");
        assert_eq!(
            reader.reads(),
            3,
            "{count} peer chunks must not cost a read each"
        );
    }

    /// A peer can spend all 127 bytes before CRLF on an extension; the window must still carry the closing pair, or every such chunk pays a fill.
    #[test]
    fn a_maximum_size_line_keeps_the_closing_crlf_in_the_framing_read() {
        let line = format!("10000;{}\r\n", "a".repeat(121));
        assert_eq!(line.len(), 129, "127 bytes of line and its CRLF");
        for count in [1usize, 2, 4, 8, 16] {
            let payload: Vec<u8> = vec![0x5Au8; CHUNK * count];
            let mut wire = Vec::new();
            for _ in 0..count {
                wire.extend_from_slice(line.as_bytes());
                wire.extend(std::iter::repeat_n(0x5Au8, CHUNK));
                wire.extend_from_slice(b"\r\n");
            }
            wire.extend_from_slice(b"0\r\n\r\n");
            let mut reader = Reader {
                read: std::io::Cursor::new(wire),
                prefix: Vec::new(),
                at: 0,
                left: 0,
                ended: false,
                reads: 0,
                pending_head: false,
                head_progress: None,
                chunk: Chunk::Body,
            };
            let mut got = Vec::new();
            let mut buf = vec![0u8; CHUNK];
            loop {
                let n = reader.read(&mut buf).expect("reads");
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            assert_eq!(got, payload, "{count} chunks: the bytes must be unchanged");
            assert_eq!(
                reader.reads(),
                count + 1,
                "{count} chunks: the closing pair must ride in the framing read"
            );
        }
    }

    /// The record arm takes the buffer its own head read filled, head octets and all: what rode behind the delimiter is handed over inside it, not copied into a second owner.
    #[test]
    fn the_record_head_hands_over_the_buffer_it_filled() {
        const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        const TAIL: &[u8] = b"2\r\nhi\r\n";
        let mut wire = Vec::from(HEAD);
        wire.extend_from_slice(TAIL);
        let (reader, _writer) = connect_split(
            std::io::Cursor::new(wire),
            Sink(Arc::new(Mutex::new(Vec::new()))),
            "h",
            "/share",
            &[],
            &"X".repeat(500),
        )
        .expect("dials the head");
        assert_eq!(reader.at, HEAD.len(), "the cursor sits past the head");
        assert_eq!(
            reader.prefix.len(),
            HEAD.len() + TAIL.len(),
            "one buffer carries the answer and what rode behind it"
        );
        assert_eq!(
            reader.prefix[reader.at..].as_ptr() as usize - reader.prefix.as_ptr() as usize,
            reader.at,
            "and those bytes lie inside the allocation the head read made"
        );
    }

    /// The kept head hands the reader its own buffer with the head already walked past: the chunk that rode in behind the head is delivered without asking the socket, and its bytes never move.
    #[test]
    fn a_chunk_that_rode_in_with_the_head_costs_no_syscall() {
        const HEAD: &[u8] =
            b"POST /share HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut prefix = Vec::from(HEAD);
        prefix.extend_from_slice(b"2\r\nhi\r\n0\r\n\r\n");
        let base = prefix.as_ptr();
        let capacity = prefix.capacity();
        let (mut reader, _writer) = split_halves(
            std::io::Cursor::new(Vec::from(&b"never read"[..])),
            Sink(Arc::new(Mutex::new(Vec::new()))),
            prefix,
            HEAD.len(),
        );
        let mut got = [0u8; 2];
        assert_eq!(reader.read(&mut got).expect("delivers"), 2);
        assert_eq!(&got, b"hi", "the chunk behind the head, not a re-read");
        assert_eq!(reader.read(&mut got).expect("ends"), 0);
        assert!(
            reader.ended,
            "the terminator was walked out of the same buffer"
        );
        assert_eq!(reader.reads(), 0, "the socket was never asked");
        assert_eq!(
            reader.prefix.as_ptr(),
            base,
            "delivered from the buffer those bytes arrived in"
        );
        assert_eq!(reader.prefix.capacity(), capacity, "on a held capacity");
    }

    /// The downlink's body is handed to the relay as a span of the buffer that read it: taking the window neither moves those bytes nor grows the buffer.
    #[test]
    fn a_body_window_is_the_readers_own_buffer() {
        let line = format!("{CHUNK:X}\r\n");
        let line_len = line.len();
        let payload: Vec<u8> = (0..CHUNK).map(|i| (i % 251) as u8).collect();
        let mut wire = line.into_bytes();
        wire.extend_from_slice(&payload);
        wire.extend_from_slice(b"\r\n0\r\n\r\n");
        let base = wire.as_ptr();
        let capacity = wire.capacity();
        let (mut reader, _writer) = split_halves(
            std::io::Cursor::new(Vec::new()),
            Sink(Arc::new(Mutex::new(Vec::new()))),
            wire,
            0,
        );
        {
            let window = crate::proxy::WindowRead::read_window(&mut reader).expect("reads");
            assert_eq!(window.parts(), &[(line_len, CHUNK)]);
            assert_eq!(
                window.bytes().as_ptr(),
                base,
                "the window is the buffer the body arrived in, not a copy"
            );
            assert_eq!(&window.bytes()[line_len..][..CHUNK], &payload[..]);
        }
        assert_eq!(reader.reads(), 0, "the socket was never asked");
        assert_eq!(reader.prefix.as_ptr(), base, "the buffer did not move");
        assert_eq!(
            reader.prefix.capacity(),
            capacity,
            "the buffer did not grow"
        );
        assert!(
            crate::proxy::WindowRead::read_window(&mut reader)
                .expect("ends")
                .is_empty(),
            "the terminator ends the body"
        );
        assert!(reader.ended);
    }

    /// Every byte the `Read` path delivers, the window path delivers too, across chunk sizes either side of the prefetch window.
    #[test]
    fn a_window_delivers_every_byte_the_read_does() {
        let chunks = [1usize, 2, 3, 5, 7, 11, 64, 8 * 1024, CHUNK, CHUNK + 1];
        let mut wire = Vec::new();
        for &n in &chunks {
            wire.extend_from_slice(format!("{n:X}\r\n").as_bytes());
            wire.extend(std::iter::repeat_n((n % 251) as u8, n));
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        let mut plain = Reader {
            read: std::io::Cursor::new(wire.clone()),
            prefix: Vec::new(),
            at: 0,
            left: 0,
            ended: false,
            reads: 0,
            pending_head: false,
            head_progress: None,
            chunk: Chunk::Body,
        };
        let mut want = Vec::new();
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = plain.read(&mut buf).expect("reads");
            if n == 0 {
                break;
            }
            want.extend_from_slice(&buf[..n]);
        }
        let mut windowed = Reader {
            read: std::io::Cursor::new(wire),
            prefix: Vec::new(),
            at: 0,
            left: 0,
            ended: false,
            reads: 0,
            pending_head: false,
            head_progress: None,
            chunk: Chunk::Body,
        };
        let mut got = Vec::new();
        loop {
            let window = crate::proxy::WindowRead::read_window(&mut windowed).expect("reads");
            if window.is_empty() {
                break;
            }
            for &(start, len) in window.parts() {
                got.extend_from_slice(&window.bytes()[start..start + len]);
            }
        }
        assert_eq!(got, want, "the window path is byte-identical");
        assert_eq!(
            want.len(),
            chunks.iter().sum::<usize>(),
            "every chunk body was delivered"
        );
    }

    /// One read's worth of prefix leaves as one gather: eight 8 KiB bodies in one window, not eight windows.
    #[test]
    fn a_window_gathers_every_chunk_one_read_brought() {
        let body = 8 * 1024usize;
        let chunks = 8usize;
        let mut wire = Vec::new();
        for n in 0..chunks {
            wire.extend_from_slice(format!("{body:X}\r\n").as_bytes());
            wire.extend(std::iter::repeat_n((n % 251) as u8, body));
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        let mut reader = Reader {
            read: std::io::Cursor::new(Vec::new()),
            prefix: wire,
            at: 0,
            left: 0,
            ended: false,
            reads: 0,
            pending_head: false,
            head_progress: None,
            chunk: Chunk::Body,
        };
        let mut got = Vec::new();
        let windows = {
            let window = crate::proxy::WindowRead::read_window(&mut reader).expect("reads");
            for &(start, len) in window.parts() {
                got.extend_from_slice(&window.bytes()[start..start + len]);
            }
            window.parts().len()
        };
        assert_eq!(
            windows, chunks,
            "one window carries every chunk the prefix holds"
        );
        assert_eq!(reader.reads(), 0, "the prefix was already answered");
        let mut want = Vec::new();
        for n in 0..chunks {
            want.extend(std::iter::repeat_n((n % 251) as u8, body));
        }
        assert_eq!(got, want, "the gather is byte-identical to the bodies");
    }

    /// A bad size line after a body is the next call's error, so the body already gathered still leaves first, as `Read` does.
    #[test]
    fn a_window_defers_a_framing_error_until_the_body_it_gathered_is_out() {
        let mut reader = Reader {
            read: std::io::Cursor::new(Vec::new()),
            prefix: b"1\r\na\r\nG\r\n".to_vec(),
            at: 0,
            left: 0,
            ended: false,
            reads: 0,
            pending_head: false,
            head_progress: None,
            chunk: Chunk::Body,
        };
        let mut got = Vec::new();
        {
            let window =
                crate::proxy::WindowRead::read_window(&mut reader).expect("the body first");
            for &(start, len) in window.parts() {
                got.extend_from_slice(&window.bytes()[start..start + len]);
            }
        }
        assert_eq!(got, b"a");
        assert!(
            crate::proxy::WindowRead::read_window(&mut reader).is_err(),
            "the invalid size line is reported on the next read"
        );
    }

    /// The counter must see the *short* reads too: one byte at a time is the worst case, and it is what makes a bounded window better than an unbounded one.
    #[test]
    fn a_trickling_stream_still_drains_whole() {
        struct Trickle {
            inner: std::io::Cursor<Vec<u8>>,
        }
        impl Read for Trickle {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let take = buf.len().min(1);
                self.inner.read(&mut buf[..take])
            }
        }

        let mut wire = Vec::new();
        wire.extend_from_slice(b"40\r\n");
        wire.extend(std::iter::repeat_n(0x11u8, 64));
        wire.extend_from_slice(b"\r\n");
        wire.extend_from_slice(b"0\r\n\r\n");
        let mut reader = Reader {
            read: Trickle {
                inner: std::io::Cursor::new(wire),
            },
            prefix: Vec::new(),
            at: 0,
            left: 0,
            ended: false,
            reads: 0,
            pending_head: false,
            head_progress: None,
            chunk: Chunk::Body,
        };
        let mut got = Vec::new();
        reader.read_to_end(&mut got).expect("drains");
        assert_eq!(got, vec![0x11u8; 64]);
        assert!(
            reader.reads() > 64,
            "one byte per read cannot be fewer reads than bytes, got {}",
            reader.reads()
        );
    }

    /// A socket delivers what the peer wrote, not what the frame asks for: the two bytes that close a chunk can arrive one per read, and a reader that insists both sit in its buffer refuses an intact stream.
    #[test]
    fn a_crlf_split_across_reads_still_drains() {
        struct Segments {
            pieces: std::vec::IntoIter<&'static [u8]>,
        }
        impl Read for Segments {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let Some(piece) = self.pieces.next() else {
                    return Ok(0);
                };
                let n = piece.len().min(buf.len());
                buf[..n].copy_from_slice(&piece[..n]);
                Ok(n)
            }
        }

        let mut reader = Reader {
            read: Segments {
                pieces: vec![b"4\r\nping\r".as_slice(), b"\n4\r\npong\r\n0\r\n\r\n"].into_iter(),
            },
            prefix: Vec::new(),
            at: 0,
            left: 0,
            ended: false,
            reads: 0,
            pending_head: false,
            head_progress: None,
            chunk: Chunk::Body,
        };
        let mut got = Vec::new();
        reader.read_to_end(&mut got).expect("drains");
        assert_eq!(got, b"pingpong");
    }

    #[test]
    fn chunks_drain_in_order_before_the_close_is_answered() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, writer) = accept(stream, "/share").expect("serves");
            let mut first = [0u8; 26];
            reader.read_exact(&mut first).expect("reads header");
            assert!(writer.send(&[0, 0]));
            let mut ping = [0u8; 4];
            reader.read_exact(&mut ping).expect("reads ping");
            assert_eq!(&ping, b"ping");
            assert!(writer.send(b"ping"));
            let mut drained = Vec::new();
            reader.read_to_end(&mut drained).expect("drains the close");
            assert_eq!(drained, [] as [u8; 0]);
            writer.finish();
        });
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .expect("timeout");
        let pad = "X".repeat(500);
        let (mut reader, writer) = connect(stream, "h", "/share", &[], &pad).expect("dials");
        assert!(writer.send(&[1u8; 26]));
        let mut reply = [0u8; 2];
        reader.read_exact(&mut reply).expect("replies");
        assert_eq!(reply, [0, 0]);
        assert!(writer.send(b"ping"));
        writer.finish();
        let mut back = Vec::new();
        reader.read_to_end(&mut back).expect("echoes");
        assert_eq!(back, b"ping");
        server.join().expect("joins");
    }

    #[test]
    fn exchange_rejects_a_wrong_path() {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            assert!(accept(stream, "/share").is_none());
        });
        let mut stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        stream
            .write_all(b"POST /other HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n")
            .expect("writes");
        server.join().expect("joins");
        drop(stream);
    }

    #[test]
    fn settings_parse_covers_the_test_config() {
        let node = crate::json::parse(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {
            "path": "/interop-xhttp/", "mode": "packet-up", "xPaddingBytes": 64,
            "uplinkHTTPMethod": "POST", "sessionIDPlacement": "path",
            "seqPlacement": "path", "uplinkDataPlacement": "body",
            "uplinkChunkSize": 4096, "scMaxEachPostBytes": 4096,
            "scMinPostsIntervalMs": 1,
            "xmux": {"maxConcurrency": 1, "hMaxRequestTimes": 64, "hMaxReusableSecs": 3600}}}}"#,
        )
        .expect("parses");
        let settings =
            XhttpSettings::from_json(node.get("streamSettings")).expect("settings parse");
        assert_eq!(settings.path, "/interop-xhttp/");
        assert_eq!(settings.mode, XhttpMode::PacketUp);
        assert_eq!(settings.x_padding_bytes, (64, 64));
        assert_eq!(settings.uplink_method, "POST");
        assert_eq!(settings.session_placement, Placement::Path);
        assert_eq!(settings.seq_placement, Placement::Path);
        assert_eq!(settings.uplink_data_placement, Placement::Body);
        assert_eq!(settings.sc_max_each_post, 4096);
        assert_eq!(settings.sc_min_posts_interval_ms, (1, 1));
        assert_eq!(settings.x_padding_method, PadMethod::RepeatX);
        assert!(!settings.x_padding_obfs);
        assert!(!settings.no_sse);

        let bad_mode =
            crate::json::parse(r#"{"xhttpSettings": {"mode": "multi"}}"#).expect("parses");
        assert!(XhttpSettings::from_json(Some(&bad_mode)).is_none());
        let bad_placement =
            crate::json::parse(r#"{"xhttpSettings": {"sessionIDPlacement": "cookie-jar"}}"#)
                .expect("parses");
        assert!(XhttpSettings::from_json(Some(&bad_placement)).is_none());
        let bad_padding =
            crate::json::parse(r#"{"xhttpSettings": {"xPaddingBytes": -3}}"#).expect("parses");
        assert!(XhttpSettings::from_json(Some(&bad_padding)).is_none());
        let missing = crate::json::parse(r#"{"network": "tcp"}"#).expect("parses");
        assert!(XhttpSettings::from_json(Some(&missing)).is_none());
        assert!(XhttpSettings::from_json(None).is_none());
        let bare = crate::json::parse(r#"{"network": "xhttp"}"#).expect("parses");
        assert_eq!(
            XhttpSettings::from_json(Some(&bare))
                .expect("defaults")
                .mode,
            XhttpMode::StreamOne
        );
        let auto_plain = crate::json::parse(r#"{"xhttpSettings": {}}"#).expect("parses");
        assert_eq!(
            XhttpSettings::from_json(Some(&auto_plain))
                .expect("auto")
                .mode,
            XhttpMode::PacketUp
        );
        let auto_reality =
            crate::json::parse(r#"{"security": "reality", "xhttpSettings": {"mode": "auto"}}"#)
                .expect("parses");
        assert_eq!(
            XhttpSettings::from_json(Some(&auto_reality))
                .expect("auto")
                .mode,
            XhttpMode::StreamOne
        );
        let auto_down = crate::json::parse(
            r#"{"security": "reality", "xhttpSettings": {"downloadSettings": {}}}"#,
        )
        .expect("parses");
        assert_eq!(
            XhttpSettings::from_json(Some(&auto_down))
                .expect("auto")
                .mode,
            XhttpMode::StreamUp
        );
    }

    #[test]
    fn h2c_is_an_opt_in_framing_on_the_cleartext_carrier() {
        let default = crate::json::parse(r#"{"network": "xhttp"}"#).expect("parses");
        assert!(
            !XhttpSettings::from_json(Some(&default))
                .expect("default")
                .h2c
        );
        let h2c = crate::json::parse(r#"{"network": "xhttp", "xhttpSettings": {"h2c": true}}"#)
            .expect("parses");
        assert!(XhttpSettings::from_json(Some(&h2c)).expect("h2c").h2c);
        let object = crate::json::parse(
            r#"{"network": "xhttp", "xhttpSettings": {"extra": {"h2c": true}}}"#,
        )
        .expect("parses");
        assert!(XhttpSettings::from_json(Some(&object)).expect("h2c").h2c);
        let string = crate::json::parse(
            r#"{"network": "xhttp", "xhttpSettings": {"extra": "{\"h2c\": true}"}}"#,
        )
        .expect("parses");
        assert!(XhttpSettings::from_json(Some(&string)).expect("h2c").h2c);
        let cleared = crate::json::parse(
            r#"{"network": "xhttp", "xhttpSettings": {"h2c": true, "extra": {"h2c": false}}}"#,
        )
        .expect("parses");
        assert!(!XhttpSettings::from_json(Some(&cleared)).expect("h2c").h2c);
        let replaced = crate::json::parse(
            r#"{"network": "xhttp", "xhttpSettings": {"h2c": true, "extra": {}}}"#,
        )
        .expect("parses");
        assert!(!XhttpSettings::from_json(Some(&replaced)).expect("h2c").h2c);
    }

    /// The path placements read the segments in order without collecting them: the default
    /// session-then-seq walk takes the same first two segments a list would index.
    #[test]
    fn the_path_placements_are_read_without_a_list() {
        let mut settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/up/"}}}"#,
        );
        let (meta, counts) =
            ferrox_core::alloc_count::measure(|| extract_meta("", "/up/abc/7", &settings));
        assert_eq!(counts.allocs, 0, "the segments are borrowed: {counts:?}");
        assert_eq!(meta, (Some("abc"), Some("7")));
        settings.session_placement = Placement::Query;
        settings.session_key = "x_session".to_owned();
        settings.seq_placement = Placement::Path;
        assert_eq!(
            extract_meta("", "/up/abc/7?x_session=z", &settings),
            (Some("z"), Some("abc")),
            "a seq-only path takes the first segment"
        );
        assert_eq!(
            extract_meta("", "/up/", &settings),
            (None, None),
            "a path with no segments names nothing"
        );
    }

    /// The reference reads its obfuscation knobs from `extra`, which replaces the whole settings block except host, path and mode.
    #[test]
    fn the_extra_block_replaces_every_knob_but_path_and_mode() {
        let node = crate::json::parse(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {
            "path": "/tunnel", "mode": "stream-one", "scMaxEachPostBytes": 4096,
            "extra": {"xPaddingBytes": "1-1", "xPaddingObfsMode": true, "xPaddingKey": "ctx",
                "xPaddingHeader": "x-grpc-context", "xPaddingMethod": "tokenish",
                "sessionIDPlacement": "header", "sessionIDKey": "Idempotency-Key",
                "seqPlacement": "header", "seqKey": "Upload-Offset"}}}}"#,
        )
        .expect("parses");
        let got = XhttpSettings::from_json(node.get("streamSettings")).expect("extra parses");
        assert_eq!(got.path, "/tunnel", "path stays on the outer block");
        assert_eq!(got.mode, XhttpMode::StreamOne, "and so does mode");
        assert!(got.x_padding_obfs);
        assert_eq!(got.x_padding_bytes, (1, 1));
        assert_eq!(got.x_padding_key, "ctx");
        assert_eq!(got.x_padding_header, "x-grpc-context");
        assert_eq!(got.x_padding_method, PadMethod::Tokenish);
        assert_eq!(
            got.x_padding_placement,
            Placement::QueryInHeader,
            "unset inside extra, so the reference default applies"
        );
        assert_eq!(got.session_placement, Placement::Header);
        assert_eq!(got.session_key, "Idempotency-Key");
        assert_eq!(got.seq_placement, Placement::Header);
        assert_eq!(got.seq_key, "Upload-Offset");
        assert_eq!(
            got.sc_max_each_post, 1_000_000,
            "a knob the outer block sets and extra omits is replaced by the default, not merged"
        );

        let linked = crate::json::parse(
            r#"{"xhttpSettings": {"path": "/tunnel",
                "extra": "{\"xPaddingObfsMode\":true,\"xPaddingKey\":\"ctx\"}"}}"#,
        )
        .expect("parses");
        let got = XhttpSettings::from_json(Some(&linked)).expect("string extra parses");
        assert!(got.x_padding_obfs);
        assert_eq!(got.x_padding_key, "ctx");

        let null = crate::json::parse(r#"{"xhttpSettings": {"path": "/p", "extra": null}}"#)
            .expect("parses");
        assert!(
            !XhttpSettings::from_json(Some(&null))
                .expect("null extra")
                .x_padding_obfs
        );
        let bad = crate::json::parse(r#"{"xhttpSettings": {"extra": 7}}"#).expect("parses");
        assert!(XhttpSettings::from_json(Some(&bad)).is_none());
    }

    /// Where a hub's answer goes when the row is about the status, not the socket.
    #[derive(Clone)]
    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl Write for Sink {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("sink").extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl crate::proxy::FrameWrite for Sink {
        fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
            let mut seen = self.0.lock().expect("sink");
            for part in parts {
                seen.extend_from_slice(part);
            }
            true
        }
    }

    /// The status a hub answers a head with. `accept_core` writes a refusal and ends the connection, and writes 200 and returns the pair when it serves, so the bytes it wrote answer either way.
    fn status_through_core(head: &str, settings: &XhttpSettings) -> u16 {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let _ = accept_core(
            head.as_bytes(),
            Vec::new(),
            Upload::Read(std::io::Cursor::new(vec![0u8; 1])),
            Sink(Arc::clone(&seen)),
            settings,
            None,
            None,
        );
        let text = String::from_utf8(seen.lock().expect("sink").clone()).unwrap_or_default();
        text.split_ascii_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or(0)
    }

    fn settings_from(raw: &str) -> XhttpSettings {
        let node = crate::json::parse(raw).expect("parses");
        XhttpSettings::from_json(node.get("streamSettings")).expect("settings")
    }

    #[test]
    fn a_stream_one_dial_carries_the_trailing_slash_the_reference_reads() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share", "mode": "stream-one"}}}"#,
        );
        let path = dial_path(&settings);
        assert_eq!(path, "/share/");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut sink = Sink(Arc::clone(&seen));
        let pad = referer_pad_value(&settings);
        send_dial_head(&mut sink, "front.example", &path, &settings.headers, &pad).expect("head");
        let head = String::from_utf8(seen.lock().expect("sink").clone()).expect("utf8");
        assert!(head.starts_with("POST /share/ HTTP/1.1\r\n"), "{head}");
        assert!(
            head.contains("Referer: http://front.example/share/?x_padding="),
            "{head}"
        );
        // The reference dialer disables keep-alives (dialer.go:272).
        assert!(head.contains("Connection: close\r\n"), "{head}");
        let query = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share", "mode": "stream-one", "sessionIDPlacement": "query", "seqPlacement": "query"}}}"#,
        );
        assert_eq!(dial_path(&query), "/share");
    }

    /// The pad hangs off the referer's path alone: the configured query rides on the request line, so the hub's extractor still finds `x_padding` when both are set.
    #[test]
    fn a_configured_query_keeps_the_pad_on_the_referer_path() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share?a=1", "mode": "stream-one"}}}"#,
        );
        let path = dial_path(&settings);
        assert_eq!(path, "/share/?a=1");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut sink = Sink(Arc::clone(&seen));
        let pad = referer_pad_value(&settings);
        send_dial_head(&mut sink, "front.example", &path, &settings.headers, &pad).expect("head");
        let head = String::from_utf8(seen.lock().expect("sink").clone()).expect("utf8");
        assert!(head.starts_with("POST /share/?a=1 HTTP/1.1\r\n"), "{head}");
        assert!(
            head.contains("Referer: http://front.example/share/?x_padding="),
            "{head}"
        );
    }

    #[test]
    fn a_configured_header_and_the_fetch_defaults_reach_every_dial_head() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/up/", "headers": {"X-Fetch": "1"}}}}"#,
        );
        assert_eq!(
            settings.headers,
            vec![("X-Fetch".to_owned(), "1".to_owned())]
        );
        let head = dial_head("front.example", &settings, "session", None);
        assert!(head.contains("Sec-Fetch-Mode: cors\r\n"), "{head}");
        assert!(head.contains("X-Fetch: 1\r\n"), "{head}");
        assert_eq!(
            head.matches("Host: front.example\r\n").count(),
            1,
            "the fixed Host line is the only one"
        );
    }

    fn xmux_settings(body: &str) -> Option<XhttpSettings> {
        let node = crate::json::parse(&format!(
            r#"{{"xhttpSettings": {{"mode": "stream-up", "xmux": {body}}}}}"#
        ))
        .expect("parses");
        XhttpSettings::from_json(Some(&node))
    }

    /// `xmux` is the reference's `Int32Range` spelling and its own defaults, and the two bounds exclude
    /// each other exactly as its `Build` refuses them.
    #[test]
    fn xmux_reads_the_references_ranges_and_defaults() {
        let block = |body: &str| {
            xmux_settings(body)
                .expect("a valid block")
                .xmux
                .expect("a stated block")
        };

        let empty = block("{}");
        assert_eq!(
            (
                empty.max_connections,
                empty.h_max_request_times,
                empty.h_max_reusable_secs
            ),
            ((3, 3), (600, 900), (1800, 3000)),
            "an empty block takes the reference's pool defaults"
        );

        let one = block(r#"{"maxConnections": 2}"#);
        assert_eq!(one.max_connections, (2, 2));
        assert_eq!(
            one.h_max_request_times,
            (0, 0),
            "one named field skips the defaults"
        );

        let span = block(r#"{"maxConnections": "9-4", "hKeepAlivePeriod": 30}"#);
        assert_eq!(span.max_connections, (4, 9), "the bounds are ordered");
        assert_eq!(span.h_keep_alive_period, 30);

        let signed = block(r#"{"cMaxReuseTimes": "-1--3", "maxConcurrency": "-7"}"#);
        assert_eq!(signed.c_max_reuse_times, (-3, -1));
        assert_eq!(
            signed.max_concurrency,
            (-7, -7),
            "a negative bound is a sentinel"
        );

        let none = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/"}}}"#,
        );
        assert!(none.xmux.is_none(), "an absent block states nothing");

        assert!(
            xmux_settings(r#"{"maxConnections": 3, "maxConcurrency": 2}"#).is_none(),
            "both bounds at once are refused"
        );
        let negative = block(r#"{"maxConnections": 3, "maxConcurrency": "-2"}"#);
        assert_eq!(
            negative.max_concurrency,
            (-2, -2),
            "a negative bound is a sentinel, so only one bound is set"
        );

        for (body, why) in [
            (r#"{"maxConnections": "3-"}"#, "a truncated range"),
            (r#"{"maxConnections": []}"#, "an array is not a range"),
            (r#"{"hKeepAlivePeriod": "30"}"#, "the period is an integer"),
        ] {
            assert!(xmux_settings(body).is_none(), "{why}: {body}");
        }
    }

    /// The answer head is opened once for the bytes it will hold: a padded answer used to start as
    /// a seventeen-byte `String` and grow into a kilobyte, and it built the downlink header as its
    /// own `String` only to copy it in.
    #[test]
    fn a_padded_answer_is_written_from_one_buffer() {
        let mut settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/up/"}}}"#,
        );
        settings.x_padding_obfs = true;
        settings.x_padding_method = PadMethod::RepeatX;
        settings.x_padding_header = "X-Pad".to_owned();
        settings.x_padding_key = "pad".to_owned();
        let padded = "X".repeat(700);
        let framing = "Content-Length: 0\r\nConnection: keep-alive\r\n\r\n";
        let tail = format!(
            "X-Accel-Buffering: no\r\nCache-Control: no-store\r\nContent-Type: text/event-stream\r\n{framing}"
        );
        for (placement, line) in [
            (Placement::Header, format!("X-Pad: {padded}\r\n")),
            (
                Placement::Cookie,
                format!("Set-Cookie: pad={padded}; Path=/\r\n"),
            ),
            (Placement::Query, format!("X-Padding: {padded}\r\n")),
        ] {
            settings.x_padding_placement = placement;
            let want = format!("HTTP/1.1 200 OK\r\n{line}{tail}");
            let mut out = Vec::with_capacity(1024);
            let ((), counts) = ferrox_core::alloc_count::measure(|| {
                padded_response(&mut out, &settings, &padded, framing);
            });
            assert_eq!(
                counts.allocs, 1,
                "the head buffer is the answer's only allocation: {counts:?}"
            );
            assert_eq!(out, want.as_bytes(), "the bytes are the padded answer");
        }
    }

    /// The body lands in uninitialised room: the read that owns every byte writes it before the
    /// body is handed on, so zeroing the buffer first was a pass over bytes about to be overwritten.
    #[test]
    fn a_body_read_lands_in_room_it_never_zeroes() {
        let wire = [0x5Au8; 64];
        let mut source = std::io::Cursor::new(&wire[..]);
        let (read, counts) = ferrox_core::alloc_count::measure(|| {
            read_body(
                &mut source,
                b"head-tail",
                32,
                crate::budgets::head_arrival(),
            )
        });
        let (body, pre) = read.expect("the body");
        assert_eq!(pre, 9, "what the head left over is the body's own head");
        let mut want = b"head-tail".to_vec();
        want.extend_from_slice(&wire[..23]);
        assert_eq!(body, want, "the bytes are the body");
        assert_eq!(counts.zeroed, 0, "the read fills every byte: {counts:?}");
    }

    /// A poll grain on an armed socket is not the body's end: a POST whose body arrives late still lands.
    #[test]
    fn a_body_read_waits_out_a_poll_grain() {
        struct Late {
            grains: usize,
            body: std::io::Cursor<Vec<u8>>,
        }
        impl std::io::Read for Late {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.grains > 0 {
                    self.grains -= 1;
                    return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
                }
                self.body.read(buf)
            }
        }
        let mut late = Late {
            grains: 2,
            body: std::io::Cursor::new(b"body".to_vec()),
        };
        let (body, pre) =
            read_body(&mut late, b"", 4, std::time::Duration::from_secs(1)).expect("the body");
        assert_eq!((body, pre), (b"body".to_vec(), 0));
        let mut late = Late {
            grains: 2,
            body: std::io::Cursor::new(b"later".to_vec()),
        };
        match drain_body(&mut late, 64, std::time::Duration::from_secs(1)) {
            Drained::Done(body) => assert_eq!(body, b"later"),
            _ => panic!("the drain gave up on a poll grain"),
        }
        let mut late = Late {
            grains: usize::MAX,
            body: std::io::Cursor::new(Vec::new()),
        };
        assert!(
            read_body(&mut late, b"", 4, std::time::Duration::from_millis(5)).is_none(),
            "a withheld body ends at its deadline"
        );
        let mut late = Late {
            grains: usize::MAX,
            body: std::io::Cursor::new(Vec::new()),
        };
        assert!(
            matches!(
                drain_body(&mut late, 64, std::time::Duration::from_millis(5)),
                Drained::Broken
            ),
            "a withheld stream ends at its deadline"
        );
    }

    /// A chunked body that withholds its first frame ends at the body deadline, not in the framing read's poll sleep.
    #[test]
    fn a_withheld_chunked_body_ends_at_its_deadline() {
        struct Silent;
        impl std::io::Read for Silent {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
            }
        }
        let mut framed = Reader {
            read: Silent,
            prefix: Vec::new(),
            at: 0,
            left: 0,
            ended: false,
            reads: 0,
            pending_head: false,
            head_progress: None,
            chunk: Chunk::Body,
        };
        let started = std::time::Instant::now();
        assert!(
            matches!(
                drain_body(&mut framed, 64, std::time::Duration::from_millis(5)),
                Drained::Broken
            ),
            "a withheld chunked body ends at its deadline"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "the deadline ends the framing read, not the poll sleep"
        );
        assert!(framed.reads > 0, "the framing read reached the source");
    }

    /// A byte just inside each idle window still cannot outlive the hard body cap.
    #[test]
    fn a_drip_cannot_outlive_the_hard_body_cap() {
        struct Drip;
        impl std::io::Read for Drip {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                std::thread::sleep(std::time::Duration::from_millis(10));
                buf[0] = 0;
                Ok(1)
            }
        }
        crate::budgets::apply(&crate::config::Budgets {
            relay_stall: Some(std::time::Duration::from_millis(30)),
            ..Default::default()
        });
        let mut drip = Drip;
        let started = std::time::Instant::now();
        let read = read_body(&mut drip, b"", 100, std::time::Duration::from_secs(60));
        let drained = drain_body(&mut drip, usize::MAX, std::time::Duration::from_secs(60));
        crate::budgets::clear();
        assert!(read.is_none(), "the hard cap ends a dripped body");
        assert!(
            matches!(drained, Drained::Broken),
            "the hard cap ends a dripped stream"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "both end at the hard cap, not the idle budget"
        );
    }

    /// What a body read leaves behind is the next request's head; it moves down inside the head's buffer, where the old shape copied it into a fresh one.
    #[test]
    fn the_tail_a_body_read_leaves_stays_in_the_head_buffer() {
        let wire = b"NEXT-HEAD-payload".to_vec();
        let base = wire.as_ptr();
        let capacity = wire.capacity();
        let pre = 10;
        let (tail, counts) = ferrox_core::alloc_count::measure(move || carry_tail(wire, pre));
        assert_eq!(
            tail,
            b"payload".to_vec(),
            "the tail is the bytes behind the body"
        );
        assert_eq!(
            tail.as_ptr(),
            base,
            "the tail moved down in the buffer, not into a new one"
        );
        assert_eq!(tail.capacity(), capacity, "the head's room is kept");
        assert_eq!(
            counts.allocs, 0,
            "the carry is the head's buffer: {counts:?}"
        );
        let old = b"NEXT-HEAD-payload".to_vec();
        let (copied, old_counts) = ferrox_core::alloc_count::measure(move || old[pre..].to_vec());
        assert_eq!(copied, tail, "the carry is the same bytes");
        assert_eq!(
            old_counts.allocs, 1,
            "the copy the carry used to pay: {old_counts:?}"
        );
    }

    /// The connection header is compared where it lies: lowercasing the value first was a `String`
    /// per request that said whether the connection stays.
    #[test]
    fn a_connection_header_is_named_without_a_lowercase_copy() {
        let head = "POST /up HTTP/1.1\r\nHost: h\r\nConnection: Keep-Alive\r\n\r\n";
        let (keep, counts) = ferrox_core::alloc_count::measure(|| keeps_alive(head));
        assert!(keep, "HTTP/1.1 keeps alive when told to");
        assert_eq!(counts.allocs, 0, "the field is read in place: {counts:?}");
        assert!(
            !keeps_alive("POST /up HTTP/1.1\r\nConnection: keep-alive, CLOSE\r\n\r\n"),
            "a close in the list wins"
        );
        assert!(
            keeps_alive("POST /up HTTP/1.0\r\nConnection: KEEP-ALIVE\r\n\r\n"),
            "HTTP/1.0 keeps alive only when told"
        );
        assert!(!keeps_alive("POST /up HTTP/1.0\r\n\r\n"));
    }

    /// A missing or `auto` mode is the dialer's default, not a promise about what may arrive: the reference hub gates a shape only when the mode was written down (`hub.go:154`, `:199`, `:241` all read `Mode != "" && Mode != "auto" && Mode != <shape>`). Our own `xhttp::connect` writes the `stream-one` POST, so a hub resolved from `{"path": "/share"}` refusing it is a hub that answers no dial its own client can make — which is what left `vless-xhttp-down-8` with no flow at any connection count.
    #[test]
    fn an_unstated_mode_serves_the_dialers_own_head() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share"}}}"#,
        );
        assert_eq!(
            settings.mode,
            XhttpMode::PacketUp,
            "auto resolves the way the reference dialer does"
        );
        assert_eq!(settings.mode_source, ModeSource::Auto);
        let head = format!(
            "POST /share HTTP/1.1\r\nHost: h\r\nReferer: {}\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
            "http://127.0.0.1/share?x_padding=".to_owned() + &"X".repeat(500)
        );
        assert_eq!(
            status_through_core(&head, &settings),
            200,
            "an auto hub refused the head its own dialer writes"
        );
    }

    /// The dial's head is the thread's own room: the first dial stages it, the next
    /// twelve reuse the same buffer, and the bytes are the ones the reference writes.
    #[test]
    fn the_dial_head_is_staged_once_per_thread() {
        struct Sink {
            bytes: [u8; 4096],
            at: usize,
        }
        impl Write for Sink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.bytes[self.at..self.at + buf.len()].copy_from_slice(buf);
                self.at += buf.len();
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl crate::proxy::FrameWrite for Sink {
            fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
                parts.iter().all(|part| self.write_all(part).is_ok())
            }
        }
        // The first access may also allocate the thread-local itself on some platforms.
        let mut warm = Sink {
            bytes: [0u8; 4096],
            at: 0,
        };
        let pad = "X".repeat(500);
        send_dial_head(&mut warm, "example.com", "/share", &[], &pad).expect("writes");
        let staged = DIAL_HEAD.with(|cell| {
            let head = cell.borrow();
            (head.as_ptr(), head.capacity())
        });
        let (sink, counts) = ferrox_core::alloc_count::measure(|| {
            let mut sink = Sink {
                bytes: [0u8; 4096],
                at: 0,
            };
            for _ in 0..12 {
                sink.at = 0;
                send_dial_head(&mut sink, "example.com", "/share", &[], &pad).expect("writes");
            }
            sink
        });
        assert_eq!(counts.allocs, 0, "twelve dials reuse the staged room");
        DIAL_HEAD.with(|cell| {
            let head = cell.borrow();
            assert_eq!(
                (head.as_ptr(), head.capacity()),
                staged,
                "the head's buffer did not move or grow"
            );
        });
        let head = String::from_utf8_lossy(&sink.bytes[..sink.at]);
        assert!(
            head.starts_with(
                "POST /share HTTP/1.1\r\nHost: example.com\r\nReferer: http://example.com/share?x_padding="
            ),
            "{head}"
        );
        let run = head
            .split("?x_padding=")
            .nth(1)
            .and_then(|rest| rest.split("\r\n").next())
            .expect("the padding run");
        assert!(
            !run.is_empty() && run.chars().all(|byte| byte == 'X'),
            "the padding is a run of X: {head}"
        );
        assert!(
            head.ends_with(
                "\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n"
            ),
            "{head}"
        );
    }

    /// The two halves of one process over a socket: `connect` writes the head its own random padding asks for, and the hub built from the same config has to answer it. Before this fix the hub answered `HTTP/1.1 400` to that head at every connection count, which is why `vless-xhttp-down-8` completed no flow.
    /// `sessionIDTable` and `sessionIDLength` draw the session id from a table (`GenerateSessionID`, config.go:511); either missing keeps the UUID the reference mints by default.
    #[test]
    fn a_configured_session_id_table_shapes_the_id() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {
                "path": "/up", "mode": "packet-up", "sessionIDTable": "hex", "sessionIDLength": 16}}}"#,
        );
        let id = settings.session_id();
        assert_eq!(id.len(), 16, "the configured length: {id}");
        assert!(
            id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "the named table: {id}"
        );
        let uuid = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/up", "mode": "packet-up"}}}"#,
        )
        .session_id();
        assert_eq!(uuid.len(), 36, "no table keeps the UUID: {uuid}");
    }

    fn framed(chunks: &[usize]) -> Vec<u8> {
        let mut wire = Vec::new();
        for &n in chunks {
            wire.extend_from_slice(format!("{n:X}\r\n").as_bytes());
            wire.extend(std::iter::repeat_n(0x5Au8, n));
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        wire
    }

    fn packet_settings(mode: XhttpMode) -> XhttpSettings {
        let mut settings = XhttpSettings::stream_one();
        settings.path = "/share/".to_owned();
        settings.mode = mode;
        settings
    }

    /// One request head off the wire, with the target and body length its bytes name.
    fn head_text(stream: &mut Connection) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).expect("reads the head");
            head.push(byte[0]);
        }
        String::from_utf8(head).expect("ascii head")
    }

    fn take_head(stream: &mut Connection) -> (String, usize) {
        let text = head_text(stream);
        let target = text
            .split("\r\n")
            .next()
            .and_then(|line| line.split(' ').nth(1))
            .expect("a request target")
            .to_owned();
        let length = text
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        (target, length)
    }

    /// A packet-up dial posts each slice under its own seq on the upload socket, and the downlink GET carries the same session under the normalised path.
    #[test]
    fn a_packet_up_dial_posts_every_slice_under_one_session() {
        let mut settings = packet_settings(XhttpMode::PacketUp);
        settings.sc_max_each_post = 2;
        let down_listener = crate::conn::test_bind("127.0.0.1:0").expect("binds downlink");
        let up_listener = crate::conn::test_bind("127.0.0.1:0").expect("binds uplink");
        let down_port = down_listener.local_addr().expect("addr").port();
        let up_port = up_listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (mut down, _) = down_listener.accept().expect("accepts the downlink");
            let (get, _) = take_head(&mut down);
            down.write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndone\r\n0\r\n\r\n",
            )
            .expect("answers the downlink");
            let (mut up, _) = up_listener.accept().expect("accepts the uplink");
            let mut posts = Vec::new();
            for _ in 0..2 {
                let (target, length) = take_head(&mut up);
                let mut body = vec![0u8; length];
                up.read_exact(&mut body).expect("reads the packet");
                posts.push((target, body));
                up.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .expect("answers the packet");
            }
            (get, posts)
        });
        let down = Connection::connect(("127.0.0.1", down_port)).expect("connects the downlink");
        let up = Connection::connect(("127.0.0.1", up_port)).expect("connects the uplink");
        let (mut reader, writer) =
            connect_dual(down, up, "127.0.0.1", &settings).expect("the dial is answered");
        assert!(writer.send(b"abcd"));
        let mut got = [0u8; 4];
        reader.read_exact(&mut got).expect("reads the downlink");
        assert_eq!(&got, b"done");
        let (get, posts) = server.join().expect("joins");
        let session = get
            .strip_prefix("/share/")
            .expect("the session rides the path");
        assert_eq!(posts[0].0, format!("/share/{session}/0"));
        assert_eq!(posts[1].0, format!("/share/{session}/1"));
        assert_eq!(posts[0].1, b"ab");
        assert_eq!(posts[1].1, b"cd");
    }

    /// A packet-up POST whose answer is still in flight lets the relay queue the next window, and the poster posts that queue as one body.
    type Posts = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

    struct HeldUp {
        posts: Posts,
        wrote_first: std::sync::mpsc::SyncSender<()>,
        answer: Mutex<std::sync::mpsc::Receiver<()>>,
        answered: AtomicBool,
        reply_at: usize,
    }

    impl Write for HeldUp {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl crate::proxy::FrameWrite for HeldUp {
        fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
            let head = parts.first().copied().unwrap_or_default();
            let body = parts.get(1).copied().unwrap_or_default();
            let text = String::from_utf8_lossy(head);
            let target = text.split(' ').nth(1).unwrap_or_default().to_owned();
            self.posts
                .lock()
                .expect("posts")
                .push((target, body.to_vec()));
            let _ = self.wrote_first.try_send(());
            true
        }
    }

    impl Read for HeldUp {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.answered.swap(true, Ordering::SeqCst) {
                let _ = self.answer.lock().expect("answer").recv();
            }
            let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            if self.reply_at == reply.len() {
                self.reply_at = 0;
            }
            let n = (reply.len() - self.reply_at).min(buf.len());
            buf[..n].copy_from_slice(&reply[self.reply_at..self.reply_at + n]);
            self.reply_at += n;
            Ok(n)
        }
    }

    struct HeldUpDial {
        writer: XhttpWriter,
        posts: Posts,
        release: std::sync::mpsc::Sender<()>,
        first_written: std::sync::mpsc::Receiver<()>,
    }

    fn held_up(settings: &XhttpSettings) -> HeldUpDial {
        let posts = Arc::new(Mutex::new(Vec::new()));
        let (wrote_first, first_written) = std::sync::mpsc::sync_channel(1);
        let (release, answer) = std::sync::mpsc::channel();
        let up = HeldUp {
            posts: Arc::clone(&posts),
            wrote_first,
            answer: Mutex::new(answer),
            answered: AtomicBool::new(false),
            reply_at: 0,
        };
        let writer = XhttpWriter::packets(up, "h", settings, "session".to_owned());
        HeldUpDial {
            writer,
            posts,
            release,
            first_written,
        }
    }

    #[test]
    fn a_packet_up_upload_batches_what_queues_behind_an_answer() {
        let mut settings = packet_settings(XhttpMode::PacketUp);
        settings.sc_max_each_post = 64;
        settings.sc_min_posts_interval_ms = (0, 0);
        let HeldUpDial {
            writer,
            posts,
            release,
            first_written,
        } = held_up(&settings);
        assert!(writer.send(&[0u8; 32]));
        first_written
            .recv_timeout(Duration::from_secs(5))
            .expect("the first post left");
        assert!(writer.send(&[1u8; 32]));
        assert!(writer.send(&[2u8; 32]));
        release.send(()).expect("releases the answer");
        writer.finish();
        let posts = posts.lock().expect("posts");
        assert_eq!(posts.len(), 2, "the queued windows share one post");
        assert_eq!(posts[0].1, [0u8; 32]);
        let mut batched = vec![1u8; 32];
        batched.extend_from_slice(&[2u8; 32]);
        assert_eq!(posts[1].1, batched, "the batched post carries both windows");
        assert!(posts[0].0.ends_with("/session/0"));
        assert!(posts[1].0.ends_with("/session/1"));
    }

    /// A packet-up answer is read into the upload lane's own window: the head of every POST returns to the same allocation rather than paying a fresh buffer the answer never keeps.
    #[test]
    fn a_packet_up_answer_is_read_without_allocating() {
        let answer = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let wires = [answer.as_slice(), answer.as_slice()];
        let mut head = Vec::with_capacity(HEAD_LIMIT);
        let capacity = head.capacity();
        let (ok, counts) = ferrox_core::alloc_count::measure(|| {
            wires
                .into_iter()
                .all(|wire| drain_answer(&mut std::io::Cursor::new(wire), &mut head))
        });
        assert!(ok, "both answers are 200");
        assert_eq!(
            (counts.allocs, counts.bytes, counts.zeroed),
            (0, 0, 0),
            "the lane reuses its answer window: {counts:?}"
        );
        assert_eq!(head.capacity(), capacity, "the answer window does not grow");
    }

    /// A full queue answers at once instead of waiting inside the lane the other flows share.
    #[test]
    fn a_full_packet_up_queue_parks_instead_of_waiting() {
        let mut settings = packet_settings(XhttpMode::PacketUp);
        settings.sc_max_each_post = 4;
        settings.sc_min_posts_interval_ms = (0, 0);
        let HeldUpDial {
            writer,
            posts,
            release,
            first_written,
        } = held_up(&settings);
        assert!(writer.send(b"abcd"));
        first_written
            .recv_timeout(Duration::from_secs(5))
            .expect("the first post left");
        assert!(matches!(
            crate::proxy::CarrierSink::push(&writer, b"efgh"),
            crate::proxy::Push::Took(4)
        ));
        assert!(matches!(
            crate::proxy::CarrierSink::push(&writer, b"ij"),
            crate::proxy::Push::Parked
        ));
        release.send(()).expect("releases the answer");
        writer.finish();
        let posts = posts.lock().expect("posts");
        assert_eq!(posts.len(), 2);
        assert_eq!(posts[1].1, b"efgh");
    }

    /// A poster the OS refuses to spawn must fail the upload instead of parking it on a queue nobody drains.
    #[test]
    fn a_failed_poster_fails_the_upload_instead_of_parking_it() {
        let mut settings = packet_settings(XhttpMode::PacketUp);
        settings.sc_max_each_post = 4;
        settings.sc_min_posts_interval_ms = (0, 0);
        let (wrote_first, _first_written) = std::sync::mpsc::sync_channel(1);
        let (release, answer) = std::sync::mpsc::channel();
        let up = Arc::new(Packer {
            transport: Mutex::new(Box::new(H1Post {
                stream: Box::new(HeldUp {
                    posts: Arc::new(Mutex::new(Vec::new())),
                    wrote_first,
                    answer: Mutex::new(answer),
                    answered: AtomicBool::new(false),
                    reply_at: 0,
                }),
                host: "h".to_owned(),
                settings: settings.clone(),
                session: "session".to_owned(),
                answer: Vec::new(),
            })),
            queue: Mutex::new(vec![0u8; 4]),
            cv: Condvar::new(),
            closed: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            settings,
            seq: AtomicU64::new(0),
            last: Mutex::new(None),
        });
        let packets = Packets::new(Arc::clone(&up), None);
        let (sent, got) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sent.send(packets.send(b"x"));
        });
        assert_eq!(
            got.recv_timeout(Duration::from_secs(2)),
            Ok(false),
            "a failed poster must fail instead of parking"
        );
        assert!(up.failed.load(Ordering::SeqCst), "the failure is recorded");
        drop(release);
    }

    /// Any tail the relay hands over rides the post it queued behind, and the posts put the upload back byte for byte.
    #[test]
    fn a_packet_up_upload_posts_every_byte_in_order() {
        let mut settings = packet_settings(XhttpMode::PacketUp);
        settings.sc_max_each_post = 7;
        settings.sc_min_posts_interval_ms = (0, 0);
        let HeldUpDial {
            writer,
            posts,
            release,
            first_written: _,
        } = held_up(&settings);
        release.send(()).expect("answers without holding");
        let pieces: [&[u8]; 5] = [b"ab", &[0u8; 7], &[1u8; 8], &[2u8; 3], b""];
        let mut want = Vec::new();
        for piece in pieces {
            assert!(writer.send(piece));
            want.extend_from_slice(piece);
        }
        writer.finish();
        let posts = posts.lock().expect("posts");
        let got: Vec<u8> = posts
            .iter()
            .flat_map(|(_, body)| body.iter().copied())
            .collect();
        assert_eq!(got, want);
        assert!(posts
            .iter()
            .all(|(_, body)| !body.is_empty() && body.len() <= 7));
    }

    /// A stream-up dial uploads the whole payload before the downlink carries a byte: the two halves are independent, and the upload's `0` terminator ends the session the downlink reads from.
    #[test]
    fn a_stream_up_dial_uploads_before_its_downlink() {
        let settings = packet_settings(XhttpMode::StreamUp);
        let down_listener = crate::conn::test_bind("127.0.0.1:0").expect("binds downlink");
        let up_listener = crate::conn::test_bind("127.0.0.1:0").expect("binds uplink");
        let down_port = down_listener.local_addr().expect("addr").port();
        let up_port = up_listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (mut down, _) = down_listener.accept().expect("accepts the downlink");
            let (get, _) = take_head(&mut down);
            let (mut up, _) = up_listener.accept().expect("accepts the uplink");
            let head = head_text(&mut up);
            let mut body = Vec::new();
            loop {
                let mut line = Vec::new();
                let mut byte = [0u8; 1];
                while !line.ends_with(b"\r\n") {
                    up.read_exact(&mut byte).expect("reads a chunk line");
                    line.push(byte[0]);
                }
                let size = usize::from_str_radix(
                    std::str::from_utf8(&line[..line.len() - 2])
                        .expect("ascii size")
                        .trim(),
                    16,
                )
                .expect("a chunk size");
                if size == 0 {
                    break;
                }
                let mut data = vec![0u8; size + 2];
                up.read_exact(&mut data).expect("reads the chunk");
                body.extend_from_slice(&data[..size]);
            }
            let post_line = head
                .lines()
                .next()
                .and_then(|l| l.split(' ').nth(1).map(String::from));
            (get, post_line, body)
        });
        let down = Connection::connect(("127.0.0.1", down_port)).expect("connects the downlink");
        let up = Connection::connect(("127.0.0.1", up_port)).expect("connects the uplink");
        let (_reader, writer) =
            connect_dual(down, up, "127.0.0.1", &settings).expect("the dial is answered");
        assert!(writer.send(b"ping"));
        writer.finish();
        let (get, post, body) = server.join().expect("joins");
        let session = get
            .strip_prefix("/share/")
            .expect("the session rides the path");
        assert_eq!(
            post,
            Some(format!("/share/{session}")),
            "the upload rides the downlink's own session"
        );
        assert_eq!(
            body, b"ping",
            "the upload carried the payload before the downlink spoke"
        );
    }

    /// `uplinkDataPlacement`'s other two arms: the whole packet is one base64url string split at `uplinkChunkSize` points across `X-Data-{i}` headers or `x_data_{i}` cookies, the body stays empty, and `uplinkHTTPMethod` picks the request line.
    #[test]
    fn a_packet_up_dial_honours_header_and_cookie_placement() {
        let payload: Vec<u8> = (0..200usize).map(|i| (i as u8).wrapping_mul(97)).collect();
        for (placement, key, method) in [("header", "X-Data", "GET"), ("cookie", "x_data", "POST")]
        {
            let settings = settings_from(&format!(
                r#"{{"streamSettings": {{"network": "xhttp", "xhttpSettings": {{
                    "path": "/up", "mode": "packet-up", "uplinkDataPlacement": "{placement}",
                    "uplinkChunkSize": 64, "uplinkHTTPMethod": "{method}"}}}}}}"#
            ));
            assert_eq!(settings.uplink_data_key, key);
            assert_eq!(settings.uplink_chunk, (64, 64));
            let down_listener = crate::conn::test_bind("127.0.0.1:0").expect("binds downlink");
            let up_listener = crate::conn::test_bind("127.0.0.1:0").expect("binds uplink");
            let down_port = down_listener.local_addr().expect("addr").port();
            let up_port = up_listener.local_addr().expect("addr").port();
            let server = thread::spawn(move || {
                let (mut down, _) = down_listener.accept().expect("accepts the downlink");
                let _ = head_text(&mut down);
                down.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
                    .expect("answers the downlink");
                let (mut up, _) = up_listener.accept().expect("accepts the uplink");
                let head = head_text(&mut up);
                up.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .expect("answers the packet");
                head
            });
            let down =
                Connection::connect(("127.0.0.1", down_port)).expect("connects the downlink");
            let up = Connection::connect(("127.0.0.1", up_port)).expect("connects the uplink");
            let (_reader, writer) =
                connect_dual(down, up, "127.0.0.1", &settings).expect("the dial is answered");
            assert!(writer.send(&payload), "{placement}: the packet left");
            let head = server.join().expect("joins");
            assert!(
                head.starts_with(&format!("{method} /up/")),
                "{placement}: the uplink method: {head}"
            );
            assert_eq!(
                head.contains("Content-Length"),
                method == "POST",
                "{placement}: only a bodyless POST carries a zero length: {head}"
            );
            let (encoded, parts) = if placement == "header" {
                let mut joined = String::new();
                let mut parts = 0;
                for i in 0.. {
                    let name = format!("{key}-{i}: ");
                    let Some(line) = head.lines().find(|line| line.starts_with(&name)) else {
                        break;
                    };
                    joined.push_str(&line[name.len()..]);
                    parts += 1;
                }
                (joined, parts)
            } else {
                let cookie = head
                    .lines()
                    .find(|line| line.starts_with("Cookie: ") && line.contains("x_data_0="))
                    .expect("the data cookies ride one Cookie line");
                let mut joined = String::new();
                let mut parts = 0;
                for i in 0.. {
                    let name = format!("{key}_{i}=");
                    let Some(part) = cookie[8..].split("; ").find(|part| part.starts_with(&name))
                    else {
                        break;
                    };
                    joined.push_str(&part[name.len()..]);
                    parts += 1;
                }
                (joined, parts)
            };
            assert_eq!(
                parts,
                encoded.len().div_ceil(64),
                "{placement}: the parts are not the configured size: {head}"
            );
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&encoded)
                .expect("base64url parts");
            assert_eq!(decoded, payload, "{placement}: the parts decoded wrong");
        }
    }

    /// The two halves of one process over a socket: `connect` writes the head its own random padding asks for, and the hub built from the same config has to answer it. Before this fix the hub answered `HTTP/1.1 400` to that head at every connection count, which is why `vless-xhttp-down-8` completed no flow.
    #[test]
    fn the_dialer_and_its_own_hub_complete_on_loopback() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share"}}}"#,
        );
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let Ok(read) = stream.try_clone() else {
                return;
            };
            let (mut reader, writer) = accept_split_with_settings(read, stream, &settings, None)
                .expect("the hub served the dial");
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).expect("reads the uplink");
            assert!(writer.send(b"pong"));
            writer.finish();
        });
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, writer) = connect(stream, "127.0.0.1", "/share", &[], &"X".repeat(500))
            .expect("the dial was answered");
        assert!(writer.send(b"ping"));
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("reads the downlink");
        assert_eq!(&buf, b"pong");
        server.join().expect("joins");
    }

    /// The pad the dial writes is the one the hub validates: a configured range reaches the head, where a fixed 100–900 run would answer 400 against a hub told to take four bytes.
    #[test]
    fn the_dial_pad_is_the_configured_range_not_a_fixed_run() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share", "mode": "stream-one", "xPaddingBytes": "4-4"}}}"#,
        );
        assert_eq!(settings.x_padding_bytes, (4, 4));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut sink = Sink(Arc::clone(&seen));
        let pad = referer_pad_value(&settings);
        send_dial_head(
            &mut sink,
            "front.example",
            &dial_path(&settings),
            &settings.headers,
            &pad,
        )
        .expect("head");
        let head = String::from_utf8(seen.lock().expect("sink").clone()).expect("utf8");
        assert!(
            head.contains("?x_padding=XXXX\r\n"),
            "the dial wrote a run its own hub refuses: {head}"
        );
    }

    /// A plaintext session's upload lane must park on a poll quantum: the boxed window cannot arm the socket itself, and an unarmed read holds its worker for as long as the peer keeps the body open, which is the whole download.
    #[test]
    fn a_plaintext_session_upload_parks_instead_of_holding_its_worker() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share", "mode": "stream-one"}}}"#,
        );
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let Ok(read) = stream.try_clone() else {
                return;
            };
            let Some((mut reader, _writer)) =
                accept_split_with_settings(read, stream, &settings, None)
            else {
                return;
            };
            let mut buf = [0u8; 16];
            let _step = crate::proxy::RelayStep::enter();
            let parked = match reader.read(&mut buf) {
                Ok(_) => false,
                Err(error) => crate::proxy::is_timeout(&error),
            };
            tx.send(parked).expect("sends");
        });
        let mut client = Connection::connect(("127.0.0.1", port)).expect("connects");
        let head = format!(
            "POST /share HTTP/1.1\r\nHost: h\r\nReferer: {}\r\nTransfer-Encoding: chunked\r\n\r\n",
            "http://127.0.0.1/share?x_padding=".to_owned() + &"X".repeat(500)
        );
        client.write_all(head.as_bytes()).expect("head");
        assert!(
            rx.recv_timeout(std::time::Duration::from_secs(2))
                .expect("the upload lane parked instead of blocking its worker"),
            "the session's socket carries no poll quantum"
        );
    }

    /// The relaxation is only for a mode nobody stated: a `packet-up` hub still refuses a session-less POST, so the knobs demonstrably reach the accept path.
    #[test]
    fn a_stated_mode_still_refuses_the_session_less_post() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share", "mode": "packet-up"}}}"#,
        );
        assert_eq!(settings.mode_source, ModeSource::Stated);
        let head = format!(
            "POST /share HTTP/1.1\r\nHost: h\r\nReferer: {}\r\nTransfer-Encoding: chunked\r\n\r\n",
            "http://127.0.0.1/share?x_padding=".to_owned() + &"X".repeat(500)
        );
        assert_eq!(
            status_through_core(&head, &settings),
            400,
            "a hub told packet-up served a stream-one POST"
        );
    }

    /// An auto hub keeps serving both shapes it resolved to: the downlink GET and the packet POST it was already answering are still answered, so gating on a stated mode narrowed nothing.
    #[test]
    fn an_unstated_mode_still_serves_the_shape_it_resolved_to() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share"}}}"#,
        );
        assert_eq!(settings.mode_source, ModeSource::Auto);
        let referer = "http://127.0.0.1/share?x_padding=".to_owned() + &"X".repeat(500);
        let post = format!(
            "POST /share/autohub/0 HTTP/1.1\r\nHost: h\r\nReferer: {referer}\r\nContent-Length: 1\r\n\r\n"
        );
        assert_eq!(
            status_through_core(&post, &settings),
            200,
            "the packet shape an auto hub resolved to stopped being served"
        );
        let get = format!("GET /share/autohub HTTP/1.1\r\nHost: h\r\nReferer: {referer}\r\n\r\n");
        assert_eq!(
            status_through_core(&get, &settings),
            200,
            "the downlink shape an auto hub resolved to stopped being served"
        );
    }

    /// A peer that sends part of a head and stops ends at the head's own budget: nothing has armed the socket when the first byte lands, so without one the slot waits forever.
    #[test]
    fn a_partial_head_ends_at_its_budget_instead_of_holding_the_slot() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share"}}}"#,
        );
        crate::budgets::apply(&crate::config::Budgets {
            head_arrival: Some(std::time::Duration::from_millis(100)),
            ..Default::default()
        });
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = std::sync::mpsc::channel();
        crate::budgets::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let Ok(read) = stream.try_clone() else {
                return;
            };
            let began = std::time::Instant::now();
            let served = accept_split_with_settings(read, stream, &settings, None);
            let _ = tx.send((served.is_none(), began.elapsed()));
        });
        let mut client = Connection::connect(("127.0.0.1", port)).expect("connects");
        client
            .write_all(b"GET /share HTTP/1.1\r\nHost: h")
            .expect("writes a partial head");
        let (refused, took) = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the slot ended");
        assert!(refused, "a partial head was served");
        assert!(
            took < std::time::Duration::from_secs(5),
            "the head waited {took:?}"
        );
    }

    /// A `stream-one` hub still refuses the separate downlink GET, so the relaxation reaches the mode nobody stated and not the check itself.
    #[test]
    fn a_stated_stream_one_still_refuses_the_session_get() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share", "mode": "stream-one"}}}"#,
        );
        assert_eq!(settings.mode_source, ModeSource::Stated);
        let referer = "http://127.0.0.1/share?x_padding=".to_owned() + &"X".repeat(500);
        let get = format!("GET /share/autohub HTTP/1.1\r\nHost: h\r\nReferer: {referer}\r\n\r\n");
        assert_eq!(
            status_through_core(&get, &settings),
            400,
            "a hub told stream-one served the downlink GET"
        );
    }

    /// The carrier is the owner now: a relay's upload half-closes into `XhttpWriter::finish` (`0\r\n\r\n`), which ends the session and lifts the park, so an `auto` hub serves the stream-up shape like the reference (`hub.go:154` gates only a stated mode).
    #[test]
    fn an_unstated_mode_serves_the_shape_once_a_carrier_owns_the_upload() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share"}}}"#,
        );
        let listener = Arc::new(crate::conn::test_bind("127.0.0.1:0").expect("binds"));
        let port = listener.local_addr().expect("addr").port();
        let referer = "http://127.0.0.1/share?x_padding=".to_owned() + &"X".repeat(500);

        let serve = move |settings: XhttpSettings| {
            let listener = Arc::clone(&listener);
            thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accepts");
                let Ok(read) = stream.try_clone() else {
                    return;
                };
                let (mut head, at) = crate::proxy::read_exact_head(
                    &mut stream,
                    HEAD_LIMIT,
                    crate::budgets::head_arrival(),
                )
                .expect("head");
                let prefix = head.split_off(at);
                if let Served::Session(mut reader, writer) = accept_core(
                    &head,
                    prefix,
                    Upload::Read(read),
                    stream,
                    &settings,
                    None,
                    None,
                ) {
                    let mut drained = Vec::new();
                    let _ = reader.read_to_end(&mut drained);
                    writer.finish();
                }
            })
        };

        let down = serve(settings.clone());
        let up = serve(settings.clone());

        let mut get = Connection::connect(("127.0.0.1", port)).expect("connects the downlink");
        get.write_all(
            format!("GET /share/autohub HTTP/1.1\r\nHost: h\r\nReferer: {referer}\r\n\r\n")
                .as_bytes(),
        )
        .expect("writes the GET");

        let mut uplink = Connection::connect(("127.0.0.1", port)).expect("connects the uplink");
        uplink.write_all(
            format!("POST /share/autohub HTTP/1.1\r\nHost: h\r\nReferer: {referer}\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
                .as_bytes(),
        )
        .expect("writes the POST");

        let mut answered = Vec::new();
        uplink.read_to_end(&mut answered).expect("reads the answer");
        assert!(
            String::from_utf8_lossy(&answered[..answered.len().min(12)]).starts_with("HTTP/1.1 2"),
            "an auto hub took the stream-up shape once a carrier owned the upload, wrote {answered:?}"
        );
        down.join().expect("joins the downlink service");
        up.join().expect("joins the uplink service");
    }

    /// A session takes one stream-up body, as the reference's upload queue does: a second POST is
    /// answered 409 instead of 200, because a 200 promises bytes the reader never takes.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn a_second_stream_up_upload_is_refused_before_it_is_acknowledged() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share", "mode": "stream-up"}}}"#,
        );
        let listener = Arc::new(crate::conn::test_bind("127.0.0.1:0").expect("binds"));
        let port = listener.local_addr().expect("addr").port();
        let serve = move || {
            let listener = Arc::clone(&listener);
            let settings = settings.clone();
            thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accepts");
                let Ok(read) = stream.try_clone() else {
                    return;
                };
                let (mut head, at) = crate::proxy::read_exact_head(
                    &mut stream,
                    HEAD_LIMIT,
                    crate::budgets::head_arrival(),
                )
                .expect("head");
                let prefix = head.split_off(at);
                if let Served::Session(mut reader, writer) = accept_core(
                    &head,
                    prefix,
                    Upload::Read(read),
                    stream,
                    &settings,
                    None,
                    None,
                ) {
                    let mut buf = [0u8; 64];
                    loop {
                        match reader.read(&mut buf) {
                            Ok(0) => break,
                            Ok(_) => {}
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                            Err(_) => break,
                        }
                    }
                    writer.finish();
                }
            })
        };

        let referer = format!("http://127.0.0.1/share?x_padding={}", "X".repeat(500));
        let declared = serve();
        let mut down = Connection::connect(("127.0.0.1", port)).expect("connects the downlink");
        down.write_all(
            format!("GET /share/twouploads HTTP/1.1\r\nHost: h\r\nReferer: {referer}\r\n\r\n")
                .as_bytes(),
        )
        .expect("writes the GET");
        assert!(
            ok_status_text(&head_text(&mut down)),
            "the downlink was not answered"
        );

        let first = serve();
        let mut uplink =
            Connection::connect(("127.0.0.1", port)).expect("connects the first uplink");
        uplink
            .write_all(
                format!(
                    "POST /share/twouploads HTTP/1.1\r\nHost: h\r\nReferer: {referer}\r\nTransfer-Encoding: chunked\r\n\r\n"
                )
                .as_bytes(),
            )
            .expect("writes the first POST");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !get_or_create_session("twouploads")
            .state
            .lock()
            .expect("session lock")
            .upload_attached
        {
            assert!(
                std::time::Instant::now() < deadline,
                "the upload was never attached"
            );
            thread::sleep(Duration::from_millis(5));
        }

        let second = serve();
        let mut refused = Connection::connect(("127.0.0.1", port)).expect("connects the second");
        refused
            .write_all(
                format!(
                    "POST /share/twouploads HTTP/1.1\r\nHost: h\r\nReferer: {referer}\r\nTransfer-Encoding: chunked\r\n\r\n"
                )
                .as_bytes(),
            )
            .expect("writes the second POST");
        let answer = head_text(&mut refused);
        assert!(
            answer.starts_with("HTTP/1.1 409"),
            "a second stream-up upload was acknowledged, wrote {answer:?}"
        );

        uplink
            .write_all(b"0\r\n\r\n")
            .expect("ends the first upload");
        let answered = head_text(&mut uplink);
        assert!(
            ok_status_text(&answered),
            "the first upload was never acknowledged, wrote {answered:?}"
        );
        first.join().expect("joins the first service");
        second.join().expect("joins the second service");
        declared.join().expect("joins the downlink service");
    }

    /// A packet-up session whose downlink never arrives holds its packets forever; a later bind must start fresh rather than read a sequence from a flow that already stalled.
    #[test]
    fn a_packet_up_session_with_no_downlink_is_replaced_after_the_stall() {
        crate::budgets::apply(&crate::config::Budgets {
            relay_stall: Some(std::time::Duration::from_millis(200)),
            ..Default::default()
        });
        let stale = get_or_create_session("packet-up-no-downlink");
        assert!(
            stale.push_packet(1, b"stale".to_vec(), 16),
            "the packet is buffered"
        );
        thread::sleep(std::time::Duration::from_millis(250));
        let fresh = get_or_create_session("packet-up-no-downlink");
        let packets = fresh.state.lock().expect("session lock").packets.len();
        end_session("packet-up-no-downlink");
        crate::budgets::clear();
        assert!(
            !Arc::ptr_eq(&stale, &fresh),
            "a session with no downlink outlived the stall and kept its stale sequence"
        );
        assert_eq!(packets, 0, "the replacement starts with no packets");
    }

    /// The stall sweep is about silence, not age: a packet-up session that keeps receiving packets
    /// past the budget is still alive and must keep the same sequence.
    #[test]
    fn an_active_packet_up_session_is_not_swept_by_its_age() {
        crate::budgets::apply(&crate::config::Budgets {
            relay_stall: Some(std::time::Duration::from_millis(500)),
            ..Default::default()
        });
        let id = "packet-up-active";
        let session = get_or_create_session(id);
        // A silence ten times inside the budget keeps a loaded runner's descheduling out of the verdict.
        for seq in 0..12u64 {
            thread::sleep(std::time::Duration::from_millis(50));
            assert!(
                session.push_packet(seq, vec![seq as u8], 16),
                "the active packet is accepted"
            );
            let current = get_or_create_session(id);
            assert!(
                Arc::ptr_eq(&session, &current),
                "an active packet-up session was swept after {}ms",
                (seq + 1) * 50
            );
        }
        end_session(id);
        crate::budgets::clear();
    }

    /// A live lookup is a map read until this thread's stall budget elapses.
    #[test]
    fn a_live_session_lookup_does_not_sweep_the_table() {
        crate::budgets::apply(&crate::config::Budgets {
            relay_stall: Some(std::time::Duration::from_secs(3_600)),
            ..Default::default()
        });
        let id = "packet-up-live-no-sweep";
        let session = get_or_create_session(id);
        SWEEPS.with(|sweeps| sweeps.set(0));
        for _ in 0..64 {
            assert!(Arc::ptr_eq(&session, &get_or_create_session(id)));
        }
        let swept = SWEEPS.with(std::cell::Cell::get);
        end_session(id);
        crate::budgets::clear();
        assert_eq!(swept, 0, "a live lookup swept the session table");
    }

    /// A reader left over from an ended session must not remove the fresh session that reused its id:
    /// the map's owner is the session the entry points at, not whoever drops last with the same key.
    #[test]
    fn a_stale_reader_drop_keeps_the_session_that_reused_its_id() {
        let id = "reused-xhttp-session";
        let stale = get_or_create_session(id);
        let reader = SessionReader::new(Arc::clone(&stale), id.to_owned());
        end_session(id);
        let fresh = get_or_create_session(id);
        assert!(!Arc::ptr_eq(&stale, &fresh), "the id was reused");
        drop(reader);
        let carried = session_is_carried(id);
        end_session(id);
        assert!(
            carried,
            "the stale reader's drop removed the replacement session"
        );
    }

    #[test]
    fn a_stream_up_session_with_no_downlink_ends_at_its_idle_budget() {
        let session = get_or_create_session("post-only-idle");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = {
            let session = Arc::clone(&session);
            thread::spawn(move || {
                session.wait_ended_for(std::time::Duration::from_millis(200));
                let _ = done_tx.send(());
            })
        };
        done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("a post-only session returns instead of parking its handler");
        worker.join().expect("joins");
        assert!(
            !sessions()
                .lock()
                .expect("sessions lock")
                .contains_key("post-only-idle"),
            "the idle session is removed"
        );
    }

    #[test]
    fn a_stream_up_session_with_no_downlink_writes_its_deferred_answer() {
        let session = get_or_create_session("post-only-answer");
        let (sent_tx, sent_rx) = std::sync::mpsc::channel();
        session.defer_response_at(
            std::time::Instant::now() + std::time::Duration::from_millis(100),
            Box::new(move || {
                let _ = sent_tx.send(());
            }),
        );
        sent_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the deferred answer is written when the session expires");
        assert!(
            !sessions()
                .lock()
                .expect("sessions lock")
                .contains_key("post-only-answer"),
            "the idle session is removed"
        );
    }

    #[test]
    fn a_stream_up_session_with_a_downlink_waits_for_it() {
        let session = bound_session("post-with-downlink", None, true);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = {
            let session = Arc::clone(&session);
            thread::spawn(move || {
                session.wait_ended_for(std::time::Duration::from_millis(200));
                let _ = done_tx.send(());
            })
        };
        assert!(
            done_rx
                .recv_timeout(std::time::Duration::from_millis(500))
                .is_err(),
            "a bound downlink keeps the session open past the idle budget"
        );
        end_session("post-with-downlink");
        assert!(
            done_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .is_ok(),
            "ending the session wakes the post"
        );
        worker.join().expect("joins");
    }

    /// The reference writes its 200 but Go holds it until the handler returns after `httpSC.Wait()`
    /// (hub.go:237); a client that reads it earlier closes the upload body (client.go:90).
    #[allow(clippy::too_many_lines)]
    #[test]
    fn a_stream_up_post_is_answered_only_after_its_session_ends() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share", "mode": "stream-up"}}}"#,
        );
        let referer = format!("http://127.0.0.1/share?x_padding={}", "X".repeat(500));
        let down_listener = crate::conn::test_bind("127.0.0.1:0").expect("binds the downlink");
        let down_port = down_listener.local_addr().expect("addr").port();
        let up_listener = crate::conn::test_bind("127.0.0.1:0").expect("binds the uplink");
        let up_port = up_listener.local_addr().expect("addr").port();

        let (end_down, hold_down) = std::sync::mpsc::channel::<()>();
        let down = {
            let settings = settings.clone();
            thread::spawn(move || {
                let (mut stream, _) = down_listener.accept().expect("accepts the downlink");
                let Ok(read) = stream.try_clone() else {
                    return;
                };
                let (mut head, at) = crate::proxy::read_exact_head(
                    &mut stream,
                    HEAD_LIMIT,
                    crate::budgets::head_arrival(),
                )
                .expect("head");
                let prefix = head.split_off(at);
                let Served::Session(mut reader, writer) = accept_core(
                    &head,
                    prefix,
                    Upload::Read(read),
                    stream,
                    &settings,
                    None,
                    None,
                ) else {
                    panic!("the downlink was not a session");
                };
                let mut buf = [0u8; 64];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => break,
                    }
                }
                let _ = hold_down.recv_timeout(Duration::from_secs(5));
                drop(reader);
                writer.finish();
            })
        };
        let up = {
            let settings = settings.clone();
            thread::spawn(move || {
                let (mut stream, _) = up_listener.accept().expect("accepts the uplink");
                let Ok(read) = stream.try_clone() else {
                    return;
                };
                let (mut head, at) = crate::proxy::read_exact_head(
                    &mut stream,
                    HEAD_LIMIT,
                    crate::budgets::head_arrival(),
                )
                .expect("head");
                let prefix = head.split_off(at);
                let _ = accept_core(
                    &head,
                    prefix,
                    Upload::Read(read),
                    stream,
                    &settings,
                    None,
                    None,
                );
            })
        };

        let mut get = Connection::connect(("127.0.0.1", down_port)).expect("connects the downlink");
        get.write_all(
            format!("GET /share/up-late HTTP/1.1\r\nHost: h\r\nReferer: {referer}\r\n\r\n")
                .as_bytes(),
        )
        .expect("writes the GET");
        let answered = head_text(&mut get);
        assert!(
            ok_status_text(&answered),
            "the downlink was not answered, wrote {answered:?}"
        );

        let mut uplink = Connection::connect(("127.0.0.1", up_port)).expect("connects the uplink");
        uplink
            .write_all(
                format!("POST /share/up-late HTTP/1.1\r\nHost: h\r\nReferer: {referer}\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nz\r\n0\r\n\r\n")
                    .as_bytes(),
            )
            .expect("writes the POST");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !get_or_create_session("up-late")
            .state
            .lock()
            .expect("session lock")
            .upload_attached
        {
            assert!(
                std::time::Instant::now() < deadline,
                "the upload was never attached"
            );
            thread::sleep(Duration::from_millis(5));
        }
        thread::sleep(Duration::from_millis(50));
        uplink
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("arms the probe");
        let mut probe = [0u8; 1];
        match uplink.read(&mut probe) {
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) => {}
            other => panic!("the upload was answered before its session ended: {other:?}"),
        }

        let _ = end_down.send(());
        uplink
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("rearms the read");
        let mut answer = Vec::new();
        uplink.read_to_end(&mut answer).expect("reads the answer");
        assert!(
            ok_status_text(&String::from_utf8_lossy(&answer)),
            "the upload was never answered, wrote {answer:?}"
        );
        down.join().expect("joins the downlink");
        up.join().expect("joins the uplink");
    }

    /// A poll grain from the upload keeps the session open; a socket deadline still ends it.
    #[test]
    fn a_poll_grain_keeps_the_session_and_a_deadline_ends_it() {
        struct Once(bool, std::io::ErrorKind);
        impl Read for Once {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if !self.0 {
                    self.0 = true;
                    return Err(std::io::Error::from(self.1));
                }
                buf[..2].copy_from_slice(b"hi");
                Ok(2)
            }
        }
        let session = get_or_create_session("poll-grain-upload");
        session.set_upload(Box::new(Once(false, std::io::ErrorKind::WouldBlock)), None);
        let mut reader = SessionReader::new(Arc::clone(&session), "poll-grain-upload".to_owned());
        let mut buf = [0u8; 8];
        let error = reader.read(&mut buf).expect_err("the poll grain");
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        assert!(
            !session.state.lock().expect("session lock").ended,
            "a poll grain ended the session"
        );
        assert_eq!(reader.read(&mut buf).expect("the upload resumes"), 2);
        assert_eq!(&buf[..2], b"hi");
        end_session("poll-grain-upload");

        let ended = get_or_create_session("deadline-upload");
        ended.set_upload(Box::new(Once(false, std::io::ErrorKind::TimedOut)), None);
        let mut reader = SessionReader::new(Arc::clone(&ended), "deadline-upload".to_owned());
        assert!(reader.read(&mut buf).is_err());
        assert!(
            ended.state.lock().expect("session lock").ended,
            "a socket deadline left the session open"
        );
        end_session("deadline-upload");
    }

    /// A plain H1 upload socket polls on a `RELAY_POLL` deadline; with the descriptor known, that
    /// deadline parks the lane on it instead of ending a session whose downlink is still moving bytes.
    #[test]
    fn a_socket_deadline_on_a_known_upload_keeps_the_session() {
        struct Timeout;
        impl Read for Timeout {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::TimedOut))
            }
        }
        let session = get_or_create_session("known-upload-deadline");
        session.set_upload(Box::new(Timeout), Some(0));
        let mut reader =
            SessionReader::new(Arc::clone(&session), "known-upload-deadline".to_owned());
        let mut buf = [0u8; 8];
        let error = reader.read(&mut buf).expect_err("the socket poll");
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        assert!(
            !session.state.lock().expect("session lock").ended,
            "a socket poll on a known upload ended the session"
        );
        end_session("known-upload-deadline");
    }

    /// A TLS half's deadline surfaces as an `io::Error` of another kind; it is a poll, not the end.
    #[test]
    fn a_tls_timeout_without_a_descriptor_keeps_the_session() {
        struct Tls;
        impl Read for Tls {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(ferrox_core::tls::TlsError::Timeout.into())
            }
        }
        let session = get_or_create_session("tls-timeout-upload");
        session.set_upload(Box::new(Tls), None);
        let mut reader = SessionReader::new(Arc::clone(&session), "tls-timeout-upload".to_owned());
        assert!(reader.read(&mut [0u8; 8]).is_err());
        assert!(
            !session.state.lock().expect("session lock").ended,
            "a TLS timeout ended the session"
        );
        end_session("tls-timeout-upload");
    }

    /// Both parks — the uplink's `wait_ended` and the downlink's `Read::read` — wait on `session.cv`, and until a carrier owned the session the only thing that ever notified it was a `SessionReader`'s Drop. A client that opened one half and died left the other half's thread parked for the life of the process.
    #[test]
    fn a_carrier_death_lifts_both_parks() {
        let (down_done, down_waiting) = std::sync::mpsc::channel();
        let down = get_or_create_session("parked-downlink");
        thread::spawn(move || {
            let mut reader = SessionReader::new(down, "parked-downlink".to_owned());
            let mut buf = [0u8; 8];
            // Nothing is ever posted to this session, so this read is the park itself; the poll grain is not the end.
            let got = loop {
                match reader.read(&mut buf) {
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    outcome => break outcome,
                }
            };
            let _ = down_done.send(got.expect("reads"));
        });
        let (up_done, up_waiting) = std::sync::mpsc::channel();
        let up = get_or_create_session("parked-uplink");
        thread::spawn(move || {
            up.wait_ended();
            let _ = up_done.send(());
        });
        thread::sleep(crate::budgets::RELAY_IDLE);
        end_session("parked-downlink");
        end_session("parked-uplink");
        assert_eq!(
            down_waiting.recv_timeout(std::time::Duration::from_secs(5)),
            Ok(0),
            "a parked downlink never saw the end"
        );
        assert!(
            up_waiting
                .recv_timeout(std::time::Duration::from_secs(5))
                .is_ok(),
            "an uplink with no downlink parked its POST thread forever"
        );
    }

    /// A refused packet is a lost one — the downlink pops a strict sequence — so the 500 has to end the session it overflowed: leaving it alive parks the reader on a sequence no peer will resend.
    #[test]
    fn a_refused_packet_ends_the_session_it_overflowed() {
        let node = crate::json::parse(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {
                "path": "/up/", "mode": "packet-up"}}}"#,
        )
        .expect("parses");
        let settings = XhttpSettings::from_json(node.get("streamSettings")).expect("settings");
        let session = get_or_create_session("overflowed");
        for seq in 0..30u64 {
            assert!(
                session.push_packet(seq, vec![seq as u8], 30),
                "thirty fit before the refusal"
            );
        }
        let head = format!(
            "POST /up/overflowed/30 HTTP/1.1\r\nHost: h\r\nReferer: {}\r\nContent-Length: 1\r\n\r\n",
            "http://127.0.0.1/up/?x_padding=".to_owned() + &"X".repeat(128)
        );
        let seen = Arc::new(Mutex::new(Vec::new()));
        assert!(
            matches!(
                accept_core(
                    head.as_bytes(),
                    Vec::new(),
                    Upload::Read(std::io::Cursor::new(vec![30u8])),
                    Sink(Arc::clone(&seen)),
                    &settings,
                    None,
                    None,
                ),
                Served::Closed
            ),
            "a refused packet must not hand the caller a session to read"
        );
        let answered = String::from_utf8(seen.lock().expect("sink").clone())
            .unwrap_or_default()
            .chars()
            .take(12)
            .collect::<String>();
        assert_eq!(answered, "HTTP/1.1 500", "the overflow answered no 500");
        assert!(
            !session_is_carried("overflowed"),
            "the overflowed session stayed alive with its parked reader"
        );
    }

    /// A packet-up uplink is one POST per `scMaxEachPostBytes`, not one per TCP connection: the reference hub answers a request and waits for the next on the same socket (`hub.go:562` sets a 4 s read-header timeout, it does not close). Answering once and dropping the connection costs a handshake per 4 KiB of uplink.
    #[test]
    fn one_connection_carries_the_packet_up_uplink() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/up", "mode": "packet-up"}}}"#,
        );
        let referer = "http://127.0.0.1/up?x_padding=".to_owned() + &"X".repeat(500);
        let post = |seq: u64, body: &str| {
            format!(
                "POST /up/wire/{seq} HTTP/1.1\r\nHost: h\r\nReferer: {referer}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",
                body.len()
            )
        };
        let seen = Arc::new(Mutex::new(Vec::new()));
        let served = accept_split_with_settings(
            std::io::Cursor::new(format!("{}{}", post(0, "ping"), post(1, "pong")).into_bytes()),
            Sink(Arc::clone(&seen)),
            &settings,
            None,
        );
        let text = String::from_utf8(seen.lock().expect("sink").clone()).unwrap_or_default();
        assert_eq!(
            text.matches("HTTP/1.1 200 OK").count(),
            2,
            "the second post arrived on a connection the first one closed"
        );
        assert!(
            served.is_none(),
            "an uplink with nothing left to read owns no session"
        );
        let mut reader = SessionReader::new(get_or_create_session("wire"), "wire".to_owned());
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("the first packet");
        assert_eq!(&buf, b"ping", "the first post reached no session");
        reader.read_exact(&mut buf).expect("the second packet");
        assert_eq!(&buf, b"pong", "the second post reached no session");
    }

    /// The packet can ride `X-Data-{i}` headers or `x_data_{i}` cookies instead of the body: the client base64url-encodes the *whole* packet and splits that one string at random points (`config.go:66-94`), and the hub joins the parts and decodes once (`hub.go:249-285`) — so a part boundary lands mid-group and only the joined tail carries the remainder.
    #[test]
    fn a_packet_split_across_data_parts_reaches_the_session_whole() {
        let packet: Vec<u8> = (0..200usize).map(|i| (i as u8).wrapping_mul(97)).collect();
        let mut encoded = String::new();
        ferrox_core::transport::early_encode_into(&mut encoded, &packet);
        let cuts = [0usize, 41, 97, encoded.len()];
        for (placement, sid) in [("header", "data_headers"), ("cookie", "data_cookies")] {
            let settings = settings_from(&format!(
                r#"{{"streamSettings": {{"network": "xhttp", "xhttpSettings": {{
                    "path": "/up", "mode": "packet-up", "uplinkDataPlacement": "{placement}"}}}}}}"#
            ));
            let referer = "http://127.0.0.1/up?x_padding=".to_owned() + &"X".repeat(500);
            let (first, second, third) = (
                &encoded[cuts[0]..cuts[1]],
                &encoded[cuts[1]..cuts[2]],
                &encoded[cuts[2]..cuts[3]],
            );
            let parts = if placement == "header" {
                format!("X-Data-0: {first}\r\nX-Data-1: {second}\r\nX-Data-2: {third}\r\n")
            } else {
                format!("Cookie: x_data_0={first};x_data_1={second};x_data_2={third}\r\n")
            };
            let head = format!(
                "POST /up/{sid}/0 HTTP/1.1\r\nHost: h\r\nReferer: {referer}\r\n{parts}Content-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let seen = Arc::new(Mutex::new(Vec::new()));
            assert!(
                matches!(
                    accept_core(
                        head.as_bytes(),
                        Vec::new(),
                        Upload::Read(std::io::Cursor::new(Vec::new())),
                        Sink(Arc::clone(&seen)),
                        &settings,
                        None,
                        None,
                    ),
                    Served::Closed
                ),
                "{placement}: the parts left a session for the caller to carry"
            );
            // Asserted before the read: a refusal would otherwise park `read_exact` on a packet that never arrives.
            let answered =
                String::from_utf8(seen.lock().expect("sink").clone()).unwrap_or_default();
            assert!(
                answered.starts_with("HTTP/1.1 200"),
                "{placement}: the hub refused the parts: {answered}"
            );
            let mut reader = SessionReader::new(get_or_create_session(sid), sid.to_owned());
            let mut got = vec![0u8; packet.len()];
            reader
                .read_exact(&mut got)
                .unwrap_or_else(|_| panic!("{placement}: the parts reached no reader"));
            assert_eq!(got, packet, "{placement}: the joined parts decoded wrong");
        }
    }

    /// The parts are read off one walk of the head and decoded across their cuts. The join is kept here as the oracle and measured beside the arm, because a per-part lookup re-splits the whole head and the join copies every part.
    #[test]
    fn the_data_parts_decode_off_one_walk_of_the_head() {
        let packet: Vec<u8> = (0..200usize).map(|i| (i as u8).wrapping_mul(97)).collect();
        let mut encoded = String::new();
        ferrox_core::transport::early_encode_into(&mut encoded, &packet);
        for placement in ["header", "cookie"] {
            let settings = settings_from(&format!(
                r#"{{"streamSettings": {{"network": "xhttp", "xhttpSettings": {{
                    "path": "/up", "mode": "packet-up", "uplinkDataPlacement": "{placement}"}}}}}}"#
            ));
            let (first, second, third) = (&encoded[..41], &encoded[41..97], &encoded[97..]);
            let parts = if placement == "header" {
                format!("X-Data-0: {first}\r\nX-Data-1: {second}\r\nX-Data-2: {third}\r\n")
            } else {
                format!("Cookie: x_data_0={first};x_data_1={second};x_data_2={third}\r\n")
            };
            let referer = "http://127.0.0.1/up?x_padding=".to_owned() + &"X".repeat(500);
            let head = format!(
                "POST /up/one_walk/0 HTTP/1.1\r\nHost: h\r\nReferer: {referer}\r\n{parts}Content-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let (decoded, counts) =
                ferrox_core::alloc_count::measure(|| data_parts(&head, &settings));
            assert_eq!(
                decoded.as_deref(),
                Some(&packet[..]),
                "{placement}: the parts are the packet"
            );
            assert_eq!(
                counts.allocs, 3,
                "{placement}: the field list, the part list and the output are the only buffers: {counts:?}"
            );
            let (joined, join_counts) = ferrox_core::alloc_count::measure(|| {
                let key = if settings.uplink_data_key.is_empty() {
                    if placement == "header" {
                        "X-Data".to_owned()
                    } else {
                        "x_data".to_owned()
                    }
                } else {
                    settings.uplink_data_key.clone()
                };
                let mut joined = String::new();
                let mut name = String::with_capacity(key.len() + 4);
                for i in 0.. {
                    name.clear();
                    let _ = std::fmt::write(
                        &mut name,
                        format_args!("{key}{}{i}", if placement == "header" { '-' } else { '_' }),
                    );
                    let hit = if placement == "header" {
                        crate::proxy::header_value(head.as_bytes(), &name)
                    } else {
                        header_cookie(&head, &name)
                    };
                    match hit {
                        Some(v) => joined.push_str(v),
                        None => break,
                    }
                }
                ferrox_core::transport::url_decode(&joined)
            });
            assert_eq!(
                joined.as_deref(),
                Some(&packet[..]),
                "{placement}: the oracle decodes the packet"
            );
            assert_eq!(
                join_counts.allocs, 6,
                "{placement}: the join's key, name, three growth steps and output: {join_counts:?}"
            );
            assert!(
                counts.allocs < join_counts.allocs,
                "{placement}: the join cost {join_counts:?} where one walk cost {counts:?}"
            );
        }
    }

    /// Five digits are not a base64 length and the reference refuses them with a 400; the per-character ladder dropped the last digit and handed a short packet up as if it were whole. The same head with four digits answers 200, so the refusal is the decode's and not the request's shape.
    #[test]
    fn a_trailing_digit_in_the_data_parts_is_refused() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {
                "path": "/up", "mode": "packet-up", "uplinkDataPlacement": "header"}}}"#,
        );
        let referer = "http://127.0.0.1/up?x_padding=".to_owned() + &"X".repeat(500);
        let post = |sid: &str, value: &str| {
            format!(
                "POST /up/{sid}/0 HTTP/1.1\r\nHost: h\r\nReferer: {referer}\r\nX-Data-0: {value}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
        };
        assert_eq!(
            status_through_core(&post("lone_digit", "abcde"), &settings),
            400,
            "a lone trailing digit answered as if it carried a packet"
        );
        assert_eq!(
            status_through_core(&post("four_digits", "Zm9v"), &settings),
            200,
            "the same head with a base64 length was refused too, so the 400 above is not the shape's"
        );
    }

    /// A `Connection: close` request ends the reuse: the hub answers it and lets the socket go, so a client that asked for one request per connection never waits on a half-open one.
    #[test]
    fn a_request_that_says_close_takes_the_connection_with_it() {
        let settings = settings_from(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/up", "mode": "packet-up"}}}"#,
        );
        let referer = "http://127.0.0.1/up?x_padding=".to_owned() + &"X".repeat(500);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let served = accept_split_with_settings(
            std::io::Cursor::new(
                format!(
                    "POST /up/farewell/0 HTTP/1.1\r\nHost: h\r\nReferer: {referer}\r\nContent-Length: 4\r\nConnection: close\r\n\r\npingPOST /up/farewell/1 HTTP/1.1\r\nHost: h\r\nReferer: {referer}\r\nContent-Length: 4\r\n\r\npong"
                )
                .into_bytes(),
            ),
            Sink(Arc::clone(&seen)),
            &settings,
            None,
        );
        let text = String::from_utf8(seen.lock().expect("sink").clone()).unwrap_or_default();
        assert_eq!(
            text.matches("HTTP/1.1 200 OK").count(),
            1,
            "a request that asked to close left the next one unanswered"
        );
        assert!(served.is_none(), "the closed request owned no session");
    }

    #[test]
    fn a_full_packet_heap_refuses_one_more() {
        let session = get_or_create_session("heap-full-test");
        for seq in 0..30u64 {
            assert!(
                session.push_packet(seq, vec![seq as u8], 30),
                "first thirty fit"
            );
        }
        assert!(
            !session.push_packet(30, vec![30], 30),
            "the thirty-first is refused"
        );
        close_session(&session);
    }

    /// A windowed upload hands the relay its own bytes: the read must not route through the copy buffer.
    #[test]
    fn a_windowed_upload_reads_without_a_copy() {
        struct Windowed {
            bytes: Vec<u8>,
            at: usize,
        }

        impl std::io::Read for Windowed {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("the window path read through the copy");
            }
        }

        impl crate::proxy::WindowRead for Windowed {
            fn read_window(&mut self) -> std::io::Result<crate::proxy::Window<'_>> {
                if self.at < self.bytes.len() {
                    self.at = self.bytes.len();
                    return Ok(crate::proxy::Window::one(&self.bytes));
                }
                Ok(crate::proxy::Window::empty())
            }
        }

        let source = Windowed {
            bytes: vec![1, 2, 3, 4],
            at: 0,
        };
        let expected = source.bytes.as_ptr();
        let session = get_or_create_session("windowed-upload-test");
        session.state.lock().expect("session lock").upload = Some(Box::new(source));
        let mut reader = SessionReader::new(Arc::clone(&session), String::new());
        {
            let window = crate::proxy::WindowRead::read_window(&mut reader).expect("window");
            assert_eq!(window.bytes(), &[1, 2, 3, 4]);
            assert_eq!(
                window.bytes().as_ptr(),
                expected,
                "the relay writes the upload's own bytes"
            );
        }
        assert!(crate::proxy::WindowRead::read_window(&mut reader)
            .expect("empty")
            .is_empty());
        close_session(&session);
    }

    /// A finished downlink has already ended the session; a later read must not touch an upload whose peer is gone.
    #[test]
    fn an_ended_session_does_not_read_its_upload() {
        struct Blocked;

        impl std::io::Read for Blocked {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("read a finished session's upload");
            }
        }

        let session = Arc::new(Session {
            state: Mutex::new(SessionState {
                upload: Some(Box::new(crate::proxy::Copied::new(Blocked))),
                upload_attached: false,
                upload_done: false,
                upload_fd: None,
                packets: BTreeMap::new(),
                next_seq: 0,
                ended: true,
                downlink: false,
                last_seen: std::time::Instant::now(),
                response: None,
            }),
            cv: Condvar::new(),
            id: String::new(),
        });
        let mut reader = SessionReader::new(session, String::new());
        let mut byte = [0u8; 1];
        assert_eq!(
            reader.read(&mut byte).expect("ends"),
            0,
            "a finished session ends its read"
        );

        let session = Arc::new(Session {
            state: Mutex::new(SessionState {
                upload: None,
                upload_attached: false,
                upload_done: false,
                upload_fd: None,
                packets: BTreeMap::new(),
                next_seq: 0,
                ended: true,
                downlink: false,
                last_seen: std::time::Instant::now(),
                response: None,
            }),
            cv: Condvar::new(),
            id: String::new(),
        });
        let mut reader = SessionReader::new(session, String::new());
        reader.upload = Some(Box::new(crate::proxy::Copied::new(Blocked)));
        assert_eq!(
            reader.read(&mut byte).expect("ends"),
            0,
            "a retained upload ends when the session does"
        );
    }

    /// A session with no upload and no packet must wake on the relay grain: a sibling that ended has no other way to end this leg.
    #[test]
    fn a_session_read_wakes_when_no_upload_arrives() {
        let session = Arc::new(Session {
            state: Mutex::new(SessionState {
                upload: None,
                upload_attached: false,
                upload_done: false,
                upload_fd: None,
                packets: BTreeMap::new(),
                next_seq: 0,
                ended: false,
                downlink: false,
                last_seen: std::time::Instant::now(),
                response: None,
            }),
            cv: Condvar::new(),
            id: String::new(),
        });
        let mut reader = SessionReader::new(session, String::new());
        let (sender, receiver) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let mut byte = [0u8; 1];
            let _ = sender.send(reader.read(&mut byte).map_err(|error| error.kind()));
        });
        assert_eq!(
            receiver.recv_timeout(std::time::Duration::from_secs(1)),
            Ok(Err(std::io::ErrorKind::WouldBlock)),
            "the reader parked past the relay grain with no sibling wake"
        );
    }

    #[test]
    fn a_packet_window_is_the_sessions_own_buffer() {
        let session = Arc::new(Session {
            state: Mutex::new(SessionState {
                upload: None,
                upload_attached: false,
                upload_done: false,
                upload_fd: None,
                packets: BTreeMap::new(),
                next_seq: 0,
                ended: false,
                downlink: false,
                last_seen: std::time::Instant::now(),
                response: None,
            }),
            cv: Condvar::new(),
            id: String::new(),
        });
        let packet: Vec<u8> = (0u8..64).collect();
        let base = packet.as_ptr();
        assert!(session.push_packet(0, packet, 8));
        let mut reader = SessionReader::new(session, String::new());
        let window = crate::proxy::WindowRead::read_window(&mut reader).unwrap();
        assert_eq!(
            window.bytes().as_ptr(),
            base,
            "the window is the packet's own allocation"
        );
        assert_eq!(window.bytes().len(), 64, "the whole packet is the window");
        assert_eq!(window.parts(), &[(0, 64)]);
    }
}

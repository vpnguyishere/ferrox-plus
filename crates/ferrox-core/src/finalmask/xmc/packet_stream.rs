#[cfg(test)]
use super::protocol::write_long;
use super::protocol::{
    decode_packet_body, read_long, read_varint_with_length, write_packet, write_string, Packet,
    MAX_PACKET_BODY_LENGTH, MAX_STRING_LENGTH,
};
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub const CHANNEL: &str = "xmc:data";
pub const CLIENTBOUND_CUSTOM_PAYLOAD: i32 = 0x01;
pub const SERVERBOUND_CUSTOM_PAYLOAD: i32 = 0x02;
pub const KEEPALIVE_PACKET: i32 = 0x04;
pub const MAX_PACKET_DATA: usize = 24 * 1024;
pub const KEEPALIVE_PERIOD: Duration = Duration::from_secs(15);

const KEEPALIVE_POLL: Duration = Duration::from_millis(100);
const KEEPALIVE_POLLS: usize = 150;

pub struct PacketStream<R, W> {
    reader: Mutex<ReadState<R>>,
    writer: Arc<Mutex<W>>,
    is_client: bool,
    stop: Arc<AtomicBool>,
    keepalive: Option<JoinHandle<()>>,
}

struct ReadState<R> {
    reader: R,
    buffer: Vec<u8>,
    pending: Vec<u8>,
    chunk: [u8; 8192],
}

impl<R: Read> ReadState<R> {
    fn next_packet(&mut self) -> io::Result<Packet> {
        loop {
            if let Some((packet, length)) = buffered_packet(&self.buffer)? {
                self.buffer.drain(..length);
                return Ok(packet);
            }
            match self.reader.read(&mut self.chunk) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "minecraft packet stream closed",
                    ))
                }
                Ok(read) => self.buffer.extend_from_slice(&self.chunk[..read]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
}

fn buffered_packet(buffer: &[u8]) -> io::Result<Option<(Packet, usize)>> {
    let mut data = buffer;
    let (length, prefix) = match read_varint_with_length(&mut data) {
        Ok(field) => field,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    };
    if length < 1 || length as usize > MAX_PACKET_BODY_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("read packet: bad length: {length}"),
        ));
    }
    let total = prefix + length as usize;
    if buffer.len() < total {
        return Ok(None);
    }
    let packet = decode_packet_body(&buffer[prefix..total])?;
    Ok(Some((packet, total)))
}

impl<R, W> PacketStream<R, W>
where
    W: Write + Send + 'static,
{
    pub fn new(reader: R, writer: W, is_client: bool) -> Self {
        let writer = Arc::new(Mutex::new(writer));
        let stop = Arc::new(AtomicBool::new(false));
        let keepalive = if is_client {
            None
        } else {
            Some(spawn_keepalive(Arc::clone(&writer), Arc::clone(&stop)))
        };
        Self {
            reader: Mutex::new(ReadState {
                reader,
                buffer: Vec::new(),
                pending: Vec::new(),
                chunk: [0; 8192],
            }),
            writer,
            is_client,
            stop,
            keepalive,
        }
    }
}

impl<R, W: Write> PacketStream<R, W> {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    pub fn shutdown(&mut self) {
        self.stop();
        if let Some(handle) = self.keepalive.take() {
            let _ = handle.join();
        }
    }

    fn local_custom_payload_id(&self) -> i32 {
        if self.is_client {
            SERVERBOUND_CUSTOM_PAYLOAD
        } else {
            CLIENTBOUND_CUSTOM_PAYLOAD
        }
    }

    fn remote_custom_payload_id(&self) -> i32 {
        if self.is_client {
            CLIENTBOUND_CUSTOM_PAYLOAD
        } else {
            SERVERBOUND_CUSTOM_PAYLOAD
        }
    }

    fn write_keepalive(&self, id: i64) -> io::Result<()> {
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| io::Error::other("packet stream writer poisoned"))?;
        write_packet(&mut *writer, KEEPALIVE_PACKET, &id.to_be_bytes())
            .map_err(|error| io::Error::other(format!("write minecraft keep-alive: {error}")))
    }

    #[cfg(test)]
    pub(crate) fn send_keepalive(&self, id: i64) -> io::Result<()> {
        self.write_keepalive(id)
    }
}

impl<R: Read, W: Write> Read for &PacketStream<R, W> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let mut reader = self
            .reader
            .lock()
            .map_err(|_| io::Error::other("packet stream reader poisoned"))?;
        if !reader.pending.is_empty() {
            let taken = output.len().min(reader.pending.len());
            output[..taken].copy_from_slice(&reader.pending[..taken]);
            reader.pending.drain(..taken);
            return Ok(taken);
        }

        loop {
            let packet = reader.next_packet().map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("read minecraft packet stream: {error}"),
                )
            })?;
            if packet.id == self.remote_custom_payload_id() {
                let Some(payload) = parse_custom_payload(&packet)? else {
                    continue;
                };
                if payload.is_empty() {
                    continue;
                }
                let taken = output.len().min(payload.len());
                output[..taken].copy_from_slice(&payload[..taken]);
                if taken < payload.len() {
                    reader.pending.extend_from_slice(&payload[taken..]);
                }
                return Ok(taken);
            }

            if packet.id == KEEPALIVE_PACKET {
                let mut data = packet.data.as_slice();
                let id = read_long(&mut data).map_err(|error| {
                    io::Error::other(format!("read minecraft keep-alive: {error}"))
                })?;
                if self.is_client {
                    self.write_keepalive(id)?;
                }
            }
        }
    }
}

impl<R: Read, W: Write> Read for PacketStream<R, W> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        (&*self).read(output)
    }
}

impl<R, W: Write> Write for &PacketStream<R, W> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }

        let mut writer = self
            .writer
            .lock()
            .map_err(|_| io::Error::other("packet stream writer poisoned"))?;
        let mut written = 0;
        while written < input.len() {
            let end = (written + MAX_PACKET_DATA).min(input.len());
            let mut data = Vec::with_capacity(CHANNEL.len() + end - written + 1);
            write_string(&mut data, CHANNEL)?;
            data.extend_from_slice(&input[written..end]);
            write_packet(&mut *writer, self.local_custom_payload_id(), &data).map_err(|error| {
                io::Error::other(format!("write minecraft custom payload: {error}"))
            })?;
            written = end;
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer
            .lock()
            .map_err(|_| io::Error::other("packet stream writer poisoned"))?
            .flush()
    }
}

impl<R, W: Write> Write for PacketStream<R, W> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        (&*self).write(input)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&*self).flush()
    }
}

impl<R, W> Drop for PacketStream<R, W> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.keepalive.take() {
            let _ = handle.join();
        }
    }
}

impl<R, W> std::fmt::Debug for PacketStream<R, W> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PacketStream")
            .field("is_client", &self.is_client)
            .field(
                "pending",
                &self
                    .reader
                    .try_lock()
                    .map(|reader| reader.pending.len())
                    .ok(),
            )
            .finish_non_exhaustive()
    }
}

fn parse_custom_payload(packet: &Packet) -> io::Result<Option<&[u8]>> {
    let mut data = packet.data.as_slice();
    let channel = read_channel(&mut data).map_err(|error| {
        io::Error::other(format!("read minecraft custom payload channel: {error}"))
    })?;
    if channel != CHANNEL {
        return Ok(None);
    }
    Ok(Some(data))
}

fn read_channel<'a>(data: &mut &'a [u8]) -> io::Result<&'a str> {
    let (length, _) = read_varint_with_length(data)?;
    if !(0..=MAX_STRING_LENGTH).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("read string: bad length: {length}"),
        ));
    }
    let length = length as usize;
    if length > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "failed to fill whole buffer",
        ));
    }
    let (channel, rest) = data.split_at(length);
    *data = rest;
    std::str::from_utf8(channel)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "read string: invalid utf-8"))
}

fn spawn_keepalive<W: Write + Send + 'static>(
    writer: Arc<Mutex<W>>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let id = AtomicI64::new(0);
        loop {
            for _ in 0..KEEPALIVE_POLLS {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                thread::sleep(KEEPALIVE_POLL);
            }
            let Ok(mut writer) = writer.lock() else {
                return;
            };
            let value = id.fetch_add(1, Ordering::Relaxed) + 1;
            if write_packet(&mut *writer, KEEPALIVE_PACKET, &value.to_be_bytes()).is_err() {
                return;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finalmask::xmc::protocol::{encode_packet, read_packet, read_varint_with_length};
    use std::collections::VecDeque;

    #[derive(Clone)]
    struct Pipe {
        bytes: Arc<Mutex<VecDeque<u8>>>,
    }

    impl Pipe {
        fn new() -> Self {
            Self {
                bytes: Arc::new(Mutex::new(VecDeque::new())),
            }
        }

        fn push(&self, data: &[u8]) {
            self.bytes.lock().expect("pipe").extend(data);
        }

        fn collected(&self) -> Vec<u8> {
            self.bytes.lock().expect("pipe").drain(..).collect()
        }
    }

    impl Read for Pipe {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let mut bytes = self.bytes.lock().expect("pipe");
            let taken = output.len().min(bytes.len());
            for (slot, byte) in output.iter_mut().zip(bytes.drain(..taken)) {
                *slot = byte;
            }
            Ok(taken)
        }
    }

    impl Write for Pipe {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            self.push(input);
            Ok(input.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn frame(id: i32, data: &[u8]) -> Vec<u8> {
        encode_packet(id, data).expect("frame")
    }

    #[test]
    fn writes_split_at_the_payload_limit_and_round_trip_both_ways() {
        let client_out = Pipe::new();
        let server_out = Pipe::new();
        let mut client = PacketStream::new(server_out.clone(), client_out.clone(), true);
        let mut server = PacketStream::new(client_out.clone(), server_out.clone(), false);

        let client_payload: Vec<u8> = (0..60_000).map(|index| (index % 251) as u8).collect();
        let server_payload: Vec<u8> = (0..50_000).map(|index| (index % 239) as u8).collect();

        client.write_all(&client_payload).expect("client writes");
        let mut received = vec![0; client_payload.len()];
        server.read_exact(&mut received).expect("server reads");
        assert_eq!(received, client_payload);

        server.write_all(&server_payload).expect("server writes");
        let mut received = vec![0; server_payload.len()];
        client.read_exact(&mut received).expect("client reads");
        assert_eq!(received, server_payload);

        client.shutdown();
        server.shutdown();
    }

    #[test]
    fn a_write_over_the_limit_becomes_several_frames() {
        let out = Pipe::new();
        let mut stream = PacketStream::new(Pipe::new(), out.clone(), true);
        let payload = vec![7u8; MAX_PACKET_DATA * 2 + 1];
        assert_eq!(stream.write(&payload).expect("writes"), payload.len());

        let wire = out.collected();
        let mut data = wire.as_slice();
        let mut frames = 0;
        let mut recovered = Vec::new();
        while !data.is_empty() {
            let (length, prefix) = read_varint_with_length(&mut data).expect("length");
            let body = &data[..length as usize];
            data = &data[length as usize..];
            let mut body_reader = body;
            let _ = read_varint_with_length(&mut body_reader).expect("id");
            let _ = prefix;
            let packet = Packet {
                id: body[0] as i32,
                data: body[1..].to_vec(),
            };
            let payload = parse_custom_payload(&packet)
                .expect("payload")
                .expect("channel");
            recovered.extend_from_slice(payload);
            frames += 1;
        }
        assert_eq!(frames, 3);
        assert_eq!(recovered, payload);
    }

    #[test]
    fn a_custom_payload_is_a_slice_of_its_frame() {
        let mut data = Vec::new();
        write_string(&mut data, CHANNEL).expect("channel");
        data.extend_from_slice(b"hello");
        let packet = Packet {
            id: CLIENTBOUND_CUSTOM_PAYLOAD,
            data,
        };
        let (payload, counts) = crate::alloc_count::measure(|| {
            parse_custom_payload(&packet)
                .expect("payload")
                .expect("channel")
        });
        assert_eq!(payload, b"hello");
        assert_eq!(
            payload.as_ptr(),
            packet.data[packet.data.len() - payload.len()..].as_ptr(),
            "the payload is the frame's own bytes"
        );
        assert_eq!(counts.allocs, 0, "reading the channel takes no heap");
    }

    #[test]
    fn a_custom_payload_channel_keeps_the_string_rules() {
        let invalid_utf8 = Packet {
            id: CLIENTBOUND_CUSTOM_PAYLOAD,
            data: vec![1, 0xff],
        };
        let error = parse_custom_payload(&invalid_utf8).expect_err("invalid utf-8");
        assert!(error.to_string().contains("read string: invalid utf-8"));

        let too_long = Packet {
            id: CLIENTBOUND_CUSTOM_PAYLOAD,
            data: vec![0x81, 0x20],
        };
        let error = parse_custom_payload(&too_long).expect_err("length over the string cap");
        assert!(error.to_string().contains("read string: bad length: 4097"));

        let truncated = Packet {
            id: CLIENTBOUND_CUSTOM_PAYLOAD,
            data: vec![8, b'x'],
        };
        let error = parse_custom_payload(&truncated).expect_err("short channel");
        assert!(error.to_string().contains("failed to fill whole buffer"));

        let overlong = Packet {
            id: CLIENTBOUND_CUSTOM_PAYLOAD,
            data: vec![0x88, 0x00],
        };
        assert!(
            parse_custom_payload(&overlong).is_err(),
            "a non-canonical length is still refused"
        );
    }

    #[test]
    fn a_client_echoes_keepalives_and_skips_other_payloads() {
        let out = Pipe::new();
        let input = Pipe::new();

        let mut keepalive = Vec::new();
        write_long(&mut keepalive, 42).expect("keepalive");
        input.push(&frame(KEEPALIVE_PACKET, &keepalive));

        let mut foreign = Vec::new();
        write_string(&mut foreign, "minecraft:brand").expect("channel");
        foreign.extend_from_slice(b"ignored");
        input.push(&frame(CLIENTBOUND_CUSTOM_PAYLOAD, &foreign));

        let mut empty = Vec::new();
        write_string(&mut empty, CHANNEL).expect("channel");
        input.push(&frame(CLIENTBOUND_CUSTOM_PAYLOAD, &empty));

        let mut payload = Vec::new();
        write_string(&mut payload, CHANNEL).expect("channel");
        payload.extend_from_slice(b"hello");
        input.push(&frame(CLIENTBOUND_CUSTOM_PAYLOAD, &payload));

        let mut client = PacketStream::new(input, out.clone(), true);
        let mut received = [0; 5];
        client.read_exact(&mut received).expect("reads payload");
        assert_eq!(&received, b"hello");

        let echoed = out.collected();
        let mut data = echoed.as_slice();
        let (length, _) = read_varint_with_length(&mut data).expect("length");
        let body = &data[..length as usize];
        let mut body_reader = body;
        assert_eq!(
            read_varint_with_length(&mut body_reader).expect("id").0,
            KEEPALIVE_PACKET
        );
        assert_eq!(read_long(&mut body_reader).expect("id"), 42);
        assert_eq!(data.len(), length as usize, "only the keepalive is echoed");

        client.shutdown();
    }

    #[test]
    fn a_server_can_send_a_keepalive() {
        let out = Pipe::new();
        let mut server = PacketStream::new(Pipe::new(), out.clone(), false);
        server.send_keepalive(9).expect("keepalive");

        let wire = out.collected();
        let mut data = wire.as_slice();
        let packet = read_packet(&mut data).expect("packet");
        assert_eq!(packet.id, KEEPALIVE_PACKET);
        let mut body = packet.data.as_slice();
        assert_eq!(read_long(&mut body).expect("id"), 9);
        assert_eq!(data, b"");

        server.shutdown();
    }

    #[test]
    fn a_server_ignores_inbound_keepalives() {
        let out = Pipe::new();
        let input = Pipe::new();

        let mut keepalive = Vec::new();
        write_long(&mut keepalive, 7).expect("keepalive");
        input.push(&frame(KEEPALIVE_PACKET, &keepalive));

        let mut payload = Vec::new();
        write_string(&mut payload, CHANNEL).expect("channel");
        payload.extend_from_slice(b"data");
        input.push(&frame(SERVERBOUND_CUSTOM_PAYLOAD, &payload));

        let mut server = PacketStream::new(input, out.clone(), false);
        let mut received = [0; 4];
        server.read_exact(&mut received).expect("reads payload");
        assert_eq!(&received, b"data");
        assert!(out.collected().is_empty(), "a server does not echo");

        server.shutdown();
    }

    #[test]
    fn channel_frames_are_plain_minecraft_framing() {
        let out = Pipe::new();
        let mut stream = PacketStream::new(Pipe::new(), out.clone(), true);
        stream.write_all(b"hello").expect("writes");
        assert_eq!(
            out.collected(),
            [
                0x0f, 0x02, 0x08, b'x', b'm', b'c', b':', b'd', b'a', b't', b'a', b'h', b'e', b'l',
                b'l', b'o'
            ]
        );
        stream.shutdown();
    }
}

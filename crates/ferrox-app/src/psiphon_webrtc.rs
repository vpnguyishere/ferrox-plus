//! A str0m WebRTC data channel between the client and an in-proxy destination.

use crate::psiphon_broker::{Broker, Client, Destination, Front, Metrics};
use crate::psiphon_ssh::random;
use crate::psiphon_ssh::Identity;
use std::collections::VecDeque;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};
use str0m::change::{SdpAnswer, SdpPendingOffer};
use str0m::channel::{ChannelConfig, ChannelId, Reliability};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, Input, Output, Rtc};

const STUN_COOKIE: u32 = 0x2112_a442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_SUCCESS: u16 = 0x0101;
const STUN_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const STUN_MAPPED_ADDRESS: u16 = 0x0001;
const MAX_DATAGRAM: usize = 65_536;
const PADDING_DONE: i64 = -1;
const MESSAGE_TIMEOUT: Duration = Duration::from_millis(5);
const STREAM_MESSAGE: usize = 16 * 1024;

/// A live WebRTC data channel carrying in-proxy bytes.
pub(crate) struct WebRtc {
    rtc: Rtc,
    socket: UdpSocket,
    local: SocketAddr,
    pending: Option<SdpPendingOffer>,
    channel: ChannelId,
    open: bool,
    buffer: Vec<u8>,
    events: VecDeque<Event>,
    peer: Option<IpAddr>,
}

impl WebRtc {
    /// Gather candidates, create the offer SDP, and return the pending answer.
    pub(crate) fn offer(
        destination: IpAddr,
        stun_servers: &[String],
        timeout: Duration,
        servers: &[SocketAddr],
        unreliable: bool,
    ) -> Result<(Self, String), String> {
        let socket = bind_socket(destination)?;
        let local = socket
            .local_addr()
            .map_err(|error| format!("psiphon webrtc local: {error}"))?;
        let mut rtc = Rtc::new(Instant::now());
        let host = Candidate::host(local, "udp")
            .map_err(|error| format!("psiphon webrtc candidate: {error}"))?;
        let _ = rtc.add_local_candidate(host);
        let stun_timeout = timeout.min(Duration::from_secs(3));
        for server in stun_servers.iter().take(2) {
            if let Ok(Some(mapped)) = stun_binding(&socket, local, server, stun_timeout, servers) {
                if let Ok(candidate) = Candidate::server_reflexive(mapped, local, "udp") {
                    let _ = rtc.add_local_candidate(candidate);
                }
            }
        }
        let mut changes = rtc.sdp_api();
        let config = ChannelConfig {
            label: label(),
            ordered: !unreliable,
            reliability: if unreliable {
                Reliability::MaxRetransmits { retransmits: 0 }
            } else {
                Reliability::Reliable
            },
            ..ChannelConfig::default()
        };
        let channel = changes.add_channel_with_config(config);
        let (offer, pending) = changes
            .apply()
            .ok_or_else(|| "psiphon webrtc: no offer".to_owned())?;
        Ok((
            Self {
                rtc,
                socket,
                local,
                pending: Some(pending),
                channel,
                open: false,
                buffer: vec![0u8; MAX_DATAGRAM],
                events: VecDeque::new(),
                peer: None,
            },
            offer.to_sdp_string(),
        ))
    }

    /// Apply the broker's answer SDP.
    pub(crate) fn answer(&mut self, sdp: &str) -> Result<(), String> {
        let answer = SdpAnswer::from_sdp_string(sdp)
            .map_err(|error| format!("psiphon webrtc answer: {error}"))?;
        let pending = self
            .pending
            .take()
            .ok_or_else(|| "psiphon webrtc: already answered".to_owned())?;
        self.rtc
            .sdp_api()
            .accept_answer(pending, answer)
            .map_err(|error| format!("psiphon webrtc answer: {error}"))
    }

    /// Drive ICE and DTLS until the data channel opens.
    pub(crate) fn await_channel(&mut self, timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            let next = self.pump()?;
            if self.open || self.rtc.channel(self.channel).is_some() {
                self.open = true;
                self.pump()?;
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("psiphon webrtc: data channel did not open".to_owned());
            }
            self.wait(next.min(deadline))?;
        }
    }

    /// Write one message on the data channel.
    pub(crate) fn send(&mut self, data: &[u8]) -> Result<(), String> {
        loop {
            let accepted = self
                .rtc
                .channel(self.channel)
                .ok_or_else(|| "psiphon webrtc: data channel is closed".to_owned())?
                .write(true, data)
                .map_err(|error| format!("psiphon webrtc write: {error}"))?;
            let mut events = Vec::new();
            let next = self.pump_into(&mut events)?;
            self.events.extend(events);
            if accepted {
                return Ok(());
            }
            self.wait(next)?;
        }
    }

    /// Read the next message from the data channel, or `None` on timeout.
    pub(crate) fn receive(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, String> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(event) = self.events.pop_front() {
                match event {
                    Event::ChannelData(data) if data.id == self.channel => {
                        return Ok(Some(data.data))
                    }
                    Event::ChannelClose(id) if id == self.channel => {
                        return Err("psiphon webrtc: data channel closed".to_owned())
                    }
                    Event::IceConnectionStateChange(str0m::IceConnectionState::Disconnected) => {
                        return Err("psiphon webrtc: ICE disconnected".to_owned())
                    }
                    _ => {}
                }
            } else {
                let mut events = Vec::new();
                let next = self.pump_into(&mut events)?;
                self.events.extend(events);
                if self.events.is_empty() {
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                    self.wait(next.min(deadline))?;
                }
            }
        }
    }

    /// The address the last peer datagram came from.
    pub(crate) fn peer_ip(&self) -> Option<IpAddr> {
        self.peer
    }

    /// Move the engine onto a driver thread and expose it as an `io` stream.
    pub(crate) fn into_stream(self, timeout: Duration) -> Result<WebRtcStream, String> {
        WebRtcStream::spawn(self, timeout, false)
    }

    /// Move the engine onto a driver thread and preserve each write as one datagram.
    pub(crate) fn into_datagram_stream(self, timeout: Duration) -> Result<WebRtcStream, String> {
        WebRtcStream::spawn(self, timeout, true)
    }

    /// Drain engine output, sending every transmitted datagram.
    fn pump(&mut self) -> Result<Instant, String> {
        let mut events = Vec::new();
        let next = self.pump_into(&mut events)?;
        self.events.extend(events);
        Ok(next)
    }

    /// Drain engine output, sending datagrams and collecting events.
    fn pump_into(&mut self, events: &mut Vec<Event>) -> Result<Instant, String> {
        loop {
            match self
                .rtc
                .poll_output()
                .map_err(|error| format!("psiphon webrtc: {error}"))?
            {
                Output::Timeout(until) => return Ok(until),
                Output::Transmit(transmit) => {
                    let _ = self
                        .socket
                        .send_to(&transmit.contents, transmit.destination);
                }
                Output::Event(Event::ChannelOpen(id, _)) if id == self.channel => {
                    self.open = true;
                }
                Output::Event(event) => events.push(event),
            }
        }
    }

    /// Wait for one datagram or for the engine's next deadline.
    fn wait(&mut self, until: Instant) -> Result<(), String> {
        let wait = until
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1));
        self.socket
            .set_read_timeout(Some(wait))
            .map_err(|error| format!("psiphon webrtc timeout: {error}"))?;
        match self.socket.recv_from(&mut self.buffer) {
            Ok((length, source)) => {
                self.peer = Some(source.ip());
                let destination = self.local;
                let input =
                    Receive::new(Protocol::Udp, source, destination, &self.buffer[..length])
                        .map_or_else(
                            |_| Input::Timeout(Instant::now()),
                            |receive| Input::Receive(Instant::now(), receive),
                        );
                self.rtc
                    .handle_input(input)
                    .map_err(|error| format!("psiphon webrtc receive: {error}"))
            }
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::ConnectionReset
                ) =>
            {
                self.rtc
                    .handle_input(Input::Timeout(Instant::now()))
                    .map_err(|error| format!("psiphon webrtc timeout: {error}"))
            }
            Err(error) => Err(format!("psiphon webrtc receive: {error}")),
        }
    }
}

/// Return a random lowercase hex data-channel label.
fn label() -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let length = usize::from(u16::from_be_bytes(random::<2>()) % 32) + 1;
    let mut label = String::with_capacity(length * 2);
    for byte in &random::<32>()[..length] {
        label.push(char::from(HEX[usize::from(byte >> 4)]));
        label.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    label
}

/// Bind a UDP socket on the interface the destination routes through.
fn bind_socket(destination: IpAddr) -> Result<UdpSocket, String> {
    let unspecified = if destination.is_ipv6() {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    };
    let probe = UdpSocket::bind(SocketAddr::new(unspecified, 0))
        .map_err(|error| format!("psiphon webrtc probe: {error}"))?;
    probe
        .connect(SocketAddr::new(destination, 9))
        .map_err(|error| format!("psiphon webrtc route: {error}"))?;
    let local = probe
        .local_addr()
        .map_err(|error| format!("psiphon webrtc route: {error}"))?;
    drop(probe);
    UdpSocket::bind(SocketAddr::new(local.ip(), 0))
        .map_err(|error| format!("psiphon webrtc bind: {error}"))
}

/// Send one RFC 5389 binding request and return its mapped address.
fn stun_binding(
    socket: &UdpSocket,
    local: SocketAddr,
    server: &str,
    timeout: Duration,
    servers: &[SocketAddr],
) -> Result<Option<SocketAddr>, String> {
    let ipv6 = local.is_ipv6();
    let same_family = |address: &SocketAddr| address.is_ipv6() == ipv6;
    let (host, port) = if let Ok(address) = server.parse::<SocketAddr>() {
        (address.ip().to_string(), address.port())
    } else if let Ok(address) = server.parse::<IpAddr>() {
        (address.to_string(), 3478)
    } else if let Some((host, port)) = server.rsplit_once(':') {
        match port.parse::<u16>() {
            Ok(port) => (host.trim_matches(['[', ']']).to_owned(), port),
            Err(_) => (server.to_owned(), 3478),
        }
    } else {
        (server.to_owned(), 3478)
    };
    let target = crate::psiphon_dns::resolve(&host, port, servers)
        .map_err(|error| format!("psiphon webrtc STUN {server}: {error}"))?
        .into_iter()
        .find(same_family)
        .ok_or_else(|| format!("psiphon webrtc STUN {server}: no address"))?;
    let transaction = random::<12>();
    let mut request = Vec::with_capacity(20);
    request.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    request.extend_from_slice(&0u16.to_be_bytes());
    request.extend_from_slice(&STUN_COOKIE.to_be_bytes());
    request.extend_from_slice(&transaction);
    socket
        .send_to(&request, target)
        .map_err(|error| format!("psiphon webrtc STUN send: {error}"))?;
    let deadline = Instant::now() + timeout;
    let mut reply = [0u8; 512];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        let wait = deadline
            .saturating_duration_since(now)
            .max(Duration::from_millis(1));
        socket
            .set_read_timeout(Some(wait))
            .map_err(|error| format!("psiphon webrtc STUN timeout: {error}"))?;
        let (length, source) = match socket.recv_from(&mut reply) {
            Ok(reply) => reply,
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Ok(None)
            }
            Err(error) => return Err(format!("psiphon webrtc STUN receive: {error}")),
        };
        if source == target {
            if let Some(mapped) = parse_stun(&reply[..length], &transaction) {
                return Ok(Some(mapped));
            }
        }
    }
}

/// Decode a binding success and return its mapped address.
fn parse_stun(reply: &[u8], transaction: &[u8; 12]) -> Option<SocketAddr> {
    if reply.len() < 20 {
        return None;
    }
    let kind = u16::from_be_bytes([reply[0], reply[1]]);
    let length = usize::from(u16::from_be_bytes([reply[2], reply[3]]));
    if kind != STUN_BINDING_SUCCESS
        || u32::from_be_bytes([reply[4], reply[5], reply[6], reply[7]]) != STUN_COOKIE
        || reply.get(8..20)? != transaction.as_slice()
        || reply.len() < 20 + length
    {
        return None;
    }
    let mut offset = 20;
    while offset + 4 <= 20 + length {
        let attribute = u16::from_be_bytes([reply[offset], reply[offset + 1]]);
        let size = usize::from(u16::from_be_bytes([reply[offset + 2], reply[offset + 3]]));
        let value = reply.get(offset + 4..offset + 4 + size)?;
        if let Some(address) = match attribute {
            STUN_XOR_MAPPED_ADDRESS => mapped(value, transaction, true),
            STUN_MAPPED_ADDRESS => mapped(value, transaction, false),
            _ => None,
        } {
            return Some(address);
        }
        offset += 4 + ((size + 3) & !3);
    }
    None
}

/// Unmask a MAPPED or XOR-MAPPED address attribute.
fn mapped(value: &[u8], transaction: &[u8; 12], xor: bool) -> Option<SocketAddr> {
    if value.len() < 4 {
        return None;
    }
    let family = value[1];
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    if xor {
        port ^= 0x2112;
    }
    match family {
        0x01 if value.len() >= 8 => {
            let mut octets = [value[4], value[5], value[6], value[7]];
            if xor {
                let cookie = STUN_COOKIE.to_be_bytes();
                for (octet, cookie) in octets.iter_mut().zip(cookie) {
                    *octet ^= cookie;
                }
            }
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        0x02 if value.len() >= 20 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&value[4..20]);
            if xor {
                let cookie = STUN_COOKIE.to_be_bytes();
                for (octet, cookie) in octets[..4].iter_mut().zip(cookie) {
                    *octet ^= cookie;
                }
                for (octet, transaction) in octets[4..].iter_mut().zip(transaction.iter()) {
                    *octet ^= transaction;
                }
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => None,
    }
}

type InputChannel = Arc<Mutex<Receiver<Result<Vec<u8>, String>>>>;

/// One in-proxy stream: bytes framed onto the data channel by a driver thread.
pub(crate) struct WebRtcStream {
    out: SyncSender<Vec<u8>>,
    input: InputChannel,
    pending: Arc<Mutex<(Vec<u8>, usize)>>,
    stop: Arc<AtomicBool>,
    padding_sent: Arc<AtomicBool>,
    read_timeout: Arc<Mutex<Option<Duration>>>,
    write_timeout: Arc<Mutex<Option<Duration>>>,
}

impl ferrox_core::tls::RecordAlignment for WebRtcStream {}

impl Clone for WebRtcStream {
    fn clone(&self) -> Self {
        Self {
            out: self.out.clone(),
            input: Arc::clone(&self.input),
            pending: Arc::clone(&self.pending),
            stop: Arc::clone(&self.stop),
            padding_sent: Arc::clone(&self.padding_sent),
            read_timeout: Arc::clone(&self.read_timeout),
            write_timeout: Arc::clone(&self.write_timeout),
        }
    }
}

impl WebRtcStream {
    /// Start the driver thread and the bounded queues.
    fn spawn(webrtc: WebRtc, timeout: Duration, raw: bool) -> Result<Self, String> {
        let (out, out_rx) = mpsc::sync_channel(64);
        let (input_tx, input) = mpsc::sync_channel(16);
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let padding_sent = Arc::new(AtomicBool::new(raw));
        thread::Builder::new()
            .name("psiphon-webrtc".to_owned())
            .spawn(move || drive(webrtc, out_rx, input_tx, thread_stop, raw))
            .map_err(|error| format!("psiphon webrtc driver: {error}"))?;
        Ok(Self {
            out,
            input: Arc::new(Mutex::new(input)),
            pending: Arc::new(Mutex::new((Vec::new(), 0))),
            stop,
            padding_sent,
            read_timeout: Arc::new(Mutex::new(Some(timeout))),
            write_timeout: Arc::new(Mutex::new(Some(timeout))),
        })
    }

    /// Set or clear the read and write timeout.
    pub(crate) fn set_timeout(&self, timeout: Option<Duration>) {
        *lock(&self.read_timeout) = timeout;
        *lock(&self.write_timeout) = timeout;
    }

    /// Set or clear only the read timeout, leaving the write deadline in place.
    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) {
        *lock(&self.read_timeout) = timeout;
    }

    /// End the driver and every clone of this stream.
    pub(crate) fn shutdown(&self) {
        self.stop.store(true, Ordering::Release);
    }
}

impl Read for WebRtcStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut pending = lock(&self.pending);
        loop {
            if pending.1 < pending.0.len() {
                let taken = (pending.0.len() - pending.1).min(buf.len());
                buf[..taken].copy_from_slice(&pending.0[pending.1..pending.1 + taken]);
                pending.1 += taken;
                return Ok(taken);
            }
            pending.0.clear();
            pending.1 = 0;
            let input = lock(&self.input);
            let timeout = *lock(&self.read_timeout);
            let received = match timeout {
                Some(timeout) => input.recv_timeout(timeout),
                None => input.recv().map_err(|_| RecvTimeoutError::Disconnected),
            };
            match received {
                Ok(Ok(data)) => {
                    pending.0 = data;
                }
                Ok(Err(error)) => {
                    return Err(io::Error::new(ErrorKind::ConnectionAborted, error));
                }
                Err(RecvTimeoutError::Timeout) => {
                    return Err(io::Error::from(ErrorKind::TimedOut));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::from(ErrorKind::UnexpectedEof));
                }
            }
        }
    }
}

impl WebRtcStream {
    /// Queue a packet built from several slices as one or more data-channel messages.
    pub(crate) fn write_parts(&self, bufs: &[&[u8]]) -> io::Result<usize> {
        let total: usize = bufs.iter().map(|buf| buf.len()).sum();
        if total == 0 {
            return Ok(0);
        }
        let first = !self.padding_sent.swap(true, Ordering::AcqRel);
        let mut message = Vec::with_capacity(STREAM_MESSAGE + 2);
        let mut header_len = 0;
        if first {
            put_varint(&mut message, PADDING_DONE);
            header_len = message.len();
        }
        for buf in bufs {
            let mut at = 0;
            while at < buf.len() {
                if message.len() - header_len >= STREAM_MESSAGE {
                    self.send(std::mem::take(&mut message))?;
                    message.reserve(STREAM_MESSAGE + 2);
                    header_len = 0;
                }
                let room = STREAM_MESSAGE - (message.len() - header_len);
                let take = room.min(buf.len() - at);
                message.extend_from_slice(&buf[at..at + take]);
                at += take;
            }
        }
        if message.len() > header_len {
            self.send(message)?;
        }
        Ok(total)
    }

    /// Queue one framed message, respecting the current write timeout.
    fn send(&self, message: Vec<u8>) -> io::Result<()> {
        let timeout = *lock(&self.write_timeout);
        let deadline = timeout.map(|timeout| Instant::now() + timeout);
        let mut message = message;
        loop {
            match self.out.try_send(message) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Full(back)) => {
                    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                        return Err(io::Error::from(ErrorKind::TimedOut));
                    }
                    message = back;
                    thread::sleep(Duration::from_millis(1));
                }
                Err(TrySendError::Disconnected(_)) => {
                    return Err(io::Error::from(ErrorKind::BrokenPipe));
                }
            }
        }
    }
}

impl Write for WebRtcStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_parts(&[buf])
    }

    /// The driver has no user-space buffer to flush.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Move datagrams between the engine and the bounded stream queues.
#[allow(clippy::needless_pass_by_value)]
fn drive(
    mut webrtc: WebRtc,
    out: Receiver<Vec<u8>>,
    input: SyncSender<Result<Vec<u8>, String>>,
    stop: Arc<AtomicBool>,
    raw: bool,
) {
    let mut peer_padding_done = false;
    let mut backlog: VecDeque<Result<Vec<u8>, String>> = VecDeque::new();
    loop {
        if stop.load(Ordering::Acquire) {
            return;
        }
        let mut wrote = false;
        for _ in 0..16 {
            match out.try_recv() {
                Ok(data) if data.is_empty() => {}
                Ok(data) => {
                    if let Err(error) = webrtc.send(&data) {
                        backlog.clear();
                        backlog.push_back(Err(error));
                    }
                    wrote = true;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return,
            }
        }
        while let Some(message) = backlog.pop_front() {
            match input.try_send(message) {
                Ok(()) => {}
                Err(TrySendError::Full(message)) => {
                    backlog.push_front(message);
                    break;
                }
                Err(TrySendError::Disconnected(_)) => return,
            }
        }
        if !backlog.is_empty() {
            if let Err(error) = webrtc.pump() {
                backlog.clear();
                backlog.push_back(Err(error));
            }
            thread::sleep(MESSAGE_TIMEOUT);
            continue;
        }
        let timeout = if wrote {
            Duration::ZERO
        } else {
            MESSAGE_TIMEOUT
        };
        match webrtc.receive(timeout) {
            Ok(Some(data)) if raw => {
                if !data.is_empty() {
                    backlog.push_back(Ok(data));
                }
            }
            Ok(Some(data)) => match unframe(data, &mut peer_padding_done) {
                Ok(Some(payload)) if !payload.is_empty() => backlog.push_back(Ok(payload)),
                Ok(_) => {}
                Err(error) => backlog.push_back(Err(error)),
            },
            Ok(None) => {}
            Err(error) => backlog.push_back(Err(error)),
        }
    }
}

/// Encode one signed zigzag varint.
fn put_varint(out: &mut Vec<u8>, value: i64) {
    let mut word = (value as u64) << 1;
    if value < 0 {
        word = !word;
    }
    loop {
        let byte = (word & 0x7f) as u8;
        word >>= 7;
        if word == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Decode one signed zigzag varint and advance `at`.
fn take_varint(data: &[u8], at: &mut usize) -> Option<i64> {
    let mut word = 0u64;
    let mut shift = 0u32;
    for (offset, byte) in data[*at..].iter().enumerate() {
        if offset == 10 {
            return None;
        }
        word |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            *at += offset + 1;
            let value = (word >> 1).cast_signed();
            return Some(if word & 1 == 0 { value } else { !value });
        }
        shift += 7;
    }
    None
}

/// Skip the peer's padding header and bytes, or return the message payload in the buffer it arrived in.
fn unframe(mut data: Vec<u8>, done: &mut bool) -> Result<Option<Vec<u8>>, String> {
    if *done {
        return Ok(Some(data));
    }
    let mut at = 0;
    let padding = take_varint(&data, &mut at)
        .ok_or_else(|| "psiphon webrtc: invalid padding header".to_owned())?;
    if padding < 0 {
        *done = true;
        if at >= data.len() {
            return Ok(None);
        }
        data.drain(..at);
        return Ok(Some(data));
    }
    let skip = at
        .checked_add(usize::try_from(padding).unwrap_or(usize::MAX))
        .filter(|skip| *skip <= data.len())
        .ok_or_else(|| "psiphon webrtc: invalid padding length".to_owned())?;
    if skip >= data.len() {
        return Ok(None);
    }
    data.drain(..skip);
    Ok(Some(data))
}

/// Lock, recovering the data after a panic.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Clone, Copy)]
struct Cidr {
    base: IpAddr,
    prefix: u8,
}

impl Cidr {
    fn parse(text: &str) -> Option<Self> {
        let (address, prefix) = text.split_once('/')?;
        let base = address.trim().parse::<IpAddr>().ok()?;
        let prefix = prefix.trim().parse::<u8>().ok()?;
        let width = if base.is_ipv4() { 32 } else { 128 };
        (prefix <= width).then_some(Self { base, prefix })
    }

    fn contains(&self, address: IpAddr) -> bool {
        match (self.base, address) {
            (IpAddr::V4(base), IpAddr::V4(address)) => {
                mask(u128::from(u32::from(base)), self.prefix, 32)
                    == mask(u128::from(u32::from(address)), self.prefix, 32)
            }
            (IpAddr::V6(base), IpAddr::V6(address)) => {
                mask(u128::from(base), self.prefix, 128)
                    == mask(u128::from(address), self.prefix, 128)
            }
            _ => false,
        }
    }
}

fn mask(value: u128, prefix: u8, width: u32) -> u128 {
    if prefix == 0 {
        0
    } else {
        let bits = if width == 32 {
            u128::from(u32::MAX)
        } else {
            u128::MAX
        };
        value & (bits << (width - u32::from(prefix)))
    }
}

/// Everything one in-proxy dial needs: a broker, its fronts, and the compartments.
pub(crate) struct Conduit {
    broker: Broker,
    fronts: Vec<Front>,
    common: Vec<[u8; 32]>,
    personal: Vec<[u8; 32]>,
    stun_servers: Vec<String>,
    protocols: Vec<String>,
    timeout: Duration,
    headers: Vec<(String, String)>,
    dns: Vec<SocketAddr>,
    reject: Vec<Cidr>,
    geoip: Option<crate::psiphon_geoip::GeoIp>,
}

impl Conduit {
    /// Build a conduit from a tactics payload and the selected compartments.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        broker: Broker,
        fronts: Vec<Front>,
        common: Vec<[u8; 32]>,
        personal: Vec<[u8; 32]>,
        stun_servers: Vec<String>,
        protocols: Vec<String>,
        timeout: Duration,
        headers: Vec<(String, String)>,
        dns: Vec<SocketAddr>,
        reject_cidrs: &[String],
        geoip: Option<crate::psiphon_geoip::GeoIp>,
    ) -> Self {
        let reject = reject_cidrs
            .iter()
            .filter_map(|text| {
                let cidr = Cidr::parse(text);
                if cidr.is_none() {
                    eprintln!("psiphon conduit: ignoring invalid CIDR {text:?}");
                }
                cidr
            })
            .collect();
        Self {
            broker,
            fronts,
            common,
            personal,
            stun_servers,
            protocols,
            timeout,
            headers,
            dns,
            reject,
            geoip,
        }
    }

    /// Dial the destination through the first broker front that answers.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn open(
        &self,
        address: IpAddr,
        destination: &Destination,
        identity: &Identity<'_>,
    ) -> Result<(WebRtcStream, Relay), String> {
        if self.fronts.is_empty() {
            return Err("psiphon conduit: no broker front".to_owned());
        }
        if !matches!(
            destination.base_protocol(),
            "OSSH"
                | "SSH"
                | "TLS-OSSH"
                | "SHADOWSOCKS-OSSH"
                | "QUIC-OSSH"
                | "UNFRONTED-MEEK-OSSH"
                | "UNFRONTED-MEEK-HTTPS-OSSH"
                | "UNFRONTED-MEEK-SESSION-TICKET-OSSH"
                | "FRONTED-MEEK-OSSH"
                | "FRONTED-MEEK-HTTP-OSSH"
                | "FRONTED-MEEK-QUIC-OSSH"
        ) {
            return Err(format!(
                "psiphon conduit: {} is not carried by this lane",
                destination.protocol
            ));
        }
        if !self.protocols.is_empty()
            && !self
                .protocols
                .iter()
                .any(|protocol| protocol.eq_ignore_ascii_case(destination.protocol))
        {
            return Err(format!(
                "psiphon conduit: {} is not in the configured protocol list",
                destination.protocol
            ));
        }
        let metrics = Metrics::from_identity(identity);
        let mut why = String::new();
        for front in &self.fronts {
            let unreliable = matches!(
                destination.base_protocol(),
                "QUIC-OSSH" | "FRONTED-MEEK-QUIC-OSSH"
            );
            let (mut webrtc, sdp) = match WebRtc::offer(
                address,
                &self.stun_servers,
                self.timeout,
                &self.dns,
                unreliable,
            ) {
                Ok(offer) => offer,
                Err(error) => {
                    why = error;
                    continue;
                }
            };
            let mut client = match Client::connect(
                self.broker.clone(),
                front,
                self.timeout,
                None,
                &self.headers,
                &self.dns,
            ) {
                Ok(client) => client,
                Err(error) => {
                    why = error;
                    continue;
                }
            };
            let offer = match client.client_offer(
                destination,
                &self.common,
                &self.personal,
                &sdp,
                &metrics,
            ) {
                Ok(offer) => offer,
                Err(error) => {
                    why = error;
                    continue;
                }
            };
            if offer.answer_sdp.is_empty() {
                why = format!(
                    "psiphon conduit: broker returned no answer (limited {}, no match {}, upgrade {})",
                    offer.limited, offer.no_match, offer.must_upgrade
                );
                continue;
            }
            if let Err(error) = webrtc.answer(&offer.answer_sdp) {
                why = error;
                continue;
            }
            if let Err(error) = webrtc.await_channel(self.timeout) {
                why = error;
                continue;
            }
            if !self.reject.is_empty() || self.geoip.is_some() {
                let Some(peer) = webrtc.peer_ip() else {
                    why = String::from("psiphon conduit: peer address was not observed");
                    continue;
                };
                if self.reject.iter().any(|cidr| cidr.contains(peer))
                    || self.geoip.as_ref().is_some_and(|geoip| geoip.rejects(peer))
                {
                    why = format!("psiphon conduit: rejected in-proxy {peer}");
                    continue;
                }
            }
            let stream = if matches!(
                destination.base_protocol(),
                "QUIC-OSSH" | "FRONTED-MEEK-QUIC-OSSH"
            ) {
                webrtc.into_datagram_stream(self.timeout)?
            } else {
                webrtc.into_stream(self.timeout)?
            };
            return Ok((
                stream,
                Relay {
                    client,
                    connection_id: offer.connection_id,
                    initial: offer.relay_packet_to_server,
                },
            ));
        }
        Err(why)
    }
}

/// The broker session attached to one live in-proxy stream.
pub(crate) struct Relay {
    client: Client,
    connection_id: Vec<u8>,
    initial: Vec<u8>,
}

impl Relay {
    /// The initial broker-to-server packet the handshake carries.
    pub(crate) fn initial(&self) -> &[u8] {
        &self.initial
    }

    /// The raw connection id the handshake names.
    pub(crate) fn connection_id(&self) -> &[u8] {
        &self.connection_id
    }

    /// Relay one server packet and return the broker's next packet.
    pub(crate) fn relay(&mut self, packet: &[u8]) -> Result<Vec<u8>, String> {
        self.client.relay_packet(&self.connection_id, packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cidr_matches_only_its_own_family_and_prefix() {
        let cidr = Cidr::parse("192.0.2.0/24").expect("CIDR");
        assert!(cidr.contains("192.0.2.55".parse().expect("IP")));
        assert!(!cidr.contains("198.51.100.1".parse().expect("IP")));
        assert!(!cidr.contains("2001:db8::1".parse().expect("IP")));
        let cidr = Cidr::parse("2001:db8::/32").expect("CIDR");
        assert!(cidr.contains("2001:db8:1::1".parse().expect("IP")));
        assert!(!cidr.contains("2001:db9::1".parse().expect("IP")));
        assert!(Cidr::parse("192.0.2.0/33").is_none());
    }

    #[test]
    fn an_xor_mapped_address_is_unmasked() {
        let transaction = [7u8; 12];
        let port = 0x1f40u16 ^ 0x2112;
        let mut value = vec![0, 1, port.to_be_bytes()[0], port.to_be_bytes()[1]];
        let cookie = STUN_COOKIE.to_be_bytes();
        value.extend_from_slice(&[
            0xc0 ^ cookie[0],
            cookie[1],
            0x02 ^ cookie[2],
            0x01 ^ cookie[3],
        ]);
        let mut reply = vec![0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42];
        reply.extend_from_slice(&transaction);
        reply.extend_from_slice(&STUN_XOR_MAPPED_ADDRESS.to_be_bytes());
        reply.extend_from_slice(&8u16.to_be_bytes());
        reply.extend_from_slice(&value);
        assert_eq!(
            parse_stun(&reply, &transaction),
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                8000
            ))
        );
    }

    #[test]
    fn a_signed_padding_header_round_trips() {
        for value in [-1i64, 0, 1, 63, 64, 300, i64::from(i32::MIN)] {
            let mut encoded = Vec::new();
            put_varint(&mut encoded, value);
            let mut at = 0;
            assert_eq!(take_varint(&encoded, &mut at), Some(value));
            assert_eq!(at, encoded.len());
        }
    }

    #[test]
    fn a_padding_header_marks_done_and_hides_decoy_messages() {
        let mut done = false;
        let mut header = Vec::new();
        put_varint(&mut header, -1);
        header.extend_from_slice(b"hello");
        assert_eq!(unframe(header, &mut done), Ok(Some(b"hello".to_vec())));
        assert!(done);

        let mut done = false;
        let mut decoy = Vec::new();
        put_varint(&mut decoy, 3);
        decoy.extend_from_slice(b"xxx");
        assert_eq!(unframe(decoy, &mut done), Ok(None));
        assert!(!done);
    }

    #[test]
    fn an_unframed_payload_keeps_the_message_allocation() {
        let mut done = false;
        let mut data = Vec::new();
        put_varint(&mut data, 2);
        data.extend_from_slice(b"xxpayload");
        let base = data.as_ptr();
        let capacity = data.capacity();
        let (payload, counts) = ferrox_core::alloc_count::measure(|| unframe(data, &mut done));
        let payload = payload.expect("payload").expect("a kept message");
        assert_eq!(payload.as_slice(), b"payload");
        assert_eq!(counts.allocs, 0, "the header is skipped in place");
        assert_eq!(payload.as_ptr(), base, "the message buffer does not move");
        assert_eq!(payload.capacity(), capacity, "the capacity does not grow");
    }

    #[test]
    fn a_loopback_peer_opens_the_data_channel() {
        let (mut client, offer) = WebRtc::offer(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &[],
            Duration::from_secs(1),
            &[],
            false,
        )
        .expect("offer");
        let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("remote socket");
        let local = socket.local_addr().expect("remote local");
        let mut remote = Rtc::new(Instant::now());
        let _ = remote.add_local_candidate(Candidate::host(local, "udp").expect("candidate"));
        let offer = str0m::change::SdpOffer::from_sdp_string(&offer).expect("offer sdp");
        let answer = remote.sdp_api().accept_offer(offer).expect("answer");
        client
            .answer(&answer.to_sdp_string())
            .expect("accept answer");
        let remote = std::thread::spawn(move || {
            let mut remote = remote;
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut channel = None;
            socket
                .set_read_timeout(Some(Duration::from_millis(20)))
                .expect("timeout");
            while Instant::now() < deadline {
                let mut events = Vec::new();
                pump(&mut remote, &socket, &mut events);
                for event in events {
                    match event {
                        Event::ChannelOpen(id, _) => channel = Some(id),
                        Event::ChannelData(data) => {
                            let id = channel.expect("open");
                            let accepted = remote
                                .channel(id)
                                .expect("channel")
                                .write(true, &data.data)
                                .expect("echo");
                            if accepted {
                                pump(&mut remote, &socket, &mut Vec::new());
                                return;
                            }
                        }
                        _ => {}
                    }
                }
                let mut buffer = [0u8; 2048];
                if let Ok((length, source)) = socket.recv_from(&mut buffer) {
                    let destination = socket.local_addr().expect("local");
                    if let Ok(receive) =
                        Receive::new(Protocol::Udp, source, destination, &buffer[..length])
                    {
                        remote
                            .handle_input(Input::Receive(Instant::now(), receive))
                            .expect("input");
                    }
                }
            }
            panic!("remote never received data");
        });
        client
            .await_channel(Duration::from_secs(5))
            .expect("channel");
        client.send(b"hello").expect("send");
        assert_eq!(
            client.receive(Duration::from_secs(5)),
            Ok(Some(b"hello".to_vec()))
        );
        remote.join().expect("remote");
    }

    fn pump(rtc: &mut Rtc, socket: &UdpSocket, events: &mut Vec<Event>) {
        loop {
            match rtc.poll_output().expect("output") {
                Output::Timeout(_) => return,
                Output::Transmit(transmit) => {
                    socket
                        .send_to(&transmit.contents, transmit.destination)
                        .expect("transmit");
                }
                Output::Event(event) => events.push(event),
            }
        }
    }

    #[test]
    fn a_private_offer_names_a_data_channel() {
        let (webrtc, sdp) = WebRtc::offer(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &[],
            Duration::from_secs(1),
            &[],
            false,
        )
        .expect("offer");
        assert!(sdp.contains("m=application"));
        assert!(webrtc.socket.local_addr().is_ok());
    }
}

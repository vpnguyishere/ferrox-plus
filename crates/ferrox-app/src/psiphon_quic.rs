//! A synchronous `QUIC-OSSH` client: a `rustls` TLS 1.3 handshake carried in
//! QUIC packets, one bidirectional stream, and the Psiphon obfuscation layer.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::many_single_char_names,
    clippy::missing_const_for_fn,
    clippy::similar_names,
    clippy::struct_excessive_bools
)]

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::io::{self, ErrorKind, IoSlice, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use hkdf::Hkdf;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::SecureRandom;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::quic::{ClientConnection, KeyChange, Keys, Secrets, Version};
use rustls::{DigitallySignedStruct, Side, SignatureScheme};
use sha2::Sha256;

use crate::psiphon_ssh::{tls_passthrough, tls_passthrough_key, Proxy, Server};
use crate::psiphon_webrtc::WebRtcStream;

const READ_WAIT: Duration = Duration::from_millis(2);
const KEEPALIVE: Duration = Duration::from_secs(15);
const MAX_PACKET_SIZE: usize = 1452;
const OBFUSCATION_OVERHEAD: usize = 13;
const PADDING_LIMIT: usize = 1280;
const MAX_SEND_QUEUE: usize = 512 * 1024;
const MAX_RECV_QUEUE: usize = 512 * 1024;
const MAX_PAYLOAD: usize = 1200;
const MAX_UDP_PAYLOAD: u64 = 1439;
const INITIAL_WINDOW: u64 = 8 * 1024 * 1024;
const STREAM_WINDOW: u64 = 8 * 1024 * 1024;
const MSS: u64 = 1200;
const INITIAL_CWND: u64 = 10 * MSS;
const MAX_CWND: u64 = 8 * 1024 * 1024;
const QUIC_VERSION: u32 = 1;
const CID_LEN: usize = 16;
const INITIAL: usize = 0;
const HANDSHAKE: usize = 1;
const ONE_RTT: usize = 2;

pub(crate) const SUPPORTED_QUIC_VERSIONS: &[&str] = &[
    "QUICv1",
    "RANDOMIZED-QUICv1",
    "OBFUSCATED-QUICv1",
    "DECOY-QUICv1",
];

struct QuicNoise {
    before: u8,
    after_first: u8,
    junk_min: usize,
    junk_max: usize,
    first_random: usize,
    second_random: usize,
    interval: Duration,
}

impl QuicNoise {
    fn lookup(name: &str) -> Option<Self> {
        let (before, after_first, junk_min, junk_max, first_random, second_random, interval) =
            match name.trim().to_ascii_lowercase().as_str() {
                "" | "off" | "none" => return None,
                "light" => (1, 0, 32, 96, 16, 0, Duration::from_millis(3)),
                "gfw" | "aggressive" | "heavy" => (2, 1, 64, 256, 24, 32, Duration::from_millis(5)),
                _ => (2, 2, 48, 190, 24, 48, Duration::from_millis(4)),
            };
        Some(Self {
            before,
            after_first,
            junk_min,
            junk_max,
            first_random,
            second_random,
            interval,
        })
    }

    fn send(&self, socket: &UdpSocket) -> io::Result<()> {
        for _ in 0..self.before {
            self.junk(socket)?;
            thread::sleep(self.interval);
        }
        let mut first = vec![0x0d, 0x0a, 0x0d, 0x0a];
        first.extend_from_slice(
            &u32::try_from(std::time::UNIX_EPOCH.elapsed().map_or(0, |d| d.as_secs()))
                .unwrap_or(0)
                .to_be_bytes(),
        );
        first.resize(first.len() + self.first_random, 0);
        getrandom::fill(&mut first[8..]).map_err(|_| io::Error::other("psiphon quic noise"))?;
        send_guarded(socket, &mut first)?;
        thread::sleep(Duration::from_millis(2));
        for _ in 0..self.after_first {
            self.junk(socket)?;
            thread::sleep(self.interval);
        }
        if self.second_random > 0 {
            let mut second = vec![0u8; self.second_random];
            getrandom::fill(&mut second).map_err(|_| io::Error::other("psiphon quic noise"))?;
            send_guarded(socket, &mut second)?;
        }
        Ok(())
    }

    fn junk(&self, socket: &UdpSocket) -> io::Result<()> {
        let span = self.junk_max.saturating_sub(self.junk_min).max(1);
        let mut packet = vec![0u8; self.junk_min + bounded_random(span)?];
        getrandom::fill(&mut packet).map_err(|_| io::Error::other("psiphon quic noise"))?;
        send_guarded(socket, &mut packet)
    }
}

fn send_guarded(socket: &UdpSocket, packet: &mut [u8]) -> io::Result<()> {
    if packet.len() >= 5 && packet[0] >> 4 == 0x0c && packet[1..5] == [0, 0, 0, 1] {
        packet[0] ^= 0x40;
    }
    for at in [29, 31, 34] {
        if packet.len() >= at + 4 && &packet[at..at + 4] == b"CHLO" {
            packet[at] ^= 0x20;
        }
    }
    socket.send(packet).map(|_| ())
}

thread_local! {
    static PENDING_RANDOM: RefCell<Option<[u8; 32]>> = const { RefCell::new(None) };
}

struct Shared {
    state: Mutex<State>,
    readable: Condvar,
    writable: Condvar,
}

struct State {
    send: VecDeque<Vec<u8>>,
    send_bytes: usize,
    recv: Vec<u8>,
    read_at: usize,
    error: Option<String>,
    eof: bool,
    write_closed: bool,
    close_requested: bool,
    timeout: Option<Duration>,
}

impl State {
    fn fail(&mut self, why: impl Into<String>) {
        if self.error.is_none() {
            self.error = Some(why.into());
        }
        self.eof = true;
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One bidirectional QUIC stream carrying the SSH transport.
pub(crate) struct QuicStream {
    shared: Arc<Shared>,
}

impl Clone for QuicStream {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

/// The obfuscation mode, structural randomization, proof key and packet key an entry selects.
fn quic_parameters(server: &Server) -> Result<(bool, bool, bool, &str, [u8; 32]), String> {
    let version = if server.quic_versions.is_empty() {
        SUPPORTED_QUIC_VERSIONS
            [bounded_random(SUPPORTED_QUIC_VERSIONS.len()).map_err(|error| error.to_string())?]
    } else {
        server
            .quic_versions
            .iter()
            .map(String::as_str)
            .find(|version| SUPPORTED_QUIC_VERSIONS.contains(version))
            .ok_or_else(|| {
                "psiphon quic: the entry does not allow a supported QUIC mode".to_owned()
            })?
    };
    let obfuscated = matches!(version, "OBFUSCATED-QUICv1" | "DECOY-QUICv1");
    let decoy = version == "DECOY-QUICv1";
    let randomized = version == "RANDOMIZED-QUICv1";
    let proof_key = tls_passthrough_key(server);
    if proof_key.is_empty() {
        return Err("psiphon quic: entry has no passthrough key".to_owned());
    }
    let packet_key = if obfuscated {
        let key = server
            .obfuscation_key
            .as_deref()
            .filter(|key| !key.is_empty())
            .ok_or_else(|| "psiphon quic: entry has no obfuscation key".to_owned())?;
        packet_key(key)?
    } else {
        [0u8; 32]
    };
    Ok((obfuscated, decoy, randomized, proof_key, packet_key))
}

/// Wrap a packet source in the entry's QUIC obfuscation layer.
fn packet_io(
    io: PacketIo,
    obfuscated: bool,
    decoy: bool,
    packet_key: [u8; 32],
) -> Result<Udp, String> {
    if !obfuscated {
        return Ok(Udp::Plain(io));
    }
    Ok(Udp::Obfuscated(ObfuscatedUdp {
        io,
        key: packet_key,
        nonce: [0u8; 12],
        decoy: if decoy {
            Some(u8::try_from(bounded_random(10).map_err(|error| error.to_string())?).unwrap_or(0))
        } else {
            None
        },
    }))
}

impl QuicStream {
    /// Dial a direct QUIC-OSSH server over a UDP socket.
    pub(crate) fn connect(
        server: &Server,
        timeout: Duration,
        proxy: Option<&Proxy>,
    ) -> Result<Self, String> {
        if proxy.is_some() {
            return Err("psiphon quic: an upstream proxy cannot carry UDP QUIC".to_owned());
        }
        let (obfuscated, decoy, randomized, proof_key, packet_key) = quic_parameters(server)?;
        let remote = SocketAddr::new(server.address, server.port);
        let bind = if remote.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        };
        let socket = UdpSocket::bind(bind)
            .and_then(|socket| socket.connect(remote).map(|()| socket))
            .map_err(|error| format!("psiphon quic socket {remote}: {error}"))?;
        socket
            .set_read_timeout(Some(timeout))
            .and_then(|()| socket.set_write_timeout(Some(timeout)))
            .map_err(|error| format!("psiphon quic socket {remote}: {error}"))?;
        if !obfuscated {
            if let Some(noise) = server.quic_noise.as_deref().and_then(QuicNoise::lookup) {
                noise
                    .send(&socket)
                    .map_err(|error| format!("psiphon quic noise {remote}: {error}"))?;
            }
        }
        let udp = packet_io(PacketIo::Socket(socket), obfuscated, decoy, packet_key)?;
        Self::connect_over(udp, remote, timeout, proof_key, randomized)
    }

    /// Dial QUIC-OSSH through an in-proxy WebRTC data channel.
    pub(crate) fn connect_inproxy(
        server: &Server,
        timeout: Duration,
        stream: WebRtcStream,
    ) -> Result<Self, String> {
        let (obfuscated, decoy, randomized, proof_key, packet_key) = quic_parameters(server)?;
        let remote = SocketAddr::new(server.address, server.port);
        stream.set_timeout(Some(timeout));
        let udp = packet_io(PacketIo::WebRtc(stream), obfuscated, decoy, packet_key)?;
        Self::connect_over(udp, remote, timeout, proof_key, randomized)
    }

    /// Complete the QUIC handshake over a packet source and start its driver.
    fn connect_over(
        mut udp: Udp,
        remote: SocketAddr,
        timeout: Duration,
        proof_key: &str,
        randomized: bool,
    ) -> Result<Self, String> {
        let mut engine = Engine::new(proof_key, randomized)?;
        let deadline = Instant::now() + timeout;
        let mut datagram = vec![0u8; 65535];
        loop {
            engine.flush(&mut udp, Instant::now())?;
            if engine.ready() {
                break;
            }
            let now = Instant::now();
            if now >= deadline {
                return Err("psiphon quic handshake timed out".to_owned());
            }
            let wait = engine
                .wait_timeout(now)
                .min(deadline.saturating_duration_since(now))
                .max(Duration::from_millis(1));
            udp.set_read_timeout(Some(wait));
            match udp.recv(&mut datagram) {
                Ok(count) => {
                    let now = Instant::now();
                    if let Err(error) = engine.receive(&mut datagram[..count], now) {
                        if !discardable(&error) {
                            return Err(error);
                        }
                    }
                }
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(error) => return Err(format!("psiphon quic receive {remote}: {error}")),
            }
        }
        engine.open_stream();
        engine.flush(&mut udp, Instant::now())?;

        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                send: VecDeque::new(),
                send_bytes: 0,
                recv: Vec::new(),
                read_at: 0,
                error: None,
                eof: false,
                write_closed: false,
                close_requested: false,
                timeout: Some(timeout),
            }),
            readable: Condvar::new(),
            writable: Condvar::new(),
        });
        let driver = Arc::clone(&shared);
        thread::Builder::new()
            .name("psiphon-quic".to_owned())
            .spawn(move || drive(&driver, udp, engine))
            .map_err(|error| format!("psiphon quic thread: {error}"))?;
        Ok(Self { shared })
    }

    pub(crate) fn set_timeout(&self, timeout: Option<Duration>) {
        self.set_read_timeout(timeout);
    }

    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) {
        let mut state = lock(&self.shared.state);
        state.timeout = timeout;
        drop(state);
        self.shared.readable.notify_all();
    }

    pub(crate) fn shutdown(&self) {
        let mut state = lock(&self.shared.state);
        state.write_closed = true;
        state.close_requested = true;
        state.eof = true;
        drop(state);
        self.shared.readable.notify_all();
        self.shared.writable.notify_all();
    }
}

impl Read for QuicStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut state = lock(&self.shared.state);
        loop {
            if let Some(error) = state.error.clone() {
                return Err(io::Error::new(ErrorKind::BrokenPipe, error));
            }
            if state.read_at < state.recv.len() {
                let available = &state.recv[state.read_at..];
                let count = buf.len().min(available.len());
                buf[..count].copy_from_slice(&available[..count]);
                state.read_at += count;
                if state.read_at == state.recv.len() {
                    state.recv.clear();
                    state.read_at = 0;
                } else if state.read_at >= 64 * 1024 {
                    let read_at = state.read_at;
                    state.recv.drain(..read_at);
                    state.read_at = 0;
                }
                return Ok(count);
            }
            if state.eof {
                return Ok(0);
            }
            let timeout = state.timeout;
            let (next, expired) = match timeout {
                Some(timeout) => {
                    let (next, result) = self
                        .shared
                        .readable
                        .wait_timeout(state, timeout)
                        .unwrap_or_else(PoisonError::into_inner);
                    (next, result.timed_out())
                }
                None => (
                    self.shared
                        .readable
                        .wait(state)
                        .unwrap_or_else(PoisonError::into_inner),
                    false,
                ),
            };
            state = next;
            if expired && state.read_at == state.recv.len() && !state.eof && state.error.is_none() {
                return Err(io::Error::new(
                    ErrorKind::WouldBlock,
                    "psiphon quic read timed out",
                ));
            }
        }
    }
}

impl Write for QuicStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut state = lock(&self.shared.state);
        if state.write_closed || state.eof {
            return Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "psiphon quic is shut down",
            ));
        }
        if let Some(error) = state.error.clone() {
            return Err(io::Error::new(ErrorKind::BrokenPipe, error));
        }
        let deadline = state.timeout.map(|timeout| Instant::now() + timeout);
        while state.send_bytes > 0 && state.send_bytes + buf.len() > MAX_SEND_QUEUE {
            let (next, expired) = wait_writable(&self.shared, state, deadline);
            state = next;
            if expired {
                return Err(io::Error::new(
                    ErrorKind::TimedOut,
                    "psiphon quic write timed out",
                ));
            }
            if state.write_closed || state.eof {
                return Err(io::Error::new(
                    ErrorKind::BrokenPipe,
                    "psiphon quic is shut down",
                ));
            }
            if let Some(error) = state.error.clone() {
                return Err(io::Error::new(ErrorKind::BrokenPipe, error));
            }
        }
        state.send_bytes += buf.len();
        state.send.push_back(buf.to_vec());
        drop(state);
        self.shared.writable.notify_one();
        Ok(buf.len())
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let total: usize = bufs.iter().map(|buf| buf.len()).sum();
        if total == 0 {
            return Ok(0);
        }
        let mut state = lock(&self.shared.state);
        if state.write_closed || state.eof {
            return Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "psiphon quic is shut down",
            ));
        }
        if let Some(error) = state.error.clone() {
            return Err(io::Error::new(ErrorKind::BrokenPipe, error));
        }
        let deadline = state.timeout.map(|timeout| Instant::now() + timeout);
        while state.send_bytes > 0 && state.send_bytes + total > MAX_SEND_QUEUE {
            let (next, expired) = wait_writable(&self.shared, state, deadline);
            state = next;
            if expired {
                return Err(io::Error::new(
                    ErrorKind::TimedOut,
                    "psiphon quic write timed out",
                ));
            }
            if state.write_closed || state.eof {
                return Err(io::Error::new(
                    ErrorKind::BrokenPipe,
                    "psiphon quic is shut down",
                ));
            }
            if let Some(error) = state.error.clone() {
                return Err(io::Error::new(ErrorKind::BrokenPipe, error));
            }
        }
        for buf in bufs {
            if !buf.is_empty() {
                state.send_bytes += buf.len();
                state.send.push_back(buf.to_vec());
            }
        }
        drop(state);
        self.shared.writable.notify_all();
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn wait_writable<'a>(
    shared: &'a Shared,
    state: MutexGuard<'a, State>,
    deadline: Option<Instant>,
) -> (MutexGuard<'a, State>, bool) {
    let Some(deadline) = deadline else {
        return (
            shared
                .writable
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner),
            false,
        );
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return (state, true);
    }
    let (next, result) = shared
        .writable
        .wait_timeout(state, remaining)
        .unwrap_or_else(PoisonError::into_inner);
    (next, result.timed_out())
}

enum PacketIo {
    Socket(UdpSocket),
    WebRtc(WebRtcStream),
}

impl PacketIo {
    fn send(&mut self, plain: &[u8]) -> io::Result<usize> {
        match self {
            Self::Socket(socket) => socket.send(plain),
            Self::WebRtc(stream) => stream.write(plain),
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Socket(socket) => socket.recv(buf),
            Self::WebRtc(stream) => stream.read(buf),
        }
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) {
        match self {
            Self::Socket(socket) => {
                let _ = socket.set_read_timeout(timeout);
            }
            Self::WebRtc(stream) => stream.set_read_timeout(timeout),
        }
    }
}

enum Udp {
    Obfuscated(ObfuscatedUdp),
    Plain(PacketIo),
}

impl Udp {
    fn send(&mut self, plain: &[u8]) -> io::Result<usize> {
        match self {
            Self::Obfuscated(udp) => udp.send(plain),
            Self::Plain(io) => io.send(plain),
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Obfuscated(udp) => udp.recv(buf),
            Self::Plain(io) => io.recv(buf),
        }
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) {
        match self {
            Self::Obfuscated(udp) => udp.io.set_read_timeout(timeout),
            Self::Plain(io) => io.set_read_timeout(timeout),
        }
    }
}

struct ObfuscatedUdp {
    io: PacketIo,
    key: [u8; 32],
    nonce: [u8; 12],
    decoy: Option<u8>,
}

impl ObfuscatedUdp {
    fn send(&mut self, plain: &[u8]) -> io::Result<usize> {
        if plain.len() > MAX_PACKET_SIZE - OBFUSCATION_OVERHEAD {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "psiphon quic packet too long",
            ));
        }
        let mut framed = [0u8; MAX_PACKET_SIZE];
        loop {
            getrandom::fill(&mut self.nonce).map_err(|_| io::Error::other("psiphon quic nonce"))?;
            let max_padding = PADDING_LIMIT.saturating_sub(plain.len()).min(255);
            let padding = bounded_random(max_padding + 1)?;
            framed[..12].copy_from_slice(&self.nonce);
            framed[12] = padding as u8;
            let padding_end = 13 + padding;
            getrandom::fill(&mut framed[13..padding_end])
                .map_err(|_| io::Error::other("psiphon quic padding"))?;
            framed[padding_end..padding_end + plain.len()].copy_from_slice(plain);
            let end = padding_end + plain.len();
            let mut cipher = ChaCha20::new(&self.key.into(), &self.nonce.into());
            cipher.apply_keystream(&mut framed[12..end]);
            if !looks_like_quic_initial(&framed[..end]) {
                self.io.send(&framed[..end])?;
                return Ok(plain.len());
            }
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let count = self.io.recv(buf)?;
            if let Some(left) = self.decoy.as_mut() {
                if *left > 0 && bounded_random(2)? == 1 {
                    *left -= 1;
                    let length = 1 + bounded_random(PADDING_LIMIT)?;
                    let mut decoy = [0u8; PADDING_LIMIT];
                    getrandom::fill(&mut decoy[..length])
                        .map_err(|_| io::Error::other("psiphon quic decoy"))?;
                    let _ = self.io.send(&decoy[..length]);
                }
            }
            if count < OBFUSCATION_OVERHEAD {
                continue;
            }
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&buf[..12]);
            {
                let mut cipher = ChaCha20::new(&self.key.into(), &nonce.into());
                cipher.apply_keystream(&mut buf[12..count]);
            }
            let padding = usize::from(buf[12]);
            let start = OBFUSCATION_OVERHEAD + padding;
            if start > count {
                continue;
            }
            let length = count - start;
            buf.copy_within(start..count, 0);
            if length == 0 || buf[0] & 0x40 == 0 {
                continue;
            }
            return Ok(length);
        }
    }
}

fn bounded_random(bound: usize) -> io::Result<usize> {
    if bound <= 1 {
        return Ok(0);
    }
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).map_err(|_| io::Error::other("psiphon quic padding"))?;
    let value = u64::from(u32::from_le_bytes(bytes));
    Ok(((value * bound as u64) >> 32) as usize)
}

fn looks_like_quic_initial(packet: &[u8]) -> bool {
    packet.len() >= 5 && packet[0] >> 4 == 0x0c && packet[1..5] == [0, 0, 0, 1]
}

fn packet_key(key: &str) -> Result<[u8; 32], String> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"quic-obfuscation-key"), key.as_bytes());
    let mut derived = [0u8; 32];
    hkdf.expand(&[], &mut derived)
        .map_err(|error| format!("psiphon quic key: {error}"))?;
    Ok(derived)
}

#[derive(Clone, Copy)]
struct SentPacket {
    pn: u64,
    space: usize,
    sent_at: Instant,
    size: u64,
    crypto: Option<(u64, u64)>,
    stream: Option<(u64, u64)>,
    window: bool,
}

struct Engine {
    tls: ClientConnection,
    initial: Keys,
    handshake: Option<Keys>,
    one_rtt: Option<Keys>,
    next_secrets: Option<Secrets>,
    key_phase: bool,
    level: usize,
    dcid: Vec<u8>,
    scid: Vec<u8>,
    next_pn: [u64; 3],
    largest: [u64; 3],
    ack_seen: [Vec<u64>; 3],
    ack_pending: [bool; 3],
    crypto_send: [Vec<u8>; 3],
    crypto_sent: [usize; 3],
    crypto_recv: [BTreeMap<u64, Vec<u8>>; 3],
    crypto_next: [u64; 3],
    stream_id: u64,
    stream_base: u64,
    stream_data: Vec<u8>,
    stream_sent: u64,
    recv_map: BTreeMap<u64, Vec<u8>>,
    recv_next: u64,
    recv_delivered: u64,
    recv_fin_at: u64,
    recv_fin: bool,
    recv_eof: bool,
    max_data: u64,
    max_stream: u64,
    peer_max_data: u64,
    peer_max_stream: u64,
    peer_streams_bidi: u64,
    peer_params: bool,
    received: Vec<u8>,
    sent: Vec<SentPacket>,
    retx: VecDeque<(u64, u64)>,
    srtt: Option<Duration>,
    rttvar: Duration,
    cwnd: u64,
    bytes_in_flight: u64,
    last_send: Instant,
    opened: bool,
    close_sent: bool,
    window_update: bool,
    path_response: Option<[u8; 8]>,
    tx_scratch: Vec<u8>,
}

impl Engine {
    fn new(key: &str, randomized: bool) -> Result<Self, String> {
        let config = client_config(randomized)?;
        let mut dcid = vec![0u8; CID_LEN];
        getrandom::fill(&mut dcid).map_err(|error| format!("psiphon quic dcid: {error}"))?;
        let mut scid = vec![0u8; CID_LEN];
        getrandom::fill(&mut scid).map_err(|error| format!("psiphon quic scid: {error}"))?;
        let params = transport_params(&scid, randomized)?;
        let name = quic_server_name();
        let server_name = ServerName::try_from(name.as_str())
            .map_err(|error| format!("psiphon quic server name: {error}"))?
            .to_owned();
        let passthrough = tls_passthrough(key)?;
        let tls = PENDING_RANDOM
            .with(|slot| {
                *slot.borrow_mut() = Some(passthrough);
                let created =
                    ClientConnection::new(Arc::new(config), Version::V1, server_name, params);
                slot.borrow_mut().take();
                created
            })
            .map_err(|error| format!("psiphon quic tls: {error}"))?;
        let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
            .tls13()
            .and_then(rustls::Tls13CipherSuite::quic_suite)
            .ok_or_else(|| "psiphon quic initial suite".to_owned())?;
        let initial = suite.keys(&dcid, Side::Client, Version::V1);
        let mut engine = Self {
            tls,
            initial,
            handshake: None,
            one_rtt: None,
            next_secrets: None,
            key_phase: false,
            level: INITIAL,
            dcid,
            scid,
            next_pn: [0; 3],
            largest: [0; 3],
            ack_seen: std::array::from_fn(|_| Vec::new()),
            ack_pending: [false; 3],
            crypto_send: std::array::from_fn(|_| Vec::new()),
            crypto_sent: [0; 3],
            crypto_recv: std::array::from_fn(|_| BTreeMap::new()),
            crypto_next: [0; 3],
            stream_id: 0,
            stream_base: 0,
            stream_data: Vec::new(),
            stream_sent: 0,
            recv_map: BTreeMap::new(),
            recv_next: 0,
            recv_delivered: 0,
            recv_fin_at: 0,
            recv_fin: false,
            recv_eof: false,
            max_data: INITIAL_WINDOW,
            max_stream: STREAM_WINDOW,
            peer_max_data: 0,
            peer_max_stream: 0,
            peer_streams_bidi: 0,
            peer_params: false,
            received: Vec::new(),
            sent: Vec::new(),
            retx: VecDeque::new(),
            srtt: None,
            rttvar: Duration::ZERO,
            cwnd: INITIAL_CWND,
            bytes_in_flight: 0,
            last_send: Instant::now(),
            opened: false,
            close_sent: false,
            window_update: false,
            path_response: None,
            tx_scratch: Vec::new(),
        };
        engine.pump_tls()?;
        Ok(engine)
    }

    fn keys(&self, space: usize) -> Option<&Keys> {
        match space {
            INITIAL => Some(&self.initial),
            HANDSHAKE => self.handshake.as_ref(),
            ONE_RTT => self.one_rtt.as_ref(),
            _ => None,
        }
    }

    fn ready(&self) -> bool {
        self.one_rtt.is_some() && !self.tls.is_handshaking() && self.peer_params
    }

    fn open_stream(&mut self) {
        self.stream_id = 0;
        self.opened = true;
    }

    fn pump_tls(&mut self) -> Result<(), String> {
        loop {
            let mut bytes = Vec::new();
            let change = self.tls.write_hs(&mut bytes);
            if !bytes.is_empty() {
                self.crypto_send[self.level].extend_from_slice(&bytes);
            }
            match change {
                Some(KeyChange::Handshake { keys }) => {
                    self.handshake = Some(keys);
                    self.level = HANDSHAKE;
                }
                Some(KeyChange::OneRtt { keys, next }) => {
                    self.one_rtt = Some(keys);
                    self.next_secrets = Some(next);
                    self.level = ONE_RTT;
                }
                None => break,
            }
        }
        if !self.peer_params {
            if let Some(params) = self.tls.quic_transport_parameters() {
                let params = params.to_vec();
                self.apply_peer_params(&params)?;
            }
        }
        Ok(())
    }

    fn apply_peer_params(&mut self, params: &[u8]) -> Result<(), String> {
        let mut at = 0usize;
        while at < params.len() {
            let id = get_varint(params, &mut at)
                .ok_or_else(|| "psiphon quic transport parameter".to_owned())?;
            let len = get_varint(params, &mut at)
                .ok_or_else(|| "psiphon quic transport parameter".to_owned())?;
            let len =
                usize::try_from(len).map_err(|_| "psiphon quic transport parameter".to_owned())?;
            let end = at
                .checked_add(len)
                .filter(|end| *end <= params.len())
                .ok_or_else(|| "psiphon quic transport parameter".to_owned())?;
            match id {
                0x04 => self.peer_max_data = get_varint(params, &mut at).unwrap_or(0),
                0x06 => self.peer_max_stream = get_varint(params, &mut at).unwrap_or(0),
                0x08 => self.peer_streams_bidi = get_varint(params, &mut at).unwrap_or(0),
                _ => {}
            }
            at = end;
        }
        self.peer_params = true;
        if self.peer_max_stream == 0 {
            self.peer_max_stream = self.peer_max_data;
        }
        if self.peer_streams_bidi == 0 {
            return Err("psiphon quic: peer refuses a stream".to_owned());
        }
        if self.peer_max_stream == 0 {
            return Err("psiphon quic: peer grants no stream credit".to_owned());
        }
        Ok(())
    }

    fn wait_timeout(&self, now: Instant) -> Duration {
        let pto = self.pto();
        let next = self
            .sent
            .first()
            .map(|packet| packet.sent_at + pto)
            .map_or(READ_WAIT, |at| at.saturating_duration_since(now));
        next.min(READ_WAIT).max(Duration::from_millis(1))
    }

    fn pto(&self) -> Duration {
        self.srtt
            .map_or(Duration::from_millis(250), |srtt| {
                srtt * 2 + self.rttvar * 4 + Duration::from_millis(25)
            })
            .max(Duration::from_millis(200))
    }

    fn flush(&mut self, udp: &mut Udp, now: Instant) -> Result<(), String> {
        self.pump_tls()?;
        self.expire(now);
        for space in [INITIAL, HANDSHAKE] {
            if self.ack_pending[space] || self.crypto_pending(space) {
                self.send_space(space, udp, now)?;
            }
        }
        if self.one_rtt.is_some() {
            for _ in 0..64 {
                if !self.send_space(ONE_RTT, udp, now)? {
                    break;
                }
            }
        }
        Ok(())
    }

    fn crypto_pending(&self, space: usize) -> bool {
        self.crypto_sent[space] < self.crypto_send[space].len()
    }

    fn expire(&mut self, now: Instant) {
        let pto = self.pto();
        let mut at = 0;
        while at < self.sent.len() && now.saturating_duration_since(self.sent[at].sent_at) >= pto {
            let packet = self.sent[at];
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(packet.size);
            if let Some((offset, _len)) = packet.crypto {
                self.crypto_sent[packet.space] =
                    self.crypto_sent[packet.space].min(offset as usize);
            }
            if let Some((offset, len)) = packet.stream {
                self.retx.push_back((offset, len));
            }
            if packet.window {
                self.window_update = true;
            }
            at += 1;
        }
        if at > 0 {
            self.sent.drain(..at);
            self.cwnd = INITIAL_CWND;
        }
    }

    #[allow(clippy::too_many_lines)]
    fn send_space(&mut self, space: usize, udp: &mut Udp, now: Instant) -> Result<bool, String> {
        if self.keys(space).is_none() {
            return Ok(false);
        }
        let pn = self.next_pn[space];
        let head = if space == ONE_RTT {
            1 + self.dcid.len() + 4
        } else {
            0
        };
        let mut payload = std::mem::take(&mut self.tx_scratch);
        payload.clear();
        payload.reserve(head + MAX_PAYLOAD + 64);
        if head > 0 {
            payload.resize(head, 0);
        }
        let mut crypto_frame = None;
        let mut stream_frame = None;
        let mut window_frame = false;
        let mut ack_eliciting = false;
        if self.ack_pending[space] {
            put_ack(&mut payload, &self.ack_seen[space]);
            self.ack_pending[space] = false;
            self.ack_seen[space].clear();
        }
        if space == ONE_RTT {
            if let Some(token) = self.path_response.take() {
                payload.push(0x1b);
                payload.extend_from_slice(&token);
                ack_eliciting = true;
            }
            if self.window_update {
                put_varint(&mut payload, 0x10);
                put_varint(&mut payload, self.max_data);
                put_varint(&mut payload, 0x11);
                put_varint(&mut payload, self.stream_id);
                put_varint(&mut payload, self.max_stream);
                self.window_update = false;
                window_frame = true;
                ack_eliciting = true;
            }
            if let Some((offset, len)) = self.retx.pop_front() {
                if let Some(frame) = self.write_stream_frame(&mut payload, offset, len) {
                    stream_frame = Some(frame);
                    ack_eliciting = true;
                }
            }
            if stream_frame.is_none()
                && self.opened
                && self.stream_sent < self.stream_base + self.stream_data.len() as u64
                && self.bytes_in_flight < self.cwnd
            {
                let available = (self.stream_base + self.stream_data.len() as u64)
                    .saturating_sub(self.stream_sent);
                let limit = self
                    .peer_max_stream
                    .min(self.peer_max_data)
                    .saturating_sub(self.stream_sent);
                let room = available
                    .min(limit)
                    .min(Self::max_payload_room(payload.len() - head) as u64);
                if room > 0 {
                    if let Some(frame) =
                        self.write_stream_frame(&mut payload, self.stream_sent, room)
                    {
                        self.stream_sent += frame.1;
                        stream_frame = Some(frame);
                        ack_eliciting = true;
                    }
                }
            }
        } else if self.crypto_pending(space) {
            let data = &self.crypto_send[space][self.crypto_sent[space]..];
            let len = data.len().min(Self::max_payload_room(payload.len() - head));
            if len > 0 {
                let offset = self.crypto_sent[space] as u64;
                payload.push(0x06);
                put_varint(&mut payload, offset);
                put_varint(&mut payload, len as u64);
                payload.extend_from_slice(&data[..len]);
                crypto_frame = Some((offset, len as u64));
                ack_eliciting = true;
            }
        }
        if payload.len() == head {
            if space == ONE_RTT && now.saturating_duration_since(self.last_send) >= KEEPALIVE {
                payload.push(0x01);
                ack_eliciting = true;
            } else {
                self.tx_scratch = payload;
                return Ok(false);
            }
        }
        if space == INITIAL {
            self.pad_initial(&mut payload, pn);
        }
        if space == ONE_RTT {
            self.seal_short(pn, &mut payload, head)?;
            self.next_pn[space] += 1;
            let size = payload.len() as u64;
            if ack_eliciting {
                self.sent.push(SentPacket {
                    pn,
                    space,
                    sent_at: now,
                    size,
                    crypto: crypto_frame,
                    stream: stream_frame,
                    window: window_frame,
                });
                self.bytes_in_flight = self.bytes_in_flight.saturating_add(size);
            }
            self.last_send = now;
            udp.send(&payload)
                .map_err(|error| format!("psiphon quic send failed: {error}"))?;
            self.tx_scratch = payload;
            return Ok(true);
        }
        let packet = self.seal(space, pn, &payload)?;
        self.tx_scratch = payload;
        self.next_pn[space] += 1;
        let size = packet.len() as u64;
        if ack_eliciting {
            self.sent.push(SentPacket {
                pn,
                space,
                sent_at: now,
                size,
                crypto: crypto_frame,
                stream: stream_frame,
                window: window_frame,
            });
            self.bytes_in_flight = self.bytes_in_flight.saturating_add(size);
        }
        self.last_send = now;
        udp.send(&packet)
            .map_err(|error| format!("psiphon quic send failed: {error}"))?;
        Ok(true)
    }

    fn max_payload_room(used: usize) -> usize {
        MAX_PAYLOAD.saturating_sub(used)
    }

    fn pad_initial(&self, payload: &mut Vec<u8>, _pn: u64) {
        let header = long_header_len(true, self.dcid.len(), self.scid.len(), 4);
        let filled = header + 4 + payload.len() + 16;
        if filled < 1200 {
            payload.resize(payload.len() + (1200 - filled), 0);
        }
    }

    fn write_stream_frame(
        &self,
        payload: &mut Vec<u8>,
        offset: u64,
        len: u64,
    ) -> Option<(u64, u64)> {
        if offset < self.stream_base {
            return None;
        }
        let start = usize::try_from(offset - self.stream_base).ok()?;
        let len = usize::try_from(len).ok()?;
        let end = start.checked_add(len)?.min(self.stream_data.len());
        if end <= start {
            return None;
        }
        let bytes = &self.stream_data[start..end];
        payload.push(0x08 | if offset > 0 { 0x04 } else { 0 } | 0x02);
        put_varint(payload, self.stream_id);
        if offset > 0 {
            put_varint(payload, offset);
        }
        put_varint(payload, bytes.len() as u64);
        payload.extend_from_slice(bytes);
        Some((offset, bytes.len() as u64))
    }

    fn seal(&self, space: usize, pn: u64, payload: &[u8]) -> Result<Vec<u8>, String> {
        let keys = self
            .keys(space)
            .ok_or_else(|| "psiphon quic keys".to_owned())?;
        let pn_len = 4usize;
        let packet_type = match space {
            INITIAL => 0u8,
            HANDSHAKE => 2u8,
            _ => 3u8,
        };
        let mut header = Vec::with_capacity(64);
        header.push(0x80 | packet_type << 4 | (pn_len as u8 - 1));
        header.extend_from_slice(&QUIC_VERSION.to_be_bytes());
        header.push(u8::try_from(self.dcid.len()).unwrap_or(0));
        header.extend_from_slice(&self.dcid);
        header.push(u8::try_from(self.scid.len()).unwrap_or(0));
        header.extend_from_slice(&self.scid);
        if space == INITIAL {
            put_varint(&mut header, 0);
        }
        let length = pn_len as u64 + payload.len() as u64 + 16;
        put_varint(&mut header, length);
        let pn_offset = header.len();
        header.extend_from_slice(&pn.to_be_bytes()[8 - pn_len..]);
        let header_len = header.len();
        let mut packet = header;
        packet.extend_from_slice(payload);
        let (head, body) = packet.split_at_mut(header_len);
        let tag = keys
            .local
            .packet
            .encrypt_in_place(pn, head, body)
            .map_err(|error| format!("psiphon quic seal: {error}"))?;
        packet.extend_from_slice(tag.as_ref());
        let sample_len = keys.local.header.sample_len();
        let sample_at = pn_offset + 4;
        if packet.len() < sample_at + sample_len {
            return Err("psiphon quic short packet".to_owned());
        }
        let mut sample = [0u8; 16];
        let sample = sample
            .get_mut(..sample_len)
            .ok_or_else(|| "psiphon quic short sample".to_owned())?;
        sample.copy_from_slice(&packet[sample_at..sample_at + sample_len]);
        let (first, rest) = packet.split_at_mut(1);
        let pn_slice = &mut rest[pn_offset - 1..pn_offset + pn_len - 1];
        keys.local
            .header
            .encrypt_in_place(sample, &mut first[0], pn_slice)
            .map_err(|error| format!("psiphon quic header: {error}"))?;
        Ok(packet)
    }

    /// Sealing a one-RTT packet in the buffer its frames were built in: the header fills the prefix the caller reserved, the payload is encrypted where it lies, and the tag lands after it, so no plaintext is copied into a second allocation.
    fn seal_short(&self, pn: u64, packet: &mut Vec<u8>, head: usize) -> Result<(), String> {
        let keys = self
            .one_rtt
            .as_ref()
            .ok_or_else(|| "psiphon quic keys".to_owned())?;
        let pn_len = 4usize;
        let pn_offset = 1 + self.dcid.len();
        if packet.len() < head || head != pn_offset + pn_len {
            return Err("psiphon quic short packet".to_owned());
        }
        packet[0] = 0x40 | (u8::from(self.key_phase) << 2) | (pn_len as u8 - 1);
        packet[1..pn_offset].copy_from_slice(&self.dcid);
        packet[pn_offset..head].copy_from_slice(&pn.to_be_bytes()[8 - pn_len..]);
        let (header, body) = packet.split_at_mut(head);
        let tag = keys
            .local
            .packet
            .encrypt_in_place(pn, header, body)
            .map_err(|error| format!("psiphon quic seal: {error}"))?;
        packet.extend_from_slice(tag.as_ref());
        let sample_len = keys.local.header.sample_len();
        if packet.len() < head + sample_len {
            return Err("psiphon quic short packet".to_owned());
        }
        let mut sample = [0u8; 16];
        let sample = sample
            .get_mut(..sample_len)
            .ok_or_else(|| "psiphon quic short sample".to_owned())?;
        sample.copy_from_slice(&packet[head..head + sample_len]);
        let (first, rest) = packet.split_at_mut(1);
        let pn_slice = &mut rest[pn_offset - 1..head - 1];
        keys.local
            .header
            .encrypt_in_place(sample, &mut first[0], pn_slice)
            .map_err(|error| format!("psiphon quic header: {error}"))?;
        Ok(())
    }

    fn receive(&mut self, datagram: &mut [u8], now: Instant) -> Result<(), String> {
        let mut at = 0usize;
        while at < datagram.len() {
            let first = datagram[at];
            if first & 0x80 != 0 {
                if at + 7 > datagram.len() {
                    break;
                }
                let version = u32::from_be_bytes([
                    datagram[at + 1],
                    datagram[at + 2],
                    datagram[at + 3],
                    datagram[at + 4],
                ]);
                if version == 0 {
                    return Err("psiphon quic: version negotiation".to_owned());
                }
                if version != QUIC_VERSION {
                    return Err(format!("psiphon quic: unsupported version {version}"));
                }
                let dcid_len = usize::from(datagram[at + 5]);
                let mut cursor = at + 6;
                if cursor + dcid_len + 1 > datagram.len() {
                    break;
                }
                cursor += dcid_len;
                let scid_len = usize::from(datagram[cursor]);
                cursor += 1;
                if cursor + scid_len > datagram.len() {
                    break;
                }
                let scid = datagram[cursor..cursor + scid_len].to_vec();
                cursor += scid_len;
                let packet_type = (first >> 4) & 0x03;
                if packet_type == 3 {
                    return Err("psiphon quic: retry is not supported".to_owned());
                }
                if packet_type == 0 {
                    let Some(token_len) = get_varint(datagram, &mut cursor) else {
                        break;
                    };
                    let token_len = usize::try_from(token_len).unwrap_or(0);
                    cursor = cursor.saturating_add(token_len);
                }
                if cursor >= datagram.len() {
                    break;
                }
                let Some(length) = get_varint(datagram, &mut cursor) else {
                    break;
                };
                let length = usize::try_from(length).unwrap_or(0);
                let end = cursor.saturating_add(length).min(datagram.len());
                if end <= cursor {
                    break;
                }
                let space = match packet_type {
                    0 => INITIAL,
                    2 => HANDSHAKE,
                    _ => break,
                };
                if !scid.is_empty() && scid != self.dcid {
                    self.dcid = scid;
                }
                let pn_offset = cursor - at;
                self.open(space, &mut datagram[at..end], pn_offset, now)?;
                at = end;
            } else {
                let pn_offset = 1 + self.scid.len();
                if at + pn_offset > datagram.len() {
                    break;
                }
                self.open(ONE_RTT, &mut datagram[at..], pn_offset, now)?;
                break;
            }
        }
        Ok(())
    }

    fn open(
        &mut self,
        space: usize,
        packet: &mut [u8],
        pn_offset: usize,
        now: Instant,
    ) -> Result<(), String> {
        let (pn, header_end, key_phase) = {
            let Some(keys) = self.keys(space) else {
                return Ok(());
            };
            let sample_len = keys.remote.header.sample_len();
            if packet.len() < pn_offset + 4 + sample_len {
                return Ok(());
            }
            let mut sample = [0u8; 16];
            let sample = sample
                .get_mut(..sample_len)
                .ok_or_else(|| "psiphon quic short sample".to_owned())?;
            sample.copy_from_slice(&packet[pn_offset + 4..pn_offset + 4 + sample_len]);
            let mut first = packet[0];
            let mut pnb = [
                packet[pn_offset],
                packet[pn_offset + 1],
                packet[pn_offset + 2],
                packet[pn_offset + 3],
            ];
            keys.remote
                .header
                .decrypt_in_place(&sample, &mut first, &mut pnb)
                .map_err(|error| format!("psiphon quic header: {error}"))?;
            let pn_len = usize::from(first & 0x03) + 1;
            let truncated = pnb[..pn_len]
                .iter()
                .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
            let pn = decode_pn(truncated, (pn_len * 8) as u32, self.largest[space]);
            packet[0] = first;
            packet[pn_offset..pn_offset + pn_len].copy_from_slice(&pnb[..pn_len]);
            let header_end = pn_offset + pn_len;
            if packet.len() <= header_end + 16 {
                return Ok(());
            }
            (pn, header_end, space == ONE_RTT && first & 0x04 != 0)
        };
        let mut plain_len = None;
        if key_phase != self.key_phase {
            if let Some(mut secrets) = self.next_secrets.clone() {
                let next = secrets.next_packet_keys();
                let mut trial = packet.to_vec();
                let (header, payload) = trial.split_at_mut(header_end);
                if let Ok(plain) = next.remote.decrypt_in_place(pn, header, payload) {
                    plain_len = Some(plain.len());
                    if let Some(keys) = self.one_rtt.as_mut() {
                        keys.local.packet = next.local;
                        keys.remote.packet = next.remote;
                    }
                    self.next_secrets = Some(secrets);
                    self.key_phase = key_phase;
                    packet.copy_from_slice(&trial);
                }
            }
        }
        let plain_len = if let Some(plain_len) = plain_len {
            plain_len
        } else {
            let Some(keys) = self.keys(space) else {
                return Ok(());
            };
            let (header, payload) = packet.split_at_mut(header_end);
            keys.remote
                .packet
                .decrypt_in_place(pn, header, payload)
                .map_err(|error| format!("psiphon quic decrypt: {error}"))?
                .len()
        };
        self.largest[space] = self.largest[space].max(pn);
        let seen = &mut self.ack_seen[space];
        if let Err(at) = seen.binary_search(&pn) {
            seen.insert(at, pn);
        }
        self.ack_pending[space] = true;
        self.handle_frames(space, &packet[header_end..header_end + plain_len], now)
    }

    #[allow(clippy::too_many_lines)]
    fn handle_frames(&mut self, space: usize, payload: &[u8], now: Instant) -> Result<(), String> {
        let mut at = 0usize;
        while at < payload.len() {
            let Some(kind) = get_varint(payload, &mut at) else {
                break;
            };
            match kind {
                0x00 | 0x01 | 0x1e => {}
                0x02 | 0x03 => {
                    let Some(largest) = get_varint(payload, &mut at) else {
                        break;
                    };
                    let Some(_delay) = get_varint(payload, &mut at) else {
                        break;
                    };
                    let Some(count) = get_varint(payload, &mut at) else {
                        break;
                    };
                    let Some(first) = get_varint(payload, &mut at) else {
                        break;
                    };
                    let mut acked = Vec::new();
                    let mut low = largest.saturating_sub(first);
                    acked.push((low, largest));
                    for _ in 0..count {
                        let Some(gap) = get_varint(payload, &mut at) else {
                            break;
                        };
                        let Some(len) = get_varint(payload, &mut at) else {
                            break;
                        };
                        let high = low.saturating_sub(gap + 2);
                        low = high.saturating_sub(len);
                        acked.push((low, high));
                    }
                    if kind == 0x03 {
                        let _ = get_varint(payload, &mut at);
                        let _ = get_varint(payload, &mut at);
                        let _ = get_varint(payload, &mut at);
                    }
                    self.ack(space, &acked, now);
                }
                0x04 => {
                    let Some(stream) = get_varint(payload, &mut at) else {
                        break;
                    };
                    let _ = get_varint(payload, &mut at);
                    let _ = get_varint(payload, &mut at);
                    if stream == self.stream_id {
                        return Err("psiphon quic: stream reset".to_owned());
                    }
                }
                0x05 => {
                    let _ = get_varint(payload, &mut at);
                    let _ = get_varint(payload, &mut at);
                }
                0x06 => {
                    let Some(offset) = get_varint(payload, &mut at) else {
                        break;
                    };
                    let Some(len) = get_varint(payload, &mut at) else {
                        break;
                    };
                    let len = usize::try_from(len).unwrap_or(0);
                    let end = at.saturating_add(len).min(payload.len());
                    self.feed_crypto(space, offset, &payload[at..end])?;
                    at = end;
                }
                0x08..=0x0f => {
                    let off_bit = kind & 0x04 != 0;
                    let len_bit = kind & 0x02 != 0;
                    let fin = kind & 0x01 != 0;
                    let Some(stream) = get_varint(payload, &mut at) else {
                        break;
                    };
                    let offset = if off_bit {
                        match get_varint(payload, &mut at) {
                            Some(offset) => offset,
                            None => break,
                        }
                    } else {
                        0
                    };
                    let len = if len_bit {
                        match get_varint(payload, &mut at) {
                            Some(len) => usize::try_from(len).unwrap_or(0),
                            None => break,
                        }
                    } else {
                        payload.len().saturating_sub(at)
                    };
                    let end = at.saturating_add(len).min(payload.len());
                    if stream == self.stream_id {
                        self.feed_stream(offset, &payload[at..end], fin)?;
                    }
                    at = end;
                }
                0x10 => {
                    if let Some(value) = get_varint(payload, &mut at) {
                        self.peer_max_data = self.peer_max_data.max(value);
                    }
                }
                0x11 => {
                    let Some(stream) = get_varint(payload, &mut at) else {
                        break;
                    };
                    let Some(value) = get_varint(payload, &mut at) else {
                        break;
                    };
                    if stream == self.stream_id {
                        self.peer_max_stream = self.peer_max_stream.max(value);
                    }
                }
                0x12 | 0x13 => {
                    if let Some(value) = get_varint(payload, &mut at) {
                        if kind == 0x12 {
                            self.peer_streams_bidi = self.peer_streams_bidi.max(value);
                        }
                    }
                }
                0x14 => {
                    let _ = get_varint(payload, &mut at);
                    self.window_update = true;
                }
                0x15 => {
                    let _ = get_varint(payload, &mut at);
                    let _ = get_varint(payload, &mut at);
                    self.window_update = true;
                }
                0x16 | 0x17 | 0x19 => {
                    let _ = get_varint(payload, &mut at);
                }
                0x18 => {
                    let _ = get_varint(payload, &mut at);
                    let _ = get_varint(payload, &mut at);
                    let Some(len) = get_varint(payload, &mut at) else {
                        break;
                    };
                    at = at
                        .saturating_add(usize::try_from(len).unwrap_or(0))
                        .saturating_add(16);
                }
                0x1a => {
                    if at + 8 > payload.len() {
                        break;
                    }
                    let mut token = [0u8; 8];
                    token.copy_from_slice(&payload[at..at + 8]);
                    at += 8;
                    self.path_response = Some(token);
                }
                0x1b => {
                    at = at.saturating_add(8);
                }
                0x1c => {
                    let code = get_varint(payload, &mut at).unwrap_or(0);
                    let _ = get_varint(payload, &mut at);
                    let _ = get_varint(payload, &mut at);
                    return Err(format!("psiphon quic closed: {code}"));
                }
                0x1d => {
                    let code = get_varint(payload, &mut at).unwrap_or(0);
                    let _ = get_varint(payload, &mut at);
                    return Err(format!("psiphon quic application closed: {code}"));
                }
                0x07 | 0x30 | 0x31 => {
                    let Some(len) = get_varint(payload, &mut at) else {
                        break;
                    };
                    at = at.saturating_add(usize::try_from(len).unwrap_or(0));
                }
                _ => return Err(format!("psiphon quic: unknown frame {kind:#x}")),
            }
        }
        Ok(())
    }

    fn ack(&mut self, space: usize, ranges: &[(u64, u64)], now: Instant) {
        let len = self.sent.len();
        let mut write = 0usize;
        let mut newest: Option<SentPacket> = None;
        let mut acked_bytes = 0u64;
        for read in 0..len {
            let packet = self.sent[read];
            if packet.space == space
                && ranges
                    .iter()
                    .any(|(low, high)| packet.pn >= *low && packet.pn <= *high)
            {
                self.bytes_in_flight = self.bytes_in_flight.saturating_sub(packet.size);
                acked_bytes += packet.size;
                if newest.is_none_or(|newest| packet.sent_at > newest.sent_at) {
                    newest = Some(packet);
                }
            } else {
                self.sent[write] = packet;
                write += 1;
            }
        }
        if write == len {
            return;
        }
        self.sent.truncate(write);
        if let Some(packet) = newest {
            let sample = now.saturating_duration_since(packet.sent_at);
            if let Some(srtt) = self.srtt {
                let diff = sample.abs_diff(srtt);
                self.rttvar = (self.rttvar * 3 + diff) / 4;
                self.srtt = Some((srtt * 7 + sample) / 8);
            } else {
                self.srtt = Some(sample);
                self.rttvar = sample / 2;
            }
        }
        let growth = (MSS * acked_bytes / self.cwnd.max(1)).max(MSS);
        self.cwnd = (self.cwnd + growth).min(MAX_CWND);
        self.compact_stream();
    }

    fn compact_stream(&mut self) {
        let first = self
            .sent
            .iter()
            .filter_map(|packet| packet.stream.map(|(offset, _)| offset))
            .chain(self.retx.iter().map(|(offset, _)| *offset))
            .min()
            .unwrap_or(self.stream_sent)
            .min(self.stream_sent);
        if first > self.stream_base {
            let advance = usize::try_from(first - self.stream_base).unwrap_or(usize::MAX);
            let advance = advance.min(self.stream_data.len());
            self.stream_data.drain(..advance);
            self.stream_base = self.stream_base.saturating_add(advance as u64);
        }
    }

    fn feed_crypto(&mut self, space: usize, offset: u64, data: &[u8]) -> Result<(), String> {
        if data.is_empty() {
            return Ok(());
        }
        self.crypto_recv[space].insert(offset, data.to_vec());
        loop {
            let next = self.crypto_next[space];
            let Some(offset) = self.crypto_recv[space].keys().next().copied() else {
                break;
            };
            if offset > next {
                break;
            }
            let Some(data) = self.crypto_recv[space].remove(&offset) else {
                break;
            };
            let skip = usize::try_from(next.saturating_sub(offset)).unwrap_or(0);
            if skip >= data.len() {
                continue;
            }
            let chunk_len = data.len() - skip;
            self.tls
                .read_hs(&data[skip..])
                .map_err(|error| format!("psiphon quic tls: {error}"))?;
            self.crypto_next[space] = next.saturating_add(chunk_len as u64);
            self.pump_tls()?;
        }
        Ok(())
    }

    fn feed_stream(&mut self, offset: u64, data: &[u8], fin: bool) -> Result<(), String> {
        let end = offset.saturating_add(data.len() as u64);
        if end > self.max_stream || end > self.max_data {
            return Err("psiphon quic: stream flow control violated".to_owned());
        }
        if fin {
            self.recv_fin = true;
            self.recv_fin_at = end;
        }
        if data.is_empty() {
            if self.recv_fin && self.recv_next >= self.recv_fin_at {
                self.recv_eof = true;
            }
            return Ok(());
        }
        if self.recv_map.is_empty() && offset <= self.recv_next {
            let skip = usize::try_from(self.recv_next - offset).unwrap_or(usize::MAX);
            if skip < data.len() {
                self.received.extend_from_slice(&data[skip..]);
                self.recv_next = end;
            }
        } else if offset < self.recv_next {
            let skip = usize::try_from(self.recv_next - offset).unwrap_or(usize::MAX);
            if skip < data.len() {
                self.recv_map
                    .entry(self.recv_next)
                    .or_insert_with(|| data[skip..].to_vec());
            }
        } else {
            self.recv_map.entry(offset).or_insert_with(|| data.to_vec());
        }
        loop {
            let next = self.recv_next;
            let Some(offset) = self.recv_map.keys().next().copied() else {
                break;
            };
            if offset > next {
                break;
            }
            let Some(data) = self.recv_map.remove(&offset) else {
                break;
            };
            let skip = usize::try_from(next.saturating_sub(offset)).unwrap_or(0);
            if skip >= data.len() {
                continue;
            }
            self.received.extend_from_slice(&data[skip..]);
            self.recv_next = next.saturating_add((data.len() - skip) as u64);
        }
        if self.recv_fin && self.recv_next >= self.recv_fin_at && self.recv_map.is_empty() {
            self.recv_eof = true;
        }
        Ok(())
    }

    fn release(&mut self, count: u64) {
        self.recv_delivered = self.recv_delivered.saturating_add(count);
        if self.recv_delivered + STREAM_WINDOW / 2 > self.max_stream {
            self.max_stream = self.recv_delivered + STREAM_WINDOW;
            self.max_data = self.recv_delivered + INITIAL_WINDOW;
            self.window_update = true;
        }
    }

    fn pull_received(&mut self, out: &mut Vec<u8>, limit: usize) -> usize {
        if out.is_empty() && limit >= self.received.len() {
            std::mem::swap(out, &mut self.received);
            return out.len();
        }
        let count = self.received.len().min(limit);
        out.extend_from_slice(&self.received[..count]);
        self.received.drain(..count);
        count
    }

    fn queue_stream(&mut self, data: &[u8]) -> usize {
        if !self.opened {
            return 0;
        }
        let queued_end = self.stream_base + self.stream_data.len() as u64;
        let limit = self.peer_max_stream.min(self.peer_max_data);
        let room = limit.saturating_sub(queued_end);
        let count = usize::try_from(room.min(data.len() as u64)).unwrap_or(0);
        self.stream_data.extend_from_slice(&data[..count]);
        count
    }
}

fn discardable(error: &str) -> bool {
    error.starts_with("psiphon quic header:") || error.starts_with("psiphon quic decrypt:")
}

fn drive(shared: &Arc<Shared>, mut udp: Udp, mut engine: Engine) {
    let mut datagram = vec![0u8; 65535];
    loop {
        let now = Instant::now();
        {
            let mut state = lock(&shared.state);
            let mut wrote = false;
            loop {
                let (empty, count) = {
                    let Some(front) = state.send.front_mut() else {
                        break;
                    };
                    if front.is_empty() {
                        (true, 0)
                    } else {
                        let count = engine.queue_stream(front);
                        if count == 0 {
                            break;
                        }
                        front.drain(..count);
                        (front.is_empty(), count)
                    }
                };
                if count > 0 {
                    state.send_bytes = state.send_bytes.saturating_sub(count);
                    wrote = true;
                }
                if empty {
                    state.send.pop_front();
                }
            }
            if wrote {
                shared.writable.notify_all();
            }
        }

        let mut pulled = 0u64;
        {
            let mut state = lock(&shared.state);
            if state.read_at > 0 {
                let read_at = state.read_at;
                state.recv.drain(..read_at);
                state.read_at = 0;
            }
            let room = MAX_RECV_QUEUE.saturating_sub(state.recv.len());
            if room > 0 {
                pulled = engine.pull_received(&mut state.recv, room) as u64;
            }
            if pulled > 0 {
                shared.readable.notify_all();
            }
            if engine.recv_eof && engine.received.is_empty() {
                state.eof = true;
                shared.readable.notify_all();
            }
        }
        if pulled > 0 {
            engine.release(pulled);
        }

        let close = {
            let mut state = lock(&shared.state);
            if Arc::strong_count(shared) == 1 {
                state.close_requested = true;
            }
            state.close_requested
        };
        if close {
            if !engine.close_sent {
                let now = Instant::now();
                let _ = engine.send_close(&mut udp, now);
                engine.close_sent = true;
            }
            return;
        }

        if let Err(error) = engine.flush(&mut udp, now) {
            fail(shared, error);
            return;
        }

        let wait = engine.wait_timeout(Instant::now());
        udp.set_read_timeout(Some(wait));
        match udp.recv(&mut datagram) {
            Ok(count) => {
                let now = Instant::now();
                if let Err(error) = engine.receive(&mut datagram[..count], now) {
                    if !discardable(&error) {
                        fail(shared, error);
                        return;
                    }
                }
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(error) => {
                fail(shared, format!("psiphon quic receive failed: {error}"));
                return;
            }
        }
    }
}

impl Engine {
    fn send_close(&mut self, udp: &mut Udp, now: Instant) -> Result<(), String> {
        let space = if self.one_rtt.is_some() {
            ONE_RTT
        } else if self.handshake.is_some() {
            HANDSHAKE
        } else {
            INITIAL
        };
        let head = if space == ONE_RTT {
            1 + self.dcid.len() + 4
        } else {
            0
        };
        let mut payload = Vec::with_capacity(head + 8);
        if head > 0 {
            payload.resize(head, 0);
        }
        put_varint(&mut payload, 0x1c);
        put_varint(&mut payload, 0);
        put_varint(&mut payload, 0);
        put_varint(&mut payload, 0);
        if space == INITIAL {
            self.pad_initial(&mut payload, self.next_pn[space]);
        }
        let pn = self.next_pn[space];
        let packet = if space == ONE_RTT {
            self.seal_short(pn, &mut payload, head)?;
            payload
        } else {
            self.seal(space, pn, &payload)?
        };
        self.next_pn[space] += 1;
        let _ = now;
        udp.send(&packet)
            .map_err(|error| format!("psiphon quic close failed: {error}"))?;
        Ok(())
    }
}

fn fail(shared: &Shared, why: impl Into<String>) {
    let mut state = lock(&shared.state);
    state.fail(why);
    drop(state);
    shared.readable.notify_all();
    shared.writable.notify_all();
}

fn client_config(randomized: bool) -> Result<rustls::ClientConfig, String> {
    let mut provider = rustls::crypto::ring::default_provider();
    if randomized {
        randomize_cipher_suites(&mut provider)?;
        randomize_kx_groups(&mut provider)?;
    }
    let schemes = provider
        .signature_verification_algorithms
        .supported_schemes();
    provider.secure_random = &PASSTHROUGH_RANDOM;
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| format!("psiphon quic tls: {error}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify { schemes }))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    Ok(tls)
}

#[derive(Debug)]
struct PassthroughRandom;

static PASSTHROUGH_RANDOM: PassthroughRandom = PassthroughRandom;

impl SecureRandom for PassthroughRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        if buf.len() == 32 {
            if let Some(message) = PENDING_RANDOM.with(|slot| slot.borrow_mut().take()) {
                buf.copy_from_slice(&message);
                return Ok(());
            }
        }
        getrandom::fill(buf).map_err(|_| rustls::crypto::GetRandomFailed)
    }
}

#[derive(Debug)]
struct NoVerify {
    schemes: Vec<SignatureScheme>,
}

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

fn quic_server_name() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::fill(&mut bytes).is_err() {
        return "psiphon.ca".to_owned();
    }
    let length = 4 + usize::from(bytes[0] % 12);
    let mut name = String::with_capacity(length + 4);
    for byte in &bytes[1..=length] {
        name.push(char::from(b'a' + byte % 26));
    }
    name.push_str(match bytes[15] % 3 {
        0 => ".com",
        1 => ".net",
        _ => ".org",
    });
    name
}

fn transport_params(scid: &[u8], randomized: bool) -> Result<Vec<u8>, String> {
    let mut params = vec![
        (0x01, varint_bytes(60_000)),
        (0x03, varint_bytes(MAX_UDP_PAYLOAD)),
        (0x04, varint_bytes(INITIAL_WINDOW)),
        (0x05, varint_bytes(STREAM_WINDOW)),
        (0x06, varint_bytes(STREAM_WINDOW)),
        (0x08, varint_bytes(1)),
        (0x0e, varint_bytes(2)),
        (0x0f, scid.to_vec()),
    ];
    if randomized {
        let mut grease = [0u8; 16];
        let length = draw_below(grease.len())?;
        getrandom::fill(&mut grease[..length])
            .map_err(|error| format!("psiphon quic transport parameter: {error}"))?;
        params.push((27 + 31 * draw_below(100)? as u64, grease[..length].to_vec()));
        shuffle(&mut params)?;
    }
    let mut encoded = Vec::new();
    for (id, value) in params {
        put_parameter(&mut encoded, id, &value);
    }
    Ok(encoded)
}

/// A uniform draw below `bound`, using the system generator rather than a TLS transcript seed.
fn draw_below(bound: usize) -> Result<usize, String> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(|error| format!("psiphon quic entropy: {error}"))?;
    Ok((u64::from_be_bytes(bytes) % bound as u64) as usize)
}

fn shuffle<T>(items: &mut [T]) -> Result<(), String> {
    for at in (1..items.len()).rev() {
        let other = draw_below(at + 1)?;
        items.swap(at, other);
    }
    Ok(())
}

fn randomize_kx_groups(provider: &mut rustls::crypto::CryptoProvider) -> Result<(), String> {
    let mut groups = std::mem::take(&mut provider.kx_groups);
    let key_share = groups
        .iter()
        .position(|group| u16::from(group.name()) == 0x001d);
    if let Some(at) = key_share {
        let x25519 = groups.remove(at);
        shuffle(&mut groups)?;
        while !groups.is_empty() && draw_below(2)? == 0 {
            groups.pop();
        }
        groups.insert(0, x25519);
    } else {
        shuffle(&mut groups)?;
    }
    provider.kx_groups = groups;
    Ok(())
}

fn randomize_cipher_suites(provider: &mut rustls::crypto::CryptoProvider) -> Result<(), String> {
    let mut suites: Vec<_> = provider
        .cipher_suites
        .iter()
        .copied()
        .filter(|suite| suite.tls13().is_some())
        .collect();
    if suites.is_empty() {
        return Ok(());
    }
    shuffle(&mut suites)?;
    while suites.len() > 1 && draw_below(2)? == 0 {
        suites.pop();
    }
    provider.cipher_suites = suites;
    Ok(())
}

fn put_parameter(params: &mut Vec<u8>, id: u64, value: &[u8]) {
    put_varint(params, id);
    put_varint(params, value.len() as u64);
    params.extend_from_slice(value);
}

fn varint_bytes(value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    put_varint(&mut bytes, value);
    bytes
}

fn put_varint(buf: &mut Vec<u8>, value: u64) {
    if value < 1 << 6 {
        buf.push(value as u8);
    } else if value < 1 << 14 {
        buf.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < 1 << 30 {
        buf.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else {
        buf.extend_from_slice(&(value | 0xC000_0000_0000_0000).to_be_bytes());
    }
}

fn get_varint(buf: &[u8], at: &mut usize) -> Option<u64> {
    let first = *buf.get(*at)?;
    let len = 1usize << (first >> 6);
    if *at + len > buf.len() {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for index in 1..len {
        value = (value << 8) | u64::from(buf[*at + index]);
    }
    *at += len;
    Some(value)
}

fn put_ack(buf: &mut Vec<u8>, seen: &[u64]) {
    let mut iter = seen.iter().rev();
    let Some(&largest) = iter.next() else {
        return;
    };
    let mut ranges = [(0u64, 0u64); 32];
    let mut count = 0usize;
    let mut high = largest;
    let mut low = largest;
    for &pn in iter {
        if pn + 1 == low {
            low = pn;
        } else if count >= 31 {
            break;
        } else {
            ranges[count] = (low, high);
            count += 1;
            low = pn;
            high = pn;
        }
    }
    ranges[count] = (low, high);
    count += 1;
    buf.push(0x02);
    put_varint(buf, ranges[0].1);
    put_varint(buf, 0);
    put_varint(buf, (count - 1) as u64);
    put_varint(buf, ranges[0].1 - ranges[0].0);
    for index in 0..count - 1 {
        let (previous, _) = ranges[index];
        let (low, high) = ranges[index + 1];
        put_varint(buf, previous.saturating_sub(high).saturating_sub(2));
        put_varint(buf, high - low);
    }
}

fn decode_pn(truncated: u64, bits: u32, largest: u64) -> u64 {
    let expected = largest.wrapping_add(1);
    let window = 1u64 << bits;
    let half = window / 2;
    let mask = window - 1;
    let candidate = (expected & !mask) | truncated;
    if candidate + half <= expected {
        candidate.wrapping_add(window)
    } else if candidate > expected.wrapping_add(half) && candidate >= window {
        candidate - window
    } else {
        candidate
    }
}

fn long_header_len(initial: bool, dcid_len: usize, scid_len: usize, pn_len: usize) -> usize {
    1 + 4 + 1 + dcid_len + 1 + scid_len + usize::from(initial) + 2 + pn_len
}

#[cfg(test)]
mod tests {
    use super::{
        get_varint, randomize_cipher_suites, randomize_kx_groups, transport_params, Engine,
        ObfuscatedUdp, PacketIo, QuicNoise, SentPacket, INITIAL_CWND, MAX_PACKET_SIZE,
        OBFUSCATION_OVERHEAD, ONE_RTT,
    };
    use std::net::UdpSocket;
    use std::time::{Duration, Instant};

    #[test]
    fn quic_noise_presets_match_the_reference() {
        assert!(QuicNoise::lookup("").is_none());
        assert!(QuicNoise::lookup("off").is_none());
        let light = QuicNoise::lookup("light").expect("light");
        assert_eq!(
            (light.before, light.after_first, light.first_random),
            (1, 0, 16)
        );
        let gfw = QuicNoise::lookup("AGGRESSIVE").expect("gfw");
        assert_eq!(
            (
                gfw.before,
                gfw.after_first,
                gfw.first_random,
                gfw.second_random
            ),
            (2, 1, 24, 32)
        );
        let firewall = QuicNoise::lookup("anything else").expect("firewall");
        assert_eq!(
            (
                firewall.before,
                firewall.after_first,
                firewall.first_random,
                firewall.second_random
            ),
            (2, 2, 24, 48)
        );
    }

    fn parameter_ids(encoded: &[u8]) -> Vec<u64> {
        let mut ids = Vec::new();
        let mut at = 0;
        while at < encoded.len() {
            let id = get_varint(encoded, &mut at).expect("parameter id");
            let length = get_varint(encoded, &mut at).expect("parameter length");
            at += usize::try_from(length).expect("parameter length");
            ids.push(id);
        }
        ids
    }

    #[test]
    fn randomized_transport_parameters_grease_and_shuffle_their_order() {
        assert_eq!(
            parameter_ids(&transport_params(&[7u8; 16], false).expect("fixed")),
            vec![0x01, 0x03, 0x04, 0x05, 0x06, 0x08, 0x0e, 0x0f]
        );
        let mut orders = std::collections::BTreeSet::new();
        for _ in 0..8 {
            let encoded = transport_params(&[7u8; 16], true).expect("randomized");
            let ids = parameter_ids(&encoded);
            for wanted in [0x01, 0x03, 0x04, 0x05, 0x06, 0x08, 0x0e, 0x0f] {
                assert!(ids.contains(&wanted), "missing {wanted:#x}");
            }
            assert!(ids
                .iter()
                .any(|id| *id >= 27 && *id <= 3096 && (*id - 27) % 31 == 0));
            orders.insert(format!("{ids:?}"));
        }
        assert!(orders.len() > 1, "the order never moved");
    }

    #[test]
    fn randomized_cipher_suites_stay_tls13() {
        let mut provider = rustls::crypto::ring::default_provider();
        randomize_cipher_suites(&mut provider).expect("suite randomization");
        let first = provider
            .cipher_suites
            .first()
            .expect("a TLS 1.3 suite survives");
        assert!(first.tls13().is_some());
        assert!(provider
            .cipher_suites
            .iter()
            .all(|suite| suite.tls13().is_some()));
    }

    #[test]
    fn randomized_key_groups_keep_x25519_as_the_key_share() {
        let mut provider = rustls::crypto::ring::default_provider();
        randomize_kx_groups(&mut provider).expect("group randomization");
        let first = provider.kx_groups.first().expect("a group");
        assert_eq!(u16::from(first.name()), 0x001d);
    }

    #[test]
    fn obfuscated_udp_round_trips_every_packet_length() {
        let left = UdpSocket::bind(("127.0.0.1", 0)).expect("left socket");
        let right = UdpSocket::bind(("127.0.0.1", 0)).expect("right socket");
        left.connect(right.local_addr().expect("right address"))
            .expect("left connect");
        right
            .connect(left.local_addr().expect("left address"))
            .expect("right connect");
        left.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("left timeout");
        right
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("right timeout");
        let key = [0x5au8; 32];
        let mut sender = ObfuscatedUdp {
            io: PacketIo::Socket(right),
            key,
            nonce: [0u8; 12],
            decoy: None,
        };
        let mut receiver = ObfuscatedUdp {
            io: PacketIo::Socket(left),
            key,
            nonce: [0u8; 12],
            decoy: None,
        };
        for length in [1usize, 13, 64, 255, 1199, 1200, 1267] {
            let plain: Vec<u8> = (0..length).map(|index| index as u8 | 0x40).collect();
            sender.send(&plain).expect("send");
            let mut buffer = vec![0u8; MAX_PACKET_SIZE];
            let count = receiver.recv(&mut buffer).expect("receive");
            assert_eq!(&buffer[..count], &plain[..], "length {length}");
        }
        assert!(sender
            .send(&vec![0u8; MAX_PACKET_SIZE - OBFUSCATION_OVERHEAD + 1])
            .is_err());
    }

    #[test]
    fn in_order_stream_data_lands_without_a_staging_allocation() {
        let mut engine = Engine::new("test", false).expect("engine");
        engine.received.reserve(4096);
        engine.feed_stream(0, &[7u8; 1200], false).expect("first");
        let ((), counts) = ferrox_core::alloc_count::measure(|| {
            engine
                .feed_stream(1200, &[9u8; 1200], false)
                .expect("second");
        });
        assert_eq!(
            counts.allocs, 0,
            "the in-order path appends into the receive window"
        );
        assert_eq!(engine.recv_next, 2400);
        assert_eq!(&engine.received[1200..], &[9u8; 1200][..]);
    }

    #[test]
    fn a_gap_is_filled_by_the_packet_before_it() {
        let mut engine = Engine::new("test", false).expect("engine");
        engine.feed_stream(4, b"efgh", false).expect("tail");
        engine.feed_stream(0, b"abcd", false).expect("head");
        assert_eq!(engine.received.as_slice(), b"abcdefgh");
        assert_eq!(engine.recv_next, 8);
    }

    #[test]
    fn pull_received_hands_the_buffer_over_without_copying() {
        let mut engine = Engine::new("test", false).expect("engine");
        engine.feed_stream(0, b"hello", false).expect("data");
        let mut out = Vec::new();
        let (count, counts) =
            ferrox_core::alloc_count::measure(|| engine.pull_received(&mut out, 8));
        assert_eq!(count, 5);
        assert_eq!(out.as_slice(), b"hello");
        assert_eq!(counts.allocs, 0, "the window is swapped, not copied");
        assert!(engine.received.is_empty());
    }

    #[test]
    fn expire_retransmits_the_old_prefix_and_drops_it() {
        let mut engine = Engine::new("test", false).expect("engine");
        engine.stream_sent = 400;
        engine.stream_data = vec![0u8; 400];
        engine.bytes_in_flight = 400;
        let base = Instant::now();
        engine.sent = (0..4)
            .map(|index| SentPacket {
                pn: index,
                space: ONE_RTT,
                sent_at: base + Duration::from_millis(index * 10),
                size: 100,
                crypto: None,
                stream: Some((index * 100, 100)),
                window: false,
            })
            .collect();
        engine.expire(base + Duration::from_millis(1000));
        assert!(engine.sent.is_empty());
        assert_eq!(engine.bytes_in_flight, 0);
        assert_eq!(
            engine.retx.iter().copied().collect::<Vec<_>>(),
            vec![(0, 100), (100, 100), (200, 100), (300, 100)]
        );
        assert_eq!(engine.cwnd, INITIAL_CWND);
    }

    #[test]
    fn ack_keeps_unacked_packets_in_order() {
        let mut engine = Engine::new("test", false).expect("engine");
        engine.bytes_in_flight = 500;
        let base = Instant::now();
        engine.sent = (0..5)
            .map(|index| SentPacket {
                pn: index,
                space: ONE_RTT,
                sent_at: base + Duration::from_millis(index * 10),
                size: 100,
                crypto: None,
                stream: None,
                window: false,
            })
            .collect();
        engine.ack(ONE_RTT, &[(1, 1), (3, 3)], base + Duration::from_millis(50));
        let left: Vec<u64> = engine.sent.iter().map(|packet| packet.pn).collect();
        assert_eq!(left, vec![0, 2, 4]);
        assert_eq!(engine.bytes_in_flight, 300);
    }
}

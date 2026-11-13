//! CONNECT-IP over HTTP/2, the TCP carrier RFC 9484 §3 names: the same
//! `connect-ip` request and capsule stream as the QUIC listener, sharing its
//! port, users, address pools and forwarding table.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use ferrox_core::foxy::{connectip, frames};
use ferrox_core::tls::{CertEntry, ServerKeyKind, TlsConfig, TlsProvider as _, TlsServerConfig};

use crate::h2::{self, Decoder};
use crate::masque::{self, deliver, withdrawn, Granted, ServerSpec, Shared, AUTH_REALM};
use crate::wg_stack::{Packet, UdpRoutes};

const HANDSHAKE: Duration = Duration::from_secs(10);
const EDGE_RETRY: Duration = Duration::from_secs(1);
const READ_WAIT: Duration = Duration::from_millis(10);
const WARP_ASSIGN_WAIT: Duration = Duration::from_millis(250);
const PING_TIMEOUT: Duration = Duration::from_secs(15);
const READ_ROOM: usize = 16 * 1024;
const PREFACE: usize = 24;
const SETTINGS_INITIAL_WINDOW: u16 = 0x4;
const SETTINGS_ENABLE_CONNECT: u16 = 0x8;
const FRAME_CAP: usize = 1 << 20;
const QUEUED_CAP: usize = 64;
const DEFAULT_WINDOW: i64 = 65_535;
const H2_CONNECTIONS: usize = 256;

#[derive(Clone, Default)]
pub(crate) struct Deadline(Arc<AtomicU64>);

fn monotonic_nanos() -> u64 {
    static BASE: OnceLock<Instant> = OnceLock::new();
    u64::try_from(BASE.get_or_init(Instant::now).elapsed().as_nanos()).unwrap_or(u64::MAX)
}

impl Deadline {
    fn arm(&self, at: Instant) {
        let left = u64::try_from(at.saturating_duration_since(Instant::now()).as_nanos())
            .unwrap_or(u64::MAX);
        self.0.store(
            monotonic_nanos().saturating_add(left).max(1),
            Ordering::Relaxed,
        );
    }

    /// Disarm the handshake clock.
    pub(crate) fn clear(&self) {
        self.0.store(0, Ordering::Relaxed);
    }

    fn remaining(&self) -> Option<Duration> {
        let at = self.0.load(Ordering::Relaxed);
        (at != 0).then(|| Duration::from_nanos(at.saturating_sub(monotonic_nanos())))
    }

    /// The instant the handshake clock names, while it is armed.
    fn at(&self) -> Option<Instant> {
        self.remaining().map(|left| Instant::now() + left)
    }
}

pub(crate) struct DeadlineStream {
    io: TcpStream,
    deadline: Deadline,
    read_wait: std::cell::Cell<Duration>,
    read_tight: std::cell::Cell<bool>,
    write_tight: std::cell::Cell<bool>,
}

impl DeadlineStream {
    fn new(io: TcpStream, deadline: Deadline) -> Self {
        Self {
            io,
            deadline,
            read_wait: std::cell::Cell::new(HANDSHAKE),
            read_tight: std::cell::Cell::new(false),
            write_tight: std::cell::Cell::new(false),
        }
    }

    /// Set the steady-state read wait unless the handshake clock is tight.
    pub(crate) fn set_read_timeout(&self, wait: Option<Duration>) {
        let wait = wait.unwrap_or(HANDSHAKE);
        self.read_wait.set(wait);
        if !self.read_tight.get() {
            let _ = self.io.set_read_timeout(Some(wait));
        }
    }

    fn prepare_read(&self) -> std::io::Result<()> {
        match self.deadline.remaining() {
            None => {
                if self.read_tight.replace(false) {
                    let _ = self.io.set_read_timeout(Some(self.read_wait.get()));
                }
                Ok(())
            }
            Some(left) if left.is_zero() => Err(std::io::ErrorKind::TimedOut.into()),
            Some(left) => {
                self.io
                    .set_read_timeout(Some(left.min(self.read_wait.get())))?;
                self.read_tight.set(true);
                Ok(())
            }
        }
    }

    fn prepare_write(&self) -> std::io::Result<()> {
        match self.deadline.remaining() {
            None => {
                if self.write_tight.replace(false) {
                    let _ = self.io.set_write_timeout(Some(HANDSHAKE));
                }
                Ok(())
            }
            Some(left) if left.is_zero() => Err(std::io::ErrorKind::TimedOut.into()),
            Some(left) => {
                self.io.set_write_timeout(Some(left.min(HANDSHAKE)))?;
                self.write_tight.set(true);
                Ok(())
            }
        }
    }
}

/// Wrap a TCP stream in the handshake clock and disable Nagle.
pub(crate) fn handshake_stream(tcp: TcpStream) -> (DeadlineStream, Deadline) {
    let _ = tcp.set_nodelay(true);
    let deadline = Deadline::default();
    deadline.arm(Instant::now() + HANDSHAKE);
    (DeadlineStream::new(tcp, deadline.clone()), deadline)
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.prepare_read()?;
        self.io.read(buf)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.prepare_write()?;
        let written = self.io.write(buf)?;
        if self.deadline.remaining().is_some_and(|left| left.is_zero()) {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.prepare_write()?;
        self.io.flush()
    }
}

impl ferrox_core::tls::RecordAlignment for DeadlineStream {}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

/// The h2 listener's live-connection table: a thread per admitted connection, and a
/// refused accept once the table is full so an unauthenticated peer cannot grow it without bound.
struct H2Slots {
    live: AtomicUsize,
    cap: usize,
}

struct H2Slot(Arc<H2Slots>);

impl H2Slots {
    fn new(cap: usize) -> Arc<Self> {
        Arc::new(Self {
            live: AtomicUsize::new(0),
            cap,
        })
    }

    fn acquire(self: &Arc<Self>) -> Option<H2Slot> {
        self.live
            .try_update(Ordering::AcqRel, Ordering::Relaxed, |live| {
                (live < self.cap).then_some(live + 1)
            })
            .ok()?;
        Some(H2Slot(Arc::clone(self)))
    }
}

impl Drop for H2Slot {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The TCP half of a MASQUE inbound: one thread per HTTP/2 connection on the
/// listener the inbound bound beside its QUIC socket.
pub(crate) fn serve(
    identity: Arc<TlsServerConfig>,
    shared: Arc<Shared>,
    spec: Arc<ServerSpec>,
    listener: TcpListener,
) {
    let slots = H2Slots::new(H2_CONNECTIONS);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else {
                continue;
            };
            let Some(slot) = slots.acquire() else {
                continue;
            };
            let _ = stream.set_nodelay(true);
            handshake_timeouts(&stream);
            let shared = Arc::clone(&shared);
            let spec = Arc::clone(&spec);
            let identity = Arc::clone(&identity);
            if let Err(error) = std::thread::Builder::new()
                .name("ferrox-masque-h2".into())
                .spawn(move || {
                    let _slot = slot;
                    connection(stream, &identity, shared, spec);
                })
            {
                eprintln!("masque: cannot spawn HTTP/2 connection handler: {error}");
            }
        }
    });
}

/// Bound both directions until the TLS handshake finishes.
fn handshake_timeouts(stream: &TcpStream) {
    let _ = stream.set_read_timeout(Some(HANDSHAKE));
    let _ = stream.set_write_timeout(Some(HANDSHAKE));
}

/// Serve one TLS connection over h2 or h1, chosen by ALPN.
fn connection(
    stream: TcpStream,
    identity: &TlsServerConfig,
    shared: Arc<Shared>,
    spec: Arc<ServerSpec>,
) {
    let deadline = Deadline::default();
    deadline.arm(Instant::now() + HANDSHAKE);
    let io = DeadlineStream::new(stream, deadline.clone());
    let Ok(mut tls) = ferrox_core::tls::accept(identity, io) else {
        return;
    };
    if tls.handshake().is_err() {
        return;
    }
    deadline.arm(Instant::now() + HANDSHAKE);
    if tls.alpn() == Some(b"http/1.1") {
        deadline.clear();
        tls.get_ref().get_ref().set_read_timeout(Some(READ_WAIT));
        crate::masque_h1::serve(tls, shared, spec);
        return;
    }
    if tls.alpn() != Some(b"h2") {
        return;
    }
    tls.get_ref().get_ref().set_read_timeout(Some(READ_WAIT));
    let mut wire = Wire {
        stream: Box::new(tls),
        pending: Vec::new(),
        closed: false,
        deadline,
    };
    if wire.preface() {
        Session::new(shared, spec).run(&mut wire);
    }
}

/// The cleartext half of a MASQUE inbound: prior-knowledge HTTP/2 over a bare
/// TCP socket, for a config that explicitly names `security: none`.
pub(crate) fn serve_cleartext(shared: Arc<Shared>, spec: Arc<ServerSpec>, listener: TcpListener) {
    let slots = H2Slots::new(H2_CONNECTIONS);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else {
                continue;
            };
            let Some(slot) = slots.acquire() else {
                continue;
            };
            let _ = stream.set_nodelay(true);
            let _ = stream.set_read_timeout(Some(READ_WAIT));
            let _ = stream.set_write_timeout(Some(HANDSHAKE));
            let shared = Arc::clone(&shared);
            let spec = Arc::clone(&spec);
            if let Err(error) = std::thread::Builder::new()
                .name("ferrox-masque-h2c".into())
                .spawn(move || {
                    let _slot = slot;
                    connection_cleartext(stream, shared, spec);
                })
            {
                eprintln!("masque: cannot spawn HTTP/2 cleartext handler: {error}");
            }
        }
    });
}

/// Serve one prior-knowledge h2c connection over bare TCP.
fn connection_cleartext(stream: TcpStream, shared: Arc<Shared>, spec: Arc<ServerSpec>) {
    let mut wire = cleartext_wire(stream);
    if wire.preface() {
        Session::new(shared, spec).run(&mut wire);
    }
}

/// Wrap a cleartext TCP stream in the same clock the TLS carrier uses.
fn cleartext_wire(stream: TcpStream) -> Wire {
    let (io, deadline) = handshake_stream(stream);
    io.set_read_timeout(Some(READ_WAIT));
    Wire {
        stream: Box::new(io),
        pending: Vec::new(),
        closed: false,
        deadline,
    }
}

struct Wire {
    stream: Box<dyn ReadWrite + Send>,
    pending: Vec<u8>,
    closed: bool,
    deadline: Deadline,
}

impl Wire {
    /// Read the h2c preface inside the handshake clock, refusing a late or malformed one.
    fn preface(&mut self) -> bool {
        let deadline = self
            .deadline
            .at()
            .unwrap_or_else(|| Instant::now() + HANDSHAKE);
        while self.pending.len() < PREFACE {
            if Instant::now() > deadline || !self.fill() || self.closed {
                return false;
            }
        }
        if Instant::now() > deadline || !self.pending.starts_with(h2::MAGIC) {
            return false;
        }
        self.pending.drain(..PREFACE);
        self.deadline.clear();
        true
    }

    /// One read: the caller's wait is the socket's timeout, so a quiet peer
    /// parks here rather than spinning.
    fn fill(&mut self) -> bool {
        let mut room = [0u8; READ_ROOM];
        match self.stream.read(&mut room) {
            Ok(0) => {
                self.closed = true;
                false
            }
            Ok(n) => {
                self.pending.extend_from_slice(&room[..n]);
                true
            }
            Err(error) if ferrox_core::tls::TlsError::is_timeout(&error) => {
                if self.deadline.remaining().is_some_and(|left| left.is_zero()) {
                    self.closed = true;
                    false
                } else {
                    true
                }
            }
            Err(_) => {
                self.closed = true;
                false
            }
        }
    }

    fn send(&mut self, kind: u8, flags: u8, id: u32, body: &[u8]) -> bool {
        let head = h2::frame_head(body.len(), kind, flags, id);
        let sent = self
            .stream
            .write_all(&head)
            .and_then(|()| self.stream.write_all(body));
        if sent.is_err() {
            self.closed = true;
            return false;
        }
        true
    }
}

struct Frame {
    kind: u8,
    flags: u8,
    id: u32,
    start: usize,
    end: usize,
}

/// One whole frame in a pending buffer, as its body's range: the caller reads the body where it landed instead of copying it out. `Err` is a frame past the cap, which closes the wire.
fn frame_at(pending: &[u8], at: usize) -> Result<Option<Frame>, ()> {
    let Some(head) = pending.get(at..at.saturating_add(9)) else {
        return Ok(None);
    };
    let len = usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
    if len > FRAME_CAP {
        return Err(());
    }
    let end = at.saturating_add(9).saturating_add(len);
    if pending.len() < end {
        return Ok(None);
    }
    let id = u32::from_be_bytes(head[5..9].try_into().expect("four bytes")) & 0x7fff_ffff;
    Ok(Some(Frame {
        kind: head[3],
        flags: head[4],
        id,
        start: at.saturating_add(9),
        end,
    }))
}

/// The dialer's half of the same wire: the request rides stream one, capsules
/// go out as DATA, and the peer's assignment names the addresses the stack may
/// source. Windows are tracked per stream and per connection, as the reference
/// transport does, so a peer that grants only one cannot be overrun.
pub(crate) struct Client {
    wire: Wire,
    decoder: Decoder,
    stream: u32,
    status: Option<u16>,
    continuation: Option<(u32, Vec<u8>)>,
    send_window: i64,
    peer_window: i64,
    connection_window: i64,
    queued: VecDeque<Vec<u8>>,
    queued_at: usize,
    capsules: Vec<u8>,
    capsule_at: usize,
    pub(crate) addresses: Vec<IpAddr>,
    pub(crate) mtu: usize,
    pub(crate) packets: Vec<Vec<u8>>,
    early_bytes: usize,
    to_stack: Option<Sender<Packet>>,
    routes: Option<UdpRoutes>,
    warp: bool,
    end: bool,
    last_frame: Instant,
}

/// An edge still binding refuses the first dial the way a QUIC handshake loses it, so a refused dial is retried for a second.
fn dial_until_bound(
    edge: SocketAddr,
    mut dial: impl FnMut(SocketAddr) -> std::io::Result<TcpStream>,
) -> Result<TcpStream, String> {
    let deadline = Instant::now() + EDGE_RETRY;
    loop {
        match dial(edge) {
            Ok(stream) => return Ok(stream),
            Err(error)
                if error.kind() == std::io::ErrorKind::ConnectionRefused
                    && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(format!("cannot reach {edge}: {error}")),
        }
    }
}

fn connect_edge(edge: SocketAddr) -> Result<TcpStream, String> {
    dial_until_bound(edge, |edge| TcpStream::connect_timeout(&edge, HANDSHAKE))
}

/// Build the CONNECT fields for WARP or RFC 9484 plus the configured headers.
fn request_fields<'a>(
    authority: &'a str,
    path: &'a str,
    headers: &'a [(String, String)],
    warp: bool,
    scheme: &'a str,
) -> Vec<(&'a str, &'a str)> {
    let mut fields = Vec::with_capacity(6 + headers.len());
    fields.push((":method", "CONNECT"));
    fields.push((":scheme", scheme));
    fields.push((":path", path));
    fields.push((":authority", authority));
    if warp {
        fields.push(("cf-connect-proto", "cf-connect-ip"));
        fields.push(("pq-enabled", "false"));
    } else {
        fields.push((":protocol", "connect-ip"));
        fields.push(("capsule-protocol", "?1"));
    }
    fields.extend(
        headers
            .iter()
            .filter(|(name, _)| {
                !(warp && matches!(name.as_str(), "cf-connect-proto" | "pq-enabled"))
            })
            .map(|(name, value)| (name.as_str(), value.as_str())),
    );
    fields
}

/// Write settings and CONNECT, wait for 2xx, then bind or request addresses.
fn handshake(
    stream: Box<dyn ReadWrite + Send>,
    deadline: Deadline,
    warp: Option<&masque::Warp>,
    authority: &str,
    path: &str,
    headers: &[(String, String)],
    scheme: &str,
) -> Result<Client, String> {
    let mut client = Client {
        wire: Wire {
            stream,
            pending: Vec::new(),
            closed: false,
            deadline,
        },
        decoder: Decoder::default(),
        stream: 1,
        status: None,
        continuation: None,
        send_window: DEFAULT_WINDOW,
        peer_window: DEFAULT_WINDOW,
        connection_window: DEFAULT_WINDOW,
        queued: VecDeque::new(),
        queued_at: 0,
        capsules: Vec::new(),
        capsule_at: 0,
        addresses: Vec::new(),
        mtu: masque::DEFAULT_MTU,
        packets: Vec::new(),
        early_bytes: 0,
        to_stack: None,
        routes: None,
        warp: warp.is_some(),
        end: false,
        last_frame: Instant::now(),
    };
    let mut settings = Vec::with_capacity(12);
    settings.extend_from_slice(&SETTINGS_ENABLE_CONNECT.to_be_bytes());
    settings.extend_from_slice(&1u32.to_be_bytes());
    settings.extend_from_slice(&SETTINGS_INITIAL_WINDOW.to_be_bytes());
    settings.extend_from_slice(&h2::WINDOW.to_be_bytes());
    let raised = h2::WINDOW - u32::try_from(DEFAULT_WINDOW).expect("a positive window");
    if !client.wire.send(h2::T_SETTINGS, 0, 0, &settings)
        || !client.wire.send(h2::T_WINDOW, 0, 0, &raised.to_be_bytes())
    {
        return Err("the edge closed while settings were written".to_owned());
    }
    let block = h2::block_encode(&request_fields(
        authority,
        path,
        headers,
        warp.is_some(),
        scheme,
    ));
    if !client
        .wire
        .send(h2::T_HEADERS, h2::F_END_HEADERS, client.stream, &block)
    {
        return Err("the edge closed while the request was written".to_owned());
    }
    let deadline = client
        .wire
        .deadline
        .at()
        .unwrap_or_else(|| Instant::now() + HANDSHAKE);
    while client.status.is_none() {
        if Instant::now() > deadline {
            return Err("the edge sent no response head".to_owned());
        }
        client.pump();
        if client.wire.closed || client.end {
            return Err("the edge closed before the response head".to_owned());
        }
        client.wire.fill();
    }
    let status = client.status.unwrap_or(0);
    if !(200..300).contains(&status) {
        return Err(format!("the edge answered {status}"));
    }
    if let Some(warp) = warp {
        let deadline = Instant::now() + WARP_ASSIGN_WAIT;
        while client.addresses.is_empty() && Instant::now() < deadline {
            client.wire.fill();
            client.pump();
            if client.wire.closed || client.end {
                break;
            }
        }
        if client.addresses.is_empty() {
            client.addresses = warp.local_addresses();
        }
    } else {
        client.request_addresses()?;
    }
    client.wire.deadline.clear();
    Ok(client)
}

impl Client {
    /// Dial the edge over TLS, negotiate h2, and handshake.
    pub(crate) fn dial(
        tls_config: &TlsConfig,
        insecure: bool,
        warp: Option<&masque::Warp>,
        edge: SocketAddr,
        authority: &str,
        path: &str,
        headers: &[(String, String)],
    ) -> Result<Self, String> {
        let tcp = connect_edge(edge)?;
        let _ = tcp.set_read_timeout(Some(HANDSHAKE));
        let _ = tcp.set_write_timeout(Some(HANDSHAKE));
        let (tcp, deadline) = handshake_stream(tcp);
        let owned = warp_tls(tls_config, warp);
        let mut tls = ferrox_core::tls::connect(owned.as_ref().unwrap_or(tls_config), tcp)
            .map_err(|error| format!("tls: {error}"))?;
        tls.handshake()
            .map_err(|error| format!("tls handshake: {error}"))?;
        if tls.alpn() != Some(b"h2".as_slice()) {
            return Err("the edge did not negotiate h2".to_owned());
        }
        verify_warp(&tls, insecure, warp)?;
        tls.get_ref().set_read_timeout(Some(READ_WAIT));
        tls.write_all(h2::MAGIC)
            .map_err(|error| format!("preface: {error}"))?;
        handshake(
            Box::new(tls),
            deadline,
            warp,
            authority,
            path,
            headers,
            "https",
        )
    }

    /// Dial the edge over bare TCP and handshake prior-knowledge h2c.
    pub(crate) fn dial_cleartext(
        edge: SocketAddr,
        authority: &str,
        path: &str,
        headers: &[(String, String)],
    ) -> Result<Self, String> {
        let tcp = connect_edge(edge)?;
        let _ = tcp.set_read_timeout(Some(READ_WAIT));
        let _ = tcp.set_write_timeout(Some(HANDSHAKE));
        let (tcp, deadline) = handshake_stream(tcp);
        let mut tcp = tcp;
        tcp.set_read_timeout(Some(READ_WAIT));
        tcp.write_all(h2::MAGIC)
            .map_err(|error| format!("preface: {error}"))?;
        handshake(
            Box::new(tcp),
            deadline,
            None,
            authority,
            path,
            headers,
            "http",
        )
    }

    /// Ask for both families and wait for the assignment inside the handshake clock.
    fn request_addresses(&mut self) -> Result<(), String> {
        let v4 = [0u8; 4];
        let v6 = [0u8; 16];
        let mut requests = Vec::with_capacity(40);
        connectip::address_requests(&[(1, 4, &v4), (2, 6, &v6)], &mut requests);
        self.capsule(&requests);
        let deadline = self
            .wire
            .deadline
            .at()
            .unwrap_or_else(|| Instant::now() + HANDSHAKE);
        while self.addresses.is_empty() {
            if Instant::now() > deadline {
                return Err("no address assigned".to_owned());
            }
            self.flush();
            self.pump();
            if self.wire.closed || self.end {
                return Err("the edge closed before assigning an address".to_owned());
            }
            if self.addresses.is_empty() {
                self.wire.fill();
            }
        }
        Ok(())
    }

    /// Delivers queued packets and pumps bounded tunnel batches until the session or wire ends.
    pub(crate) fn run(
        &mut self,
        from_tunnel: &Receiver<Vec<u8>>,
        to_stack: &Sender<Packet>,
        routes: &UdpRoutes,
        keepalive: Option<Duration>,
    ) {
        self.to_stack = Some(to_stack.clone());
        self.routes = Some(routes.clone());
        for packet in self.packets.drain(..) {
            deliver(to_stack, routes, &packet);
        }
        self.early_bytes = 0;
        let mut capsule = Vec::new();
        let mut ping_at = None;
        while !self.wire.closed && !self.end {
            self.pump();
            if self.wire.closed || self.end {
                break;
            }
            if let Some(period) = keepalive {
                let now = Instant::now();
                if let Some(at) = ping_at {
                    if self.last_frame >= at {
                        ping_at = None;
                    } else if now.duration_since(at) >= PING_TIMEOUT {
                        self.end = true;
                        break;
                    }
                }
                if ping_at.is_none() && now.duration_since(self.last_frame) >= period {
                    if !self.wire.send(h2::T_PING, 0, 0, &[0u8; 8]) {
                        break;
                    }
                    ping_at = Some(now);
                }
            }
            self.flush();
            if self.wire.closed || self.end {
                break;
            }
            for _ in 0..QUEUED_CAP {
                if self.end || self.wire.closed {
                    break;
                }
                let Ok(packet) = from_tunnel.try_recv() else {
                    break;
                };
                capsule.clear();
                if self.warp {
                    connectip::packet_encode_bare(&packet, &mut capsule);
                } else {
                    datagram(&packet, &mut capsule);
                }
                self.capsule(&capsule);
            }
            self.flush();
            if self.wire.closed || self.end {
                break;
            }
            if !self.wire.fill() {
                break;
            }
        }
    }

    fn pump(&mut self) {
        let mut pending = std::mem::take(&mut self.wire.pending);
        let mut at = 0;
        loop {
            match frame_at(&pending, at) {
                Ok(Some(frame)) => {
                    self.on(
                        frame.kind,
                        frame.flags,
                        frame.id,
                        &pending[frame.start..frame.end],
                    );
                    at = frame.end;
                    if self.end || self.wire.closed {
                        break;
                    }
                }
                Ok(None) => break,
                Err(()) => {
                    self.wire.closed = true;
                    break;
                }
            }
        }
        if at > 0 {
            pending.drain(..at);
        }
        self.wire.pending = pending;
    }

    fn on(&mut self, kind: u8, flags: u8, id: u32, body: &[u8]) {
        self.last_frame = Instant::now();
        match kind {
            h2::T_SETTINGS if flags & h2::F_ACK == 0 => {
                let mut at = 0;
                while at + 6 <= body.len() {
                    let setting = u16::from_be_bytes([body[at], body[at + 1]]);
                    let value = u32::from_be_bytes([
                        body[at + 2],
                        body[at + 3],
                        body[at + 4],
                        body[at + 5],
                    ]);
                    if setting == SETTINGS_INITIAL_WINDOW {
                        let next = i64::from(value);
                        self.send_window += next - self.peer_window;
                        self.peer_window = next;
                    }
                    at += 6;
                }
                self.wire.send(h2::T_SETTINGS, h2::F_ACK, 0, &[]);
            }
            h2::T_WINDOW if body.len() == 4 => {
                let increment =
                    u32::from_be_bytes(body.try_into().expect("four bytes")) & 0x7fff_ffff;
                if id == 0 {
                    self.connection_window += i64::from(increment);
                } else if id == self.stream {
                    self.send_window += i64::from(increment);
                }
            }
            h2::T_PING if flags & h2::F_ACK == 0 => {
                self.wire.send(h2::T_PING, h2::F_ACK, 0, body);
            }
            h2::T_HEADERS if id == self.stream => {
                let block = strip_padding(flags, body, true);
                if flags & h2::F_END_HEADERS != 0 {
                    self.head(block);
                } else {
                    self.continuation = Some((id, block.to_vec()));
                }
                if flags & h2::F_END != 0 {
                    self.end = true;
                }
            }
            h2::T_CONT => {
                if let Some((stream, mut block)) = self.continuation.take() {
                    if stream != id {
                        self.end = true;
                        return;
                    }
                    let data = strip_padding(flags, body, false);
                    if block.len() + data.len() > FRAME_CAP {
                        self.end = true;
                        return;
                    }
                    block.extend_from_slice(data);
                    if flags & h2::F_END_HEADERS != 0 {
                        self.head(&block);
                    } else {
                        self.continuation = Some((id, block));
                    }
                }
            }
            h2::T_DATA if id == self.stream => {
                let length = body.len();
                let data = strip_padding(flags, body, false);
                self.window(length);
                self.capsules(data);
                if flags & h2::F_END != 0 {
                    self.end = true;
                }
            }
            h2::T_RST if id == self.stream => self.end = true,
            h2::T_GOAWAY => self.end = true,
            _ => {}
        }
    }

    fn head(&mut self, block: &[u8]) {
        if self.status.is_some() {
            return;
        }
        let mut status = None;
        let decoded = self
            .decoder
            .decode(block, &mut |name, value| {
                if name == b":status" {
                    status = std::str::from_utf8(value)
                        .ok()
                        .and_then(|value| value.parse().ok());
                }
            })
            .is_some();
        if decoded {
            self.status = status;
        } else {
            self.end = true;
        }
    }

    fn window(&mut self, length: usize) {
        if length == 0 {
            return;
        }
        let length = u32::try_from(length).unwrap_or(u32::MAX).to_be_bytes();
        self.wire.send(h2::T_WINDOW, 0, 0, &length);
        self.wire.send(h2::T_WINDOW, 0, self.stream, &length);
    }

    fn capsules(&mut self, bytes: &[u8]) {
        let mut capsules = std::mem::take(&mut self.capsules);
        let mut at = 0;
        let mut answers = Vec::new();
        if capsules.is_empty() {
            let mut used = 0;
            let split: fn(&[u8]) -> Option<(usize, connectip::Capsule<'_>)> = if self.warp {
                connectip::capsule_split_bare
            } else {
                connectip::capsule_split
            };
            while let Some((n, capsule)) = split(&bytes[used..]) {
                used += n;
                if let Some(answer) = self.handle(capsule) {
                    answers.push(answer);
                }
            }
            if used < bytes.len() {
                capsules.extend_from_slice(&bytes[used..]);
            }
        } else {
            at = self.capsule_at;
            capsules.extend_from_slice(bytes);
            let split: fn(&[u8]) -> Option<(usize, connectip::Capsule<'_>)> = if self.warp {
                connectip::capsule_split_bare
            } else {
                connectip::capsule_split
            };
            while let Some((n, capsule)) = split(&capsules[at..]) {
                at += n;
                if let Some(answer) = self.handle(capsule) {
                    answers.push(answer);
                }
            }
            if at > 0 {
                capsules.drain(..at);
                at = 0;
            }
        }
        self.capsules = capsules;
        self.capsule_at = at;
        if self.capsules.len() > FRAME_CAP {
            self.end = true;
        }
        for answer in answers {
            self.capsule(&answer);
        }
    }

    /// Apply one capsule, holding a pre-stack datagram within the early-buffer caps.
    fn handle(&mut self, capsule: connectip::Capsule<'_>) -> Option<Vec<u8>> {
        match capsule {
            connectip::Capsule::AddressAssign(body) => {
                if self.addresses.is_empty() {
                    let mut assigned = Vec::new();
                    if connectip::address_assign(body, &mut assigned).is_some() {
                        self.addresses.extend(assigned.iter().filter_map(|grant| {
                            (!grant.refused())
                                .then(|| masque::address_of(grant))
                                .flatten()
                        }));
                    }
                } else if let Some(address) = withdrawn(body, &self.addresses) {
                    eprintln!("masque: the proxy withdrew {address}");
                    self.end = true;
                }
                None
            }
            connectip::Capsule::Datagram(packet) => {
                if let (Some(to_stack), Some(routes)) = (&self.to_stack, &self.routes) {
                    deliver(to_stack, routes, packet);
                } else if self.packets.len() >= masque::EARLY_PACKETS
                    || self.early_bytes.saturating_add(packet.len()) > masque::EARLY_BYTES
                {
                    self.end = true;
                } else {
                    self.early_bytes += packet.len();
                    self.packets.push(packet.to_vec());
                }
                None
            }
            connectip::Capsule::AddressRequest(body) => {
                let granted = masque::respond(body, &self.addresses);
                if granted.is_empty() {
                    return None;
                }
                let mut out = Vec::new();
                connectip::address_assign_encode(&granted, &mut out);
                Some(out)
            }
            _ => None,
        }
    }

    /// Sends within peer credit or queues up to the cap; terminated sessions accept nothing.
    fn capsule(&mut self, capsule: &[u8]) {
        if self.end || self.wire.closed {
            return;
        }
        let length = i64::try_from(capsule.len()).unwrap_or(i64::MAX);
        if self.queued.is_empty() && length <= self.send_window.min(self.connection_window) {
            if self.wire.send(h2::T_DATA, 0, self.stream, capsule) {
                self.send_window -= length;
                self.connection_window -= length;
            }
        } else if self.queued.len() < QUEUED_CAP {
            self.queued.push_back(capsule.to_vec());
        } else {
            self.end = true;
        }
    }

    /// Drains queued capsule bytes within peer credit while preserving a partial front capsule.
    fn flush(&mut self) {
        if self.end || self.wire.closed {
            return;
        }
        while let Some(answer) = self.queued.pop_front() {
            let start = self.queued_at;
            let room = self.send_window.min(self.connection_window);
            if room <= 0 {
                self.queued.push_front(answer);
                return;
            }
            let take = (answer.len() - start).min(usize::try_from(room).unwrap_or(usize::MAX));
            if !self
                .wire
                .send(h2::T_DATA, 0, self.stream, &answer[start..start + take])
            {
                return;
            }
            self.send_window -= i64::try_from(take).unwrap_or(i64::MAX);
            self.connection_window -= i64::try_from(take).unwrap_or(i64::MAX);
            self.queued_at = start + take;
            if self.queued_at < answer.len() {
                self.queued.push_front(answer);
            } else {
                self.queued_at = 0;
            }
        }
    }
}

struct Session {
    shared: Arc<Shared>,
    spec: Arc<ServerSpec>,
    decoder: Decoder,
    capsules: Vec<u8>,
    capsule_at: usize,
    request: Option<u32>,
    continuation: Option<(u32, Vec<u8>, u8)>,
    outgoing: Option<Receiver<Vec<u8>>>,
    queued: VecDeque<Vec<u8>>,
    queued_at: usize,
    send_window: i64,
    peer_window: i64,
    granted: Option<Granted>,
    addrs: Vec<IpAddr>,
    udp: Option<masque::UdpLane>,
    warp: bool,
    end: bool,
}

impl Session {
    fn new(shared: Arc<Shared>, spec: Arc<ServerSpec>) -> Self {
        Self {
            shared,
            spec,
            decoder: Decoder::default(),
            capsules: Vec::new(),
            capsule_at: 0,
            request: None,
            continuation: None,
            outgoing: None,
            queued: VecDeque::new(),
            queued_at: 0,
            send_window: DEFAULT_WINDOW,
            peer_window: DEFAULT_WINDOW,
            granted: None,
            addrs: Vec::new(),
            udp: None,
            warp: false,
            end: false,
        }
    }

    /// Serve one connection from the handshake clock onward.
    fn run(&mut self, wire: &mut Wire) {
        self.run_until(
            wire,
            wire.deadline
                .at()
                .unwrap_or_else(|| Instant::now() + HANDSHAKE),
        );
    }

    /// Serve buffered frames until the wire closes or the deadline passes before a request.
    fn run_until(&mut self, wire: &mut Wire, deadline: Instant) {
        let mut settings = Vec::new();
        settings.extend_from_slice(&SETTINGS_ENABLE_CONNECT.to_be_bytes());
        settings.extend_from_slice(&1u32.to_be_bytes());
        wire.send(h2::T_SETTINGS, 0, 0, &settings);
        while !wire.closed && !self.end {
            let mut pending = std::mem::take(&mut wire.pending);
            let mut at = 0;
            loop {
                match frame_at(&pending, at) {
                    Ok(Some(frame)) => {
                        if self.request.is_none() && Instant::now() >= deadline {
                            self.end = true;
                            break;
                        }
                        self.on(
                            wire,
                            frame.kind,
                            frame.flags,
                            frame.id,
                            &pending[frame.start..frame.end],
                        );
                        at = frame.end;
                        if self.end || wire.closed {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(()) => {
                        wire.closed = true;
                        break;
                    }
                }
            }
            if at > 0 {
                pending.drain(..at);
            }
            wire.pending = pending;
            if self.request.is_none() && Instant::now() >= deadline {
                self.end = true;
                break;
            }
            self.flush(wire);
            if wire.closed || self.end {
                break;
            }
            if !wire.fill() {
                break;
            }
        }
    }

    fn on(&mut self, wire: &mut Wire, kind: u8, flags: u8, id: u32, body: &[u8]) {
        match kind {
            h2::T_SETTINGS if flags & h2::F_ACK == 0 => {
                let mut at = 0;
                while at + 6 <= body.len() {
                    let setting = u16::from_be_bytes([body[at], body[at + 1]]);
                    let value = u32::from_be_bytes([
                        body[at + 2],
                        body[at + 3],
                        body[at + 4],
                        body[at + 5],
                    ]);
                    if setting == SETTINGS_INITIAL_WINDOW {
                        let next = i64::from(value);
                        self.send_window += next - self.peer_window;
                        self.peer_window = next;
                    }
                    at += 6;
                }
                wire.send(h2::T_SETTINGS, h2::F_ACK, 0, &[]);
            }
            h2::T_WINDOW if body.len() == 4 => {
                let increment =
                    u32::from_be_bytes(body.try_into().expect("four bytes")) & 0x7fff_ffff;
                if id == 0 || Some(id) == self.request {
                    self.send_window += i64::from(increment);
                }
            }
            h2::T_PING if flags & h2::F_ACK == 0 => {
                wire.send(h2::T_PING, h2::F_ACK, 0, body);
            }
            h2::T_HEADERS => {
                if let Some(active) = self.request {
                    if id != active {
                        wire.send(h2::T_RST, 0, id, &7u32.to_be_bytes());
                    }
                    return;
                }
                let block = strip_padding(flags, body, true);
                if flags & h2::F_END_HEADERS != 0 {
                    self.request(wire, id, block);
                } else {
                    self.continuation = Some((id, block.to_vec(), flags));
                }
            }
            h2::T_CONT => {
                if let Some((stream, mut block, head_flags)) = self.continuation.take() {
                    if stream != id {
                        self.end = true;
                        return;
                    }
                    let data = strip_padding(flags, body, false);
                    if block.len() + data.len() > FRAME_CAP {
                        self.end = true;
                        return;
                    }
                    block.extend_from_slice(data);
                    if flags & h2::F_END_HEADERS != 0 {
                        self.request(wire, id, &block);
                    } else {
                        self.continuation = Some((id, block, head_flags));
                    }
                }
            }
            h2::T_DATA => {
                if Some(id) != self.request {
                    return;
                }
                let length = body.len();
                let data = strip_padding(flags, body, false);
                self.window(wire, length);
                self.capsules(wire, data);
                if flags & h2::F_END != 0 {
                    self.end = true;
                }
            }
            h2::T_RST if Some(id) == self.request => self.end = true,
            h2::T_GOAWAY => self.end = true,
            _ => {}
        }
    }

    fn request(&mut self, wire: &mut Wire, id: u32, block: &[u8]) {
        let mut fields = Vec::new();
        let decoded = self
            .decoder
            .decode(block, &mut |name, value| {
                fields.push((name.to_vec(), value.to_vec()));
            })
            .is_some();
        let field = |name: &[u8]| {
            fields
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_slice())
        };
        let warp = self.spec.warp && field(b"cf-connect-proto") == Some(masque::WARP_PROTOCOL);
        let protocol = if warp {
            masque::WARP_PROTOCOL
        } else {
            field(b":protocol").unwrap_or_default()
        };
        let udp = protocol == b"connect-udp";
        let target = udp
            .then(|| field(b":path"))
            .flatten()
            .and_then(masque::udp_target);
        let path_ok = if udp {
            target.is_some()
        } else {
            field(b":path").is_some_and(|path| self.spec.path_matches(path, protocol))
        };
        let method_ok = field(b":method") == Some(b"CONNECT");
        let protocol_ok = udp || self.spec.accepts_protocol(protocol);
        let capsules_ok = warp
            || field(b"capsule-protocol")
                .and_then(|value| value.strip_prefix(b"?"))
                .is_some_and(|value| value.split(|byte| *byte == b';').next() == Some(b"1"));
        if !decoded {
            self.reply(wire, id, 400, udp);
            return;
        }
        if !path_ok {
            self.reply(wire, id, if udp { 400 } else { 404 }, udp);
            return;
        }
        if !method_ok || !protocol_ok || !capsules_ok {
            self.reply(wire, id, 400, udp);
            return;
        }
        let authenticated = if udp {
            self.spec
                .udp_authenticated(field(b"proxy-authorization"), field(b"authorization"))
        } else {
            self.spec
                .request_authenticated(protocol, field(b"authorization"))
        };
        if !authenticated {
            self.reply(wire, id, 401, udp);
            return;
        }
        if udp {
            self.accept_udp(wire, id, target);
            return;
        }
        self.warp = warp;
        let Some(addrs) = masque::assign(&self.shared) else {
            self.reply(wire, id, 503, false);
            return;
        };
        let (sender, outgoing) = mpsc::sync_channel::<Vec<u8>>(masque::QUEUE);
        let queue = masque::TunnelQueue::new(sender, None);
        let Some(granted) = masque::register(&self.shared, &addrs, &queue) else {
            masque::release(&self.shared, &addrs);
            self.reply(wire, id, 503, false);
            return;
        };
        self.addrs = addrs;
        self.granted = Some(granted);
        self.outgoing = Some(outgoing);
        self.request = Some(id);
        let block = h2::block_encode(&[(":status", "200"), ("capsule-protocol", "?1")]);
        wire.send(h2::T_HEADERS, h2::F_END_HEADERS, id, &block);
        let mut control = Vec::new();
        connectip::address_assign_encode(&masque::grants(&self.addrs, 0), &mut control);
        self.capsule(wire, &control);
        control.clear();
        connectip::route_advert_encode(&masque::routes(&self.addrs), &mut control);
        self.capsule(wire, &control);
        if !wire.closed && self.queued.is_empty() {
            wire.deadline.clear();
        }
    }

    fn accept_udp(&mut self, wire: &mut Wire, id: u32, target: Option<(String, u16)>) {
        let Some((host, port)) = target else {
            self.reply(wire, id, 400, true);
            return;
        };
        let Ok(lane) = masque::UdpLane::open(&host, port) else {
            self.reply(wire, id, 503, true);
            return;
        };
        self.udp = Some(lane);
        self.request = Some(id);
        let block = h2::block_encode(&[(":status", "200"), ("capsule-protocol", "?1")]);
        wire.send(h2::T_HEADERS, h2::F_END_HEADERS, id, &block);
        if !wire.closed {
            wire.deadline.clear();
        }
    }

    fn reply(&mut self, wire: &mut Wire, id: u32, status: u16, proxy: bool) {
        let status = status.to_string();
        let mut fields = vec![(":status", status.as_str())];
        if status == "401" {
            fields.push((
                if proxy {
                    "proxy-authenticate"
                } else {
                    "www-authenticate"
                },
                AUTH_REALM,
            ));
        }
        let block = h2::block_encode(&fields);
        wire.send(h2::T_HEADERS, h2::F_END_HEADERS | h2::F_END, id, &block);
        self.end = true;
    }

    fn window(&mut self, wire: &mut Wire, length: usize) {
        let Some(request) = self.request else {
            return;
        };
        if length == 0 {
            return;
        }
        let length = u32::try_from(length).expect("a frame fits four bytes");
        wire.send(h2::T_WINDOW, 0, 0, &length.to_be_bytes());
        wire.send(h2::T_WINDOW, 0, request, &length.to_be_bytes());
    }

    fn capsules(&mut self, wire: &mut Wire, bytes: &[u8]) {
        self.capsules.extend_from_slice(bytes);
        let mut answers = Vec::new();
        let split: fn(&[u8]) -> Option<(usize, connectip::Capsule<'_>)> = if self.warp {
            connectip::capsule_split_bare
        } else {
            connectip::capsule_split
        };
        while let Some((used, capsule)) = split(&self.capsules[self.capsule_at..]) {
            self.capsule_at += used;
            match capsule {
                connectip::Capsule::Datagram(packet) => {
                    if let Some(udp) = &self.udp {
                        udp.send(packet);
                    } else {
                        masque::forward(&self.shared, &self.spec, &self.addrs, packet);
                    }
                }
                connectip::Capsule::AddressRequest(body) if self.udp.is_none() => {
                    let granted = masque::respond(body, &self.addrs);
                    if !granted.is_empty() {
                        let mut out = Vec::new();
                        connectip::address_assign_encode(&granted, &mut out);
                        answers.push(out);
                    }
                }
                _ => {}
            }
        }
        if self.capsule_at > 0 {
            self.capsules.drain(..self.capsule_at);
            self.capsule_at = 0;
        }
        if self.capsules.len() > FRAME_CAP {
            self.end = true;
        }
        for answer in answers {
            self.capsule(wire, &answer);
        }
    }

    /// Sends or bounds queued reply capsules only while the request and wire remain live.
    fn capsule(&mut self, wire: &mut Wire, capsule: &[u8]) {
        if self.end || wire.closed {
            return;
        }
        let Some(id) = self.request else {
            return;
        };
        if self.queued.is_empty()
            && i64::try_from(capsule.len()).unwrap_or(i64::MAX) <= self.send_window
        {
            if wire.send(h2::T_DATA, 0, id, capsule) {
                self.send_window -= i64::try_from(capsule.len()).unwrap_or(i64::MAX);
            }
        } else if self.queued.len() < QUEUED_CAP {
            self.queued.push_back(capsule.to_vec());
        } else {
            self.end = true;
        }
    }

    /// Drains live reply capsules in order, preserving any suffix blocked by peer credit.
    fn flush(&mut self, wire: &mut Wire) {
        if self.end || wire.closed {
            return;
        }
        while let Some(answer) = self.queued.pop_front() {
            let Some(id) = self.request else {
                self.queued.push_front(answer);
                return;
            };
            let start = self.queued_at;
            if self.send_window <= 0 {
                self.queued.push_front(answer);
                break;
            }
            let take =
                (answer.len() - start).min(usize::try_from(self.send_window).unwrap_or(usize::MAX));
            if !wire.send(h2::T_DATA, 0, id, &answer[start..start + take]) {
                return;
            }
            self.send_window -= i64::try_from(take).unwrap_or(i64::MAX);
            self.queued_at = start + take;
            if self.queued_at < answer.len() {
                self.queued.push_front(answer);
            } else {
                self.queued_at = 0;
            }
        }
        for _ in 0..QUEUED_CAP {
            if wire.closed || self.end {
                break;
            }
            let Some(packet) = (if let Some(udp) = &self.udp {
                udp.try_recv()
            } else {
                self.outgoing
                    .as_ref()
                    .and_then(|outgoing| outgoing.try_recv().ok())
            }) else {
                break;
            };
            let mut capsule = Vec::with_capacity(packet.len() + 8);
            if self.warp {
                bare_datagram(&packet, &mut capsule);
            } else {
                datagram(&packet, &mut capsule);
            }
            self.capsule(wire, &capsule);
        }
        if self.request.is_some() && !wire.closed && self.queued.is_empty() {
            wire.deadline.clear();
        }
    }
}

fn strip_padding(flags: u8, body: &[u8], headers: bool) -> &[u8] {
    if flags & h2::F_PADDED != 0 {
        let Some((&padding, rest)) = body.split_first() else {
            return body;
        };
        let rest = if headers && flags & h2::F_PRIORITY != 0 {
            rest.get(5..).unwrap_or_default()
        } else {
            rest
        };
        return rest
            .get(..rest.len().saturating_sub(usize::from(padding)))
            .unwrap_or_default();
    }
    if headers && flags & h2::F_PRIORITY != 0 {
        return body.get(5..).unwrap_or_default();
    }
    body
}

fn datagram(packet: &[u8], out: &mut Vec<u8>) {
    frames::quic_varint(out, 0);
    frames::quic_varint(out, (packet.len() + 1) as u64);
    out.push(0);
    out.extend_from_slice(packet);
}

/// The WARP HTTP/2 body carries a bare packet with no context byte.
fn bare_datagram(packet: &[u8], out: &mut Vec<u8>) {
    frames::quic_varint(out, 0);
    frames::quic_varint(out, packet.len() as u64);
    out.extend_from_slice(packet);
}

fn warp_tls(tls_config: &TlsConfig, warp: Option<&masque::Warp>) -> Option<TlsConfig> {
    let warp = warp?;
    let mut config = tls_config.clone();
    config.insecure = true;
    config.client_cert = Some(Arc::new(CertEntry {
        cert_chain: vec![warp.certificate().to_vec()],
        key_der: warp.key().to_vec(),
        key_kind: ServerKeyKind::Pkcs8,
        reload: None,
        ocsp: None,
    }));
    Some(config)
}

fn verify_warp(
    tls: &impl ferrox_core::tls::TlsProvider,
    insecure: bool,
    warp: Option<&masque::Warp>,
) -> Result<(), String> {
    let Some(warp) = warp else {
        return Ok(());
    };
    if insecure {
        return Ok(());
    }
    let leaf = tls
        .peer_leaf()
        .ok_or("warp: the edge sent no certificate")?;
    let spki = masque::warp_spki(leaf).ok_or("warp: the edge certificate is malformed")?;
    if spki == warp.public_key() {
        Ok(())
    } else {
        Err("warp: the edge public key does not match".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::UdpSocket;
    use std::sync::Mutex;

    use ferrox_core::foxy::connectip::{self, UdpDatagram};
    use ferrox_core::tls::TlsConfig;

    use super::*;
    use crate::json::Json;

    #[test]
    fn a_warp_request_names_its_protocol_in_a_header() {
        let fields = request_fields("cloudflareaccess.com:443", "/", &[], true, "https");
        assert_eq!(
            fields,
            vec![
                (":method", "CONNECT"),
                (":scheme", "https"),
                (":path", "/"),
                (":authority", "cloudflareaccess.com:443"),
                ("cf-connect-proto", "cf-connect-ip"),
                ("pq-enabled", "false"),
            ]
        );
        assert!(!fields
            .iter()
            .any(|(name, _)| *name == ":protocol" || *name == "capsule-protocol"));
    }

    #[test]
    fn an_rfc_request_names_its_protocol_in_a_pseudo_header() {
        let fields = request_fields("edge", "/.well-known/masque/ip/*/*/", &[], false, "https");
        assert!(fields.contains(&(":protocol", "connect-ip")));
        assert!(fields.contains(&("capsule-protocol", "?1")));
        assert!(!fields.iter().any(|(name, _)| *name == "cf-connect-proto"));
    }

    #[test]
    fn a_full_h2_slot_table_refuses_another_connection() {
        let slots = H2Slots::new(2);
        let first = slots.acquire().expect("the first slot");
        let second = slots.acquire().expect("the second slot");
        assert!(
            slots.acquire().is_none(),
            "a full table admitted another connection"
        );
        drop(first);
        assert!(
            slots.acquire().is_some(),
            "a released slot was not reusable"
        );
        drop(second);
    }

    fn bare_client() -> Client {
        Client {
            wire: Wire {
                stream: Box::new(std::io::Cursor::new(Vec::new())),
                pending: Vec::new(),
                closed: false,
                deadline: Deadline::default(),
            },
            decoder: Decoder::default(),
            stream: 1,
            status: None,
            continuation: None,
            send_window: DEFAULT_WINDOW,
            peer_window: DEFAULT_WINDOW,
            connection_window: DEFAULT_WINDOW,
            queued: std::collections::VecDeque::new(),
            queued_at: 0,
            capsules: Vec::new(),
            capsule_at: 0,
            addresses: Vec::new(),
            mtu: masque::DEFAULT_MTU,
            packets: Vec::new(),
            early_bytes: 0,
            to_stack: None,
            routes: None,
            warp: false,
            end: false,
            last_frame: Instant::now(),
        }
    }

    #[test]
    fn an_accepted_stream_bounds_both_handshake_directions() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
        let address = listener.local_addr().expect("an address");
        let _client = TcpStream::connect(address).expect("a client");
        let (server, _) = listener.accept().expect("an accepted stream");
        handshake_timeouts(&server);
        assert_eq!(
            server.read_timeout().expect("a read timeout"),
            Some(HANDSHAKE)
        );
        assert_eq!(
            server.write_timeout().expect("a write timeout"),
            Some(HANDSHAKE)
        );
    }

    fn udp_packet(destination_port: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 14, 0, 2]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
        packet[20..22].copy_from_slice(&1234u16.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..26].copy_from_slice(&8u16.to_be_bytes());
        packet
    }

    #[test]
    fn a_frame_body_is_read_where_it_landed() {
        let body = [0x00, 0x02, 0x00, 0xde, 0xad];
        let mut pending = Vec::new();
        pending.extend_from_slice(&h2::frame_head(body.len(), h2::T_DATA, 0, 1));
        pending.extend_from_slice(&body);
        let ((), counts) = ferrox_core::alloc_count::measure(|| {
            let frame = frame_at(&pending, 0)
                .expect("a frame")
                .expect("a whole frame");
            assert_eq!((frame.kind, frame.flags, frame.id), (h2::T_DATA, 0, 1));
            assert_eq!(&pending[frame.start..frame.end], &body);
        });
        assert_eq!(
            counts.allocs, 0,
            "the frame body is read where it landed: {counts:?}"
        );
    }

    #[test]
    fn a_whole_capsule_is_read_where_it_landed() {
        let mut capsule = Vec::new();
        frames::quic_varint(&mut capsule, 0x1234);
        frames::quic_varint(&mut capsule, 0);
        let mut client = bare_client();
        let ((), counts) = ferrox_core::alloc_count::measure(|| client.capsules(&capsule));
        assert_eq!(
            counts.allocs, 0,
            "a whole capsule is parsed without staging: {counts:?}"
        );
        assert_eq!(
            client.capsules.capacity(),
            0,
            "a whole capsule is never staged"
        );
        assert_eq!(client.packets.len(), 0);
    }

    /// The count cap ends the session on the datagram after the last one held.
    #[test]
    fn a_pre_stack_datagram_flood_is_bounded() {
        let mut capsule = Vec::new();
        datagram(&udp_packet(53), &mut capsule);
        let mut client = bare_client();
        for _ in 0..masque::EARLY_PACKETS {
            client.capsules(&capsule);
        }
        assert!(!client.end, "the count cap itself is accepted");
        assert_eq!(client.packets.len(), masque::EARLY_PACKETS);
        client.capsules(&capsule);
        assert!(client.end, "the next datagram ends the session");
        assert_eq!(client.packets.len(), masque::EARLY_PACKETS);
    }

    /// The byte cap ends the session before the count cap is reached.
    #[test]
    fn a_pre_stack_datagram_byte_flood_is_bounded() {
        let packet = vec![0u8; masque::EARLY_BYTES / masque::EARLY_PACKETS + 1];
        let mut capsule = Vec::new();
        datagram(&packet, &mut capsule);
        let mut client = bare_client();
        for _ in 0..masque::EARLY_PACKETS {
            client.capsules(&capsule);
            if client.end {
                break;
            }
        }
        assert!(client.end, "the byte cap ends the session");
        assert!(client.packets.len() < masque::EARLY_PACKETS);
        assert!(client.early_bytes <= masque::EARLY_BYTES);
    }

    /// Each exhausted window independently enforces the documented 64-capsule limit and overflow termination.
    #[test]
    fn a_stalled_send_window_bounds_the_queued_capsules() {
        for (stream, connection) in [(0, 0), (0, DEFAULT_WINDOW), (DEFAULT_WINDOW, 0)] {
            let mut client = bare_client();
            client.send_window = stream;
            client.connection_window = connection;
            for _ in 0..64 {
                client.capsule(&[0, 2, 0, 42]);
            }
            assert_eq!(client.queued.len(), 64);
            assert!(!client.end, "the cap itself is accepted");
            for _ in 0..64 {
                client.capsule(&[0, 2, 0, 42]);
            }
            assert_eq!(client.queued.len(), 64);
            assert!(client.end, "the next capsule ends the session");
        }
    }

    #[test]
    fn a_stalled_server_send_window_bounds_the_queued_capsules() {
        let mut session = Session::new(masque::test_shared(), Arc::new(masque::test_spec()));
        session.request = Some(1);
        session.send_window = 0;
        let mut wire = Wire {
            stream: Box::new(std::io::Cursor::new(Vec::new())),
            pending: Vec::new(),
            closed: false,
            deadline: Deadline::default(),
        };
        let mut capsule = Vec::new();
        datagram(&udp_packet(53), &mut capsule);
        for _ in 0..=QUEUED_CAP {
            session.capsule(&mut wire, &capsule);
        }
        assert_eq!(
            session.queued.len(),
            QUEUED_CAP,
            "a stalled window keeps at most {QUEUED_CAP} capsules"
        );
        assert!(session.end, "the capsule past the cap ends the session");
    }

    #[test]
    fn a_blocked_queue_head_still_drains_outgoing_to_the_cap() {
        let mut session = Session::new(masque::test_shared(), Arc::new(masque::test_spec()));
        session.request = Some(1);
        session.send_window = 0;
        let (sender, outgoing) = mpsc::sync_channel(masque::QUEUE);
        session.outgoing = Some(outgoing);
        let mut wire = Wire {
            stream: Box::new(std::io::Cursor::new(Vec::new())),
            pending: Vec::new(),
            closed: false,
            deadline: Deadline::default(),
        };
        let mut capsule = Vec::new();
        datagram(&udp_packet(53), &mut capsule);
        for _ in 0..QUEUED_CAP {
            session.capsule(&mut wire, &capsule);
        }
        sender.send(udp_packet(53)).expect("a packet");
        session.flush(&mut wire);
        assert!(session.end, "a full queue ends the session");
    }

    #[test]
    fn a_capsule_larger_than_the_window_is_sent_in_parts() {
        let mut client = bare_client();
        client.send_window = 10;
        client.connection_window = 10;
        client.capsule(&[0u8; 25]);
        assert_eq!(client.queued.len(), 1, "the capsule waits for room");
        client.flush();
        assert_eq!(client.queued_at, 10, "the first part used the window");
        assert_eq!(client.queued.len(), 1);
        client.send_window = 10;
        client.connection_window = 10;
        client.flush();
        assert_eq!(client.queued_at, 20, "the second part used the window");
        assert_eq!(client.queued.len(), 1);
        client.send_window = 10;
        client.connection_window = 10;
        client.flush();
        assert!(
            client.queued.is_empty(),
            "the last part finished the capsule"
        );
        assert_eq!(client.queued_at, 0);
    }

    #[test]
    fn connect_keeps_the_peer_initial_window() {
        let mut session = Session::new(masque::test_shared(), Arc::new(masque::test_spec()));
        let mut wire = Wire {
            stream: Box::new(std::io::Cursor::new(Vec::new())),
            pending: Vec::new(),
            closed: false,
            deadline: Deadline::default(),
        };
        let mut settings = Vec::new();
        settings.extend_from_slice(&SETTINGS_INITIAL_WINDOW.to_be_bytes());
        settings.extend_from_slice(&0u32.to_be_bytes());
        session.on(&mut wire, h2::T_SETTINGS, 0, 0, &settings);
        assert_eq!(session.send_window, 0, "the peer's window is recorded");
        let path = session.spec.path.clone();
        let block = h2::block_encode(&[
            (":method", "CONNECT"),
            (":protocol", "connect-ip"),
            (":scheme", "https"),
            (":path", &path),
            (":authority", "edge"),
            ("capsule-protocol", "?1"),
            ("authorization", "Basic YTpi"),
        ]);
        session.on(&mut wire, h2::T_HEADERS, h2::F_END_HEADERS, 1, &block);
        assert_eq!(session.send_window, 0, "CONNECT keeps the peer's window");
    }

    fn initial_window(value: u32) -> Vec<u8> {
        let mut settings = Vec::new();
        settings.extend_from_slice(&SETTINGS_INITIAL_WINDOW.to_be_bytes());
        settings.extend_from_slice(&value.to_be_bytes());
        settings
    }

    #[test]
    fn a_changed_initial_window_keeps_the_client_credit() {
        let mut client = bare_client();
        client.on(h2::T_SETTINGS, 0, 0, &initial_window(100));
        client.on(h2::T_WINDOW, 0, 1, &1_000u32.to_be_bytes());
        assert_eq!(client.send_window, 1_100, "the update grants credit");
        client.on(h2::T_SETTINGS, 0, 0, &initial_window(50));
        assert_eq!(
            client.send_window, 1_050,
            "the new initial value moves the window by its difference"
        );
    }

    #[test]
    fn a_changed_initial_window_keeps_the_server_credit() {
        let mut session = Session::new(masque::test_shared(), Arc::new(masque::test_spec()));
        let mut wire = Wire {
            stream: Box::new(std::io::Cursor::new(Vec::new())),
            pending: Vec::new(),
            closed: false,
            deadline: Deadline::default(),
        };
        session.on(&mut wire, h2::T_SETTINGS, 0, 0, &initial_window(100));
        session.on(&mut wire, h2::T_WINDOW, 0, 0, &1_000u32.to_be_bytes());
        assert_eq!(session.send_window, 1_100, "the update grants credit");
        session.on(&mut wire, h2::T_SETTINGS, 0, 0, &initial_window(50));
        assert_eq!(
            session.send_window, 1_050,
            "the new initial value moves the window by its difference"
        );
    }

    struct Quiet {
        reads: usize,
    }

    impl Read for Quiet {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            if self.reads == 0 {
                return Ok(0);
            }
            self.reads -= 1;
            Err(std::io::Error::from(std::io::ErrorKind::TimedOut))
        }
    }

    impl Write for Quiet {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn an_expired_handshake_deadline_stops_a_trickled_read() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
        let address = listener.local_addr().expect("an address");
        let peer = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(address).expect("connects");
            for _ in 0..20 {
                if stream.write_all(&[0]).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        let (stream, _) = listener.accept().expect("accepts");
        let deadline = Deadline::default();
        deadline.arm(Instant::now());
        let mut stream = DeadlineStream::new(stream, deadline);
        let start = Instant::now();
        let mut error = None;
        let mut byte = [0u8; 1];
        while start.elapsed() < Duration::from_millis(500) {
            match stream.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => {}
                Err(reason) => {
                    error = Some(reason);
                    break;
                }
            }
        }
        let _ = peer.join();
        assert!(
            error.is_some_and(|reason| reason.kind() == std::io::ErrorKind::TimedOut),
            "the read outlived its absolute deadline"
        );
    }

    #[test]
    fn a_timeout_after_the_deadline_closes_the_wire() {
        let deadline = Deadline::default();
        deadline.arm(Instant::now());
        let mut wire = Wire {
            stream: Box::new(Quiet { reads: 1_000 }),
            pending: Vec::new(),
            closed: false,
            deadline,
        };
        assert!(!wire.fill(), "an expired deadline ends the read");
        assert!(wire.closed, "the wire is closed, not retried as idle");
    }

    #[test]
    fn a_silent_peer_is_ended_after_the_handshake() {
        let mut session = Session::new(masque::test_shared(), Arc::new(masque::test_spec()));
        let mut wire = Wire {
            stream: Box::new(Quiet { reads: 1_000 }),
            pending: Vec::new(),
            closed: false,
            deadline: Deadline::default(),
        };
        let deadline = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .expect("a past deadline");
        session.run_until(&mut wire, deadline);
        assert!(session.end, "a silent peer is ended at the deadline");
    }

    #[test]
    fn a_continuation_block_cannot_grow_past_the_frame_cap() {
        let mut session = Session::new(masque::test_shared(), Arc::new(masque::test_spec()));
        let mut wire = Wire {
            stream: Box::new(std::io::Cursor::new(Vec::new())),
            pending: Vec::new(),
            closed: false,
            deadline: Deadline::default(),
        };
        let half = vec![0u8; FRAME_CAP / 2 + 1];
        session.on(&mut wire, h2::T_HEADERS, 0, 1, &half);
        assert!(session.continuation.is_some(), "the header block is open");
        session.on(&mut wire, h2::T_CONT, 0, 1, &half);
        assert!(session.end, "the accumulated block is capped");
    }

    struct Recorder {
        out: Arc<Mutex<Vec<u8>>>,
    }

    impl Read for Recorder {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for Recorder {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.out.lock().expect("a recorder").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A cleartext connection starts with the handshake clock already armed.
    #[test]
    fn a_cleartext_wire_arms_the_handshake_clock() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
        let address = listener.local_addr().expect("an address");
        let client = TcpStream::connect(address).expect("a client");
        let (server, _) = listener.accept().expect("a server");
        let wire = cleartext_wire(server);
        assert!(wire
            .deadline
            .remaining()
            .is_some_and(|left| left > Duration::ZERO));
        drop(client);
    }

    struct Gate {
        out: Arc<Mutex<Vec<u8>>>,
        deadline: Instant,
    }

    impl Read for Gate {
        /// Nothing is ever read from the gate.
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for Gate {
        /// Wait out the clock before the ping answer, then record every write.
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if buf.len() == 9 && buf[3] == h2::T_PING && buf[4] == h2::F_ACK {
                let wait = self.deadline.saturating_duration_since(Instant::now());
                if !wait.is_zero() {
                    std::thread::sleep(wait + Duration::from_millis(1));
                }
            }
            self.out.lock().expect("a gate").extend_from_slice(buf);
            Ok(buf.len())
        }

        /// Flushes are no-ops on the in-memory gate.
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// An already-due clock ends the session before the first buffered frame is answered.
    #[test]
    fn a_due_handshake_clock_ends_before_any_frame() {
        let out = Arc::new(Mutex::new(Vec::new()));
        let mut pending = Vec::new();
        pending.extend_from_slice(&h2::frame_head(8, h2::T_PING, 0, 0));
        pending.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let mut wire = Wire {
            stream: Box::new(Recorder {
                out: Arc::clone(&out),
            }),
            pending,
            closed: false,
            deadline: Deadline::default(),
        };
        let mut session = Session::new(masque::test_shared(), Arc::new(masque::test_spec()));
        let past = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .expect("a past instant");
        session.run_until(&mut wire, past);
        assert!(session.end, "the handshake clock ended the session");
        assert_eq!(
            out.lock().expect("a recorder").len(),
            15,
            "the due clock stopped before the ping was answered"
        );
    }

    /// A clock that falls due after the first frame stops the second one from being answered.
    #[test]
    fn a_handshake_clock_that_falls_due_between_frames_stops_the_next() {
        let gate = Instant::now() + Duration::from_secs(2);
        let out = Arc::new(Mutex::new(Vec::new()));
        let mut pending = Vec::new();
        for _ in 0..2 {
            pending.extend_from_slice(&h2::frame_head(8, h2::T_PING, 0, 0));
            pending.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        }
        let mut wire = Wire {
            stream: Box::new(Gate {
                out: Arc::clone(&out),
                deadline: gate,
            }),
            pending,
            closed: false,
            deadline: Deadline::default(),
        };
        let mut session = Session::new(masque::test_shared(), Arc::new(masque::test_spec()));
        session.run_until(&mut wire, gate);
        assert!(session.end, "the handshake clock ended the session");
        assert_eq!(
            out.lock().expect("a gate").len(),
            32,
            "the due clock stopped before the second ping was answered"
        );
    }

    #[test]
    fn priority_bytes_are_stripped_from_headers_alone() {
        let body = [0u8, 0, 0, 0, 0, 0xaa];
        assert_eq!(
            strip_padding(h2::F_PRIORITY, &body, true),
            &[0xaa],
            "the priority fields are not part of the HPACK block"
        );
        assert_eq!(
            strip_padding(h2::F_PRIORITY, &body, false),
            &body,
            "the priority bit has no meaning outside HEADERS"
        );
    }

    #[test]
    fn a_near_cap_block_is_rejected_without_growing() {
        let mut session = Session::new(masque::test_shared(), Arc::new(masque::test_spec()));
        let half = FRAME_CAP / 2 + 1;
        session.continuation = Some((1, vec![0u8; half], 0));
        let body = vec![0u8; half];
        let mut wire = Wire {
            stream: Box::new(std::io::Cursor::new(Vec::new())),
            pending: Vec::new(),
            closed: false,
            deadline: Deadline::default(),
        };
        let ((), counts) = ferrox_core::alloc_count::measure(|| {
            session.on(&mut wire, h2::T_CONT, 0, 1, &body);
        });
        assert!(session.end, "the oversized block is rejected");
        assert_eq!(
            counts.allocs, 0,
            "the cap is checked before extending: {counts:?}"
        );
    }

    #[test]
    fn an_empty_data_frame_sends_no_window_update() {
        let mut session = Session::new(masque::test_shared(), Arc::new(masque::test_spec()));
        session.request = Some(1);
        let out = Arc::new(Mutex::new(Vec::new()));
        let mut wire = Wire {
            stream: Box::new(Recorder {
                out: Arc::clone(&out),
            }),
            pending: Vec::new(),
            closed: false,
            deadline: Deadline::default(),
        };
        session.on(&mut wire, h2::T_DATA, h2::F_END, 1, &[]);
        assert!(
            out.lock().expect("a recorder").is_empty(),
            "an empty DATA frame credits nothing"
        );
    }

    /// Restored stream and connection credit drains the accepted capsules in their original order.
    #[test]
    fn queued_capsules_flush_when_the_peer_grants_window() {
        let capsule = [0, 2, 0, 42];
        let mut client = bare_client();
        client.send_window = 0;
        client.connection_window = 0;
        let mut session = Session::new(masque::test_shared(), Arc::new(masque::test_spec()));
        session.request = Some(1);
        session.send_window = 0;
        let mut wire = bare_client().wire;
        wire.deadline.arm(Instant::now() + Duration::from_secs(1));
        for _ in 0..QUEUED_CAP {
            client.capsule(&capsule);
            session.capsule(&mut wire, &capsule);
        }
        assert!(
            wire.deadline.remaining().is_some(),
            "a queued capsule must keep the handshake clock armed"
        );
        let window = u32::try_from(QUEUED_CAP * capsule.len())
            .expect("window")
            .to_be_bytes();
        client.on(h2::T_WINDOW, 0, 0, &window);
        client.flush();
        assert_eq!(client.queued.len(), QUEUED_CAP, "stream is still blocked");
        client.on(h2::T_WINDOW, 0, 1, &window);
        session.on(&mut wire, h2::T_WINDOW, 0, 1, &window);
        client.flush();
        session.flush(&mut wire);
        assert!(client.queued.is_empty());
        assert!(session.queued.is_empty());
        assert!(
            wire.deadline.remaining().is_none(),
            "an empty queue releases the handshake clock"
        );
        assert_eq!(client.send_window, 0);
        assert_eq!(client.connection_window, 0);
        assert_eq!(session.send_window, 0);
        assert!(!client.end);
        assert!(!session.end);
        assert!(!client.wire.closed);
        assert!(!wire.closed);
    }

    /// Overflow terminates a bounded batch without consuming the next tunnel or reply packet.
    #[test]
    fn an_overflow_stops_draining_the_packet_channels() {
        let (sender, receiver) = mpsc::sync_channel(masque::QUEUE);
        sender.send(vec![42]).expect("a packet");
        sender.send(vec![42]).expect("a packet");
        let mut client = bare_client();
        client.send_window = 0;
        for _ in 0..QUEUED_CAP {
            client.capsule(&[0, 2, 0, 42]);
        }
        let (to_stack, _) = mpsc::channel();
        let routes = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        client.run(&receiver, &to_stack, &routes, None);
        assert!(client.end);
        assert_eq!(client.queued.len(), QUEUED_CAP);
        assert_eq!(receiver.try_iter().count(), 1);

        let mut session = Session::new(masque::test_shared(), Arc::new(masque::test_spec()));
        session.request = Some(1);
        session.send_window = 0;
        let (sender, receiver) = mpsc::sync_channel(masque::QUEUE);
        sender.send(vec![42]).expect("a packet");
        sender.send(vec![42]).expect("a packet");
        session.outgoing = Some(receiver);
        let mut wire = bare_client().wire;
        for _ in 0..QUEUED_CAP {
            session.capsule(&mut wire, &[0, 2, 0, 42]);
        }
        session.flush(&mut wire);
        assert!(session.end);
        assert_eq!(session.queued.len(), QUEUED_CAP);
        assert_eq!(
            session
                .outgoing
                .as_ref()
                .expect("receiver")
                .try_iter()
                .count(),
            1
        );
    }

    /// A failed wire write leaves the next tunnel packet available to its receiver.
    #[test]
    fn a_closed_wire_stops_draining_the_packet_channel() {
        let (sender, receiver) = mpsc::sync_channel(masque::QUEUE);
        sender.send(vec![42]).expect("a packet");
        sender.send(vec![43]).expect("a packet");
        let mut client = bare_client();
        client.wire.stream = Box::new(std::io::Cursor::new(Vec::<u8>::new().into_boxed_slice()));
        let (to_stack, _) = mpsc::channel();
        let routes = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        client.run(&receiver, &to_stack, &routes, None);
        assert!(client.wire.closed);
        assert!(!client.end, "write failure alone closes the wire");
        assert_eq!(
            receiver.try_recv().expect("the next packet stays queued"),
            [43]
        );
        assert!(receiver.try_recv().is_err());
    }

    /// A quiet client sends the reference's PING once the period has passed.
    #[test]
    fn a_quiet_client_pings_at_the_configured_period() {
        let out = Arc::new(Mutex::new(Vec::new()));
        let mut client = bare_client();
        client.wire.stream = Box::new(Recorder {
            out: Arc::clone(&out),
        });
        let (sender, receiver) = mpsc::sync_channel(masque::QUEUE);
        drop(sender);
        let (to_stack, _) = mpsc::channel();
        let routes = Arc::new(Mutex::new(std::collections::HashMap::new()));
        client.run(&receiver, &to_stack, &routes, Some(Duration::ZERO));
        let written = out.lock().expect("a recorder");
        assert!(
            written
                .windows(9)
                .any(|head| { head == [0, 0, 8, h2::T_PING, 0, 0, 0, 0, 0].as_slice() }),
            "the quiet client sent the h2 PING: {written:?}"
        );
    }

    /// Terminal calls preserve queue contents, partial offsets, window credit and wire output.
    #[test]
    fn ended_or_closed_sessions_leave_capsules_and_channels_untouched() {
        for (ended, closed) in [(true, false), (false, true)] {
            let mut client = bare_client();
            client.send_window = 0;
            client.capsule(&[0, 2, 0, 42]);
            client.end = ended;
            client.wire.closed = closed;
            client.capsule(&[0, 2, 0, 43]);
            assert_eq!(client.queued.len(), 1, "no enqueue after termination");
            client.send_window = DEFAULT_WINDOW;
            client.flush();
            assert_eq!(client.queued.len(), 1, "no flush after termination");
            assert_eq!(client.send_window, DEFAULT_WINDOW);

            let mut session = Session::new(masque::test_shared(), Arc::new(masque::test_spec()));
            session.request = Some(1);
            session.send_window = 0;
            let mut wire = bare_client().wire;
            session.capsule(&mut wire, &[0, 2, 0, 42]);
            session.end = ended;
            wire.closed = closed;
            session.capsule(&mut wire, &[0, 2, 0, 43]);
            assert_eq!(session.queued.len(), 1, "no enqueue after termination");
            let (sender, receiver) = mpsc::sync_channel(masque::QUEUE);
            sender.send(vec![42]).expect("a packet");
            session.outgoing = Some(receiver);
            session.send_window = DEFAULT_WINDOW;
            session.flush(&mut wire);
            assert_eq!(session.queued.len(), 1, "no flush after termination");
            assert_eq!(session.send_window, DEFAULT_WINDOW);
            assert_eq!(
                session
                    .outgoing
                    .as_ref()
                    .expect("receiver")
                    .try_iter()
                    .count(),
                1
            );
        }
    }

    #[test]
    fn a_datagram_capsule_goes_straight_to_its_lane() {
        let packet = udp_packet(53);
        let mut capsule = Vec::new();
        datagram(&packet, &mut capsule);
        let (lane, received) = std::sync::mpsc::channel();
        let mut table = std::collections::HashMap::new();
        table.insert(53, lane);
        let routes = Arc::new(std::sync::Mutex::new(table));
        let (to_stack, _stack_rx) = std::sync::mpsc::channel();
        let mut client = bare_client();
        client.routes = Some(routes);
        client.to_stack = Some(to_stack);
        client.capsules(&capsule);
        assert_eq!(
            client.capsules.capacity(),
            0,
            "a whole capsule is never staged"
        );
        assert_eq!(
            client.packets.len(),
            0,
            "the packet went straight to its lane"
        );
        assert_eq!(received.recv().expect("delivered"), packet);
    }

    #[test]
    fn an_incomplete_capsule_cannot_grow_past_the_frame_cap() {
        let mut client = bare_client();
        let mut partial = Vec::new();
        frames::quic_varint(&mut partial, 0);
        frames::quic_varint(&mut partial, (FRAME_CAP + 2) as u64);
        partial.resize(FRAME_CAP + 1, 0);
        client.capsules(&partial);
        assert!(client.end, "an incomplete capsule grew past the frame cap");
    }

    #[test]
    fn a_dial_refused_until_the_edge_binds_is_retried() {
        let edge = TcpListener::bind("127.0.0.1:0").expect("edge");
        let address = edge.local_addr().expect("addr");
        let mut dials = 0;
        let stream = dial_until_bound(address, |address| {
            dials += 1;
            if dials < 3 {
                return Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
            }
            TcpStream::connect_timeout(&address, Duration::from_secs(1))
        })
        .expect("reached the edge");
        drop(stream);
        assert_eq!(dials, 3);
        drop(edge);
    }

    fn pem_lines(pem: &str) -> String {
        pem.trim_end()
            .lines()
            .map(|line| format!("\"{line}\""))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn inbound(settings: &str) -> Json {
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        crate::json::parse(&format!(
            r#"{{"settings":{settings},"streamSettings":{{"security":"tls","tlsSettings":{{"alpn":["h3","h2"],"certificates":[{{"certificate":[{}],"key":[{}]}}]}}}}}}"#,
            pem_lines(&minted.cert.pem()),
            pem_lines(&minted.signing_key.serialize_pem())
        ))
        .expect("a masque inbound")
    }

    fn freedom(redirect: &str) -> crate::proxy::Outbound {
        let root = crate::json::parse(&format!(
            r#"{{"outbounds":[{{"protocol":"freedom","settings":{{"redirect":"{redirect}"}}}}]}}"#
        ))
        .expect("a freedom outbound");
        crate::proxy::Outbound::Freedom(Arc::new(
            crate::proxy::find_freedom_outbound(&root)
                .expect("the outbound reads")
                .expect("a freedom outbound"),
        ))
    }

    fn field(block: &mut Vec<u8>, name: &str, value: &[u8]) {
        block.push(0);
        block.push(name.len() as u8);
        block.extend_from_slice(name.as_bytes());
        block.push(value.len() as u8);
        block.extend_from_slice(value);
    }

    fn read_frame<S: Read + ?Sized>(stream: &mut S) -> (u8, u8, u32, Vec<u8>) {
        let mut head = [0u8; 9];
        stream.read_exact(&mut head).expect("a frame head");
        let len = usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).expect("a frame body");
        (
            head[3],
            head[4],
            u32::from_be_bytes(head[5..9].try_into().expect("four bytes")),
            body,
        )
    }

    fn write_frame<S: Write + ?Sized>(stream: &mut S, kind: u8, flags: u8, id: u32, body: &[u8]) {
        let head = h2::frame_head(body.len(), kind, flags, id);
        stream.write_all(&head).expect("a frame head");
        stream.write_all(body).expect("a frame body");
    }

    fn established(echo: SocketAddr) -> (ferrox_core::tls::ClientSession<TcpStream>, IpAddr) {
        established_with(echo, false)
    }

    /// Open a tunnel to the h2 listener, in the WARP dialect when asked.
    fn established_with(
        echo: SocketAddr,
        warp: bool,
    ) -> (ferrox_core::tls::ClientSession<TcpStream>, IpAddr) {
        let settings = if warp {
            r#"{"warp":true,"address":["10.14.0.1/24","fd14::1/64"]}"#
        } else {
            r#"{"users":[{"email":"u@example.com","password":"p"}],"address":["10.14.0.1/24","fd14::1/64"]}"#
        };
        let config = inbound(settings);
        let port =
            crate::masque::serve_inbound(&config, &freedom(&echo.to_string()), "127.0.0.1:0")
                .expect("serve");

        let tcp = TcpStream::connect(("127.0.0.1", port)).expect("tcp");
        tcp.set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        let config = TlsConfig {
            server_name: "localhost".to_owned(),
            alpn: Arc::from([b"h2".to_vec()]),
            insecure: true,
            ..TlsConfig::default()
        };
        let mut tls = ferrox_core::tls::connect(&config, tcp).expect("tls");
        tls.handshake().expect("handshake");
        assert_eq!(tls.alpn(), Some(b"h2".as_slice()));

        tls.write_all(h2::MAGIC).expect("preface");
        write_frame(&mut tls, h2::T_SETTINGS, 0, 0, &[]);
        let mut block = Vec::new();
        field(&mut block, ":method", b"CONNECT");
        field(&mut block, ":scheme", b"https");
        field(
            &mut block,
            ":path",
            if warp {
                b"/"
            } else {
                b"/.well-known/masque/ip/*/*/"
            },
        );
        field(
            &mut block,
            ":authority",
            format!("localhost:{port}").as_bytes(),
        );
        if warp {
            field(&mut block, "cf-connect-proto", b"cf-connect-ip");
        } else {
            field(&mut block, ":protocol", b"connect-ip");
            field(&mut block, "capsule-protocol", b"?1");
            field(&mut block, "authorization", b"Basic dUBleGFtcGxlLmNvbTpw");
        }
        write_frame(&mut tls, h2::T_HEADERS, h2::F_END_HEADERS, 1, &block);

        let mut status = None;
        let mut assigned = Vec::new();
        while status.is_none() || assigned.is_empty() {
            let (kind, flags, id, body) = read_frame(&mut tls);
            if kind == h2::T_SETTINGS {
                if flags & h2::F_ACK == 0 {
                    write_frame(&mut tls, h2::T_SETTINGS, h2::F_ACK, 0, &[]);
                }
            } else if kind == h2::T_HEADERS && id == 1 {
                let mut fields = Vec::new();
                Decoder::default()
                    .decode(&body, &mut |name, value| {
                        fields.push((name.to_vec(), value.to_vec()));
                    })
                    .expect("a header block");
                status = fields
                    .iter()
                    .find(|(name, _)| name == b":status")
                    .map(|(_, value)| String::from_utf8_lossy(value).into_owned());
            } else if kind == h2::T_DATA && id == 1 {
                let split: fn(&[u8]) -> Option<(usize, connectip::Capsule<'_>)> = if warp {
                    connectip::capsule_split_bare
                } else {
                    connectip::capsule_split
                };
                let mut at = 0;
                while let Some((used, capsule)) = split(&body[at..]) {
                    at += used;
                    if let connectip::Capsule::AddressAssign(body) = capsule {
                        connectip::address_assign(body, &mut assigned).expect("an assignment");
                    }
                }
            }
        }
        assert_eq!(status.as_deref(), Some("200"));
        let client = assigned
            .iter()
            .find(|grant| grant.version == 4)
            .map(|grant| {
                let octets: [u8; 4] = grant.address[..4].try_into().expect("four bytes");
                IpAddr::from(octets)
            })
            .expect("a v4 address");
        (tls, client)
    }

    fn inbound_cleartext(settings: &str) -> Json {
        crate::json::parse(&format!(
            r#"{{"settings":{settings},"streamSettings":{{"network":"masque","security":"none"}}}}"#
        ))
        .expect("a cleartext masque inbound")
    }

    trait ReadWrite: Read + Write {}
    impl<T: Read + Write> ReadWrite for T {}

    type TestStream = Box<dyn ReadWrite>;

    fn open_connect_udp(
        target: &str,
        port: u16,
        bearer: &str,
        cleartext: bool,
    ) -> (TestStream, Vec<(String, String)>) {
        let settings =
            r#"{"users":[{"email":"u@example.com","password":"p"}],"address":["10.14.0.1/24"]}"#;
        let config = if cleartext {
            inbound_cleartext(settings)
        } else {
            inbound(settings)
        };
        let served = crate::masque::serve_inbound(&config, &freedom("127.0.0.1:1"), "127.0.0.1:0")
            .expect("serve");
        let tcp = TcpStream::connect(("127.0.0.1", served)).expect("tcp");
        tcp.set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        let mut stream: TestStream = if cleartext {
            Box::new(tcp)
        } else {
            let config = TlsConfig {
                server_name: "localhost".to_owned(),
                alpn: Arc::from([b"h2".to_vec()]),
                insecure: true,
                ..TlsConfig::default()
            };
            let mut tls = ferrox_core::tls::connect(&config, tcp).expect("tls");
            tls.handshake().expect("handshake");
            assert_eq!(tls.alpn(), Some(b"h2".as_slice()));
            Box::new(tls)
        };
        stream.write_all(h2::MAGIC).expect("preface");
        write_frame(&mut *stream, h2::T_SETTINGS, 0, 0, &[]);
        let mut block = Vec::new();
        field(&mut block, ":method", b"CONNECT");
        field(&mut block, ":protocol", b"connect-udp");
        field(&mut block, ":scheme", b"https");
        field(
            &mut block,
            ":authority",
            format!("localhost:{served}").as_bytes(),
        );
        let path = format!("/.well-known/masque/udp/{target}/{port}/");
        field(&mut block, ":path", path.as_bytes());
        field(&mut block, "capsule-protocol", b"?1");
        let pass = format!("Bearer {bearer}");
        field(&mut block, "proxy-authorization", pass.as_bytes());
        write_frame(&mut *stream, h2::T_HEADERS, h2::F_END_HEADERS, 1, &block);

        let mut fields = Vec::new();
        while fields.is_empty() {
            let (kind, flags, id, body) = read_frame(&mut *stream);
            if kind == h2::T_SETTINGS {
                if flags & h2::F_ACK == 0 {
                    write_frame(&mut *stream, h2::T_SETTINGS, h2::F_ACK, 0, &[]);
                }
            } else if kind == h2::T_HEADERS && id == 1 {
                Decoder::default()
                    .decode(&body, &mut |name, value| {
                        fields.push((
                            String::from_utf8_lossy(name).into_owned(),
                            String::from_utf8_lossy(value).into_owned(),
                        ));
                    })
                    .expect("a header block");
            }
        }
        (stream, fields)
    }

    fn status(fields: &[(String, String)]) -> Option<&str> {
        fields
            .iter()
            .find(|(name, _)| name == ":status")
            .map(|(_, value)| value.as_str())
    }

    fn echo_once() -> SocketAddr {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("echo");
        let address = echo.local_addr().expect("address");
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            if let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], from);
            }
        });
        address
    }

    fn read_udp_echo(stream: &mut TestStream) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            let (kind, flags, id, body) = read_frame(&mut *stream);
            if kind == h2::T_SETTINGS {
                if flags & h2::F_ACK == 0 {
                    write_frame(&mut *stream, h2::T_SETTINGS, h2::F_ACK, 0, &[]);
                }
                continue;
            }
            if kind != h2::T_DATA || id != 1 {
                continue;
            }
            let mut at = 0;
            while let Some((used, capsule)) = connectip::capsule_split(&body[at..]) {
                at += used;
                if let connectip::Capsule::Datagram(payload) = capsule {
                    return payload.to_vec();
                }
            }
        }
        panic!("no datagram came back");
    }

    #[test]
    fn an_h2_connect_udp_tunnel_carries_a_datagram_to_its_target() {
        let address = echo_once();
        let (mut stream, fields) = open_connect_udp("127.0.0.1", address.port(), "p", false);
        assert_eq!(status(&fields), Some("200"));
        let mut capsule = Vec::new();
        datagram(b"hello", &mut capsule);
        write_frame(&mut *stream, h2::T_DATA, 0, 1, &capsule);
        assert_eq!(read_udp_echo(&mut stream), b"hello");
    }

    #[test]
    fn a_second_h2_connect_udp_stream_is_refused_rather_than_left_waiting() {
        let address = echo_once();
        let (mut stream, fields) = open_connect_udp("127.0.0.1", address.port(), "p", false);
        assert_eq!(status(&fields), Some("200"));
        write_frame(&mut *stream, h2::T_HEADERS, h2::F_END_HEADERS, 3, &[]);
        loop {
            let (kind, flags, id, body) = read_frame(&mut *stream);
            if kind == h2::T_SETTINGS {
                if flags & h2::F_ACK == 0 {
                    write_frame(&mut *stream, h2::T_SETTINGS, h2::F_ACK, 0, &[]);
                }
                continue;
            }
            if kind == h2::T_RST && id == 3 {
                assert_eq!(body, 7u32.to_be_bytes(), "REFUSED_STREAM");
                return;
            }
        }
    }

    #[test]
    fn an_h2c_connect_udp_tunnel_carries_a_datagram_to_its_target() {
        let address = echo_once();
        let (mut stream, fields) = open_connect_udp("127.0.0.1", address.port(), "p", true);
        assert_eq!(status(&fields), Some("200"));
        let mut capsule = Vec::new();
        datagram(b"h2c", &mut capsule);
        write_frame(&mut *stream, h2::T_DATA, 0, 1, &capsule);
        assert_eq!(read_udp_echo(&mut stream), b"h2c");
    }

    #[test]
    fn a_connect_udp_tunnel_refuses_a_wrong_bearer_with_a_proxy_challenge() {
        let (_, fields) = open_connect_udp("127.0.0.1", 9, "wrong", false);
        assert_eq!(status(&fields), Some("401"));
        assert!(fields.iter().any(|(name, _)| name == "proxy-authenticate"));
    }

    #[test]
    fn an_h2_tunnel_assigns_and_carries_a_datagram() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("echo");
        let echo_address = echo.local_addr().expect("address");
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            if let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], from);
            }
        });

        let (mut tls, client) = established(echo_address);

        let mut packet = Vec::new();
        assert!(connectip::udp_datagram(
            &UdpDatagram {
                source: &client
                    .to_string()
                    .parse::<std::net::Ipv4Addr>()
                    .expect("v4")
                    .octets(),
                destination: &[192, 0, 2, 1],
                source_port: 1234,
                destination_port: echo_address.port(),
                payload: b"hello",
            },
            &mut packet
        ));
        let mut capsule = Vec::new();
        datagram(&packet, &mut capsule);
        write_frame(&mut tls, h2::T_DATA, 0, 1, &capsule);

        let deadline = Instant::now() + Duration::from_secs(20);
        let mut answered = None;
        while Instant::now() < deadline && answered.is_none() {
            let (kind, _, id, body) = read_frame(&mut tls);
            if kind != h2::T_DATA || id != 1 {
                continue;
            }
            let mut at = 0;
            while let Some((used, capsule)) = connectip::capsule_split(&body[at..]) {
                at += used;
                if let connectip::Capsule::Datagram(packet) = capsule {
                    if let Some(datagram) = connectip::udp_from_packet(packet) {
                        answered = Some(datagram.payload.to_vec());
                    }
                }
            }
        }
        assert_eq!(
            answered.as_deref(),
            Some(b"hello".as_slice()),
            "{client} → 192.0.2.1:{}",
            echo_address.port()
        );
    }

    #[test]
    fn a_warp_h2_tunnel_assigns_and_carries_a_bare_datagram() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("echo");
        let echo_address = echo.local_addr().expect("address");
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            if let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], from);
            }
        });

        let (mut tls, client) = established_with(echo_address, true);
        let mut packet = Vec::new();
        assert!(connectip::udp_datagram(
            &UdpDatagram {
                source: &client
                    .to_string()
                    .parse::<std::net::Ipv4Addr>()
                    .expect("v4")
                    .octets(),
                destination: &[192, 0, 2, 1],
                source_port: 1234,
                destination_port: echo_address.port(),
                payload: b"warp",
            },
            &mut packet
        ));
        let mut capsule = Vec::new();
        bare_datagram(&packet, &mut capsule);
        write_frame(&mut tls, h2::T_DATA, 0, 1, &capsule);

        let deadline = Instant::now() + Duration::from_secs(20);
        let mut answered = None;
        while Instant::now() < deadline && answered.is_none() {
            let (kind, _, id, body) = read_frame(&mut tls);
            if kind != h2::T_DATA || id != 1 {
                continue;
            }
            let mut at = 0;
            while let Some((used, capsule)) = connectip::capsule_split_bare(&body[at..]) {
                at += used;
                if let connectip::Capsule::Datagram(packet) = capsule {
                    if let Some(datagram) = connectip::udp_from_packet(packet) {
                        answered = Some(datagram.payload.to_vec());
                    }
                }
            }
        }
        assert_eq!(
            answered.as_deref(),
            Some(b"warp".as_slice()),
            "{client} → 192.0.2.1:{}",
            echo_address.port()
        );
    }
}

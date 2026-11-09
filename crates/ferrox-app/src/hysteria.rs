use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, ToSocketAddrs as _, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use ferrox_core::foxy::frames;
use ferrox_core::hysteria::{self, Defrag, Masquerade, UdpMessage};

use crate::conn::Connection;
use crate::proxy::lane_pool::Next;
use crate::quic::{Unfilled, RECV_ROOM};

const AUTH_STREAM: u64 = 0;

const FIRST_FLOW_STREAM: u64 = 4;

const HEAD_CAP: usize = 16 * 1024;

const ROUTE_POLL: Duration = Duration::from_millis(100);

const STREAM_POLL: Duration = Duration::from_millis(5);

const SCID_LEN: usize = 16;

/// The reader's socket poll, matching the reference's one-second cleanup tick: it bounds how long a reaped association's thread lives, since a UDP socket has no shutdown to wake a blocked read.
const UDP_POLL: Duration = Duration::from_secs(1);

/// A target reply is a whole UDP datagram, so one buffer of the wire's UDP ceiling holds any single response the association reads.
const UDP_TARGET_BUF: usize = hysteria::MAX_UDP_PAYLOAD;

pub(crate) struct Dial {
    pub(crate) host: String,
    pub(crate) address: String,
    pub(crate) port: u16,
    pub(crate) config: hysteria::Config,
    pub(crate) roots: Option<ferrox_core::tls::Anchors>,
}

#[derive(Clone)]
pub(crate) struct Session {
    pub(crate) shared: Arc<Mutex<quiche::Connection>>,
    pub(crate) sock: Arc<crate::quic::Datagram>,
    pub(crate) local: SocketAddr,
    // Written once by `connect` from the auth response and read by the UDP dial that follows: a server that skips the lane header still carries TCP flows, so the flag gates datagrams only, never the connection.
    pub(crate) udp_supported: bool,
    /// The pooled connection's one socket reader; `None` on a dial that drives the socket itself.
    pub(crate) driver: Option<Arc<Driver>>,
    /// Wakes a writer whose stream filled its window when the reader has taken a datagram: an ACK frees send capacity, and a 5 ms poll on a loopback ACK is fifty times too coarse.
    pub(crate) send_wake: Option<Arc<StreamWake>>,
    /// The reference's `keepAlivePeriod`: an idle lane sends an ack-eliciting packet this often so a middlebox or the peer's idle timer cannot retire it.
    pub(crate) keep_alive: Option<Duration>,
}

/// One stream's latch: the pump bumps it when a datagram filled the stream, and the flow reading it parks until then instead of waiting on the shared socket with the others.
pub(crate) struct StreamWake {
    gen: Mutex<u64>,
    cv: Condvar,
}

impl StreamWake {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            gen: Mutex::new(0),
            cv: Condvar::new(),
        })
    }
}

impl StreamWake {
    fn seen(&self) -> u64 {
        self.gen.lock().map_or(0, |gen| *gen)
    }

    pub(crate) fn bump(&self) {
        if let Ok(mut gen) = self.gen.lock() {
            *gen = gen.wrapping_add(1);
        }
        self.cv.notify_all();
    }

    fn wait(&self, seen: u64, timeout: Duration) {
        let Ok(gen) = self.gen.lock() else {
            return;
        };
        if *gen == seen {
            let _ = self.cv.wait_timeout(gen, timeout);
        }
    }
}

/// The session's one socket reader. A pooled connection carries every flow the client multiplexes, so a thread per flow waiting on its socket wakes all of them for every datagram; the pump takes each datagram once and wakes only the stream it filled.
pub(crate) struct Driver {
    alive: AtomicBool,
    stop: AtomicBool,
    streams: Mutex<HashMap<u64, Arc<StreamWake>>>,
    send: Arc<StreamWake>,
}

impl Driver {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            alive: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            streams: Mutex::new(HashMap::new()),
            send: StreamWake::new(),
        })
    }

    pub(crate) fn running(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    pub(crate) fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    pub(crate) fn register(&self, stream: u64) -> Arc<StreamWake> {
        if let Ok(mut streams) = self.streams.lock() {
            if let Some(wake) = streams.get(&stream) {
                return Arc::clone(wake);
            }
            let wake = StreamWake::new();
            streams.insert(stream, Arc::clone(&wake));
            return wake;
        }
        StreamWake::new()
    }

    /// The wake of a stream this driver has not seen, or `None` when one is already registered: the served side uses the map itself as its served set, so a packet that names an already-running stream costs one probe, not a separate set's probe and then this map's.
    pub(crate) fn claim(&self, stream: u64) -> Option<Arc<StreamWake>> {
        let Ok(mut streams) = self.streams.lock() else {
            return None;
        };
        match streams.entry(stream) {
            std::collections::hash_map::Entry::Occupied(_) => None,
            std::collections::hash_map::Entry::Vacant(slot) => {
                let wake = StreamWake::new();
                slot.insert(Arc::clone(&wake));
                Some(wake)
            }
        }
    }

    /// Binds this reader to a session and starts it: the session, its flows and its writers all hold one driver.
    pub(crate) fn attach(self: &Arc<Self>, session: &mut Session) {
        session.driver = Some(Arc::clone(self));
        session.send_wake = Some(Arc::clone(&self.send));
        self.spawn(session);
    }

    fn wake(&self, stream: u64) {
        if let Ok(streams) = self.streams.lock() {
            if let Some(wake) = streams.get(&stream) {
                wake.bump();
            }
        }
    }

    fn spawn(self: &Arc<Self>, session: &Session) {
        let shared = Arc::clone(&session.shared);
        let sock = Arc::clone(&session.sock);
        let local = session.local;
        let keep_alive = session.keep_alive;
        let pump = Arc::clone(self);
        self.alive.store(true, Ordering::Relaxed);
        std::thread::spawn(move || {
            let session = Session {
                shared,
                sock,
                local,
                udp_supported: false,
                driver: None,
                send_wake: None,
                keep_alive,
            };
            let mut ready = Vec::with_capacity(16);
            let mut last_sent = 0usize;
            let mut last_at = Instant::now();
            while !pump.stop.load(Ordering::Relaxed) {
                if !drive_once(&session, STREAM_POLL) {
                    let closed = match session.shared.lock() {
                        Ok(conn) => conn.is_closed(),
                        Err(_) => true,
                    };
                    if closed {
                        break;
                    }
                    std::thread::sleep(STREAM_POLL);
                    continue;
                }
                if let Some(period) = keep_alive {
                    let sent = match session.shared.lock() {
                        Ok(conn) => {
                            if conn.is_closed() {
                                break;
                            }
                            conn.stats().sent
                        }
                        Err(_) => break,
                    };
                    if sent != last_sent {
                        last_sent = sent;
                        last_at = Instant::now();
                    } else if last_at.elapsed() >= period {
                        if let Ok(mut conn) = session.shared.lock() {
                            let _ = conn.send_ack_eliciting();
                            crate::quic::flush_egress(&mut conn, &session.sock);
                            last_sent = conn.stats().sent;
                        }
                        last_at = Instant::now();
                    }
                }
                pump.send.bump();
                ready.clear();
                if let Ok(conn) = session.shared.lock() {
                    ready.extend(conn.readable());
                }
                if ready.is_empty() {
                    continue;
                }
                let Ok(streams) = pump.streams.lock() else {
                    break;
                };
                for stream in &ready {
                    if let Some(wake) = streams.get(stream) {
                        wake.bump();
                    }
                }
            }
            pump.alive.store(false, Ordering::Relaxed);
        });
    }
}

/// Write a stream's whole buffer under the send budget, releasing the pacer before it parks so a reader can answer.
pub(crate) fn send_all(session: &Session, stream: u64, buf: &[u8], fin: bool) -> bool {
    send_all_metered(session, stream, buf, fin, None)
}

/// Sends under the budget and counts each slice the connection accepts as it leaves.
fn send_all_metered(
    session: &Session,
    stream: u64,
    mut buf: &[u8],
    fin: bool,
    meter: Option<&crate::stats::Meter>,
) -> bool {
    let deadline = Instant::now() + crate::quic::SEND_WAIT;
    let mut paced = false;
    loop {
        let before = session.send_wake.as_ref().map_or(0, |wake| wake.seen());
        let last = buf.is_empty();
        if last && !fin {
            return true;
        }
        let Ok(mut conn) = session.shared.lock() else {
            return false;
        };
        match conn.stream_send(stream, buf, fin && last) {
            Ok(written) => {
                if let Some(meter) = meter {
                    meter.write(written);
                }
                buf = &buf[written..];
                crate::quic::flush_egress(&mut conn, &session.sock);
                if buf.is_empty() && (!fin || last) {
                    return true;
                }
                if written > 0 {
                    paced = false;
                    continue;
                }
            }
            Err(quiche::Error::Done) => {}
            Err(_) => return false,
        }
        if Instant::now() >= deadline {
            return false;
        }
        if !paced {
            // A pacer holding the next packet is released by the wheel's timer, not by another `send`.
            conn.on_timeout();
            crate::quic::flush_egress(&mut conn, &session.sock);
            paced = true;
            continue;
        }
        drop(conn);
        paced = false;
        if let Some(wake) = session.send_wake.as_ref() {
            wake.wait(before, STREAM_POLL);
        } else {
            std::thread::sleep(STREAM_POLL);
        }
    }
}

/// One turn of the quiche wheel with the lock held for quiche calls only, never for the socket wait between them — the shape the pool's pump takes, so a writer's one `send_all` is never starved by a reader's polling. The queue already behind the datagram the turn waited for is taken in the same turn, so a reader fed back-to-back packets pays one lock and one egress sweep for up to a batch of them rather than one of each per packet.
pub(crate) fn drive_once(session: &Session, wait: Duration) -> bool {
    let timeout = {
        let Ok(conn) = session.shared.lock() else {
            return false;
        };
        if conn.is_closed() {
            return false;
        }
        conn.timeout()
            .map_or(wait, |left| left.min(wait))
            .max(Duration::from_millis(1))
    };
    if !session.sock.refresh_read_timeout(timeout) {
        return false;
    }
    let mut room = Unfilled::<RECV_ROOM>::new();
    #[cfg(target_os = "linux")]
    let mut batch = crate::quic::Batch::new();
    #[cfg(target_os = "linux")]
    let mut batched = false;
    let incoming = {
        #[cfg(target_os = "linux")]
        match crate::quic::recv_batch(&session.sock, &mut batch) {
            crate::quic::Drain::Read => {
                batched = true;
                Some((0, session.local))
            }
            crate::quic::Drain::Empty => None,
            crate::quic::Drain::Unbatchable => match session.sock.recv_from(room.as_mut()) {
                Ok(found) => Some(found),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    None
                }
                Err(_) => {
                    std::thread::sleep(wait);
                    return false;
                }
            },
            // A socket that coalesces must not be read one segment wide.
            crate::quic::Drain::Unreadable => {
                std::thread::sleep(wait);
                return false;
            }
        }
        #[cfg(not(target_os = "linux"))]
        match session.sock.recv_from(room.as_mut()) {
            Ok(found) => Some(found),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                None
            }
            Err(_) => {
                std::thread::sleep(wait);
                return false;
            }
        }
    };
    let Ok(mut conn) = session.shared.lock() else {
        return false;
    };
    if conn.is_closed() {
        return false;
    }
    #[cfg(target_os = "linux")]
    if batched {
        for at in 0..batch.len() {
            let Some((bytes, from)) = batch.at(at) else {
                continue;
            };
            let info = quiche::RecvInfo {
                from,
                to: session.local,
            };
            let _ = conn.recv(bytes, info);
        }
        take_queued(&mut conn, session);
        crate::quic::flush_egress(&mut conn, &session.sock);
        return true;
    }
    match incoming {
        Some((n, from)) => {
            let info = quiche::RecvInfo {
                from,
                to: session.local,
            };
            let _ = conn.recv(&mut room.as_mut()[..n], info);
            take_queued(&mut conn, session);
        }
        None => conn.on_timeout(),
    }
    crate::quic::flush_egress(&mut conn, &session.sock);
    true
}

/// The datagrams already queued behind the one the turn took, never waiting for one that has not arrived: a lane whose read is the wire's own hands over a batch in one call, and a masked one reads what is there behind a tail short enough that a writer is not held behind it.
fn take_queued(conn: &mut quiche::Connection, session: &Session) {
    if !session.sock.refresh_read_timeout(crate::quic::PUMP_TAIL) {
        return;
    }
    #[cfg(target_os = "linux")]
    {
        let mut batch = crate::quic::Batch::new();
        match crate::quic::recv_batch(&session.sock, &mut batch) {
            crate::quic::Drain::Read => {
                for at in 0..batch.len() {
                    let Some((bytes, from)) = batch.at(at) else {
                        continue;
                    };
                    let info = quiche::RecvInfo {
                        from,
                        to: session.local,
                    };
                    let _ = conn.recv(bytes, info);
                }
                return;
            }
            crate::quic::Drain::Empty | crate::quic::Drain::Unreadable => return,
            crate::quic::Drain::Unbatchable => {}
        }
    }
    let mut room = Unfilled::<RECV_ROOM>::new();
    for _ in 0..crate::quic::RECV_SLOTS {
        let Ok((n, from)) = session.sock.recv_from(room.as_mut()) else {
            return;
        };
        let info = quiche::RecvInfo {
            from,
            to: session.local,
        };
        let _ = conn.recv(&mut room.as_mut()[..n], info);
    }
}

fn read_headers_block(session: &Session, stream: u64, deadline: Instant) -> Option<Vec<u8>> {
    let mut head = Vec::with_capacity(128);
    let mut room = Unfilled::<4096>::new();
    loop {
        if head.len() >= HEAD_CAP || Instant::now() >= deadline {
            return None;
        }
        let mut at = 0usize;
        if let Some(frame) = frames::h3_frame(&head, &mut at) {
            if frame.kind != frames::H3_HEADERS {
                return None;
            }
            let len = frame.length as usize;
            if head.len() >= at + len {
                head.drain(..at);
                head.truncate(len);
                return Some(head);
            }
        }
        let read = {
            let Ok(mut conn) = session.shared.lock() else {
                return None;
            };
            match conn.stream_recv(stream, room.as_mut()) {
                Ok((n, _)) => Some(n),
                Err(quiche::Error::Done) => None,
                Err(_) => return None,
            }
        };
        if let Some(n) = read {
            head.extend_from_slice(&room.as_mut()[..n]);
        } else {
            let _ = drive_once(session, STREAM_POLL);
        }
    }
}

fn control_settings(session: &Session) -> bool {
    let mut settings = Vec::new();
    frames::quic_varint(&mut settings, 0x04);
    frames::quic_varint(&mut settings, 0);
    send_all(session, 2, &settings, true)
}

fn post_auth(session: &Session, auth: &str, cc_rx: u64) -> Option<bool> {
    let mut block = Vec::with_capacity(64 + auth.len());
    hysteria::build_auth_request(auth, cc_rx, &mut block);
    let mut frame = Vec::with_capacity(16 + block.len());
    frames::quic_varint(&mut frame, frames::H3_HEADERS);
    frames::quic_varint(&mut frame, block.len() as u64);
    frame.extend_from_slice(&block);
    if !send_all(session, AUTH_STREAM, &frame, true) {
        return None;
    }
    let deadline = Instant::now() + crate::quic::HANDSHAKE_TIMEOUT;
    let body = read_headers_block(session, AUTH_STREAM, deadline)?;
    hysteria::read_auth_response(&body)
}

/// The handshakes this process has paid; a test watches a reused connection leave it untouched.
#[cfg(test)]
pub(crate) static HANDSHAKES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Dial the configured lane, wrap its socket in the mask or hop it names, and finish the QUIC handshake and auth.
pub(crate) fn connect(dial: &Dial) -> Option<Session> {
    #[cfg(test)]
    HANDSHAKES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let roots = dial.roots.as_deref().unwrap_or(&[]);
    let (sock, mut peer, local) = crate::quic::udp_to_server(&dial.address, dial.port)?;
    if let Some(realm) = dial.config.realm.as_deref() {
        peer = crate::hysteria_realm::dial_peer(&sock, realm)?;
    }
    let mut scid = [0u8; SCID_LEN];
    getrandom::fill(&mut scid).ok()?;
    let cid = quiche::ConnectionId::from_ref(&scid);
    let mut config = crate::quic::quiche_config(roots, Some(dial.config.cc.quiche_name()))?;
    if let Some(params) = &dial.config.quic {
        crate::quic::apply_hysteria_quic(&mut config, params, false);
    }
    // A bulk upload starts at 400 packets: quiche's ten leaves the first window smaller than the server's first read, and BBR then paces every ACK.
    config.set_initial_congestion_window_packets(400);
    // The client enables the datagram lane exactly as the served connection does: advertising it changes no stream byte of a TCP-only flow, and it is what lets `dgram_max_writable_len` answer for a UDP dial on this connection.
    config.enable_dgram(true, 1024, 1024);
    let Ok(mut conn) = quiche::connect(Some(&dial.host), &cid, local, peer, &mut config) else {
        return None;
    };
    let obfs = hysteria::Salamander::new(&dial.config.obfs_password);
    // A hop plan rotates the server port over a fresh socket per stay; salamander still seals each datagram, so only the destination and socket move, never a frame above. A gecko plan fragments and pads before the hop writes, so both ride one dial.
    let sock = match dial
        .config
        .hop
        .as_ref()
        .filter(|hop| !hop.ranges.is_empty())
    {
        Some(hop) => {
            let bind = if peer.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            };
            match (obfs, dial.config.gecko) {
                (Some(obfs), Some(window)) => crate::quic::Datagram::gecked_hopped(
                    peer,
                    hop.ports(),
                    hop.interval_ms,
                    bind,
                    &sock,
                    obfs,
                    window,
                )
                .ok()?,
                (obfs, None) => crate::quic::Datagram::hopped(
                    peer,
                    hop.ports(),
                    hop.interval_ms,
                    bind,
                    &sock,
                    obfs.map(crate::quic::Mask::Salamander),
                )
                .ok()?,
                // Gecko is parsed only with a salamander password it can mask with, so this arm is unreachable from a config.
                (None, Some(_)) => return None,
            }
        }
        None => match (obfs, dial.config.gecko) {
            // A gecko dial fragments and pads its long-header packets, salamander still sealing each frame; a password too short to mask with is refused at parse, never here.
            (Some(obfs), Some(window)) => crate::quic::Datagram::gecked(sock, obfs, window).ok()?,
            (Some(obfs), None) => crate::quic::Datagram::obfuscated(sock, obfs),
            (None, _) => crate::quic::Datagram::plain(sock),
        },
    };
    crate::quic::drive_handshake(&mut conn, &sock, local)?;
    let keep_alive = dial
        .config
        .quic
        .as_ref()
        .map(|params| params.keep_alive)
        .filter(|seconds| *seconds != 0)
        .map(Duration::from_secs);
    let mut session = Session {
        shared: Arc::new(Mutex::new(conn)),
        sock: Arc::new(sock),
        local,
        udp_supported: false,
        driver: None,
        send_wake: None,
        keep_alive,
    };
    if !control_settings(&session) {
        return None;
    }
    let cc_rx = dial
        .config
        .quic
        .as_ref()
        .map_or(0, |params| params.brutal_down);
    let udp = post_auth(&session, &dial.config.auth, cc_rx)?;
    session.udp_supported = udp;
    Some(session)
}

#[derive(Clone)]
pub(crate) struct Flow {
    session: Session,
    stream: u64,
    pub(crate) backlog: Vec<u8>,
    pub(crate) at: usize,
    /// Whether `read` may drive the socket itself: a flow on the server's routed socket must not, because `serve_loop` reads every datagram and routes it, and a second reader steals packets the router must see.
    drive: bool,
    /// The latch the session's pump bumps when this stream has data; `None` when this flow drives.
    wake: Option<Arc<StreamWake>>,
    /// The `[0, 0]` acknowledgement still owed to the stream's first read: two on a client-opened flow, none on the server's, because the server reads the request the client already sent.
    reply: usize,
    /// The peer's FIN arrived, possibly with the last bytes: the next read after the backlog ends reports EOF instead of waiting for a connection close.
    peer_fin: bool,
    meter: crate::stats::Meter,
}

impl Flow {
    /// Adds counters to the flow while keeping the ones it already carries.
    pub(crate) fn with_meter(mut self, meter: crate::stats::Meter) -> Self {
        self.meter = self.meter.merged(meter);
        self
    }

    pub(crate) fn with_wake(mut self, wake: Option<Arc<StreamWake>>) -> Self {
        self.wake = wake;
        self
    }

    pub(crate) fn with_send_wake(mut self, wake: Arc<StreamWake>) -> Self {
        self.session.send_wake = Some(wake);
        self
    }

    /// Carries the dial's reader and send wake onto the flow, so a pooled flow's writer waits on the ACK the driver takes instead of a 5 ms poll.
    pub(crate) fn with_session(mut self, session: &Session) -> Self {
        self.session.driver.clone_from(&session.driver);
        self.session.send_wake.clone_from(&session.send_wake);
        self
    }

    pub(crate) fn from_parts(
        shared: Arc<Mutex<quiche::Connection>>,
        sock: Arc<crate::quic::Datagram>,
        local: SocketAddr,
        stream: u64,
        backlog: Vec<u8>,
        drive: bool,
        peer_fin: bool,
    ) -> Self {
        Self {
            session: Session {
                shared,
                sock,
                local,
                udp_supported: false,
                driver: None,
                send_wake: None,
                keep_alive: None,
            },
            stream,
            backlog,
            at: 0,
            drive,
            wake: None,
            reply: 0,
            peer_fin,
            meter: crate::stats::Meter::default(),
        }
    }

    pub(crate) fn close(&self) {
        if let Ok(mut conn) = self.session.shared.lock() {
            let _ = conn.stream_send(self.stream, &[], true);
            crate::quic::flush_egress(&mut conn, &self.session.sock);
        }
    }
}

fn broken() -> std::io::Error {
    std::io::Error::from(std::io::ErrorKind::BrokenPipe)
}

impl Flow {
    /// Consumes the reply before the stream's payload: a server that buffers `[0, 0]` until its first downlink byte cannot hold an upload-only flow open, so the opening write returns before the reply and the first read pays it.
    fn drain_reply(&mut self) -> std::io::Result<()> {
        let deadline = Instant::now() + crate::quic::HANDSHAKE_TIMEOUT;
        while self.reply > 0 {
            let before = self.wake.as_ref().map_or(0, |wake| wake.seen());
            let mut room = Unfilled::<2>::new();
            let want = self.reply.min(room.as_mut().len());
            let read = {
                let Ok(mut conn) = self.session.shared.lock() else {
                    return Err(broken());
                };
                if conn.is_closed() {
                    return Ok(());
                }
                match conn.stream_recv(self.stream, &mut room.as_mut()[..want]) {
                    Ok((0, true)) => return Err(broken()),
                    Ok((n, fin)) => {
                        if fin && self.reply > n {
                            return Err(broken());
                        }
                        self.peer_fin |= fin;
                        crate::quic::flush_egress(&mut conn, &self.session.sock);
                        Some(n)
                    }
                    Err(quiche::Error::Done) => None,
                    Err(_) => return Err(broken()),
                }
            };
            if let Some(n) = read {
                if room.as_mut()[..n].iter().any(|byte| *byte != 0) {
                    return Err(broken());
                }
                self.reply -= n;
                continue;
            }
            if Instant::now() >= deadline {
                return Err(broken());
            }
            if self.drive {
                let _ = drive_once(&self.session, STREAM_POLL);
                continue;
            }
            let pumped = self.wake.is_some()
                && self
                    .session
                    .driver
                    .as_ref()
                    .is_none_or(|driver| driver.running());
            if let Some(wake) = self.wake.as_ref().filter(|_| pumped) {
                wake.wait(before, STREAM_POLL);
                continue;
            }
            {
                let Ok(conn) = self.session.shared.lock() else {
                    return Err(broken());
                };
                if conn.is_closed() {
                    return Ok(());
                }
            }
            std::thread::sleep(STREAM_POLL);
        }
        Ok(())
    }

    /// One turn of the read loop: bytes when the stream has them, `None` when this turn waited
    /// and found nothing. The relay's fixed lane re-queues on `None`, so a quiet flow hands its
    /// worker back instead of parking it for the life of the stream; `Read` loops over the same
    /// step, which is what a caller that asked for a blocking read still gets.
    pub(crate) fn read_step(&mut self, buf: &mut [u8]) -> std::io::Result<Option<usize>> {
        if buf.is_empty() {
            return Ok(Some(0));
        }
        self.drain_reply()?;
        if self.at < self.backlog.len() {
            let n = (self.backlog.len() - self.at).min(buf.len());
            buf[..n].copy_from_slice(&self.backlog[self.at..self.at + n]);
            self.at += n;
            self.meter.read(n);
            return Ok(Some(n));
        }
        if self.peer_fin {
            return Ok(Some(0));
        }
        loop {
            let before = self.wake.as_ref().map_or(0, |wake| wake.seen());
            let read = {
                let Ok(mut conn) = self.session.shared.lock() else {
                    return Err(broken());
                };
                if conn.is_closed() {
                    return Ok(Some(0));
                }
                match conn.stream_recv(self.stream, buf) {
                    Ok((n, fin)) => {
                        self.peer_fin |= fin;
                        crate::quic::flush_egress(&mut conn, &self.session.sock);
                        Some(n)
                    }
                    Err(quiche::Error::Done) => None,
                    Err(_) => return Err(broken()),
                }
            };
            if let Some(n) = read {
                self.meter.read(n);
                if n == 0 && self.peer_fin {
                    return Ok(Some(0));
                }
                return Ok(Some(n));
            }
            if self.drive {
                let _ = drive_once(&self.session, STREAM_POLL);
                return Ok(None);
            }
            let pumped = self.wake.is_some()
                && self
                    .session
                    .driver
                    .as_ref()
                    .is_none_or(|driver| driver.running());
            if let Some(wake) = self.wake.as_ref().filter(|_| pumped) {
                wake.wait(before, STREAM_POLL);
                if wake.seen() != before {
                    continue;
                }
                return Ok(None);
            }
            {
                let Ok(conn) = self.session.shared.lock() else {
                    return Err(broken());
                };
                if conn.is_closed() {
                    return Ok(Some(0));
                }
            }
            std::thread::sleep(STREAM_POLL);
            return Ok(None);
        }
    }
}

impl Read for Flow {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if let Some(n) = self.read_step(buf)? {
                return Ok(n);
            }
        }
    }
}

impl Write for Flow {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if send_all_metered(&self.session, self.stream, buf, false, Some(&self.meter)) {
            Ok(buf.len())
        } else {
            Err(broken())
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn open_flow(session: &Session, stream: u64, header: &[u8]) -> Option<Flow> {
    open_flow_with_reply(session, stream, header, 2)
}

fn open_flow_with_reply(
    session: &Session,
    stream: u64,
    header: &[u8],
    reply: usize,
) -> Option<Flow> {
    let mut prefix = Vec::with_capacity(2 + header.len());
    hysteria::tcp_prefix(&mut prefix);
    prefix.extend_from_slice(header);
    let (drive, wake) = match &session.driver {
        Some(driver) if driver.running() => (false, Some(driver.register(stream))),
        _ => (true, None),
    };
    if !send_all(session, stream, &prefix, false) {
        return None;
    }
    Some(Flow {
        session: session.clone(),
        stream,
        backlog: Vec::new(),
        at: 0,
        drive,
        wake,
        reply,
        peer_fin: false,
        meter: crate::stats::Meter::default(),
    })
}

/// Reads a Hysteria v2 TCP request body whose `0x401` frame type is already in the backlog behind `at`, leaving every byte where it arrived.
pub(crate) fn read_request(flow: &mut Flow, deadline: Instant) -> Option<String> {
    let prefix = flow.at;
    let mut head = std::mem::take(&mut flow.backlog);
    let mut room = Unfilled::<4096>::new();
    loop {
        match hysteria::decode_tcp_request_body(head.get(prefix..)?) {
            Ok((address, used)) => {
                let address = address.to_owned();
                flow.backlog = head;
                flow.at = prefix + used;
                return Some(address);
            }
            Err(hysteria::RequestError::Invalid) => return None,
            Err(hysteria::RequestError::Incomplete) => {
                if head.len().saturating_sub(prefix) >= HEAD_CAP || Instant::now() >= deadline {
                    return None;
                }
                let n = flow.read(room.as_mut()).ok()?;
                if n == 0 {
                    return None;
                }
                head.extend_from_slice(&room.as_mut()[..n]);
            }
        }
    }
}

/// One authenticated connection and the next flow stream it can open: the pinned client multiplexes every TCP flow this way, and the server already serves them.
struct Pooled {
    session: Session,
    next_stream: u64,
    used: Instant,
}

/// What a pooled connection is a connection to, keyed the way the quic carrier keys its pool: a different credential or CA set is a different connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Server {
    host: String,
    address: String,
    port: u16,
    cc: &'static str,
    auth: String,
    /// A hop plan is its own connection: a hopped dial never reuses a plain one to the
    /// same address, nor the reverse, since the two move the server port differently.
    hop: Option<hysteria::Hop>,
    /// A tuned QUIC lane is its own connection: its windows and idle bound were negotiated, so a plain dial may not ride it.
    quic: Option<hysteria::QuicParams>,
    /// A realm rendezvous is its own connection: its punch peer was negotiated through that
    /// rendezvous, so a dial through another may not ride it.
    realm: Option<Box<ferrox_core::realm::Config>>,
    roots: Option<ferrox_core::tls::Anchors>,
}

/// How long an unused connection may sit before a dial pays a fresh handshake: half of quiche's idle timeout, so a reuse always lands before either side closes it.
const REUSE_WINDOW: Duration = Duration::from_millis(crate::quic::IDLE_TIMEOUT_MS / 2);

static POOL: std::sync::OnceLock<Mutex<HashMap<Server, Vec<Pooled>>>> = std::sync::OnceLock::new();

fn pool() -> &'static Mutex<HashMap<Server, Vec<Pooled>>> {
    POOL.get_or_init(|| Mutex::new(HashMap::new()))
}

fn server_of(dial: &Dial) -> Server {
    Server {
        host: dial.host.clone(),
        address: dial.address.clone(),
        port: dial.port,
        cc: dial.config.cc.quiche_name(),
        auth: dial.config.auth.clone(),
        hop: dial.config.hop.clone(),
        quic: dial.config.quic,
        realm: dial.config.realm.clone(),
        roots: dial.roots.clone(),
    }
}

/// Whether a pooled connection can still open a flow: quiche takes no new application data once a connection is closed, draining, or carrying a close in either direction.
fn usable(conn: &quiche::Connection) -> bool {
    !conn.is_closed()
        && !conn.is_draining()
        && conn.local_error().is_none()
        && conn.peer_error().is_none()
}

/// The connections a flow may ride, each with the stream id reserved to it; closed or stale entries are dropped here, so a dead handle never blocks a dial.
fn candidates(dial: &Dial) -> Vec<(Session, u64)> {
    let Ok(mut pool) = pool().lock() else {
        return Vec::new();
    };
    let Some(entries) = pool.get_mut(&server_of(dial)) else {
        return Vec::new();
    };
    let now = Instant::now();
    entries.retain(|entry| {
        let live = entry.next_stream / 4 < crate::quic::MAX_STREAMS
            && now.saturating_duration_since(entry.used) < REUSE_WINDOW
            && entry.session.shared.lock().is_ok_and(|conn| usable(&conn));
        if !live {
            if let Some(driver) = &entry.session.driver {
                driver.stop();
            }
        }
        live
    });
    entries
        .iter_mut()
        .map(|entry| {
            let stream = entry.next_stream;
            entry.next_stream += 4;
            entry.used = now;
            (entry.session.clone(), stream)
        })
        .collect()
}

fn evict(dial: &Dial, session: &Session) {
    if let Some(driver) = &session.driver {
        driver.stop();
    }
    let Ok(mut pool) = pool().lock() else {
        return;
    };
    let Some(entries) = pool.get_mut(&server_of(dial)) else {
        return;
    };
    entries.retain(|entry| !Arc::ptr_eq(&entry.session.shared, &session.shared));
}

fn keep(dial: &Dial, session: Session, next_stream: u64) {
    let Ok(mut pool) = pool().lock() else {
        return;
    };
    pool.entry(server_of(dial)).or_default().push(Pooled {
        session,
        next_stream,
        used: Instant::now(),
    });
}

#[cfg(test)]
pub(crate) fn handshake_count() -> usize {
    HANDSHAKES.load(std::sync::atomic::Ordering::Relaxed)
}

/// Closes every pooled connection so a test can watch the next dial pay a fresh handshake.
#[cfg(test)]
pub(crate) fn close_pooled() {
    let Ok(pool) = pool().lock() else {
        return;
    };
    for entry in pool.values().flatten() {
        if let Some(driver) = &entry.session.driver {
            driver.stop();
        }
        if let Ok(mut conn) = entry.session.shared.lock() {
            let _ = conn.close(false, 0, b"pool closed by test");
        }
    }
}

pub(crate) fn open(dial: &Dial, header: &[u8], reply: usize) -> Option<Flow> {
    open_pooled(dial, header, reply)
}

/// A flow's read in a lane's shape: one turn, `WouldBlock` when it waited, so the relay hands its
/// worker back rather than parking inside `Read`.
pub(crate) struct FlowRead(Flow);

impl FlowRead {
    #[must_use]
    pub(crate) fn new(flow: Flow) -> Self {
        Self(flow)
    }
}

impl Read for FlowRead {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.0.read_step(buf)? {
            Some(n) => Ok(n),
            None => Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
        }
    }
}

/// A flow over the outbound's live connection when a stream opens on it, a fresh handshake otherwise; a pooled connection that stopped opening is dropped where it is found.
fn open_pooled(dial: &Dial, header: &[u8], reply: usize) -> Option<Flow> {
    for (session, stream) in candidates(dial) {
        if let Some(flow) = open_flow_with_reply(&session, stream, header, reply) {
            return Some(flow);
        }
        if session.shared.lock().is_ok_and(|conn| !usable(&conn)) {
            evict(dial, &session);
        }
    }
    let mut session = connect(dial)?;
    let driver = Driver::new();
    driver.attach(&mut session);
    let Some(flow) = open_flow_with_reply(&session, FIRST_FLOW_STREAM, header, reply) else {
        driver.stop();
        return None;
    };
    keep(dial, session, FIRST_FLOW_STREAM + 4);
    Some(flow)
}

pub(crate) fn dial_vless(
    client: &Connection,
    dial: &Dial,
    id: &[u8; 16],
    target: &crate::proxy::Destination,
) {
    let header = crate::proxy::vless_header(id, 1, target);
    dial_header(client, dial, &header, 2);
}

pub(crate) fn dial_header(client: &Connection, dial: &Dial, header: &[u8], reply: usize) {
    let Some(flow) = open_pooled(dial, header, reply) else {
        return;
    };
    relay(client, &flow);
}

pub(crate) fn relay(tcp: &Connection, flow: &Flow) {
    let Ok(mut tcp_read) = tcp.try_clone() else {
        return;
    };
    let Ok(mut tcp_write) = tcp.try_clone() else {
        return;
    };
    // A read nobody bounded cannot hand its lane back: an unarmed caller takes the poll grain.
    if tcp_read.read_timeout().ok().flatten().is_none() {
        let _ = tcp_read.set_read_timeout(Some(crate::budgets::RELAY_POLL));
    }
    let done = crate::proxy::RelayFinish::new(
        false,
        Arc::new(|| {}),
        Some(Box::new({
            let flow = flow.clone();
            move || flow.close()
        })),
    );

    let mut up = flow.clone();
    let forward = Arc::clone(&done);
    let mut buffer = crate::proxy::RelayBuf::new();
    crate::proxy::lane_pool::submit(
        Box::new(move || {
            let next = match tcp_read.read(buffer.as_mut()) {
                Ok(0) => Next::Done,
                Ok(n) => {
                    if up.write_all(buffer.filled(n)).is_ok() {
                        Next::More
                    } else {
                        Next::Done
                    }
                }
                Err(error) if crate::proxy::is_timeout(&error) => {
                    if forward.ended_and_idle(crate::budgets::RELAY_RESPONSE_IDLE) {
                        Next::Done
                    } else {
                        buffer.release();
                        Next::Idle
                    }
                }
                Err(_) => Next::Done,
            };
            if next == Next::Idle {
                crate::proxy::note_wait_finish(&forward);
            }
            if next == Next::Done {
                up.close();
            }
            next
        }),
        Box::new({
            let done = Arc::clone(&done);
            move || {
                done.mark_ended();
                done.lane_done();
            }
        }),
    );

    let mut back = flow.clone();
    let backward = Arc::clone(&done);
    let mut buffer = crate::proxy::RelayBuf::new();
    crate::proxy::lane_pool::submit(
        Box::new(move || {
            let next = match back.read_step(buffer.as_mut()) {
                Ok(Some(0)) | Err(_) => Next::Done,
                Ok(Some(n)) => {
                    if tcp_write.write_all(buffer.filled(n)).is_ok() {
                        Next::More
                    } else {
                        Next::Done
                    }
                }
                Ok(None) => {
                    if backward.ended_and_idle(crate::budgets::RELAY_RESPONSE_IDLE) {
                        Next::Done
                    } else {
                        buffer.release();
                        Next::Idle
                    }
                }
            };
            if next == Next::Done {
                let _ = tcp_write.shutdown(Shutdown::Write);
            }
            next
        }),
        Box::new({
            let done = Arc::clone(&done);
            move || {
                done.mark_ended();
                done.lane_done();
            }
        }),
    );
}

/// A serving identity's QUIC config: the lane's transport tuning, its certificate list, and its congestion controller.
pub(crate) fn server_config(
    identity: &ferrox_core::tls::TlsServerConfig,
    cc: hysteria::Congestion,
    quic: Option<&hysteria::QuicParams>,
) -> Option<quiche::Config> {
    let mut config = crate::quic::tls_config(identity)?;
    config.set_application_protos(&[crate::quic::ALPN]).ok()?;
    config.set_cc_algorithm_name(cc.quiche_name()).ok()?;
    // A bulk download starts at 400 packets: quiche's ten leaves the first window smaller than one flow's first read, and BBR then paces every ACK.
    config.set_initial_congestion_window_packets(400);
    // A served connection always carries an auth validator, and the reference enables the datagram lane exactly when one is present, so the lane is on unconditionally here; the depths are the peer's unsent-datagram queue, matching `udpMessageChanSize`.
    config.enable_dgram(true, 1024, 1024);
    match quic {
        Some(params) => {
            crate::quic::apply_hysteria_quic(&mut config, params, true);
            config.set_max_send_udp_payload_size(crate::quic::MAX_DATAGRAM);
            config.set_max_recv_udp_payload_size(crate::quic::MAX_DATAGRAM);
        }
        // The served side carries the same ceilings as the dial: without them quiche's autotuner has no room above the initial window, and a peer's upload is paced by `window / rtt` for its whole life.
        None => crate::quic::tune_transport(&mut config),
    }
    Some(config)
}

pub(crate) type Serve = Arc<dyn Fn(Flow) + Send + Sync>;

struct Inbound {
    conn: Arc<Mutex<quiche::Connection>>,
    client_cid: Vec<u8>,
    initial_dcid: Vec<u8>,
    source_ids: Vec<Vec<u8>>,
    authed: bool,
    settings_sent: bool,
    settings_done: bool,
    auth_buf: Vec<u8>,
    wakes: Arc<Driver>,
    udp: HashMap<u32, UdpFlow>,
    /// The listener's `brutalDown`, answered as this client's `hysteria-cc-rx` hint.
    cc_rx: u64,
}

/// One datagram association: the connected target socket the router relays through, the reassembly its inbound fragments run through, the last activity the idle reap watches, and the flag that tells its reader thread to end. A UDP socket cannot be shut down to wake a blocked read, so the reader polls on the timeout and watches the flag the reap sets.
struct UdpFlow {
    target: Arc<UdpSocket>,
    defrag: Defrag,
    last: Instant,
    stop: Arc<AtomicBool>,
}

fn answer_auth(conn: &mut quiche::Connection, ok: bool, cc_rx: u64) -> bool {
    let mut block = Vec::with_capacity(32);
    if ok {
        hysteria::build_auth_response(true, cc_rx, &mut block);
    } else {
        ferrox_core::foxy::hpack::qpack_literal_many(&[(":status", "404")], &mut block);
    }
    let mut frame = Vec::with_capacity(16 + block.len());
    frames::quic_varint(&mut frame, frames::H3_HEADERS);
    frames::quic_varint(&mut frame, block.len() as u64);
    frame.extend_from_slice(&block);
    conn.stream_send(AUTH_STREAM, &frame, true).is_ok()
}

/// Drains the client's HTTP/3 SETTINGS so the unread bytes never hold flow control, and reports the stream's FIN so the caller stops paying the call per packet.
fn drain_settings(conn: &mut quiche::Connection) -> bool {
    let mut room = Unfilled::<128>::new();
    loop {
        match conn.stream_recv(2, room.as_mut()) {
            Ok((0, _)) => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn serve_stream(
    shared: &Arc<Mutex<quiche::Connection>>,
    sock: &Arc<crate::quic::Datagram>,
    local: SocketAddr,
    stream: u64,
    serve: &Serve,
    peer: SocketAddr,
    masq: &Masquerade,
    wake: Arc<StreamWake>,
) {
    let mut head = Vec::with_capacity(8);
    let mut room = Unfilled::<64>::new();
    let mut peer_fin = false;
    let prefix = loop {
        if head.len() >= 8 {
            return;
        }
        let before = wake.seen();
        let read = {
            let Ok(mut conn) = shared.lock() else {
                return;
            };
            match conn.stream_recv(stream, room.as_mut()) {
                Ok((0, true)) => return,
                Ok((0, _)) | Err(quiche::Error::Done) => None,
                Ok((n, fin)) => {
                    peer_fin |= fin;
                    Some(n)
                }
                Err(_) => return,
            }
        };
        if let Some(n) = read {
            head.extend_from_slice(&room.as_mut()[..n]);
        } else {
            {
                let Ok(conn) = shared.lock() else {
                    return;
                };
                if conn.is_closed() {
                    return;
                }
            }
            wake.wait(before, STREAM_POLL);
            continue;
        }
        if head.is_empty() {
            continue;
        }
        let want = 1usize << usize::from(head[0] >> 6);
        if head.len() >= want {
            let Some(consumed) = hysteria::read_tcp_prefix(&head) else {
                // Not a hysteria flow prefix. A stream opening with an HTTP/3 frame type is a browser asking for a page in a flow's slot: answer it as the cover site. Any other prefix is dropped, exactly as an unreadable flow was.
                if matches!(
                    frames::quic_read(&head, &mut 0usize),
                    Some(kind) if kind == frames::H3_HEADERS || kind == frames::H3_DATA
                ) {
                    serve_masquerade_stream(shared, sock, stream, head, peer, masq);
                }
                return;
            };
            break consumed;
        }
    };
    let mut flow = Flow::from_parts(
        Arc::clone(shared),
        Arc::clone(sock),
        local,
        stream,
        head,
        false,
        peer_fin,
    );
    flow.wake = Some(wake);
    // The prefix stays in the buffer and the cursor steps over it, so no payload byte is moved.
    flow.at = prefix;
    serve(flow);
}

/// How long a masquerade origin may take to answer before the cover gives up and answers the bad-gateway line.
const ORIGIN_TIMEOUT: Duration = Duration::from_secs(5);

/// The most bytes a masquerade origin's reply may grow to before the reader stops, so a cover page never buffers without bound; the wire's own single-datagram ceiling is the natural cap.
const MASQ_BODY_CAP: usize = hysteria::MAX_UDP_PAYLOAD;

/// Answers a browser request that arrived on a flow slot: read the whole request off the stream, build the cover response, and finish the stream with it so the browser sees a complete reply while the connection stays up for its next request.
fn serve_masquerade_stream(
    shared: &Arc<Mutex<quiche::Connection>>,
    sock: &Arc<crate::quic::Datagram>,
    stream: u64,
    seed: Vec<u8>,
    peer: SocketAddr,
    masq: &Masquerade,
) {
    let Some(request) = read_h3_request(shared, stream, seed) else {
        return;
    };
    let peer = peer.to_string();
    let mut reply = Vec::new();
    masq_bytes(masq, &request, Some(&peer), &mut reply);
    let Ok(mut conn) = shared.lock() else {
        return;
    };
    if conn.is_closed() {
        return;
    }
    let _ = conn.stream_send(stream, &reply, true);
    crate::quic::flush_egress(&mut conn, sock);
}

/// Reads a browser's HTTP/3 request off a stream the router has already begun: the bytes in `buf` first, then whatever still arrives. A request whose headers are whole and which declares no body returns at once, so a keep-alive stream the browser leaves open never blocks the cover; a body is drained only until its declared length or the stream's finish.
fn read_h3_request(
    shared: &Arc<Mutex<quiche::Connection>>,
    stream: u64,
    mut buf: Vec<u8>,
) -> Option<hysteria::H3Request> {
    let mut room = Unfilled::<4096>::new();
    loop {
        if let Some(request) = assemble_request(&buf) {
            let declares_body = request.headers.iter().any(|(name, _)| {
                name.eq_ignore_ascii_case("content-length")
                    || name.eq_ignore_ascii_case("transfer-encoding")
            });
            if !declares_body || !request.body.is_empty() {
                return Some(request);
            }
        }
        if buf.len() >= HEAD_CAP {
            return assemble_request(&buf);
        }
        let fin = {
            let Ok(mut conn) = shared.lock() else {
                return assemble_request(&buf);
            };
            if conn.is_closed() {
                return assemble_request(&buf);
            }
            match conn.stream_recv(stream, room.as_mut()) {
                Ok((0, _)) | Err(quiche::Error::Done) => false,
                Ok((n, fin)) => {
                    buf.extend_from_slice(&room.as_mut()[..n]);
                    fin
                }
                Err(_) => return assemble_request(&buf),
            }
        };
        if fin {
            return assemble_request(&buf);
        }
        std::thread::sleep(STREAM_POLL);
    }
}

/// Walks a request stream's HTTP/3 frames once: the first `HEADERS` block becomes the request line and fields, and every `DATA` payload that follows becomes the body. `None` while any frame is still incomplete, so the reader keeps waiting rather than answering a half request.
fn assemble_request(bytes: &[u8]) -> Option<hysteria::H3Request> {
    let mut at = 0usize;
    let mut request: Option<hysteria::H3Request> = None;
    while let Some(frame) = frames::h3_frame(bytes, &mut at) {
        let end = at + frame.length as usize;
        let payload = bytes.get(at..end)?;
        match frame.kind {
            frames::H3_HEADERS if request.is_none() => {
                request = hysteria::parse_h3_request(payload);
            }
            frames::H3_DATA => {
                if let Some(request) = request.as_mut() {
                    request.body.extend_from_slice(payload);
                }
            }
            _ => {}
        }
        at = end;
    }
    request
}

/// Builds the HTTP/3 cover response for one request, dispatching on the configured masquerade type: a not-found, a canned line, a static file, or a reverse-proxied origin. The caller finishes the stream with these bytes.
fn masq_bytes(
    masq: &Masquerade,
    request: &hysteria::H3Request,
    peer: Option<&str>,
    out: &mut Vec<u8>,
) {
    match masq {
        Masquerade::NotFound => not_found(out),
        Masquerade::Response {
            status,
            headers,
            body,
        } => {
            let fields: Vec<(&str, &str)> = headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect();
            hysteria::encode_h3_response(*status, &fields, body, out);
        }
        Masquerade::File { dir } => serve_file(dir, request, out),
        Masquerade::Proxy {
            url,
            rewrite_host,
            x_forwarded,
            insecure,
        } => serve_proxy(
            url,
            *rewrite_host,
            *x_forwarded,
            *insecure,
            request,
            peer,
            out,
        ),
    }
}

/// The plain not-found line the reference cover answers with, reused as the miss for a static file and the default type.
fn not_found(out: &mut Vec<u8>) {
    hysteria::encode_h3_response(
        404,
        &[("content-type", "text/plain; charset=utf-8")],
        b"404 page not found\n",
        out,
    );
}

/// Serves one static file under `dir` to a browser request, refusing any path that steps out of the root. A directory yields its `index.html`, else a minimal listing; an escaping, missing, or unreadable path yields the not-found.
fn serve_file(dir: &str, request: &hysteria::H3Request, out: &mut Vec<u8>) {
    let Some(path) = safe_path(dir, &request.path) else {
        return not_found(out);
    };
    if path.is_dir() {
        let index = path.join("index.html");
        if let Ok(bytes) = std::fs::read(&index) {
            let kind = hysteria::content_type(&index.to_string_lossy());
            return hysteria::encode_h3_response(200, &[("content-type", kind)], &bytes, out);
        }
        let listing = directory_listing(&path);
        return hysteria::encode_h3_response(
            200,
            &[("content-type", "text/html; charset=utf-8")],
            listing.as_bytes(),
            out,
        );
    }
    let kind = hysteria::content_type(&path.to_string_lossy());
    match std::fs::read(&path) {
        Ok(bytes) => hysteria::encode_h3_response(200, &[("content-type", kind)], &bytes, out),
        Err(_) => not_found(out),
    }
}

/// Resolves a browser `:path` to a file under `root`, percent-decoding it and rejecting any `..` step, so the served path never climbs above the masquerade directory. A leading slash names the directory's own root, not the filesystem's.
fn safe_path(root: &str, path: &str) -> Option<std::path::PathBuf> {
    let trimmed = path.split(['?', '#']).next().unwrap_or(path);
    let decoded = percent_decode(trimmed)?;
    let mut joined = std::path::PathBuf::from(root);
    for segment in decoded.split('/') {
        match segment {
            "" | "." => {}
            ".." => return None,
            other => {
                if other.contains('\\') || other.contains('\0') {
                    return None;
                }
                joined.push(other);
            }
        }
    }
    Some(joined)
}

/// A minimal HTML directory listing, used only when a masquerade directory has no `index.html`: enough of a page to pass as a static site's index.
fn directory_listing(dir: &std::path::Path) -> String {
    let name = dir.to_string_lossy();
    let mut html = format!("<!doctype html><html><head><title>Index of {name}</title></head><body><h1>Index of {name}</h1><ul>");
    let Ok(entries) = std::fs::read_dir(dir) else {
        html.push_str("</ul></body></html>");
        return html;
    };
    let mut names: Vec<String> = entries
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    for entry in names {
        let esc = html_escape(&entry);
        html.push_str("<li><a href=\"");
        html.push_str(&esc);
        html.push_str("\">");
        html.push_str(&esc);
        html.push_str("</a></li>");
    }
    html.push_str("</ul></body></html>");
    html
}

/// The characters that must not leak raw into a listing's HTML, so a crafted filename cannot inject markup into the cover page.
fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            other => out.push(other),
        }
    }
    out
}

/// Percent-decodes a URL path; a `%` not followed by two hex digits is not valid and rejects the whole path, so a half-decoded traversal never slips through. A path with no escape is already the text it decodes to, so it is lent back rather than copied into a buffer the copy would leave unchanged — the browser's own request line almost never escapes anything.
fn percent_decode(input: &str) -> Option<std::borrow::Cow<'_, str>> {
    if !input.as_bytes().contains(&b'%') {
        return Some(std::borrow::Cow::Borrowed(input));
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hi = hex_val(*bytes.get(i + 1)?)?;
                let lo = hex_val(*bytes.get(i + 2)?)?;
                out.push(hi << 4 | lo);
                i += 3;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok().map(std::borrow::Cow::Owned)
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Forwards a browser request to a masquerade origin over a hand-written HTTP/1.1 exchange and re-emits the reply as HTTP/3, dropping the origin's hop-by-hop headers. One connection per request, closed on the origin's `connection: close`; any failure to reach or parse the origin answers the bad-gateway line.
fn serve_proxy(
    url: &str,
    rewrite_host: bool,
    x_forwarded: bool,
    insecure: bool,
    request: &hysteria::H3Request,
    peer: Option<&str>,
    out: &mut Vec<u8>,
) {
    match fetch_origin(url, request, rewrite_host, x_forwarded, insecure, peer) {
        Some(origin) => {
            let fields: Vec<(&str, &str)> = origin
                .headers
                .iter()
                .filter(|(name, _)| !is_hop_by_hop(name))
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect();
            hysteria::encode_h3_response(origin.status, &fields, &origin.body, out);
        }
        None => hysteria::encode_h3_response(
            502,
            &[("content-type", "text/plain; charset=utf-8")],
            b"502 Bad Gateway\n",
            out,
        ),
    }
}

/// Dials the origin `url` names and runs one HTTP/1.1 exchange: `unix` connects a socket at the path, `http` resolves host and port, and `https` wraps that TCP dial in the client TLS the relay already speaks — verifying against the platform roots, or accepting the chain as presented when the cover names `insecure`. Any scheme this build cannot reach answers bad-gateway rather than a silent downgrade.
fn fetch_origin(
    url: &str,
    request: &hysteria::H3Request,
    rewrite_host: bool,
    x_forwarded: bool,
    insecure: bool,
    peer: Option<&str>,
) -> Option<hysteria::OriginResponse> {
    let (scheme, rest) = url.split_once("://")?;
    let head = origin_request(request, rest, rewrite_host, x_forwarded, peer);
    match scheme {
        "unix" | "http" => exchange_plain(scheme, rest, &head),
        "https" => exchange_tls(rest, &head, insecure),
        _ => None,
    }
}

/// The trust a cover origin's TLS dial carries: `insecure` names no roots because the verifier accepts the chain as presented, while a verified dial reaches the platform anchors the rest of the build trusts. The server name is the authority host, so SNI and the name check share one view of it.
fn origin_tls_config(host: &str, insecure: bool) -> ferrox_core::tls::TlsConfig {
    ferrox_core::tls::TlsConfig {
        server_name: host.to_owned(),
        roots: if insecure {
            ferrox_core::tls::Anchors::default()
        } else {
            crate::quic::system_roots()
        },
        insecure,
        resumption: true,
        ..Default::default()
    }
}

/// Where an origin scheme dials, and the host an `https` cover carries as SNI: the authority's port defaults to the scheme's own, and one split feeds both the dial and the name check, so they cannot disagree about which host was reached. A scheme this build cannot dial, and an authority whose port is not a port, yield `None` — bad-gateway, never a silent downgrade.
fn origin_dial<'a>(scheme: &str, rest: &'a str) -> Option<(crate::conn::Target, &'a str)> {
    let host = rest.split('/').next().unwrap_or(rest);
    if scheme == "unix" {
        let target = crate::conn::parse_target(&format!("unix:{rest}")).ok()?;
        return Some((target, host));
    }
    let port = match scheme {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let (host_only, port) = match host.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().ok()?),
        None => (host, port),
    };
    let target = crate::conn::parse_target(&format!("{host_only}:{port}")).ok()?;
    Some((target, host_only))
}

/// The seam's dial for an origin target, every leg of the exchange inside the budget: the connect gets the bound the reads already had, so an origin a firewall pins answers bad-gateway in five seconds instead of parking the stream handler for the kernel's own retransmission — and the request write gets one, so an origin that accepts but never reads cannot hold the cover open either.
fn dial_origin(target: &crate::conn::Target) -> Option<Connection> {
    let stream = crate::conn::connect(target, ORIGIN_TIMEOUT).ok()?;
    let _ = stream.set_read_timeout(Some(ORIGIN_TIMEOUT));
    let _ = stream.set_write_timeout(Some(ORIGIN_TIMEOUT));
    Some(stream)
}

/// Runs one closed exchange over plain TCP, or over the socket an origin path names, since the seam dials either family the same bounded way.
fn exchange_plain(scheme: &str, rest: &str, head: &[u8]) -> Option<hysteria::OriginResponse> {
    let (target, _) = origin_dial(scheme, rest)?;
    let mut stream = dial_origin(&target)?;
    stream.write_all(head).ok()?;
    stream.flush().ok()?;
    read_origin(&mut stream)
}

/// Runs one closed exchange over the client TLS session the relay already speaks: the same authority split and default port as the plain dial, then the request written and the reply read through the encrypted stream, so a cover that dials a real site carries its bytes no further than any other origin answer.
fn exchange_tls(rest: &str, head: &[u8], insecure: bool) -> Option<hysteria::OriginResponse> {
    let (target, host) = origin_dial("https", rest)?;
    let stream = dial_origin(&target)?;
    let mut tls = ferrox_core::tls::connect(&origin_tls_config(host, insecure), stream).ok()?;
    tls.write_all(head).ok()?;
    tls.flush().ok()?;
    read_origin(&mut tls)
}

/// Rebuilds the browser request as an HTTP/1.1 exchange line: the method and path, a `Host` from the origin or the request's own authority, the request's ordinary headers minus the hop-by-hop ones, and the forwarded headers when asked. The body follows its copied `content-length`.
fn origin_request(
    request: &hysteria::H3Request,
    authority: &str,
    rewrite_host: bool,
    x_forwarded: bool,
    peer: Option<&str>,
) -> Vec<u8> {
    let host = if rewrite_host || request.authority.is_empty() {
        authority
    } else {
        &request.authority
    };
    let target = if request.path.is_empty() {
        "/"
    } else {
        request.path.as_str()
    };
    let method = if request.method.is_empty() {
        "GET"
    } else {
        request.method.as_str()
    };
    let mut head = Vec::with_capacity(256 + request.body.len());
    let _ = write!(&mut head, "{method} {target} HTTP/1.1\r\n");
    let _ = write!(&mut head, "Host: {host}\r\n");
    for (name, value) in &request.headers {
        if is_hop_by_hop(name) {
            continue;
        }
        let _ = write!(&mut head, "{name}: {value}\r\n");
    }
    if x_forwarded {
        if let Some(for_ip) = peer {
            let _ = write!(&mut head, "X-Forwarded-For: {for_ip}\r\n");
        }
        let _ = write!(&mut head, "X-Forwarded-Proto: https\r\n");
    }
    let _ = write!(&mut head, "Connection: close\r\n");
    head.extend_from_slice(b"\r\n");
    head.extend_from_slice(&request.body);
    head
}

/// A header that belongs to one hop only and must not be copied onto an origin request or back to the browser.
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Reads an origin's whole HTTP/1.1 reply to its close, then reduces it to status, headers, and body; the buffered bytes stop at the cover's cap so a runaway origin never exhausts memory.
fn read_origin<R: Read>(stream: &mut R) -> Option<hysteria::OriginResponse> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8 * 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if raw.len() >= MASQ_BODY_CAP {
                    break;
                }
            }
        }
    }
    hysteria::parse_origin_response(&raw)
}

/// Bring one datagram association up: resolve the address the client named, connect a target socket of the matching family, and hand a reader thread the same socket so its replies return over the lane. `None` when the address is unresolvable or no socket can be raised, and the datagram is then dropped.
fn open_udp(
    shared: &Arc<Mutex<quiche::Connection>>,
    sock: &Arc<crate::quic::Datagram>,
    session: u32,
    address: &str,
) -> Option<UdpFlow> {
    let peer = address
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())?;
    let bind = if peer.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let target = UdpSocket::bind(bind).ok()?;
    target.connect(peer).ok()?;
    target.set_read_timeout(Some(UDP_POLL)).ok()?;
    let target = Arc::new(target);
    let stop = Arc::new(AtomicBool::new(false));
    std::thread::spawn({
        let shared = Arc::clone(shared);
        let sock = Arc::clone(sock);
        let target = Arc::clone(&target);
        let stop = Arc::clone(&stop);
        let address = address.to_owned();
        move || udp_reader(&shared, &sock, &target, &stop, session, &address)
    });
    Some(UdpFlow {
        target,
        defrag: Defrag::new(),
        last: Instant::now(),
        stop,
    })
}

/// Read the target socket and put every reply back on the lane, fragmenting to the peer's writable datagram size so a large response still arrives: one packet id per reply, its fragments sharing it, exactly as the client sends to us. A read that only timed out checks whether the reap or the closed connection told it to stop, so the thread lives no longer than one poll past its association.
fn udp_reader(
    shared: &Arc<Mutex<quiche::Connection>>,
    sock: &Arc<crate::quic::Datagram>,
    target: &Arc<UdpSocket>,
    stop: &AtomicBool,
    session: u32,
    address: &str,
) {
    // One buffer for a whole target reply and one for the wire, both kept at capacity across the association's life so a steady relay never reallocates; the fragments view `buf`, so they are rebuilt each read rather than carried.
    let mut buf = vec![0u8; UDP_TARGET_BUF];
    let mut wire = Vec::new();
    let mut packet = 0u16;
    loop {
        let n = match target.recv(&mut buf) {
            Ok(n) => n,
            Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                let closed = shared.lock().map_or(true, |conn| conn.is_closed());
                if closed || stop.load(Ordering::Relaxed) {
                    break;
                }
                continue;
            }
            Err(_) => break,
        };
        let Ok(mut conn) = shared.lock() else {
            break;
        };
        if conn.is_closed() {
            break;
        }
        let Some(max) = conn.dgram_max_writable_len() else {
            break;
        };
        packet = packet.wrapping_add(1);
        let message = UdpMessage {
            session,
            packet,
            frag: 0,
            frags: 1,
            address,
            payload: &buf[..n],
        };
        let Ok(fragments) = hysteria::fragments_udp(&message, max) else {
            break;
        };
        for frag in fragments {
            wire.clear();
            hysteria::encode_udp_unchecked(&frag, &mut wire);
            let _ = conn.dgram_send(&wire);
        }
        crate::quic::flush_egress(&mut conn, sock);
    }
}

/// The one datagram flow a client association currently relays: the session id its datagrams carry (never reused on the connection, so a late server packet cannot misroute to a new flow) and the destination the socks front asked for, which is what a reply is re-wrapped with.
struct Association {
    session_id: u32,
    destination: SocketAddr,
}

/// What the writer and the reader of one client association share: the flow now relayed, the reassembly its fragments feed, and the client address the relay last sent from. Only the writer rotates a flow, and only after the connection lock is held, so the reader never relays against a half-applied change and a retired flow's late datagrams land on the floor rather than on the new association.
struct Lane {
    flow: Mutex<Option<Association>>,
    defrag: Mutex<Defrag>,
    source: Mutex<Option<SocketAddr>>,
}

/// The client's UDP uplink over the hysteria carrier: read the relay socket, put every datagram on the connection's datagram lane, and let a companion thread drive the connection and carry replies back. One destination at a time — a change rotates the association, stamping a fresh session id that the connection has never used, over a connection of its own: the pool is a TCP instrument, its staleness caught by a flow's reply deadline a datagram send has no answer to, so a lane dials fresh and is live from the first packet. The relay's read timeout, `budgets::udp_idle()`, is already armed where the front was raised, so silence ends the loop and retires the association with its reader; a server that refused the lane in auth is answered in silence, as the references do. Salamander obfuscation, when the outbound names it, is already wrapped at the `quic::Datagram` seam by `connect`, so no byte of this path changes when the password is set.
pub(crate) fn serve_udp(relay: &UdpSocket, dial: &Dial) {
    let Some(session) = connect(dial) else {
        return;
    };
    if !session.udp_supported {
        return;
    }
    // The reader answers through its own handle on the same relay socket; a clone that fails means the front is already gone.
    let Ok(reply) = relay.try_clone() else {
        return;
    };
    let lane = Arc::new(Lane {
        flow: Mutex::new(None),
        defrag: Mutex::new(Defrag::new()),
        source: Mutex::new(None),
    });
    let stop = Arc::new(AtomicBool::new(false));
    let reader = std::thread::spawn({
        let session = session.clone();
        let lane = Arc::clone(&lane);
        let stop = Arc::clone(&stop);
        move || client_reader(&session, &lane, &stop, &reply)
    });
    let mut buf = vec![0u8; UDP_TARGET_BUF];
    // One wire buffer and one packet buffer, kept at capacity across the association's life so a steady relay never reallocates. The fragment list is born in the loop because its messages borrow the message's own bytes.
    let mut wire = Vec::with_capacity(UDP_TARGET_BUF + 64);
    let mut packet = 0u16;
    // Ids the lane stamps, taken in order and never reused on this connection, so a late reply to a retired flow cannot land on a new one.
    let mut next_id = 1u32;
    // The flow now relayed, cached off the rotation: the id it stamps, the destination compared per packet, and the string the wire's address field borrows — so no steady packet re-formats the address or takes the flow lock.
    let mut relayed: Option<(u32, SocketAddr, String)> = None;
    while let Ok((n, src)) = relay.recv_from(&mut buf) {
        let Some((dest, payload)) = crate::proxy::parse_socks_udp(&buf[..n]) else {
            continue;
        };
        if payload.is_empty() {
            continue;
        }
        let Ok(mut conn) = session.shared.lock() else {
            break;
        };
        if conn.is_closed() {
            break;
        }
        // A connection that takes no datagrams cannot carry the lane.
        let Some(max) = conn.dgram_max_writable_len() else {
            break;
        };
        if let Ok(mut slot) = lane.source.lock() {
            *slot = Some(src);
        }
        if relayed.as_ref().is_none_or(|(_, held, _)| *held != dest) {
            let id = next_id;
            next_id += 1;
            let address = dest.to_string();
            if let Ok(mut slot) = lane.flow.lock() {
                *slot = Some(Association {
                    session_id: id,
                    destination: dest,
                });
            }
            if let Ok(mut reassembly) = lane.defrag.lock() {
                *reassembly = Defrag::new();
            }
            relayed = Some((id, dest, address));
        }
        let Some((session_id, _, address)) = &relayed else {
            continue;
        };
        let session_id = *session_id;
        packet = packet.wrapping_add(1);
        let message = UdpMessage {
            session: session_id,
            packet,
            frag: 0,
            frags: 1,
            address,
            payload,
        };
        let Ok(fragments) = hysteria::fragments_udp(&message, max) else {
            continue;
        };
        for frag in fragments {
            wire.clear();
            hysteria::encode_udp_unchecked(&frag, &mut wire);
            let _ = conn.dgram_send(&wire);
        }
        crate::quic::flush_egress(&mut conn, &session.sock);
    }
    stop.store(true, Ordering::Relaxed);
    let _ = reader.join();
}

/// Take one queued datagram under the connection lock and release it before the caller relays, so the driver never waits behind a socket send.
fn recv_one<T>(shared: &Mutex<T>, next: impl FnOnce(&mut T) -> Option<Vec<u8>>) -> Option<Vec<u8>> {
    let mut guard = shared.lock().ok()?;
    next(&mut guard)
}

/// Drive the connection and hand every whole datagram of the flow being relayed back to the relay socket, re-wrapped in the socks5 UDP frame the client sent its first packet in. The drive stays `drive_once`'s, shared with the TCP pump, so writer and reader take the connection lock in the same one-turn shape and neither holds it across a socket wait; the `UDP_POLL` bound is how long a stop flag outlives the reader, since a UDP socket has no shutdown to wake a blocked read.
fn client_reader(session: &Session, lane: &Lane, stop: &AtomicBool, relay: &UdpSocket) {
    let mut reply_head = Vec::with_capacity(22);
    loop {
        if stop.load(Ordering::Relaxed) || !drive_once(session, UDP_POLL) {
            break;
        }
        while let Some(data) = recv_one(session.shared.as_ref(), |conn| conn.dgram_recv_buf().ok())
        {
            let Ok(message) = hysteria::decode_udp(&data) else {
                continue;
            };
            let Ok(held) = lane.flow.lock() else {
                break;
            };
            let Some(association) = held.as_ref() else {
                continue;
            };
            if message.session != association.session_id {
                continue;
            }
            let destination = association.destination;
            drop(held);
            let mut assembled = Vec::new();
            let Some(payload) = lane.defrag.lock().ok().and_then(|mut reassembly| {
                reassembly
                    .feed(&message, &mut assembled)
                    .ok()
                    .flatten()
                    .map(|(_address, payload)| payload)
            }) else {
                continue;
            };
            let Some(src) = lane.source.lock().ok().and_then(|slot| *slot) else {
                continue;
            };
            let (front, tail) =
                crate::proxy::socks_udp_parts(&mut reply_head, &destination, payload);
            let _ = crate::proxy::send_to_two(relay, front, tail, src);
        }
    }
}

/// Fold every datagram that arrived on this connection into its session's reassembly and relay the whole messages to their target sockets, raising an association on a session's first datagram. A datagram before auth is not for the lane yet, and a reassembly that rejects a forged fragment retires its session.
fn relay_datagrams(
    inbound: &mut Inbound,
    sock: &Arc<crate::quic::Datagram>,
    shared: &Arc<Mutex<quiche::Connection>>,
    conn: &mut quiche::Connection,
) {
    if !inbound.authed {
        return;
    }
    while let Ok(data) = conn.dgram_recv_buf() {
        let Ok(message) = hysteria::decode_udp(&data) else {
            continue;
        };
        let session = message.session;
        let flow = match inbound.udp.entry(session) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(vacant) => {
                let Some(opened) = open_udp(shared, sock, session, message.address) else {
                    continue;
                };
                vacant.insert(opened)
            }
        };
        let mut assembled = Vec::new();
        let whole = flow.defrag.feed(&message, &mut assembled);
        flow.last = Instant::now();
        let forged = whole.is_err();
        match whole {
            Ok(Some((_address, payload))) => {
                let _ = flow.target.send(payload);
            }
            Ok(None) => {}
            Err(_) => flow.stop.store(true, Ordering::Relaxed),
        }
        if forged {
            inbound.udp.remove(&session);
        }
    }
}

struct Router<'a> {
    sock: Arc<crate::quic::Datagram>,
    local: SocketAddr,
    auths: &'a [String],
    serve: &'a Serve,
    masq: Arc<Masquerade>,
    realm_state: Option<Arc<crate::hysteria_realm::RealmState>>,
    /// The reference's `udpIdleTimeout`: how long a datagram association may stay quiet.
    udp_idle: Duration,
    /// This server's `brutalDown`, answered as the client's `hysteria-cc-rx` hint.
    cc_rx: u64,
    /// Whether an accepted connection advertises the token a peer resets it with; the reference's default, off only when `disableStatelessReset` names it.
    stateless_reset: bool,
    routes: HashMap<Vec<u8>, Inbound>,
    /// The route each client CID and initial DCID names, so an Initial's retransmit finds its lane in one probe instead of walking every route.
    by_client_cid: HashMap<Vec<u8>, Vec<u8>>,
    by_initial_dcid: HashMap<Vec<u8>, Vec<u8>>,
}

/// A stateless reset token belongs to one connection, so the shared template is minted afresh before each accept; a failed mint refuses the connection rather than sharing one.
fn mint_reset_token(template: &mut quiche::Config, enabled: bool) -> bool {
    if !enabled {
        template.set_stateless_reset_token(None);
        return true;
    }
    let mut token = [0u8; 16];
    if getrandom::fill(&mut token).is_err() {
        return false;
    }
    template.set_stateless_reset_token(Some(u128::from_le_bytes(token)));
    true
}

fn auth_exchange(
    sock: &crate::quic::Datagram,
    conn: &mut quiche::Connection,
    auths: &[String],
    inbound: &mut Inbound,
    peer: SocketAddr,
    masq: &Masquerade,
) -> Option<bool> {
    let mut room = Unfilled::<4096>::new();
    loop {
        match conn.stream_recv(AUTH_STREAM, room.as_mut()) {
            Ok((0, _)) | Err(_) => break,
            Ok((n, _)) => inbound.auth_buf.extend_from_slice(&room.as_mut()[..n]),
        }
    }
    if inbound.auth_buf.len() >= HEAD_CAP {
        return Some(false);
    }
    let mut at = 0usize;
    let body = frames::h3_frame(&inbound.auth_buf, &mut at)
        .filter(|frame| frame.kind == frames::H3_HEADERS)
        .and_then(|frame| inbound.auth_buf.get(at..at + frame.length as usize))?;
    // A request that is not the hysteria handshake shape is a browser: it is answered as the cover site on this very stream — the plain not-found when no richer cover is configured — and the connection is kept for its later requests. A right-shape, wrong-password handshake still falls through below and refuses exactly as a plain hysteria server would.
    if !hysteria::is_hysteria_auth_shape(body) {
        let request = hysteria::parse_h3_request(body).unwrap_or_default();
        inbound.auth_buf.clear();
        inbound.authed = true;
        let peer = peer.to_string();
        let mut reply = Vec::new();
        masq_bytes(masq, &request, Some(&peer), &mut reply);
        if conn.stream_send(AUTH_STREAM, &reply, true).is_err() {
            return None;
        }
        crate::quic::flush_egress(conn, sock);
        return Some(true);
    }
    let ok = auths
        .iter()
        .any(|auth| hysteria::verify_auth_request(body, auth));
    if !answer_auth(conn, ok, inbound.cc_rx) {
        return None;
    }
    crate::quic::flush_egress(conn, sock);
    inbound.auth_buf.clear();
    inbound.authed = true;
    Some(ok)
}

impl Router<'_> {
    fn accept(
        &mut self,
        packet: &mut [u8],
        from: SocketAddr,
        template: &mut quiche::Config,
        client_cid: &[u8],
        initial_dcid: &[u8],
    ) {
        let mut scid = [0u8; SCID_LEN];
        if getrandom::fill(&mut scid).is_err() || !mint_reset_token(template, self.stateless_reset)
        {
            return;
        }
        let cid = quiche::ConnectionId::from_ref(&scid);
        let Ok(mut conn) = quiche::accept(&cid, None, self.local, from, template) else {
            return;
        };
        let info = quiche::RecvInfo {
            from,
            to: self.local,
        };
        if conn.recv(packet, info).is_err() {
            return;
        }
        let mut out = [0u8; crate::quic::MAX_DATAGRAM];
        crate::quic::issue_spare_scids(&mut conn, &self.sock, &mut out);
        crate::quic::flush_egress(&mut conn, &self.sock);
        let key = scid.to_vec();
        let inbound = Inbound {
            conn: Arc::new(Mutex::new(conn)),
            client_cid: client_cid.to_vec(),
            initial_dcid: initial_dcid.to_vec(),
            source_ids: Vec::new(),
            authed: false,
            settings_sent: false,
            settings_done: false,
            auth_buf: Vec::new(),
            wakes: Driver::new(),
            udp: HashMap::new(),
            cc_rx: self.cc_rx,
        };
        if let Some(old) = self.routes.insert(key.clone(), inbound) {
            self.forget(&key, &old);
        }
        if !client_cid.is_empty() {
            self.by_client_cid.insert(client_cid.to_vec(), key.clone());
        }
        if !initial_dcid.is_empty() {
            self.by_initial_dcid
                .insert(initial_dcid.to_vec(), key.clone());
        }
        if let Some(inbound) = self.routes.get_mut(&key) {
            if let Ok(guard) = inbound.conn.lock() {
                let ids: Vec<_> = guard.source_ids().collect();
                for id in ids {
                    let raw = id.as_ref().to_vec();
                    self.by_initial_dcid.insert(raw.clone(), key.clone());
                    inbound.source_ids.push(raw);
                }
            }
        }
    }

    /// Drop the reverse names a replaced route held, so a later Initial cannot be sent to a lane the table no longer carries.
    fn forget(&mut self, key: &[u8], inbound: &Inbound) {
        forget_route(
            &mut self.by_client_cid,
            &mut self.by_initial_dcid,
            key,
            &inbound.client_cid,
            &inbound.initial_dcid,
            &inbound.source_ids,
        );
    }

    /// The lane an Initial names, if one already carries it: its DCID is the key a retransmit arrives under, and a client CID matches the first flight's source id.
    fn initial_route(&self, dcid: &[u8], peer_cid: &[u8]) -> Option<Vec<u8>> {
        let live = |key: &Vec<u8>| self.routes.contains_key(key.as_slice());
        if let Some(key) = self.by_initial_dcid.get(dcid).filter(|key| live(key)) {
            return Some(key.clone());
        }
        if peer_cid.is_empty() {
            return None;
        }
        self.by_client_cid
            .get(peer_cid)
            .filter(|key| live(key))
            .cloned()
    }

    /// Hand one received packet to the route it names, then let every route that took it send once.
    fn drive(&mut self, dcid: &[u8], packet: &mut [u8], from: SocketAddr) {
        let Self {
            routes,
            sock,
            auths,
            serve,
            masq,
            local,
            ..
        } = self;
        let Some(inbound) = routes.get_mut(dcid) else {
            return;
        };
        let shared = Arc::clone(&inbound.conn);
        let info = quiche::RecvInfo { from, to: *local };
        {
            let Ok(mut conn) = shared.lock() else {
                return;
            };
            if conn.recv(packet, info).is_err() {
                return;
            }
            // An established lane's acknowledgements leave with the batch that carried the packet, in `wake`, not one send per datagram.
            if !conn.is_established() || conn.is_closed() {
                crate::quic::flush_egress(&mut conn, sock);
                return;
            }
            if !inbound.settings_done {
                inbound.settings_done = drain_settings(&mut conn);
            }
            // The server's SETTINGS go out before its auth answer: a client whose H3 stack waits for them, as the pinned one does, posts its auth only after they arrive.
            if !inbound.settings_sent {
                let mut settings = Vec::new();
                frames::quic_varint(&mut settings, 0x04);
                frames::quic_varint(&mut settings, 0);
                let _ = conn.stream_send(3, &settings, true);
                crate::quic::flush_egress(&mut conn, sock);
                inbound.settings_sent = true;
            }
            if !inbound.authed {
                let Some(ok) = auth_exchange(sock, &mut conn, auths, inbound, from, masq) else {
                    return;
                };
                if !ok {
                    let _ = conn.close(false, 0, b"refused");
                    crate::quic::flush_egress(&mut conn, sock);
                    return;
                }
            }
            for id in conn.readable() {
                if id < FIRST_FLOW_STREAM || id % 4 != 0 {
                    continue;
                }
                let Some(wake) = inbound.wakes.claim(id) else {
                    continue;
                };
                let thread_shared = Arc::clone(&shared);
                let thread_sock = Arc::clone(sock);
                let thread_serve = Arc::clone(serve);
                let thread_masq = Arc::clone(masq);
                let local = *local;
                let peer = from;
                std::thread::spawn(move || {
                    serve_stream(
                        &thread_shared,
                        &thread_sock,
                        local,
                        id,
                        &thread_serve,
                        peer,
                        &thread_masq,
                        wake,
                    );
                });
            }
            relay_datagrams(inbound, sock, &shared, &mut conn);
        }
    }

    fn wake(&mut self) {
        let Self { routes, sock, .. } = self;
        for inbound in routes.values() {
            let Ok(mut conn) = inbound.conn.lock() else {
                continue;
            };
            for id in conn.readable() {
                if id >= FIRST_FLOW_STREAM && id % 4 == 0 {
                    inbound.wakes.wake(id);
                }
            }
            crate::quic::flush_egress(&mut conn, sock);
        }
    }

    fn idle(&mut self) {
        let Self {
            routes,
            by_client_cid,
            by_initial_dcid,
            sock,
            udp_idle,
            ..
        } = self;
        let now = Instant::now();
        // One pass, one lock per route: the dead are dropped where they are found, the living take their turn of the wheel, and a datagram association idle past the timeout is told to stop so its reader ends within one poll.
        routes.retain(|key, inbound| {
            let Ok(mut conn) = inbound.conn.lock() else {
                return true;
            };
            if conn.is_closed() {
                forget_route(
                    by_client_cid,
                    by_initial_dcid,
                    key,
                    &inbound.client_cid,
                    &inbound.initial_dcid,
                    &inbound.source_ids,
                );
                for flow in inbound.udp.values() {
                    flow.stop.store(true, Ordering::Relaxed);
                }
                inbound.udp.clear();
                return false;
            }
            conn.on_timeout();
            crate::quic::flush_egress(&mut conn, sock);
            inbound.udp.retain(|_, flow| {
                if now.duration_since(flow.last) > *udp_idle {
                    flow.stop.store(true, Ordering::Relaxed);
                    false
                } else {
                    true
                }
            });
            true
        });
    }
}

/// Drop a route's reverse names when they still point at it, so a replaced or reaped lane leaves no stale lookup.
fn forget_route(
    by_client_cid: &mut HashMap<Vec<u8>, Vec<u8>>,
    by_initial_dcid: &mut HashMap<Vec<u8>, Vec<u8>>,
    key: &[u8],
    client_cid: &[u8],
    initial_dcid: &[u8],
    source_ids: &[Vec<u8>],
) {
    if !client_cid.is_empty()
        && by_client_cid
            .get(client_cid)
            .is_some_and(|held| held.as_slice() == key)
    {
        by_client_cid.remove(client_cid);
    }
    if !initial_dcid.is_empty()
        && by_initial_dcid
            .get(initial_dcid)
            .is_some_and(|held| held.as_slice() == key)
    {
        by_initial_dcid.remove(initial_dcid);
    }
    for alias in source_ids {
        if by_initial_dcid
            .get(alias)
            .is_some_and(|held| held.as_slice() == key)
        {
            by_initial_dcid.remove(alias);
        }
    }
}

fn route_packet(
    router: &mut Router<'_>,
    template: &mut quiche::Config,
    packet: &mut [u8],
    from: SocketAddr,
) {
    let Ok(header) = quiche::Header::from_slice(packet, SCID_LEN) else {
        return;
    };
    if header.ty != quiche::Type::Short && header.version != quiche::PROTOCOL_VERSION {
        return;
    }
    let initial = header.ty == quiche::Type::Initial;
    let dcid = header.dcid.as_ref();
    let peer_cid = header.scid.as_ref();
    if dcid.len() > 20 || peer_cid.len() > 20 {
        return;
    }
    let mut dcid_buf = [0u8; 20];
    dcid_buf[..dcid.len()].copy_from_slice(dcid);
    let mut peer_buf = [0u8; 20];
    peer_buf[..peer_cid.len()].copy_from_slice(peer_cid);
    let dcid = &dcid_buf[..dcid.len()];
    let peer_cid = &peer_buf[..peer_cid.len()];
    if initial {
        // A client that sends a zero-length source CID, as the pinned client does, has no peer CID to look up: matching the empty slice against every route sends a new connection's Initial to whichever stale route came first, and the handshake never completes. Its initial DCID is the key a retransmit carries; a new connection's random DCID matches nothing and is accepted.
        let known = router.routes.contains_key(dcid);
        let retransmit = if known {
            None
        } else {
            router.initial_route(dcid, peer_cid)
        };
        if known {
            router.drive(dcid, packet, from);
        } else if let Some(key) = retransmit {
            router.drive(&key, packet, from);
        } else {
            router.accept(packet, from, template, peer_cid, dcid);
        }
    } else if router.routes.contains_key(dcid) {
        router.drive(dcid, packet, from);
    } else if let Some(key) = router.initial_route(dcid, peer_cid) {
        router.drive(&key, packet, from);
    }
}

/// The socket and validated server configuration a served hysteria loop needs, built where a bind
/// failure can still be reported instead of inside the detached thread.
pub(crate) struct Prepared {
    sock: crate::quic::Datagram,
    local: std::net::SocketAddr,
    template: quiche::Config,
}

pub(crate) fn prepare(
    address: &str,
    identity: &ferrox_core::tls::TlsServerConfig,
    cc: hysteria::Congestion,
    obfs_password: &str,
    quic: Option<&hysteria::QuicParams>,
) -> Option<Prepared> {
    let bound = address
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())?;
    let sock = crate::quic::bind_datagram(address).ok()?;
    let local = sock.local_addr().unwrap_or(bound);
    let template = server_config(identity, cc, quic)?;
    let sock = match hysteria::Salamander::new(obfs_password) {
        Some(obfs) => crate::quic::Datagram::obfuscated(sock, obfs),
        None => crate::quic::Datagram::plain(sock),
    };
    Some(Prepared {
        sock,
        local,
        template,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn serve_loop(
    address: &str,
    auths: &[String],
    identity: &ferrox_core::tls::TlsServerConfig,
    cc: hysteria::Congestion,
    obfs_password: &str,
    masq: &Masquerade,
    serve: &Serve,
    udp_idle: Duration,
    quic: Option<&hysteria::QuicParams>,
    realm: Option<&ferrox_core::realm::Config>,
) {
    let Some(prepared) = prepare(address, identity, cc, obfs_password, quic) else {
        return;
    };
    serve_prepared(prepared, auths, masq, serve, udp_idle, quic, realm);
}

pub(crate) fn serve_prepared(
    prepared: Prepared,
    auths: &[String],
    masq: &Masquerade,
    serve: &Serve,
    udp_idle: Duration,
    quic: Option<&hysteria::QuicParams>,
    realm: Option<&ferrox_core::realm::Config>,
) {
    let Prepared {
        sock,
        local,
        mut template,
    } = prepared;
    let sock = Arc::new(sock);
    let realm_state = realm.map(|_| crate::hysteria_realm::RealmState::new());
    if let Some((cfg, state)) = realm.cloned().zip(realm_state.clone()) {
        let stop = Arc::new(AtomicBool::new(false));
        let sock_for_realm = Arc::clone(&sock);
        std::thread::spawn(move || {
            crate::hysteria_realm::serve_registration(sock_for_realm, &cfg, state, stop);
        });
    }
    let mut router = Router {
        sock: Arc::clone(&sock),
        local,
        auths,
        serve,
        masq: Arc::from(masq.clone()),
        realm_state,
        udp_idle,
        cc_rx: quic.map_or(0, |params| params.brutal_down),
        stateless_reset: quic.is_none_or(|params| !params.disable_stateless_reset),
        routes: HashMap::new(),
        by_client_cid: HashMap::new(),
        by_initial_dcid: HashMap::new(),
    };
    let mut buf = Unfilled::<RECV_ROOM>::new();
    if router.sock.set_read_timeout(Some(ROUTE_POLL)).is_err() {
        return;
    }
    #[cfg(target_os = "linux")]
    let mut batch = crate::quic::Batch::new();
    loop {
        #[cfg(target_os = "linux")]
        match crate::quic::recv_batch(&router.sock, &mut batch) {
            crate::quic::Drain::Read => {
                for at in 0..batch.len() {
                    let Some((packet, from)) = batch.at(at) else {
                        continue;
                    };
                    if router.realm_state.as_ref().is_some_and(|state| {
                        crate::hysteria_realm::demux(state, &router.sock, packet, from)
                    }) {
                        continue;
                    }
                    route_packet(&mut router, &mut template, packet, from);
                }
                router.wake();
                continue;
            }
            crate::quic::Drain::Empty => {
                router.idle();
                continue;
            }
            crate::quic::Drain::Unbatchable => {}
            // A socket that coalesces must not be read one segment wide.
            crate::quic::Drain::Unreadable => return,
        }
        match router.sock.recv_from(buf.as_mut()) {
            Ok((n, from)) => {
                if router.realm_state.as_ref().is_some_and(|state| {
                    crate::hysteria_realm::demux(state, &router.sock, &buf.as_mut()[..n], from)
                }) {
                    router.wake();
                    continue;
                }
                route_packet(&mut router, &mut template, &mut buf.as_mut()[..n], from);
                router.wake();
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                router.idle();
            }
            Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::MAX_DATAGRAM;

    /// The buffer form the decode had, kept as the bytes every path has to still reach.
    fn the_buffer_decode(input: &str) -> Option<String> {
        let bytes = input.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0usize;
        while i < bytes.len() {
            match bytes[i] {
                b'%' => {
                    let hi = hex_val(*bytes.get(i + 1)?)?;
                    let lo = hex_val(*bytes.get(i + 2)?)?;
                    out.push(hi << 4 | lo);
                    i += 3;
                }
                other => {
                    out.push(other);
                    i += 1;
                }
            }
        }
        String::from_utf8(out).ok()
    }

    /// The escapes a browser sends, the multi-byte and literal-percent ones, and the half-escapes that reject the whole path.
    const DECODED_PATHS: &[&str] = &[
        "",
        "/",
        "/index.html",
        "/static/css/site.css?v=2",
        "/a%20b/c.txt",
        "/%2E%2E/escape",
        "/%2e%2e%2f",
        "/caf%C3%A9/menu.json",
        "/100%25",
        "/a%2",
        "/a%zz",
        "/%",
        "/%FF",
        "/sp ace/../x",
    ];

    /// Every path decodes to the bytes the buffer form produced and rejects exactly the paths it rejected, so lending a percent-free path back changes no answer.
    #[test]
    fn every_path_decodes_to_the_bytes_the_buffer_form_decoded() {
        for path in DECODED_PATHS {
            assert_eq!(
                percent_decode(path).as_deref(),
                the_buffer_decode(path).as_deref(),
                "path {path:?}"
            );
        }
    }

    /// A path with no escape opens nothing: 4096 static requests are lent the request's own text, and the one buffer is opened only when a `%` can change a byte.
    #[test]
    fn a_path_with_no_escape_is_lent_back_undecoded() {
        let ((), counts) = ferrox_core::alloc_count::measure(|| {
            for _ in 0..4096 {
                std::hint::black_box(percent_decode(std::hint::black_box("/static/css/site.css")));
            }
        });
        assert_eq!(counts.allocs, 0, "no escape, no buffer");
        assert!(
            matches!(
                percent_decode("/static/css/site.css"),
                Some(std::borrow::Cow::Borrowed(_))
            ),
            "the answer is the caller's own text"
        );
        let (_, escaped) = ferrox_core::alloc_count::measure(|| percent_decode("/a%20b"));
        assert_eq!(escaped.allocs, 1, "an escape opens the one buffer it needs");
    }

    /// The whole static answer over a real file adds only the path it builds and the one growth that path takes to the platform's own read, measured in the same process so an allocator that opens more for a file is a floor and not a budget.
    #[test]
    fn a_static_file_answer_opens_only_the_path_and_the_file() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ferrox-static-answer-{}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("stages dir");
        std::fs::write(dir.join("hello.txt"), b"static bytes").expect("stages file");
        let request = hysteria::H3Request {
            method: "GET".to_owned(),
            path: "/hello.txt".to_owned(),
            authority: "cover.test".to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let root = dir.to_str().expect("ascii").to_owned();
        // The floor is the platform's own file work on the path `serve_file` resolves, so the difference is this tree's buffers and nothing the standard library opens.
        let file = dir.join("hello.txt");
        let ((), floor) = ferrox_core::alloc_count::measure(|| {
            let _ = std::hint::black_box(&file).is_dir();
            std::hint::black_box(std::fs::read(std::hint::black_box(&file)).expect("reads"));
        });
        let mut out = Vec::with_capacity(256);
        serve_file(&root, &request, &mut out);
        assert!(
            out.windows(12).any(|window| window == b"static bytes"),
            "the file's bytes are in the answer"
        );
        let ((), counts) = ferrox_core::alloc_count::measure(|| {
            out.clear();
            serve_file(std::hint::black_box(&root), &request, &mut out);
        });
        assert_eq!(
            counts.allocs,
            floor.allocs + 2,
            "the path buffer and its one growth are all the answer adds to the platform's own read"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The client's UDP reply leaves the head and the arrived payload as two parts, so the payload
    /// is handed to the socket where it landed rather than gathered into a reply buffer.
    #[test]
    fn a_client_reply_hands_the_payload_over_by_pointer() {
        let destination: SocketAddr = "198.51.100.7:5353".parse().expect("addr");
        let payload: Vec<u8> = (0..512).map(|i| (i as u8) ^ 0x0f).collect();
        let mut head = Vec::with_capacity(22);
        let (front, tail) = crate::proxy::socks_udp_parts(&mut head, &destination, &payload);
        assert_eq!(
            tail.as_ptr(),
            payload.as_ptr(),
            "the payload must be the sendmsg part itself, not a copy of it"
        );
        assert_eq!(tail.len(), payload.len());
        assert_eq!(
            front,
            &[0u8, 0, 0, 1, 198, 51, 100, 7, 0x14, 0xe9][..],
            "the head is the reserved pair, the ipv4 family, its body and a port"
        );
        let ((), counts) = ferrox_core::alloc_count::measure(|| {
            for _ in 0..4096 {
                let (front, tail) =
                    crate::proxy::socks_udp_parts(&mut head, &destination, &payload);
                std::hint::black_box((front.as_ptr(), tail.as_ptr()));
            }
        });
        assert_eq!(counts.allocs, 0, "the head is reused, the payload is lent");
    }

    #[test]
    fn server_config_refuses_without_a_chain_it_can_read() {
        let cc = hysteria::Congestion::Bbr;
        let empty = ferrox_core::tls::TlsServerConfig {
            certs: Vec::new(),
            ..minted_identity()
        };
        assert!(server_config(&empty, cc, None).is_none());
        let mut double = minted_identity();
        double.certs[0].key_der = vec![0u8; 16];
        assert!(server_config(&double, cc, None).is_none());
    }

    #[test]
    fn a_served_lane_starts_with_a_window_wider_than_ten_packets() {
        let identity = minted_identity();
        let roots = identity.certs[0].cert_chain.clone();
        let client_addr = "127.0.0.1:50000".parse().expect("addr");
        let server_addr = "127.0.0.1:443".parse().expect("addr");
        let client_cid = [1u8; SCID_LEN];
        let server_cid = [2u8; SCID_LEN];
        let mut client_config =
            crate::quic::quiche_config(&roots, Some("reno")).expect("trusts the lane");
        let mut server_config =
            server_config(&identity, hysteria::Congestion::Reno, None).expect("serves");
        let mut client = quiche::connect(
            None,
            &quiche::ConnectionId::from_ref(&client_cid),
            client_addr,
            server_addr,
            &mut client_config,
        )
        .expect("connects");
        let mut server = quiche::accept(
            &quiche::ConnectionId::from_ref(&server_cid),
            None,
            server_addr,
            client_addr,
            &mut server_config,
        )
        .expect("accepts");
        let mut up = Unfilled::<MAX_DATAGRAM>::new();
        let mut down = Unfilled::<MAX_DATAGRAM>::new();
        for _ in 0..8 {
            while let Ok((n, _)) = client.send(up.as_mut()) {
                server
                    .recv(
                        &mut up.as_mut()[..n],
                        quiche::RecvInfo {
                            from: client_addr,
                            to: server_addr,
                        },
                    )
                    .expect("drives the server");
            }
            while let Ok((n, _)) = server.send(down.as_mut()) {
                client
                    .recv(
                        &mut down.as_mut()[..n],
                        quiche::RecvInfo {
                            from: server_addr,
                            to: client_addr,
                        },
                    )
                    .expect("drives the client");
            }
            if client.is_established() && server.is_established() {
                break;
            }
        }
        assert!(server.is_established(), "the lane handshook");
        let payload = vec![0u8; 1 << 20];
        let mut off = 0;
        while off < payload.len() {
            match server.stream_send(1, &payload[off..], true) {
                Ok(n) => off += n,
                Err(quiche::Error::Done) => break,
                Err(e) => panic!("stream_send: {e:?}"),
            }
        }
        let mut sent = 0usize;
        while let Ok((n, _)) = server.send(down.as_mut()) {
            sent += n;
        }
        assert!(
            sent > 100_000,
            "the first flight is {sent} bytes; a ten-packet window stops near 12 KiB"
        );
    }

    #[test]
    fn a_stateless_reset_token_is_minted_afresh_per_accept() {
        let config = hysteria::Config {
            quic: Some(hysteria::QuicParams::default()),
            ..hysteria::Config::default()
        };
        let mut server = server_template(&config);
        let first = peer_params_with(&mut server, true);
        let second = peer_params_with(&mut server, true);
        assert!(
            first.stateless_reset_token.is_some(),
            "an enabled reset sends a token"
        );
        assert_ne!(
            first.stateless_reset_token, second.stateless_reset_token,
            "two connections never share one token"
        );
    }

    #[test]
    fn a_disabled_stateless_reset_sends_no_token() {
        let config = hysteria::Config::default();
        let mut server = server_template(&config);
        let params = peer_params_with(&mut server, false);
        assert!(
            params.stateless_reset_token.is_none(),
            "a disabled reset advertises nothing"
        );
    }

    fn minted_identity() -> ferrox_core::tls::TlsServerConfig {
        let minted = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("mints a certificate");
        ferrox_core::tls::TlsServerConfig {
            certs: vec![ferrox_core::tls::CertEntry {
                cert_chain: crate::quic::parse_ca_pem(minted.cert.pem().as_bytes()),
                key_der: minted.signing_key.serialize_der(),
                key_kind: ferrox_core::tls::ServerKeyKind::Pkcs8,
                reload: None,
                ocsp: None,
            }],
            alpn: Vec::new(),
            min_version: None,
            max_version: None,
            cipher_suites: Vec::new(),
            send_tickets: true,
            reject_unknown_sni: false,
            server_config_cache: std::sync::Arc::default(),
            ech_server_keys: None,
            master_key_log: None,
        }
    }

    /// A server template over a freshly minted certificate.
    fn server_template(config: &hysteria::Config) -> quiche::Config {
        server_config(&minted_identity(), config.cc, config.quic.as_ref()).expect("a server config")
    }

    /// One accept off the shared template, then a client handshake to read what it sent.
    fn peer_params_with(server: &mut quiche::Config, reset: bool) -> quiche::TransportParams {
        assert!(mint_reset_token(server, reset));
        let mut client_config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("configures");
        client_config.verify_peer(false);
        client_config
            .set_application_protos(&[crate::quic::ALPN])
            .expect("negotiates");
        let client_addr = "127.0.0.1:50000".parse().expect("addr");
        let server_addr = "127.0.0.1:443".parse().expect("addr");
        let client_cid = [1u8; SCID_LEN];
        let server_cid = [2u8; SCID_LEN];
        let mut client = quiche::connect(
            None,
            &quiche::ConnectionId::from_ref(&client_cid),
            client_addr,
            server_addr,
            &mut client_config,
        )
        .expect("connects");
        let mut server = quiche::accept(
            &quiche::ConnectionId::from_ref(&server_cid),
            None,
            server_addr,
            client_addr,
            server,
        )
        .expect("accepts");
        let mut up = Unfilled::<MAX_DATAGRAM>::new();
        let mut down = Unfilled::<MAX_DATAGRAM>::new();
        for _ in 0..4 {
            while let Ok((n, _)) = client.send(up.as_mut()) {
                server
                    .recv(
                        &mut up.as_mut()[..n],
                        quiche::RecvInfo {
                            from: client_addr,
                            to: server_addr,
                        },
                    )
                    .expect("drives the server");
            }
            while let Ok((n, _)) = server.send(down.as_mut()) {
                client
                    .recv(
                        &mut down.as_mut()[..n],
                        quiche::RecvInfo {
                            from: server_addr,
                            to: client_addr,
                        },
                    )
                    .expect("drives the client");
            }
            if client.is_established() {
                break;
            }
        }
        client
            .peer_transport_params()
            .cloned()
            .expect("the server's shape arrived")
    }

    #[test]
    fn a_hop_plan_is_its_own_pool_key() {
        // The same address dialed with and without a hop plan is two connections: a hopped flow moves its server port and a plain one does not, so neither may ride the other's pooled socket.
        let dial = |hop: Option<hysteria::Hop>| Dial {
            host: "localhost".to_owned(),
            address: "127.0.0.1".to_owned(),
            port: 443,
            config: hysteria::Config {
                version: 2,
                auth: "a".to_owned(),
                cc: hysteria::Congestion::Bbr,
                obfs_password: String::new(),
                hop,
                gecko: None,
                ..hysteria::Config::default()
            },
            roots: None,
        };
        let plan = hysteria::Hop {
            ranges: vec![hysteria::PortRange {
                start: 443,
                end: 444,
            }],
            interval_ms: (5_000, 5_000),
        };
        assert_eq!(
            server_of(&dial(None)),
            server_of(&dial(None)),
            "plain reuses plain"
        );
        assert_eq!(
            server_of(&dial(Some(plan.clone()))),
            server_of(&dial(Some(plan.clone()))),
            "a plan reuses itself"
        );
        assert_ne!(
            server_of(&dial(None)),
            server_of(&dial(Some(plan))),
            "a hop never rides a plain connection"
        );
    }

    #[test]
    fn a_quic_tuned_plan_is_its_own_pool_key() {
        // A tuned lane negotiated its windows and idle bound on its handshake, so a plain dial may not ride it, nor it a plain one.
        let dial = |quic: Option<hysteria::QuicParams>| Dial {
            host: "localhost".to_owned(),
            address: "127.0.0.1".to_owned(),
            port: 443,
            config: hysteria::Config {
                version: 2,
                auth: "a".to_owned(),
                cc: hysteria::Congestion::Bbr,
                obfs_password: String::new(),
                quic,
                ..hysteria::Config::default()
            },
            roots: None,
        };
        let tuned = hysteria::QuicParams {
            max_idle: 10,
            ..hysteria::QuicParams::default()
        };
        assert_eq!(
            server_of(&dial(None)),
            server_of(&dial(None)),
            "plain reuses plain"
        );
        assert_eq!(
            server_of(&dial(Some(tuned))),
            server_of(&dial(Some(tuned))),
            "a tuned lane reuses itself"
        );
        assert_ne!(
            server_of(&dial(None)),
            server_of(&dial(Some(tuned))),
            "a tuned lane never rides a plain connection"
        );
    }

    #[test]
    fn a_datagram_association_reaps_on_the_configured_idle() {
        // The reaper's bound is the stream's `udpIdleTimeout`, not the fixed default: a six-second-old association dies at five seconds and lives at sixty.
        let reaps = |udp_idle: Duration| {
            let auths: Vec<String> = Vec::new();
            let handler: Serve = Arc::new(|_| {});
            let session = idle_session();
            let stop = Arc::new(AtomicBool::new(false));
            let target = std::net::UdpSocket::bind("127.0.0.1:0").expect("binds");
            let mut udp = HashMap::new();
            udp.insert(
                1,
                UdpFlow {
                    target: Arc::new(target),
                    defrag: Defrag::new(),
                    last: Instant::now()
                        .checked_sub(Duration::from_secs(6))
                        .expect("six seconds ago"),
                    stop: Arc::clone(&stop),
                },
            );
            let mut by_scid = HashMap::new();
            by_scid.insert(
                vec![1u8; SCID_LEN],
                Inbound {
                    conn: Arc::clone(&session.shared),
                    client_cid: vec![2u8; 8],
                    initial_dcid: vec![3u8; 8],
                    source_ids: Vec::new(),
                    authed: true,
                    settings_sent: true,
                    settings_done: true,
                    auth_buf: Vec::new(),
                    wakes: Driver::new(),
                    udp,
                    cc_rx: 0,
                },
            );
            let mut router = Router {
                sock: Arc::clone(&session.sock),
                local: session.local,
                auths: &auths,
                serve: &handler,
                masq: Arc::new(Masquerade::NotFound),
                realm_state: None,
                udp_idle,
                cc_rx: 0,
                stateless_reset: false,
                routes: by_scid,
                by_client_cid: HashMap::new(),
                by_initial_dcid: HashMap::new(),
            };
            router.idle();
            stop.load(Ordering::Relaxed)
        };
        assert!(
            reaps(Duration::from_secs(5)),
            "five seconds reaps a six-second-old association"
        );
        assert!(!reaps(Duration::from_secs(60)), "sixty seconds keeps it");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn a_retransmitted_initial_reuses_its_lane_without_a_second_route() {
        // A retransmit names the first flight's DCID and source CID; route_packet must drive it on the lane accept already made rather than add a second route. The client's next flight is the observable that `drive` reaches that lane.
        let server_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("binds");
        let local = server_sock.local_addr().expect("addr");
        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("binds");
        client_sock.connect(local).expect("connects");
        client_sock
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("arms");
        let client_addr = client_sock.local_addr().expect("addr");
        let auths: Vec<String> = Vec::new();
        let handler: Serve = Arc::new(|_| {});
        let mut router = Router {
            sock: Arc::new(crate::quic::Datagram::plain(server_sock)),
            local,
            auths: &auths,
            serve: &handler,
            masq: Arc::new(Masquerade::NotFound),
            realm_state: None,
            udp_idle: Duration::from_secs(60),
            cc_rx: 0,
            stateless_reset: false,
            routes: HashMap::new(),
            by_client_cid: HashMap::new(),
            by_initial_dcid: HashMap::new(),
        };
        let mut template = server_template(&hysteria::Config::default());
        let mut client_config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("configures");
        client_config.verify_peer(false);
        client_config
            .set_application_protos(&[crate::quic::ALPN])
            .expect("negotiates");
        let client_cid = [0x42u8; SCID_LEN];
        let mut client = quiche::connect(
            None,
            &quiche::ConnectionId::from_ref(&client_cid),
            client_addr,
            local,
            &mut client_config,
        )
        .expect("connects");
        let mut room = Unfilled::<MAX_DATAGRAM>::new();
        let (n, _) = client.send(room.as_mut()).expect("an Initial");
        let initial = room.as_mut()[..n].to_vec();
        let mut head = initial.clone();
        let header = quiche::Header::from_slice(&mut head, SCID_LEN).expect("an Initial header");
        let initial_dcid = header.dcid.as_ref().to_vec();
        let peer_cid = header.scid.as_ref().to_vec();
        let mut wire = initial.clone();
        route_packet(&mut router, &mut template, &mut wire, client_addr);
        assert_eq!(router.routes.len(), 1, "the first Initial makes one route");
        let key = router.routes.keys().next().expect("a route").clone();
        assert_eq!(
            router.by_initial_dcid.get(initial_dcid.as_slice()),
            Some(&key)
        );
        assert_eq!(router.by_client_cid.get(peer_cid.as_slice()), Some(&key));
        assert_eq!(
            router.initial_route(&[0x99u8; 8], &peer_cid),
            Some(key.clone()),
            "a source CID alone names its lane"
        );
        let received = |router: &Router<'_>| {
            router
                .routes
                .get(key.as_slice())
                .expect("the route")
                .conn
                .lock()
                .expect("locks")
                .stats()
                .recv
        };
        let mut down = [0u8; 2048];
        loop {
            match client_sock.recv_from(&mut down) {
                Ok((n, from)) => {
                    client
                        .recv(
                            &mut down[..n],
                            quiche::RecvInfo {
                                from,
                                to: client_addr,
                            },
                        )
                        .expect("the client reads the server");
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(error) => panic!("the server's answer: {error}"),
            }
        }
        let (n, _) = client
            .send(room.as_mut())
            .expect("the client's next flight");
        let next = room.as_mut()[..n].to_vec();
        let before = received(&router);
        let mut wire = next;
        route_packet(&mut router, &mut template, &mut wire, client_addr);
        assert!(
            received(&router) > before,
            "the next flight reached the existing connection"
        );
        assert_eq!(router.routes.len(), 1, "the next flight adds no route");
        // The replayed Initial is a duplicate quiche drops before its counters, so it is checked for the route table alone.
        let mut wire = initial;
        route_packet(&mut router, &mut template, &mut wire, client_addr);
        assert_eq!(router.routes.len(), 1, "a retransmit adds no route");
        assert!(!router.by_initial_dcid.is_empty());
        assert_eq!(router.by_client_cid.len(), 1);
    }

    #[test]
    fn an_idle_reap_drops_a_closed_routes_reverse_names() {
        let session = idle_session();
        {
            let mut conn = session.shared.lock().expect("locks");
            let _ = conn.close(false, 0, b"done");
        }
        let client = vec![2u8; 8];
        let initial = vec![3u8; 8];
        let key = vec![1u8; SCID_LEN];
        let auths: Vec<String> = Vec::new();
        let handler: Serve = Arc::new(|_| {});
        let mut router = Router {
            sock: Arc::clone(&session.sock),
            local: session.local,
            auths: &auths,
            serve: &handler,
            masq: Arc::new(Masquerade::NotFound),
            realm_state: None,
            udp_idle: Duration::from_secs(60),
            cc_rx: 0,
            stateless_reset: false,
            routes: HashMap::from([(
                key.clone(),
                Inbound {
                    conn: Arc::clone(&session.shared),
                    client_cid: client.clone(),
                    initial_dcid: initial.clone(),
                    source_ids: Vec::new(),
                    authed: false,
                    settings_sent: false,
                    settings_done: false,
                    auth_buf: Vec::new(),
                    wakes: Driver::new(),
                    udp: HashMap::new(),
                    cc_rx: 0,
                },
            )]),
            by_client_cid: HashMap::from([(client, key.clone())]),
            by_initial_dcid: HashMap::from([(initial, key)]),
        };
        router.idle();
        assert!(router.routes.is_empty());
        assert!(router.by_client_cid.is_empty());
        assert!(router.by_initial_dcid.is_empty());
    }

    /// Forgetting a route drops its source-id aliases and leaves another route's aliases alone.
    #[test]
    fn forgetting_a_route_removes_only_its_source_id_aliases() {
        let key = vec![1u8; 4];
        let other = vec![2u8; 4];
        let client = b"client".to_vec();
        let initial = b"initial".to_vec();
        let alias = b"alias".to_vec();
        let alias2 = b"alias2".to_vec();
        let foreign = b"foreign".to_vec();
        let mut by_client_cid = HashMap::from([
            (client.clone(), key.clone()),
            (foreign.clone(), other.clone()),
        ]);
        let mut by_initial_dcid = HashMap::from([
            (initial.clone(), key.clone()),
            (alias.clone(), key.clone()),
            (alias2.clone(), key.clone()),
            (foreign.clone(), other.clone()),
        ]);
        forget_route(
            &mut by_client_cid,
            &mut by_initial_dcid,
            &key,
            &client,
            &initial,
            &[alias, alias2, foreign.clone()],
        );
        assert_eq!(by_client_cid.len(), 1);
        assert_eq!(by_client_cid.get(&foreign), Some(&other));
        assert_eq!(by_initial_dcid.len(), 1);
        assert_eq!(by_initial_dcid.get(&foreign), Some(&other));
    }

    fn idle_session() -> Session {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("configures");
        config
            .set_application_protos(&[crate::quic::ALPN])
            .expect("negotiates");
        let scid = [7u8; SCID_LEN];
        let cid = quiche::ConnectionId::from_ref(&scid);
        let local = "127.0.0.1:0".parse().expect("addr");
        let peer = "127.0.0.1:1".parse().expect("addr");
        let conn = quiche::connect(None, &cid, local, peer, &mut config).expect("connects");
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("binds");
        Session {
            shared: Arc::new(Mutex::new(conn)),
            sock: Arc::new(crate::quic::Datagram::plain(sock)),
            local,
            udp_supported: false,
            driver: None,
            send_wake: None,
            keep_alive: None,
        }
    }

    #[test]
    fn a_parsed_request_leaves_its_payload_where_it_landed() {
        let session = idle_session();
        let payload = b"vless-bytes-behind-the-request";
        let mut head = Vec::new();
        hysteria::encode_tcp_request("127.0.0.1:8080", &[9, 9], &mut head);
        let payload_at = head.len();
        head.extend_from_slice(payload);
        let payload_base = head[payload_at..].as_ptr();
        let mut flow = Flow::from_parts(
            Arc::clone(&session.shared),
            Arc::clone(&session.sock),
            session.local,
            FIRST_FLOW_STREAM,
            head,
            true,
            false,
        );
        // The state serve_stream hands over: the frame type stepped over, nothing moved.
        flow.at = hysteria::read_tcp_prefix(&flow.backlog).expect("prefix");
        let base = flow.backlog.as_ptr();
        let room = flow.backlog.capacity();
        let deadline = Instant::now() + Duration::from_secs(1);
        let address = read_request(&mut flow, deadline).expect("parses");
        assert_eq!(address, "127.0.0.1:8080");
        assert_eq!(flow.backlog.as_ptr(), base, "the buffer never moved");
        assert_eq!(flow.backlog.capacity(), room, "no reallocation");
        assert_eq!(
            &flow.backlog[..2],
            &[0x44, 0x01],
            "the frame type stayed where it arrived"
        );
        assert_eq!(
            &flow.backlog[3..17],
            b"127.0.0.1:8080",
            "the request body stayed where it arrived"
        );
        assert_eq!(
            flow.backlog[flow.at..].as_ptr(),
            payload_base,
            "the payload stayed where it arrived"
        );
        assert_eq!(&flow.backlog[flow.at..], payload);
    }

    /// A stream is served by the turn that first claims it, and a second claim leaves the pump's wake alone.
    #[test]
    fn a_stream_is_claimed_by_the_turn_that_serves_it() {
        let driver = Driver::new();
        let wake = driver.claim(4).expect("the first claim serves the stream");
        assert!(
            driver.claim(4).is_none(),
            "a served stream is not served twice"
        );
        assert!(
            Arc::ptr_eq(&wake, &driver.register(4)),
            "the claim left the wake the pump bumps"
        );
        assert!(driver.claim(8).is_some(), "another stream is its own claim");
    }

    #[test]
    fn a_turn_takes_the_datagrams_queued_behind_its_first() {
        let session = idle_session();
        let to = session.sock.local_addr().expect("addr");
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("binds");
        // Loopback delivers into the receive queue before the send returns, so the whole queue is there when the turn starts.
        for _ in 0..crate::quic::RECV_SLOTS {
            peer.send_to(&[0u8; 64], to).expect("sends");
        }
        assert!(drive_once(&session, Duration::from_millis(50)));
        let probe = session.sock.try_clone().expect("clones");
        probe
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("arms");
        let mut room = Unfilled::<MAX_DATAGRAM>::new();
        let mut left = 0usize;
        while probe.recv_from(room.as_mut()).is_ok() {
            left += 1;
        }
        assert_eq!(left, 0, "a turn left {left} queued datagrams unread");
    }

    #[test]
    fn the_connection_lock_is_free_before_the_datagram_is_relayed() {
        let shared = Mutex::new(vec![vec![1u8, 2, 3]]);
        let data = recv_one(&shared, Vec::pop).expect("one datagram");
        assert_eq!(data, vec![1, 2, 3]);
        assert!(
            shared.try_lock().is_ok(),
            "the relay holds no connection lock"
        );
    }
}

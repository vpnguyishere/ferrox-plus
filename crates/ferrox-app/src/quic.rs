use crate::conn::Connection;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, ToSocketAddrs as _, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub(crate) struct QuicDial {
    pub(crate) id: [u8; 16],
    /// The edge's name and the address it is dialled at, shared rather than copied: a dial names the same bytes twice, and the flow's dial copies the pair again per carrier.
    pub(crate) host: std::sync::Arc<str>,
    pub(crate) address: std::sync::Arc<str>,
    pub(crate) port: u16,
    /// A pooled connection through a hop is its own connection, never reused for a direct dial.
    pub(crate) upstream: Option<crate::foxy::UpstreamProxy>,
    pub(crate) roots: Option<ferrox_core::tls::Anchors>,
    /// The sealed client hello a server can open; it belongs to the connection, so a lane that offered one is never lent to a dial that did not.
    pub(crate) ech_config_list: Option<std::sync::Arc<[u8]>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct QuicServer {
    address: std::sync::Arc<str>,
    port: u16,
    host: std::sync::Arc<str>,
    upstream: Option<crate::foxy::UpstreamProxy>,
    roots: Option<ferrox_core::tls::Anchors>,
    ech_config_list: Option<std::sync::Arc<[u8]>>,
}

impl QuicServer {
    /// What a dial shares with the connections it can ride: everything that changes which edge and which trust the connection belongs to.
    fn of(dial: &QuicDial) -> Self {
        Self {
            address: dial.address.clone(),
            port: dial.port,
            host: dial.host.clone(),
            upstream: dial.upstream.clone(),
            roots: dial.roots.clone(),
            ech_config_list: dial.ech_config_list.clone(),
        }
    }
}

/// How many flows one lane lends before it is handed back for a fresh dial: reuse without a bound is the leak the lane was first closed for, and a stream id only comes back if the edge grants it.
pub(crate) const MAX_FLOWS_ON_LANE: u64 = 64;

struct PooledState {
    /// One handle per flow, shared by every burst it arrives in: a hand-off takes a refcount, not a `dup`.
    sessions: HashMap<u64, Arc<Connection>>,
    opening: HashSet<u64>,
    next_id: u64,
    /// The generation of the pump thread that owns the lane's read side, or zero: a thread clears only its own, so a lane a later lease has already re-armed is left untouched.
    pump: u64,
    /// When the lane's pump left and no thread owns it: the thread follows only the leases it can serve, so an idle edge and a flow that reads its own socket pin none and the next flow rides the same handshake.
    parked: Option<Instant>,
}

/// The shared connection a flow rides, its socket, its local address, and the bidirectional stream id it opened.
pub(crate) struct PooledStream {
    pub(crate) conn: Arc<Mutex<quiche::Connection>>,
    pub(crate) sock: Arc<Datagram>,
    pub(crate) local: SocketAddr,
    pub(crate) id: u64,
    /// The pool entry the stream was taken from, or none when it was built outside the pool: dropping the stream is what hands the id back, so no path that ends a flow has to remember to.
    entry: Option<PooledConn>,
}

impl Drop for PooledStream {
    /// One owner, so a lane that finishes, an open that fails and a caller that returns early all pay the pool back; an id left on the table would be a stream the lane lent and never got back.
    fn drop(&mut self) {
        if let Some(entry) = self.entry.take() {
            leave_session(&entry.table, self.id);
        }
    }
}

impl PooledStream {
    /// Half-closes this stream: the peer reads what was sent, then the end. A FIN costs no flow-control credit, so one attempt is the whole wait.
    pub(crate) fn fin(&self) -> bool {
        let Ok(mut conn) = self.conn.lock() else {
            return false;
        };
        let sent = conn.stream_send(self.id, &[], true).is_ok();
        flush_egress(&mut conn, &self.sock);
        sent
    }

    /// Stops this stream in both directions: an unreset flow keeps being filled into a window nobody drains, charged to the account.
    pub(crate) fn cancel(&self) {
        stop_stream(&self.conn, &self.sock, self.id);
    }

    /// A byte-stream handle on this lease: the same connection and id, without a second lease, so the caller keeps this one alive until both directions end.
    pub(crate) fn stream_handle(&self) -> QuicStream {
        QuicStream {
            conn: Arc::clone(&self.conn),
            sock: Arc::clone(&self.sock),
            id: self.id,
            meter: crate::stats::Meter::default(),
            peer_fin: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// Stops one stream in both directions: the connection itself is untouched and keeps carrying other flows.
fn stop_stream(conn: &Mutex<quiche::Connection>, sock: &Datagram, id: u64) {
    if let Ok(mut conn) = conn.lock() {
        let _ = conn.stream_shutdown(id, quiche::Shutdown::Write, 0);
        let _ = conn.stream_shutdown(id, quiche::Shutdown::Read, 0);
        flush_egress(&mut conn, sock);
    }
}

#[derive(Clone)]
struct PooledConn {
    conn: Arc<Mutex<quiche::Connection>>,
    table: Arc<Mutex<PooledState>>,
    sock: Arc<Datagram>,
    key: Arc<QuicServer>,
}

struct QuicPool {
    inner: Mutex<HashMap<QuicServer, PooledConn>>,
}

impl QuicPool {
    /// The connection already open to this edge, if there is one a flow can still ride.
    fn stream(&self, dial: &QuicDial) -> Option<PooledConn> {
        let key = QuicServer::of(dial);
        let entry = self.inner.lock().ok()?.get(&key).cloned()?;
        // Spent or let go by the edge while parked: hand the lane back rather than ride it, and the caller's `or_else` dials the next one.
        if flow_credit(&entry) && lane_is_live(&entry) {
            return Some(entry);
        }
        self.retire(&key, &entry);
        None
    }

    /// Drop this lane and no other: a concurrent dial can have put a fresh connection under the same key while we were reading the old one.
    fn retire(&self, key: &QuicServer, entry: &PooledConn) {
        if let Ok(mut pool) = self.inner.lock() {
            if pool
                .get(key)
                .is_some_and(|live| Arc::ptr_eq(&live.conn, &entry.conn))
            {
                pool.remove(key);
            }
        }
        // A lane still carrying flows leaves the pool without a goodbye: a `done` frame here would end streams a flow is mid-write to. Its own last lease parks it, and the connection goes with the leases that held it.
        let Ok(mut conn) = entry.conn.lock() else {
            return;
        };
        if entry
            .table
            .lock()
            .is_ok_and(|table| table.sessions.is_empty() && table.opening.is_empty())
        {
            let _ = conn.close(false, 0, b"done");
            flush_egress(&mut conn, &entry.sock);
        }
    }
}

static QUIC_POOL: OnceLock<QuicPool> = OnceLock::new();

fn pool() -> &'static QuicPool {
    QUIC_POOL.get_or_init(|| QuicPool {
        inner: Mutex::new(HashMap::new()),
    })
}

pub(crate) const ALPN: &[u8] = b"h3";

const SCID_LEN: usize = 16;

pub(crate) const MAX_DATAGRAM: usize = 1350;

/// A datagram buffer reused from a thread-local pool: a new size pays one zero pass, a returned buffer pays none, and every slice names initialized bytes.
pub(crate) struct Unfilled<const N: usize> {
    bytes: Vec<u8>,
}

/// The buffers one thread has returned, capped so a burst is reused without the pool becoming a heap of its own.
const BUFFER_CACHE: usize = 1024 * 1024;

#[derive(Default)]
struct BufferPool {
    bytes: Vec<Vec<u8>>,
    cached: usize,
}

impl BufferPool {
    const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            cached: 0,
        }
    }

    fn take(&mut self, len: usize) -> Option<Vec<u8>> {
        let at = self.bytes.iter().rposition(|bytes| bytes.len() == len)?;
        let bytes = self.bytes.swap_remove(at);
        self.cached -= bytes.len();
        Some(bytes)
    }

    fn put(&mut self, bytes: Vec<u8>) {
        if self.cached + bytes.len() <= BUFFER_CACHE {
            self.cached += bytes.len();
            self.bytes.push(bytes);
        }
    }
}

thread_local! {
    static BUFFERS: RefCell<BufferPool> = const { RefCell::new(BufferPool::new()) };
}

impl<const N: usize> Unfilled<N> {
    #[must_use]
    pub(crate) fn new() -> Self {
        let bytes = BUFFERS
            .with(|pool| pool.borrow_mut().take(N))
            .unwrap_or_else(|| vec![0; N]);
        Self { bytes }
    }

    #[must_use]
    pub(crate) fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// The first `len` bytes, which the call this buffer was handed wrote before it published `len`.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub(crate) fn written(&self, len: usize) -> &[u8] {
        &self.bytes[..len.min(N)]
    }
}

impl<const N: usize> Drop for Unfilled<N> {
    fn drop(&mut self) {
        if self.bytes.len() != N {
            return;
        }
        let bytes = std::mem::take(&mut self.bytes);
        let _ = BUFFERS.try_with(|pool| pool.borrow_mut().put(bytes));
    }
}

pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// A handshake that has processed no packet at all for this long is on a path that drops datagrams: quiche retransmits the Initial several times inside it, and a peer that answers at all answers before.
const SILENT_HANDSHAKE: Duration = Duration::from_secs(5);

pub(crate) const IDLE_TIMEOUT_MS: u64 = 300_000;

/// The receive credit an edge may hold against this process at the first byte: quiche parks every delivered byte here until the app reads it, so the advertised window is the memory the edge gets to spend before the first `MAX_STREAM_DATA` update.
pub(crate) const MAX_DATA: u64 = 16_777_216;
pub(crate) const MAX_STREAM_DATA: u64 = 4_194_304;
pub(crate) const MAX_STREAMS: u64 = 100;

/// The rate every window in this file is sized for, in bytes per second: 1 Gbit/s, the fastest link a lane's own socket is expected to feed.
const WINDOW_RATE: u64 = 125_000_000;

/// The bytes a link of `rate` holds in flight over one round trip — the window a flow must be allowed before the window, and not the link, is what limits it. A window narrower than this caps a flow at `window / rtt`; a wider one buys nothing. Integer arithmetic throughout, because the product is a count of bytes and rounding it is the whole answer.
const fn in_flight(rate: u64, rtt_ms: u64) -> u64 {
    rate * rtt_ms / 1000
}

/// The ceilings quiche's own receiver autotuner may double up to, one round trip at a time. They are strictly wider than the initial credit above, which is the point: quiche doubles a window when it is drained twice inside two round trips, and a ceiling equal to the initial window turns every one of those doublings into a no-op, leaving the flow paced by `window / rtt` on every path where the product is larger than a megabyte.
pub(crate) const MAX_CONNECTION_WINDOW: u64 = in_flight(WINDOW_RATE, 256);
pub(crate) const MAX_STREAM_WINDOW: u64 = in_flight(WINDOW_RATE, 64);

const PUMP_POLL: Duration = Duration::from_millis(500);

/// The pump drain's read window: one lock is amortised over this many bytes on the downlink, and it is the uplink relay's read quantum on the same lane.
const PUMP_WINDOW: usize = 32 * 1024;

pub(crate) const SEND_WAIT: Duration = Duration::from_secs(10);

static TRUST_SEQ: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
pub(crate) static QSTAGES: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

#[cfg(test)]
pub(crate) fn qstage(ev: String) {
    if let Ok(mut log) = QSTAGES.lock() {
        log.push(ev);
    }
}

/// A loopback edge's wait for the next packet before quiche runs timers; it keeps an idle test connection alive.
#[cfg(test)]
pub(crate) const SERVER_POLL: Duration = Duration::from_millis(100);

#[cfg(test)]
pub(crate) fn qms() -> u128 {
    static QT0: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    QT0.get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis()
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const fn b64_table() -> [u8; 256] {
    let mut table = [255u8; 256];
    let mut i = 0usize;
    while i < 64 {
        table[B64[i] as usize] = i as u8;
        i += 1;
    }
    table
}

const B64_TABLE: [u8; 256] = b64_table();

fn base64_encode_block(out: &mut [u8; 64], bytes: &[u8]) -> usize {
    assert!(bytes.len() <= 48, "base64 lines are 48 input bytes");
    // A PEM line is 48 input bytes except the last, so the full line is the hot case. Over it the group index is a fixed-range induction variable: bytes[gi*3..][..3] stays under 48 and out[gi*4..][..4] under 64 for every gi in 0..16, so the compiler proves every access in range and the line encodes as straight-line loads, shifts and stores with no bounds check and no per-group slice re-slicing.
    if bytes.len() == 48 {
        for gi in 0..16 {
            let (s, d) = (gi * 3, gi * 4);
            let word = (u32::from(bytes[s]) << 16)
                | (u32::from(bytes[s + 1]) << 8)
                | u32::from(bytes[s + 2]);
            out[d] = B64[(word >> 18) as usize];
            out[d + 1] = B64[((word >> 12) & 63) as usize];
            out[d + 2] = B64[((word >> 6) & 63) as usize];
            out[d + 3] = B64[(word & 63) as usize];
        }
        return 64;
    }
    let mut written = 0;
    let mut rest = bytes;
    // A full three-byte group needs no serial shift-and-or to build the word and no per-slot branch: the three bytes load straight into a 24-bit window at fixed shifts, and the four sextets are fixed shifts written as four stores. This is the whole 48-byte line sixteen times over; the padding case lands once, on the line's tail.
    while let Some(g) = rest.first_chunk::<3>() {
        let word = (u32::from(g[0]) << 16) | (u32::from(g[1]) << 8) | u32::from(g[2]);
        out[written] = B64[(word >> 18) as usize];
        out[written + 1] = B64[((word >> 12) & 63) as usize];
        out[written + 2] = B64[((word >> 6) & 63) as usize];
        out[written + 3] = B64[(word & 63) as usize];
        written += 4;
        rest = &rest[3..];
    }
    // The trailing one or two bytes, the only place a pad appears, reached once per line.
    match rest {
        [a] => {
            let w = u32::from(*a) << 16;
            out[written] = B64[(w >> 18) as usize];
            out[written + 1] = B64[((w >> 12) & 63) as usize];
            out[written + 2] = b'=';
            out[written + 3] = b'=';
            written += 4;
        }
        [a, b] => {
            let w = (u32::from(*a) << 16) | (u32::from(*b) << 8);
            out[written] = B64[(w >> 18) as usize];
            out[written + 1] = B64[((w >> 12) & 63) as usize];
            out[written + 2] = B64[((w >> 6) & 63) as usize];
            out[written + 3] = b'=';
            written += 4;
        }
        _ => {}
    }
    written
}

fn base64_value(byte: u8) -> Option<u8> {
    let v = B64_TABLE[byte as usize];
    if v == 255 {
        None
    } else {
        Some(v)
    }
}

fn base64_decode(text: &[u8], out: &mut Vec<u8>) -> bool {
    let mut word = 0u32;
    let mut slots = 0;
    let mut pads = 0;
    for byte in text {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if *byte == b'=' {
            pads += 1;
            word <<= 6;
        } else {
            if pads > 0 {
                return false;
            }
            let Some(digit) = base64_value(*byte) else {
                return false;
            };
            word = (word << 6) | u32::from(digit);
        }
        slots += 1;
        if slots == 4 {
            if pads > 2 {
                return false;
            }
            out.push((word >> 16) as u8);
            if pads < 2 {
                out.push((word >> 8) as u8);
            }
            if pads == 0 {
                out.push(word as u8);
            }
            word = 0;
            slots = 0;
            pads = 0;
        }
    }
    slots == 0
}

/// The exact byte length `der_to_pem` writes: two header lines of `11 + label + 6` and `9 + label + 6`, plus one base64 line per 48 input bytes (64 chars full, `4 · ⌈rem/3⌉` partial) and its newline.
fn pem_capacity(der_len: usize, label_len: usize) -> usize {
    let full = der_len / 48;
    let rem = der_len % 48;
    let lines = full + usize::from(rem != 0);
    (11 + label_len + 6) + (full * 64 + rem.div_ceil(3) * 4) + lines + (9 + label_len + 6)
}

pub(crate) fn der_to_pem(der: &[u8], label: &str) -> Vec<u8> {
    let mut pem = Vec::with_capacity(pem_capacity(der.len(), label.len()));
    append_pem(&mut pem, der, label);
    pem
}

/// Append one PEM block into a buffer the caller has already reserved to `pem_capacity`, so the fill is memcpy into live capacity — no reallocation moves the bytes already there. The reservation is the caller's single job: `der_to_pem` opens the exact length and the chain and bundle open the summed length, so re-reserving per block would only recompute `pem_capacity`'s arithmetic and hit a no-op the callers already proved.
#[inline(never)]
fn append_pem(pem: &mut Vec<u8>, der: &[u8], label: &str) {
    pem.extend_from_slice(b"-----BEGIN ");
    pem.extend_from_slice(label.as_bytes());
    pem.extend_from_slice(b"-----\n");
    let mut block = [0u8; 64];
    for line in der.chunks(48) {
        let n = base64_encode_block(&mut block, line);
        pem.extend_from_slice(&block[..n]);
        pem.push(b'\n');
    }
    pem.extend_from_slice(b"-----END ");
    pem.extend_from_slice(label.as_bytes());
    pem.extend_from_slice(b"-----\n");
}

pub(crate) fn parse_ca_pem(pem: &[u8]) -> Vec<Vec<u8>> {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END: &[u8] = b"-----END CERTIFICATE-----";
    let mut certs = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.windows(BEGIN.len()).position(|w| w == BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let Some(end) = after.windows(END.len()).position(|w| w == END) else {
            return Vec::new();
        };
        let mut der = Vec::new();
        if !base64_decode(&after[..end], &mut der) {
            return Vec::new();
        }
        certs.push(der);
        rest = &after[end + END.len()..];
    }
    certs
}

// create_new is O_EXCL, so a name already in a shared tmp fails instead of being followed or truncated.
fn stage_trust_file(bundle: &[u8]) -> Option<(std::path::PathBuf, String)> {
    let name = format!(
        "ferrox-quic-roots-{}-{}.pem",
        std::process::id(),
        TRUST_SEQ.fetch_add(1, Ordering::Relaxed)
    );
    stage_at(&std::env::temp_dir().join(name), bundle)
}

fn stage_at(path: &std::path::Path, bundle: &[u8]) -> Option<(std::path::PathBuf, String)> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    std::io::Write::write_all(&mut file, bundle).ok()?;
    let text = path.to_str()?.to_owned();
    Some((path.to_path_buf(), text))
}

/// The transport shape every lane in this file shares, in one place: the initial credit, the ceiling its autotuner may grow to, and the datagram both ends are bounded to.
///
/// The datagram is the whole arithmetic of a QUIC lane's syscall count. A packet carries 1350 bytes of UDP payload instead of the 1200 quiche defaults to, so a megabyte leaves in 776 datagrams rather than 874 — 11.2 percent fewer sends, fewer ACKs, and fewer receive interrupts for the same bytes, and the lane's own receive buffer is already exactly this wide, so what it advertises is what it can hold.
pub(crate) fn tune_transport(config: &mut quiche::Config) {
    config.set_max_idle_timeout(IDLE_TIMEOUT_MS);
    config.set_initial_max_data(MAX_DATA);
    config.set_initial_max_stream_data_bidi_local(MAX_STREAM_DATA);
    config.set_initial_max_stream_data_bidi_remote(MAX_STREAM_DATA);
    config.set_initial_max_stream_data_uni(MAX_STREAM_DATA);
    config.set_initial_max_streams_bidi(MAX_STREAMS);
    config.set_initial_max_streams_uni(MAX_STREAMS);
    config.set_max_connection_window(MAX_CONNECTION_WINDOW);
    config.set_max_stream_window(MAX_STREAM_WINDOW);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM);
    // What the lane may be handed is what its own receive buffer holds: advertising quiche's 65527 while reading into `MAX_DATAGRAM` truncates any wider datagram a peer takes the advertisement at its word on.
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM);
}

/// The reference's `finalmask.quicParams` windows, idle bound and stream cap, a zero field taking the reference's default; `bbrProfile`, `brutal*`, `disableChromeParrot`, `disableGSO` and `disableStatelessReset` are accepted but have no quiche knob.
pub(crate) fn apply_hysteria_quic(
    config: &mut quiche::Config,
    params: &ferrox_core::hysteria::QuicParams,
    server: bool,
) {
    use ferrox_core::hysteria::QuicParams;
    config.set_max_idle_timeout(params.idle_seconds().saturating_mul(1000));
    let stream = QuicParams::stream_window(params.init_stream_window, false);
    config.set_initial_max_stream_data_bidi_local(stream);
    config.set_initial_max_stream_data_bidi_remote(stream);
    config.set_initial_max_stream_data_uni(stream);
    config.set_max_stream_window(QuicParams::stream_window(params.max_stream_window, false));
    config.set_initial_max_data(QuicParams::stream_window(
        params.init_connection_window,
        true,
    ));
    config.set_max_connection_window(QuicParams::stream_window(
        params.max_connection_window,
        true,
    ));
    if server || params.max_incoming_streams != 0 {
        let streams = if params.max_incoming_streams == 0 {
            1024
        } else {
            params.max_incoming_streams
        };
        config.set_initial_max_streams_bidi(streams);
        config.set_initial_max_streams_uni(streams);
    }
    if params.no_path_mtu {
        config.discover_pmtu(false);
    }
}

/// One ALPN and one flow-control shape for the lane: a weaker peer negotiates down, never up.
pub(crate) fn tune(config: &mut quiche::Config, alpn: &[u8]) -> bool {
    if config.set_application_protos(&[alpn]).is_err() {
        return false;
    }
    tune_transport(config);
    true
}

/// A serving identity: the lane's own tuning plus the certificate chain quiche reads at load time.
pub(crate) fn serve_config(identity: &ferrox_core::tls::TlsServerConfig) -> Option<quiche::Config> {
    let mut config = tls_config(identity)?;
    if !tune(&mut config, ALPN) {
        return None;
    }
    Some(config)
}

/// The TLS half of a serving identity, before a carrier adds its own ALPN and tuning.
pub(crate) fn tls_config(identity: &ferrox_core::tls::TlsServerConfig) -> Option<quiche::Config> {
    let builder = if identity.ech_server_keys.is_some() {
        identity.ech_server_context_builder().ok()?
    } else {
        ferrox_core::tls::quic_server_context_builder(identity).ok()?
    };
    quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder).ok()
}

pub(crate) fn quiche_config(roots: &[Vec<u8>], cc: Option<&str>) -> Option<quiche::Config> {
    quiche_config_alpn(roots, cc, &[ALPN])
}

/// The same staged trust bundle and tuning under another ALPN, for a client
/// whose protocol is not this tree's own transport (`doq` is DNS-over-QUIC).
pub(crate) fn quiche_config_alpn(
    roots: &[Vec<u8>],
    cc: Option<&str>,
    alpn: &[&[u8]],
) -> Option<quiche::Config> {
    if roots.is_empty() {
        return None;
    }
    let mut bundle = Vec::with_capacity(
        roots
            .iter()
            .map(|der| pem_capacity(der.len(), "CERTIFICATE".len()))
            .sum(),
    );
    for root in roots {
        append_pem(&mut bundle, root, "CERTIFICATE");
    }
    let (path, path_text) = stage_trust_file(&bundle)?;
    let config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .ok()
        .and_then(|mut config| {
            config.verify_peer(true);
            config.set_application_protos(alpn).ok()?;
            if let Some(name) = cc {
                config.set_cc_algorithm_name(name).ok()?;
            }
            tune_transport(&mut config);
            config.load_verify_locations_from_file(&path_text).ok()?;
            Some(config)
        });
    let _ = std::fs::remove_file(&path);
    config
}

/// The built configs, keyed by the trust bundle they were staged from.
type BuiltConfigs = Mutex<HashMap<Vec<Vec<u8>>, Arc<Mutex<quiche::Config>>>>;

/// One built config per trust bundle: quiche documents a `Config` as shared between connections, and building one writes every anchor out as PEM, parses it back off the filesystem and deletes the file.
static CONFIGS: OnceLock<BuiltConfigs> = OnceLock::new();

/// Dial through the config this trust bundle was built into: the first dial of a bundle pays the staged file, a later one is handed the built config with no copy of the anchors. A bundle that will not build is not cached, so it names itself per dial as it always did.
pub(crate) fn with_config<T>(
    roots: &[Vec<u8>],
    dial: impl FnOnce(&mut quiche::Config) -> Option<T>,
) -> Option<T> {
    let cell = {
        let mut configs = CONFIGS.get_or_init(Default::default).lock().ok()?;
        if let Some(cell) = configs.get(roots) {
            Arc::clone(cell)
        } else {
            let staged = crate::foxy::debug_on().then(Instant::now);
            let config = quiche_config(roots, None)?;
            debug_staged(staged);
            let cell = Arc::new(Mutex::new(config));
            configs.insert(roots.to_vec(), Arc::clone(&cell));
            cell
        }
    };
    let mut config = cell.lock().ok()?;
    dial(&mut config)
}

/// The one phase a warm dial stops paying, behind `FOXY_DEBUG`: the bundle written out, parsed back and deleted. An untraced lane makes no clock call here.
fn debug_staged(staged: Option<Instant>) {
    let Some(staged) = staged else { return };
    eprintln!(
        "foxy-debug: quic config staged in {}ms",
        staged.elapsed().as_millis()
    );
}

/// The datagrams one egress sweep hands the socket in one call: a 64 KiB relay read queues about fifty behind each other, so a batch of sixty-four sends a whole frame where the loop paid one syscall per packet.
#[cfg(target_os = "linux")]
const SEND_SLOTS: usize = 64;

/// The most full packets one GSO datagram may carry: 48 × 1350 stays under the 65507-byte UDP ceiling, so a
/// sixty-four packet sweep leaves as two GSO datagrams instead of one that the kernel refuses whole.
#[cfg(target_os = "linux")]
const GSO_SEGMENTS: usize = 48;

pub(crate) fn flush_egress(conn: &mut quiche::Connection, sock: &Datagram) {
    sock.retry_held();
    if sock.held.holding.load(Ordering::Relaxed) {
        return;
    }
    #[cfg(target_os = "linux")]
    if sock.batchable() {
        flush_burst(conn, sock);
        return;
    }
    let mut room = Unfilled::<MAX_DATAGRAM>::new();
    let out = room.as_mut();
    while let Ok((written, info)) = conn.send(out) {
        if !sock.send_or_hold(&out[..written], info.to) {
            break;
        }
    }
}

/// Every datagram quiche has ready, in batches of `SEND_SLOTS`. Each packet is written straight into its own slot and addressed by the peer quiche named for it, and only the slots a sweep fills pay a header, so the batch costs neither a copy nor any wiring the per-packet loop did not already make.
#[cfg(target_os = "linux")]
fn flush_burst(conn: &mut quiche::Connection, sock: &Datagram) {
    let mut slots: [Unfilled<MAX_DATAGRAM>; SEND_SLOTS] =
        std::array::from_fn(|_| Unfilled::<MAX_DATAGRAM>::new());
    let mut peers: [std::mem::MaybeUninit<libc::sockaddr_storage>; SEND_SLOTS] =
        std::array::from_fn(|_| std::mem::MaybeUninit::uninit());
    let mut parts: [std::mem::MaybeUninit<libc::iovec>; SEND_SLOTS] =
        std::array::from_fn(|_| std::mem::MaybeUninit::uninit());
    let mut batch: [std::mem::MaybeUninit<libc::mmsghdr>; SEND_SLOTS] =
        std::array::from_fn(|_| std::mem::MaybeUninit::uninit());
    let mut lens = [0usize; SEND_SLOTS];
    let mut tos: [Option<SocketAddr>; SEND_SLOTS] = [None; SEND_SLOTS];
    // The sweep is over when quiche has nothing more to hand, so a frame wider than the slots leaves in batch after batch, exactly as the per-packet loop drained it.
    let mut at = 0usize;
    let mut drained = false;
    while !drained {
        match conn.send(slots[at].as_mut()) {
            Ok((written, info)) if written > 0 => {
                let (storage, len) = crate::proxy::sockaddr_of(info.to);
                peers[at].write(storage);
                lens[at] = written;
                tos[at] = Some(info.to);
                parts[at].write(libc::iovec {
                    iov_base: slots[at].as_mut().as_mut_ptr().cast(),
                    iov_len: written,
                });
                batch[at].write(libc::mmsghdr {
                    msg_hdr: libc::msghdr {
                        msg_name: peers[at].as_mut_ptr().cast(),
                        msg_namelen: len,
                        msg_iov: parts[at].as_mut_ptr(),
                        msg_iovlen: 1,
                        msg_control: std::ptr::null_mut(),
                        msg_controllen: 0,
                        msg_flags: 0,
                    },
                    msg_len: 0,
                });
                at += 1;
            }
            Ok(_) | Err(_) => drained = true,
        }
        if at == SEND_SLOTS {
            if !send_batch(sock, &mut batch, &slots, at, &lens, &tos) {
                drained = true;
            }
            at = 0;
        }
    }
    if at > 0 {
        send_batch(sock, &mut batch, &slots, at, &lens, &tos);
    }
}

/// One GSO datagram carries up to `GSO_SEGMENTS` packets: the kernel cuts it at `MAX_DATAGRAM` before the wire, so
/// a burst that was one `sendmmsg` with sixty-four headers becomes one `sendmsg` with one header and one control
/// message. Every packet in the run goes to the same peer and every one but the last is a full `MAX_DATAGRAM`
/// segment. A batch that cannot be one GSO datagram keeps the `sendmmsg` path.
#[cfg(target_os = "linux")]
fn send_batch(
    sock: &Datagram,
    batch: &mut [std::mem::MaybeUninit<libc::mmsghdr>],
    slots: &[Unfilled<MAX_DATAGRAM>; SEND_SLOTS],
    want: usize,
    lens: &[usize],
    tos: &[Option<SocketAddr>],
) -> bool {
    let mut done = 0usize;
    while done < want {
        let n = (want - done).min(GSO_SEGMENTS);
        if n >= 2 && can_gso(&lens[done..done + n], &tos[done..done + n]) {
            match send_gso(sock, slots, lens, done, n, tos[done]) {
                Gso::Sent => {
                    done += n;
                    continue;
                }
                Gso::Refused => {
                    for i in done + n..want {
                        if let Some(to) = tos[i] {
                            sock.hold(slots[i].written(lens[i]), to);
                        }
                    }
                    return false;
                }
                Gso::Unsupported => {}
            }
        }
        return send_mmsg(sock, batch, slots, want, done, lens, tos);
    }
    true
}

/// Whether the slots below `want` are one GSO datagram: every packet but the last is a full `MAX_DATAGRAM` segment,
/// and every packet goes to the same peer.
#[cfg(target_os = "linux")]
fn can_gso(lens: &[usize], tos: &[Option<SocketAddr>]) -> bool {
    let Some(to) = tos.first().copied().flatten() else {
        return false;
    };
    lens.len() >= 2
        && tos.iter().all(|peer| *peer == Some(to))
        && lens[..lens.len() - 1]
            .iter()
            .all(|len| *len == MAX_DATAGRAM)
        && lens
            .last()
            .is_some_and(|len| *len > 0 && *len <= MAX_DATAGRAM)
}

/// The result of trying the one-datagram path: `Unsupported` is the kernel refusing the control message, which
/// falls back to `sendmmsg`; `Refused` is a full queue, which holds the whole burst for the next sweep.
#[cfg(target_os = "linux")]
enum Gso {
    Sent,
    Refused,
    Unsupported,
}

/// One `sendmsg` with a `UDP_SEGMENT` control message: each packet is its own iovec, so the run costs one header and
/// no copy, and the kernel cuts and checksums every segment itself. The bytes on the wire are the bytes `sendmmsg`
/// would have written.
#[cfg(target_os = "linux")]
fn send_gso(
    sock: &Datagram,
    slots: &[Unfilled<MAX_DATAGRAM>; SEND_SLOTS],
    lens: &[usize],
    start: usize,
    want: usize,
    to: Option<SocketAddr>,
) -> Gso {
    use std::os::fd::AsRawFd as _;
    #[repr(C)]
    struct Segment {
        header: libc::cmsghdr,
        size: u16,
    }
    let Some(to) = to else {
        return Gso::Unsupported;
    };
    let mut parts: [std::mem::MaybeUninit<libc::iovec>; SEND_SLOTS] =
        std::array::from_fn(|_| std::mem::MaybeUninit::uninit());
    let mut total = 0usize;
    for (at, part) in parts.iter_mut().enumerate().take(want) {
        let slot = start + at;
        let bytes = slots[slot].written(lens[slot]);
        total += bytes.len();
        part.write(libc::iovec {
            iov_base: bytes.as_ptr().cast_mut().cast(),
            iov_len: bytes.len(),
        });
    }
    let (mut storage, name_len) = crate::proxy::sockaddr_of(to);
    let mut control = Segment {
        header: libc::cmsghdr {
            cmsg_len: unsafe { libc::CMSG_LEN(2) } as usize,
            cmsg_level: libc::SOL_UDP,
            cmsg_type: libc::UDP_SEGMENT,
        },
        size: MAX_DATAGRAM as u16,
    };
    let message = libc::msghdr {
        msg_name: (&raw mut storage).cast(),
        msg_namelen: name_len,
        msg_iov: parts.as_mut_ptr().cast(),
        msg_iovlen: want,
        msg_control: (&raw mut control).cast(),
        msg_controllen: unsafe { libc::CMSG_SPACE(2) } as usize,
        msg_flags: 0,
    };
    // SAFETY: `message` names `parts`, `storage` and `control`, which outlive the call, and each part points at a slot the caller filled for the same sweep.
    let sent = unsafe { libc::sendmsg(sock.sock.as_raw_fd(), &raw const message, 0) };
    if sent == isize::try_from(total).unwrap_or(isize::MAX) {
        return Gso::Sent;
    }
    if sent < 0 {
        let error = std::io::Error::last_os_error();
        if refused(&error) {
            for i in start..start + want {
                sock.hold(slots[i].written(lens[i]), to);
            }
            return Gso::Refused;
        }
    }
    Gso::Unsupported
}

/// One `sendmmsg` over the slots the sweep filled, retried from the first message the kernel did not take. A datagram
/// the kernel still refuses is held for the next sweep rather than dropped: quiche never retransmits a DATAGRAM frame,
/// so the loss would be an inner TCP hole only a retransmit timer repairs. Nothing is held back when every message was
/// taken.
#[cfg(target_os = "linux")]
fn send_mmsg(
    sock: &Datagram,
    batch: &mut [std::mem::MaybeUninit<libc::mmsghdr>],
    slots: &[Unfilled<MAX_DATAGRAM>; SEND_SLOTS],
    want: usize,
    start: usize,
    lens: &[usize],
    tos: &[Option<SocketAddr>],
) -> bool {
    use std::os::fd::AsRawFd as _;
    let mut done = start;
    while done < want {
        let rest = &mut batch[done..want];
        // SAFETY: every header below `want` was written by the caller this iteration, `MaybeUninit` is transparent over the header the call reads, and the buffers each names outlive the caller's frame.
        let sent = unsafe {
            libc::sendmmsg(
                sock.sock.as_raw_fd(),
                rest.as_mut_ptr().cast::<libc::mmsghdr>(),
                rest.len() as libc::c_uint,
                0,
            )
        };
        match sent {
            n if n <= 0 => {
                if refused(&std::io::Error::last_os_error()) {
                    for (i, slot) in slots.iter().enumerate().take(want).skip(done) {
                        if let Some(to) = tos[i] {
                            sock.hold(slot.written(lens[i]), to);
                        }
                    }
                    return false;
                }
                return true;
            }
            n => done += usize::try_from(n).unwrap_or(0),
        }
    }
    true
}

/// The datagrams one receive takes at a time: sixteen coalesced slots are up to a thousand packets per call, and a
/// plain peer still fills sixteen per call. A slot is a whole `GRO_ROOM` burst, so this count is the batch's memory
/// and is kept apart from the segment cap. A lane with no batched call reads one datagram at a time.
pub(crate) const RECV_SLOTS: usize = 16;

/// The most segments one `UDP_GRO` datagram carries, a kernel constant independent of how many
/// entries a batch reads per call.
#[cfg(target_os = "linux")]
const GRO_SEGMENTS: usize = 64;

/// The largest coalesced datagram a GSO peer can hand back: a full `GRO_SEGMENTS` burst of
/// `MAX_DATAGRAM` packets.
#[cfg(target_os = "linux")]
const GRO_ROOM: usize = MAX_DATAGRAM * GRO_SEGMENTS;

/// Room for one `UDP_GRO` control message, which is a header and a segment size.
#[cfg(target_os = "linux")]
const CONTROL_ROOM: usize = 64;

/// The arrays one thread's batch reads into. Kept out of `Batch` itself so a pool can hand the same allocation to
/// every pump on a thread: the slots are a GSO burst wide, which is too much to build again for each visit.
#[cfg(target_os = "linux")]
struct BatchData {
    slots: Vec<Unfilled<GRO_ROOM>>,
    peers: Vec<std::mem::MaybeUninit<libc::sockaddr_storage>>,
    names: Vec<std::mem::MaybeUninit<libc::socklen_t>>,
    lens: Vec<std::mem::MaybeUninit<libc::c_uint>>,
    controls: Vec<[u8; CONTROL_ROOM]>,
    segs: Vec<usize>,
    starts: Vec<usize>,
    used: usize,
    len: usize,
}

#[cfg(target_os = "linux")]
impl BatchData {
    fn new() -> Self {
        Self {
            slots: (0..RECV_SLOTS).map(|_| Unfilled::new()).collect(),
            peers: (0..RECV_SLOTS)
                .map(|_| std::mem::MaybeUninit::uninit())
                .collect(),
            names: (0..RECV_SLOTS)
                .map(|_| std::mem::MaybeUninit::uninit())
                .collect(),
            lens: (0..RECV_SLOTS)
                .map(|_| std::mem::MaybeUninit::uninit())
                .collect(),
            controls: vec![[0u8; CONTROL_ROOM]; RECV_SLOTS],
            segs: vec![0; RECV_SLOTS],
            starts: vec![0; RECV_SLOTS + 1],
            used: 0,
            len: 0,
        }
    }
}

#[cfg(target_os = "linux")]
thread_local! {
    #[allow(
        clippy::vec_box,
        reason = "a batch's slots are megabytes wide, so the pool keeps them behind the box that the batch's stack handle names"
    )]
    static BATCH_POOL: std::cell::RefCell<Vec<Box<BatchData>>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// One batch per live pump on a thread: a nested `take_queued` may hold a second, and more than that is memory a thread no longer needs.
#[cfg(target_os = "linux")]
const BATCH_POOL_MAX: usize = 2;

/// A batch of datagrams read off a lane's socket: the bytes of each, the peer it came from and the length of that
/// peer's name. A slot can be one datagram or a coalesced GSO burst; `starts` maps the packet index a caller walks
/// to the slot and the segment inside it, so a coalesced burst reads exactly like the packets it carried.
#[cfg(target_os = "linux")]
pub(crate) struct Batch {
    data: Option<Box<BatchData>>,
}

#[cfg(target_os = "linux")]
impl Batch {
    pub(crate) fn new() -> Self {
        Self { data: None }
    }

    fn data(&self) -> Option<&BatchData> {
        self.data.as_deref()
    }

    /// The slots this batch reads into, taken from the thread's pool on its first read.
    fn data_mut(&mut self) -> &mut BatchData {
        if self.data.is_none() {
            let data = BATCH_POOL
                .try_with(|pool| pool.borrow_mut().pop())
                .ok()
                .flatten()
                .unwrap_or_else(|| Box::new(BatchData::new()));
            self.data = Some(data);
        }
        self.data.as_deref_mut().expect("a batch owns its slots")
    }

    /// How many packets the last read filled, with a coalesced slot counted as the segments it carries.
    pub(crate) fn len(&self) -> usize {
        self.data().map_or(0, |data| data.len)
    }

    /// The slot holding packet `at`, found through the prefix sums `recv_batch` wrote.
    fn slot_of(&self, at: usize) -> Option<usize> {
        let data = self.data()?;
        if at >= data.len {
            return None;
        }
        let starts = &data.starts[..=data.used];
        starts.partition_point(|&start| start <= at).checked_sub(1)
    }

    /// The byte range of packet `at` inside its slot: a slot read without GRO has one packet, and a coalesced one
    /// is cut at the segment size the kernel named.
    fn range(&self, slot: usize, at: usize) -> Option<(usize, usize)> {
        let data = self.data()?;
        // SAFETY: `recv_batch` wrote this slot's length before it published the slot in `len`.
        let raw = usize::try_from(unsafe { *data.lens.get(slot)?.assume_init_ref() }).ok()?;
        let seg = data.segs.get(slot).copied().unwrap_or(0);
        if seg == 0 {
            return Some((0, raw));
        }
        let index = at.checked_sub(*data.starts.get(slot)?)?;
        let start = index.checked_mul(seg)?;
        if start >= raw {
            return None;
        }
        Some((start, (start + seg).min(raw)))
    }

    /// One packet of the batch, with the peer it came from: the bytes are read out of the slot the kernel wrote, and
    /// the address out of the storage it filled.
    pub(crate) fn at(&mut self, at: usize) -> Option<(&mut [u8], SocketAddr)> {
        let slot = self.slot_of(at)?;
        let (start, end) = self.range(slot, at)?;
        // SAFETY: `recv_batch` wrote this slot's name and peer before it published the slot in `len`.
        let data = self.data()?;
        let from = crate::proxy::socket_addr_of(
            unsafe { data.peers.get(slot)?.assume_init_ref() },
            unsafe { *data.names.get(slot)?.assume_init_ref() },
        )?;
        let bytes = self
            .data_mut()
            .slots
            .get_mut(slot)?
            .as_mut()
            .get_mut(start..end)?;
        Some((bytes, from))
    }

    /// The routing key of one packet, borrowed from the bytes the kernel wrote there: a run of datagrams for one lane
    /// is compared and looked up without copying a key out of the batch.
    pub(crate) fn key(&self, at: usize) -> Option<&[u8]> {
        let slot = self.slot_of(at)?;
        let (start, end) = self.range(slot, at)?;
        packet_key(self.data()?.slots.get(slot)?.written(end).get(start..)?)
    }
}

#[cfg(target_os = "linux")]
impl Drop for Batch {
    /// Return the slots to the thread's pool, keeping only the batches a live pump may still ask for.
    fn drop(&mut self) {
        if let Some(data) = self.data.take() {
            let _ = BATCH_POOL.try_with(|pool| {
                let mut pool = pool.borrow_mut();
                if pool.len() < BATCH_POOL_MAX {
                    pool.push(data);
                }
            });
        }
    }
}

/// A platform with no batched call has no batch to own, and the lane says so before it reads.
#[cfg(not(target_os = "linux"))]
pub(crate) struct Batch;

#[cfg(not(target_os = "linux"))]
impl Batch {
    pub(crate) fn new() -> Self {
        Self
    }

    /// How many datagrams the last read filled: a platform with no batched call never fills one.
    #[allow(
        clippy::unused_self,
        reason = "the batched read is Linux's, and this is where the other platforms say so"
    )]
    pub(crate) fn len(&self) -> usize {
        0
    }

    /// One datagram of the batch: a platform with no batched call has none to give.
    pub(crate) fn at(&mut self, _at: usize) -> Option<(&mut [u8], SocketAddr)> {
        let _ = self;
        None
    }
}

/// How one batched read ended: `Read` is a batch the kernel filled, `Empty` is a queue with nothing in it,
/// `Unbatchable` is a lane whose read is a shape of its own, and `Unreadable` is a batchable lane whose batched read
/// failed, so its single-datagram fallback must not run against a socket that still coalesces.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[allow(
    dead_code,
    reason = "a platform with no batched call never reads a batch, so it never builds one either"
)]
pub(crate) enum Drain {
    Read,
    Empty,
    Unbatchable,
    Unreadable,
}

/// Every datagram the socket has queued, in at most `RECV_SLOTS` per call, read straight into the batch's own slots.
/// A lane that reads one datagram per syscall is paced by the syscall, not by the wire: a QUIC packet is 1350 bytes,
/// and a fast link delivers one every ten microseconds, which a syscall per packet cannot keep up with. A GSO peer's
/// burst lands as one large datagram and is cut back into packets here, so quiche still sees one packet per call.
#[cfg(target_os = "linux")]
pub(crate) fn recv_batch(sock: &Datagram, batch: &mut Batch) -> Drain {
    use std::os::fd::AsRawFd as _;
    if !sock.batchable() {
        return Drain::Unbatchable;
    }
    let data = batch.data_mut();
    let mut parts: [libc::iovec; RECV_SLOTS] = std::array::from_fn(|_| libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: GRO_ROOM,
    });
    let mut headers: [std::mem::MaybeUninit<libc::mmsghdr>; RECV_SLOTS] =
        std::array::from_fn(|_| std::mem::MaybeUninit::uninit());
    let room = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    for at in 0..RECV_SLOTS {
        parts[at].iov_base = data.slots[at].as_mut().as_mut_ptr().cast();
        headers[at].write(libc::mmsghdr {
            msg_hdr: libc::msghdr {
                msg_name: data.peers[at].as_mut_ptr().cast(),
                msg_namelen: room,
                msg_iov: (&raw mut parts[at]).cast(),
                msg_iovlen: 1,
                msg_control: data.controls[at].as_mut_ptr().cast(),
                msg_controllen: CONTROL_ROOM,
                msg_flags: 0,
            },
            msg_len: 0,
        });
    }
    // `MSG_WAITFORONE` returns on the first datagram that is there rather than waiting for the whole batch: the caller's deadline is the socket's own arm, and a batch that waited for eight would turn one slow packet into eight slow packets.
    //
    // The timeout is the socket's own arm and not the call's. The first receive of a batch runs without `MSG_DONTWAIT`, so it waits exactly as long as a `recvfrom` on this socket waits — which is the `SO_RCVTIMEO` the lane armed — and the reads behind it carry `MSG_DONTWAIT`, so they take what is already queued and answer at once. A call's own deadline would have been checked only between the reads, never against the first one.
    //
    // SAFETY: every header names a slot of `batch`, a peer of `batch` and a part of `parts`, all of which outlive the call, and the kernel writes each slot only as far as the datagram it read.
    let got = loop {
        let got = unsafe {
            libc::recvmmsg(
                sock.sock.as_raw_fd(),
                headers.as_mut_ptr().cast::<libc::mmsghdr>(),
                RECV_SLOTS as libc::c_uint,
                libc::MSG_WAITFORONE as _,
                std::ptr::null_mut(),
            )
        };
        if got >= 0 {
            break got;
        }
        // A queue with nothing in it is the socket's own arm expiring: the empty batch is that answer.
        let error = std::io::Error::last_os_error();
        data.used = 0;
        data.len = 0;
        match error.kind() {
            // A signal between the call and the queue took no datagram: the next call waits the rest of the arm.
            std::io::ErrorKind::Interrupted => {}
            std::io::ErrorKind::WouldBlock => break -1,
            // A failed read leaves a coalescing socket: a one-segment fallback would cut the next burst down to it.
            _ => return Drain::Unreadable,
        }
    };
    if got < 0 {
        return Drain::Empty;
    }
    if got == 0 {
        data.used = 0;
        data.len = 0;
        return Drain::Empty;
    }
    // A read that ran dry after some datagrams is the count, not the error: the kernel answers with what it took.
    let got = usize::try_from(got).unwrap_or(0).min(RECV_SLOTS);
    data.starts[0] = 0;
    for (at, header) in headers.iter().enumerate().take(got) {
        // SAFETY: `recvmmsg` wrote `msg_len` for every message it reported, and the name length is the one the kernel filled beside it.
        let header = unsafe { header.assume_init_ref() };
        let raw = usize::try_from(header.msg_len).unwrap_or(0);
        data.lens[at].write(header.msg_len);
        data.names[at].write(header.msg_hdr.msg_namelen);
        let seg = gro_segment(&header.msg_hdr, raw);
        data.segs[at] = seg;
        let count = if seg == 0 { 1 } else { raw.div_ceil(seg) };
        data.starts[at + 1] = data.starts[at] + count;
    }
    data.used = got;
    data.len = data.starts[got];
    Drain::Read
}

/// The segment size the kernel named for a coalesced read, or zero when the datagram is one packet.
#[cfg(target_os = "linux")]
fn gro_segment(header: &libc::msghdr, raw: usize) -> usize {
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(header) };
    while !cmsg.is_null() {
        // SAFETY: the kernel wrote each header the linked list names inside the control buffer the caller owns.
        let control = unsafe { &*cmsg };
        if control.cmsg_level == libc::SOL_UDP && control.cmsg_type == libc::UDP_GRO {
            // SAFETY: `CMSG_DATA` names the payload of a header the kernel wrote, and the length check below keeps the read inside it.
            let len = control
                .cmsg_len
                .saturating_sub(unsafe { libc::CMSG_LEN(0) } as usize);
            if len >= std::mem::size_of::<libc::c_int>() {
                let data = unsafe { libc::CMSG_DATA(cmsg) };
                let mut bytes = [0u8; std::mem::size_of::<libc::c_int>()];
                // SAFETY: the header's payload holds the `int` the kernel wrote, which `len` just checked.
                unsafe { std::ptr::copy_nonoverlapping(data, bytes.as_mut_ptr(), bytes.len()) };
                let seg = usize::try_from(libc::c_int::from_ne_bytes(bytes)).unwrap_or(0);
                if seg > 0 && seg <= raw {
                    return seg;
                }
            }
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(header, cmsg) };
    }
    0
}

/// A platform with no batched call has no batch: the read is one datagram at a time, and the lane says so.
#[cfg(not(target_os = "linux"))]
#[allow(
    dead_code,
    reason = "the batched read is Linux's, and the drain is the answer on the platforms that have one"
)]
pub(crate) fn recv_batch(_sock: &Datagram, _batch: &mut Batch) -> Drain {
    Drain::Unbatchable
}

/// The HTTP/3 opening, carried exactly once per connection: a second control stream is a connection error.
pub(crate) fn send_h3_opening(conn: &mut quiche::Connection, sock: &Datagram) -> bool {
    for (stream, payload) in crate::foxy::H3::h3_opening() {
        let mut rest = &payload[..];
        while !rest.is_empty() {
            match conn.stream_send(stream, rest, false) {
                Ok(0) | Err(_) => return false,
                Ok(wrote) => rest = &rest[wrote..],
            }
        }
    }
    flush_egress(conn, sock);
    true
}

/// The most datagrams one pump takes before it hands the connection back, so a busy socket cannot hold the lock from the other flows.
const PUMP_BURST: usize = 64;

/// How long a pump waits for a datagram once it has taken the one it came for: long enough to catch what is already in flight, far shorter than the caller's own deadline.
pub(crate) const PUMP_TAIL: Duration = Duration::from_millis(1);

pub(crate) fn pump_once(
    conn: &mut quiche::Connection,
    sock: &Datagram,
    local: SocketAddr,
    wait: Duration,
) -> bool {
    let timer = conn.timeout().map_or(wait, |left| left.min(wait));
    if !sock.refresh_read_timeout(timer.max(Duration::from_millis(1))) {
        return false;
    }
    let mut room = Unfilled::<RECV_ROOM>::new();
    let buf = room.as_mut();
    // One armed wait, then the queue already full behind it: a 16 KiB DATA frame is a dozen datagrams, and absorbing one per visit paid a timer set and an egress sweep for each.
    let mut taken = 0usize;
    // The batched read is Linux's, and only where the datagram is the datagram on the wire: a gecko fragment, a hop, an obfuscation or a relay frame all rewrite the bytes, so those lanes keep the one-datagram read.
    #[cfg(target_os = "linux")]
    let mut batch = Batch::new();
    loop {
        // The batch first: a socket with datagrams queued hands over all of them in one call, and the per-datagram read below then finds the queue empty.
        #[cfg(target_os = "linux")]
        match recv_batch(sock, &mut batch) {
            Drain::Read => {
                for at in 0..batch.len() {
                    let Some((bytes, from)) = batch.at(at) else {
                        continue;
                    };
                    let info = quiche::RecvInfo { from, to: local };
                    let _ = conn.recv(bytes, info);
                    taken += 1;
                }
                // Re-armed once the packets the visit waited for land: what follows is queued and costs no wait, or is not coming yet and the caller's deadline should wait for it; a failed re-arm leaves the first arm in place.
                if taken > 0 {
                    let _ = sock.refresh_read_timeout(PUMP_TAIL);
                }
                if taken >= PUMP_BURST {
                    break;
                }
                continue;
            }
            // An empty queue is the socket's own arm expiring, and the tick is what it owes the connection.
            Drain::Empty => {
                conn.on_timeout();
                flush_egress(conn, sock);
                return true;
            }
            Drain::Unbatchable => {}
            // A socket that coalesces must not be read one segment wide.
            Drain::Unreadable => return false,
        }
        match sock.recv_from(buf) {
            Ok((n, from)) => {
                let info = quiche::RecvInfo { from, to: local };
                let _ = conn.recv(&mut buf[..n], info);
                taken += 1;
                // Re-armed once the packet the visit waited for lands: what follows is queued and costs no wait, or is not coming yet and the caller's deadline should wait for it; a failed re-arm leaves the first arm in place.
                if taken == 1 {
                    let _ = sock.refresh_read_timeout(PUMP_TAIL);
                }
                if taken == PUMP_BURST {
                    break;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                conn.on_timeout();
                flush_egress(conn, sock);
                return true;
            }
            Err(_) => return false,
        }
    }
    flush_egress(conn, sock);
    true
}

pub(crate) fn drive_handshake(
    conn: &mut quiche::Connection,
    sock: &Datagram,
    local: SocketAddr,
) -> Option<()> {
    drive_handshake_by(conn, sock, local, HANDSHAKE_TIMEOUT)
}

/// The handshake loop under the caller's budget: only the deadline differs, and a probe chooses a smaller one.
pub(crate) fn drive_handshake_by(
    conn: &mut quiche::Connection,
    sock: &Datagram,
    local: SocketAddr,
    budget: Duration,
) -> Option<()> {
    drive_handshake_watching(conn, sock, local, budget, SILENT_HANDSHAKE)
}

/// The handshake loop with the silence floor named, so a test can watch a dead path be abandoned without waiting five seconds.
fn drive_handshake_watching(
    conn: &mut quiche::Connection,
    sock: &Datagram,
    local: SocketAddr,
    budget: Duration,
    silence: Duration,
) -> Option<()> {
    let start = Instant::now();
    let trace = crate::foxy::debug_on().then_some(start);
    let deadline = start + budget;
    let mut turns = 0u32;
    while !conn.is_established() {
        turns += 1;
        let now = Instant::now();
        if conn.is_closed() || now >= deadline {
            debug_handshake(trace, "died", turns, conn);
            return None;
        }
        let quiet = now.saturating_duration_since(start);
        // A path that drops QUIC answers no packet at all, so silence past the floor is the path rather than a slow handshake.
        if quiet >= silence && conn.stats().recv == 0 {
            debug_handshake(trace, "silent", turns, conn);
            return None;
        }
        flush_egress(conn, sock);
        let left = deadline.saturating_duration_since(Instant::now());
        // Cut the wait to the silence floor, so a dead path is abandoned on time rather than at the next backoff.
        if !pump_once(conn, sock, local, left.min(silence.saturating_sub(quiet))) {
            debug_handshake(trace, "socket", turns, conn);
            return None;
        }
    }
    debug_handshake(trace, "ok", turns, conn);
    Some(())
}

/// One handshake's shape behind `FOXY_DEBUG`: the seconds it took, the turns it waited in and the packets each way — the three numbers that tell a slow edge from a slow pump.
fn debug_handshake(trace: Option<Instant>, how: &str, turns: u32, conn: &quiche::Connection) {
    let Some(started) = trace else { return };
    let stats = conn.stats();
    eprintln!(
        "foxy-debug: quic hand {how} {}ms turns={turns} recv={} sent={}",
        started.elapsed().as_millis(),
        stats.recv,
        stats.sent,
    );
}

/// A cold lane's phases behind `FOXY_DEBUG`: the name lookup, the socket, the handshake and the opening settings the first flow pays and its successors ride past. An untraced build hands these `None`, so a lane that is not being read makes no clock call.
fn debug_pool(
    dial: &QuicDial,
    built: Option<Instant>,
    resolved: Option<Instant>,
    bound: Option<Instant>,
    handed: Option<Instant>,
) {
    let (Some(built), Some(resolved), Some(bound), Some(handed)) = (built, resolved, bound, handed)
    else {
        return;
    };
    eprintln!(
        "foxy-debug: quic pool {}:{} resolve={}ms bind={}ms hand={}ms opening={}ms",
        dial.address,
        dial.port,
        resolved.duration_since(built).as_millis(),
        bound.duration_since(resolved).as_millis(),
        handed.duration_since(bound).as_millis(),
        Instant::now().duration_since(handed).as_millis(),
    );
}

pub(crate) fn stream_send_all(
    conn: &mut quiche::Connection,
    sock: &Datagram,
    stream: u64,
    mut buf: &[u8],
    fin: bool,
    deadline: Instant,
) -> bool {
    while !buf.is_empty() || fin {
        match conn.stream_send(stream, buf, fin && buf.is_empty()) {
            Ok(written) => {
                buf = &buf[written..];
                if buf.is_empty() {
                    flush_egress(conn, sock);
                    return true;
                }
                if written == 0 && !send_credit_wait(conn, sock, deadline) {
                    return false;
                }
            }
            Err(quiche::Error::Done) => {
                if !send_credit_wait(conn, sock, deadline) {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
    flush_egress(conn, sock);
    true
}

/// Flush, then read the socket before retrying a blocked send: sleeping deaf to it leaves the peer's
/// `MAX_STREAM_DATA` unread, so a send past the initial flow window never resumes.
fn send_credit_wait(conn: &mut quiche::Connection, sock: &Datagram, deadline: Instant) -> bool {
    flush_egress(conn, sock);
    if Instant::now() >= deadline {
        return false;
    }
    let Ok(local) = sock.local_addr() else {
        return false;
    };
    let left = deadline.saturating_duration_since(Instant::now());
    pump_once(conn, sock, local, left)
}

/// A send on a lane whose pump owns the socket: the caller never reads it, so a blocked send waits for the pump's ACK instead of stealing its datagram.
fn stream_send_all_parked(
    shared: &Mutex<quiche::Connection>,
    sock: &Datagram,
    stream: u64,
    mut buf: &[u8],
    fin: bool,
    deadline: Instant,
) -> bool {
    while !buf.is_empty() || fin {
        let outcome = {
            let Ok(mut conn) = shared.lock() else {
                return false;
            };
            if conn.is_closed() {
                return false;
            }
            match conn.stream_send(stream, buf, fin && buf.is_empty()) {
                Ok(written) => {
                    flush_egress(&mut conn, sock);
                    Some(written)
                }
                Err(quiche::Error::Done) => None,
                Err(_) => return false,
            }
        };
        match outcome {
            Some(written) => {
                buf = &buf[written..];
                if buf.is_empty() {
                    return true;
                }
                if written > 0 {
                    continue;
                }
            }
            None if buf.is_empty() && !fin => return true,
            None => {}
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(STREAM_POLL);
    }
    true
}

/// The receive half of `stream_send_all_parked`: the pump feeds the connection, so the waiter polls it without reading the socket.
fn stream_recv_exact_parked(
    shared: &Mutex<quiche::Connection>,
    stream: u64,
    want: usize,
    deadline: Instant,
) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(want);
    let mut chunk = [0u8; 8192];
    while out.len() < want {
        let end = (want - out.len()).min(chunk.len());
        let found = {
            let Ok(mut conn) = shared.lock() else {
                return None;
            };
            if conn.is_closed() {
                return None;
            }
            match conn.stream_recv(stream, &mut chunk[..end]) {
                Ok((0, _)) | Err(quiche::Error::Done) => None,
                Ok(found) => Some(found),
                Err(_) => return None,
            }
        };
        if let Some((n, fin)) = found {
            out.extend_from_slice(&chunk[..n]);
            if fin {
                break;
            }
        } else if Instant::now() >= deadline {
            return None;
        } else {
            std::thread::sleep(STREAM_POLL);
        }
    }
    (out.len() == want).then_some(out)
}

pub(crate) fn stream_recv_exact(
    conn: &mut quiche::Connection,
    sock: &Datagram,
    local: SocketAddr,
    stream: u64,
    want: usize,
    deadline: Instant,
) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(want);
    let mut chunk = [0u8; 8192];
    while out.len() < want {
        let end = (want - out.len()).min(chunk.len());
        match conn.stream_recv(stream, &mut chunk[..end]) {
            Ok((0, _)) | Err(quiche::Error::Done) => {
                if conn.is_closed() || Instant::now() >= deadline {
                    return None;
                }
                let left = deadline.saturating_duration_since(Instant::now());
                if !pump_once(conn, sock, local, left) {
                    return None;
                }
            }
            Ok((n, fin)) => {
                out.extend_from_slice(&chunk[..n]);
                if fin {
                    break;
                }
            }
            Err(_) => return None,
        }
    }
    (out.len() == want).then_some(out)
}

/// Platform CA bundle fallback layouts; an empty root store is trust-nothing, not "trust the platform".
const BUNDLES: [&str; 10] = [
    "/etc/ssl/cert.pem",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/opt/homebrew/etc/ca-certificates/cert.pem",
    "/usr/local/etc/ca-certificates/cert.pem",
    "C:/Program Files/Git/mingw64/ssl/certs/ca-bundle.crt",
    "C:/Program Files/Git/usr/ssl/certs/ca-bundle.crt",
    "C:/msys64/mingw64/ssl/certs/ca-bundle.crt",
    "C:/msys64/usr/ssl/certs/ca-bundle.crt",
];

pub(crate) fn system_roots() -> ferrox_core::tls::Anchors {
    // Read once for the process: the platform store is not a per-flow input, and every dial that asked for it was paying a walk of the filesystem and a copy of every certificate in it.
    static READ_ONCE: OnceLock<ferrox_core::tls::Anchors> = OnceLock::new();
    Arc::clone(READ_ONCE.get_or_init(|| Arc::from(platform_roots())))
}

fn platform_roots() -> Vec<Vec<u8>> {
    // Platform store first: macOS bundle files hold a handful of roots, so bundle-first answers unknown issuer.
    let native = rustls_native_certs::load_native_certs();
    let roots: Vec<Vec<u8>> = native
        .certs
        .into_iter()
        .map(|cert| cert.to_vec())
        .filter(|der| !der.is_empty())
        .collect();
    if !roots.is_empty() {
        return roots;
    }
    if let Ok(path) = std::env::var("SSL_CERT_FILE") {
        if let Ok(pem) = std::fs::read(&path) {
            let roots = parse_ca_pem(&pem);
            if !roots.is_empty() {
                return roots;
            }
        }
    }
    for path in BUNDLES {
        if let Ok(pem) = std::fs::read(path) {
            let roots = parse_ca_pem(&pem);
            if !roots.is_empty() {
                return roots;
            }
        }
    }
    // Android keeps one file per CA under this directory rather than a bundle; PEM or DER halves are accepted.
    if let Ok(entries) = std::fs::read_dir("/system/etc/security/cacerts") {
        let mut roots = Vec::new();
        for entry in entries.flatten() {
            let Ok(bytes) = std::fs::read(entry.path()) else {
                continue;
            };
            if bytes.starts_with(b"-----BEGIN") {
                roots.extend(parse_ca_pem(&bytes));
            } else if !bytes.is_empty() {
                roots.push(bytes);
            }
        }
        if !roots.is_empty() {
            return roots;
        }
    }
    Vec::new()
}

/// A socket that accepts the kernel's coalesced datagrams: Linux hands a GSO burst back as one buffer and names
/// the segment size in a `UDP_GRO` control message, so the batch splits it before quiche sees a packet. Every lane
/// asks for a receive buffer before a first datagram can land on it.
pub(crate) fn bind_datagram(address: &str) -> std::io::Result<UdpSocket> {
    bind_datagram_gro(address, true)
}

/// A socket for a lane that reads one datagram per `recv_from`: GRO stays off, because a
/// coalesced burst would be truncated to the caller's buffer.
pub(crate) fn bind_datagram_plain(address: &str) -> std::io::Result<UdpSocket> {
    bind_datagram_gro(address, false)
}

/// Bind a datagram socket with a lane's buffers, coalescing only when the lane can read a coalesced datagram.
fn bind_datagram_gro(address: &str, gro: bool) -> std::io::Result<UdpSocket> {
    let sock = UdpSocket::bind(address)?;
    #[cfg(target_os = "linux")]
    if gro {
        set_gro(&sock, true);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = gro;
    set_receive_buffer(&sock, DATAGRAM_BUFFER);
    set_send_buffer(&sock, DATAGRAM_BUFFER);
    Ok(sock)
}

#[cfg(target_os = "linux")]
fn set_gro(sock: &UdpSocket, on: bool) {
    use std::os::fd::AsRawFd as _;
    let value: libc::c_int = libc::c_int::from(on);
    // SAFETY: `value` outlives the call, and the size is its own.
    unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_UDP,
            libc::UDP_GRO,
            std::ptr::addr_of!(value).cast(),
            libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())
                .unwrap_or(libc::socklen_t::MAX),
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn set_gro(_sock: &UdpSocket, _on: bool) {}

fn clear_gro(sock: &UdpSocket) {
    set_gro(sock, false);
}

/// The buffer a lane's socket asks for, in each direction: the edge is granted a whole stream window of
/// datagrams at once (`MAX_STREAM_DATA`), so a socket holding a few of them turns every pause in the pump into
/// loss the lane pays for in retransmit timers rather than in packets. The send side is the same number for the
/// mirror reason: quiche hands the socket a burst of a window's worth of datagrams and a `send_to` the kernel
/// cannot queue is a datagram quiche has already counted as sent.
const DATAGRAM_BUFFER: i32 = 1 << 20;

/// The least the ask has to land as for the lane to be worth reading back: a Linux default already clears it, a macOS and a Windows default do not, which is where the arm is observable.
#[cfg(test)]
const DATAGRAM_RECV_BUF_FLOOR: i32 = 1 << 18;

/// Ask the socket for `bytes` of a buffer; a platform that caps the ask hands back what it granted.
#[cfg(unix)]
fn set_buffer(sock: &UdpSocket, option: libc::c_int, bytes: i32) {
    use std::os::fd::AsRawFd as _;
    // SAFETY: `bytes` outlives the call, and the size is its own.
    unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            std::ptr::addr_of!(bytes).cast(),
            libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())
                .unwrap_or(libc::socklen_t::MAX),
        );
    }
}

#[cfg(unix)]
fn set_receive_buffer(sock: &UdpSocket, bytes: i32) {
    set_buffer(sock, libc::SO_RCVBUF, bytes);
}

/// A macOS socket's send buffer defaults to a few kilobytes, so a burst quiche has already declared sent is refused
/// by the kernel and lost: the lane asks for the same buffer in both directions and lets the kernel cap it.
#[cfg(unix)]
fn set_send_buffer(sock: &UdpSocket, bytes: i32) {
    set_buffer(sock, libc::SO_SNDBUF, bytes);
}

/// What the socket actually holds, as the kernel reports it.
#[cfg(all(test, unix))]
fn get_buffer(sock: &UdpSocket, option: libc::c_int) -> i32 {
    use std::os::fd::AsRawFd as _;
    let mut got: libc::c_int = 0;
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())
        .unwrap_or(libc::socklen_t::MAX);
    // SAFETY: `got` and `len` are the buffer and the length the kernel writes through.
    let ok = unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            std::ptr::addr_of_mut!(got).cast(),
            std::ptr::addr_of_mut!(len),
        )
    };
    if ok == 0 {
        got
    } else {
        0
    }
}

#[cfg(all(test, unix))]
fn receive_buffer(sock: &UdpSocket) -> i32 {
    get_buffer(sock, libc::SO_RCVBUF)
}

#[cfg(all(test, unix))]
fn send_buffer(sock: &UdpSocket) -> i32 {
    get_buffer(sock, libc::SO_SNDBUF)
}

/// Ask the socket for `bytes` of a buffer; a platform that caps the ask hands back what it granted.
#[cfg(windows)]
fn set_buffer(sock: &UdpSocket, option: i32, bytes: i32) {
    use std::os::windows::io::AsRawSocket as _;
    use windows_sys::Win32::Networking::WinSock::setsockopt;
    // SAFETY: `bytes` outlives the call, the handle is the socket's own, and the length is that of the value pointed at.
    unsafe {
        setsockopt(
            sock.as_raw_socket() as usize,
            windows_sys::Win32::Networking::WinSock::SOL_SOCKET,
            option,
            std::ptr::addr_of!(bytes).cast(),
            i32::try_from(std::mem::size_of::<i32>()).unwrap_or(i32::MAX),
        );
    }
}

#[cfg(windows)]
fn set_receive_buffer(sock: &UdpSocket, bytes: i32) {
    set_buffer(
        sock,
        windows_sys::Win32::Networking::WinSock::SO_RCVBUF,
        bytes,
    );
}

#[cfg(all(test, windows))]
fn receive_buffer(sock: &UdpSocket) -> i32 {
    get_buffer(sock, windows_sys::Win32::Networking::WinSock::SO_RCVBUF)
}

#[cfg(all(test, windows))]
fn send_buffer(sock: &UdpSocket) -> i32 {
    get_buffer(sock, windows_sys::Win32::Networking::WinSock::SO_SNDBUF)
}

#[cfg(windows)]
fn set_send_buffer(sock: &UdpSocket, bytes: i32) {
    set_buffer(
        sock,
        windows_sys::Win32::Networking::WinSock::SO_SNDBUF,
        bytes,
    );
}

/// What the socket actually holds, as the kernel reports it.
#[cfg(all(test, windows))]
fn get_buffer(sock: &UdpSocket, option: i32) -> i32 {
    use std::os::windows::io::AsRawSocket as _;
    use windows_sys::Win32::Networking::WinSock::{getsockopt, SOL_SOCKET};
    let mut got: i32 = 0;
    let mut len = i32::try_from(std::mem::size_of::<i32>()).unwrap_or(i32::MAX);
    // SAFETY: `got` and `len` are the buffer and the length the kernel writes through, on the socket's own handle.
    let ok = unsafe {
        getsockopt(
            sock.as_raw_socket() as usize,
            SOL_SOCKET,
            option,
            std::ptr::addr_of_mut!(got).cast(),
            std::ptr::addr_of_mut!(len),
        )
    };
    if ok == 0 {
        got
    } else {
        0
    }
}

/// What a datagram socket is armed to wait for: `Some(None)` blocks forever, `Some(Some(d))` waits `d`, and `None` records no arm yet.
type Arm = Option<Option<Duration>>;

/// The datagram masks this tree carries: Hysteria v2's salamander/gecko key and Hysteria v1's xplus key.
#[derive(Clone)]
pub(crate) enum Mask {
    Salamander(ferrox_core::hysteria::Salamander),
    XPlus(ferrox_core::hysteria_v1::XPlus),
}

impl Mask {
    fn seal_into(&self, plain: &[u8], out: &mut [u8]) -> Option<usize> {
        match self {
            Self::Salamander(mask) => mask.seal_into(plain, out),
            Self::XPlus(mask) => mask.seal_into(plain, out),
        }
    }

    fn deobfuscate_in_place(&self, datagram: &mut [u8]) -> Option<usize> {
        match self {
            Self::Salamander(mask) => mask.deobfuscate_in_place(datagram),
            Self::XPlus(mask) => mask.deobfuscate_in_place(datagram),
        }
    }
}

/// One datagram socket: a relay or an obfuscation below changes no handshake, frame or stream above, so the hops live here.
pub(crate) struct Datagram {
    sock: UdpSocket,
    relay: Option<Relay>,
    obfs: Option<Mask>,
    /// A hopped client dial: the server port moves on a schedule and the socket
    /// with it, so a UDP flow keeps ending and a new one starting to a filter.
    /// Shared behind an `Arc` so a writer clone and a reader clone move together.
    hop: Option<Arc<Hopper>>,
    /// A `obfs: gecko` client dial: long-header packets are fragmented and padded on
    /// the way out and reassembled on the way in, masking still salamander's. Shared
    /// behind an `Arc` so the reassembly table and message counter are one owner.
    gecko: Option<Arc<Gecko>>,
    /// The read wait this file description carries, shared behind an `Arc` because
    /// `SO_RCVTIMEO` belongs to the socket and not the handle: a wait remembered per
    /// holder lets the next read by another holder skip an arm the first one undid.
    armed: Arc<Mutex<Arm>>,
    /// The datagrams a full peer queue refused, retried before the next sweep.
    /// Shared behind an `Arc` because a clone describes the same file description
    /// and the same peer, and a datagram one clone holds must be retried by both.
    held: Arc<Held>,
}

/// The datagrams the kernel refused that a later sweep retries, in the order quiche
/// wrote them: a QUIC DATAGRAM frame is never retransmitted, so a dropped write is an
/// inner TCP hole only a retransmit timer repairs. `holding` gates the lock, so the
/// path that never refuses pays one atomic load.
#[derive(Default)]
struct Held {
    queue: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
    holding: AtomicBool,
}

/// The most datagrams one lane holds for a peer that is not reading: the queue is
/// drained by the next sweep, so a peer this far behind is not coming back.
const HELD_LIMIT: usize = 256;

/// A write the kernel refused for a reason that clears: a non-blocking socket with a
/// full path, or a full queue on the far side. Any other error is the path ending.
fn refused(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
    ) || error.raw_os_error() == Some(libc::ENOBUFS)
}

/// Where datagrams go. The association's control connection is held, never read: dropping it ends it.
#[derive(Clone)]
struct Relay {
    via: SocketAddr,
    _control: Arc<Connection>,
}

/// The most one datagram costs in headers: two reserved bytes, one flag byte, the longest address and the port.
const RELAY_HEADER: usize = 22;

/// One obfuscated datagram is a salt ahead of the QUIC packet it masks, so the wire frame is the widest salt wider than the largest plain datagram.
const SALAMANDER_SALT: usize = ferrox_core::hysteria_v1::XPLUS_SALT;

/// The widest frame a masked lane reads: the largest datagram plus the salt in front of it. A receive room this wide unmasks where the wire bytes landed; a narrower one reads into a scratch a salt wider and copies the plaintext back.
pub(crate) const RECV_ROOM: usize = MAX_DATAGRAM + SALAMANDER_SALT;

/// Read one datagram and unmask it where it landed when the caller's room holds the salt too, so no second buffer carries the plaintext.
fn masked_read(
    read: impl FnOnce(&mut [u8]) -> std::io::Result<(usize, SocketAddr)>,
    buf: &mut [u8],
    obfs: &Mask,
) -> std::io::Result<(usize, SocketAddr)> {
    if let Some(room) = buf.get_mut(..RECV_ROOM) {
        let (found, from) = read(room)?;
        return obfs
            .deobfuscate_in_place(&mut room[..found])
            .map(|plain| (plain, from))
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData));
    }
    let mut room = Unfilled::<RECV_ROOM>::new();
    let (found, from) = read(room.as_mut())?;
    let plain = obfs
        .deobfuscate_in_place(&mut room.as_mut()[..found])
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
    let out = buf
        .get_mut(..plain)
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    out.copy_from_slice(&room.as_mut()[..plain]);
    Ok((plain, from))
}

/// How long a socket the schedule just left stays readable, so a reply still in
/// flight on the old flow is not lost the instant the port moves. The reference
/// lingers the same ten seconds; a datagram that misses both windows is a real loss.
const HOP_LINGER: u64 = 10_000;

/// How many sockets a move may leave readable behind itself. A gecko reply splits
/// into at most eight datagrams and reading each one can move the schedule again, so
/// sixteen outlives every fragment of one reply while a zero stay stays bounded.
const HOP_LINGER_SOCKETS: usize = 16;

/// The moving part of a hopped dial: the socket the current stay reads and writes
/// through, the server port it is aimed at, when the stay ends, and — until their
/// linger expires — the sockets earlier stays left, still read for their replies. A
/// reply may split across datagrams, and each read of one moves the schedule, so one
/// previous socket is not enough to drain it.
struct HopState {
    current: Arc<UdpSocket>,
    port: u16,
    until: Instant,
    linger: Vec<(Arc<UdpSocket>, Instant)>,
}

/// A client datagram socket that moves its server destination port among `ports`
/// every `interval_ms`, binding a fresh local socket on each move so a filter sees a
/// new flow rather than one long-lived one. Only the server's own port moves: a
/// datagram addressed elsewhere passes through on the same flow. A reply from any
/// hopped port is turned back to the nominal `server` port so QUIC above, which
/// named the connection by one peer, keeps accepting it. The rotation and the stay
/// come from the core's pure `pick_next`/`stay_ms`, fed one rng roll each, so nothing
/// here is left to prove by reading.
pub(crate) struct Hopper {
    server: SocketAddr,
    ports: Vec<u16>,
    interval_ms: (u64, u64),
    bind: &'static str,
    /// The socket the dial opened with, kept so a poisoned schedule lock — unreachable
    /// while the guarded sections panic-free — can still carry a fixed flow.
    anchor: Arc<UdpSocket>,
    timeout: Mutex<Option<Duration>>,
    state: Mutex<HopState>,
}

/// One 64-bit draw folded into the core's pure pick and stay. A failure yields 0,
/// which still names a valid port and stay, so the hop degrades to a fixed schedule
/// rather than failing the dial outright.
fn entropy() -> u64 {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_or(0, |()| u64::from_le_bytes(bytes))
}

impl Hopper {
    /// Begin a plan from `first`, the socket the dial opened to the nominal port: its
    /// clone is the first current socket, so a handshake named for `server` can finish
    /// before the schedule ever moves. The port and stay are drawn up front.
    fn open(
        server: SocketAddr,
        mut ports: Vec<u16>,
        interval_ms: (u64, u64),
        bind: &'static str,
        first: &UdpSocket,
    ) -> std::io::Result<Self> {
        ports.sort_unstable();
        ports.dedup();
        let anchor = Arc::new(first.try_clone()?);
        let current = Arc::clone(&anchor);
        let port = ferrox_core::hysteria::pick_next(&ports, server.port(), entropy() as usize);
        let until = Instant::now()
            + Duration::from_millis(ferrox_core::hysteria::stay_ms(interval_ms, entropy()));
        Ok(Self {
            server,
            ports,
            interval_ms,
            bind,
            timeout: Mutex::new(None),
            anchor,
            state: Mutex::new(HopState {
                current,
                port,
                until,
                linger: Vec::new(),
            }),
        })
    }

    /// Stamp the dial's current read timeout onto a freshly bound socket, so a
    /// timeout set before a rotation still bites the socket bound in between.
    fn apply_timeout(&self, sock: &UdpSocket) {
        if let Ok(timeout) = self.timeout.lock() {
            let _ = sock.set_read_timeout(*timeout);
        }
    }

    /// The socket and server port for now, moving the schedule first when the current
    /// stay has run out: a fresh socket is bound and the old one kept until its linger
    /// expires, a new port picked and a new stay armed. A bind failure keeps the
    /// current socket rather than stalling the flow, but still repicks and re-arms so
    /// the next attempt moves on. Called on both send and receive, so one clock drives
    /// the whole connection.
    fn current(&self) -> (Arc<UdpSocket>, u16) {
        let Ok(mut state) = self.state.lock() else {
            return (Arc::clone(&self.anchor), self.server.port());
        };
        let now = Instant::now();
        if now >= state.until {
            let port =
                ferrox_core::hysteria::pick_next(&self.ports, state.port, entropy() as usize);
            let stay =
                Duration::from_millis(ferrox_core::hysteria::stay_ms(self.interval_ms, entropy()));
            if let Ok(sock) = bind_datagram_plain(self.bind) {
                self.apply_timeout(&sock);
                let linger = now + Duration::from_millis(HOP_LINGER);
                let left = std::mem::replace(&mut state.current, Arc::new(sock));
                let _ = left.set_nonblocking(true);
                state.linger.retain(|(_, until)| *until > now);
                if state.linger.len() >= HOP_LINGER_SOCKETS {
                    state.linger.remove(0);
                }
                state.linger.push((left, linger));
            }
            state.port = port;
            state.until = now + stay;
        }
        (Arc::clone(&state.current), state.port)
    }

    /// The socket and destination for a datagram aimed at `to`: only the server's own
    /// port moves, so a datagram to any other target keeps its address and the flow.
    fn egress(&self, to: SocketAddr) -> (Arc<UdpSocket>, SocketAddr) {
        let (sock, port) = self.current();
        if to != self.server || port == self.server.port() {
            return (sock, to);
        }
        let mut dest = self.server;
        dest.set_port(port);
        (sock, dest)
    }

    /// Write one datagram on the current flow, salting it first when obfuscated. Only
    /// the server's own datagram has its port rewritten; anything else is passed on.
    fn send(&self, buf: &[u8], to: SocketAddr, obfs: Option<&Mask>) -> std::io::Result<usize> {
        let (sock, dest) = self.egress(to);
        let Some(obfs) = obfs else {
            return sock.send_to(buf, dest);
        };
        let mut wire = Unfilled::<{ MAX_DATAGRAM + SALAMANDER_SALT }>::new();
        let sealed = obfs
            .seal_into(buf, wire.as_mut())
            .ok_or(std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        sock.send_to(&wire.as_mut()[..sealed], dest)
    }

    /// Read one datagram, advancing the schedule first so a reader sees the same
    /// rotation a writer would and the sockets just left still linger. The current
    /// flow is tried, then every socket a move left behind, newest first, until one
    /// answers; a hopped reply source is turned back to the nominal server port. The
    /// lingering sockets are read non-blocking, so a dry sweep costs no wait and only
    /// the current flow is waited on, once. Its dry read is the same `WouldBlock` a
    /// plain socket returns, so the drive loop keeps its no-packet path.
    fn recv(&self, buf: &mut [u8], obfs: Option<&Mask>) -> std::io::Result<(usize, SocketAddr)> {
        let (current, _) = self.current();
        let lingering: Vec<Arc<UdpSocket>> = match self.state.lock() {
            Ok(mut state) => {
                let now = Instant::now();
                state.linger.retain(|(_, until)| *until > now);
                state
                    .linger
                    .iter()
                    .rev()
                    .map(|(sock, _)| Arc::clone(sock))
                    .collect()
            }
            Err(_) => Vec::new(),
        };
        for sock in std::iter::once(current).chain(lingering) {
            match Self::read_into(&sock, buf, obfs) {
                Ok((found, mut from)) => {
                    if from.ip() == self.server.ip()
                        && ferrox_core::hysteria::is_hop_port(
                            &self.ports,
                            self.server.port(),
                            from.port(),
                        )
                    {
                        from.set_port(self.server.port());
                    }
                    return Ok((found, from));
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
    }

    /// Read one datagram off `sock`, unmasking it into the caller's buffer when the
    /// lane is obfuscated.
    fn read_into(
        sock: &UdpSocket,
        buf: &mut [u8],
        obfs: Option<&Mask>,
    ) -> std::io::Result<(usize, SocketAddr)> {
        let Some(obfs) = obfs else {
            return sock.recv_from(buf);
        };
        masked_read(|room| sock.recv_from(room), buf, obfs)
    }

    /// The current flow's address, read without moving the schedule.
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        let Ok(state) = self.state.lock() else {
            return self.anchor.local_addr();
        };
        state.current.local_addr()
    }

    /// Record the timeout for sockets bound by later moves, and stamp it on the one
    /// reads will use now.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        if let Ok(mut applied) = self.timeout.lock() {
            *applied = timeout;
        }
        let Ok(state) = self.state.lock() else {
            return Ok(());
        };
        state.current.set_read_timeout(timeout)
    }
}

/// How long one half-reassembled gecko message may sit before a reader drops it, and
/// how many the socket will hold in total and per source. The reference gives these
/// the same numbers; a message that outlives its ttl is a real loss, not a leak.
const GECKO_TTL: Duration = Duration::from_secs(8);
const GECKO_MAX_MESSAGES: usize = 4096;
const GECKO_MAX_PER_SOURCE: usize = 8;
/// The largest frame the `obfs: gecko` window sizes against, so the stack scratch a
/// fragment is built in is big enough for any padded frame the plan can ask for.
const GECKO_BUFFER: usize = ferrox_core::hysteria::Gecko::MAX_BUFFER as usize;

/// One message mid-reassembly: its chunk count, the payloads landed so far indexed
/// by chunk, and when it expires.
struct GeckoMessage {
    chunks: Vec<Option<Vec<u8>>>,
    total: usize,
    received: usize,
    until: Instant,
}

/// A `obfs: gecko` datagram socket: salamander-masks every datagram, and on a QUIC
/// long-header write splits it into `2..=8` padded frames sent as separate datagrams,
/// reassembling them on read keyed by `(peer, message id)`. A short-header packet is
/// masked whole and passes through, so only the handshake Initial is fragmented — the
/// stream and datagram lanes above see one packet in, one packet out, exactly as an
/// unobfuscated dial. The chunk count, pad length and message id are drawn here from
/// the core's pure `gecko_pad_len`/`gecko_chunk_range`, so the frame bytes stay a
/// bit-tested construction while only the randomisation lives beside the socket.
/// Expiry is swept lazily on the reader rather than by a background timer thread.
pub(crate) struct Gecko {
    sock: UdpSocket,
    hop: Option<Arc<Hopper>>,
    obfs: ferrox_core::hysteria::Salamander,
    min: usize,
    max: usize,
    msg: AtomicU64,
    reassembly: Mutex<HashMap<(IpAddr, u8), GeckoMessage>>,
}

impl Gecko {
    fn new(
        sock: UdpSocket,
        obfs: ferrox_core::hysteria::Salamander,
        window: ferrox_core::hysteria::Gecko,
    ) -> Self {
        Self {
            sock,
            hop: None,
            obfs,
            min: usize::from(window.min_pkt),
            max: usize::from(window.max_pkt),
            msg: AtomicU64::new(0),
            reassembly: Mutex::new(HashMap::new()),
        }
    }

    /// A gecko lane whose every frame leaves through the hop's current socket, so port-hopping and the fragmenting mask ride one dial.
    fn hopped(
        obfs: ferrox_core::hysteria::Salamander,
        window: ferrox_core::hysteria::Gecko,
        hop: Arc<Hopper>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            sock: hop.anchor.try_clone()?,
            hop: Some(hop),
            obfs,
            min: usize::from(window.min_pkt),
            max: usize::from(window.max_pkt),
            msg: AtomicU64::new(0),
            reassembly: Mutex::new(HashMap::new()),
        })
    }

    /// Write one wire datagram through the hop when this lane has one, else straight out of the socket it was built on.
    fn send_wire(&self, buf: &[u8], to: SocketAddr) -> std::io::Result<usize> {
        match self.hop.as_ref() {
            Some(hop) => hop.send(buf, to, None),
            None => self.sock.send_to(buf, to),
        }
    }

    /// Read one wire datagram from the hop's current (and lingering) sockets, else from the fixed one.
    fn recv_wire(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        match self.hop.as_ref() {
            Some(hop) => hop.recv(buf, None),
            None => self.sock.recv_from(buf),
        }
    }

    /// Seal one masked datagram and write it, returning the plain bytes consumed.
    fn send_masked(&self, buf: &[u8], to: SocketAddr) -> std::io::Result<usize> {
        let mut wire = Unfilled::<{ MAX_DATAGRAM + SALAMANDER_SALT }>::new();
        let sealed = self
            .obfs
            .seal_into(buf, wire.as_mut())
            .ok_or(invalid(std::io::ErrorKind::InvalidInput))?;
        self.send_wire(&wire.as_mut()[..sealed], to)
    }

    /// Split a long-header packet into `2..=8` chunks, each framed, padded to the
    /// window and masked as its own datagram. The message id is one draw for the whole
    /// packet; the chunk count and each pad are drawn per write.
    fn send_fragmented(&self, buf: &[u8], to: SocketAddr) -> std::io::Result<usize> {
        let total = ferrox_core::hysteria::GECKO_MIN_CHUNKS
            + (entropy()
                % (ferrox_core::hysteria::GECKO_MAX_CHUNKS
                    - ferrox_core::hysteria::GECKO_MIN_CHUNKS
                    + 1) as u64) as usize;
        let msg_id = self.msg.fetch_add(1, Ordering::Relaxed) as u8;
        let mut pad = [0u8; GECKO_BUFFER];
        let mut frame = Unfilled::<GECKO_BUFFER>::new();
        let mut wire = Unfilled::<{ GECKO_BUFFER + SALAMANDER_SALT }>::new();
        for idx in 0..total {
            let (start, end) = ferrox_core::hysteria::gecko_chunk_range(buf.len(), idx, total)
                .ok_or(invalid(std::io::ErrorKind::InvalidInput))?;
            let chunk = &buf[start..end];
            let base = ferrox_core::hysteria::SALAMANDER_SALT
                + ferrox_core::hysteria::GECKO_HEADER
                + chunk.len();
            let pad_len = usize::from(ferrox_core::hysteria::gecko_pad_len(
                self.min,
                self.max,
                base,
                entropy(),
            ));
            if pad_len > 0 {
                // Padding is the point of the lane; a failed draw leaves zeros, which salamander still masks to noise.
                let _ = getrandom::fill(&mut pad[..pad_len]);
            }
            let written = ferrox_core::hysteria::encode_gecko_frame(
                ferrox_core::hysteria::GeckoFrame {
                    msg_id,
                    chunk_idx: idx as u8,
                    total_chunks: total as u8,
                    pad_len: pad_len as u16,
                },
                &pad[..pad_len],
                chunk,
                frame.as_mut(),
            )
            .ok_or(invalid(std::io::ErrorKind::InvalidInput))?;
            let sealed = self
                .obfs
                .seal_into(&frame.as_mut()[..written], wire.as_mut())
                .ok_or(invalid(std::io::ErrorKind::InvalidInput))?;
            self.send_wire(&wire.as_mut()[..sealed], to)?;
        }
        Ok(buf.len())
    }

    fn send(&self, buf: &[u8], to: SocketAddr) -> std::io::Result<usize> {
        if buf
            .first()
            .is_some_and(|b| b & ferrox_core::hysteria::GECKO_FLAG != 0)
        {
            return self.send_fragmented(buf, to);
        }
        self.send_masked(buf, to)
    }

    /// Land one frame's payload and return the whole message once every chunk has
    /// arrived. A duplicate, an inconsistent count, an out-of-range index or a source
    /// or global cap already reached all drop the chunk rather than growing state.
    fn accept(
        &self,
        from: SocketAddr,
        frame: ferrox_core::hysteria::GeckoFrame,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        let total = usize::from(frame.total_chunks);
        let index = usize::from(frame.chunk_idx);
        // Keyed by address, not address-and-port: a hop opens a fresh socket per stay, so one split message can arrive from several source ports.
        let key = (from.ip(), frame.msg_id);
        let now = Instant::now();
        let mut table = self.reassembly.lock().ok()?;
        table.retain(|_, message| message.until > now);
        if !table.contains_key(&key) {
            if table.len() >= GECKO_MAX_MESSAGES {
                return None;
            }
            if table.keys().filter(|(source, _)| *source == key.0).count() >= GECKO_MAX_PER_SOURCE {
                return None;
            }
            table.insert(
                key,
                GeckoMessage {
                    chunks: vec![None; total],
                    total,
                    received: 0,
                    until: now + GECKO_TTL,
                },
            );
        }
        let message = table.get_mut(&key)?;
        if message.total != total || index >= total || message.chunks[index].is_some() {
            return None;
        }
        message.chunks[index] = Some(payload.to_vec());
        message.received += 1;
        if message.received < total {
            return None;
        }
        let mut out = Vec::with_capacity(payload.len() * total);
        for chunk in &mut message.chunks {
            out.extend(chunk.take().unwrap_or_default());
        }
        table.remove(&key);
        Some(out)
    }

    /// Read frames until a whole message assembles or the socket runs dry, so one call
    /// consumes every datagram currently waiting — the reference reader's shape. A
    /// short-header packet is handed straight up; an empty socket is the same
    /// `WouldBlock` a plain read gives, so the drive loop keeps its no-packet path.
    fn recv(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        loop {
            let mut wire = Unfilled::<{ GECKO_BUFFER + SALAMANDER_SALT }>::new();
            let (found, from) = match self.recv_wire(wire.as_mut()) {
                Ok(read) => read,
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
                }
                Err(err) => return Err(err),
            };
            let Some(plain) = self
                .obfs
                .deobfuscate_in_place(&mut wire.as_mut()[..found])
                .map(|len| &wire.as_mut()[..len])
            else {
                return Err(invalid(std::io::ErrorKind::InvalidData));
            };
            if plain
                .first()
                .is_none_or(|b| b & ferrox_core::hysteria::GECKO_FLAG == 0)
            {
                let Some(out) = buf.get_mut(..plain.len()) else {
                    return Err(invalid(std::io::ErrorKind::InvalidInput));
                };
                out.copy_from_slice(plain);
                return Ok((plain.len(), from));
            }
            let Some((frame, payload)) = ferrox_core::hysteria::decode_gecko_frame(plain) else {
                // A malformed frame is dropped, exactly as the reference reader does.
                continue;
            };
            let Some(message) = self.accept(from, frame, payload) else {
                continue;
            };
            let Some(out) = buf.get_mut(..message.len()) else {
                return Err(invalid(std::io::ErrorKind::InvalidInput));
            };
            out.copy_from_slice(&message);
            return Ok((message.len(), from));
        }
    }
}

/// An `io::Error` of the given kind, the shape the datagram lane already returns.
fn invalid(kind: std::io::ErrorKind) -> std::io::Error {
    std::io::Error::from(kind)
}

impl Datagram {
    pub(crate) fn plain(sock: UdpSocket) -> Self {
        Self {
            sock,
            relay: None,
            obfs: None,
            hop: None,
            gecko: None,
            armed: Arc::default(),
            held: Arc::default(),
        }
    }

    /// A socket whose every datagram is salamander-masked under `obfs`, the Hysteria v2 `obfs: salamander` lane.
    pub(crate) fn obfuscated(sock: UdpSocket, obfs: ferrox_core::hysteria::Salamander) -> Self {
        clear_gro(&sock);
        Self {
            sock,
            relay: None,
            obfs: Some(Mask::Salamander(obfs)),
            hop: None,
            gecko: None,
            armed: Arc::default(),
            held: Arc::default(),
        }
    }

    /// A socket whose every datagram is xplus-masked under `obfs`, the Hysteria v1 obfuscation.
    pub(crate) fn xplus(sock: UdpSocket, obfs: ferrox_core::hysteria_v1::XPlus) -> Self {
        clear_gro(&sock);
        Self {
            sock,
            relay: None,
            obfs: Some(Mask::XPlus(obfs)),
            hop: None,
            gecko: None,
            armed: Arc::default(),
            held: Arc::default(),
        }
    }

    pub(crate) fn relayed(sock: UdpSocket, via: SocketAddr, control: Arc<Connection>) -> Self {
        clear_gro(&sock);
        Self {
            sock,
            relay: Some(Relay {
                via,
                _control: control,
            }),
            obfs: None,
            hop: None,
            gecko: None,
            armed: Arc::default(),
            held: Arc::default(),
        }
    }

    /// A client dial that fragments its long-header packets and pads them into
    /// `window`, salamander-masking every frame — the Hysteria v2 `obfs: gecko` lane.
    /// `obfs` is the mask `Gecko` seals each frame with; the fixed socket never moves.
    pub(crate) fn gecked(
        sock: UdpSocket,
        obfs: ferrox_core::hysteria::Salamander,
        window: ferrox_core::hysteria::Gecko,
    ) -> std::io::Result<Self> {
        clear_gro(&sock);
        let handle = sock.try_clone()?;
        Ok(Self {
            sock,
            relay: None,
            obfs: None,
            hop: None,
            gecko: Some(Arc::new(Gecko::new(handle, obfs, window))),
            armed: Arc::default(),
            held: Arc::default(),
        })
    }

    /// A gecko dial that also hops its server port: every fragment is sealed, padded and written through the hop's current socket, so the two lanes compose instead of one dropping the other's bytes.
    pub(crate) fn gecked_hopped(
        server: SocketAddr,
        ports: Vec<u16>,
        interval_ms: (u64, u64),
        bind: &'static str,
        first: &UdpSocket,
        obfs: ferrox_core::hysteria::Salamander,
        window: ferrox_core::hysteria::Gecko,
    ) -> std::io::Result<Self> {
        clear_gro(first);
        let hop = Arc::new(Hopper::open(server, ports, interval_ms, bind, first)?);
        Ok(Self {
            sock: first.try_clone()?,
            relay: None,
            obfs: None,
            hop: Some(Arc::clone(&hop)),
            gecko: Some(Arc::new(Gecko::hopped(obfs, window, hop)?)),
            armed: Arc::default(),
            held: Arc::default(),
        })
    }

    /// A client dial that moves its server port among `ports` every `interval_ms`,
    /// opening a fresh local socket on each move so NAT sees a distinct flow. `server`
    /// is the address QUIC above names the connection by (the nominal port); replies
    /// from any hopped port are turned back to it. `obfs` still seals each datagram.
    pub(crate) fn hopped(
        server: SocketAddr,
        ports: Vec<u16>,
        interval_ms: (u64, u64),
        bind: &'static str,
        first: &UdpSocket,
        obfs: Option<Mask>,
    ) -> std::io::Result<Self> {
        clear_gro(first);
        let hopper = Hopper::open(server, ports, interval_ms, bind, first)?;
        Ok(Self {
            sock: first.try_clone()?,
            relay: None,
            obfs,
            hop: Some(Arc::new(hopper)),
            gecko: None,
            armed: Arc::default(),
            held: Arc::default(),
        })
    }

    /// A lane the kernel can speak to in batches: no gecko fragment, no hop, no obfuscation and no relay frame, so the datagram quiche wrote is the datagram on the wire, and Linux is where the batched call exists.
    #[cfg(target_os = "linux")]
    fn batchable(&self) -> bool {
        self.gecko.is_none() && self.hop.is_none() && self.obfs.is_none() && self.relay.is_none()
    }

    /// Send one datagram, or hold it when the kernel refused it for a reason that
    /// clears. A QUIC DATAGRAM frame is never retransmitted, so a held datagram is
    /// the difference between a pacing blip and a hole the inner TCP must time out.
    fn send_or_hold(&self, buf: &[u8], to: SocketAddr) -> bool {
        if let Err(error) = self.send_to(buf, to) {
            if refused(&error) {
                self.hold(buf, to);
                return false;
            }
        }
        true
    }

    /// Park a refused datagram behind the ones already waiting, in quiche's order.
    fn hold(&self, buf: &[u8], to: SocketAddr) {
        let Ok(mut queue) = self.held.queue.lock() else {
            return;
        };
        if queue.len() < HELD_LIMIT {
            queue.push_back((buf.to_vec(), to));
            self.held.holding.store(true, Ordering::Relaxed);
        }
    }

    /// Retry what a refusal left behind, oldest first, stopping at the first
    /// refusal so a peer sees the order quiche wrote.
    fn retry_held(&self) {
        if !self.held.holding.load(Ordering::Relaxed) {
            return;
        }
        let Ok(mut queue) = self.held.queue.lock() else {
            return;
        };
        while let Some((bytes, to)) = queue.pop_front() {
            if let Err(error) = self.send_to(&bytes, to) {
                if refused(&error) {
                    queue.push_front((bytes, to));
                    return;
                }
            }
        }
        self.held.holding.store(false, Ordering::Relaxed);
    }

    pub(crate) fn send_to(&self, buf: &[u8], to: SocketAddr) -> std::io::Result<usize> {
        if let Some(gecko) = self.gecko.as_ref() {
            return gecko.send(buf, to);
        }
        if let Some(hop) = self.hop.as_ref() {
            return hop.send(buf, to, self.obfs.as_ref());
        }
        if self.obfs.is_none() && self.relay.is_none() {
            return self.sock.send_to(buf, to);
        }
        let mut room = Unfilled::<{ RELAY_HEADER + MAX_DATAGRAM }>::new();
        let framed = room.as_mut();
        // The socket is addressed to the hop rather than the target whenever a relay frames the datagram.
        let target = self.relay.as_ref().map_or(to, |relay| relay.via);
        let plain = match self.relay.as_ref() {
            None => buf,
            Some(_) => relay_frame(buf, to, framed)
                .ok_or(std::io::Error::from(std::io::ErrorKind::InvalidInput))?,
        };
        let Some(obfs) = self.obfs.as_ref() else {
            return self.sock.send_to(plain, target);
        };
        // A fresh salt masks whatever the hop above produced.
        let mut wire = Unfilled::<{ MAX_DATAGRAM + SALAMANDER_SALT }>::new();
        let sealed = obfs
            .seal_into(plain, wire.as_mut())
            .ok_or(std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        self.sock.send_to(&wire.as_mut()[..sealed], target)
    }

    pub(crate) fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        if let Some(gecko) = self.gecko.as_ref() {
            return gecko.recv(buf);
        }
        if let Some(hop) = self.hop.as_ref() {
            return hop.recv(buf, self.obfs.as_ref());
        }
        let Some(obfs) = self.obfs.as_ref() else {
            return self.raw_recv_from(buf);
        };
        masked_read(|room| self.raw_recv_from(room), buf, obfs)
    }

    /// A read with no obfuscation on it: plain bytes straight from the socket, or the relay hop stripped.
    fn raw_recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let Some(relay) = self.relay.as_ref() else {
            return self.sock.recv_from(buf);
        };
        let (found, from) = self.sock.recv_from(buf)?;
        if from != relay.via {
            // A datagram from anywhere but the hop is not for this association.
            return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        }
        let Some((header, peer)) = relay_inbound(&buf[..found]) else {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        };
        buf.copy_within(header..found, 0);
        Ok((found - header, peer))
    }

    pub(crate) fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match self.hop.as_ref() {
            Some(hop) => hop.local_addr(),
            None => self.sock.local_addr(),
        }
    }

    pub(crate) fn try_clone(&self) -> std::io::Result<Self> {
        Ok(Self {
            sock: self.sock.try_clone()?,
            relay: self.relay.clone(),
            obfs: self.obfs.clone(),
            hop: self.hop.clone(),
            gecko: self.gecko.clone(),
            armed: Arc::clone(&self.armed),
            held: Arc::clone(&self.held),
        })
    }

    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        // The arm and its record are one step under the shared cell, so a concurrent holder cannot leave the cell naming a wait the socket does not carry.
        let guard = self.armed.lock();
        let result = match self.hop.as_ref() {
            Some(hop) => hop.set_read_timeout(timeout),
            None => self.sock.set_read_timeout(timeout),
        };
        if let Ok(mut armed) = guard {
            *armed = Some(timeout);
        }
        result
    }

    /// Arm the read wait only when this file description does not already carry it: the record is shared by every handle of the socket, so an arm made through one cannot be skipped past by a read through another.
    pub(crate) fn refresh_read_timeout(&self, want: Duration) -> bool {
        if self
            .armed
            .lock()
            .is_ok_and(|armed| *armed == Some(Some(want)))
        {
            return true;
        }
        self.set_read_timeout(Some(want)).is_ok()
    }

    /// This socket, when a readiness wait on it answers for `recv_from`: a hopped dial reads a descriptor that moves and a gecko reader reassembles inside its own table, so on those two a packet can be ready here and still not be one the reader will hand over.
    pub(crate) fn waits_here(&self) -> Option<&Self> {
        (self.hop.is_none() && self.gecko.is_none()).then_some(self)
    }

    /// Wait for a datagram to land without taking it: `Ok(true)` is readiness, and the next `recv_from` through this socket is what delivers the packet. A lane's own reader is never displaced by a wait.
    #[cfg(unix)]
    pub(crate) fn wait_readable(&self, timeout: Duration) -> std::io::Result<bool> {
        use std::os::fd::AsRawFd as _;
        let millis = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        let mut row = libc::pollfd {
            fd: self.sock.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            // SAFETY: one descriptor this socket holds, one element in the array, and the call writes only `revents`.
            let ready = unsafe { libc::poll(&raw mut row, 1, millis) };
            if ready > 0 {
                return Ok(row.revents != 0);
            }
            if ready == 0 {
                return Ok(false);
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    /// The Windows spelling of the same wait: one `WSAPoll` row, whose error code comes from `WSAGetLastError`.
    #[cfg(windows)]
    pub(crate) fn wait_readable(&self, timeout: Duration) -> std::io::Result<bool> {
        use std::os::windows::io::AsRawSocket as _;
        use windows_sys::Win32::Networking::WinSock::{
            WSAGetLastError, WSAPoll, POLLERR, POLLHUP, POLLIN, POLLRDNORM, SOCKET, WSAPOLLFD,
        };
        let millis = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        let mut row = WSAPOLLFD {
            fd: self.sock.as_raw_socket() as SOCKET,
            events: POLLIN | POLLRDNORM,
            revents: 0,
        };
        // SAFETY: one handle this socket holds and one element the call writes `revents` into.
        let ready = unsafe { WSAPoll(&raw mut row, 1, millis) };
        if ready < 0 {
            return Err(std::io::Error::from_raw_os_error(unsafe {
                WSAGetLastError()
            }));
        }
        let readable = POLLIN | POLLRDNORM | POLLHUP | POLLERR;
        Ok(ready > 0 && row.revents & readable != 0)
    }
}

#[cfg(unix)]
impl std::os::fd::AsRawFd for Datagram {
    /// The descriptor `recv_from` reads, which is not one for a hopped dial — see [`Datagram::waits_here`].
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.sock.as_raw_fd()
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsRawSocket for Datagram {
    /// The handle `recv_from` reads, which is not one for a hopped dial — see [`Datagram::waits_here`].
    fn as_raw_socket(&self) -> std::os::windows::io::RawSocket {
        self.sock.as_raw_socket()
    }
}

/// Frame one datagram behind the relay header that carries its real target, returning the bytes for the hop; `None` when `into` has no room. The socket itself is addressed to the hop, not `to`.
fn relay_frame<'a>(buf: &[u8], to: SocketAddr, into: &'a mut [u8]) -> Option<&'a [u8]> {
    let into = into.get_mut(..RELAY_HEADER + buf.len())?;
    // The hop reads these three before the target, so they are filled rather than left as stack garbage.
    into[..3].fill(0);
    let header = match to {
        SocketAddr::V4(addr) => {
            into[3] = 1;
            into[4..8].copy_from_slice(&addr.ip().octets());
            into[8..10].copy_from_slice(&addr.port().to_be_bytes());
            10
        }
        SocketAddr::V6(addr) => {
            into[3] = 4;
            into[4..20].copy_from_slice(&addr.ip().octets());
            into[20..22].copy_from_slice(&addr.port().to_be_bytes());
            22
        }
    };
    into[header..header + buf.len()].copy_from_slice(buf);
    Some(&into[..header + buf.len()])
}

/// A relayed datagram's header and target address; fragments are never reassembled, so they do not read.
fn relay_inbound(head: &[u8]) -> Option<(usize, SocketAddr)> {
    let [_, _, 0, kind] = *head.get(..4)? else {
        return None;
    };
    let (raw, width) = match kind {
        1 => (head.get(4..8)?, 4),
        4 => (head.get(4..20)?, 16),
        _ => return None,
    };
    let port = head.get(4 + width..6 + width)?;
    let ip = if width == 4 {
        let mut octets = [0u8; 4];
        octets.copy_from_slice(raw);
        std::net::IpAddr::from(octets)
    } else {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(raw);
        std::net::IpAddr::from(octets)
    };
    Some((
        6 + width,
        SocketAddr::new(ip, u16::from_be_bytes([port[0], port[1]])),
    ))
}

pub(crate) fn udp_to_server(
    address: &str,
    port: u16,
) -> Option<(UdpSocket, SocketAddr, SocketAddr)> {
    let peer = format!("{address}:{port}").to_socket_addrs().ok()?.next()?;
    let sock = if peer.is_ipv6() {
        bind_datagram("[::]:0").ok()?
    } else {
        bind_datagram("0.0.0.0:0").ok()?
    };
    let local = sock.local_addr().ok()?;
    Some((sock, peer, local))
}

/// Handshake under the caller's budget: a probe pays it once for silence, a named carrier gets the full budget.
pub(crate) fn handshake_within(
    sock: &Datagram,
    peer: SocketAddr,
    local: SocketAddr,
    server_name: &str,
    roots: &[Vec<u8>],
    ech_config_list: Option<&[u8]>,
    budget: Duration,
) -> Option<quiche::Connection> {
    let mut scid = [0u8; SCID_LEN];
    getrandom::fill(&mut scid).ok()?;
    let cid = quiche::ConnectionId::from_ref(&scid);
    let mut conn = with_config(roots, |config| {
        quiche::connect(Some(server_name), &cid, local, peer, config).ok()
    })?;
    if let Some(list) = ech_config_list {
        conn.as_mut().set_ech_config_list(list).ok()?;
    }
    drive_handshake_by(&mut conn, sock, local, budget)?;
    Some(conn)
}

/// The leases a readable stream belongs to: a stream nobody rides is drained here, so its bytes do not sit on a connection waiting for a flow that already ended.
fn hand_off(
    conn: &mut quiche::Connection,
    table: &Arc<Mutex<PooledState>>,
    chunk: &mut [u8],
    ready: &mut Vec<(u64, Arc<Connection>)>,
) {
    for id in conn.readable() {
        let Ok(leases) = table.lock() else {
            break;
        };
        if leases.opening.contains(&id) {
            continue;
        }
        let Some(half) = leases.sessions.get(&id).cloned() else {
            drop(leases);
            while let Ok((n, _)) = conn.stream_recv(id, chunk) {
                if n == 0 {
                    break;
                }
            }
            continue;
        };
        ready.push((id, half));
    }
}

/// Hand every datagram a batch holds to quiche as its own packet, in the order the kernel wrote them.
fn deliver_batch(conn: &mut quiche::Connection, batch: &mut Batch, local: SocketAddr) {
    for at in 0..batch.len() {
        let Some((bytes, from)) = batch.at(at) else {
            continue;
        };
        let info = quiche::RecvInfo { from, to: local };
        let _ = conn.recv(bytes, info);
    }
}

/// Drive one connection's reads and writes until its socket or connection ends, taking a batch of datagrams per turn.
fn pump(
    shared: &Arc<Mutex<quiche::Connection>>,
    table: &Arc<Mutex<PooledState>>,
    sock: &Datagram,
    local: SocketAddr,
) {
    let mut ready: Vec<(u64, Arc<Connection>)> = Vec::new();
    // One lock per 32 KiB rather than per 8: the drain is the connection's busiest shared path, and every pass pays the mutex twice.
    let mut chunk = crate::proxy::RelayBuf::with_len(PUMP_WINDOW).into_vec();
    // The obfuscated fallback lands the salt in the room too, so `masked_read` unmasks in place rather than staging every plaintext through a scratch.
    let mut room = Unfilled::<RECV_ROOM>::new();
    let buf = room.as_mut();
    // The batch lives across the turns, so a turn does not build the slots again.
    let mut batch = Batch::new();
    loop {
        // The lock covers quiche calls only: a stalled peer must not stall the sessions sharing the connection.
        let timeout = {
            let Ok(mut conn) = shared.lock() else {
                return;
            };
            if conn.is_closed() {
                return;
            }
            // The previous pass read streams after its flush, so the window updates and ACKs that reading produced are still queued: send them before waiting, or the peer stalls on a closed window.
            flush_egress(&mut conn, sock);
            conn.timeout()
                .map_or(PUMP_POLL, |left| left.min(PUMP_POLL))
                .max(Duration::from_millis(1))
        };
        if !sock.refresh_read_timeout(timeout) {
            return;
        }
        // The batched read is Linux's, and only where the datagram is the datagram on the wire: a gecko fragment, a hop, an obfuscation or a relay frame all rewrite the bytes, so those lanes keep the one-datagram read.
        let drain = recv_batch(sock, &mut batch);
        // An empty batch is the socket's own arm expiring, and the tick is what it owes the connection: a read that timed out is the same answer the batch gives, so the two are one case.
        let mut timed_out = false;
        let incoming = match drain {
            Drain::Read => None,
            Drain::Empty => {
                timed_out = true;
                None
            }
            Drain::Unbatchable => match sock.recv_from(buf) {
                Ok(found) => Some(found),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    timed_out = true;
                    None
                }
                Err(_) => return,
            },
            // A socket that coalesces must not be read one segment wide.
            Drain::Unreadable => return,
        };
        ready.clear();
        {
            #[cfg(test)]
            let took = Instant::now();
            let Ok(mut conn) = shared.lock() else {
                return;
            };
            #[cfg(test)]
            qstage(format!("pump-lock {}ms", took.elapsed().as_millis()));
            if conn.is_closed() {
                return;
            }
            if drain == Drain::Read {
                deliver_batch(&mut conn, &mut batch, local);
            }

            match incoming {
                Some((n, from)) => {
                    let info = quiche::RecvInfo { from, to: local };
                    let _ = conn.recv(&mut buf[..n], info);
                }
                None if timed_out => conn.on_timeout(),
                None => {}
            }
            flush_egress(&mut conn, sock);
            hand_off(&mut conn, table, &mut chunk, &mut ready);
            if conn.is_closed() {
                return;
            }
            // A quiet socket and an empty lane ends the thread; the lease that follows it starts the next one on the same connection.
            if timed_out && park_if_idle(table) {
                return;
            }
        }
        for (id, up) in ready.drain(..) {
            loop {
                let (n, fin) = {
                    let Ok(mut conn) = shared.lock() else {
                        return;
                    };
                    match conn.stream_recv(id, &mut chunk) {
                        Ok((0, _)) | Err(_) => break,
                        Ok(found) => found,
                    }
                };
                if (&*up).write_all(&chunk[..n]).is_err() {
                    break;
                }
                if fin {
                    let _ = up.shutdown(Shutdown::Write);
                    break;
                }
            }
        }
    }
}

/// Whether the lane still has streams to lend: `next_id` moves one bidi id per lease, so it counts every flow the connection has carried.
fn flow_credit(entry: &PooledConn) -> bool {
    entry
        .table
        .lock()
        .is_ok_and(|table| table.next_id / 4 < MAX_FLOWS_ON_LANE)
}

/// Whether the edge still holds the lane: quiche's idle timer is an absolute instant, so one timeout call across a park gap is the peer's arithmetic, not a budget of ours.
fn lane_is_live(entry: &PooledConn) -> bool {
    let Ok(mut conn) = entry.conn.lock() else {
        return false;
    };
    conn.on_timeout();
    !conn.is_closed()
}

/// Take a stream on the lane, and put a pump behind a parked one that this lease can use in the same table lock: a thread leaving an empty lane and a lease landing on it cannot both win the flag, so no flow waits on a thread that already ended.
fn lend(pooled: &PooledConn, up: Option<Connection>, drive: bool) -> Option<u64> {
    let mut table = pooled.table.lock().ok()?;
    if table.sessions.len() + table.opening.len() >= MAX_STREAMS as usize {
        return None;
    }
    // A lease that hands its stream to a client and one that reads the stream itself both need the lane's datagrams taken; the second kind gets the driver because no client thread will read for it, and `hand_off` skips an id still opening.
    if drive && table.parked.take().is_some() {
        let (Ok(pump_sock), Ok(local)) = (pooled.sock.try_clone(), pooled.sock.local_addr()) else {
            table.parked = Some(Instant::now());
            return None;
        };
        table.pump += 1;
        let owner = PumpOwner {
            table: Arc::clone(&pooled.table),
            generation: table.pump,
        };
        let (shared, leases) = (Arc::clone(&pooled.conn), Arc::clone(&pooled.table));
        std::thread::spawn(move || {
            // The owner moves with the thread: every exit from `pump` hands the lane back, so no return can leave it unowned.
            let _owner = owner;
            pump(&shared, &leases, &pump_sock, local);
        });
    }
    let id = table.next_id;
    table.next_id += 4;
    if let Some(up) = up {
        table.sessions.insert(id, Arc::new(up));
    }
    table.opening.insert(id);
    Some(id)
}

/// Whether the pump in hand should end: a lane no lease rides parks with its thread gone, so an idle edge costs no thread and keeps its handshake. The decision and the hand-back are one lock, so a lease landing on the lane either joins before it parks or starts the next pump after it.
fn park_if_idle(table: &Arc<Mutex<PooledState>>) -> bool {
    table.lock().is_ok_and(|mut state| {
        if !state.sessions.is_empty() || !state.opening.is_empty() {
            return false;
        }
        state.pump = 0;
        state.parked = Some(Instant::now());
        true
    })
}

/// A pump's ownership of its lane: cleared when the thread leaves, whichever exit it took, so a close or a socket error cannot leave the flag clear with no thread behind it.
struct PumpOwner {
    table: Arc<Mutex<PooledState>>,
    generation: u64,
}

impl Drop for PumpOwner {
    fn drop(&mut self) {
        if let Ok(mut state) = self.table.lock() {
            if state.pump == self.generation {
                state.pump = 0;
                state.parked = Some(Instant::now());
            }
        }
    }
}

/// Hand the stream id back: the lane stays, and the pump parks itself once nothing else rides it, so the next flow rides the same handshake instead of paying for a new one.
fn leave_session(table: &Arc<Mutex<PooledState>>, id: u64) {
    if let Ok(mut table) = table.lock() {
        table.sessions.remove(&id);
        table.opening.remove(&id);
    }
}

fn uplink_stream(pooled: &PooledConn, id: u64, client: &Connection) {
    #[cfg(test)]
    let port = pooled.key.port;
    let Ok(flush_sock) = pooled.sock.try_clone() else {
        leave_session(&pooled.table, id);
        return;
    };
    let Ok(mut plain) = client.try_clone() else {
        leave_session(&pooled.table, id);
        return;
    };
    let mut chunk = crate::proxy::RelayBuf::with_len(PUMP_WINDOW).into_vec();
    loop {
        #[cfg(test)]
        let read_at = Instant::now();
        match plain.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                #[cfg(test)]
                qstage(format!(
                    "{} t={} up-read {id} {n} waited {}ms",
                    port,
                    qms(),
                    read_at.elapsed().as_millis()
                ));
                let mut rest = &chunk[..n];
                let deadline = Instant::now() + SEND_WAIT;
                let sent = loop {
                    #[cfg(test)]
                    let waited = Instant::now();
                    let Ok(mut conn) = pooled.conn.lock() else {
                        #[cfg(test)]
                        qstage(format!("{} t={} up-lock-none {id}", port, qms()));
                        break false;
                    };
                    #[cfg(test)]
                    qstage(format!(
                        "{} t={} up-lock {id} {}ms",
                        port,
                        qms(),
                        waited.elapsed().as_millis()
                    ));
                    if conn.is_closed() {
                        #[cfg(test)]
                        qstage(format!("{} t={} up-closed {id}", port, qms()));
                        break false;
                    }
                    match conn.stream_send(id, rest, false) {
                        Ok(written) => {
                            rest = &rest[written..];
                            flush_egress(&mut conn, &flush_sock);
                            if rest.is_empty() {
                                break true;
                            }
                            if written == 0 {
                                if Instant::now() >= deadline {
                                    #[cfg(test)]
                                    qstage(format!("{} t={} up-stall {id}", port, qms()));
                                    break false;
                                }
                                drop(conn);
                                std::thread::sleep(Duration::from_millis(5));
                            }
                        }
                        Err(quiche::Error::Done) => {
                            if Instant::now() >= deadline {
                                #[cfg(test)]
                                qstage(format!("{} t={} up-done-timeout {id}", port, qms()));
                                break false;
                            }
                            drop(conn);
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => {
                            #[cfg(test)]
                            qstage(format!("{} t={} up-err {id}", port, qms()));
                            break false;
                        }
                    }
                };
                if !sent {
                    #[cfg(test)]
                    qstage(format!("{} t={} up-unsent {id}", port, qms()));
                    break;
                }
                #[cfg(test)]
                qstage(format!("{} t={} up {id} {n}", port, qms()));
            }
        }
    }
    if let Ok(mut conn) = pooled.conn.lock() {
        let _ = conn.stream_send(id, &[], true);
    }
    #[cfg(test)]
    qstage(format!("{} t={} uplink-end {id}", port, qms()));
    leave_session(&pooled.table, id);
}

pub(crate) fn dial_pooled(
    client: &Connection,
    dial: &QuicDial,
    target: &crate::proxy::Destination,
) {
    let header = crate::proxy::vless_header(&dial.id, 1, target);
    dial_pooled_with(client, dial, &header, true);
}

/// A pooled stream whose first bytes are the caller's own header, and whose reply the protocol either owes or does not.
pub(crate) fn dial_pooled_with(
    client: &Connection,
    dial: &QuicDial,
    header: &[u8],
    expect_reply: bool,
) {
    let pooled = pool().stream(dial);
    #[cfg(test)]
    qstage(format!(
        "{} t={} lookup hit={}",
        dial.port,
        qms(),
        pooled.is_some()
    ));
    let Some(pooled) = pooled.or_else(|| {
        let fresh = build_pooled(dial)?;
        #[cfg(test)]
        qstage(format!("{} t={} built", dial.port, qms()));
        let Ok(mut pool) = pool().inner.lock() else {
            return Some(fresh);
        };
        if let Some(live) = pool.get(fresh.key.as_ref()) {
            if let Ok(mut conn) = fresh.conn.lock() {
                let _ = conn.close(false, 0, b"superseded");
            }
            Some(live.clone())
        } else {
            pool.insert(fresh.key.as_ref().clone(), fresh.clone());
            Some(fresh)
        }
    }) else {
        #[cfg(test)]
        qstage(format!("{} t={} build-none", dial.port, qms()));
        return;
    };
    let Some(id) = lend(&pooled, client.try_clone().ok(), true) else {
        #[cfg(test)]
        qstage(format!("{} t={} open-none", dial.port, qms()));
        return;
    };
    #[cfg(test)]
    qstage(format!("{} t={} opened {id}", dial.port, qms()));
    let Ok(flush_sock) = pooled.sock.try_clone() else {
        leave_session(&pooled.table, id);
        return;
    };
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let opened = stream_send_all_parked(&pooled.conn, &flush_sock, id, header, false, deadline)
        && (!expect_reply
            || stream_recv_exact_parked(&pooled.conn, id, 2, deadline).as_deref() == Some(&[0, 0]));
    #[cfg(test)]
    qstage(format!("{} t={} header {id} {opened}", dial.port, qms()));
    if !opened {
        leave_session(&pooled.table, id);
        return;
    }
    if let Ok(mut table) = pooled.table.lock() {
        table.opening.remove(&id);
    }
    #[cfg(test)]
    qstage(format!("{} t={} graduated {id}", dial.port, qms()));
    uplink_stream(&pooled, id, client);
}

/// A stream on the pooled connection under the named budget; a connection the budget missed is never pooled.
pub(crate) fn pooled_stream_within(dial: &QuicDial, budget: Duration) -> Option<PooledStream> {
    lease_within(dial, budget, false)
}

/// A lease that reads its own stream: the lane's pump drives the connection while the lease is alive, since no client thread reads the socket for it.
pub(crate) fn pumped_stream_within(dial: &QuicDial, budget: Duration) -> Option<PooledStream> {
    lease_within(dial, budget, true)
}

fn lease_within(dial: &QuicDial, budget: Duration, drive: bool) -> Option<PooledStream> {
    let pooled = pool().stream(dial).or_else(|| {
        let fresh = build_pooled_within(dial, budget)?;
        let Ok(mut pool) = pool().inner.lock() else {
            return Some(fresh);
        };
        if let Some(live) = pool.get(fresh.key.as_ref()) {
            return Some(live.clone());
        }
        pool.insert(fresh.key.as_ref().clone(), fresh.clone());
        Some(fresh)
    })?;
    // The address is read before the id is taken: a lease that cannot say where it is has no id to give back yet.
    let local = pooled.sock.local_addr().ok()?;
    let id = lend(&pooled, None, drive)?;
    Some(PooledStream {
        conn: Arc::clone(&pooled.conn),
        sock: Arc::clone(&pooled.sock),
        local,
        id,
        entry: Some(pooled),
    })
}

/// Whether the pool still holds a connection for this dial: an entry that has lent its whole grant is still held until a lease looks at it.
#[cfg(test)]
pub(crate) fn pool_holds(dial: &QuicDial) -> bool {
    peek(dial).is_some()
}

/// Whether a held lane has no pump: the flag is the pump's own way of saying it left, so this is the witness that an idle edge costs no thread.
#[cfg(test)]
pub(crate) fn lane_parked(dial: &QuicDial) -> bool {
    peek(dial).is_some_and(|lane| lane.table.lock().is_ok_and(|table| table.parked.is_some()))
}

/// Whether a held lane has no stream left to lend: past the grant a lease looks at it, the lane is handed back for a fresh dial.
#[cfg(test)]
pub(crate) fn lane_spent(dial: &QuicDial) -> bool {
    peek(dial).is_some_and(|lane| !flow_credit(&lane))
}

/// Whether a lookup hands this lane back: the judgement the pool makes, run without taking a lease or dialling the next one, so the witness sees the hand-back rather than a fresh connection.
#[cfg(test)]
pub(crate) fn lane_handed_back(dial: &QuicDial) -> bool {
    pool().stream(dial).is_none()
}

/// The lane a dial would be handed, read without judging it: a witness that retired what it was looking at would hide the leak it names.
#[cfg(test)]
fn peek(dial: &QuicDial) -> Option<PooledConn> {
    let key = QuicServer::of(dial);
    pool()
        .inner
        .lock()
        .ok()
        .and_then(|pool| pool.get(&key).cloned())
}

fn build_pooled(dial: &QuicDial) -> Option<PooledConn> {
    build_pooled_within(dial, HANDSHAKE_TIMEOUT)
}

fn build_pooled_within(dial: &QuicDial, budget: Duration) -> Option<PooledConn> {
    let roots = dial.roots.as_deref().unwrap_or(&[]);
    let built = crate::foxy::debug_on().then(Instant::now);
    // One attempt per resolved address: the first answer is not always the reachable one.
    let peers: Vec<SocketAddr> = format!("{}:{}", dial.address, dial.port)
        .to_socket_addrs()
        .ok()?
        .collect();
    let resolved = built.map(|_| Instant::now());
    // One hop per connection, not per address. An HTTP hop is TCP-only: refusing beats bypassing the proxy.
    let relay = match dial.upstream.as_ref() {
        Some(proxy) if proxy.http() => return None,
        Some(proxy) => Some(crate::foxy::associate_udp(proxy)?),
        None => None,
    };
    for peer in peers {
        let Ok(sock) = (if peer.is_ipv6() {
            bind_datagram("[::]:0")
        } else {
            bind_datagram("0.0.0.0:0")
        }) else {
            continue;
        };
        let Ok(local) = sock.local_addr() else {
            continue;
        };
        let sock = match relay.as_ref() {
            Some((control, via)) => Datagram::relayed(sock, *via, Arc::clone(control)),
            None => Datagram::plain(sock),
        };
        let bound = resolved.map(|_| Instant::now());
        let Some(mut conn) = handshake_within(
            &sock,
            peer,
            local,
            &dial.host,
            roots,
            dial.ech_config_list.as_deref(),
            budget,
        ) else {
            continue;
        };
        let handed = bound.map(|_| Instant::now());
        if !send_h3_opening(&mut conn, &sock) {
            continue;
        }
        let table = Arc::new(Mutex::new(PooledState {
            sessions: HashMap::new(),
            opening: HashSet::new(),
            next_id: 0,
            pump: 0,
            // No thread yet: only a lease whose bytes the pump can hand over starts one, so a connection nobody rode and a flow that reads its own socket cost none.
            parked: Some(Instant::now()),
        }));
        debug_pool(dial, built, resolved, bound, handed);
        return Some(PooledConn {
            conn: Arc::new(Mutex::new(conn)),
            table,
            sock: Arc::new(sock),
            key: Arc::new(QuicServer::of(dial)),
        });
    }
    None
}

/// One VLESS session on a serving connection: stream bytes through the shared connection lock.
#[derive(Clone)]
pub(crate) struct QuicStream {
    conn: Arc<Mutex<quiche::Connection>>,
    sock: Arc<Datagram>,
    id: u64,
    meter: crate::stats::Meter,
    /// The peer's FIN can arrive with the last bytes, and `Read` has nowhere to report it; keeping it makes the next read the EOF instead of a read the poll repeats.
    peer_fin: Arc<AtomicBool>,
}

/// How long one stream read polls quiche before idling: FIN and close land inside the next quantum.
const STREAM_QUANTUM: Duration = Duration::from_millis(100);

/// Between polls of quiche state, so a waiting read never holds the connection lock.
const STREAM_POLL: Duration = Duration::from_millis(5);

impl Read for QuicStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.peer_fin.load(Ordering::Relaxed) {
            return Ok(0);
        }
        let deadline = Instant::now() + STREAM_QUANTUM;
        loop {
            match self.conn.lock() {
                Ok(mut conn) => {
                    if conn.is_closed() {
                        return Ok(0);
                    }
                    let (n, fin) = match conn.stream_recv(self.id, buf) {
                        Ok(got) => got,
                        Err(quiche::Error::Done) => (0, false),
                        Err(error) => {
                            return Err(std::io::Error::other(format!(
                                "quic stream read: {error:?}"
                            )));
                        }
                    };
                    if n > 0 {
                        self.peer_fin.store(fin, Ordering::Relaxed);
                        flush_egress(&mut conn, &self.sock);
                        self.meter.read(n);
                        return Ok(n);
                    }
                    if fin {
                        self.peer_fin.store(true, Ordering::Relaxed);
                        return Ok(0);
                    }
                }
                Err(_) => {
                    return Err(std::io::Error::other("quic connection lock poisoned"));
                }
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            std::thread::sleep(STREAM_POLL);
        }
    }
}

impl Write for QuicStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // The lock covers one send each: a flow-control wait must not hold it, or ACKs stop arriving.
        let deadline = Instant::now() + SEND_WAIT;
        let mut rest = buf;
        while !rest.is_empty() {
            match self.send_once(rest) {
                Ok(0) => {
                    if Instant::now() >= deadline {
                        return Err(std::io::Error::other("quic stream send timed out"));
                    }
                    std::thread::sleep(STREAM_POLL);
                }
                Ok(n) => {
                    self.meter.write(n);
                    rest = &rest[n..];
                }
                Err(error) => return Err(error),
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let Ok(mut conn) = self.conn.lock() else {
            return Err(std::io::Error::other("quic connection lock poisoned"));
        };
        flush_egress(&mut conn, &self.sock);
        Ok(())
    }
}

impl crate::proxy::Duplicate for QuicStream {
    /// Two handles of one stream: the clone shares the connection and the id and costs no
    /// syscall, and neither half holds a lock across the wait the other direction wants.
    fn duplicate(&self) -> Option<Self> {
        Some(self.clone())
    }
}

impl QuicStream {
    /// Counts both directions against the caller's meters, keeping any an earlier layer already set.
    /// Adds counters to the stream while keeping the ones it already carries.
    pub(crate) fn with_meter(mut self, meter: crate::stats::Meter) -> Self {
        self.meter = self.meter.merged(meter);
        self
    }

    /// One send flight without holding the lock across the wait behind it.
    fn send_once(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let Ok(mut conn) = self.conn.lock() else {
            return Err(std::io::Error::other("quic connection lock poisoned"));
        };
        match conn.stream_send(self.id, buf, false) {
            Ok(n) => {
                flush_egress(&mut conn, &self.sock);
                Ok(n)
            }
            Err(quiche::Error::Done) => Ok(0),
            Err(error) => Err(std::io::Error::other(format!(
                "quic stream send: {error:?}"
            ))),
        }
    }

    /// Half-close our direction: the peer reads everything sent, then EOF. A stream the peer already
    /// reset is finished, not a send to wait ten seconds for; and the wait itself takes the lock one
    /// poll at a time, so a lane finishing never parks every other stream behind it.
    pub(crate) fn fin(&self) -> bool {
        let deadline = Instant::now() + SEND_WAIT;
        loop {
            let outcome = {
                let Ok(mut conn) = self.conn.lock() else {
                    return false;
                };
                if conn.is_closed() || conn.stream_finished(self.id) {
                    Some(true)
                } else {
                    match conn.stream_send(self.id, &[], true) {
                        Ok(_) => {
                            flush_egress(&mut conn, &self.sock);
                            Some(true)
                        }
                        Err(quiche::Error::Done) if conn.stream_finished(self.id) => Some(true),
                        Err(quiche::Error::Done) => None,
                        Err(_) => Some(false),
                    }
                }
            };
            match outcome {
                Some(done) => return done,
                None if Instant::now() >= deadline => return false,
                None => std::thread::sleep(STREAM_POLL),
            }
        }
    }

    /// Stop the stream in both directions; the connection itself is untouched.
    pub(crate) fn close(&self) {
        stop_stream(&self.conn, &self.sock, self.id);
    }
}

/// One serving session: the QUIC connection behind one lock, the stream ids already handed out.
struct ServerConn {
    conn: Arc<Mutex<quiche::Connection>>,
    seen: Mutex<HashSet<u64>>,
    visit: AtomicU64,
    gone: AtomicBool,
}

/// The per-stream entry point a VLESS inbound serves: one stream, one session, no shared state.
pub(crate) type Serve = Arc<dyn Fn(QuicStream) + Send + Sync>;

/// The driver's two datagram scratch buffers and the tables one reap fills, passed as one so routing stays within the argument budget and a batch reuses its slots instead of allocating.
struct Scratch {
    buf: [u8; MAX_DATAGRAM],
    out: [u8; MAX_DATAGRAM],
    fresh: Vec<(Arc<Mutex<quiche::Connection>>, u64)>,
    learned: Vec<(Vec<u8>, Arc<ServerConn>)>,
    closed: Vec<Vec<u8>>,
    /// The stamp one reap writes on every state it visits, so a second key for that state is a load, not a scan.
    epoch: u64,
    /// The earliest timer a live connection wants, carried from the reap that read it to the wait it gates.
    deadline: Option<Instant>,
}

/// The driver: one UDP socket is read by this loop alone, so no packet is fed to the wrong connection.
pub(crate) fn serve_loop(
    sock: Datagram,
    config: &Arc<Mutex<quiche::Config>>,
    serve: &Serve,
    stop: &Arc<AtomicBool>,
) {
    let Ok(local) = sock.local_addr() else {
        return;
    };
    let sock = Arc::new(sock);
    let mut conns: HashMap<Vec<u8>, Arc<ServerConn>> = HashMap::new();
    let mut scratch = Scratch {
        buf: [0u8; MAX_DATAGRAM],
        out: [0u8; MAX_DATAGRAM],
        fresh: Vec::new(),
        learned: Vec::new(),
        closed: Vec::new(),
        epoch: 0,
        deadline: None,
    };
    #[cfg(target_os = "linux")]
    let mut batch = Batch::new();
    while !stop.load(Ordering::Relaxed) {
        let start = Instant::now();
        // The deadline the last reap read: the same lock pass that answers the readable streams answers when the connection next needs a timer, so no visit pays a second walk of the table.
        let wait = scratch
            .deadline
            .map_or(Duration::from_millis(100), |deadline| {
                deadline
                    .saturating_duration_since(start)
                    .min(Duration::from_millis(100))
            })
            .max(Duration::from_millis(1));
        if !sock.refresh_read_timeout(wait) {
            return;
        }
        // A serving lane takes the queue in a batch where the platform has one: a burst of a dozen packets is one read, one lock per lane and one reap, not one of each per packet.
        #[cfg(target_os = "linux")]
        match recv_batch(&sock, &mut batch) {
            Drain::Read => {
                route_batch(
                    &sock,
                    local,
                    config,
                    &mut conns,
                    &mut batch,
                    &mut scratch.out,
                );
                reap(serve, &sock, &mut conns, &mut scratch);
                continue;
            }
            Drain::Empty => {
                run_timers(&mut conns, &sock, start.elapsed());
                reap(serve, &sock, &mut conns, &mut scratch);
                continue;
            }
            Drain::Unbatchable => {}
            // A socket that coalesces must not be read one segment wide.
            Drain::Unreadable => return,
        }
        match sock.recv_from(&mut scratch.buf) {
            Ok((n, from)) => {
                let Scratch { buf, out, .. } = &mut scratch;
                route(&sock, local, config, &mut conns, &mut buf[..n], out, from);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                run_timers(&mut conns, &sock, start.elapsed());
            }
            Err(_) => return,
        }
        reap(serve, &sock, &mut conns, &mut scratch);
    }
}

/// Run the timers whose deadline this wait passed, answering what they queued.
fn run_timers(conns: &mut HashMap<Vec<u8>, Arc<ServerConn>>, sock: &Datagram, elapsed: Duration) {
    for state in conns.values() {
        let Ok(mut conn) = state.conn.lock() else {
            continue;
        };
        if conn.timeout().is_none_or(|left| left <= elapsed) {
            conn.on_timeout();
            flush_egress(&mut conn, sock);
        }
    }
}

/// Source IDs quiche issues mid-connection: any packet may carry one, so every new one routes.
fn learn_ids(
    conns: &mut HashMap<Vec<u8>, Arc<ServerConn>>,
    state: &Arc<ServerConn>,
    conn: &quiche::Connection,
) {
    for id in conn.source_ids() {
        if !conns.contains_key(id.as_ref()) {
            conns.insert(id.as_ref().to_vec(), Arc::clone(state));
        }
    }
}

/// The routing key a packet carries, read without building a header: a short-header DCID is the fixed-width server id at a known offset, and that is every packet on an established lane, so the lookup copies nothing and allocates nothing. A long header names its DCID length at byte five.
fn packet_key(buf: &[u8]) -> Option<&[u8]> {
    let first = *buf.first()?;
    if first & 0x80 == 0 {
        return buf.get(1..1 + quiche::MAX_CONN_ID_LEN);
    }
    let dcid_len = usize::from(*buf.get(5)?);
    if dcid_len > quiche::MAX_CONN_ID_LEN {
        return None;
    }
    buf.get(6..6 + dcid_len)
}

/// One packet to its connection, or to a new connection when it knocks with an Initial.
fn route(
    sock: &Datagram,
    local: SocketAddr,
    config: &Arc<Mutex<quiche::Config>>,
    conns: &mut HashMap<Vec<u8>, Arc<ServerConn>>,
    buf: &mut [u8],
    out: &mut [u8],
    from: SocketAddr,
) {
    let Some(key) = packet_key(buf) else {
        return;
    };
    if let Some(state) = conns.get(key).cloned() {
        let Ok(mut conn) = state.conn.lock() else {
            return;
        };
        let info = quiche::RecvInfo { from, to: local };
        let _ = conn.recv(buf, info);
        flush_egress(&mut conn, sock);
        learn_ids(conns, &state, &conn);
        return;
    }
    // A short header names an established lane or nothing: only a long header can open one.
    if buf.first().is_none_or(|first| first & 0x80 == 0) {
        return;
    }
    let Ok(header) = quiche::Header::from_slice(buf, quiche::MAX_CONN_ID_LEN) else {
        return;
    };
    if header.ty != quiche::Type::Initial {
        return;
    }
    if !quiche::version_is_supported(header.version) {
        if let Ok(len) = quiche::negotiate_version(&header.scid, &header.dcid, out) {
            let _ = sock.send_to(&out[..len], from);
        }
        return;
    }
    // Server SCIDs are the parse length, so short-header DCIDs read exactly, not into payload.
    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    if getrandom::fill(&mut scid).is_err() {
        return;
    }
    let cid = quiche::ConnectionId::from_ref(&scid);
    let Ok(mut guard) = config.lock() else {
        return;
    };
    let Ok(mut conn) = quiche::accept(&cid, None, local, from, &mut guard) else {
        return;
    };
    drop(guard);
    let info = quiche::RecvInfo { from, to: local };
    if conn.recv(buf, info).is_err() {
        return;
    }
    flush_egress(&mut conn, sock);
    let state = Arc::new(ServerConn {
        conn: Arc::new(Mutex::new(conn)),
        seen: Mutex::new(HashSet::new()),
        visit: AtomicU64::new(0),
        gone: AtomicBool::new(false),
    });
    conns.insert(scid.to_vec(), Arc::clone(&state));
    conns.insert(header.dcid.as_ref().to_vec(), state);
}

/// A whole receive batch, one lock per run of datagrams for the same lane. A burst for one lane is what a data frame is, so the common batch pays one lock, one `learn_ids` pass per run and one egress sweep for the run, not one of each per packet. A lane's run keeps the kernel's order; a run for another lane starts its own.
#[cfg(target_os = "linux")]
fn route_batch(
    sock: &Datagram,
    local: SocketAddr,
    config: &Arc<Mutex<quiche::Config>>,
    conns: &mut HashMap<Vec<u8>, Arc<ServerConn>>,
    batch: &mut Batch,
    out: &mut [u8],
) {
    let mut at = 0;
    while at < batch.len() {
        let Some(key) = batch.key(at) else {
            at += 1;
            continue;
        };
        let Some(state) = conns.get(key).cloned() else {
            // A lane the table does not hold: one datagram through the path that may accept or negotiate.
            let Some((bytes, from)) = batch.at(at) else {
                at += 1;
                continue;
            };
            route(sock, local, config, conns, bytes, out, from);
            at += 1;
            continue;
        };
        let mut end = at + 1;
        while end < batch.len() {
            if batch.key(end) != Some(key) {
                break;
            }
            end += 1;
        }
        if let Ok(mut conn) = state.conn.lock() {
            for index in at..end {
                let Some((bytes, from)) = batch.at(index) else {
                    continue;
                };
                let info = quiche::RecvInfo { from, to: local };
                let _ = conn.recv(bytes, info);
            }
            // The peer cannot use an id before this run's flush carries it, so the run learns once after every packet.
            learn_ids(conns, &state, &conn);
            flush_egress(&mut conn, sock);
        }
        at = end;
    }
}

/// New peer streams to sessions, finished ones out of the table, dead connections dropped. One lock per connection covers the closed, timer, source-id and readable questions, and the tables live across calls so a busy connection does not pay for them again on every visit.
fn reap(
    serve: &Serve,
    sock: &Arc<Datagram>,
    conns: &mut HashMap<Vec<u8>, Arc<ServerConn>>,
    scratch: &mut Scratch,
) {
    scratch.fresh.clear();
    scratch.learned.clear();
    scratch.closed.clear();
    scratch.epoch = scratch.epoch.wrapping_add(1);
    let epoch = scratch.epoch;
    let mut deadline = None;
    // A state is keyed once per connection id, so the stamp keeps one connection's questions asked once.
    for (key, state) in conns.iter() {
        if state.visit.load(Ordering::Relaxed) == epoch {
            // A closed connection still owes every key it routes: they leave together.
            if state.gone.load(Ordering::Relaxed) {
                scratch.closed.push(key.clone());
            }
            continue;
        }
        state.visit.store(epoch, Ordering::Relaxed);
        let Ok(conn) = state.conn.lock() else {
            continue;
        };
        if conn.is_closed() {
            state.gone.store(true, Ordering::Relaxed);
            scratch.closed.push(key.clone());
            continue;
        }
        if let Some(at) = conn.timeout_instant() {
            deadline = Some(deadline.map_or(at, |soonest: Instant| soonest.min(at)));
        }
        // New source IDs first: a packet carrying one must route on the next datagram.
        for id in conn.source_ids() {
            if !conns.contains_key(id.as_ref()) {
                scratch
                    .learned
                    .push((id.as_ref().to_vec(), Arc::clone(state)));
            }
        }
        if let Ok(mut seen) = state.seen.lock() {
            let mut spawned = false;
            for stream in conn.readable() {
                // Client bidirectional streams only: the H3 opening rides unidirectional ones.
                if stream % 4 != 0 || !seen.insert(stream) {
                    continue;
                }
                scratch.fresh.push((Arc::clone(&state.conn), stream));
                spawned = true;
            }
            // Only a pass that added a stream can leave a finished one behind: an idle connection's set has nothing to sweep.
            if spawned {
                seen.retain(|stream| !conn.stream_finished(*stream));
            }
        }
    }
    scratch.deadline = deadline;
    for (key, state) in scratch.learned.drain(..) {
        conns.entry(key).or_insert(state);
    }
    for key in scratch.closed.drain(..) {
        conns.remove(&key);
    }
    for (conn, stream) in scratch.fresh.drain(..) {
        let session = QuicStream {
            conn,
            sock: Arc::clone(sock),
            id: stream,
            meter: crate::stats::Meter::default(),
            peer_fin: Arc::new(AtomicBool::new(false)),
        };
        let serve = Arc::clone(serve);
        std::thread::spawn(move || serve(session));
    }
}

/// One connection, one stream, no pool thread: which reader owns a shared connection must not decide the proof.
#[cfg(test)]
pub(crate) fn direct_stream(
    host: &str,
    address: &str,
    port: u16,
    roots: &[Vec<u8>],
) -> Option<PooledStream> {
    let (sock, peer, local) = udp_to_server(address, port)?;
    direct_stream_on(Datagram::plain(sock), peer, local, host, roots)
}

/// The same stream over a caller-framed socket: how a loopback proves a relayed dial.
#[cfg(test)]
pub(crate) fn direct_stream_on(
    sock: Datagram,
    peer: SocketAddr,
    local: SocketAddr,
    host: &str,
    roots: &[Vec<u8>],
) -> Option<PooledStream> {
    let mut conn = handshake_within(&sock, peer, local, host, roots, None, HANDSHAKE_TIMEOUT)?;
    if !send_h3_opening(&mut conn, &sock) {
        return None;
    }
    Some(PooledStream {
        conn: std::sync::Arc::new(std::sync::Mutex::new(conn)),
        sock: std::sync::Arc::new(sock),
        local,
        id: 4,
        // Built outside the pool: nothing to hand back when the lane ends.
        entry: None,
    })
}

/// One datagram off a loopback edge's socket, or nothing when none arrived.
#[cfg(test)]
pub(crate) fn server_poll(sock: &Datagram, buf: &mut [u8]) -> Option<(usize, SocketAddr)> {
    sock.set_read_timeout(Some(SERVER_POLL)).ok()?;
    match sock.recv_from(buf) {
        Ok(found) => Some(found),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            None
        }
        Err(e) => panic!("loopback edge socket died: {e:?}"),
    }
}

/// Lets a waiting connection run its own timers and answer what it queued between packets.
#[cfg(test)]
pub(crate) fn server_idle(conn: &mut quiche::Connection, sock: &Datagram, out: &mut [u8]) {
    conn.on_timeout();
    while let Ok((written, info)) = conn.send(out) {
        let _ = sock.send_to(&out[..written], info.to);
    }
}

/// The loopback edge's half: its first Initial goes to quiche and the handshake is driven to completion.
#[cfg(test)]
pub(crate) fn server_accept(
    sock: &Datagram,
    local: SocketAddr,
    config: &mut quiche::Config,
) -> quiche::Connection {
    let mut buf = [0u8; MAX_DATAGRAM];
    let mut out = [0u8; MAX_DATAGRAM];
    let mut conn = loop {
        let Some((n, from)) = server_poll(sock, &mut buf) else {
            continue;
        };
        let Ok(header) = quiche::Header::from_slice(&mut buf[..n], 20) else {
            continue;
        };
        if header.ty != quiche::Type::Initial || header.version != quiche::PROTOCOL_VERSION {
            continue;
        }
        let mut scid = [0u8; 16];
        getrandom::fill(&mut scid).expect("random");
        let cid = quiche::ConnectionId::from_ref(&scid);
        let mut fresh = quiche::accept(&cid, None, local, from, config).expect("accepts");
        let info = quiche::RecvInfo { from, to: local };
        fresh.recv(&mut buf[..n], info).expect("handshakes");
        while let Ok((written, info)) = fresh.send(&mut out) {
            let _ = sock.send_to(&out[..written], info.to);
        }
        break fresh;
    };
    while !conn.is_established() {
        if let Some((n, from)) = server_poll(sock, &mut buf) {
            let info = quiche::RecvInfo { from, to: local };
            conn.recv(&mut buf[..n], info).expect("drives");
            while let Ok((written, info)) = conn.send(&mut out) {
                let _ = sock.send_to(&out[..written], info.to);
            }
        } else {
            server_idle(&mut conn, sock, &mut out);
        }
    }
    conn
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A returned buffer is the next one handed out, so the pool never zeroes a datagram twice.
    #[test]
    fn a_returned_datagram_buffer_is_reused_without_an_allocation() {
        let mut first = Unfilled::<256>::new();
        first.as_mut()[0] = 0xa5;
        drop(first);
        let (mut second, counts) = ferrox_core::alloc_count::measure(Unfilled::<256>::new);
        assert_eq!(counts.allocs, 0, "a returned buffer is reused");
        assert_eq!(
            second.as_mut()[0],
            0xa5,
            "the reused buffer keeps the bytes it already had"
        );
    }

    /// Only a refusal that clears is retried: a held datagram is a second chance, and a
    /// path that has ended has no next sweep to take it.
    #[test]
    fn a_refusal_that_clears_is_the_only_one_held() {
        for clears in [
            std::io::Error::from(std::io::ErrorKind::WouldBlock),
            std::io::Error::from(std::io::ErrorKind::Interrupted),
            std::io::Error::from_raw_os_error(libc::ENOBUFS),
        ] {
            assert!(refused(&clears), "{clears} clears");
        }
        for ended in [
            std::io::Error::from_raw_os_error(libc::ECONNREFUSED),
            std::io::Error::from_raw_os_error(libc::ENETUNREACH),
            std::io::Error::from(std::io::ErrorKind::InvalidInput),
        ] {
            assert!(!refused(&ended), "{ended} does not clear");
        }
    }

    /// A halted sweep leaves datagrams held, and the next one retries them in the
    /// order quiche wrote. Loopback drops a datagram a full queue cannot take rather
    /// than refusing the write, so a live refusal cannot be staged here: what this
    /// holds is the queue's order and the flag that makes the retry free, and the
    /// masque matrix cell is where a kernel refusal meets the hold for real.
    #[test]
    fn a_held_datagram_is_retried_in_order() {
        let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind the receiver");
        let to = receiver.local_addr().expect("the receiver's address");
        let sender = Datagram::plain(UdpSocket::bind("127.0.0.1:0").expect("bind the sender"));
        let held: Vec<Vec<u8>> = (0..8u8).map(|index| vec![index; 64]).collect();
        for bytes in &held {
            sender.hold(bytes, to);
        }
        assert!(
            sender.held.holding.load(Ordering::Relaxed),
            "a hold is what a sweep retries"
        );
        sender.retry_held();
        assert!(
            !sender.held.holding.load(Ordering::Relaxed),
            "an empty queue arms no retry"
        );

        receiver.set_nonblocking(true).expect("a reading queue");
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut got = Vec::new();
        let mut buf = [0u8; 128];
        while got.len() < held.len() && Instant::now() < deadline {
            match receiver.recv_from(&mut buf) {
                Ok((n, _)) => got.push(buf[..n].to_vec()),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("recv: {error}"),
            }
        }
        assert_eq!(
            got, held,
            "every held datagram arrives once, in the order it was held"
        );
    }

    /// A retry that cannot drain must stop the sweep before new datagrams overtake it.
    #[test]
    fn a_blocked_retry_stops_the_sweep() {
        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind the peer");
        peer.set_nonblocking(true).expect("nonblocking");
        let to = peer.local_addr().expect("the peer's address");
        let socket = bind_datagram("127.0.0.1:0").expect("bind the sender");
        let local = socket.local_addr().expect("the sender's address");
        let sock = Datagram::plain(socket);

        sock.hold(b"older", to);
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = sock.held.queue.lock().expect("lock the queue");
            panic!("poison the held queue");
        }));
        assert!(poisoned.is_err(), "the queue is left holding");
        assert!(sock.held.holding.load(Ordering::Relaxed));

        let mut scid = [0u8; SCID_LEN];
        getrandom::fill(&mut scid).expect("random");
        let cid = quiche::ConnectionId::from_ref(&scid);
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("config");
        config.set_application_protos(&[ALPN]).expect("alpn");
        let mut conn =
            quiche::connect(Some("held.test"), &cid, local, to, &mut config).expect("connects");

        flush_egress(&mut conn, &sock);
        let mut buf = [0u8; 2048];
        let mut received = false;
        for _ in 0..50 {
            match peer.recv_from(&mut buf) {
                Ok(_) => {
                    received = true;
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(_) => break,
            }
        }
        assert!(
            !received,
            "a blocked retry must stop the sweep before new datagrams"
        );
    }

    /// The store is read once, not once per dial: two calls name the same allocation rather than the same bytes.
    #[test]
    fn the_platform_anchors_are_read_once() {
        assert!(
            Arc::ptr_eq(&system_roots(), &system_roots()),
            "one allocation answers for every caller"
        );
    }

    /// Trust anchors come from the platform bundle, so a publicly trusted host is not trusted by nothing.
    #[test]
    fn the_platform_bundle_is_read_into_trust_anchors() {
        let roots = system_roots();
        if cfg!(any(target_os = "macos", target_os = "linux")) {
            assert!(roots.len() > 50, "a bundle with {} anchors", roots.len());
        }
        assert_eq!(parse_ca_pem(b"not a pem at all"), Vec::<Vec<u8>>::new());
    }

    /// A path that drops QUIC is silence, not a budget: the handshake is abandoned at its silence floor rather than waited out.
    #[test]
    fn a_silent_quic_path_is_abandoned_before_the_handshake_budget() {
        let peer = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let sock = bind_datagram("127.0.0.1:0").expect("binds");
        let local = sock.local_addr().expect("local");
        let sock = Datagram::plain(sock);
        let mut scid = [0u8; SCID_LEN];
        getrandom::fill(&mut scid).expect("random");
        let cid = quiche::ConnectionId::from_ref(&scid);
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("config");
        config.set_application_protos(&[ALPN]).expect("alpn");
        let mut conn = quiche::connect(
            Some("silent.test"),
            &cid,
            local,
            peer.local_addr().expect("peer"),
            &mut config,
        )
        .expect("connects");
        let started = Instant::now();
        let answer = drive_handshake_watching(
            &mut conn,
            &sock,
            local,
            HANDSHAKE_TIMEOUT,
            Duration::from_millis(50),
        );
        assert!(answer.is_none(), "a silent path never establishes");
        assert_eq!(conn.stats().recv, 0, "nothing answered");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "abandoned in {:?}, not at the {} s budget",
            started.elapsed(),
            HANDSHAKE_TIMEOUT.as_secs()
        );
    }

    /// The read option is why a GSO burst is one syscall on the receive side, so it is read back rather than assumed.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_quic_socket_is_bound_with_datagram_coalescing_on() {
        fn gro(sock: &UdpSocket) -> Option<bool> {
            use std::os::fd::AsRawFd as _;
            let mut on: libc::c_int = -1;
            let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())
                .expect("size fits a socklen");
            // SAFETY: `on` and `len` describe the buffer the kernel writes into.
            let got = unsafe {
                libc::getsockopt(
                    sock.as_raw_fd(),
                    libc::SOL_UDP,
                    libc::UDP_GRO,
                    std::ptr::addr_of_mut!(on).cast(),
                    std::ptr::addr_of_mut!(len),
                )
            };
            (got == 0).then_some(on == 1)
        }
        let probe = bind_datagram("127.0.0.1:0").expect("binds");
        if gro(&probe) != Some(true) {
            return;
        }
        let sock = bind_datagram("127.0.0.1:0").expect("binds");
        assert_eq!(gro(&sock), Some(true), "a GSO burst is coalesced");
        let obfs = || ferrox_core::hysteria::Salamander::new("hy2!").expect("four-byte key");
        let masked = Datagram::obfuscated(bind_datagram("127.0.0.1:0").expect("binds"), obfs());
        assert_eq!(
            gro(&masked.sock),
            Some(false),
            "a masked lane reads one datagram at a time"
        );
        assert!(udp_to_server("127.0.0.1", 443).is_some(), "still dials");
    }

    /// A GSO burst is one `sendmsg` on the wire and the same packets on the read side: the segment size the kernel
    /// reports is what `recv_batch` cuts, so a coalesced slot hands quiche the packets `sendmmsg` would have handed it.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_gso_burst_arrives_as_its_segments() {
        let receiver = Datagram::plain(bind_datagram("127.0.0.1:0").expect("receiver binds"));
        let peer = receiver.local_addr().expect("receiver address");
        let sender = Datagram::plain(bind_datagram("127.0.0.1:0").expect("sender binds"));
        let mut slots: [Unfilled<MAX_DATAGRAM>; SEND_SLOTS] =
            std::array::from_fn(|_| Unfilled::<MAX_DATAGRAM>::new());
        for (at, slot) in slots.iter_mut().enumerate().take(2) {
            slot.as_mut()
                .fill(u8::try_from(at + 1).expect("two slots fit a byte"));
        }
        let mut lens = [0usize; SEND_SLOTS];
        lens[0] = MAX_DATAGRAM;
        lens[1] = MAX_DATAGRAM;
        match send_gso(&sender, &slots, &lens, 0, 2, Some(peer)) {
            Gso::Sent => {}
            Gso::Unsupported => return,
            Gso::Refused => panic!("the loopback queue refused a two-segment GSO datagram"),
        }
        let mut batch = Batch::new();
        assert_eq!(recv_batch(&receiver, &mut batch), Drain::Read);
        assert_eq!(batch.len(), 2, "the coalesced datagram is cut in two");
        for at in 0..2 {
            let (bytes, _) = batch.at(at).expect("segment");
            assert_eq!(bytes.len(), MAX_DATAGRAM);
            assert!(
                bytes
                    .iter()
                    .all(|byte| *byte == u8::try_from(at + 1).unwrap()),
                "segment {at} keeps its own bytes"
            );
        }
    }

    /// The lane asks for a receive buffer before a first datagram can land on it, and the ask is read back rather than assumed: a parked lane holds whatever the edge sent while no pump owned the socket, and a default buffer would drop it. The send side is the same ask: a burst quiche has already accounted for is lost if the kernel's queue is a macOS default.
    #[test]
    fn a_quic_socket_arms_both_of_its_buffers() {
        let sock = bind_datagram("127.0.0.1:0").expect("binds");
        assert!(
            receive_buffer(&sock) >= DATAGRAM_RECV_BUF_FLOOR,
            "the lane asked for {} and holds {}",
            DATAGRAM_BUFFER,
            receive_buffer(&sock)
        );
        assert!(
            send_buffer(&sock) >= DATAGRAM_RECV_BUF_FLOOR,
            "the lane asked for {} and holds {}",
            DATAGRAM_BUFFER,
            send_buffer(&sock)
        );
    }

    /// The datagram the lane builds is the datagram its own receive buffer holds: quiche's 1200-byte default
    /// leaves a 1350-byte packet unbuilt and costs a datagram for every 1200 bytes, and a real connection is
    /// where that is read — the size quiche's packet builder takes is the one the peer's transport parameters
    /// and this config agree on, and the lane's own advertisement is the buffer it can actually read into.
    #[test]
    fn the_lane_sends_the_datagram_its_buffer_holds() {
        let (client, mut server) = lane_pair();
        assert_eq!(
            client.conn.max_send_udp_payload_size(),
            MAX_DATAGRAM,
            "the size quiche's packet builder is handed"
        );
        let pattern: Vec<u8> = (0..16 * 1024).map(|i| (i % 251) as u8).collect();
        let wrote = server.conn.stream_send(1, &pattern, false).expect("writes");
        flush_egress(&mut server.conn, &server.sock);
        let _ = client
            .sock
            .set_read_timeout(Some(Duration::from_millis(20)));
        let packets = drain_packets(&client.sock);
        let datagrams = packets.len();
        let widest = packets
            .iter()
            .map(|(bytes, _)| bytes.len())
            .max()
            .unwrap_or(0);
        assert!(
            datagrams > 1,
            "the frame leaves as a burst, saw {datagrams}"
        );
        assert_eq!(
            widest, MAX_DATAGRAM,
            "every full packet carries {MAX_DATAGRAM} bytes of the {wrote} written"
        );
    }

    /// The ceiling leaves the receiver's autotuner room to double: quiche grows a window by two each time it is
    /// drained twice inside two round trips, up to `max_window`. A ceiling equal to the initial window turns
    /// every one of those doublings into a no-op, and the flow is then paced by `window / rtt` for its whole life.
    /// The product is the arithmetic: 1 Gbit/s holds 64 ms of bytes in flight in 8 MB and 256 ms in 32 MB.
    #[test]
    fn the_window_ceiling_leaves_the_autotuner_room() {
        let stream = std::hint::black_box(MAX_STREAM_WINDOW);
        let connect = std::hint::black_box(MAX_CONNECTION_WINDOW);
        assert!(stream > MAX_STREAM_DATA, "a stream ceiling above its floor");
        assert!(connect > MAX_DATA, "a connection ceiling above its floor");
        assert_eq!(stream, in_flight(std::hint::black_box(WINDOW_RATE), 64));
        assert_eq!(connect, in_flight(std::hint::black_box(WINDOW_RATE), 256));
        assert!(
            connect >= stream,
            "one stream cannot outgrow the connection that carries it"
        );
    }

    #[test]
    fn a_relayed_datagram_frames_its_target_ahead_of_its_payload() {
        use crate::conn::Connection;
        let association = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let control = Connection::connect(association.local_addr().expect("addr")).expect("dials");
        let _ = association.accept().expect("accepts");
        let hop = bind_datagram("127.0.0.1:0").expect("binds");
        let target = bind_datagram("127.0.0.1:0").expect("binds");
        let lane = Datagram::relayed(
            bind_datagram("127.0.0.1:0").expect("binds"),
            hop.local_addr().expect("addr"),
            std::sync::Arc::new(control),
        );
        let SocketAddr::V4(target) = target.local_addr().expect("addr") else {
            panic!("a v4 target");
        };
        lane.send_to(b"ping", target.into())
            .expect("frames and sends");
        hop.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("times out");
        let mut got = [0u8; 32];
        let (n, _) = hop.recv_from(&mut got).expect("the hop reads it");
        let mut want = vec![0, 0, 0, 1];
        want.extend_from_slice(&target.ip().octets());
        want.extend_from_slice(&target.port().to_be_bytes());
        want.extend_from_slice(b"ping");
        assert_eq!(
            &got[..n],
            &want[..],
            "reserved, fragment, family, address, port, payload"
        );
    }

    #[test]
    fn an_obfuscated_read_unmasks_where_the_wire_bytes_landed() {
        let key = "hy2!";
        let server = Datagram::obfuscated(
            bind_datagram("127.0.0.1:0").expect("binds"),
            ferrox_core::hysteria::Salamander::new(key).expect("four-byte key"),
        );
        let peer = server.local_addr().expect("addr");
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("times out");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let salt = [7u8; ferrox_core::hysteria::SALAMANDER_SALT];
        let plain = [0x33u8; 200];
        let mut wire = Vec::new();
        ferrox_core::hysteria::Salamander::new(key)
            .expect("four-byte key")
            .obfuscate_with_salt(&salt, &plain, &mut wire);
        sender.send_to(&wire, peer).expect("sends");
        let mut got = [0x5au8; RECV_ROOM];
        let (n, _) = server.recv_from(&mut got).expect("reads a salted frame");
        assert_eq!(n, plain.len(), "the salt never reaches the caller");
        assert_eq!(&got[..n], &plain[..], "unmasked to the bytes that went in");
        // The unmask shifted the payload to the front of this buffer, so the salt-wide tail it never reaches still holds the frame's masked end; a copy out of a scratch would have left the caller's own bytes there.
        let tail = ferrox_core::hysteria::SALAMANDER_SALT;
        assert_eq!(
            &got[n..n + tail],
            &wire[n..n + tail],
            "the read did not unmask in the caller's own buffer"
        );
    }

    #[test]
    fn an_obfuscated_lane_round_trips_a_full_datagram_over_loopback() {
        let obfs = || ferrox_core::hysteria::Salamander::new("hy2!").expect("four-byte key");
        let server = Datagram::obfuscated(bind_datagram("127.0.0.1:0").expect("binds"), obfs());
        let client = Datagram::obfuscated(bind_datagram("127.0.0.1:0").expect("binds"), obfs());
        let peer = server.local_addr().expect("addr");
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("times out");
        // A full-sized plain datagram is salt wider on the wire, so the send frame is one the caller buffer was never sized for.
        let plain = [0x5au8; MAX_DATAGRAM];
        client.send_to(&plain, peer).expect("seals and sends");
        let mut got = [0u8; MAX_DATAGRAM];
        let (n, from) = server.recv_from(&mut got).expect("reads a salted frame");
        assert_eq!(n, plain.len(), "the salt never reaches the caller");
        assert_eq!(&got[..n], &plain[..], "unmasked to the bytes that went in");
        assert_eq!(
            from,
            client.local_addr().expect("addr"),
            "the peer survives the hop"
        );
    }

    #[test]
    fn base64_matches_the_rfc_vectors() {
        let mut block = [0u8; 64];
        for (raw, text) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foobar", "Zm9vYmFy"),
        ] {
            let n = base64_encode_block(&mut block, raw.as_bytes());
            assert_eq!(&block[..n], text.as_bytes());
            let mut back = Vec::new();
            assert!(base64_decode(&block[..n], &mut back));
            assert_eq!(back, raw.as_bytes());
        }
        let mut garbage = Vec::new();
        assert!(!base64_decode(b"!!!", &mut garbage));
        assert!(!base64_decode(b"Zg=", &mut garbage));
        let long = vec![0xabu8; 50];
        let mut wrapped = Vec::new();
        for chunk in long.chunks(48) {
            let n = base64_encode_block(&mut block, chunk);
            wrapped.extend_from_slice(&block[..n]);
        }
        wrapped.insert(64, b'\n');
        let mut unwrapped = Vec::new();
        assert!(base64_decode(&wrapped, &mut unwrapped));
        assert_eq!(unwrapped, long);
    }

    #[test]
    fn pem_wraps_at_sixty_four_columns() {
        let pem = der_to_pem(&[0xabu8; 48], "CERTIFICATE");
        let text = std::str::from_utf8(&pem).expect("ascii");
        assert!(text.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(text.ends_with("-----END CERTIFICATE-----\n"));
        for line in text.lines().skip(1) {
            if line.starts_with("-----END") {
                break;
            }
            assert_eq!(line.len(), 64);
        }
        assert_eq!(parse_ca_pem(&pem), vec![vec![0xabu8; 48]]);
    }

    /// The allocation claim, gated: a PEM buffer reserved to `pem_capacity` lands at exactly its length, so filling it never reallocates and copies what was already written.
    #[test]
    fn a_pem_buffer_is_reserved_to_its_exact_length() {
        for len in [0usize, 1, 2, 3, 46, 47, 48, 49, 96, 97, 143, 300] {
            let pem = der_to_pem(&vec![0x5au8; len], "CERTIFICATE");
            assert_eq!(
                pem.len(),
                pem.capacity(),
                "len {len}: a slack capacity means a reallocation copied the prefix"
            );
        }
    }

    /// Pointer identity witnesses the removed double buffer: appending a second block into a buffer reserved for both leaves the first block's address unmoved, and the bytes are the concatenation the old `extend_from_slice(&der_to_pem(..))` produced.
    #[test]
    fn appending_into_a_reserved_buffer_does_not_move_it() {
        let first = der_to_pem(&[7u8; 30], "CERTIFICATE");
        let second = der_to_pem(&[9u8; 50], "CERTIFICATE");
        let mut chain = Vec::with_capacity(first.len() + second.len());
        append_pem(&mut chain, &[7u8; 30], "CERTIFICATE");
        let base = chain.as_ptr();
        append_pem(&mut chain, &[9u8; 50], "CERTIFICATE");
        assert_eq!(
            base,
            chain.as_ptr(),
            "the second append reallocated away the first — a copy the reservation was meant to avoid"
        );
        let mut want = first;
        want.extend_from_slice(&second);
        assert_eq!(
            chain, want,
            "the appended bytes match the old double-buffer output"
        );
    }

    /// Bit-identity across the wrap and pad boundaries: the reservation changed where bytes land, never which bytes.
    #[test]
    fn pem_survives_the_pad_and_wrap_boundaries() {
        for len in [1usize, 2, 3, 4, 46, 47, 48, 49, 50, 51, 95, 96, 97] {
            let der: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i).expect("len < 256"))
                .collect();
            let pem = der_to_pem(&der, "CERTIFICATE");
            assert_eq!(parse_ca_pem(&pem), vec![der], "len {len}");
        }
    }

    #[test]
    fn corrupt_bundle_parses_to_nothing() {
        assert_eq!(parse_ca_pem(b"no blocks here"), Vec::<Vec<u8>>::new());
        let mut pem = der_to_pem(&[1u8; 32], "CERTIFICATE");
        pem.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----\n");
        assert_eq!(parse_ca_pem(&pem), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn the_base64_table_agrees_with_the_alphabet() {
        for byte in 0..=u8::MAX {
            let scanned = B64
                .iter()
                .position(|digit| *digit == byte)
                .map_or(u8::MAX, |slot| slot as u8);
            assert_eq!(B64_TABLE[usize::from(byte)], scanned, "byte {byte:#04x}");
        }
        for (slot, digit) in B64.iter().enumerate() {
            assert_eq!(base64_value(*digit), Some(slot as u8));
        }
        for byte in [b'=', b' ', b'\n', b'!', 0, 0xff] {
            assert_eq!(base64_value(byte), None);
        }
    }

    fn owned_staging_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("ferrox-quic-test-{}-{tag}.pem", std::process::id()))
    }

    #[test]
    fn staging_refuses_a_name_something_else_already_holds() {
        let path = owned_staging_path("taken");
        std::fs::write(&path, b"planted").expect("plants");
        assert!(stage_at(&path, b"mine").is_none());
        assert_eq!(std::fs::read(&path).expect("reads"), b"planted");
        std::fs::remove_file(&path).expect("removes");
        let (back, text) = stage_at(&path, b"mine").expect("stages");
        assert_eq!(back, path);
        assert_eq!(text, path.to_string_lossy());
        assert_eq!(std::fs::read(&path).expect("reads"), b"mine");
        std::fs::remove_file(&path).expect("removes");
    }

    #[test]
    fn staging_returns_the_name_it_wrote_so_the_caller_can_remove_it() {
        let path = owned_staging_path("removable");
        let (back, text) = stage_at(&path, b"bundle").expect("stages");
        assert_eq!(back, path);
        assert_eq!(text, path.to_string_lossy());
        assert_eq!(std::fs::read(&path).expect("reads"), b"bundle");
        std::fs::remove_file(&path).expect("removes");
        assert!(!path.exists());
    }

    #[test]
    fn one_trust_bundle_shares_its_built_config() {
        let minted = rcgen::generate_simple_self_signed(vec!["shared-config.test".to_owned()])
            .expect("mints");
        let roots = parse_ca_pem(minted.cert.pem().as_bytes());
        let other = rcgen::generate_simple_self_signed(vec!["other-config.test".to_owned()])
            .expect("mints");
        let built = |roots: &[Vec<u8>]| {
            with_config(roots, |config| Some(std::ptr::from_ref(config))).expect("builds")
        };
        let (first, again) = (built(&roots), built(&roots));
        assert!(
            std::ptr::eq(first, again),
            "a second dial staged a second bundle"
        );
        assert!(
            !std::ptr::eq(first, built(&parse_ca_pem(other.cert.pem().as_bytes()))),
            "a second bundle rode the first one's config"
        );
        assert!(
            with_config(&[], |_| Some(())).is_none(),
            "a bundle that would not build was cached as one that did"
        );
    }

    #[test]
    fn a_warm_config_lookup_allocates_nothing() {
        let roots = system_roots();
        with_config(&roots, |_| Some(())).expect("builds");
        let ((), counts) = ferrox_core::alloc_count::measure(|| {
            for _ in 0..4096 {
                with_config(&roots, |_| Some(())).expect("warms");
            }
        });
        assert_eq!(
            counts.allocs, 0,
            "a warm dial asks the cache with the caller's own anchors"
        );
    }

    #[test]
    fn config_refuses_without_trust() {
        assert!(quiche_config(&[], None).is_none());
        assert!(quiche_config(&[vec![0u8; 16]], None).is_none());
    }

    fn minted_identity() -> ferrox_core::tls::TlsServerConfig {
        minted_identity_for("quic.test")
    }

    fn minted_identity_for(name: &str) -> ferrox_core::tls::TlsServerConfig {
        let minted = rcgen::generate_simple_self_signed(vec![name.to_owned()]).expect("mints");
        let roots = parse_ca_pem(minted.cert.pem().as_bytes());
        assert_ne!(roots, Vec::<Vec<u8>>::new());
        ferrox_core::tls::TlsServerConfig {
            certs: vec![ferrox_core::tls::CertEntry {
                cert_chain: roots,
                key_der: minted.signing_key.serialize_der(),
                key_kind: ferrox_core::tls::ServerKeyKind::Pkcs8,
                reload: None,
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

    /// The X25519 key behind `ECH_CONFIG`'s public half, shared with the TLS ECH test.
    const ECH_PRIVATE_KEY: [u8; 32] = [
        0x78, 0xb5, 0xc8, 0x5f, 0x0f, 0x03, 0x50, 0x06, 0x9b, 0x97, 0x32, 0x9f, 0x44, 0x8e, 0xbe,
        0x95, 0x8e, 0x4b, 0x34, 0x77, 0x71, 0x3d, 0x5a, 0xc6, 0x51, 0x0c, 0x69, 0x51, 0x98, 0xd1,
        0xe8, 0x78,
    ];

    /// An `ECHConfig` for `public.test` whose X25519 public half matches `ECH_PRIVATE_KEY`.
    const ECH_CONFIG: &[u8] = &[
        0xfe, 0x0d, 0x00, 0x3a, 0x07, 0x00, 0x20, 0x00, 0x20, 0x2a, 0xb0, 0xe0, 0x4c, 0x48, 0x44,
        0x9d, 0xa1, 0x19, 0x81, 0x50, 0xc8, 0xf0, 0x45, 0xf0, 0x35, 0xd0, 0xb8, 0xb1, 0xca, 0xc4,
        0x0c, 0x29, 0xcd, 0x46, 0x0b, 0xbf, 0xae, 0x95, 0xb8, 0xd7, 0x03, 0x00, 0x04, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x0b, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2e, 0x74, 0x65, 0x73, 0x74,
        0x00, 0x00,
    ];

    fn ech_server_key_tlv() -> Vec<u8> {
        let mut keys = Vec::with_capacity(4 + ECH_PRIVATE_KEY.len() + ECH_CONFIG.len());
        keys.extend_from_slice(&(ECH_PRIVATE_KEY.len() as u16).to_be_bytes());
        keys.extend_from_slice(&ECH_PRIVATE_KEY);
        keys.extend_from_slice(&(ECH_CONFIG.len() as u16).to_be_bytes());
        keys.extend_from_slice(ECH_CONFIG);
        keys
    }

    fn ech_identity() -> ferrox_core::tls::TlsServerConfig {
        let mut identity = minted_identity();
        identity.ech_server_keys = Some(ech_server_key_tlv().into());
        identity
    }

    fn ech_client_list() -> Vec<u8> {
        let mut list = Vec::with_capacity(2 + ECH_CONFIG.len());
        list.extend_from_slice(&(ECH_CONFIG.len() as u16).to_be_bytes());
        list.extend_from_slice(ECH_CONFIG);
        list
    }

    #[test]
    fn a_two_entry_identity_builds_every_context() {
        let mut identity = minted_identity_for("first.test");
        identity
            .certs
            .push(minted_identity_for("second.test").certs.remove(0));
        assert!(
            tls_config(&identity).is_some(),
            "both entries build on the serving context"
        );
    }

    #[test]
    fn serve_config_loads_a_minted_identity() {
        assert!(serve_config(&minted_identity()).is_some());
        let mut rejecting = minted_identity();
        rejecting.reject_unknown_sni = true;
        assert!(
            serve_config(&rejecting).is_some(),
            "the SNI rule builds on the QUIC context"
        );
    }

    #[test]
    fn the_certificate_the_sni_names_is_the_one_served() {
        let mut identity = minted_identity_for("first.test");
        identity
            .certs
            .push(minted_identity_for("second.test").certs.remove(0));
        let (client, server) = lane_pair_of_name(
            &identity,
            Some("second.test"),
            &identity.certs[1].cert_chain,
            None,
        );
        assert!(client.conn.is_established() && server.conn.is_established());
    }

    #[test]
    fn a_hello_without_a_name_answers_the_first_certificate() {
        let mut identity = minted_identity_for("first.test");
        identity
            .certs
            .push(minted_identity_for("second.test").certs.remove(0));
        let (client, server) =
            lane_pair_of_name(&identity, None, &identity.certs[0].cert_chain, None);
        assert!(client.conn.is_established() && server.conn.is_established());
    }

    #[test]
    fn a_hello_without_a_name_is_refused_when_the_list_rejects_it() {
        let mut identity = minted_identity_for("first.test");
        identity
            .certs
            .push(minted_identity_for("second.test").certs.remove(0));
        identity.reject_unknown_sni = true;
        let (client, server) =
            lane_pair_raw(&identity, None, &identity.certs[0].cert_chain, None, false);
        assert!(
            !client.conn.is_established() && !server.conn.is_established(),
            "an unnamed hello is refused when the list rejects unknown names"
        );
    }

    #[test]
    fn an_unknown_name_is_refused_when_the_list_rejects_it() {
        let mut identity = minted_identity_for("first.test");
        identity
            .certs
            .push(minted_identity_for("second.test").certs.remove(0));
        identity.reject_unknown_sni = true;
        let (client, server) = lane_pair_raw(
            &identity,
            Some("other.test"),
            &identity.certs[0].cert_chain,
            None,
            false,
        );
        assert!(
            !client.conn.is_established() && !server.conn.is_established(),
            "the unmatched hello is refused before a certificate"
        );
    }

    #[test]
    fn serve_config_builds_the_ech_context() {
        assert!(serve_config(&ech_identity()).is_some());
        let mut broken = ech_identity();
        broken.ech_server_keys = Some(vec![0, 1, 2].into());
        assert!(serve_config(&broken).is_none());
    }

    #[test]
    fn serve_config_refuses_without_a_chain_or_key() {
        let empty = ferrox_core::tls::TlsServerConfig {
            certs: Vec::new(),
            alpn: Vec::new(),
            min_version: None,
            max_version: None,
            cipher_suites: Vec::new(),
            send_tickets: true,
            reject_unknown_sni: false,
            server_config_cache: std::sync::Arc::default(),
            ech_server_keys: None,
            master_key_log: None,
        };
        assert!(serve_config(&empty).is_none());
        let mut no_key = minted_identity();
        no_key.certs[0].key_der = vec![0u8; 16];
        assert!(serve_config(&no_key).is_none());
    }

    #[test]
    fn config_loads_a_minted_anchor() {
        let minted =
            rcgen::generate_simple_self_signed(vec!["quic.test".to_owned()]).expect("mints");
        let roots = parse_ca_pem(minted.cert.pem().as_bytes());
        assert_ne!(roots, Vec::<Vec<u8>>::new());
        assert!(quiche_config(&roots, None).is_some());
        assert!(quiche_config(&roots, Some("bbr")).is_some());
        assert!(quiche_config(&roots, Some("no-such-cc")).is_none());
    }

    /// A handful of listeners stand in for the ports a firewall forwards to one
    /// server. A zero-millisecond stay forces the schedule to move on every send, so
    /// a burst aimed at the nominal address must spread over more than one port and
    /// every datagram must land on exactly one — a witness that the egress port is
    /// really rewritten and that the move opens a real, delivering socket.
    #[test]
    fn a_hopped_dial_spreads_its_datagrams_over_more_than_one_server_port() {
        const MAGIC: &[u8] = b"hop-spread";
        let mut ports = Vec::new();
        let mut listeners = Vec::new();
        for _ in 0..4 {
            let sock = UdpSocket::bind("127.0.0.1:0").expect("binds");
            ports.push(sock.local_addr().expect("addr").port());
            sock.set_read_timeout(Some(Duration::from_millis(20))).ok();
            listeners.push(sock);
        }
        let server: SocketAddr = format!("127.0.0.1:{}", ports[0]).parse().expect("addr");
        let first = UdpSocket::bind("0.0.0.0:0").expect("binds");
        let hop = Datagram::hopped(server, ports.clone(), (0, 0), "0.0.0.0:0", &first, None)
            .expect("hops");
        let sends = 200;
        for _ in 0..sends {
            hop.send_to(MAGIC, server).expect("sends");
        }
        let mut received = 0usize;
        let mut touched = std::collections::HashSet::new();
        for listener in &listeners {
            let mut buf = [0u8; 64];
            while let Ok((n, _)) = listener.recv_from(&mut buf) {
                if n != MAGIC.len() || &buf[..n] != MAGIC {
                    continue;
                }
                received += 1;
                touched.insert(listener.local_addr().expect("addr").port());
            }
        }
        assert_eq!(received, sends, "every datagram reached exactly one port");
        assert!(
            touched.len() > 1,
            "the plan moved off the single dialed port"
        );
    }

    /// A long stay holds the schedule still, so one socket carries the flow. The
    /// opening pick is some port other than the nominal one; whichever listener
    /// receives the burst is the current port, and its reply must read back with the
    /// nominal server port so QUIC above, which named the peer by one address, still
    /// accepts it — the witness that a hopped reply source is turned back.
    #[test]
    fn a_reply_from_a_hopped_port_reads_back_as_the_nominal_server() {
        let mut ports = Vec::new();
        let mut listeners = Vec::new();
        for _ in 0..4 {
            let sock = UdpSocket::bind("127.0.0.1:0").expect("binds");
            ports.push(sock.local_addr().expect("addr").port());
            sock.set_read_timeout(Some(Duration::from_millis(50))).ok();
            listeners.push(sock);
        }
        let server: SocketAddr = format!("127.0.0.1:{}", ports[0]).parse().expect("addr");
        let first = UdpSocket::bind("0.0.0.0:0").expect("binds");
        let first_port = first.local_addr().expect("addr").port();
        let still = u64::MAX / 4;
        let hop = Datagram::hopped(
            server,
            ports.clone(),
            (still, still),
            "0.0.0.0:0",
            &first,
            None,
        )
        .expect("hops");
        hop.send_to(b"ping", server).expect("sends");
        let mut landed = None;
        for listener in &listeners {
            let mut buf = [0u8; 64];
            while let Ok((n, src)) = listener.recv_from(&mut buf) {
                if n > 0 && src.port() == first_port {
                    listener.send_to(b"pong", src).expect("replies");
                    landed = Some(listener.local_addr().expect("addr").port());
                    break;
                }
            }
            if landed.is_some() {
                break;
            }
        }
        let hop_port = landed.expect("the burst landed on a hopped port");
        assert_ne!(
            hop_port,
            server.port(),
            "the current port is not the nominal"
        );
        let mut buf = [0u8; 64];
        hop.set_read_timeout(Some(Duration::from_millis(100)))
            .expect("timeout");
        let deadline = Instant::now() + Duration::from_secs(5);
        let (n, from) = loop {
            match hop.recv_from(&mut buf) {
                Ok((n, from)) if from.ip() == server.ip() && from.port() == server.port() => {
                    break (n, from);
                }
                Ok(_) => {}
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.kind() == std::io::ErrorKind::TimedOut => {}
                Err(error) => panic!("reads the reply: {error}"),
            }
            assert!(
                Instant::now() < deadline,
                "the nominal server did not reply"
            );
        };
        assert_eq!(&buf[..n], b"pong");
        assert_eq!(from.ip(), server.ip());
        assert_eq!(
            from.port(),
            server.port(),
            "the hopped source became the nominal"
        );
    }

    fn gecko_salamander() -> ferrox_core::hysteria::Salamander {
        ferrox_core::hysteria::Salamander::new("gecko-key").expect("a usable key")
    }

    fn gecko_window() -> ferrox_core::hysteria::Gecko {
        ferrox_core::hysteria::Gecko::new(512, 1200).expect("a valid window")
    }

    /// Two gecko dials face each other over loopback. A long-header packet written by
    /// one arrives at the other split across several datagrams and reassembles to the
    /// exact bytes, and a short-header packet passes through as one — the witness that
    /// the fragmenter, the salamander mask and the reassembly agree end to end.
    #[test]
    fn a_gecko_dial_reassembles_its_split_long_header() {
        let a = UdpSocket::bind("0.0.0.0:0").expect("binds");
        let writer_port = a.local_addr().expect("addr").port();
        let b = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let b_addr = b.local_addr().expect("addr");
        b.set_read_timeout(Some(Duration::from_millis(400)))
            .expect("timeout");
        let writer = Datagram::gecked(a, gecko_salamander(), gecko_window()).expect("geckos");
        let reader = Datagram::gecked(b, gecko_salamander(), gecko_window()).expect("geckos");
        // A QUIC long header (byte 0 high bit set), at a length no chunk count divides so the last chunk carries a real remainder.
        let mut packet: Vec<u8> = (0u16..900).map(|i| (i % 251) as u8).collect();
        packet[0] |= ferrox_core::hysteria::GECKO_FLAG;
        writer.send_to(&packet, b_addr).expect("sends");
        let mut buf = [0u8; 2048];
        let (n, _from) = loop {
            let (n, from) = reader.recv_from(&mut buf).expect("reassembles");
            if from.port() == writer_port {
                break (n, from);
            }
        };
        assert_eq!(&buf[..n], &packet[..], "the split packet rebuilt exactly");
        assert_eq!(n, packet.len());
        // A short-header packet is masked whole and comes back as a single pass-through.
        let short = vec![0x40u8; 40];
        writer.send_to(&short, b_addr).expect("sends short");
        let (m, _) = loop {
            let (m, from) = reader.recv_from(&mut buf).expect("reads short");
            if from.port() == writer_port {
                break (m, from);
            }
        };
        assert_eq!(&buf[..m], &short[..], "a short header is not fragmented");
    }

    /// A peer that never fragments still reads back whole: a long-header packet sent
    /// by a gecko dial is split on the wire, so more than one datagram must reach the
    /// listening socket — the witness that the fragmentation really happens, not that
    /// the writer merely happened to send one packet.
    #[test]
    fn a_gecko_long_header_leaves_the_socket_as_more_than_one_datagram() {
        let server = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let server_addr = server.local_addr().expect("addr");
        server
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("timeout");
        let client = UdpSocket::bind("0.0.0.0:0").expect("binds");
        let client_port = client.local_addr().expect("addr").port();
        let writer = Datagram::gecked(client, gecko_salamander(), gecko_window()).expect("geckos");
        let mut packet: Vec<u8> = vec![0xab; 900];
        packet[0] = ferrox_core::hysteria::GECKO_FLAG;
        writer.send_to(&packet, server_addr).expect("sends");
        let mut datagrams = 0usize;
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = server.recv_from(&mut buf) {
            if from.port() != client_port {
                continue;
            }
            if n == 0 {
                break;
            }
            datagrams += 1;
            // Each fragment sits inside the padded window the plan named.
            assert!(
                (512..=1200).contains(&n),
                "a fragment is padded into its window, saw {n}"
            );
        }
        assert!(
            datagrams >= 2,
            "a long header really split across datagrams, saw {datagrams}"
        );
    }

    /// A gecko dial that also hops: every fragment is a separate masked datagram,
    /// the schedule moves between them (a zero stay), and the padded window survives
    /// the hop — the witness that the fragmenter writes through the hop's socket
    /// rather than a fixed one.
    #[test]
    fn a_hopped_gecko_dial_sends_its_fragments_over_more_than_one_port() {
        let mut ports = Vec::new();
        let mut listeners = Vec::new();
        for _ in 0..4 {
            let sock = UdpSocket::bind("127.0.0.1:0").expect("binds");
            ports.push(sock.local_addr().expect("addr").port());
            sock.set_read_timeout(Some(Duration::from_millis(50))).ok();
            listeners.push(sock);
        }
        let server: SocketAddr = format!("127.0.0.1:{}", ports[0]).parse().expect("addr");
        let first = UdpSocket::bind("0.0.0.0:0").expect("binds");
        let writer = Datagram::gecked_hopped(
            server,
            ports.clone(),
            (0, 0),
            "0.0.0.0:0",
            &first,
            gecko_salamander(),
            gecko_window(),
        )
        .expect("geckos over a hop");
        let mut packet: Vec<u8> = vec![0xab; 900];
        packet[0] = ferrox_core::hysteria::GECKO_FLAG;
        writer.send_to(&packet, server).expect("sends");
        let mut datagrams = 0usize;
        let mut touched = std::collections::HashSet::new();
        for listener in &listeners {
            let mut buf = [0u8; 2048];
            while let Ok((n, _)) = listener.recv_from(&mut buf) {
                if n == 0 {
                    break;
                }
                datagrams += 1;
                touched.insert(listener.local_addr().expect("addr").port());
                assert!(
                    (512..=1200).contains(&n),
                    "a fragment is padded into its window, saw {n}"
                );
                let plain = n.min(packet.len());
                assert_ne!(
                    buf[..plain],
                    packet[..plain],
                    "a fragment left the socket inside its salamander mask"
                );
            }
        }
        assert!(
            datagrams >= 2,
            "a long header really split across datagrams, saw {datagrams}"
        );
        assert!(
            touched.len() > 1,
            "the fragments moved off the single dialed port"
        );
    }

    /// A hopped gecko writer and a plain gecko reader agree on the bytes: every
    /// fragment travels through the hop's send path, the reader reassembles, and the
    /// packet comes back exactly — the witness that composing the two lanes did not
    /// change a frame.
    #[test]
    fn a_hopped_gecko_dial_reassembles_at_a_plain_gecko_peer() {
        let reader_sock = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let reader_addr = reader_sock.local_addr().expect("addr");
        reader_sock
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("timeout");
        let reader =
            Datagram::gecked(reader_sock, gecko_salamander(), gecko_window()).expect("geckos");
        let first = UdpSocket::bind("0.0.0.0:0").expect("binds");
        let writer = Datagram::gecked_hopped(
            reader_addr,
            vec![reader_addr.port()],
            (0, 0),
            "0.0.0.0:0",
            &first,
            gecko_salamander(),
            gecko_window(),
        )
        .expect("geckos over a hop");
        let mut packet: Vec<u8> = (0u16..900).map(|i| (i % 251) as u8).collect();
        packet[0] |= ferrox_core::hysteria::GECKO_FLAG;
        writer.send_to(&packet, reader_addr).expect("sends");
        let mut buf = [0u8; 2048];
        let (n, _) = reader.recv_from(&mut buf).expect("reassembles");
        assert_eq!(&buf[..n], &packet[..], "the split packet rebuilt exactly");
    }

    /// A reply split across datagrams still reassembles when the hopped dial moves every
    /// stay: the socket the fragments landed on stays readable while the plan rotates past
    /// it, so the reply is drained instead of stranded.
    #[test]
    fn a_hopped_gecko_dial_reassembles_a_split_reply() {
        let server_sock = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let server_addr = server_sock.local_addr().expect("addr");
        server_sock
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("timeout");
        let server =
            Datagram::gecked(server_sock, gecko_salamander(), gecko_window()).expect("geckos");
        let first = UdpSocket::bind("0.0.0.0:0").expect("binds");
        let client = Datagram::gecked_hopped(
            server_addr,
            vec![server_addr.port()],
            (0, 0),
            "0.0.0.0:0",
            &first,
            gecko_salamander(),
            gecko_window(),
        )
        .expect("geckos over a hop");
        client
            .set_read_timeout(Some(Duration::from_millis(10)))
            .expect("timeout");

        // A short-header packet tells the server which hopped socket to answer on.
        client.send_to(b"hello", server_addr).expect("sends");
        let mut room = [0u8; 64];
        let (_, from) = server
            .recv_from(&mut room)
            .expect("the server reads the dial");
        // The answer is a long header, so the server splits it across several datagrams.
        let mut reply: Vec<u8> = (0u16..900).map(|i| (i % 251) as u8).collect();
        reply[0] |= ferrox_core::hysteria::GECKO_FLAG;
        server.send_to(&reply, from).expect("sends the reply");

        let mut buf = [0u8; 2048];
        let (n, _) = client.recv_from(&mut buf).expect("reassembles the reply");
        assert_eq!(&buf[..n], &reply[..], "the split reply rebuilt exactly");
    }

    /// A socket, its address and a connection that answers nothing: the pump's queue is what these witnesses read, so no peer and no handshake is needed to fill it.
    fn deaf_lane() -> (Datagram, SocketAddr, quiche::Connection) {
        let sock = Datagram::plain(bind_datagram("127.0.0.1:0").expect("binds"));
        let local = sock.local_addr().expect("addr");
        let mut config = serve_config(&minted_identity()).expect("serves");
        let mut cid = [0u8; 16];
        getrandom::fill(&mut cid).expect("random");
        let cid = quiche::ConnectionId::from_ref(&cid);
        let peer: SocketAddr = "127.0.0.1:53099".parse().expect("addr");
        let conn = quiche::accept(&cid, None, local, peer, &mut config).expect("accepts");
        (sock, local, conn)
    }

    /// Every packet a lane's socket holds, with a coalesced GSO burst cut back into the packets it carried.
    fn drain_packets(lane: &Datagram) -> Vec<(Vec<u8>, SocketAddr)> {
        let mut out = Vec::new();
        #[cfg(target_os = "linux")]
        {
            let mut batch = Batch::new();
            loop {
                match recv_batch(lane, &mut batch) {
                    Drain::Read => {
                        for at in 0..batch.len() {
                            if let Some((bytes, from)) = batch.at(at) {
                                out.push((bytes.to_vec(), from));
                            }
                        }
                    }
                    Drain::Empty | Drain::Unreadable => return out,
                    Drain::Unbatchable => break,
                }
            }
        }
        let mut room = [0u8; MAX_DATAGRAM];
        while let Ok((n, peer)) = lane.recv_from(&mut room) {
            out.push((room[..n].to_vec(), peer));
        }
        out
    }

    /// One side's sweep, then everything its peer's socket holds delivered into that peer: the handshake and the gate both ride the batched path rather than a ferry of their own.
    fn pass(
        from: &mut quiche::Connection,
        from_sock: &Datagram,
        to: &mut quiche::Connection,
        to_lane: &Datagram,
        to_addr: SocketAddr,
    ) {
        flush_egress(from, from_sock);
        let _ = to_lane.set_read_timeout(Some(Duration::from_millis(20)));
        for (mut bytes, peer) in drain_packets(to_lane) {
            let info = quiche::RecvInfo {
                from: peer,
                to: to_addr,
            };
            let _ = to.recv(&mut bytes, info);
        }
    }

    /// A lane: its socket, the address it holds, and the connection riding it.
    struct Lane {
        sock: Datagram,
        addr: SocketAddr,
        conn: quiche::Connection,
    }

    /// Client and server handshaked over two real loopback sockets, because a batched sweep is only readable from the peer's side of the wire.
    fn lane_pair() -> (Lane, Lane) {
        lane_pair_of(&minted_identity())
    }

    fn lane_pair_of(identity: &ferrox_core::tls::TlsServerConfig) -> (Lane, Lane) {
        lane_pair_of_offer(identity, None)
    }

    fn lane_pair_of_offer(
        identity: &ferrox_core::tls::TlsServerConfig,
        offer: Option<&[u8]>,
    ) -> (Lane, Lane) {
        lane_pair_of_name(
            identity,
            Some("quic.test"),
            &identity.certs[0].cert_chain,
            offer,
        )
    }

    fn lane_pair_of_name(
        identity: &ferrox_core::tls::TlsServerConfig,
        name: Option<&str>,
        roots: &[Vec<u8>],
        offer: Option<&[u8]>,
    ) -> (Lane, Lane) {
        let (client, server) = lane_pair_raw(identity, name, roots, offer, true);
        assert!(
            client.conn.is_established() && server.conn.is_established(),
            "the lane handshook over the very sweep under test"
        );
        (client, server)
    }

    fn lane_pair_raw(
        identity: &ferrox_core::tls::TlsServerConfig,
        name: Option<&str>,
        roots: &[Vec<u8>],
        offer: Option<&[u8]>,
        verify: bool,
    ) -> (Lane, Lane) {
        let mut server_config = serve_config(identity).expect("serves");
        server_config.set_active_connection_id_limit(4);
        let mut client_config = if verify {
            quiche_config(roots, None).expect("trusts")
        } else {
            let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("configures");
            config.verify_peer(false);
            config.set_application_protos(&[ALPN]).expect("negotiates");
            config
        };
        client_config.set_active_connection_id_limit(4);
        let server_sock = Datagram::plain(bind_datagram("127.0.0.1:0").expect("binds"));
        let server_addr = server_sock.local_addr().expect("addr");
        let client_sock = Datagram::plain(bind_datagram("127.0.0.1:0").expect("binds"));
        let client_addr = client_sock.local_addr().expect("addr");
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).expect("random");
        let server_id = quiche::ConnectionId::from_ref(&bytes);
        let server = quiche::accept(
            &server_id,
            None,
            server_addr,
            client_addr,
            &mut server_config,
        )
        .expect("accepts");
        getrandom::fill(&mut bytes).expect("random");
        let client_id = quiche::ConnectionId::from_ref(&bytes);
        let mut client = quiche::connect(
            name,
            &client_id,
            client_addr,
            server_addr,
            &mut client_config,
        )
        .expect("connects");
        if let Some(offer) = offer {
            client
                .as_mut()
                .set_ech_config_list(offer)
                .expect("offers ech");
        }
        let mut client = Lane {
            sock: client_sock,
            addr: client_addr,
            conn: client,
        };
        let mut server = Lane {
            sock: server_sock,
            addr: server_addr,
            conn: server,
        };
        for _ in 0..64 {
            pass(
                &mut client.conn,
                &client.sock,
                &mut server.conn,
                &server.sock,
                server.addr,
            );
            pass(
                &mut server.conn,
                &server.sock,
                &mut client.conn,
                &client.sock,
                client.addr,
            );
            if client.conn.is_established() && server.conn.is_established() {
                break;
            }
        }
        (client, server)
    }

    /// An ECH-serving lane still completes a QUIC handshake from a client that offers no ECH:
    /// the keys change the hello a server can open, never the fallback it answers.
    #[test]
    fn an_ech_serving_lane_answers_a_client_without_an_offer() {
        let (mut client, mut server) = lane_pair_of(&ech_identity());
        assert!(client.conn.is_established() && server.conn.is_established());
        assert!(!client.conn.as_mut().ech_accepted());
        assert!(!server.conn.as_mut().ech_accepted());
    }

    /// An ECH-serving lane opens the inner hello and both ends confirm it: the client knows
    /// the offer was taken, and the server read the name from the sealed half.
    #[test]
    fn an_ech_serving_lane_accepts_an_offer() {
        let list = ech_client_list();
        let (mut client, mut server) = lane_pair_of_offer(&ech_identity(), Some(&list));
        assert!(client.conn.is_established() && server.conn.is_established());
        assert!(
            client.conn.as_mut().ech_accepted(),
            "the client saw acceptance"
        );
        assert!(
            server.conn.as_mut().ech_accepted(),
            "the server opened the inner hello"
        );
    }

    /// A peer that rebinds its address keeps the lane: quiche validates the new path and the
    /// stream id is still the one both ends opened before the move.
    #[test]
    fn a_peer_rebind_keeps_the_quic_lane() {
        let (mut client, mut server) = lane_pair();
        let id = 0;
        let sent = client
            .conn
            .stream_send(id, b"before", false)
            .expect("opens");
        assert_eq!(sent, b"before".len());
        let mut buf = [0u8; 32];
        let mut got = 0;
        for _ in 0..64 {
            pass(
                &mut client.conn,
                &client.sock,
                &mut server.conn,
                &server.sock,
                server.addr,
            );
            match server.conn.stream_recv(id, &mut buf) {
                Ok((n, _)) => {
                    got = n;
                    break;
                }
                Err(quiche::Error::Done) => {}
                Err(error) => panic!("reads before the move: {error:?}"),
            }
        }
        assert_eq!(&buf[..got], b"before");

        for _ in 0..2 {
            let mut scid = [0u8; 16];
            getrandom::fill(&mut scid).expect("random");
            client
                .conn
                .new_scid(&quiche::ConnectionId::from_ref(&scid), 0, true)
                .expect("adds a client source id");
            getrandom::fill(&mut scid).expect("random");
            server
                .conn
                .new_scid(&quiche::ConnectionId::from_ref(&scid), 0, true)
                .expect("adds a server source id");
        }
        for _ in 0..4 {
            pass(
                &mut client.conn,
                &client.sock,
                &mut server.conn,
                &server.sock,
                server.addr,
            );
            pass(
                &mut server.conn,
                &server.sock,
                &mut client.conn,
                &client.sock,
                client.addr,
            );
        }

        let moved = Datagram::plain(bind_datagram("127.0.0.1:0").expect("binds"));
        let moved_addr = moved.local_addr().expect("addr");
        client
            .conn
            .migrate(moved_addr, server.addr)
            .expect("migrates");
        client.sock = moved;
        client.addr = moved_addr;
        client.conn.stream_send(id, b"after", false).expect("sends");

        let mut after = [0u8; 32];
        let mut got = 0;
        for _ in 0..64 {
            pass(
                &mut client.conn,
                &client.sock,
                &mut server.conn,
                &server.sock,
                server.addr,
            );
            pass(
                &mut server.conn,
                &server.sock,
                &mut client.conn,
                &client.sock,
                client.addr,
            );
            match server.conn.stream_recv(id, &mut after) {
                Ok((n, _)) => {
                    got = n;
                    break;
                }
                Err(quiche::Error::Done) => {}
                Err(error) => panic!("reads after the move: {error:?}"),
            }
        }
        assert_eq!(&after[..got], b"after");
    }

    /// The production dial hands the offer to the connection before its first packet, not only the
    /// test helper: a config that names ECH is what makes both ends report acceptance.
    #[test]
    fn a_client_dial_offers_the_configured_ech_list() {
        let identity = ech_identity();
        let server_sock = Datagram::plain(bind_datagram("127.0.0.1:0").expect("binds"));
        let server_addr = server_sock.local_addr().expect("addr");
        let mut server_config = serve_config(&identity).expect("serves");
        let server = std::thread::spawn(move || {
            let mut conn = server_accept(&server_sock, server_addr, &mut server_config);
            conn.as_mut().ech_accepted()
        });
        let client_sock = Datagram::plain(bind_datagram("127.0.0.1:0").expect("binds"));
        let local = client_sock.local_addr().expect("addr");
        let list = ech_client_list();
        let mut client = handshake_within(
            &client_sock,
            server_addr,
            local,
            "quic.test",
            &identity.certs[0].cert_chain,
            Some(&list),
            Duration::from_secs(5),
        )
        .expect("handshakes");
        assert!(
            client.as_mut().ech_accepted(),
            "the dial offered and the server accepted"
        );
        assert!(server.join().expect("joins"), "the server opened it");
    }

    /// A sweep hands the socket every datagram quiche offered rather than one batch of slots, and the peer reads the same bytes in the same order: the connection is asked, right after the call, whether it still has a packet ready.
    #[test]
    fn an_egress_sweep_drains_its_whole_queue() {
        let (mut client, mut server) = lane_pair();
        let pattern: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
        let wrote = server.conn.stream_send(1, &pattern, false).expect("writes");
        assert!(
            wrote >= 4 * MAX_DATAGRAM,
            "the write queued a frame several batches wide, saw {wrote}"
        );
        flush_egress(&mut server.conn, &server.sock);
        let mut left = [0u8; MAX_DATAGRAM];
        assert!(
            server.conn.send(&mut left).is_err(),
            "the sweep took every datagram quiche was ready to hand over"
        );
        let _ = client
            .sock
            .set_read_timeout(Some(Duration::from_millis(20)));
        let mut got = 0usize;
        for (mut bytes, peer) in drain_packets(&client.sock) {
            got += 1;
            let info = quiche::RecvInfo {
                from: peer,
                to: client.addr,
            };
            let _ = client.conn.recv(&mut bytes, info);
        }
        assert!(
            got >= 2,
            "one sweep moved a burst rather than a single datagram, saw {got}"
        );
        let mut buf = vec![0u8; wrote + 1];
        let (read, _) = client.conn.stream_recv(1, &mut buf).expect("reads");
        assert!(
            read > 0,
            "the burst carried stream bytes the peer could read"
        );
        assert_eq!(
            buf[..read],
            pattern[..read],
            "the batch delivered the frame in order, whole"
        );
    }

    /// A waiter beside a pump must leave the pump's datagram on the socket: the queue is the witness, since a waiter that read it would empty the queue before the pump saw it.
    #[test]
    fn a_parked_receive_leaves_the_socket_to_its_pump() {
        let (sock, local, conn) = deaf_lane();
        sock.send_to(&[0xc0, 0x00, 0x00, 0x01, 7], local)
            .expect("queues");
        let shared = Mutex::new(conn);
        let deadline = Instant::now() + Duration::from_millis(20);
        assert!(stream_recv_exact_parked(&shared, 0, 2, deadline).is_none());
        let mut buf = [0u8; 64];
        assert!(
            sock.recv_from(&mut buf).is_ok(),
            "the parked waiter read the pump's datagram"
        );
    }

    /// One visit to the socket absorbs the whole burst waiting on it, and the witness is the queue itself: one armed wait and a fourth read that must find nothing says whether three datagrams were taken in one visit or one at a time.
    #[test]
    fn one_pump_absorbs_the_whole_datagram_burst_on_the_socket() {
        let (sock, local, mut conn) = deaf_lane();
        for salt in 0..3u8 {
            sock.send_to(&[0xc0, 0x00, 0x00, 0x01, salt], local)
                .expect("queues");
        }
        // The one-millisecond wait is also the floor, so it expires once the queue is dry: the third read is the first nothing arrived on, which is only true if the two before it were taken in the same visit.
        assert!(pump_once(&mut conn, &sock, local, Duration::from_millis(1)));
        assert!(
            sock.recv_from(&mut [0u8; 64]).is_err(),
            "the queue was drained"
        );
    }

    /// Absorbing the burst must not cost the caller the wait it armed: `stream_recv_exact` hands this function its whole remaining budget, so the drain is bounded by the queue, not by the budget.
    #[test]
    fn a_pump_that_absorbs_its_burst_does_not_hold_the_wait_it_armed() {
        let (sock, local, mut conn) = deaf_lane();
        for salt in 0..3u8 {
            sock.send_to(&[0xc0, 0x00, 0x00, 0x01, salt], local)
                .expect("queues");
        }
        let started = Instant::now();
        assert!(pump_once(&mut conn, &sock, local, Duration::from_secs(1)));
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "the visit ended with the queue, not with the arm"
        );
    }

    /// The record of the armed wait belongs to the file description, not the handle: `SO_RCVTIMEO` is shared by a socket and every clone of it, so a clone that kept its own record would arm nothing.
    #[test]
    fn a_clone_carries_the_socket_it_was_cloned_from_one_arm_record() {
        let sock = Datagram::plain(bind_datagram("127.0.0.1:0").expect("binds"));
        let clone = sock.try_clone().expect("clones");
        assert!(
            Arc::ptr_eq(&sock.armed, &clone.armed),
            "the second handle kept a record of a wait the socket does not carry"
        );
    }

    /// Two handles over one lane socket, each polling on its own budget — the shape of a pooled `pump` beside a flow's `pump_once`, or a hysteria reader beside its TCP pump. The read that asks for the long wait has to get it even though the other handle armed the socket short in between; a per-handle record skips that arm and the reader returns in the other's milliseconds.
    #[test]
    fn a_wait_undone_by_another_handle_is_armed_again_before_the_read() {
        let sock = Datagram::plain(bind_datagram("127.0.0.1:0").expect("binds"));
        assert!(sock.refresh_read_timeout(Duration::from_millis(400)));
        let other = sock.try_clone().expect("clones");
        assert!(other.refresh_read_timeout(Duration::from_millis(4)));
        assert!(sock.refresh_read_timeout(Duration::from_millis(400)));
        let started = Instant::now();
        let quiet = sock.recv_from(&mut [0u8; MAX_DATAGRAM]);
        let waited = started.elapsed();
        assert!(quiet.is_err(), "an empty socket does not answer");
        assert!(
            waited >= Duration::from_millis(100),
            "the read waited {waited:?}, not the arm it asked for"
        );
    }

    /// The routing key is a window into the packet the kernel wrote: its base is the DCID inside the caller's buffer, so the lookup costs no copy of its own.
    #[test]
    fn a_route_key_is_a_window_into_the_packet() {
        let mut short = [0u8; 64];
        short[0] = 0x40;
        short[1..=quiche::MAX_CONN_ID_LEN].fill(7);
        let key = packet_key(&short).expect("a short header names its DCID");
        assert_eq!(key, &short[1..=quiche::MAX_CONN_ID_LEN]);
        assert_eq!(
            key.as_ptr(),
            short[1..].as_ptr(),
            "the key was copied out of the packet"
        );

        let mut long = [0u8; 64];
        long[0] = 0xc0;
        long[1..5].copy_from_slice(&1u32.to_be_bytes());
        long[5] = 8;
        long[6..14].fill(9);
        let key = packet_key(&long).expect("a long header names its DCID length");
        assert_eq!(key, &long[6..14]);
        assert_eq!(
            key.as_ptr(),
            long[6..].as_ptr(),
            "the key was copied out of the packet"
        );
    }

    /// The header the route used to build allocated its DCID out of the packet on every datagram; the key borrows it, so the established lane's lookup allocates nothing. The two halves are measured side by side, so the removed allocation is the witness rather than a reading of the code.
    #[test]
    fn the_route_key_replaces_the_allocating_header_parse() {
        let mut packet = [0u8; 64];
        packet[0] = 0x40;
        packet[1..=quiche::MAX_CONN_ID_LEN].fill(7);
        let (header, parsed) = ferrox_core::alloc_count::measure(|| {
            let mut copy = packet;
            quiche::Header::from_slice(&mut copy, quiche::MAX_CONN_ID_LEN).ok()
        });
        assert!(header.is_some(), "the header parses");
        assert!(
            parsed.allocs > 0,
            "the parse this replaces copied the DCID out of the packet"
        );
        let (key, routed) = ferrox_core::alloc_count::measure(|| packet_key(&packet));
        assert!(key.is_some(), "the key reads");
        assert_eq!(
            routed.allocs, 0,
            "the routing key copied the DCID out of the packet"
        );
    }
}

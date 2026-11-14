//! Foxy lane: a CONNECT tunnel to an account's CDN edge over H1/H2/H3; a lane hands the caller a carrier-agnostic `Read + Write`.

use crate::conn::Connection;
use ferrox_core::foxy::connectip;
use ferrox_core::foxy::{
    self, authority, edge_authority, edge_peer, frames, hpack, masque, Failure, Pass,
};
use ferrox_core::tls::RecordAlignment;
use ferrox_core::tls::TlsProvider;
use std::io::{Read, Write};
use std::net::{SocketAddr, ToSocketAddrs as _};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
/// Attempts at one address before the lane moves on, and the pause between them: an edge that closes a handshake it started answers again in ~0.1s, so retry fast without waiting minutes on a dead address.
const EDGE_ATTEMPTS: usize = 8;
const EDGE_BACKOFF_MS: u64 = 250;
const HEADER_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_FRAME: usize = frames::MAX_FRAME as usize;
const MAX_HEAD: usize = 8_192;
/// The head walk's window, the size the byte walk pre-sized its buffer to: one read of it takes a status line and its empty line, and a wider window would only divert more of the tunnel's first bytes into the tail they are carried in.
const HEAD_WINDOW: usize = 256;
/// The widest answer a hop's head may be, and the window that proves it: a hop's head is peeked rather than read, so a window this wide diverts no tunnel bytes.
const HOP_HEAD: usize = 4_096;
/// Unparsed capsule-stream cap: fail the association rather than buffer a peer that never completes a capsule.
const DATAGRAM_BUF_MAX: usize = 256 * 1024;
const SEND_WAIT: Duration = Duration::from_secs(10);
/// What an empty turn on the lane's socket waits for a datagram, when nothing narrower is armed.
const PUMP_WAIT: Duration = Duration::from_millis(5);
/// The client's first unidirectional stream, carrying the SETTINGS that make the connection HTTP/3.
const CONTROL_STREAM: u64 = 2;
/// The ceiling of a QUIC frame header: two varints of at most eight bytes each. The request stream's window is this size and nothing larger, because a payload never passes through it — it lands in the buffer its reader uses.
const H3_PEEK: usize = 16;
/// The largest frame block the lane will consume without keeping it: a HEADERS answer's block and any frame the tunnel has no use for are bounded by one head, so a peer cannot make the lane wait on a block bigger than a header.
const H3_SKIP: usize = MAX_HEAD;
const H3_FRAME: usize = 16 * 1024;

/// The carriers the lane can carry, in `auto`'s preference order: HTTP/2 (the edge speaks it and a resumed TCP session carries the bytes), HTTP/1.1 (every edge does), QUIC (one handshake carries every flow, and it is the only carrier that carries a datagram).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Carrier {
    H1,
    H2,
    H3,
    /// Try each carrier in turn: an edge that will not answer HTTP/2 is a slower tunnel, not a refused one.
    Auto,
}

impl Carrier {
    /// The word `--carrier` takes and a status line prints, so a lane reports the rung it was given under the name it was given.
    #[must_use]
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::H1 => "h1",
            Self::H2 => "h2",
            Self::H3 => "h3",
            Self::Auto => "auto",
        }
    }

    /// The byte a carrier is remembered under: a cache key that names a carrier needs one byte of it, and a joined name was a `String` per lookup.
    #[must_use]
    pub(crate) const fn key(self) -> u8 {
        match self {
            Self::H1 => 0,
            Self::H2 => 1,
            Self::H3 => 2,
            Self::Auto => 3,
        }
    }

    #[must_use]
    pub(crate) const fn alpn(self) -> &'static [u8] {
        match self {
            Self::H1 => b"http/1.1",
            Self::H2 => b"h2",
            Self::H3 => b"h3",
            // An unexpanded `auto` offers nothing: a dial reaching here fails the handshake instead of quietly dialling HTTP/2.
            Self::Auto => b"",
        }
    }

    /// The carriers to try, most preferred first, three entries for every carrier.
    ///
    /// `auto` opens on `h2` and not on `h3`: the edge answers HTTP/3, but it answers it on a QUIC session whose congestion window starts empty on a path the edge has never seen, while HTTP/2 rides a resumed TCP session whose window the edge has already grown. On CI's own egress, against the real edge, `h2` outran `h3` and `auto` in every run and on every runner, so the rung that answered first was the rung that cost the most.
    ///
    /// A named carrier leads its ladder, but `h3` is a preference and not a pin: a path can drop QUIC outright, and silence is not a refusal the edge can fall through on its own, so the TCP rungs follow it.
    #[must_use]
    pub(crate) const fn order(self) -> [Self; 3] {
        match self {
            Self::Auto => [Self::H2, Self::H1, Self::H3],
            Self::H3 => [Self::H3, Self::H2, Self::H1],
            Self::H2 => [Self::H2, Self::H2, Self::H2],
            Self::H1 => [Self::H1, Self::H1, Self::H1],
        }
    }

    /// The carriers a CONNECT-UDP flow rides: HTTP/3 carries a capsule natively, HTTP/2 as a stream, and HTTP/1.1 through RFC 9298 §4's upgrade.
    #[must_use]
    pub(crate) const fn udp_order() -> [Self; 3] {
        [Self::H3, Self::H2, Self::H1]
    }

    /// The carriers a CONNECT-IP flow rides: HTTP/1.1 has no mapping for the address request, so the datagram orders diverge here.
    #[must_use]
    pub(crate) const fn ip_order() -> [Self; 2] {
        [Self::H3, Self::H2]
    }
}

/// Reads a carrier from a config or a link: `auto` is a carrier, and an unknown name is `auto`, never a silent HTTP/2.
pub(crate) fn carrier(name: &str) -> Carrier {
    match name {
        "h1" | "http/1.1" => Carrier::H1,
        "h2" | "http/2" => Carrier::H2,
        "h3" | "quic" => Carrier::H3,
        _ => Carrier::Auto,
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FoxyDial {
    /// The edge name: the TLS server name, the ALPN subject, and the country the hostname pins. Shared rather than copied, because a flow dials the same edge through several carriers and every one of them read this name.
    pub(crate) host: std::sync::Arc<str>,
    pub(crate) port: u16,
    /// The address to connect to, when it is not the name's own resolution.
    pub(crate) address: Option<SocketAddr>,
    pub(crate) carrier: Carrier,
    /// The upstream hop the dial chains through (TCP over CONNECT or SOCKS5; QUIC over a SOCKS5 UDP association).
    pub(crate) upstream: Option<UpstreamProxy>,
    pub(crate) roots: ferrox_core::tls::Anchors,
    pub(crate) pins: foxy::pin::Pins,
    pub(crate) pass: Pass,
}

/// One hop before the edge: plain HTTP CONNECT or a no-auth SOCKS5 handshake; anything else, including credentials, refuses.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct UpstreamProxy {
    http: bool,
    host: std::sync::Arc<str>,
    port: u16,
}

impl UpstreamProxy {
    /// Whether the hop speaks HTTP CONNECT, a TCP-only hop: a QUIC carrier must be refused instead.
    pub(crate) fn http(&self) -> bool {
        self.http
    }
}

pub(crate) fn upstream_proxy(text: &str) -> Option<UpstreamProxy> {
    let text = text.trim();
    let (http, rest) = text
        .strip_prefix("http://")
        .map(|rest| (true, rest))
        .or_else(|| text.strip_prefix("socks5://").map(|rest| (false, rest)))
        .or_else(|| text.strip_prefix("socks5h://").map(|rest| (false, rest)))?;
    let (host, port) = rest.rsplit_once(':')?;
    if host.is_empty() || host.contains('/') || host.contains('@') {
        return None;
    }
    let port = port.parse::<u16>().ok()?;
    // A URL spells a v6 host in brackets and the lane's address reader wants the bare address; `authority` puts them back where a name is what the wire needs.
    let host = host
        .strip_prefix('[')
        .and_then(|bare| bare.strip_suffix(']'))
        .unwrap_or(host);
    Some(UpstreamProxy {
        http,
        host: std::sync::Arc::from(host),
        port,
    })
}

/// The TLS session to the edge, dialed address by address — the handshake and ALPN are part of "does this address work"; a configured hop is the dial instead.
fn tls_to_edge(dial: &FoxyDial) -> Result<ferrox_core::tls::RustlsProvider<Connection>, Failure> {
    if let Some(proxy) = dial.upstream.as_ref() {
        return edge_over_hop(proxy, dial);
    }
    // The address the lane holds, or the one the edge's name already is, reaches the socket as it stands: no name spelled, no list collected, no resolver asked.
    match dial.address.or_else(|| edge_peer(&dial.host, dial.port)) {
        Some(peer) => dial_peers(dial, std::iter::once(peer)),
        None => dial_peers(
            dial,
            authority(&dial.host, dial.port)
                .to_socket_addrs()
                .map_err(|_| Failure::Io)?,
        ),
    }
}

/// The peers an edge is reached through, tried in the order they came: the handshake's half-second budget and `EDGE_ATTEMPTS` quick asks at each, then the next one.
fn dial_peers<I: Iterator<Item = SocketAddr>>(
    dial: &FoxyDial,
    peers: I,
) -> Result<ferrox_core::tls::RustlsProvider<Connection>, Failure> {
    let mut tried = 0usize;
    let mut last = Failure::Io;
    for peer in peers {
        tried += 1;
        // The edge sometimes closes a handshake it started with no reason, seconds away from carrying the tunnel; 8 quick asks make that a leg, not a flow.
        for attempt in 0..EDGE_ATTEMPTS {
            let stream = match crate::conn::dial_tcp(&peer, CONNECT_TIMEOUT) {
                Ok(stream) => stream,
                Err(error) => {
                    debug_address(peer, || format!("tcp {error}"));
                    break;
                }
            };
            let _ = stream.set_nodelay(true);
            // Half-second handshake budget: a quiet edge would otherwise hold the flow for the OS TCP timeout, which answers EAGAIN on macOS.
            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
            match finish_tls(dial, stream) {
                Ok(tls) => {
                    // The handshake's budget hands over to the head's: an edge that finishes TLS and never answers the CONNECT costs this open the named head wait, not the life of the flow.
                    let _ = tls
                        .get_ref()
                        .set_read_timeout(Some(crate::budgets::head_arrival()));
                    return Ok(tls);
                }
                Err(failure) => {
                    last = failure;
                    // An ALPN mismatch is the edge naming a protocol, which no retry changes; only losing the connection is worth a second try.
                    let worth = matches!(failure, Failure::Io);
                    if attempt + 1 < EDGE_ATTEMPTS && worth {
                        std::thread::sleep(after_attempt(attempt));
                        continue;
                    }
                    debug_address(peer, || failure.to_string());
                    break;
                }
            }
        }
    }
    if tried > 1 {
        eprintln!("foxy: the edge carried the lane on none of its {tried} addresses");
    }
    Err(last)
}

/// The edge through the configured hop, retried like a direct dial: a hop head read answers `WouldBlock`, not `TimedOut`, on macOS (`Os { code: 35 }`).
fn edge_over_hop(
    proxy: &UpstreamProxy,
    dial: &FoxyDial,
) -> Result<ferrox_core::tls::RustlsProvider<Connection>, Failure> {
    let mut tried = 0usize;
    let mut failure = Failure::Io;
    for attempt in 0..EDGE_ATTEMPTS {
        tried += 1;
        match tcp_via(proxy, &dial.host, dial.port).and_then(|stream| finish_tls(dial, stream)) {
            Ok(tls) => return Ok(tls),
            Err(lost) => {
                failure = lost;
                let worth = matches!(failure, Failure::Io | Failure::Stream);
                if attempt + 1 < EDGE_ATTEMPTS && worth {
                    std::thread::sleep(after_attempt(attempt));
                }
            }
        }
    }
    debug_loss("the hop refused the edge", || {
        format!("after {tried} attempts")
    });
    Err(failure)
}

/// The pause before the next attempt at one address: flat, because the edge answers a refusal in ~0.1s, so 8 attempts cost seconds, not a whole budget.
fn after_attempt(_attempt: usize) -> std::time::Duration {
    Duration::from_millis(EDGE_BACKOFF_MS)
}

/// Whether the lane's diagnostics are wanted, read once: the flag cannot change under a running process, and asking the environment for it on every flow paid a lookup and a lock in the dial path.
pub(crate) fn debug_on() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("FOXY_DEBUG").is_ok())
}

/// Diagnostics behind `FOXY_DEBUG`: a red leg is only actionable when it names the address, the stage and the platform error — a refusal and a hang share a message otherwise. The error is a closure because the trace is off by default, and a rendered error was built for every failed attempt on a lane whose trace nobody reads.
fn debug_loss(stage: &str, error: impl FnOnce() -> String) {
    if debug_on() {
        eprintln!("foxy-debug: {stage}: {}", error());
    }
}

fn debug_address(peer: SocketAddr, why: impl FnOnce() -> String) {
    if debug_on() {
        eprintln!("foxy-debug: address {peer} lost: {}", why());
    }
}

/// One address, all the way to a usable session, naming the failed stage — a bare "io" cannot be told apart from any other leg's.
fn finish_tls(
    dial: &FoxyDial,
    stream: Connection,
) -> Result<ferrox_core::tls::RustlsProvider<Connection>, Failure> {
    let mut tls = match ferrox_core::tls::RustlsProvider::connect(&tls_config(dial), stream) {
        Ok(tls) => tls,
        Err(error) => {
            debug_loss("the TLS client failed to start", || error.to_string());
            return Err(error.into());
        }
    };
    if let Err(error) = tls.handshake() {
        debug_loss("the TLS handshake with the edge failed", || {
            error.to_string()
        });
        return Err(error.into());
    }
    negotiated(&tls, dial)
        .inspect_err(|_| debug_stage("the edge named no protocol this lane speaks"))
        .map(|()| tls)
}

/// The `ALPN` list each carrier offers, built once: the list is a function of the carrier alone, and a dial that built its own paid a vector and an arc for a list of one.
fn carrier_alpn(carrier: Carrier) -> std::sync::Arc<[Vec<u8>]> {
    static LISTS: std::sync::OnceLock<[std::sync::Arc<[Vec<u8>]>; 4]> = std::sync::OnceLock::new();
    let lists = LISTS.get_or_init(|| {
        [
            std::sync::Arc::from([Carrier::H1.alpn().to_vec()]),
            std::sync::Arc::from([Carrier::H2.alpn().to_vec()]),
            std::sync::Arc::from([Carrier::H3.alpn().to_vec()]),
            std::sync::Arc::from([Carrier::Auto.alpn().to_vec()]),
        ]
    });
    std::sync::Arc::clone(&lists[carrier.key() as usize])
}

fn tls_config(dial: &FoxyDial) -> ferrox_core::tls::TlsConfig {
    ferrox_core::tls::TlsConfig {
        server_name: dial.host.to_string(),
        alpn: carrier_alpn(dial.carrier),
        roots: Arc::clone(&dial.roots),
        pins: dial.pins.clone(),
        cert_pins: std::sync::Arc::from(Vec::new()),
        verify_names: std::sync::Arc::default(),
        cipher_suites: std::sync::Arc::default(),
        curves: std::sync::Arc::default(),
        insecure: false,
        resumption: true,
        fingerprint: None,
        ech_config_list: None,
        websocket: false,
        master_key_log: None,
        client_cert: None,
        client_random: None,
        padding: None,
        ..Default::default()
    }
}

/// The CONNECT a plain HTTP hop is asked to tunnel and the answer it gives: the authority is gathered out of the name, the port's digits and the brackets a literal already spells, so no joined form is built to be copied again, and the head is proved by a `peek` that consumes only its own octets — whatever the hop sent after `\r\n\r\n` is the record the caller reads next.
fn hop_connect(stream: &mut Connection, host: &str, port: u16) -> Result<(), Failure> {
    // The digits land at the end of a stack array, as the masquerade answer puts its status there.
    let mut digits = [0u8; 5];
    let mut at = digits.len();
    let mut rest = port;
    loop {
        at -= 1;
        digits[at] = b'0' + (rest % 10) as u8;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    let port = &digits[at..];
    let bracketed = host.contains(':');
    let open: &[u8] = if bracketed { b"[" } else { b"" };
    let close: &[u8] = if bracketed { b"]" } else { b"" };
    crate::proxy::write_all_parts::<13>(
        stream,
        &[
            b"CONNECT ",
            open,
            host.as_bytes(),
            close,
            b":",
            port,
            b" HTTP/1.1\r\nHost: ",
            open,
            host.as_bytes(),
            close,
            b":",
            port,
            b"\r\n\r\n",
        ],
    )
    .map_err(|_| Failure::Io)?;
    let mut head = [0u8; HOP_HEAD];
    let mut have = 0usize;
    let mut scanned = 0usize;
    loop {
        let seen = stream.peek(&mut head[have..]).map_err(|_| Failure::Io)?;
        if seen == 0 {
            return Err(Failure::Io);
        }
        let filled = have + seen;
        let Some(end) = foxy::head_end_grown(&head[..filled], &mut scanned) else {
            if filled == head.len() {
                return Err(Failure::Io);
            }
            // No terminator yet, so every octet seen so far is head: take them, and let the next peek block on the wire instead of rereading the ones already here.
            read_exact(stream, &mut head[have..filled]).map_err(|_| Failure::Io)?;
            have = filled;
            continue;
        };
        read_exact(stream, &mut head[have..end + 4]).map_err(|_| Failure::Io)?;
        let code = foxy::connect_status(&head[..end + 4]).map_err(|_| Failure::Io)?;
        return opened(code);
    }
}

/// TCP to a host through one upstream hop: the TLS name stays the destination's, so the hop carries bytes it can neither read nor address.
pub(crate) fn tcp_via(proxy: &UpstreamProxy, host: &str, port: u16) -> Result<Connection, Failure> {
    let mut stream = tcp_to_proxy(proxy).ok_or(Failure::Io)?;
    if proxy.http {
        hop_connect(&mut stream, host, port)?;
    } else {
        socks_greeting(&mut stream)?;
        let host_len = u8::try_from(host.len()).map_err(|_| Failure::Io)?;
        let mut request = vec![5, 1, 0, 3, host_len];
        request.extend_from_slice(host.as_bytes());
        request.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&request).map_err(|_| Failure::Io)?;
        // The hop's bound address is not the edge's: read past it and drop it, the connection itself is the answer.
        if socks_reply(&mut stream)?.is_none() {
            return Err(Failure::Io);
        }
    }
    Ok(stream)
}

/// One UDP association with a SOCKS5 hop: greeting, a request naming no destination, the relay address; the caller holds the control connection — dropping it ends the association.
pub(crate) fn associate_udp(proxy: &UpstreamProxy) -> Option<(Arc<Connection>, SocketAddr)> {
    let mut control = tcp_to_proxy(proxy)?;
    if socks_greeting(&mut control).is_err() {
        return None;
    }
    if control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).is_err() {
        return None;
    }
    let Ok(Some(relay)) = socks_reply(&mut control) else {
        return None;
    };
    Some((Arc::new(control), relay))
}

/// The one hop this tree speaks to, dialed: a proxy that does not answer at all is a failed dial, not a lane running direct.
fn tcp_to_proxy(proxy: &UpstreamProxy) -> Option<Connection> {
    match edge_peer(&proxy.host, proxy.port) {
        Some(peer) => tcp_to_peers(std::iter::once(peer)),
        None => tcp_to_peers(authority(&proxy.host, proxy.port).to_socket_addrs().ok()?),
    }
}

/// The hop's peers in the order they came: a hop answering on the second listed family is still the hop this lane uses.
fn tcp_to_peers<I: Iterator<Item = SocketAddr>>(peers: I) -> Option<Connection> {
    for addr in peers {
        if let Ok(stream) = crate::conn::dial_tcp(&addr, CONNECT_TIMEOUT) {
            let _ = stream.set_nodelay(true);
            // The hop's head is small and peeked, so a few seconds is the honest bound; without it a missing byte holds the flow for the OS's minutes-long timeout.
            let _ = stream.set_read_timeout(Some(HEADER_TIMEOUT));
            return Some(stream);
        }
    }
    None
}

/// No authentication offered, none accepted: a hop that selects anything else is one this lane cannot use.
fn socks_greeting(stream: &mut Connection) -> Result<(), Failure> {
    stream.write_all(&[5, 1, 0]).map_err(|_| Failure::Io)?;
    let mut method = [0u8; 2];
    read_exact(stream, &mut method).map_err(|_| Failure::Io)?;
    if method != [5, 0] {
        return Err(Failure::Io);
    }
    Ok(())
}

/// Whether the hop granted the request, and the address it bound: a refusal answers the same reply with a non-zero status, and a name in the reply is something this tree cannot address back.
fn socks_reply(stream: &mut Connection) -> Result<Option<SocketAddr>, Failure> {
    let mut head = [0u8; 4];
    read_exact(stream, &mut head).map_err(|_| Failure::Io)?;
    if head[1] != 0 {
        return Ok(None);
    }
    let mut read = |into: &mut [u8]| read_exact(stream, into).map_err(|_| Failure::Io);
    let ip = match head[3] {
        1 => {
            let mut octets = [0u8; 4];
            read(&mut octets)?;
            std::net::Ipv4Addr::from(octets).into()
        }
        4 => {
            let mut octets = [0u8; 16];
            read(&mut octets)?;
            std::net::Ipv6Addr::from(octets).into()
        }
        _ => return Err(Failure::Io),
    };
    let mut port = [0u8; 2];
    read(&mut port)?;
    Ok(Some(SocketAddr::new(ip, u16::from_be_bytes(port))))
}

/// A handshake that answered a different ALPN is a refusal, not a downgrade: the lane asked for exactly one protocol.
fn negotiated<S: TlsProvider>(tls: &S, dial: &FoxyDial) -> Result<(), Failure> {
    match tls.alpn() {
        Some(got) if got == dial.carrier.alpn() => Ok(()),
        _ => Err(Failure::Frame),
    }
}

fn opened(status: u16) -> Result<(), Failure> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(Failure::Rejected(status))
    }
}

fn read_exact<S: Read>(io: &mut S, buf: &mut [u8]) -> std::io::Result<()> {
    let mut at = 0usize;
    while at < buf.len() {
        match io.read(&mut buf[at..]) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            // A socket timeout on macOS answers EAGAIN, so a would-block read is the same answer: retried by the caller, which is what a quantum is for.
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) && at == 0 =>
            {
                return Err(error);
            }
            Err(error) => return Err(error),
            Ok(read) => at += read,
        }
    }
    Ok(())
}

/// HTTP/1.1 CONNECT: the request, the status line, then the target's own bytes.
/// The `Proxy-Authorization` head literal is a parameter so one seven-run builder serves every scheme a lane dials with; `refused_target` is the lane's own field-and-value, and a lane that names none never has an answer's head walked twice.
pub(crate) fn open_h1(
    dial: &FoxyDial,
    target: &str,
    authorization_head: &'static [u8],
    credential: &str,
    refused_target: Option<(&[u8], &[u8])>,
) -> Result<Tls1, Failure> {
    let mut tls = tls_to_edge(dial)?;
    tls.write_all_slices(&foxy::connect_request(
        target,
        authorization_head,
        credential,
    ))
    .map_err(|_| Failure::Io)?;
    let (status, carried) = head(&mut tls, refused_target)?;
    opened(status)?;
    Ok(Tls1 {
        tls,
        carried,
        at: 0,
        park: None,
    })
}

/// Walks the CONNECT answer a window at a time and parses it where the octets landed: the head never enters a buffer of its own. What the last read took past `\r\n\r\n` is the tunnel's own first byte stream, so it comes back as exactly-sized tail rather than being discarded and re-waited for on the socket.
fn head<S: Read>(
    io: &mut S,
    refused_target: Option<(&[u8], &[u8])>,
) -> Result<(u16, Vec<u8>), Failure> {
    // The budget bounds the whole head, not one read of it: a drip that keeps every read inside the socket's arm still ends at the wall.
    let until = Instant::now() + crate::budgets::head_arrival();
    let mut window = [0u8; HEAD_WINDOW];
    let mut filled = 0usize;
    loop {
        if Instant::now() >= until {
            return Err(Failure::Stream);
        }
        let read = io
            .read(&mut window[filled..])
            .map_err(|_| Failure::Stream)?;
        if read == 0 {
            return Err(Failure::Stream);
        }
        filled += read;
        if let Some(end) = foxy::head_end(&window[..filled]) {
            let head = &window[..end + 4];
            let status = foxy::connect_status(head)?;
            if is_refused_target(head, status, refused_target) {
                return Err(Failure::BlockedHost(status));
            }
            return Ok((status, window[end + 4..filled].to_vec()));
        }
        if filled == window.len() {
            return long_head(io, &window, until, refused_target);
        }
    }
}

/// The cold answer to an edge that sends more than a status line: the octets already walked move into a buffer that grows to what the edge sends, the window keeps serving the reads, and `MAX_HEAD` still bounds the whole head.
fn long_head<S: Read>(
    io: &mut S,
    walked: &[u8; HEAD_WINDOW],
    until: Instant,
    refused_target: Option<(&[u8], &[u8])>,
) -> Result<(u16, Vec<u8>), Failure> {
    let mut head = Vec::with_capacity(walked.len() * 2);
    head.extend_from_slice(walked);
    let mut window = [0u8; HEAD_WINDOW];
    let mut scanned = head.len();
    loop {
        if let Some(end) = foxy::head_end_grown(&head, &mut scanned) {
            let block = &head[..end + 4];
            let status = foxy::connect_status(block)?;
            if is_refused_target(block, status, refused_target) {
                return Err(Failure::BlockedHost(status));
            }
            return Ok((status, head[end + 4..].to_vec()));
        }
        if head.len() >= MAX_HEAD {
            return Err(Failure::Frame);
        }
        if Instant::now() >= until {
            return Err(Failure::Stream);
        }
        let room = window.len().min(MAX_HEAD - head.len());
        let read = io.read(&mut window[..room]).map_err(|_| Failure::Stream)?;
        if read == 0 {
            return Err(Failure::Stream);
        }
        head.extend_from_slice(&window[..read]);
    }
}

/// Whether this refusal is the edge naming the target: a lane that configured no field never asks, and an answer that opened the tunnel is not walked a second time.
fn is_refused_target(head: &[u8], status: u16, refused_target: Option<(&[u8], &[u8])>) -> bool {
    opened(status).is_err()
        && refused_target.is_some_and(|(name, value)| foxy::head_field(head, name) == Some(value))
}

/// Hands the caller what it asked for out of the tail the head walk left behind, and moves the cursor: a copy of bytes, never a move of what is left. The read that delivers the last octet releases the buffer, so nothing of the walk is held idle for the life of the tunnel.
fn hand_back(carried: &mut Vec<u8>, at: &mut usize, buf: &mut [u8]) -> usize {
    let take = buf.len().min(carried.len() - *at);
    buf[..take].copy_from_slice(&carried[*at..*at + take]);
    *at += take;
    if *at == carried.len() {
        *carried = Vec::new();
        *at = 0;
    }
    take
}

/// HTTP/2 CONNECT: preface, settings, one stream and the status in its first header block. A session that carried a flow is kept and lent to the next flow as a new stream, so a warm flow pays one round trip instead of a TCP and a TLS handshake.
pub(crate) fn open_h2(dial: &FoxyDial, target: &str) -> Result<Tls2, Failure> {
    let mut block = Vec::with_capacity(96 + dial.pass.token.len());
    hpack::hpack_connect(target, &dial.pass.token, &mut block);
    open_stream(dial, &block)
}

/// Opens one stream on a session to this edge, reusing a session already open: the flow rides it on a stream of its own, and the handshake it paid is not paid again.
fn open_stream(dial: &FoxyDial, block: &[u8]) -> Result<Tls2, Failure> {
    // A session already open to this edge is the cheap one: the flow rides it on a stream of its own, and the handshake it paid is not paid again.
    if let Some(session) = pool_find(dial) {
        match attach(&session, block) {
            Ok(lane) => return Ok(lane),
            // A session the edge closed while it was idle is the one handshake this reuse may cost; every other refusal is the edge's answer and is not retried on a new session.
            Err(Failure::Stream | Failure::Io) => pool_forget(&session),
            Err(failure) => return Err(failure),
        }
    }
    let session = open_session(dial)?;
    let lane = attach(&session, block)?;
    pool_register(SessionKey::of(dial), &session);
    Ok(lane)
}

/// The identity one pooled session is lent under: a CONNECT stream names any target, so only the edge, the hop, the anchors, the pins and the account have to match.
#[derive(Clone)]
struct SessionKey {
    host: std::sync::Arc<str>,
    port: u16,
    address: Option<SocketAddr>,
    upstream: Option<UpstreamProxy>,
    /// The trust store itself, not a pointer to it: the key holds the anchors alive for as long as the session it belongs to, so pointer identity cannot be recycled by a store that was dropped.
    anchors: ferrox_core::tls::Anchors,
    pins: foxy::pin::Pins,
    token: Arc<str>,
}

impl SessionKey {
    fn of(dial: &FoxyDial) -> Self {
        Self {
            host: dial.host.clone(),
            port: dial.port,
            address: dial.address,
            upstream: dial.upstream.clone(),
            anchors: Arc::clone(&dial.roots),
            pins: dial.pins.clone(),
            token: Arc::clone(&dial.pass.token),
        }
    }

    /// Whether a stored key names the same edge this dial is about: the lookup borrows the dial, so a warm flow costs no name of its own.
    fn names(&self, dial: &FoxyDial) -> bool {
        self.host == dial.host
            && self.port == dial.port
            && self.address == dial.address
            && self.upstream == dial.upstream
            && Arc::ptr_eq(&self.anchors, &dial.roots)
            && self.pins == dial.pins
            && self.token == dial.pass.token
    }
}

/// The idle sessions kept for the next flows: enough for a browser's parallel connections, and no more; the test process runs every edge at once, so it keeps more.
const POOL_IDLE: usize = if cfg!(test) { 1024 } else { 8 };
/// How long a session is lent again: the edge's own idle timeout is longer, and a session older than this is a handshake the lane would rather pay than trust.
const POOL_TTL: Duration = Duration::from_secs(20);
/// The largest odd stream id the protocol names; a session that spent it is not lent again.
const LAST_STREAM: u32 = 0x7fff_ffff;

type PoolEntry = (SessionKey, Instant, Arc<Session>);

fn pool() -> &'static std::sync::Mutex<Vec<PoolEntry>> {
    static POOL: std::sync::OnceLock<std::sync::Mutex<Vec<PoolEntry>>> = std::sync::OnceLock::new();
    POOL.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// A session open to this edge, if one is: the flow rides it on a stream of its own, and the handshake it paid is not paid again. The session stays in the registry while it is ridden — a flow that took it did not take it away from the others.
fn pool_find(dial: &FoxyDial) -> Option<Arc<Session>> {
    let mut pool = pool().lock().ok()?;
    let now = Instant::now();
    // A session older than the TTL is a handshake the lane would rather pay than trust, and one the edge has closed is no session at all.
    pool.retain(|(_, at, _)| now.duration_since(*at) < POOL_TTL);
    let at = pool.iter().rposition(|(held, _, _)| held.names(dial))?;
    let session = pool[at].2.clone();
    if session.is_gone() {
        return None;
    }
    Some(session)
}

/// A session the edge closed while it was idle goes back to nothing: it is not lent again, and the flow that found it closed pays the handshake it was saving.
fn pool_forget(session: &Arc<Session>) {
    let Ok(mut pool) = pool().lock() else {
        return;
    };
    pool.retain(|(_, _, held)| !Arc::ptr_eq(held, session));
}

/// A session opened to an edge is registered, so the next flow to that edge finds it and rides it instead of dialling.
fn pool_register(key: SessionKey, session: &Arc<Session>) {
    let Ok(mut pool) = pool().lock() else {
        return;
    };
    if pool.len() >= POOL_IDLE {
        pool.remove(0);
    }
    pool.push((key, Instant::now(), Arc::clone(session)));
}

/// One UDP target as its own H2 connection carrying CONNECT-UDP: a lane stays one stream on one connection, so a second target is a second connection.
pub(crate) fn open_udp(
    dial: &FoxyDial,
    target_host: &str,
    target_port: u16,
) -> Result<Tls2, Failure> {
    let edge = edge_authority(&dial.host, dial.port);
    let mut block = Vec::with_capacity(160 + dial.pass.token.len() + target_host.len());
    masque::connect_udp(
        &edge,
        target_host,
        target_port,
        &dial.pass.token,
        &mut block,
    );
    let session = open_session(dial)?;
    attach(&session, &block)
}

/// One UDP target as its own HTTP/1.1 upgrade carrying CONNECT-UDP: RFC 9298 §4's fallback for an edge whose TLS answers no HTTP/2 or HTTP/3.
pub(crate) fn open_udp_h1(
    dial: &FoxyDial,
    target_host: &str,
    target_port: u16,
) -> Result<H1Datagram, Failure> {
    let edge = edge_authority(&dial.host, dial.port);
    let mut tls = tls_to_edge(dial)?;
    let mut request = Vec::with_capacity(192 + dial.pass.token.len() + target_host.len());
    masque::connect_udp_h1(
        &edge,
        target_host,
        target_port,
        &dial.pass.token,
        &mut request,
    );
    tls.write_all(&request).map_err(|_| Failure::Io)?;
    let (status, carried) = head(&mut tls, None)?;
    if status != 101 {
        return Err(Failure::Rejected(status));
    }
    Ok(H1Datagram {
        tls: Tls1 {
            tls,
            carried,
            at: 0,
            park: None,
        },
        capsule_buf: Vec::new(),
        handed: 0,
    })
}

/// One HTTP/2 session to the edge: the preface, the settings, and a socket with no stream on it yet.
fn open_session(dial: &FoxyDial) -> Result<Arc<Session>, Failure> {
    let mut tls = tls_to_edge(dial)?;

    // The stream window arrives in the settings; the connection window only moves by a frame, so without this the tunnel is paced by a round trip for its first 64 KiB.
    let mut opening = Vec::with_capacity(48);
    opening.extend_from_slice(frames::PREFACE);
    h2_frame(
        frames::SETTINGS,
        0,
        0,
        &frames::CLIENT_SETTINGS,
        &mut opening,
    );
    h2_frame(
        frames::WINDOW_UPDATE,
        0,
        0,
        &(frames::WINDOW - frames::DEFAULT_WINDOW).to_be_bytes(),
        &mut opening,
    );
    tls.write_all(&opening).map_err(|_| Failure::Io)?;
    Ok(Arc::new(Session {
        inner: std::sync::Mutex::new(SessionInner {
            tls,
            // What a flow may put on the wire is only what the edge grants: the stream window arrives in its settings and the connection window only moves by a `WINDOW_UPDATE` on stream 0, so both start at the protocol default rather than at the window this lane asks the edge to keep open for it.
            conn: foxy::flow::Window::new(i64::from(frames::DEFAULT_WINDOW)),
            peer_initial: frames::DEFAULT_WINDOW,
            max_frame: MAX_FRAME,
            next_stream: 1,
            streams: std::collections::HashMap::new(),
            frame: FrameState::default(),
            out: Vec::new(),
            gone: false,
            conn_pending: 0,
            park: None,
            quantum: crate::budgets::head_arrival(),
        }),
    }))
}

/// Opens a CONNECT stream on a session and waits for its status: the stream is the flow's, and the session outlives it.
fn attach(session: &Arc<Session>, block: &[u8]) -> Result<Tls2, Failure> {
    let mut inner = session.inner.lock().map_err(|_| Failure::Io)?;
    if inner.gone {
        return Err(Failure::Stream);
    }
    let stream = inner.next_stream;
    if stream >= LAST_STREAM {
        return Err(Failure::Stream);
    }
    inner.next_stream += 2;
    let peer_initial = inner.peer_initial;
    let mut lane = Tls2 {
        session: Arc::clone(session),
        stream,
    };
    let mut opening = Vec::with_capacity(frames::H2_HEADER + block.len());
    h2_frame(frames::HEADERS, 0x4, stream, block, &mut opening);
    inner.tls.write_all(&opening).map_err(|_| Failure::Io)?;
    inner.tls.flush().map_err(|_| Failure::Io)?;
    inner
        .streams
        .insert(stream, Stream::new(i64::from(peer_initial) as u32));
    drop(inner);
    let status = lane.await_status()?;
    opened(status)?;
    Ok(lane)
}

/// The stage the lane's edge dial lost, behind `FOXY_DEBUG`: a red leg is only actionable when it says where.
fn debug_stage(stage: &str) {
    if debug_on() {
        eprintln!("foxy-debug: {stage}");
    }
}

fn h2_frame(kind: u8, flags: u8, stream: u32, payload: &[u8], out: &mut Vec<u8>) {
    let frame = frames::H2Frame {
        kind,
        flags,
        stream,
        length: payload.len() as u32,
    };
    out.extend_from_slice(&frame.header());
    out.extend_from_slice(payload);
}

/// The credit a lane holds before it grants it back: the edge is granted a 16 MiB window to fill, so a held update cannot stall it, while a write per frame spends a record and a segment on 26 bytes the edge already owes us.
const CREDIT_FLOOR: u32 = 1 << 16;

/// The two `WINDOW_UPDATE` frames a credit grants differ only by stream id, so their eighteen header bytes are constant and each call writes the increment into the two slots left zero here; the stream slot is patched per lane.
const CREDIT_TEMPLATE: [u8; 26] = {
    let mut out = [0u8; 26];
    // length 4, WINDOW_UPDATE, no flags, the stream at [5..9] and stream 0 at [13..22].
    out[2] = 4;
    out[3] = frames::WINDOW_UPDATE;
    out[15] = 4;
    out[16] = frames::WINDOW_UPDATE;
    out
};

/// The grant a taken byte earns: the stream's own `WINDOW_UPDATE` and the connection's, in the bytes the template holds, so a grant is one record and two frames. A grant of nothing is not written: a `WINDOW_UPDATE` of zero is a protocol error.
fn grant(stream: u32, stream_increment: u32, conn_increment: u32, out: &mut Vec<u8>) {
    out.clear();
    if stream_increment > 0 {
        out.extend_from_slice(&CREDIT_TEMPLATE[..13]);
        out[5..9].copy_from_slice(&stream.to_be_bytes());
        out[9..13].copy_from_slice(&stream_increment.to_be_bytes());
    }
    if conn_increment > 0 {
        let base = out.len();
        out.extend_from_slice(&CREDIT_TEMPLATE[13..]);
        out[base + 9..base + 13].copy_from_slice(&conn_increment.to_be_bytes());
    }
}

/// Grants back what a stream has taken and what the connection has taken: the two counters are held apart, because a grant is owed per stream and once for the connection, and a session with many streams takes more from the connection than from any one of them.
fn flush_credit(inner: &mut SessionInner, stream: u32) -> Result<(), Failure> {
    let stream_increment = inner
        .streams
        .get_mut(&stream)
        .map_or(0, |entry| std::mem::take(&mut entry.pending_credit));
    let conn_increment = std::mem::take(&mut inner.conn_pending);
    if stream_increment == 0 && conn_increment == 0 {
        return Ok(());
    }
    let mut out = std::mem::take(&mut inner.out);
    grant(stream, stream_increment, conn_increment, &mut out);
    let written = inner.tls.write_all(&out);
    inner.out = out;
    written.map_err(|_| Failure::Io)
}

/// Holds the credit a DATA payload grants back until it is worth a write: the edge has a 16 MiB window to ride on, so a held update is never the reason it stalls, while one 26-byte frame per inbound frame spends a TLS record and a segment to move a number the edge has already granted.
///
/// The credit is held on the stream that took the bytes and on the connection, because a grant is owed per stream and once over every stream.
fn credit(inner: &mut SessionInner, stream: u32, len: usize) -> Result<(), Failure> {
    // Saturating because the held total is only ever a flush threshold: a lane that has taken the whole 16 MiB window and not yet granted any of it is served by the flush, not by an exact count.
    let bytes = u32::try_from(len).unwrap_or(u32::MAX);
    if let Some(entry) = inner.streams.get_mut(&stream) {
        entry.pending_credit = entry.pending_credit.saturating_add(bytes);
    }
    inner.conn_pending = inner.conn_pending.saturating_add(bytes);
    let crossed = inner
        .streams
        .get(&stream)
        .is_some_and(|entry| entry.pending_credit >= CREDIT_FLOOR)
        || inner.conn_pending >= CREDIT_FLOOR;
    if crossed {
        return flush_credit(inner, stream);
    }
    Ok(())
}

/// The edge's `SETTINGS` applied to the session: a new `INITIAL_WINDOW_SIZE` moves every stream's window by the difference, and a new maximum frame size bounds what the session sends.
fn apply_settings(inner: &mut SessionInner, payload: &[u8]) {
    let mut at = 0usize;
    while let Some((id, value)) = frames::setting(payload, at) {
        match id {
            4 => {
                let delta = i64::from(value) - i64::from(inner.peer_initial);
                inner.peer_initial = value;
                for entry in inner.streams.values_mut() {
                    entry.window.shift(delta);
                }
            }
            5 => inner.max_frame = (value as usize).clamp(16_384, MAX_FRAME),
            _ => {}
        }
        at += 6;
    }
}

/// One UDP payload out as one DATAGRAM capsule, split over DATA frames when needed: the capsule stream is byte-oriented and the reader reassembles. The frame header and the capsule header ride a fixed buffer and the payload keeps the caller's bytes, so the whole datagram is never staged before the record takes it.
fn write_capsule(inner: &mut SessionInner, stream: u32, payload: &[u8]) -> std::io::Result<()> {
    if inner.streams.get(&stream).is_some_and(|s| s.fin) {
        return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
    }
    let mut prefix = [0u8; 10];
    let plen = masque::datagram_prefix_into(&mut prefix, payload.len());
    let total = plen + payload.len();
    // The whole capsule rides or waits: a credit the lane has not been granted would be spent by the capsule's head, and a caller holding this lane cannot read the `WINDOW_UPDATE` that would grant it.
    let spend = stream_spend(inner, stream);
    if u32::try_from(total).unwrap_or(u32::MAX) > spend {
        return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
    }
    let mut at = 0usize;
    while at < total {
        let max = inner.max_frame;
        let frame = foxy::flow::frame_size(total - at, max).min(spend);
        charge_stream(inner, stream, frame);
        let frame = frame as usize;
        let header = frames::H2Frame {
            kind: frames::DATA,
            flags: 0,
            stream,
            length: frame as u32,
        }
        .header();
        let end = at + frame;
        // A frame boundary may fall inside the capsule header, so the header is a slice of `prefix` and the payload a slice of the caller's buffer, joined only where one frame spans both.
        if end <= plen {
            inner
                .tls
                .write_all_slices(&[&header[..], &prefix[at..end]])?;
        } else if at < plen {
            inner.tls.write_all_slices(&[
                &header[..],
                &prefix[at..plen],
                &payload[..end - plen],
            ])?;
        } else {
            inner
                .tls
                .write_all_slices(&[&header[..], &payload[at - plen..end - plen]])?;
        }
        at = end;
    }
    Ok(())
}

/// The status of a CONNECT, out of the header block the edge sent for that stream: a block that is not whole yet has no status.
fn status_of(inner: &SessionInner, stream: u32) -> Result<Option<u16>, Failure> {
    let Some(entry) = inner.streams.get(&stream) else {
        return Ok(None);
    };
    if !entry.head_end {
        return Ok(None);
    }
    if let Some(status) = hpack::hpack_status(&entry.head) {
        Ok(Some(status))
    } else {
        debug_block(&entry.head);
        Err(Failure::Frame)
    }
}

/// The credit one stream may spend on a frame: the edge grants the stream and the connection windows independently, so the tighter of the two is the limit.
fn stream_spend(inner: &SessionInner, stream: u32) -> u32 {
    let own = inner.streams.get(&stream).map_or(0, |s| s.window.left());
    own.min(inner.conn.left())
}

/// Spends the credit of one frame on both windows it is spent against: the stream's own and the connection's, whose bytes every stream pays at once.
fn charge_stream(inner: &mut SessionInner, stream: u32, len: u32) {
    if let Some(entry) = inner.streams.get_mut(&stream) {
        entry.window.take(len);
    }
    inner.conn.take(len);
}

/// A relay over a TLS stream that speaks HTTP/2: a caller writing bytes sees a DATA frame, a caller reading bytes sees one's payload.
///
/// The lane is a handle on one stream of a session: the session owns the socket, the connection's credit and the frames, and many flows may ride one session at once.
pub(crate) struct Tls2 {
    /// The session this stream rides: one TLS connection to the edge, shared by every flow that opens a stream on it.
    session: Arc<Session>,
    /// The CONNECT stream this lane owns: `1` on a fresh session, then the next odd id each time the session is lent again.
    stream: u32,
}

/// One HTTP/2 session to the edge: the socket, the connection's own credit, and the streams that ride it.
pub(crate) struct Session {
    inner: std::sync::Mutex<SessionInner>,
}

impl Session {
    /// Whether the edge has taken this session away: a reset, a `GOAWAY` or a broken frame leaves it able to carry nothing, so it is not lent again.
    fn is_gone(&self) -> bool {
        self.inner.lock().map_or(true, |inner| inner.gone)
    }
}

/// The session's state, under its one lock: one socket is one reader and one writer, so every frame is taken by one of them.
struct SessionInner {
    tls: ferrox_core::tls::RustlsProvider<Connection>,
    /// The credit the whole connection may spend: every stream's bytes are spent against it at once, so it is a connection's window and not a stream's.
    conn: foxy::flow::Window,
    /// The `INITIAL_WINDOW_SIZE` the edge last announced: a change moves every stream by the difference, and the streams already running move too.
    peer_initial: u32,
    /// The widest frame the edge may send.
    max_frame: usize,
    /// The next odd stream id this session hands out: a client's streams are odd, and the edge answers on the id it was given.
    next_stream: u32,
    /// The streams open on this session, and the bytes that arrived for one whose flow is not reading yet.
    streams: std::collections::HashMap<u32, Stream>,
    /// The frame in flight off the wire, and the stream it belongs to.
    frame: FrameState,
    /// The frame this session writes, reused so a relay allocates nothing per frame.
    out: Vec<u8>,
    /// The session answered with a reset, a `GOAWAY`, or a broken frame: it can carry no flow further and is never lent again.
    gone: bool,
    /// The bytes the edge has sent into the connection's granted window that the session has taken but not yet granted back, over every stream: the connection's own credit is owed once, whatever stream the bytes arrived on.
    conn_pending: u32,
    /// The wait a leg that has handed the lock back may spend on this session's socket: the quantum a relay armed, less the grain its blocking read takes. `None` until one arms it, because a caller that reads this session alone has no lock to release.
    park: Option<Duration>,
    /// The wait one socket read takes: the grain the relay armed, and the bound the head walk waits under.
    quantum: Duration,
}

/// One CONNECT stream on a session: its own credit, its own staged bytes, its own capsule stream.
struct Stream {
    /// The credit this stream may spend: the edge grants it on this stream and the connection's credit bounds it too, so the tighter of the two is what a frame may carry.
    window: foxy::flow::Window,
    /// Bytes read from a DATA frame the caller has not taken, with a cursor: draining would move what is left on every call.
    carry: Vec<u8>,
    at: usize,
    /// Capsule-stream bytes not parsed yet: one capsule may span DATA frames, so frames accumulate here.
    capsule_buf: Vec<u8>,
    /// Octets of the head DATAGRAM capsule already handed to a caller whose buffer was shorter than the datagram: the capsule stays staged until this reaches its length, so a short read costs the tail nothing.
    handed: usize,
    /// The header block the edge sent for this stream, and whether it is whole: a status arrives in pieces, and each piece belongs to the stream it names.
    head: Vec<u8>,
    head_end: bool,
    /// Bytes the edge has sent into this stream's granted window that this stream has taken but not yet granted back: the update goes out when the held credit reaches `CREDIT_FLOOR`, never per frame.
    pending_credit: u32,
    /// The peer ended this stream: nothing more will arrive on it.
    fin: bool,
    /// This flow has closed its half of the stream.
    sent_end: bool,
    /// The IP packet under construction, reused so a datagram allocates nothing: an IP header, a UDP header and the payload, written once and handed to the frame. A packet per datagram took a buffer that grew three times on its way to the wire.
    packet: Vec<u8>,
}

impl Stream {
    /// A fresh stream on a session: its credit starts at the size the edge last announced, and everything else starts empty.
    fn new(peer_initial: u32) -> Self {
        Self {
            window: foxy::flow::Window::new(i64::from(peer_initial)),
            carry: Vec::new(),
            at: 0,
            capsule_buf: Vec::new(),
            handed: 0,
            head: Vec::new(),
            head_end: false,
            pending_credit: 0,
            fin: false,
            sent_end: false,
            packet: Vec::new(),
        }
    }
}

/// How much of the frame in flight has arrived: a read quantum expires between two socket reads, not between two frames.
#[derive(Default)]
struct FrameState {
    head: [u8; frames::H2_HEADER],
    head_at: usize,
    payload_at: usize,
    /// The DATA frame in flight that has not yet reached its caller: a caller's buffer smaller than the frame, or a quantum that expired mid-frame, leaves the rest here so the next read resumes into its buffer instead of re-fetching what was already paid for.
    data_at: u32,
    data_len: u32,
    /// The `END_STREAM` of the frame in flight: only the delivery that takes its last byte may tell the caller the stream ended.
    data_end: bool,
    /// Bytes handed into the caller's buffer by the current call: the frame's total cursor cannot tell one call's delivery from the next's, and the credit is owed per byte the caller actually got.
    delivered: u32,
    /// The stream the frame in flight belongs to: a session's socket carries many streams, and the bytes on it belong to the frame that named one.
    stream: u32,
}

/// Fills `buf` from `at` on, leaving `at` where the wire stopped: a timeout mid-buffer is a pause the next call resumes, and only a closed stream ends it.
fn fill_from<S: Read>(io: &mut S, buf: &mut [u8], at: &mut usize) -> std::io::Result<()> {
    while *at < buf.len() {
        match io.read(&mut buf[*at..]) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            Ok(read) => *at += read,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Consumes the payload of the DATA frame in flight, straight into the destination: the destination gets exactly the room left in the frame, so no caller can be fed a byte of the next frame's header, and a quantum that expires mid-frame hands over what arrived and leaves the rest in `state`.
fn fill_data<S: Read>(
    io: &mut S,
    state: &mut FrameState,
    dst: &mut [u8],
) -> std::io::Result<usize> {
    let want = (state.data_len - state.data_at).min(dst.len() as u32) as usize;
    let mut at = 0usize;
    while at < want {
        match io.read(&mut dst[at..want]) {
            Ok(0) => {
                state.data_at += at as u32;
                state.delivered += at as u32;
                if at == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
                }
                return Ok(at);
            }
            Ok(read) => at += read,
            // The pause mid-frame is a handover, not a loss: what arrived sits in the caller's buffer, and the cursor says where the wire stopped.
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                state.data_at += at as u32;
                state.delivered += at as u32;
                if at == 0 {
                    return Err(error);
                }
                return Ok(at);
            }
            Err(error) => {
                state.data_at += at as u32;
                state.delivered += at as u32;
                return Err(error);
            }
        }
    }
    state.data_at += at as u32;
    state.delivered += at as u32;
    Ok(at)
}

/// The rest of a DATA frame a previous read stopped inside of: delivered to its owner's buffer or staged in the stream's own, whichever the caller's room allows.
fn resume_data<S: Read>(
    io: &mut S,
    state: &mut FrameState,
    out: &mut Vec<u8>,
    dst: &mut [u8],
    stream: u32,
) -> std::io::Result<(frames::H2Frame, bool)> {
    // A caller that cannot receive the rest of the frame into its buffer cannot receive it at all: the bytes already handed over are not replayable, and staging them again would be the loss this path exists to avoid.
    if dst.is_empty() {
        return Err(std::io::Error::other(
            "foxy: a resumed frame met a caller with no room",
        ));
    }
    if state.stream == stream {
        fill_data(io, state, dst)?;
        let done = state.data_at == state.data_len;
        let frame = frames::H2Frame {
            kind: frames::DATA,
            flags: if done && state.data_end {
                frames::END_STREAM
            } else {
                0
            },
            stream: state.stream,
            length: if done { state.data_len } else { 0 },
        };
        if done {
            state.data_len = 0;
            state.data_at = 0;
            state.data_end = false;
        }
        return Ok((frame, true));
    }
    // The frame in flight belongs to another flow, and its first part is already in that flow's own buffer: the rest is staged here and handed to its owner, so a frame is never split between two readers' answers.
    let want = (state.data_len - state.data_at) as usize;
    crate::proxy::resize_scratch(out, want);
    fill_from(io, out, &mut state.payload_at)?;
    let taken = state.payload_at as u32;
    state.data_at += taken;
    state.delivered += taken;
    state.payload_at = 0;
    let done = state.data_at == state.data_len;
    let frame = frames::H2Frame {
        kind: frames::DATA,
        flags: if done && state.data_end {
            frames::END_STREAM
        } else {
            0
        },
        stream: state.stream,
        length: taken,
    };
    if done {
        state.data_len = 0;
        state.data_at = 0;
        state.data_end = false;
    }
    Ok((frame, false))
}

/// One frame off the wire; a socket timeout keeps its kind so a relay can tell an idle quantum from a dead peer.
///
/// An unpadded DATA frame for the reading flow goes straight into `dst` with no staging buffer between the lane and its caller: the answer carries the frame's end flag only on the delivery of its last byte, and a caller whose buffer filled mid-frame sees a zero-length marker, the bytes where it put them, and the remainder waiting in `state`. A frame for another stream is staged in that stream's own buffer, and one staged cannot also be handed over here. A padded one stages, because the padding comes off before the caller sees a byte.
///
/// The second value says where the payload landed: `true` when it is in `dst`, `false` when it is in `out`.
fn read_frame<S: Read>(
    io: &mut S,
    state: &mut FrameState,
    out: &mut Vec<u8>,
    dst: &mut [u8],
    stream: u32,
) -> std::io::Result<(frames::H2Frame, bool)> {
    if state.data_len > 0 {
        return resume_data(io, state, out, dst, stream);
    }
    fill_from(io, &mut state.head, &mut state.head_at)?;
    let frame = frames::H2Frame::parse(&state.head)
        .ok_or_else(|| std::io::Error::other("foxy: a header that is not a frame"))?;
    // Only the reading flow's own stream is delivered straight into the caller's buffer: a frame for another stream has to be staged in that stream's own buffer, and one staged cannot also be handed over here.
    if frame.kind == frames::DATA
        && frame.stream == stream
        && frame.length > 0
        && frame.flags & frames::PADDED == 0
        && !dst.is_empty()
    {
        out.clear();
        state.data_len = frame.length;
        state.data_at = 0;
        state.data_end = frame.flags & frames::END_STREAM != 0;
        state.stream = frame.stream;
        state.head_at = 0;
        state.head = [0u8; frames::H2_HEADER];
        fill_data(io, state, dst)?;
        if state.data_at < state.data_len {
            return Ok((
                frames::H2Frame {
                    kind: frames::DATA,
                    flags: 0,
                    stream,
                    length: 0,
                },
                true,
            ));
        }
        let end = std::mem::take(&mut state.data_end);
        state.data_len = 0;
        state.data_at = 0;
        return Ok((
            frames::H2Frame {
                kind: frames::DATA,
                flags: if end { frames::END_STREAM } else { 0 },
                stream: frame.stream,
                length: frame.length,
            },
            true,
        ));
    }
    if state.payload_at == 0 {
        // The widest frame worth a buffer is the one this lane asked the edge to be allowed to send, not the limit the edge named for its own receives.
        if frame.length > frames::MAX_FRAME {
            return Err(std::io::Error::other(
                "foxy: a frame wider than the lane ever asked for",
            ));
        }
        crate::proxy::resize_scratch(out, frame.length as usize);
    }
    fill_from(io, out, &mut state.payload_at)?;
    state.head_at = 0;
    state.payload_at = 0;
    state.head = [0u8; frames::H2_HEADER];
    Ok((frame, false))
}

impl Tls2 {
    /// The session's lock, held for as long as the caller needs it: a session's socket is one reader and one writer, so every frame is taken under this one lock.
    fn inner(&self) -> Result<std::sync::MutexGuard<'_, SessionInner>, Failure> {
        self.session.inner.lock().map_err(|_| Failure::Io)
    }

    /// The session's state for a test that reads a counter no caller sees.
    #[cfg(test)]
    fn test_inner(&self) -> std::sync::MutexGuard<'_, SessionInner> {
        self.session.inner.lock().expect("the session lock")
    }

    /// This lane's stream for a test that reads or stages it: its counters and buffers belong to one stream of a shared session.
    #[cfg(test)]
    fn test_stream<R>(&self, body: impl FnOnce(&mut Stream) -> R) -> R {
        let mut inner = self.test_inner();
        body(
            inner
                .streams
                .get_mut(&self.stream)
                .expect("the lane's stream is open"),
        )
    }

    pub(crate) fn set_read_quantum(&self, quantum: Duration) -> std::io::Result<()> {
        let mut inner = self.inner().map_err(io)?;
        inner.quantum = quantum;
        inner.tls.get_ref().set_read_timeout(Some(quantum))
    }

    /// The arm for a lane whose lock both relay directions share: the blocking read takes one grain — `SESSION_POLL`, the cadence a shared lock is armed with elsewhere in the app — and the rest of the quantum is spent outside the lock, parked on the socket `read_wait` hands back. A writer then waits out a grain, not a wait.
    pub(crate) fn set_relay_quantum(&mut self, quantum: Duration) -> std::io::Result<()> {
        {
            let mut inner = self.inner().map_err(io)?;
            inner.park = Some(quantum);
        }
        self.set_read_quantum(quantum.min(crate::budgets::SESSION_POLL))
    }

    /// The socket to park on, when a socket read is the only thing that can move this lane: a staged frame's bytes and a TLS record's plaintext are both one read away from the caller, and waiting on the wire for them would park a leg that has work to hand over.
    pub(crate) fn read_wait(&self) -> Option<(EdgeWait, Duration)> {
        let inner = self.session.inner.lock().ok()?;
        let park = inner.park?;
        let stream = inner.streams.get(&self.stream)?;
        // Bytes already in this stream's own buffer are the state to refuse on: a staged payload is the caller's to take, and a leg that parks on the socket instead would wait for a byte that has already arrived.
        if stream.at < stream.carry.len() {
            return None;
        }
        if !inner.tls.wants_read() {
            return None;
        }
        Some((EdgeWait::Tcp(inner.tls.get_ref().try_clone().ok()?), park))
    }

    /// Ends this lane's half of its stream: an empty DATA with `END_STREAM`, so the edge closes the tunnel while the session stays open for the next stream.
    pub(crate) fn finish(&mut self) -> Result<(), Failure> {
        let mut inner = self.inner()?;
        if inner.gone {
            return Ok(());
        }
        if inner
            .streams
            .get(&self.stream)
            .is_none_or(|stream| stream.sent_end)
        {
            return Ok(());
        }
        let mut out = Vec::with_capacity(frames::H2_HEADER);
        h2_frame(frames::DATA, frames::END_STREAM, self.stream, &[], &mut out);
        inner.tls.write_all(&out).map_err(|_| Failure::Io)?;
        inner.tls.flush().map_err(|_| Failure::Io)?;
        if let Some(stream) = inner.streams.get_mut(&self.stream) {
            stream.sent_end = true;
        }
        Ok(())
    }

    /// A stream is returned to the pool only when both halves of it ended and nothing broke it: a half-closed or reset stream is not a session the next flow may ride.
    fn reusable(&self) -> bool {
        let Ok(inner) = self.inner() else {
            return false;
        };
        if inner.gone {
            return false;
        }
        inner
            .streams
            .get(&self.stream)
            .is_some_and(|stream| stream.fin && stream.sent_end)
    }

    /// Reads one frame off the session's socket and hands it to `body`, with the payload borrowed.
    ///
    /// A `dst` with room takes a DATA frame's payload directly, and only for this lane's own stream: a frame for another stream has to be staged in that stream's own buffer, and one staged cannot also be handed over here. The bytes this call delivered are counted in `frame_state.delivered`.
    fn with_frame<R>(
        &mut self,
        dst: &mut [u8],
        body: impl FnOnce(&mut SessionInner, frames::H2Frame, &[u8], bool) -> R,
    ) -> std::io::Result<R> {
        let mut inner = self.inner().map_err(io)?;
        let mut payload = std::mem::take(&mut inner.out);
        inner.frame.delivered = 0;
        let stream = self.stream;
        let (frame, delivered) = {
            let SessionInner { tls, frame, .. } = &mut *inner;
            match read_frame(tls, frame, &mut payload, dst, stream) {
                Ok(read) => read,
                Err(error) => {
                    inner.out = payload;
                    return Err(error);
                }
            }
        };
        // A SETTINGS is applied and answered, a PING is echoed, and a PUSH_PROMISE is refused, on whichever stream's read took the frame: all belong to the connection, not to the flow that happened to read them.
        match frames::h2_routed(frame, &payload) {
            frames::H2Routed::Settings {
                ack: false,
                payload: settings,
            } => {
                let mut ack = Vec::with_capacity(frames::H2_HEADER);
                h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut ack);
                let _ = inner.tls.write_all(&ack);
                apply_settings(&mut inner, settings);
            }
            frames::H2Routed::Ping {
                ack: false,
                payload: ping,
            } => {
                let mut echo = Vec::with_capacity(frames::H2_HEADER + ping.len());
                h2_frame(frames::PING, 0x1, 0, ping, &mut echo);
                let _ = inner.tls.write_all(&echo);
            }
            // HTTP/2 8.2: a push is refused on the stream it promises, with `REFUSED_STREAM` — the only stream the lane answers that is not the one it opened.
            frames::H2Routed::Push { promised } => {
                let mut reset = Vec::with_capacity(frames::H2_HEADER + 4);
                h2_frame(
                    frames::RST_STREAM,
                    0,
                    promised,
                    &7u32.to_be_bytes(),
                    &mut reset,
                );
                let _ = inner.tls.write_all(&reset);
            }
            _ => {}
        }
        let out = body(&mut inner, frame, &payload, delivered);
        inner.out = payload;
        Ok(out)
    }

    /// Grants back everything this lane has taken: the held totals are cleared whether or not the write lands, because a lane that cannot write has lost the flow the credit would have paced.
    fn flush_credit(&mut self) -> Result<(), Failure> {
        let mut inner = self.inner()?;
        flush_credit(&mut inner, self.stream)
    }

    /// Hands this stream back to its session: the id is spent, the bytes staged on it are dropped, and the session stays open for the next flow.
    fn release(&mut self) {
        let Ok(mut inner) = self.inner() else {
            return;
        };
        inner.streams.remove(&self.stream);
    }

    /// Resets a flow that ended before its stream did: an edge left unreset keeps fetching the response into a window nobody drains, charged to the account, and its stream entry would ride the session for the rest of the pool's life.
    fn cancel(&mut self) {
        let Ok(mut inner) = self.inner() else {
            return;
        };
        if inner.gone || !inner.streams.contains_key(&self.stream) {
            return;
        }
        let mut reset = Vec::with_capacity(frames::H2_HEADER + 4);
        h2_frame(
            frames::RST_STREAM,
            0,
            self.stream,
            &8u32.to_be_bytes(),
            &mut reset,
        );
        let _ = inner.tls.write_all(&reset);
        let _ = inner.tls.flush();
        inner.streams.remove(&self.stream);
    }

    /// Builds one IP packet into this stream's own scratch and writes it, under one lock: the scratch belongs to the stream, so a build and the write that empties it cannot be split by another flow's turn.
    fn write_ip(
        &mut self,
        source: &[u8],
        destination: &[u8],
        source_port: u16,
        destination_port: u16,
        payload: &[u8],
    ) -> (bool, std::io::Result<()>) {
        let Ok(mut inner) = self.inner() else {
            return (false, Err(io(Failure::Io)));
        };
        let peer_initial = inner.peer_initial;
        let stream = self.stream;
        let built = {
            let entry = inner
                .streams
                .entry(stream)
                .or_insert_with(|| Stream::new(peer_initial));
            build_packet(
                &mut entry.packet,
                source,
                destination,
                source_port,
                destination_port,
                payload,
            )
        };
        if !built {
            return (false, Ok(()));
        }
        // The packet leaves the scratch and comes back to it: the buffer is the stream's own and keeps its address across the write, so the next datagram writes over these bytes rather than into a new buffer.
        let packet = inner
            .streams
            .get_mut(&stream)
            .map_or_else(Vec::new, |entry| std::mem::take(&mut entry.packet));
        let sent = write_capsule(&mut inner, stream, &packet);
        if let Some(entry) = inner.streams.get_mut(&stream) {
            entry.packet = packet;
        }
        (true, sent)
    }

    /// Waits for the status of this lane's CONNECT: the head block is this stream's own, and a fragment of it arrives as a CONTINUATION on the same id.
    fn await_status(&mut self) -> Result<u16, Failure> {
        // The status is the h2 form of the head, so it waits the named head budget; unset, that is the same twenty seconds.
        let deadline = Instant::now() + crate::budgets::head_arrival();
        loop {
            if Instant::now() >= deadline {
                return Err(Failure::Stream);
            }
            let own = self.stream;
            let status = self.with_frame(&mut [], |inner, frame, payload, _| {
                match frames::h2_routed(frame, payload) {
                    frames::H2Routed::Headers {
                        stream,
                        block,
                        end_headers,
                        ..
                    } if stream == own => {
                        if let Some(entry) = inner.streams.get_mut(&stream) {
                            entry.head.extend_from_slice(block);
                            entry.head_end = end_headers;
                        }
                        status_of(inner, own)
                    }
                    frames::H2Routed::Continuation { stream, block, end } if stream == own => {
                        if let Some(entry) = inner.streams.get_mut(&stream) {
                            entry.head.extend_from_slice(block);
                            entry.head_end = end;
                        }
                        status_of(inner, own)
                    }
                    frames::H2Routed::Data {
                        stream,
                        payload,
                        end,
                        wire,
                    } => {
                        // A DATA frame that arrives while the status is still out is payload the edge sent early: hold its credit like any other, and let the walk ignore the bytes until `END_STREAM` says the status itself is gone.
                        if let Some(entry) = inner.streams.get_mut(&stream) {
                            entry.fin = end;
                            entry.carry.extend_from_slice(payload);
                        }
                        let _ = credit(inner, stream, wire);
                        Ok(None)
                    }
                    frames::H2Routed::Window { stream, increment } => {
                        if stream == 0 {
                            inner.conn.add(increment);
                        } else if let Some(entry) = inner.streams.get_mut(&stream) {
                            entry.window.add(increment);
                        }
                        Ok(None)
                    }
                    frames::H2Routed::Reset { .. } | frames::H2Routed::GoAway { .. } => {
                        inner.gone = true;
                        Err(Failure::Stream)
                    }
                    _ => Ok(None),
                }
            });
            let status = status.map_err(|_| Failure::Stream)??;
            if let Some(status) = status {
                return Ok(status);
            }
        }
    }

    /// Hands the caller what it asked for out of `carry` and moves the cursor: a copy of bytes, never a move of what is left.
    fn take(&mut self, buf: &mut [u8]) -> usize {
        let Ok(mut inner) = self.inner() else {
            return 0;
        };
        let Some(stream) = inner.streams.get_mut(&self.stream) else {
            return 0;
        };
        let take = buf.len().min(stream.carry.len() - stream.at);
        buf[..take].copy_from_slice(&stream.carry[stream.at..stream.at + take]);
        stream.at += take;
        if stream.at == stream.carry.len() {
            stream.carry.clear();
            stream.at = 0;
        }
        take
    }

    /// One UDP payload as one DATAGRAM capsule, split over DATA frames when needed: the capsule stream is byte-oriented and the reader reassembles. The frame header and the capsule header ride a fixed buffer and the payload keeps the caller's bytes, so the whole datagram is never staged before the record takes it.
    pub(crate) fn write_datagram(&mut self, payload: &[u8]) -> std::io::Result<()> {
        let mut inner = self.inner().map_err(io)?;
        write_capsule(&mut inner, self.stream, payload)
    }

    /// One UDP payload out of the capsule stream: frames accumulate until a whole DATAGRAM capsule parses, a payload wider than the caller's buffer arrives over several reads, and empty datagrams are skipped so `Ok(0)` stays the end of stream.
    pub(crate) fn read_datagram(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let capsule = {
                let own = self.stream;
                let mut inner = self.inner().map_err(io)?;
                let Some(stream) = inner.streams.get(&own) else {
                    return Ok(0);
                };
                match masque::datagram_split(&stream.capsule_buf) {
                    Some((used, payload)) => {
                        let len = payload.len();
                        let at = stream.handed;
                        let take = buf.len().min(len - at);
                        buf[..take].copy_from_slice(&payload[at..at + take]);
                        // A capsule is released only when its last octet has been copied, and the count is what the caller got rather than what the capsule holds.
                        if let Some(stream) = inner.streams.get_mut(&own) {
                            if at + take == len {
                                stream.capsule_buf.drain(..used);
                                stream.handed = 0;
                            } else {
                                stream.handed = at + take;
                            }
                        }
                        Some((len, take))
                    }
                    None => None,
                }
            };
            if let Some((len, take)) = capsule {
                if len == 0 {
                    continue;
                }
                return Ok(take);
            }
            let fin = {
                let inner = self.inner().map_err(io)?;
                inner
                    .streams
                    .get(&self.stream)
                    .is_none_or(|stream| stream.fin)
            };
            if fin {
                return Ok(0);
            }
            let over = {
                let inner = self.inner().map_err(io)?;
                inner
                    .streams
                    .get(&self.stream)
                    .is_some_and(|stream| stream.capsule_buf.len() > DATAGRAM_BUF_MAX)
            };
            if over {
                let mut inner = self.inner().map_err(io)?;
                if let Some(stream) = inner.streams.get_mut(&self.stream) {
                    stream.capsule_buf.clear();
                    stream.handed = 0;
                }
                return Err(std::io::Error::other(
                    "foxy: a capsule stream that never parses",
                ));
            }
            let read = self.with_frame(&mut [], |inner, frame, payload, _| {
                stage_datagram(inner, frame, payload, buf)
            });
            let read = read??;
            if read > 0 {
                return Ok(read);
            }
        }
    }
}

/// One routed frame for a CONNECT-UDP tunnel: a whole capsule is handed to the caller where it lies, and a split one waits in the stream's buffer.
fn stage_datagram(
    inner: &mut SessionInner,
    frame: frames::H2Frame,
    payload: &[u8],
    buf: &mut [u8],
) -> std::io::Result<usize> {
    match frames::h2_routed(frame, payload) {
        frames::H2Routed::Data {
            stream,
            payload,
            end,
            wire,
        } => {
            let Some(entry) = inner.streams.get_mut(&stream) else {
                return Ok(0);
            };
            entry.fin = end;
            // A capsule is usually whole inside one DATA frame, so it is handed over where it lies and only the ones behind it staged; nothing is handed over while a split capsule waits, because stream order is datagram order.
            if entry.capsule_buf.is_empty() {
                if let Some((used, datagram)) = masque::datagram_split(payload) {
                    // A buffer shorter than the datagram stages it instead, so the walk above can finish it one read at a time.
                    if buf.len() >= datagram.len() {
                        buf[..datagram.len()].copy_from_slice(datagram);
                        entry.capsule_buf.extend_from_slice(&payload[used..]);
                        let _ = credit(inner, stream, wire);
                        return Ok(datagram.len());
                    }
                }
            }
            entry.capsule_buf.extend_from_slice(payload);
            credit(inner, stream, wire).map_err(io)?;
            Ok(0)
        }
        frames::H2Routed::Window { stream, increment } => {
            if stream == 0 {
                inner.conn.add(increment);
            } else if let Some(entry) = inner.streams.get_mut(&stream) {
                entry.window.add(increment);
            }
            Ok(0)
        }
        frames::H2Routed::Reset { .. } | frames::H2Routed::GoAway { .. } => {
            inner.gone = true;
            Ok(0)
        }
        _ => Ok(0),
    }
}

/// One routed frame for a CONNECT-IP address request: the capsule bytes are staged on the stream they name.
fn stage_address(
    inner: &mut SessionInner,
    frame: frames::H2Frame,
    payload: &[u8],
) -> std::io::Result<()> {
    match frames::h2_routed(frame, payload) {
        frames::H2Routed::Data {
            stream,
            payload,
            end,
            wire,
        } => {
            if let Some(entry) = inner.streams.get_mut(&stream) {
                entry.capsule_buf.extend_from_slice(payload);
                entry.fin = end;
            }
            credit(inner, stream, wire).map_err(io)?;
            Ok(())
        }
        frames::H2Routed::Window { stream, increment } => {
            if stream == 0 {
                inner.conn.add(increment);
            } else if let Some(entry) = inner.streams.get_mut(&stream) {
                entry.window.add(increment);
            }
            Ok(())
        }
        frames::H2Routed::Reset { .. } | frames::H2Routed::GoAway { .. } => {
            inner.gone = true;
            Ok(())
        }
        _ => Ok(()),
    }
}

/// One routed frame for a CONNECT-IP tunnel: a packet whole inside a DATA frame is copied straight to the caller, and the bytes behind it staged for the next read.
fn route_packet(
    inner: &mut SessionInner,
    frame: frames::H2Frame,
    payload: &[u8],
    into: &mut Vec<u8>,
) -> std::io::Result<bool> {
    match frames::h2_routed(frame, payload) {
        frames::H2Routed::Data {
            stream,
            payload,
            end,
            wire,
        } => {
            if let Some(entry) = inner.streams.get_mut(&stream) {
                entry.fin = end;
            }
            // The capsule is usually whole inside one DATA frame, so it is handed out where it lies and only the bytes behind it staged; nothing is handed out while a split capsule waits, because stream order is packet order.
            let whole = {
                let Some(entry) = inner.streams.get_mut(&stream) else {
                    return Ok(false);
                };
                if entry.capsule_buf.is_empty() {
                    if let Some((used, connectip::Capsule::Datagram(packet))) =
                        connectip::capsule_split(payload)
                    {
                        into.clear();
                        into.extend_from_slice(packet);
                        entry.capsule_buf.extend_from_slice(&payload[used..]);
                        Some(true)
                    } else {
                        entry.capsule_buf.extend_from_slice(payload);
                        None
                    }
                } else {
                    entry.capsule_buf.extend_from_slice(payload);
                    None
                }
            };
            credit(inner, stream, wire).map_err(io)?;
            Ok(whole.unwrap_or(false))
        }
        frames::H2Routed::Window { stream, increment } => {
            if stream == 0 {
                inner.conn.add(increment);
            } else if let Some(entry) = inner.streams.get_mut(&stream) {
                entry.window.add(increment);
            }
            Ok(false)
        }
        frames::H2Routed::Reset { .. } | frames::H2Routed::GoAway { .. } => {
            inner.gone = true;
            Ok(false)
        }
        _ => Ok(false),
    }
}

/// One HTTP/2 session to the edge, opening written and no stream yet, for the live check of what the edge does with a second CONNECT — no loopback edge can stand in for the real one.
#[cfg(test)]
pub(crate) fn raw_h2_session(
    dial: &FoxyDial,
) -> Result<ferrox_core::tls::RustlsProvider<Connection>, Failure> {
    open_h2_with_raw(dial)
}

/// The dial half of `open_h2_with`, before any stream.
#[cfg(test)]
fn open_h2_with_raw(
    dial: &FoxyDial,
) -> Result<ferrox_core::tls::RustlsProvider<Connection>, Failure> {
    let mut tls = tls_to_edge(dial)?;
    let mut opening = Vec::with_capacity(48);
    opening.extend_from_slice(frames::PREFACE);
    h2_frame(
        frames::SETTINGS,
        0,
        0,
        &frames::CLIENT_SETTINGS,
        &mut opening,
    );
    h2_frame(
        frames::WINDOW_UPDATE,
        0,
        0,
        &(frames::WINDOW - frames::DEFAULT_WINDOW).to_be_bytes(),
        &mut opening,
    );
    tls.write_all(&opening).map_err(|_| Failure::Io)?;
    tls.flush().map_err(|_| Failure::Io)?;
    Ok(tls)
}

impl Write for Tls2 {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut inner = self.inner().map_err(io)?;
        let fin = inner
            .streams
            .get(&self.stream)
            .is_none_or(|stream| stream.fin);
        if fin {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        let max = inner.max_frame;
        let frame = foxy::flow::frame_size(buf.len(), max).min(stream_spend(&inner, self.stream));
        if frame == 0 {
            return Ok(0);
        }
        charge_stream(&mut inner, self.stream, frame);
        let frame = frame as usize;
        // Header and payload in one write: two writes would be two TLS records, and the record boundary is on the wire.
        let header = frames::H2Frame {
            kind: frames::DATA,
            flags: 0,
            stream: self.stream,
            length: frame as u32,
        }
        .header();
        inner.tls.write_parts(&header, &buf[..frame])?;
        Ok(frame)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut inner = self.inner().map_err(io)?;
        inner.tls.flush()
    }
}

impl Read for Tls2 {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let staged = {
                let inner = self.inner().map_err(io)?;
                inner
                    .streams
                    .get(&self.stream)
                    .is_some_and(|stream| stream.at < stream.carry.len())
            };
            if staged {
                return Ok(self.take(buf));
            }
            let fin = {
                let inner = self.inner().map_err(io)?;
                inner
                    .streams
                    .get(&self.stream)
                    .is_none_or(|stream| stream.fin)
            };
            if fin {
                return Ok(0);
            }
            // An unpadded payload is copied once, by the frame reader, straight into the caller's buffer: nothing is staged between the lane and its caller, and a frame the caller has no room left for resumes in the caller's own space on the next read.
            let own = self.stream;
            let read = self.with_frame(
                buf,
                |inner, frame, payload, delivered| -> std::io::Result<usize> {
                    match frames::h2_routed(frame, payload) {
                        frames::H2Routed::Data {
                            stream,
                            payload,
                            end,
                            wire,
                        } => {
                            if stream != own {
                                // A frame for another flow is staged in that flow's own buffer and its credit held here, so a flow that is not reading yet does not lose its bytes and does not stall the one that is.
                                if let Some(entry) = inner.streams.get_mut(&stream) {
                                    entry.fin = end;
                                    entry.carry.extend_from_slice(payload);
                                }
                                let _ = credit(inner, stream, wire);
                                return Ok(0);
                            }
                            if delivered {
                                // The payload is already in the caller's buffer and none is left in the lane's hands: what this call handed over is counted in `delivered`, and the credit is owed for exactly that.
                                if let Some(entry) = inner.streams.get_mut(&stream) {
                                    entry.fin = end;
                                }
                                let got = inner.frame.delivered as usize;
                                if got > 0 {
                                    // The frame's own length: the whole DATA payload is what the window counts.
                                    credit(inner, stream, frame.length as usize).map_err(io)?;
                                }
                                return Ok(got);
                            }
                            // A caller that asked for nothing and a padded frame both land here: the padding comes off before the rest stages, so the stage holds the payload and the window is owed the body the frame spent.
                            let taken = 0usize;
                            if let Some(entry) = inner.streams.get_mut(&stream) {
                                entry.fin = end;
                            }
                            let mut staged = std::mem::take(&mut inner.out);
                            stage_into(inner, own, payload, taken, &mut staged);
                            inner.out = staged;
                            credit(inner, stream, wire).map_err(io)?;
                            Ok(0)
                        }
                        frames::H2Routed::Window { stream, increment } => {
                            if stream == 0 {
                                inner.conn.add(increment);
                            } else if let Some(entry) = inner.streams.get_mut(&stream) {
                                entry.window.add(increment);
                            }
                            Ok(0)
                        }
                        frames::H2Routed::Reset { .. } | frames::H2Routed::GoAway { .. } => {
                            inner.gone = true;
                            if let Some(entry) = inner.streams.get_mut(&own) {
                                entry.fin = true;
                            }
                            Ok(0)
                        }
                        _ => Ok(0),
                    }
                },
            );
            let read = read??;
            if read > 0 {
                return Ok(read);
            }
        }
    }
}

/// Stages a payload the caller had no room for, in the stream's own buffer: only the bytes past what was taken are copied, and the buffer is reused so a frame that does not fit costs no allocation.
fn stage_into(
    inner: &mut SessionInner,
    stream: u32,
    payload: &[u8],
    taken: usize,
    _scratch: &mut Vec<u8>,
) {
    let Some(entry) = inner.streams.get_mut(&stream) else {
        return;
    };
    if taken < payload.len() {
        entry.carry.clear();
        entry.carry.extend_from_slice(&payload[taken..]);
        entry.at = 0;
    }
}

/// The HTTP/1.1 relay: bytes in, bytes out, once the status has been read. The head walk reads a whole window at a time, so the octets that arrived past `\r\n\r\n` in the answer's own record are the tunnel's first bytes and are handed over from here before the socket is touched again.
pub(crate) struct Tls1 {
    tls: ferrox_core::tls::RustlsProvider<Connection>,
    /// What the head walk took past the delimiter, with a cursor: draining would move what is left on every call.
    carried: Vec<u8>,
    at: usize,
    /// How long a leg that has handed its lock back may wait on this lane's socket for the next byte: the quantum a relay armed, less the grain its blocking read takes. `None` until one arms it, because a caller that reads this lane alone has no lock to release.
    park: Option<Duration>,
}

/// Undecodable-block dump behind `FOXY_DEBUG`: the hex of a header block no codec here reads, so a red live run names the encoding.
fn debug_block(block: &[u8]) {
    if debug_on() {
        eprintln!("foxy-debug: undecodable header block {block:02x?}");
    }
}

impl Tls1 {
    /// Bounds one blocking read so a caller that holds this lane alone can still be interrupted by its own timeout.
    pub(crate) fn set_read_quantum(&self, quantum: Duration) -> std::io::Result<()> {
        self.tls.get_ref().set_read_timeout(Some(quantum))
    }

    /// The arm for a lane whose lock both relay directions share: the blocking read takes one grain — `SESSION_POLL`, the cadence a shared lock is armed with elsewhere in the app — and the rest of the quantum is spent outside the lock, parked on the socket `read_wait` hands back. A writer then waits out a grain, not a wait.
    pub(crate) fn set_relay_quantum(&mut self, quantum: Duration) -> std::io::Result<()> {
        self.park = Some(quantum);
        self.set_read_quantum(quantum.min(crate::budgets::SESSION_POLL))
    }

    /// The socket to park on, when a socket read is the only thing that can move this lane: bytes the head walk took past the delimiter are the tunnel's own and come from the buffer, and a record whose plaintext the TLS layer still holds is one read away, not one wait.
    pub(crate) fn read_wait(&self) -> Option<(EdgeWait, Duration)> {
        let park = self
            .park
            .filter(|_| self.at >= self.carried.len() && self.tls.wants_read())?;
        Some((EdgeWait::Tcp(self.tls.get_ref().try_clone().ok()?), park))
    }
}

impl Write for Tls1 {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.tls.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.tls.flush()
    }
}

impl Read for Tls1 {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.at < self.carried.len() {
            return Ok(hand_back(&mut self.carried, &mut self.at, buf));
        }
        self.tls.read(buf)
    }
}

/// HTTP/3 CONNECT over one pooled QUIC connection (control stream, request stream, one HEADERS each way, DATA both ways — the pooling is what makes QUIC worth having); ending the lane is what hands the stream back to the pool, and a lane that never got built hands it back the same way.
pub(crate) type Quic = crate::quic::PooledStream;

pub(crate) struct H3 {
    /// The stream this lane rides, and the pool entry it owes back when the lane ends.
    quic: Quic,
    /// The request stream's frame window, sized to one header and nothing more: `head[..filled]` has arrived, `head[carried..filled]` is unparsed, and a payload the header names never lands here — the tunnel's goes to its caller's buffer, a capsule's to the capsule stream. Its capacity is the whole claim: a lane that stages a frame before reading it would need a wider window, and the bytes would be identical either way.
    head: Vec<u8>,
    filled: usize,
    carried: usize,
    /// Bytes of the DATA frame being delivered that the caller has not asked for yet: a frame spans reads from here, straight from the stream into each call's own buffer.
    body: usize,
    /// The block the last header named that the lane has not finished consuming, if any: `Keep` appends it to the capsule stream and `Drop` appends it where the stream can forget it whole. The count has to survive a quantum park — the header is already spent, so a walk that re-read it would put the next frame out of order.
    pending: Option<Pending>,
    /// The frame this lane writes, reused so a relay allocates nothing per frame.
    out: Vec<u8>,
    /// The IP packet under construction, reused so a datagram allocates nothing: an IP header, a UDP header and the payload, written once and handed to the frame. A packet per datagram took a buffer that grew three times on its way to the wire.
    packet: Vec<u8>,
    /// Capsule-stream bytes no whole DATAGRAM capsule has consumed yet: one capsule may span DATA frames, so frames accumulate only here. The answer's header block rides through it too, and it is cleared once the status is decoded.
    capsule_buf: Vec<u8>,
    /// The first byte of `capsule_buf` the reader has not consumed: readers advance this instead of draining, so a frame of many capsules moves the tail once rather than once per capsule.
    capsule_at: usize,
    /// Octets of the head DATAGRAM capsule already handed to a caller whose buffer was shorter than the datagram: the capsule stays staged until this reaches its length, so a short read costs the tail nothing.
    handed: usize,
    /// Payload octets still owed by a DATA frame that held exactly one DATAGRAM capsule: the capsule's bytes are read from the stream straight into the caller, so the frame is not first staged in `capsule_buf`.
    direct: usize,
    fin: bool,
    /// The peer sent its fin: nothing more will arrive on the request stream, so a reader that has the bytes it was given is at the end of the tunnel and a reader that has none is at the end of a stream that carried none.
    closed: bool,
    deadline: Instant,
    /// How long this lane waits for a CONNECT answer: a carrier's own open gets the head timeout, a disposable probe gets the budget its caller names.
    head_wait: Duration,
    /// Bounds one blocking `Read::read` the way the socket timeout bounds TCP carriers: set, it returns `WouldBlock` after the quantum so a one-lock relay can interleave.
    quantum: Option<Duration>,
    /// How long a leg that has handed its lock back may wait on this lane's datagram socket for the next one: the quantum a relay armed. `None` until one arms it, because a caller that reads this lane alone has no lock to release.
    park: Option<Duration>,
    /// Turns the lane has spent waiting for a datagram, so the trace says whether a slow open waited on the wire or on its own grain.
    turns: u32,
}

/// A frame block the lane is still consuming: `rest` bytes to go, landing at the capsule buffer's tail from `mark`, and `keep` telling the reader's own capsules from a frame the lane only has to get past. It exists because a header is spent the moment it is parsed — a park that forgot the count would re-read the header and take the next frame's bytes as this one's.
struct Pending {
    rest: usize,
    mark: usize,
    keep: bool,
}

impl H3 {
    pub(crate) fn set_read_quantum(&mut self, quantum: Duration) {
        self.quantum = Some(quantum);
    }

    /// The arm for a lane whose lock both relay directions share: the blocking read takes one grain — `SESSION_POLL`, the cadence a shared lock is armed with elsewhere in the app — and the rest of the quantum is spent outside the lock, parked on the lane's datagram socket. A poll takes no packet, so the packet that wakes the leg is still the lane's to read.
    pub(crate) fn set_relay_quantum(&mut self, quantum: Duration) {
        self.park = Some(quantum);
        self.set_read_quantum(quantum.min(crate::budgets::SESSION_POLL));
    }

    /// The socket to park on, when the wire is the only thing that can move this lane. Bytes already in the window are the state to refuse on: a header the window can hold is parsed by the read that has it, so a read that handed back `WouldBlock` with the window spent did so after looking at the stream — a frame body or a block still in flight is then waiting on a packet, and a blind sleep costs it the whole of `RELAY_IDLE`. The wait is cut to the connection's own next tick, because this lane's read is what services its loss timer and no other thread pumps it.
    pub(crate) fn read_wait(&self) -> Option<(EdgeWait, Duration)> {
        let park = self
            .park
            .filter(|_| self.carried >= self.filled && self.quic.sock.waits_here().is_some())?;
        let tick = self
            .with_conn_read(quiche::Connection::timeout)
            .flatten()
            .unwrap_or(park);
        Some((
            EdgeWait::Udp(std::sync::Arc::clone(&self.quic.sock)),
            park.min(tick),
        ))
    }

    pub(crate) fn open(dial: &FoxyDial, target: &str, quic: Quic) -> Result<Self, Failure> {
        Self::open_within(dial, target, quic, HEADER_TIMEOUT)
    }

    pub(crate) fn open_within(
        dial: &FoxyDial,
        target: &str,
        quic: Quic,
        head_wait: Duration,
    ) -> Result<Self, Failure> {
        let mut lane = Self {
            quic,
            head: vec![0u8; H3_PEEK],
            filled: 0,
            carried: 0,
            body: 0,
            pending: None,
            out: Vec::new(),
            packet: Vec::new(),
            capsule_buf: Vec::new(),
            capsule_at: 0,
            handed: 0,
            direct: 0,
            fin: false,
            closed: false,
            deadline: Instant::now(),
            head_wait,
            quantum: None,
            park: None,
            turns: 0,
        };
        let head = debug_on().then(Instant::now);
        let status = lane.request(target, &dial.pass.token);
        if let Some(at) = head {
            eprintln!(
                "foxy-debug: h3 stream {} head {}ms turns={} answered={}",
                lane.quic.id,
                at.elapsed().as_millis(),
                lane.turns,
                status.is_ok(),
            );
        }
        opened(status?)?;
        Ok(lane)
    }

    fn with_conn<T>(&mut self, body: impl FnOnce(&mut quiche::Connection) -> T) -> Option<T> {
        let mut guard = self.quic.conn.lock().ok()?;
        let out = body(&mut guard);
        crate::quic::flush_egress(&mut guard, &self.quic.sock);
        Some(out)
    }

    /// Whether the request stream has nothing left in it: the peer sent its fin and every byte it sent has been read. A fin alone says no more will arrive, so bytes already in the stream's own buffer are still the caller's.
    fn drained(&self) -> bool {
        if !self.closed {
            return false;
        }
        let id = self.quic.id;
        self.with_conn_read(|conn| conn.stream_finished(id))
            .unwrap_or(false)
    }

    /// The connection under its lock, read-only: a reader that asks what is left has nothing to send, and the egress sweep is a syscall the read did not ask for.
    fn with_conn_read<T>(&self, body: impl FnOnce(&quiche::Connection) -> T) -> Option<T> {
        let guard = self.quic.conn.lock().ok()?;
        Some(body(&guard))
    }

    /// The HTTP/3 opening a fresh connection carries exactly once: a complete SETTINGS plus QPACK encoder/decoder hellos, literal-only with no dynamic table; a truncated SETTINGS waits forever and a second control stream is a connection error, and nothing is ever finished.
    pub(crate) fn h3_opening() -> [(u64, Vec<u8>); 3] {
        let mut control = Vec::with_capacity(16);
        frames::quic_varint(&mut control, 0x00);
        let settings = [0x01u8, 0x00, 0x07, 0x00, 0x08, 0x00];
        frames::quic_varint(&mut control, 0x04);
        frames::quic_varint(&mut control, settings.len() as u64);
        control.extend_from_slice(&settings);
        let mut encoder = Vec::with_capacity(2);
        frames::quic_varint(&mut encoder, 0x02);
        let mut decoder = Vec::with_capacity(2);
        frames::quic_varint(&mut decoder, 0x03);
        [(CONTROL_STREAM, control), (6, encoder), (10, decoder)]
    }

    /// One UDP target as its own stream on a shared HTTP/3 connection: the extended CONNECT names `capsule-protocol: ?1` and datagrams ride DATAGRAM capsules — RFC 9298, the same capsule stream the HTTP/2 edge carries.
    pub(crate) fn open_udp(
        dial: &FoxyDial,
        target_host: &str,
        target_port: u16,
        quic: Quic,
    ) -> Result<Self, Failure> {
        let mut lane = Self {
            quic,
            head: vec![0u8; H3_PEEK],
            filled: 0,
            carried: 0,
            body: 0,
            pending: None,
            out: Vec::new(),
            packet: Vec::new(),
            capsule_buf: Vec::new(),
            capsule_at: 0,
            handed: 0,
            direct: 0,
            fin: false,
            closed: false,
            deadline: Instant::now(),
            head_wait: HEADER_TIMEOUT,
            quantum: None,
            park: None,
            turns: 0,
        };
        let status = lane.udp_request(dial, target_host, target_port)?;
        opened(status)?;
        Ok(lane)
    }

    /// One CONNECT-IP tunnel as its own stream on a shared HTTP/3 connection: the request names `connect-ip` and `capsule-protocol: ?1`, and the address request that follows opens a tunnel carrying every destination.
    pub(crate) fn open_ip(dial: &FoxyDial, quic: Quic) -> Result<Self, Failure> {
        let mut lane = Self {
            quic,
            head: vec![0u8; H3_PEEK],
            filled: 0,
            carried: 0,
            body: 0,
            pending: None,
            out: Vec::new(),
            packet: Vec::new(),
            capsule_buf: Vec::new(),
            capsule_at: 0,
            handed: 0,
            direct: 0,
            fin: false,
            closed: false,
            deadline: Instant::now(),
            head_wait: HEADER_TIMEOUT,
            quantum: None,
            park: None,
            turns: 0,
        };
        let edge = edge_authority(&dial.host, dial.port);
        let mut block = Vec::with_capacity(160 + dial.pass.token.len());
        connectip::connect_ip_qpack(&edge, "*", 0, &dial.pass.token, &mut block);
        let mut frame = Vec::with_capacity(16 + block.len());
        frames::quic_varint(&mut frame, frames::H3_HEADERS);
        frames::quic_varint(&mut frame, block.len() as u64);
        frame.extend_from_slice(&block);
        lane.send(lane.quic.id, &frame, false)?;
        let status = lane.read_head()?;
        opened(status)?;
        let mut request = Vec::new();
        connectip::address_request(1, 4, &[0, 0, 0, 0], &mut request);
        connectip::address_request(2, 6, &[0; 16], &mut request);
        // The request rides one DATA frame the way a packet does: capsules here are framed, and raw bytes would read as a frame header.
        let mut head = [0u8; 9];
        let hl = frames::h3_data_header(&mut head, request.len() as u64);
        lane.send_pair(lane.quic.id, &head[..hl], &request)?;
        Ok(lane)
    }

    fn udp_request(
        &mut self,
        dial: &FoxyDial,
        target_host: &str,
        target_port: u16,
    ) -> Result<u16, Failure> {
        let edge = edge_authority(&dial.host, dial.port);
        let mut block = Vec::with_capacity(160 + dial.pass.token.len() + target_host.len());
        masque::connect_udp_qpack(
            &edge,
            target_host,
            target_port,
            &dial.pass.token,
            &mut block,
        );
        let mut frame = Vec::with_capacity(16 + block.len());
        frames::quic_varint(&mut frame, frames::H3_HEADERS);
        frames::quic_varint(&mut frame, block.len() as u64);
        frame.extend_from_slice(&block);
        self.send(self.quic.id, &frame, false)?;
        self.read_head()
    }

    /// One turn of the request stream for the capsule reader: the header is peeked, a DATA frame's block lands at the capsule buffer's tail where the association reads its capsules, and a block this lane has no use for is consumed without being kept. Nothing of a frame's payload crosses the frame window, so a capsule byte reaches its reader through one lane buffer instead of a window and then a buffer.
    fn fill_capsules(&mut self) -> Result<(), Failure> {
        let started = Instant::now();
        self.deadline = started + HEADER_TIMEOUT;
        if self.pending.is_some() {
            // A block that arrived in pieces resumes its own count; the caller's split test sees it as soon as it is whole.
            return self.pending_block(started);
        }
        self.compact_capsules();
        self.walk_capsules(started)
    }

    /// Moves the capsules the reader has consumed off the front once per frame: a frame holding many capsules then moves its tail once, not once per capsule.
    fn compact_capsules(&mut self) {
        if self.capsule_at == 0 {
            return;
        }
        if self.capsule_at == self.capsule_buf.len() {
            self.capsule_buf.clear();
        } else {
            self.capsule_buf.drain(..self.capsule_at);
        }
        self.capsule_at = 0;
    }

    /// Releases the capsules the cursor has passed: a stream with nothing left is emptied, so the one-capsule datagram path still sees an empty buffer.
    fn release_capsules(&mut self) {
        if self.capsule_at == self.capsule_buf.len() {
            self.capsule_buf.clear();
            self.capsule_at = 0;
        }
    }

    /// Consumes one frame per turn: a header that is not whole yet leaves the caller to retry, because the capsules already in the buffer are what its reader is waiting for.
    fn walk_capsules(&mut self, started: Instant) -> Result<(), Failure> {
        let Some((frame, head)) = self.peek()? else {
            if self.closed {
                // The peer finished the stream: a capsule that never came is a capsule the peer never sent, and a reader that waits for it waits for the whole head timeout.
                return Err(Failure::Stream);
            }
            return Ok(());
        };
        let Some(body) = self.carried.checked_add(head) else {
            return Err(Failure::Frame);
        };
        let Ok(length) = usize::try_from(frame.length) else {
            return Err(Failure::Stream);
        };
        match frame.kind {
            frames::H3_DATA => {
                self.take_block(body, length, true, started)?;
                Ok(())
            }
            frames::H3_RESET | frames::H3_GOAWAY => {
                self.fin = true;
                self.carried = self.filled;
                Ok(())
            }
            _ => {
                if length > H3_SKIP {
                    return Err(Failure::Frame);
                }
                self.take_block(body, length, false, started)?;
                Ok(())
            }
        }
    }

    /// Sends the address request and reads the assignment: without one the lane has no source address to write into a packet, and a proxy that refuses is refused rather than guessed at.
    pub(crate) fn address_assign(
        &mut self,
    ) -> Result<Option<ferrox_core::foxy::connectip::Assigned>, Failure> {
        let deadline = Instant::now() + HEADER_TIMEOUT;
        let mut assigned = None;
        while Instant::now() < deadline {
            if let Some((used, capsule)) =
                connectip::capsule_split(&self.capsule_buf[self.capsule_at..])
            {
                let (granted, quit) = match capsule {
                    connectip::Capsule::AddressAssign(body) => {
                        let mut into = Vec::new();
                        if connectip::address_assign(body, &mut into).is_none() {
                            (None, true)
                        } else {
                            (into.into_iter().find(|grant| !grant.refused()), false)
                        }
                    }
                    connectip::Capsule::RouteAdvert(body) => {
                        let mut routes = Vec::new();
                        let _ = connectip::route_advert(body, &mut routes);
                        (None, false)
                    }
                    _ => (None, false),
                };
                self.capsule_at += used;
                self.release_capsules();
                if let Some(granted) = granted {
                    assigned = Some(granted);
                }
                if quit {
                    return Err(Failure::Frame);
                }
                if assigned.is_some() {
                    return Ok(assigned);
                }
                continue;
            }
            if self.fin {
                return Err(Failure::Stream);
            }
            self.fill_capsules().map_err(io)?;
        }
        Ok(assigned)
    }

    /// One IP packet, as a frame's payload the caller takes whole: a frame that is exactly one DATAGRAM capsule whose packet is already queued is read straight into the caller's buffer, so the packet crosses userspace once; a capsule that spanned frames is staged and then copied, as before.
    pub(crate) fn read_ip(&mut self, into: &mut Vec<u8>) -> std::io::Result<bool> {
        let started = Instant::now();
        // One wait per call, armed from its start: the peek below may pull before the first walk arms it.
        self.deadline = started + HEADER_TIMEOUT;
        loop {
            // A DATA frame that is exactly one DATAGRAM capsule is handed straight to the caller once its packet is queued: the capsule header is spent in the peek window, the packet lands in the caller's own buffer, and the frame never enters `capsule_buf`.
            if self.capsule_buf.len() == self.capsule_at && self.pending.is_none() {
                if let Some((frame, head)) = self.peek().map_err(io)? {
                    let body = self
                        .carried
                        .checked_add(head)
                        .ok_or_else(|| io(Failure::Frame))?;
                    if frame.kind == frames::H3_DATA && body < self.filled {
                        let length =
                            usize::try_from(frame.length).map_err(|_| io(Failure::Stream))?;
                        if let Some((capsule_head, payload)) =
                            connectip::packet_header(&self.head[body..self.filled])
                        {
                            let here = self.filled - (body + capsule_head);
                            let id = self.quic.id;
                            let queued = self
                                .with_conn_read(|conn| conn.stream_readable_len(id, payload))
                                .unwrap_or(0);
                            if length == capsule_head + payload
                                && payload > 0
                                && payload <= DATAGRAM_BUF_MAX
                                && here + queued >= payload
                            {
                                self.carried = body + capsule_head;
                                return self.direct_packet(into, payload);
                            }
                        }
                    }
                }
            }
            if let Some((used, capsule)) =
                connectip::capsule_split(&self.capsule_buf[self.capsule_at..])
            {
                let connectip::Capsule::Datagram(packet) = capsule else {
                    self.capsule_at += used;
                    self.release_capsules();
                    continue;
                };
                into.clear();
                into.extend_from_slice(packet);
                self.capsule_at += used;
                self.release_capsules();
                if !into.is_empty() {
                    return Ok(true);
                }
                continue;
            }
            if self.fin {
                return Ok(false);
            }
            if self.closed {
                // The peer finished the stream: the packet that never came is a packet the peer never sent.
                return Ok(false);
            }
            if self
                .quantum
                .is_some_and(|quantum| started.elapsed() >= quantum)
            {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            self.fill_capsules().map_err(io)?;
        }
    }

    /// One DATAGRAM capsule's packet read from the stream into the caller's buffer: the capsule header is spent in the window and the packet never enters `capsule_buf`. The caller is only taken here once every byte is queued, so a short read is a stream that ended early rather than a wait.
    fn direct_packet(&mut self, into: &mut Vec<u8>, payload: usize) -> std::io::Result<bool> {
        into.clear();
        crate::proxy::grow_scratch(into, payload);
        let mut filled = 0usize;
        while filled < payload {
            if self.carried < self.filled {
                let n = (self.filled - self.carried).min(payload - filled);
                into[filled..filled + n]
                    .copy_from_slice(&self.head[self.carried..self.carried + n]);
                self.carried += n;
                filled += n;
                continue;
            }
            let id = self.quic.id;
            let read = self.with_conn(|conn| conn.stream_recv(id, &mut into[filled..]));
            match read {
                Some(Ok((read, fin))) if read > 0 => {
                    filled += read;
                    if fin && filled < payload {
                        into.truncate(filled);
                        self.closed = true;
                        return Err(io(Failure::Stream));
                    }
                }
                Some(Ok((_, true)) | Err(quiche::Error::Done)) => {
                    into.truncate(filled);
                    self.closed = true;
                    return Err(io(Failure::Stream));
                }
                _ => {
                    into.truncate(filled);
                    return Err(io(Failure::Io));
                }
            }
        }
        Ok(true)
    }

    /// One UDP payload as one DATAGRAM capsule inside one DATA frame. The two headers ride the lane's own scratch and the payload keeps the caller's buffer: quiche copies every slice it is handed, so joining the datagram ahead of that copy crossed each of its bytes in userspace twice.
    pub(crate) fn write_datagram(&mut self, payload: &[u8]) -> std::io::Result<()> {
        if self.fin {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        let mut prefix = [0u8; 10];
        let plen = masque::datagram_prefix_into(&mut prefix, payload.len());
        let mut head = [0u8; 9];
        let hl = frames::h3_data_header(&mut head, (plen + payload.len()) as u64);
        let mut out = std::mem::take(&mut self.out);
        out.clear();
        out.extend_from_slice(&head[..hl]);
        out.extend_from_slice(&prefix[..plen]);
        let sent = self.send_pair(self.quic.id, &out, payload);
        self.out = out;
        sent.map_err(io)?;
        Ok(())
    }

    /// One UDP payload out of the capsule stream: DATA frames are consumed into the capsule stream until a whole DATAGRAM capsule appears, capsules that span frames accumulate, a payload wider than the caller's buffer arrives over several reads, and empty datagrams are skipped so `Ok(0)` stays the end of stream.
    pub(crate) fn read_datagram(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let started = Instant::now();
        // One wait per call, armed from its start: re-armed inside the loop the check below could never see an expiry, so a peer that stopped answering cost this lane nothing but its own parking.
        self.deadline = started + HEADER_TIMEOUT;
        if self.direct > 0 {
            return self.direct_into(buf, started);
        }
        loop {
            // A DATA frame that is exactly one DATAGRAM capsule is handed straight to the caller: the capsule header is spent in the peek window, the payload lands in the caller's own buffer, and the frame never enters `capsule_buf`.
            if self.capsule_buf.len() == self.capsule_at && self.pending.is_none() {
                if let Some((frame, head)) = self.peek().map_err(io)? {
                    let body = self
                        .carried
                        .checked_add(head)
                        .ok_or_else(|| io(Failure::Frame))?;
                    if frame.kind == frames::H3_DATA && body < self.filled {
                        let length =
                            usize::try_from(frame.length).map_err(|_| io(Failure::Stream))?;
                        if let Some((capsule_head, payload)) =
                            masque::datagram_header(&self.head[body..self.filled])
                        {
                            if length == capsule_head + payload
                                && payload > 0
                                && payload <= DATAGRAM_BUF_MAX
                            {
                                self.carried = body + capsule_head;
                                self.direct = payload;
                                return self.direct_into(buf, started);
                            }
                        }
                    }
                }
            }
            if let Some((used, payload)) =
                masque::datagram_split(&self.capsule_buf[self.capsule_at..])
            {
                let len = payload.len();
                let at = self.handed;
                let take = buf.len().min(len - at);
                buf[..take].copy_from_slice(&payload[at..at + take]);
                // A capsule is released only when its last octet has been copied, and the count is what the caller got rather than what the capsule holds.
                if at + take == len {
                    self.capsule_at += used;
                    self.release_capsules();
                    self.handed = 0;
                } else {
                    self.handed = at + take;
                }
                if len == 0 {
                    continue;
                }
                return Ok(take);
            }
            if self.fin {
                return Ok(0);
            }
            if self.closed {
                // The peer finished the stream: the datagram that never came is a datagram the peer never sent, and `Ok(0)` is the end of the stream.
                return Ok(0);
            }
            if self
                .quantum
                .is_some_and(|quantum| started.elapsed() >= quantum)
            {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            if self.capsule_buf.len() - self.capsule_at > DATAGRAM_BUF_MAX {
                self.capsule_buf.clear();
                self.capsule_at = 0;
                self.handed = 0;
                return Err(std::io::Error::other(
                    "foxy: a capsule stream that never parses",
                ));
            }
            self.fill_capsules().map_err(io)?;
        }
    }

    /// The payload of a DATA frame that held exactly one DATAGRAM capsule, read from the stream into the caller's own buffer: the capsule's header is spent in the window and its payload never enters `capsule_buf`. A caller whose buffer is shorter keeps the rest on the lane, and the next read resumes at the cursor.
    fn direct_into(&mut self, buf: &mut [u8], started: Instant) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut left = self.direct;
        let mut delivered = 0usize;
        while left > 0 && delivered < buf.len() {
            if self.carried < self.filled {
                let n = (self.filled - self.carried)
                    .min(left)
                    .min(buf.len() - delivered);
                buf[delivered..delivered + n]
                    .copy_from_slice(&self.head[self.carried..self.carried + n]);
                self.carried += n;
                left -= n;
                delivered += n;
                continue;
            }
            if self
                .quantum
                .is_some_and(|quantum| started.elapsed() >= quantum)
            {
                break;
            }
            if self.closed {
                self.direct = left;
                if delivered > 0 {
                    return Ok(delivered);
                }
                return Err(io(Failure::Stream));
            }
            let want = left.min(buf.len() - delivered);
            let id = self.quic.id;
            match self.with_conn(|conn| conn.stream_recv(id, &mut buf[delivered..delivered + want]))
            {
                Some(Ok((0, true))) => {
                    self.direct = left;
                    self.closed = true;
                    if delivered > 0 {
                        return Ok(delivered);
                    }
                    return Err(io(Failure::Stream));
                }
                Some(Ok((read, fin))) => {
                    delivered += read;
                    left -= read;
                    if fin {
                        self.closed = true;
                        if left > 0 {
                            self.direct = left;
                            if delivered > 0 {
                                return Ok(delivered);
                            }
                            return Err(io(Failure::Stream));
                        }
                    }
                }
                Some(Err(quiche::Error::Done)) => {
                    if Instant::now() >= self.deadline {
                        self.direct = left;
                        if delivered > 0 {
                            return Ok(delivered);
                        }
                        return Err(io(Failure::Stream));
                    }
                    self.pump(self.pump_wait());
                }
                _ => {
                    self.direct = left;
                    if delivered > 0 {
                        return Ok(delivered);
                    }
                    return Err(io(Failure::Io));
                }
            }
        }
        self.direct = left;
        if delivered == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        }
        Ok(delivered)
    }

    fn request(&mut self, target: &str, bearer: &str) -> Result<u16, Failure> {
        let mut block = Vec::with_capacity(96 + bearer.len());
        hpack::qpack_connect(target, bearer, &mut block);
        let mut frame = Vec::with_capacity(16 + block.len());
        frames::quic_varint(&mut frame, frames::H3_HEADERS);
        frames::quic_varint(&mut frame, block.len() as u64);
        frame.extend_from_slice(&block);
        self.send(self.quic.id, &frame, false)?;
        self.read_head()
    }

    fn send(&mut self, stream: u64, buf: &[u8], fin: bool) -> Result<(), Failure> {
        let deadline = Instant::now() + SEND_WAIT;
        let mut rest = buf;
        while !rest.is_empty() {
            let written = self
                .with_conn(|conn| conn.stream_send(stream, rest, false))
                .ok_or(Failure::Io)?
                .map_err(|_| Failure::Io)?;
            rest = &rest[written..];
            if written == 0 {
                if Instant::now() >= deadline {
                    return Err(Failure::Io);
                }
                self.pump(self.pump_wait());
            }
        }
        if fin {
            self.fin(stream)?;
        }
        Ok(())
    }

    /// The frame's header and its payload accepted under one lock and flushed once: two `send` calls pay the connection mutex twice, and the egress sweep after the header alone puts those nine bytes in a datagram of their own.
    fn send_pair(&mut self, stream: u64, head: &[u8], payload: &[u8]) -> Result<(), Failure> {
        let deadline = Instant::now() + SEND_WAIT;
        let (mut head, mut payload) = (head, payload);
        loop {
            let (took_head, took_body) = self
                .with_conn(|conn| {
                    let n = conn.stream_send(stream, head, false).ok()?;
                    if n < head.len() || payload.is_empty() {
                        return Some((n, 0));
                    }
                    let m = conn.stream_send(stream, payload, false).ok()?;
                    Some((n, m))
                })
                .ok_or(Failure::Io)?
                .ok_or(Failure::Io)?;
            head = &head[took_head..];
            payload = &payload[took_body..];
            if head.is_empty() && payload.is_empty() {
                return Ok(());
            }
            if took_head + took_body == 0 {
                if Instant::now() >= deadline {
                    return Err(Failure::Io);
                }
                self.pump(self.pump_wait());
            }
        }
    }

    fn fin(&mut self, stream: u64) -> Result<(), Failure> {
        let sent = self
            .with_conn(|conn| conn.stream_send(stream, &[], true))
            .ok_or(Failure::Io)?;
        sent.map(|_| ()).map_err(|_| Failure::Io)
    }

    /// How long one empty turn waits for a datagram: the read's own grain where a relay armed one, because the lane's lock is what the other direction of the flow is standing behind, and the idle tick everywhere else.
    fn pump_wait(&self) -> Duration {
        self.quantum
            .map_or(PUMP_WAIT, |quantum| quantum.min(PUMP_WAIT))
    }

    fn pump(&mut self, wait: Duration) {
        self.turns += 1;
        let local = self.quic.local;
        if let Ok(mut guard) = self.quic.conn.lock() {
            crate::quic::pump_once(&mut guard, &self.quic.sock, local, wait);
        }
    }

    /// Pulls the request stream until the answer's HEADERS frame is whole and reads the status out of it: a header is peeked, the block it names lands in the buffer the lane keeps arrived bytes in, and any frame ahead of the answer is consumed rather than waited on. Nothing past the answer's own header is read here, so the tunnel's first DATA frame is still on the stream when this returns.
    fn read_head(&mut self) -> Result<u16, Failure> {
        let started = Instant::now();
        self.deadline = started + self.head_wait;
        loop {
            if self.pending.is_some() {
                self.pending_block(started)?;
                continue;
            }
            let Some((frame, head)) = self.peek()? else {
                if self.closed {
                    // The peer finished the stream without an answer: the head wait would otherwise spin until its deadline for bytes that will not come.
                    return Err(Failure::Stream);
                }
                continue;
            };
            let Some(body) = self.carried.checked_add(head) else {
                return Err(Failure::Frame);
            };
            let Ok(length) = usize::try_from(frame.length) else {
                return Err(Failure::Stream);
            };
            if length > H3_SKIP {
                // A block bigger than a head is not an answer, a trailer or an application error; it is a peer that does not want this lane to reach its next frame.
                return Err(Failure::Frame);
            }
            match frame.kind {
                frames::H3_HEADERS => {
                    let mark = self.take_block(body, length, true, started)?;
                    if self.pending.is_some() {
                        continue;
                    }
                    let block = &self.capsule_buf[mark..];
                    let status = hpack::qpack_status(block).ok_or_else(|| {
                        debug_block(block);
                        Failure::Frame
                    })?;
                    self.capsule_buf.truncate(mark);
                    return Ok(status);
                }
                frames::H3_RESET | frames::H3_GOAWAY => return Err(Failure::Stream),
                _ => {
                    self.take_block(body, length, false, started)?;
                }
            }
        }
    }

    /// The frame header at the cursor, if a whole one is there: a window that is full of bytes and still does not parse is not a header — the ceiling is the largest header a QUIC varint pair can be, so the lane ends there instead of growing a window to find out.
    fn peek(&mut self) -> Result<Option<(frames::H3Frame, usize)>, Failure> {
        if let Some(frame) = self.parse_head() {
            return Ok(Some(frame));
        }
        if self.filled - self.carried >= self.head.len() {
            return Err(Failure::Frame);
        }
        self.fill_peek()?;
        if let Some(frame) = self.parse_head() {
            return Ok(Some(frame));
        }
        if self.closed && self.filled > self.carried {
            // The peer finished the stream with a frame header half in the window: a truncated frame, and the lane ends there rather than waiting for bytes that will not come.
            return Err(Failure::Stream);
        }
        Ok(None)
    }

    /// The frame header the window holds, if it is a whole one: the kind and the length, and how many bytes the header itself took.
    fn parse_head(&self) -> Option<(frames::H3Frame, usize)> {
        let mut head = 0usize;
        frames::h3_frame(&self.head[self.carried..self.filled], &mut head)
            .map(|frame| (frame, head))
    }

    /// What one frame's header says the reader should do: a DATA frame's body becomes the caller's to read, a frame the tunnel does not read is consumed, and a reset or a goaway ends the tunnel without a block of its own.
    fn dispatch(
        &mut self,
        frame: frames::H3Frame,
        head: usize,
        started: Instant,
    ) -> Result<Dispatch, Failure> {
        let Some(body_at) = self.carried.checked_add(head) else {
            return Err(Failure::Frame);
        };
        let Ok(length) = usize::try_from(frame.length) else {
            return Err(Failure::Stream);
        };
        if frame.kind == frames::H3_DATA {
            self.carried = body_at;
            // An empty DATA frame carries no bytes and is not the end of the stream: only a finished stream or a reset ends the tunnel, and handing back zero here is what a caller reads as EOF.
            if length == 0 {
                return Ok(Dispatch::Again);
            }
            self.body = length;
            return Ok(Dispatch::Again);
        }
        if frame.kind == frames::H3_RESET || frame.kind == frames::H3_GOAWAY {
            // The kind is in the header, so an ending needs no block of its own: the frame that follows it is never read.
            self.fin = true;
            self.carried = self.filled;
            return Ok(Dispatch::Ended);
        }
        if length > H3_SKIP {
            return Err(Failure::Frame);
        }
        self.take_block(body_at, length, false, started)?;
        Ok(Dispatch::Again)
    }

    /// The block a header names, consumed into the capsule buffer's tail: the bytes the peek already pulled arrive first, `keep` says whether the rest is the stream's own or a frame this lane has no use for, and the lane's cursor moves past what the window held either way. Returns where the block began, which is what its reader cuts back to.
    fn take_block(
        &mut self,
        body: usize,
        length: usize,
        keep: bool,
        started: Instant,
    ) -> Result<usize, Failure> {
        let held = (self.filled - body).min(length);
        let mark = self.capsule_buf.len();
        if keep {
            self.capsule_buf
                .extend_from_slice(&self.head[body..body + held]);
        }
        self.carried = body + held;
        self.pending = Some(Pending {
            rest: length - held,
            mark,
            keep,
        });
        self.pending_block(started)?;
        Ok(mark)
    }

    /// Finishes the block the last header named: its bytes arrive at the capsule buffer's tail, and one nobody reads is cut back out when it is whole. The tail the block needs is asked for once, because a poll that re-grew it per arrival zeroed every byte the peer had not sent yet — once per datagram, for a block it would fill in the end anyway. Every exit hands back only what quiche actually wrote. A quantum that expires mid-block leaves the count on the lane, so the next turn resumes at the tail — the header is already spent, and a walk that read it again would put every frame after it out of order.
    fn pending_block(&mut self, started: Instant) -> Result<(), Failure> {
        let Some(mut block) = self.pending.take() else {
            return Ok(());
        };
        let id = self.quic.id;
        let mut buf = std::mem::take(&mut self.capsule_buf);
        let base = buf.len();
        if block.rest > 0 {
            let room = DATAGRAM_BUF_MAX.saturating_sub(base).min(block.rest);
            if room == 0 {
                self.capsule_buf = buf;
                return Err(Failure::Frame);
            }
            // The room is claimed without a zero pass: the block's bytes are what the peer sends into it, and the zeroing was a memset of a region the walk was about to overwrite — once per datagram, for a block it fills in the end anyway. The length is set past the written bytes and rolled back on every path that leaves it short.
            crate::proxy::grow_scratch(&mut buf, base + room);
            let mut used = base;
            loop {
                if Instant::now() >= self.deadline {
                    buf.truncate(used);
                    self.capsule_buf = buf;
                    return Err(Failure::Stream);
                }
                let read = match self.with_conn(|conn| conn.stream_recv(id, &mut buf[used..])) {
                    Some(Ok((0, true))) => {
                        // The stream ended with the block still short: a truncated frame, which is where the walk stops rather than waiting for bytes that will not come.
                        buf.truncate(used);
                        self.capsule_buf = buf;
                        return Err(Failure::Stream);
                    }
                    Some(Ok((read, fin))) => {
                        if fin {
                            // The fin came with these bytes: the block is whole or the peer never finished it.
                            if block.rest > read {
                                buf.truncate(used + read);
                                self.capsule_buf = buf;
                                return Err(Failure::Stream);
                            }
                            self.closed = true;
                        }
                        read
                    }
                    Some(Err(quiche::Error::Done)) => 0,
                    _ => {
                        buf.truncate(used);
                        self.capsule_buf = buf;
                        return Err(Failure::Io);
                    }
                };
                used += read;
                block.rest -= read;
                if block.rest == 0 {
                    if !block.keep {
                        buf.truncate(block.mark);
                    }
                    self.capsule_buf = buf;
                    return Ok(());
                }
                if used == buf.len() {
                    // The room a capsule stream may hold ran out with the block still owed: a stream that never parses.
                    self.capsule_buf = buf;
                    return Err(Failure::Frame);
                }
                if self.closed {
                    // The peer finished the stream with the block still owed: a frame the peer never finished, and a walk that waits for the rest of it waits for the whole head timeout.
                    buf.truncate(used);
                    self.capsule_buf = buf;
                    return Err(Failure::Stream);
                }
                if self
                    .quantum
                    .is_some_and(|quantum| started.elapsed() >= quantum)
                {
                    buf.truncate(used);
                    self.capsule_buf = buf;
                    self.pending = Some(block);
                    return Ok(());
                }
                if read == 0 {
                    // Nothing had arrived: the socket is what turns a dropped datagram into a retransmission, so a walk that only asks the stream never reads the packet that answers it.
                    self.pump(self.pump_wait());
                }
            }
        }
        if !block.keep {
            buf.truncate(block.mark);
        }
        self.capsule_buf = buf;
        Ok(())
    }

    /// The window's spare room from the stream, with whatever is still unparsed moved to its front first: the window is a header wide and never larger, so a full one is a boundary rather than a reason to allocate.
    fn fill_peek(&mut self) -> Result<(), Failure> {
        if self.carried == self.filled {
            self.filled = 0;
            self.carried = 0;
        } else if self.carried > 0 {
            self.head.copy_within(self.carried..self.filled, 0);
            self.filled -= self.carried;
            self.carried = 0;
        }
        let at = self.filled;
        let read = self.pull(at, self.head.len() - at)?;
        self.filled += read;
        Ok(())
    }

    /// Up to `want` bytes of the request stream into the window at `at`, or a pump when nothing has arrived — the same two answers a QUIC stream gives, minus the second copy.
    fn pull(&mut self, at: usize, want: usize) -> Result<usize, Failure> {
        let id = self.quic.id;
        let mut window = std::mem::take(&mut self.head);
        let mut read = self.with_conn(|conn| conn.stream_recv(id, &mut window[at..at + want]));
        // The pump is what puts a datagram's bytes into the stream, so the read that ran one looks at the stream again: a hand-back that skips that look leaves the byte inside the connection until the caller comes round, which costs a quantum for one octet.
        if matches!(read, Some(Err(quiche::Error::Done))) && Instant::now() < self.deadline {
            self.pump(self.pump_wait());
            read = self.with_conn(|conn| conn.stream_recv(id, &mut window[at..at + want]));
        }
        self.head = window;
        match read {
            Some(Ok((0, true))) => {
                // The stream ended with nothing in it: a reader that has bytes is at the end of the tunnel.
                self.closed = true;
                Ok(0)
            }
            Some(Ok((read, fin))) => {
                if fin {
                    self.closed = true;
                }
                Ok(read)
            }
            Some(Err(quiche::Error::Done)) => {
                if Instant::now() >= self.deadline {
                    return Err(Failure::Stream);
                }
                Ok(0)
            }
            _ => Err(Failure::Io),
        }
    }

    /// Delivers the frame in flight: what already sits in the window moves first — those bytes crossed once before this lane knew their length — and the rest arrives from the stream straight into the caller's buffer. A quantum that expires mid-frame hands back what was delivered; the next read resumes at the cursor.
    fn body_into(&mut self, buf: &mut [u8], started: Instant) -> std::io::Result<usize> {
        let mut delivered = 0usize;
        while self.body > 0 && delivered < buf.len() {
            if self.carried < self.filled {
                let n = (self.filled - self.carried)
                    .min(self.body)
                    .min(buf.len() - delivered);
                buf[delivered..delivered + n]
                    .copy_from_slice(&self.head[self.carried..self.carried + n]);
                self.carried += n;
                self.body -= n;
                delivered += n;
                continue;
            }
            if self
                .quantum
                .is_some_and(|quantum| started.elapsed() >= quantum)
            {
                break;
            }
            if self.closed {
                // The peer finished the stream with the body still owed: a frame the peer never finished, and a lane that waits for the rest of it waits for the whole head timeout.
                return Err(io(Failure::Stream));
            }
            let want = self.body.min(buf.len() - delivered);
            let id = self.quic.id;
            let read =
                self.with_conn(|conn| conn.stream_recv(id, &mut buf[delivered..delivered + want]));
            match read {
                Some(Ok((0, true))) => return Err(io(Failure::Stream)),
                Some(Ok((read, fin))) => {
                    delivered += read;
                    self.body -= read;
                    if fin {
                        // The fin came with these bytes, so the stream is over: a body still owed is a frame the peer never finished.
                        if self.body > 0 {
                            return Err(io(Failure::Stream));
                        }
                        self.closed = true;
                    }
                }
                Some(Err(quiche::Error::Done)) => {
                    if Instant::now() >= self.deadline {
                        return Err(io(Failure::Stream));
                    }
                    self.pump(self.pump_wait());
                }
                _ => return Err(io(Failure::Io)),
            }
        }
        Ok(delivered)
    }
}

impl Write for H3 {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.fin {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        let frame = foxy::flow::frame_size(buf.len(), H3_FRAME);
        if frame == 0 {
            return Ok(0);
        }
        // The frame's varints are their own send and the payload keeps the caller's buffer: quiche copies every slice it is handed, so staging the two together would be a second copy of every byte.
        let mut head = [0u8; 9];
        let hl = frames::h3_data_header(&mut head, u64::from(frame));
        self.send_pair(self.quic.id, &head[..hl], &buf[..frame as usize])
            .map_err(io)?;
        Ok(frame as usize)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.with_conn(|_| ()).ok_or_else(|| io(Failure::Io))
    }
}

impl Read for H3 {
    /// The tunnel, not the stream: the caller gets the payload of DATA frames, because a frame header read as payload carries the tunnel's own framing into every byte after it. The caller's buffer is filled across frames: a lane that hands back one frame per read makes the caller's read syscall per frame, and the acknowledgement quiche sends when the app drains the stream is what the edge's congestion window grows on.
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let started = Instant::now();
        // One wait per read call, armed from its own start: re-arming inside the loop would let a peer that answers nothing park this lane forever, where the socket carriers' read timeout costs the caller `head_wait` and returns.
        self.deadline = started + self.head_wait;
        let mut delivered = 0usize;
        loop {
            if self.body > 0 {
                // The frame in flight: its body goes into the caller's buffer, and a body the caller's buffer cannot hold all of is finished by the next call.
                let took = self.body_into(&mut buf[delivered..], started)?;
                delivered += took;
                if self.body > 0 {
                    // The quantum ended the body short: what arrived is the caller's, and the rest waits for the next call. Handing back nothing here would read as the end of the stream.
                    return if delivered > 0 {
                        Ok(delivered)
                    } else {
                        Err(blocked())
                    };
                }
                continue;
            }
            if self.fin {
                // The tunnel is over: the bytes already delivered are the caller's, and the next read is the end of the stream.
                return Ok(delivered);
            }
            if self.closed {
                // The peer finished the stream. The bytes it sent are in the caller's hands, and what the stream still holds behind them is the caller's too: a fin says no more will arrive, not that none arrived.
                if self.body > 0 {
                    // A frame the peer never finished: a tunnel that ends mid-frame is a broken tunnel, not a short one.
                    return Err(io(Failure::Stream));
                }
                if self.carried < self.filled {
                    // The window holds bytes the peer sent: they are the last of the tunnel, and a frame header among them is read before the tunnel ends.
                    let Some((frame, head)) = self.parse_head() else {
                        // A remainder that is not a frame header: the peer sent bytes no frame names, and a tunnel that ends on them is a broken tunnel.
                        return Err(io(Failure::Stream));
                    };
                    match self.dispatch(frame, head, started).map_err(io)? {
                        Dispatch::Again => continue,
                        Dispatch::Ended => return Ok(delivered),
                    }
                }
                if self.drained() {
                    return Ok(delivered);
                }
                return Err(io(Failure::Stream));
            }
            if delivered == buf.len() {
                return Ok(delivered);
            }
            if self
                .quantum
                .is_some_and(|quantum| started.elapsed() >= quantum)
            {
                return if delivered > 0 {
                    Ok(delivered)
                } else {
                    Err(blocked())
                };
            }
            if self.pending.is_some() {
                // The block of a frame the tunnel does not read: consumed here so the next header is the next frame's, and a quantum that expired inside it is resumed, not re-parsed.
                self.pending_block(started).map_err(io)?;
                continue;
            }
            let Some((frame, head)) = self.peek().map_err(io)? else {
                // No whole frame yet: a header the peer has not finished sending, or a stream that owes nothing right now. What already arrived is the caller's.
                if delivered > 0 {
                    return Ok(delivered);
                }
                continue;
            };
            match self.dispatch(frame, head, started).map_err(io)? {
                Dispatch::Again => {}
                Dispatch::Ended => return Ok(delivered),
            }
        }
    }
}

/// What one frame's header says the reader should do next: the frame is a payload to deliver, or the tunnel is over.
enum Dispatch {
    /// The frame was taken in: a DATA frame's body is now the caller's to read, and a frame the tunnel does not read has been consumed.
    Again,
    /// The frame was a reset or a goaway: the tunnel is over and the frame that follows it is never read.
    Ended,
}

/// Reads the two-letter country out of whatever the probe answered: a `loc=XX` line, a `"countryCode":"XX"` field, or nothing — a probe that cannot be read is not evidence.
#[must_use]
pub(crate) fn exit_country(head: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(head);
    if let Some(after) = text.split_once("loc=") {
        let code: String = after
            .1
            .chars()
            .take_while(char::is_ascii_alphanumeric)
            .collect();
        if code.len() == 2 && code.chars().all(|c| c.is_ascii_uppercase()) {
            return Some(code);
        }
    }
    let key = "\"countryCode\":\"";
    let at = text.find(key)? + key.len();
    text.get(at..at + 2)
        .filter(|code| code.chars().all(|c| c.is_ascii_uppercase()))
        .map(str::to_owned)
}

fn io(failure: Failure) -> std::io::Error {
    std::io::Error::other(failure.to_string())
}

/// The answer a lane gives when its quantum ran out with nothing to show: not the end of the stream, which is zero bytes and no error, but a turn handed back so the caller may come again.
fn blocked() -> std::io::Error {
    std::io::Error::from(std::io::ErrorKind::WouldBlock)
}

/// One IP packet built into the lane's own scratch: the codec's build, into a buffer that already holds the room. The scratch is cleared rather than dropped, so the datagram after this one writes over the last one's bytes and takes no allocation of its own.
fn build_packet(
    into: &mut Vec<u8>,
    source: &[u8],
    destination: &[u8],
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> bool {
    into.clear();
    // The room is claimed before the build, so the appends below never reallocate: the packet is the header and the payload, and the payload's size is known before the first byte is written. The delta is against the length, not the capacity, because a reservation is measured from the length — a delta against the capacity would leave the room short and the first append would grow the buffer anyway.
    let header = if source.len() == 4 {
        ferrox_core::foxy::connectip::IPV4_HEADER
    } else {
        ferrox_core::foxy::connectip::IPV6_HEADER
    };
    let want = header + ferrox_core::foxy::connectip::UDP_HEADER + payload.len();
    if into.capacity() < want {
        into.reserve_exact(want - into.len());
    }
    ferrox_core::foxy::connectip::udp_datagram(
        &ferrox_core::foxy::connectip::UdpDatagram {
            source,
            destination,
            source_port,
            destination_port,
            payload,
        },
        into,
    )
}

/// One CONNECT-UDP lane over an HTTP/1.1 upgrade: the byte stream after `101` is the capsule stream, so the lane frames each datagram where the other carriers' frame does.
pub(crate) struct H1Datagram {
    tls: Tls1,
    /// Capsule-stream bytes no whole DATAGRAM capsule has consumed yet: one capsule may span TLS records, so records accumulate only here.
    capsule_buf: Vec<u8>,
    /// Octets of the head DATAGRAM capsule already handed to a caller whose buffer was shorter than the datagram: the capsule stays staged until this reaches its length.
    handed: usize,
}

impl H1Datagram {
    pub(crate) fn set_read_quantum(&self, quantum: Duration) -> std::io::Result<()> {
        self.tls.set_read_quantum(quantum)
    }

    pub(crate) fn write_datagram(&mut self, payload: &[u8]) -> std::io::Result<()> {
        let mut prefix = [0u8; 10];
        let plen = masque::datagram_prefix_into(&mut prefix, payload.len());
        self.tls.tls.write_all_slices(&[&prefix[..plen], payload])
    }

    pub(crate) fn read_datagram(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let capsule = match masque::datagram_split(&self.capsule_buf) {
                Some((used, payload)) => {
                    let len = payload.len();
                    let at = self.handed;
                    let take = buf.len().min(len - at);
                    buf[..take].copy_from_slice(&payload[at..at + take]);
                    if at + take == len {
                        self.capsule_buf.drain(..used);
                        self.handed = 0;
                    } else {
                        self.handed = at + take;
                    }
                    Some((len, take))
                }
                None => None,
            };
            if let Some((len, take)) = capsule {
                if len == 0 {
                    continue;
                }
                return Ok(take);
            }
            if self.capsule_buf.len() > DATAGRAM_BUF_MAX {
                self.capsule_buf.clear();
                self.handed = 0;
                return Err(std::io::Error::other(
                    "foxy: a capsule stream that never parses",
                ));
            }
            let mut window = [0u8; 8192];
            let read = self.tls.read(&mut window)?;
            if read == 0 {
                return Ok(0);
            }
            self.capsule_buf.extend_from_slice(&window[..read]);
        }
    }
}

/// One CONNECT-UDP lane on whichever carrier the edge answers: a UDP flow is a capsule stream either way, and which carrier carries it is the dial's question.
pub(crate) enum Datagram {
    H1(Box<H1Datagram>),
    H2(Box<Tls2>),
    H3(Box<H3>),
}

/// One CONNECT-IP lane, on whichever carrier the edge answers: there is one tunnel for *every* destination at once, so the lane carries an IP address the proxy assigned it and demultiplexes by the destination in the packet; the tunnel opens by an address request and the assignment, both arriving as capsules on the stream the packets ride.
pub(crate) enum Ip {
    /// HTTP/2, whose frames carry the capsule stream as their payload.
    H2(Box<Tls2>),
    /// HTTP/3, whose frames carry it the same way.
    H3(Box<H3>),
}

impl Ip {
    /// Opens the tunnel on the carrier the dial names, with the address the proxy assigned.
    pub(crate) fn open(
        dial: &FoxyDial,
        quic: Option<Quic>,
    ) -> Result<(Self, Option<ferrox_core::foxy::connectip::Assigned>), Failure> {
        match (quic, dial.carrier) {
            (Some(quic), _) => {
                let mut lane = H3::open_ip(dial, quic)?;
                let assigned = lane.address_assign()?;
                Ok((Self::H3(Box::new(lane)), assigned))
            }
            (None, Carrier::H1) => Err(Failure::Frame),
            (None, _) => {
                let lane = open_ip_h2(dial)?;
                Ok((Self::H2(Box::new(lane.0)), lane.1))
            }
        }
    }

    /// Flushes what a write staged so the edge reads it: a lane over a TLS session writes into the session, and the record leaves on the flush.
    pub(crate) fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::H2(lane) => lane.flush(),
            Self::H3(lane) => lane.flush(),
        }
    }

    /// One UDP payload out, as one IP packet: the build is the codec's, the frame that carries it is the carrier's.
    pub(crate) fn write(
        &mut self,
        source: &[u8],
        destination: &[u8],
        source_port: u16,
        destination_port: u16,
        payload: &[u8],
    ) -> std::io::Result<bool> {
        // The packet is built into the lane's own scratch, which the datagram after it reuses: a packet per datagram took a buffer that grew from nothing to the payload's size in three steps, and every datagram of a flow paid for it. The scratch is lent out for the write and taken back after, because the lane's own borrow of it is what keeps it alive.
        let (built, sent) = match self {
            Self::H2(lane) => {
                let (built, sent) =
                    lane.write_ip(source, destination, source_port, destination_port, payload);
                (built, sent)
            }
            Self::H3(lane) => {
                let built = build_packet(
                    &mut lane.packet,
                    source,
                    destination,
                    source_port,
                    destination_port,
                    payload,
                );
                let packet = std::mem::take(&mut lane.packet);
                let sent = lane.write_datagram(&packet);
                lane.packet = packet;
                (built, sent)
            }
        };
        if !built {
            return Ok(false);
        }
        // The packet leaves on the flush rather than waiting for the next write: these are datagrams, and one that waits is one the peer never sees.
        sent.map(|()| true)
    }

    /// One UDP payload in, as one IP packet: the destination is what a reply is addressed to, and the packet is written into the caller's buffer, so a reply costs a copy and no allocation.
    pub(crate) fn read(&mut self, into: &mut Vec<u8>) -> std::io::Result<bool> {
        match self {
            Self::H2(lane) => lane.read_ip(into),
            Self::H3(lane) => lane.read_ip(into),
        }
    }

    /// Bounds one blocking read on either carrier, so a tunnel nobody has answered parks its relay on the quantum's tick rather than forever.
    pub(crate) fn set_read_quantum(&mut self, quantum: Duration) -> std::io::Result<()> {
        match self {
            Self::H2(lane) => lane.set_read_quantum(quantum),
            Self::H3(lane) => {
                lane.set_read_quantum(quantum);
                Ok(())
            }
        }
    }
}

/// One CONNECT-IP lane as its own H2 connection: the tunnel carries UDP datagrams for every destination, so a lane is one connection rather than a stream per target.
pub(crate) fn open_ip_h2(
    dial: &FoxyDial,
) -> Result<(Tls2, Option<ferrox_core::foxy::connectip::Assigned>), Failure> {
    let edge = edge_authority(&dial.host, dial.port);
    let mut block = Vec::with_capacity(160 + dial.pass.token.len());
    connectip::connect_ip(&edge, "*", 0, &dial.pass.token, &mut block);
    let mut lane = open_stream(dial, &block)?;
    let assigned = lane.address_assign()?;
    Ok((lane, assigned))
}

impl Tls2 {
    /// Sends the address request and reads the assignment: without one the lane has no source address to write into a packet, and a proxy that refuses is refused rather than guessed at.
    /// A CONNECT-IP request split into the frames the stream's own window allows, paced by its credit.
    fn send_capsules(&self, request: &[u8]) -> Result<(), Failure> {
        let mut at = 0usize;
        let send_by = Instant::now() + HEADER_TIMEOUT;
        while at < request.len() {
            let frame = {
                let inner = self.inner()?;
                let max = inner.max_frame;
                foxy::flow::frame_size(request.len() - at, max)
                    .min(stream_spend(&inner, self.stream))
            };
            if frame == 0 {
                if Instant::now() >= send_by {
                    return Err(Failure::Stream);
                }
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            let mut inner = self.inner()?;
            charge_stream(&mut inner, self.stream, frame);
            let frame = frame as usize;
            let header = frames::H2Frame {
                kind: frames::DATA,
                flags: 0,
                stream: self.stream,
                length: frame as u32,
            }
            .header();
            inner
                .tls
                .write_parts(&header, &request[at..at + frame])
                .map_err(|_| Failure::Io)?;
            at += frame;
        }
        Ok(())
    }

    fn address_assign(
        &mut self,
    ) -> Result<Option<ferrox_core::foxy::connectip::Assigned>, Failure> {
        let mut request = Vec::new();
        connectip::address_request(1, 4, &[0, 0, 0, 0], &mut request);
        connectip::address_request(2, 6, &[0; 16], &mut request);
        // The request rides the capsule stream inside DATA frames, the way a packet does: raw TLS bytes would desynchronise the edge's frame walk.
        self.send_capsules(&request)?;

        let deadline = Instant::now() + HEADER_TIMEOUT;
        let mut assigned = None;
        while Instant::now() < deadline {
            let own = self.stream;
            // The capsule is taken out of the stream's own buffer under the lock that owns it, and read before the buffer is drained, so a refused or granted answer costs no copy of it.
            let capsule = {
                let mut inner = self.inner()?;
                let Some(stream) = inner.streams.get(&own) else {
                    return Err(Failure::Stream);
                };
                match connectip::capsule_split(&stream.capsule_buf) {
                    None => None,
                    Some((used, capsule)) => {
                        let (granted, quit) = match capsule {
                            connectip::Capsule::AddressAssign(body) => {
                                let mut into = Vec::new();
                                if connectip::address_assign(body, &mut into).is_none() {
                                    (None, true)
                                } else {
                                    (into.into_iter().find(|grant| !grant.refused()), false)
                                }
                            }
                            connectip::Capsule::RouteAdvert(body) => {
                                let mut routes = Vec::new();
                                let _ = connectip::route_advert(body, &mut routes);
                                (None, false)
                            }
                            _ => (None, false),
                        };
                        if let Some(stream) = inner.streams.get_mut(&own) {
                            stream.capsule_buf.drain(..used);
                        }
                        Some((granted, quit))
                    }
                }
            };
            if let Some((granted, quit)) = capsule {
                if let Some(granted) = granted {
                    assigned = Some(granted);
                }
                if quit {
                    return Err(Failure::Frame);
                }
                if assigned.is_some() {
                    return Ok(assigned);
                }
                continue;
            }
            let fin = {
                let inner = self.inner()?;
                inner.streams.get(&own).is_none_or(|stream| stream.fin)
            };
            if fin {
                return Err(Failure::Stream);
            }
            {
                let mut inner = self.inner()?;
                if let Some(entry) = inner.streams.get_mut(&own) {
                    if entry.capsule_buf.len() > DATAGRAM_BUF_MAX {
                        entry.capsule_buf.clear();
                        return Err(Failure::Frame);
                    }
                }
            }
            let read = self.with_frame(&mut [], |inner, frame, payload, _| {
                stage_address(inner, frame, payload)
            });
            read??;
        }
        Ok(assigned)
    }

    /// One IP packet, as a datagram this lane can read both ends of. A capsule whole inside one DATA frame is handed out where it lies, so the packet crosses userspace once instead of through the capsule buffer.
    pub(crate) fn read_ip(&mut self, into: &mut Vec<u8>) -> std::io::Result<bool> {
        loop {
            let own = self.stream;
            // The capsule is taken out of the stream's own buffer under the lock that owns it: the packet is a slice of that buffer, so the lock has to be held while it is copied out.
            let staged = {
                let mut inner = self.inner().map_err(io)?;
                // The capsule buffer is taken out for the walk and put back after it: a capsule is a slice of that buffer, and a slice and the buffer cannot be held at once.
                let Some(entry) = inner.streams.get_mut(&own) else {
                    return Ok(false);
                };
                let mut staged = std::mem::take(&mut entry.capsule_buf);
                let mut found = false;
                if let Some((used, capsule)) = connectip::capsule_split(&staged) {
                    if let connectip::Capsule::Datagram(packet) = capsule {
                        into.clear();
                        into.extend_from_slice(packet);
                        found = true;
                    }
                    staged.drain(..used);
                }
                if let Some(entry) = inner.streams.get_mut(&own) {
                    entry.capsule_buf = staged;
                }
                found.then_some(())
            };
            if staged.is_some() {
                if !into.is_empty() {
                    return Ok(true);
                }
                continue;
            }
            let fin = {
                let inner = self.inner().map_err(io)?;
                inner.streams.get(&own).is_none_or(|stream| stream.fin)
            };
            if fin {
                return Ok(false);
            }
            {
                let mut inner = self.inner().map_err(io)?;
                if let Some(entry) = inner.streams.get_mut(&own) {
                    if entry.capsule_buf.len() > DATAGRAM_BUF_MAX {
                        entry.capsule_buf.clear();
                        return Err(std::io::Error::other(
                            "foxy: a capsule stream that never parses",
                        ));
                    }
                }
            }
            let read = self.with_frame(&mut [], |inner, frame, payload, _| {
                route_packet(inner, frame, payload, into)
            });
            if read?? && !into.is_empty() {
                return Ok(true);
            }
            // An empty datagram is skipped, exactly as the staged path skips one, so a false answer stays the end of stream.
        }
    }
}

/// Opens the tunnel on whichever carrier the dial names and hands the caller something it can read and write; the `H3` arm needs the connection the pool already established.
pub(crate) enum Tunnel {
    H1(Box<Tls1>),
    H2(Tls2),
    H3(Box<H3>),
}

/// The socket a relay leg parks on after it has handed the lane back: a TCP carrier's edge connection, or an h3 lane's datagram socket. Both answers are readiness only — neither takes a byte, so what wakes the wait is still there for the lane's own reader.
pub(crate) enum EdgeWait {
    Tcp(Connection),
    Udp(std::sync::Arc<crate::quic::Datagram>),
}

impl EdgeWait {
    pub(crate) fn wait_readable(&self, timeout: Duration) -> std::io::Result<bool> {
        match self {
            Self::Tcp(edge) => edge.wait_readable(timeout),
            Self::Udp(sock) => sock.wait_readable(timeout),
        }
    }
}

#[cfg(unix)]
impl std::os::fd::AsRawFd for EdgeWait {
    /// The descriptor this wait blocks on, which is the one its own socket's `recv` reads.
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        match self {
            Self::Tcp(edge) => edge.as_raw_fd(),
            Self::Udp(sock) => sock.as_raw_fd(),
        }
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsRawSocket for EdgeWait {
    /// The handle this wait blocks on, which is the one its own socket's `recv` reads.
    fn as_raw_socket(&self) -> std::os::windows::io::RawSocket {
        match self {
            Self::Tcp(edge) => edge.as_raw_socket(),
            Self::Udp(sock) => sock.as_raw_socket(),
        }
    }
}

impl Tunnel {
    pub(crate) fn open(dial: &FoxyDial, target: &str, quic: Option<Quic>) -> Result<Self, Failure> {
        match (dial.carrier, quic) {
            (Carrier::H1, _) => open_h1(dial, target, foxy::BEARER_HEAD, &dial.pass.token, None)
                .map(|lane| Self::H1(Box::new(lane))),
            (Carrier::H2, _) => open_h2(dial, target).map(Self::H2),
            (Carrier::H3, Some(quic)) => {
                H3::open(dial, target, quic).map(|lane| Self::H3(Box::new(lane)))
            }
            // No QUIC connection means the path never answered: silence is an I/O failure, not the edge closing a stream.
            (Carrier::H3, None) => Err(Failure::Io),
            // `auto` is expanded by the caller into the carriers it prefers; an unexpanded one here is a bug, and the answer is not a downgrade.
            (Carrier::Auto, _) => Err(Failure::Frame),
        }
    }

    /// The disposable probe's open: the same lane, but its CONNECT waits the budget the caller names rather than a carrier's full head timeout.
    pub(crate) fn open_within(
        dial: &FoxyDial,
        target: &str,
        quic: Quic,
        head_wait: Duration,
    ) -> Result<Self, Failure> {
        H3::open_within(dial, target, quic, head_wait).map(|lane| Self::H3(Box::new(lane)))
    }

    /// Ends the flow's half of the stream where the carrier has one: an h2 session whose request half stays open is not a session the next flow may ride.
    pub(crate) fn finish(&mut self) -> Result<(), Failure> {
        match self {
            Self::H2(lane) => lane.finish(),
            Self::H3(lane) => {
                if lane.fin || lane.quic.fin() {
                    Ok(())
                } else {
                    Err(Failure::Io)
                }
            }
            Self::H1(_) => Ok(()),
        }
    }

    /// Returns this flow's stream to the session when both halves ended; one that did not is left to the lane's drop, which resets it.
    pub(crate) fn settle(mut self) {
        let Self::H2(lane) = &mut self else {
            return;
        };
        if !lane.reusable() {
            return;
        }
        if lane.flush_credit().is_err() {
            return;
        }
        lane.release();
    }

    /// Bounds one blocking read on every carrier so a relay sharing one lane between its two directions stops holding its lock while idle: reads past the quantum answer `WouldBlock` and the relay retries instead of wedging.
    pub(crate) fn set_read_quantum(&mut self, quantum: Duration) -> std::io::Result<()> {
        match self {
            Self::H1(lane) => lane.set_read_quantum(quantum),
            Self::H2(lane) => lane.set_read_quantum(quantum),
            Self::H3(lane) => {
                lane.set_read_quantum(quantum);
                Ok(())
            }
        }
    }

    /// The relay's arm: every carrier reads one grain and waits the rest of the quantum outside the lock, on the socket `read_wait` hands it — which a lane fronted by a hop or a gecko does not have.
    pub(crate) fn set_relay_quantum(&mut self, quantum: Duration) -> std::io::Result<()> {
        match self {
            Self::H1(lane) => lane.set_relay_quantum(quantum),
            Self::H2(lane) => lane.set_relay_quantum(quantum),
            Self::H3(lane) => {
                lane.set_relay_quantum(quantum);
                Ok(())
            }
        }
    }

    /// The edge socket a parked downlink leg waits on, with how long it may wait: `Some` only once the lane can hand over nothing without the wire — no staged frame, no plaintext the TLS layer still holds, no packet the lane's own reader would displace.
    pub(crate) fn read_wait(&self) -> Option<(EdgeWait, Duration)> {
        match self {
            Self::H1(lane) => lane.read_wait(),
            Self::H2(lane) => lane.read_wait(),
            Self::H3(lane) => lane.read_wait(),
        }
    }
}

impl Drop for Tunnel {
    /// Ends a lane no settle handed back — a client gone before its grant, a failed write — because an h2 stream left open keeps the edge fetching into a window nobody drains, charged to the account, and an h3 stream half-open is still being filled.
    fn drop(&mut self) {
        match self {
            Self::H2(lane) => {
                if lane.reusable() {
                    lane.release();
                } else {
                    let _ = lane.flush_credit();
                    lane.cancel();
                }
            }
            Self::H3(lane) if !lane.closed && !lane.fin => lane.quic.cancel(),
            Self::H3(_) | Self::H1(_) => {}
        }
    }
}

impl std::io::Write for Datagram {
    fn write(&mut self, payload: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::H1(lane) => lane.write_datagram(payload),
            Self::H2(lane) => lane.write_datagram(payload),
            Self::H3(lane) => lane.write_datagram(payload),
        }
        .map(|()| payload.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl std::io::Read for Datagram {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::H1(lane) => lane.read_datagram(buf),
            Self::H2(lane) => lane.read_datagram(buf),
            Self::H3(lane) => lane.read_datagram(buf),
        }
    }
}

impl Write for Tunnel {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::H1(lane) => lane.write(buf),
            Self::H2(lane) => lane.write(buf),
            Self::H3(lane) => lane.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::H1(lane) => lane.flush(),
            Self::H2(lane) => lane.flush(),
            Self::H3(lane) => lane.flush(),
        }
    }
}

impl Read for Tunnel {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::H1(lane) => lane.read(buf),
            Self::H2(lane) => lane.read(buf),
            Self::H3(lane) => lane.read(buf),
        }
    }
}

/// The SOCKS reply a refusal becomes: an edge that declined the target says so locally instead of paying a round trip to hear the same status again.
pub(crate) fn refusal_reply(failure: Failure) -> u8 {
    match failure {
        Failure::Rejected(status) if foxy::target_is_unreachable(status) => 0x04,
        // The edge named the host, so the client hears the same answer it would from an unreachable target.
        Failure::BlockedHost(_) => 0x04,
        Failure::Stream => 0x06,
        Failure::Rejected(_) | Failure::Frame | Failure::Io | Failure::Untrusted => 0x01,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Read` source that answers a whole buffer in one call and counts the calls it got: the read count is exact here, which is what a loopback socket cannot promise.
    struct HeadSource<'a> {
        bytes: &'a [u8],
        at: usize,
        reads: usize,
    }

    impl Read for HeadSource<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reads += 1;
            let take = buf.len().min(self.bytes.len() - self.at);
            buf[..take].copy_from_slice(&self.bytes[self.at..self.at + take]);
            self.at += take;
            Ok(take)
        }
    }

    /// An edge that answers in its own record costs one read: the walk used to pay one `Read::read`, and one pass through the record deframer, per octet of the status line.
    #[test]
    fn the_head_walk_reads_the_answer_in_one_call() {
        let bytes = b"HTTP/1.1 200 Connection established\r\n\r\nfirst tunnel bytes";
        let mut source = HeadSource {
            bytes,
            at: 0,
            reads: 0,
        };
        let (status, carried) = head(&mut source, None).expect("walks the head");
        assert_eq!(status, 200);
        assert_eq!(
            carried, b"first tunnel bytes",
            "the octets that arrived past the empty line in the same record come with the status"
        );
        assert_eq!(
            source.reads, 1,
            "one window read for an answer that came in one record"
        );
        assert_eq!(
            carried.capacity(),
            carried.len(),
            "the tail is sized to its own bytes, not to the window that found it"
        );
    }

    /// The tail is handed over from where it landed and released by the read that delivers its last octet: a relay that has taken the tunnel's first bytes holds nothing of the walk.
    #[test]
    fn the_pipelined_tail_is_released_by_the_read_that_spends_it() {
        let mut carried = b"tunnel-first".to_vec();
        let mut at = 0usize;
        let mut buf = [0u8; 4];
        assert_eq!(hand_back(&mut carried, &mut at, &mut buf), 4);
        assert_eq!(&buf, b"tunn");
        assert_eq!(carried.capacity(), 12, "held, because octets still wait");
        let mut rest = [0u8; 8];
        assert_eq!(hand_back(&mut carried, &mut at, &mut rest), 8);
        assert_eq!(&rest, b"el-first");
        assert_eq!(carried.capacity(), 0, "the last byte releases the window");
        assert_eq!(at, 0, "and the cursor is ready for the socket");
    }

    /// A head longer than the window is the cold answer of an edge that sends more than a status line: the walk still finds the delimiter, still hands on what follows it, and still refuses a head that runs past `MAX_HEAD` without one.
    #[test]
    fn a_head_longer_than_the_window_is_walked_without_losing_its_tail() {
        let mut bytes = b"HTTP/1.1 200 OK\r\n".to_vec();
        for at in 0..40 {
            bytes.extend_from_slice(format!("X-Pad-{at}: pad-pad-pad-pad\r\n").as_bytes());
        }
        bytes.extend_from_slice(b"\r\npiped");
        let mut source = HeadSource {
            bytes: &bytes,
            at: 0,
            reads: 0,
        };
        let (status, carried) = head(&mut source, None).expect("walks the long head");
        assert_eq!(status, 200);
        assert_eq!(carried, b"piped");
        assert!(
            source.reads < 12,
            "a window at a time, not a byte at a time: {} reads",
            source.reads
        );

        let long = vec![b'x'; MAX_HEAD + 8];
        let mut source = HeadSource {
            bytes: &long,
            at: 0,
            reads: 0,
        };
        assert_eq!(head(&mut source, None).err(), Some(Failure::Frame));

        let mut at_bound = b"HTTP/1.1 200 ".to_vec();
        while at_bound.len() < MAX_HEAD - 4 {
            at_bound.push(b'x');
        }
        at_bound.extend_from_slice(b"\r\n\r\n");
        let mut source = HeadSource {
            bytes: &at_bound,
            at: 0,
            reads: 0,
        };
        let (status, carried) = head(&mut source, None).expect("walks to the bound");
        assert_eq!(status, 200);
        assert!(
            carried.is_empty(),
            "the empty line was the last thing the edge sent"
        );
    }

    /// A grant is the two `WINDOW_UPDATE` frames a crossing owes: the stream it took the bytes on and the connection, each carrying its own increment, and nothing at all for an increment of zero.
    #[test]
    fn the_credit_template_is_the_two_window_update_frames() {
        for stream in [1u32, 3] {
            let mut out = Vec::new();
            grant(stream, 0, 0, &mut out);
            assert!(out.is_empty(), "a grant of nothing writes nothing");
            grant(stream, 11, 22, &mut out);
            for (slot, id, increment) in [(0usize, stream, 11u32), (13, 0, 22)] {
                let frame = frames::H2Frame {
                    kind: frames::WINDOW_UPDATE,
                    flags: 0,
                    stream: id,
                    length: 4,
                };
                assert_eq!(
                    &out[slot..slot + 9],
                    &frame.header()[..],
                    "header at {slot}"
                );
                assert_eq!(
                    &out[slot + 9..slot + 13],
                    &increment.to_be_bytes(),
                    "increment at {slot}"
                );
            }
            out.clear();
            grant(stream, 7, 0, &mut out);
            assert_eq!(out.len(), 13, "a stream grant without a connection grant");
        }
    }

    fn dial(host: &str, carrier: Carrier) -> FoxyDial {
        FoxyDial {
            host: std::sync::Arc::from(host),
            port: 443,
            address: Some(SocketAddr::from(([127, 0, 0, 1], 1))),
            carrier,
            upstream: None,
            roots: Vec::new().into(),
            pins: foxy::pin::Pins::default(),
            pass: Pass {
                token: std::sync::Arc::from("the-pass"),
                expires_at: None,
                quota_remaining: None,
                quota_reset: None,
                quota_limit: None,
            },
        }
    }

    #[test]
    fn every_carrier_asks_for_exactly_its_own_alpn() {
        for (carrier, want) in [
            (Carrier::H1, &b"http/1.1"[..]),
            (Carrier::H2, &b"h2"[..]),
            (Carrier::H3, &b"h3"[..]),
        ] {
            assert_eq!(
                &*tls_config(&dial("edge.example", carrier)).alpn,
                &[want.to_vec()]
            );
        }
    }

    #[test]
    fn the_tls_config_names_the_edge_and_carries_its_pins() {
        let mut d = dial("edge.example", Carrier::H2);
        d.roots = vec![vec![1, 2, 3]].into();
        d.pins = foxy::pin::Pins::parse([
            "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned()
        ]);
        let config = tls_config(&d);
        assert_eq!(config.server_name, "edge.example");
        assert_eq!(
            config.roots,
            ferrox_core::tls::Anchors::from(vec![vec![1, 2, 3]])
        );
        assert_eq!(config.pins.len(), 1);
    }

    /// The `ALPN` list a carrier offers is built once and shared: a dial that built its own paid a vector and an arc for a list of one, and the list is a function of the carrier alone.
    #[test]
    fn a_carriers_alpn_list_is_shared_rather_than_built_per_dial() {
        let first = carrier_alpn(Carrier::H2);
        let second = carrier_alpn(Carrier::H2);
        assert!(
            std::sync::Arc::ptr_eq(&first, &second),
            "two dials hold the same list, not two lists"
        );
        assert_eq!(
            &*first,
            &[b"h2".to_vec()],
            "and the list is the carrier's own protocol"
        );
        // The list is warmed before the window opens, so what the window prices is a dial's own lookup and not the one build the process does.
        std::hint::black_box(carrier_alpn(Carrier::H2));
        let ((), counts) = ferrox_core::alloc_count::measure(|| {
            for _ in 0..4096 {
                std::hint::black_box(carrier_alpn(Carrier::H2));
            }
        });
        assert_eq!(
            (counts.allocs, counts.bytes, counts.zeroed),
            (0, 0, 0),
            "4096 dials ask for the carrier's list and none of them builds one"
        );
    }

    /// The order the lane trusts to find a tunnel, and the order a datagram trusts: `auto` walks all three, UDP walks the two that can carry a capsule at all.
    #[test]
    fn the_carriers_are_ordered_by_what_the_edge_answers_best() {
        // `auto` opens on `h2`: against the real edge on CI's own egress, `h2` outran `h3` and the old `auto` order in every run and on every runner, because a QUIC session's congestion window starts empty where a resumed TCP session's does not. The exact order is the gate, so the ladder cannot lose a carrier to a reorder: all three are named here.
        assert_eq!(
            Carrier::Auto.order(),
            [Carrier::H2, Carrier::H1, Carrier::H3]
        );
        assert_eq!(Carrier::H2.order(), [Carrier::H2, Carrier::H2, Carrier::H2]);
        assert_eq!(Carrier::H3.order(), [Carrier::H3, Carrier::H2, Carrier::H1]);
        assert_eq!(
            Carrier::udp_order(),
            [Carrier::H3, Carrier::H2, Carrier::H1]
        );
        assert_eq!(Carrier::ip_order(), [Carrier::H3, Carrier::H2]);
    }

    /// The pause between attempts bounds the budget the whole dial spends: a peer that would have answered is not waited on for long.
    #[test]
    fn an_edge_attempt_is_retried_under_a_growing_pause() {
        // The pause is flat because a refusal comes back fast: eight asks at one address is a couple of seconds of pause, not a leg's budget.
        assert_eq!(super::after_attempt(0), Duration::from_millis(250));
        assert_eq!(super::after_attempt(7), Duration::from_millis(250));
        let budget: u64 = (0..EDGE_ATTEMPTS - 1)
            .map(|attempt| super::after_attempt(attempt).as_millis() as u64)
            .sum();
        assert!(
            budget <= 5_000,
            "eight asks at one address cost a couple of seconds, not {budget}ms"
        );
    }

    #[test]
    fn only_a_two_hundred_opens_the_tunnel() {
        for status in [200u16, 204, 299] {
            assert!(opened(status).is_ok(), "{status}");
        }
        for status in [199u16, 300, 401, 403, 502] {
            assert_eq!(opened(status), Err(Failure::Rejected(status)));
        }
    }

    #[test]
    fn a_refusal_becomes_the_socks_reply_that_says_so() {
        assert_eq!(refusal_reply(Failure::Rejected(502)), 0x04);
        assert_eq!(refusal_reply(Failure::BlockedHost(403)), 0x04);
        assert_eq!(refusal_reply(Failure::Rejected(403)), 0x01);
        assert_eq!(refusal_reply(Failure::Stream), 0x06);
        assert_eq!(refusal_reply(Failure::Io), 0x01);
        assert_eq!(refusal_reply(Failure::Frame), 0x01);
        assert_eq!(refusal_reply(Failure::Untrusted), 0x01);
    }

    #[test]
    fn the_dial_order_is_the_pinned_country_only() {
        let edges = vec![
            foxy::Candidate {
                host: "de1".into(),
                port: 443,
                country: "DE".into(),
                city: "berlin".into(),
            },
            foxy::Candidate {
                host: "us1".into(),
                port: 443,
                country: "US".into(),
                city: "nyc".into(),
            },
            foxy::Candidate {
                host: "de2".into(),
                port: 443,
                country: "DE".into(),
                city: "frankfurt".into(),
            },
        ];
        let order = foxy::dial_order(&edges, "DE", None, 3);
        assert_eq!(order.len(), 2);
        assert!(order.iter().all(|edge| edge.country == "DE"));
    }

    /// No QUIC connection is the path's silence, so the failure names I/O and not a stream the edge never closed.
    #[test]
    fn a_quic_lane_without_a_connection_is_a_refusal_not_a_panic() {
        assert_eq!(
            Tunnel::open(&dial("edge.example", Carrier::H3), "e:443", None).err(),
            Some(Failure::Io)
        );
    }

    #[test]
    fn an_upstream_proxy_names_its_scheme_host_and_port() {
        let http = upstream_proxy("http://proxy.local:8080").expect("parses");
        assert!(http.http);
        assert_eq!((&*http.host, http.port), ("proxy.local", 8080));
        let socks = upstream_proxy("socks5://proxy.local:1080").expect("parses");
        assert!(!socks.http);
        assert_eq!((&*socks.host, socks.port), ("proxy.local", 1080));
        let h = upstream_proxy("socks5h://proxy.local:1080").expect("parses");
        assert!(!h.http);
        let v6 = upstream_proxy("socks5://[2001:db8::1]:1080").expect("parses");
        assert_eq!(
            (v6.host, v6.port),
            (std::sync::Arc::from("2001:db8::1"), 1080),
            "a v6 hop is read as the address it spells, brackets and all"
        );
        for bad in [
            "",
            "proxy.local:8080",
            "gopher://proxy.local:70",
            "http://proxy.local",
            "http://proxy.local:99999",
            "http://proxy.local:80/extra",
            "http://user:pass@proxy.local:8080",
        ] {
            assert!(upstream_proxy(bad).is_none(), "{bad:?} refuses");
        }
    }

    #[test]
    fn an_exit_probe_is_read_in_either_shape_it_can_answer_in() {
        assert_eq!(exit_country(b"fl=1\nloc=DE\n"), Some("DE".to_owned()));
        assert_eq!(
            exit_country(b"{\"status\":\"success\",\"countryCode\":\"US\"}"),
            Some("US".to_owned())
        );
        assert_eq!(
            exit_country(b"loc=de"),
            None,
            "a lowercase answer is not a country code"
        );
        assert_eq!(exit_country(b"nothing here"), None);
        assert_eq!(exit_country(b"loc=DEU"), None);
    }
}

#[cfg(test)]
pub(crate) mod loopback {
    use super::*;
    use crate::conn::Listener;

    pub(crate) const PAYLOAD: &[u8] = b"the tunnel carries the bytes unchanged";

    pub(crate) fn minted(alpn: &[u8]) -> (Vec<Vec<u8>>, ferrox_core::tls::TlsServerConfig) {
        minted_at(alpn, "localhost")
    }

    /// The same edge under the name the dialer puts in its handshake: a lane dialled at an IP literal needs an `IpAddress` SAN, which is a different check in the verifier than a DNS one.
    pub(crate) fn minted_at(
        alpn: &[u8],
        subject: &str,
    ) -> (Vec<Vec<u8>>, ferrox_core::tls::TlsServerConfig) {
        let minted = rcgen::generate_simple_self_signed(vec![subject.to_owned()]).expect("mints");
        let roots = crate::quic::parse_ca_pem(minted.cert.pem().as_bytes());
        let server = ferrox_core::tls::TlsServerConfig {
            certs: vec![ferrox_core::tls::CertEntry {
                cert_chain: vec![minted.cert.der().to_vec()],
                key_der: minted.signing_key.serialize_der(),
                key_kind: ferrox_core::tls::ServerKeyKind::Pkcs8,
                reload: None,
                ocsp: None,
            }],
            alpn: vec![alpn.to_vec()],
            min_version: None,
            max_version: None,
            cipher_suites: Vec::new(),
            curves: Vec::new(),
            send_tickets: true,
            reject_unknown_sni: false,
            server_config_cache: std::sync::Arc::default(),
            ech_server_keys: None,
            master_key_log: None,
            kernel_tx: false,
            kernel_rx: false,
        };
        (roots, server)
    }

    pub(crate) fn dial_for(
        roots: Vec<Vec<u8>>,
        port: u16,
        carrier: Carrier,
        pins: foxy::pin::Pins,
    ) -> FoxyDial {
        FoxyDial {
            host: std::sync::Arc::from("localhost"),
            port,
            address: Some(SocketAddr::from(([127, 0, 0, 1], port))),
            carrier,
            upstream: None,
            roots: roots.into(),
            pins,
            pass: Pass {
                token: std::sync::Arc::from("the-pass"),
                expires_at: None,
                quota_remaining: None,
                quota_reset: None,
                quota_limit: None,
            },
        }
    }

    /// The name a status line prints is the name `--carrier` takes, so a lane reports the rung it was given under the word it was given.
    #[test]
    fn a_carrier_names_itself_with_the_word_the_cli_takes() {
        for (word, named) in [
            ("auto", Carrier::Auto),
            ("h1", Carrier::H1),
            ("h2", Carrier::H2),
            ("h3", Carrier::H3),
        ] {
            assert_eq!(named.name(), word);
            assert_eq!(carrier(word), named, "the parse and the name agree");
        }
    }

    /// A dial names the trust store, it does not own a copy of it: two dials of one edge, and the configs built from them, answer with the same allocation.
    #[test]
    fn every_dial_of_one_trust_names_the_same_anchors() {
        let anchors = crate::quic::system_roots();
        let no_pins = foxy::pin::Pins::default();
        let first = FoxyDial {
            roots: Arc::clone(&anchors),
            ..dial_for(Vec::new(), 443, Carrier::H2, no_pins.clone())
        };
        let second = FoxyDial {
            roots: anchors,
            ..dial_for(Vec::new(), 443, Carrier::H3, no_pins)
        };
        assert!(
            Arc::ptr_eq(&tls_config(&first).roots, &tls_config(&second).roots),
            "the platform store is read once for the process, not once per dial"
        );
    }

    /// An address that accepts TCP is not an address that carries the lane: `localhost` answers v6 first on both runners that matter, so a silent v6 listener must not cost the lane the v4 edge behind it.
    #[test]
    fn an_address_whose_tls_does_not_answer_costs_the_lane_the_next_one() {
        use ferrox_core::tls::TlsProvider as _;

        let (roots, server) = minted(b"h2");
        let mute = crate::conn::test_bind("[::1]:0").expect("binds v6");
        let mute_port = mute.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            // Accepts the connection and then says nothing, which is the whole of an address that cannot carry TLS.
            let (stream, _) = mute.accept().expect("accepts");
            drop(stream);
        });
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds v4");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            tls.handshake().expect("handshakes");
            while tls.read(&mut [0u8; 1]).map_or(true, |n| n > 0) {}
        });

        let dial = FoxyDial {
            // The port the name resolves to for both families, so the two listeners are the two addresses of one name.
            host: std::sync::Arc::from("localhost"),
            port: mute_port.min(port) + mute_port.max(port).saturating_sub(mute_port),
            address: None,
            carrier: Carrier::H2,
            upstream: None,
            roots: roots.into(),
            pins: foxy::pin::Pins::default(),
            pass: Pass {
                token: std::sync::Arc::from("the-pass"),
                expires_at: None,
                quota_remaining: None,
                quota_reset: None,
                quota_limit: None,
            },
        };
        // The v4 edge's port, which is the one that speaks.
        let dial = FoxyDial { port, ..dial };
        let tls = tls_to_edge(&dial).expect("dials the address whose TLS answers");
        assert_eq!(tls.alpn(), Some(&b"h2"[..]), "the session is the live one");
    }

    /// An address the config names is the dial it named: a name that answers does not get it, because the named address is the poison-proof dial and the TLS name is verified against it.
    #[test]
    fn an_address_the_config_names_is_the_dial_it_named() {
        let (roots, _server) = minted(b"h2");
        let dial = FoxyDial {
            host: std::sync::Arc::from("localhost"),
            port: 443,
            address: Some(SocketAddr::from(([127, 0, 0, 1], 1))),
            carrier: Carrier::H2,
            upstream: None,
            roots: roots.into(),
            pins: foxy::pin::Pins::default(),
            pass: Pass {
                token: std::sync::Arc::from("the-pass"),
                expires_at: None,
                quota_remaining: None,
                quota_reset: None,
                quota_limit: None,
            },
        };
        assert!(
            tls_to_edge(&dial).is_err(),
            "the named address is the only one"
        );
    }

    /// An edge whose chain this device does not trust is a fact about the certificate, not about the moment: the lane asks it once and names the refusal, where an io failure reads as a peer that is merely slow.
    #[test]
    fn an_untrusted_edge_is_named_and_asked_once() {
        use ferrox_core::tls::TlsProvider as _;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (_foreign_roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let asked = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&asked);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                counter.fetch_add(1, Ordering::SeqCst);
                let Ok(mut tls) =
                    ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                else {
                    continue;
                };
                let _ = tls.handshake();
            }
        });

        // The roots of some other hand: the same shape of certificate, on a chain that does not verify.
        let (roots, _) = minted(b"h2");
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let at = Instant::now();
        let failure = tls_to_edge(&dial).expect_err("the chain is refused");
        assert_eq!(failure, Failure::Untrusted, "{failure}");
        assert!(
            at.elapsed() < Duration::from_millis(EDGE_BACKOFF_MS),
            "one ask costs no backoff, it took {:?}",
            at.elapsed()
        );
        assert_eq!(
            asked.load(Ordering::SeqCst),
            1,
            "an edge that never had the certificate is not asked eight times"
        );
    }

    /// A silent edge is a peer that is slow, not a peer that is dead: the CONNECT it never answers costs the open the named head wait and a `Stream` failure the walk can move past, where an unbounded head read held the flow for as long as the edge kept the session.
    #[test]
    fn a_silent_edge_costs_the_open_its_head_budget_not_the_flow() {
        use ferrox_core::tls::TlsProvider as _;

        for (alpn, carrier, label) in [
            (&b"http/1.1"[..], Carrier::H1, "h1"),
            (&b"h2"[..], Carrier::H2, "h2"),
        ] {
            // The budget is re-applied per iteration because each leg clears it before its asserts, so a panic never leaks a tight arm to the next test.
            let root =
                crate::json::parse(r#"{"budgets": {"headArrival": "300ms"}}"#).expect("parses");
            crate::budgets::apply(
                &crate::config::budgets(&root).expect("a name the engine acts on"),
            );
            let (roots, server) = minted(alpn);
            let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
            let port = listener.local_addr().expect("addr").port();
            let edge = std::thread::spawn(move || {
                // Handshakes, reads the request, answers nothing: the session stays open until the client's failure ends it.
                let (stream, _) = listener.accept().expect("accepts");
                let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server, stream)
                    .expect("accepts");
                tls.handshake().expect("handshakes");
                let mut sink = [0u8; 64];
                while tls.read(&mut sink).is_ok_and(|read| read > 0) {}
            });
            let dial = dial_for(roots, port, carrier, foxy::pin::Pins::default());
            let at = Instant::now();
            let opened = Tunnel::open(&dial, "example.com:443", None).err();
            crate::budgets::clear();
            let failure = opened.expect("the head never arrives");
            assert_eq!(failure, Failure::Stream, "{label} against a silent edge");
            assert!(
                at.elapsed() < Duration::from_secs(5),
                "the head budget expired the dial, it took {:?}",
                at.elapsed()
            );
            edge.join().expect("joins");
        }
    }

    /// A head that arrives a byte at a time is the arithmetic the silent-edge test does not reach: every drip stays inside the armed per-byte wait, so only a wall on the whole head keeps a trickling edge from holding the open for its length times the budget.
    #[test]
    fn a_dripping_head_costs_the_open_its_head_budget_not_its_length() {
        use ferrox_core::tls::TlsProvider as _;

        let root = crate::json::parse(r#"{"budgets": {"headArrival": "300ms"}}"#).expect("parses");
        crate::budgets::apply(&crate::config::budgets(&root).expect("a name the engine acts on"));
        let (roots, server) = minted(b"http/1.1");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                read_exact(&mut tls, &mut byte).expect("reads the request");
                request.push(byte[0]);
            }
            for byte in b"HTTP/1.1 200 Connection established\r\n\r\n" {
                if tls.write_all(&[*byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(60));
            }
        });
        let dial = dial_for(roots, port, Carrier::H1, foxy::pin::Pins::default());
        let at = Instant::now();
        let opened = Tunnel::open(&dial, "example.com:443", None).err();
        crate::budgets::clear();
        let failure = opened.expect("the head never lands whole");
        assert_eq!(failure, Failure::Stream, "a drip ends at the wall");
        assert!(
            at.elapsed() < Duration::from_secs(2),
            "43 drips of 60 ms are not 2580 ms of open, it took {:?}",
            at.elapsed()
        );
        edge.join().expect("joins");
    }

    fn round_trip(tunnel: &mut Tunnel) {
        tunnel.write_all(PAYLOAD).expect("writes");
        tunnel.flush().expect("flushes");
        let mut back = vec![0u8; PAYLOAD.len()];
        tunnel.read_exact(&mut back).expect("reads");
        assert_eq!(back, PAYLOAD);
    }

    /// A dial whose hop is the only way to the edge: the name the CONNECT carries is not the name anything resolves, so a dial that reaches the edge has gone through the hop.
    fn hop_stream(proxy: &UpstreamProxy) -> Connection {
        let dial = upstream_dial(proxy.clone(), None);
        tcp_via(proxy, &dial.host, dial.port).expect("chains through the hop")
    }

    fn upstream_dial(proxy: UpstreamProxy, edge: Option<SocketAddr>) -> FoxyDial {
        FoxyDial {
            host: std::sync::Arc::from("edge.test"),
            port: 2499,
            address: edge,
            carrier: Carrier::H1,
            upstream: Some(proxy),
            roots: Vec::new().into(),
            pins: foxy::pin::Pins::default(),
            pass: Pass {
                token: std::sync::Arc::from("the-pass"),
                expires_at: None,
                quota_remaining: None,
                quota_reset: None,
                quota_limit: None,
            },
        }
    }

    fn read_head(stream: &mut dyn std::io::Read) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).expect("reads a head");
            head.push(byte[0]);
        }
        String::from_utf8(head).expect("ascii")
    }

    #[test]
    fn tcp_through_an_http_upstream_sends_connect_and_carries_bytes() {
        let proxy = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = proxy.local_addr().expect("addr").port();
        let seen = std::thread::spawn(move || {
            let (mut stream, _) = proxy.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let head = read_head(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .expect("answers");
            let mut buf = [0u8; 64];
            let read = stream.read(&mut buf).expect("reads");
            stream.write_all(&buf[..read]).expect("echoes");
            head
        });
        let proxy = upstream_proxy(&format!("http://127.0.0.1:{port}")).expect("parses");
        let mut stream = hop_stream(&proxy);
        stream.write_all(PAYLOAD).expect("writes");
        let mut back = vec![0u8; PAYLOAD.len()];
        stream.read_exact(&mut back).expect("echoes");
        assert_eq!(back, PAYLOAD);
        assert_eq!(
            seen.join().expect("joins"),
            "CONNECT edge.test:2499 HTTP/1.1\r\nHost: edge.test:2499\r\n\r\n"
        );
    }

    /// The v6 case the joined authority used to guarantee: gathered as name, brackets and digits, it still reaches the hop bracketed, because a bare `::1:2499` is an authority nothing can read.
    #[test]
    fn a_hop_connect_brackets_a_literal_edge() {
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = front.local_addr().expect("addr");
        let seen = std::thread::spawn(move || {
            let (mut hop, _) = front.accept().expect("accepts");
            hop.set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let head = read_head(&mut hop);
            hop.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .expect("answers");
            head
        });
        let mut client = Connection::connect(addr).expect("connects");
        hop_connect(&mut client, "::1", 2499).expect("opens the tunnel");
        assert_eq!(
            seen.join().expect("joins"),
            "CONNECT [::1]:2499 HTTP/1.1\r\nHost: [::1]:2499\r\n\r\n"
        );
    }

    /// The hop's CONNECT and the head it is answered with, counted in the window the app's tests share: the name never enters a buffer of its own and neither does the answer.
    #[test]
    fn a_hop_connect_allocates_nothing() {
        const DIALS: usize = 64;
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = front.local_addr().expect("addr");
        let mut clients = Vec::with_capacity(DIALS);
        let mut hops = Vec::with_capacity(DIALS);
        for _ in 0..DIALS {
            clients.push(Connection::connect(addr).expect("connects"));
            let (hop, _) = front.accept().expect("accepts");
            hops.push(hop);
        }
        // Queued before the window opens, so what the window holds is the gathered write, the peek and the head's own read.
        for hop in &mut hops {
            hop.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .expect("answers");
        }
        let ((), counts) = ferrox_core::alloc_count::measure(|| {
            for client in &mut clients {
                hop_connect(client, "edge.test", 2499).expect("opens the tunnel");
            }
        });
        assert_eq!(
            (counts.allocs, counts.bytes, counts.zeroed),
            (0, 0, 0),
            "{DIALS} hops, and no byte of the CONNECT or its answer went through a buffer"
        );
    }

    /// A hop that answers with the tunnel's first bytes already behind its head: the head is proved by a `peek`, so those bytes stay on the socket for the caller, where a window that read the answer would have taken them.
    #[test]
    fn a_hop_head_leaves_the_tunnel_s_first_bytes_on_the_socket() {
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = front.local_addr().expect("addr");
        let (released_tx, released_rx) = std::sync::mpsc::channel::<()>();
        let answering = std::thread::spawn(move || {
            let (mut hop, _) = front.accept().expect("accepts");
            hop.set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            hop.write_all(b"HTTP/1.1 200 Connection established\r\n\r\nfirst-bytes-of-the-tunnel")
                .expect("answers");
            let head = read_head(&mut hop);
            // A close with the CONNECT still in the hop's buffer answers `RST`, and an `RST` costs the caller the bytes behind the head: the hop holds its socket until the read above has happened.
            released_rx.recv().expect("the caller read");
            head
        });
        let mut client = Connection::connect(addr).expect("connects");
        hop_connect(&mut client, "edge.test", 2499).expect("opens the tunnel");
        let mut tail = [0u8; 25];
        read_exact(&mut client, &mut tail).expect("the tail is still on the socket");
        assert_eq!(&tail, b"first-bytes-of-the-tunnel");
        released_tx.send(()).expect("releases the hop");
        assert_eq!(
            answering.join().expect("joins"),
            "CONNECT edge.test:2499 HTTP/1.1\r\nHost: edge.test:2499\r\n\r\n"
        );
    }

    /// A hop that sends the first line of its head and then withholds the rest must cost the read arm, not the core: a peek that leaves its octets in the socket would see them again forever, so the walk takes what it has seen before it waits for more.
    #[test]
    fn a_hop_that_withholds_its_terminator_waits_on_the_wire_not_on_its_own_octets() {
        const ARM: Duration = Duration::from_secs(1);
        const GIVE_UP: Duration = Duration::from_secs(5);
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = front.local_addr().expect("addr");
        let (partial_tx, partial_rx) = std::sync::mpsc::channel::<()>();
        let (released_tx, released_rx) = std::sync::mpsc::channel::<()>();
        let answering = std::thread::spawn(move || {
            let (mut hop, _) = front.accept().expect("accepts");
            hop.write_all(b"HTTP/1.1 200 Connection established")
                .expect("a head with no empty line");
            partial_tx.send(()).expect("signals");
            let _ = released_rx.recv();
        });
        let mut client = Connection::connect(addr).expect("connects");
        client.set_read_timeout(Some(ARM)).expect("arms a read");
        partial_rx
            .recv_timeout(GIVE_UP)
            .expect("the hop answered before the walk started");
        let (verdict_tx, verdict_rx) = std::sync::mpsc::channel();
        let _walked = std::thread::spawn(move || {
            let _ = verdict_tx.send(hop_connect(&mut client, "edge.test", 2499));
        });
        let verdict = verdict_rx.recv_timeout(GIVE_UP).expect(
            "a withheld terminator cost the walk its read arm, not a spin over the octets it had already seen",
        );
        assert!(verdict.is_err(), "a head with no empty line opens nothing");
        released_tx.send(()).expect("releases the hop");
        answering.join().expect("joins");
    }

    #[test]
    fn tcp_through_a_socks5_upstream_shakes_hands_and_carries_bytes() {
        let proxy = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = proxy.local_addr().expect("addr").port();
        let seen = std::thread::spawn(move || {
            let (mut stream, _) = proxy.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut greet = [0u8; 3];
            read_exact(&mut stream, &mut greet).expect("greets");
            stream.write_all(&[5, 0]).expect("selects");
            let mut request = vec![0u8; 16];
            read_exact(&mut stream, &mut request).expect("connects");
            let mut want = vec![5, 1, 0, 3, 9];
            want.extend_from_slice(b"edge.test");
            want.extend_from_slice(&2499u16.to_be_bytes());
            assert_eq!(request, want);
            stream
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .expect("grants");
            let mut buf = [0u8; 64];
            let read = stream.read(&mut buf).expect("reads");
            stream.write_all(&buf[..read]).expect("echoes");
            greet.to_vec()
        });
        let proxy = upstream_proxy(&format!("socks5://127.0.0.1:{port}")).expect("parses");
        let mut stream = hop_stream(&proxy);
        stream.write_all(PAYLOAD).expect("writes");
        let mut back = vec![0u8; PAYLOAD.len()];
        stream.read_exact(&mut back).expect("echoes");
        assert_eq!(back, PAYLOAD);
        assert_eq!(seen.join().expect("joins"), vec![5, 1, 0]);
    }

    /// A hop that refuses is a failed dial and not a fallback: the edge is never dialed around a proxy the config named, because a lane that bypasses its configured hop is a leak.
    #[test]
    fn a_refused_upstream_is_a_failed_dial_and_not_a_direct_one() {
        let proxy = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = proxy.local_addr().expect("addr").port();
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let edge_port = listener.local_addr().expect("addr").port();
        let (dialed_tx, dialed_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                drop(stream);
                let _ = dialed_tx.send(());
            }
        });
        std::thread::spawn(move || {
            let (mut stream, _) = proxy.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut greet = [0u8; 3];
            read_exact(&mut stream, &mut greet).expect("greets");
            stream.write_all(&[5, 0]).expect("selects");
            let mut request = vec![0u8; 15];
            read_exact(&mut stream, &mut request).expect("connects");
            // A general failure, which is how a hop says it will not connect.
            stream
                .write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0])
                .expect("refuses");
        });
        let proxy = upstream_proxy(&format!("socks5://127.0.0.1:{port}")).expect("parses");
        let edge = Some(SocketAddr::from(([127, 0, 0, 1], edge_port)));
        assert!(
            tls_to_edge(&upstream_dial(proxy.clone(), edge)).is_err(),
            "a refused hop is a failed dial"
        );
        assert!(
            dialed_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "the edge on port {edge_port} was dialed around the hop"
        );
    }

    #[test]
    fn h1_through_an_http_upstream_reaches_its_edge() {
        let (roots, server) = minted(b"http/1.1");
        let edge = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let edge_port = edge.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            let (stream, _) = edge.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            tls.handshake().expect("handshakes");
            let request = read_head(&mut tls);
            assert_eq!(
                request,
                "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Bearer the-pass\r\n\r\n"
            );
            tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .expect("answers");
            let mut buf = [0u8; 64];
            let read = tls.read(&mut buf).expect("reads");
            assert_eq!(&buf[..read], PAYLOAD);
            tls.write_all(&buf[..read]).expect("echoes");
        });
        let proxy = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let proxy_port = proxy.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            let (mut downstream, _) = proxy.accept().expect("accepts");
            downstream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let head = read_head(&mut downstream);
            assert_eq!(
                head,
                format!(
                    "CONNECT localhost:{edge_port} HTTP/1.1\r\nHost: localhost:{edge_port}\r\n\r\n"
                )
            );
            downstream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .expect("answers");
            let edge = Connection::connect(("127.0.0.1", edge_port)).expect("dials");
            let (mut up_read, mut up_write) = (edge.try_clone().expect("clones"), edge);
            let mut down = downstream.try_clone().expect("clones");
            let pipe = std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                while let Ok(read) = down.read(&mut buf) {
                    if read == 0 || up_write.write_all(&buf[..read]).is_err() {
                        break;
                    }
                }
            });
            let mut buf = [0u8; 8192];
            while let Ok(read) = up_read.read(&mut buf) {
                if read == 0 || downstream.write_all(&buf[..read]).is_err() {
                    break;
                }
            }
            pipe.join().expect("joins");
        });
        let mut dial = dial_for(roots, edge_port, Carrier::H1, foxy::pin::Pins::default());
        dial.upstream = upstream_proxy(&format!("http://127.0.0.1:{proxy_port}"));
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        round_trip(&mut tunnel);
    }

    /// A SOCKS5 hop for the QUIC carrier: a TCP side answering `UDP ASSOCIATE` with the address of its relay socket, and a relay carrying datagrams with the association's own header — both halves write that header themselves, so the framing is witnessed by something other than the code it checks.
    fn socks_relay(edge_port: u16) -> UpstreamProxy {
        let control = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let proxy_port = control.local_addr().expect("addr").port();
        let relay = crate::quic::bind_datagram("127.0.0.1:0").expect("binds");
        let relay_addr = relay.local_addr().expect("addr");
        std::thread::spawn(move || {
            let (mut stream, _) = control.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(30)))
                .expect("times out");
            let mut greet = [0u8; 3];
            read_exact(&mut stream, &mut greet).expect("greets");
            assert_eq!(greet, [5, 1, 0], "no authentication offered");
            stream.write_all(&[5, 0]).expect("selects");
            let mut ask = [0u8; 10];
            read_exact(&mut stream, &mut ask).expect("associates");
            assert_eq!(&ask[..4], [5, 3, 0, 1], "a UDP association, naming nothing");
            let octets = match relay_addr.ip() {
                std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
                std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
            };
            let mut grant = vec![5, 0, 0, 1];
            grant.extend_from_slice(&octets);
            grant.extend_from_slice(&relay_addr.port().to_be_bytes());
            stream.write_all(&grant).expect("grants");
            // The association lives as long as the control connection does, so this thread holds it until the lane is done with the hop.
            let mut sink = [0u8; 64];
            let _ = stream.read(&mut sink);
        });
        std::thread::spawn(move || {
            relay
                .set_read_timeout(Some(Duration::from_secs(60)))
                .expect("times out");
            let mut lane: Option<SocketAddr> = None;
            let mut buf = [0u8; 2048];
            while let Ok((n, from)) = relay.recv_from(&mut buf) {
                match lane {
                    // The lane's first datagram is the one that says so: the association names no destination, so nothing arrives from the edge until the lane has spoken.
                    None => lane = Some(from),
                    Some(lane) if lane == from => {
                        if n < 10 || buf[2] != 0 || buf[3] != 1 {
                            continue;
                        }
                        let ip = [buf[4], buf[5], buf[6], buf[7]];
                        let port = u16::from_be_bytes([buf[8], buf[9]]);
                        let _ = relay.send_to(&buf[10..n], SocketAddr::from((ip, port)));
                    }
                    Some(lane) => {
                        // The edge's answer, framed for the lane the way the lane's own header framed the request.
                        let mut framed = vec![0, 0, 0, 1, 127, 0, 0, 1];
                        framed.extend_from_slice(&edge_port.to_be_bytes());
                        framed.extend_from_slice(&buf[..n]);
                        let _ = relay.send_to(&framed, lane);
                    }
                }
            }
        });
        upstream_proxy(&format!("socks5://127.0.0.1:{proxy_port}")).expect("parses")
    }

    #[test]
    fn the_quic_carrier_rides_a_socks5_upstream_and_carries_the_bytes() {
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let edge_port = sock.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let (uni_tx, uni_rx) = std::sync::mpsc::channel();
        let edge = h3_edge(sock, server, seen_tx, uni_tx, PAYLOAD.to_vec());
        let proxy = socks_relay(edge_port);
        let (client, peer, local) = crate::quic::udp_to_server("127.0.0.1", edge_port)
            .expect("a socket the edge can be addressed from");
        let (relay_control, relay) = associate_udp(&proxy).expect("associates");
        let quic = crate::quic::direct_stream_on(
            crate::quic::Datagram::relayed(client, relay, relay_control),
            peer,
            local,
            "localhost",
            &roots,
        )
        .expect("a connection through the hop");
        let mut dial = dial_for(roots, edge_port, Carrier::H3, foxy::pin::Pins::default());
        dial.upstream = Some(proxy);
        let mut tunnel = Tunnel::open(&dial, "example.com:443", Some(quic)).expect("opens");
        let block = seen_rx
            // The edge's own budget is a minute, so a lane that needs longer than that is a hang and not a slow machine.
            .recv_timeout(Duration::from_secs(60))
            .expect("block");
        let mut want = Vec::new();
        hpack::qpack_connect("example.com:443", "the-pass", &mut want);
        assert_eq!(block, want, "the edge read the block the lane wrote");
        // The opening arrived as well as the request: a relay that dropped the control stream would still carry the request stream, because both travel the same datagrams.
        let uni = uni_rx.recv_timeout(Duration::from_secs(60)).expect("uni");
        let stream = |id| {
            uni.iter()
                .find(|(known, _, _)| *known == id)
                .unwrap_or_else(|| panic!("stream {id} opened"))
        };
        let (_, control, control_fin) = stream(2);
        let mut at = 0usize;
        assert_eq!(control.first(), Some(&0x00), "a control stream type");
        at += 1;
        assert_eq!(control.get(at), Some(&0x04), "one SETTINGS frame");
        at += 1;
        let len = frames::quic_read(control, &mut at).expect("a length") as usize;
        assert_eq!(
            control.len(),
            at + len,
            "a complete SETTINGS, no truncation"
        );
        assert!(!control_fin, "control stays open");
        for (id, first) in [(6u64, 0x02u8), (10, 0x03)] {
            let (_, bytes, fin) = stream(id);
            assert_eq!(bytes.as_slice(), &[first], "qpack stream {id}");
            assert!(!fin, "qpack stream {id} stays open");
        }
        round_trip(&mut tunnel);
        edge.join().expect("joins");
    }

    #[test]
    fn the_http11_carrier_sends_three_fields_and_carries_the_bytes() {
        let (roots, server) = minted(b"http/1.1");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            tls.handshake().expect("handshakes");
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                read_exact(&mut tls, &mut byte).expect("reads the request");
                head.push(byte[0]);
            }
            let request = String::from_utf8(head).expect("ascii");
            assert_eq!(
                request,
                "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Bearer the-pass\r\n\r\n"
            );
            tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .expect("answers");
            let mut buf = [0u8; 64];
            let read = tls.read(&mut buf).expect("reads");
            assert_eq!(&buf[..read], PAYLOAD);
            tls.write_all(&buf[..read]).expect("echoes");
        });
        let dial = dial_for(roots, port, Carrier::H1, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        round_trip(&mut tunnel);
        edge.join().expect("joins");
    }

    /// The no-loss gate for the bulk head walk: an edge that puts the answer and the target's first bytes in one record has to have both reach the relay, in order. A walk that read one byte at a time could not overshoot the delimiter, so nothing in the suite saw this shape before.
    #[test]
    fn the_head_walk_hands_on_the_bytes_the_edge_pipelined_behind_it() {
        let (roots, server) = minted(b"http/1.1");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            tls.handshake().expect("handshakes");
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                read_exact(&mut tls, &mut byte).expect("reads the request");
                request.push(byte[0]);
            }
            let mut reply = b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec();
            reply.extend_from_slice(b"the target speaks first");
            tls.write_all(&reply).expect("answers in one record");
            let mut echoed = [0u8; PAYLOAD.len()];
            assert!(read_exact_poll(&mut tls, &mut echoed), "reads the tunnel");
            tls.write_all(&echoed).expect("echoes");
        });
        let dial = dial_for(roots, port, Carrier::H1, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let mut spoken = [0u8; 23];
        tunnel
            .read_exact(&mut spoken)
            .expect("the pipelined octets come before the socket");
        assert_eq!(&spoken, b"the target speaks first");
        round_trip(&mut tunnel);
        edge.join().expect("joins");
    }

    #[test]
    fn a_rejected_http11_request_is_a_status_not_a_tunnel() {
        let (roots, server) = minted(b"http/1.1");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            tls.handshake().expect("handshakes");
            let mut buf = [0u8; 1024];
            let _ = tls.read(&mut buf);
            tls.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .expect("answers");
            std::thread::sleep(Duration::from_millis(50));
        });
        let dial = dial_for(roots, port, Carrier::H1, foxy::pin::Pins::default());
        assert_eq!(
            Tunnel::open(&dial, "example.com:443", None).err(),
            Some(Failure::Rejected(407))
        );
        assert_eq!(refusal_reply(Failure::Rejected(407)), 0x01);
        edge.join().expect("joins");
    }

    /// Reads exactly `buf` the way a real edge server must: a socket timeout answers `WouldBlock` on macOS under scheduler load and means "nothing yet", not a closed lane, so it is retried until the budget or a genuine close — aborting on the timeout would tear the lane down mid-echo while nothing is wrong.
    fn read_exact_poll<S: Read>(io: &mut S, buf: &mut [u8]) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        let mut at = 0usize;
        while at < buf.len() {
            match io.read(&mut buf[at..]) {
                Ok(0) => return false,
                Ok(read) => at += read,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    if std::time::Instant::now() >= deadline {
                        return false;
                    }
                }
                Err(_) => return false,
            }
        }
        true
    }

    /// The edge side of the HTTP/2 carrier: preface, settings, one stream, one status, then DATA both ways.
    fn h2_edge(
        listener: Listener,
        server: ferrox_core::tls::TlsServerConfig,
        seen: std::sync::mpsc::Sender<Vec<u8>>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            tls.handshake().expect("handshakes");
            let mut head = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut head) {
                return;
            }
            assert_eq!(head, frames::PREFACE);
            let mut ack = Vec::new();
            h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut ack);
            tls.write_all(&ack).ok();
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                match frames::h2_event(frame, &payload, 1) {
                    frames::H2Event::Settings { ack: false, .. } => {
                        let mut out = Vec::new();
                        h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut out);
                        tls.write_all(&out).ok();
                    }
                    frames::H2Event::Headers { block, .. } => {
                        let _ = seen.send(block.to_vec());
                        let mut out = Vec::new();
                        h2_frame(frames::HEADERS, 0x5, 1, &[0x88], &mut out);
                        tls.write_all(&out).ok();
                    }
                    frames::H2Event::Data { payload, .. } => {
                        let mut out = Vec::new();
                        h2_frame(frames::DATA, 0, 1, payload, &mut out);
                        tls.write_all(&out).ok();
                    }
                    _ => {}
                }
            }
        })
    }

    #[test]
    fn the_http2_carrier_writes_one_literal_header_block_and_relays() {
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let _edge = h2_edge(listener, server, seen_tx);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let block = seen_rx
            .recv_timeout(Duration::from_secs(20))
            .expect("block");
        let mut want = Vec::new();
        hpack::hpack_connect("example.com:443", "the-pass", &mut want);
        assert_eq!(block, want, "the edge reads the same block the lane wrote");
        round_trip(&mut tunnel);
    }

    #[test]
    fn the_shared_lane_carries_both_directions_at_once() {
        const BIG: usize = 16 * 1024;
        const STEP: usize = 1024;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, _seen_rx) = std::sync::mpsc::channel();
        let _edge = h2_edge(listener, server, seen_tx);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        tunnel
            .set_read_quantum(Duration::from_millis(5))
            .expect("bounds one read");
        let lane = std::sync::Arc::new(std::sync::Mutex::new(tunnel));
        let sent: Vec<u8> = (0..BIG).map(|i| (i % 251) as u8).collect();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let forward = std::sync::Arc::clone(&lane);
        let chunk = sent.clone();
        std::thread::spawn(move || {
            let mut at = 0usize;
            while at < chunk.len() {
                let end = (at + STEP).min(chunk.len());
                // The guard is bound and dropped before the idle sleep: a guard that lived to the end of the `match` would hold the lane through the sleep, and the writer behind the same mutex would wait it out.
                let mut guard = forward.lock().expect("locks");
                let wrote = match guard.write(&chunk[at..end]) {
                    Ok(0) => 0,
                    Ok(wrote) => wrote,
                    Err(error) => panic!("the write failed: {error}"),
                };
                drop(guard);
                if wrote == 0 {
                    std::thread::sleep(Duration::from_millis(5));
                } else {
                    at += wrote;
                }
            }
            done_tx.send(()).expect("reports");
        });
        let mut back = vec![0u8; BIG];
        let mut at = 0usize;
        while at < BIG {
            // The lane is shared with the writer, so the guard is handed back before the idle sleep: a tight poll that keeps the lane starves the writer behind the same mutex, and the writer is the half that has the bytes to send.
            let mut guard = lane.lock().expect("locks");
            let read = match guard.read(&mut back[at..]) {
                Ok(0) => panic!("the echo ended early"),
                Ok(read) => read,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    0
                }
                Err(error) => panic!("the echo failed: {error}"),
            };
            drop(guard);
            if read == 0 {
                std::thread::sleep(Duration::from_millis(1));
            } else {
                at += read;
            }
        }
        done_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("both directions flow at once");
        assert_eq!(back, sent);
    }

    /// The edge side of a session that outlives its streams: a status on every CONNECT, an echo on the stream it arrived on, and an end for a stream the lane ends.
    fn h2_session_edge(
        listener: Listener,
        server: ferrox_core::tls::TlsServerConfig,
        accepts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || loop {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            accepts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
            let Ok(mut tls) =
                ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
            else {
                continue;
            };
            if tls.handshake().is_err() {
                continue;
            }
            let mut preface = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut preface) || preface != frames::PREFACE {
                continue;
            }
            let mut ack = Vec::new();
            h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut ack);
            tls.write_all(&ack).ok();
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    break;
                }
                let Some(frame) = frames::H2Frame::parse(&header) else {
                    break;
                };
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    break;
                }
                let mut out = Vec::new();
                match frame.kind {
                    frames::SETTINGS if frame.flags & 0x1 == 0 => {
                        h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut out);
                    }
                    frames::HEADERS => {
                        h2_frame(frames::HEADERS, 0x4, frame.stream, &[0x88], &mut out);
                    }
                    frames::DATA => {
                        h2_frame(
                            frames::DATA,
                            frame.flags & frames::END_STREAM,
                            frame.stream,
                            &payload,
                            &mut out,
                        );
                    }
                    _ => {}
                }
                if !out.is_empty() && tls.write_all(&out).is_err() {
                    break;
                }
            }
        })
    }

    #[test]
    fn a_warm_flow_reuses_the_session_its_predecessor_left() {
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let accepts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let _edge = h2_session_edge(listener, server, std::sync::Arc::clone(&accepts));
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut first = Tunnel::open(&dial, "one.test:80", None).expect("opens");
        round_trip(&mut first);
        first
            .set_read_quantum(Duration::from_secs(2))
            .expect("bounds one read");
        first.finish().expect("ends the request half");
        let mut end = [0u8; 1];
        assert_eq!(first.read(&mut end).expect("reads the end"), 0);
        first.settle();
        let mut second = Tunnel::open(&dial, "two.test:80", None).expect("reopens");
        round_trip(&mut second);
        second
            .set_read_quantum(Duration::from_secs(2))
            .expect("bounds one read");
        second.finish().expect("ends the request half");
        assert_eq!(second.read(&mut end).expect("reads the end"), 0);
        second.settle();
        let mut third = Tunnel::open(&dial, "three.test:80", None).expect("reopens again");
        round_trip(&mut third);
        assert_eq!(
            accepts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "every flow after the first rides the session the first opened"
        );
    }

    /// The registry, not a lease: a flow that is still open does not take its session away from the next one.
    #[test]
    fn two_live_flows_ride_one_session() {
        const EACH: usize = 2 * 1024;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let accepts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let _edge = h2_session_edge(listener, server, std::sync::Arc::clone(&accepts));
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut first = Tunnel::open(&dial, "one.test:80", None).expect("opens");
        let mut second =
            Tunnel::open(&dial, "two.test:80", None).expect("opens while the first is live");
        {
            let (Tunnel::H2(one), Tunnel::H2(two)) = (&first, &second) else {
                panic!("two h2 lanes");
            };
            assert_ne!(
                one.stream, two.stream,
                "the second flow took a stream of its own"
            );
        }
        assert_eq!(
            accepts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the second flow dialled the edge again instead of riding the first flow's session"
        );
        let one: Vec<u8> = (0..EACH).map(|i| (i % 251) as u8).collect();
        let two: Vec<u8> = (0..EACH).map(|i| ((i + 7) % 251) as u8).collect();
        first.write_all(&one).expect("writes the first");
        first.flush().expect("flushes the first");
        second.write_all(&two).expect("writes the second");
        second.flush().expect("flushes the second");
        let mut back_one = vec![0u8; EACH];
        let mut back_two = vec![0u8; EACH];
        first.read_exact(&mut back_one).expect("reads the first");
        second.read_exact(&mut back_two).expect("reads the second");
        assert_eq!(back_one, one, "the first flow got its own bytes");
        assert_eq!(back_two, two, "the second flow got its own bytes");
    }

    /// An h2 edge that answers the open, writes the frames handed to it, and then drains until the socket goes quiet.
    fn scripted_h2_edge(
        listener: Listener,
        server: ferrox_core::tls::TlsServerConfig,
        pieces: Vec<Vec<u8>>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            tls.get_ref()
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("times out");
            let mut preface = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut preface) {
                return;
            }
            let mut opening = Vec::new();
            h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut opening);
            h2_frame(frames::HEADERS, 0x4, 1, &[0x88], &mut opening);
            for piece in pieces {
                opening.extend_from_slice(&piece);
            }
            tls.write_all(&opening).expect("writes the script");
            tls.flush().expect("flushes the script");
            loop {
                let mut byte = [0u8; 1];
                match tls.read(&mut byte) {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
            }
        })
    }

    /// On a session two flows share, a flow ends with an empty DATA carrying `END_STREAM` on its own stream: the frame that closes a predecessor's stream must not close the lane that rides the session after it.
    #[test]
    fn a_foreign_stream_s_end_does_not_end_our_lane() {
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let mut foreign = Vec::new();
        h2_frame(frames::DATA, frames::END_STREAM, 3, &[], &mut foreign);
        let edge = scripted_h2_edge(listener, server, vec![foreign, data_frame(b"tail")]);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let Tunnel::H2(lane) = &mut tunnel else {
            panic!("an h2 lane");
        };
        lane.set_read_quantum(Duration::from_millis(20))
            .expect("arms a quantum");
        let mut buf = [0u8; 16];
        let mut back = Vec::new();
        for _ in 0..200 {
            match lane.read(&mut buf) {
                Ok(0) => break,
                Ok(got) => {
                    back.extend_from_slice(&buf[..got]);
                    if back == b"tail" {
                        break;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => panic!("the lane said: {error}"),
            }
        }
        assert_eq!(back, b"tail", "a frame for another stream ended this lane");
        edge.join().expect("joins");
    }

    /// An edge that answers the open, sends one `SETTINGS` after the status has been handed back, and then reports every frame the lane writes as `(kind, flags, length)`.
    fn midflow_settings_edge(
        listener: Listener,
        server: ferrox_core::tls::TlsServerConfig,
        settings: Vec<u8>,
        seen_tx: std::sync::mpsc::Sender<(u8, u8, u32)>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            tls.get_ref()
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("times out");
            let mut preface = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut preface) {
                return;
            }
            let mut opening = Vec::new();
            h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut opening);
            h2_frame(frames::HEADERS, 0x4, 1, &[0x88], &mut opening);
            h2_frame(frames::SETTINGS, 0, 0, &settings, &mut opening);
            tls.write_all(&opening).expect("writes the script");
            tls.flush().expect("flushes the script");
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let Some(frame) = frames::H2Frame::parse(&header) else {
                    return;
                };
                let mut body = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut body) {
                    return;
                }
                if seen_tx
                    .send((frame.kind, frame.flags, frame.length))
                    .is_err()
                {
                    return;
                }
            }
        })
    }

    /// HTTP/2 6.5.3 and 6.9.2: a `SETTINGS` frame arrives whenever the peer likes, bounds every frame sent after it, and is owed an answer.
    #[test]
    fn a_settings_that_arrives_mid_flow_bounds_the_frames_we_send() {
        const BODY: usize = 48 * 1024;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let _edge = midflow_settings_edge(
            listener,
            server,
            vec![0x00, 0x05, 0x00, 0x00, 0x40, 0x00],
            seen_tx,
        );
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let Tunnel::H2(lane) = &mut tunnel else {
            panic!("an h2 lane");
        };
        lane.set_read_quantum(Duration::from_millis(20))
            .expect("arms a quantum");
        let mut peek = [0u8; 16];
        let _ = lane.read(&mut peek);
        assert_eq!(
            lane.test_inner().max_frame,
            16 * 1024,
            "the ask that arrived after the status never moved the lane"
        );
        lane.write_all(&vec![0xa5u8; BODY])
            .expect("writes the body");
        let mut sizes = Vec::new();
        let mut acked = false;
        let mut seen = 0usize;
        for _ in 0..16 {
            match seen_rx.recv_timeout(Duration::from_secs(2)) {
                Ok((frames::SETTINGS, 0x1, 0)) => acked = true,
                Ok((frames::DATA, _, len)) => {
                    sizes.push(len);
                    seen += len as usize;
                }
                Ok(_) => {}
                Err(_) => break,
            }
            if acked && seen >= BODY {
                break;
            }
        }
        assert!(acked, "a SETTINGS the lane read went unacknowledged");
        assert!(
            sizes.iter().all(|len| *len <= 16 * 1024),
            "frames wider than the mid-flow ask: {sizes:?}"
        );
    }

    /// An edge that answers the open with a `PUSH_PROMISE` — ahead of the status, or after it has been handed back — and reports every `RST_STREAM` the lane writes as `(stream, code)`.
    fn push_promise_edge(
        listener: Listener,
        server: ferrox_core::tls::TlsServerConfig,
        promised: u32,
        after_status: bool,
        rst_tx: std::sync::mpsc::Sender<(u32, u32)>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            tls.get_ref()
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("times out");
            let mut preface = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut preface) {
                return;
            }
            let mut promise = promised.to_be_bytes().to_vec();
            promise.push(0x88);
            let mut opening = Vec::new();
            h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut opening);
            if !after_status {
                h2_frame(frames::PUSH_PROMISE, 0x4, 1, &promise, &mut opening);
            }
            h2_frame(frames::HEADERS, 0x4, 1, &[0x88], &mut opening);
            if after_status {
                h2_frame(frames::PUSH_PROMISE, 0x4, 1, &promise, &mut opening);
            }
            opening.extend_from_slice(&data_frame(b"tail"));
            tls.write_all(&opening).expect("writes the script");
            tls.flush().expect("flushes the script");
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let Some(frame) = frames::H2Frame::parse(&header) else {
                    return;
                };
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                if frame.kind == frames::RST_STREAM
                    && rst_tx.send((frame.stream, frames::be32(&payload))).is_err()
                {
                    return;
                }
            }
        })
    }

    /// Reads the edge's four bytes through `lane`, then asserts every `RST_STREAM` it wrote refused `promised` with `REFUSED_STREAM`.
    fn the_push_is_refused_on(
        lane: &mut Tls2,
        promised: u32,
        rst_rx: &std::sync::mpsc::Receiver<(u32, u32)>,
    ) {
        lane.set_read_quantum(Duration::from_millis(20))
            .expect("arms a quantum");
        let mut buf = [0u8; 16];
        let mut back = Vec::new();
        for _ in 0..200 {
            match lane.read(&mut buf) {
                Ok(0) => break,
                Ok(got) => {
                    back.extend_from_slice(&buf[..got]);
                    if back == b"tail" {
                        break;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => panic!("the lane said: {error}"),
            }
        }
        assert_eq!(back, b"tail", "refusing the push ended the lane's own flow");
        let mut refused = Vec::new();
        while let Ok(one) = rst_rx.recv_timeout(Duration::from_millis(200)) {
            refused.push(one);
        }
        assert_eq!(
            refused,
            vec![(promised, 7)],
            "the push was not refused on the stream it promised, with `REFUSED_STREAM`"
        );
    }

    /// An edge that answers the open with its status and a body it never ends, reporting every `RST_STREAM` the lane writes as `(stream, code)`.
    fn abort_edge(
        listener: Listener,
        server: ferrox_core::tls::TlsServerConfig,
        rst_tx: std::sync::mpsc::Sender<(u32, u32)>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            tls.get_ref()
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("times out");
            let mut preface = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut preface) {
                return;
            }
            let mut opening = Vec::new();
            h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut opening);
            h2_frame(frames::HEADERS, 0x4, 1, &[0x88], &mut opening);
            opening.extend_from_slice(&data_frame(b"four"));
            tls.write_all(&opening).expect("writes the script");
            tls.flush().expect("flushes the script");
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let Some(frame) = frames::H2Frame::parse(&header) else {
                    return;
                };
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                if frame.kind == frames::RST_STREAM
                    && rst_tx.send((frame.stream, frames::be32(&payload))).is_err()
                {
                    return;
                }
            }
        })
    }

    /// HTTP/2 8.1: a flow that stops before its stream ends is reset, because an edge left unreset keeps fetching the response into a window nobody drains, charged to the account.
    #[test]
    fn a_flow_abandoned_mid_response_resets_its_stream() {
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (rst_tx, rst_rx) = std::sync::mpsc::channel();
        let _edge = abort_edge(listener, server, rst_tx);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let Tunnel::H2(lane) = &mut tunnel else {
            panic!("an h2 lane");
        };
        lane.set_read_quantum(Duration::from_millis(20))
            .expect("arms a quantum");
        let mut buf = [0u8; 16];
        let mut back = Vec::new();
        for _ in 0..200 {
            match lane.read(&mut buf) {
                Ok(0) => break,
                Ok(took) => {
                    back.extend_from_slice(&buf[..took]);
                    if back == b"four" {
                        break;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => panic!("the lane said: {error}"),
            }
        }
        assert_eq!(back, b"four", "the status body did not arrive");
        tunnel.settle();
        assert_eq!(
            rst_rx.recv_timeout(Duration::from_secs(2)),
            Ok((1, 8)),
            "the abandoned flow left its stream open, so the edge keeps sending into it"
        );
    }

    /// HTTP/2 8.2: a push is refused on the stream it promises, with `REFUSED_STREAM`, and the stream the tunnel opened stays open.
    #[test]
    fn a_push_promise_is_refused_on_the_stream_it_promises() {
        const PROMISED: u32 = 2;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (rst_tx, rst_rx) = std::sync::mpsc::channel();
        let _edge = push_promise_edge(listener, server, PROMISED, false, rst_tx);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let Tunnel::H2(lane) = &mut tunnel else {
            panic!("an h2 lane");
        };
        the_push_is_refused_on(lane, PROMISED, &rst_rx);
    }

    /// A promise the lane meets after the status is refused the same way: the reader that takes it is not the open's own walk, so the refusal has to live where every stream's read passes.
    #[test]
    fn a_push_promise_after_the_status_is_refused_too() {
        const PROMISED: u32 = 2;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (rst_tx, rst_rx) = std::sync::mpsc::channel();
        let _edge = push_promise_edge(listener, server, PROMISED, true, rst_tx);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let Tunnel::H2(lane) = &mut tunnel else {
            panic!("an h2 lane");
        };
        the_push_is_refused_on(lane, PROMISED, &rst_rx);
    }

    /// The read quantum is what lets the writer behind the same mutex have a turn, so it must not cost the frame: a pause inside one DATA frame has to resume where it stopped, not abandon the bytes already promised to the header.
    #[test]
    fn a_frame_that_straddles_a_read_quantum_arrives_whole() {
        const BODY: usize = 32 * 1024;
        const HALF: usize = BODY / 2;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            tls.get_ref()
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("times out");
            let mut preface = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut preface) {
                return;
            }
            let mut ack = Vec::new();
            h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut ack);
            tls.write_all(&ack).ok();
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                if matches!(
                    frames::h2_event(frame, &payload, 1),
                    frames::H2Event::Headers { .. }
                ) {
                    break;
                }
            }
            let mut status = Vec::new();
            h2_frame(frames::HEADERS, 0x5, 1, &[0x88], &mut status);
            tls.write_all(&status).expect("answers 200");
            let body: Vec<u8> = (0..BODY).map(|i| (i % 251) as u8).collect();
            std::thread::sleep(Duration::from_millis(200));
            let head = frames::H2Frame {
                kind: frames::DATA,
                flags: 0,
                stream: 1,
                length: BODY as u32,
            }
            .header();
            // One frame, two writes: the second lands only after the lane's quantum has expired inside the first.
            tls.write_all(&head).expect("writes the header");
            tls.write_all(&body[..HALF]).expect("writes the first half");
            tls.flush().expect("flushes the first half");
            std::thread::sleep(Duration::from_millis(300));
            tls.write_all(&body[HALF..]).expect("writes the tail");
            tls.flush().expect("flushes the tail");
        });
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        tunnel
            .set_read_quantum(Duration::from_millis(20))
            .expect("bounds one read");
        let mut back = Vec::new();
        let mut buf = [0u8; 4096];
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while back.len() < BODY && std::time::Instant::now() < deadline {
            match tunnel.read(&mut buf) {
                Ok(0) => panic!("the lane called an end of stream inside a frame"),
                Ok(read) => back.extend_from_slice(&buf[..read]),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("the lane lost the frame: {error}"),
            }
        }
        let want: Vec<u8> = (0..BODY).map(|i| (i % 251) as u8).collect();
        assert_eq!(
            back, want,
            "a quantum inside a frame must not drop its tail"
        );
        edge.join().expect("the edge finishes");
    }

    /// An edge the lane let go of must finish on the reset it was sent, not on the poll deadline a pooled session would otherwise leave it waiting out.
    fn join_edge_within(edge: std::thread::JoinHandle<()>, budget: Duration) {
        let began = Instant::now();
        while !edge.is_finished() {
            assert!(
                began.elapsed() < budget,
                "the edge waited {:?} for its poll deadline instead of the reset",
                began.elapsed()
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        edge.join().expect("the edge finishes");
    }

    /// An edge that names a 16 KiB `SETTINGS_MAX_FRAME_SIZE` for its own receives, answers the status, then pushes each piece and drains what the lane sends back until the socket ends.
    fn narrow_receive_edge(
        listener: Listener,
        server: ferrox_core::tls::TlsServerConfig,
        pieces: Vec<Vec<u8>>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            // The poll clock is for the reads after the handshake: armed before it, a 50 ms gap between records on a loaded runner aborts the handshake and the lane's open spends its head budget before the retry (Windows over 60 s in three runs).
            tls.get_ref()
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("times out");
            let mut preface = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut preface) {
                return;
            }
            let mut setting = Vec::new();
            setting.extend_from_slice(&5u16.to_be_bytes());
            setting.extend_from_slice(&(16 * 1024u32).to_be_bytes());
            let mut opening = Vec::new();
            h2_frame(frames::SETTINGS, 0, 0, &setting, &mut opening);
            h2_frame(frames::HEADERS, 0x4, 1, &[0x88], &mut opening);
            tls.write_all(&opening).expect("answers the status");
            tls.flush().expect("flushes");
            for piece in pieces {
                tls.write_all(&piece).expect("pushes");
                tls.flush().expect("flushes");
            }
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut rest = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut rest) {
                    return;
                }
                // The lane resets its stream on drop while the pooled session stays open, so the reset is the edge's end.
                if frame.kind == frames::RST_STREAM {
                    return;
                }
            }
        })
    }

    /// The size an edge may *send* is the one this lane asked for in its own SETTINGS, not the one the edge asked for, so a 32 KiB trailer from an edge that named a 16 KiB limit is read whole instead of leaving its tail to be parsed as the next frame's header.
    #[test]
    fn a_frame_wider_than_the_edge_s_own_send_limit_is_read_whole() {
        const TRAILER: usize = 32 * 1024;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let mut trailer = Vec::new();
        h2_frame(frames::HEADERS, 0x4, 1, &vec![0xa5; TRAILER], &mut trailer);
        let pieces = vec![trailer, data_frame(b"tail")];
        let edge = narrow_receive_edge(listener, server, pieces);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let Tunnel::H2(lane) = &mut tunnel else {
            panic!("an h2 lane");
        };
        assert_eq!(
            lane.test_inner().max_frame,
            16 * 1024,
            "the edge's own limit is what the lane sends by"
        );
        tunnel
            .set_read_quantum(Duration::from_millis(20))
            .expect("bounds one read");
        let mut back = Vec::new();
        let mut buf = [0u8; 4096];
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while back.len() < 4 && std::time::Instant::now() < deadline {
            match tunnel.read(&mut buf) {
                Ok(0) => panic!("the lane called an end of stream before the body arrived"),
                Ok(read) => back.extend_from_slice(&buf[..read]),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("the lane lost the frame: {error}"),
            }
        }
        assert_eq!(
            back, b"tail",
            "the octets past the edge's own limit became the next frame's header"
        );
        drop(tunnel);
        join_edge_within(edge, Duration::from_secs(5));
    }

    /// A length the lane never asked for is refused before it is believed: the frame buffer is never sized by a header a peer invented, so the widest body the lane will hold is the 256 KiB its own SETTINGS named.
    #[test]
    fn a_frame_wider_than_the_lane_ever_asked_for_is_refused_not_allocated() {
        const OVER: usize = frames::MAX_FRAME as usize + 1024;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        // The header of a frame this wide, and no body at all: the lane is asked to wait for OVER octets it must not promise room for.
        let head = frames::H2Frame {
            kind: frames::HEADERS,
            flags: 0x4,
            stream: 1,
            length: OVER as u32,
        }
        .header()
        .to_vec();
        let edge = narrow_receive_edge(listener, server, vec![head]);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let Tunnel::H2(lane) = &mut tunnel else {
            panic!("an h2 lane");
        };
        lane.set_read_quantum(Duration::from_millis(20))
            .expect("bounds one read");
        let staged = lane.test_inner().out.capacity();
        let mut buf = [0u8; 4096];
        let error = (0..20)
            .find_map(|_| match lane.read(&mut buf) {
                Ok(0) => Some(std::io::Error::other("the lane called an end of stream")),
                Ok(_) => None,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    None
                }
                Err(error) => Some(error),
            })
            .expect("a refusal, not a wait");
        assert!(
            error.to_string().contains("wider than the lane"),
            "the lane said: {error}"
        );
        assert_eq!(
            lane.test_inner().out.capacity(),
            staged,
            "the frame's own length was never used to size a buffer"
        );
        drop(tunnel);
        join_edge_within(edge, Duration::from_secs(5));
    }

    /// The census line for a leg parked at a named wait, waited for: a moment spent is not evidence the leg parked, and a flow that never reached its wait hands its lane back for free.
    fn wait_for_leg(name: &str, leg: std::thread::ThreadId, budget: Duration) {
        let began = Instant::now();
        while crate::census::held(name, leg).is_none() {
            assert!(
                began.elapsed() < budget,
                "the leg never parked in `{name}` after {:?}:\n{}",
                began.elapsed(),
                crate::census::dump()
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// A flow's forward leg is parked in a blocking read on the client, so the end of a flow has to wake that read: a leg that never wakes keeps its pool worker, its lane and the lane's buffers for the life of the process.
    #[test]
    fn a_lane_that_ends_releases_the_leg_parked_on_its_client() {
        const PARK: Duration = Duration::from_secs(10);
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (close_tx, close_rx) = std::sync::mpsc::channel::<()>();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            tls.get_ref()
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("times out");
            let mut preface = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut preface) {
                return;
            }
            let mut ack = Vec::new();
            h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut ack);
            tls.write_all(&ack).ok();
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                if matches!(
                    frames::h2_event(frame, &payload, 1),
                    frames::H2Event::Headers { .. }
                ) {
                    break;
                }
            }
            let mut status = Vec::new();
            h2_frame(frames::HEADERS, 0x5, 1, &[0x88], &mut status);
            tls.write_all(&status).expect("answers 200");
            let _ = close_rx.recv();
        });
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        tunnel
            .set_read_quantum(Duration::from_millis(5))
            .expect("bounds one read");
        let lane = Arc::new(std::sync::Mutex::new(tunnel));
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let _browser = Connection::connect(front.local_addr().expect("addr")).expect("connects");
        let (client, _) = front.accept().expect("accepts");
        let (ended_tx, ended_rx) = std::sync::mpsc::channel::<()>();
        let flow_lane = Arc::clone(&lane);
        let flow = std::thread::spawn(move || {
            crate::proxy::relay_tunnel(&client, &flow_lane);
            let _ = ended_tx.send(());
        });
        // The leg has to be parked before the lane ends, or the test measures a flow that never started.
        wait_for_leg("tunnel-leg-read", flow.thread().id(), PARK);
        close_tx.send(()).expect("ends the edge");
        edge.join().expect("the edge finishes");
        ended_rx
            .recv_timeout(PARK)
            .expect("the flow ends when its lane is gone");
    }

    /// The other half of the same promise: a client that says goodbye while its lane stays open has ended the flow, so the leg parked reading that lane has to come back rather than hold the lane, its stream and the flow's own thread for the life of the process.
    #[test]
    fn a_client_that_ends_releases_the_leg_parked_on_its_lane() {
        const PARK: Duration = Duration::from_secs(10);
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        // The edge answers, then holds the stream open the way a keep-alive target does: nothing on the lane ends this flow.
        let (hold_tx, hold_rx) = std::sync::mpsc::channel::<()>();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            tls.get_ref()
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("times out");
            let mut preface = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut preface) {
                return;
            }
            let mut ack = Vec::new();
            h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut ack);
            tls.write_all(&ack).ok();
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                if matches!(
                    frames::h2_event(frame, &payload, 1),
                    frames::H2Event::Headers { .. }
                ) {
                    break;
                }
            }
            let mut status = Vec::new();
            h2_frame(frames::HEADERS, 0x5, 1, &[0x88], &mut status);
            tls.write_all(&status).expect("answers 200");
            let _ = hold_rx.recv();
        });
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        tunnel
            .set_read_quantum(Duration::from_millis(5))
            .expect("bounds one read");
        let lane = Arc::new(std::sync::Mutex::new(tunnel));
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let browser = Connection::connect(front.local_addr().expect("addr")).expect("connects");
        let (client, _) = front.accept().expect("accepts");
        let (ended_tx, ended_rx) = std::sync::mpsc::channel::<()>();
        let flow_lane = Arc::clone(&lane);
        let flow = std::thread::spawn(move || {
            crate::proxy::relay_tunnel(&client, &flow_lane);
            let _ = ended_tx.send(());
        });
        // The leg has to be parked on the lane before the client goes, or the test measures a flow that never started.
        wait_for_leg("tunnel-leg-read", flow.thread().id(), PARK);
        browser
            .shutdown(std::net::Shutdown::Write)
            .expect("the client says goodbye");
        ended_rx
            .recv_timeout(PARK)
            .expect("the flow ends when its client says goodbye");
        hold_tx.send(()).expect("the edge is released");
        edge.join().expect("the edge finishes");
    }

    /// The edge of a parked lane: it answers the open in its carrier's own shape, then says nothing — the quiet keep-alive target — and counts every unit that comes up.
    fn quiet_edge(
        carrier: Carrier,
        listener: Listener,
        server: ferrox_core::tls::TlsServerConfig,
        arrived_tx: std::sync::mpsc::Sender<u8>,
    ) -> std::thread::JoinHandle<()> {
        let framed = matches!(carrier, Carrier::H2);
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            tls.get_ref()
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("times out");
            let mut opening = Vec::new();
            if framed {
                let mut preface = vec![0u8; frames::PREFACE.len()];
                if !read_exact_poll(&mut tls, &mut preface) {
                    return;
                }
                h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut opening);
                h2_frame(frames::HEADERS, 0x5, 1, &[0x88], &mut opening);
            } else {
                let mut request = Vec::new();
                let mut byte = [0u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    if !read_exact_poll(&mut tls, &mut byte) {
                        return;
                    }
                    request.push(byte[0]);
                }
                opening.extend_from_slice(b"HTTP/1.1 200 Connection established\r\n\r\n");
            }
            tls.write_all(&opening).expect("answers 200");
            tls.flush().expect("flushes");
            let mut seen = 0u8;
            loop {
                let mut ended = false;
                if framed {
                    let mut header = [0u8; frames::H2_HEADER];
                    if !read_exact_poll(&mut tls, &mut header) {
                        return;
                    }
                    let frame = frames::H2Frame::parse(&header).expect("parses");
                    let mut payload = vec![0u8; frame.length as usize];
                    if !read_exact_poll(&mut tls, &mut payload) {
                        return;
                    }
                    if frame.kind == frames::RST_STREAM {
                        return;
                    }
                    if frame.kind != frames::DATA {
                        continue;
                    }
                    ended = frame.flags & frames::END_STREAM != 0;
                } else {
                    let mut byte = [0u8; 1];
                    if !read_exact_poll(&mut tls, &mut byte) {
                        return;
                    }
                }
                seen += 1;
                if arrived_tx.send(seen).is_err() {
                    return;
                }
                if framed && ended {
                    return;
                }
            }
        })
    }

    /// The wait a parked downlink leg takes is not the uplink's: the lane's lock comes back before the leg waits, so a browser's first byte after a quiet edge does not pay for that quiet. Both TCP carriers arm the same way, so the same flow runs on each. The wait is armed far wider than production's 100 ms quantum on purpose — a stall this test looks for is the wait itself, and a 500 ms hold with a 100 ms budget would leave it room to hide — and the reach sits just under it, so a loaded machine's scheduling delay does not read as the wait.
    #[test]
    fn a_parked_downlink_leg_does_not_hold_the_uplink_behind_its_wait() {
        const WAIT: Duration = Duration::from_millis(500);
        const REACH: Duration = Duration::from_millis(400);
        const BYTES: u8 = 4;
        for (carrier, alpn) in [(Carrier::H2, &b"h2"[..]), (Carrier::H1, &b"http/1.1"[..])] {
            let (roots, server) = minted(alpn);
            let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
            let port = listener.local_addr().expect("addr").port();
            let (arrived_tx, arrived_rx) = std::sync::mpsc::channel::<u8>();
            let edge = quiet_edge(carrier, listener, server, arrived_tx);
            let dial = dial_for(roots, port, carrier, foxy::pin::Pins::default());
            let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
            tunnel.set_relay_quantum(WAIT).expect("bounds one wait");
            let lane = Arc::new(std::sync::Mutex::new(tunnel));
            let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
            let mut browser =
                Connection::connect(front.local_addr().expect("addr")).expect("connects");
            let (client, _) = front.accept().expect("accepts");
            let flow_lane = Arc::clone(&lane);
            let relay = std::thread::spawn(move || {
                crate::proxy::relay_tunnel(&client, &flow_lane);
            });
            // The downlink leg has to be parked before the first byte goes up, or the test measures a flow that never waited.
            wait_for_leg("downlink-park", relay.thread().id(), WAIT * 4);
            let started = Instant::now();
            for byte in 1..=BYTES {
                browser
                    .write_all(&[b'a' + byte])
                    .expect("the browser speaks");
                assert_eq!(
                    arrived_rx
                        .recv_timeout(WAIT * 4)
                        .expect("the byte reaches the edge"),
                    byte,
                    "the {carrier:?} uplink lost a byte, so the edge counted a different one"
                );
            }
            let reached = started.elapsed();
            assert!(
                reached < REACH,
                "{BYTES} {carrier:?} uplink bytes waited {reached:?} for a lane its parked downlink leg was holding"
            );
            drop(browser);
            let _ = relay.join();
            // The relay's own handle is only one of two: the lane closes when the test lets go of it too, and the edge is waiting on that.
            drop(lane);
            let _ = edge.join();
        }

        // The QUIC carrier parks the same way, on its lane's datagram socket: the edge owes the downlink only after the uplink has paid for it, so the leg that reads the answer is parked before a byte goes up.
        {
            let (roots, server) = minted(b"h3");
            let sock = crate::quic::Datagram::plain(
                crate::quic::bind_datagram("127.0.0.1:0").expect("binds"),
            );
            let port = sock.local_addr().expect("addr").port();
            let (seen_tx, seen_rx) = std::sync::mpsc::channel();
            let (uni_tx, _uni_rx) = std::sync::mpsc::channel();
            let edge = h3_edge(sock, server, seen_tx, uni_tx, PAYLOAD.to_vec());
            let dial = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
            let quic = crate::quic::direct_stream("localhost", "127.0.0.1", port, &dial.roots)
                .expect("a connection");
            let mut tunnel = Tunnel::open(&dial, "example.com:443", Some(quic)).expect("opens");
            tunnel.set_relay_quantum(WAIT).expect("bounds one wait");
            seen_rx
                .recv_timeout(Duration::from_secs(30))
                .expect("the edge read the block");
            let lane = Arc::new(std::sync::Mutex::new(tunnel));
            let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
            let mut browser =
                Connection::connect(front.local_addr().expect("addr")).expect("connects");
            let (client, _) = front.accept().expect("accepts");
            let flow_lane = Arc::clone(&lane);
            let relay = std::thread::spawn(move || {
                crate::proxy::relay_tunnel(&client, &flow_lane);
            });
            wait_for_leg("downlink-park", relay.thread().id(), WAIT * 4);
            let started = Instant::now();
            browser.write_all(PAYLOAD).expect("the browser speaks");
            browser
                .set_read_timeout(Some(WAIT * 4))
                .expect("bounds the read");
            let mut got = [0u8; PAYLOAD.len()];
            browser.read_exact(&mut got).expect("the echo returns");
            let reached = started.elapsed();
            assert_eq!(got, PAYLOAD, "the QUIC round trip moved other bytes");
            assert!(
                reached < REACH,
                "a QUIC downlink waited {reached:?} behind its own parked leg"
            );
            drop(browser);
            let _ = relay.join();
            drop(lane);
            let _ = edge.join();
        }
    }

    /// The lane is the flow's shared resource: the leg that hands bytes to the client has to give the lane back before it waits on the socket, or a client that has stopped reading costs its own upload the road it came in on.
    #[test]
    fn a_client_that_has_stopped_reading_does_not_cost_the_flow_its_lane() {
        const CHUNK: usize = 16 * 1024;
        const PARK: Duration = Duration::from_secs(10);
        const WAKE: Duration = Duration::from_millis(300);
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        // The edge answers, then pushes a download past what a client that never reads can queue: 4 MiB, several times the loopback queue a parked leg leaves behind.
        let (close_tx, close_rx) = std::sync::mpsc::channel::<()>();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            tls.get_ref()
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("times out");
            // Past the 300 ms the test polls at, so the edge is still parked on its push while the lane is asked for its lock.
            tls.get_ref()
                .set_write_timeout(Some(Duration::from_millis(800)))
                .expect("write times out");
            let mut preface = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut preface) {
                return;
            }
            let mut ack = Vec::new();
            h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut ack);
            tls.write_all(&ack).ok();
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                if matches!(
                    frames::h2_event(frame, &payload, 1),
                    frames::H2Event::Headers { .. }
                ) {
                    break;
                }
            }
            let mut status = Vec::new();
            h2_frame(frames::HEADERS, 0x5, 1, &[0x88], &mut status);
            tls.write_all(&status).expect("answers 200");
            let body = vec![0xA5u8; CHUNK];
            for _ in 0..256 {
                if close_rx.try_recv().is_ok() {
                    return;
                }
                let mut out = Vec::new();
                h2_frame(frames::DATA, 0, 1, &body, &mut out);
                if tls.write_all(&out).is_err() {
                    return;
                }
            }
            let _ = close_rx.recv();
        });
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        tunnel
            .set_read_quantum(Duration::from_millis(5))
            .expect("bounds one read");
        let lane = Arc::new(std::sync::Mutex::new(tunnel));
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        // The browser asks for the flow and then never reads a byte, which is the whole of a stalled download from the relay's side.
        let browser = Connection::connect(front.local_addr().expect("addr")).expect("connects");
        let (client, _) = front.accept().expect("accepts");
        let (ended_tx, ended_rx) = std::sync::mpsc::channel::<()>();
        let flow_lane = Arc::clone(&lane);
        let (leg_tx, leg_rx) = std::sync::mpsc::channel::<std::thread::ThreadId>();
        std::thread::spawn(move || {
            let _ = leg_tx.send(std::thread::current().id());
            crate::proxy::relay_tunnel(&client, &flow_lane);
            let _ = ended_tx.send(());
        });
        // The leg has to be parked on the client's socket before the lane is asked for.
        let leg = leg_rx.recv().expect("the leg names itself");
        wait_for_leg("tunnel-leg-write", leg, PARK);
        let started = Instant::now();
        let handed_back = loop {
            if lane.try_lock().is_ok() {
                break true;
            }
            if started.elapsed() >= WAKE {
                break false;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(
            handed_back,
            "the leg parked writing a client that never reads is still holding the lane"
        );
        drop(browser);
        close_tx.send(()).ok();
        ended_rx
            .recv_timeout(PARK)
            .expect("the flow ends with its client");
        edge.join().expect("the edge finishes");
    }

    /// A lane whose peer is gone never says so to a writer that has no credit left: the window check answers before the socket is touched, so a leg parked on a stalled upload ends only when the other direction reports it is done.
    #[test]
    fn a_lane_that_dies_while_the_upload_is_parked_ends_the_flow() {
        const CHUNK: usize = 16 * 1024;
        const PARK: Duration = Duration::from_secs(10);
        const WAKE: Duration = Duration::from_millis(500);
        // One chunk past the credit the edge grants, so the last write is the one that cannot go through.
        const UPLOAD: usize = frames::DEFAULT_WINDOW as usize + CHUNK;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel::<usize>();
        // The edge reads the whole credit, grants none of it back, and hangs up once it has had every byte the lane is allowed to send.
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            tls.get_ref()
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("times out");
            let mut preface = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut preface) {
                return;
            }
            let mut ack = Vec::new();
            h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut ack);
            tls.write_all(&ack).ok();
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                if matches!(
                    frames::h2_event(frame, &payload, 1),
                    frames::H2Event::Headers { .. }
                ) {
                    break;
                }
            }
            let mut status = Vec::new();
            h2_frame(frames::HEADERS, 0x5, 1, &[0x88], &mut status);
            tls.write_all(&status).expect("answers 200");
            // The edge reads the credit it granted and gives none of it back, then hangs up on the lane that still has a chunk to send.
            let mut credit = 0usize;
            while credit < frames::DEFAULT_WINDOW as usize {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                if frame.kind == frames::DATA {
                    credit += payload.len();
                    let _ = seen_tx.send(payload.len());
                }
            }
        });
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        tunnel
            .set_read_quantum(Duration::from_millis(5))
            .expect("bounds one read");
        let lane = Arc::new(std::sync::Mutex::new(tunnel));
        let front = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = front.local_addr().expect("addr");
        // The upload leaves the client's socket before the lane stops taking it, so the leg's only wait is the lane.
        let browser = std::thread::spawn(move || {
            let mut socket = Connection::connect(addr).expect("connects");
            let body = vec![0x5Au8; CHUNK];
            for _ in 0..UPLOAD / CHUNK {
                if socket.write_all(&body).is_err() {
                    return;
                }
            }
        });
        let (client, _) = front.accept().expect("accepts");
        let (ended_tx, ended_rx) = std::sync::mpsc::channel::<()>();
        let flow_lane = Arc::clone(&lane);
        std::thread::spawn(move || {
            crate::proxy::relay_tunnel(&client, &flow_lane);
            let _ = ended_tx.send(());
        });
        let mut credit = 0usize;
        while credit < frames::DEFAULT_WINDOW as usize {
            credit += seen_rx
                .recv_timeout(PARK)
                .expect("the edge keeps reading what the lane sends");
        }
        ended_rx
            .recv_timeout(WAKE)
            .expect("the upload parked on a dead lane is still holding its workers");
        browser.join().expect("the browser finishes");
        edge.join().expect("the edge finishes");
    }

    /// An upload is paced by what the edge grants, not by what the lane reads back: this edge answers no payload at all and grants exactly the credit it consumes, so a lane that spends credit on inbound DATA rather than on the edge's `WINDOW_UPDATE` frames stops partway and a lane that reads them finishes the body.
    #[test]
    fn an_upload_is_paced_by_the_grants_the_edge_sends_rather_than_by_the_bytes_it_reads() {
        const GRANT: u32 = 32 * 1024;
        const CHUNK: usize = 16 * 1024;
        // Wider than either window the lane starts with, so the body only leaves if both the stream and the connection credit are refilled.
        const UPLOAD: usize = 8 * GRANT as usize;
        const PARK: Duration = Duration::from_secs(30);
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel::<usize>();
        // A consuming edge: it reads every frame, answers with a grant per payload, and never sends a payload of its own.
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            tls.get_ref()
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("times out");
            let mut preface = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut preface) {
                return;
            }
            let mut opening = Vec::new();
            let mut settings = Vec::new();
            settings.extend_from_slice(&4u16.to_be_bytes());
            settings.extend_from_slice(&GRANT.to_be_bytes());
            h2_frame(frames::SETTINGS, 0, 0, &settings, &mut opening);
            h2_frame(frames::HEADERS, 0x4, 1, &[0x88], &mut opening);
            tls.write_all(&opening).expect("advertises and answers");
            let mut taken = 0usize;
            while taken < UPLOAD {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                if frame.kind != frames::DATA {
                    continue;
                }
                taken += payload.len();
                let _ = seen_tx.send(payload.len());
                let increment = (payload.len() as u32).to_be_bytes();
                let mut grant = Vec::new();
                h2_frame(frames::WINDOW_UPDATE, 0, 1, &increment, &mut grant);
                h2_frame(frames::WINDOW_UPDATE, 0, 0, &increment, &mut grant);
                tls.write_all(&grant).expect("grants what it took");
            }
        });
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        tunnel
            .set_read_quantum(Duration::from_millis(5))
            .expect("bounds one read");
        let body = vec![0x5Au8; CHUNK];
        let mut wrote = 0usize;
        let mut probe = [0u8; 8];
        let by = Instant::now() + PARK;
        while wrote < UPLOAD {
            assert!(
                Instant::now() < by,
                "the upload stopped at {wrote} of {UPLOAD} bytes"
            );
            match tunnel.write(&body) {
                Ok(0) => {
                    // The credit only arrives as a frame, so the way to earn it back is to read the lane.
                    let _ = tunnel.read(&mut probe);
                }
                Ok(written) => wrote += written,
                Err(error) => panic!("the lane ended the upload: {error}"),
            }
        }
        let mut arrived = 0usize;
        while arrived < UPLOAD {
            arrived += seen_rx
                .recv_timeout(PARK)
                .expect("the edge keeps taking what the lane sends");
        }
        assert_eq!(arrived, UPLOAD);
        edge.join().expect("the edge finishes");
    }

    /// A byte-level test cannot see a copy, so capacity is the witness: `out` is the write buffer and `carry` the read one, and a lane that stages a payload before handing it over has grown the buffer it staged in.
    #[test]
    fn a_relayed_byte_is_copied_once_on_its_way_through_the_lane() {
        const BIG: usize = 40 * 1024;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, _seen_rx) = std::sync::mpsc::channel();
        let _edge = h2_edge(listener, server, seen_tx);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let Tunnel::H2(lane) = &mut tunnel else {
            panic!("an h2 lane");
        };
        let sent: Vec<u8> = (0..BIG).map(|i| (i % 251) as u8).collect();
        let staged = lane.test_inner().out.capacity();
        let mut wrote = 0usize;
        while wrote < sent.len() {
            match lane.write(&sent[wrote..]) {
                Ok(0) => panic!("a lane that stops writing"),
                Ok(advanced) => wrote += advanced,
                Err(error) => panic!("the write failed: {error}"),
            }
        }
        lane.flush().expect("flushes");
        assert_eq!(
            lane.test_inner().out.capacity(),
            staged,
            "the payload went into the record, not into a staging buffer"
        );
        // A read hands the frame payload straight to the caller's buffer: what is staged is only what the caller's buffer had no room for.
        let mut back = vec![0u8; BIG];
        let mut read = 0usize;
        while read < BIG {
            read += lane.read(&mut back[read..]).expect("reads");
        }
        assert_eq!(back, sent, "the bytes are the bytes either way");
        assert_eq!(
            lane.test_stream(|s| s.carry.capacity()),
            0,
            "nothing was staged"
        );
        assert_eq!(
            lane.test_stream(|s| s.at),
            0,
            "the read cursor is where it started"
        );
    }

    /// A loopback HTTP/1.1 edge that answers the RFC 9298 upgrade and echoes the first datagram back in one capsule.
    fn masque_h1_edge(
        listener: Listener,
        server: ferrox_core::tls::TlsServerConfig,
        seen: std::sync::mpsc::Sender<Vec<u8>>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            let request = read_head(&mut tls);
            seen.send(request.into_bytes()).expect("reports the head");
            tls.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n",
            )
            .expect("answers the upgrade");
            tls.flush().expect("flushes the answer");
            let mut stream = Vec::new();
            let mut window = [0u8; 1024];
            loop {
                let read = match tls.read(&mut window) {
                    Ok(0) | Err(_) => return,
                    Ok(read) => read,
                };
                stream.extend_from_slice(&window[..read]);
                if let Some((_, datagram)) = masque::datagram_split(&stream) {
                    let mut echo = Vec::new();
                    masque::datagram_encode(datagram, &mut echo);
                    tls.write_all(&echo).expect("echoes");
                    tls.flush().expect("flushes the echo");
                    // The echo is not the end of the edge: the lane must find it still there after the capsule.
                    std::thread::sleep(Duration::from_millis(250));
                    return;
                }
            }
        })
    }

    #[test]
    fn the_h1_carrier_opens_connect_udp_and_echoes_a_datagram() {
        let (roots, server) = minted(b"http/1.1");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let edge = masque_h1_edge(listener, server, seen_tx);
        let dial = dial_for(roots, port, Carrier::H1, foxy::pin::Pins::default());
        let mut lane = open_udp_h1(&dial, "example.com", 443).expect("opens");
        let request = seen_rx.recv_timeout(Duration::from_secs(20)).expect("head");
        let text = String::from_utf8_lossy(&request);
        for field in [
            "GET https://localhost:",
            "/.well-known/masque/udp/example.com/443/",
            "Upgrade: connect-udp",
            "Capsule-Protocol: ?1",
            "Proxy-Authorization: Bearer the-pass",
        ] {
            assert!(text.contains(field), "missing {field}");
        }
        lane.write_datagram(b"hello udp").expect("writes");
        lane.set_read_quantum(Duration::from_secs(5))
            .expect("bounds a read");
        let mut back = [0u8; 64];
        let mut at = 0usize;
        while at < b"hello udp".len() {
            match lane.read_datagram(&mut back[at..]) {
                Ok(0) => panic!("the echo ended early"),
                Ok(read) => at += read,
                Err(error) => panic!("the echo failed: {error}"),
            }
        }
        assert_eq!(&back[..at], b"hello udp");
        edge.join().expect("joins");
    }

    /// A capsule wider than the caller's buffer keeps its tail on the h1 lane, and the next read resumes at the cursor rather than dropping the rest.
    #[test]
    fn a_h1_datagram_wider_than_the_caller_s_buffer_keeps_its_tail() {
        const BODY: usize = 1_350;
        let (roots, server) = minted(b"http/1.1");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, _seen_rx) = std::sync::mpsc::channel();
        let edge = masque_h1_edge(listener, server, seen_tx);
        let dial = dial_for(roots, port, Carrier::H1, foxy::pin::Pins::default());
        let mut lane = open_udp_h1(&dial, "example.com", 443).expect("opens");
        let wide: Vec<u8> = (0..BODY).map(|i| (i % 251) as u8).collect();
        lane.write_datagram(&wide).expect("writes");
        lane.set_read_quantum(Duration::from_secs(5))
            .expect("bounds a read");
        let mut piece = [0u8; 64];
        let mut got = Vec::new();
        while got.len() < BODY {
            match lane.read_datagram(&mut piece) {
                Ok(0) => panic!("the echo ended early"),
                Ok(read) => {
                    assert!(
                        read > 0 && read <= piece.len(),
                        "a read reports what its buffer got"
                    );
                    got.extend_from_slice(&piece[..read]);
                }
                Err(error) => panic!("the echo failed: {error}"),
            }
        }
        assert_eq!(got, wide, "every octet once, in the order it was sent");
        assert!(
            lane.capsule_buf.is_empty(),
            "the spent capsule left nothing staged"
        );
        assert_eq!(lane.handed, 0, "and no cursor either");
        edge.join().expect("joins");
    }

    /// A frame read a hundred bytes at a time leaves nothing staged in the lane: every byte the caller took went from the wire into its own buffer, and between those visits the lane holds only the cursor.
    #[test]
    fn a_frame_read_a_hundred_bytes_at_a_time_stages_nothing() {
        const FRAME: usize = 16 * 1024;
        const STEP: usize = 100;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, _seen_rx) = std::sync::mpsc::channel();
        let _edge = h2_edge(listener, server, seen_tx);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let Tunnel::H2(lane) = &mut tunnel else {
            panic!("an h2 lane");
        };
        let sent: Vec<u8> = (0..FRAME).map(|i| (i % 251) as u8).collect();
        lane.write_all(&sent).expect("writes");
        lane.flush().expect("flushes");
        let mut back = vec![0u8; FRAME];
        let mut at = 0usize;
        while at < FRAME {
            let room = (FRAME - at).min(STEP);
            let read = lane.read(&mut back[at..at + room]).expect("reads");
            assert!(read > 0, "a frame that stops mid-way");
            at += read;
        }
        assert_eq!(back, sent, "the bytes are the bytes either way");
        assert!(
            lane.test_stream(|s| s.carry.is_empty()),
            "the remainder was drained"
        );
        assert_eq!(
            lane.test_stream(|s| s.at),
            0,
            "the read cursor is where it started"
        );
    }

    /// The downlink edge: it answers the status, writes each named piece (pausing after it if one is named), and reports every `WINDOW_UPDATE` it reads from the lane until the socket ends.
    fn downlink_edge(
        listener: Listener,
        server: ferrox_core::tls::TlsServerConfig,
        pieces: Vec<(Vec<u8>, Option<Duration>)>,
        updates: std::sync::mpsc::Sender<(u32, u32)>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            tls.get_ref()
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("times out");
            let mut preface = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut preface) {
                return;
            }
            let mut opening = Vec::new();
            h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut opening);
            h2_frame(frames::HEADERS, 0x4, 1, &[0x88], &mut opening);
            tls.write_all(&opening).expect("answers the status");
            for (piece, pause) in pieces {
                tls.write_all(&piece).expect("pushes");
                tls.flush().expect("flushes");
                if let Some(pause) = pause {
                    std::thread::sleep(pause);
                }
            }
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                if frame.kind == frames::WINDOW_UPDATE && payload.len() == 4 {
                    let increment = u32::from_be_bytes(payload[..4].try_into().expect("four"));
                    let _ = updates.send((frame.stream, increment));
                }
                // The lane resets its stream on drop while the pooled session stays open, so the reset is the edge's end.
                if frame.kind == frames::RST_STREAM {
                    return;
                }
            }
        })
    }

    /// One DATA frame, whole: the header names the payload it carries.
    /// A DATA frame with padding: the pad byte, the payload, the pad tail.
    fn padded_data_frame(payload: &[u8], pad: usize) -> Vec<u8> {
        let mut body = Vec::with_capacity(1 + payload.len() + pad);
        body.push(pad as u8);
        body.extend_from_slice(payload);
        body.extend(std::iter::repeat_n(pad as u8, pad));
        let mut out = frames::H2Frame {
            kind: frames::DATA,
            flags: 0x8,
            stream: 1,
            length: body.len() as u32,
        }
        .header()
        .to_vec();
        out.extend_from_slice(&body);
        out
    }

    fn data_frame(payload: &[u8]) -> Vec<u8> {
        let mut out = frames::H2Frame {
            kind: frames::DATA,
            flags: 0,
            stream: 1,
            length: payload.len() as u32,
        }
        .header()
        .to_vec();
        out.extend_from_slice(payload);
        out
    }

    /// The rest of a frame the caller only half-takes stays on the wire, not in a buffer the relay copies through: the lane holds a cursor and the next read resumes into the caller's own space.
    #[test]
    fn half_a_frame_reaches_the_caller_with_the_rest_left_on_the_wire() {
        const FRAME: usize = 8 * 1024;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let payload: Vec<u8> = (0..FRAME).map(|i| (i % 251) as u8).collect();
        let (tx, _rx) = std::sync::mpsc::channel();
        let _edge = downlink_edge(listener, server, vec![(data_frame(&payload), None)], tx);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let Tunnel::H2(lane) = &mut tunnel else {
            panic!("an h2 lane");
        };
        let mut half = [0u8; FRAME / 2];
        let got = lane.read(&mut half).expect("the first half");
        assert_eq!(
            got,
            half.len(),
            "the caller's buffer was filled and stopped"
        );
        assert_eq!(lane.test_inner().frame.data_len, FRAME as u32);
        assert_eq!(
            lane.test_inner().frame.data_at,
            FRAME as u32 / 2,
            "the cursor says what the wire still owes"
        );
        assert!(
            lane.test_stream(|s| s.carry.is_empty()),
            "the rest was not staged anywhere"
        );
        let mut rest = [0u8; FRAME / 2];
        let got = lane.read(&mut rest).expect("the second half");
        assert_eq!(got, rest.len());
        assert_eq!(lane.test_inner().frame.data_len, 0, "the frame is spent");
        assert_eq!(
            &half[..],
            &payload[..FRAME / 2],
            "the first half is the first half"
        );
        assert_eq!(
            &rest[..],
            &payload[FRAME / 2..],
            "the second half resumed where the wire stopped"
        );
    }

    /// A read quantum that expires mid-frame is a handover, not a loss: what arrived sits in the caller's buffer, the lane keeps the cursor, and the resume re-reads nothing that was already paid for.
    #[test]
    fn a_quantum_that_expires_mid_frame_resumes_without_re_reading_a_byte() {
        const FRAME: usize = 8 * 1024;
        const PART: usize = 3 * 1024;
        const STEP: usize = 1000;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let payload: Vec<u8> = (0..FRAME).map(|i| (i % 251) as u8).collect();
        let (tx, _rx) = std::sync::mpsc::channel();
        let mut head = data_frame(&payload);
        head.truncate(frames::H2_HEADER + PART);
        let tail = payload[PART..FRAME].to_vec();
        let _edge = downlink_edge(
            listener,
            server,
            vec![
                (head, Some(Duration::from_millis(200))),
                (tail, Some(Duration::from_millis(50))),
            ],
            tx,
        );
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        tunnel
            .set_read_quantum(Duration::from_millis(30))
            .expect("bounds one read");
        let Tunnel::H2(lane) = &mut tunnel else {
            panic!("an h2 lane");
        };
        let mut back = vec![0u8; FRAME];
        let mut at = 0usize;
        let mut parks = 0usize;
        let mut mid_frame_parks = 0usize;
        let stop_by = Instant::now() + Duration::from_secs(20);
        while at < FRAME {
            assert!(Instant::now() < stop_by, "the frame never finished");
            let room = (FRAME - at).min(STEP);
            match lane.read(&mut back[at..at + room]) {
                Ok(read) => {
                    assert!(read > 0, "a read that returns nothing without saying so");
                    at += read;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    parks += 1;
                    if lane.test_inner().frame.data_len > 0 {
                        mid_frame_parks += 1;
                        assert!(
                            lane.test_inner().frame.data_len == FRAME as u32
                                && lane.test_inner().frame.data_at > 0
                                && lane.test_inner().frame.data_at < FRAME as u32,
                            "the pause lost which frame was in flight"
                        );
                        assert!(
                            lane.test_stream(|s| s.carry.is_empty()),
                            "the pause staged nothing"
                        );
                    }
                }
                Err(error) => panic!("the lane died: {error}"),
            }
        }
        assert!(
            mid_frame_parks > 0,
            "the witness needs a pause inside the frame, not before it: {parks} parks"
        );
        assert_eq!(back, payload, "the pause cost no byte and added none");
        assert_eq!(lane.test_inner().frame.data_len, 0);
    }

    /// A frame whose bytes do not all arrive is a dead lane, not an endless short read: the caller learns the stream broke rather than waiting on payload that will not come.
    #[test]
    fn a_frame_truncated_on_the_wire_ends_the_flow_it_was_meant_for() {
        const CLAIM: usize = 4096;
        const ARRIVED: usize = 1024;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let payload: Vec<u8> = (0..CLAIM).map(|i| (i % 251) as u8).collect();
        let mut push = data_frame(&payload);
        push.truncate(frames::H2_HEADER + ARRIVED);
        // The edge pushes the truncated frame and leaves: its goodbye is what the lane must read as a break.
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            tls.get_ref()
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("times out");
            let mut preface = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut preface) {
                return;
            }
            let mut opening = Vec::new();
            h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut opening);
            h2_frame(frames::HEADERS, 0x4, 1, &[0x88], &mut opening);
            tls.write_all(&opening).expect("answers the status");
            tls.write_all(&push).expect("pushes the fragment");
            tls.flush().expect("flushes the fragment");
            // The client's own frames are read before the goodbye: a close with them unread is an RST, and an RST can take the truncated frame down with it.
            let mut byte = [0u8; 1];
            while matches!(tls.read(&mut byte), Ok(read) if read > 0) {}
        });
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let Tunnel::H2(lane) = &mut tunnel else {
            panic!("an h2 lane");
        };
        let mut back = [0u8; CLAIM];
        let mut at = 0usize;
        let mut broken = false;
        let stop_by = Instant::now() + Duration::from_secs(20);
        while !broken {
            assert!(
                Instant::now() < stop_by,
                "no verdict on the truncated frame"
            );
            match lane.read(&mut back[at..]) {
                Ok(read) => {
                    assert!(
                        read > 0,
                        "a clean end is not the answer to a truncated frame"
                    );
                    at += read;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => broken = true,
            }
        }
        assert!(at < CLAIM, "the truncation was swallowed as a full frame");
        assert_eq!(&back[..at], &payload[..at], "what arrived is what was sent");
        edge.join().expect("the edge finishes");
    }

    /// The credit a lane owes is held to the floor and granted back in one pair, not written per frame: crossing `CREDIT_FLOOR` costs two `WINDOW_UPDATE` frames no matter how many frames filled it.
    #[test]
    fn credit_crossing_the_floor_costs_one_pair_not_one_per_frame() {
        const FRAME: usize = 16 * 1024;
        const FRAMES: usize = 5;
        const TOTAL: usize = FRAME * FRAMES;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let payload: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();
        let pieces = (0..FRAMES)
            .map(|i| (data_frame(&payload[i * FRAME..(i + 1) * FRAME]), None))
            .collect();
        let (tx, rx) = std::sync::mpsc::channel();
        let edge = downlink_edge(listener, server, pieces, tx);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let Tunnel::H2(lane) = &mut tunnel else {
            panic!("an h2 lane");
        };
        let mut back = vec![0u8; TOTAL];
        let mut at = 0usize;
        while at < TOTAL {
            at += lane.read(&mut back[at..]).expect("reads");
        }
        assert_eq!(back, payload);
        assert_eq!(
            lane.test_stream(|s| s.pending_credit),
            (TOTAL - CREDIT_FLOOR as usize) as u32,
            "the crossing was granted and the remainder held"
        );
        drop(tunnel);
        let mut tally = Vec::new();
        while let Ok(update) = rx.recv_timeout(Duration::from_secs(20)) {
            tally.push(update);
        }
        edge.join().expect("the edge finishes");
        // One pair at the crossing (the template grants stream 1 then stream 0), beside the lane's own opening grant on stream 0.
        let grants: Vec<_> = tally
            .iter()
            .filter(|(_, increment)| *increment == CREDIT_FLOOR)
            .copied()
            .collect();
        assert_eq!(
            grants,
            vec![(1, CREDIT_FLOOR), (0, CREDIT_FLOOR)],
            "five frames cost one pair, not five"
        );
        let held = (TOTAL - CREDIT_FLOOR as usize) as u32;
        assert_eq!(
            &tally[3..],
            &[(1, held), (0, held)],
            "the held remainder is returned once when the lane ends: {tally:?}"
        );
        assert_eq!(
            tally.len(),
            5,
            "no other window update left the lane: {tally:?}"
        );
    }

    /// The witness for `carrier-foxy padded-frame-credit-octets`: RFC 7540 6.9 puts the
    /// whole DATA payload into the flow-control window, the Pad Length octet and the
    /// Padding included, so a padded frame gives the peer its wire length back and a peer
    /// with a strict window does not lose an octet a frame.
    #[test]
    fn a_padded_frame_credits_its_whole_wire_payload() {
        const FRAME: usize = 16 * 1024;
        const FRAMES: usize = 4;
        const PAD: usize = 7;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let payload: Vec<u8> = (0..FRAME * FRAMES).map(|i| (i % 251) as u8).collect();
        let pieces = (0..FRAMES)
            .map(|i| {
                (
                    padded_data_frame(&payload[i * FRAME..(i + 1) * FRAME], PAD),
                    None,
                )
            })
            .collect();
        let (tx, rx) = std::sync::mpsc::channel();
        let edge = downlink_edge(listener, server, pieces, tx);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let Tunnel::H2(lane) = &mut tunnel else {
            panic!("an h2 lane");
        };
        // The room takes every frame whole, so every frame's credit is owed when read.
        let wire = (FRAME + 1 + PAD) as u32;
        let mut back = vec![0u8; FRAME * FRAMES];
        let mut at = 0usize;
        while at < back.len() {
            at += lane.read(&mut back[at..]).expect("reads");
        }
        assert_eq!(
            back, payload,
            "the room took the four payloads, not four bodies with a pad byte and a pad tail"
        );
        assert_eq!(
            lane.test_stream(|s| s.pending_credit),
            0,
            "the frames crossed the floor and the grant took every octet of them"
        );
        drop(tunnel);
        join_edge_within(edge, Duration::from_secs(5));
        let mut tally = Vec::new();
        while let Ok(update) = rx.try_recv() {
            tally.push(update);
        }
        let granted: Vec<_> = tally
            .iter()
            .filter(|(_, increment)| *increment == FRAMES as u32 * wire)
            .copied()
            .collect();
        assert_eq!(
            granted,
            vec![(1, FRAMES as u32 * wire), (0, FRAMES as u32 * wire)],
            "the grant is every frame's wire length, the pad byte and the pad tail included"
        );
    }

    /// The witness for `carrier-foxy padded-frame-payload-octets`: RFC 7540 6.1 keeps the Pad
    /// Length octet and the Padding out of the payload, so a caller with room for the whole
    /// frame gets the payload and never the padding around it.
    #[test]
    fn a_padded_frame_hands_back_only_its_payload() {
        const FRAME: usize = 8 * 1024;
        const PAD: usize = 7;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let payload: Vec<u8> = (0..FRAME).map(|i| (i % 251) as u8).collect();
        let (tx, _rx) = std::sync::mpsc::channel();
        let edge = downlink_edge(
            listener,
            server,
            vec![(padded_data_frame(&payload, PAD), None)],
            tx,
        );
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let Tunnel::H2(lane) = &mut tunnel else {
            panic!("an h2 lane");
        };
        let mut back = vec![0u8; FRAME];
        let mut at = 0usize;
        while at < FRAME {
            at += lane.read(&mut back[at..]).expect("reads");
        }
        assert_eq!(
            back, payload,
            "the delivery opened with the pad-length octet and closed on the pad tail"
        );
        assert_eq!(
            lane.test_stream(|s| s.carry.capacity()),
            FRAME,
            "the whole payload was staged once, which is the price of taking the padding off"
        );
        drop(tunnel);
        join_edge_within(edge, Duration::from_secs(5));
    }

    /// The other half of `carrier-foxy padded-frame-payload-octets`: the same padding read
    /// through a buffer a fraction of the frame's size, so the bytes the caller gets do not
    /// depend on how much room it had.
    #[test]
    fn a_padded_frame_read_in_pieces_hands_back_only_its_payload() {
        const FRAME: usize = 8 * 1024;
        const FRAMES: usize = 2;
        const STEP: usize = 1000;
        const PAD: usize = 200;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let payload: Vec<u8> = (0..FRAME * FRAMES).map(|i| (i % 251) as u8).collect();
        let pieces = (0..FRAMES)
            .map(|i| {
                (
                    padded_data_frame(&payload[i * FRAME..(i + 1) * FRAME], PAD),
                    None,
                )
            })
            .collect();
        let (tx, _rx) = std::sync::mpsc::channel();
        let edge = downlink_edge(listener, server, pieces, tx);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let Tunnel::H2(lane) = &mut tunnel else {
            panic!("an h2 lane");
        };
        let mut back = vec![0u8; FRAME * FRAMES];
        let mut at = 0usize;
        while at < back.len() {
            let room = (back.len() - at).min(STEP);
            let read = lane.read(&mut back[at..at + room]).expect("reads");
            assert!(read > 0, "a padded frame that stops arriving");
            at += read;
        }
        assert_eq!(
            back, payload,
            "the payload came out shifted by the octets that pad it, whatever the room"
        );
        drop(tunnel);
        edge.join().expect("the edge finishes");
    }

    /// The witness for `carrier-foxy padding-only-frame-payload-octets`: a frame whose whole
    /// body is padding carries no payload, so nothing reaches the caller and the window is
    /// still owed every octet the frame spent.
    #[test]
    fn a_frame_of_only_padding_hands_the_caller_nothing_and_still_credits_its_wire() {
        const PAD: usize = 5;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (tx, _rx) = std::sync::mpsc::channel();
        let edge = downlink_edge(
            listener,
            server,
            vec![
                (padded_data_frame(&[], PAD), None),
                (data_frame(b"tail"), None),
            ],
            tx,
        );
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let Tunnel::H2(lane) = &mut tunnel else {
            panic!("an h2 lane");
        };
        let mut back = [0u8; 64];
        let mut got = 0usize;
        while got < 4 {
            got += lane.read(&mut back[got..]).expect("reads");
        }
        assert_eq!(
            &back[..got],
            b"tail",
            "the pad-only frame's six octets were handed over as payload"
        );
        assert_eq!(
            lane.test_stream(|s| s.pending_credit),
            (PAD as u32 + 1) + 4,
            "the frame that delivered nothing still spent six octets of window"
        );
        drop(tunnel);
        join_edge_within(edge, Duration::from_secs(5));
    }

    /// Credit held below the floor never reaches the wire: a lane that has taken less than `CREDIT_FLOOR` owes the edge a number, not a write.
    #[test]
    fn credit_held_under_the_floor_never_reaches_the_wire() {
        const FRAME: usize = 16 * 1024;
        const LAST: usize = 16 * 1024 - 153;
        const TOTAL: usize = 3 * FRAME + LAST;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let payload: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();
        let mut pieces = (0..3)
            .map(|i| (data_frame(&payload[i * FRAME..(i + 1) * FRAME]), None))
            .collect::<Vec<_>>();
        pieces.push((data_frame(&payload[3 * FRAME..]), None));
        let (tx, rx) = std::sync::mpsc::channel();
        let edge = downlink_edge(listener, server, pieces, tx);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let Tunnel::H2(lane) = &mut tunnel else {
            panic!("an h2 lane");
        };
        let mut back = vec![0u8; TOTAL];
        let mut at = 0usize;
        while at < TOTAL {
            at += lane.read(&mut back[at..]).expect("reads");
        }
        assert_eq!(back, payload);
        assert_eq!(
            lane.test_stream(|s| s.pending_credit),
            TOTAL as u32,
            "everything taken is still owed, unstated"
        );
        drop(tunnel);
        let tally: Vec<_> = (0..10)
            .map_while(|_| rx.recv_timeout(Duration::from_millis(500)).ok())
            .collect();
        edge.join().expect("the edge finishes");
        assert!(
            tally
                .iter()
                .all(|(_, increment)| *increment != CREDIT_FLOOR),
            "a held credit below the floor wrote nothing: {tally:?}"
        );
    }

    #[test]
    fn the_http2_carrier_assembles_a_status_split_over_continuation() {
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            tls.handshake().expect("handshakes");
            let mut head = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut head) {
                return;
            }
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                match frames::h2_event(frame, &payload, 1) {
                    frames::H2Event::Settings { ack: false, .. } => {
                        let mut out = Vec::new();
                        h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut out);
                        tls.write_all(&out).expect("acks the settings");
                    }
                    frames::H2Event::Headers { .. } => {
                        // The status in two fragments: an indexed field the lane skips, then the indexed 200 on a CONTINUATION.
                        let mut first = Vec::new();
                        h2_frame(frames::HEADERS, 0x0, 1, &[0x80 | 0x21], &mut first);
                        tls.write_all(&first).expect("sends the fragment");
                        let mut rest = Vec::new();
                        h2_frame(frames::CONTINUATION, 0x4, 1, &[0x88], &mut rest);
                        tls.write_all(&rest).expect("sends the tail");
                        return;
                    }
                    _ => {}
                }
            }
        });
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        assert!(Tunnel::open(&dial, "example.com:443", None).is_ok());
        edge.join().expect("joins");
    }

    /// The CONNECT-IP tunnel over HTTP/2: the request is `connect-ip`, the assignment that follows carries the tunnel's own address, and a datagram to one destination rides the tunnel the address bought rather than a stream of its own.
    #[test]
    fn the_connect_ip_carrier_opens_one_tunnel_and_carries_a_datagram() {
        let (roots, server) = minted(b"\x68\x32");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let (udp_tx, udp_rx) = std::sync::mpsc::channel();
        let edge = ip_h2_edge(listener, server, seen_tx, udp_tx, 1);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let (mut lane, assigned) = Ip::open(&dial, None).expect("opens");
        let assigned = assigned.expect("an address");
        assert!(!assigned.refused(), "the tunnel owns an address");
        assert_eq!(assigned.bytes(), &[198, 51, 100, 9]);
        assert_eq!(assigned.width(), 4, "an IPv4 tunnel");
        let block = seen_rx
            .recv_timeout(Duration::from_secs(20))
            .expect("block");
        let text = String::from_utf8_lossy(&block);
        for field in [
            "CONNECT",
            "connect-ip",
            "/.well-known/masque/ip/*/0/",
            "Bearer the-pass",
            "capsule-protocol",
            "?1",
        ] {
            assert!(text.contains(field), "missing {field}");
        }
        let written = lane
            .write(
                &[198, 51, 100, 9],
                &[203, 0, 113, 9],
                40_000,
                443,
                b"hello ip",
            )
            .expect("writes");
        assert!(written, "the packet was built");
        lane.flush().expect("flushes");
        let (destination, port, payload) = udp_rx
            .recv_timeout(Duration::from_secs(20))
            .expect("the edge read it");
        assert_eq!(destination, vec![203, 0, 113, 9]);
        assert_eq!(port, 443);
        assert_eq!(payload, b"hello ip");
        // The reply is read as a packet whose source is where the datagram went, and a byte-equal packet cannot see a staging copy, so capacity is the witness: reset the capsule buffer with nothing pending, read one reply, and the buffer a whole-in-one-frame capsule would have been staged through must still be empty.
        {
            let Ip::H2(inner) = &mut lane else {
                unreachable!("an h2 dial opens an h2 lane");
            };
            assert!(
                inner.test_stream(|s| s.capsule_buf.is_empty()),
                "the assignment left no capsule bytes pending"
            );
            inner.test_stream(|s| s.capsule_buf = Vec::new());
        }
        let mut packet = Vec::new();
        assert!(lane.read(&mut packet).expect("reads"), "a reply");
        let Ip::H2(inner) = &mut lane else {
            unreachable!("an h2 dial opens an h2 lane");
        };
        assert_eq!(
            inner.test_stream(|s| s.capsule_buf.capacity()),
            0,
            "a datagram whole inside one DATA frame was handed out, not staged through the capsule buffer"
        );
        let read = connectip::udp_from_packet(&packet).expect("parses");
        assert!(read.verified);
        assert_eq!(
            read.source,
            &[203, 0, 113, 9],
            "the reply is from the target"
        );
        assert_eq!(read.destination, &[198, 51, 100, 9]);
        assert_eq!(read.payload, b"hello ip");
        edge.join().expect("joins");
    }

    /// The packet a datagram is built in is the lane's own buffer, and it stays that buffer: across a push and a drain the base pointer does not move and the capacity does not grow. A byte-level test passes with the copy and without it, so only the pointer can witness that the packet was not built in a buffer of its own.
    #[test]
    fn the_packet_scratch_is_the_lanes_own_buffer_and_it_stays_there() {
        let (roots, server) = minted(b"\x68\x32");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let (udp_tx, udp_rx) = std::sync::mpsc::channel();
        let edge = ip_h2_edge(listener, server, seen_tx, udp_tx, 3);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let (mut lane, _) = Ip::open(&dial, None).expect("opens");
        let _ = seen_rx
            .recv_timeout(Duration::from_secs(20))
            .expect("the edge read the block");

        let mut base = 0usize;
        let mut room = 0usize;
        let mut packet = Vec::new();
        for round in 0..3usize {
            let written = lane
                .write(
                    &[198, 51, 100, 9],
                    &[203, 0, 113, 9],
                    40_000,
                    443,
                    &[b'x'; 400],
                )
                .expect("writes");
            assert!(written, "the packet was built");
            lane.flush().expect("flushes");
            let (_destination, _port, payload) = udp_rx
                .recv_timeout(Duration::from_secs(20))
                .expect("the edge read it");
            assert_eq!(payload.len(), 400, "the payload arrived whole");
            // The reply is drained too, so the cycle is a push and a drain and not a push alone.
            assert!(lane.read(&mut packet).expect("reads"), "a reply");
            assert_eq!(packet.len(), 428, "the reply is the packet whole");

            let Ip::H2(inner) = &mut lane else {
                unreachable!("an h2 dial opens an h2 lane");
            };
            let at = inner.test_stream(|s| s.packet.as_ptr()) as usize;
            let claimed = inner.test_stream(|s| s.packet.capacity());
            if round == 0 {
                base = at;
                room = claimed;
                assert!(
                    claimed >= 428,
                    "the room for the packet was claimed before the build, got {claimed}"
                );
            } else {
                assert_eq!(at, base, "the packet buffer did not move");
                assert_eq!(claimed, room, "the packet buffer did not grow");
            }
        }
        edge.join().expect("joins");
    }

    /// The packet a reply is read into is the caller's own buffer, and it stays that buffer: across a push and a drain the base pointer does not move and the capacity does not grow. A byte-level test passes with the copy and without it, so only the pointer can witness that the reply was not read into a buffer of its own.
    #[test]
    fn the_read_packet_is_the_callers_own_buffer_and_it_stays_there() {
        let (roots, server) = minted(b"\x68\x32");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let (udp_tx, udp_rx) = std::sync::mpsc::channel();
        let edge = ip_h2_edge(listener, server, seen_tx, udp_tx, 3);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let (mut lane, _) = Ip::open(&dial, None).expect("opens");
        let _ = seen_rx
            .recv_timeout(Duration::from_secs(20))
            .expect("the edge read the block");

        let mut packet = Vec::with_capacity(1024);
        let mut base = packet.as_ptr() as usize;
        let mut room = packet.capacity();
        for round in 0..3usize {
            let written = lane
                .write(
                    &[198, 51, 100, 9],
                    &[203, 0, 113, 9],
                    40_000,
                    443,
                    &[b'x'; 400],
                )
                .expect("writes");
            assert!(written, "the packet was built");
            lane.flush().expect("flushes");
            let _ = udp_rx
                .recv_timeout(Duration::from_secs(20))
                .expect("the edge read it");
            assert!(lane.read(&mut packet).expect("reads"), "a reply");
            assert_eq!(packet.len(), 428, "the reply is the packet whole");

            let at = packet.as_ptr() as usize;
            let claimed = packet.capacity();
            if round == 0 {
                base = at;
                room = claimed;
            } else {
                assert_eq!(at, base, "the read buffer did not move");
                assert_eq!(claimed, room, "the read buffer did not grow");
            }
        }
        edge.join().expect("joins");
    }

    /// The tunnel carries more than one destination, which is what the shared address buys: a second destination rides the tunnel the first one opened.
    #[test]
    fn one_tunnel_carries_every_destination_at_once() {
        let (roots, server) = minted(b"\x68\x32");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let (udp_tx, udp_rx) = std::sync::mpsc::channel();
        let edge = ip_h2_edge(listener, server, seen_tx, udp_tx, 2);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let (mut lane, _) = Ip::open(&dial, None).expect("opens");
        let _ = seen_rx
            .recv_timeout(Duration::from_secs(20))
            .expect("block");
        for (host, payload) in [
            ([203, 0, 113, 1], &b"first"[..]),
            ([203, 0, 113, 2], &b"second"[..]),
        ] {
            assert!(lane
                .write(&[198, 51, 100, 9], &host, 40_000, 443, payload)
                .expect("writes"));
            lane.flush().expect("flushes");
        }
        for (host, payload) in [
            ([203, 0, 113, 1], &b"first"[..]),
            ([203, 0, 113, 2], &b"second"[..]),
        ] {
            let (destination, _, seen) = udp_rx
                .recv_timeout(Duration::from_secs(20))
                .expect("the edge read it");
            assert_eq!(destination, host.to_vec());
            assert_eq!(seen, payload);
        }
        edge.join().expect("joins");
    }

    /// The one capsule header that never completes: a datagram capsule whose own length field names 16 MiB, so `capsule_split` wants bytes the tunnel never carries.
    fn junk_capsule(len: usize) -> Vec<u8> {
        let mut junk = vec![0xa5u8; len];
        junk[..5].copy_from_slice(&[0x00, 0x80, 0xff, 0xff, 0xff]);
        junk
    }

    /// A CONNECT-IP edge that answers the open and then streams capsules that never finish — with, or instead of, the assignment.
    fn junk_ip_h2_edge(
        listener: Listener,
        server: ferrox_core::tls::TlsServerConfig,
        assign: bool,
        frames: usize,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            // The handshake reads on the session's budget; a quantum armed here is a flush's latency for the stream that follows it.
            let socket = stream.try_clone().expect("clones");
            stream
                .set_read_timeout(Some(crate::budgets::handshake()))
                .expect("times out");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            socket
                .set_read_timeout(Some(crate::budgets::RELAY_QUANTUM))
                .expect("times out");
            let mut head = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut head) {
                return;
            }
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                if let frames::H2Event::Headers { .. } = frames::h2_event(frame, &payload, 1) {
                    break;
                }
            }
            let mut out = Vec::new();
            h2_frame(frames::HEADERS, 0x5, 1, &[0x88], &mut out);
            tls.write_all(&out).expect("answers");
            out.clear();
            if assign {
                ip_h2_assign(&mut tls);
            }
            let junk = junk_capsule(32 * 1024);
            for _ in 0..frames {
                out.clear();
                h2_frame(frames::DATA, 0, 1, &junk, &mut out);
                tls.write_all(&out)
                    .expect("streams a capsule that never ends");
            }
            tls.flush().expect("flushes the stream");
            // The edge stays until the lane goes quiet: an edge that hung up first would hand the read an EOF, and the buffer it is testing would never be looked at.
            let until = std::time::Instant::now() + Duration::from_secs(30);
            while std::time::Instant::now() < until {
                let mut byte = [0u8; 1];
                match tls.read(&mut byte) {
                    Ok(0) => return,
                    Ok(_) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => return,
                }
            }
        })
    }

    /// HTTP/2 CONNECT-IP lanes stage the bytes behind a capsule in the lane's own buffer, so a peer that streams frames which never split into one has to be stopped at the ceiling the UDP reader already uses rather than at whatever the caller's patience is.
    #[test]
    fn a_capsule_stream_that_never_parses_stops_at_the_lane_s_ceiling() {
        const FRAMES: usize = 12;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let edge = junk_ip_h2_edge(listener, server, true, FRAMES);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let (mut lane, _) = Ip::open(&dial, None).expect("opens");
        let Ip::H2(inner) = &mut lane else {
            unreachable!("an h2 dial opens an h2 lane");
        };
        inner
            .set_read_quantum(Duration::from_millis(200))
            .expect("arms a quantum");
        let mut named = None;
        let mut packet = Vec::new();
        for _ in 0..24 {
            match lane.read(&mut packet) {
                Ok(true) => panic!("a junk capsule reached the caller"),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => {
                    named = Some(error.to_string());
                    break;
                }
                _ => {}
            }
        }
        let held = match &lane {
            Ip::H2(inner) => inner.test_stream(|s| s.capsule_buf.len()),
            Ip::H3(_) => unreachable!("an h2 dial opens an h2 lane"),
        };
        assert!(
            held <= DATAGRAM_BUF_MAX,
            "the lane went on holding {held} bytes past its ceiling"
        );
        assert!(
            named
                .as_deref()
                .is_some_and(|text| text.contains("never parses")),
            "the lane never named the stream it could not parse: {named:?}"
        );
        drop(lane);
        edge.join().expect("joins");
    }

    /// A loopback HTTP/2 edge that speaks CONNECT-IP: it answers the request, sends an `ADDRESS_ASSIGN` for the tunnel's own address, then relays whichever destination the packet names — one stream carrying more than one destination, where a CONNECT-UDP edge answers only a single target.
    fn ip_h2_edge(
        listener: Listener,
        server: ferrox_core::tls::TlsServerConfig,
        seen: std::sync::mpsc::Sender<Vec<u8>>,
        udp: std::sync::mpsc::Sender<(Vec<u8>, u16, Vec<u8>)>,
        want: usize,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            // A TLS flush performs one read when nothing is pending to write, so the socket's read timeout is a flush's latency: the handshake gets the session's budget, and the relays afterwards arm a quantum.
            let socket = stream.try_clone().expect("clones");
            stream
                .set_read_timeout(Some(crate::budgets::handshake()))
                .expect("times out");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            tls.handshake().expect("handshakes");
            socket
                .set_read_timeout(Some(crate::budgets::RELAY_QUANTUM))
                .expect("times out");
            let mut head = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut head) {
                return;
            }
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                match frames::h2_event(frame, &payload, 1) {
                    frames::H2Event::Settings { ack: false, .. } => {
                        let mut out = Vec::new();
                        h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut out);
                        tls.write_all(&out).expect("acks the settings");
                    }
                    frames::H2Event::Headers { block, .. } => {
                        seen.send(block.to_vec()).expect("reports the block");
                        let mut out = Vec::new();
                        h2_frame(frames::HEADERS, 0x5, 1, &[0x88], &mut out);
                        tls.write_all(&out).expect("answers");
                        break;
                    }
                    _ => {}
                }
            }
            // The address the proxy assigns: an RFC 1918 one, since the tunnel is a private network and not the internet.
            ip_h2_assign(&mut tls);
            // The client's address request arrives as DATA before the first packet, so the capsule loop below drains it where it lies.
            ip_h2_relay(&mut tls, &udp, want);
        })
    }

    /// The assignment a CONNECT-IP edge answers with: one address the tunnel owns, flushed so the lane's first read finds it.
    fn ip_h2_assign(tls: &mut ferrox_core::tls::RustlsServerProvider<Connection>) {
        let mut capsule = Vec::new();
        connectip::address_assign_encode(&[ip_tunnel_grant()], &mut capsule);
        let mut frame = Vec::new();
        h2_frame(frames::DATA, 0, 1, &capsule, &mut frame);
        tls.write_all(&frame).expect("assigns an address");
        tls.flush().expect("flushes the assignment");
    }

    /// The one grant both CONNECT-IP edges answer with: the tunnel's own RFC 1918-ish address, request id one, `198.51.100.9/32`.
    fn ip_tunnel_grant() -> connectip::Assigned {
        let mut address = [0u8; 16];
        address[..4].copy_from_slice(&[198, 51, 100, 9]);
        connectip::Assigned {
            request_id: 1,
            version: 4,
            address,
            prefix: 32,
        }
    }

    /// The packets one CONNECT-IP edge carries: each names its destination, so one stream serves `want` of them and then the edge rests.
    fn ip_h2_relay(
        tls: &mut ferrox_core::tls::RustlsServerProvider<Connection>,
        udp: &std::sync::mpsc::Sender<(Vec<u8>, u16, Vec<u8>)>,
        want: usize,
    ) {
        let mut stream = Vec::new();
        let mut carried = 0usize;
        loop {
            let mut header = [0u8; frames::H2_HEADER];
            if read_exact(tls, &mut header).is_err() {
                continue;
            }
            let Some(frame) = frames::H2Frame::parse(&header) else {
                continue;
            };
            let mut payload = vec![0u8; frame.length as usize];
            if read_exact(tls, &mut payload).is_err() {
                continue;
            }
            if frame.kind != frames::DATA {
                continue;
            }
            stream.extend_from_slice(&payload);
            while let Some((used, capsule)) = connectip::capsule_split(&stream) {
                let packet = if let connectip::Capsule::Datagram(packet) = capsule {
                    packet.to_vec()
                } else {
                    stream.drain(..used);
                    continue;
                };
                stream.drain(..used);
                let Some(read) = connectip::udp_from_packet(&packet) else {
                    continue;
                };
                if read.source != [198, 51, 100, 9] {
                    continue;
                }
                udp.send((
                    read.destination.to_vec(),
                    read.destination_port,
                    read.payload.to_vec(),
                ))
                .expect("reports the datagram");
                // A reply from the destination, which is what a caller reads.
                let mut reply = Vec::new();
                assert!(connectip::udp_datagram(
                    &connectip::UdpDatagram {
                        source: read.destination,
                        destination: &[198, 51, 100, 9],
                        source_port: read.destination_port,
                        destination_port: read.source_port,
                        payload: read.payload,
                    },
                    &mut reply
                ));
                let mut coded = Vec::new();
                connectip::packet_encode(&reply, &mut coded);
                let mut frame = Vec::new();
                h2_frame(frames::DATA, 0, 1, &coded, &mut frame);
                tls.write_all(&frame).expect("replies");
                tls.flush().expect("flushes the reply");
                carried += 1;
                if carried >= want {
                    // The reply is not the end of the edge: a lane that has to read a second frame to find the rest of its capsule must find the edge still there.
                    std::thread::sleep(Duration::from_millis(250));
                    return;
                }
            }
        }
    }
    #[test]
    fn the_masque_carrier_opens_connect_udp_and_echoes_a_datagram() {
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let edge = masque_h2_edge(listener, server, seen_tx, 1);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut lane = open_udp(&dial, "example.com", 443).expect("opens");
        let block = seen_rx
            .recv_timeout(Duration::from_secs(20))
            .expect("block");
        let text = String::from_utf8_lossy(&block);
        for field in [
            "connect-udp",
            "/.well-known/masque/udp/example.com/443/",
            "Bearer the-pass",
        ] {
            assert!(text.contains(field), "missing {field}");
        }
        // A byte-level echo cannot see a staging copy, so capacity is the witness on the write side: reset the pooled write buffer, write one datagram, and the buffer a stage would have grown must still be empty.
        lane.test_inner().out = Vec::new();
        lane.write_datagram(b"hello udp").expect("writes");
        lane.flush().expect("flushes");
        assert_eq!(
            lane.test_inner().out.capacity(),
            0,
            "the datagram's payload went into the record, not into a staging buffer"
        );
        read_datagram(&mut lane, b"hello udp");
        assert!(
            lane.test_stream(|s| s.capsule_buf.is_empty()),
            "a capsule whole inside one frame is not staged"
        );
        edge.join().expect("joins");
    }

    /// A capsule the edge split over several DATA frames arrives as one datagram, and the only bytes staged are the ones the split made it stage: the reassembly is the copy that cannot be avoided.
    #[test]
    fn a_capsule_split_over_frames_reassembles_as_one_datagram() {
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let edge = masque_h2_edge(listener, server, seen_tx, 2);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut lane = open_udp(&dial, "example.com", 443).expect("opens");
        let _block = seen_rx
            .recv_timeout(Duration::from_secs(20))
            .expect("block");
        lane.write_datagram(b"hello udp").expect("writes");
        lane.flush().expect("flushes");
        read_datagram(&mut lane, b"hello udp");
        assert!(
            lane.test_stream(|s| s.capsule_buf.is_empty()),
            "the remainder was drained"
        );
        edge.join().expect("joins");
    }

    /// A frame boundary is not a capsule boundary: two DATAGRAM capsules inside one DATA frame are two datagrams, in order — the edge echoes a received frame as one frame, so the pair comes back together or not at all.
    #[test]
    fn a_frame_of_two_datagrams_arrives_as_two_datagrams() {
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, _seen_rx) = std::sync::mpsc::channel();
        let _edge = h2_edge(listener, server, seen_tx);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut lane = open_udp(&dial, "example.com", 443).expect("opens");
        let mut both = Vec::new();
        masque::datagram_encode(b"first", &mut both);
        masque::datagram_encode(b"second", &mut both);
        lane.write_all(&both).expect("writes");
        lane.flush().expect("flushes");
        lane.set_read_quantum(Duration::from_secs(5))
            .expect("bounds a read");
        read_datagram(&mut lane, b"first");
        read_datagram(&mut lane, b"second");
    }

    /// A capsule wider than the caller's buffer: the count one read reports is the octets its buffer got, the octets behind them are owed by the next read, and the capsule after them keeps its place in the stream.
    #[test]
    fn a_datagram_wider_than_the_caller_s_buffer_keeps_its_tail() {
        const BODY: usize = 1_350;
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let wide: Vec<u8> = (0..BODY).map(|i| (i % 251) as u8).collect();
        let mut capsules = Vec::new();
        masque::datagram_encode(&wide, &mut capsules);
        masque::datagram_encode(b"behind it", &mut capsules);
        let (tx, _rx) = std::sync::mpsc::channel();
        let _edge = downlink_edge(listener, server, vec![(data_frame(&capsules), None)], tx);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut lane = open_udp(&dial, "example.com", 443).expect("opens");
        lane.set_read_quantum(Duration::from_secs(5))
            .expect("bounds a read");
        let mut piece = [0u8; 64];
        let mut got = Vec::new();
        while got.len() < BODY {
            let read = lane
                .read_datagram(&mut piece)
                .expect("a piece of the staged capsule");
            assert!(
                read > 0 && read <= piece.len(),
                "a read reports what its buffer got, not what the capsule holds"
            );
            got.extend_from_slice(&piece[..read]);
        }
        assert_eq!(got, wide, "every octet once, in the order it was sent");
        read_datagram(&mut lane, b"behind it");
        assert!(
            lane.test_stream(|s| s.capsule_buf.is_empty()),
            "the two spent capsules left nothing staged"
        );
        assert_eq!(lane.test_stream(|s| s.handed), 0, "and no cursor either");
    }

    /// One datagram through the lane, asserted whole; a buffer that has grown is the only thing a staged capsule leaves behind.
    fn read_datagram(lane: &mut Tls2, want: &[u8]) {
        let mut back = [0u8; 64];
        let mut at = 0usize;
        while at < want.len() {
            match lane.read_datagram(&mut back[at..]) {
                Ok(0) => panic!("the echo ended early"),
                Ok(read) => at += read,
                Err(error) => panic!("the echo failed: {error}"),
            }
        }
        assert_eq!(&back[..at], want);
    }

    /// A loopback HTTP/2 edge that answers a CONNECT-UDP request and echoes the datagram back, `parts` bytes of capsule to a DATA frame.
    fn masque_h2_edge(
        listener: Listener,
        server: ferrox_core::tls::TlsServerConfig,
        seen: std::sync::mpsc::Sender<Vec<u8>>,
        parts: usize,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            tls.handshake().expect("handshakes");
            let mut head = vec![0u8; frames::PREFACE.len()];
            if !read_exact_poll(&mut tls, &mut head) {
                return;
            }
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                match frames::h2_event(frame, &payload, 1) {
                    frames::H2Event::Settings { ack: false, .. } => {
                        let mut out = Vec::new();
                        h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut out);
                        tls.write_all(&out).expect("acks the settings");
                    }
                    frames::H2Event::Headers { block, .. } => {
                        seen.send(block.to_vec()).expect("reports the block");
                        let mut out = Vec::new();
                        h2_frame(frames::HEADERS, 0x5, 1, &[0x88], &mut out);
                        tls.write_all(&out).expect("answers");
                        break;
                    }
                    _ => {}
                }
            }
            let mut stream = Vec::new();
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                if !read_exact_poll(&mut tls, &mut header) {
                    return;
                }
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                if !read_exact_poll(&mut tls, &mut payload) {
                    return;
                }
                if frame.kind != frames::DATA {
                    continue;
                }
                stream.extend_from_slice(&payload);
                if let Some((_, datagram)) = masque::datagram_split(&stream) {
                    let mut echo = Vec::new();
                    masque::datagram_encode(datagram, &mut echo);
                    // The capsule in one piece, or split over `parts` frames: a frame boundary inside a capsule is legal, and the lane has to answer the datagram either way.
                    let halves: Vec<usize> =
                        (1..parts).map(|part| echo.len() * part / parts).collect();
                    let mut at = 0usize;
                    for cut in halves.into_iter().chain([echo.len()]) {
                        let mut out = Vec::new();
                        h2_frame(frames::DATA, 0, 1, &echo[at..cut], &mut out);
                        tls.write_all(&out).expect("echoes");
                        at = cut;
                    }
                    // The echo is not the end of the edge: a lane that has to read a second frame to find the rest of its capsule must find the edge still there, and a TLS peer that drops on a reader's next syscall is one the runner decides.
                    std::thread::sleep(Duration::from_millis(250));
                    return;
                }
            }
        })
    }

    /// A loopback QUIC edge that speaks the HTTP/3 opening and nothing else that matters: one request stream answered with a 200, and one capsule echoed back.
    fn quic_udp_edge(
        sock: crate::quic::Datagram,
        server: ferrox_core::tls::TlsServerConfig,
        seen: std::sync::mpsc::Sender<Vec<u8>>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut config = crate::quic::serve_config(&server).expect("serves");
            let local = sock.local_addr().expect("addr");
            let mut conn = crate::quic::server_accept(&sock, local, &mut config);
            let mut buf = [0u8; 1350];
            let mut out = [0u8; 1350];
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            let mut stream = None;
            let mut raw = Vec::new();
            while stream.is_none() {
                assert!(std::time::Instant::now() < deadline, "the request arrives");
                let Some((n, from)) = crate::quic::server_poll(&sock, &mut buf) else {
                    crate::quic::server_idle(&mut conn, &sock, &mut out);
                    continue;
                };
                let info = quiche::RecvInfo { from, to: local };
                conn.recv(&mut buf[..n], info).expect("drives");
                let ids: Vec<u64> = conn.readable().collect();
                for id in ids {
                    if id % 4 != 0 {
                        continue;
                    }
                    let piece = drain(&mut conn, id);
                    if !piece.is_empty() {
                        raw.extend_from_slice(&piece);
                        stream = Some(id);
                    }
                }
                while let Ok((written, info)) = conn.send(&mut out) {
                    let _ = sock.send_to(&out[..written], info.to);
                }
            }
            let stream = stream.expect("a request stream");
            let mut at = 0usize;
            let frame = frames::h3_frame(&raw, &mut at).expect("a frame");
            seen.send(raw[at..at + frame.length as usize].to_vec())
                .expect("reports");
            answer_udp(
                &sock, local, &mut conn, stream, &mut buf, &mut out, deadline,
            );
        })
    }

    /// The 200 the request is answered with, then the capsule echoed: the frame the edge sends back is the frame it read, header and capsule together, because the frame's payload *is* the capsule stream.
    fn answer_udp(
        sock: &crate::quic::Datagram,
        local: SocketAddr,
        conn: &mut quiche::Connection,
        stream: u64,
        buf: &mut [u8; 1350],
        out: &mut [u8; 1350],
        deadline: Instant,
    ) {
        let mut reply = Vec::new();
        frames::quic_varint(&mut reply, frames::H3_HEADERS);
        frames::quic_varint(&mut reply, 3);
        // `0xd9` is QPACK static index 25, which is `:status 200`: the indexed field line, after the block's two required zero bytes.
        reply.extend_from_slice(&[0x00, 0x00, 0xd9]);
        conn.stream_send(stream, &reply, false).expect("answers");
        // A frame's header and its payload can arrive in different packets, so a capsule is walked whole or not at all: only what whole frames cover is spent out of the window.
        let mut pending: Vec<u8> = Vec::new();
        while std::time::Instant::now() < deadline {
            let Some((n, from)) = crate::quic::server_poll(sock, buf) else {
                crate::quic::server_idle(conn, sock, out);
                continue;
            };
            let info = quiche::RecvInfo { from, to: local };
            conn.recv(&mut buf[..n], info).expect("drives");
            pending.extend_from_slice(&drain(conn, stream));
            let mut echo = Vec::new();
            let mut at = 0usize;
            let mut whole = 0usize;
            while at < pending.len() {
                let start = at;
                let Some(frame) = frames::h3_frame(&pending, &mut at) else {
                    break;
                };
                let end = at + frame.length as usize;
                if end > pending.len() {
                    break;
                }
                if matches!(
                    frames::h3_event(frame, &pending[at..end]),
                    frames::H3Event::Data { .. }
                ) {
                    echo.extend_from_slice(&pending[start..end]);
                }
                at = end;
                whole = end;
            }
            pending.drain(..whole);
            if !echo.is_empty() {
                // One datagram is one DATA frame, so a flow that split its own capsule over several of them would be a change the peer sees.
                assert_eq!(
                    frames::h3_frame(&echo, &mut 0).map(|frame| frame.kind),
                    Some(frames::H3_DATA),
                    "the echo carries a DATA frame"
                );
                conn.stream_send(stream, &echo, false).expect("echoes");
                while let Ok((written, info)) = conn.send(out) {
                    let _ = sock.send_to(&out[..written], info.to);
                }
                return;
            }
            while let Ok((written, info)) = conn.send(out) {
                let _ = sock.send_to(&out[..written], info.to);
            }
        }
    }

    /// A loopback QUIC edge that speaks CONNECT-IP: one request stream answered with a 200, an address assignment for the tunnel's own address, and a relay that answers whichever destination the packet names.
    fn quic_ip_edge(
        sock: crate::quic::Datagram,
        server: ferrox_core::tls::TlsServerConfig,
        seen: std::sync::mpsc::Sender<Vec<u8>>,
        udp: std::sync::mpsc::Sender<(Vec<u8>, u16, Vec<u8>)>,
        want: usize,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut config = crate::quic::serve_config(&server).expect("serves");
            let local = sock.local_addr().expect("addr");
            let mut conn = crate::quic::server_accept(&sock, local, &mut config);
            let mut buf = [0u8; 1350];
            let mut out = [0u8; 1350];
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            let mut stream = None;
            let mut raw = Vec::new();
            while stream.is_none() {
                assert!(std::time::Instant::now() < deadline, "the request arrives");
                let Some((n, from)) = crate::quic::server_poll(&sock, &mut buf) else {
                    crate::quic::server_idle(&mut conn, &sock, &mut out);
                    continue;
                };
                let info = quiche::RecvInfo { from, to: local };
                conn.recv(&mut buf[..n], info).expect("drives");
                let ids: Vec<u64> = conn.readable().collect();
                for id in ids {
                    if id % 4 != 0 {
                        continue;
                    }
                    let piece = drain(&mut conn, id);
                    if !piece.is_empty() {
                        raw.extend_from_slice(&piece);
                        stream = Some(id);
                    }
                }
                while let Ok((written, info)) = conn.send(&mut out) {
                    let _ = sock.send_to(&out[..written], info.to);
                }
            }
            let stream = stream.expect("a request stream");
            let mut at = 0usize;
            let frame = frames::h3_frame(&raw, &mut at).expect("a frame");
            seen.send(raw[at..at + frame.length as usize].to_vec())
                .expect("reports");
            answer_ip(&sock, local, &mut conn, stream, &udp, want);
        })
    }

    /// The 200 the CONNECT-IP request is answered with, the assignment the tunnel owns, and one relayed packet per destination: the reply is a new packet with the ends swapped, because the tunnel carries addresses and not an echo.
    fn answer_ip(
        sock: &crate::quic::Datagram,
        local: SocketAddr,
        conn: &mut quiche::Connection,
        stream: u64,
        udp: &std::sync::mpsc::Sender<(Vec<u8>, u16, Vec<u8>)>,
        want: usize,
    ) {
        let mut buf = [0u8; 1350];
        let mut out = [0u8; 1350];
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        let mut reply = Vec::new();
        frames::quic_varint(&mut reply, frames::H3_HEADERS);
        frames::quic_varint(&mut reply, 3);
        reply.extend_from_slice(&[0x00, 0x00, 0xd9]);
        conn.stream_send(stream, &reply, false).expect("answers");
        // The tunnel's own grant, encoded by the same codec the client reads it back with.
        let mut capsule = Vec::new();
        connectip::address_assign_encode(&[ip_tunnel_grant()], &mut capsule);
        send_h3_data(conn, stream, &capsule);
        while let Ok((written, info)) = conn.send(&mut out) {
            let _ = sock.send_to(&out[..written], info.to);
        }
        // The client's address request arrives as DATA before the first packet, so the capsule loop below drains it where it lies.
        let mut pending: Vec<u8> = Vec::new();
        let mut stream_buf: Vec<u8> = Vec::new();
        let mut carried = 0usize;
        while std::time::Instant::now() < deadline {
            let Some((n, from)) = crate::quic::server_poll(sock, &mut buf) else {
                crate::quic::server_idle(conn, sock, &mut out);
                continue;
            };
            let info = quiche::RecvInfo { from, to: local };
            conn.recv(&mut buf[..n], info).expect("drives");
            pending.extend_from_slice(&drain(conn, stream));
            let mut at = 0usize;
            let mut whole = 0usize;
            while at < pending.len() {
                let Some(frame) = frames::h3_frame(&pending, &mut at) else {
                    break;
                };
                let end = at + frame.length as usize;
                if end > pending.len() {
                    break;
                }
                if matches!(
                    frames::h3_event(frame, &pending[at..end]),
                    frames::H3Event::Data { .. }
                ) {
                    stream_buf.extend_from_slice(&pending[at..end]);
                }
                at = end;
                whole = end;
            }
            pending.drain(..whole);
            while let Some((used, capsule)) = connectip::capsule_split(&stream_buf) {
                let packet = if let connectip::Capsule::Datagram(packet) = capsule {
                    packet.to_vec()
                } else {
                    stream_buf.drain(..used);
                    continue;
                };
                stream_buf.drain(..used);
                let Some(read) = connectip::udp_from_packet(&packet) else {
                    continue;
                };
                if read.source != [198, 51, 100, 9] {
                    continue;
                }
                udp.send((
                    read.destination.to_vec(),
                    read.destination_port,
                    read.payload.to_vec(),
                ))
                .expect("reports the datagram");
                // A reply from the destination, which is what a caller reads.
                let mut reply = Vec::new();
                assert!(connectip::udp_datagram(
                    &connectip::UdpDatagram {
                        source: read.destination,
                        destination: &[198, 51, 100, 9],
                        source_port: read.destination_port,
                        destination_port: read.source_port,
                        payload: read.payload,
                    },
                    &mut reply
                ));
                let mut coded = Vec::new();
                connectip::packet_encode(&reply, &mut coded);
                send_h3_data(conn, stream, &coded);
                while let Ok((written, info)) = conn.send(&mut out) {
                    let _ = sock.send_to(&out[..written], info.to);
                }
                carried += 1;
                if carried >= want {
                    // The reply is not the end of the edge: a lane that has to read a second frame to find the rest of its capsule must find the edge still there.
                    std::thread::sleep(Duration::from_millis(250));
                    return;
                }
            }
            while let Ok((written, info)) = conn.send(&mut out) {
                let _ = sock.send_to(&out[..written], info.to);
            }
        }
    }

    /// One H3 DATA frame carrying `payload` on `stream`: capsules on this stream are framed, and the header is its own send because quiche copies every slice it is handed.
    fn send_h3_data(conn: &mut quiche::Connection, stream: u64, payload: &[u8]) {
        let mut head = [0u8; 9];
        let hl = frames::h3_data_header(&mut head, payload.len() as u64);
        conn.stream_send(stream, &head[..hl], false)
            .expect("frames");
        conn.stream_send(stream, payload, false).expect("carries");
    }

    /// CONNECT-IP over QUIC: the request names `connect-ip`, the assignment carries the tunnel's own address, and a datagram rides the tunnel it bought — the block the edge reads is asserted against the block the codec writes, so this is the carrier's proof, not the codec's.
    #[test]
    fn the_connect_ip_carrier_opens_one_tunnel_over_quic_and_carries_a_datagram() {
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let (udp_tx, udp_rx) = std::sync::mpsc::channel();
        let edge = quic_ip_edge(sock, server, seen_tx, udp_tx, 1);
        let dial = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
        let quic = crate::quic::direct_stream("localhost", "127.0.0.1", port, &dial.roots)
            .expect("a connection");
        let (mut lane, assigned) = Ip::open(&dial, Some(quic)).expect("opens");
        let assigned = assigned.expect("an address");
        assert!(!assigned.refused(), "the tunnel owns an address");
        assert_eq!(assigned.bytes(), &[198, 51, 100, 9]);
        assert_eq!(assigned.width(), 4, "an IPv4 tunnel");
        let block = seen_rx
            .recv_timeout(Duration::from_secs(60))
            .expect("block");
        let mut want = Vec::new();
        connectip::connect_ip_qpack(&format!("localhost:{port}"), "*", 0, "the-pass", &mut want);
        assert_eq!(block, want, "the edge reads the block the lane wrote");
        let written = lane
            .write(
                &[198, 51, 100, 9],
                &[203, 0, 113, 9],
                40_000,
                443,
                b"hello ip",
            )
            .expect("writes");
        assert!(written, "the packet was built");
        lane.flush().expect("flushes");
        let (destination, port, payload) = udp_rx
            .recv_timeout(Duration::from_secs(60))
            .expect("the edge read it");
        assert_eq!(destination, vec![203, 0, 113, 9]);
        assert_eq!(port, 443);
        assert_eq!(payload, b"hello ip");
        // The reply comes back from the destination, and the lane reads it as a packet whose source is where the datagram went.
        let mut packet = Vec::new();
        assert!(lane.read(&mut packet).expect("reads"), "a reply");
        let read = connectip::udp_from_packet(&packet).expect("parses");
        assert!(read.verified);
        assert_eq!(
            read.source,
            &[203, 0, 113, 9],
            "the reply is from the target"
        );
        assert_eq!(read.destination, &[198, 51, 100, 9]);
        assert_eq!(read.payload, b"hello ip");
        edge.join().expect("joins");
    }

    /// A QUIC lane belongs to the pool, not to the lease that opened it: one lease ending leaves the connection the other still rides, a lease the flow reads itself starts no pump, and the next flow rides the same handshake.
    #[test]
    fn a_lane_outlives_its_leases_and_the_next_flow_rides_it() {
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        let (seen_tx, _seen_rx) = std::sync::mpsc::channel();
        let (udp_tx, udp_rx) = std::sync::mpsc::channel();
        let edge = quic_ip_edge(sock, server, seen_tx, udp_tx, 1);
        let dial = crate::quic::QuicDial {
            id: [0u8; 16],
            host: std::sync::Arc::from("localhost"),
            address: std::sync::Arc::from("127.0.0.1"),
            port,
            upstream: None,
            roots: Some(roots.clone().into()),
            ech_config_list: None,
        };
        let first = crate::quic::pooled_stream_within(&dial, crate::quic::HANDSHAKE_TIMEOUT)
            .expect("a pooled stream");
        let lane = std::sync::Arc::clone(&first.conn);
        assert!(crate::quic::pool_holds(&dial), "a live lease holds it");
        let second = crate::quic::pooled_stream_within(&dial, crate::quic::HANDSHAKE_TIMEOUT)
            .expect("a second stream on the same connection");
        drop(first);
        assert!(
            crate::quic::pool_holds(&dial),
            "one lease ending does not evict a connection the other still rides"
        );
        {
            let foxy = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
            let (mut lane, _) = Ip::open(&foxy, Some(second)).expect("the tunnel opens");
            assert!(
                lane.write(
                    &[198, 51, 100, 9],
                    &[203, 0, 113, 9],
                    40_000,
                    443,
                    b"hello ip"
                )
                .expect("writes"),
                "the packet was built"
            );
            lane.flush().expect("flushes");
            udp_rx
                .recv_timeout(Duration::from_secs(60))
                .expect("the edge read it");
            lane.read(&mut Vec::new()).expect("reads");
        }
        assert!(
            crate::quic::pool_holds(&dial),
            "the lane outlived the last lease that rode it"
        );
        let third = crate::quic::pooled_stream_within(&dial, crate::quic::HANDSHAKE_TIMEOUT)
            .expect("the next flow rides the parked lane");
        assert!(
            std::sync::Arc::ptr_eq(&lane, &third.conn),
            "one handshake serves three flows, not three handshakes"
        );
        // The flag a pump clears to run is still set, so no second reader of this socket exists: `lend` starts a thread only for a lease whose bytes it can hand over.
        assert!(
            crate::quic::lane_parked(&dial),
            "a lease the flow reads itself starts no pump"
        );
        drop(third);
        edge.join().expect("joins");
    }

    /// A lane lends a bounded number of flows: the lookup after its grant is spent hands it back for a fresh dial, and a flow already riding it is left alone rather than closed with it.
    #[test]
    fn a_lane_that_lent_its_whole_grant_of_flows_is_handed_back() {
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        let (seen_tx, _seen_rx) = std::sync::mpsc::channel();
        let (udp_tx, udp_rx) = std::sync::mpsc::channel();
        let edge = quic_ip_edge(sock, server, seen_tx, udp_tx, 1);
        let dial = crate::quic::QuicDial {
            id: [0u8; 16],
            host: std::sync::Arc::from("localhost"),
            address: std::sync::Arc::from("127.0.0.1"),
            port,
            upstream: None,
            roots: Some(roots.clone().into()),
            ech_config_list: None,
        };
        let mut last = None;
        for flow in 1..=crate::quic::MAX_FLOWS_ON_LANE {
            let lease = crate::quic::pooled_stream_within(&dial, crate::quic::HANDSHAKE_TIMEOUT)
                .expect("a lease on the lane");
            if flow == crate::quic::MAX_FLOWS_ON_LANE {
                last = Some(lease);
            } else {
                drop(lease);
            }
        }
        assert!(
            crate::quic::pool_holds(&dial),
            "a spent lane is held until a lease looks at it"
        );
        assert!(
            crate::quic::lane_spent(&dial),
            "the lane has no flow left to lend"
        );
        assert!(
            crate::quic::lane_handed_back(&dial),
            "a spent lane is not the one a flow rides"
        );
        assert!(
            !crate::quic::pool_holds(&dial),
            "the hand-back took the entry out of the pool"
        );
        let foxy = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
        let (mut tunnel, _) = Ip::open(&foxy, last).expect("the rode-over lane still carries it");
        assert!(
            tunnel
                .write(
                    &[198, 51, 100, 9],
                    &[203, 0, 113, 9],
                    40_000,
                    443,
                    b"at the cap"
                )
                .expect("writes"),
            "the last flow the lane lends still carries bytes"
        );
        tunnel.flush().expect("flushes");
        udp_rx
            .recv_timeout(Duration::from_secs(60))
            .expect("the edge read it");
        assert!(
            tunnel.read(&mut Vec::new()).expect("reads"),
            "the lane lent its last flow a reply"
        );
        edge.join().expect("joins");
    }

    /// MASQUE over the pooled QUIC connection: a QPACK block naming `connect-udp` and the capsule protocol, and a datagram riding one DATAGRAM capsule inside one DATA frame — the block the edge reads is asserted against the block the codec writes, so this is the carrier's proof, not the codec's.
    #[test]
    fn the_masque_carrier_opens_connect_udp_over_quic_and_echoes_a_datagram() {
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let edge = quic_udp_edge(sock, server, seen_tx);
        let dial = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
        let quic = crate::quic::direct_stream("localhost", "127.0.0.1", port, &dial.roots)
            .expect("a connection");
        let mut lane = H3::open_udp(&dial, "example.com", 443, quic).expect("opens");
        let block = seen_rx
            .recv_timeout(Duration::from_secs(60))
            .expect("block");
        let mut want = Vec::new();
        masque::connect_udp_qpack(
            &format!("localhost:{port}"),
            "example.com",
            443,
            "the-pass",
            &mut want,
        );
        assert_eq!(block, want, "the edge reads the block the lane wrote");
        let big: Vec<u8> = (0..1350u64).map(|i| (i % 251) as u8).collect();
        // A stage would grow the lane's write scratch to the datagram's own length, so capacity is the witness: the bytes the edge reads are identical either way.
        lane.out = Vec::new();
        lane.write_datagram(&big).expect("writes a datagram");
        assert!(
            lane.out.capacity() <= 19,
            "the lane staged {} bytes to write a {}-byte datagram",
            lane.out.capacity(),
            big.len()
        );
        // The same datagram coming back is a capsule wider than one QUIC packet: one block the stream hands over, every one of its bytes owed.
        let mut back = vec![0u8; big.len()];
        let mut at = 0usize;
        while at < big.len() {
            match lane.read_datagram(&mut back[at..]) {
                Ok(0) => panic!("the echo ended early"),
                Ok(read) => at += read,
                Err(error) => panic!("the echo failed: {error}"),
            }
        }
        assert_eq!(back, big, "a capsule over several reads arrives whole");
        edge.join().expect("joins");
    }

    /// The QUIC twin of a frame that carries two datagrams: the edge answers a DATA frame with the frame it read, header and capsules together, so one frame leaving the lane must come back as two datagrams in order.
    #[test]
    fn a_quic_frame_of_two_datagrams_arrives_as_two_datagrams() {
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        let (seen_tx, _seen_rx) = std::sync::mpsc::channel();
        let edge = quic_udp_edge(sock, server, seen_tx);
        let dial = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
        let quic = crate::quic::direct_stream("localhost", "127.0.0.1", port, &dial.roots)
            .expect("a connection");
        let mut lane = H3::open_udp(&dial, "example.com", 443, quic).expect("opens");
        lane.set_read_quantum(Duration::from_secs(5));
        let mut both = Vec::new();
        masque::datagram_encode(b"first", &mut both);
        masque::datagram_encode(b"second", &mut both);
        lane.write_all(&both).expect("writes one frame");
        for want in [b"first".as_slice(), b"second".as_slice()] {
            let mut back = [0u8; 64];
            let mut at = 0usize;
            while at < want.len() {
                match lane.read_datagram(&mut back[at..]) {
                    Ok(0) => panic!("the echo ended early"),
                    Ok(read) => at += read,
                    Err(error) => panic!("the echo failed: {error}"),
                }
            }
            assert_eq!(&back[..at], want);
        }
        edge.join().expect("joins");
    }

    #[test]
    fn the_http2_carrier_reads_a_huffman_coded_status() {
        let (roots, server) = minted(b"h2");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            tls.handshake().expect("handshakes");
            let mut sink = vec![0u8; 4096];
            let _ = tls.read(&mut sink);
            // an indexed `:status` of 200, which is one byte
            let mut out = Vec::new();
            h2_frame(frames::HEADERS, 0x5, 1, &[0x88], &mut out);
            tls.write_all(&out).expect("answers");
            std::thread::sleep(Duration::from_millis(100));
        });
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        assert!(Tunnel::open(&dial, "example.com:443", None).is_ok());
        edge.join().expect("joins");
    }

    #[test]
    fn a_pinned_edge_that_is_not_the_pin_is_refused() {
        let (roots, server) = minted(b"http/1.1");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            let _ = tls.handshake();
            std::thread::sleep(Duration::from_millis(200));
        });
        let wrong = foxy::pin::Pins::parse([
            "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned()
        ]);
        let dial = dial_for(roots, port, Carrier::H1, wrong);
        assert!(Tunnel::open(&dial, "example.com:443", None).is_err());
        edge.join().expect("joins");
    }

    #[test]
    fn a_pinned_edge_that_is_the_pin_opens_the_tunnel() {
        let (roots, server) = minted(b"http/1.1");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let right = foxy::pin::Pins::parse([
            foxy::pin::spki_pin(&server.certs[0].cert_chain[0]).expect("pins")
        ]);
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            tls.handshake().expect("handshakes");
            let mut sink = vec![0u8; 1024];
            let _ = tls.read(&mut sink);
            tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .expect("answers");
            std::thread::sleep(Duration::from_millis(100));
        });
        let dial = dial_for(roots, port, Carrier::H1, right);
        assert!(Tunnel::open(&dial, "example.com:443", None).is_ok());
        edge.join().expect("joins");
    }

    /// A device whose trust store cannot build the edge's chain is not a device that distrusts the edge: the pinned leaf is its own anchor, so the tunnel opens and carries bytes where the same edge with no pin is refused.
    #[test]
    fn a_pinned_leaf_carries_the_tunnel_when_the_store_cannot_build_the_chain() {
        let (_foreign, server) = minted(b"http/1.1");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let right = foxy::pin::Pins::parse([
            foxy::pin::spki_pin(&server.certs[0].cert_chain[0]).expect("pins")
        ]);
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            tls.handshake().expect("handshakes");
            let mut sink = vec![0u8; 1024];
            let _ = tls.read(&mut sink);
            tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .expect("answers");
            let read = tls.read(&mut sink).expect("reads the payload");
            tls.write_all(&sink[..read]).expect("echoes");
        });
        // The roots of some other hand: the same shape of certificate, on a chain that does not verify.
        let (roots, _) = minted(b"http/1.1");
        let dial = dial_for(roots, port, Carrier::H1, right);
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None)
            .expect("the pinned leaf is its own anchor");
        round_trip(&mut tunnel);
        edge.join().expect("joins");
    }

    /// The anchor is the key the operator named, not any key: a pin that is not this edge's leaf leaves the stale store exactly as refusing as it was.
    #[test]
    fn a_pin_that_is_not_the_edges_key_is_still_refused_without_a_trust_store() {
        let (_foreign, server) = minted(b"http/1.1");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            let _ = tls.handshake();
        });
        let wrong = foxy::pin::Pins::parse([
            "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned()
        ]);
        let (roots, _) = minted(b"http/1.1");
        let dial = dial_for(roots, port, Carrier::H1, wrong);
        let failure = Tunnel::open(&dial, "example.com:443", None)
            .err()
            .expect("a stranger's pin");
        assert_eq!(failure, Failure::Untrusted, "{failure}");
        edge.join().expect("joins");
    }

    /// Pinning replaces who signed the leaf, not what the leaf says: a pinned key answering for a name the certificate does not cover is still refused, which is the check a pinned leaf alone would have skipped.
    #[test]
    fn a_pinned_leaf_still_has_to_answer_the_name_it_was_dialled_for() {
        let (_foreign, server) = minted(b"http/1.1");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let right = foxy::pin::Pins::parse([
            foxy::pin::spki_pin(&server.certs[0].cert_chain[0]).expect("pins")
        ]);
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut tls = ferrox_core::tls::RustlsServerProvider::accept(server.clone(), stream)
                .expect("accepts");
            let _ = tls.handshake();
        });
        let (roots, _) = minted(b"http/1.1");
        // The minted leaf covers `localhost`; this dial names another host to the same address.
        let dial = FoxyDial {
            host: std::sync::Arc::from("edge.test"),
            ..dial_for(roots, port, Carrier::H1, right)
        };
        let failure = Tunnel::open(&dial, "example.com:443", None)
            .err()
            .expect("the wrong name");
        assert_eq!(failure, Failure::Untrusted, "{failure}");
        edge.join().expect("joins");
    }

    /// The edge half of the QUIC carrier: a control stream, one HEADERS frame with a QPACK status, and DATA frames echoing the uplink back then streaming `downlink` — the proof the QUIC lane lacked: the wire request compared byte for byte with the lane's block, the status read through the QPACK decoder, and the bytes after the head travelling through the tunnel; a codec test answers none of those three.
    fn h3_edge(
        sock: crate::quic::Datagram,
        server: ferrox_core::tls::TlsServerConfig,
        seen: std::sync::mpsc::Sender<Vec<u8>>,
        uni: std::sync::mpsc::Sender<Vec<(u64, Vec<u8>, bool)>>,
        downlink: Vec<u8>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut config = crate::quic::serve_config(&server).expect("serves");
            let local = sock.local_addr().expect("addr");
            let mut conn = crate::quic::server_accept(&sock, local, &mut config);
            let mut buf = [0u8; 1350];
            let mut out = [0u8; 1350];
            // A server's own control stream is its first unidirectional stream, id 3, and the client's SETTINGS are answered on it.
            let mut control = Vec::new();
            frames::quic_varint(&mut control, frames::H3_DATA);
            frames::quic_varint(&mut control, 0);
            conn.stream_send(3, &control, true).expect("opens control");
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            let mut request = None;
            // The client's unidirectional streams, id plus bytes plus whether the lane closed one: control must arrive whole and stay open.
            let mut uni_streams: Vec<(u64, Vec<u8>, bool)> = Vec::new();
            let uni_ready = |streams: &[(u64, Vec<u8>, bool)]| {
                [2u64, 6, 10].iter().all(|want| {
                    streams
                        .iter()
                        .any(|(id, bytes, _)| id == want && !bytes.is_empty())
                })
            };
            while request.is_none() || !uni_ready(&uni_streams) {
                assert!(std::time::Instant::now() < deadline, "the request arrives");
                let Some((n, from)) = crate::quic::server_poll(&sock, &mut buf) else {
                    crate::quic::server_idle(&mut conn, &sock, &mut out);
                    continue;
                };
                let info = quiche::RecvInfo { from, to: local };
                conn.recv(&mut buf[..n], info).expect("drives");
                let ids: Vec<u64> = conn.readable().collect();
                for id in ids {
                    if id % 4 == 2 {
                        drain_uni(&mut conn, id, &mut uni_streams);
                        continue;
                    }
                    // The control stream is unidirectional and the request is not, so the stream id itself tells them apart.
                    if id % 4 != 0 {
                        continue;
                    }
                    let piece = drain(&mut conn, id);
                    if !piece.is_empty() {
                        request = Some((id, piece));
                    }
                }
                while let Ok((written, info)) = conn.send(&mut out) {
                    let _ = sock.send_to(&out[..written], info.to);
                }
            }
            let _ = uni.send(uni_streams);
            let (stream, raw) = request.expect("read");
            let mut at = 0usize;
            let frame = frames::h3_frame(&raw, &mut at).expect("a frame");
            let block = raw[at..at + frame.length as usize].to_vec();
            let _ = seen.send(block);

            let mut reply = Vec::new();
            frames::quic_varint(&mut reply, frames::H3_HEADERS);
            frames::quic_varint(&mut reply, 3);
            // `0xd9` is QPACK static index 25, which is `:status 200`: the indexed field line with a six-bit prefix, then the block's two required zero bytes.
            reply.extend_from_slice(&[0x00, 0x00, 0xd9]);
            conn.stream_send(stream, &reply, false).expect("answers");
            while let Ok((written, info)) = conn.send(&mut out) {
                let _ = sock.send_to(&out[..written], info.to);
            }
            echo_stream(
                &sock, local, &mut conn, &mut buf, &mut out, stream, &downlink,
            );
        })
    }

    /// Streams `downlink` onto one request stream as DATA frames, held to the length of the lane's own payload until the uplink has come in: a lane that never wrote gets nothing back, and a downlink longer than the uplink still arrives. The tunnel half of the loopback proof, and the downlink half the byte-count witnesses stand on.
    fn echo_stream(
        sock: &crate::quic::Datagram,
        local: SocketAddr,
        conn: &mut quiche::Connection,
        buf: &mut [u8; 1350],
        out: &mut [u8; 1350],
        stream: u64,
        downlink: &[u8],
    ) {
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        let mut received: Vec<u8> = Vec::new();
        let mut pending: Vec<u8> = Vec::new();
        let mut frame: Vec<u8> = Vec::new();
        let mut sent = 0usize;
        // The head of what the edge sends is the echo's debt: no byte leaves before the uplink paid for it, so a lane that never wrote never reads. Past `PAYLOAD` the stream is the edge's own to give and it flows at the credit's pace, which is what lets a downlink longer than the uplink arrive at all.
        let echo = PAYLOAD.len().min(downlink.len());
        let mut quiet = std::time::Instant::now();
        loop {
            assert!(std::time::Instant::now() < deadline, "the tunnel echoes");
            match crate::quic::server_poll(sock, &mut buf[..]) {
                Some((n, from)) => {
                    let info = quiche::RecvInfo { from, to: local };
                    conn.recv(&mut buf[..n], info).expect("drives");
                    pending.extend_from_slice(&drain(&mut *conn, stream));
                }
                // A quiet turn still drives the connection: its timer is what turns a datagram the loopback dropped back into a retransmission.
                None => conn.on_timeout(),
            }
            let mut at = 0usize;
            let mut whole = 0usize;
            while let Some(head) = frames::h3_frame(&pending, &mut at) {
                let end = at + head.length as usize;
                if end > pending.len() {
                    break;
                }
                if let frames::H3Event::Data { payload, .. } =
                    frames::h3_event(head, &pending[at..end])
                {
                    received.extend_from_slice(payload);
                }
                at = end;
                whole = end;
            }
            // Only what whole frames cover is spent: a header that arrived without its payload has to wait for the rest of it.
            pending.drain(..whole);
            if sent < downlink.len() {
                let owed = if sent < echo {
                    received.len().min(downlink.len())
                } else {
                    downlink.len()
                };
                let n = owed.saturating_sub(sent).min(16_384);
                if n > 0 {
                    frame.clear();
                    frames::quic_varint(&mut frame, frames::H3_DATA);
                    frames::quic_varint(&mut frame, n as u64);
                    frame.extend_from_slice(&downlink[sent..sent + n]);
                    // The credit-aware write: a send buffer the reader has not emptied takes only part of a frame, and the rest lives on solely because the writer waited for it.
                    assert!(
                        crate::quic::stream_send_all(conn, sock, stream, &frame, false, deadline),
                        "the echo reaches the lane"
                    );
                    sent += n;
                }
            }
            let mut wrote = false;
            while let Ok((written, info)) = conn.send(out) {
                wrote = true;
                let _ = sock.send_to(&out[..written], info.to);
            }
            // Handing quiche the bytes is not delivering them: the tail of a burst survives a dropped datagram only while someone is left to retransmit it, so the edge stays until a whole quiet period has nothing to send.
            if wrote || sent < downlink.len() {
                quiet = std::time::Instant::now();
            } else if sent == downlink.len() && quiet.elapsed() >= Duration::from_millis(200) {
                return;
            }
        }
    }

    /// One unidirectional stream's bytes plus whether it has closed, merged into the snapshot the test asserts the lane's opening against.
    fn drain_uni(conn: &mut quiche::Connection, id: u64, streams: &mut Vec<(u64, Vec<u8>, bool)>) {
        let mut chunk = [0u8; 8192];
        loop {
            match conn.stream_recv(id, &mut chunk) {
                Ok((0, _)) | Err(_) => break,
                Ok((n, fin)) => match streams.iter_mut().find(|(known, _, _)| *known == id) {
                    Some((_, bytes, closed)) => {
                        bytes.extend_from_slice(&chunk[..n]);
                        *closed = *closed || fin;
                    }
                    None => streams.push((id, chunk[..n].to_vec(), fin)),
                },
            }
        }
    }

    /// Every byte a stream holds, read into a buffer that exists: a `Vec` handed to `stream_recv` is a zero-length slice and never receives anything.
    fn drain(conn: &mut quiche::Connection, id: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut chunk = [0u8; 8192];
        while let Ok((n, _)) = conn.stream_recv(id, &mut chunk) {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..n]);
        }
        out
    }

    #[test]
    fn the_quic_carrier_sends_the_block_reads_the_status_and_carries_the_bytes() {
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let (uni_tx, uni_rx) = std::sync::mpsc::channel();
        let edge = h3_edge(sock, server, seen_tx, uni_tx, PAYLOAD.to_vec());

        let dial = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
        let quic = crate::quic::direct_stream("localhost", "127.0.0.1", port, &dial.roots)
            .expect("a connection");
        let mut tunnel = Tunnel::open(&dial, "example.com:443", Some(quic)).expect("opens");
        let block = seen_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("block");
        let mut want = Vec::new();
        hpack::qpack_connect("example.com:443", "the-pass", &mut want);
        assert_eq!(block, want, "the edge reads the same block the lane wrote");
        let uni = uni_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("uni streams");
        let stream = |id| {
            uni.iter()
                .find(|(known, _, _)| *known == id)
                .unwrap_or_else(|| panic!("stream {id} opened"))
        };
        let (_, control, control_fin) = stream(2);
        let mut at = 0usize;
        assert_eq!(control.first(), Some(&0x00), "a control stream type");
        at += 1;
        assert_eq!(control.get(at), Some(&0x04), "one SETTINGS frame");
        at += 1;
        let len = frames::quic_read(control, &mut at).expect("a length") as usize;
        assert_eq!(
            control.len(),
            at + len,
            "a complete SETTINGS, no truncation"
        );
        assert!(!control_fin, "control stays open");
        for (id, first) in [(6u64, 0x02u8), (10, 0x03)] {
            let (_, bytes, fin) = stream(id);
            assert_eq!(bytes.as_slice(), &[first], "qpack stream {id}");
            assert!(!fin, "qpack stream {id} stays open");
        }
        round_trip(&mut tunnel);
        // The frame's varints are sent beside the payload rather than staged with it, so the lane's write buffer never grows: capacity is the witness, because the bytes are the same either way.
        let Tunnel::H3(lane) = &tunnel else {
            panic!("an h3 lane");
        };
        assert_eq!(lane.out.capacity(), 0, "no buffer was staged to write one");
        edge.join().expect("joins");
    }

    /// A downlink several times the old frame cap: bytes no window could have held whole, so a lane that stages a frame before handing it over would have to grow one.
    const DOWNLINK: usize = 204_800;

    #[test]
    fn the_h3_downlink_hands_the_caller_the_frame_without_staging_it() {
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let (uni_tx, _uni_rx) = std::sync::mpsc::channel();
        let downlink: Vec<u8> = (0..DOWNLINK as u64).map(|i| (i % 251) as u8).collect();
        let edge = h3_edge(sock, server, seen_tx, uni_tx, downlink.clone());

        let dial = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
        let quic = crate::quic::direct_stream("localhost", "127.0.0.1", port, &dial.roots)
            .expect("a connection");
        let mut tunnel = Tunnel::open(&dial, "example.com:443", Some(quic)).expect("opens");
        seen_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("the edge read the block");
        tunnel.write_all(PAYLOAD).expect("writes");
        tunnel.flush().expect("flushes");

        // Small caller buffers: every frame spans many reads, so a resumed-read bug cannot hide behind one big pull.
        let mut chunk = vec![0u8; 4096];
        let mut got: Vec<u8> = Vec::new();
        while got.len() < downlink.len() {
            let read = tunnel.read(&mut chunk).expect("reads");
            assert!(
                read > 0,
                "a read that returns nothing is an EOF, and the stream has not ended"
            );
            assert!(
                read <= chunk.len(),
                "the lane never hands back more than the caller asked for"
            );
            got.extend_from_slice(&chunk[..read]);
        }
        assert_eq!(
            got, downlink,
            "every downlink byte arrives, in order, with no framing in it"
        );
        let Tunnel::H3(lane) = &tunnel else {
            panic!("an h3 lane");
        };
        // The window's own size is the claim: a lane that read the first 64 KiB of the download at open, or staged a frame before handing it over, needed a wider one, and every byte the caller got was identical either way.
        assert_eq!(
            lane.head.capacity(),
            H3_PEEK,
            "the frame window is one header wide, not a frame wide"
        );
        // The window holds at most a header and the spill of the frame it names: under the old lane this is where the whole 16 KiB frame sat before any of it reached the caller.
        assert!(
            lane.filled - lane.carried <= H3_PEEK,
            "the window staged {} bytes of a frame the caller was reading",
            lane.filled - lane.carried
        );
        assert_eq!(lane.body, 0, "the frame in flight was delivered, not kept");
        assert_eq!(
            lane.capsule_buf.len(),
            0,
            "nothing the tunnel does not read was left on the lane"
        );
        edge.join().expect("joins");
    }

    /// A read that crosses a frame boundary hands the caller one buffer's worth of bytes and no more: the old lane stopped at every frame, so a caller reading 4096 bytes asked the edge for 16 KiB and was answered in pieces.
    #[test]
    fn an_h3_read_crosses_the_frames_under_it() {
        const FRAME: usize = 512;
        const FRAMES: usize = 32;
        const BUFFER: usize = 4096;
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        // Frames smaller than the caller's buffer: a lane that answers one frame per read stops at every frame's edge, and a lane that fills the buffer takes eight frames at a time.
        let downlink: Vec<u8> = (0..(FRAME * FRAMES) as u64)
            .map(|i| (i % 251) as u8)
            .collect();
        let mut pieces = vec![(h3_answer(), Duration::ZERO)];
        for at in (0..downlink.len()).step_by(FRAME) {
            pieces.push((h3_data(&downlink[at..at + FRAME]), Duration::ZERO));
        }
        let edge = h3_scripted_edge(sock, server, pieces);

        let dial = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
        let quic = crate::quic::direct_stream("localhost", "127.0.0.1", port, &dial.roots)
            .expect("a connection");
        let mut tunnel = Tunnel::open(&dial, "example.com:443", Some(quic)).expect("opens");
        tunnel
            .set_read_quantum(Duration::from_millis(100))
            .expect("arms");

        let mut chunk = vec![0u8; BUFFER];
        let mut got: Vec<u8> = Vec::new();
        let mut reads = 0usize;
        let until = std::time::Instant::now() + Duration::from_secs(30);
        while got.len() < downlink.len() {
            assert!(std::time::Instant::now() < until, "the download arrives");
            match tunnel.read(&mut chunk) {
                Ok(0) => panic!("the lane called the end of the stream with bytes owed"),
                Ok(read) => {
                    assert!(read <= BUFFER, "the lane hands back no more than asked");
                    reads += 1;
                    got.extend_from_slice(&chunk[..read]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("the tunnel failed: {error}"),
            }
        }
        assert_eq!(got, downlink, "every downlink byte arrives, in order");
        // The old lane answered one frame per read and stopped at the frame's edge, so a 4096-byte caller over thirty-two 512-byte frames paid thirty-two reads; the lane that fills the caller's buffer pays the frames the download is cut into.
        assert!(
            reads <= FRAMES / 8 + 1,
            "the lane took {reads} reads for {} bytes, one per frame rather than one per buffer",
            FRAME * FRAMES
        );
        edge.join().expect("joins");
    }

    /// A peer that finishes its stream ends the tunnel: the bytes it sent are the caller's, and the read after them is the end of the stream rather than a wait for a frame that will never come.
    #[test]
    fn an_h3_stream_the_peer_finished_ends_the_tunnel() {
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        let edge = h3_fin_edge(
            sock,
            server,
            vec![
                (h3_answer(), Duration::ZERO),
                (h3_data(b"the last of the tunnel"), Duration::ZERO),
            ],
        );

        let dial = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
        let quic = crate::quic::direct_stream("localhost", "127.0.0.1", port, &dial.roots)
            .expect("a connection");
        let mut tunnel = Tunnel::open(&dial, "example.com:443", Some(quic)).expect("opens");
        tunnel
            .set_read_quantum(Duration::from_millis(100))
            .expect("arms");

        let mut chunk = [0u8; 64];
        let mut got: Vec<u8> = Vec::new();
        let until = std::time::Instant::now() + Duration::from_secs(30);
        // The read that returns nothing is the end of the stream, and it comes after the bytes: a lane that reported the end first would lose them.
        loop {
            assert!(std::time::Instant::now() < until, "the tunnel ends");
            match tunnel.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => got.extend_from_slice(&chunk[..read]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("the tunnel failed: {error}"),
            }
        }
        assert_eq!(
            got, b"the last of the tunnel",
            "the bytes the peer sent arrive before the end of the stream"
        );
        edge.join().expect("joins");
    }

    /// A QUIC edge that answers the request stream with exactly these pieces, each followed by a pause of its own: the frame shapes a plain echo cannot make — a capsule whose first half waits for its second, a header whose block arrives only after the lane has parked on it.
    fn h3_scripted_edge(
        sock: crate::quic::Datagram,
        server: ferrox_core::tls::TlsServerConfig,
        pieces: Vec<(Vec<u8>, Duration)>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut config = crate::quic::serve_config(&server).expect("serves");
            let local = sock.local_addr().expect("addr");
            let mut conn = crate::quic::server_accept(&sock, local, &mut config);
            let mut buf = [0u8; 1350];
            let mut out = [0u8; 1350];
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            let mut stream = None;
            while stream.is_none() {
                assert!(std::time::Instant::now() < deadline, "the request arrives");
                let Some((n, from)) = crate::quic::server_poll(&sock, &mut buf) else {
                    crate::quic::server_idle(&mut conn, &sock, &mut out);
                    continue;
                };
                let info = quiche::RecvInfo { from, to: local };
                conn.recv(&mut buf[..n], info).expect("drives");
                let ids: Vec<u64> = conn.readable().collect();
                for id in ids {
                    if id % 4 != 0 {
                        continue;
                    }
                    if !drain(&mut conn, id).is_empty() {
                        stream = Some(id);
                    }
                }
                crate::quic::server_idle(&mut conn, &sock, &mut out);
            }
            let stream = stream.expect("a request stream");
            for (piece, pause) in pieces {
                // The credit-aware send: a piece the congestion window cannot take is a piece the edge waits for rather than drops, and a script that sends thirty-two frames pays the window's pace.
                assert!(
                    crate::quic::stream_send_all(&mut conn, &sock, stream, &piece, false, deadline,),
                    "the piece reaches the lane"
                );
                crate::quic::server_idle(&mut conn, &sock, &mut out);
                let until = std::time::Instant::now() + pause;
                while std::time::Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(5));
                    crate::quic::server_idle(&mut conn, &sock, &mut out);
                }
            }
            let until = std::time::Instant::now() + Duration::from_millis(400);
            while std::time::Instant::now() < until {
                if let Some((n, from)) = crate::quic::server_poll(&sock, &mut buf) {
                    let info = quiche::RecvInfo { from, to: local };
                    let _ = conn.recv(&mut buf[..n], info);
                }
                crate::quic::server_idle(&mut conn, &sock, &mut out);
            }
        })
    }

    /// The 200 every scripted edge answers with, as the frame the lane peeks rather than reads.
    fn h3_answer() -> Vec<u8> {
        let mut reply = Vec::new();
        frames::quic_varint(&mut reply, frames::H3_HEADERS);
        frames::quic_varint(&mut reply, 3);
        reply.extend_from_slice(&[0x00, 0x00, 0xd9]);
        reply
    }

    /// A scripted edge that finishes its request stream: the pieces land as they are, and then the stream is closed, so the lane sees the peer's fin rather than a frame header it mistook for one.
    fn h3_fin_edge(
        sock: crate::quic::Datagram,
        server: ferrox_core::tls::TlsServerConfig,
        pieces: Vec<(Vec<u8>, Duration)>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut config = crate::quic::serve_config(&server).expect("serves");
            let local = sock.local_addr().expect("addr");
            let mut conn = crate::quic::server_accept(&sock, local, &mut config);
            let mut buf = [0u8; 1350];
            let mut out = [0u8; 1350];
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            let mut stream = None;
            while stream.is_none() {
                assert!(std::time::Instant::now() < deadline, "the request arrives");
                let Some((n, from)) = crate::quic::server_poll(&sock, &mut buf) else {
                    crate::quic::server_idle(&mut conn, &sock, &mut out);
                    continue;
                };
                let info = quiche::RecvInfo { from, to: local };
                conn.recv(&mut buf[..n], info).expect("drives");
                let ids: Vec<u64> = conn.readable().collect();
                for id in ids {
                    if id % 4 != 0 {
                        continue;
                    }
                    if !drain(&mut conn, id).is_empty() {
                        stream = Some(id);
                    }
                }
                crate::quic::server_idle(&mut conn, &sock, &mut out);
            }
            let stream = stream.expect("a request stream");
            for (piece, pause) in pieces {
                assert!(
                    crate::quic::stream_send_all(&mut conn, &sock, stream, &piece, false, deadline,),
                    "the piece reaches the lane"
                );
                crate::quic::server_idle(&mut conn, &sock, &mut out);
                let until = std::time::Instant::now() + pause;
                while std::time::Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(5));
                    crate::quic::server_idle(&mut conn, &sock, &mut out);
                }
            }
            // The fin: the peer is done, and the lane must learn that from the stream rather than from a frame header it read as one. An empty send with the fin flag is how a QUIC stream says "no more", as opposed to the reset a shutdown would send.
            assert!(
                crate::quic::stream_send_all(&mut conn, &sock, stream, &[], true, deadline,),
                "the fin reaches the lane"
            );
            let until = std::time::Instant::now() + Duration::from_millis(400);
            while std::time::Instant::now() < until {
                if let Some((n, from)) = crate::quic::server_poll(&sock, &mut buf) {
                    let info = quiche::RecvInfo { from, to: local };
                    let _ = conn.recv(&mut buf[..n], info);
                }
                crate::quic::server_idle(&mut conn, &sock, &mut out);
            }
        })
    }

    /// One DATA frame holding `payload`, the way an edge sends it: varint kind, varint length, bytes.
    fn h3_data(payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frames::quic_varint(&mut frame, frames::H3_DATA);
        frames::quic_varint(&mut frame, payload.len() as u64);
        frame.extend_from_slice(payload);
        frame
    }

    /// The frame walk read out of a tunnel, with a quantum short enough to park on and a caller that treats a park as a retry rather than an end.
    fn h3_tunnel_reads(tunnel: &mut Tunnel, want: usize) -> Vec<u8> {
        let mut got = Vec::new();
        let mut chunk = [0u8; 8];
        let until = std::time::Instant::now() + Duration::from_secs(30);
        while got.len() < want {
            assert!(std::time::Instant::now() < until, "the tunnel delivers");
            match tunnel.read(&mut chunk) {
                Ok(0) => panic!("the lane called the end of the stream with {want} bytes owed"),
                Ok(read) => got.extend_from_slice(&chunk[..read]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("the tunnel failed: {error}"),
            }
        }
        got
    }

    /// A frame that is exactly one DATAGRAM capsule is read into the caller's own buffer: the staged capsule buffer never grows, so a payload that was copied through it is gone, and a short caller still takes the tail one piece at a time.
    #[test]
    fn a_quic_datagram_in_one_frame_never_enters_the_capsule_buffer() {
        const BODY: usize = 1_350;
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        let wide: Vec<u8> = (0..BODY).map(|i| (i % 251) as u8).collect();
        let mut capsules = Vec::new();
        masque::datagram_encode(&wide, &mut capsules);
        let edge = h3_scripted_edge(
            sock,
            server,
            vec![
                (h3_answer(), Duration::ZERO),
                (h3_data(&capsules), Duration::ZERO),
            ],
        );
        let dial = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
        let quic = crate::quic::direct_stream("localhost", "127.0.0.1", port, &dial.roots)
            .expect("a connection");
        let mut lane = H3::open_udp(&dial, "example.com", 443, quic).expect("opens");
        lane.set_read_quantum(Duration::from_secs(5));
        let staged = lane.capsule_buf.capacity();
        let mut piece = [0u8; 64];
        let mut got = Vec::new();
        let until = std::time::Instant::now() + Duration::from_secs(30);
        while got.len() < BODY {
            assert!(std::time::Instant::now() < until, "the pieces arrive");
            match lane.read_datagram(&mut piece) {
                Ok(0) => panic!("a short read called the end of the stream with its payload owed"),
                Ok(read) => {
                    assert!(read > 0 && read <= piece.len());
                    got.extend_from_slice(&piece[..read]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("the capsule failed: {error}"),
            }
        }
        assert_eq!(got, wide, "every octet once, in the order it was sent");
        assert_eq!(
            lane.capsule_buf.capacity(),
            staged,
            "the payload crossed straight into the caller, not through the capsule buffer"
        );
        assert_eq!(lane.direct, 0, "the frame is spent");
        edge.join().expect("joins");
    }

    /// A DATA frame holding many DATAGRAM capsules advances a cursor instead of draining the buffer per capsule: the consumed prefix stays until the frame is done, and every payload still arrives in order.
    #[test]
    fn a_frame_of_capsules_advances_a_cursor_instead_of_draining() {
        const COUNT: usize = 32;
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        let mut capsules = Vec::new();
        let mut sent = Vec::new();
        for at in 0..COUNT {
            let payload = [at as u8; 8];
            sent.extend_from_slice(&payload);
            masque::datagram_encode(&payload, &mut capsules);
        }
        let edge = h3_scripted_edge(
            sock,
            server,
            vec![
                (h3_answer(), Duration::ZERO),
                (h3_data(&capsules), Duration::ZERO),
            ],
        );
        let dial = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
        let quic = crate::quic::direct_stream("localhost", "127.0.0.1", port, &dial.roots)
            .expect("a connection");
        let mut lane = H3::open_udp(&dial, "example.com", 443, quic).expect("opens");
        lane.set_read_quantum(Duration::from_secs(5));
        let mut got = Vec::new();
        let mut buf = [0u8; 64];
        let until = std::time::Instant::now() + Duration::from_secs(30);
        while got.len() < sent.len() {
            assert!(std::time::Instant::now() < until, "the payloads arrive");
            match lane.read_datagram(&mut buf) {
                Ok(0) => panic!("an empty read with {} bytes owed", sent.len() - got.len()),
                Ok(read) => {
                    got.extend_from_slice(&buf[..read]);
                    if got.len() < sent.len() {
                        assert_eq!(
                            lane.capsule_buf.len(),
                            capsules.len(),
                            "the consumed capsule is a cursor, not a drain"
                        );
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("the capsule failed: {error}"),
            }
        }
        assert_eq!(got, sent, "every payload once, in the order it was sent");
        assert!(
            lane.capsule_buf.is_empty(),
            "nothing is left for the next frame"
        );
        edge.join().expect("joins");
    }

    /// A CONNECT-IP packet that arrives as one DATAGRAM capsule in one frame is read straight into the caller's buffer: the capsule buffer's allocation never grows, so the packet was not staged between the stream and its caller.
    #[test]
    fn a_connect_ip_packet_in_one_frame_is_read_into_the_caller() {
        let (roots, server) = minted(b"h3");
        // A packet wider than one QUIC datagram leaves in two, and a coalescing edge socket would hand its one-datagram read a burst it truncates.
        let sock = crate::quic::Datagram::plain(
            crate::quic::bind_datagram_plain("127.0.0.1:0").expect("binds"),
        );
        let port = sock.local_addr().expect("addr").port();
        let (seen_tx, _seen_rx) = std::sync::mpsc::channel();
        let (udp_tx, udp_rx) = std::sync::mpsc::channel();
        let edge = quic_ip_edge(sock, server, seen_tx, udp_tx, 1);
        let dial = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
        let quic = crate::quic::direct_stream("localhost", "127.0.0.1", port, &dial.roots)
            .expect("a connection");
        let (mut lane, _) = Ip::open(&dial, Some(quic)).expect("opens");
        let wide = vec![0x5a; 1_300];
        assert!(lane
            .write(&[198, 51, 100, 9], &[203, 0, 113, 9], 40_000, 443, &wide)
            .expect("writes"));
        lane.flush().expect("flushes");
        udp_rx
            .recv_timeout(Duration::from_secs(60))
            .expect("the edge read it");
        let mut packet = Vec::with_capacity(2_048);
        let base = packet.as_ptr();
        let staged = match &lane {
            Ip::H3(inner) => inner.capsule_buf.capacity(),
            Ip::H2(_) => unreachable!("an h3 tunnel"),
        };
        assert!(lane.read(&mut packet).expect("reads"), "a reply");
        assert_eq!(
            packet.as_ptr(),
            base,
            "the packet landed in the caller's own allocation"
        );
        assert_eq!(
            packet.capacity(),
            2_048,
            "the caller's buffer did not regrow"
        );
        let Ip::H3(inner) = &lane else {
            unreachable!("an h3 tunnel");
        };
        assert_eq!(
            inner.capsule_buf.capacity(),
            staged,
            "the packet never entered the capsule buffer"
        );
        assert!(inner.capsule_buf.is_empty(), "nothing is left staged");
        assert_eq!(
            connectip::udp_from_packet(&packet).expect("parses").payload,
            &wide[..]
        );
        edge.join().expect("joins");
    }

    /// A DATAGRAM capsule that spans two DATA frames, the second of them 400 ms behind the first: the old lane marked the stream finished on the strength of a frame header, so the first half was the whole answer it reported and the association lost the rest of it.
    #[test]
    fn a_quic_capsule_split_over_frames_arrives_as_one_datagram() {
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        let mut capsule = Vec::new();
        masque::datagram_encode(b"a capsule over two frames", &mut capsule);
        let half = capsule.len() / 2;
        let edge = h3_scripted_edge(
            sock,
            server,
            vec![
                (h3_answer(), Duration::ZERO),
                (h3_data(&capsule[..half]), Duration::from_millis(400)),
                (h3_data(&capsule[half..]), Duration::ZERO),
            ],
        );
        let dial = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
        let quic = crate::quic::direct_stream("localhost", "127.0.0.1", port, &dial.roots)
            .expect("a connection");
        let mut lane = H3::open_udp(&dial, "example.com", 443, quic).expect("opens");
        lane.set_read_quantum(Duration::from_millis(100));
        let mut back = [0u8; 64];
        let until = std::time::Instant::now() + Duration::from_secs(30);
        let read = loop {
            assert!(std::time::Instant::now() < until, "the two halves arrive");
            match lane.read_datagram(&mut back) {
                Ok(0) => panic!("the capsule reader called the end of the stream with its second half still owed"),
                Ok(read) => break read,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("the capsule failed: {error}"),
            }
        };
        assert_eq!(&back[..read], b"a capsule over two frames");
        assert!(!lane.fin, "a frame boundary is not the end of the stream");
        edge.join().expect("joins");
    }

    /// The same debt on the QUIC carrier: a capsule wider than the caller's buffer is paid one buffer at a time, and the capsule behind it is still there to read.
    #[test]
    fn a_quic_datagram_wider_than_the_caller_s_buffer_keeps_its_tail() {
        const BODY: usize = 1_350;
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        let wide: Vec<u8> = (0..BODY).map(|i| (i % 251) as u8).collect();
        let mut capsules = Vec::new();
        masque::datagram_encode(&wide, &mut capsules);
        masque::datagram_encode(b"behind it", &mut capsules);
        let edge = h3_scripted_edge(
            sock,
            server,
            vec![
                (h3_answer(), Duration::ZERO),
                (h3_data(&capsules), Duration::ZERO),
            ],
        );
        let dial = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
        let quic = crate::quic::direct_stream("localhost", "127.0.0.1", port, &dial.roots)
            .expect("a connection");
        let mut lane = H3::open_udp(&dial, "example.com", 443, quic).expect("opens");
        lane.set_read_quantum(Duration::from_millis(100));
        let mut piece = [0u8; 64];
        let mut got = Vec::new();
        let until = std::time::Instant::now() + Duration::from_secs(30);
        while got.len() < BODY {
            assert!(std::time::Instant::now() < until, "the pieces arrive");
            match lane.read_datagram(&mut piece) {
                Ok(0) => panic!(
                    "a short read called the end of the stream with its capsule still staged"
                ),
                Ok(read) => {
                    assert!(
                        read > 0 && read <= piece.len(),
                        "a read reports what its buffer got, not what the capsule holds"
                    );
                    got.extend_from_slice(&piece[..read]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("the capsule failed: {error}"),
            }
        }
        assert_eq!(got, wide, "every octet once, in the order it was sent");
        let mut back = [0u8; 64];
        let read = loop {
            assert!(
                std::time::Instant::now() < until,
                "the next capsule arrives"
            );
            match lane.read_datagram(&mut back) {
                Ok(0) => panic!("the capsule behind it was called the end of the stream"),
                Ok(read) => break read,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("the capsule failed: {error}"),
            }
        };
        assert_eq!(&back[..read], b"behind it");
        assert!(
            lane.capsule_buf.is_empty(),
            "the two spent capsules left nothing staged"
        );
        assert_eq!(lane.handed, 0, "and no cursor either");
        edge.join().expect("joins");
    }

    /// One DATA frame whose block crosses a packet boundary: the header is spent, the first half of the block lands, and the peer goes quiet before the rest of it arrives. The resumed walk owes those bytes to the block it already named, so the tail must land after the head rather than over it.
    #[test]
    fn a_quic_block_that_arrives_in_pieces_keeps_the_pieces_it_already_holds() {
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        let mut capsule = Vec::new();
        masque::datagram_encode(
            b"the head of this block lands first, the tail a packet later",
            &mut capsule,
        );
        let frame = h3_data(&capsule);
        let head = frame.len() - capsule.len();
        let cut = head + capsule.len() / 2;
        let edge = h3_scripted_edge(
            sock,
            server,
            vec![
                (h3_answer(), Duration::ZERO),
                (frame[..cut].to_vec(), Duration::from_millis(400)),
                (frame[cut..].to_vec(), Duration::ZERO),
            ],
        );
        let dial = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
        let quic = crate::quic::direct_stream("localhost", "127.0.0.1", port, &dial.roots)
            .expect("a connection");
        let mut lane = H3::open_udp(&dial, "example.com", 443, quic).expect("opens");
        lane.set_read_quantum(Duration::from_secs(5));
        let mut back = [0u8; 96];
        let until = std::time::Instant::now() + Duration::from_secs(30);
        let read = loop {
            assert!(std::time::Instant::now() < until, "the two pieces arrive");
            match lane.read_datagram(&mut back) {
                Ok(0) => panic!("the block's tail was called the end of the stream"),
                Ok(read) => break read,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("the capsule failed: {error}"),
            }
        };
        assert_eq!(
            &back[..read],
            b"the head of this block lands first, the tail a packet later",
            "the piece that arrived first is still there when the rest lands"
        );
        assert_eq!(lane.capsule_buf.len(), 0, "the spent capsule is not held");
        edge.join().expect("joins");
    }

    /// A HEADERS trailer parked halfway through: its header is spent before its block lands, so the resumed walk must finish the block rather than read the next header out of the trailer's own bytes.
    #[test]
    fn a_quic_trailer_that_parks_mid_block_keeps_the_frames_behind_it() {
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        let mut header_only = Vec::new();
        frames::quic_varint(&mut header_only, frames::H3_HEADERS);
        frames::quic_varint(&mut header_only, 3);
        let edge = h3_scripted_edge(
            sock,
            server,
            vec![
                (h3_answer(), Duration::ZERO),
                (h3_data(b"first"), Duration::ZERO),
                (header_only, Duration::from_millis(400)),
                (vec![0x00, 0x00, 0xd9], Duration::from_millis(200)),
                (h3_data(b"second"), Duration::ZERO),
            ],
        );
        let dial = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
        let quic = crate::quic::direct_stream("localhost", "127.0.0.1", port, &dial.roots)
            .expect("a connection");
        let mut tunnel = Tunnel::open(&dial, "example.com:443", Some(quic)).expect("opens");
        tunnel
            .set_read_quantum(Duration::from_millis(100))
            .expect("arms");
        assert_eq!(
            h3_tunnel_reads(&mut tunnel, b"firstsecond".len()),
            b"firstsecond",
            "the trailer is consumed and the payload behind it arrives whole"
        );
        let Tunnel::H3(lane) = &tunnel else {
            panic!("an h3 lane");
        };
        assert_eq!(lane.capsule_buf.len(), 0, "the trailer left nothing staged");
        assert!(lane.pending.is_none(), "and no half-read block either");
        edge.join().expect("joins");
    }

    /// An empty DATA frame ahead of the payload: it carries no bytes, which is not the same thing as carrying none left.
    #[test]
    fn an_empty_data_frame_is_not_the_end_of_the_tunnel() {
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        let edge = h3_scripted_edge(
            sock,
            server,
            vec![
                (h3_answer(), Duration::from_millis(50)),
                (h3_data(b""), Duration::from_millis(50)),
                (h3_data(b"after the empty one"), Duration::ZERO),
            ],
        );
        let dial = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
        let quic = crate::quic::direct_stream("localhost", "127.0.0.1", port, &dial.roots)
            .expect("a connection");
        let mut tunnel = Tunnel::open(&dial, "example.com:443", Some(quic)).expect("opens");
        tunnel
            .set_read_quantum(Duration::from_millis(100))
            .expect("arms");
        assert_eq!(
            h3_tunnel_reads(&mut tunnel, b"after the empty one".len()),
            b"after the empty one"
        );
        edge.join().expect("joins");
    }

    /// A DATA frame the edge puts ahead of its answer: the head walk could not parse it and asked for more window rather than spending it, so the same header was re-read every turn while the window grew and zeroed another 64 KiB at each floor, and the open failed at its deadline with the answer never reached.
    #[test]
    fn a_frame_ahead_of_the_answer_is_consumed_rather_than_waited_on() {
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        let edge = h3_scripted_edge(
            sock,
            server,
            vec![
                (h3_data(&[0x7fu8; 300]), Duration::from_millis(50)),
                (h3_answer(), Duration::from_millis(50)),
                (h3_data(b"past the padding"), Duration::ZERO),
            ],
        );
        let dial = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
        let quic = crate::quic::direct_stream("localhost", "127.0.0.1", port, &dial.roots)
            .expect("a connection");
        let mut tunnel = Tunnel::open(&dial, "example.com:443", Some(quic))
            .expect("a padded answer still opens");
        assert_eq!(
            h3_tunnel_reads(&mut tunnel, b"past the padding".len()),
            b"past the padding",
            "the frame ahead of the answer costs the payload behind it nothing"
        );
        let Tunnel::H3(lane) = &tunnel else {
            panic!("an h3 lane");
        };
        assert_eq!(
            lane.head.capacity(),
            H3_PEEK,
            "a frame ahead of the answer grew no window"
        );
        assert_eq!(
            lane.capsule_buf.len(),
            0,
            "and left nothing of itself behind"
        );
        edge.join().expect("joins");
    }
}

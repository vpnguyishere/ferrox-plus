//! MASQUE CONNECT-IP over HTTP/3 (RFC 9484): the request names `connect-ip`, the
//! control capsules ride the request stream as HTTP/3 DATA frames, and every IP
//! packet rides a QUIC DATAGRAM with a quarter-stream-id prefix and context zero.
//!
//! A client assigns both families and hands its inner packets to the userspace
//! stack; a server authenticates once, assigns one address per family from each
//! pool, and forwards a packet to the tunnel that owns its destination — or to
//! the stack when no tunnel does.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferrox_core::foxy::connectip::{self, Assigned, Route};
use ferrox_core::foxy::frames;
use ferrox_core::foxy::hpack;
use ferrox_core::foxy::masque as udp_capsule;
use ferrox_core::tls::TlsConfig;

use crate::conn::Connection;
use crate::json::Json;
use crate::proxy::{Destination, Outbound};
use crate::quic::{self, Datagram};
use crate::wg_stack::{self, ClientFlow, Packet, ToTunnel, UdpRoutes};
use crate::wireguard::DeviceConfig;

const TICK: Duration = Duration::from_millis(10);
const WARP_ASSIGN_WAIT: Duration = Duration::from_millis(250);
/// Reconnect schedule: the first dial is immediate, a failure doubles from a second to a
/// minute, and only a lane that lived past the stable window clears the history.
const RECONNECT_INITIAL: Duration = Duration::from_secs(1);
const RECONNECT_MAX: Duration = Duration::from_secs(60);
const RECONNECT_STABLE: Duration = Duration::from_secs(10);
/// The reference's quiet-period keepalive when `xmux.hKeepAlivePeriod` is absent.
const H3_KEEPALIVE: Duration = Duration::from_secs(10);
const H2_KEEPALIVE: Duration = Duration::from_secs(45);
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
const ESTABLISH_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_PATH: &str = "/.well-known/masque/ip/*/*/";
const UDP_PATH_PREFIX: &[u8] = b"/.well-known/masque/udp/";
/// The authority and path xray's WARP transport dials when the config names none.
const WARP_HOST: &str = "cloudflareaccess.com";
pub(crate) const WARP_PROTOCOL: &[u8] = b"cf-connect-ip";
/// The draft-datagram setting Cloudflare's endpoint reads.
const SETTINGS_DATAGRAM_DRAFT: u64 = 0x276;
/// The resolvers xray's MASQUE client asks when `remoteDNS` names none.
const DEFAULT_REMOTE_DNS: [IpAddr; 4] = [
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
];
pub(crate) const DEFAULT_MTU: usize = 1280;
pub(crate) const QUEUE: usize = 512;
/// Datagrams a client may hold before its stack attaches, and their total bytes.
pub(crate) const EARLY_PACKETS: usize = 64;
pub(crate) const EARLY_BYTES: usize = 1 << 20;

/// The most capsule bytes one HTTP/3 request stream may hold while a capsule is incomplete, the
/// same ceiling the HTTP/2 path uses.
const CAPSULE_CAP: usize = 1 << 20;
/// Frames the connection may hold before `dgram_send` refuses more: the
/// reference queues 32, and a peer that drains slower drops what the wire
/// delivers above its own receive queue, which the inner TCP then backs off
/// from for seconds.
const DGRAM_INFLIGHT: usize = 32;
/// The client queues a whole stack batch, not the acknowledgement's grain; the server keeps `DGRAM_INFLIGHT`.
const DGRAM_SEND_QUEUE: usize = QUEUE;
/// A burst the reader has not drained is a lost DATAGRAM and a second of inner TCP RTO; aether asks up to 7 MiB of its lanes.
const MASQUE_BUFFER: i32 = 4 << 20;
/// The server's own connection ID: a short header carries no length, so the demultiplexer reads exactly this many bytes.
const CID_LEN: usize = 16;
pub(crate) const AUTH_REALM: &str = "Basic realm=\"masque\", charset=\"UTF-8\"";
const H3_SETTINGS: u64 = 0x04;
const SETTINGS_H3_DATAGRAM: u64 = 0x33;
const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x8;

/// One client outbound: the conversation it opened, the stack that answers its
/// inner TCP flows, and the per-lane route table its datagrams return through.
pub(crate) struct MasqueOut {
    spec: ClientSpec,
    inner: Mutex<Slot>,
}

#[derive(Debug)]
struct Slot {
    inner: Option<Arc<Inner>>,
    reconnect: Reconnect,
}

#[derive(Debug)]
struct Reconnect {
    attempts: u32,
    next_dial: Instant,
}

impl Reconnect {
    fn new(now: Instant) -> Self {
        Self {
            attempts: 0,
            next_dial: now,
        }
    }

    fn due(&self, now: Instant) -> bool {
        now >= self.next_dial
    }

    fn advance(&mut self, now: Instant) {
        let delay = RECONNECT_INITIAL
            .saturating_mul(1 << self.attempts.min(6))
            .min(RECONNECT_MAX);
        self.attempts = self.attempts.saturating_add(1);
        self.next_dial = now + delay;
    }

    fn reset(&mut self, now: Instant) {
        self.attempts = 0;
        self.next_dial = now;
    }
}

#[derive(Debug)]
struct Inner {
    config: Arc<DeviceConfig>,
    flows: Sender<ClientFlow>,
    to_tunnel: ToTunnel,
    routes: UdpRoutes,
    alive: Arc<AtomicBool>,
    stable: Arc<AtomicBool>,
}

/// A local socket that carries a nested tunnel's datagrams through this conversation.
#[derive(Debug)]
pub(crate) struct UdpForwarder {
    pub(crate) local: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl Drop for UdpForwarder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// The lane names its spec; the spec redacts the headers that carry a token and
/// the key WARP signs with.
impl std::fmt::Debug for MasqueOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasqueOut")
            .field("spec", &self.spec)
            .field("inner", &self.inner)
            .finish()
    }
}

impl MasqueOut {
    pub(crate) fn new(outbound: &Json) -> Result<Self, String> {
        let spec = ClientSpec::from(outbound)?;
        Ok(Self {
            spec,
            inner: Mutex::new(Slot {
                inner: None,
                reconnect: Reconnect::new(Instant::now()),
            }),
        })
    }

    pub(crate) fn edge(&self) -> Option<SocketAddr> {
        crate::proxy::resolve_outbound(&self.spec.address, self.spec.port)
    }

    fn ensure(&self) -> Result<Arc<Inner>, String> {
        self.ensure_at(Instant::now(), || open(&self.spec))
    }

    fn ensure_at(
        &self,
        now: Instant,
        dial: impl FnOnce() -> Result<Inner, String>,
    ) -> Result<Arc<Inner>, String> {
        let mut slot = self
            .inner
            .lock()
            .map_err(|_| "masque: the lane lock is poisoned".to_owned())?;
        if let Some(inner) = slot
            .inner
            .as_ref()
            .filter(|inner| inner.alive.load(Ordering::Acquire))
        {
            return Ok(Arc::clone(inner));
        }
        if let Some(dead) = slot.inner.take() {
            if dead.stable.load(Ordering::Relaxed) {
                slot.reconnect.reset(now);
            } else {
                slot.reconnect.advance(now);
            }
        }
        if !slot.reconnect.due(now) {
            let wait = slot.reconnect.next_dial.duration_since(now);
            return Err(format!(
                "masque: reconnecting in {:.1}s",
                wait.as_secs_f64()
            ));
        }
        let inner = match dial() {
            Ok(inner) => Arc::new(inner),
            Err(reason) => {
                slot.reconnect.advance(now);
                return Err(reason);
            }
        };
        slot.inner = Some(Arc::clone(&inner));
        Ok(inner)
    }

    pub(crate) fn serve_tcp(&self, client: Connection, asked: &Destination, prefix: &[u8]) {
        let inner = match self.ensure() {
            Ok(inner) => inner,
            Err(reason) => {
                eprintln!("masque: {reason}");
                return;
            }
        };
        let Some(destination) = self.resolve(&inner, asked) else {
            eprintln!("masque: destination `{asked:?}` does not resolve");
            return;
        };
        if inner
            .flows
            .send(ClientFlow {
                client,
                destinations: vec![destination],
                prefix: prefix.to_vec(),
            })
            .is_err()
        {
            eprintln!("masque: the userspace stack is gone");
        }
    }

    /// A data-plane probe for the auto race: the tunnel answers a DNS name
    /// before it is trusted with a flow.
    pub(crate) fn probe(&self, host: &str, port: u16) -> bool {
        let Ok(inner) = self.ensure() else {
            return false;
        };
        wg_stack::resolve_over_tunnel(
            &inner.config,
            &inner.to_tunnel,
            &inner.routes,
            &self.spec.remote_dns,
            host,
            port,
        )
        .is_some()
    }

    pub(crate) fn serve_udp(&self, relay: &UdpSocket, associate: Option<&Connection>) {
        match self.ensure() {
            Ok(inner) => {
                let remote = self.spec.remote_dns.as_slice();
                wg_stack::client_udp(
                    relay,
                    &inner.config,
                    &inner.to_tunnel,
                    &inner.routes,
                    associate,
                    &|host, port| {
                        if let Some(answer) = wg_stack::resolve_over_tunnel(
                            &inner.config,
                            &inner.to_tunnel,
                            &inner.routes,
                            remote,
                            host,
                            port,
                        ) {
                            return vec![answer];
                        }
                        crate::proxy::resolve_endpoint(host, port)
                            .into_iter()
                            .collect()
                    },
                    0,
                );
            }
            Err(reason) => eprintln!("masque: {reason}"),
        }
    }

    /// A fixed-target datagram lane through this tunnel, dialled on its first datagram.
    pub(crate) fn udp_forwarder(
        self: &Arc<Self>,
        target: SocketAddr,
    ) -> Result<UdpForwarder, String> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .map_err(|error| format!("masque forwarder: cannot bind: {error}"))?;
        let local = socket
            .local_addr()
            .map_err(|error| format!("masque forwarder: no local address: {error}"))?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let tunnel = Arc::clone(self);
        std::thread::spawn(move || {
            let mut probe = vec![0u8; 65_535];
            let _ = socket.set_read_timeout(Some(TICK));
            let mut reported = false;
            while !thread_stop.load(Ordering::Relaxed) {
                match socket.peek_from(&mut probe) {
                    Ok(_) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(_) => break,
                }
                let inner = match tunnel.ensure() {
                    Ok(inner) => {
                        reported = false;
                        inner
                    }
                    Err(reason) => {
                        if !reported {
                            eprintln!("masque: {reason}");
                            reported = true;
                        }
                        std::thread::sleep(TICK);
                        continue;
                    }
                };
                wg_stack::client_udp_forward(
                    &socket,
                    &inner.config,
                    &inner.to_tunnel,
                    &inner.routes,
                    target,
                    0,
                    &thread_stop,
                );
                std::thread::sleep(TICK);
            }
        });
        Ok(UdpForwarder { local, stop })
    }

    /// A name resolves inside the tunnel the reference names, then falls back to
    /// the host so an unreachable DNS server never makes a name undialable.
    fn resolve(&self, inner: &Inner, asked: &Destination) -> Option<SocketAddr> {
        let Destination::Name(host, port) = asked else {
            return asked.socket();
        };
        wg_stack::resolve_over_tunnel(
            &inner.config,
            &inner.to_tunnel,
            &inner.routes,
            &self.spec.remote_dns,
            host,
            *port,
        )
        .or_else(|| crate::proxy::resolve_endpoint(host, *port))
    }
}

/// Open the carrier the configured security and ALPN select.
fn open(spec: &ClientSpec) -> Result<Inner, String> {
    let Some(tls) = spec.tls.as_deref() else {
        if spec.warp.is_some() {
            return Err("masque warp: security none is not a WARP carrier".to_owned());
        }
        return open_h2c(spec);
    };
    if uses_h1(tls) {
        if spec.warp.is_some() {
            return Err("masque warp: HTTP/1.1 is not a WARP carrier".to_owned());
        }
        return open_h1(spec);
    }
    if uses_h2(tls) {
        return open_h2(spec);
    }
    let (sock, peer, local) = quic::udp_to_server(&spec.address, spec.port)
        .ok_or_else(|| format!("cannot resolve masque `{}:{}`", spec.address, spec.port))?;
    let net = quic::network_generation();
    quic::set_receive_buffer(&sock, MASQUE_BUFFER);
    quic::set_send_buffer(&sock, MASQUE_BUFFER);
    let sock = Datagram::plain(sock);
    let mut lane = establish(spec, &sock, peer, local)?;
    let addresses = lane.addresses.clone();
    let mtu = lane.mtu;
    let initial = std::mem::take(&mut lane.packets);
    let alive = Arc::clone(&lane.alive);
    let keepalive = spec.keepalive(H3_KEEPALIVE);
    Ok(assemble(
        addresses,
        mtu,
        spec.large_segments,
        initial,
        alive,
        move |from_tunnel, to_stack, routes| {
            io(
                lane,
                &sock,
                local,
                peer,
                net,
                keepalive,
                from_tunnel,
                to_stack,
                routes,
            );
        },
    ))
}

/// The reference picks HTTP/2 only when the configured ALPN names it and does
/// not name HTTP/3; anything else takes the QUIC carrier.
fn uses_h2(tls: &TlsConfig) -> bool {
    tls.alpn.iter().any(|protocol| protocol.as_slice() == b"h2")
        && !tls.alpn.iter().any(|protocol| protocol.as_slice() == b"h3")
}

/// The reference has no HTTP/1.1 carrier; the RFC does, and an edge that names
/// only `http/1.1` is asking for it.
fn uses_h1(tls: &TlsConfig) -> bool {
    tls.alpn
        .iter()
        .any(|protocol| protocol.as_slice() == b"http/1.1")
        && !tls.alpn.iter().any(|protocol| protocol.as_slice() == b"h2")
        && !tls.alpn.iter().any(|protocol| protocol.as_slice() == b"h3")
}

/// Open the TLS/HTTP-2 carrier and assemble its tunnel.
fn open_h2(spec: &ClientSpec) -> Result<Inner, String> {
    let edge = resolve_edge(spec)?;
    let mut authority = authority(spec);
    if spec.warp.is_some() && split_host_port(&authority).is_none() {
        authority = format!("{authority}:443");
    }
    let tls = spec
        .tls
        .as_deref()
        .ok_or("masque: HTTP/2 requires security tls")?;
    let keepalive = spec.keepalive(H2_KEEPALIVE);
    let mut client = crate::masque_h2::Client::dial(
        tls,
        tls.insecure,
        spec.warp.as_ref(),
        edge,
        &authority,
        &spec.path,
        &spec.headers,
    )
    .map_err(|reason| format!("masque: {reason}"))?;
    let addresses = client.addresses.clone();
    let mtu = client.mtu;
    let initial = std::mem::take(&mut client.packets);
    Ok(assemble(
        addresses,
        mtu,
        spec.large_segments,
        initial,
        Arc::new(AtomicBool::new(true)),
        move |from_tunnel, to_stack, routes| {
            client.run(&from_tunnel, &to_stack, &routes, keepalive);
        },
    ))
}

/// Open the TLS/HTTP-1.1 carrier and assemble its tunnel.
fn open_h1(spec: &ClientSpec) -> Result<Inner, String> {
    let tls = spec
        .tls
        .as_deref()
        .ok_or("masque: HTTP/1.1 requires security tls")?;
    let edge = resolve_edge(spec)?;
    let authority = authority(spec);
    let mut client =
        crate::masque_h1::Client::dial(tls, edge, &authority, &spec.path, &spec.headers)
            .map_err(|reason| format!("masque: {reason}"))?;
    let addresses = client.addresses.clone();
    let mtu = client.mtu;
    let initial = std::mem::take(&mut client.packets);
    Ok(assemble(
        addresses,
        mtu,
        spec.large_segments,
        initial,
        Arc::new(AtomicBool::new(true)),
        move |from_tunnel, to_stack, routes| {
            client.run(&from_tunnel, &to_stack, &routes);
        },
    ))
}

/// Open the cleartext prior-knowledge HTTP/2 carrier.
fn open_h2c(spec: &ClientSpec) -> Result<Inner, String> {
    let edge = resolve_edge(spec)?;
    let authority = authority(spec);
    let keepalive = spec.keepalive(H2_KEEPALIVE);
    let mut client =
        crate::masque_h2::Client::dial_cleartext(edge, &authority, &spec.path, &spec.headers)
            .map_err(|reason| format!("masque: {reason}"))?;
    let addresses = client.addresses.clone();
    let mtu = client.mtu;
    let initial = std::mem::take(&mut client.packets);
    Ok(assemble(
        addresses,
        mtu,
        spec.large_segments,
        initial,
        Arc::new(AtomicBool::new(true)),
        move |from_tunnel, to_stack, routes| {
            client.run(&from_tunnel, &to_stack, &routes, keepalive);
        },
    ))
}

/// Resolve the configured edge to the first address it names, after the
/// socket config's `addressPortStrategy` replaces it.
fn resolve_edge(spec: &ClientSpec) -> Result<SocketAddr, String> {
    crate::proxy::resolve_outbound(&spec.address, spec.port)
        .ok_or_else(|| format!("masque: cannot resolve `{}:{}`", spec.address, spec.port))
}

/// The stack every carrier feeds, and the thread that hands the handshake's
/// early packets to it before the carrier loop takes over.
fn assemble(
    addresses: Vec<IpAddr>,
    mtu: usize,
    large_segments: bool,
    initial: Vec<Vec<u8>>,
    alive: Arc<AtomicBool>,
    run: impl FnOnce(Receiver<Vec<u8>>, Sender<Packet>, UdpRoutes) + Send + 'static,
) -> Inner {
    let config = Arc::new(DeviceConfig {
        secret: [0u8; 32],
        addresses,
        peers: Vec::new(),
        mtu,
        reserved: [0u8; 3],
        is_client: Some(true),
        no_kernel_tun: true,
        large_segments,
        dns: Vec::new(),
    });
    let (packets_tx, packets_rx) = mpsc::channel();
    let (to_tunnel, from_tunnel) = mpsc::sync_channel(QUEUE);
    let (flows, flow_rx) = mpsc::channel();
    let routes: UdpRoutes = Arc::default();
    let stack_config = Arc::clone(&config);
    let stack_tunnel = to_tunnel.clone();
    let stack_routes = Arc::clone(&routes);
    std::thread::spawn(move || {
        wg_stack::client(
            (*stack_config).clone(),
            stack_tunnel,
            packets_rx,
            flow_rx,
            0,
            stack_routes,
            None,
        );
    });
    let io_routes = Arc::clone(&routes);
    let watch = Arc::clone(&alive);
    let settled = Arc::new(AtomicBool::new(false));
    let stable = Arc::clone(&settled);
    std::thread::spawn(move || {
        let opened = Instant::now();
        for packet in initial {
            deliver(&packets_tx, &io_routes, &packet);
        }
        run(from_tunnel, packets_tx, io_routes);
        if opened.elapsed() >= RECONNECT_STABLE {
            stable.store(true, Ordering::Relaxed);
        }
        watch.store(false, Ordering::Release);
    });
    Inner {
        config,
        flows,
        to_tunnel: to_tunnel.into(),
        routes,
        alive,
        stable: settled,
    }
}

/// One lane that finished its handshake and its first address assignment: the
/// connection and request stream the caller now owns, and what it may source.
struct Lane {
    conn: quiche::Connection,
    stream: u64,
    addresses: Vec<IpAddr>,
    mtu: usize,
    packets: Vec<Vec<u8>>,
    alive: Arc<AtomicBool>,
}

#[derive(Clone)]
struct ClientSpec {
    address: String,
    port: u16,
    tls: Option<Arc<TlsConfig>>,
    path: String,
    host: Option<String>,
    headers: Vec<(String, String)>,
    remote_dns: Vec<IpAddr>,
    warp: Option<Warp>,
    keepalive: Option<i64>,
    large_segments: bool,
}

impl ClientSpec {
    /// Parse an outbound's settings, transport, and WARP block.
    fn from(outbound: &Json) -> Result<Self, String> {
        let settings = outbound
            .get("settings")
            .ok_or("masque outbound has no settings")?;
        let (address, port) =
            if let (Some(address), Some(port)) = (settings.get("address"), settings.get("port")) {
                (
                    address
                        .as_str()
                        .ok_or("masque `address` is not a string")?
                        .to_owned(),
                    port.as_port().ok_or("masque `port` is not a port")?,
                )
            } else {
                let server = settings
                    .get("server")
                    .ok_or("masque outbound has no `address`/`port` or `server`")?;
                if let Json::Str(text) = server {
                    split_host_port(text)
                        .ok_or_else(|| format!("masque server `{text}` has no port"))?
                } else {
                    let address = server
                        .get("address")
                        .and_then(Json::as_str)
                        .ok_or("masque server has no `address`")?;
                    let port = server
                        .get("port")
                        .and_then(Json::as_port)
                        .ok_or("masque server has no `port`")?;
                    (address.to_owned(), port)
                }
            };
        let security = outbound
            .get("streamSettings")
            .and_then(|settings| settings.get("security"))
            .and_then(Json::as_str)
            .unwrap_or("tls");
        let tls = if security.eq_ignore_ascii_case("none") {
            None
        } else {
            Some(crate::config::outbound_tls(outbound, &address)?)
        };
        let transport = outbound
            .get("streamSettings")
            .and_then(|settings| settings.get("masqueSettings"));
        let warp = transport
            .and_then(|settings| settings.get("warp"))
            .map(Warp::from)
            .transpose()?;
        let user = transport
            .and_then(|settings| settings.get("user"))
            .and_then(Json::as_str)
            .unwrap_or_default();
        let pass = transport
            .and_then(|settings| settings.get("pass"))
            .and_then(Json::as_str)
            .unwrap_or_default();
        if warp.is_some() && (!user.is_empty() || !pass.is_empty()) {
            return Err("masque warp: `user` and `pass` cannot be used with `warp`".to_owned());
        }
        let path = expand_path(
            transport
                .and_then(|settings| settings.get("path"))
                .and_then(Json::as_str)
                .filter(|path| !path.is_empty())
                .unwrap_or(if warp.is_some() { "/" } else { DEFAULT_PATH }),
        );
        let host = transport
            .and_then(|settings| settings.get("host"))
            .and_then(Json::as_str)
            .filter(|host| !host.is_empty())
            .map(str::to_owned)
            .or_else(|| warp.as_ref().map(|_| WARP_HOST.to_owned()));
        let mut headers = client_headers(transport);
        credentials(user, pass, &mut headers)?;
        let keepalive = keepalive(transport)?;
        let remote_dns = remote_dns(settings)?;
        let large_segments = settings
            .get("largeSegments")
            .and_then(Json::as_bool)
            .unwrap_or(false);
        Ok(Self {
            address,
            port,
            tls,
            path,
            host,
            headers,
            remote_dns,
            warp,
            keepalive,
            large_segments,
        })
    }

    /// The keepalive the carrier sends when it has been quiet: xray's
    /// `xmux.hKeepAlivePeriod` in seconds, or the carrier's own default.
    fn keepalive(&self, default: Duration) -> Option<Duration> {
        match self.keepalive {
            None | Some(0) => Some(default),
            Some(seconds) if seconds > 0 => Some(Duration::from_secs(seconds as u64)),
            Some(_) => None,
        }
    }
}

impl std::fmt::Debug for ClientSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let headers: Vec<&str> = self.headers.iter().map(|(name, _)| name.as_str()).collect();
        f.debug_struct("ClientSpec")
            .field("address", &self.address)
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field("path", &self.path)
            .field("host", &self.host)
            .field("headers", &headers)
            .field("remote_dns", &self.remote_dns)
            .field("warp", &self.warp)
            .field("keepalive", &self.keepalive)
            .field("large_segments", &self.large_segments)
            .finish()
    }
}

/// The Basic header xray writes for `user`/`pass`, and the headers it refuses beside them.
fn credentials(user: &str, pass: &str, headers: &mut Vec<(String, String)>) -> Result<(), String> {
    if user.is_empty() && pass.is_empty() {
        return Ok(());
    }
    if user.contains(':') {
        return Err("masque `user` contains a colon".to_owned());
    }
    if headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("authorization"))
    {
        return Err(
            "masque `headers` cannot contain `authorization` when `user` or `pass` is set"
                .to_owned(),
        );
    }
    let token = ferrox_core::b64::encode(format!("{user}:{pass}").as_bytes());
    headers.push(("authorization".to_owned(), format!("Basic {token}")));
    Ok(())
}

/// The path templates xray accepts resolve to the wildcard query it sends.
fn expand_path(path: &str) -> String {
    path.replace("{target}", "*")
        .replace("{ipproto}", "*")
        .replace("{?target,ipproto}", "?target=*&ipproto=*")
        .replace("{?ipproto,target}", "?ipproto=*&target=*")
        .replace("{&target,ipproto}", "&target=*&ipproto=*")
        .replace("{&ipproto,target}", "&ipproto=*&target=*")
}

/// Read configured headers, lowercasing names as the reference does.
fn client_headers(transport: Option<&Json>) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> =
        match transport.and_then(|settings| settings.get("headers")) {
            Some(Json::Arr(items)) => items
                .iter()
                .filter_map(|entry| {
                    Some((
                        entry.get("name")?.as_str()?.to_ascii_lowercase(),
                        entry.get("value")?.as_str()?.to_owned(),
                    ))
                })
                .collect(),
            Some(Json::Obj(pairs)) => pairs
                .iter()
                .map(|(name, value)| {
                    (
                        name.to_ascii_lowercase(),
                        value.as_str().unwrap_or_default().to_owned(),
                    )
                })
                .collect(),
            _ => Vec::new(),
        };
    headers.retain(|(name, _)| {
        !name.eq_ignore_ascii_case("capsule-protocol")
            && !name.eq_ignore_ascii_case("host")
            && !name.starts_with(':')
    });
    browser_user_agent(&mut headers);
    headers
}

/// xray's `xmux.hKeepAlivePeriod` is seconds; a zero names the carrier default and a negative value disables it.
fn keepalive(transport: Option<&Json>) -> Result<Option<i64>, String> {
    let Some(seconds) = transport
        .and_then(|settings| settings.get("xmux"))
        .and_then(|xmux| xmux.get("hKeepAlivePeriod"))
    else {
        return Ok(None);
    };
    seconds
        .as_i64()
        .map(Some)
        .ok_or_else(|| "masque `xmux.hKeepAlivePeriod` is not an integer".to_owned())
}

fn remote_dns(settings: &Json) -> Result<Vec<IpAddr>, String> {
    match settings.get("remoteDNS") {
        Some(Json::Arr(items)) if !items.is_empty() => items
            .iter()
            .map(|item| {
                item.as_str()
                    .ok_or("masque `remoteDNS` is not an array of addresses")?
                    .parse()
                    .map_err(|_| "masque `remoteDNS` names a non-address".to_owned())
            })
            .collect(),
        Some(Json::Arr(_)) | None => Ok(DEFAULT_REMOTE_DNS.to_vec()),
        Some(_) => Err("masque `remoteDNS` is not an array".to_owned()),
    }
}

/// Cloudflare's WARP dialect of the same tunnel: the config carries the key
/// pair instead of a password, the client mints its own certificate from that
/// key, the endpoint authenticates by its public key rather than a chain, and
/// the static addresses stand in when the proxy assigns none.
#[derive(Clone)]
pub(crate) struct Warp {
    public_key: Vec<u8>,
    certificate: Vec<u8>,
    key: Vec<u8>,
    addresses: Vec<IpAddr>,
}

impl std::fmt::Debug for Warp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Warp")
            .field("public_key", &self.public_key)
            .field("certificate", &"<redacted>")
            .field("key", &"<redacted>")
            .field("addresses", &self.addresses)
            .finish()
    }
}

impl Drop for Warp {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.key.zeroize();
    }
}

impl Warp {
    fn from(json: &Json) -> Result<Self, String> {
        let private = json
            .get("privateKey")
            .and_then(Json::as_str)
            .ok_or("masque warp has no `privateKey`")?;
        let public = json
            .get("publicKey")
            .and_then(Json::as_str)
            .ok_or("masque warp has no `publicKey`")?;
        let addresses = json
            .get("address")
            .and_then(Json::as_arr)
            .ok_or("masque warp has no `address`")?;
        let private = zeroize::Zeroizing::new(warp_key(private)?);
        let private = zeroize::Zeroizing::new(warp_pkcs8(&private)?);
        let (certificate, key) = warp_identity(&private)?;
        Ok(Self {
            public_key: warp_key(public)?,
            certificate,
            key,
            addresses: warp_addresses(addresses)?,
        })
    }

    pub(crate) fn local_addresses(&self) -> Vec<IpAddr> {
        self.addresses.clone()
    }

    pub(crate) fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub(crate) fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    pub(crate) fn key(&self) -> &[u8] {
        &self.key
    }
}

/// A key is a PEM block or base64 DER, the two forms xray's decoder accepts.
fn warp_key(text: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let text = text.trim();
    let body: String = if text.contains("-----BEGIN") {
        text.lines()
            .filter(|line| !line.starts_with("-----"))
            .collect()
    } else {
        text.to_owned()
    };
    let der = base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|_| "masque warp key is neither PEM nor base64".to_owned())?;
    if der.is_empty() {
        return Err("masque warp key is empty".to_owned());
    }
    Ok(der)
}

/// xray accepts a PKCS #8 or SEC 1 private key; the backend here reads PKCS #8,
/// so a SEC 1 key is wrapped in the fixed P-256 PKCS #8 envelope first.
fn warp_pkcs8(der: &[u8]) -> Result<Vec<u8>, String> {
    let mut at = 0;
    let Some((0x30, body, _)) = der_next(der, &mut at) else {
        return Err("masque warp private key is not DER".to_owned());
    };
    let mut inner = 0;
    let Some((0x02, _, _)) = der_next(body, &mut inner) else {
        return Err("masque warp private key has no version".to_owned());
    };
    let Some((tag, _, _)) = der_next(body, &mut inner) else {
        return Err("masque warp private key is truncated".to_owned());
    };
    match tag {
        0x30 => Ok(der.to_vec()),
        0x04 => Ok(wrap_sec1(der)),
        _ => Err("masque warp private key is not PKCS #8 or SEC 1".to_owned()),
    }
}

fn wrap_sec1(sec1: &[u8]) -> Vec<u8> {
    let algorithm = [
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    ];
    let mut inner = vec![0x02, 0x01, 0x00];
    inner.extend_from_slice(&algorithm);
    inner.push(0x04);
    der_length(sec1.len(), &mut inner);
    inner.extend_from_slice(sec1);
    let mut out = vec![0x30];
    der_length(inner.len(), &mut out);
    out.extend_from_slice(&inner);
    out
}

/// The certificate xray mints for a WARP dial: a P-256 self-signed identity
/// with a fresh serial and a long validity, carrying the config's key.
fn warp_identity(private: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let checked = rcgen::KeyPair::try_from(private)
        .map_err(|error| format!("masque warp private key: {error}"))?;
    if checked.algorithm() != &rcgen::PKCS_ECDSA_P256_SHA256 {
        return Err("masque warp private key is not a P-256 key".to_owned());
    }
    let scalar = warp_scalar(private).ok_or("masque warp private key carries no key")?;
    let point = checked.public_key_raw();
    if point.len() != 65 {
        return Err("masque warp private key is short of its public key".to_owned());
    }
    let canonical = warp_canonical_pkcs8(scalar, point);
    // the backend's loader wants the public key inside the SEC 1 envelope, where the reference's accepts the bare form
    let key = rcgen::KeyPair::try_from(canonical.as_slice())
        .map_err(|error| format!("masque warp canonical key: {error}"))?;
    let mut serial = [0u8; 16];
    getrandom::fill(&mut serial).map_err(|error| format!("masque warp serial: {error}"))?;
    let mut params = rcgen::CertificateParams::default();
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2100, 1, 1);
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));
    let certificate = params
        .self_signed(&key)
        .map_err(|error| format!("masque warp certificate: {error}"))?;
    Ok((certificate.der().to_vec(), canonical))
}

/// The private scalar of an already-PKCS #8 key: a bare octet or the octet of
/// a SEC 1 envelope whose scalar element is found.
fn warp_scalar(pkcs8: &[u8]) -> Option<&[u8]> {
    let mut at = 0;
    let Some((0x30, body, _)) = der_next(pkcs8, &mut at) else {
        return None;
    };
    let mut inner = 0;
    let Some((0x02, _, _)) = der_next(body, &mut inner) else {
        return None;
    };
    let mut at_element = inner;
    for _ in 0..2 {
        let (tag, value, _) = der_next(body, &mut at_element)?;
        if tag == 0x04 {
            return warp_scalar_element(value);
        }
    }
    None
}

fn warp_scalar_element(field: &[u8]) -> Option<&[u8]> {
    if field.len() == 32 {
        return Some(field);
    }
    let mut at = 0;
    let Some((0x30, body, _)) = der_next(field, &mut at) else {
        return None;
    };
    let mut inner = 0;
    while inner < body.len() {
        let Some((tag, value, _)) = der_next(body, &mut inner) else {
            break;
        };
        if tag == 0x04 && value.len() == 32 {
            return Some(value);
        }
    }
    None
}

/// PKCS #8 in the socket-loadable shape: the SEC 1 envelope carries the public
/// key, without which the backend refuses the same key xray accepts.
fn warp_canonical_pkcs8(scalar: &[u8], point: &[u8]) -> Vec<u8> {
    let mut sec1 = vec![0x02, 0x01, 0x01, 0x04, 0x20];
    sec1.extend_from_slice(scalar);
    let mut bit = vec![0x03, 0x42, 0x00];
    bit.extend_from_slice(point);
    let mut element = vec![0xa1, bit.len() as u8];
    element.extend_from_slice(&bit);
    sec1.extend_from_slice(&element);
    let mut sec1_element = vec![0x30];
    der_length(sec1.len(), &mut sec1_element);
    sec1_element.extend_from_slice(&sec1);
    let mut body = vec![0x02, 0x01, 0x00];
    body.extend_from_slice(&[
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    ]);
    body.push(0x04);
    der_length(sec1_element.len(), &mut body);
    body.extend_from_slice(&sec1_element);
    let mut pkcs8 = vec![0x30];
    der_length(body.len(), &mut pkcs8);
    pkcs8.extend_from_slice(&body);
    pkcs8
}

/// At most one IPv4 and one IPv6 prefix, the bind xray enforces; the address is
/// the local endpoint the config names, not a subnet's network address.
fn warp_addresses(items: &[Json]) -> Result<Vec<IpAddr>, String> {
    let mut addresses = Vec::with_capacity(items.len());
    let mut has4 = false;
    let mut has6 = false;
    for item in items {
        let text = item
            .as_str()
            .ok_or("masque warp `address` is not a string")?;
        let (address, prefix) = if let Some((address, prefix)) = text.split_once('/') {
            (
                address
                    .parse::<IpAddr>()
                    .map_err(|_| format!("masque warp address `{text}` is not an address"))?,
                prefix
                    .parse::<u8>()
                    .map_err(|_| format!("masque warp prefix `{text}` is not a number"))?,
            )
        } else {
            let address = text
                .parse::<IpAddr>()
                .map_err(|_| format!("masque warp address `{text}` is not an address"))?;
            let bits = if address.is_ipv4() { 32 } else { 128 };
            (address, bits)
        };
        let bits = if address.is_ipv4() { 32 } else { 128 };
        if prefix > bits {
            return Err(format!("masque warp prefix `{text}` is too long"));
        }
        if address.is_ipv4() {
            if has4 {
                return Err("masque warp `address` names two IPv4 addresses".to_owned());
            }
            has4 = true;
        } else {
            if has6 {
                return Err("masque warp `address` names two IPv6 addresses".to_owned());
            }
            has6 = true;
        }
        addresses.push(address);
    }
    if addresses.is_empty() {
        return Err("masque warp needs an address".to_owned());
    }
    Ok(addresses)
}

/// One DER element: tag, value and the raw bytes the tag and length cover.
fn der_next<'a>(buf: &'a [u8], at: &mut usize) -> Option<(u8, &'a [u8], &'a [u8])> {
    let start = *at;
    let tag = *buf.get(start)?;
    let mut at_value = start.checked_add(1)?;
    let first = *buf.get(at_value)?;
    at_value += 1;
    let length = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        let octets = usize::from(first & 0x7f);
        if octets == 0 || octets > 3 {
            return None;
        }
        let mut length = 0usize;
        for _ in 0..octets {
            length = (length << 8) | usize::from(*buf.get(at_value)?);
            at_value += 1;
        }
        length
    };
    let end = at_value.checked_add(length)?;
    let value = buf.get(at_value..end)?;
    *at = end;
    Some((tag, value, &buf[start..end]))
}

fn der_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
}

/// The `SubjectPublicKeyInfo` inside a leaf certificate, the field xray pins
/// WARP's endpoint to: the certificate's eighth child once the optional version
/// is counted.
pub(crate) fn warp_spki(leaf: &[u8]) -> Option<&[u8]> {
    let mut at = 0;
    let (tag, certificate, _) = der_next(leaf, &mut at)?;
    if tag != 0x30 {
        return None;
    }
    let mut tbs_at = 0;
    let (tag, tbs, _) = der_next(certificate, &mut tbs_at)?;
    if tag != 0x30 {
        return None;
    }
    let mut first_at = 0;
    let (first, _, _) = der_next(tbs, &mut first_at)?;
    let target = usize::from(first == 0xa0) + 5;
    let mut index = 0;
    let mut at = 0;
    while let Some((_, _, raw)) = der_next(tbs, &mut at) {
        if index == target {
            return Some(raw);
        }
        index += 1;
    }
    None
}

/// xray reads a browser name as a request for its own masked set rather than a literal value, and a
/// bare `golang` as a request to send none.
fn browser_user_agent(headers: &mut Vec<(String, String)>) {
    let Some(at) = headers
        .iter()
        .position(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
    else {
        headers.push((
            "user-agent".to_owned(),
            crate::headers::CHROME_UA.to_owned(),
        ));
        return;
    };
    let value = headers[at].1.as_str();
    if value.is_empty() || value.eq_ignore_ascii_case("golang") {
        headers.remove(at);
    } else if ["chrome", "firefox", "safari", "edge", "curl"]
        .iter()
        .any(|browser| value.eq_ignore_ascii_case(browser))
    {
        crate::headers::CHROME_UA.clone_into(&mut headers[at].1);
    }
}

fn split_host_port(text: &str) -> Option<(String, u16)> {
    let text = text.trim();
    if let Some(rest) = text.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        return Some((host.to_owned(), port.parse().ok()?));
    }
    let (host, port) = text.rsplit_once(':')?;
    Some((host.to_owned(), port.parse().ok()?))
}

fn client_config(spec: &ClientSpec) -> Result<quiche::Config, String> {
    if let Some(warp) = &spec.warp {
        return warp_config(warp);
    }
    let tls = spec
        .tls
        .as_deref()
        .ok_or("masque: the QUIC carrier requires security tls")?;
    let mut config = if tls.insecure || !tls.cert_pins.is_empty() {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
            .map_err(|error| format!("masque TLS: {error}"))?;
        config.verify_peer(false);
        if !quic::tune(&mut config, quic::ALPN) {
            return Err("masque cannot name the h3 protocol".to_owned());
        }
        config
    } else {
        quic::quiche_config(&tls.roots, None)
            .ok_or("masque: no certificate authorities for the edge")?
    };
    config.enable_dgram(true, quic::MAX_DATAGRAM, DGRAM_SEND_QUEUE);
    Ok(config)
}

/// The WARP TLS handshake: the client presents the certificate minted from the
/// config's key and accepts the endpoint's certificate, whose public key
/// `verify_edge` checks once the handshake finishes.
fn warp_config(warp: &Warp) -> Result<quiche::Config, String> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|error| format!("masque TLS: {error}"))?;
    config.verify_peer(false);
    if !quic::tune(&mut config, quic::ALPN) {
        return Err("masque cannot name the h3 protocol".to_owned());
    }
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|error| format!("masque warp nonce: {error}"))?;
    let base = std::env::temp_dir();
    let stem = format!(
        "ferrox-warp-{}-{:032x}",
        std::process::id(),
        u128::from_le_bytes(nonce)
    );
    let certificate = base.join(format!("{stem}.crt"));
    let key = base.join(format!("{stem}.key"));
    stage_private(
        &certificate,
        &quic::der_to_pem(&warp.certificate, "CERTIFICATE"),
    )?;
    let key_pem = zeroize::Zeroizing::new(quic::der_to_pem(&warp.key, "PRIVATE KEY"));
    if let Err(reason) = stage_private(&key, &key_pem) {
        let _ = std::fs::remove_file(&certificate);
        return Err(reason);
    }
    let loaded = certificate
        .to_str()
        .and_then(|certificate| {
            key.to_str()
                .map(|key| (certificate.to_owned(), key.to_owned()))
        })
        .ok_or("masque warp: the staged path is not UTF-8".to_owned());
    let loaded = loaded.and_then(|(certificate, key)| {
        config
            .load_cert_chain_from_pem_file(&certificate)
            .map_err(|error| format!("masque warp certificate: {error}"))?;
        config
            .load_priv_key_from_pem_file(&key)
            .map_err(|error| format!("masque warp key: {error}"))
    });
    let _ = std::fs::remove_file(&certificate);
    let _ = std::fs::remove_file(&key);
    loaded?;
    config.enable_dgram(true, quic::MAX_DATAGRAM, DGRAM_SEND_QUEUE);
    Ok(config)
}

/// Write a WARP identity file under a fresh 0600 name and never overwrite it.
fn stage_private(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("masque warp staging: {error}"))?;
    std::io::Write::write_all(&mut file, bytes)
        .map_err(|error| format!("masque warp staging: {error}"))
}

fn establish(
    spec: &ClientSpec,
    sock: &Datagram,
    peer: SocketAddr,
    local: SocketAddr,
) -> Result<Lane, String> {
    attempt(spec, sock, peer, local).map_err(|reason| format!("masque: {reason}"))
}

/// Open one QUIC attempt and take its assigned or configured addresses.
fn attempt(
    spec: &ClientSpec,
    sock: &Datagram,
    peer: SocketAddr,
    local: SocketAddr,
) -> Result<Lane, String> {
    let tls = spec
        .tls
        .as_deref()
        .ok_or("masque: the QUIC carrier requires security tls")?;
    let mut config = client_config(spec)?;
    let mut scid = vec![0u8; if spec.warp.is_some() { 20 } else { 16 }];
    getrandom::fill(&mut scid).map_err(|error| format!("masque: no connection id: {error}"))?;
    let cid = quiche::ConnectionId::from_ref(&scid);
    let mut conn = quiche::connect(Some(&tls.server_name), &cid, local, peer, &mut config)
        .map_err(|error| format!("masque: cannot open a connection: {error}"))?;
    quic::drive_handshake_by(&mut conn, sock, local, ESTABLISH_TIMEOUT)
        .ok_or("the QUIC handshake did not finish")?;
    verify_edge(spec, &conn)?;
    open_h3(&mut conn, spec)?;
    let mut stream = Stream::default();
    let status = stream.wait_head(&mut conn, sock, local, HEAD_TIMEOUT)?;
    if !(200..300).contains(&status) {
        return Err(format!("masque: the edge answered {status}"));
    }
    if let Some(warp) = &spec.warp {
        let deadline = Instant::now() + WARP_ASSIGN_WAIT;
        let mut addresses = assigned(&mut stream);
        while addresses.is_none() && Instant::now() < deadline {
            stream.poll(&mut conn, sock, local, TICK)?;
            addresses = assigned(&mut stream);
        }
        return Ok(Lane {
            conn,
            stream: stream.id,
            addresses: addresses.unwrap_or_else(|| warp.local_addresses()),
            mtu: DEFAULT_MTU,
            packets: stream.packets,
            alive: Arc::new(AtomicBool::new(true)),
        });
    }
    send_address_requests(&mut conn, stream.id)?;
    let deadline = Instant::now() + HEAD_TIMEOUT;
    let mut addresses = Vec::new();
    while addresses.is_empty() && Instant::now() < deadline {
        stream.poll(&mut conn, sock, local, TICK)?;
        for capsule in stream.take_capsules() {
            if let Owned::AddressAssign(body) = capsule {
                let mut assigned = Vec::new();
                if connectip::address_assign(&body, &mut assigned).is_some() {
                    addresses.extend(assigned.iter().filter_map(|grant| {
                        (!grant.refused()).then(|| address_of(grant)).flatten()
                    }));
                }
            }
        }
    }
    if addresses.is_empty() {
        return Err("masque: no address assigned".to_owned());
    }
    Ok(Lane {
        conn,
        stream: stream.id,
        addresses,
        mtu: DEFAULT_MTU,
        packets: stream.packets,
        alive: Arc::new(AtomicBool::new(true)),
    })
}

/// Every assignment the edge sent, in order: a WARP client uses the addresses
/// the server routes rather than the ones it was configured with.
fn assigned(stream: &mut Stream) -> Option<Vec<IpAddr>> {
    let mut addresses: Vec<IpAddr> = Vec::new();
    for capsule in stream.take_capsules() {
        let Owned::AddressAssign(body) = capsule else {
            continue;
        };
        let mut grants = Vec::new();
        if connectip::address_assign(&body, &mut grants).is_none() {
            continue;
        }
        for version in [4, 6] {
            if !grants.iter().any(|grant| grant.version == version) {
                continue;
            }
            addresses.retain(|address| {
                let family = if address.is_ipv4() { 4 } else { 6 };
                family != version
            });
            addresses.extend(grants.iter().filter_map(|grant| {
                (grant.version == version && !grant.refused())
                    .then(|| address_of(grant))
                    .flatten()
            }));
        }
    }
    (!addresses.is_empty()).then_some(addresses)
}

/// Check the WARP public key or the configured certificate pins.
fn verify_edge(spec: &ClientSpec, conn: &quiche::Connection) -> Result<(), String> {
    let tls = spec
        .tls
        .as_deref()
        .ok_or("masque: the QUIC carrier requires security tls")?;
    if let Some(warp) = &spec.warp {
        // The enrolled edge key is the verification, independent of CA trust.
        let leaf = conn
            .peer_cert()
            .ok_or("masque warp: the edge sent no certificate")?;
        let spki = warp_spki(leaf).ok_or("masque warp: the edge certificate is malformed")?;
        return if spki == warp.public_key.as_slice() {
            Ok(())
        } else {
            Err("masque warp: the edge public key does not match".to_owned())
        };
    }
    if tls.cert_pins.is_empty() {
        return Ok(());
    }
    let chain: Vec<Vec<u8>> = match conn.peer_cert_chain() {
        Some(chain) => chain.iter().map(|cert| cert.to_vec()).collect(),
        None => conn
            .peer_cert()
            .map(|cert| vec![cert.to_vec()])
            .unwrap_or_default(),
    };
    if ferrox_core::tls::verify_cert_pinned(&chain, &tls.cert_pins, &tls.server_name) {
        Ok(())
    } else {
        Err("masque: the edge certificate does not match the pins".to_owned())
    }
}

fn open_h3(conn: &mut quiche::Connection, spec: &ClientSpec) -> Result<(), String> {
    send_server_settings(conn, 2, 6, 10, spec.warp.is_some())?;
    let authority = authority(spec);
    let mut block = Vec::with_capacity(256 + spec.path.len());
    let protocol = if spec.warp.is_some() {
        WARP_PROTOCOL
    } else {
        b"connect-ip"
    };
    connectip::connect_ip_qpack_named_protocol(
        &authority,
        &spec.path,
        protocol,
        &spec.headers,
        &mut block,
    );
    let mut head = Vec::with_capacity(16 + block.len());
    frames::quic_varint(&mut head, frames::H3_HEADERS);
    frames::quic_varint(&mut head, block.len() as u64);
    head.extend_from_slice(&block);
    send_stream(conn, 0, &head, false)
}

fn send_server_settings(
    conn: &mut quiche::Connection,
    control: u64,
    encoder: u64,
    decoder: u64,
    warp: bool,
) -> Result<(), String> {
    let settings = h3_settings(warp);
    let mut frame = Vec::with_capacity(17 + settings.len());
    frames::quic_varint(&mut frame, 0x00);
    frames::quic_varint(&mut frame, H3_SETTINGS);
    frames::quic_varint(&mut frame, settings.len() as u64);
    frame.extend_from_slice(&settings);
    send_stream(conn, control, &frame, false)?;
    send_stream(conn, encoder, &[0x02], false)?;
    send_stream(conn, decoder, &[0x03], false)
}

fn h3_settings(warp: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(if warp { 25 } else { 18 });
    for (id, value) in [
        (0x01u64, 0u64),
        (0x07, 0),
        (SETTINGS_ENABLE_CONNECT_PROTOCOL, 1),
        (SETTINGS_H3_DATAGRAM, 1),
    ] {
        frames::quic_varint(&mut out, id);
        frames::quic_varint(&mut out, value);
    }
    if warp {
        frames::quic_varint(&mut out, SETTINGS_DATAGRAM_DRAFT);
        frames::quic_varint(&mut out, 1);
    }
    out
}

fn send_stream(
    conn: &mut quiche::Connection,
    stream: u64,
    bytes: &[u8],
    fin: bool,
) -> Result<(), String> {
    let mut rest = bytes;
    loop {
        match conn.stream_send(stream, rest, fin) {
            Ok(0) => return Err("masque: the stream accepted no bytes".to_owned()),
            Ok(wrote) => {
                rest = &rest[wrote..];
                if rest.is_empty() {
                    return Ok(());
                }
            }
            Err(quiche::Error::Done) => return Ok(()),
            Err(error) => return Err(format!("masque: cannot write the stream: {error}")),
        }
    }
}

fn send_address_requests(conn: &mut quiche::Connection, stream: u64) -> Result<(), String> {
    let v4 = [0u8; 4];
    let v6 = [0u8; 16];
    let mut requests = Vec::with_capacity(40);
    connectip::address_requests(&[(1, 4, &v4), (2, 6, &v6)], &mut requests);
    send_data(conn, stream, &requests)
}

fn send_data(conn: &mut quiche::Connection, stream: u64, bytes: &[u8]) -> Result<(), String> {
    let mut head = [0u8; 9];
    let length = frames::h3_data_header(&mut head, bytes.len() as u64);
    let mut frame = Vec::with_capacity(length + bytes.len());
    frame.extend_from_slice(&head[..length]);
    frame.extend_from_slice(bytes);
    send_stream(conn, stream, &frame, false)
}

/// The request authority: configured host, else SNI, with a non-default port.
fn authority(spec: &ClientSpec) -> String {
    if let Some(host) = &spec.host {
        return host.clone();
    }
    let host = spec
        .tls
        .as_deref()
        .map_or(spec.address.as_str(), |tls| tls.server_name.as_str());
    let default = if spec.tls.is_some() { 443 } else { 80 };
    if spec.port == default {
        return host.to_owned();
    }
    if host.parse::<Ipv6Addr>().is_ok() {
        return format!("[{host}]:{}", spec.port);
    }
    format!("{host}:{}", spec.port)
}

/// xray takes a subnet grant's first usable address rather than the raw bytes, so a proxy that assigns a range still names one host.
pub(crate) fn address_of(grant: &Assigned) -> Option<IpAddr> {
    match grant.version {
        4 => {
            let address = u32::from_be_bytes([
                grant.address[0],
                grant.address[1],
                grant.address[2],
                grant.address[3],
            ]);
            let host = 32u32.saturating_sub(u32::from(grant.prefix));
            let mask = if host == 32 {
                u32::MAX
            } else {
                (1u32 << host) - 1
            };
            let network = address & !mask;
            Some(IpAddr::V4(Ipv4Addr::from(if host == 0 {
                network
            } else {
                network.saturating_add(1)
            })))
        }
        6 => {
            let address = u128::from_be_bytes(grant.address);
            let prefix = grant.prefix.min(128);
            let mask = if prefix == 0 {
                u128::MAX
            } else {
                (1u128 << (128 - prefix)) - 1
            };
            let network = address & !mask;
            Some(IpAddr::V6(Ipv6Addr::from(if prefix == 128 {
                network
            } else {
                network.saturating_add(1)
            })))
        }
        _ => None,
    }
}

/// The first address a fresh `ADDRESS_ASSIGN` no longer grants: the capsule
/// replaces the set, so an omitted or refused entry is a withdrawal.
pub(crate) fn withdrawn(body: &[u8], current: &[IpAddr]) -> Option<IpAddr> {
    let mut grants = Vec::new();
    connectip::address_assign(body, &mut grants)?;
    current.iter().copied().find(|address| {
        !grants
            .iter()
            .any(|grant| !grant.refused() && grant_contains(grant, *address))
    })
}

fn grant_contains(grant: &Assigned, address: IpAddr) -> bool {
    match (grant.version, address) {
        (4, IpAddr::V4(address)) => {
            let prefix = grant.prefix.min(32);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            let granted = u32::from_be_bytes([
                grant.address[0],
                grant.address[1],
                grant.address[2],
                grant.address[3],
            ]);
            u32::from(address) & mask == granted & mask
        }
        (6, IpAddr::V6(address)) => {
            let prefix = grant.prefix.min(128);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(address) & mask == u128::from_be_bytes(grant.address) & mask
        }
        _ => false,
    }
}

/// A capsule this lane owns: the parser borrows the stream buffer, and a
/// capsule can arrive while the caller is elsewhere.
enum Owned {
    AddressAssign(Vec<u8>),
    #[cfg(test)]
    Datagram(Vec<u8>),
    Other,
}

/// The request stream's frame state: the head block and the capsule bytes a
/// CONNECT-IP tunnel answers with, kept apart because a frame can split either.
#[derive(Default)]
struct Stream {
    id: u64,
    buf: Vec<u8>,
    at: usize,
    capsules: Vec<u8>,
    capsule_at: usize,
    status: Option<u16>,
    pending: Vec<Owned>,
    done: bool,
    packets: Vec<Vec<u8>>,
    early_bytes: usize,
}

impl Stream {
    /// Hold a datagram until the stack attaches, within the early-buffer caps.
    fn stash(&mut self, datagram: Vec<u8>) -> bool {
        if self.packets.len() >= EARLY_PACKETS
            || self.early_bytes.saturating_add(datagram.len()) > EARLY_BYTES
        {
            return false;
        }
        self.early_bytes += datagram.len();
        self.packets.push(datagram);
        true
    }

    fn wait_head(
        &mut self,
        conn: &mut quiche::Connection,
        sock: &Datagram,
        local: SocketAddr,
        budget: Duration,
    ) -> Result<u16, String> {
        let deadline = Instant::now() + budget;
        while self.status.is_none() {
            if Instant::now() >= deadline {
                return Err("masque: the edge sent no response head".to_owned());
            }
            self.poll(conn, sock, local, TICK)?;
        }
        Ok(self.status.unwrap_or(0))
    }

    fn take_capsules(&mut self) -> Vec<Owned> {
        std::mem::take(&mut self.pending)
    }

    /// Deliver one pump into the request stream and hold every matching datagram, refusing a flood.
    fn poll(
        &mut self,
        conn: &mut quiche::Connection,
        sock: &Datagram,
        local: SocketAddr,
        wait: Duration,
    ) -> Result<(), String> {
        if !quic::pump_once(conn, sock, local, wait) {
            return Err("masque: the connection ended".to_owned());
        }
        if conn.is_closed() {
            return Err("masque: the edge closed the connection".to_owned());
        }
        self.read_stream(conn)?;
        while let Ok(mut datagram) = conn.dgram_recv_buf() {
            let Some((stream, packet)) = connectip::datagram_split(&datagram) else {
                continue;
            };
            if stream == self.id {
                let offset = datagram.len() - packet.len();
                datagram.drain(..offset);
                if !self.stash(datagram) {
                    return Err(
                        "masque: the edge sent too many datagrams before assigning an address"
                            .to_owned(),
                    );
                }
            }
        }
        Ok(())
    }

    fn read_stream(&mut self, conn: &mut quiche::Connection) -> Result<(), String> {
        let mut room = [0u8; 4096];
        loop {
            match conn.stream_recv(self.id, &mut room) {
                Ok((0, fin)) => {
                    self.done = fin;
                    break;
                }
                Ok((n, fin)) => {
                    self.buf.extend_from_slice(&room[..n]);
                    if self.buf.len() > CAPSULE_CAP {
                        return Err("masque: stream buffer exceeds the capsule cap".to_owned());
                    }
                    if fin {
                        self.done = true;
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(error) => return Err(format!("masque: stream read: {error}")),
            }
        }
        self.parse()?;
        Ok(())
    }

    fn parse(&mut self) -> Result<(), String> {
        let mut at = self.at;
        loop {
            let before = at;
            let Some(frame) = frames::h3_frame(&self.buf, &mut at) else {
                at = before;
                break;
            };
            let length = usize::try_from(frame.length)
                .map_err(|_| "masque: frame length does not fit".to_owned())?;
            if length > CAPSULE_CAP {
                return Err("masque: frame exceeds the capsule cap".to_owned());
            }
            let Some(room) = self.buf.get(at..at + length) else {
                at = before;
                break;
            };
            at += length;
            match frame.kind {
                frames::H3_HEADERS if self.status.is_none() => {
                    self.status = hpack::qpack_status(room);
                }
                frames::H3_DATA => self.capsules.extend_from_slice(room),
                _ => {}
            }
        }
        self.buf.drain(..at);
        self.at = 0;
        if let Some((_, declared)) = connectip::capsule_header(&self.capsules[self.capsule_at..]) {
            if declared > CAPSULE_CAP as u64 {
                return Err("masque: capsule exceeds the cap".to_owned());
            }
        }
        while let Some((used, capsule)) =
            connectip::capsule_split(&self.capsules[self.capsule_at..])
        {
            self.capsule_at += used;
            let owned = match capsule {
                connectip::Capsule::AddressAssign(body) => Owned::AddressAssign(body.to_vec()),
                #[cfg(test)]
                connectip::Capsule::Datagram(payload) if payload.len() <= DEFAULT_MTU => {
                    Owned::Datagram(payload.to_vec())
                }
                _ => Owned::Other,
            };
            self.pending.push(owned);
        }
        if self.capsule_at > 0 {
            self.capsules.drain(..self.capsule_at);
            self.capsule_at = 0;
        }
        if self.capsules.len() > CAPSULE_CAP {
            return Err("masque: capsules exceed the cap".to_owned());
        }
        Ok(())
    }
}

/// Writes inner packets to the tunnel and hands the ones it answers back: a TCP
/// packet to the stack, a UDP packet to the loopback lane waiting on its port.
#[allow(clippy::needless_pass_by_value)]
#[allow(clippy::too_many_arguments)]
fn io(
    lane: Lane,
    sock: &Datagram,
    local: SocketAddr,
    peer: SocketAddr,
    net: u64,
    keepalive: Option<Duration>,
    from_tunnel: Receiver<Vec<u8>>,
    to_stack: Sender<Packet>,
    routes: UdpRoutes,
) {
    let mut local = local;
    let mut generation = net;
    let mut moved = false;
    let Lane {
        mut conn,
        stream,
        addresses,
        ..
    } = lane;
    let mut control = Stream {
        id: stream,
        ..Stream::default()
    };
    let mut unsent: Option<Vec<u8>> = None;
    let mut keepalive_at = keepalive.map(|period| Instant::now() + period);
    loop {
        let now = quic::network_generation();
        if now != generation {
            match quic::rebind_path(&mut conn, sock, peer) {
                quic::Rebind::Moved(at) => {
                    local = at;
                    moved = true;
                    generation = now;
                }
                quic::Rebind::Same | quic::Rebind::Retry | quic::Rebind::Unsupported => {
                    generation = now;
                }
                quic::Rebind::Failed => {
                    let _ = conn.close(false, 0, b"rebind");
                    break;
                }
            }
        }
        let sent_before = conn.stats().sent;
        let recv_before = conn.stats().recv;
        while let Some(packet) = unsent.take().or_else(|| from_tunnel.try_recv().ok()) {
            match send_datagram(&mut conn, stream, &packet) {
                Emission::Queued => {}
                Emission::Full => {
                    unsent = Some(packet);
                    break;
                }
                Emission::TooLarge(icmp) => {
                    let _ = to_stack.send(Packet {
                        peer: [0u8; 32],
                        bytes: icmp,
                        at: 0,
                    });
                }
            }
        }
        quic::flush_egress(&mut conn, sock);
        if !quic::pump_once(&mut conn, sock, local, TICK) || conn.is_closed() {
            break;
        }
        if moved && quic::path_failed(&mut conn, local) {
            let _ = conn.close(false, 0, b"rebind");
            break;
        }
        if let Err(reason) = control.read_stream(&mut conn) {
            eprintln!("masque: {reason}");
            break;
        }
        let mut withdrew = false;
        for capsule in control.take_capsules() {
            if let Owned::AddressAssign(body) = capsule {
                if let Some(address) = withdrawn(&body, &addresses) {
                    eprintln!("masque: the proxy withdrew {address}");
                    withdrew = true;
                }
            }
        }
        if withdrew || control.done {
            break;
        }
        while let Ok(datagram) = conn.dgram_recv_buf() {
            let Some((id, packet)) = connectip::datagram_split(&datagram) else {
                continue;
            };
            if id != stream {
                continue;
            }
            let offset = datagram.len() - packet.len();
            deliver_owned(&to_stack, &routes, datagram, offset);
        }
        if let Some(period) = keepalive {
            let now = Instant::now();
            if conn.stats().sent != sent_before || conn.stats().recv != recv_before {
                keepalive_at = Some(now + period);
            }
            if keepalive_at.is_some_and(|at| now >= at) {
                let _ = conn.send_ack_eliciting();
                keepalive_at = Some(now + period);
            }
        }
        quic::flush_egress(&mut conn, sock);
    }
}

enum Delivery {
    Udp(Sender<Vec<u8>>),
    Stack,
}

fn delivery(routes: &UdpRoutes, packet: &[u8]) -> Option<Delivery> {
    if wg_stack::ipv4_fragment(packet) {
        return Some(Delivery::Stack);
    }
    if let Some(datagram) = connectip::udp_from_packet(packet) {
        if !datagram.verified {
            return None;
        }
        return routes
            .lock()
            .ok()?
            .get(&datagram.destination_port)
            .cloned()
            .map(Delivery::Udp);
    }
    wg_stack::stack_packet(packet).then_some(Delivery::Stack)
}

pub(crate) fn deliver(to_stack: &Sender<Packet>, routes: &UdpRoutes, packet: &[u8]) {
    match delivery(routes, packet) {
        Some(Delivery::Udp(lane)) => {
            let _ = lane.send(packet.to_vec());
        }
        Some(Delivery::Stack) => {
            let _ = to_stack.send(Packet {
                peer: [0u8; 32],
                bytes: packet.to_vec(),
                at: 0,
            });
        }
        None => {}
    }
}

/// Hand a datagram's inner packet to the stack or a UDP lane, retaining the prefix the stack records as its offset.
fn deliver_owned(
    to_stack: &Sender<Packet>,
    routes: &UdpRoutes,
    mut datagram: Vec<u8>,
    offset: usize,
) {
    let Some(to) = delivery(routes, &datagram[offset..]) else {
        return;
    };
    match to {
        Delivery::Udp(lane) => {
            datagram.drain(..offset);
            let _ = lane.send(datagram);
        }
        Delivery::Stack => {
            let _ = to_stack.send(Packet {
                peer: [0u8; 32],
                bytes: datagram,
                at: offset,
            });
        }
    }
}

enum Emission {
    Queued,
    Full,
    TooLarge(Vec<u8>),
}

/// One inner packet on its stream, or the ICMP Packet Too Big it needs instead when the lane cannot carry it: the MTU the answer names is what the inner stack has left after the stream prefix.
fn send_datagram(conn: &mut quiche::Connection, stream: u64, packet: &[u8]) -> Emission {
    let Some(max) = conn.dgram_max_writable_len() else {
        return Emission::Full;
    };
    // The stream prefix's width decides the fit, so a packet answered with ICMP or refused has never been staged.
    let overhead = frames::quic_varint_len(stream / 4) + 1;
    if overhead.saturating_add(packet.len()) > max {
        let Some(icmp) = max
            .checked_sub(overhead)
            .and_then(|mtu| connectip::icmp_too_large(packet, mtu))
        else {
            return Emission::Queued;
        };
        return Emission::TooLarge(icmp);
    }
    let mut datagram = Vec::with_capacity(overhead + packet.len());
    connectip::datagram_prefix(stream, &mut datagram);
    datagram.extend_from_slice(packet);
    // Only a full queue asks for the packet back; any other failure is the connection ending, which the loop's own close check ends. The prefixed datagram is handed to quiche's queue, not copied into it.
    match conn.dgram_send_buf(datagram) {
        Err(quiche::Error::Done) => Emission::Full,
        _ => Emission::Queued,
    }
}

/// Bind the h2 listener first on an ephemeral port, then join the QUIC socket to it,
/// retrying a UDP collision. A failed pair falls back to UDP-first so h3 still serves.
fn pair_h2_ephemeral(
    address: &str,
) -> std::io::Result<(UdpSocket, SocketAddr, Option<TcpListener>)> {
    let mut tries = 0;
    loop {
        let listener = TcpListener::bind(address)?;
        let local = listener.local_addr()?;
        match lane_udp_bind(&local.to_string()) {
            Ok(sock) => return Ok((sock, local, Some(listener))),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse && tries < 8 => {
                tries += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
thread_local! {
    /// The UDP binds a test thread refuses before one is let through, one number the budget
    /// driving test sets so it owns the collision without owning the kernel.
    static HELD_H2_UDP_BINDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The inbound lane's UDP bind, one seam for the tests: a thread that wants the pair's port
/// budget driven without owning the kernel claims the first binds through one counter.
fn lane_udp_bind(address: &str) -> std::io::Result<UdpSocket> {
    #[cfg(test)]
    if HELD_H2_UDP_BINDS.with(std::cell::Cell::get) > 0 {
        HELD_H2_UDP_BINDS.with(|held| held.set(held.get() - 1));
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "the lane the test holds",
        ));
    }
    UdpSocket::bind(address)
}

/// Open a server inbound's socket and spawn its demultiplexer, stack and forwarder.
pub(crate) fn serve_inbound(inbound: &Json, out: &Outbound, address: &str) -> Result<u16, String> {
    let spec = Arc::new(ServerSpec::from(inbound)?);
    let security = inbound
        .get("streamSettings")
        .and_then(|settings| settings.get("security"))
        .and_then(Json::as_str)
        .unwrap_or_default();
    if security.eq_ignore_ascii_case("none") {
        return serve_cleartext_inbound(&spec, out, address);
    }
    let identity = crate::proxy::quic_inbound_identity(inbound)
        .ok_or("masque inbound requires security tls or none")?;
    let Some(mut config) = quic::serve_config(&identity) else {
        return Err("unreadable masque tls identity".to_owned());
    };
    config.enable_dgram(true, quic::MAX_DATAGRAM, DGRAM_INFLIGHT);
    let tcp = identity
        .alpn
        .iter()
        .any(|alpn| alpn == b"h2" || alpn == b"http/1.1");
    let paired = if tcp && address.ends_with(":0") {
        pair_h2_ephemeral(address).ok()
    } else {
        None
    };
    let (sock, local, h2_listener) = if let Some(paired) = paired {
        paired
    } else {
        let sock = lane_udp_bind(address)
            .map_err(|error| format!("cannot bind masque `{address}`: {error}"))?;
        let local = sock
            .local_addr()
            .map_err(|error| format!("masque `{address}` has no local address: {error}"))?;
        let h2_listener = if tcp {
            if let Ok(listener) = TcpListener::bind(local) {
                Some(listener)
            } else {
                eprintln!("masque: no TCP listener on {local}; h3 still serves");
                None
            }
        } else {
            None
        };
        (sock, local, h2_listener)
    };
    quic::set_receive_buffer(&sock, MASQUE_BUFFER);
    quic::set_send_buffer(&sock, MASQUE_BUFFER);
    let sock = Arc::new(Datagram::plain(sock));
    let (packets, packets_rx) = mpsc::channel();
    let shared = Arc::new(Shared {
        pool: Mutex::new(spec.pool.clone()),
        tunnels: Mutex::new(HashMap::new()),
        packets,
        local: spec.pool.server.clone(),
    });
    let (to_tunnel, from_stack) = mpsc::sync_channel(QUEUE);
    let dispatcher = Arc::clone(&shared);
    std::thread::spawn(move || dispatch(&dispatcher, from_stack));
    if let Some(listener) = h2_listener {
        crate::masque_h2::serve(
            Arc::clone(&identity),
            Arc::clone(&shared),
            Arc::clone(&spec),
            listener,
        );
    }
    let device = DeviceConfig {
        secret: [0u8; 32],
        addresses: spec.pool.server.clone(),
        peers: Vec::new(),
        mtu: spec.mtu,
        reserved: [0u8; 3],
        is_client: Some(false),
        no_kernel_tun: true,
        large_segments: false,
        dns: Vec::new(),
    };
    let stack_out = out.clone();
    std::thread::spawn(move || {
        wg_stack::server(device, to_tunnel, packets_rx, stack_out, 0, None);
    });
    let demux_config = Arc::new(Mutex::new(config));
    let demux_sock = Arc::clone(&sock);
    let demux_shared = Arc::clone(&shared);
    let demux_spec = Arc::clone(&spec);
    std::thread::spawn(move || {
        demux(demux_sock, local, demux_config, demux_shared, demux_spec);
    });
    Ok(local.port())
}

/// Open a cleartext inbound's TCP listener and spawn its stack and forwarder.
fn serve_cleartext_inbound(
    spec: &Arc<ServerSpec>,
    out: &Outbound,
    address: &str,
) -> Result<u16, String> {
    let listener = TcpListener::bind(address)
        .map_err(|error| format!("cannot bind masque `{address}`: {error}"))?;
    let local = listener
        .local_addr()
        .map_err(|error| format!("masque `{address}` has no local address: {error}"))?;
    let (packets, packets_rx) = mpsc::channel();
    let shared = Arc::new(Shared {
        pool: Mutex::new(spec.pool.clone()),
        tunnels: Mutex::new(HashMap::new()),
        packets,
        local: spec.pool.server.clone(),
    });
    let (to_tunnel, from_stack) = mpsc::sync_channel(QUEUE);
    let dispatcher = Arc::clone(&shared);
    std::thread::spawn(move || dispatch(&dispatcher, from_stack));
    crate::masque_h2::serve_cleartext(Arc::clone(&shared), Arc::clone(spec), listener);
    let device = DeviceConfig {
        secret: [0u8; 32],
        addresses: spec.pool.server.clone(),
        peers: Vec::new(),
        mtu: spec.mtu,
        reserved: [0u8; 3],
        is_client: Some(false),
        no_kernel_tun: true,
        large_segments: false,
        dns: Vec::new(),
    };
    let stack_out = out.clone();
    std::thread::spawn(move || {
        wg_stack::server(device, to_tunnel, packets_rx, stack_out, 0, None);
    });
    Ok(local.port())
}

#[derive(Clone)]
pub(crate) struct ServerSpec {
    users: Vec<(String, String)>,
    pub(crate) path: String,
    pool: AddressPool,
    mtu: usize,
    pub(crate) warp: bool,
}

impl std::fmt::Debug for ServerSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let users: Vec<&str> = self.users.iter().map(|(email, _)| email.as_str()).collect();
        f.debug_struct("ServerSpec")
            .field("users", &users)
            .field("path", &self.path)
            .field("pool", &self.pool)
            .field("mtu", &self.mtu)
            .field("warp", &self.warp)
            .finish()
    }
}

impl ServerSpec {
    /// Parse an inbound's prefixes, users, and limits.
    fn from(inbound: &Json) -> Result<Self, String> {
        let settings = inbound
            .get("settings")
            .ok_or("masque inbound has no settings")?;
        let users: Vec<(String, String)> = settings
            .get("users")
            .or_else(|| settings.get("clients"))
            .and_then(Json::as_arr)
            .map(|users| {
                users
                    .iter()
                    .filter_map(|user| {
                        let email = user.get("email").and_then(Json::as_str)?.to_owned();
                        let password = user
                            .get("pass")
                            .and_then(Json::as_str)
                            .or_else(|| user.get("password").and_then(Json::as_str))
                            .or_else(|| user.get("account")?.get("password")?.as_str())?
                            .to_owned();
                        Some((email, password))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let warp = settings
            .get("warp")
            .and_then(Json::as_bool)
            .unwrap_or(false);
        if users.is_empty() && !warp {
            return Err("masque inbound has no user with a password".to_owned());
        }
        let addresses: Vec<String> = settings
            .get("address")
            .and_then(Json::as_arr)
            .ok_or("masque inbound has no `address`")?
            .iter()
            .filter_map(Json::as_str)
            .map(str::to_owned)
            .collect();
        if addresses.is_empty() {
            return Err("masque inbound has no address to assign".to_owned());
        }
        let pool = AddressPool::from_prefixes(&addresses)?;
        let path = inbound
            .get("streamSettings")
            .and_then(|settings| settings.get("masqueSettings"))
            .and_then(|settings| settings.get("path"))
            .and_then(Json::as_str)
            .filter(|path| !path.is_empty())
            .map_or_else(|| DEFAULT_PATH.to_owned(), expand_path);
        let mtu = settings
            .get("mtu")
            .and_then(Json::as_u32)
            .filter(|mtu| *mtu > 0)
            .map_or(DEFAULT_MTU, |mtu| mtu as usize);
        Ok(Self {
            users,
            path,
            pool,
            mtu,
            warp,
        })
    }

    pub(crate) fn accepts_protocol(&self, protocol: &[u8]) -> bool {
        protocol == b"connect-ip" || (self.warp && protocol == WARP_PROTOCOL)
    }

    pub(crate) fn path_matches(&self, path: &[u8], protocol: &[u8]) -> bool {
        if self.warp && protocol == WARP_PROTOCOL {
            return path_matches(path, "/");
        }
        path_matches(path, &self.path)
    }

    pub(crate) fn request_authenticated(&self, protocol: &[u8], header: Option<&[u8]>) -> bool {
        (self.warp && protocol == WARP_PROTOCOL) || self.authenticates(header)
    }

    pub(crate) fn udp_authenticated(
        &self,
        proxy: Option<&[u8]>,
        authorization: Option<&[u8]>,
    ) -> bool {
        self.udp_credential(proxy) || self.udp_credential(authorization)
    }

    fn udp_credential(&self, header: Option<&[u8]>) -> bool {
        let Some(text) = header.and_then(|value| std::str::from_utf8(value).ok()) else {
            return false;
        };
        let Some((scheme, token)) = text.split_once(' ') else {
            return false;
        };
        if scheme.eq_ignore_ascii_case("bearer") {
            let token = token.trim();
            self.users.iter().any(|(_, secret)| secret == token)
        } else if scheme.eq_ignore_ascii_case("basic") {
            self.authenticates(header)
        } else {
            false
        }
    }

    pub(crate) fn authenticates(&self, header: Option<&[u8]>) -> bool {
        let Some(text) = header.and_then(|value| std::str::from_utf8(value).ok()) else {
            return false;
        };
        let Some((scheme, token)) = text.split_once(' ') else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("basic") {
            return false;
        }
        let Some(decoded) = ferrox_core::b64::decode(token.trim().as_bytes()) else {
            return false;
        };
        let Ok(credentials) = std::str::from_utf8(&decoded) else {
            return false;
        };
        let Some((name, password)) = credentials.split_once(':') else {
            return false;
        };
        self.users
            .iter()
            .any(|(email, secret)| email.eq_ignore_ascii_case(name) && secret == password)
    }
}

/// What a worker waits for: a datagram the demultiplexer routed to it, or a
/// packet the stack just queued, so a flow is not clocked by the tick alone.
pub(crate) enum Arrival {
    Datagram(Vec<u8>, SocketAddr),
    Ready,
}

/// One tunnel's inbox and the handle that wakes its worker. `pending` keeps at
/// most one `Ready` in flight, so a burst queues packets, not wake-ups.
#[derive(Clone)]
pub(crate) struct TunnelQueue {
    sender: SyncSender<Vec<u8>>,
    wake: Option<Sender<Arrival>>,
    pending: Arc<AtomicBool>,
}

impl TunnelQueue {
    pub(crate) fn new(sender: SyncSender<Vec<u8>>, wake: Option<Sender<Arrival>>) -> Self {
        Self {
            sender,
            wake,
            pending: Arc::new(AtomicBool::new(false)),
        }
    }
}

pub(crate) struct Shared {
    pool: Mutex<AddressPool>,
    pub(crate) tunnels: Mutex<HashMap<IpAddr, TunnelQueue>>,
    packets: Sender<Packet>,
    local: Vec<IpAddr>,
}

/// One address a pool may hand out, per family: the server's own address, the
/// network, the usable range, the next candidate and the free runs, so an
/// assignment takes the first free address without walking the used ones.
#[derive(Debug, Clone)]
struct Family {
    server: u128,
    network: u128,
    span: u128,
    first: u128,
    last: u128,
    next: u128,
    free: BTreeMap<u128, u128>,
    #[cfg(test)]
    probes: usize,
}

#[derive(Debug, Clone, Default)]
struct AddressPool {
    v4: Option<Family>,
    v6: Option<Family>,
    server: Vec<IpAddr>,
}

impl AddressPool {
    fn from_prefixes(addresses: &[String]) -> Result<Self, String> {
        let mut pool = Self::default();
        for text in addresses {
            let (address, prefix) = text
                .split_once('/')
                .ok_or_else(|| format!("masque address `{text}` has no prefix"))?;
            let prefix: u8 = prefix
                .parse()
                .map_err(|_| format!("masque address `{text}` has a bad prefix"))?;
            let ip: IpAddr = address
                .parse()
                .map_err(|_| format!("masque address `{text}` is not an IP"))?;
            match ip {
                IpAddr::V4(ip) => {
                    if pool.v4.is_some() {
                        return Err("masque: one address per family".to_owned());
                    }
                    if prefix > 32 {
                        return Err(format!("masque address `{text}` has a bad prefix"));
                    }
                    pool.v4 = Some(Family::new(u128::from(u32::from(ip)), prefix, 32)?);
                }
                IpAddr::V6(ip) => {
                    if pool.v6.is_some() {
                        return Err("masque: one address per family".to_owned());
                    }
                    if prefix > 128 {
                        return Err(format!("masque address `{text}` has a bad prefix"));
                    }
                    pool.v6 = Some(Family::new(u128::from(ip), prefix, 128)?);
                }
            }
            pool.server.push(ip);
        }
        Ok(pool)
    }

    /// Grant one address per configured family, rolling both back when either is full.
    fn assign(&mut self) -> Vec<IpAddr> {
        let v4 = self.v4.as_mut().and_then(Family::allocate);
        let v6 = self.v6.as_mut().and_then(Family::allocate);
        let mut addrs = Vec::with_capacity(2);
        if let Some(ip) = v4 {
            addrs.push(IpAddr::V4(Ipv4Addr::from(ip as u32)));
        }
        if let Some(ip) = v6 {
            addrs.push(IpAddr::V6(Ipv6Addr::from(ip)));
        }
        if (self.v4.is_some() && v4.is_none()) || (self.v6.is_some() && v6.is_none()) {
            for address in &addrs {
                self.release(*address);
            }
            addrs.clear();
        }
        addrs
    }

    /// Return a refused or finished assignment to its family's free runs.
    fn release(&mut self, ip: IpAddr) {
        match ip {
            IpAddr::V4(ip) => {
                if let Some(family) = self.v4.as_mut() {
                    family.release(u128::from(u32::from(ip)));
                }
            }
            IpAddr::V6(ip) => {
                if let Some(family) = self.v6.as_mut() {
                    family.release(u128::from(ip));
                }
            }
        }
    }

    fn holds(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => self
                .v4
                .as_ref()
                .is_some_and(|family| family.holds(u128::from(u32::from(ip)))),
            IpAddr::V6(ip) => self
                .v6
                .as_ref()
                .is_some_and(|family| family.holds(u128::from(ip))),
        }
    }
}

#[cfg(test)]
fn test_pool() -> AddressPool {
    AddressPool::from_prefixes(&["10.14.0.0/24".to_owned()]).expect("a test pool")
}

#[cfg(test)]
pub(crate) fn test_shared() -> Arc<Shared> {
    let (packets, _packets_rx) = mpsc::channel();
    let pool = test_pool();
    Arc::new(Shared {
        local: pool.server.clone(),
        pool: Mutex::new(pool),
        tunnels: Mutex::new(HashMap::new()),
        packets,
    })
}

#[cfg(test)]
pub(crate) fn test_spec() -> ServerSpec {
    ServerSpec {
        users: vec![("a".to_owned(), "b".to_owned())],
        path: DEFAULT_PATH.to_owned(),
        pool: test_pool(),
        mtu: DEFAULT_MTU,
        warp: false,
    }
}

impl Family {
    /// A family whose free runs are the usable range minus the server's own address.
    fn new(server: u128, prefix: u8, bits: u8) -> Result<Self, String> {
        let mask = if prefix == 0 {
            u128::MAX
        } else {
            (1u128 << (bits - prefix)) - 1
        };
        let network = server & !mask;
        let span = mask;
        let first = network.saturating_add(1);
        // A v4 pool gives up its broadcast address; a v6 one has no broadcast, so the last host stays assignable exactly as the reference leaves it.
        let last = if prefix == bits {
            network
        } else if bits == 32 && prefix <= 30 {
            network.saturating_add(span - 1)
        } else {
            network.saturating_add(span)
        };
        if first > last {
            return Err("masque pool has no assignable address".to_owned());
        }
        let mut free = BTreeMap::new();
        if server >= first && server <= last {
            if first < server {
                free.insert(first, server - 1);
            }
            if server < last {
                free.insert(server + 1, last);
            }
        } else {
            free.insert(first, last);
        }
        Ok(Self {
            server,
            network,
            span,
            first,
            last,
            next: first,
            free,
            #[cfg(test)]
            probes: 0,
        })
    }

    #[cfg(test)]
    fn probe(&mut self) {
        self.probes += 1;
    }

    /// Take the first free address at or after the cursor, wrapping once.
    fn allocate(&mut self) -> Option<u128> {
        let start = if self.next < self.first || self.next > self.last {
            self.first
        } else {
            self.next
        };
        let before = self
            .free
            .range(..=start)
            .next_back()
            .map(|(&run_start, &run_end)| (run_start, run_end));
        #[cfg(test)]
        self.probe();
        let candidate = match before {
            Some((_, run_end)) if run_end >= start => start,
            Some(_) => {
                let next = self
                    .free
                    .range(start..)
                    .next()
                    .map(|(&run_start, _)| run_start);
                #[cfg(test)]
                self.probe();
                if let Some(run_start) = next {
                    run_start
                } else {
                    let first = self.free.first_key_value().map(|(&run_start, _)| run_start);
                    #[cfg(test)]
                    self.probe();
                    first?
                }
            }
            None => {
                let first = self.free.first_key_value().map(|(&run_start, _)| run_start);
                #[cfg(test)]
                self.probe();
                first?
            }
        };
        let (&run_start, &run_end) = self.free.range(..=candidate).next_back()?;
        debug_assert!(run_start <= candidate && candidate <= run_end);
        self.free.remove(&run_start);
        if run_start < candidate {
            self.free.insert(run_start, candidate - 1);
        }
        if candidate < run_end {
            self.free.insert(candidate + 1, run_end);
        }
        self.next = if candidate >= self.last {
            self.first
        } else {
            candidate + 1
        };
        Some(candidate)
    }

    /// Return an address to the free runs, merging the neighbours it touches.
    fn release(&mut self, address: u128) {
        if address < self.first || address > self.last || address == self.server {
            return;
        }
        let mut start = address;
        let mut end = address;
        let before = self
            .free
            .range(..=address)
            .next_back()
            .map(|(&run_start, &run_end)| (run_start, run_end));
        if let Some((run_start, run_end)) = before {
            if run_end >= address {
                return;
            }
            if run_end.checked_add(1) == Some(address) {
                self.free.remove(&run_start);
                start = run_start;
            }
        }
        let after = self
            .free
            .range(address..)
            .next()
            .map(|(&run_start, &run_end)| (run_start, run_end));
        if let Some((run_start, run_end)) = after {
            if address.checked_add(1) == Some(run_start) {
                self.free.remove(&run_start);
                end = run_end;
            }
        }
        self.free.insert(start, end);
    }

    fn holds(&self, address: u128) -> bool {
        address >= self.network && address <= self.network.saturating_add(self.span)
    }
}

/// A tunnel's addresses go back to the pool when its worker ends, whatever ended it.
pub(crate) struct Granted {
    shared: Arc<Shared>,
    addrs: Vec<IpAddr>,
}

impl Drop for Granted {
    fn drop(&mut self) {
        if let Ok(mut tunnels) = self.shared.tunnels.lock() {
            for address in &self.addrs {
                tunnels.remove(address);
            }
        }
        if let Ok(mut pool) = self.shared.pool.lock() {
            for address in &self.addrs {
                pool.release(*address);
            }
        }
    }
}

#[allow(clippy::needless_pass_by_value)]
fn dispatch(shared: &Shared, from_stack: Receiver<Vec<u8>>) {
    while let Ok(packet) = from_stack.recv() {
        let Some(destination) = packet_destination(&packet) else {
            continue;
        };
        let tunnel = shared
            .tunnels
            .lock()
            .ok()
            .and_then(|tunnels| tunnels.get(&destination).cloned());
        if let Some(tunnel) = tunnel {
            // A full queue drops the packet; the dispatcher must keep serving other tunnels.
            if tunnel.sender.try_send(packet).is_ok() {
                // Wake after the packet is visible, so a worker that cleared `pending` finds it.
                if let Some(wake) = &tunnel.wake {
                    if !tunnel.pending.swap(true, Ordering::Release) {
                        let _ = wake.send(Arrival::Ready);
                    }
                }
            }
        }
    }
}

type Routes = Arc<Mutex<HashMap<Vec<u8>, (u64, Sender<Arrival>)>>>;

static WORKERS: AtomicU64 = AtomicU64::new(0);
/// Enough for a busy edge, small enough that a spoofed Initial flood cannot exhaust the process.
const MAX_WORKERS: usize = 1024;

struct WorkerSlot(Arc<AtomicUsize>);

impl Drop for WorkerSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn admit_worker(live: &Arc<AtomicUsize>, cap: usize) -> Option<WorkerSlot> {
    live.try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        (current < cap).then_some(current + 1)
    })
    .ok()
    .map(|_| WorkerSlot(Arc::clone(live)))
}

#[allow(clippy::needless_pass_by_value)]
fn demux(
    sock: Arc<Datagram>,
    local: SocketAddr,
    config: Arc<Mutex<quiche::Config>>,
    shared: Arc<Shared>,
    spec: Arc<ServerSpec>,
) {
    let routes: Routes = Arc::new(Mutex::new(HashMap::new()));
    let live = Arc::new(AtomicUsize::new(0));
    let mut buf = vec![0u8; 65535];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf) else {
            continue;
        };
        let (kind, queued, dcid) = {
            let Ok(head) = quiche::Header::from_slice(&mut buf[..n], CID_LEN) else {
                continue;
            };
            let queued = routes
                .lock()
                .ok()
                .and_then(|table| table.get(head.dcid.as_ref()).map(|(_, tx)| tx.clone()));
            let dcid =
                (queued.is_none() && head.ty == quiche::Type::Initial).then(|| head.dcid.to_vec());
            (head.ty, queued, dcid)
        };
        if let Some(tx) = queued {
            let _ = tx.send(Arrival::Datagram(buf[..n].to_vec(), from));
            continue;
        }
        if kind != quiche::Type::Initial {
            continue;
        }
        let Some(dcid) = dcid else {
            continue;
        };
        let mut scid = [0u8; CID_LEN];
        if getrandom::fill(&mut scid).is_err() {
            continue;
        }
        let scid = quiche::ConnectionId::from_ref(&scid);
        let Some(slot) = admit_worker(&live, MAX_WORKERS) else {
            continue;
        };
        let Ok(mut guard) = config.lock() else {
            continue;
        };
        let Ok(conn) = quiche::accept(&scid, None, local, from, &mut guard) else {
            continue;
        };
        drop(guard);
        let server_scid = conn.source_id().to_vec();
        let (tx, rx) = mpsc::channel();
        let worker_id = WORKERS.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut table) = routes.lock() {
            table.insert(dcid.clone(), (worker_id, tx.clone()));
            table.insert(server_scid.clone(), (worker_id, tx.clone()));
        }
        let _ = tx.send(Arrival::Datagram(buf[..n].to_vec(), from));
        let sock = Arc::clone(&sock);
        let shared = Arc::clone(&shared);
        let spec = Arc::clone(&spec);
        let keys = Arc::clone(&routes);
        let worker_tx = tx.clone();
        std::thread::spawn(move || {
            worker(
                conn,
                sock,
                local,
                rx,
                worker_tx,
                shared,
                spec,
                Arc::clone(&keys),
                worker_id,
            );
            if let Ok(mut table) = keys.lock() {
                table.retain(|_, (owner, _)| *owner != worker_id);
            }
            drop(slot);
        });
    }
}

#[allow(clippy::struct_excessive_bools)]
struct Tunnel {
    stream: Option<u64>,
    buf: Vec<u8>,
    at: usize,
    headers: bool,
    capsules: Vec<u8>,
    capsule_at: usize,
    opened: bool,
    rejected: bool,
    settings_sent: bool,
    pending: Option<Vec<u8>>,
    unsent: Option<Vec<u8>>,
    outgoing: Receiver<Vec<u8>>,
    queue: TunnelQueue,
    addrs: Vec<IpAddr>,
    granted: Option<Granted>,
    registered: Vec<Vec<u8>>,
    udp: Option<UdpLane>,
    udp_target: Option<(String, u16)>,
    udp_frame: Vec<u8>,
    udp_at: usize,
}

fn sweep_due_timer(conn: &mut quiche::Connection) {
    if conn.timeout().is_some_and(|left| left.is_zero()) {
        conn.on_timeout();
    }
}

#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
fn worker(
    mut conn: quiche::Connection,
    sock: Arc<Datagram>,
    local: SocketAddr,
    rx: Receiver<Arrival>,
    tx: Sender<Arrival>,
    shared: Arc<Shared>,
    spec: Arc<ServerSpec>,
    routes: Routes,
    worker_id: u64,
) {
    let (sender, outgoing) = mpsc::sync_channel(QUEUE);
    let mut tunnel = Tunnel {
        stream: None,
        buf: Vec::new(),
        at: 0,
        headers: false,
        capsules: Vec::new(),
        capsule_at: 0,
        opened: false,
        rejected: false,
        settings_sent: false,
        pending: None,
        unsent: None,
        outgoing,
        queue: TunnelQueue::new(sender, Some(tx.clone())),
        addrs: Vec::new(),
        granted: None,
        registered: Vec::new(),
        udp: None,
        udp_target: None,
        udp_frame: Vec::new(),
        udp_at: 0,
    };
    loop {
        if conn.is_closed() {
            return;
        }
        // A held datagram waits for the acknowledgement that frees the send queue; it wakes this worker as a datagram of its own, so polling a shorter grain only burns CPU.
        let wait = conn.timeout().unwrap_or(TICK).min(TICK);
        match rx.recv_timeout(wait) {
            Ok(Arrival::Datagram(mut bytes, from)) => {
                let info = quiche::RecvInfo { from, to: local };
                let _ = conn.recv(&mut bytes, info);
            }
            Ok(Arrival::Ready) => tunnel.queue.pending.store(false, Ordering::Release),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
        sweep_due_timer(&mut conn);
        if conn.is_closed() {
            return;
        }
        if conn.is_established() {
            if !tunnel.settings_sent {
                send_server_settings(&mut conn, 3, 7, 11, spec.warp).ok();
                tunnel.settings_sent = true;
            }
            service(&mut conn, &shared, &spec, &mut tunnel);
            drain_udp(&mut conn, &mut tunnel);
        }
        'packets: while let Some(packet) = tunnel
            .unsent
            .take()
            .or_else(|| tunnel.outgoing.try_recv().ok())
        {
            let Some(stream) = tunnel.stream else {
                continue;
            };
            let mut flushed = false;
            loop {
                match send_datagram(&mut conn, stream, &packet) {
                    Emission::Queued => break,
                    Emission::TooLarge(icmp) => {
                        let _ = shared.packets.send(Packet {
                            peer: [0u8; 32],
                            bytes: icmp,
                            at: 0,
                        });
                        break;
                    }
                    Emission::Full if !flushed => {
                        quic::flush_egress(&mut conn, &sock);
                        flushed = true;
                    }
                    Emission::Full => {
                        tunnel.unsent = Some(packet);
                        break 'packets;
                    }
                }
            }
        }
        register_sources(&mut conn, &routes, worker_id, &tx, &mut tunnel.registered);
        quic::flush_egress(&mut conn, &sock);
    }
}

fn register_sources(
    conn: &mut quiche::Connection,
    routes: &Routes,
    worker_id: u64,
    tx: &Sender<Arrival>,
    registered: &mut Vec<Vec<u8>>,
) {
    let mut fresh = Vec::new();
    for id in conn.source_ids() {
        let id: &[u8] = id.as_ref();
        if !registered.iter().any(|known| known.as_slice() == id) {
            fresh.push(id.to_vec());
        }
    }
    if fresh.is_empty() {
        return;
    }
    if let Ok(mut table) = routes.lock() {
        for id in &fresh {
            table.insert(id.clone(), (worker_id, tx.clone()));
        }
        registered.extend(fresh);
    }
}

fn service(
    conn: &mut quiche::Connection,
    shared: &Arc<Shared>,
    spec: &ServerSpec,
    tunnel: &mut Tunnel,
) {
    let mut room = [0u8; 4096];
    while let Some(id) = conn.stream_readable_next() {
        if id % 4 != 0 {
            // Control and QPACK streams are read and forgotten, so their bytes do not sit on the connection waiting for a handler.
            while let Ok((n, _)) = conn.stream_recv(id, &mut room) {
                if n == 0 {
                    break;
                }
            }
            continue;
        }
        if tunnel.stream.is_some_and(|stream| stream != id) {
            while let Ok((n, _)) = conn.stream_recv(id, &mut room) {
                if n == 0 {
                    break;
                }
            }
            continue;
        }
        tunnel.stream = Some(id);
        loop {
            match conn.stream_recv(id, &mut room) {
                Ok((0, _)) | Err(quiche::Error::Done) => break,
                Ok((n, fin)) => {
                    tunnel.buf.extend_from_slice(&room[..n]);
                    if tunnel.buf.len() > CAPSULE_CAP {
                        let _ = conn.close(false, 0, b"capsule bound");
                        tunnel.rejected = true;
                        return;
                    }
                    if fin && !tunnel.headers {
                        break;
                    }
                }
                Err(_) => return,
            }
        }
        if !tunnel.headers {
            if !parse_head(tunnel, spec) {
                continue;
            }
            if tunnel.pending.is_none() {
                accept(conn, shared, spec, tunnel);
            }
            if let Some(head) = tunnel.pending.take() {
                send_stream(conn, id, &head, true).ok();
                tunnel.rejected = true;
            }
        } else if !tunnel.rejected && !parse_capsules(conn, tunnel, spec.mtu) {
            let _ = conn.close(false, 0, b"capsule bound");
            tunnel.rejected = true;
        }
    }
    if tunnel.opened && !tunnel.rejected {
        read_datagrams(conn, shared, spec, tunnel);
    }
}

/// Parses the request head once its HEADERS frame is whole, walking past the
/// reserved frames a greasing peer sends first; `false` leaves the bytes for
/// the next read.
fn parse_head(tunnel: &mut Tunnel, spec: &ServerSpec) -> bool {
    let block = loop {
        let mut at = tunnel.at;
        let Some(frame) = frames::h3_frame(&tunnel.buf, &mut at) else {
            return false;
        };
        let Ok(length) = usize::try_from(frame.length) else {
            return false;
        };
        let Some(end) = at.checked_add(length) else {
            return false;
        };
        let Some(payload) = tunnel.buf.get(at..end) else {
            return false;
        };
        tunnel.at = end;
        if frame.kind == frames::H3_HEADERS {
            break payload;
        }
    };
    let Some(fields) = hpack::qpack_fields(block) else {
        return false;
    };
    tunnel.buf.drain(..tunnel.at);
    tunnel.buf.shrink_to_fit();
    tunnel.at = 0;
    let field = |name: &[u8]| {
        fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_slice())
    };
    let method_ok = field(b":method") == Some(b"CONNECT");
    let protocol = field(b":protocol");
    let udp = protocol == Some(b"connect-udp");
    let target = udp.then(|| field(b":path")).flatten().and_then(udp_target);
    let protocol_ok = udp || protocol.is_some_and(|protocol| spec.accepts_protocol(protocol));
    let path_ok = if udp {
        target.is_some()
    } else {
        field(b":path")
            .is_some_and(|path| protocol.is_some_and(|protocol| spec.path_matches(path, protocol)))
    };
    let capsules_ok = field(b"capsule-protocol")
        .and_then(|value| value.strip_prefix(b"?"))
        .is_some_and(|value| value.split(|byte| *byte == b';').next() == Some(b"1"));
    tunnel.headers = true;
    if !path_ok {
        reject(tunnel, if udp { 400 } else { 404 });
        tunnel.rejected = true;
    } else if !method_ok || !protocol_ok || !capsules_ok {
        reject(tunnel, 400);
        tunnel.rejected = true;
    } else if udp {
        if spec.udp_authenticated(field(b"proxy-authorization"), field(b"authorization")) {
            tunnel.udp_target = target;
        } else {
            reject_auth(tunnel, true);
            tunnel.rejected = true;
        }
    } else if !protocol
        .is_some_and(|protocol| spec.request_authenticated(protocol, field(b"authorization")))
    {
        reject_auth(tunnel, false);
        tunnel.rejected = true;
    }
    true
}

/// The target a CONNECT-UDP path names (RFC 9298 §2), decoded and split at its
/// one slash: only the host is percent-decoded, so an IPv6 literal's `%3A` reads
/// as a colon while the port stays decimal.
pub(crate) fn udp_target(path: &[u8]) -> Option<(String, u16)> {
    let rest = path.strip_prefix(UDP_PATH_PREFIX)?;
    let rest = rest.strip_suffix(b"/")?;
    let at = rest.iter().position(|byte| *byte == b'/')?;
    let (host, port) = (&rest[..at], &rest[at + 1..]);
    if host.is_empty() || port.is_empty() || port.contains(&b'/') {
        return None;
    }
    let host = percent_decode(host)?;
    let host = std::str::from_utf8(&host).ok()?.to_owned();
    let port = std::str::from_utf8(port).ok()?.parse::<u16>().ok()?;
    (port != 0).then_some((host, port))
}

fn percent_decode(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0usize;
    while let Some(byte) = bytes.get(at) {
        if *byte != b'%' {
            out.push(*byte);
            at += 1;
            continue;
        }
        let high = (*bytes.get(at + 1)? as char).to_digit(16)?;
        let low = (*bytes.get(at + 2)? as char).to_digit(16)?;
        out.push((high * 16 + low) as u8);
        at += 3;
    }
    Some(out)
}

/// One CONNECT-UDP target's socket and the thread draining replies from it: the
/// lane is per request, so a stream owns one destination and one port.
pub(crate) struct UdpLane {
    socket: UdpSocket,
    outgoing: Receiver<Vec<u8>>,
    stop: Arc<AtomicBool>,
}

impl UdpLane {
    pub(crate) fn open(host: &str, port: u16) -> Result<Self, String> {
        let target = (host, port)
            .to_socket_addrs()
            .map_err(|error| format!("masque: cannot resolve `{host}:{port}`: {error}"))?
            .next()
            .ok_or_else(|| format!("masque: `{host}:{port}` resolves to no address"))?;
        let bind = if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind)
            .map_err(|error| format!("masque: cannot bind a UDP lane: {error}"))?;
        socket
            .connect(target)
            .map_err(|error| format!("masque: cannot connect to `{target}`: {error}"))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .map_err(|error| format!("masque: cannot set the UDP wait: {error}"))?;
        let reader = socket
            .try_clone()
            .map_err(|error| format!("masque: cannot clone the UDP socket: {error}"))?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let (sender, outgoing) = mpsc::sync_channel(QUEUE);
        std::thread::Builder::new()
            .name("ferrox-masque-udp".into())
            .spawn(move || {
                let mut room = vec![0u8; 65_535];
                while !worker_stop.load(Ordering::Relaxed) {
                    match reader.recv(&mut room) {
                        Ok(read) => {
                            let _ = sender.try_send(room[..read].to_vec());
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock
                                    | std::io::ErrorKind::TimedOut
                                    | std::io::ErrorKind::Interrupted
                                    | std::io::ErrorKind::ConnectionRefused
                            ) => {}
                        Err(_) => break,
                    }
                }
            })
            .map_err(|error| format!("masque: cannot spawn the UDP lane: {error}"))?;
        Ok(Self {
            socket,
            outgoing,
            stop,
        })
    }

    pub(crate) fn send(&self, payload: &[u8]) {
        let _ = self.socket.send(payload);
    }

    pub(crate) fn try_recv(&self) -> Option<Vec<u8>> {
        self.outgoing.try_recv().ok()
    }
}

impl Drop for UdpLane {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn path_query(bytes: &[u8]) -> (&[u8], &[u8]) {
    match bytes.iter().position(|byte| *byte == b'?') {
        Some(at) => (&bytes[..at], &bytes[at + 1..]),
        None => (bytes, &[]),
    }
}

/// xray parses the request URI before comparing, so an escaped star names the same path the literal does.
pub(crate) fn path_matches(got: &[u8], want: &str) -> bool {
    let (got_path, got_query) = path_query(got);
    let (want_path, want_query) = path_query(want.as_bytes());
    percent_decode(got_path).as_deref() == percent_decode(want_path).as_deref()
        && got_query == want_query
}

fn accept(
    conn: &mut quiche::Connection,
    shared: &Arc<Shared>,
    _spec: &ServerSpec,
    tunnel: &mut Tunnel,
) {
    let Some(stream) = tunnel.stream else {
        return;
    };
    if let Some((host, port)) = tunnel.udp_target.take() {
        let Ok(lane) = UdpLane::open(&host, port) else {
            reject(tunnel, 503);
            return;
        };
        tunnel.udp = Some(lane);
        tunnel.opened = true;
        let mut block = Vec::new();
        hpack::qpack_literal_many(
            &[(":status", "200"), ("capsule-protocol", "?1")],
            &mut block,
        );
        let mut head = Vec::with_capacity(16 + block.len());
        frames::quic_varint(&mut head, frames::H3_HEADERS);
        frames::quic_varint(&mut head, block.len() as u64);
        head.extend_from_slice(&block);
        send_stream(conn, stream, &head, false).ok();
        return;
    }
    let Some(addrs) = assign(shared) else {
        reject(tunnel, 503);
        return;
    };
    let Some(granted) = register(shared, &addrs, &tunnel.queue) else {
        release(shared, &addrs);
        reject(tunnel, 503);
        return;
    };
    let assignments = grants(&addrs, 0);
    tunnel.addrs = addrs;
    tunnel.granted = Some(granted);
    tunnel.opened = true;
    let mut block = Vec::new();
    hpack::qpack_literal_many(
        &[(":status", "200"), ("capsule-protocol", "?1")],
        &mut block,
    );
    let mut head = Vec::with_capacity(16 + block.len());
    frames::quic_varint(&mut head, frames::H3_HEADERS);
    frames::quic_varint(&mut head, block.len() as u64);
    head.extend_from_slice(&block);
    send_stream(conn, stream, &head, false).ok();
    let mut control = Vec::new();
    connectip::address_assign_encode(&assignments, &mut control);
    send_data(conn, stream, &control).ok();
    control.clear();
    connectip::route_advert_encode(&routes(&tunnel.addrs), &mut control);
    send_data(conn, stream, &control).ok();
}

/// One address per family from the pool, or `None` when it has none left.
pub(crate) fn assign(shared: &Arc<Shared>) -> Option<Vec<IpAddr>> {
    let addresses = shared.pool.lock().ok()?.assign();
    (!addresses.is_empty()).then_some(addresses)
}

/// The addresses an assignment was refused go back to the pool.
pub(crate) fn release(shared: &Arc<Shared>, addrs: &[IpAddr]) {
    if let Ok(mut pool) = shared.pool.lock() {
        for address in addrs {
            pool.release(*address);
        }
    }
}

/// The `ADDRESS_ASSIGN` body an answer carries: each address at its full prefix, naming the request it answers.
pub(crate) fn grants(addrs: &[IpAddr], request_id: u64) -> Vec<Assigned> {
    addrs
        .iter()
        .map(|address| match address {
            IpAddr::V4(ip) => Assigned {
                request_id,
                version: 4,
                address: {
                    let mut bytes = [0u8; 16];
                    bytes[..4].copy_from_slice(&ip.octets());
                    bytes
                },
                prefix: 32,
            },
            IpAddr::V6(ip) => Assigned {
                request_id,
                version: 6,
                address: ip.octets(),
                prefix: 128,
            },
        })
        .collect()
}

/// The `ROUTE_ADVERTISEMENT` body a tunnel's families are carried for.
pub(crate) fn routes(addrs: &[IpAddr]) -> Vec<Route> {
    let mut routes = Vec::new();
    if addrs.iter().any(IpAddr::is_ipv4) {
        routes.push(Route {
            first: [0u8; 16],
            last: {
                let mut last = [0u8; 16];
                last[..4].copy_from_slice(&[255, 255, 255, 255]);
                last
            },
            version: 4,
            protocol: 0,
        });
    }
    if addrs.iter().any(IpAddr::is_ipv6) {
        routes.push(Route {
            first: [0u8; 16],
            last: [0xff; 16],
            version: 6,
            protocol: 0,
        });
    }
    routes
}

/// The `ADDRESS_ASSIGN` body answering the requests a peer named, one grant per request the tunnel's own families can hold.
pub(crate) fn respond(body: &[u8], addrs: &[IpAddr]) -> Vec<Assigned> {
    let mut requested = Vec::new();
    if connectip::address_assign(body, &mut requested).is_none() {
        return Vec::new();
    }
    let mut assignments = Vec::new();
    for request in &requested {
        let wanted = addrs.iter().find(|address| {
            (request.version == 4 && address.is_ipv4())
                || (request.version == 6 && address.is_ipv6())
        });
        if let Some(address) = wanted {
            assignments.extend(grants(std::slice::from_ref(address), request.request_id));
        }
    }
    assignments
}

pub(crate) fn register(
    shared: &Arc<Shared>,
    addrs: &[IpAddr],
    queue: &TunnelQueue,
) -> Option<Granted> {
    let mut tunnels = shared.tunnels.lock().ok()?;
    let mut inserted = Vec::with_capacity(addrs.len());
    for address in addrs {
        if tunnels.contains_key(address) {
            for address in &inserted {
                tunnels.remove(address);
            }
            return None;
        }
        tunnels.insert(*address, queue.clone());
        inserted.push(*address);
    }
    Some(Granted {
        shared: Arc::clone(shared),
        addrs: addrs.to_vec(),
    })
}

fn parse_capsules(conn: &mut quiche::Connection, tunnel: &mut Tunnel, mtu: usize) -> bool {
    let Some(answers) = drain_capsules(tunnel, mtu) else {
        return false;
    };
    if let Some(stream) = tunnel.stream {
        for body in answers {
            send_data(conn, stream, &body).ok();
        }
    }
    true
}

/// Drain the capsules a tunnel's request stream has whole. `None` refuses a frame or capsule past
/// the cap before it can grow the buffer; a datagram wider than the tunnel MTU is dropped here.
fn drain_capsules(tunnel: &mut Tunnel, mtu: usize) -> Option<Vec<Vec<u8>>> {
    let mut at = tunnel.at;
    while let Some(frame) = frames::h3_frame(&tunnel.buf, &mut at) {
        let length = usize::try_from(frame.length).ok()?;
        if length > CAPSULE_CAP {
            return None;
        }
        let Some(room) = tunnel.buf.get(at..at + length) else {
            break;
        };
        at += length;
        if frame.kind == frames::H3_DATA {
            tunnel.capsules.extend_from_slice(room);
        }
    }
    tunnel.buf.drain(..at);
    tunnel.at = 0;
    if let Some((_, declared)) = connectip::capsule_header(&tunnel.capsules[tunnel.capsule_at..]) {
        if declared > CAPSULE_CAP as u64 {
            return None;
        }
    }
    let mut answers = Vec::new();
    while let Some((used, capsule)) =
        connectip::capsule_split(&tunnel.capsules[tunnel.capsule_at..])
    {
        tunnel.capsule_at += used;
        match capsule {
            connectip::Capsule::Datagram(payload) if payload.len() <= mtu => {
                if let Some(udp) = &tunnel.udp {
                    udp.send(payload);
                }
            }
            connectip::Capsule::AddressRequest(body) if tunnel.udp.is_none() => {
                let assignments = respond(body, &tunnel.addrs);
                if !assignments.is_empty() {
                    let mut body = Vec::new();
                    connectip::address_assign_encode(&assignments, &mut body);
                    answers.push(body);
                }
            }
            _ => {}
        }
    }
    if tunnel.capsule_at > 0 {
        tunnel.capsules.drain(..tunnel.capsule_at);
        tunnel.capsule_at = 0;
    }
    if tunnel.capsules.len() > CAPSULE_CAP {
        return None;
    }
    Some(answers)
}

/// Frames one UDP payload into the tunnel's reusable buffer and queues it on the
/// request stream until the whole capsule is written, so a full stream send buffer
/// never splits a frame.
fn drain_udp(conn: &mut quiche::Connection, tunnel: &mut Tunnel) {
    let Some(stream) = tunnel.stream else {
        return;
    };
    let Some(udp) = &tunnel.udp else {
        return;
    };
    loop {
        if tunnel.udp_at >= tunnel.udp_frame.len() {
            tunnel.udp_frame.clear();
            tunnel.udp_at = 0;
            let Some(payload) = udp.try_recv() else {
                return;
            };
            let total = udp_capsule::datagram_len(payload.len());
            let mut head = [0u8; 9];
            let length = frames::h3_data_header(&mut head, total as u64);
            tunnel.udp_frame.extend_from_slice(&head[..length]);
            udp_capsule::datagram_encode(&payload, &mut tunnel.udp_frame);
        }
        if !stream_frame(conn, stream, &tunnel.udp_frame, &mut tunnel.udp_at) {
            return;
        }
    }
}

fn stream_frame(conn: &mut quiche::Connection, stream: u64, frame: &[u8], at: &mut usize) -> bool {
    while *at < frame.len() {
        match conn.stream_send(stream, &frame[*at..], false) {
            Ok(0) | Err(_) => return false,
            Ok(wrote) => *at += wrote,
        }
    }
    true
}

fn read_datagrams(
    conn: &mut quiche::Connection,
    shared: &Arc<Shared>,
    spec: &ServerSpec,
    tunnel: &mut Tunnel,
) {
    while let Ok(datagram) = conn.dgram_recv_buf() {
        let Some((stream, packet)) = connectip::datagram_split(&datagram) else {
            continue;
        };
        if tunnel.stream != Some(stream) {
            continue;
        }
        if let Some(udp) = &tunnel.udp {
            udp.send(packet);
            continue;
        }
        let offset = datagram.len() - packet.len();
        forward_owned(shared, spec, &tunnel.addrs, datagram, offset);
    }
}

enum Forward {
    Tunnel(SyncSender<Vec<u8>>),
    Stack,
}

fn forward_to(
    shared: &Arc<Shared>,
    spec: &ServerSpec,
    addrs: &[IpAddr],
    packet: &[u8],
) -> Option<Forward> {
    let source = packet_source(packet)?;
    if !addrs.contains(&source) {
        return None;
    }
    let destination = packet_destination(packet)?;
    if dropped_destination(destination) {
        return None;
    }
    if let Ok(tunnels) = shared.tunnels.lock() {
        if let Some(other) = tunnels.get(&destination) {
            if !addrs.contains(&destination) {
                return Some(Forward::Tunnel(other.sender.clone()));
            }
            return None;
        }
    }
    if spec.pool.holds(destination) && !shared.local.contains(&destination) {
        return None;
    }
    Some(Forward::Stack)
}

pub(crate) fn forward(shared: &Arc<Shared>, spec: &ServerSpec, addrs: &[IpAddr], packet: &[u8]) {
    match forward_to(shared, spec, addrs, packet) {
        Some(Forward::Tunnel(other)) => {
            let _ = other.try_send(packet.to_vec());
        }
        Some(Forward::Stack) => {
            let _ = shared.packets.send(Packet {
                peer: peer_key(addrs),
                bytes: packet.to_vec(),
                at: 0,
            });
        }
        None => {}
    }
}

/// Forward a datagram's inner packet to a peer or the stack, retaining the prefix the stack records as its offset.
fn forward_owned(
    shared: &Arc<Shared>,
    spec: &ServerSpec,
    addrs: &[IpAddr],
    mut datagram: Vec<u8>,
    offset: usize,
) {
    let Some(to) = forward_to(shared, spec, addrs, &datagram[offset..]) else {
        return;
    };
    match to {
        Forward::Tunnel(other) => {
            datagram.drain(..offset);
            let _ = other.try_send(datagram);
        }
        Forward::Stack => {
            let _ = shared.packets.send(Packet {
                peer: peer_key(addrs),
                bytes: datagram,
                at: offset,
            });
        }
    }
}

fn reject(tunnel: &mut Tunnel, status: u16) {
    let status = status.to_string();
    let mut block = Vec::new();
    hpack::qpack_literal_many(&[(":status", &status)], &mut block);
    let mut head = Vec::with_capacity(16 + block.len());
    frames::quic_varint(&mut head, frames::H3_HEADERS);
    frames::quic_varint(&mut head, block.len() as u64);
    head.extend_from_slice(&block);
    tunnel.buf.clear();
    tunnel.at = 0;
    // The response rides the next `send`; no stream is accepted, so there is nothing else to write.
    tunnel.pending = Some(head);
}

fn reject_auth(tunnel: &mut Tunnel, proxy: bool) {
    let challenge = if proxy {
        "proxy-authenticate"
    } else {
        "www-authenticate"
    };
    let mut block = Vec::new();
    hpack::qpack_literal_many(&[(":status", "401"), (challenge, AUTH_REALM)], &mut block);
    let mut head = Vec::with_capacity(16 + block.len());
    frames::quic_varint(&mut head, frames::H3_HEADERS);
    frames::quic_varint(&mut head, block.len() as u64);
    head.extend_from_slice(&block);
    tunnel.buf.clear();
    tunnel.at = 0;
    tunnel.pending = Some(head);
}

fn packet_source(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        ))),
        6 if packet.len() >= 40 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[8..24]);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

fn packet_destination(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))),
        6 if packet.len() >= 40 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

fn dropped_destination(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_link_local() || ip.is_multicast(),
        IpAddr::V6(ip) => ip.is_unicast_link_local() || ip.is_multicast(),
    }
}

fn peer_key(addrs: &[IpAddr]) -> [u8; 32] {
    let mut key = [0u8; 32];
    for address in addrs {
        match address {
            IpAddr::V4(ip) => key[..4].copy_from_slice(&ip.octets()),
            IpAddr::V6(ip) => key[16..32].copy_from_slice(&ip.octets()),
        }
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn the_tunnel_queue_is_bounded() {
        let (release, held) = mpsc::channel();
        let inner = assemble(
            Vec::new(),
            DEFAULT_MTU,
            false,
            Vec::new(),
            Arc::new(AtomicBool::new(true)),
            move |from_tunnel, _to_stack, _routes| {
                let _ = held.recv();
                for _ in from_tunnel.iter().take(QUEUE + 1) {}
            },
        );
        let sender = inner.to_tunnel.clone();
        let (filled, filling) = mpsc::channel();
        let (sent, done) = mpsc::channel();
        let producer = std::thread::spawn(move || {
            for packet in 0..QUEUE {
                sender
                    .send(vec![packet as u8])
                    .expect("a packet below the bound");
            }
            let _ = filled.send(());
            sender.send(vec![0]).expect("the queue drains");
            let _ = sent.send(());
        });
        filling
            .recv_timeout(Duration::from_secs(2))
            .expect("the producer filled the queue");
        assert!(
            done.recv_timeout(Duration::from_millis(250)).is_err(),
            "the tunnel queue accepted more than {QUEUE} packets"
        );
        let _ = release.send(());
        done.recv_timeout(Duration::from_secs(2))
            .expect("the producer completed after the queue drained");
        producer.join().expect("the producer thread");
    }

    #[test]
    fn workers_stop_at_the_cap() {
        let live = Arc::new(AtomicUsize::new(0));
        let mut slots = Vec::new();
        for _ in 0..MAX_WORKERS {
            slots.push(admit_worker(&live, MAX_WORKERS).expect("below the cap"));
        }
        assert!(
            admit_worker(&live, MAX_WORKERS).is_none(),
            "the cap admitted another worker"
        );
        slots.pop();
        assert!(
            admit_worker(&live, MAX_WORKERS).is_some(),
            "a released slot was not reusable"
        );
    }

    #[test]
    fn pins_are_checked_even_when_the_hello_is_insecure() {
        let spec = ClientSpec {
            address: "127.0.0.1".to_owned(),
            port: 443,
            tls: Some(Arc::new(TlsConfig {
                server_name: "edge.example".to_owned(),
                insecure: true,
                cert_pins: vec![[7u8; 32]].into(),
                ..TlsConfig::default()
            })),
            path: DEFAULT_PATH.to_owned(),
            host: None,
            headers: Vec::new(),
            remote_dns: Vec::new(),
            warp: None,
            keepalive: None,
            large_segments: false,
        };
        let mut config = client_config(&spec).expect("config");
        let cid = quiche::ConnectionId::from_ref(&[0u8; 16]);
        let local: SocketAddr = "127.0.0.1:50000".parse().expect("local");
        let peer: SocketAddr = "127.0.0.1:443".parse().expect("peer");
        let conn = quiche::connect(Some("edge.example"), &cid, local, peer, &mut config)
            .expect("connection");
        assert!(
            verify_edge(&spec, &conn).is_err(),
            "a pinned edge with no certificate chain was accepted"
        );
    }

    /// The pre-free-run allocator: a cursor and a used set, kept as the differential oracle.
    struct ScanFamily {
        server: u128,
        first: u128,
        last: u128,
        next: u128,
        used: HashSet<u128>,
        probes: usize,
    }

    impl ScanFamily {
        /// Mirror the pre-free-run allocator's cursor and used set.
        fn from(family: &Family) -> Self {
            Self {
                server: family.server,
                first: family.first,
                last: family.last,
                next: family.next,
                used: HashSet::new(),
                probes: 0,
            }
        }

        /// The old first-fit walk, counting every candidate it visits.
        fn allocate(&mut self) -> Option<u128> {
            let start = if self.next < self.first || self.next > self.last {
                self.first
            } else {
                self.next
            };
            let mut candidate = start;
            loop {
                self.probes += 1;
                if candidate != self.server && !self.used.contains(&candidate) {
                    self.used.insert(candidate);
                    self.next = if candidate >= self.last {
                        self.first
                    } else {
                        candidate + 1
                    };
                    return Some(candidate);
                }
                candidate = if candidate >= self.last {
                    self.first
                } else {
                    candidate + 1
                };
                if candidate == start {
                    return None;
                }
            }
        }

        /// The old release: drop the address from the used set.
        fn release(&mut self, address: u128) {
            self.used.remove(&address);
        }
    }

    #[test]
    /// The free runs take the same addresses as the old scan, and a full pool takes a
    /// constant number of free-run lookups rather than one per host.
    fn a_pool_takes_the_scan_order_without_scanning() {
        let mut family = Family::new(u128::from(0x0a14_0001u32), 24, 32).expect("family");
        let mut scan = ScanFamily::from(&family);
        let mut allocated = Vec::new();
        let mut state = 0x1234_5678_9abc_def0u64;
        let rounds = usize::try_from(family.last - family.first + 1).expect("pool size") * 3;
        for _ in 0..rounds {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            if allocated.is_empty() || state & 3 != 0 {
                let new = family.allocate();
                let old = scan.allocate();
                assert_eq!(new, old, "the free runs changed the allocation order");
                if let Some(address) = new {
                    allocated.push(address);
                }
            } else {
                let index = (state as usize) % allocated.len();
                let address = allocated.swap_remove(index);
                family.release(address);
                scan.release(address);
            }
        }
        loop {
            let new = family.allocate();
            let old = scan.allocate();
            assert_eq!(new, old, "the free runs changed the drain order");
            if new.is_none() {
                break;
            }
        }
        let new_before = family.probes;
        let old_before = scan.probes;
        for _ in 0..100 {
            assert_eq!(family.allocate(), None);
            assert_eq!(scan.allocate(), None);
        }
        let new_work = family.probes - new_before;
        let old_work = scan.probes - old_before;
        assert!(
            new_work * 10 < old_work,
            "a full pool took {new_work} free-run probes against {old_work} scan probes"
        );
    }

    #[test]
    fn a_pool_skips_its_server_and_wraps() {
        let mut pool = AddressPool::from_prefixes(&["10.14.0.1/30".to_owned()]).expect("a pool");
        assert_eq!(
            pool.assign(),
            vec!["10.14.0.2".parse::<IpAddr>().expect("an address")]
        );
        assert_eq!(pool.assign().len(), 0);
        pool.release("10.14.0.2".parse().expect("an address"));
        assert_eq!(
            pool.assign(),
            vec!["10.14.0.2".parse::<IpAddr>().expect("an address")]
        );
    }

    #[test]
    fn a_dual_stack_pool_grants_nothing_when_one_family_is_full() {
        let mut pool =
            AddressPool::from_prefixes(&["10.14.0.1/30".to_owned(), "fd14::1/126".to_owned()])
                .expect("a pool");
        assert_eq!(pool.assign().len(), 2);
        assert!(
            pool.assign().is_empty(),
            "a tunnel was granted only one family"
        );
        assert!(
            pool.assign().is_empty(),
            "the released v6 address was handed out alone"
        );
    }

    #[test]
    fn a_v6_pool_keeps_its_last_host() {
        let mut pool = AddressPool::from_prefixes(&["fd14::1/126".to_owned()]).expect("a pool");
        assert_eq!(
            pool.assign(),
            vec!["fd14::2".parse::<IpAddr>().expect("an address")]
        );
        assert_eq!(
            pool.assign(),
            vec!["fd14::3".parse::<IpAddr>().expect("an address")]
        );
        assert_eq!(pool.assign().len(), 0);
    }

    #[test]
    fn a_pool_holds_every_address_its_prefix_covers() {
        let pool = AddressPool::from_prefixes(&["10.14.0.1/24".to_owned()]).expect("a pool");
        assert!(pool.holds("10.14.0.0".parse().expect("an address")));
        assert!(pool.holds("10.14.0.255".parse().expect("an address")));
        assert!(!pool.holds("10.15.0.1".parse().expect("an address")));
    }

    fn dead_lane(stable: bool) -> Inner {
        let (flows, _) = mpsc::channel();
        let (to_tunnel, _) = mpsc::channel::<Vec<u8>>();
        Inner {
            config: Arc::new(DeviceConfig {
                secret: [0u8; 32],
                addresses: Vec::new(),
                peers: Vec::new(),
                mtu: DEFAULT_MTU,
                reserved: [0u8; 3],
                is_client: Some(true),
                no_kernel_tun: true,
                large_segments: false,
                dns: Vec::new(),
            }),
            flows,
            to_tunnel: to_tunnel.into(),
            routes: Arc::default(),
            alive: Arc::new(AtomicBool::new(false)),
            stable: Arc::new(AtomicBool::new(stable)),
        }
    }

    #[test]
    fn a_flapping_edge_is_dialled_on_the_backoff_not_per_packet() {
        let masque = MasqueOut::new(&outbound(0)).expect("outbound");
        let start = Instant::now();
        let mut now = start;
        let mut dials = Vec::new();
        for _ in 0..2000 {
            let _ = masque.ensure_at(now, || {
                dials.push(now);
                Ok(dead_lane(false))
            });
            now += Duration::from_millis(5);
        }
        let offsets: Vec<u128> = dials
            .iter()
            .map(|at| at.duration_since(start).as_millis())
            .collect();
        assert_eq!(
            offsets,
            vec![0, 1005, 3010, 7015],
            "2000 calls over ten seconds dialled {} times",
            dials.len()
        );
    }

    #[test]
    fn a_tunnel_that_stays_up_clears_the_backoff() {
        let masque = MasqueOut::new(&outbound(0)).expect("outbound");
        let start = Instant::now();
        let mut dials = 0;
        assert!(masque
            .ensure_at(start, || {
                dials += 1;
                Err("no edge".to_owned())
            })
            .is_err());
        assert!(masque
            .ensure_at(start + Duration::from_millis(999), || {
                dials += 1;
                Ok(dead_lane(false))
            })
            .is_err());
        assert_eq!(dials, 1, "the second dial ran before its second");
        let due = start + Duration::from_secs(1);
        masque
            .ensure_at(due, || {
                dials += 1;
                Ok(dead_lane(true))
            })
            .expect("the second dial");
        let proven = due + Duration::from_millis(1);
        masque
            .ensure_at(proven, || {
                dials += 1;
                Ok(dead_lane(false))
            })
            .expect("a lane that stayed up clears the history");
        assert_eq!(dials, 3);
        assert!(masque
            .ensure_at(proven, || {
                dials += 1;
                Ok(dead_lane(false))
            })
            .is_err());
        assert!(masque
            .ensure_at(proven + Duration::from_millis(999), || {
                dials += 1;
                Ok(dead_lane(false))
            })
            .is_err());
        let retry = proven + Duration::from_secs(1);
        masque
            .ensure_at(retry, || {
                dials += 1;
                Ok(dead_lane(false))
            })
            .expect("the reset schedule starts again at one second");
        assert_eq!(dials, 4);
    }

    #[test]
    fn a_full_pool_answers_503() {
        let inbound = inbound(
            r#"{"users":[{"email":"u@example.com","pass":"p"}],"address":["10.14.0.1/30"]}"#,
        );
        let port = serve_inbound(&inbound, &freedom("127.0.0.1:1"), "127.0.0.1:0").expect("serve");
        let first = MasqueOut::new(&outbound(port)).expect("the first tunnel");
        first.ensure().expect("the first tunnel opens");
        let second = MasqueOut::new(&outbound(port)).expect("the second tunnel");
        let error = second.ensure().expect_err("the full pool answered 200");
        assert!(
            error.contains("the edge answered 503"),
            "unexpected error: {error}"
        );
        drop(first);
    }

    fn ipv4_packet(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    fn ipv6_fragment() -> Vec<u8> {
        let mut packet = vec![0u8; 48];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&8u16.to_be_bytes());
        packet[6] = 44;
        packet[7] = 64;
        packet[8..24]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet[24..40]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[40] = 6;
        packet[42..44].copy_from_slice(&1u16.to_be_bytes());
        packet
    }

    #[test]
    fn a_packet_from_outside_the_tunnel_is_not_forwarded() {
        let (packets, _packets_rx) = mpsc::channel();
        let shared = Arc::new(Shared {
            pool: Mutex::new(AddressPool::default()),
            tunnels: Mutex::new(HashMap::new()),
            packets,
            local: Vec::new(),
        });
        let spec = ServerSpec {
            users: Vec::new(),
            path: DEFAULT_PATH.to_owned(),
            pool: AddressPool::default(),
            mtu: DEFAULT_MTU,
            warp: false,
        };
        let victim: IpAddr = "10.14.0.3".parse().expect("an address");
        let (to_victim, forwarded) = mpsc::sync_channel(4);
        shared
            .tunnels
            .lock()
            .expect("tunnels")
            .insert(victim, TunnelQueue::new(to_victim, None));
        let owner: IpAddr = "10.14.0.2".parse().expect("an address");
        let forged = ipv4_packet([10, 14, 0, 99], [10, 14, 0, 3]);
        forward(&shared, &spec, &[owner], &forged);
        assert!(
            forwarded.try_recv().is_err(),
            "a packet with a source outside the tunnel reached the destination"
        );
        let allowed = ipv4_packet([10, 14, 0, 2], [10, 14, 0, 3]);
        forward(&shared, &spec, &[owner], &allowed);
        assert!(
            forwarded.try_recv().is_ok(),
            "the tunnel's own source is forwarded"
        );
    }

    #[test]
    fn a_full_tunnel_queue_does_not_stall_dispatch_for_other_tunnels() {
        let (packets, _packets_rx) = mpsc::channel();
        let shared = Arc::new(Shared {
            pool: Mutex::new(AddressPool::default()),
            tunnels: Mutex::new(HashMap::new()),
            packets,
            local: Vec::new(),
        });
        let (blocked_tx, blocked_rx) = mpsc::sync_channel(1);
        let (open_tx, open_rx) = mpsc::sync_channel(4);
        let blocked: IpAddr = "10.14.0.3".parse().expect("an address");
        let open: IpAddr = "10.14.0.4".parse().expect("an address");
        blocked_tx.send(vec![0]).expect("fill the queue");
        {
            let mut tunnels = shared.tunnels.lock().expect("tunnels");
            tunnels.insert(blocked, TunnelQueue::new(blocked_tx, None));
            tunnels.insert(open, TunnelQueue::new(open_tx, None));
        }
        let (stack, from_stack) = mpsc::channel();
        let dispatcher = std::thread::spawn(move || dispatch(&shared, from_stack));
        stack
            .send(ipv4_packet([10, 14, 0, 2], [10, 14, 0, 3]))
            .expect("a packet for the full tunnel");
        stack
            .send(ipv4_packet([10, 14, 0, 2], [10, 14, 0, 4]))
            .expect("a packet for the free tunnel");
        let delivered = open_rx.recv_timeout(Duration::from_secs(2));
        drop(blocked_rx);
        drop(stack);
        dispatcher.join().expect("the dispatcher");
        assert!(
            delivered.is_ok(),
            "a full tunnel queue held the dispatcher and starved another tunnel"
        );
    }

    #[test]
    fn a_forwarded_datagram_is_the_buffer_that_arrived() {
        let (packets, packets_rx) = mpsc::channel();
        let shared = Arc::new(Shared {
            pool: Mutex::new(AddressPool::default()),
            tunnels: Mutex::new(HashMap::new()),
            packets,
            local: Vec::new(),
        });
        let spec = ServerSpec {
            users: Vec::new(),
            path: DEFAULT_PATH.to_owned(),
            pool: AddressPool::default(),
            mtu: DEFAULT_MTU,
            warp: false,
        };
        let owner: IpAddr = "10.14.0.2".parse().expect("an address");
        let packet = ipv4_packet([10, 14, 0, 2], [192, 0, 2, 1]);
        let mut datagram = Vec::with_capacity(2 + packet.len());
        connectip::datagram_prefix(4, &mut datagram);
        datagram.extend_from_slice(&packet);
        let base = datagram.as_ptr();
        let offset = datagram.len() - packet.len();
        let packet_base = datagram[offset..].as_ptr();
        let length = datagram.len();
        let capacity = datagram.capacity();
        forward_owned(&shared, &spec, &[owner], datagram, offset);
        let forwarded = packets_rx.recv().expect("forwarded");
        assert_eq!(forwarded.at, offset);
        assert_eq!(&forwarded.bytes[forwarded.at..], packet.as_slice());
        assert_eq!(forwarded.bytes.len(), length);
        assert_eq!(
            forwarded.bytes.as_ptr(),
            base,
            "the forwarded datagram is the buffer that arrived"
        );
        assert_eq!(
            forwarded.bytes[forwarded.at..].as_ptr(),
            packet_base,
            "the packet starts at its prefix, not at a moved copy"
        );
        assert_eq!(
            forwarded.bytes.capacity(),
            capacity,
            "the buffer did not grow on its way to the stack"
        );
    }

    #[test]
    fn a_delivered_datagram_is_the_buffer_that_arrived() {
        let (to_stack, stack_rx) = mpsc::channel();
        let routes = Arc::new(Mutex::new(HashMap::new()));
        let mut packet = ipv4_packet([10, 14, 0, 2], [192, 0, 2, 1]);
        packet[9] = 6;
        let mut datagram = Vec::with_capacity(2 + packet.len());
        connectip::datagram_prefix(4, &mut datagram);
        datagram.extend_from_slice(&packet);
        let base = datagram.as_ptr();
        let offset = datagram.len() - packet.len();
        let packet_base = datagram[offset..].as_ptr();
        let length = datagram.len();
        let capacity = datagram.capacity();
        deliver_owned(&to_stack, &routes, datagram, offset);
        let delivered = stack_rx.recv().expect("delivered");
        assert_eq!(delivered.at, offset);
        assert_eq!(&delivered.bytes[delivered.at..], packet.as_slice());
        assert_eq!(delivered.bytes.len(), length);
        assert_eq!(
            delivered.bytes.as_ptr(),
            base,
            "the delivered datagram is the buffer that arrived"
        );
        assert_eq!(
            delivered.bytes[delivered.at..].as_ptr(),
            packet_base,
            "the packet starts at its prefix, not at a moved copy"
        );
        assert_eq!(
            delivered.bytes.capacity(),
            capacity,
            "the buffer did not grow on its way to the stack"
        );
    }

    /// A first IPv4 UDP fragment goes to the stack, not the datagram lane.
    #[test]
    fn an_ipv4_udp_fragment_reaches_the_stack() {
        let (to_stack, stack_rx) = mpsc::channel();
        let routes = Arc::new(Mutex::new(HashMap::new()));
        let payload = vec![0x5a; 3000];
        let datagram = connectip::UdpDatagram {
            source: &[10, 14, 0, 2],
            destination: &[192, 0, 2, 1],
            source_port: 1234,
            destination_port: 4321,
            payload: &payload,
        };
        let mut packet = Vec::new();
        assert!(connectip::udp_datagram(&datagram, &mut packet));
        let piece = 1_344usize - 20;
        packet[2..4].copy_from_slice(&((20 + piece) as u16).to_be_bytes());
        packet[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        packet[10..12].fill(0);
        let header = ferrox_core::foxy::connectip::ipv4_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&header.to_be_bytes());
        packet.truncate(20 + piece);
        deliver(&to_stack, &routes, &packet);
        let delivered = stack_rx.recv().expect("the fragment reaches the stack");
        assert_eq!(delivered.bytes, packet);
        let mut later = packet.clone();
        later[6..8].copy_from_slice(&((piece / 8) as u16).to_be_bytes());
        deliver(&to_stack, &routes, &later);
        let delivered = stack_rx.recv().expect("a later fragment reaches the stack");
        assert_eq!(delivered.bytes, later);
    }

    #[test]
    fn an_ipv6_fragment_reaches_the_stack() {
        let (to_stack, stack_rx) = mpsc::channel();
        let routes = Arc::new(Mutex::new(HashMap::new()));
        let packet = ipv6_fragment();
        deliver(&to_stack, &routes, &packet);
        let delivered = stack_rx.recv().expect("delivered");
        assert_eq!(delivered.bytes, packet);
        let mut datagram = Vec::with_capacity(3 + packet.len());
        connectip::datagram_prefix(4, &mut datagram);
        datagram.extend_from_slice(&packet);
        let offset = datagram.len() - packet.len();
        deliver_owned(&to_stack, &routes, datagram, offset);
        let delivered = stack_rx.recv().expect("delivered from its datagram");
        assert_eq!(delivered.at, offset);
        assert_eq!(&delivered.bytes[delivered.at..], packet.as_slice());
    }

    #[test]
    fn a_queued_datagram_is_the_buffer_the_caller_built() {
        let (_inbound, port) = serve("127.0.0.1:1");
        let spec = ClientSpec::from(&outbound(port)).expect("spec");
        let (sock, peer, local) = quic::udp_to_server(&spec.address, spec.port).expect("resolve");
        let sock = Datagram::plain(sock);
        let mut lane = establish(&spec, &sock, peer, local).expect("lane");
        let packet = ipv4_packet([10, 14, 0, 2], [192, 0, 2, 1]);
        let mut warm = Vec::with_capacity(3 + packet.len());
        connectip::datagram_prefix(lane.stream, &mut warm);
        warm.extend_from_slice(&packet);
        lane.conn.dgram_send_buf(warm).expect("warm");
        quic::flush_egress(&mut lane.conn, &sock);
        assert_eq!(lane.conn.dgram_send_queue_len(), 0, "the warm packet left");

        let mut datagram = Vec::with_capacity(3 + packet.len());
        connectip::datagram_prefix(lane.stream, &mut datagram);
        datagram.extend_from_slice(&packet);
        let ((), new) = ferrox_core::alloc_count::measure(|| {
            lane.conn.dgram_send_buf(datagram).expect("queued");
        });
        assert_eq!(
            new.allocs, 0,
            "the prefixed datagram is the buffer quiche queues: {new:?}"
        );

        let mut copied = Vec::with_capacity(3 + packet.len());
        connectip::datagram_prefix(lane.stream, &mut copied);
        copied.extend_from_slice(&packet);
        let ((), old) = ferrox_core::alloc_count::measure(|| {
            lane.conn.dgram_send(&copied).expect("queued");
        });
        assert_eq!(
            old.allocs, 1,
            "the old handoff copied the datagram into a second buffer: {old:?}"
        );
    }

    #[test]
    fn a_subnet_grant_names_its_first_host() {
        let grant = Assigned {
            request_id: 0,
            version: 4,
            address: [192, 0, 2, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            prefix: 24,
        };
        assert_eq!(
            address_of(&grant),
            Some("192.0.2.1".parse().expect("an address"))
        );
        let grant = Assigned {
            request_id: 0,
            version: 6,
            address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5).octets(),
            prefix: 64,
        };
        assert_eq!(
            address_of(&grant),
            Some("2001:db8::1".parse().expect("an address"))
        );
    }

    #[test]
    fn an_address_capsule_withdraws_what_it_no_longer_grants() {
        fn grant(version: u8, address: &str, prefix: u8) -> Assigned {
            let address = match address.parse::<IpAddr>().expect("an address") {
                IpAddr::V4(ip) => {
                    let mut bytes = [0u8; 16];
                    bytes[..4].copy_from_slice(&ip.octets());
                    bytes
                }
                IpAddr::V6(ip) => ip.octets(),
            };
            Assigned {
                request_id: 1,
                version,
                address,
                prefix,
            }
        }
        let v4: IpAddr = "10.13.0.2".parse().expect("an address");
        let v6: IpAddr = "fd13::2".parse().expect("an address");
        let current = vec![v4, v6];
        let withdrawn_from = |entries: &[Assigned]| {
            let mut capsule = Vec::new();
            connectip::address_assign_encode(entries, &mut capsule);
            let (_, kind) = connectip::capsule_split(&capsule).expect("a whole capsule");
            let connectip::Capsule::AddressAssign(body) = kind else {
                panic!("an assignment capsule")
            };
            withdrawn(body, &current)
        };
        assert_eq!(
            withdrawn_from(&[grant(4, "10.13.0.2", 32), grant(6, "fd13::2", 128)]),
            None
        );
        assert_eq!(withdrawn_from(&[grant(6, "fd13::2", 128)]), Some(v4));
        assert_eq!(
            withdrawn_from(&[grant(4, "10.14.0.0", 24), grant(6, "fd13::2", 128)]),
            Some(v4)
        );
        assert_eq!(
            withdrawn_from(&[grant(4, "0.0.0.0", 32), grant(6, "fd13::2", 128)]),
            Some(v4)
        );
        assert_eq!(withdrawn_from(&[]), Some(v4));
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
            r#"{{"settings":{settings},"streamSettings":{{"network":"masque","security":"tls","tlsSettings":{{"certificates":[{{"certificate":[{}],"key":[{}]}}]}}}}}}"#,
            pem_lines(&minted.cert.pem()),
            pem_lines(&minted.signing_key.serialize_pem())
        ))
        .expect("a masque inbound")
    }

    fn outbound(port: u16) -> Json {
        outbound_with(port, "Basic dUBleGFtcGxlLmNvbTpw")
    }

    fn outbound_with(port: u16, authorization: &str) -> Json {
        crate::json::parse(&format!(
            r#"{{"settings":{{"address":"127.0.0.1","port":{port}}},"streamSettings":{{"network":"masque","security":"tls","tlsSettings":{{"serverName":"localhost","allowInsecure":true}},"masqueSettings":{{"headers":{{"Authorization":"{authorization}"}}}}}}}}"#
        ))
        .expect("a masque outbound")
    }

    fn outbound_large(port: u16) -> Json {
        crate::json::parse(&format!(
            r#"{{"settings":{{"address":"127.0.0.1","port":{port},"largeSegments":true}},"streamSettings":{{"network":"masque","security":"tls","tlsSettings":{{"serverName":"localhost","allowInsecure":true}},"masqueSettings":{{"headers":{{"Authorization":"Basic dUBleGFtcGxlLmNvbTpw"}}}}}}}}"#
        ))
        .expect("a masque outbound")
    }

    fn outbound_h2(port: u16) -> Json {
        crate::json::parse(&format!(
            r#"{{"settings":{{"address":"127.0.0.1","port":{port}}},"streamSettings":{{"network":"masque","security":"tls","tlsSettings":{{"serverName":"localhost","allowInsecure":true,"alpn":["h2"]}},"masqueSettings":{{"headers":{{"Authorization":"Basic dUBleGFtcGxlLmNvbTpw"}}}}}}}}"#
        ))
        .expect("a masque outbound")
    }

    fn inbound_h2(settings: &str) -> Json {
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        crate::json::parse(&format!(
            r#"{{"settings":{settings},"streamSettings":{{"network":"masque","security":"tls","tlsSettings":{{"alpn":["h3","h2"],"certificates":[{{"certificate":[{}],"key":[{}]}}]}}}}}}"#,
            pem_lines(&minted.cert.pem()),
            pem_lines(&minted.signing_key.serialize_pem())
        ))
        .expect("a masque inbound")
    }

    fn inbound_h1(settings: &str) -> Json {
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        crate::json::parse(&format!(
            r#"{{"settings":{settings},"streamSettings":{{"network":"masque","security":"tls","tlsSettings":{{"alpn":["h3","http/1.1"],"certificates":[{{"certificate":[{}],"key":[{}]}}]}}}}}}"#,
            pem_lines(&minted.cert.pem()),
            pem_lines(&minted.signing_key.serialize_pem())
        ))
        .expect("a masque inbound")
    }

    fn inbound_h2c(settings: &str) -> Json {
        crate::json::parse(&format!(
            r#"{{"settings":{settings},"streamSettings":{{"network":"masque","security":"none"}}}}"#
        ))
        .expect("a masque inbound")
    }

    fn outbound_h1(port: u16) -> Json {
        crate::json::parse(&format!(
            r#"{{"settings":{{"address":"127.0.0.1","port":{port}}},"streamSettings":{{"network":"masque","security":"tls","tlsSettings":{{"serverName":"localhost","allowInsecure":true,"alpn":["http/1.1"]}},"masqueSettings":{{"headers":{{"Authorization":"Basic dUBleGFtcGxlLmNvbTpw"}}}}}}}}"#
        ))
        .expect("a masque outbound")
    }

    fn outbound_h2c(port: u16) -> Json {
        crate::json::parse(&format!(
            r#"{{"settings":{{"address":"127.0.0.1","port":{port}}},"streamSettings":{{"network":"masque","security":"none","masqueSettings":{{"headers":{{"Authorization":"Basic dUBleGFtcGxlLmNvbTpw"}}}}}}}}"#
        ))
        .expect("a masque outbound")
    }

    fn serve_h1(redirect: &str) -> (Json, u16) {
        let inbound = inbound_h1(
            r#"{"users":[{"email":"u@example.com","pass":"p"}],"address":["10.14.0.1/24","fd14::1/64"]}"#,
        );
        let port = serve_inbound(&inbound, &freedom(redirect), "127.0.0.1:0").expect("serve");
        (inbound, port)
    }

    fn connect_udp_h1(
        target: &str,
        port: u16,
        bearer: &str,
    ) -> (ferrox_core::tls::ClientSession<std::net::TcpStream>, String) {
        use std::io::{Read as _, Write as _};
        use std::net::TcpStream;

        use ferrox_core::tls::TlsProvider as _;

        let inbound = inbound_h1(
            r#"{"users":[{"email":"u@example.com","pass":"p"}],"address":["10.14.0.1/24"]}"#,
        );
        let served =
            serve_inbound(&inbound, &freedom("127.0.0.1:1"), "127.0.0.1:0").expect("serve");
        let tcp = TcpStream::connect(("127.0.0.1", served)).expect("tcp");
        tcp.set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        let config = TlsConfig {
            server_name: "localhost".to_owned(),
            alpn: Arc::from([b"http/1.1".to_vec()]),
            insecure: true,
            ..TlsConfig::default()
        };
        let mut tls = ferrox_core::tls::connect(&config, tcp).expect("tls");
        tls.handshake().expect("handshake");
        let path = format!("/.well-known/masque/udp/{target}/{port}/");
        let request = format!(
            "GET https://localhost:{served}{path} HTTP/1.1\r\nHost: localhost:{served}\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\nProxy-Authorization: Bearer {bearer}\r\n\r\n"
        );
        tls.write_all(request.as_bytes()).expect("request");
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            tls.read_exact(&mut byte).expect("head");
            head.push(byte[0]);
        }
        (tls, String::from_utf8(head).expect("text"))
    }

    #[test]
    fn an_h1_connect_udp_tunnel_carries_a_datagram_to_its_target() {
        use std::io::{Read as _, Write as _};
        let echo = UdpSocket::bind("127.0.0.1:0").expect("echo");
        let address = echo.local_addr().expect("address");
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            if let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], from);
            }
        });
        let (mut tls, head) = connect_udp_h1("127.0.0.1", address.port(), "p");
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        let mut capsule = Vec::new();
        connectip::packet_encode(b"hello", &mut capsule);
        tls.write_all(&capsule).expect("capsule");
        let mut wire = Vec::new();
        let mut room = [0u8; 64];
        loop {
            if let Some((used, capsule)) = connectip::capsule_split(&wire) {
                match capsule {
                    connectip::Capsule::Datagram(payload) => {
                        assert_eq!(payload, b"hello");
                        break;
                    }
                    _ => {
                        wire.drain(..used);
                    }
                }
                continue;
            }
            let read = tls.read(&mut room).expect("read");
            assert!(read > 0, "the tunnel ended before the echo");
            wire.extend_from_slice(&room[..read]);
        }
    }

    #[test]
    fn an_h1_request_offering_both_upgrades_opens_connect_ip_on_an_ip_path() {
        use std::io::{Read as _, Write as _};
        use std::net::TcpStream;

        use ferrox_core::tls::TlsProvider as _;

        let (_, served) = serve_h1("127.0.0.1:1");
        let tcp = TcpStream::connect(("127.0.0.1", served)).expect("tcp");
        tcp.set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        let config = TlsConfig {
            server_name: "localhost".to_owned(),
            alpn: Arc::from([b"http/1.1".to_vec()]),
            insecure: true,
            ..TlsConfig::default()
        };
        let mut tls = ferrox_core::tls::connect(&config, tcp).expect("tls");
        tls.handshake().expect("handshake");
        let request = format!(
            "GET https://localhost:{served}/.well-known/masque/ip/*/*/ HTTP/1.1\r\nHost: localhost:{served}\r\nConnection: Upgrade\r\nUpgrade: connect-udp, connect-ip\r\nCapsule-Protocol: ?1\r\nAuthorization: Basic dUBleGFtcGxlLmNvbTpw\r\n\r\n"
        );
        tls.write_all(request.as_bytes()).expect("request");
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            tls.read_exact(&mut byte).expect("head");
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).expect("text");
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        assert!(head.contains("Upgrade: connect-ip"), "{head}");
    }

    #[test]
    fn an_h1_connect_udp_tunnel_refuses_a_wrong_bearer_with_a_proxy_challenge() {
        let (_, head) = connect_udp_h1("127.0.0.1", 9, "wrong");
        assert!(head.starts_with("HTTP/1.1 401"), "{head}");
        assert!(head.contains("Proxy-Authenticate: Basic"), "{head}");
    }

    #[allow(clippy::type_complexity)]
    fn connect_udp_h3(
        target: &str,
        port: u16,
        bearer: &str,
    ) -> Result<(quiche::Connection, Datagram, SocketAddr, Stream, u16), String> {
        let inbound = inbound(
            r#"{"users":[{"email":"u@example.com","pass":"p"}],"address":["10.14.0.1/24"]}"#,
        );
        let served = serve_inbound(&inbound, &freedom("127.0.0.1:1"), "127.0.0.1:0")?;
        let spec = ClientSpec {
            address: "127.0.0.1".to_owned(),
            port: served,
            tls: Some(Arc::new(TlsConfig {
                server_name: "localhost".to_owned(),
                insecure: true,
                ..TlsConfig::default()
            })),
            path: DEFAULT_PATH.to_owned(),
            host: None,
            headers: Vec::new(),
            remote_dns: Vec::new(),
            warp: None,
            keepalive: None,
            large_segments: false,
        };
        let mut config = client_config(&spec)?;
        let sock = Datagram::plain(
            UdpSocket::bind("127.0.0.1:0")
                .map_err(|error| format!("masque: cannot bind the client: {error}"))?,
        );
        let local = sock
            .local_addr()
            .map_err(|error| format!("masque: no client address: {error}"))?;
        let peer: SocketAddr = format!("127.0.0.1:{served}")
            .to_socket_addrs()
            .map_err(|error| format!("masque: cannot resolve the edge: {error}"))?
            .next()
            .ok_or("masque: the edge resolved to nothing")?;
        let mut scid = [0u8; 16];
        getrandom::fill(&mut scid).map_err(|error| format!("masque: no connection id: {error}"))?;
        let cid = quiche::ConnectionId::from_ref(&scid);
        let mut conn = quiche::connect(Some("localhost"), &cid, local, peer, &mut config)
            .map_err(|error| format!("masque: cannot open a connection: {error}"))?;
        quic::drive_handshake_by(&mut conn, &sock, local, ESTABLISH_TIMEOUT)
            .ok_or("masque: the QUIC handshake did not finish")?;
        send_server_settings(&mut conn, 2, 6, 10, false)?;
        let path = format!("/.well-known/masque/udp/{target}/{port}/");
        let mut block = Vec::new();
        connectip::connect_ip_qpack_named_protocol(
            "localhost",
            &path,
            b"connect-udp",
            &[("proxy-authorization".to_owned(), format!("Bearer {bearer}"))],
            &mut block,
        );
        let mut head = Vec::new();
        frames::quic_varint(&mut head, frames::H3_HEADERS);
        frames::quic_varint(&mut head, block.len() as u64);
        head.extend_from_slice(&block);
        send_stream(&mut conn, 0, &head, false)?;
        quic::flush_egress(&mut conn, &sock);
        let mut stream = Stream::default();
        let status = stream.wait_head(&mut conn, &sock, local, HEAD_TIMEOUT)?;
        Ok((conn, sock, local, stream, status))
    }

    #[test]
    fn an_h3_connect_udp_tunnel_carries_a_datagram_to_its_target() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("echo");
        let address = echo.local_addr().expect("address");
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            if let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], from);
            }
        });
        let (mut conn, sock, local, mut stream, status) =
            connect_udp_h3("127.0.0.1", address.port(), "p").expect("opens");
        assert_eq!(status, 200);
        let mut capsule = Vec::new();
        connectip::packet_encode(b"hello", &mut capsule);
        send_data(&mut conn, 0, &capsule).expect("datagram");
        quic::flush_egress(&mut conn, &sock);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            stream.poll(&mut conn, &sock, local, TICK).expect("pump");
            for owned in stream.take_capsules() {
                if let Owned::Datagram(payload) = owned {
                    assert_eq!(payload, b"hello");
                    return;
                }
            }
            assert!(
                Instant::now() < deadline,
                "the tunnel ended before the echo"
            );
        }
    }

    fn serve_h2c(redirect: &str) -> (Json, u16) {
        let inbound = inbound_h2c(
            r#"{"users":[{"email":"u@example.com","pass":"p"}],"address":["10.14.0.1/24","fd14::1/64"]}"#,
        );
        let port = serve_inbound(&inbound, &freedom(redirect), "127.0.0.1:0").expect("serve");
        (inbound, port)
    }

    fn serve_h2(redirect: &str) -> (Json, u16) {
        let inbound = inbound_h2(
            r#"{"users":[{"email":"u@example.com","pass":"p"}],"address":["10.14.0.1/24","fd14::1/64"]}"#,
        );
        let port = serve_inbound(&inbound, &freedom(redirect), "127.0.0.1:0").expect("serve");
        (inbound, port)
    }

    /// The pair's port budget is what the h2 listener competes for: once the budget is spent, the inbound must fall back to UDP-first so h3 still binds, not give up serving.
    #[test]
    fn an_h2_pair_exhausting_the_udp_budget_still_serves_h3() {
        let exhaustion = 9;
        HELD_H2_UDP_BINDS.with(|held| held.set(exhaustion));
        let inbound = inbound_h2(
            r#"{"users":[{"email":"u@example.com","pass":"p"}],"address":["10.14.0.1/24","fd14::1/64"]}"#,
        );
        let _port = serve_inbound(&inbound, &freedom("127.0.0.1:0"), "127.0.0.1:0")
            .expect("h3 survives the pair failing to converge");
    }

    fn freedom(redirect: &str) -> Outbound {
        let root = crate::json::parse(&format!(
            r#"{{"outbounds":[{{"protocol":"freedom","settings":{{"redirect":"{redirect}"}}}}]}}"#
        ))
        .expect("a freedom outbound");
        Outbound::Freedom(Arc::new(
            crate::proxy::find_freedom_outbound(&root)
                .expect("the outbound reads")
                .expect("a freedom outbound"),
        ))
    }

    fn serve(redirect: &str) -> (Json, u16) {
        let inbound = inbound(
            r#"{"users":[{"email":"u@example.com","pass":"p"}],"address":["10.14.0.1/24","fd14::1/64"]}"#,
        );
        let port = serve_inbound(&inbound, &freedom(redirect), "127.0.0.1:0").expect("serve");
        (inbound, port)
    }

    #[test]
    fn a_tcp_flow_crosses_the_tunnel_to_a_freedom_dial() {
        use std::io::{Read as _, Write as _};
        let echo = std::net::TcpListener::bind("127.0.0.1:0").expect("echo");
        let echo_address = echo.local_addr().expect("address");
        let target: SocketAddr = format!("192.0.2.1:{}", echo_address.port())
            .parse()
            .expect("a target");
        std::thread::spawn(move || {
            for stream in echo.incoming() {
                let Ok(mut stream) = stream else { continue };
                std::thread::spawn(move || {
                    let mut buf = [0u8; 1024];
                    loop {
                        let Ok(n) = stream.read(&mut buf) else {
                            return;
                        };
                        if n == 0 || stream.write_all(&buf[..n]).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        let (_inbound, port) = serve(&echo_address.to_string());
        let masque = MasqueOut::new(&outbound(port)).expect("outbound");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("pair");
        let tun = std::net::TcpStream::connect(listener.local_addr().expect("pair address"))
            .expect("connect");
        let (mut app, _) = listener.accept().expect("accept");
        app.set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        masque.serve_tcp(Connection::from(tun), &Destination::Address(target), &[]);
        app.write_all(b"hello").expect("write");
        let mut answer = [0u8; 5];
        app.read_exact(&mut answer).expect("read");
        assert_eq!(&answer, b"hello");
    }

    #[test]
    fn a_tcp_flow_crosses_the_tunnel_over_ipv6() {
        use std::io::{Read as _, Write as _};
        let Ok(echo) = std::net::TcpListener::bind("[::1]:0") else {
            return;
        };
        let echo_address = echo.local_addr().expect("address");
        let target: SocketAddr = format!("[2001:db8::1]:{}", echo_address.port())
            .parse()
            .expect("a target");
        std::thread::spawn(move || {
            for stream in echo.incoming() {
                let Ok(mut stream) = stream else { continue };
                std::thread::spawn(move || {
                    let mut buf = [0u8; 1024];
                    loop {
                        let Ok(n) = stream.read(&mut buf) else {
                            return;
                        };
                        if n == 0 || stream.write_all(&buf[..n]).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        let (_inbound, port) = serve(&echo_address.to_string());
        let masque = MasqueOut::new(&outbound(port)).expect("outbound");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("pair");
        let tun = std::net::TcpStream::connect(listener.local_addr().expect("pair address"))
            .expect("connect");
        let (mut app, _) = listener.accept().expect("accept");
        app.set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        masque.serve_tcp(Connection::from(tun), &Destination::Address(target), &[]);
        app.write_all(b"hello").expect("write");
        let mut answer = [0u8; 5];
        app.read_exact(&mut answer).expect("read");
        assert_eq!(&answer, b"hello");
    }

    #[test]
    fn a_tcp_flow_crosses_the_h2_tunnel_to_a_freedom_dial() {
        use std::io::{Read as _, Write as _};
        let echo = std::net::TcpListener::bind("127.0.0.1:0").expect("echo");
        let echo_address = echo.local_addr().expect("address");
        let target: SocketAddr = format!("192.0.2.1:{}", echo_address.port())
            .parse()
            .expect("a target");
        std::thread::spawn(move || {
            for stream in echo.incoming() {
                let Ok(mut stream) = stream else { continue };
                std::thread::spawn(move || {
                    let mut buf = [0u8; 1024];
                    loop {
                        let Ok(n) = stream.read(&mut buf) else {
                            return;
                        };
                        if n == 0 || stream.write_all(&buf[..n]).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        let (_inbound, port) = serve_h2(&echo_address.to_string());
        let masque = MasqueOut::new(&outbound_h2(port)).expect("outbound");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("pair");
        let tun = std::net::TcpStream::connect(listener.local_addr().expect("pair address"))
            .expect("connect");
        let (mut app, _) = listener.accept().expect("accept");
        app.set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        masque.serve_tcp(Connection::from(tun), &Destination::Address(target), &[]);
        app.write_all(b"hello").expect("write");
        let mut answer = [0u8; 5];
        app.read_exact(&mut answer).expect("read");
        assert_eq!(&answer, b"hello");
    }

    fn tcp_flow(serve: fn(&str) -> (Json, u16), outbound: fn(u16) -> Json) {
        echo_flow(serve, outbound, 5, 1);
    }

    fn echo_flow(
        serve: fn(&str) -> (Json, u16),
        outbound: fn(u16) -> Json,
        chunk: usize,
        rounds: usize,
    ) {
        use std::io::{Read as _, Write as _};
        let echo = std::net::TcpListener::bind("127.0.0.1:0").expect("echo");
        let echo_address = echo.local_addr().expect("address");
        let target: SocketAddr = format!("192.0.2.1:{}", echo_address.port())
            .parse()
            .expect("a target");
        std::thread::spawn(move || {
            for stream in echo.incoming() {
                let Ok(mut stream) = stream else { continue };
                std::thread::spawn(move || {
                    let mut buf = [0u8; 1024];
                    loop {
                        let Ok(n) = stream.read(&mut buf) else {
                            return;
                        };
                        if n == 0 || stream.write_all(&buf[..n]).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        let (_inbound, port) = serve(&echo_address.to_string());
        let masque = MasqueOut::new(&outbound(port)).expect("outbound");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("pair");
        let tun = std::net::TcpStream::connect(listener.local_addr().expect("pair address"))
            .expect("connect");
        let (mut app, _) = listener.accept().expect("accept");
        app.set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        masque.serve_tcp(Connection::from(tun), &Destination::Address(target), &[]);
        let pattern: Vec<u8> = (0..chunk).map(|byte| (byte % 251) as u8).collect();
        let mut answer = vec![0u8; chunk];
        for _ in 0..rounds {
            app.write_all(&pattern).expect("write");
            app.read_exact(&mut answer).expect("read");
            assert_eq!(answer, pattern);
        }
    }

    #[test]
    fn a_tcp_flow_crosses_the_tunnel_with_large_segments() {
        tcp_flow(serve, outbound_large);
    }

    #[test]
    fn a_large_upload_crosses_the_tunnel_with_large_segments() {
        echo_flow(serve, outbound_large, 64 * 1024, 16);
    }

    #[test]
    fn a_large_download_crosses_the_tunnel_with_large_segments() {
        download_flow(1024 * 1024, outbound_large);
    }

    #[test]
    fn a_large_download_crosses_the_tunnel_with_the_default_mss() {
        download_flow(1024 * 1024, outbound);
    }

    fn download_flow(size: usize, client_outbound: fn(u16) -> Json) {
        use std::io::{Read as _, Write as _};
        let payload = vec![0xab; size];
        let sink = std::net::TcpListener::bind("127.0.0.1:0").expect("sink");
        let sink_address = sink.local_addr().expect("address");
        let target: SocketAddr = format!("192.0.2.1:{}", sink_address.port())
            .parse()
            .expect("a target");
        let served = payload.clone();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = sink.accept() else {
                return;
            };
            let _ = stream.write_all(&served);
        });
        let (_inbound, port) = serve(&sink_address.to_string());
        let masque = MasqueOut::new(&client_outbound(port)).expect("outbound");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("pair");
        let tun = std::net::TcpStream::connect(listener.local_addr().expect("pair address"))
            .expect("connect");
        let (mut app, _) = listener.accept().expect("accept");
        app.set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        masque.serve_tcp(Connection::from(tun), &Destination::Address(target), &[]);
        let mut answer = vec![0u8; payload.len()];
        let mut got = 0;
        while got < answer.len() {
            match app.read(&mut answer[got..]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(error) => panic!(
                    "download stalled after {got} of {} bytes: {error}",
                    answer.len()
                ),
            }
        }
        assert_eq!(got, payload.len(), "the download ended early");
        assert_eq!(answer, payload);
    }

    #[test]
    fn a_tcp_flow_crosses_the_h1_tunnel_to_a_freedom_dial() {
        tcp_flow(serve_h1, outbound_h1);
    }

    #[test]
    fn a_tcp_flow_crosses_the_h2c_tunnel_to_a_freedom_dial() {
        tcp_flow(serve_h2c, outbound_h2c);
    }

    #[test]
    fn a_datagram_flow_crosses_the_tunnel_to_a_freedom_dial() {
        let echo = std::net::UdpSocket::bind("127.0.0.1:0").expect("echo");
        let echo_address = echo.local_addr().expect("address");
        let target: SocketAddr = format!("192.0.2.1:{}", echo_address.port())
            .parse()
            .expect("a target");
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], from);
            }
        });
        let (_inbound, port) = serve(&echo_address.to_string());
        let masque = MasqueOut::new(&outbound(port)).expect("outbound");
        let relay = std::net::UdpSocket::bind("127.0.0.1:0").expect("relay");
        let relay_address = relay.local_addr().expect("relay address");
        let thread_relay = relay.try_clone().expect("clone");
        std::thread::spawn(move || masque.serve_udp(&thread_relay, None));
        std::thread::sleep(Duration::from_secs(1));
        let app = std::net::UdpSocket::bind("127.0.0.1:0").expect("app");
        app.set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        let mut frame = Vec::new();
        crate::proxy::socks_udp_frame(&mut frame, &target, b"hello");
        app.send_to(&frame, relay_address).expect("send");
        let mut received = [0u8; 2048];
        let (n, _) = app.recv_from(&mut received).expect("framed reply");
        let (remote, payload) = crate::proxy::parse_socks_udp(&received[..n]).expect("frame");
        assert_eq!(remote, target);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn a_datagram_flow_crosses_the_h2_tunnel_to_a_freedom_dial() {
        let echo = std::net::UdpSocket::bind("127.0.0.1:0").expect("echo");
        let echo_address = echo.local_addr().expect("address");
        let target: SocketAddr = format!("192.0.2.1:{}", echo_address.port())
            .parse()
            .expect("a target");
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], from);
            }
        });
        let (_inbound, port) = serve_h2(&echo_address.to_string());
        let masque = MasqueOut::new(&outbound_h2(port)).expect("outbound");
        let relay = std::net::UdpSocket::bind("127.0.0.1:0").expect("relay");
        let relay_address = relay.local_addr().expect("relay address");
        let thread_relay = relay.try_clone().expect("clone");
        std::thread::spawn(move || masque.serve_udp(&thread_relay, None));
        std::thread::sleep(Duration::from_secs(1));
        let app = std::net::UdpSocket::bind("127.0.0.1:0").expect("app");
        app.set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        let mut frame = Vec::new();
        crate::proxy::socks_udp_frame(&mut frame, &target, b"hello");
        app.send_to(&frame, relay_address).expect("send");
        let mut received = [0u8; 2048];
        let (n, _) = app.recv_from(&mut received).expect("framed reply");
        let (remote, payload) = crate::proxy::parse_socks_udp(&received[..n]).expect("frame");
        assert_eq!(remote, target);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn the_carrier_follows_the_alpn_list() {
        let alpn = |protocols: &[&[u8]]| TlsConfig {
            alpn: protocols.iter().map(|protocol| protocol.to_vec()).collect(),
            ..TlsConfig::default()
        };
        assert!(uses_h2(&alpn(&[b"h2"])));
        assert!(!uses_h2(&alpn(&[b"h3"])));
        assert!(!uses_h2(&alpn(&[b"h3", b"h2"])));
        assert!(!uses_h2(&alpn(&[b"h2", b"h3"])));
        assert!(!uses_h2(&alpn(&[])));
        assert!(uses_h1(&alpn(&[b"http/1.1"])));
        assert!(!uses_h1(&alpn(&[b"h2", b"http/1.1"])));
        assert!(!uses_h1(&alpn(&[b"h3", b"http/1.1"])));
    }

    #[test]
    fn a_packet_wider_than_one_datagram_is_answered_with_icmp() {
        let (_inbound, port) = serve("127.0.0.1:1");
        let spec = ClientSpec::from(&outbound(port)).expect("spec");
        let (sock, peer, local) = quic::udp_to_server(&spec.address, spec.port).expect("resolve");
        let sock = Datagram::plain(sock);
        let mut lane = establish(&spec, &sock, peer, local).expect("lane");
        let mut packet = vec![0u8; 1400];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&1400u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 14, 0, 2]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
        packet[20..22].copy_from_slice(&1234u16.to_be_bytes());
        packet[22..24].copy_from_slice(&4321u16.to_be_bytes());
        packet[24..26].copy_from_slice(&1380u16.to_be_bytes());
        let Emission::TooLarge(icmp) = send_datagram(&mut lane.conn, lane.stream, &packet) else {
            panic!("too big for one datagram");
        };
        assert_eq!(icmp[9], 1, "ICMP");
        assert_eq!((icmp[20], icmp[21]), (3, 4), "fragmentation needed");
        assert_eq!(
            icmp[12..16],
            [192, 0, 2, 1],
            "the source is what was addressed"
        );
        assert_eq!(
            icmp[16..20],
            [10, 14, 0, 2],
            "the destination is the sender"
        );
        let max = lane.conn.dgram_max_writable_len().expect("datagrams");
        let overhead = frames::quic_varint_len(lane.stream / 4) + 1;
        assert_eq!(
            u16::from_be_bytes([icmp[26], icmp[27]]) as usize,
            max - overhead
        );
        let (refused, counts) = ferrox_core::alloc_count::measure(|| {
            send_datagram(&mut lane.conn, lane.stream, &packet)
        });
        assert!(matches!(refused, Emission::TooLarge(_)));
        assert!(
            counts.bytes < packet.len(),
            "a packet too wide is answered without staging it: {counts:?}"
        );
        assert!(
            matches!(
                send_datagram(&mut lane.conn, lane.stream, &icmp),
                Emission::Queued
            ),
            "it fits"
        );
    }

    #[test]
    fn a_full_datagram_queue_refuses_the_next_packet() {
        let (_inbound, port) = serve("127.0.0.1:1");
        let spec = ClientSpec::from(&outbound(port)).expect("spec");
        let (sock, peer, local) = quic::udp_to_server(&spec.address, spec.port).expect("resolve");
        let sock = Datagram::plain(sock);
        let mut lane = establish(&spec, &sock, peer, local).expect("lane");
        let mut packet = vec![0u8; 64];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&64u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 14, 0, 2]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
        packet[20..22].copy_from_slice(&1234u16.to_be_bytes());
        packet[22..24].copy_from_slice(&4321u16.to_be_bytes());
        packet[24..26].copy_from_slice(&44u16.to_be_bytes());
        for _ in 0..DGRAM_SEND_QUEUE {
            assert!(
                matches!(
                    send_datagram(&mut lane.conn, lane.stream, &packet),
                    Emission::Queued
                ),
                "the queue is not full yet"
            );
        }
        assert!(
            matches!(
                send_datagram(&mut lane.conn, lane.stream, &packet),
                Emission::Full
            ),
            "a full queue refuses the packet instead of dropping it"
        );
        quic::flush_egress(&mut lane.conn, &sock);
        assert!(
            matches!(
                send_datagram(&mut lane.conn, lane.stream, &packet),
                Emission::Queued
            ),
            "a drained queue takes the packet that was held"
        );
    }

    #[test]
    fn a_wrong_password_is_refused_with_401() {
        let (_inbound, port) = serve("127.0.0.1:1");
        let outbound = outbound_with(port, "Basic dTpw");
        let spec = ClientSpec::from(&outbound).expect("spec");
        let reason = open(&spec).expect_err("the edge refuses");
        assert!(reason.ends_with("the edge answered 401"), "{reason}");
    }

    #[test]
    fn the_authority_prefers_a_configured_host() {
        let outbound = crate::json::parse(
            r#"{"settings":{"server":{"address":"127.0.0.1","port":8443}},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"localhost","allowInsecure":true},"masqueSettings":{"host":"edge.example:443"}}}"#,
        )
        .expect("an outbound");
        let spec = ClientSpec::from(&outbound).expect("spec");
        assert_eq!(authority(&spec), "edge.example:443");
    }

    #[test]
    fn the_reference_user_and_pass_write_the_basic_header() {
        let outbound = crate::json::parse(
            r#"{"settings":{"address":"127.0.0.1","port":8443},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"localhost","allowInsecure":true},"masqueSettings":{"user":"u","pass":"p:q","headers":{"X-Token":"a"}}}}"#,
        )
        .expect("the reference outbound");
        let spec = ClientSpec::from(&outbound).expect("the reference spec");
        assert!(spec
            .headers
            .iter()
            .any(|(name, value)| name == "authorization" && value == "Basic dTpwOnE="));
        assert!(spec
            .headers
            .iter()
            .any(|(name, value)| name == "x-token" && value == "a"));
        let conflict = crate::json::parse(
            r#"{"settings":{"address":"127.0.0.1","port":8443},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"localhost","allowInsecure":true},"masqueSettings":{"user":"u","pass":"p","headers":{"Authorization":"Bearer x"}}}}"#,
        )
        .expect("the conflicting outbound");
        assert!(ClientSpec::from(&conflict).is_err());
    }

    #[test]
    fn the_reference_path_variables_become_the_wildcards() {
        let outbound = crate::json::parse(
            r#"{"settings":{"address":"127.0.0.1","port":8443},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"localhost","allowInsecure":true},"masqueSettings":{"path":"/masque/ip/{target}/{ipproto}/"}}}"#,
        )
        .expect("the reference outbound");
        let spec = ClientSpec::from(&outbound).expect("the reference spec");
        assert_eq!(spec.path, "/masque/ip/*/*/");
        let query = crate::json::parse(
            r#"{"settings":{"address":"127.0.0.1","port":8443},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"localhost","allowInsecure":true},"masqueSettings":{"path":"/masque/ip{?target,ipproto}"}}}"#,
        )
        .expect("the query outbound");
        let query = ClientSpec::from(&query).expect("the query spec");
        assert_eq!(query.path, "/masque/ip?target=*&ipproto=*");
        let server = ServerSpec::from(&inbound(
            r#"{"users":[{"email":"u@example.com","pass":"p"}],"address":["10.14.0.1/24"]}"#,
        ))
        .expect("a server spec");
        assert_eq!(server.path, DEFAULT_PATH);
        let server = crate::json::parse(
            r#"{"settings":{"users":[{"email":"u@example.com","pass":"p"}],"address":["10.14.0.1/24"]},"streamSettings":{"masqueSettings":{"path":"/masque/ip{&target,ipproto}"}}}"#,
        )
        .expect("a templated inbound");
        let server = ServerSpec::from(&server).expect("a templated server spec");
        assert_eq!(server.path, "/masque/ip&target=*&ipproto=*");
    }

    /// `largeSegments` is off unless the outbound names it.
    #[test]
    fn large_segments_are_opt_in_for_masque() {
        let plain = ClientSpec::from(&outbound(8443)).expect("the default spec");
        assert!(!plain.large_segments);
        let opted = crate::json::parse(
            r#"{"settings":{"address":"127.0.0.1","port":8443,"largeSegments":true},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"localhost","allowInsecure":true}}}"#,
        )
        .expect("the opted outbound");
        assert!(
            ClientSpec::from(&opted)
                .expect("the opted spec")
                .large_segments
        );
    }

    #[test]
    fn the_reference_keepalive_period_reaches_the_carrier() {
        let plain = crate::json::parse(
            r#"{"settings":{"address":"127.0.0.1","port":8443},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"localhost","allowInsecure":true}}}"#,
        )
        .expect("the default outbound");
        let plain = ClientSpec::from(&plain).expect("the default spec");
        assert_eq!(plain.keepalive(H3_KEEPALIVE), Some(H3_KEEPALIVE));
        assert_eq!(plain.keepalive(H2_KEEPALIVE), Some(H2_KEEPALIVE));
        let set = crate::json::parse(
            r#"{"settings":{"address":"127.0.0.1","port":8443},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"localhost","allowInsecure":true},"masqueSettings":{"xmux":{"hKeepAlivePeriod":20}}}}"#,
        )
        .expect("the xmux outbound");
        let set = ClientSpec::from(&set).expect("the xmux spec");
        assert_eq!(set.keepalive(H3_KEEPALIVE), Some(Duration::from_secs(20)));
        let off = crate::json::parse(
            r#"{"settings":{"address":"127.0.0.1","port":8443},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"localhost","allowInsecure":true},"masqueSettings":{"xmux":{"hKeepAlivePeriod":-1}}}}"#,
        )
        .expect("the disabled outbound");
        let off = ClientSpec::from(&off).expect("the disabled spec");
        assert_eq!(off.keepalive(H3_KEEPALIVE), None);
    }

    #[test]
    fn a_warp_client_refuses_the_credentials_it_would_not_send() {
        let key = rcgen::KeyPair::generate().expect("a key");
        let private = ferrox_core::b64::encode(&key.serialize_der());
        let public =
            ferrox_core::b64::encode(&warp_key(&key.public_key_pem()).expect("the public key"));
        let text = format!(
            r#"{{"settings":{{"address":"127.0.0.1","port":8443}},"streamSettings":{{"security":"tls","tlsSettings":{{"serverName":"localhost","allowInsecure":true}},"masqueSettings":{{"warp":{{"privateKey":"{private}","publicKey":"{public}","address":["172.16.0.2/32"]}}}}}}}}"#
        );
        let outbound = crate::json::parse(&text).expect("the warp outbound");
        ClientSpec::from(&outbound).expect("the warp spec");
        for credentials in [r#""user":"u""#, r#""pass":"p""#] {
            let text = text.replace(r#""warp""#, &format!(r#"{credentials},"warp""#));
            let outbound = crate::json::parse(&text).expect("the conflicting outbound");
            let error = ClientSpec::from(&outbound).expect_err("the refused credentials");
            assert!(error.contains("warp"), "{error}");
        }
    }

    #[test]
    fn a_debug_rendering_never_names_a_credential_or_a_key() {
        let key = rcgen::KeyPair::generate().expect("a key");
        let private = ferrox_core::b64::encode(&key.serialize_der());
        let public =
            ferrox_core::b64::encode(&warp_key(&key.public_key_pem()).expect("the public key"));
        let text = format!(
            r#"{{"settings":{{"address":"127.0.0.1","port":8443}},"streamSettings":{{"security":"tls","tlsSettings":{{"serverName":"localhost","allowInsecure":true}},"masqueSettings":{{"warp":{{"privateKey":"{private}","publicKey":"{public}","address":["172.16.0.2/32"]}}}}}}}}"#
        );
        let outbound = crate::json::parse(&text).expect("the warp outbound");
        let spec = ClientSpec::from(&outbound).expect("the warp spec");
        let warp = spec.warp.as_ref().expect("the warp block");
        let key_rendering = format!("{:?}", warp.key());
        for rendered in [
            format!("{warp:?}"),
            format!("{spec:?}"),
            format!("{:?}", MasqueOut::new(&outbound).expect("the warp lane")),
        ] {
            assert!(
                !rendered.contains(&key_rendering),
                "the private key is rendered: {rendered}"
            );
        }

        let authed = crate::json::parse(
            r#"{"settings":{"address":"127.0.0.1","port":8443},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"localhost","allowInsecure":true},"masqueSettings":{"user":"alice","pass":"hunter2"}}}"#,
        )
        .expect("the authed outbound");
        let token = ferrox_core::b64::encode(b"alice:hunter2");
        let spec = ClientSpec::from(&authed).expect("the authed spec");
        for rendered in [
            format!("{spec:?}"),
            format!("{:?}", MasqueOut::new(&authed).expect("the authed lane")),
        ] {
            assert!(
                !rendered.contains(&token) && !rendered.contains("hunter2"),
                "the credential is rendered: {rendered}"
            );
        }

        let inbound = crate::json::parse(
            r#"{"settings":{"address":["172.16.0.0/24"],"users":[{"email":"a@b","pass":"server-secret"}]},"streamSettings":{"network":"masque"}}"#,
        )
        .expect("the inbound");
        let server = ServerSpec::from(&inbound).expect("the server spec");
        let rendered = format!("{server:?}");
        assert!(!rendered.contains("server-secret"), "{rendered}");
    }

    #[test]
    fn the_reference_settings_spellings_read_the_same_edge() {
        let flat = crate::json::parse(
            r#"{"settings":{"address":"127.0.0.1","port":8443},"streamSettings":{"network":"masque","security":"tls","tlsSettings":{"serverName":"localhost","allowInsecure":true}}}"#,
        )
        .expect("the reference outbound");
        let nested = crate::json::parse(
            r#"{"settings":{"server":{"address":"127.0.0.1","port":8443}},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"localhost","allowInsecure":true}}}"#,
        )
        .expect("the nested outbound");
        let flat = ClientSpec::from(&flat).expect("the reference spec");
        let nested = ClientSpec::from(&nested).expect("the nested spec");
        assert_eq!(
            (flat.address.as_str(), flat.port),
            (nested.address.as_str(), nested.port)
        );
    }

    #[test]
    fn the_reference_user_spellings_serve_the_same_table() {
        let header = Some(&b"Basic dUBleGFtcGxlLmNvbTpw"[..]);
        for settings in [
            r#"{"users":[{"email":"u@example.com","pass":"p"}],"address":["10.14.0.1/24"]}"#,
            r#"{"clients":[{"email":"u@example.com","pass":"p"}],"address":["10.14.0.1/24"]}"#,
            r#"{"users":[{"email":"u@example.com","password":"p"}],"address":["10.14.0.1/24"]}"#,
            r#"{"users":[{"email":"u@example.com","account":{"password":"p"}}],"address":["10.14.0.1/24"]}"#,
        ] {
            let spec = ServerSpec::from(&inbound(settings)).expect("a spec");
            assert!(spec.authenticates(header), "{settings}");
        }
    }

    #[test]
    fn a_warp_server_accepts_the_cloudflare_dialect_without_basic_auth() {
        let header = Some(&b"Basic dUBleGFtcGxlLmNvbTpw"[..]);
        let spec = ServerSpec::from(&inbound(
            r#"{"warp":true,"users":[{"email":"u@example.com","pass":"p"}],"address":["10.14.0.1/24"]}"#,
        ))
        .expect("a warp server spec");
        assert!(spec.accepts_protocol(WARP_PROTOCOL));
        assert!(spec.accepts_protocol(b"connect-ip"));
        assert!(spec.path_matches(b"/", WARP_PROTOCOL));
        assert!(!spec.path_matches(b"/", b"connect-ip"));
        assert!(spec.request_authenticated(WARP_PROTOCOL, None));
        assert!(!spec.request_authenticated(b"connect-ip", None));
        assert!(spec.request_authenticated(b"connect-ip", header));
        assert!(ServerSpec::from(&inbound(r#"{"warp":true,"address":["10.14.0.1/24"]}"#)).is_ok());
        assert!(ServerSpec::from(&inbound(r#"{"address":["10.14.0.1/24"]}"#)).is_err());
    }

    fn head_tunnel(buf: Vec<u8>) -> Tunnel {
        let (sender, outgoing) = mpsc::sync_channel(1);
        let (tx, _rx) = mpsc::channel();
        Tunnel {
            stream: Some(0),
            buf,
            at: 0,
            headers: false,
            capsules: Vec::new(),
            capsule_at: 0,
            opened: false,
            rejected: false,
            settings_sent: false,
            pending: None,
            unsent: None,
            outgoing,
            queue: TunnelQueue::new(sender, Some(tx)),
            addrs: Vec::new(),
            granted: None,
            registered: Vec::new(),
            udp: None,
            udp_target: None,
            udp_frame: Vec::new(),
            udp_at: 0,
        }
    }

    /// One HTTP/3 DATA frame carrying `body`, as the request stream's parser sees it.
    fn data_frame(body: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frames::quic_varint(&mut frame, frames::H3_DATA);
        frames::quic_varint(&mut frame, body.len() as u64);
        frame.extend_from_slice(body);
        frame
    }

    /// A capsule header that declares more bytes than the cap is refused as soon as the header is
    /// whole, and the buffer never grows toward the declared length.
    #[test]
    fn an_h3_capsule_past_the_cap_is_refused_before_it_grows() {
        let mut header = Vec::new();
        frames::quic_varint(&mut header, 0);
        frames::quic_varint(&mut header, (CAPSULE_CAP + 1) as u64);
        let mut tunnel = head_tunnel(data_frame(&header));
        assert!(drain_capsules(&mut tunnel, DEFAULT_MTU).is_none());
        assert!(
            tunnel.capsules.len() < CAPSULE_CAP,
            "the declared length is refused before it is buffered"
        );
    }

    /// A DATA frame whose own length is past the cap is refused before its body is appended.
    #[test]
    fn an_h3_data_frame_past_the_cap_is_refused_before_it_grows() {
        let mut frame = Vec::new();
        frames::quic_varint(&mut frame, frames::H3_DATA);
        frames::quic_varint(&mut frame, (CAPSULE_CAP + 1) as u64);
        let mut tunnel = head_tunnel(frame);
        assert!(drain_capsules(&mut tunnel, DEFAULT_MTU).is_none());
        assert!(
            tunnel.capsules.is_empty(),
            "the frame body is never buffered"
        );
    }

    /// A DATAGRAM capsule wider than the tunnel MTU is dropped at parse; one that fits reaches the
    /// lane unchanged.
    #[test]
    fn an_oversized_h3_datagram_is_dropped_at_parse() {
        let target = UdpSocket::bind("127.0.0.1:0").expect("target");
        target
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("timeout");
        let port = target.local_addr().expect("address").port();
        let mut tunnel = head_tunnel(Vec::new());
        tunnel.udp = Some(UdpLane::open("127.0.0.1", port).expect("lane"));
        let mut oversized = Vec::new();
        connectip::packet_encode(&vec![0x45; DEFAULT_MTU + 1], &mut oversized);
        tunnel.buf = data_frame(&oversized);
        assert!(drain_capsules(&mut tunnel, DEFAULT_MTU).is_some());
        let mut room = [0u8; DEFAULT_MTU + 1];
        assert!(
            target.recv_from(&mut room).is_err(),
            "the oversized packet never reaches the lane"
        );
        let packet = vec![0x45; DEFAULT_MTU];
        let mut fits = Vec::new();
        connectip::packet_encode(&packet, &mut fits);
        tunnel.buf = data_frame(&fits);
        assert!(drain_capsules(&mut tunnel, DEFAULT_MTU).is_some());
        let (read, _) = target.recv_from(&mut room).expect("the packet that fits");
        assert_eq!(read, DEFAULT_MTU);
    }

    /// quiche greases a request stream before the HEADERS frame; a peer that stops at the first
    /// frame refuses a head xray never sends and the client waits on a status that never comes.
    #[test]
    fn a_greased_head_is_read_after_the_reserved_frames() {
        let spec = ServerSpec::from(&inbound(r#"{"warp":true,"address":["10.14.0.1/24"]}"#))
            .expect("a warp server spec");
        let mut block = Vec::new();
        hpack::qpack_literal_many(
            &[
                (":method", "CONNECT"),
                (":protocol", "cf-connect-ip"),
                (":scheme", "https"),
                (":authority", "cloudflareaccess.com"),
                (":path", "/"),
                ("user-agent", ""),
                ("capsule-protocol", "?1"),
            ],
            &mut block,
        );
        let mut buf = Vec::new();
        frames::quic_varint(&mut buf, 0x21);
        frames::quic_varint(&mut buf, 0);
        frames::quic_varint(&mut buf, 0x33);
        frames::quic_varint(&mut buf, b"GREASE is the word".len() as u64);
        buf.extend_from_slice(b"GREASE is the word");
        frames::quic_varint(&mut buf, frames::H3_HEADERS);
        frames::quic_varint(&mut buf, block.len() as u64);
        buf.extend_from_slice(&block);
        let mut tunnel = head_tunnel(buf);
        assert!(parse_head(&mut tunnel, &spec));
        assert!(tunnel.headers);
        assert!(!tunnel.rejected);
        assert_eq!(tunnel.at, 0);
        assert!(!tunnel.buf.windows(6).any(|window| window == b"GREASE"));
    }

    #[test]
    fn an_incomplete_grease_frame_leaves_the_head_to_the_next_read() {
        let spec = ServerSpec::from(&inbound(r#"{"warp":true,"address":["10.14.0.1/24"]}"#))
            .expect("a warp server spec");
        let mut buf = Vec::new();
        frames::quic_varint(&mut buf, 0x33);
        frames::quic_varint(&mut buf, 4);
        buf.extend_from_slice(b"GRE");
        let mut tunnel = head_tunnel(buf);
        assert!(!parse_head(&mut tunnel, &spec));
        assert_eq!(tunnel.at, 0);
        tunnel.buf.push(b'A');
        assert!(!parse_head(&mut tunnel, &spec));
        assert_eq!(tunnel.at, 6, "the whole grease frame was walked past");
    }

    #[test]
    fn a_request_path_reads_the_way_xray_parses_it() {
        assert!(path_matches(b"/.well-known/masque/ip/*/*/", DEFAULT_PATH));
        assert!(path_matches(
            b"/.well-known/masque/ip/%2A/%2A/",
            DEFAULT_PATH
        ));
        assert!(!path_matches(b"/.well-known/masque/ip/*/*", DEFAULT_PATH));
        assert!(!path_matches(
            b"/.well-known/masque/ip/*/*/?x=1",
            DEFAULT_PATH
        ));
        assert!(!path_matches(
            b"/.well-known/masque/ip/192.0.2.1/6/",
            DEFAULT_PATH
        ));
    }

    fn answer_fields(tunnel: &Tunnel) -> Vec<(String, String)> {
        let pending = tunnel.pending.as_ref().expect("an answer");
        let mut at = 0;
        let frame = frames::h3_frame(pending, &mut at).expect("a frame");
        let block = &pending[at..at + frame.length as usize];
        hpack::qpack_fields(block)
            .expect("a qpack block")
            .into_iter()
            .map(|(key, value)| {
                (
                    String::from_utf8(key).expect("a field name"),
                    String::from_utf8(value).expect("a field value"),
                )
            })
            .collect()
    }

    #[test]
    fn an_h3_connect_udp_head_answers_in_the_masque_dialect() {
        let spec = ServerSpec::from(&inbound(
            r#"{"users":[{"email":"u@example.com","pass":"p"}],"address":["10.14.0.1/24"]}"#,
        ))
        .expect("a spec");
        let request = |path: &str, bearer: &str| {
            let mut block = Vec::new();
            hpack::qpack_literal_many(
                &[
                    (":method", "CONNECT"),
                    (":protocol", "connect-udp"),
                    (":scheme", "https"),
                    (":authority", "localhost"),
                    (":path", path),
                    ("capsule-protocol", "?1"),
                    ("proxy-authorization", bearer),
                ],
                &mut block,
            );
            let mut buf = Vec::new();
            frames::quic_varint(&mut buf, frames::H3_HEADERS);
            frames::quic_varint(&mut buf, block.len() as u64);
            buf.extend_from_slice(&block);
            head_tunnel(buf)
        };
        let mut tunnel = request("/.well-known/masque/udp/127.0.0.1/53/", "Bearer p");
        assert!(parse_head(&mut tunnel, &spec));
        assert!(!tunnel.rejected);
        assert_eq!(tunnel.udp_target, Some(("127.0.0.1".to_owned(), 53)));
        let mut wrong = request("/.well-known/masque/udp/127.0.0.1/53/", "Bearer wrong");
        assert!(parse_head(&mut wrong, &spec));
        assert!(wrong.rejected);
        assert_eq!(
            answer_fields(&wrong),
            vec![
                (":status".to_owned(), "401".to_owned()),
                ("proxy-authenticate".to_owned(), AUTH_REALM.to_owned()),
            ]
        );
        let mut bad = request("/.well-known/masque/ip/127.0.0.1/53/", "Bearer p");
        assert!(parse_head(&mut bad, &spec));
        assert!(bad.rejected);
        assert_eq!(
            answer_fields(&bad),
            vec![(":status".to_owned(), "400".to_owned())]
        );
    }

    #[test]
    fn a_udp_template_path_names_its_target_and_decodes_only_the_host() {
        assert_eq!(
            udp_target(b"/.well-known/masque/udp/example.com/443/"),
            Some(("example.com".to_owned(), 443))
        );
        assert_eq!(
            udp_target(b"/.well-known/masque/udp/2001%3Adb8%3A%3A42/53/"),
            Some(("2001:db8::42".to_owned(), 53))
        );
        for path in [
            b"/.well-known/masque/udp/example.com/0/".as_slice(),
            b"/.well-known/masque/udp/example.com/70000/",
            b"/.well-known/masque/udp/example.com/443",
            b"/.well-known/masque/udp//443/",
            b"/.well-known/masque/udp/example.com/443/extra/",
            b"/.well-known/masque/ip/example.com/443/",
        ] {
            assert_eq!(udp_target(path), None, "{path:?}");
        }
    }

    #[test]
    fn a_udp_pass_is_a_bearer_secret_or_a_basic_credential() {
        let spec = ServerSpec::from(&inbound(
            r#"{"users":[{"email":"u@example.com","pass":"p"}],"address":["10.14.0.1/24"]}"#,
        ))
        .expect("a spec");
        assert!(spec.udp_authenticated(Some(&b"Bearer p"[..]), None));
        assert!(spec.udp_authenticated(None, Some(&b"Bearer p"[..])));
        assert!(spec.udp_authenticated(Some(&b"Basic dUBleGFtcGxlLmNvbTpw"[..]), None));
        assert!(!spec.udp_authenticated(Some(&b"Bearer wrong"[..]), None));
        assert!(!spec.udp_authenticated(Some(&b"Basic dUBleGFtcGxlLmNvbTp4"[..]), None));
    }

    #[test]
    fn the_datagram_prefix_round_trips() {
        let mut out = Vec::new();
        connectip::datagram_prefix(8, &mut out);
        out.extend_from_slice(&[0x45, 0, 0, 20]);
        let (stream, packet) = connectip::datagram_split(&out).expect("a datagram");
        assert_eq!(stream, 8);
        assert_eq!(packet, &[0x45, 0, 0, 20]);
    }

    #[test]
    fn a_warp_identity_carries_the_key_it_was_given() {
        let key = rcgen::KeyPair::generate().expect("a key");
        let private = key.serialize_der();
        let public = warp_key(&key.public_key_pem()).expect("the public key");
        let (certificate, minted) = warp_identity(&private).expect("an identity");
        assert_eq!(warp_spki(&certificate), Some(public.as_slice()));
        // whatever the config carried, the minted key names the same pair
        assert_eq!(
            warp_identity(&minted).expect("re-minted").1,
            minted,
            "the minted key is canonical"
        );
    }

    #[test]
    fn a_sec1_key_is_wrapped_in_the_pkcs8_envelope() {
        let key = rcgen::KeyPair::generate().expect("a key");
        let pkcs8 = key.serialize_der();
        let mut at = 0;
        let (_, body, _) = der_next(&pkcs8, &mut at).expect("the outer sequence");
        let mut inner = 0;
        der_next(body, &mut inner).expect("the version");
        der_next(body, &mut inner).expect("the algorithm");
        let (tag, sec1, _) = der_next(body, &mut inner).expect("the key");
        assert_eq!(tag, 0x04);
        assert_eq!(warp_pkcs8(sec1).expect("a wrapped key"), pkcs8);
    }

    #[test]
    fn warp_addresses_are_one_prefix_per_family() {
        let items = [
            Json::Str("172.16.0.2/32".to_owned()),
            Json::Str("2606:4700:110:8a36::1/128".to_owned()),
        ];
        let parsed = warp_addresses(&items).expect("two prefixes");
        assert_eq!(
            parsed,
            vec![
                "172.16.0.2".parse::<IpAddr>().expect("v4"),
                "2606:4700:110:8a36::1".parse::<IpAddr>().expect("v6"),
            ]
        );
        let twice = [
            Json::Str("172.16.0.2/32".to_owned()),
            Json::Str("172.16.0.3/32".to_owned()),
        ];
        assert!(warp_addresses(&twice).is_err());
    }

    /// Encode one `ADDRESS_ASSIGN` capsule as the client's stream parser sees it.
    fn assignment(addrs: &[IpAddr]) -> Owned {
        let mut wire = Vec::new();
        connectip::address_assign_encode(&grants(addrs, 0), &mut wire);
        let (_, connectip::Capsule::AddressAssign(body)) =
            connectip::capsule_split(&wire).expect("a capsule")
        else {
            panic!("an assignment capsule");
        };
        Owned::AddressAssign(body.to_vec())
    }

    #[test]
    fn a_warp_client_takes_every_address_the_edge_assigns() {
        let v4 = "172.16.0.9".parse::<IpAddr>().expect("v4");
        let v6 = "fd00::9".parse::<IpAddr>().expect("v6");
        let mut stream = Stream {
            pending: vec![assignment(&[v4]), assignment(&[v6])],
            ..Stream::default()
        };
        assert_eq!(assigned(&mut stream), Some(vec![v4, v6]));
        assert_eq!(assigned(&mut stream), None);

        let refused = connectip::Assigned {
            request_id: 0,
            version: 4,
            address: [0u8; 16],
            prefix: 32,
        };
        let mut wire = Vec::new();
        connectip::address_assign_encode(&[refused], &mut wire);
        let (_, connectip::Capsule::AddressAssign(body)) =
            connectip::capsule_split(&wire).expect("a capsule")
        else {
            panic!("an assignment capsule");
        };
        let mut stream = Stream {
            pending: vec![
                assignment(&[v4]),
                assignment(&[v6]),
                Owned::AddressAssign(body.to_vec()),
            ],
            ..Stream::default()
        };
        assert_eq!(assigned(&mut stream), Some(vec![v6]));
    }

    #[test]
    fn a_warp_client_config_loads_the_minted_identity() {
        let key = rcgen::KeyPair::generate().expect("a key");
        let (certificate, minted) = warp_identity(&key.serialize_der()).expect("an identity");
        let warp = Warp {
            public_key: warp_key(&key.public_key_pem()).expect("the public key"),
            certificate,
            key: minted,
            addresses: vec!["172.16.0.2".parse().expect("v4")],
        };
        assert!(warp_config(&warp).is_ok());
    }

    /// A minimal key is accepted by xray yet not by the backend's socket loader,
    /// so the minter rephrases every accepted key into the envelope that loads.
    #[test]
    fn a_minimal_warp_key_is_minted_in_a_form_the_socket_loads() {
        let private = warp_pkcs8(
            &warp_key("MEECAQEwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQg==")
                .expect("a key"),
        )
        .expect("an envelope");
        let (certificate, minted) = warp_identity(&private).expect("an identity");
        let warp = Warp {
            public_key: Vec::new(),
            certificate,
            key: minted,
            addresses: vec!["10.13.0.2".parse().expect("v4")],
        };
        assert!(warp_config(&warp).is_ok());
    }

    #[test]
    fn warp_h3_settings_name_the_draft_datagram() {
        let settings = h3_settings(true);
        assert!(
            settings
                .windows(3)
                .any(|window| window == [0x42, 0x76, 0x01]),
            "the draft-datagram setting is absent"
        );
        assert!(!h3_settings(false)
            .windows(3)
            .any(|window| window == [0x42, 0x76, 0x01]));
    }

    #[test]
    fn a_due_quic_deadline_is_swept_after_an_event() {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("config");
        assert!(quic::tune(&mut config, quic::ALPN));
        config.verify_peer(false);
        let local: SocketAddr = "127.0.0.1:9".parse().expect("local address");
        let peer: SocketAddr = "127.0.0.1:8".parse().expect("peer address");
        let cid = [3u8; 16];
        let cid = quiche::ConnectionId::from_ref(&cid);
        let mut conn =
            quiche::connect(Some("localhost"), &cid, local, peer, &mut config).expect("connection");
        let mut packet = vec![0u8; 1350];
        let (n, _) = conn.send(&mut packet).expect("initial");
        assert!(n > 0, "the client produced an initial packet");

        let limit = Instant::now() + Duration::from_secs(10);
        while conn.timeout() != Some(Duration::ZERO) {
            assert!(Instant::now() < limit, "the handshake timer never fell due");
            std::thread::sleep(Duration::from_millis(5));
        }

        sweep_due_timer(&mut conn);
        assert_ne!(
            conn.timeout(),
            Some(Duration::ZERO),
            "a due QUIC deadline was left for the next receive timeout"
        );
    }

    /// The count and byte caps both bound datagrams held before the stack attaches.
    #[test]
    fn early_h3_datagrams_are_bounded_by_count_and_bytes() {
        assert_eq!((EARLY_PACKETS, EARLY_BYTES), (64, 1 << 20));
        let mut stream = Stream::default();
        for _ in 0..EARLY_PACKETS {
            assert!(stream.stash(vec![0; 32]));
        }
        assert!(!stream.stash(vec![0; 32]), "the count cap holds");
        assert_eq!(stream.packets.len(), EARLY_PACKETS);

        let mut stream = Stream::default();
        let packet = vec![0u8; EARLY_BYTES / EARLY_PACKETS + 1];
        let mut accepted = 0;
        while stream.stash(packet.clone()) {
            accepted += 1;
        }
        assert!(accepted < EARLY_PACKETS, "the byte cap holds");
        assert!(stream.early_bytes <= EARLY_BYTES);
    }

    /// The poll path, not just the stash helper, ends the session on a pre-address flood.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn poll_refuses_a_pre_stack_datagram_flood() {
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let leaf = minted.cert.der().to_vec();
        let identity = ferrox_core::tls::TlsServerConfig {
            certs: vec![ferrox_core::tls::CertEntry {
                cert_chain: vec![leaf.clone()],
                key_der: minted.signing_key.serialize_der(),
                key_kind: ferrox_core::tls::ServerKeyKind::Pkcs8,
                reload: None,
                ocsp: None,
            }],
            alpn: Vec::new(),
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
        let mut server_config = quic::serve_config(&identity).expect("serves");
        server_config.enable_dgram(true, quic::MAX_DATAGRAM, DGRAM_INFLIGHT);
        let spec = ClientSpec {
            address: "127.0.0.1".to_owned(),
            port: 0,
            tls: Some(Arc::new(TlsConfig {
                server_name: "localhost".to_owned(),
                roots: vec![leaf].into(),
                ..TlsConfig::default()
            })),
            path: DEFAULT_PATH.to_owned(),
            host: None,
            headers: Vec::new(),
            remote_dns: Vec::new(),
            warp: None,
            keepalive: None,
            large_segments: false,
        };
        let mut client_config = client_config(&spec).expect("client config");
        let server_lane = Datagram::plain(UdpSocket::bind("127.0.0.1:0").expect("binds"));
        let server_addr = server_lane.local_addr().expect("server address");
        let client_lane = Datagram::plain(UdpSocket::bind("127.0.0.1:0").expect("binds"));
        let client_addr = client_lane.local_addr().expect("client address");
        let mut server_id = [0u8; 16];
        getrandom::fill(&mut server_id).expect("random");
        let server_id = quiche::ConnectionId::from_ref(&server_id);
        let mut server = quiche::accept(
            &server_id,
            None,
            server_addr,
            client_addr,
            &mut server_config,
        )
        .expect("accepts");
        let mut client_id = [0u8; 16];
        getrandom::fill(&mut client_id).expect("random");
        let client_id = quiche::ConnectionId::from_ref(&client_id);
        let mut client = quiche::connect(
            Some("localhost"),
            &client_id,
            client_addr,
            server_addr,
            &mut client_config,
        )
        .expect("connects");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !(client.is_established() && server.is_established()) {
            assert!(Instant::now() < deadline, "the handshake did not finish");
            quic::pump_once(&mut client, &client_lane, client_addr, TICK);
            quic::pump_once(&mut server, &server_lane, server_addr, TICK);
        }
        open_h3(&mut client, &spec).expect("opens the request");
        quic::flush_egress(&mut client, &client_lane);
        quic::pump_once(&mut server, &server_lane, server_addr, TICK);
        send_server_settings(&mut server, 3, 7, 11, false).expect("settings");
        let mut block = Vec::new();
        hpack::qpack_literal_many(
            &[(":status", "200"), ("capsule-protocol", "?1")],
            &mut block,
        );
        let mut head = Vec::new();
        frames::quic_varint(&mut head, frames::H3_HEADERS);
        frames::quic_varint(&mut head, block.len() as u64);
        head.extend_from_slice(&block);
        send_stream(&mut server, 0, &head, false).expect("head");
        quic::flush_egress(&mut server, &server_lane);
        let mut stream = Stream::default();
        assert_eq!(
            stream
                .wait_head(&mut client, &client_lane, client_addr, HEAD_TIMEOUT)
                .expect("head"),
            200
        );
        for _ in 0..=EARLY_PACKETS {
            let mut datagram = Vec::with_capacity(3 + 32);
            connectip::datagram_prefix(stream.id, &mut datagram);
            datagram.extend_from_slice(&[0u8; 32]);
            server.dgram_send_buf(datagram).expect("queues a datagram");
            quic::flush_egress(&mut server, &server_lane);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        let result = loop {
            match stream.poll(&mut client, &client_lane, client_addr, TICK) {
                Ok(()) => {}
                Err(reason) => break Err(reason),
            }
            if Instant::now() >= deadline {
                break Ok(());
            }
            quic::pump_once(&mut server, &server_lane, server_addr, TICK);
        };
        assert_eq!(
            result.expect_err("the poll path refuses the flood"),
            "masque: the edge sent too many datagrams before assigning an address"
        );
        assert_eq!(stream.packets.len(), EARLY_PACKETS);
    }
}

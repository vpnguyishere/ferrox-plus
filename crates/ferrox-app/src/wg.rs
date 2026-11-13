//! `WireGuard`'s runtime: the UDP socket, the per-peer tunnels, and the threads
//! that move an inner packet between the tunnel and the userspace stack.
//!
//! One reader owns the tunnel state. It decrypts every datagram, routes it to
//! the peer that authenticated it, and hands a TCP packet to `smoltcp` or a UDP
//! packet to the lane that asked. Writers only enqueue inner packets, so no
//! flow ever locks a session or races a counter.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
#[cfg(target_os = "linux")]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ferrox_core::dns::{build_query, parse_answer, Answer};
use ferrox_core::foxy::connectip::{
    udp_datagram, udp_from_packet, UdpDatagram, IPV4_HEADER, IPV6_HEADER, UDP_HEADER,
};
use ferrox_core::wireguard::device::{tai64n, Event, Tunnel};
use ferrox_core::wireguard::handshake::{
    check_mac1, INITIATION_SIZE, TYPE_INITIATION, TYPE_RESPONSE,
};
use ferrox_core::wireguard::transport::{
    check_mac2, clear_reserved, cookie_encryption_key, create_reply, COOKIE_NONCE_SIZE,
    HEADER_SIZE as WG_HEADER_SIZE, TAG_SIZE as WG_TAG_SIZE,
};

use crate::conn::Connection;
use crate::json::Json;
use crate::proxy::{Destination, Outbound};
#[cfg(target_os = "linux")]
use crate::wg_kernel::KernelWireGuard;
use crate::wg_stack::{self, ip_bytes, ClientFlow, Packet, UdpRoutes};
use crate::wireguard::{DeviceConfig, PeerConfig};

/// The reader's wait for a datagram: it also bounds how long a queued inner
/// packet waits before the tunnel encrypts it, because a packet queued while
/// the read waits has no datagram to interrupt it.
const IO_TICK: Duration = Duration::from_millis(1);
/// The kernel queue one socket keeps for a fast link, as the reference's bind
/// asks for: a default queue holds a few milliseconds of a gigabit stream and
/// a single scheduling gap drops the datagrams a TCP flow then retransmits.
const SOCKET_BUFFER: usize = 7 << 20;
/// The reference's DNS servers when the config names none.
const DEFAULT_DNS: [IpAddr; 4] = [
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
];
/// The wire DNS port; the config names addresses, not ports.
const DNS_PORT: u16 = 53;
/// How long one remote-DNS exchange waits for its answer.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
/// How long one remote-DNS query waits before it is sent again: the tunnel may
/// still be handshaking when the first datagram is offered, and a lost query
/// is cheaper to repeat than to fail.
const DNS_RETRY: Duration = Duration::from_secs(1);
/// The source-port range reserved for remote-DNS queries, below the ephemeral
/// range the datagram lanes bind.
const DNS_PORT_FIRST: u16 = 1024;
const DNS_PORT_LAST: u16 = 49_152;
/// The most names one outbound caches.
const DNS_CACHE: usize = 256;
/// Seconds a failed lookup is remembered, so a dead name does not stall a lane per datagram.
const DNS_NEGATIVE_TTL: u32 = 5;
/// The most kernel destinations one flow races, and the lane's idle tick.
#[cfg(target_os = "linux")]
const KERNEL_RACES: usize = 8;
#[cfg(target_os = "linux")]
const KERNEL_UDP_POLL: Duration = Duration::from_millis(10);
#[cfg(target_os = "linux")]
const KERNEL_RACE_AGAIN: Duration = Duration::from_secs(2);
#[cfg(target_os = "linux")]
const KERNEL_UPLINKS: usize = 64;
#[cfg(target_os = "linux")]
type KernelLaneKey = (String, u16);
/// One DNS exchange a client name can take through either path.
type Exchange<'a> = dyn Fn(IpAddr, IpAddr, &str, u16) -> Option<(Vec<IpAddr>, u32)> + Sync + 'a;
/// The reference's cookie lifetime and its one-second under-load tail.
const COOKIE_REFRESH: u64 = 120_000;
const UNDER_LOAD: u64 = 1_000;
/// The reference queues 1024 handshakes and treats an eighth of that as load.
const COOKIE_AFTER: u32 = 128;
/// The responder's rotating cookie secret and handshake-load window. `now` is
/// the reader's monotonic milliseconds, not wall time.
#[derive(Default)]
struct CookieGuard {
    secret: [u8; 32],
    secret_set: Option<u64>,
    window: u64,
    initiations: u32,
    under_load_until: u64,
}

impl CookieGuard {
    fn observe(&mut self, now: u64) -> bool {
        if now.saturating_sub(self.window) >= UNDER_LOAD {
            self.window = now;
            self.initiations = 0;
        }
        self.initiations = self.initiations.saturating_add(1);
        if self.initiations >= COOKIE_AFTER && now >= self.under_load_until {
            self.under_load_until = now.saturating_add(UNDER_LOAD);
        }
        now < self.under_load_until
    }

    fn check(&self, now: u64, packet: &[u8], source: &[u8]) -> bool {
        self.secret_set
            .is_some_and(|set| now.saturating_sub(set) <= COOKIE_REFRESH)
            && check_mac2(packet, &self.secret, source)
    }

    fn reply(
        &mut self,
        now: u64,
        packet: &[u8],
        source: &[u8],
        encryption_key: &[u8; 32],
    ) -> Option<[u8; 64]> {
        if self
            .secret_set
            .is_none_or(|set| now.saturating_sub(set) > COOKIE_REFRESH)
        {
            getrandom::fill(&mut self.secret).ok()?;
            self.secret_set = Some(now);
        }
        let mut nonce = [0u8; COOKIE_NONCE_SIZE];
        getrandom::fill(&mut nonce).ok()?;
        let receiver = u32::from_le_bytes(packet.get(4..8)?.try_into().ok()?);
        create_reply(
            packet,
            receiver,
            &self.secret,
            source,
            encryption_key,
            &nonce,
        )
    }
}

/// The source address bytes the reference hashes: family bytes then the port in
/// big-endian, as `netip.AddrPort.MarshalBinary` writes them.
fn endpoint_bytes(source: SocketAddr) -> ([u8; 18], usize) {
    let mut bytes = [0u8; 18];
    let width = match source.ip() {
        IpAddr::V4(address) => {
            bytes[..4].copy_from_slice(&address.octets());
            4
        }
        IpAddr::V6(address) => {
            bytes[..16].copy_from_slice(&address.octets());
            16
        }
    };
    bytes[width..width + 2].copy_from_slice(&source.port().to_be_bytes());
    (bytes, width + 2)
}

/// A cached remote-DNS answer and the instant it stops being usable.
#[derive(Debug)]
struct Resolved {
    addrs: Vec<IpAddr>,
    until: Instant,
}

/// The addresses of `qtype` an answer carries, with the smallest record TTL.
fn addresses(answer: &Answer, qtype: u16) -> Option<(Vec<IpAddr>, u32)> {
    let mut addrs = Vec::new();
    let mut ttl = 300u32;
    for record in &answer.records {
        if record.kind != qtype {
            continue;
        }
        let address = match record.rdata.len() {
            4 => IpAddr::from(<[u8; 4]>::try_from(record.rdata.as_slice()).ok()?),
            16 => IpAddr::from(<[u8; 16]>::try_from(record.rdata.as_slice()).ok()?),
            _ => continue,
        };
        addrs.push(address);
        ttl = ttl.min(record.ttl.max(1));
    }
    (!addrs.is_empty()).then_some((addrs, ttl))
}

/// A client outbound: the flow channel, the inner-packet queue the stack and
/// the datagram lanes write, and the lane table the reader routes replies by.
#[derive(Debug)]
pub(crate) struct WireGuardOut {
    config: Arc<DeviceConfig>,
    flows: Sender<ClientFlow>,
    to_tunnel: Sender<Vec<u8>>,
    routes: UdpRoutes,
    stop: Arc<AtomicBool>,
    dns_servers: Vec<IpAddr>,
    dns_port: u16,
    dns_port_next: AtomicU16,
    dns_id: AtomicU16,
    resolved: Mutex<HashMap<String, Resolved>>,
    #[cfg(target_os = "linux")]
    kernel: Option<Arc<KernelWireGuard>>,
}

impl WireGuardOut {
    /// Build a client outbound that resolves names against the reference's default DNS port.
    pub(crate) fn new(config: DeviceConfig) -> Result<Self, String> {
        Self::with_dns_port(config, DNS_PORT)
    }

    /// Build the outbound and route its DNS queries to `dns_port` through the tunnel.
    fn with_dns_port(config: DeviceConfig, dns_port: u16) -> Result<Self, String> {
        if config.is_client == Some(false) {
            return Err("a wireguard outbound must set `isClient: true`".to_owned());
        }
        let dns_servers = if config.dns.is_empty() {
            DEFAULT_DNS.to_vec()
        } else {
            config.dns.clone()
        };
        #[cfg(target_os = "linux")]
        if !config.no_kernel_tun {
            match KernelWireGuard::new(&config) {
                Ok(kernel) => {
                    return Ok(Self::with_kernel(config, kernel, dns_servers, dns_port));
                }
                Err(error) => eprintln!(
                    "wireguard: kernel mode unavailable, using the userspace stack: {error}"
                ),
            }
        }
        #[cfg(not(target_os = "linux"))]
        if !config.no_kernel_tun {
            eprintln!(
                "wireguard: `noKernelTun` is false, but the kernel device is Linux-only; serving the userspace stack"
            );
        }
        let socket = bind_socket(&config)?;
        let (packets_tx, packets_rx) = mpsc::channel();
        let (to_tunnel, from_tunnel) = mpsc::channel();
        let (recycle, recycled) = mpsc::channel();
        let io_recycle = recycle.clone();
        let (flows, flow_rx) = mpsc::channel();
        let routes: UdpRoutes = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let io_config = config.clone();
        let io_packets = packets_tx.clone();
        let io_routes = Arc::clone(&routes);
        let io_stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            io(
                io_config,
                socket,
                from_tunnel,
                io_packets,
                Some(io_routes),
                Some(io_stop),
                io_recycle,
                recycled,
            );
        });
        let stack_config = config.clone();
        let stack_tunnel = to_tunnel.clone();
        let stack_routes = Arc::clone(&routes);
        std::thread::spawn(move || {
            wg_stack::client(
                stack_config,
                stack_tunnel,
                packets_rx,
                flow_rx,
                WG_HEADER_SIZE,
                stack_routes,
                Some(recycle),
            );
        });
        Ok(Self {
            config: Arc::new(config),
            flows,
            to_tunnel,
            routes,
            stop,
            dns_servers,
            dns_port,
            dns_port_next: AtomicU16::new(0),
            dns_id: AtomicU16::new(0),
            resolved: Mutex::new(HashMap::new()),
            #[cfg(target_os = "linux")]
            kernel: None,
        })
    }

    #[cfg(target_os = "linux")]
    fn with_kernel(
        config: DeviceConfig,
        kernel: KernelWireGuard,
        dns_servers: Vec<IpAddr>,
        dns_port: u16,
    ) -> Self {
        let (flows, _) = mpsc::channel();
        let (to_tunnel, _) = mpsc::channel();
        Self {
            config: Arc::new(config),
            flows,
            to_tunnel,
            routes: Arc::default(),
            stop: Arc::new(AtomicBool::new(false)),
            dns_servers,
            dns_port,
            dns_port_next: AtomicU16::new(0),
            dns_id: AtomicU16::new(0),
            resolved: Mutex::new(HashMap::new()),
            kernel: Some(Arc::new(kernel)),
        }
    }

    pub(crate) fn edge(&self) -> Option<SocketAddr> {
        self.config.peers.first().and_then(|peer| peer.endpoint)
    }

    pub(crate) fn serve_tcp(&self, client: Connection, asked: &Destination, prefix: &[u8]) {
        #[cfg(target_os = "linux")]
        if let Some(kernel) = &self.kernel {
            self.serve_tcp_kernel(kernel, client, asked, prefix);
            return;
        }
        let destinations = self.destinations(asked);
        if destinations.is_empty() {
            eprintln!("wireguard: no peer allows `{asked:?}`");
            return;
        }
        if self
            .flows
            .send(ClientFlow {
                client,
                destinations,
                prefix: prefix.to_vec(),
            })
            .is_err()
        {
            eprintln!("wireguard: the userspace stack is gone");
        }
    }

    pub(crate) fn serve_udp(&self, relay: &UdpSocket, associate: Option<&Connection>) {
        #[cfg(target_os = "linux")]
        if let Some(kernel) = &self.kernel {
            self.serve_udp_kernel(kernel, relay, associate);
            return;
        }
        wg_stack::client_udp(
            relay,
            &self.config,
            &self.to_tunnel,
            &self.routes,
            associate,
            &|host, port| self.destinations(&Destination::Name(host.to_owned(), port)),
            WG_HEADER_SIZE,
        );
    }

    #[cfg(target_os = "linux")]
    fn serve_tcp_kernel(
        &self,
        kernel: &Arc<KernelWireGuard>,
        client: Connection,
        asked: &Destination,
        prefix: &[u8],
    ) {
        let destinations = self.destinations(asked);
        if destinations.is_empty() {
            eprintln!("wireguard: no peer allows `{asked:?}`");
            return;
        }
        let kernel = Arc::clone(kernel);
        let prefix = prefix.to_vec();
        std::thread::spawn(move || {
            let (sender, receiver) = mpsc::channel();
            for target in destinations.into_iter().take(KERNEL_RACES) {
                let sender = sender.clone();
                let kernel = Arc::clone(&kernel);
                std::thread::spawn(move || {
                    if let Ok(stream) = kernel.connect_tcp(target, crate::budgets::dial()) {
                        let _ = sender.send(stream);
                    }
                });
            }
            drop(sender);
            let Ok(stream) = receiver.recv() else {
                eprintln!("wireguard: kernel dial failed");
                return;
            };
            let mut upstream = Connection::from(stream);
            if !prefix.is_empty() && upstream.write_all(&prefix).is_err() {
                return;
            }
            crate::proxy::relay_handoff(&client, &upstream);
        });
    }

    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_lines)]
    fn serve_udp_kernel(
        &self,
        kernel: &KernelWireGuard,
        relay: &UdpSocket,
        associate: Option<&Connection>,
    ) {
        let source: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
        let winner: Arc<Mutex<HashMap<KernelLaneKey, (SocketAddr, Instant)>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let replies = Arc::new(AtomicU64::new(0));
        let (closed, closed_rx) = mpsc::channel();
        let mut uplinks: HashMap<(Option<KernelLaneKey>, SocketAddr), UdpSocket> = HashMap::new();
        let mut buf = crate::proxy::udp_buffer();
        let mut app = None;
        let mut seen = 0u64;
        let mut quiet = Instant::now();
        let _ = relay.set_read_timeout(Some(KERNEL_UDP_POLL));
        if let Some(associate) = associate {
            let _ = associate.set_read_timeout(Some(crate::budgets::SESSION_POLL));
        }
        'lane: loop {
            while let Ok(closed_key) = closed_rx.try_recv() {
                uplinks.remove(&closed_key);
            }
            if associate.is_some_and(crate::proxy::peer_left) {
                break;
            }
            let (n, src) = match relay.recv_from(&mut buf) {
                Ok(read) => read,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    let now = replies.load(Ordering::Relaxed);
                    if now != seen {
                        seen = now;
                        quiet = Instant::now();
                    }
                    if quiet.elapsed() >= crate::budgets::udp_idle() {
                        break;
                    }
                    continue;
                }
                Err(_) => break,
            };
            quiet = Instant::now();
            seen = replies.load(Ordering::Relaxed);
            let Some((dest, payload)) = crate::proxy::parse_socks_udp_dest(&buf[..n]) else {
                continue;
            };
            if app.is_some_and(|bound| bound != src) {
                continue;
            }
            app = Some(src);
            if let Ok(mut slot) = source.lock() {
                *slot = Some(src);
            }
            let key: Option<KernelLaneKey> = match &dest {
                Destination::Name(host, port) => Some((host.clone(), *port)),
                Destination::Address(_) => None,
            };
            let mut targets = self.destinations(&dest);
            if targets.is_empty() {
                continue;
            }
            if let Some(key) = &key {
                if let Ok(mut slot) = winner.lock() {
                    match slot.get(key) {
                        Some((pin, at))
                            if at.elapsed() < KERNEL_RACE_AGAIN && targets.contains(pin) =>
                        {
                            targets = vec![*pin];
                        }
                        Some(_) => {
                            slot.remove(key);
                        }
                        None => {}
                    }
                }
            }
            for target in targets.into_iter().take(KERNEL_RACES) {
                let uplink = (key.clone(), target);
                if let Some(up) = uplinks.get(&uplink) {
                    let _ = up.send(payload);
                    continue;
                }
                if uplinks.len() >= KERNEL_UPLINKS {
                    break 'lane;
                }
                let Ok(up) = kernel.udp_socket(target) else {
                    continue;
                };
                let Ok(writer) = up.try_clone() else {
                    continue;
                };
                let peer = Arc::clone(&source);
                let won = Arc::clone(&winner);
                let answered = Arc::clone(&replies);
                let closed = closed.clone();
                let Ok(relay_write) = relay.try_clone() else {
                    continue;
                };
                let key = key.clone();
                let closed_key = uplink.clone();
                let _ = up.set_read_timeout(Some(crate::budgets::udp_idle()));
                std::thread::spawn(move || {
                    let mut back = crate::proxy::udp_buffer();
                    let mut framed = Vec::with_capacity(64 + crate::proxy::UDP_BUF);
                    while let Ok(read) = up.recv(&mut back) {
                        let Some(app) = peer.lock().ok().and_then(|slot| *slot) else {
                            continue;
                        };
                        let chosen = if let Some(key) = &key {
                            let Ok(mut slot) = won.lock() else {
                                continue;
                            };
                            match slot.get(key) {
                                Some((pin, _)) if *pin != target => false,
                                Some(_) => true,
                                None => {
                                    slot.insert(key.clone(), (target, Instant::now()));
                                    true
                                }
                            }
                        } else {
                            true
                        };
                        if !chosen {
                            continue;
                        }
                        let out =
                            crate::proxy::socks_udp_frame(&mut framed, &target, &back[..read]);
                        if relay_write.send_to(out, app).is_err() {
                            break;
                        }
                        answered.fetch_add(1, Ordering::Relaxed);
                    }
                    let _ = closed.send(closed_key);
                });
                uplinks.insert(uplink.clone(), writer);
                let _ = uplinks[&uplink].send(payload);
            }
        }
    }

    /// The addresses to race: a literal stands, and a name becomes every answer
    /// a peer routes. The stack caps how many it dials at once.
    fn destinations(&self, asked: &Destination) -> Vec<SocketAddr> {
        let addresses = match asked {
            Destination::Address(address) => vec![*address],
            Destination::Name(host, port) => self.resolve(host, *port),
        };
        addresses
            .into_iter()
            .filter(|address| {
                self.config
                    .peers
                    .iter()
                    .any(|peer| peer.routes(address.ip()))
            })
            .collect()
    }

    fn resolve(&self, host: &str, port: u16) -> Vec<SocketAddr> {
        if let Ok(address) = host.parse::<IpAddr>() {
            return vec![SocketAddr::new(address, port)];
        }
        self.lookup(host)
            .into_iter()
            .map(|address| SocketAddr::new(address, port))
            .collect()
    }

    /// Answers a name through the kernel when Linux exposes one, and through the tunnel's DNS exchange otherwise.
    fn lookup(&self, host: &str) -> Vec<IpAddr> {
        let key = host.trim_end_matches('.').to_ascii_lowercase();
        if let Ok(cache) = self.resolved.lock() {
            if let Some(entry) = cache.get(&key) {
                if entry.until > Instant::now() {
                    return entry.addrs.clone();
                }
            }
        }
        #[cfg(target_os = "linux")]
        let answer = if self.kernel.is_some() {
            self.query_kernel(host)
        } else {
            self.query(host)
        };
        #[cfg(not(target_os = "linux"))]
        let answer = self.query(host);
        let (addrs, ttl) = answer.unwrap_or_else(|| (Vec::new(), DNS_NEGATIVE_TTL));
        if let Ok(mut cache) = self.resolved.lock() {
            if cache.len() >= DNS_CACHE {
                cache.clear();
            }
            cache.insert(
                key,
                Resolved {
                    addrs: addrs.clone(),
                    until: Instant::now() + Duration::from_secs(u64::from(ttl)),
                },
            );
        }
        addrs
    }

    pub(crate) fn probe(&self, host: &str, _port: u16) -> bool {
        self.query(host).is_some()
    }

    fn query(&self, host: &str) -> Option<(Vec<IpAddr>, u32)> {
        self.query_with(host, &|source, server, name, qtype| {
            self.exchange(source, server, name, qtype)
        })
    }

    #[cfg(target_os = "linux")]
    fn query_kernel(&self, host: &str) -> Option<(Vec<IpAddr>, u32)> {
        let kernel = self.kernel.as_ref()?;
        self.query_with(host, &|_source, server, name, qtype| {
            self.exchange_kernel(kernel, server, name, qtype)
        })
    }

    fn query_with(&self, host: &str, exchange: &Exchange<'_>) -> Option<(Vec<IpAddr>, u32)> {
        let name = if host.ends_with('.') {
            host.to_owned()
        } else {
            format!("{host}.")
        };
        let has_v4 = self.config.addresses.iter().any(IpAddr::is_ipv4);
        let has_v6 = self.config.addresses.iter().any(IpAddr::is_ipv6);
        let mut answers = Vec::new();
        let mut ttl = 300u32;
        for server in &self.dns_servers {
            if !self.config.peers.iter().any(|peer| peer.routes(*server)) {
                continue;
            }
            let Some(source) = self
                .config
                .addresses
                .iter()
                .find(|address| address.is_ipv4() == server.is_ipv4())
                .copied()
            else {
                continue;
            };
            let (v4, v6) = std::thread::scope(|scope| {
                let v4 = has_v4.then(|| scope.spawn(|| exchange(source, *server, &name, 1)));
                let v6 = has_v6.then(|| scope.spawn(|| exchange(source, *server, &name, 28)));
                (
                    v4.and_then(|handle| handle.join().ok().flatten()),
                    v6.and_then(|handle| handle.join().ok().flatten()),
                )
            });
            for (mut records, answer_ttl) in [v4, v6].into_iter().flatten() {
                answers.append(&mut records);
                ttl = ttl.min(answer_ttl.max(1));
            }
            if !answers.is_empty() {
                break;
            }
        }
        (!answers.is_empty()).then_some((answers, ttl))
    }

    #[cfg(target_os = "linux")]
    fn exchange_kernel(
        &self,
        kernel: &KernelWireGuard,
        server: IpAddr,
        name: &str,
        qtype: u16,
    ) -> Option<(Vec<IpAddr>, u32)> {
        let id = self.dns_id.fetch_add(1, Ordering::Relaxed);
        let query = build_query(id, name.as_bytes(), qtype, None)?;
        let socket = kernel
            .udp_socket(SocketAddr::new(server, self.dns_port))
            .ok()?;
        let mut buf = [0u8; 4096];
        let deadline = Instant::now() + DNS_TIMEOUT;
        let mut resend_at = Instant::now();
        loop {
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            if now >= resend_at {
                socket.send(&query).ok()?;
                resend_at = now + DNS_RETRY;
            }
            let until = resend_at.min(deadline);
            if until <= now {
                return None;
            }
            socket.set_read_timeout(Some(until - now)).ok()?;
            match socket.recv(&mut buf) {
                Ok(read) => {
                    let payload = &buf[..read];
                    if let Some(header) = payload.get(..12) {
                        let response_id = u16::from_be_bytes([header[0], header[1]]);
                        let flags = u16::from_be_bytes([header[2], header[3]]);
                        if response_id == id && flags.trailing_zeros() >= 4 && flags & 0x0200 != 0 {
                            return self.exchange_kernel_tcp(kernel, server, &query, id, qtype);
                        }
                    }
                    let Some(answer) = parse_answer(payload) else {
                        continue;
                    };
                    if answer.id != id {
                        continue;
                    }
                    if answer.rcode != 0 {
                        return None;
                    }
                    return addresses(&answer, qtype);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return None,
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn exchange_kernel_tcp(
        &self,
        kernel: &KernelWireGuard,
        server: IpAddr,
        query: &[u8],
        id: u16,
        qtype: u16,
    ) -> Option<(Vec<IpAddr>, u32)> {
        let mut stream = kernel
            .connect_tcp(SocketAddr::new(server, self.dns_port), DNS_TIMEOUT)
            .ok()?;
        stream.set_read_timeout(Some(DNS_TIMEOUT)).ok()?;
        stream.set_write_timeout(Some(DNS_TIMEOUT)).ok()?;
        let len = u16::try_from(query.len()).ok()?;
        stream.write_all(&len.to_be_bytes()).ok()?;
        stream.write_all(query).ok()?;
        let mut prefix = [0u8; 2];
        stream.read_exact(&mut prefix).ok()?;
        let len = usize::from(u16::from_be_bytes(prefix));
        if len == 0 {
            return None;
        }
        let mut response = vec![0u8; len];
        stream.read_exact(&mut response).ok()?;
        let answer = parse_answer(&response)?;
        if answer.id != id || answer.rcode != 0 || answer.truncated {
            return None;
        }
        addresses(&answer, qtype)
    }

    /// Ask one DNS server through the tunnel, resending a prefixed query when the first is lost.
    fn exchange(
        &self,
        source: IpAddr,
        server: IpAddr,
        name: &str,
        qtype: u16,
    ) -> Option<(Vec<IpAddr>, u32)> {
        let id = self.dns_id.fetch_add(1, Ordering::Relaxed);
        let query = build_query(id, name.as_bytes(), qtype, None)?;
        let (port, replies) = self.reserve_dns_route()?;
        let source_bytes = ip_bytes(source);
        let destination_bytes = ip_bytes(server);
        let header = if source.is_ipv4() {
            IPV4_HEADER
        } else {
            IPV6_HEADER
        };
        let dns_port = self.dns_port;
        let build = || {
            let mut packet = Vec::with_capacity(
                WG_HEADER_SIZE + header + UDP_HEADER + query.len() + WG_TAG_SIZE,
            );
            packet.resize(WG_HEADER_SIZE, 0);
            udp_datagram(
                &UdpDatagram {
                    source: &source_bytes,
                    destination: &destination_bytes,
                    source_port: port,
                    destination_port: dns_port,
                    payload: &query,
                },
                &mut packet,
            )
            .then_some(packet)
        };
        let Some(packet) = build() else {
            self.remove_dns_route(port);
            return None;
        };
        if self.to_tunnel.send(packet).is_err() {
            self.remove_dns_route(port);
            return None;
        }
        let deadline = Instant::now() + DNS_TIMEOUT;
        let mut resend_at = Instant::now() + DNS_RETRY;
        let result = loop {
            let now = Instant::now();
            if now >= deadline {
                break None;
            }
            if now >= resend_at {
                let Some(packet) = build() else {
                    break None;
                };
                if self.to_tunnel.send(packet).is_err() {
                    break None;
                }
                resend_at = now + DNS_RETRY;
            }
            let until = resend_at.min(deadline);
            if until <= now {
                break None;
            }
            let inner = match replies.recv_timeout(until - now) {
                Ok(inner) => inner,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break None,
            };
            let Some(datagram) = udp_from_packet(&inner) else {
                continue;
            };
            if datagram.source != destination_bytes.as_slice()
                || datagram.source_port != self.dns_port
                || datagram.destination_port != port
            {
                continue;
            }
            let payload = datagram.payload;
            if let Some(header) = payload.get(..12) {
                let response_id = u16::from_be_bytes([header[0], header[1]]);
                let flags = u16::from_be_bytes([header[2], header[3]]);
                if response_id == id && flags.trailing_zeros() >= 4 && flags & 0x0200 != 0 {
                    break self.exchange_tcp(server, &query, id, qtype);
                }
            }
            let Some(answer) = parse_answer(payload) else {
                continue;
            };
            if answer.id != id || answer.rcode != 0 {
                continue;
            }
            break addresses(&answer, qtype);
        };
        self.remove_dns_route(port);
        result
    }

    /// Ask again over a TCP flow through the same tunnel when a UDP answer is
    /// truncated, as the reference does: a local loopback pair hands the stream
    /// to the client stack, and the query travels length-prefixed.
    fn exchange_tcp(
        &self,
        server: IpAddr,
        query: &[u8],
        id: u16,
        qtype: u16,
    ) -> Option<(Vec<IpAddr>, u32)> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).ok()?;
        let mut app = TcpStream::connect(listener.local_addr().ok()?).ok()?;
        let (tunnel, _) = listener.accept().ok()?;
        app.set_read_timeout(Some(DNS_TIMEOUT)).ok()?;
        app.set_write_timeout(Some(DNS_TIMEOUT)).ok()?;
        if self
            .flows
            .send(ClientFlow {
                client: Connection::from(tunnel),
                destinations: vec![SocketAddr::new(server, self.dns_port)],
                prefix: Vec::new(),
            })
            .is_err()
        {
            return None;
        }
        let len = u16::try_from(query.len()).ok()?;
        let mut framed = Vec::with_capacity(2 + query.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(query);
        app.write_all(&framed).ok()?;
        let mut prefix = [0u8; 2];
        app.read_exact(&mut prefix).ok()?;
        let len = usize::from(u16::from_be_bytes(prefix));
        if len == 0 {
            return None;
        }
        let mut response = vec![0u8; len];
        app.read_exact(&mut response).ok()?;
        let answer = parse_answer(&response)?;
        if answer.id != id || answer.rcode != 0 || answer.truncated {
            return None;
        }
        addresses(&answer, qtype)
    }

    fn reserve_dns_route(&self) -> Option<(u16, Receiver<Vec<u8>>)> {
        let mut routes = self.routes.lock().ok()?;
        let span = u32::from(DNS_PORT_LAST - DNS_PORT_FIRST);
        for _ in 0..span {
            let offset = u32::from(self.dns_port_next.fetch_add(1, Ordering::Relaxed)) % span;
            let port = DNS_PORT_FIRST + offset as u16;
            if let std::collections::hash_map::Entry::Vacant(entry) = routes.entry(port) {
                let (sender, receiver) = mpsc::channel();
                entry.insert(sender);
                return Some((port, receiver));
            }
        }
        None
    }

    fn remove_dns_route(&self, port: u16) {
        if let Ok(mut routes) = self.routes.lock() {
            routes.remove(&port);
        }
    }
}

impl Drop for WireGuardOut {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

const VERIFY_ASK_GAP: Duration = Duration::from_millis(600);
/// The longest a probe's receive parks, so the loop drains events and rechecks the deadline.
const VERIFY_POLL: Duration = Duration::from_millis(100);

/// The receive wait left before the caller's deadline, capped by the poll.
fn poll_wait(left: Duration) -> Option<Duration> {
    (!left.is_zero()).then(|| left.min(VERIFY_POLL))
}

/// Open one handshake against a candidate endpoint and ask a DNS question
/// through it, without the stack, so a sweep does not spend two threads per
/// edge.
pub(crate) fn verify_endpoint(
    private: [u8; 32],
    peer: [u8; 32],
    reserved: [u8; 3],
    local: Ipv4Addr,
    endpoint: SocketAddr,
    timeout: Duration,
) -> Option<Duration> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    let started = Instant::now();
    let mut tunnel = Tunnel::new(private, peer, [0; 32], endpoint, 0, reserved, tai64n_now());
    let mut events = Vec::new();
    tunnel.initiate(0, &mut events);
    let id = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.subsec_nanos())
        & 0xffff) as u16;
    let query = build_query(id, b"one.one.one.one.", 1, None)?;
    let source = ip_bytes(IpAddr::V4(local));
    let destination = ip_bytes(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    let mut next_ask = Duration::ZERO;
    let mut buf = [0u8; 4096];
    loop {
        let now = started.elapsed();
        if now >= timeout {
            return None;
        }
        for event in events.drain(..) {
            if let Event::Send { endpoint, packet } = event {
                let _ = socket.send_to(&packet, endpoint);
            }
        }
        tunnel.poll(now.as_millis() as u64, &mut events);
        if tunnel.established(now.as_millis() as u64) && now >= next_ask {
            let mut packet = Vec::with_capacity(IPV4_HEADER + UDP_HEADER + query.len());
            if !udp_datagram(
                &UdpDatagram {
                    source: &source,
                    destination: &destination,
                    source_port: 33333,
                    destination_port: DNS_PORT,
                    payload: &query,
                },
                &mut packet,
            ) {
                return None;
            }
            tunnel.send(now.as_millis() as u64, &packet, &mut events);
            next_ask = now + VERIFY_ASK_GAP;
        }
        let wait = poll_wait(timeout.saturating_sub(started.elapsed()))?;
        socket.set_read_timeout(Some(wait)).ok()?;
        if let Ok((read, source)) = socket.recv_from(&mut buf) {
            tunnel.receive(
                now.as_millis() as u64,
                recv_endpoint(source, false),
                &mut buf[..read],
                &mut events,
            );
            for event in events.drain(..) {
                match event {
                    Event::Send { endpoint, packet } => {
                        let _ = socket.send_to(&packet, endpoint);
                    }
                    Event::Data(payload) => {
                        let Some(datagram) = udp_from_packet(&payload) else {
                            continue;
                        };
                        if datagram.source != destination.as_slice()
                            || datagram.source_port != DNS_PORT
                            || datagram.destination_port != 33333
                        {
                            continue;
                        }
                        if parse_answer(datagram.payload).is_some_and(|answer| {
                            answer.id == id
                                && answer.rcode == 0
                                && answer
                                    .records
                                    .iter()
                                    .any(|record| record.kind == 1 && record.rdata.len() == 4)
                        }) {
                            let answered = started.elapsed();
                            return (answered < timeout).then_some(answered);
                        }
                    }
                    Event::DataPrefixed(_) => {}
                }
            }
        }
    }
}

/// Open the server's UDP socket and spawn its reader and stack. Returns the
/// port the OS bound, or a refusal the startup names.
pub(crate) fn serve_inbound(inbound: &Json, out: &Outbound, address: &str) -> Result<u16, String> {
    let settings = inbound
        .get("settings")
        .ok_or("wireguard inbound has no settings")?;
    let config = DeviceConfig::from_json(settings)?;
    if config.is_client == Some(true) {
        return Err("a wireguard inbound must not set `isClient: true`".to_owned());
    }
    if !config.no_kernel_tun {
        eprintln!(
            "wireguard: the reference's server always serves a userspace stack; `noKernelTun` is not read here"
        );
    }
    let socket = UdpSocket::bind(address)
        .map_err(|error| format!("cannot bind wireguard `{address}`: {error}"))?;
    let port = socket
        .local_addr()
        .map_err(|error| format!("wireguard `{address}` has no local address: {error}"))?
        .port();
    let _ = socket.set_read_timeout(Some(IO_TICK));
    let (packets_tx, packets_rx) = mpsc::channel();
    let (to_tunnel, from_tunnel) = mpsc::channel();
    let (recycle, recycled) = mpsc::channel();
    let io_recycle = recycle.clone();
    let io_config = config.clone();
    let io_packets = packets_tx.clone();
    std::thread::spawn(move || {
        io(
            io_config,
            socket,
            from_tunnel,
            io_packets,
            None,
            None,
            io_recycle,
            recycled,
        );
    });
    let stack_config = config;
    let stack_tunnel = to_tunnel;
    let stack_out = out.clone();
    std::thread::spawn(move || {
        wg_stack::server(
            stack_config,
            stack_tunnel,
            packets_rx,
            stack_out,
            WG_HEADER_SIZE,
            Some(recycle),
        );
    });
    Ok(port)
}

/// One peer's configured identity beside the tunnel state the reader owns.
struct Peer {
    config: PeerConfig,
    tunnel: Tunnel,
}

trait Allowed {
    fn allowed(&self) -> &[(IpAddr, u8)];
    fn longest_prefix(&self, destination: IpAddr) -> Option<u8>;
}

impl Allowed for Peer {
    fn allowed(&self) -> &[(IpAddr, u8)] {
        &self.config.allowed
    }

    fn longest_prefix(&self, destination: IpAddr) -> Option<u8> {
        self.config.longest_prefix(destination)
    }
}

impl Allowed for PeerConfig {
    fn allowed(&self) -> &[(IpAddr, u8)] {
        &self.allowed
    }

    fn longest_prefix(&self, destination: IpAddr) -> Option<u8> {
        PeerConfig::longest_prefix(self, destination)
    }
}

struct Peers {
    peers: Vec<Peer>,
    routes: Routes,
}

impl std::ops::Deref for Peers {
    type Target = [Peer];

    fn deref(&self) -> &[Peer] {
        &self.peers
    }
}

impl std::ops::DerefMut for Peers {
    fn deref_mut(&mut self) -> &mut [Peer] {
        &mut self.peers
    }
}

impl Peers {
    fn new(peers: Vec<Peer>) -> Self {
        let routes = Routes::new(&peers);
        Self { peers, routes }
    }

    fn peer_for(&self, destination: IpAddr) -> Option<usize> {
        self.routes.peer_for(&self.peers, destination)
    }
}

/// The tunnel reader and writer: inner packets leave, datagrams arrive, and the
/// timers run on the same clock.
#[allow(clippy::needless_pass_by_value)]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
fn io(
    config: DeviceConfig,
    socket: UdpSocket,
    from_tunnel: Receiver<Vec<u8>>,
    to_stack: Sender<Packet>,
    routes: Option<UdpRoutes>,
    stop: Option<Arc<AtomicBool>>,
    recycle: Sender<Vec<u8>>,
    recycled: Receiver<Vec<u8>>,
) {
    let _ = socket.set_read_timeout(Some(IO_TICK));
    widen(&socket);
    let ipv6_socket = socket.local_addr().is_ok_and(|address| address.is_ipv6());
    let epoch = tai64n_now();
    let mut peers = peers(&config, epoch);
    let mut cookies = CookieGuard::default();
    let started = Instant::now();
    #[cfg(target_os = "linux")]
    let mut receive_batch = ReceiveBatch::new(config.mtu, recycled);
    #[cfg(not(target_os = "linux"))]
    let _ = recycled;
    #[cfg(not(target_os = "linux"))]
    let mut buf = vec![0u8; 65_535];
    let mut incoming = Vec::new();
    let mut events = Vec::new();
    let mut sends = Vec::new();
    loop {
        if stop
            .as_ref()
            .is_some_and(|stop| stop.load(Ordering::Relaxed))
        {
            return;
        }
        let now = started.elapsed().as_millis() as u64;
        let mut pending = None;
        for _ in 0..TX_DRAIN {
            let packet = match from_tunnel.try_recv() {
                Ok(packet) => packet,
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    if let Some(index) = pending {
                        flush(
                            &mut events,
                            &socket,
                            &to_stack,
                            routes.as_ref(),
                            &peers,
                            Some(index),
                            ipv6_socket,
                            &mut sends,
                            Some(&recycle),
                        );
                    }
                    return;
                }
            };
            if packet.len() < WG_HEADER_SIZE {
                continue;
            }
            let Some((_, destination)) = wg_stack::inner_addresses(&packet[WG_HEADER_SIZE..])
            else {
                continue;
            };
            let Some(index) = peers.peer_for(destination) else {
                continue;
            };
            if pending != Some(index) {
                if let Some(previous) = pending {
                    flush(
                        &mut events,
                        &socket,
                        &to_stack,
                        routes.as_ref(),
                        &peers,
                        Some(previous),
                        ipv6_socket,
                        &mut sends,
                        Some(&recycle),
                    );
                }
                pending = Some(index);
            }
            peers[index]
                .tunnel
                .send_prefixed(now, packet, WG_HEADER_SIZE, &mut events);
        }
        if let Some(index) = pending {
            flush(
                &mut events,
                &socket,
                &to_stack,
                routes.as_ref(),
                &peers,
                Some(index),
                ipv6_socket,
                &mut sends,
                Some(&recycle),
            );
        }
        for index in 0..peers.len() {
            peers[index].tunnel.poll(now, &mut events);
            flush(
                &mut events,
                &socket,
                &to_stack,
                routes.as_ref(),
                &peers,
                Some(index),
                ipv6_socket,
                &mut sends,
                Some(&recycle),
            );
        }

        #[cfg(target_os = "linux")]
        {
            let mut first = true;
            let mut received = 0;
            loop {
                match receive_batch.recv(&socket, first) {
                    Ok(0) => break,
                    Ok(got) => {
                        first = false;
                        for at in 0..got {
                            if receive_batch.truncated(at) {
                                continue;
                            }
                            if let Some(source) = receive_batch.source(at) {
                                let source = recv_endpoint(source, ipv6_socket);
                                let Some(packet) = receive_batch.take(at) else {
                                    let packet = receive_batch.packet(at);
                                    if packet.len() >= 4 {
                                        receive_datagram(
                                            &mut peers,
                                            &mut cookies,
                                            now,
                                            source,
                                            packet,
                                            &socket,
                                            &to_stack,
                                            &mut incoming,
                                            routes.as_ref(),
                                            ipv6_socket,
                                            &mut sends,
                                        );
                                    }
                                    continue;
                                };
                                if let Some(back) = receive_datagram_owned(
                                    &mut peers,
                                    &mut cookies,
                                    now,
                                    source,
                                    packet,
                                    &socket,
                                    &to_stack,
                                    &mut incoming,
                                    routes.as_ref(),
                                    ipv6_socket,
                                    &mut sends,
                                    Some(&recycle),
                                ) {
                                    receive_batch.put_back(back);
                                }
                            }
                        }
                        received += got;
                        if got < RX_BATCH || received >= RX_BURST {
                            break;
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::Interrupted
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionRefused
                        ) =>
                    {
                        break;
                    }
                    Err(_) => return,
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let mut received = 0;
            let mut nonblocking = false;
            loop {
                match socket.recv_from(&mut buf) {
                    Ok((n, source)) if n >= 4 => {
                        let source = recv_endpoint(source, ipv6_socket);
                        receive_datagram(
                            &mut peers,
                            &mut cookies,
                            now,
                            source,
                            &mut buf[..n],
                            &socket,
                            &to_stack,
                            &mut incoming,
                            routes.as_ref(),
                            ipv6_socket,
                            &mut sends,
                        );
                        received += 1;
                        if received >= RX_BURST {
                            break;
                        }
                        if !nonblocking {
                            if socket.set_nonblocking(true).is_err() {
                                break;
                            }
                            nonblocking = true;
                        }
                    }
                    Ok(_) => break,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::Interrupted
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionRefused
                        ) =>
                    {
                        break;
                    }
                    Err(_) => {
                        if nonblocking {
                            let _ = socket.set_nonblocking(false);
                        }
                        return;
                    }
                }
            }
            if nonblocking {
                let _ = socket.set_nonblocking(false);
            }
        }
    }
}

/// Read one datagram's message kind without slicing past a short packet.
#[allow(clippy::too_many_arguments)]
fn receive_datagram(
    peers: &mut Peers,
    cookies: &mut CookieGuard,
    now: u64,
    source: SocketAddr,
    packet: &mut [u8],
    socket: &UdpSocket,
    to_stack: &Sender<Packet>,
    incoming: &mut Vec<Event>,
    routes: Option<&UdpRoutes>,
    ipv6_socket: bool,
    sends: &mut Vec<Vec<u8>>,
) {
    let Some(&first) = packet.first() else {
        return;
    };
    let kind = u32::from(first);
    if kind == TYPE_INITIATION {
        if packet.len() != INITIATION_SIZE {
            return;
        }
        let under_load = cookies.observe(now);
        clear_reserved(packet);
        handle_initiation(
            peers, now, source, &*packet, socket, to_stack, cookies, under_load, sends,
        );
        return;
    }
    let at = if kind == TYPE_RESPONSE { 8 } else { 4 };
    let Some(receiver) = packet
        .get(at..at + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
    else {
        return;
    };
    let Some(index) = peers.iter().position(|peer| peer.tunnel.owns(receiver)) else {
        return;
    };
    peers[index].tunnel.receive(now, source, packet, incoming);
    flush(
        incoming,
        socket,
        to_stack,
        routes,
        peers,
        Some(index),
        ipv6_socket,
        sends,
        None,
    );
}

/// The owned counterpart of [`receive_datagram`]: a transport record keeps the
/// buffer it was read into, and anything that does not authenticate comes back
/// for the batch to reuse.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn receive_datagram_owned(
    peers: &mut Peers,
    cookies: &mut CookieGuard,
    now: u64,
    source: SocketAddr,
    mut packet: Vec<u8>,
    socket: &UdpSocket,
    to_stack: &Sender<Packet>,
    incoming: &mut Vec<Event>,
    routes: Option<&UdpRoutes>,
    ipv6_socket: bool,
    sends: &mut Vec<Vec<u8>>,
    recycle: Option<&Sender<Vec<u8>>>,
) -> Option<Vec<u8>> {
    let Some(&first) = packet.first() else {
        return Some(packet);
    };
    let kind = u32::from(first);
    if kind == TYPE_INITIATION {
        if packet.len() != INITIATION_SIZE {
            return Some(packet);
        }
        let under_load = cookies.observe(now);
        clear_reserved(&mut packet);
        handle_initiation(
            peers, now, source, &packet, socket, to_stack, cookies, under_load, sends,
        );
        return Some(packet);
    }
    let at = if kind == TYPE_RESPONSE { 8 } else { 4 };
    let Some(receiver) = packet
        .get(at..at + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
    else {
        return Some(packet);
    };
    let Some(index) = peers.iter().position(|peer| peer.tunnel.owns(receiver)) else {
        return Some(packet);
    };
    let packet = peers[index]
        .tunnel
        .receive_owned(now, source, packet, incoming);
    flush(
        incoming,
        socket,
        to_stack,
        routes,
        peers,
        Some(index),
        ipv6_socket,
        sends,
        recycle,
    );
    packet
}

/// The most tunnel packets one socket turn forwards before it reads again, so
/// a backlog on the stack's channel cannot leave a burst wider than a peer's
/// receive queue.
const RX_BURST: usize = 256;
const TX_DRAIN: usize = 128;

#[cfg(target_os = "linux")]
const RX_BATCH: usize = 64;

/// Read a batch of tunnel datagrams in one `recvmmsg`, so a fast lane is paced
/// by the wire rather than by one syscall for every record.
#[cfg(target_os = "linux")]
struct ReceiveBatch {
    slots: Vec<Vec<u8>>,
    iovecs: Vec<libc::iovec>,
    headers: Vec<libc::mmsghdr>,
    names: Vec<libc::sockaddr_storage>,
    slot: usize,
    extra: usize,
    spare: Vec<Vec<u8>>,
    recycled: Receiver<Vec<u8>>,
}

#[cfg(target_os = "linux")]
impl ReceiveBatch {
    /// Size one slot for this MTU and one receive queue for the stack.
    fn new(mtu: usize, recycled: Receiver<Vec<u8>>) -> Self {
        let slot = mtu
            .saturating_add(WG_HEADER_SIZE + WG_TAG_SIZE)
            .max(INITIATION_SIZE);
        Self {
            slots: (0..RX_BATCH).map(|_| vec![0u8; slot]).collect(),
            iovecs: (0..RX_BATCH)
                .map(|_| libc::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0,
                })
                .collect(),
            headers: (0..RX_BATCH)
                .map(|_| libc::mmsghdr {
                    msg_hdr: libc::msghdr {
                        msg_name: std::ptr::null_mut(),
                        msg_namelen: 0,
                        msg_iov: std::ptr::null_mut(),
                        msg_iovlen: 0,
                        msg_control: std::ptr::null_mut(),
                        msg_controllen: 0,
                        msg_flags: 0,
                    },
                    msg_len: 0,
                })
                .collect(),
            names: (0..RX_BATCH)
                .map(|_| unsafe { std::mem::zeroed() })
                .collect(),
            slot,
            extra: 0,
            spare: Vec::new(),
            recycled,
        }
    }

    /// Fill every free slot from the socket in one `recvmmsg`.
    fn recv(&mut self, socket: &UdpSocket, first: bool) -> std::io::Result<usize> {
        use std::os::fd::AsRawFd as _;

        let room = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        for at in 0..RX_BATCH {
            let slot = &mut self.slots[at];
            if slot.capacity() < self.slot {
                *slot = vec![0u8; self.slot];
            }
            self.iovecs[at] = libc::iovec {
                iov_base: slot.as_mut_ptr().cast(),
                iov_len: self.slot,
            };
            self.headers[at].msg_hdr = libc::msghdr {
                msg_name: (&raw mut self.names[at]).cast(),
                msg_namelen: room,
                msg_iov: (&raw mut self.iovecs[at]).cast(),
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            };
            self.headers[at].msg_len = 0;
        }
        let mut flags = libc::MSG_WAITFORONE as libc::c_int;
        if !first {
            flags |= libc::MSG_DONTWAIT;
        }
        // SAFETY: every header names a slot, an iovec and a name in `self`, all of which outlive the call, and the kernel writes each slot only as far as the datagram it read.
        let got = unsafe {
            libc::recvmmsg(
                socket.as_raw_fd(),
                self.headers.as_mut_ptr(),
                RX_BATCH as libc::c_uint,
                flags,
                std::ptr::null_mut(),
            )
        };
        if got < 0 {
            return Err(std::io::Error::last_os_error());
        }
        usize::try_from(got).map_err(|_| std::io::Error::other("recvmmsg count"))
    }

    /// Whether the kernel cut this datagram at the slot boundary.
    fn truncated(&self, at: usize) -> bool {
        self.headers[at].msg_hdr.msg_flags & libc::MSG_TRUNC != 0
    }

    /// The bytes a slot received, bounded by what the kernel wrote.
    fn packet(&mut self, at: usize) -> &mut [u8] {
        let len = usize::try_from(self.headers[at].msg_len)
            .unwrap_or(0)
            .min(self.slots[at].len());
        &mut self.slots[at][..len]
    }

    /// Hand out one received slot and leave a replacement for the next read.
    fn take(&mut self, at: usize) -> Option<Vec<u8>> {
        self.drain_recycled();
        let replacement = if let Some(buffer) = self.spare.pop() {
            buffer
        } else if self.extra < RX_BATCH {
            self.extra += 1;
            vec![0u8; self.slot]
        } else {
            return None;
        };
        let len = usize::try_from(self.headers[at].msg_len)
            .unwrap_or(0)
            .min(self.slot);
        let mut packet = std::mem::replace(&mut self.slots[at], replacement);
        packet.truncate(len);
        Some(packet)
    }

    /// Keep a returned slot only when it still fits the configured MTU.
    fn put_back(&mut self, mut buffer: Vec<u8>) {
        if buffer.capacity() < self.slot || self.spare.len() >= RX_BATCH {
            return;
        }
        if buffer.len() < self.slot {
            buffer.resize(self.slot, 0);
        } else if buffer.len() > self.slot {
            buffer.truncate(self.slot);
        }
        buffer.shrink_to(self.slot);
        self.spare.push(buffer);
    }

    /// Move slots the stack returned into the batch spare list.
    fn drain_recycled(&mut self) {
        while let Ok(buffer) = self.recycled.try_recv() {
            self.put_back(buffer);
        }
    }

    /// The sender address the kernel wrote for this slot.
    fn source(&self, at: usize) -> Option<SocketAddr> {
        crate::proxy::socket_addr_of(&self.names[at], self.headers[at].msg_hdr.msg_namelen)
    }
}

/// Validate an initiation, apply the cookie gate, and answer with a response.
#[allow(clippy::too_many_arguments)]
fn handle_initiation(
    peers: &mut Peers,
    now: u64,
    source: SocketAddr,
    packet: &[u8],
    socket: &UdpSocket,
    to_stack: &Sender<Packet>,
    cookies: &mut CookieGuard,
    under_load: bool,
    sends: &mut Vec<Vec<u8>>,
) {
    let Some(peer) = peers.first() else {
        return;
    };
    if !check_mac1(packet, &peer.tunnel.public()) {
        return;
    }
    if under_load {
        let (source_bytes, source_width) = endpoint_bytes(source);
        let source_bytes = &source_bytes[..source_width];
        if !cookies.check(now, packet, source_bytes) {
            if let Some(reply) = cookies.reply(
                now,
                packet,
                source_bytes,
                &cookie_encryption_key(&peer.tunnel.public()),
            ) {
                let ipv6 = socket.local_addr().is_ok_and(|address| address.is_ipv6());
                let _ = socket.send_to(&reply, send_endpoint(source, ipv6));
            }
            return;
        }
    }
    let Some(state) = peers.first().and_then(|peer| {
        let message: &[u8; INITIATION_SIZE] = packet.try_into().ok()?;
        peer.tunnel.consume(message)
    }) else {
        return;
    };
    let remote = state.remote_static();
    let Some(index) = peers.iter().position(|peer| peer.config.public == remote) else {
        return;
    };
    let mut events = Vec::new();
    peers[index].tunnel.answer(now, source, state, &mut events);
    let ipv6 = socket.local_addr().is_ok_and(|address| address.is_ipv6());
    flush(
        &mut events,
        socket,
        to_stack,
        None,
        peers,
        Some(index),
        ipv6,
        sends,
        None,
    );
}

/// Send every event, and for each decrypted payload require the authenticating
/// peer to own the source by longest allowed prefix before the upper layer sees
/// it.
#[allow(clippy::too_many_arguments)]
fn flush(
    events: &mut Vec<Event>,
    socket: &UdpSocket,
    to_stack: &Sender<Packet>,
    routes: Option<&UdpRoutes>,
    peers: &Peers,
    peer: Option<usize>,
    ipv6_socket: bool,
    sends: &mut Vec<Vec<u8>>,
    recycle: Option<&Sender<Vec<u8>>>,
) {
    let candidates = peer.map(|index| peers[index].config.endpoints.as_slice());
    let mut endpoint = None;
    for event in events.drain(..) {
        match event {
            Event::Send {
                endpoint: to,
                packet,
            } => {
                if is_initiation(&packet) {
                    flush_sends(socket, ipv6_socket, endpoint, sends);
                    endpoint = None;
                    send_packet(socket, ipv6_socket, to, &packet, candidates);
                } else if ipv6_socket || to.is_ipv4() {
                    if endpoint != Some(to) {
                        flush_sends(socket, ipv6_socket, endpoint, sends);
                        endpoint = Some(to);
                    }
                    sends.push(packet);
                    if sends.len() == SEND_BATCH {
                        flush_sends(socket, ipv6_socket, endpoint, sends);
                    }
                }
            }
            Event::Data(inner) => {
                flush_sends(socket, ipv6_socket, endpoint, sends);
                endpoint = None;
                deliver_data(inner, 0, peers, peer, routes, to_stack, recycle);
            }
            Event::DataPrefixed(inner) => {
                flush_sends(socket, ipv6_socket, endpoint, sends);
                endpoint = None;
                deliver_data(
                    inner,
                    WG_HEADER_SIZE,
                    peers,
                    peer,
                    routes,
                    to_stack,
                    recycle,
                );
            }
        }
    }
    flush_sends(socket, ipv6_socket, endpoint, sends);
}

/// Hand one decrypted packet to its UDP lane or the stack, with `at` naming the
/// first payload byte when the receive buffer kept its transport header.
fn deliver_data(
    inner: Vec<u8>,
    at: usize,
    peers: &Peers,
    peer: Option<usize>,
    routes: Option<&UdpRoutes>,
    to_stack: &Sender<Packet>,
    recycle: Option<&Sender<Vec<u8>>>,
) {
    let Some(index) = peer else {
        recycle_slot(inner, at, recycle);
        return;
    };
    let Some(source) = wg_stack::inner_addresses(&inner[at..]).map(|(source, _)| source) else {
        recycle_slot(inner, at, recycle);
        return;
    };
    if peers.peer_for(source) != Some(index) {
        recycle_slot(inner, at, recycle);
        return;
    }
    if let Some(routes) = routes {
        if !wg_stack::ipv4_fragment(&inner[at..]) {
            if let Some(port) = ferrox_core::foxy::connectip::udp_from_packet(&inner[at..])
                .map(|datagram| datagram.destination_port)
            {
                if let Ok(table) = routes.lock() {
                    if let Some(lane) = table.get(&port) {
                        let payload = if at == 0 {
                            inner
                        } else {
                            let payload = inner[at..].to_vec();
                            recycle_slot(inner, at, recycle);
                            payload
                        };
                        let _ = lane.send(payload);
                        return;
                    }
                }
                recycle_slot(inner, at, recycle);
                return;
            }
        }
    }
    let _ = to_stack.send(Packet {
        peer: peers[index].config.public,
        bytes: inner,
        at,
    });
}

/// Return a prefixed receive buffer after a copy, or drop a payload-only one.
fn recycle_slot(inner: Vec<u8>, at: usize, recycle: Option<&Sender<Vec<u8>>>) {
    if let Some(recycle) = recycle.filter(|_| at != 0) {
        let _ = recycle.send(inner);
    }
}

/// The most transport packets one socket batch carries. A batch that cannot be
/// taken whole falls back to the socket for the rest, so a full queue still
/// names every packet.
const SEND_BATCH: usize = 64;

fn flush_sends(
    socket: &UdpSocket,
    ipv6: bool,
    endpoint: Option<SocketAddr>,
    sends: &mut Vec<Vec<u8>>,
) {
    if sends.is_empty() {
        return;
    }
    let Some(endpoint) = endpoint else {
        sends.clear();
        return;
    };
    if ipv6 || endpoint.is_ipv4() {
        send_batch(socket, ipv6, endpoint, sends);
    }
    sends.clear();
}

#[cfg(target_os = "linux")]
/// `UDP_SEGMENT` coalescing, off on aarch64: the arm pool's reference client
/// collapses to 72 MiB/s on the coalesced super-packet (0.40 leg, 41894636989)
/// where the `sendmmsg` path holds 189 (1.10, 41899990310).
static GSO_SUPPORTED: AtomicBool = AtomicBool::new(!cfg!(target_arch = "aarch64"));

/// Send one endpoint's transport records, coalescing equal-sized runs where the
/// kernel accepts `UDP_SEGMENT` and batching the rest with `sendmmsg`.
#[cfg(target_os = "linux")]
fn send_batch(socket: &UdpSocket, ipv6: bool, endpoint: SocketAddr, packets: &[Vec<u8>]) {
    debug_assert!(packets.len() <= SEND_BATCH);
    let to = send_endpoint(endpoint, ipv6);
    let (storage, name_len) = crate::proxy::sockaddr_of(to);
    let max_payload = if ipv6 { 65_527 } else { 65_507 };
    let mut iovecs: [libc::iovec; SEND_BATCH] = std::array::from_fn(|_| libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    });
    // SAFETY: a zeroed `mmsghdr` is the empty header the loop fills below.
    let mut headers: [libc::mmsghdr; SEND_BATCH] =
        std::array::from_fn(|_| unsafe { std::mem::zeroed() });
    let mut start = 0;
    while start < packets.len() {
        let gso = packets[start].len();
        let mut end = start + 1;
        let mut total = gso;
        let mut shorter = false;
        while end < packets.len() && !shorter {
            let len = packets[end].len();
            if len > gso || total + len > max_payload {
                break;
            }
            total += len;
            end += 1;
            shorter = len < gso;
        }
        if end - start > 1 && gso <= 65_535 && GSO_SUPPORTED.load(Ordering::Relaxed) {
            for (at, packet) in packets[start..end].iter().enumerate() {
                iovecs[at] = libc::iovec {
                    iov_base: packet.as_ptr().cast_mut().cast(),
                    iov_len: packet.len(),
                };
            }
            match send_segments(
                socket,
                &storage,
                name_len,
                &mut iovecs[..end - start],
                gso as u16,
            ) {
                Ok(sent) if sent >= total => {
                    start = end;
                    continue;
                }
                Ok(sent) if sent >= gso => {
                    start += sent / gso;
                    continue;
                }
                Ok(_) => {}
                Err(error) => {
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::EINVAL | libc::EIO | libc::ENOPROTOOPT | libc::EOPNOTSUPP)
                    ) {
                        GSO_SUPPORTED.store(false, Ordering::Relaxed);
                    }
                }
            }
        }
        send_messages(
            socket,
            &storage,
            name_len,
            to,
            &packets[start..end],
            &mut iovecs,
            &mut headers,
        );
        start = end;
    }
}

/// Hand every record to one endpoint with `sendmmsg`, then `send_to` for what
/// the call could not take.
#[cfg(target_os = "linux")]
fn send_messages(
    socket: &UdpSocket,
    storage: &libc::sockaddr_storage,
    name_len: libc::socklen_t,
    to: SocketAddr,
    packets: &[Vec<u8>],
    iovecs: &mut [libc::iovec; SEND_BATCH],
    headers: &mut [libc::mmsghdr; SEND_BATCH],
) {
    use std::os::fd::AsRawFd as _;

    for (at, packet) in packets.iter().enumerate() {
        iovecs[at] = libc::iovec {
            iov_base: packet.as_ptr().cast_mut().cast(),
            iov_len: packet.len(),
        };
        headers[at].msg_hdr = libc::msghdr {
            msg_name: (&raw const *storage).cast_mut().cast(),
            msg_namelen: name_len,
            msg_iov: (&raw mut iovecs[at]).cast(),
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
    }
    let mut done = 0;
    while done < packets.len() {
        // SAFETY: each header names its own iovec and packet, and `storage` outlives the call.
        let sent = unsafe {
            libc::sendmmsg(
                socket.as_raw_fd(),
                headers[done..].as_mut_ptr(),
                (packets.len() - done) as libc::c_uint,
                0,
            )
        };
        if sent <= 0 {
            break;
        }
        done += usize::try_from(sent).unwrap_or(0);
    }
    for packet in &packets[done..] {
        let _ = socket.send_to(packet, to);
    }
}

/// Send concatenated records as one `UDP_SEGMENT` payload, so the kernel splits
/// them into the datagrams the peer expects.
#[cfg(target_os = "linux")]
fn send_segments(
    socket: &UdpSocket,
    storage: &libc::sockaddr_storage,
    name_len: libc::socklen_t,
    iovecs: &mut [libc::iovec],
    gso: u16,
) -> std::io::Result<usize> {
    use std::os::fd::AsRawFd as _;

    const UDP_SEGMENT: libc::c_int = 103;
    #[repr(align(8))]
    struct Control([u8; 32]);
    let space = unsafe { libc::CMSG_SPACE(2) } as usize;
    let mut control = Control([0u8; 32]);
    if space > control.0.len() {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    // SAFETY: `control` is aligned and large enough for one two-byte control message, which the calls below fill before the header names it.
    unsafe {
        let header = control.0.as_mut_ptr().cast::<libc::cmsghdr>();
        (*header).cmsg_level = libc::IPPROTO_UDP;
        (*header).cmsg_type = UDP_SEGMENT;
        (*header).cmsg_len = libc::CMSG_LEN(2) as _;
        std::ptr::copy_nonoverlapping(gso.to_ne_bytes().as_ptr(), libc::CMSG_DATA(header), 2);
    }
    let message = libc::msghdr {
        msg_name: (&raw const *storage).cast_mut().cast(),
        msg_namelen: name_len,
        msg_iov: iovecs.as_mut_ptr(),
        msg_iovlen: iovecs.len(),
        msg_control: control.0.as_mut_ptr().cast(),
        msg_controllen: space as _,
        msg_flags: 0,
    };
    // SAFETY: the name, iovecs and control all outlive the call, and the kernel only reads them.
    let sent = unsafe { libc::sendmsg(socket.as_raw_fd(), &raw const message, 0) };
    if sent < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(sent as usize)
}

#[cfg(not(target_os = "linux"))]
fn send_batch(socket: &UdpSocket, ipv6: bool, endpoint: SocketAddr, packets: &[Vec<u8>]) {
    let to = send_endpoint(endpoint, ipv6);
    for packet in packets {
        let _ = socket.send_to(packet, to);
    }
}

fn tai64n_now() -> [u8; 12] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    tai64n(now.as_secs(), now.subsec_nanos())
}

fn peers(config: &DeviceConfig, epoch: [u8; 12]) -> Peers {
    Peers::new(
        config
            .peers
            .iter()
            .map(|peer| Peer {
                config: peer.clone(),
                tunnel: Tunnel::new(
                    config.secret,
                    peer.public,
                    peer.preshared,
                    peer.endpoint.unwrap_or_else(|| {
                        let address = config
                            .addresses
                            .iter()
                            .find(|address| address.is_ipv4())
                            .or_else(|| config.addresses.first())
                            .copied()
                            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                        SocketAddr::new(address, 0)
                    }),
                    peer.keepalive,
                    config.reserved,
                    epoch,
                ),
            })
            .collect(),
    )
}

const ROUTE_V4_LINEAR: usize = 32;
const ROUTE_V6_LINEAR: usize = 128;
const NO_PEER: u32 = u32::MAX;

struct RouteNode {
    child: [u32; 2],
    peer: u32,
}

impl RouteNode {
    fn new() -> Self {
        Self {
            child: [NO_PEER; 2],
            peer: NO_PEER,
        }
    }
}

struct Routes {
    v4: Option<Vec<RouteNode>>,
    v6: Option<Vec<RouteNode>>,
}

impl Routes {
    fn new<A: Allowed>(peers: &[A]) -> Self {
        let mut prefixes = 0usize;
        let mut valid = true;
        let mut v4_prefixes = 0usize;
        let mut v6_prefixes = 0usize;
        for peer in peers {
            prefixes += peer.allowed().len();
            for (address, bits) in peer.allowed() {
                match address {
                    IpAddr::V4(_) if *bits <= 32 => v4_prefixes += 1,
                    IpAddr::V6(_) if *bits <= 128 => v6_prefixes += 1,
                    _ => valid = false,
                }
            }
        }
        if !valid {
            return Self { v4: None, v6: None };
        }
        let mut v4 = (v4_prefixes > 0 && prefixes > ROUTE_V4_LINEAR).then(|| {
            let mut nodes = Vec::with_capacity(v4_prefixes + 1);
            nodes.push(RouteNode::new());
            nodes
        });
        let mut v6 = (v6_prefixes > 0 && prefixes > ROUTE_V6_LINEAR).then(|| {
            let mut nodes = Vec::with_capacity(v6_prefixes + 1);
            nodes.push(RouteNode::new());
            nodes
        });
        for (index, peer) in peers.iter().enumerate() {
            for (address, bits) in peer.allowed() {
                match address {
                    IpAddr::V4(address) => {
                        if let Some(nodes) = v4.as_mut() {
                            insert_route(
                                nodes,
                                u128::from(u32::from_be_bytes(address.octets())),
                                usize::from(*bits),
                                32,
                                index,
                            );
                        }
                    }
                    IpAddr::V6(address) => {
                        if let Some(nodes) = v6.as_mut() {
                            insert_route(
                                nodes,
                                u128::from_be_bytes(address.octets()),
                                usize::from(*bits),
                                128,
                                index,
                            );
                        }
                    }
                }
            }
        }
        Self { v4, v6 }
    }

    fn peer_for<A: Allowed>(&self, peers: &[A], destination: IpAddr) -> Option<usize> {
        match destination {
            IpAddr::V4(address) => {
                let Some(nodes) = &self.v4 else {
                    return peer_for_scan(peers, destination);
                };
                lookup_route(nodes, u128::from(u32::from_be_bytes(address.octets())), 32)
            }
            IpAddr::V6(address) => {
                let Some(nodes) = &self.v6 else {
                    return peer_for_scan(peers, destination);
                };
                lookup_route(nodes, u128::from_be_bytes(address.octets()), 128)
            }
        }
    }
}

fn insert_route(nodes: &mut Vec<RouteNode>, value: u128, bits: usize, width: usize, peer: usize) {
    debug_assert!(peer < NO_PEER as usize);
    let mut at = 0usize;
    for depth in 0..bits {
        let bit = ((value >> (width - 1 - depth)) & 1) as usize;
        let next = nodes[at].child[bit];
        at = if next == NO_PEER {
            nodes.push(RouteNode::new());
            let next = nodes.len() - 1;
            nodes[at].child[bit] = next as u32;
            next
        } else {
            next as usize
        };
    }
    nodes[at].peer = peer as u32;
}

fn lookup_route(nodes: &[RouteNode], value: u128, width: usize) -> Option<usize> {
    let root = nodes.first()?;
    let mut at = 0usize;
    let mut found = (root.peer != NO_PEER).then_some(root.peer as usize);
    for depth in 0..width {
        let bit = ((value >> (width - 1 - depth)) & 1) as usize;
        let next = nodes[at].child[bit];
        if next == NO_PEER {
            break;
        }
        at = next as usize;
        if nodes[at].peer != NO_PEER {
            found = Some(nodes[at].peer as usize);
        }
    }
    found
}

fn peer_for_scan<A: Allowed>(peers: &[A], destination: IpAddr) -> Option<usize> {
    peers
        .iter()
        .enumerate()
        .filter_map(|(index, peer)| peer.longest_prefix(destination).map(|bits| (index, bits)))
        .max_by_key(|(_, bits)| *bits)
        .map(|(index, _)| index)
}

fn bind_socket(config: &DeviceConfig) -> Result<UdpSocket, String> {
    let mut v4 = false;
    let mut v6 = false;
    let mut any = false;
    for peer in &config.peers {
        for endpoint in peer.endpoints.iter().copied().chain(peer.endpoint) {
            any = true;
            if endpoint.is_ipv4() {
                v4 = true;
            } else {
                v6 = true;
            }
        }
    }
    if !any {
        return Err("wireguard client: no peer has an `endpoint`".to_owned());
    }
    if v4 && v6 {
        match bind_dual_stack() {
            Ok(socket) => return Ok(socket),
            Err(dual) if v4 => {
                let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
                return UdpSocket::bind(address).map_err(|ipv4| {
                    format!("cannot bind wireguard's UDP socket: dual-stack: {dual}; IPv4: {ipv4}")
                });
            }
            Err(error) => return Err(error),
        }
    }
    let unspecified = if v4 {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    UdpSocket::bind(unspecified)
        .map_err(|error| format!("cannot bind wireguard's UDP socket: {error}"))
}

fn bind_dual_stack() -> Result<UdpSocket, String> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|error| format!("cannot create wireguard's dual-stack socket: {error}"))?;
    socket
        .set_only_v6(false)
        .map_err(|error| format!("cannot enable wireguard's dual-stack socket: {error}"))?;
    let address = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
    socket
        .bind(&address.into())
        .map_err(|error| format!("cannot bind wireguard's dual-stack socket: {error}"))?;
    Ok(socket.into())
}

/// Ask the kernel for the queue the reference gives its `WireGuard` socket. It
/// may cap the request at `net.core.*mem_max`; the default is the smaller
/// number, and a larger ask never costs the flow anything.
fn widen(socket: &UdpSocket) {
    let sock = socket2::SockRef::from(socket);
    let _ = sock.set_recv_buffer_size(SOCKET_BUFFER);
    let _ = sock.set_send_buffer_size(SOCKET_BUFFER);
}

/// Send a handshake to every configured endpoint candidate, so a name that
/// resolves to two families or two hosts is raced; data follows the endpoint
/// the responder pinned.
fn is_initiation(packet: &[u8]) -> bool {
    packet.len() == INITIATION_SIZE
        && u32::from_le_bytes(packet[..4].try_into().unwrap_or([0; 4])) == TYPE_INITIATION
}

fn send_packet(
    socket: &UdpSocket,
    ipv6: bool,
    endpoint: SocketAddr,
    packet: &[u8],
    candidates: Option<&[SocketAddr]>,
) {
    if is_initiation(packet) {
        if ipv6 || endpoint.is_ipv4() {
            let _ = socket.send_to(packet, send_endpoint(endpoint, ipv6));
        }
        for target in candidates.unwrap_or_default() {
            if *target == endpoint || (!ipv6 && target.is_ipv6()) {
                continue;
            }
            let _ = socket.send_to(packet, send_endpoint(*target, ipv6));
        }
        return;
    }
    if ipv6 || endpoint.is_ipv4() {
        let _ = socket.send_to(packet, send_endpoint(endpoint, ipv6));
    }
}

fn send_endpoint(endpoint: SocketAddr, ipv6: bool) -> SocketAddr {
    match endpoint {
        SocketAddr::V4(address) if ipv6 => SocketAddr::new(
            IpAddr::V6(Ipv4Addr::to_ipv6_mapped(address.ip())),
            address.port(),
        ),
        _ => endpoint,
    }
}

/// Normalize a received endpoint to the tunnel's address family.
fn recv_endpoint(socket: SocketAddr, ipv6: bool) -> SocketAddr {
    match socket {
        SocketAddr::V6(address) if ipv6 => match address.ip().to_ipv4_mapped() {
            Some(ip) => SocketAddr::new(IpAddr::V4(ip), address.port()),
            None => SocketAddr::V6(address),
        },
        _ => socket,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    /// The first packet a handshake or data path queued for sending.
    fn sent(events: &[Event]) -> Vec<u8> {
        events
            .iter()
            .find_map(|event| match event {
                Event::Send { packet, .. } => Some(packet.clone()),
                Event::Data(_) | Event::DataPrefixed(_) => None,
            })
            .expect("an outbound packet")
    }

    fn routed_configs(count: u16) -> Vec<PeerConfig> {
        let mut peers = Vec::with_capacity(usize::from(count));
        for index in 0..count {
            let v4 = Ipv4Addr::new(10, (index >> 8) as u8, index as u8, 1);
            let v6 =
                Ipv6Addr::from(0xfd00_0000_0000_0000_0000_0000_0000_0000u128 | u128::from(index));
            peers.push(PeerConfig {
                public: [index as u8; 32],
                preshared: [0; 32],
                endpoint: None,
                endpoints: Vec::new(),
                keepalive: 0,
                allowed: vec![
                    ("10.0.0.0".parse().unwrap(), 8),
                    (IpAddr::V4(v4), 32),
                    ("fd00::".parse().unwrap(), 8),
                    (IpAddr::V6(v6), 128),
                ],
            });
        }
        peers
    }

    #[inline(never)]
    fn route_scan_once(peers: &[PeerConfig], destination: IpAddr) -> Option<usize> {
        peer_for_scan(peers, destination)
    }

    #[inline(never)]
    fn route_table_once(
        peers: &[PeerConfig],
        routes: &Routes,
        destination: IpAddr,
    ) -> Option<usize> {
        routes.peer_for(peers, destination)
    }

    #[test]
    fn a_probe_waits_no_longer_than_the_deadline_or_the_poll() {
        assert_eq!(poll_wait(Duration::ZERO), None);
        assert_eq!(poll_wait(Duration::from_secs(30)), Some(VERIFY_POLL));
        assert_eq!(
            poll_wait(Duration::from_millis(40)),
            Some(Duration::from_millis(40))
        );
    }

    /// The prefix table answers every lookup the peer scan answered, including
    /// the last peer on a tie and the deepest prefix on an overlap.
    #[test]
    fn a_prefix_table_picks_the_peer_the_scan_picks() {
        let peers = routed_configs(512);
        let routes = Routes::new(&peers);
        assert!(
            routes.v4.is_some() && routes.v6.is_some(),
            "both tables are the path under test"
        );
        for destination in [
            "10.0.1.1",
            "10.9.9.9",
            "192.0.2.1",
            "fd00::101",
            "fd00::ffff",
            "2001:db8::1",
        ] {
            let destination: IpAddr = destination.parse().unwrap();
            assert_eq!(
                routes.peer_for(&peers, destination),
                peer_for_scan(&peers, destination)
            );
        }
        let destination = "10.0.1.1".parse().unwrap();
        assert_eq!(
            route_scan_once(&peers, destination),
            route_table_once(&peers, &routes, destination)
        );
    }

    /// A peer cannot claim another peer's source address as its own.
    #[test]
    fn a_peer_may_not_originate_another_peers_source() {
        let config = DeviceConfig {
            secret: [0x11; 32],
            addresses: vec!["10.0.0.1".parse().unwrap()],
            peers: vec![
                PeerConfig {
                    public: [0x22; 32],
                    preshared: [0; 32],
                    endpoint: None,
                    endpoints: Vec::new(),
                    keepalive: 0,
                    allowed: vec![("10.0.0.2".parse().unwrap(), 32)],
                },
                PeerConfig {
                    public: [0x33; 32],
                    preshared: [0; 32],
                    endpoint: None,
                    endpoints: Vec::new(),
                    keepalive: 0,
                    allowed: vec![("10.0.0.0".parse().unwrap(), 8)],
                },
            ],
            mtu: 1420,
            reserved: [0; 3],
            is_client: Some(false),
            no_kernel_tun: true,
            large_segments: false,
            dns: Vec::new(),
        };
        let peers = peers(&config, [0; 12]);
        let socket = UdpSocket::bind("127.0.0.1:0").expect("socket");
        let (to_stack, packets) = mpsc::channel();
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        let mut events = vec![Event::Data(packet)];
        flush(
            &mut events,
            &socket,
            &to_stack,
            None,
            &peers,
            Some(1),
            false,
            &mut Vec::new(),
            None,
        );
        assert!(packets.try_recv().is_err(), "the owner is peer zero");
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[12..16].copy_from_slice(&[10, 1, 2, 3]);
        let mut events = vec![Event::Data(packet)];
        flush(
            &mut events,
            &socket,
            &to_stack,
            None,
            &peers,
            Some(1),
            false,
            &mut Vec::new(),
            None,
        );
        assert!(packets.try_recv().is_ok(), "the peer owns its own source");
    }

    /// One `recvmmsg` returns every queued datagram to the batch.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_batch_receives_every_datagram() {
        let receiver = UdpSocket::bind("127.0.0.1:0").expect("receiver");
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("sender");
        let packets: Vec<Vec<u8>> = (0..4).map(|i| vec![i; 32]).collect();
        let address = receiver.local_addr().expect("address");
        for packet in &packets {
            sender.send_to(packet, address).expect("datagram");
        }
        let (_recycle, recycled) = mpsc::channel();
        let mut batch = ReceiveBatch::new(1500, recycled);
        let got = batch.recv(&receiver, true).expect("batch");
        assert_eq!(got, packets.len(), "the batch reads all four");
        for (at, packet) in packets.iter().enumerate().take(got) {
            assert_eq!(batch.packet(at), packet.as_slice());
            assert_eq!(batch.source(at), Some(sender.local_addr().unwrap()));
        }
    }

    /// A record the kernel truncated is dropped, not authenticated as a short packet.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_truncated_record_is_not_handed_out() {
        let (_recycle, recycled) = mpsc::channel();
        let mut batch = ReceiveBatch::new(1500, recycled);
        batch.headers[0].msg_hdr.msg_flags = libc::MSG_TRUNC;
        assert!(batch.truncated(0));
        batch.headers[0].msg_hdr.msg_flags = 0;
        assert!(!batch.truncated(0));
    }

    /// A slot consumed through the recycle channel keeps its allocation and capacity.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_taken_slot_returns_to_the_batch() {
        let (recycle, recycled) = mpsc::channel();
        let mut batch = ReceiveBatch::new(1500, recycled);
        let first = batch.take(0).expect("a slot");
        let base = first.as_ptr();
        let capacity = first.capacity();
        recycle.send(first).expect("the slot comes back");
        let _ = batch.take(0).expect("a replacement");
        assert_eq!(batch.slots[0].as_ptr(), base);
        assert_eq!(batch.slots[0].capacity(), capacity);
    }

    /// A batch hands out only its base slots and one extra slot per base slot.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_batch_stops_taking_after_its_extra_budget() {
        let (_recycle, recycled) = mpsc::channel();
        let mut batch = ReceiveBatch::new(1500, recycled);
        for _ in 0..RX_BATCH {
            assert!(
                batch.take(0).is_some(),
                "the base and extra slots are handed out"
            );
        }
        assert!(batch.take(0).is_none(), "the extra budget is bounded");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_batch_sends_every_transport_packet_in_order() {
        let receiver = UdpSocket::bind("127.0.0.1:0").expect("receiver");
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("sender");
        let packets: Vec<Vec<u8>> = (0..4).map(|i| vec![i; 32]).collect();
        send_batch(
            &sender,
            false,
            receiver.local_addr().expect("address"),
            &packets,
        );
        let mut got = Vec::new();
        for _ in 0..packets.len() {
            let mut buf = [0u8; 64];
            let (n, _) = receiver.recv_from(&mut buf).expect("datagram");
            got.push(buf[..n].to_vec());
        }
        assert_eq!(got, packets);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_batch_keeps_each_packet_size_after_segmentation() {
        let receiver = UdpSocket::bind("127.0.0.1:0").expect("receiver");
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("sender");
        let packets: Vec<Vec<u8>> = [128usize, 128, 64, 256, 256, 32]
            .into_iter()
            .map(|len| vec![len as u8; len])
            .collect();
        send_batch(
            &sender,
            false,
            receiver.local_addr().expect("address"),
            &packets,
        );
        let mut got = Vec::new();
        for _ in 0..packets.len() {
            let mut buf = [0u8; 256];
            let (n, _) = receiver.recv_from(&mut buf).expect("datagram");
            got.push(buf[..n].to_vec());
        }
        assert_eq!(got, packets);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_sendmsg_fallback_keeps_every_transport_packet_in_order() {
        let receiver = UdpSocket::bind("127.0.0.1:0").expect("receiver");
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("sender");
        let to = receiver.local_addr().expect("address");
        let (storage, name_len) = crate::proxy::sockaddr_of(to);
        let packets: Vec<Vec<u8>> = (0..4).map(|i| vec![i; 32]).collect();
        let mut iovecs: [libc::iovec; SEND_BATCH] = std::array::from_fn(|_| libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        });
        // SAFETY: a zeroed `mmsghdr` is the empty header `send_messages` fills.
        let mut headers: [libc::mmsghdr; SEND_BATCH] =
            std::array::from_fn(|_| unsafe { std::mem::zeroed() });
        send_messages(
            &sender,
            &storage,
            name_len,
            to,
            &packets,
            &mut iovecs,
            &mut headers,
        );
        let mut got = Vec::new();
        for _ in 0..packets.len() {
            let mut buf = [0u8; 64];
            let (n, _) = receiver.recv_from(&mut buf).expect("datagram");
            got.push(buf[..n].to_vec());
        }
        assert_eq!(got, packets);
    }

    #[test]
    fn a_short_datagram_is_refused_before_any_slice() {
        let Ok(socket) = UdpSocket::bind("127.0.0.1:0") else {
            return;
        };
        let (to_stack, _stack) = mpsc::channel();
        let mut peers = Peers::new(Vec::new());
        let mut cookies = CookieGuard::default();
        let mut incoming = Vec::new();
        let mut sends = Vec::new();
        let source = socket.local_addr().expect("address");
        for (kind, len) in [
            (TYPE_RESPONSE, 4),
            (TYPE_RESPONSE, 7),
            (TYPE_RESPONSE, 11),
            (TYPE_INITIATION, 4),
            (TYPE_INITIATION, INITIATION_SIZE - 1),
        ] {
            let mut packet = vec![0u8; len];
            let bytes = kind.to_le_bytes();
            let copied = len.min(bytes.len());
            packet[..copied].copy_from_slice(&bytes[..copied]);
            receive_datagram(
                &mut peers,
                &mut cookies,
                0,
                source,
                &mut packet,
                &socket,
                &to_stack,
                &mut incoming,
                None,
                false,
                &mut sends,
            );
        }
    }

    #[test]
    fn a_tcp_flow_crosses_the_tunnel_to_a_freedom_dial() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo");
        let echo_address = echo.local_addr().expect("address");
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = echo.accept() else {
                return;
            };
            let mut buf = [0u8; 1024];
            let mut seen = 0;
            loop {
                let Ok(n) = stream.read(&mut buf) else {
                    return;
                };
                if n == 0 || stream.write_all(&buf[..n]).is_err() {
                    return;
                }
                seen += n;
                if seen >= 9 {
                    return;
                }
            }
        });

        let client_private = [0x11; 32];
        let server_private = [0x22; 32];
        let client_public = ferrox_core::wireguard::device::public_key(&client_private);
        let server_public = ferrox_core::wireguard::device::public_key(&server_private);
        let hex = ferrox_core::foxy::account::hex_encode;
        let server_settings = format!(
            r#"{{"secretKey":"{}","endpoint":["10.0.0.1"],"users":[{{"account":{{"publicKey":"{}","allowedIPs":["10.0.0.2/32"]}}}}]}}"#,
            hex(&server_private),
            hex(&client_public)
        );
        let inbound =
            crate::json::parse(&format!(r#"{{"settings":{server_settings}}}"#)).expect("inbound");
        let out = Outbound::Freedom(Arc::new(crate::proxy::FreedomOut::default()));
        let port = serve_inbound(&inbound, &out, "127.0.0.1:0").expect("serve");
        assert_ne!(port, 0);

        let client = DeviceConfig::from_json(
            &crate::json::parse(&format!(
                r#"{{"secretKey":"{}","address":["10.0.0.2"],"reserved":[1,2,3],"peers":[{{"publicKey":"{}","endpoint":"127.0.0.1:{port}"}}]}}"#,
                hex(&client_private),
                hex(&server_public)
            ))
            .expect("client config"),
        )
        .expect("device");
        let wireguard = WireGuardOut::new(client).expect("outbound");
        let listener = TcpListener::bind("127.0.0.1:0").expect("pair");
        let tun = std::net::TcpStream::connect(listener.local_addr().expect("pair address"))
            .expect("connect");
        let (mut app, _) = listener.accept().expect("accept");
        app.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        wireguard.serve_tcp(
            Connection::from(tun),
            &Destination::Address(echo_address),
            b"head",
        );
        app.write_all(b"hello").expect("write");
        let mut answer = [0u8; 9];
        app.read_exact(&mut answer).expect("read");
        assert_eq!(&answer, b"headhello");
        let mut eof = [0u8; 1];
        assert_eq!(app.read(&mut eof).expect("eof"), 0);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn a_name_races_every_routed_answer_before_the_flow() {
        let dns = UdpSocket::bind("127.0.0.1:0").expect("dns");
        let dns_address = dns.local_addr().expect("dns address");
        let (answered, answer) = mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            loop {
                let (n, from) = match dns.recv_from(&mut buf) {
                    Ok(received) => received,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::Interrupted
                                | std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionRefused
                        ) =>
                    {
                        continue;
                    }
                    Err(_) => return,
                };
                let Some(question) = ferrox_core::dns::parse_query(&buf[..n]) else {
                    continue;
                };
                let Some(reply) = ferrox_core::dns::ip_answer(
                    &question,
                    0,
                    60,
                    &[vec![192, 0, 2, 1], vec![127, 0, 0, 1]],
                ) else {
                    continue;
                };
                if dns.send_to(&reply, from).is_ok() {
                    let _ = answered.send(());
                }
            }
        });

        let echo = TcpListener::bind("127.0.0.1:0").expect("echo");
        let echo_address = echo.local_addr().expect("echo address");
        std::thread::spawn(move || {
            for _ in 0..2 {
                let Ok((mut stream, _)) = echo.accept() else {
                    return;
                };
                let mut buf = [0u8; 1024];
                let mut seen = 0;
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 || stream.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    seen += n;
                    if seen >= 9 {
                        break;
                    }
                }
            }
        });

        let client_private = [0x11; 32];
        let server_private = [0x22; 32];
        let client_public = ferrox_core::wireguard::device::public_key(&client_private);
        let server_public = ferrox_core::wireguard::device::public_key(&server_private);
        let hex = ferrox_core::foxy::account::hex_encode;
        let server_settings = format!(
            r#"{{"secretKey":"{}","endpoint":["10.0.0.1"],"users":[{{"account":{{"publicKey":"{}","allowedIPs":["10.0.0.2/32"]}}}}]}}"#,
            hex(&server_private),
            hex(&client_public)
        );
        let inbound =
            crate::json::parse(&format!(r#"{{"settings":{server_settings}}}"#)).expect("inbound");
        let out = Outbound::Freedom(Arc::new(crate::proxy::FreedomOut::default()));
        let port = serve_inbound(&inbound, &out, "127.0.0.1:0").expect("serve");

        let dead = UdpSocket::bind("127.0.0.1:0").expect("dead endpoint");
        let client = DeviceConfig {
            secret: client_private,
            addresses: vec!["10.0.0.2".parse().unwrap()],
            peers: vec![
                PeerConfig {
                    public: server_public,
                    preshared: [0; 32],
                    endpoint: Some(dead.local_addr().expect("dead address")),
                    endpoints: vec![dead.local_addr().expect("dead address")],
                    keepalive: 0,
                    allowed: vec![("192.0.2.1".parse().unwrap(), 32)],
                },
                PeerConfig {
                    public: server_public,
                    preshared: [0; 32],
                    endpoint: Some(format!("127.0.0.1:{port}").parse().unwrap()),
                    endpoints: vec![format!("127.0.0.1:{port}").parse().unwrap()],
                    keepalive: 0,
                    allowed: vec![("127.0.0.1".parse().unwrap(), 32)],
                },
            ],
            mtu: 1420,
            reserved: [0; 3],
            is_client: Some(true),
            no_kernel_tun: true,
            large_segments: false,
            dns: vec!["127.0.0.1".parse().unwrap()],
        };
        let wireguard = WireGuardOut::with_dns_port(client, dns_address.port()).expect("outbound");
        let cross = |asked: Destination| {
            let listener = TcpListener::bind("127.0.0.1:0").expect("pair");
            let tun = std::net::TcpStream::connect(listener.local_addr().expect("pair address"))
                .expect("connect");
            let (mut app, _) = listener.accept().expect("accept");
            app.set_read_timeout(Some(Duration::from_secs(30)))
                .expect("timeout");
            wireguard.serve_tcp(Connection::from(tun), &asked, b"head");
            app.write_all(b"hello").expect("write");
            let mut received = [0u8; 9];
            app.read_exact(&mut received).expect("read");
            assert_eq!(&received, b"headhello");
        };
        cross(Destination::Address(echo_address));
        assert_eq!(
            wireguard.resolve("example.test", 7),
            vec![
                "192.0.2.1:7".parse().expect("address"),
                "127.0.0.1:7".parse().expect("address"),
            ]
        );
        answer
            .recv_timeout(Duration::from_secs(5))
            .expect("the resolver asked the tunnel's DNS server");
        cross(Destination::Name(
            "example.test".to_owned(),
            echo_address.port(),
        ));
    }

    #[test]
    fn a_failed_name_is_remembered() {
        let config = DeviceConfig {
            secret: [0x11; 32],
            addresses: vec!["10.0.0.2".parse().unwrap()],
            peers: vec![PeerConfig {
                public: [0x22; 32],
                preshared: [0; 32],
                endpoint: Some("127.0.0.1:9".parse().unwrap()),
                endpoints: Vec::new(),
                keepalive: 0,
                allowed: vec![("192.0.2.0".parse().unwrap(), 24)],
            }],
            mtu: 1420,
            reserved: [0; 3],
            is_client: Some(true),
            no_kernel_tun: true,
            large_segments: false,
            dns: vec!["127.0.0.1".parse().unwrap()],
        };
        let wireguard = WireGuardOut::new(config).expect("outbound");
        assert_eq!(wireguard.lookup("missing.example"), Vec::<IpAddr>::new());
        let cache = wireguard.resolved.lock().expect("cache");
        let entry = cache.get("missing.example").expect("negative entry");
        assert_eq!(entry.addrs, Vec::<IpAddr>::new());
        assert!(entry.until > Instant::now());
    }

    /// The retry is driven by the route itself, not a wall clock over a socket: the first query is
    /// dropped and the second is answered, so the count of sends is exact.
    #[test]
    fn a_lost_query_is_sent_again() {
        let config = DeviceConfig {
            secret: [0; 32],
            addresses: vec!["10.0.0.2".parse().unwrap()],
            peers: Vec::new(),
            mtu: 1420,
            reserved: [0; 3],
            is_client: Some(true),
            no_kernel_tun: true,
            large_segments: false,
            dns: Vec::new(),
        };
        let (to_tunnel, packets) = mpsc::channel();
        let routes: UdpRoutes = Arc::default();
        let out = WireGuardOut {
            config: Arc::new(config),
            flows: mpsc::channel().0,
            to_tunnel,
            routes: Arc::clone(&routes),
            stop: Arc::new(AtomicBool::new(false)),
            dns_servers: Vec::new(),
            dns_port: 53,
            dns_port_next: AtomicU16::new(0),
            dns_id: AtomicU16::new(0),
            resolved: Mutex::new(HashMap::new()),
            #[cfg(target_os = "linux")]
            kernel: None,
        };
        let (sent, sends) = mpsc::channel();
        thread::scope(|scope| {
            let routes = Arc::clone(&routes);
            scope.spawn(move || {
                let mut count = 0;
                while let Ok(packet) = packets.recv_timeout(Duration::from_secs(10)) {
                    count += 1;
                    if count == 1 {
                        continue;
                    }
                    let Some(datagram) = udp_from_packet(&packet[WG_HEADER_SIZE..]) else {
                        continue;
                    };
                    let Some(question) = ferrox_core::dns::parse_query(datagram.payload) else {
                        continue;
                    };
                    let Some(reply) =
                        ferrox_core::dns::ip_answer(&question, 0, 60, &[vec![192, 0, 2, 1]])
                    else {
                        continue;
                    };
                    let mut inner = Vec::new();
                    assert!(udp_datagram(
                        &UdpDatagram {
                            source: datagram.destination,
                            destination: datagram.source,
                            source_port: datagram.destination_port,
                            destination_port: datagram.source_port,
                            payload: &reply,
                        },
                        &mut inner,
                    ));
                    let table = routes.lock().expect("routes");
                    table
                        .get(&datagram.source_port)
                        .expect("the exchange reserved a route")
                        .send(inner)
                        .expect("the answer reaches the route");
                    let _ = sent.send(count);
                    return;
                }
            });
            assert_eq!(
                out.exchange(
                    "10.0.0.2".parse().expect("source"),
                    "127.0.0.1".parse().expect("server"),
                    "example.test.",
                    1,
                ),
                Some((vec!["192.0.2.1".parse().expect("address")], 60))
            );
            assert_eq!(sends.recv().expect("the answer was sent"), 2);
        });
    }

    /// The DNS half of the truncated-answer witness: UDP answers the question with the truncation bit set, TCP answers the same one in full on the same port, and both keep serving while the question is asked again until the returned guard is dropped.
    fn dns_servers(udp: UdpSocket, tcp: TcpListener) -> DnsServers {
        udp.set_read_timeout(Some(Duration::from_millis(100)))
            .expect("DNS server poll");
        tcp.set_nonblocking(true).expect("DNS TCP accept poll");
        let stopped = Arc::new(AtomicBool::new(false));
        let udp_stopped = Arc::clone(&stopped);
        let dns_udp = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while !udp_stopped.load(Ordering::Relaxed) {
                let (n, from) = match udp.recv_from(&mut buf) {
                    Ok(received) => received,
                    Err(error) if crate::proxy::is_timeout(&error) => continue,
                    Err(error) => panic!("DNS UDP: {error}"),
                };
                let Some(question) = ferrox_core::dns::parse_query(&buf[..n]) else {
                    continue;
                };
                let Some(mut reply) =
                    ferrox_core::dns::ip_answer(&question, 0, 60, &[vec![192, 0, 2, 9]])
                else {
                    continue;
                };
                reply[2] |= 0x02;
                udp.send_to(&reply, from).expect("truncated DNS reply");
            }
        });
        let tcp_stopped = Arc::clone(&stopped);
        // A question asked again is answered again, and a connection that never finishes its frame costs only the reads that waited for it: the accept is polled so a stopped loop leaves even while no question arrives, and each stream's own bound reads put the ceiling on the join below.
        let dns_tcp = std::thread::spawn(move || {
            while !tcp_stopped.load(Ordering::Relaxed) {
                let (mut stream, _) = match tcp.accept() {
                    Ok(accepted) => accepted,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(_) => return,
                };
                // Where the platform says so an accepted stream keeps the listener's mode, and a nonblocking read ignores the timeout that bounds it.
                stream.set_nonblocking(false).expect("DNS TCP blocking");
                let bound = Some(Duration::from_secs(1));
                stream.set_read_timeout(bound).expect("DNS TCP read");
                stream.set_write_timeout(bound).expect("DNS TCP write");
                let mut prefix = [0u8; 2];
                if stream.read_exact(&mut prefix).is_err() {
                    continue;
                }
                let mut query = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
                if stream.read_exact(&mut query).is_err() {
                    continue;
                }
                let Some(question) = ferrox_core::dns::parse_query(&query) else {
                    continue;
                };
                let Some(reply) =
                    ferrox_core::dns::ip_answer(&question, 0, 60, &[vec![127, 0, 0, 1]])
                else {
                    continue;
                };
                let len = u16::try_from(reply.len()).expect("fits");
                let mut framed = Vec::with_capacity(2 + reply.len());
                framed.extend_from_slice(&len.to_be_bytes());
                framed.extend_from_slice(&reply);
                let _ = stream.write_all(&framed);
            }
        });
        DnsServers {
            stopped,
            servers: [Some(dns_udp), Some(dns_tcp)],
        }
    }

    /// The two DNS servers of the witness above, stopped and joined on every exit from the test that made them — a deadline panic included — because a thread still parked in `accept` holds the port out of the next test's hands.
    struct DnsServers {
        stopped: Arc<AtomicBool>,
        servers: [Option<std::thread::JoinHandle<()>>; 2],
    }

    impl Drop for DnsServers {
        fn drop(&mut self) {
            self.stopped.store(true, Ordering::Relaxed);
            for handle in self.servers.iter_mut().filter_map(Option::take) {
                let _ = handle.join();
            }
        }
    }

    /// The pending-record batch keeps its allocation across flushes.
    #[test]
    fn a_batch_reuses_its_pending_buffer() {
        let config = DeviceConfig {
            secret: [0x11; 32],
            addresses: vec!["10.0.0.1".parse().unwrap()],
            peers: vec![PeerConfig {
                public: [0x22; 32],
                preshared: [0; 32],
                endpoint: None,
                endpoints: Vec::new(),
                keepalive: 0,
                allowed: vec![("10.0.0.0".parse().unwrap(), 8)],
            }],
            mtu: 1420,
            reserved: [0; 3],
            is_client: Some(false),
            no_kernel_tun: true,
            large_segments: false,
            dns: Vec::new(),
        };
        let peers = peers(&config, [0; 12]);
        let socket = UdpSocket::bind("127.0.0.1:0").expect("socket");
        let target = UdpSocket::bind("127.0.0.1:0")
            .expect("target")
            .local_addr()
            .expect("address");
        let (to_stack, _packets) = mpsc::channel();
        let mut sends = Vec::new();
        let mut capacity = 0;
        for _ in 0..2 {
            let mut events: Vec<Event> = (0..4)
                .map(|index| Event::Send {
                    endpoint: target,
                    packet: vec![index; 32],
                })
                .collect();
            flush(
                &mut events,
                &socket,
                &to_stack,
                None,
                &peers,
                Some(0),
                false,
                &mut sends,
                None,
            );
            assert_eq!(sends.len(), 0, "the batch is drained by the flush");
            if capacity == 0 {
                capacity = sends.capacity();
                assert!(capacity >= 4, "the batch held the four records");
            } else {
                assert_eq!(sends.capacity(), capacity, "the batch does not reallocate");
            }
        }
    }

    /// A truncated UDP response retries the same DNS question over TCP on the reserved server port.
    #[test]
    fn a_truncated_answer_is_asked_again_over_tcp() {
        // The listening transport picks the port: a Windows runner hands out UDP ephemerals that its excluded ranges and TIME_WAIT band hold shut for TCP, which is what ran the retry loop out, and a port TCP just bound is bindable by definition.
        let (tcp, udp, dns_address) = (0..4096)
            .find_map(|_| {
                let tcp = TcpListener::bind("127.0.0.1:0").expect("dns tcp");
                let address = tcp.local_addr().expect("dns address");
                match UdpSocket::bind(address) {
                    Ok(udp) => Some((tcp, udp, address)),
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::AddrInUse
                                | std::io::ErrorKind::PermissionDenied
                                | std::io::ErrorKind::AddrNotAvailable
                        ) =>
                    {
                        None
                    }
                    Err(error) => panic!("dns udp: {error}"),
                }
            })
            .expect("a port free for both DNS transports");
        let _servers = dns_servers(udp, tcp);

        let client_private = [0x11; 32];
        let server_private = [0x22; 32];
        let client_public = ferrox_core::wireguard::device::public_key(&client_private);
        let server_public = ferrox_core::wireguard::device::public_key(&server_private);
        let hex = ferrox_core::foxy::account::hex_encode;
        let server_settings = format!(
            r#"{{"secretKey":"{}","endpoint":["10.0.0.1"],"users":[{{"account":{{"publicKey":"{}","allowedIPs":["10.0.0.2/32"]}}}}]}}"#,
            hex(&server_private),
            hex(&client_public)
        );
        let inbound =
            crate::json::parse(&format!(r#"{{"settings":{server_settings}}}"#)).expect("inbound");
        let out = Outbound::Freedom(Arc::new(crate::proxy::FreedomOut::default()));
        let port = serve_inbound(&inbound, &out, "127.0.0.1:0").expect("serve");

        let client = DeviceConfig::from_json(
            &crate::json::parse(&format!(
                r#"{{"secretKey":"{}","address":["10.0.0.2"],"remoteDNS":["127.0.0.1"],"peers":[{{"publicKey":"{}","endpoint":"127.0.0.1:{port}"}}]}}"#,
                hex(&client_private),
                hex(&server_public)
            ))
            .expect("client config"),
        )
        .expect("device");
        let wireguard = WireGuardOut::with_dns_port(client, dns_address.port()).expect("outbound");
        // The exchange's own five seconds measure the runner under a 1 700-test suite rather than the tunnel, and a give-up caches its empty answer for five more, so the wall clock bounds the wait, the answer stays the assertion, and a stale negative goes first.
        let until = Instant::now() + Duration::from_secs(30);
        let answer = loop {
            let answer = wireguard.resolve("example.test", 7);
            if !answer.is_empty() {
                break answer;
            }
            assert!(
                Instant::now() < until,
                "the truncated answer never reached the TCP retry"
            );
            wireguard.resolved.lock().expect("cache").clear();
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(answer, vec!["127.0.0.1:7".parse().expect("address")]);
    }

    #[test]
    fn a_client_with_peers_in_both_families_binds_a_dual_stack_socket() {
        let v4: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let v6: SocketAddr = "[::1]:9".parse().unwrap();
        let config = DeviceConfig {
            secret: [0x11; 32],
            addresses: vec!["10.0.0.2".parse().unwrap()],
            peers: vec![PeerConfig {
                public: [0x22; 32],
                preshared: [0; 32],
                endpoint: Some(v4),
                endpoints: vec![v4, v6],
                keepalive: 0,
                allowed: vec![("0.0.0.0".parse().unwrap(), 0)],
            }],
            mtu: 1420,
            reserved: [0; 3],
            is_client: Some(true),
            no_kernel_tun: true,
            large_segments: false,
            dns: Vec::new(),
        };
        let socket = bind_socket(&config).expect("dual-stack socket");
        assert!(socket.local_addr().expect("address").is_ipv6());
        let v4: SocketAddr = "127.0.0.1:7".parse().unwrap();
        let mapped = send_endpoint(v4, true);
        assert_eq!(mapped, "[::ffff:127.0.0.1]:7".parse().unwrap());
        assert_eq!(recv_endpoint(mapped, true), v4);
    }

    /// A receiver on an ephemeral CI port can see unrelated datagrams; match the sender's port so
    /// a stray packet neither satisfies nor breaks the claim about what `send_packet` wrote.
    fn recv_from_port(socket: &UdpSocket, port: u16, buf: &mut [u8]) -> usize {
        loop {
            let (n, from) = socket.recv_from(buf).expect("a datagram from the sender");
            if from.port() == port {
                return n;
            }
        }
    }

    fn quiet_from_ports(socket: &UdpSocket, ports: &[u16], buf: &mut [u8]) -> bool {
        loop {
            match socket.recv_from(buf) {
                Ok((_, from)) if ports.contains(&from.port()) => return false,
                Ok(_) => {}
                Err(_) => return true,
            }
        }
    }

    #[test]
    fn a_handshake_races_every_endpoint_candidate_and_data_follows_one() {
        let Ok(v4) = UdpSocket::bind("127.0.0.1:0") else {
            return;
        };
        let Ok(v6) = UdpSocket::bind("[::1]:0") else {
            return;
        };
        let Ok(sender) = bind_dual_stack() else {
            return;
        };
        for socket in [&v4, &v6] {
            socket
                .set_read_timeout(Some(Duration::from_secs(1)))
                .expect("timeout");
        }
        let candidates = vec![
            v4.local_addr().expect("v4 address"),
            v6.local_addr().expect("v6 address"),
        ];
        let sender_port = sender.local_addr().expect("sender address").port();
        let mut initiation = vec![0u8; INITIATION_SIZE];
        initiation[..4].copy_from_slice(&TYPE_INITIATION.to_le_bytes());
        send_packet(&sender, true, candidates[0], &initiation, Some(&candidates));
        let mut buf = [0u8; 256];
        assert_eq!(
            recv_from_port(&v4, sender_port, &mut buf),
            INITIATION_SIZE,
            "v4 initiation"
        );
        assert_eq!(
            recv_from_port(&v6, sender_port, &mut buf),
            INITIATION_SIZE,
            "v6 initiation"
        );
        let mut transport = vec![0u8; 32];
        transport[..4]
            .copy_from_slice(&ferrox_core::wireguard::transport::TYPE_TRANSPORT.to_le_bytes());
        send_packet(&sender, true, candidates[0], &transport, Some(&candidates));
        assert_eq!(
            recv_from_port(&v4, sender_port, &mut buf),
            transport.len(),
            "v4 transport"
        );
        v6.set_read_timeout(Some(Duration::from_millis(300)))
            .expect("timeout");
        assert!(
            quiet_from_ports(&v6, &[sender_port], &mut buf),
            "data follows the pinned endpoint"
        );
        let Ok(v4_only) = UdpSocket::bind("127.0.0.1:0") else {
            return;
        };
        let fallback_port = v4_only.local_addr().expect("fallback address").port();
        send_packet(
            &v4_only,
            false,
            candidates[0],
            &initiation,
            Some(&candidates),
        );
        assert_eq!(
            recv_from_port(&v4, fallback_port, &mut buf),
            INITIATION_SIZE,
            "v4 fallback"
        );
        assert!(
            quiet_from_ports(&v6, &[sender_port, fallback_port], &mut buf),
            "a v4-only socket skips the v6 candidate"
        );
    }

    #[test]
    fn a_roamed_endpoint_still_receives_a_rekey() {
        let Ok(v4) = UdpSocket::bind("127.0.0.1:0") else {
            return;
        };
        let Ok(v6) = UdpSocket::bind("[::1]:0") else {
            return;
        };
        let Ok(roamed) = UdpSocket::bind("127.0.0.1:0") else {
            return;
        };
        let Ok(sender) = bind_dual_stack() else {
            return;
        };
        let candidates = vec![
            v4.local_addr().expect("v4 address"),
            v6.local_addr().expect("v6 address"),
        ];
        let roamed_address = roamed.local_addr().expect("roamed address");
        for socket in [&v4, &v6, &roamed] {
            socket
                .set_read_timeout(Some(Duration::from_secs(1)))
                .expect("timeout");
        }
        let mut initiation = vec![0u8; INITIATION_SIZE];
        initiation[..4].copy_from_slice(&TYPE_INITIATION.to_le_bytes());
        send_packet(
            &sender,
            true,
            roamed_address,
            &initiation,
            Some(&candidates),
        );
        let mut buf = [0u8; 256];
        assert_eq!(
            v4.recv_from(&mut buf).expect("v4 initiation").0,
            INITIATION_SIZE
        );
        assert_eq!(
            v6.recv_from(&mut buf).expect("v6 initiation").0,
            INITIATION_SIZE
        );
        assert_eq!(
            roamed.recv_from(&mut buf).expect("roamed initiation").0,
            INITIATION_SIZE
        );
        let mut transport = vec![0u8; 32];
        transport[..4]
            .copy_from_slice(&ferrox_core::wireguard::transport::TYPE_TRANSPORT.to_le_bytes());
        send_packet(&sender, true, roamed_address, &transport, Some(&candidates));
        assert_eq!(
            roamed.recv_from(&mut buf).expect("roamed data").0,
            transport.len()
        );
    }

    #[test]
    fn the_handshake_window_requires_cookies_after_an_eighth_of_the_queue() {
        let mut guard = CookieGuard::default();
        for _ in 0..(COOKIE_AFTER - 1) {
            assert!(!guard.observe(0));
        }
        assert!(guard.observe(0), "the 128th initiation is under load");
        assert!(guard.observe(500), "the load tail outlives the burst");
        assert!(!guard.observe(1_001), "a quiet second clears the window");
    }

    #[test]
    fn cookie_source_bytes_are_the_reference_address_port_form() {
        let (v4, width) = endpoint_bytes("127.0.0.1:51820".parse().unwrap());
        assert_eq!(&v4[..width], &[127, 0, 0, 1, 0xca, 0x6c]);
        let (v6, width) = endpoint_bytes("[::1]:53".parse().unwrap());
        let mut expected = [0u8; 18];
        expected[15] = 1;
        expected[16..].copy_from_slice(&53u16.to_be_bytes());
        assert_eq!(&v6[..width], &expected);
    }

    #[test]
    fn a_loaded_responder_issues_a_cookie_and_accepts_the_retry() {
        let client_private = [0x11; 32];
        let server_private = [0x22; 32];
        let client_public = ferrox_core::wireguard::device::public_key(&client_private);
        let server_public = ferrox_core::wireguard::device::public_key(&server_private);
        let config = DeviceConfig {
            secret: server_private,
            addresses: vec!["10.0.0.1".parse().unwrap()],
            peers: vec![PeerConfig {
                public: client_public,
                preshared: [0; 32],
                endpoint: None,
                endpoints: Vec::new(),
                keepalive: 0,
                allowed: vec![("10.0.0.2".parse().unwrap(), 32)],
            }],
            mtu: 1420,
            reserved: [0; 3],
            is_client: Some(false),
            no_kernel_tun: true,
            large_segments: false,
            dns: Vec::new(),
        };
        let server = UdpSocket::bind("127.0.0.1:0").expect("server");
        let server_address = server.local_addr().expect("server address");
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let client = UdpSocket::bind("127.0.0.1:0").expect("client");
        let client_address = client.local_addr().expect("client address");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");

        let mut peer = peers(&config, [0; 12]);
        let (to_stack, _) = mpsc::channel();
        let mut guard = CookieGuard::default();
        let mut initiator = Tunnel::new(
            client_private,
            server_public,
            [0; 32],
            server_address,
            0,
            [0; 3],
            [0; 12],
        );
        let mut events = Vec::new();
        assert!(initiator.initiate(0, &mut events));
        let first = sent(&events);
        handle_initiation(
            &mut peer,
            0,
            client_address,
            &first,
            &server,
            &to_stack,
            &mut guard,
            true,
            &mut Vec::new(),
        );

        let mut cookie = [0u8; 64];
        let (n, _) = client.recv_from(&mut cookie).expect("cookie reply");
        assert_eq!(n, cookie.len());
        assert_eq!(
            u32::from(cookie[0]),
            ferrox_core::wireguard::transport::TYPE_COOKIE_REPLY
        );

        let mut incoming = Vec::new();
        initiator.receive(0, server_address, &mut cookie, &mut incoming);
        let retry = sent(&incoming);
        assert!(
            retry[INITIATION_SIZE - 16..].iter().any(|byte| *byte != 0),
            "mac2 is set"
        );
        handle_initiation(
            &mut peer,
            1,
            client_address,
            &retry,
            &server,
            &to_stack,
            &mut guard,
            true,
            &mut Vec::new(),
        );

        let mut answer = [0u8; 128];
        let (n, _) = client.recv_from(&mut answer).expect("handshake response");
        assert_eq!(u32::from(answer[0]), TYPE_RESPONSE);
        assert_eq!(n, 92);
    }
}

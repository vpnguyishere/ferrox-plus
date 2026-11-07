//! A tiny synchronous DNS fallback with the reference's client knobs: alternate
//! and preferred servers, per-server attempts, EDNS0, 0x20 QNAME casing, a
//! TTL cache, and preresolved CIDR answers.
//!
//! The system resolver is still asked first when nothing says otherwise, so the
//! ordinary path pays no query. Every knob is opt-in; the defaults reproduce
//! the previous behaviour byte for byte.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REPLY: usize = 4096;
const CACHE_LIMIT: usize = 4096;

#[derive(Clone, Debug)]
struct CacheEntry {
    addresses: Vec<IpAddr>,
    expires: Instant,
}

/// The client DNS knobs; every default keeps the previous fallback behaviour.
#[derive(Clone, Debug)]
pub(crate) struct Config {
    pub(crate) servers: Vec<SocketAddr>,
    pub(crate) preferred: Vec<SocketAddr>,
    pub(crate) attempts_per_server: usize,
    pub(crate) attempts_per_preferred: usize,
    pub(crate) request_timeout: Duration,
    pub(crate) await_timeout: Duration,
    pub(crate) prefer_alternate_probability: f64,
    pub(crate) edns0_probability: f64,
    pub(crate) qname_casing_probability: f64,
    pub(crate) cache_extension: Duration,
    pub(crate) preresolved_labels: HashMap<String, Vec<(IpAddr, u8)>>,
    pub(crate) preresolved_probability: f64,
    cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
}

impl Config {
    /// A config with the given alternate servers and reference defaults.
    pub(crate) fn from_servers(servers: &[SocketAddr]) -> Self {
        Self {
            servers: servers.to_vec(),
            preferred: Vec::new(),
            attempts_per_server: 2,
            attempts_per_preferred: 1,
            request_timeout: DEFAULT_TIMEOUT,
            await_timeout: Duration::from_millis(10),
            prefer_alternate_probability: 0.0,
            edns0_probability: 0.0,
            qname_casing_probability: 0.0,
            cache_extension: Duration::ZERO,
            preresolved_labels: HashMap::new(),
            preresolved_probability: 0.0,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Parse a CIDR list into networks; a bare address is a full-length prefix.
    pub(crate) fn cidrs(texts: &[String]) -> Vec<(IpAddr, u8)> {
        let mut networks = Vec::new();
        for text in texts {
            let text = text.trim();
            let (address, prefix) = match text.split_once('/') {
                Some((address, prefix)) => (address, Some(prefix)),
                None => (text, None),
            };
            let Ok(address) = address.parse::<IpAddr>() else {
                continue;
            };
            let full = if address.is_ipv4() { 32 } else { 128 };
            let Ok(prefix) = prefix.map_or(Ok(full), str::parse::<u8>) else {
                continue;
            };
            if prefix > full {
                continue;
            }
            networks.push((address, prefix));
        }
        networks
    }

    /// A live cached answer, dropping an expired entry.
    fn cache_get(&self, host: &str) -> Option<Vec<IpAddr>> {
        let mut cache = self.cache.lock().ok()?;
        let entry = cache.get(host)?;
        if entry.expires <= Instant::now() {
            cache.remove(host);
            return None;
        }
        Some(entry.addresses.clone())
    }

    /// Cache an answer for its TTL, evicting expired entries at the limit.
    fn cache_put(&self, host: &str, addresses: Vec<IpAddr>, ttl: Duration) {
        if addresses.is_empty() {
            return;
        }
        let ttl = ttl.saturating_add(self.cache_extension);
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };
        if cache.len() >= CACHE_LIMIT {
            cache.retain(|_, entry| entry.expires > Instant::now());
            if cache.len() >= CACHE_LIMIT {
                cache.clear();
            }
        }
        cache.insert(
            host.to_owned(),
            CacheEntry {
                addresses,
                expires: Instant::now() + ttl.max(Duration::from_secs(1)),
            },
        );
    }

    /// A random address from a matching preresolved CIDR for one record family.
    fn preresolve(&self, provider: Option<&str>, host: &str, want_v4: bool) -> Option<IpAddr> {
        let name = host.trim_end_matches('.').to_ascii_lowercase();
        let networks = provider
            .and_then(|provider| self.preresolved_labels.get(&provider.to_ascii_lowercase()))
            .or_else(|| self.preresolved_labels.get(&name))
            .or_else(|| self.preresolved_labels.get(""))?;
        if networks.is_empty() {
            return None;
        }
        let candidates: Vec<&(IpAddr, u8)> = networks
            .iter()
            .filter(|(address, _)| address.is_ipv4() == want_v4)
            .collect();
        if candidates.is_empty() {
            return None;
        }
        let index = usize::try_from(random_below(
            u64::try_from(candidates.len()).unwrap_or(u64::MAX),
        ))
        .unwrap_or(0);
        let (address, prefix) = *candidates[index];
        Some(random_in(address, prefix))
    }
}

/// Resolve with an explicit config, used by the lane's settings and by tests.
#[allow(clippy::too_many_lines)]
pub(crate) fn resolve_with(config: &Config, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(address, port)]);
    }
    let name = host.trim_end_matches('.').to_ascii_lowercase();
    if let Some(addresses) = config.cache_get(&name) {
        return Ok(with_port(addresses, port));
    }
    let prefer_alternate = coin(config.prefer_alternate_probability);
    if !prefer_alternate {
        if let Ok(addresses) = (host, port).to_socket_addrs() {
            let addresses: Vec<SocketAddr> = addresses.collect();
            if !addresses.is_empty() {
                return Ok(addresses);
            }
        }
    }
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no alternate DNS server");
    let servers = alternate_servers(config);
    for server in &servers {
        let attempts = if config.preferred.iter().any(|preferred| preferred == server) {
            config.attempts_per_preferred.max(1)
        } else {
            config.attempts_per_server.max(1)
        };
        for _ in 0..attempts {
            match query(&name, *server, config) {
                Ok((addresses, ttl)) if !addresses.is_empty() => {
                    config.cache_put(&name, addresses.clone(), ttl);
                    return Ok(with_port(addresses, port));
                }
                Ok(_) => {
                    last = io::Error::new(
                        io::ErrorKind::NotFound,
                        "alternate DNS answered no address",
                    );
                }
                Err(error) => last = error,
            }
        }
    }
    if prefer_alternate {
        if let Ok(addresses) = (host, port).to_socket_addrs() {
            let addresses: Vec<SocketAddr> = addresses.collect();
            if !addresses.is_empty() {
                return Ok(addresses);
            }
        }
    }
    Err(last)
}

/// Resolve a fronting dial domain, using its provider's preresolved CIDRs when one is selected.
pub(crate) fn resolve_fronting(
    config: &Config,
    provider: Option<&str>,
    host: &str,
    port: u16,
) -> io::Result<Vec<SocketAddr>> {
    let mut addresses = Vec::new();
    if coin(config.preresolved_probability) {
        if let Some(address) = config.preresolve(provider, host, true) {
            addresses.push(address);
        }
        if let Some(address) = config.preresolve(provider, host, false) {
            addresses.push(address);
        }
    }
    if addresses.is_empty() {
        resolve_with(config, host, port)
    } else {
        Ok(with_port(addresses, port))
    }
}

/// Preferred servers first when the coin lands, then the configured alternates.
fn alternate_servers(config: &Config) -> Vec<SocketAddr> {
    let mut servers = Vec::new();
    servers.extend(config.preferred.iter().copied());
    for server in &config.servers {
        if !servers.contains(server) {
            servers.push(*server);
        }
    }
    servers
}

/// Pair every address with the requested port.
fn with_port(addresses: Vec<IpAddr>, port: u16) -> Vec<SocketAddr> {
    addresses
        .into_iter()
        .map(|address| SocketAddr::new(address, port))
        .collect()
}

/// One random coin with the given probability, never consuming entropy for a certain result.
fn coin(probability: f64) -> bool {
    if probability <= 0.0 {
        return false;
    }
    if probability >= 1.0 {
        return true;
    }
    f64::from(u16::from_be_bytes(crate::psiphon_ssh::random::<2>())) / 65_536.0 < probability
}

/// A random value in `0..bound`.
fn random_below(bound: u64) -> u64 {
    if bound <= 1 {
        return 0;
    }
    u64::from_be_bytes(crate::psiphon_ssh::random::<8>()) % bound
}

/// A random host in `address/prefix`, so a preresolved CIDR answers without a query.
fn random_in(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            let host = u32::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix.min(32)))
            };
            let span = if prefix >= 32 { 0 } else { u32::MAX >> prefix };
            let offset = u32::try_from(random_below(u64::from(span) + 1)).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from((host & mask) | offset))
        }
        IpAddr::V6(address) => {
            let mut octets = address.octets();
            let mut keep = usize::from(prefix.min(128));
            for octet in &mut octets {
                if keep >= 8 {
                    keep -= 8;
                } else if keep > 0 {
                    let host_mask = 0xffu8 >> keep;
                    *octet &= !host_mask;
                    *octet |= crate::psiphon_ssh::random::<1>()[0] & host_mask;
                    keep = 0;
                } else {
                    *octet = crate::psiphon_ssh::random::<1>()[0];
                }
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }
}

/// Ask one server for A and AAAA in parallel, returning the addresses and the smallest TTL.
fn query(host: &str, server: SocketAddr, config: &Config) -> io::Result<(Vec<IpAddr>, Duration)> {
    let (sender, receiver) = mpsc::channel();
    for record in [1u16, 28] {
        let sender = sender.clone();
        let name = host.to_owned();
        let config = config.clone();
        thread::Builder::new()
            .name(format!("psiphon-dns-{record}"))
            .spawn(move || {
                let _ = sender.send((record, query_one(&name, server, record, &config)));
            })
            .map_err(|error| io::Error::other(format!("psiphon DNS thread: {error}")))?;
    }
    drop(sender);
    let mut addresses = Vec::new();
    let mut ttl = Duration::ZERO;
    let mut error = io::Error::new(io::ErrorKind::NotFound, "no DNS answer");
    let mut answered = false;
    for _ in 0..2 {
        let reply = if answered {
            receiver.recv_timeout(config.await_timeout)
        } else {
            receiver
                .recv()
                .map_err(|_| mpsc::RecvTimeoutError::Disconnected)
        };
        let Ok((record, result)) = reply else {
            break;
        };
        match result {
            Ok((found, found_ttl)) if !found.is_empty() => {
                answered = true;
                ttl = if ttl.is_zero() {
                    found_ttl
                } else {
                    ttl.min(found_ttl)
                };
                addresses.extend(found);
            }
            Ok(_) => {
                error = io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "alternate DNS answered no {} record",
                        if record == 1 { "A" } else { "AAAA" }
                    ),
                );
            }
            Err(failure) => error = failure,
        }
    }
    if addresses.is_empty() {
        Err(error)
    } else {
        Ok((addresses, ttl))
    }
}

/// Send one record query and parse the reply from this server.
fn query_one(
    host: &str,
    server: SocketAddr,
    record: u16,
    config: &Config,
) -> io::Result<(Vec<IpAddr>, Duration)> {
    let bind = if server.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = UdpSocket::bind(bind)?;
    socket.connect(server)?;
    socket.set_read_timeout(Some(config.request_timeout))?;
    let id = crate::psiphon_ssh::random::<2>();
    let edns0 = coin(config.edns0_probability);
    let casing = coin(config.qname_casing_probability);
    let (request, sent_name) = query_packet(id, host, record, edns0, casing)?;
    socket.send(&request)?;
    let mut reply = [0u8; MAX_REPLY];
    let count = socket.recv(&mut reply)?;
    parse_reply(id, &reply[..count], record, sent_name.as_deref(), casing)
}

/// Build the query, optionally with EDNS0 and randomized QNAME casing.
fn query_packet(
    id: [u8; 2],
    host: &str,
    record: u16,
    edns0: bool,
    casing: bool,
) -> io::Result<(Vec<u8>, Option<Vec<u8>>)> {
    let name = host.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad DNS name"));
    }
    let mut packet = Vec::with_capacity(12 + name.len() + 6 + 11);
    packet.extend_from_slice(&id);
    packet.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, u8::from(edns0)]);
    for label in name.split('.') {
        let length = u8::try_from(label.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS label too long"))?;
        if label.is_empty() || length > 63 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad DNS label"));
        }
        packet.push(length);
        if casing {
            for byte in label.bytes() {
                let upper = crate::psiphon_ssh::random::<1>()[0] & 1 == 0;
                packet.push(if upper {
                    byte.to_ascii_uppercase()
                } else {
                    byte.to_ascii_lowercase()
                });
            }
        } else {
            packet.extend_from_slice(label.as_bytes());
        }
    }
    packet.push(0);
    let name_bytes = packet[12..packet.len()].to_vec();
    packet.extend_from_slice(&record.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    if edns0 {
        packet.extend_from_slice(&[0, 0, 41, 0x10, 0x00, 0, 0, 0, 0, 0, 0]);
    }
    Ok((packet, Some(name_bytes)))
}

/// Parse a reply, checking the ID, question echo, and answer record type.
fn parse_reply(
    id: [u8; 2],
    reply: &[u8],
    record: u16,
    sent_name: Option<&[u8]>,
    exact: bool,
) -> io::Result<(Vec<IpAddr>, Duration)> {
    if reply.len() < 12 || reply[..2] != id[..] || reply[2] & 0x80 == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad DNS reply"));
    }
    if reply[3] & 0x0f != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "DNS error"));
    }
    let questions = usize::from(u16::from_be_bytes([reply[4], reply[5]]));
    let answers = usize::from(u16::from_be_bytes([reply[6], reply[7]]));
    let mut at = 12;
    for index in 0..questions {
        let start = at;
        skip_name(reply, &mut at)?;
        if index == 0 {
            if let Some(sent) = sent_name {
                let echo = &reply[start..at];
                let matched = if exact {
                    echo == sent
                } else {
                    echo.eq_ignore_ascii_case(sent)
                };
                if !matched {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "DNS question changed",
                    ));
                }
            }
        }
        at = at
            .checked_add(4)
            .filter(|at| *at <= reply.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short DNS question"))?;
    }
    let mut addresses = Vec::new();
    let mut ttl = Duration::MAX;
    for _ in 0..answers {
        skip_name(reply, &mut at)?;
        let head = reply
            .get(at..at + 10)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short DNS answer"))?;
        let kind = u16::from_be_bytes([head[0], head[1]]);
        let class = u16::from_be_bytes([head[2], head[3]]);
        let seconds = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
        let length = usize::from(u16::from_be_bytes([head[8], head[9]]));
        at += 10;
        let data = reply
            .get(at..at + length)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short DNS record"))?;
        at += length;
        if kind != record || class != 1 {
            continue;
        }
        ttl = ttl.min(Duration::from_secs(u64::from(seconds)));
        match (kind, data) {
            (1, [a, b, c, d]) => addresses.push(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
            (28, bytes) if bytes.len() == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(bytes);
                addresses.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
    }
    let ttl = if ttl == Duration::MAX {
        Duration::ZERO
    } else {
        ttl
    };
    Ok((addresses, ttl))
}

fn skip_name(reply: &[u8], at: &mut usize) -> io::Result<()> {
    loop {
        let length = usize::from(
            *reply
                .get(*at)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short DNS name"))?,
        );
        *at += 1;
        match length & 0xc0 {
            0xc0 => {
                *at += 1;
                return Ok(());
            }
            0 => {
                if length == 0 {
                    return Ok(());
                }
                *at = (*at)
                    .checked_add(length)
                    .filter(|at| *at <= reply.len())
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short DNS label"))?;
            }
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad DNS name")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{resolve_fronting, resolve_with, Config};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::thread;

    #[test]
    fn a_literal_address_needs_no_query() {
        let addresses =
            resolve_with(&Config::from_servers(&[]), "192.0.2.7", 443).expect("literal");
        assert_eq!(addresses, [SocketAddr::from(([192, 0, 2, 7], 443))]);
    }

    /// Answer one query with a record of the type the client asked for.
    fn responder(socket: &UdpSocket) {
        let mut request = [0u8; 512];
        let (count, peer) = socket.recv_from(&mut request).expect("query");
        let request = &request[..count];
        let question_end = 12
            + request[12..]
                .iter()
                .position(|byte| *byte == 0)
                .expect("question")
            + 5;
        let record = u16::from_be_bytes([request[question_end - 4], request[question_end - 3]]);
        let mut reply = Vec::new();
        reply.extend_from_slice(&request[..2]);
        reply.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        reply.extend_from_slice(&request[12..question_end]);
        reply.extend_from_slice(&[0xc0, 0x0c]);
        reply.extend_from_slice(&record.to_be_bytes());
        reply.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
        if record == 28 {
            reply.extend_from_slice(&[0, 16]);
            reply.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7]);
        } else {
            reply.extend_from_slice(&[0, 4, 203, 0, 113, 7]);
        }
        socket.send_to(&reply, peer).expect("reply");
    }

    #[test]
    fn an_alternate_server_answers_a_record() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("socket");
        let server = socket.local_addr().expect("address");
        let responder = thread::spawn(move || responder(&socket));
        let config = Config::from_servers(&[server]);
        let (addresses, _) =
            super::query_one("psiphon.test", server, 1, &config).expect("alternate");
        responder.join().expect("responder");
        assert_eq!(addresses, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))]);
    }

    #[test]
    /// The cache answers a repeated name without opening a socket.
    fn the_cache_answers_the_second_query_without_a_socket() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("socket");
        let server = socket.local_addr().expect("address");
        let responder = thread::spawn(move || responder(&socket));
        let mut config = Config::from_servers(&[server]);
        config.prefer_alternate_probability = 1.0;
        config.request_timeout = std::time::Duration::from_millis(50);
        let first = resolve_with(&config, "psiphon.test", 443).expect("first");
        responder.join().expect("responder");
        let second = resolve_with(&config, "psiphon.test", 443).expect("cached");
        assert_eq!(first, second);
    }

    #[test]
    /// A preresolved CIDR answers without a query.
    fn a_preresolved_cidr_answers_without_a_query() {
        let mut config = Config::from_servers(&[]);
        config.preresolved_labels =
            HashMap::from([(String::new(), Config::cidrs(&["203.0.113.0/24".to_owned()]))]);
        config.preresolved_probability = 1.0;
        let addresses = resolve_fronting(&config, None, "psiphon.test", 443).expect("preresolved");
        assert_eq!(addresses.len(), 1);
        match addresses[0].ip() {
            IpAddr::V4(address) => assert_eq!(address.octets()[..3], [203, 0, 113]),
            IpAddr::V6(_) => panic!("wrong family"),
        }
    }

    #[test]
    /// Invalid CIDR entries are dropped while valid ones stay.
    fn a_cidr_parses_bad_entries_away() {
        assert_eq!(
            Config::cidrs(&[
                "10.0.0.0/8".to_owned(),
                "nope".to_owned(),
                "10.0.0.0/nope".to_owned(),
                "10.0.0.0/33".to_owned(),
                "2001:db8::/129".to_owned(),
            ]),
            vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)]
        );
    }

    #[test]
    /// A labelled preresolved CIDR only answers that provider.
    fn a_preresolved_label_only_answers_its_provider() {
        let mut config = Config::from_servers(&[]);
        config.preresolved_labels = HashMap::from([(
            "provider-a".to_owned(),
            Config::cidrs(&["203.0.113.0/24".to_owned()]),
        )]);
        config.preresolved_probability = 1.0;
        assert!(config
            .preresolve(Some("provider-b"), "psiphon.test", true)
            .is_none());
        assert!(config
            .preresolve(Some("provider-a"), "psiphon.test", true)
            .is_some());
    }

    #[test]
    /// A full-length prefix keeps the whole address.
    fn a_full_host_prefix_keeps_every_bit() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        assert_eq!(super::random_in(v4, 32), v4);
        let v6: IpAddr = "2001:db8::1".parse().expect("address");
        assert_eq!(super::random_in(v6, 128), v6);
        match super::random_in(v6, 32) {
            IpAddr::V6(address) => {
                assert_eq!(&address.octets()[..4], &[0x20, 0x01, 0x0d, 0xb8]);
            }
            IpAddr::V4(_) => panic!("wrong family"),
        }
    }

    #[test]
    /// An empty answer does not reset the smallest TTL.
    fn an_empty_record_does_not_zero_the_ttl() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("socket");
        let server = socket.local_addr().expect("address");
        let responder = thread::spawn(move || responder(&socket));
        let mut config = Config::from_servers(&[server]);
        config.request_timeout = std::time::Duration::from_millis(50);
        let (addresses, ttl) = super::query("psiphon.test", server, &config).expect("query");
        responder.join().expect("responder");
        assert_eq!(addresses.len(), 1);
        assert_eq!(ttl, std::time::Duration::from_secs(60));
    }

    #[test]
    /// A reply whose question echo changed case is refused.
    fn a_changed_question_echo_is_refused_when_casing_was_sent() {
        let id = [0x12, 0x34];
        let sent = b"\x07PSIPHON\x04TEST\x00";
        let echo = b"\x07psiphon\x04test\x00";
        let mut reply = Vec::new();
        reply.extend_from_slice(&id);
        reply.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0]);
        reply.extend_from_slice(echo);
        reply.extend_from_slice(&[0, 1, 0, 1]);
        assert!(super::parse_reply(id, &reply, 1, Some(&sent[..]), false).is_ok());
        assert!(super::parse_reply(id, &reply, 1, Some(&sent[..]), true).is_err());
    }
}

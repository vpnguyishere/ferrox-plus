//! The reference's `LightProxy` lane: a pinned TLS proxy that carries a
//! destination without an SSH tunnel, framed by a CBOR header and initial
//! padding so the first records look like ordinary browser traffic.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferrox_core::tls::{TlsConfig, TlsProvider as _};

use crate::psiphon_broker::{decode, encode, Value};

const PROTOCOL: &str = "TLS";
const VERSION: u8 = 0x01;
const STOP_PADDING: u16 = 0xffff;
const PADDING_MIN: usize = 900;
const PADDING_MAX: usize = 1400;
const MAX_RECORD: usize = 16 * 1024;
const POLL: Duration = Duration::from_millis(50);
const IO_TIMEOUT: Duration = Duration::from_secs(1);
const BUFFER: usize = 16 * 1024;
const FAILURE_COOLDOWN: Duration = Duration::from_secs(5);

/// The configuration of one `LightProxy` client.
#[derive(Clone, Debug)]
pub(crate) struct Config {
    pub(crate) entry: String,
    pub(crate) tracker: i64,
    pub(crate) sponsor: String,
    pub(crate) platform: String,
    pub(crate) build_rev: String,
    pub(crate) device_region: Option<String>,
    pub(crate) session_id: String,
    pub(crate) network_type: String,
    pub(crate) recommended_probability: f64,
    pub(crate) custom_probability: f64,
    pub(crate) custom_hostnames: Vec<String>,
    pub(crate) inactive: Duration,
    pub(crate) dial_timeout: Duration,
    pub(crate) test_fetch_address: Option<String>,
    pub(crate) tls_shape: crate::psiphon_ssh::TlsShape,
}

#[derive(Clone, Debug)]
struct ProxyEntry {
    dial_ipv4: SocketAddr,
    dial_ipv6: Option<SocketAddr>,
    recommended_sni: String,
    recommended_sni_regex: String,
    obfuscation_key: Vec<u8>,
    verify_pin: Vec<u8>,
    verify_server_name: String,
}

/// One configured proxy; concurrent dials share its counters and replay slot.
pub(crate) struct Client {
    config: Config,
    entry: ProxyEntry,
    sponsor: Vec<u8>,
    platform: u8,
    build_rev: Vec<u8>,
    session_id: Vec<u8>,
    network: u8,
    connection: AtomicI64,
    replay: Mutex<Option<String>>,
    failed_until: Mutex<Option<Instant>>,
}

impl Client {
    /// Decode and validate the signed entry once, so a bad entry is one line at startup.
    pub(crate) fn new(config: Config) -> Result<Self, String> {
        let encoded = ferrox_core::b64::decode(config.entry.trim().as_bytes())
            .ok_or_else(|| "psiphon light: LightProxyEntry is not base64".to_owned())?;
        let entry = decode_entry(&encoded)?;
        let sponsor = crate::psiphon::hex_decode(&config.sponsor)
            .ok_or_else(|| "psiphon light: SponsorId is not hex".to_owned())?;
        let build_rev = crate::psiphon::hex_decode(&config.build_rev)
            .ok_or_else(|| "psiphon light: ClientBuildRev is not hex".to_owned())?;
        let session_id = crate::psiphon::hex_decode(&config.session_id)
            .ok_or_else(|| "psiphon light: SessionID is not hex".to_owned())?;
        Ok(Self {
            platform: encode_platform(&config.platform),
            network: encode_network(&config.network_type),
            sponsor,
            build_rev,
            session_id,
            config,
            entry,
            connection: AtomicI64::new(0),
            replay: Mutex::new(None),
            failed_until: Mutex::new(None),
        })
    }

    /// The tunnel liveness threshold the reference applies before falling back.
    pub(crate) fn inactive(&self) -> Duration {
        self.config.inactive
    }

    /// In test-fetch mode only that address is routed through the proxy.
    pub(crate) fn routes(&self, host: &str, port: u16) -> bool {
        match self.config.test_fetch_address.as_deref() {
            Some(address) => normalize_destination(host, port).is_ok_and(|target| {
                normalize_configured_address(address).is_some_and(|configured| configured == target)
            }),
            None => true,
        }
    }

    /// Dial the destination through the proxy and return the loopback socket the
    /// existing direct relay copies to and from.
    pub(crate) fn dial(
        &self,
        host: &str,
        port: u16,
        proxy: Option<&crate::psiphon_ssh::Proxy>,
    ) -> Result<TcpStream, String> {
        if lock(&self.failed_until).is_some_and(|until| Instant::now() < until) {
            return Err("psiphon light: cooling down after a failed dial".to_owned());
        }
        let result = self.dial_once(host, port, proxy);
        if result.is_err() {
            *lock(&self.replay) = None;
            *lock(&self.failed_until) = Some(Instant::now() + FAILURE_COOLDOWN);
        } else {
            *lock(&self.failed_until) = None;
        }
        result
    }

    /// The dial body, after the failure cooldown check.
    fn dial_once(
        &self,
        host: &str,
        port: u16,
        proxy: Option<&crate::psiphon_ssh::Proxy>,
    ) -> Result<TcpStream, String> {
        let destination = normalize_destination(host, port)?;
        let connection = self.connection.fetch_add(1, Ordering::Relaxed) + 1;
        let started = Instant::now();
        let (tcp, ipv6) = self.tcp_connect(proxy)?;
        let tcp_duration = started.elapsed();
        let _ = tcp.set_nodelay(true);
        let _ = tcp.set_read_timeout(Some(self.config.dial_timeout));
        let _ = tcp.set_write_timeout(Some(self.config.dial_timeout));

        let passthrough =
            crate::psiphon_ssh::tls_passthrough(&crate::psiphon::hex(&self.entry.obfuscation_key))?;
        let sni = self.select_sni();
        let tls = TlsConfig {
            server_name: sni.clone(),
            insecure: true,
            fingerprint: Some(self.config.tls_shape.fingerprint()),
            client_random: Some(passthrough),
            ..TlsConfig::default()
        };
        let tls_started = Instant::now();
        let mut session = ferrox_core::tls::connect(&tls, tcp)
            .map_err(|error| format!("psiphon light TLS: {error}"))?;
        session
            .handshake()
            .map_err(|error| format!("psiphon light TLS handshake: {error}"))?;
        let tls_duration = tls_started.elapsed();
        let leaf = session
            .peer_leaf()
            .ok_or_else(|| "psiphon light: the proxy presented no certificate".to_owned())?;
        let digest = ferrox_core::foxy::pin::digest(leaf)
            .ok_or_else(|| "psiphon light: the proxy certificate has no key".to_owned())?;
        if digest.as_slice() != self.entry.verify_pin.as_slice() {
            return Err("psiphon light: the proxy certificate pin does not match".to_owned());
        }
        if !self.entry.verify_server_name.is_empty()
            && !verify_name(leaf, &self.entry.verify_server_name)
        {
            return Err(format!(
                "psiphon light: the proxy certificate does not name {}",
                self.entry.verify_server_name
            ));
        }
        let _ = session.get_ref().set_read_timeout(Some(POLL));
        let _ = session.get_ref().set_write_timeout(Some(IO_TIMEOUT));

        let header = self.header(connection, &destination, tcp_duration, tls_duration)?;
        let shutdown = session.get_ref().try_clone().ok();
        let stream = LightStream::new(session, header).with_shutdown(shutdown);
        let local = loopback(stream, self.config.dial_timeout)?;
        *lock(&self.replay) = Some(sni);
        let _ = ipv6;
        Ok(local)
    }

    /// Dial the proxy, racing the v4 and v6 addresses when both are configured.
    fn tcp_connect(
        &self,
        proxy: Option<&crate::psiphon_ssh::Proxy>,
    ) -> Result<(TcpStream, bool), String> {
        if let Some(ipv6) = self.entry.dial_ipv6 {
            let done = Arc::new(AtomicBool::new(false));
            let (sender, receiver) = std::sync::mpsc::channel();
            for (address, is_ipv6) in [(self.entry.dial_ipv4, false), (ipv6, true)] {
                let sender = sender.clone();
                let done = Arc::clone(&done);
                let proxy = proxy.cloned();
                let timeout = self.config.dial_timeout;
                let _ = std::thread::Builder::new()
                    .name("psiphon-light-dial".to_owned())
                    .spawn(move || {
                        let result = connect_one(address, proxy.as_ref(), timeout);
                        if done.load(Ordering::Acquire) {
                            return;
                        }
                        if result.is_ok() {
                            done.store(true, Ordering::Release);
                        }
                        let _ = sender.send((result, is_ipv6));
                    });
            }
            drop(sender);
            let mut last = "psiphon light: no address answered".to_owned();
            for _ in 0..2 {
                match receiver.recv_timeout(self.config.dial_timeout + Duration::from_millis(100)) {
                    Ok((Ok(stream), is_ipv6)) => {
                        done.store(true, Ordering::Release);
                        return Ok((stream, is_ipv6));
                    }
                    Ok((Err(error), _)) => last = error,
                    Err(_) => break,
                }
            }
            return Err(last);
        }
        connect_one(self.entry.dial_ipv4, proxy, self.config.dial_timeout)
            .map(|stream| (stream, false))
    }

    /// Draw the cover name, reusing the name a successful dial remembered.
    fn select_sni(&self) -> String {
        if let Some(replay) = lock(&self.replay).clone() {
            return replay;
        }
        let has_recommended =
            !self.entry.recommended_sni_regex.is_empty() || !self.entry.recommended_sni.is_empty();
        if has_recommended && coin(self.config.recommended_probability) {
            if !self.entry.recommended_sni_regex.is_empty() {
                return crate::psiphon_ssh::random_hostname(&self.entry.recommended_sni_regex)
                    .unwrap_or_else(fallback_hostname);
            }
            return self.entry.recommended_sni.clone();
        }
        if coin(self.config.custom_probability) && !self.config.custom_hostnames.is_empty() {
            let draw = usize::from(u16::from_be_bytes(crate::psiphon_ssh::dial_random::<2>()));
            let index = draw % self.config.custom_hostnames.len();
            if let Some(name) =
                crate::psiphon_ssh::random_hostname(&self.config.custom_hostnames[index])
            {
                return name;
            }
        }
        fallback_hostname()
    }

    /// Build the versioned CBOR header the first write carries.
    fn header(
        &self,
        connection: i64,
        destination: &str,
        tcp_duration: Duration,
        tls_duration: Duration,
    ) -> Result<Vec<u8>, String> {
        let mut fields = Vec::with_capacity(12);
        if !self.sponsor.is_empty() {
            fields.push((Value::UInt(1), Value::Bytes(self.sponsor.clone())));
        }
        if self.platform != 0 {
            fields.push((Value::UInt(2), Value::UInt(u64::from(self.platform))));
        }
        if !self.build_rev.is_empty() {
            fields.push((Value::UInt(3), Value::Bytes(self.build_rev.clone())));
        }
        if let Some(region) = self.config.device_region.as_deref() {
            let region: String = region.chars().take(2).collect();
            if !region.is_empty() {
                fields.push((Value::UInt(4), Value::Text(region)));
            }
        }
        if !self.session_id.is_empty() {
            fields.push((Value::UInt(5), Value::Bytes(self.session_id.clone())));
        }
        if self.config.tracker != 0 {
            fields.push((Value::UInt(6), Value::Int(self.config.tracker)));
        }
        if self.network != 0 {
            fields.push((Value::UInt(7), Value::UInt(u64::from(self.network))));
        }
        if connection != 0 {
            fields.push((Value::UInt(8), Value::Int(connection)));
        }
        fields.push((Value::UInt(9), Value::Text(destination.to_owned())));
        let tcp_nanos = i64::try_from(tcp_duration.as_nanos()).unwrap_or(i64::MAX);
        if tcp_nanos != 0 {
            fields.push((Value::UInt(11), Value::Int(tcp_nanos)));
        }
        let tls_nanos = i64::try_from(tls_duration.as_nanos()).unwrap_or(i64::MAX);
        if tls_nanos != 0 {
            fields.push((Value::UInt(12), Value::Int(tls_nanos)));
        }
        let cbor = encode(&Value::Map(fields));
        let size = u16::try_from(cbor.len())
            .map_err(|_| "psiphon light: header exceeds 65535 bytes".to_owned())?;
        let mut wire = Vec::with_capacity(3 + cbor.len());
        wire.push(VERSION);
        wire.extend_from_slice(&size.to_be_bytes());
        wire.extend_from_slice(&cbor);
        Ok(wire)
    }
}

/// Decode the signed entry's proxy fields and TLS pin.
fn decode_entry(encoded: &[u8]) -> Result<ProxyEntry, String> {
    let (value, used) =
        decode(encoded).ok_or_else(|| "psiphon light: LightProxyEntry is not CBOR".to_owned())?;
    if used != encoded.len() {
        return Err("psiphon light: LightProxyEntry has trailing bytes".to_owned());
    }
    let entry = value
        .get(2)
        .ok_or_else(|| "psiphon light: LightProxyEntry has no proxy entry".to_owned())?;
    let protocol = entry.get(1).and_then(Value::text).unwrap_or_default();
    if protocol != PROTOCOL {
        return Err(format!(
            "psiphon light: proxy protocol {protocol:?} is not {PROTOCOL}"
        ));
    }
    let dial_ipv4 = parse_address(
        entry.get(2).and_then(Value::text).unwrap_or_default(),
        false,
    )?;
    let dial_ipv6 = match entry.get(7).and_then(Value::text).unwrap_or_default() {
        "" => None,
        text => Some(parse_address(text, true)?),
    };
    let obfuscation_key = entry
        .get(4)
        .and_then(Value::bytes)
        .filter(|key| !key.is_empty())
        .ok_or_else(|| "psiphon light: proxy entry has no obfuscation key".to_owned())?
        .to_vec();
    let verify_pin = entry
        .get(5)
        .and_then(Value::bytes)
        .filter(|pin| !pin.is_empty())
        .ok_or_else(|| "psiphon light: proxy entry has no verify pin".to_owned())?
        .to_vec();
    Ok(ProxyEntry {
        dial_ipv4,
        dial_ipv6,
        recommended_sni: entry
            .get(3)
            .and_then(Value::text)
            .unwrap_or_default()
            .to_owned(),
        recommended_sni_regex: entry
            .get(8)
            .and_then(Value::text)
            .unwrap_or_default()
            .to_owned(),
        obfuscation_key,
        verify_pin,
        verify_server_name: entry
            .get(6)
            .and_then(Value::text)
            .unwrap_or_default()
            .to_owned(),
    })
}

/// The reference's pins-only verifier still checks `VerifyServerName` against
/// the leaf's SANs, then its CN; dates are not checked.
fn verify_name(leaf: &[u8], expected: &str) -> bool {
    let mut names = Vec::new();
    collect_names(leaf, 0, leaf.len(), 0, &mut names);
    names.iter().any(|name| matches_name(name, expected))
}

/// Collect every DNS name in one certificate DER element.
fn collect_names(der: &[u8], at: usize, end: usize, depth: usize, out: &mut Vec<String>) {
    if depth > 32 {
        return;
    }
    let mut at = at;
    while at < end {
        let Some((tag, body, next)) = element(der, at) else {
            return;
        };
        if tag == 0x06 && der.get(body..body + 3) == Some(&[0x55, 0x1d, 0x11][..]) {
            let mut after = next;
            if let Some((0x01, _, after_bool)) = element(der, after) {
                after = after_bool;
            }
            if let Some((0x04, body, end)) = element(der, after) {
                collect_general_names(der, body, end, out);
            }
        } else if tag == 0x06 && der.get(body..body + 3) == Some(&[0x55, 0x04, 0x03][..]) {
            if let Some((0x0c | 0x13 | 0x16, body, end)) = element(der, next) {
                out.push(String::from_utf8_lossy(&der[body..end]).into_owned());
            }
        }
        if tag & 0x20 != 0 {
            collect_names(der, body, next, depth + 1, out);
        }
        at = next;
    }
}

/// Collect the DNS names in one `GeneralNames` sequence.
fn collect_general_names(der: &[u8], at: usize, end: usize, out: &mut Vec<String>) {
    let mut at = at;
    while at < end {
        let Some((tag, body, next)) = element(der, at) else {
            return;
        };
        if tag == 0x82 {
            out.push(String::from_utf8_lossy(&der[body..next]).into_owned());
        }
        at = next;
    }
}

/// Read one DER tag and its body bounds.
fn element(der: &[u8], at: usize) -> Option<(u8, usize, usize)> {
    let tag = *der.get(at)?;
    let first = *der.get(at + 1)?;
    let (length, body) = if first < 0x80 {
        (usize::from(first), at + 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 8 {
            return None;
        }
        let mut length = 0usize;
        for index in 0..count {
            length = length
                .checked_mul(256)?
                .checked_add(usize::from(*der.get(at + 2 + index)?))?;
        }
        (length, at + 2 + count)
    };
    let end = body.checked_add(length)?;
    (end <= der.len()).then_some((tag, body, end))
}

/// Match a certificate name, including a one-label wildcard.
fn matches_name(pattern: &str, name: &str) -> bool {
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return name.strip_suffix(suffix).is_some_and(|prefix| {
            prefix
                .strip_suffix('.')
                .is_some_and(|label| !label.is_empty() && !label.contains('.'))
        });
    }
    pattern == name
}

/// Parse a configured proxy address and check its IP family.
fn parse_address(text: &str, ipv6: bool) -> Result<SocketAddr, String> {
    let address: SocketAddr = text
        .parse()
        .map_err(|_| format!("psiphon light: proxy address {text:?} is not host:port"))?;
    if ipv6 != address.is_ipv6() {
        return Err(format!(
            "psiphon light: proxy address {text:?} is the wrong IP family"
        ));
    }
    Ok(address)
}

/// Connect one proxy address, directly or through the configured upstream proxy.
fn connect_one(
    address: SocketAddr,
    proxy: Option<&crate::psiphon_ssh::Proxy>,
    timeout: Duration,
) -> Result<TcpStream, String> {
    match proxy {
        Some(proxy) => proxy.connect(address, timeout),
        None => TcpStream::connect_timeout(&address, timeout)
            .map_err(|error| format!("psiphon light: connect {address}: {error}")),
    }
}

/// Normalize a configured destination before comparing it.
fn normalize_configured_address(text: &str) -> Option<String> {
    let text = text.trim();
    if let Ok(address) = text.parse::<SocketAddr>() {
        return Some(address.to_string());
    }
    let (host, port) = text.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    normalize_destination(host.trim_matches(|ch| ch == '[' || ch == ']'), port).ok()
}

/// Normalize a runtime destination to lowercase host and decimal port.
fn normalize_destination(host: &str, port: u16) -> Result<String, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port).to_string());
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err("psiphon light: destination host is empty".to_owned());
    }
    Ok(format!("{host}:{port}"))
}

/// Map the reference platform name to its header code.
fn encode_platform(platform: &str) -> u8 {
    let platform = platform.to_ascii_lowercase();
    if platform.contains("ios") {
        1
    } else if platform.contains("android") {
        2
    } else if platform.contains("windows") {
        3
    } else {
        0
    }
}

/// Map the reference network type to its header code.
fn encode_network(network: &str) -> u8 {
    match network.to_ascii_uppercase().as_str() {
        "WIFI" => 1,
        "MOBILE" => 2,
        "WIRED" => 3,
        "VPN" => 4,
        "UNKNOWN" => 5,
        _ => 0,
    }
}

/// Draw the fallback cover name.
fn fallback_hostname() -> String {
    crate::psiphon_ssh::random_hostname(r"[a-z]{8,16}\.(com|net|org)")
        .unwrap_or_else(|| "www.example.com".to_owned())
}

/// Draw one probability coin from the dial seed.
fn coin(probability: f64) -> bool {
    if probability >= 1.0 {
        return true;
    }
    if probability <= 0.0 {
        return false;
    }
    f64::from(u16::from_be_bytes(crate::psiphon_ssh::dial_random::<2>())) / 65_536.0 < probability
}

/// Take a lock, recovering the guard after a panic.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The loopback side of a light connection: a local socket the direct relay
/// already knows how to copy, so no new flow kind is needed.
fn loopback<T: Read + Write + ShutdownWrite + Send + 'static>(
    stream: T,
    timeout: Duration,
) -> Result<TcpStream, String> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| format!("psiphon light loopback bind: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("psiphon light loopback address: {error}"))?;
    let local = TcpStream::connect_timeout(&address, timeout)
        .map_err(|error| format!("psiphon light loopback connect: {error}"))?;
    let _ = local.set_nodelay(true);
    let _ = local.set_read_timeout(None);
    let _ = local.set_write_timeout(None);
    let local_address = local
        .local_addr()
        .map_err(|error| format!("psiphon light loopback local address: {error}"))?;
    std::thread::Builder::new()
        .name("psiphon-light-relay".to_owned())
        .spawn(move || loop {
            let Ok((peer, _)) = listener.accept() else {
                return;
            };
            if peer.peer_addr().ok() != Some(local_address) {
                continue;
            }
            relay(stream, peer);
            return;
        })
        .map_err(|error| format!("psiphon light loopback thread: {error}"))?;
    Ok(local)
}

/// A relay stream that can pass an upload EOF to the proxy without closing reads.
trait ShutdownWrite {
    /// Half-close the proxy-facing write side.
    fn shutdown_write(&mut self);
    /// The number of framed bytes not yet handed to the TLS writer.
    fn queued(&self) -> usize;
}

impl<T> ShutdownWrite for LightStream<T> {
    /// Half-close the proxy-facing write side.
    fn shutdown_write(&mut self) {
        if let Some(shutdown) = self.shutdown.as_ref() {
            let _ = shutdown.shutdown(std::net::Shutdown::Write);
        }
    }

    /// The number of framed bytes not yet handed to the TLS writer.
    fn queued(&self) -> usize {
        self.pending_len()
    }
}

/// Service both directions over one framed TLS stream, keeping partial writes.
fn relay<T: Read + Write + ShutdownWrite>(mut stream: T, mut peer: TcpStream) {
    let _ = peer.set_nodelay(true);
    let _ = peer.set_read_timeout(Some(POLL));
    let _ = peer.set_write_timeout(Some(POLL));
    let mut up = vec![0u8; BUFFER];
    let mut down = vec![0u8; BUFFER];
    let mut down_at = 0usize;
    let mut down_len = 0usize;
    let mut peer_eof = false;
    let mut upload_eof = false;
    let mut stream_eof = false;
    loop {
        if down_at < down_len {
            match peer.write(&down[down_at..down_len]) {
                Ok(0) => return,
                Ok(count) => down_at += count,
                Err(error) if idle(&error) => {}
                Err(_) => return,
            }
            if down_at == down_len {
                down_at = 0;
                down_len = 0;
            }
        }
        match stream.flush() {
            Ok(()) => {}
            Err(error) if idle(&error) => {}
            Err(_) => return,
        }
        let upload_blocked = stream.queued() > 0;
        if upload_eof && !upload_blocked {
            stream.shutdown_write();
            upload_eof = false;
        }
        if !peer_eof && !upload_blocked && pending(&peer) {
            match peer.read(&mut up) {
                Ok(0) => {
                    peer_eof = true;
                    upload_eof = true;
                }
                Ok(count) => {
                    if stream.write_all(&up[..count]).is_err() {
                        return;
                    }
                }
                Err(error) if idle(&error) => {}
                Err(_) => return,
            }
        }
        if down_at == down_len && !stream_eof && (upload_blocked || !pending(&peer)) {
            match stream.read(&mut down) {
                Ok(0) => stream_eof = true,
                Ok(count) => {
                    down_len = count;
                    down_at = 0;
                }
                Err(error) if idle(&error) => {}
                Err(_) => return,
            }
        }
        if stream_eof && down_at == down_len {
            return;
        }
    }
}

/// Whether the loopback peer has bytes ready, without consuming them.
fn pending(peer: &TcpStream) -> bool {
    let _ = peer.set_nonblocking(true);
    let ready = matches!(peer.peek(&mut [0u8; 1]), Ok(count) if count > 0);
    let _ = peer.set_nonblocking(false);
    ready
}

/// Whether a read timeout means the other direction should get a turn.
fn idle(error: &io::Error) -> bool {
    ferrox_core::tls::TlsError::is_timeout(error)
}

/// The reference's light framing: a first write carries the header and a padded
/// payload, then a stop sentinel and ordinary payload; reads mirror it.
pub(crate) struct LightStream<T> {
    inner: T,
    header: Vec<u8>,
    header_sent: bool,
    padding_done: bool,
    wire: Vec<u8>,
    wire_at: usize,
    payload: std::ops::Range<usize>,
    pending: Vec<u8>,
    pending_at: usize,
    shutdown: Option<TcpStream>,
}

impl<T> LightStream<T> {
    /// Wrap the TLS stream with the header its first write must carry.
    fn new(inner: T, header: Vec<u8>) -> Self {
        Self {
            inner,
            header,
            header_sent: false,
            padding_done: false,
            wire: Vec::with_capacity(BUFFER),
            wire_at: 0,
            payload: 0..0,
            pending: Vec::new(),
            pending_at: 0,
            shutdown: None,
        }
    }

    /// Keep a transport clone so an upload EOF can half-close the proxy socket.
    fn with_shutdown(mut self, shutdown: Option<TcpStream>) -> Self {
        self.shutdown = shutdown;
        self
    }

    /// The number of framed bytes not yet handed to the TLS writer.
    fn pending_len(&self) -> usize {
        self.pending.len() - self.pending_at
    }
}

impl<T: Read> Read for LightStream<T> {
    /// Read framed payload, keeping the wire buffer's consumed prefix as an offset.
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if !self.payload.is_empty() {
                let count = (self.payload.end - self.payload.start).min(out.len());
                out[..count]
                    .copy_from_slice(&self.wire[self.payload.start..self.payload.start + count]);
                self.payload.start += count;
                return Ok(count);
            }
            self.compact();
            if self.padding_done {
                if self.wire_at == self.wire.len() {
                    return self.inner.read(out);
                }
                let count = (self.wire.len() - self.wire_at).min(out.len());
                out[..count].copy_from_slice(&self.wire[self.wire_at..self.wire_at + count]);
                self.wire_at += count;
                return Ok(count);
            }
            let at = self.wire_at;
            if self.wire.len() - at < 2 {
                if !fill(&mut self.inner, &mut self.wire)? {
                    return Ok(0);
                }
                continue;
            }
            let padding = u16::from_be_bytes([self.wire[at], self.wire[at + 1]]);
            if padding == STOP_PADDING {
                self.wire_at += 2;
                self.padding_done = true;
                continue;
            }
            if self.wire.len() - at < 4 {
                if !fill(&mut self.inner, &mut self.wire)? {
                    return Ok(0);
                }
                continue;
            }
            let payload = u16::from_be_bytes([self.wire[at + 2], self.wire[at + 3]]);
            if payload == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "psiphon light: zero payload",
                ));
            }
            let frame = 4 + usize::from(padding) + usize::from(payload);
            if self.wire.len() - at < frame {
                if !fill(&mut self.inner, &mut self.wire)? {
                    return Ok(0);
                }
                continue;
            }
            let start = at + 4 + usize::from(padding);
            self.payload = start..start + usize::from(payload);
            self.wire_at = self.payload.end;
        }
    }
}

impl<T> LightStream<T> {
    /// Drop the consumed prefix once it is worth the move, so a long run of frames
    /// does not carry every byte it has already returned.
    fn compact(&mut self) {
        if self.wire_at == 0 {
            return;
        }
        if self.wire_at == self.wire.len() {
            self.wire.clear();
            self.wire_at = 0;
            return;
        }
        if self.wire_at < BUFFER / 2 && self.wire.len() < self.wire.capacity() {
            return;
        }
        let live = self.wire.len() - self.wire_at;
        self.wire.copy_within(self.wire_at.., 0);
        self.wire.truncate(live);
        self.wire_at = 0;
    }
}

/// Read one frame into `wire`, returning whether more frames remain.
fn fill<T: Read>(inner: &mut T, wire: &mut Vec<u8>) -> io::Result<bool> {
    let mut temp = [0u8; BUFFER];
    match inner.read(&mut temp) {
        Ok(0) => Ok(false),
        Ok(count) => {
            wire.extend_from_slice(&temp[..count]);
            Ok(true)
        }
        Err(error) => Err(error),
    }
}

impl<T: Write> Write for LightStream<T> {
    /// Queue payload, padding the first write and splitting large records.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.padding_done {
            self.pending.extend_from_slice(buf);
            self.drain()?;
            return Ok(buf.len());
        }
        let mut frame = Vec::with_capacity(self.header.len() + buf.len() + 2 + 17);
        if !self.header_sent {
            frame.extend_from_slice(&self.header);
            self.header_sent = true;
        }
        let mut size = frame.len() + buf.len() + 2 + 17;
        if size > PADDING_MAX {
            frame.extend_from_slice(&STOP_PADDING.to_be_bytes());
            self.padding_done = true;
        } else {
            size += 2;
            let min = PADDING_MIN.saturating_sub(size);
            let max = PADDING_MAX.saturating_sub(size).max(min);
            let draw = usize::from(u16::from_be_bytes(crate::psiphon_ssh::dial_random::<2>()));
            let padding = min + draw % (max - min + 1);
            if padding >= usize::from(STOP_PADDING) || buf.len() > usize::from(u16::MAX) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "psiphon light: oversized frame",
                ));
            }
            frame.extend_from_slice(&(padding as u16).to_be_bytes());
            frame.extend_from_slice(&(buf.len() as u16).to_be_bytes());
            frame.resize(frame.len() + padding, 0);
        }
        frame.extend_from_slice(buf);
        self.pending.extend_from_slice(&frame);
        self.drain()?;
        Ok(buf.len())
    }

    /// Flush queued bytes and the TLS writer.
    fn flush(&mut self) -> io::Result<()> {
        if !self.drain()? {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "psiphon light: upload is still pending",
            ));
        }
        self.inner.flush()
    }
}

impl<T: Write> LightStream<T> {
    /// Hand queued bytes to the TLS writer in 8-16 KiB records; false means a timeout.
    fn drain(&mut self) -> io::Result<bool> {
        while self.pending_at < self.pending.len() {
            let rest = &self.pending[self.pending_at..];
            let count = if rest.len() > MAX_RECORD {
                let min = MAX_RECORD / 2;
                let draw = usize::from(u16::from_be_bytes(crate::psiphon_ssh::dial_random::<2>()));
                min + draw % (MAX_RECORD - min + 1)
            } else {
                rest.len()
            };
            match self.inner.write(&rest[..count]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "psiphon light: TLS writer accepted no bytes",
                    ));
                }
                Ok(written) => self.pending_at += written,
                Err(error) if idle(&error) => return Ok(false),
                Err(error) => return Err(error),
            }
        }
        self.pending.clear();
        self.pending_at = 0;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a test proxy entry with the given fields.
    fn entry_bytes(fields: Vec<(Value, Value)>) -> Vec<u8> {
        encode(&Value::Map(vec![
            (Value::UInt(1), Value::Bytes(Vec::new())),
            (Value::UInt(2), Value::Map(fields)),
        ]))
    }

    /// The proxy fields a valid test entry carries.
    fn proxy_fields() -> Vec<(Value, Value)> {
        vec![
            (Value::UInt(1), Value::Text("TLS".to_owned())),
            (Value::UInt(2), Value::Text("192.0.2.1:443".to_owned())),
            (Value::UInt(3), Value::Text("edge.example".to_owned())),
            (Value::UInt(4), Value::Bytes(vec![1, 2, 3])),
            (Value::UInt(5), Value::Bytes(vec![7; 32])),
        ]
    }

    #[test]
    fn a_signed_proxy_entry_decodes() {
        let entry = decode_entry(&entry_bytes(proxy_fields())).expect("entry");
        assert_eq!(entry.dial_ipv4, "192.0.2.1:443".parse().expect("address"));
        assert_eq!(entry.recommended_sni, "edge.example");
        assert_eq!(entry.verify_pin, vec![7; 32]);
    }

    #[test]
    fn an_entry_with_the_wrong_protocol_is_refused() {
        let mut fields = proxy_fields();
        fields[0] = (Value::UInt(1), Value::Text("SSH".to_owned()));
        assert!(decode_entry(&entry_bytes(fields)).is_err());
    }

    #[test]
    fn an_entry_without_a_pin_is_refused() {
        let mut fields = proxy_fields();
        fields.retain(|(key, _)| key != &Value::UInt(5));
        assert!(decode_entry(&entry_bytes(fields)).is_err());
    }

    #[test]
    fn the_header_starts_with_the_version_and_round_trips() {
        let config = Config {
            entry: String::new(),
            tracker: 7,
            sponsor: "0102".to_owned(),
            platform: "Android".to_owned(),
            build_rev: String::new(),
            device_region: Some("US".to_owned()),
            session_id: String::new(),
            network_type: "WIFI".to_owned(),
            recommended_probability: 0.0,
            custom_probability: 0.0,
            custom_hostnames: Vec::new(),
            inactive: Duration::from_secs(30),
            dial_timeout: Duration::from_secs(20),
            test_fetch_address: None,
            tls_shape: crate::psiphon_ssh::TlsShape::default(),
        };
        let client = Client {
            platform: encode_platform(&config.platform),
            network: encode_network(&config.network_type),
            sponsor: vec![1, 2],
            build_rev: Vec::new(),
            session_id: Vec::new(),
            entry: ProxyEntry {
                dial_ipv4: "192.0.2.1:443".parse().expect("address"),
                dial_ipv6: None,
                recommended_sni: String::new(),
                recommended_sni_regex: String::new(),
                obfuscation_key: vec![1],
                verify_pin: vec![7; 32],
                verify_server_name: String::new(),
            },
            config,
            connection: AtomicI64::new(0),
            replay: Mutex::new(None),
            failed_until: Mutex::new(None),
        };
        let header = client
            .header(
                3,
                "example.com:443",
                Duration::from_nanos(1),
                Duration::from_nanos(2),
            )
            .expect("header");
        assert_eq!(header[0], VERSION);
        let size = usize::from(u16::from_be_bytes([header[1], header[2]]));
        let (value, used) = decode(&header[3..]).expect("cbor");
        assert_eq!(used, size);
        assert_eq!(value.get(1), Some(&Value::Bytes(vec![1, 2])));
        assert_eq!(value.get(2), Some(&Value::UInt(2)));
        assert_eq!(value.get(4), Some(&Value::Text("US".to_owned())));
        assert_eq!(value.get(6), Some(&Value::UInt(7)));
        assert_eq!(value.get(7), Some(&Value::UInt(1)));
        assert_eq!(value.get(8), Some(&Value::UInt(3)));
        assert_eq!(
            value.get(9),
            Some(&Value::Text("example.com:443".to_owned()))
        );
        assert!(value.get(10).is_none());
        assert_eq!(value.get(11), Some(&Value::UInt(1)));
        assert_eq!(value.get(12), Some(&Value::UInt(2)));
    }

    #[test]
    fn a_server_name_matches_san_and_cn_wildcards() {
        assert!(matches_name("edge.example", "edge.example"));
        assert!(matches_name("*.example", "edge.example"));
        assert!(!matches_name("*.example", "example"));
        assert!(!matches_name("*.example", "a.edge.example"));
    }

    #[test]
    fn a_configured_test_address_is_normalized_before_it_is_compared() {
        assert_eq!(
            normalize_configured_address("Example.COM.:443").as_deref(),
            Some("example.com:443")
        );
        assert_eq!(
            normalize_configured_address("[2001:db8::1]:443").as_deref(),
            Some("[2001:db8::1]:443")
        );
    }

    #[test]
    fn destination_addresses_are_normalized() {
        assert_eq!(
            normalize_destination("Example.COM.", 443).expect("host"),
            "example.com:443"
        );
        assert_eq!(
            normalize_destination("2001:db8::1", 443).expect("ip"),
            "[2001:db8::1]:443"
        );
    }

    #[test]
    fn a_padded_frame_and_stop_sentinel_read_back_as_payload() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&3u16.to_be_bytes());
        wire.extend_from_slice(&5u16.to_be_bytes());
        wire.extend_from_slice(&[0; 3]);
        wire.extend_from_slice(b"hello");
        wire.extend_from_slice(&STOP_PADDING.to_be_bytes());
        wire.extend_from_slice(b"plain");
        let mut stream = LightStream::new(io::Cursor::new(wire), Vec::new());
        let mut out = [0u8; 5];
        stream.read_exact(&mut out).expect("first");
        assert_eq!(&out, b"hello");
        let mut rest = [0u8; 5];
        stream.read_exact(&mut rest).expect("second");
        assert_eq!(&rest, b"plain");
    }

    /// The read shape before the offset cursor: each frame's payload was collected
    /// out of the wire, so every frame paid one buffer.
    fn draining_frames(wire: &mut Vec<u8>, frames: usize) -> usize {
        let mut bytes = 0;
        for _ in 0..frames {
            let padding = u16::from_be_bytes([wire[0], wire[1]]);
            assert_ne!(padding, STOP_PADDING);
            let payload = u16::from_be_bytes([wire[2], wire[3]]);
            wire.drain(..4 + usize::from(padding));
            let frame: Vec<u8> = wire.drain(..usize::from(payload)).collect();
            bytes += frame.len();
        }
        bytes
    }

    /// The offset cursor keeps one wire buffer: the old shape collected a buffer per
    /// frame, while the new read returns the frame's bytes where they already lie.
    #[test]
    fn a_frame_read_keeps_one_wire_buffer() {
        let frames = 64;
        let payload = b"data";
        let mut wire = Vec::new();
        for _ in 0..frames {
            wire.extend_from_slice(&0u16.to_be_bytes());
            wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            wire.extend_from_slice(payload);
        }

        let mut old = wire.clone();
        let (old_bytes, old_counts) =
            ferrox_core::alloc_count::measure(|| draining_frames(&mut old, frames));
        assert_eq!(old_bytes, frames * payload.len());
        assert_eq!(
            old_counts.allocs, frames,
            "the old read collected a buffer per frame"
        );

        let mut stream = LightStream::new(io::Cursor::new(wire), Vec::new());
        let base = stream.wire.as_ptr();
        let capacity = stream.wire.capacity();
        let mut out = [0u8; 4];
        let ((), counts) = ferrox_core::alloc_count::measure(|| {
            for _ in 0..frames {
                stream.read_exact(&mut out).expect("frame");
                assert_eq!(&out, payload);
            }
        });
        assert_eq!(
            counts.allocs, 0,
            "the offset read allocates nothing: {counts:?}"
        );
        assert_eq!(stream.wire.as_ptr(), base, "the wire buffer did not move");
        assert_eq!(stream.wire.capacity(), capacity, "the wire capacity held");
    }

    /// A writer that reports one timeout before accepting bytes.
    struct SlowWriter {
        bytes: Vec<u8>,
        block: bool,
    }

    impl Write for SlowWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.block {
                self.block = false;
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_blocked_write_resumes_without_duplicating_bytes() {
        let mut stream = LightStream::new(
            SlowWriter {
                bytes: Vec::new(),
                block: true,
            },
            vec![0xaa, 0xbb],
        );
        stream.write_all(b"hello").expect("queued");
        assert!(stream.pending_len() > 0);
        stream.flush().expect("drained");
        assert_eq!(
            stream
                .inner
                .bytes
                .windows(5)
                .filter(|window| *window == b"hello")
                .count(),
            1
        );
    }

    #[test]
    fn the_first_write_pads_and_the_next_write_splits() {
        let mut stream = LightStream::new(Vec::new(), vec![0xaa, 0xbb]);
        stream.write_all(b"hello").expect("first");
        let wire = stream.inner;
        assert_eq!(&wire[..2], &[0xaa, 0xbb]);
        assert!(wire.len() + 17 >= PADDING_MIN);
        assert!(wire.len() + 17 <= PADDING_MAX);
        assert!(wire.windows(5).any(|window| window == b"hello"));
    }
}

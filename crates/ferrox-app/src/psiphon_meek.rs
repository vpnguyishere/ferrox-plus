//! The meek relay the native `Psiphon` lane rides for unfronted and CDN-fronted
//! entries: a loopback TCP stream whose bytes are carried in `POST /` requests.

use crate::psiphon_ssh::{
    current_dial_seed, derive_key, dial_fill, dial_random, dial_seed_scope, random, Proxy, Rc4,
    TlsShape, MAGIC, SEED_LENGTH,
};
use crate::psiphon_webrtc::WebRtcStream;
use aes::cipher::{KeyIvInit, StreamCipher};
use crypto_box::aead::{Aead, OsRng};
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use ferrox_core::tls::{ClientSession, RecordAlignment as _, TlsConfig, TlsProvider as _};
use hkdf::Hkdf;
use sha2::Sha256;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

pub(crate) const MAX_REQUEST_PAYLOAD: usize = 64 * 1024;
const LIMITED_READ_CHUNK: usize = 4 * 1024;
const MIN_COOKIE_PADDING: usize = 16;
const MAX_COOKIE_PADDING: usize = 256;
const POLL: Duration = Duration::from_millis(100);
const MAX_POLL: Duration = Duration::from_secs(5);
/// One stalled connect is a dead candidate, not the whole rotation's budget.
const MAX_CONNECT_ATTEMPT: Duration = Duration::from_secs(2);
/// A UDP front that drops datagrams without an ICMP report is also a dead
/// candidate; a full QUIC handshake fits in this budget on a slow link.
const MAX_HANDSHAKE_ATTEMPT: Duration = Duration::from_secs(5);
const POLL_GROWTH: f64 = 1.5;
const USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36";

const ALTERNATE_CONTENT_TYPES: &[&str] = &[
    "application/octet-stream",
    "audio/mpeg",
    "image/jpeg",
    "video/mpeg",
];

/// The per-connection meek choices the reference draws for the lifetime of
/// the relay: the cookie name, request content type, payload cap and the
/// probability a successful round trip drops the connection.
#[derive(Clone, Debug)]
struct Profile {
    /// The cookie name drawn for this connection.
    cookie_name: String,
    /// The request content type drawn for this connection.
    content_type: &'static str,
    /// The largest request body this connection may send.
    request_limit: usize,
    /// The chance a successful round trip drops the connection.
    redial_tls: f64,
    /// The payload padding this connection selected.
    payload_padding: Option<PaddingConfig>,
    /// The User-Agent this connection sends when the headers name none.
    user_agent: String,
}

/// The padding sizes and omission chance one connection drew.
#[derive(Clone, Copy, Debug)]
struct PaddingConfig {
    omit: f64,
    min: usize,
    max: usize,
}

type PaddingCipher = ctr::Ctr128BE<aes::Aes256>;

/// Derive one direction's padding header stream from the obfuscated key and cookie.
fn padding_cipher(
    obfuscated_key: &str,
    cookie: &str,
    direction: &[u8],
) -> Result<PaddingCipher, String> {
    let hkdf = Hkdf::<Sha256>::new(Some(cookie.as_bytes()), obfuscated_key.as_bytes());
    let mut key = [0u8; 32];
    hkdf.expand(direction, &mut key)
        .map_err(|_| "psiphon meek padding key".to_owned())?;
    PaddingCipher::new_from_slices(&key, &[0u8; 16])
        .map_err(|_| "psiphon meek padding cipher".to_owned())
}

/// Prepend padding to a request body, advancing the request cipher once per payload.
struct PaddingSender {
    cipher: PaddingCipher,
    config: PaddingConfig,
}

impl PaddingSender {
    fn new(
        obfuscated_key: &str,
        cookie: &str,
        direction: &[u8],
        config: PaddingConfig,
    ) -> Result<Self, String> {
        Ok(Self {
            cipher: padding_cipher(obfuscated_key, cookie, direction)?,
            config,
        })
    }

    /// A non-empty payload gets the no-padding prefix; an empty one may be padded or omitted.
    fn pad(&mut self, body: &[u8]) -> Result<Vec<u8>, String> {
        if body.is_empty() {
            if coin_probability(self.config.omit) {
                return Ok(Vec::new());
            }
            let span = self.config.max - self.config.min + 1;
            let size = self.config.min
                + usize::try_from(random_below(u64::try_from(span).unwrap_or(1))).unwrap_or(0);
            let mut header = [1u8, (size >> 8) as u8, size as u8];
            self.cipher.apply_keystream(&mut header);
            let mut out = Vec::with_capacity(header.len() + size);
            out.extend_from_slice(&header);
            out.resize(header.len() + size, 0);
            getrandom::fill(&mut out[header.len()..])
                .map_err(|error| format!("psiphon meek padding entropy: {error}"))?;
            return Ok(out);
        }
        let mut prefix = [0u8];
        self.cipher.apply_keystream(&mut prefix);
        let mut out = Vec::with_capacity(1 + body.len());
        out.push(prefix[0]);
        out.extend_from_slice(body);
        Ok(out)
    }
}

/// Strip padding from the start of a response body, advancing the response cipher.
struct PaddingReceiver {
    cipher: PaddingCipher,
}

impl PaddingReceiver {
    fn new(obfuscated_key: &str, cookie: &str, direction: &[u8]) -> Result<Self, String> {
        Ok(Self {
            cipher: padding_cipher(obfuscated_key, cookie, direction)?,
        })
    }

    fn strip(&mut self, body: &[u8]) -> Result<Vec<u8>, String> {
        let mut at = 0;
        loop {
            if at >= body.len() {
                return Ok(Vec::new());
            }
            let mut prefix = [body[at]];
            self.cipher.apply_keystream(&mut prefix);
            at += 1;
            match prefix[0] {
                0 => return Ok(body[at..].to_vec()),
                1 => {
                    let Some(size) = body.get(at..at + 2) else {
                        return Err("psiphon meek padding: truncated size".to_owned());
                    };
                    let mut size = [size[0], size[1]];
                    self.cipher.apply_keystream(&mut size);
                    at += 2;
                    let size = usize::from(u16::from_be_bytes(size));
                    if at + size > body.len() {
                        return Err("psiphon meek padding: truncated padding".to_owned());
                    }
                    at += size;
                }
                _ => return Err("psiphon meek padding: unknown prefix".to_owned()),
            }
        }
    }
}

/// One random coin with the given probability.
fn coin_probability(probability: f64) -> bool {
    if probability <= 0.0 {
        return false;
    }
    if probability >= 1.0 {
        return true;
    }
    f64::from(u16::from_be_bytes(dial_random::<2>())) / 65_536.0 < probability
}

/// A random value in `0..bound`.
fn random_below(bound: u64) -> u64 {
    if bound <= 1 {
        return 0;
    }
    u64::from_be_bytes(dial_random::<8>()) % bound
}

/// The reference's alternate cookie name: two to ten characters from `[a-z_]`.
fn alternate_cookie_name() -> String {
    let length = 2 + usize::from(dial_random::<1>()[0]) % 9;
    (0..length)
        .map(|_| {
            let draw = dial_random::<1>()[0] % 27;
            if draw == 26 {
                '_'
            } else {
                char::from(b'a' + draw)
            }
        })
        .collect()
}

/// Choose the reference's per-connection meek values from the lane shape.
fn profile(shape: &TlsShape, protocol: &str) -> Profile {
    let cookie_name = if coin_probability(shape.meek_alternate_cookie_name) {
        alternate_cookie_name()
    } else {
        char::from(b'A' + dial_random::<1>()[0] % 26).to_string()
    };
    let content_type = if coin_probability(shape.meek_alternate_content_type) {
        ALTERNATE_CONTENT_TYPES[usize::from(dial_random::<1>()[0]) % ALTERNATE_CONTENT_TYPES.len()]
    } else {
        ALTERNATE_CONTENT_TYPES[0]
    };
    let shaped = shape.meek_traffic_shaping_protocols.is_empty()
        || shape
            .meek_traffic_shaping_protocols
            .iter()
            .any(|name| name == protocol || name == &cookie_protocol(protocol));
    let (request_limit, redial_tls) = if shaped && coin_probability(shape.meek_traffic_shaping) {
        let low = shape.meek_min_limit_request.clamp(1, MAX_REQUEST_PAYLOAD);
        let high = shape
            .meek_max_limit_request
            .clamp(1, MAX_REQUEST_PAYLOAD)
            .max(low);
        let request_limit = low
            + usize::try_from(random_below(u64::try_from(high - low).unwrap_or(0) + 1))
                .unwrap_or(0);
        (request_limit, shape.meek_redial_tls)
    } else {
        (MAX_REQUEST_PAYLOAD, 0.0)
    };
    let payload_padding =
        if protocol.contains("MEEK") && coin_probability(shape.meek_payload_padding) {
            let min = shape.meek_payload_padding_min.min(65_533);
            Some(PaddingConfig {
                omit: shape.meek_payload_padding_omit,
                min,
                max: shape.meek_payload_padding_max.min(65_533).max(min),
            })
        } else {
            None
        };
    let request_limit = if payload_padding.is_some() {
        request_limit.saturating_sub(1).max(1)
    } else {
        request_limit
    };
    let user_agent = if coin_probability(shape.user_agent_probability) {
        crate::psiphon_user_agent::generate()
    } else {
        String::new()
    };
    Profile {
        cookie_name,
        content_type,
        request_limit,
        redial_tls,
        payload_padding,
        user_agent,
    }
}

/// Choose the HTTP/1 response body chunk size for the active buffer limit.
fn response_read_chunk(limit: bool) -> usize {
    if limit {
        LIMITED_READ_CHUNK
    } else {
        crate::foxy_account::DEFAULT_READ_CHUNK
    }
}

/// Choose the HTTP/3 response body chunk size for the active buffer limit.
fn h3_read_chunk(limit: bool) -> usize {
    if limit {
        LIMITED_READ_CHUNK
    } else {
        16 * 1024
    }
}

/// One server entry's meek front.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct Meek {
    pub(crate) dial: String,
    pub(crate) port: u16,
    pub(crate) host: String,
    pub(crate) sni: String,
    pub(crate) public_key: String,
    pub(crate) obfuscated_key: String,
    pub(crate) disable_sni: bool,
    pub(crate) alpn: Vec<Vec<u8>>,
    pub(crate) fronts: Vec<(String, u16)>,
    pub(crate) hosts: Vec<String>,
    pub(crate) https: bool,
    pub(crate) quic: bool,
    pub(crate) fronted: bool,
    pub(crate) protocol: &'static str,
    pub(crate) provider_id: Option<String>,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) dns: Vec<SocketAddr>,
    pub(crate) verify_server_names: Vec<String>,
    pub(crate) verify_pins: Vec<String>,
    pub(crate) shape: TlsShape,
}

/// Start the loopback relay and return the socket the SSH handshake rides.
pub(crate) fn connect(
    meek: &Meek,
    timeout: Duration,
    proxy: Option<&Proxy>,
    dns: &crate::psiphon_dns::Config,
    limit_buffer_sizes: bool,
) -> Result<TcpStream, String> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| format!("psiphon meek listener: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("psiphon meek listener: {error}"))?;
    let local = TcpStream::connect_timeout(&address, timeout)
        .map_err(|error| format!("psiphon meek loopback: {error}"))?;
    local
        .set_nodelay(true)
        .and_then(|()| local.set_read_timeout(Some(timeout)))
        .and_then(|()| local.set_write_timeout(Some(timeout)))
        .map_err(|error| format!("psiphon meek loopback: {error}"))?;
    let config = meek.clone();
    let proxy = proxy.cloned();
    let dns = dns.clone();
    let seed = current_dial_seed();
    std::thread::Builder::new()
        .name("psiphon-meek".to_owned())
        .spawn(move || {
            let _scope = seed.map(dial_seed_scope);
            match listener.accept() {
                Ok((socket, _)) => {
                    if let Err(why) = relay(
                        socket,
                        &config,
                        proxy.as_ref(),
                        timeout,
                        &dns,
                        limit_buffer_sizes,
                    ) {
                        eprintln!("psiphon: fronted-meek relay: {why}");
                    }
                }
                Err(why) => eprintln!("psiphon: fronted-meek accept: {why}"),
            }
        })
        .map_err(|error| format!("psiphon meek thread: {error}"))?;
    Ok(local)
}

/// Start the loopback relay over an in-proxy WebRTC stream.
pub(crate) fn connect_inproxy(
    stream: WebRtcStream,
    meek: &Meek,
    timeout: Duration,
    limit_buffer_sizes: bool,
) -> Result<TcpStream, String> {
    let transport = if meek.quic {
        stream.set_timeout(Some(timeout));
        let server_name = if meek.disable_sni {
            String::new()
        } else {
            meek.sni.clone()
        };
        MeekStream::H3(Box::new(crate::psiphon_h3::H3::connect_over(
            stream,
            &meek.dial,
            &server_name,
            timeout,
        )?))
    } else if meek.https {
        stream.set_timeout(Some(timeout));
        let server_name = if meek.disable_sni {
            "0.0.0.0".to_owned()
        } else {
            meek.sni.clone()
        };
        let fragment = server_name.parse::<IpAddr>().is_err()
            && meek.shape.fragment_client_hello(meek.protocol);
        let verify = !meek.verify_server_names.is_empty() || !meek.verify_pins.is_empty();
        if verify && meek.shape.disable_system_root_cas {
            return Err(
                "psiphon meek: DisableSystemRootCAs cannot be combined with verification"
                    .to_owned(),
            );
        }
        let roots = if verify {
            meek.shape.roots.load()?
        } else {
            Vec::new().into()
        };
        let fingerprint = meek
            .shape
            .fingerprint(meek.fronted, meek.provider_id.as_deref());
        let config = TlsConfig {
            server_name,
            alpn: vec![b"http/1.1".to_vec()].into(),
            roots,
            insecure: !verify,
            verify_names: if verify {
                std::sync::Arc::from(meek.verify_server_names.clone())
            } else {
                std::sync::Arc::from([])
            },
            pins: ferrox_core::foxy::pin::Pins::parse(meek.verify_pins.clone()),
            resumption: true,
            fingerprint: Some(fingerprint),
            omit_session_id: meek.shape.omit_session_id(fingerprint),
            padding: meek.shape.padding(),
            obfuscated_ticket: meek
                .shape
                .obfuscated_ticket(meek.protocol, &meek.obfuscated_key)?,
            ..TlsConfig::default()
        };
        let stream = crate::psiphon_fragment::TlsHelloFragmentor::new(stream, fragment);
        let mut tls = ferrox_core::tls::connect(&config, stream)
            .map_err(|error| format!("psiphon meek tls {}: {error}", meek.sni))?;
        tls.handshake()
            .map_err(|error| format!("psiphon meek handshake {}: {error}", meek.sni))?;
        MeekStream::TlsWebRtc(tls)
    } else {
        MeekStream::WebRtc(stream)
    };
    start_relay(meek, timeout, transport, limit_buffer_sizes)
}

/// Send one request over a fresh fronted stream and return its response body.
pub(crate) fn post(
    meek: &Meek,
    path: &'static str,
    endpoint: Option<&'static str>,
    body: &[u8],
    timeout: Duration,
    proxy: Option<&Proxy>,
    dns: &crate::psiphon_dns::Config,
) -> Result<Vec<u8>, String> {
    let mut http =
        MeekHttp::new(meek.clone(), proxy.cloned(), timeout, path, endpoint)?.with_dns(dns.clone());
    http.round_trip(body)
}

fn start_relay(
    meek: &Meek,
    timeout: Duration,
    transport: MeekStream,
    limit_buffer_sizes: bool,
) -> Result<TcpStream, String> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| format!("psiphon meek listener: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("psiphon meek listener: {error}"))?;
    let local = TcpStream::connect_timeout(&address, timeout)
        .map_err(|error| format!("psiphon meek loopback: {error}"))?;
    local
        .set_nodelay(true)
        .and_then(|()| local.set_read_timeout(Some(timeout)))
        .and_then(|()| local.set_write_timeout(Some(timeout)))
        .map_err(|error| format!("psiphon meek loopback: {error}"))?;
    let config = meek.clone();
    let seed = current_dial_seed();
    std::thread::Builder::new()
        .name("psiphon-meek".to_owned())
        .spawn(move || {
            let _scope = seed.map(dial_seed_scope);
            match listener.accept() {
                Ok((socket, _)) => {
                    if let Err(why) =
                        relay_stream(socket, &config, timeout, transport, limit_buffer_sizes)
                    {
                        eprintln!("psiphon: in-proxy-meek relay: {why}");
                    }
                }
                Err(why) => eprintln!("psiphon: in-proxy-meek accept: {why}"),
            }
        })
        .map_err(|error| format!("psiphon meek thread: {error}"))?;
    Ok(local)
}

/// Carry the fronted meek relay until the local stream closes.
fn relay(
    mut local: TcpStream,
    meek: &Meek,
    proxy: Option<&Proxy>,
    timeout: Duration,
    dns: &crate::psiphon_dns::Config,
    limit_buffer_sizes: bool,
) -> Result<(), String> {
    local
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("psiphon meek socket: {error}"))?;
    let mut http = MeekHttp::new(meek.clone(), proxy.cloned(), timeout, "/", None)?
        .with_dns(dns.clone())
        .with_limit_buffer_sizes(limit_buffer_sizes);
    let mut buffer = vec![0u8; http.request_limit()];
    let mut interval = POLL;
    loop {
        local
            .set_read_timeout(Some(interval))
            .map_err(|error| format!("psiphon meek socket: {error}"))?;
        let body = match local.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => &buffer[..read],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                &[]
            }
            Err(error) => return Err(format!("psiphon meek read: {error}")),
        };
        let reply = http.round_trip(body)?;
        if body.is_empty() && reply.is_empty() {
            interval = interval.mul_f64(POLL_GROWTH).min(MAX_POLL);
        } else {
            interval = POLL;
        }
        if !reply.is_empty() {
            local
                .write_all(&reply)
                .map_err(|error| format!("psiphon meek write: {error}"))?;
        }
    }
    Ok(())
}

/// Carry a preconnected in-proxy meek relay until the local stream closes.
fn relay_stream(
    mut local: TcpStream,
    meek: &Meek,
    timeout: Duration,
    transport: MeekStream,
    limit_buffer_sizes: bool,
) -> Result<(), String> {
    local
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("psiphon meek socket: {error}"))?;
    let mut http = MeekHttp::new_over(meek.clone(), timeout, "/", transport)?
        .with_limit_buffer_sizes(limit_buffer_sizes);
    let mut buffer = vec![0u8; http.request_limit()];
    let mut interval = POLL;
    loop {
        local
            .set_read_timeout(Some(interval))
            .map_err(|error| format!("psiphon meek socket: {error}"))?;
        let body = match local.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => &buffer[..read],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                &[]
            }
            Err(error) => return Err(format!("psiphon meek read: {error}")),
        };
        let reply = http.round_trip(body)?;
        if body.is_empty() && reply.is_empty() {
            interval = interval.mul_f64(POLL_GROWTH).min(MAX_POLL);
        } else {
            interval = POLL;
        }
        if !reply.is_empty() {
            local
                .write_all(&reply)
                .map_err(|error| format!("psiphon meek write: {error}"))?;
        }
    }
    Ok(())
}

/// A TCP stream with or without the fragmentor beneath TLS.
enum FragmentOrTcp {
    Tcp(TcpStream),
    Fragment(crate::psiphon_fragment::FragmentStream),
}

/// A plain TCP or TLS stream carrying meek HTTP.
enum MeekStream {
    Plain(TcpStream),
    Fragment(crate::psiphon_fragment::FragmentStream),
    Tls(ClientSession<crate::psiphon_fragment::TlsHelloFragmentor<TcpStream>>),
    TlsFragment(
        ClientSession<
            crate::psiphon_fragment::TlsHelloFragmentor<crate::psiphon_fragment::FragmentStream>,
        >,
    ),
    WebRtc(WebRtcStream),
    TlsWebRtc(ClientSession<crate::psiphon_fragment::TlsHelloFragmentor<WebRtcStream>>),
    H3(Box<crate::psiphon_h3::H3>),
}

impl Read for MeekStream {
    /// Read from the plain or TLS stream.
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buf),
            Self::Fragment(stream) => stream.read(buf),
            Self::Tls(stream) => stream.read(buf),
            Self::TlsFragment(stream) => stream.read(buf),
            Self::WebRtc(stream) => stream.read(buf),
            Self::TlsWebRtc(stream) => stream.read(buf),
            Self::H3(_) => Err(std::io::Error::other("psiphon h3 is not a byte stream")),
        }
    }
}

impl Write for MeekStream {
    /// Write to the plain or TLS stream.
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buf),
            Self::Fragment(stream) => stream.write(buf),
            Self::Tls(stream) => stream.write(buf),
            Self::TlsFragment(stream) => stream.write(buf),
            Self::WebRtc(stream) => stream.write(buf),
            Self::TlsWebRtc(stream) => stream.write(buf),
            Self::H3(_) => Err(std::io::Error::other("psiphon h3 is not a byte stream")),
        }
    }

    /// Flush the plain or TLS stream.
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Fragment(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
            Self::TlsFragment(stream) => stream.flush(),
            Self::WebRtc(stream) => stream.flush(),
            Self::TlsWebRtc(stream) => stream.flush(),
            Self::H3(_) => Ok(()),
        }
    }
}

impl MeekStream {
    /// The head and the caller's body in one completion: one TLS record, and the body is never
    /// staged in a request buffer first.
    fn write_parts(&mut self, parts: &[&[u8]]) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => crate::proxy::write_all_parts::<2>(stream, parts),
            Self::Fragment(stream) => crate::proxy::write_all_parts::<2>(stream, parts),
            Self::Tls(stream) => stream.write_all_slices(parts),
            Self::TlsFragment(stream) => stream.write_all_slices(parts),
            Self::WebRtc(stream) => crate::proxy::write_all_parts::<2>(stream, parts),
            Self::TlsWebRtc(stream) => stream.write_all_slices(parts),
            Self::H3(_) => Err(std::io::Error::other("psiphon h3 is not a byte stream")),
        }
    }

    /// Both socket timeouts on the stream under any wrapper.
    fn set_timeout(&mut self, timeout: Duration) -> Result<(), String> {
        match self {
            Self::Plain(stream) => MeekHttp::set_timeouts(stream, timeout),
            Self::Fragment(stream) => MeekHttp::set_timeouts(stream.get_ref(), timeout),
            Self::Tls(stream) => MeekHttp::set_timeouts(stream.get_ref().inner(), timeout),
            Self::TlsFragment(stream) => {
                MeekHttp::set_timeouts(stream.get_ref().inner().get_ref(), timeout)
            }
            Self::WebRtc(stream) => {
                stream.set_timeout(Some(timeout));
                Ok(())
            }
            Self::TlsWebRtc(stream) => {
                stream.get_ref().inner().set_timeout(Some(timeout));
                Ok(())
            }
            Self::H3(_) => Ok(()),
        }
    }

    /// Whether the peer closed the stream.
    fn peer_closed(&self) -> bool {
        let stream = match self {
            Self::Plain(stream) => stream,
            Self::Fragment(stream) => stream.get_ref(),
            Self::Tls(stream) if stream.closed() => return true,
            Self::Tls(stream) => stream.get_ref().inner(),
            Self::TlsFragment(stream) if stream.closed() => return true,
            Self::TlsFragment(stream) => stream.get_ref().inner().get_ref(),
            Self::WebRtc(_) => return false,
            Self::TlsWebRtc(stream) => return stream.closed(),
            Self::H3(h3) => return h3.is_closed(),
        };
        if stream.set_nonblocking(true).is_err() {
            return false;
        }
        let mut byte = [0u8; 1];
        let closed = matches!(stream.peek(&mut byte), Ok(0));
        let _ = stream.set_nonblocking(false);
        closed
    }
}

/// The protocols the reference wraps in its HTTP request transformer.
fn uses_http_transform(protocol: &str) -> bool {
    matches!(
        protocol,
        "UNFRONTED-MEEK-OSSH"
            | "UNFRONTED-MEEK-HTTP-OSSH"
            | "FRONTED-MEEK-HTTP-OSSH"
            | "FRONTED-MEEK-CDN-HTTP-OSSH"
    )
}

/// The HTTP transform this connection selected, or `None` for a non-HTTP or untransformed dial.
fn http_transform(meek: &Meek) -> Option<std::sync::Arc<Vec<crate::psiphon_dns::Transform>>> {
    if !uses_http_transform(meek.protocol) {
        return None;
    }
    meek.shape
        .http_transform(meek.fronted, meek.provider_id.as_deref())
}

/// A stream whose every read and write must finish before one request deadline.
struct DeadlineStream<'a> {
    stream: &'a mut MeekStream,
    deadline: Instant,
}

impl DeadlineStream<'_> {
    /// The request budget left, armed on the stream before the next syscall.
    fn arm(&mut self) -> std::io::Result<()> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "psiphon meek request deadline",
            ));
        }
        self.stream.set_timeout(left).map_err(std::io::Error::other)
    }

    fn write_parts(&mut self, parts: &[&[u8]]) -> std::io::Result<()> {
        self.arm()?;
        self.stream.write_parts(parts).map_err(expired_as_timed_out)
    }
}

/// A configured timeout is caller data, so a value too large for `Instant`
/// must not panic; such a budget is effectively unbounded for one request.
fn request_deadline(timeout: Duration) -> Instant {
    Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(|| Instant::now() + Duration::from_hours(100 * 365 * 24))
}

/// The armed socket timeout reports `WouldBlock` on Unix, including macOS;
/// after `arm` that means the request deadline fired.
fn expired_as_timed_out(error: std::io::Error) -> std::io::Error {
    if error.kind() == std::io::ErrorKind::WouldBlock {
        return std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "psiphon meek request deadline",
        );
    }
    error
}

impl Read for DeadlineStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.arm()?;
        self.stream.read(buf).map_err(expired_as_timed_out)
    }
}

impl Write for DeadlineStream<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.arm()?;
        self.stream.write(buf).map_err(expired_as_timed_out)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.arm()?;
        self.stream.flush().map_err(expired_as_timed_out)
    }
}

pub(crate) struct MeekHttp {
    meek: Meek,
    proxy: Option<Proxy>,
    timeout: Duration,
    path: &'static str,
    stream: Option<MeekStream>,
    cookie: Option<(String, String)>,
    profile: Profile,
    request_padding: Option<PaddingSender>,
    response_padding: Option<PaddingReceiver>,
    http_transform: Option<std::sync::Arc<Vec<crate::psiphon_dns::Transform>>>,
    front_index: usize,
    alpn_warned: bool,
    preconnected: bool,
    limit_buffer_sizes: bool,
    dns: crate::psiphon_dns::Config,
    /// Candidate addresses named by a test instead of a live resolver.
    #[cfg(test)]
    injected_addresses: Option<Vec<SocketAddr>>,
}

impl MeekHttp {
    /// Build a meek HTTP client from an entry and optional proxy.
    fn new(
        meek: Meek,
        proxy: Option<Proxy>,
        timeout: Duration,
        path: &'static str,
        endpoint: Option<&'static str>,
    ) -> Result<Self, String> {
        let chosen = profile(&meek.shape, meek.protocol);
        let transform = http_transform(&meek);
        let padding = chosen.payload_padding.filter(|_| endpoint.is_none());
        let cookie = Some(make_cookie(
            &meek,
            endpoint,
            &chosen.cookie_name,
            padding.is_some(),
        )?);
        let (request_padding, response_padding) = match (&cookie, padding) {
            (Some((_, value)), Some(config)) => (
                Some(PaddingSender::new(
                    &meek.obfuscated_key,
                    value,
                    b"meek-payload-padding-requests",
                    config,
                )?),
                Some(PaddingReceiver::new(
                    &meek.obfuscated_key,
                    value,
                    b"meek-payload-padding-responses",
                )?),
            ),
            _ => (None, None),
        };
        let dns = crate::psiphon_dns::Config::from_servers(&meek.dns);
        Ok(Self {
            meek,
            proxy,
            timeout,
            path,
            stream: None,
            cookie,
            profile: chosen,
            request_padding,
            response_padding,
            http_transform: transform,
            front_index: 0,
            alpn_warned: false,
            preconnected: false,
            limit_buffer_sizes: false,
            dns,
            #[cfg(test)]
            injected_addresses: None,
        })
    }

    /// Apply a per-request timeout to the next round trip and every later dial.
    pub(crate) fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Build a cookieless HTTP client for a plaintext broker endpoint.
    pub(crate) fn new_plain(
        meek: Meek,
        proxy: Option<Proxy>,
        timeout: Duration,
        path: &'static str,
    ) -> Self {
        let chosen = Profile {
            cookie_name: String::new(),
            content_type: ALTERNATE_CONTENT_TYPES[0],
            request_limit: MAX_REQUEST_PAYLOAD,
            redial_tls: 0.0,
            payload_padding: None,
            user_agent: USER_AGENT.to_owned(),
        };
        let transform = http_transform(&meek);
        let dns = crate::psiphon_dns::Config::from_servers(&meek.dns);
        Self {
            meek,
            proxy,
            timeout,
            path,
            stream: None,
            cookie: None,
            profile: chosen,
            request_padding: None,
            response_padding: None,
            http_transform: transform,
            front_index: 0,
            alpn_warned: false,
            preconnected: false,
            limit_buffer_sizes: false,
            dns,
            #[cfg(test)]
            injected_addresses: None,
        }
    }

    /// Build a client over an already-open in-proxy transport.
    fn new_over(
        meek: Meek,
        timeout: Duration,
        path: &'static str,
        stream: MeekStream,
    ) -> Result<Self, String> {
        let chosen = profile(&meek.shape, meek.protocol);
        let transform = http_transform(&meek);
        let cookie = Some(make_cookie(
            &meek,
            None,
            &chosen.cookie_name,
            chosen.payload_padding.is_some(),
        )?);
        let (request_padding, response_padding) = match (&cookie, chosen.payload_padding) {
            (Some((_, value)), Some(config)) => (
                Some(PaddingSender::new(
                    &meek.obfuscated_key,
                    value,
                    b"meek-payload-padding-requests",
                    config,
                )?),
                Some(PaddingReceiver::new(
                    &meek.obfuscated_key,
                    value,
                    b"meek-payload-padding-responses",
                )?),
            ),
            _ => (None, None),
        };
        let dns = crate::psiphon_dns::Config::from_servers(&meek.dns);
        Ok(Self {
            meek,
            proxy: None,
            timeout,
            path,
            stream: Some(stream),
            cookie,
            profile: chosen,
            request_padding,
            response_padding,
            http_transform: transform,
            front_index: 0,
            alpn_warned: false,
            preconnected: true,
            limit_buffer_sizes: false,
            dns,
            #[cfg(test)]
            injected_addresses: None,
        })
    }

    /// Use the lane's resolver knobs and cache instead of a per-client default.
    pub(crate) fn with_dns(mut self, dns: crate::psiphon_dns::Config) -> Self {
        self.dns = dns;
        self
    }

    /// Apply `LimitMeekBufferSizes` to both response readers.
    fn with_limit_buffer_sizes(mut self, limit: bool) -> Self {
        self.limit_buffer_sizes = limit;
        self
    }

    /// The HTTP/1 response chunk this client will pass to `read_reply`.
    #[cfg(test)]
    fn response_chunk(&self) -> usize {
        response_read_chunk(self.limit_buffer_sizes)
    }

    /// The HTTP/3 response chunk this client will pass to `H3::round_trip`.
    #[cfg(test)]
    fn h3_response_chunk(&self) -> usize {
        h3_read_chunk(self.limit_buffer_sizes)
    }

    /// The largest request body this connection may stage.
    fn request_limit(&self) -> usize {
        self.profile.request_limit
    }

    /// Whether a data retry can resend this body without duplicating a reply.
    fn retry_safe(&self) -> bool {
        match self.stream.as_ref() {
            Some(MeekStream::H3(h3)) => !h3.response_started(),
            None => self.meek.quic,
            _ => false,
        }
    }

    /// Send one request body and return the response body.
    pub(crate) fn round_trip(&mut self, body: &[u8]) -> Result<Vec<u8>, String> {
        if self.stream.is_none() {
            self.open()?;
        }
        let poll = body.is_empty();
        let padded;
        let body = if let Some(sender) = self.request_padding.as_mut() {
            padded = sender.pad(body)?;
            padded.as_slice()
        } else {
            body
        };
        let reply = match self.exchange(body) {
            Ok(reply) => reply,
            Err(why) if !self.preconnected && (poll || self.retry_safe()) => {
                self.stream = None;
                self.open()?;
                self.exchange(body).map_err(|_| why)?
            }
            Err(why) => {
                self.stream = None;
                return Err(why);
            }
        };
        if coin_probability(self.profile.redial_tls) && !self.preconnected {
            self.stream = None;
        }
        Ok(reply)
    }

    /// Try each front and each resolved address until one handshakes. A single
    /// refused front is a dead candidate, not the end of the relay.
    fn open(&mut self) -> Result<(), String> {
        if self.preconnected {
            return Err("psiphon meek connection is gone".to_owned());
        }
        let deadline = request_deadline(self.timeout);
        let mut last = "psiphon meek: no front to dial".to_owned();
        let fronts = self.meek.fronts.len().max(1);
        for _ in 0..fronts {
            self.rotate_front();
            if Self::remaining(deadline, self.timeout).is_none() {
                break;
            }
            let addresses = match self.resolved_addresses() {
                Ok(addresses) => addresses,
                Err(why) => {
                    last = why;
                    continue;
                }
            };
            for address in addresses {
                let Some(timeout) = Self::remaining(deadline, self.timeout) else {
                    break;
                };
                match self.open_once(address, timeout) {
                    Ok(()) => {
                        if self.meek.fronted {
                            self.dns.verify_cache_extension(&self.meek.dial);
                        }
                        return Ok(());
                    }
                    Err(why) => last = why,
                }
            }
        }
        Err(last)
    }

    /// The candidate addresses for the current front. Tests name them directly
    /// so the resolved-IP rotation does not need a live resolver.
    fn resolved_addresses(&self) -> Result<Vec<SocketAddr>, String> {
        #[cfg(test)]
        if let Some(addresses) = &self.injected_addresses {
            return Ok(addresses.clone());
        }
        crate::psiphon_dns::resolve_fronting(
            &self.dns,
            self.meek.provider_id.as_deref(),
            &self.meek.dial,
            self.meek.port,
        )
        .map_err(|error| format!("psiphon meek resolve {}: {error}", self.meek.dial))
    }

    /// Dial one address and start a TLS session when the front requires one.
    #[allow(clippy::too_many_lines)]
    fn open_once(&mut self, address: SocketAddr, timeout: Duration) -> Result<(), String> {
        if self.meek.quic && self.proxy.is_none() {
            let sni = if self.meek.disable_sni {
                String::new()
            } else {
                self.meek.sni.clone()
            };
            // A silent UDP front gets a capped handshake so the next front still runs.
            let handshake = timeout.min(MAX_HANDSHAKE_ATTEMPT);
            let h3 = crate::psiphon_h3::H3::connect_address(
                address,
                &self.meek.dial,
                &sni,
                handshake,
                self.timeout,
            )?;
            self.stream = Some(MeekStream::H3(Box::new(h3)));
            return Ok(());
        }
        // A stalled direct connect is one candidate; the proxy leg keeps its full handshake budget.
        let connect = timeout.min(MAX_CONNECT_ATTEMPT);
        let stream = match &self.proxy {
            Some(proxy) => proxy.connect(address, timeout)?,
            None => TcpStream::connect_timeout(&address, connect)
                .map_err(|error| format!("psiphon meek connect {}: {error}", self.meek.dial))?,
        };
        // A plain stream has no handshake, so it goes straight to the full timeout.
        let fragment = self.meek.shape.may_fragment(self.meek.protocol);
        Self::set_timeouts(
            &stream,
            if self.meek.https {
                timeout
            } else {
                self.timeout
            },
        )?;
        if !self.meek.https {
            self.stream = Some(if fragment {
                MeekStream::Fragment(crate::psiphon_fragment::FragmentStream::new(
                    stream,
                    self.meek.shape.fragmentor.clone(),
                ))
            } else {
                MeekStream::Plain(stream)
            });
            return Ok(());
        }
        let stream = if fragment {
            FragmentOrTcp::Fragment(crate::psiphon_fragment::FragmentStream::new(
                stream,
                self.meek.shape.fragmentor.clone(),
            ))
        } else {
            FragmentOrTcp::Tcp(stream)
        };
        // The SSH host key authenticates the payload; the fronting certificate is only cover.
        let server_name = if self.meek.disable_sni {
            address.ip().to_string()
        } else {
            self.meek.sni.clone()
        };
        let alpn =
            if self.meek.alpn.is_empty() || self.meek.alpn.iter().any(|name| name == b"http/1.1") {
                vec![b"http/1.1".to_vec()]
            } else {
                if !self.alpn_warned {
                    eprintln!("psiphon: fronting ALPN names no http/1.1; using http/1.1");
                    self.alpn_warned = true;
                }
                vec![b"http/1.1".to_vec()]
            };
        let fragment = server_name.parse::<IpAddr>().is_err()
            && self.meek.shape.fragment_client_hello(self.meek.protocol);
        let verify = !self.meek.verify_server_names.is_empty() || !self.meek.verify_pins.is_empty();
        if verify && self.meek.shape.disable_system_root_cas {
            return Err(
                "psiphon meek: DisableSystemRootCAs cannot be combined with verification"
                    .to_owned(),
            );
        }
        let roots = if verify {
            self.meek.shape.roots.load()?
        } else {
            Vec::new().into()
        };
        let fingerprint = self
            .meek
            .shape
            .fingerprint(self.meek.fronted, self.meek.provider_id.as_deref());
        let config = TlsConfig {
            server_name,
            alpn: alpn.into(),
            roots,
            insecure: !verify,
            verify_names: if verify {
                std::sync::Arc::from(self.meek.verify_server_names.clone())
            } else {
                std::sync::Arc::from([])
            },
            pins: ferrox_core::foxy::pin::Pins::parse(self.meek.verify_pins.clone()),
            resumption: true,
            fingerprint: Some(fingerprint),
            omit_session_id: self.meek.shape.omit_session_id(fingerprint),
            padding: self.meek.shape.padding(),
            obfuscated_ticket: self
                .meek
                .shape
                .obfuscated_ticket(self.meek.protocol, &self.meek.obfuscated_key)?,
            ..TlsConfig::default()
        };
        match stream {
            FragmentOrTcp::Tcp(stream) => {
                let stream = crate::psiphon_fragment::TlsHelloFragmentor::new(stream, fragment);
                let mut tls = ferrox_core::tls::connect(&config, stream)
                    .map_err(|error| format!("psiphon meek tls {}: {error}", self.meek.sni))?;
                tls.handshake().map_err(|error| {
                    format!("psiphon meek handshake {}: {error}", self.meek.sni)
                })?;
                Self::set_timeouts(tls.get_ref().inner(), self.timeout)?;
                self.stream = Some(MeekStream::Tls(tls));
            }
            FragmentOrTcp::Fragment(stream) => {
                let stream = crate::psiphon_fragment::TlsHelloFragmentor::new(stream, fragment);
                let mut tls = ferrox_core::tls::connect(&config, stream)
                    .map_err(|error| format!("psiphon meek tls {}: {error}", self.meek.sni))?;
                tls.handshake().map_err(|error| {
                    format!("psiphon meek handshake {}: {error}", self.meek.sni)
                })?;
                Self::set_timeouts(tls.get_ref().inner().get_ref(), self.timeout)?;
                self.stream = Some(MeekStream::TlsFragment(tls));
            }
        }
        Ok(())
    }

    /// Both socket timeouts on the TCP stream under any meek wrapper.
    fn set_timeouts(stream: &TcpStream, timeout: Duration) -> Result<(), String> {
        stream
            .set_read_timeout(Some(timeout))
            .and_then(|()| stream.set_write_timeout(Some(timeout)))
            .map_err(|error| format!("psiphon meek socket: {error}"))
    }

    /// The per-attempt budget left before the whole rotation's deadline.
    fn remaining(deadline: Instant, cap: Duration) -> Option<Duration> {
        let left = deadline.saturating_duration_since(Instant::now());
        (!left.is_zero()).then(|| left.min(cap))
    }

    /// Advance to the next fronting address.
    fn rotate_front(&mut self) {
        let index = self.front_index;
        self.front_index = self.front_index.wrapping_add(1);
        if let Some((dial, port)) = self.meek.fronts.get(index % self.meek.fronts.len().max(1)) {
            self.meek.dial.clone_from(dial);
            self.meek.port = *port;
        }
        if let Some(host) = self.meek.hosts.get(index % self.meek.hosts.len().max(1)) {
            self.meek.host.clone_from(host);
        }
    }

    /// Whether the current front closed the stream.
    fn peer_closed(&self) -> bool {
        self.stream.as_ref().is_none_or(MeekStream::peer_closed)
    }

    /// Exchange one request, rotating to a fresh front after a failure.
    fn exchange(&mut self, body: &[u8]) -> Result<Vec<u8>, String> {
        if self.stream.is_none() {
            self.open()?;
        }
        if !body.is_empty() && self.peer_closed() {
            self.stream = None;
            self.open()?;
        }
        let cookie = self
            .cookie
            .as_ref()
            .map(|(name, value)| format!("{name}={value}"));
        let mut host = self.meek.host.as_str();
        let mut headers: Vec<(&str, &str)> = self
            .meek
            .headers
            .iter()
            .filter_map(|(name, value)| {
                if name.eq_ignore_ascii_case("host") {
                    host = value;
                    None
                } else {
                    Some((name.as_str(), value.as_str()))
                }
            })
            .collect();
        for (name, value) in [
            ("Content-Type", self.profile.content_type),
            ("User-Agent", self.profile.user_agent.as_str()),
            ("Accept", "*/*"),
            ("Connection", "keep-alive"),
        ] {
            if !headers
                .iter()
                .any(|(have, _)| have.eq_ignore_ascii_case(name))
            {
                headers.push((name, value));
            }
        }
        let combined_cookie;
        if let Some(cookie) = cookie.as_deref() {
            if let Some(index) = headers
                .iter()
                .position(|(name, _)| name.eq_ignore_ascii_case("cookie"))
            {
                combined_cookie = format!("{}; {cookie}", headers[index].1);
                headers[index].1 = &combined_cookie;
            } else {
                headers.push(("Cookie", cookie));
            }
        }
        if let Some(MeekStream::H3(h3)) = self.stream.as_mut() {
            let headers: Vec<(&str, &str)> = headers
                .iter()
                .copied()
                .filter(|(name, _)| !is_hop_by_hop(name))
                .collect();
            let reply = h3.round_trip(
                host,
                self.path,
                &headers,
                body,
                self.timeout,
                h3_read_chunk(self.limit_buffer_sizes),
            )?;
            if reply.status != 200 {
                return Err(format!("psiphon meek status {}", reply.status));
            }
            self.absorb_cookie(&reply.headers);
            let mut body = reply.body;
            if let Some(receiver) = self.response_padding.as_mut() {
                body = receiver.strip(&body)?;
            }
            return Ok(body);
        }
        let mut head =
            crate::foxy_account::request_head("POST", host, self.path, &headers, body.len());
        if let Some(transform) = self.http_transform.as_deref().map(Vec::as_slice) {
            head = crate::psiphon_dns::apply_bytes_transform(transform, &head)
                .map_err(|error| format!("psiphon meek transform: {error}"))?;
        }
        let deadline = request_deadline(self.timeout);
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| "psiphon meek has no connection".to_owned())?;
        let mut stream = DeadlineStream { stream, deadline };
        stream
            .write_parts(&[&head, body])
            .and_then(|()| stream.flush())
            .map_err(|error| format!("psiphon meek request: {error}"))?;
        let reply = crate::foxy_account::read_reply(
            &mut stream,
            response_read_chunk(self.limit_buffer_sizes),
        )
        .map_err(|_| "psiphon meek response".to_owned())?;
        if reply.status != 200 {
            return Err(format!("psiphon meek status {}", reply.status));
        }
        self.absorb_cookie(&reply.headers);
        if reply
            .header("connection")
            .is_some_and(|value| value.eq_ignore_ascii_case("close"))
        {
            self.stream = None;
        }
        let mut body = reply.body;
        if let Some(receiver) = self.response_padding.as_mut() {
            body = receiver.strip(&body)?;
        }
        Ok(body)
    }

    /// Take a renewed meek cookie from a response.
    fn absorb_cookie(&mut self, headers: &[(String, String)]) {
        let Some((cookie_name, cookie_value)) = self.cookie.as_mut() else {
            return;
        };
        for (name, value) in headers {
            if !name.eq_ignore_ascii_case("set-cookie") {
                continue;
            }
            let pair = value.split(';').next().unwrap_or(value);
            if let Some((name, value)) = pair.split_once('=') {
                if name.trim() == cookie_name {
                    value.trim().clone_into(cookie_value);
                }
            }
        }
    }
}

/// Whether a header is connection-specific and must not cross HTTP/3.
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade" | "host"
    )
}

/// The protocol name the meek cookie reports, with the CDN marker removed.
fn cookie_protocol(protocol: &str) -> String {
    protocol.replacen("-CDN", "", 1)
}

/// The JSON a meek cookie carries before encryption.
fn cookie_plaintext(protocol: &str, endpoint: Option<&str>, padding: bool) -> String {
    let protocol = cookie_protocol(protocol);
    match (padding, endpoint) {
        (true, Some(endpoint)) => {
            format!(r#"{{"v":4,"p":true,"t":"{protocol}","e":"{endpoint}"}}"#)
        }
        (true, None) => format!(r#"{{"v":4,"p":true,"t":"{protocol}"}}"#),
        (false, Some(endpoint)) => format!(r#"{{"v":4,"t":"{protocol}","e":"{endpoint}"}}"#),
        (false, None) => format!(r#"{{"v":4,"t":"{protocol}"}}"#),
    }
}

/// Build the cookie header for a meek request with the profile's cookie name.
fn make_cookie(
    meek: &Meek,
    endpoint: Option<&str>,
    name: &str,
    padding: bool,
) -> Result<(String, String), String> {
    let key = ferrox_core::b64::decode(meek.public_key.as_bytes())
        .ok_or_else(|| "psiphon meek cookie key is not base64".to_owned())?;
    let key = PublicKey::from_slice(&key)
        .map_err(|_| "psiphon meek cookie key is not 32 bytes".to_owned())?;
    let mut rng = OsRng;
    let secret = SecretKey::generate(&mut rng);
    let ephemeral = secret.public_key();
    let boxed = SalsaBox::new(&key, &secret);
    let nonce = crypto_box::aead::Nonce::<SalsaBox>::from_slice(&[0u8; 24]);
    let plaintext = cookie_plaintext(meek.protocol, endpoint, padding);
    let sealed = boxed
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| "psiphon meek cookie encryption".to_owned())?;
    let seed = random::<SEED_LENGTH>();
    let mut client = Rc4::new(&derive_key(
        &seed,
        meek.obfuscated_key.as_bytes(),
        b"client_to_server",
    ));
    let padding_len = MIN_COOKIE_PADDING
        + usize::from(u16::from_be_bytes(dial_random::<2>()))
            % (MAX_COOKIE_PADDING - MIN_COOKIE_PADDING + 1);
    let mut value = Vec::with_capacity(SEED_LENGTH + 8 + padding_len + 32 + sealed.len());
    value.extend_from_slice(&seed);
    value.extend_from_slice(&MAGIC.to_be_bytes());
    value.extend_from_slice(&u32::try_from(padding_len).unwrap_or(0).to_be_bytes());
    let mut padding = vec![0u8; padding_len];
    dial_fill(&mut padding);
    value.extend_from_slice(&padding);
    client.apply(&mut value[SEED_LENGTH..]);
    let seed_len = value.len();
    value.extend_from_slice(ephemeral.as_bytes());
    value.extend_from_slice(&sealed);
    client.apply(&mut value[seed_len..]);
    Ok((name.to_owned(), ferrox_core::b64::encode(&value)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One deterministic fronted-meek entry for the unit tests.
    fn entry() -> Meek {
        Meek {
            dial: "front.example".to_owned(),
            port: 443,
            host: "cdn.example".to_owned(),
            sni: "front.example".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            obfuscated_key: "key".to_owned(),
            disable_sni: false,
            alpn: Vec::new(),
            fronts: vec![("front.example".to_owned(), 443)],
            hosts: vec!["cdn.example".to_owned()],
            https: true,
            quic: false,
            fronted: true,
            protocol: "FRONTED-MEEK-OSSH",
            headers: Vec::new(),
            dns: Vec::new(),
            provider_id: None,
            verify_server_names: Vec::new(),
            verify_pins: Vec::new(),
            shape: TlsShape {
                meek_alternate_cookie_name: 0.0,
                meek_alternate_content_type: 0.0,
                ..TlsShape::default()
            },
        }
    }

    /// Bind a port and release it so the next connect is refused immediately.
    fn refused_address() -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind a dead front");
        let address = listener.local_addr().expect("dead front address");
        drop(listener);
        address
    }

    #[test]
    fn a_refused_front_does_not_end_the_dial() {
        let live = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind a live front");
        let live_port = live.local_addr().expect("live front address").port();
        let dead_port = refused_address().port();
        let meek = Meek {
            dial: "127.0.0.1".to_owned(),
            port: dead_port,
            fronts: vec![
                (Ipv4Addr::LOCALHOST.to_string(), dead_port),
                (Ipv4Addr::LOCALHOST.to_string(), live_port),
            ],
            hosts: vec!["cdn.example".to_owned()],
            https: false,
            quic: false,
            ..entry()
        };
        let mut http = MeekHttp::new_plain(meek, None, Duration::from_secs(8), "/");
        http.open().expect("the second front handshakes");
        assert!(http.stream.is_some());
        assert_eq!(http.meek.port, live_port);
    }

    #[test]
    fn a_refused_resolved_ip_does_not_end_the_dial() {
        let live = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind a live front");
        let live = live.local_addr().expect("live front address");
        let dead = refused_address();
        let meek = Meek {
            https: false,
            quic: false,
            ..entry()
        };
        let mut http = MeekHttp::new_plain(meek, None, Duration::from_secs(8), "/");
        http.injected_addresses = Some(vec![dead, live]);
        http.open().expect("the next resolved IP handshakes");
        assert!(http.stream.is_some());
    }

    #[test]
    fn all_refused_fronts_report_the_last_failure() {
        let first = refused_address().port();
        let second = refused_address().port();
        let meek = Meek {
            dial: "127.0.0.1".to_owned(),
            port: first,
            fronts: vec![
                (Ipv4Addr::LOCALHOST.to_string(), first),
                (Ipv4Addr::LOCALHOST.to_string(), second),
            ],
            hosts: vec!["cdn.example".to_owned()],
            https: false,
            quic: false,
            ..entry()
        };
        let mut http = MeekHttp::new_plain(meek, None, Duration::from_secs(8), "/");
        let why = http.open().expect_err("no front connects");
        assert!(why.contains("psiphon meek connect"), "{why}");
        assert!(http.stream.is_none());
        assert_eq!(http.front_index, 2);
    }

    #[test]
    fn the_limited_response_chunk_is_four_kib() {
        assert_eq!(
            response_read_chunk(false),
            crate::foxy_account::DEFAULT_READ_CHUNK
        );
        assert_eq!(response_read_chunk(true), LIMITED_READ_CHUNK);
        assert_eq!(h3_read_chunk(false), 16 * 1024);
        assert_eq!(h3_read_chunk(true), LIMITED_READ_CHUNK);
    }

    #[test]
    fn both_relay_paths_carry_the_limit_into_each_response_reader() {
        for (limit, http1, h3) in [
            (false, crate::foxy_account::DEFAULT_READ_CHUNK, 16 * 1024),
            (true, LIMITED_READ_CHUNK, LIMITED_READ_CHUNK),
        ] {
            let http = MeekHttp::new(entry(), None, Duration::from_secs(1), "/", None)
                .expect("http")
                .with_limit_buffer_sizes(limit);
            assert_eq!(http.response_chunk(), http1);
            assert_eq!(http.h3_response_chunk(), h3);
        }
    }

    /// A cookie carries the seed and the encrypted endpoint payload.
    #[test]
    fn a_cookie_carries_a_seed_then_an_encrypted_payload() {
        let meek = entry();
        let chosen = profile(&meek.shape, meek.protocol);
        let (name, value) = make_cookie(&meek, None, &chosen.cookie_name, false).expect("cookie");
        assert_eq!(name, chosen.cookie_name);
        assert!(name.as_bytes()[0].is_ascii_uppercase());
        let bytes = ferrox_core::b64::decode(value.as_bytes()).expect("base64");
        assert!(bytes.len() > SEED_LENGTH + 8 + MIN_COOKIE_PADDING + 32);
    }

    /// The default profile draws one uppercase cookie letter.
    #[test]
    fn the_cookie_name_is_one_letter_when_the_alternate_coin_fails() {
        let meek = entry();
        let chosen = profile(&meek.shape, meek.protocol);
        let (name, _) = make_cookie(&meek, None, &chosen.cookie_name, false).expect("cookie");
        assert_eq!(name.len(), 1);
    }

    /// An alternate cookie name is a two-to-ten character lowercase word.
    #[test]
    fn an_alternate_cookie_name_is_a_lowercase_word() {
        let shape = TlsShape {
            meek_alternate_cookie_name: 1.0,
            ..TlsShape::default()
        };
        for _ in 0..64 {
            let chosen = profile(&shape, "FRONTED-MEEK-OSSH");
            assert!((2..=10).contains(&chosen.cookie_name.len()));
            assert!(chosen
                .cookie_name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_'));
        }
    }

    #[test]
    fn the_profile_draws_a_user_agent_by_probability() {
        let always = TlsShape {
            user_agent_probability: 1.0,
            ..TlsShape::default()
        };
        let never = TlsShape {
            user_agent_probability: 0.0,
            ..TlsShape::default()
        };
        for _ in 0..16 {
            let chosen = profile(&always, "FRONTED-MEEK-OSSH");
            assert!(chosen.user_agent.starts_with("Mozilla/5.0 ("));
        }
        let empty = profile(&never, "FRONTED-MEEK-OSSH");
        assert!(!empty.user_agent.starts_with("Mozilla/5.0 ("));
    }

    /// An alternate content type is one of the cover media types.
    #[test]
    fn an_alternate_content_type_is_a_cover_type() {
        let shape = TlsShape {
            meek_alternate_content_type: 1.0,
            ..TlsShape::default()
        };
        for _ in 0..64 {
            let chosen = profile(&shape, "FRONTED-MEEK-OSSH");
            assert!(ALTERNATE_CONTENT_TYPES.contains(&chosen.content_type));
        }
    }

    /// A shaped request cap falls inside the configured range.
    #[test]
    fn traffic_shaping_draws_the_request_limit_inside_its_range() {
        let shape = TlsShape {
            meek_traffic_shaping: 1.0,
            meek_min_limit_request: 1024,
            meek_max_limit_request: 2048,
            ..TlsShape::default()
        };
        for _ in 0..64 {
            let chosen = profile(&shape, "FRONTED-MEEK-OSSH");
            assert!((1024..=2048).contains(&chosen.request_limit));
        }
    }

    /// A protocol outside the shaping list keeps the full cap.
    #[test]
    fn traffic_shaping_skips_a_protocol_outside_its_limit() {
        let shape = TlsShape {
            meek_traffic_shaping: 1.0,
            meek_traffic_shaping_protocols: vec!["TLS-OSSH".to_owned()],
            meek_min_limit_request: 1024,
            meek_max_limit_request: 2048,
            ..TlsShape::default()
        };
        let chosen = profile(&shape, "FRONTED-MEEK-OSSH");
        assert_eq!(chosen.request_limit, MAX_REQUEST_PAYLOAD);
    }

    /// Redial is selected only when the shaping coin lands.
    #[test]
    fn redial_tls_is_selected_only_inside_traffic_shaping() {
        let shaped = TlsShape {
            meek_traffic_shaping: 1.0,
            meek_redial_tls: 1.0,
            ..TlsShape::default()
        };
        assert_eq!(profile(&shaped, "FRONTED-MEEK-OSSH").redial_tls, 1.0);
        let unshaped = TlsShape {
            meek_traffic_shaping: 0.0,
            meek_redial_tls: 1.0,
            ..TlsShape::default()
        };
        assert_eq!(profile(&unshaped, "FRONTED-MEEK-OSSH").redial_tls, 0.0);
    }

    /// A head and the caller's body reach the socket as the one request the staged buffer built.
    #[test]
    fn the_head_and_body_are_the_request_the_staging_buffer_built() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("binds");
        let address = listener.local_addr().expect("address");
        let body = vec![0x5au8; 4096];
        let head = crate::foxy_account::request_head(
            "POST",
            "cdn.example",
            "/",
            &[("X-A", "1")],
            body.len(),
        );
        let want = crate::foxy_account::request("POST", "cdn.example", "/", &[("X-A", "1")], &body);
        let total = want.len();
        let reader = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accepts");
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            let mut got = vec![0u8; total];
            socket.read_exact(&mut got).expect("reads");
            got
        });
        let stream = TcpStream::connect(address).expect("connects");
        let mut meek = MeekStream::Plain(stream);
        meek.write_parts(&[&head, &body]).expect("writes");
        meek.flush().expect("flushes");
        assert_eq!(reader.join().expect("joins"), want);
    }

    /// A timeout larger than an `Instant` can hold is a budget, not a panic.
    #[test]
    fn a_timeout_too_large_for_an_instant_still_gets_a_deadline() {
        assert!(request_deadline(Duration::MAX) > Instant::now());
    }

    /// A response that trickles bytes still stops at the request deadline.
    #[test]
    fn a_trickling_response_cannot_outlive_the_request_deadline() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("binds");
        let address = listener.local_addr().expect("address");
        let writer = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accepts");
            for _ in 0..50 {
                if socket.write_all(b"x").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        let stream = TcpStream::connect(address).expect("connects");
        let mut meek = MeekStream::Plain(stream);
        let mut io = DeadlineStream {
            stream: &mut meek,
            deadline: Instant::now() + Duration::from_millis(40),
        };
        let mut got = 0usize;
        let mut buf = [0u8; 8];
        let error = loop {
            match io.read(&mut buf) {
                Ok(0) => break None,
                Ok(read) => got += read,
                Err(error) => break Some(error),
            }
        };
        assert!(
            got < 50,
            "the deadline stopped the trickle after {got} bytes"
        );
        assert_eq!(
            error.expect("a timed-out read").kind(),
            std::io::ErrorKind::TimedOut
        );
        drop(meek);
        writer.join().expect("joins");
    }

    /// Padding is selected only for a MEEK protocol and only when its coin lands.
    #[test]
    fn payload_padding_is_selected_only_for_meek_when_the_coin_lands() {
        let shape = TlsShape {
            meek_payload_padding: 1.0,
            meek_payload_padding_min: 8,
            meek_payload_padding_max: 16,
            ..TlsShape::default()
        };
        let chosen = profile(&shape, "FRONTED-MEEK-OSSH");
        assert!(chosen.payload_padding.is_some());
        assert_eq!(chosen.request_limit, MAX_REQUEST_PAYLOAD - 1);
        assert!(profile(&shape, "TLS-OSSH").payload_padding.is_none());
        let off = TlsShape {
            meek_payload_padding: 0.0,
            ..TlsShape::default()
        };
        assert!(profile(&off, "FRONTED-MEEK-OSSH").payload_padding.is_none());
    }

    fn padding_pair(omit: f64) -> (PaddingSender, PaddingReceiver) {
        let config = PaddingConfig {
            omit,
            min: 8,
            max: 16,
        };
        (
            PaddingSender::new("key", "cookie", b"requests", config).expect("sender"),
            PaddingReceiver::new("key", "cookie", b"requests").expect("receiver"),
        )
    }

    /// A non-empty payload carries the no-padding prefix and is restored byte for byte.
    #[test]
    fn a_padded_payload_round_trips_through_the_sender_and_receiver() {
        for len in [1usize, 17, 4096] {
            let (mut sender, mut receiver) = padding_pair(0.0);
            let body = vec![0x5au8; len];
            let padded = sender.pad(&body).expect("pads");
            assert_eq!(padded.len(), len + 1);
            assert_eq!(receiver.strip(&padded).expect("strips"), body);
        }
    }

    /// An empty payload is either a full padding frame or omitted entirely.
    #[test]
    fn an_empty_payload_is_padded_or_omitted() {
        let (mut sender, mut receiver) = padding_pair(0.0);
        let padded = sender.pad(&[]).expect("pads");
        assert!((3 + 8..=3 + 16).contains(&padded.len()));
        assert_eq!(receiver.strip(&padded).expect("strips"), [] as [u8; 0]);

        let (mut sender, _) = padding_pair(1.0);
        assert_eq!(sender.pad(&[]).expect("pads"), [] as [u8; 0]);
    }

    /// Consecutive padded frames are consumed until the payload begins.
    #[test]
    fn a_padding_receiver_consumes_every_frame_before_the_payload() {
        let (mut sender, mut receiver) = padding_pair(0.0);
        let mut frames = sender.pad(&[]).expect("pads");
        frames.extend(sender.pad(&[]).expect("pads"));
        frames.extend(sender.pad(&[0x42, 0x43]).expect("pads"));
        assert_eq!(receiver.strip(&frames).expect("strips"), [0x42, 0x43]);
    }

    /// The cookie signals payload padding only when the profile selected it.
    #[test]
    fn the_cookie_signals_payload_padding() {
        assert_eq!(
            cookie_plaintext("FRONTED-MEEK-OSSH", None, false),
            r#"{"v":4,"t":"FRONTED-MEEK-OSSH"}"#
        );
        assert_eq!(
            cookie_plaintext("FRONTED-MEEK-CDN-OSSH", Some("endpoint"), true),
            r#"{"v":4,"p":true,"t":"FRONTED-MEEK-OSSH","e":"endpoint"}"#
        );
    }

    #[test]
    fn the_cookie_names_the_base_tunnel_protocol() {
        assert_eq!(
            cookie_protocol("FRONTED-MEEK-CDN-OSSH"),
            "FRONTED-MEEK-OSSH"
        );
        assert_eq!(
            cookie_protocol("FRONTED-MEEK-CDN-HTTP-OSSH"),
            "FRONTED-MEEK-HTTP-OSSH"
        );
        assert_eq!(
            cookie_protocol("UNFRONTED-MEEK-HTTPS-OSSH"),
            "UNFRONTED-MEEK-HTTPS-OSSH"
        );
    }
}

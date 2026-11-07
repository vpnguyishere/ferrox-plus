//! The meek relay the native `Psiphon` lane rides for unfronted and CDN-fronted
//! entries: a loopback TCP stream whose bytes are carried in `POST /` requests.

use crate::psiphon_ssh::{derive_key, random, Proxy, Rc4, TlsShape, MAGIC, SEED_LENGTH};
use crate::psiphon_webrtc::WebRtcStream;
use crypto_box::aead::{Aead, OsRng};
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use ferrox_core::tls::{ClientSession, RecordAlignment as _, TlsConfig, TlsProvider as _};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

pub(crate) const MAX_REQUEST_PAYLOAD: usize = 64 * 1024;
const LIMITED_READ_CHUNK: usize = 4 * 1024;
const MIN_COOKIE_PADDING: usize = 16;
const MAX_COOKIE_PADDING: usize = 256;
const POLL: Duration = Duration::from_millis(100);
const MAX_POLL: Duration = Duration::from_secs(5);
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
}

/// One random coin with the given probability.
fn coin_probability(probability: f64) -> bool {
    if probability <= 0.0 {
        return false;
    }
    if probability >= 1.0 {
        return true;
    }
    f64::from(u16::from_be_bytes(random::<2>())) / 65_536.0 < probability
}

/// A random value in `0..bound`.
fn random_below(bound: u64) -> u64 {
    if bound <= 1 {
        return 0;
    }
    u64::from_be_bytes(random::<8>()) % bound
}

/// The reference's alternate cookie name: two to ten characters from `[a-z_]`.
fn alternate_cookie_name() -> String {
    let length = 2 + usize::from(random::<1>()[0]) % 9;
    (0..length)
        .map(|_| {
            let draw = random::<1>()[0] % 27;
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
        char::from(b'A' + random::<1>()[0] % 26).to_string()
    };
    let content_type = if coin_probability(shape.meek_alternate_content_type) {
        ALTERNATE_CONTENT_TYPES[usize::from(random::<1>()[0]) % ALTERNATE_CONTENT_TYPES.len()]
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
    Profile {
        cookie_name,
        content_type,
        request_limit,
        redial_tls,
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
    std::thread::Builder::new()
        .name("psiphon-meek".to_owned())
        .spawn(move || match listener.accept() {
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
        let config = TlsConfig {
            server_name,
            alpn: vec![b"http/1.1".to_vec()].into(),
            roots: crate::quic::system_roots(),
            insecure: true,
            resumption: true,
            fingerprint: Some(meek.shape.fingerprint()),
            padding: meek.shape.padding(),
            ..TlsConfig::default()
        };
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
    std::thread::Builder::new()
        .name("psiphon-meek".to_owned())
        .spawn(move || match listener.accept() {
            Ok((socket, _)) => {
                if let Err(why) =
                    relay_stream(socket, &config, timeout, transport, limit_buffer_sizes)
                {
                    eprintln!("psiphon: in-proxy-meek relay: {why}");
                }
            }
            Err(why) => eprintln!("psiphon: in-proxy-meek accept: {why}"),
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
    Tls(ClientSession<TcpStream>),
    TlsFragment(ClientSession<crate::psiphon_fragment::FragmentStream>),
    WebRtc(WebRtcStream),
    TlsWebRtc(ClientSession<WebRtcStream>),
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

    /// Whether the peer closed the stream.
    fn peer_closed(&self) -> bool {
        let stream = match self {
            Self::Plain(stream) => stream,
            Self::Fragment(stream) => stream.get_ref(),
            Self::Tls(stream) if stream.closed() => return true,
            Self::Tls(stream) => stream.get_ref(),
            Self::TlsFragment(stream) if stream.closed() => return true,
            Self::TlsFragment(stream) => stream.get_ref().get_ref(),
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

pub(crate) struct MeekHttp {
    meek: Meek,
    proxy: Option<Proxy>,
    timeout: Duration,
    path: &'static str,
    stream: Option<MeekStream>,
    cookie: Option<(String, String)>,
    profile: Profile,
    front_index: usize,
    alpn_warned: bool,
    preconnected: bool,
    limit_buffer_sizes: bool,
    dns: crate::psiphon_dns::Config,
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
        let cookie = Some(make_cookie(&meek, endpoint, &chosen.cookie_name)?);
        let dns = crate::psiphon_dns::Config::from_servers(&meek.dns);
        Ok(Self {
            meek,
            proxy,
            timeout,
            path,
            stream: None,
            cookie,
            profile: chosen,
            front_index: 0,
            alpn_warned: false,
            preconnected: false,
            limit_buffer_sizes: false,
            dns,
        })
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
        };
        let dns = crate::psiphon_dns::Config::from_servers(&meek.dns);
        Self {
            meek,
            proxy,
            timeout,
            path,
            stream: None,
            cookie: None,
            profile: chosen,
            front_index: 0,
            alpn_warned: false,
            preconnected: false,
            limit_buffer_sizes: false,
            dns,
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
        let cookie = Some(make_cookie(&meek, None, &chosen.cookie_name)?);
        let dns = crate::psiphon_dns::Config::from_servers(&meek.dns);
        Ok(Self {
            meek,
            proxy: None,
            timeout,
            path,
            stream: Some(stream),
            cookie,
            profile: chosen,
            front_index: 0,
            alpn_warned: false,
            preconnected: true,
            limit_buffer_sizes: false,
            dns,
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

    /// Send one request body and return the response body.
    pub(crate) fn round_trip(&mut self, body: &[u8]) -> Result<Vec<u8>, String> {
        if self.stream.is_none() {
            self.open()?;
        }
        let reply = match self.exchange(body) {
            Ok(reply) => reply,
            Err(why) if body.is_empty() && !self.preconnected => {
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

    /// Dial the next front and start a TLS session when required.
    #[allow(clippy::too_many_lines)]
    fn open(&mut self) -> Result<(), String> {
        if self.preconnected {
            return Err("psiphon meek connection is gone".to_owned());
        }
        self.rotate_front();
        if self.meek.quic && self.proxy.is_none() {
            let sni = if self.meek.disable_sni {
                String::new()
            } else {
                self.meek.sni.clone()
            };
            let h3 = crate::psiphon_h3::H3::connect(
                &self.meek.dial,
                self.meek.port,
                &sni,
                self.timeout,
                &self.dns,
            )?;
            self.stream = Some(MeekStream::H3(Box::new(h3)));
            return Ok(());
        }
        let address = crate::psiphon_dns::resolve_fronting(
            &self.dns,
            self.meek.provider_id.as_deref(),
            &self.meek.dial,
            self.meek.port,
        )
        .map_err(|error| format!("psiphon meek resolve {}: {error}", self.meek.dial))?
        .into_iter()
        .next()
        .ok_or_else(|| format!("psiphon meek resolve {}: no address", self.meek.dial))?;
        let stream = match &self.proxy {
            Some(proxy) => proxy.connect(address, self.timeout)?,
            None => TcpStream::connect_timeout(&address, self.timeout)
                .map_err(|error| format!("psiphon meek connect {}: {error}", self.meek.dial))?,
        };
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.timeout)))
            .map_err(|error| format!("psiphon meek socket: {error}"))?;
        let fragment = self.meek.shape.may_fragment(self.meek.protocol);
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
        let config = TlsConfig {
            server_name,
            alpn: alpn.into(),
            roots: crate::quic::system_roots(),
            insecure: true,
            resumption: true,
            fingerprint: Some(self.meek.shape.fingerprint()),
            padding: self.meek.shape.padding(),
            ..TlsConfig::default()
        };
        match stream {
            FragmentOrTcp::Tcp(stream) => {
                let mut tls = ferrox_core::tls::connect(&config, stream)
                    .map_err(|error| format!("psiphon meek tls {}: {error}", self.meek.sni))?;
                tls.handshake().map_err(|error| {
                    format!("psiphon meek handshake {}: {error}", self.meek.sni)
                })?;
                self.stream = Some(MeekStream::Tls(tls));
            }
            FragmentOrTcp::Fragment(stream) => {
                let mut tls = ferrox_core::tls::connect(&config, stream)
                    .map_err(|error| format!("psiphon meek tls {}: {error}", self.meek.sni))?;
                tls.handshake().map_err(|error| {
                    format!("psiphon meek handshake {}: {error}", self.meek.sni)
                })?;
                self.stream = Some(MeekStream::TlsFragment(tls));
            }
        }
        Ok(())
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
            ("User-Agent", USER_AGENT),
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
            return Ok(reply.body);
        }
        let head = crate::foxy_account::request_head("POST", host, self.path, &headers, body.len());
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| "psiphon meek has no connection".to_owned())?;
        stream
            .write_parts(&[&head, body])
            .and_then(|()| stream.flush())
            .map_err(|error| format!("psiphon meek request: {error}"))?;
        let reply =
            crate::foxy_account::read_reply(stream, response_read_chunk(self.limit_buffer_sizes))
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
        Ok(reply.body)
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

/// Build the cookie header for a meek request with the profile's cookie name.
fn make_cookie(
    meek: &Meek,
    endpoint: Option<&str>,
    name: &str,
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
    let plaintext = match endpoint {
        Some(endpoint) => format!(
            r#"{{"v":4,"t":"{}","e":"{}"}}"#,
            cookie_protocol(meek.protocol),
            endpoint
        ),
        None => format!(r#"{{"v":4,"t":"{}"}}"#, cookie_protocol(meek.protocol)),
    };
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
        + usize::from(u16::from_be_bytes(random::<2>()))
            % (MAX_COOKIE_PADDING - MIN_COOKIE_PADDING + 1);
    let mut value = Vec::with_capacity(SEED_LENGTH + 8 + padding_len + 32 + sealed.len());
    value.extend_from_slice(&seed);
    value.extend_from_slice(&MAGIC.to_be_bytes());
    value.extend_from_slice(&u32::try_from(padding_len).unwrap_or(0).to_be_bytes());
    let mut padding = vec![0u8; padding_len];
    getrandom::fill(&mut padding).map_err(|error| format!("psiphon meek entropy: {error}"))?;
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
            shape: TlsShape {
                meek_alternate_cookie_name: 0.0,
                meek_alternate_content_type: 0.0,
                ..TlsShape::default()
            },
        }
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
        let (name, value) = make_cookie(&meek, None, &chosen.cookie_name).expect("cookie");
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
        let (name, _) = make_cookie(&meek, None, &chosen.cookie_name).expect("cookie");
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

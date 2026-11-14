use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use super::{Stream, TlsError, TlsProvider};
use crate::tls::rustls_backend::RustlsServerProvider;
#[cfg(test)]
use aes_gcm::aead::Payload;
use aes_gcm::aead::{Aead as _, AeadInOut as _, KeyInit as _};
use ring::signature::KeyPair as _;

const GROUP_X25519: u16 = 0x001d;
const GROUP_X25519_MLKEM768: u16 = 0x11ec;
const GROUP_X25519_MLKEM768_DRAFT: u16 = 0x6399;
const MLKEM768_KEY_LEN: usize = 1184;
const TLS13: u16 = 0x0304;
const OID_ED25519: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];
const PKCS8_ED25519_SEED_HEADER: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const SIGNATURE_LEN: usize = 64;
const MAX_RECORD: usize = 16_384 + 2_048;
const MAX_HELLO: usize = 1 << 16;

const ED25519_SEED: [u8; 32] = [
    0x64, 0x6f, 0x76, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x2d, 0x72, 0x65, 0x61, 0x6c, 0x69, 0x74, 0x79,
    0x2d, 0x65, 0x64, 0x32, 0x35, 0x31, 0x39, 0x2d, 0x73, 0x65, 0x65, 0x64, 0x2d, 0x76, 0x31, 0x63,
];

/// How fast the cover origin may be fed once a splice has passed `after_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    pub after_bytes: u64,
    pub bytes_per_sec: u64,
    pub burst_bytes_per_sec: u64,
}

/// The cover origin an unauthenticated peer is spliced into, dialled lazily so
/// that an authenticated client costs the real site nothing.
#[derive(Debug, Clone, Default)]
pub struct RealityServerConfig {
    pub private_key: [u8; 32],
    pub short_ids: Vec<[u8; 8]>,
    pub server_names: Vec<String>,
    pub max_time_skew: Option<Duration>,
    pub min_client_ver: Option<[u8; 3]>,
    pub max_client_ver: Option<[u8; 3]>,
    pub limit_fallback_upload: Option<RateLimit>,
    pub limit_fallback_download: Option<RateLimit>,
    pub dest: Option<String>,
    pub xver: u8,
    pub show: bool,
}

/// The two ends of a socket, for the PROXY-protocol header a cover origin is
/// sent before anything else: `local` is the source the cover origin sees and
/// `peer` the destination it was dialled on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Edges {
    pub peer: Option<SocketAddr>,
    pub local: Option<SocketAddr>,
}

impl Edges {
    pub fn of(io: &TcpStream) -> Self {
        Self {
            peer: io.peer_addr().ok(),
            local: io.local_addr().ok(),
        }
    }
}

/// What the server answers with once the `ClientHello` has been read: either an
/// authenticated session, or the splice that carries an unauthenticated peer to
/// the cover origin it asked for.
#[allow(
    clippy::large_enum_variant,
    reason = "the session holds the TLS stack and the splice holds two sockets; boxing either would add a pointer chase to every handshake"
)]
pub enum RealityAccept<S: Stream> {
    Session(RealityServer<S>),
    Proxied(Proxied<S>),
}

impl<S: Stream> std::fmt::Debug for RealityAccept<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Session(_) => f.write_str("RealityAccept::Session"),
            Self::Proxied(_) => f.write_str("RealityAccept::Proxied"),
        }
    }
}

/// An unauthenticated peer and the cover origin it is now being spliced into.
pub struct Proxied<S: Stream> {
    pub client: S,
    pub target: TcpStream,
    pub upload: Option<RateLimit>,
    pub download: Option<RateLimit>,
}

impl<S: Stream> std::fmt::Debug for Proxied<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proxied")
            .field("upload", &self.upload)
            .field("download", &self.download)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct RealityServer<S: Stream> {
    inner: RustlsServerProvider<Replay<RecordLimiter<S>>>,
}

impl<S: Stream> RealityServer<S> {
    pub fn transport(&self) -> &S {
        self.inner.get_ref().transport().get_ref()
    }

    /// Whether bytes the client's hello read past are still waiting to be replayed, so a raw
    /// transport read would miss them.
    pub fn has_pending(&self) -> bool {
        self.inner.get_ref().has_pending()
    }

    /// Reads the `ClientHello`, authenticates it, and answers with the session or
    /// with the splice. A hello that does not authenticate and has no cover
    /// origin configured is an error, which is the whole of a refusal. A peer
    /// that broke the parse rules is spliced too, carrying the bytes it already
    /// spent; only one that sent nothing at all is closed.
    pub fn accept(
        cfg: &RealityServerConfig,
        now_ms: u64,
        io: S,
        edges: Edges,
    ) -> Result<RealityAccept<S>, TlsError> {
        let mut replay = Replay::new(RecordLimiter::new(io));
        let (mut raw, body, hello) = match read_client_hello(&mut replay) {
            Ok(heard) => heard,
            Err((why, read)) => {
                if read.is_empty() {
                    return Err(why);
                }
                return splice(cfg, replay.into_inner().into_inner(), &read, edges);
            }
        };
        let auth_key = match body {
            Body::Inline { len } => authenticate(cfg, &mut raw[5..5 + len], &hello, now_ms),
            Body::Split(mut split) => authenticate(cfg, &mut split, &hello, now_ms),
        };
        let Some(auth_key) = auth_key else {
            return splice(cfg, replay.into_inner().into_inner(), &raw, edges);
        };
        let identity = super::TlsServerConfig {
            alpn: Vec::new(),
            min_version: None,
            max_version: None,
            cipher_suites: Vec::new(),
            curves: Vec::new(),
            certs: vec![super::CertEntry {
                cert_chain: vec![bound_certificate(&auth_key, first_name(cfg))],
                key_der: ed25519_pkcs8(),
                key_kind: super::ServerKeyKind::Pkcs8,
                reload: None,
                ocsp: None,
            }],
            send_tickets: false,
            reject_unknown_sni: false,
            server_config_cache: std::sync::Arc::default(),
            ech_server_keys: None,
            master_key_log: None,
            kernel_tx: false,
            kernel_rx: false,
        };
        replay.set_prefix(raw);
        Ok(RealityAccept::Session(Self {
            inner: RustlsServerProvider::accept_reality(identity, replay)?,
        }))
    }
}

impl<S: Stream> TlsProvider for RealityServer<S> {
    fn name() -> &'static str {
        "rustls"
    }

    fn suites(&self) -> Vec<String> {
        self.inner.suites()
    }

    fn handshake(&mut self) -> Result<(), TlsError> {
        self.inner.handshake()
    }

    fn open(&mut self, ciphertext: &[u8], buf: &mut [u8]) -> std::io::Result<(usize, usize)> {
        self.inner.open(ciphertext, buf)
    }

    fn alpn(&self) -> Option<&[u8]> {
        self.inner.alpn()
    }

    fn closed(&self) -> bool {
        self.inner.closed()
    }

    /// The name the client's hello replayed into the session, so the inner
    /// handshake's own answer is the matched one.
    fn sni(&self) -> Option<&[u8]> {
        self.inner.sni()
    }

    fn seal_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> std::io::Result<usize> {
        self.inner.seal_into(plaintext, out)
    }

    fn seal_slices_into(&mut self, parts: &[&[u8]], out: &mut Vec<u8>) -> std::io::Result<()> {
        self.inner.seal_slices_into(parts, out)
    }
}

// Already bounded outside: the accept path reads through a limiter from the first byte.
impl<S: Stream> super::RecordAlignment for RealityServer<S> {
    fn disarm_record_alignment(&mut self) {
        self.inner.disarm_record_alignment();
    }

    fn write_all_slices(&mut self, parts: &[&[u8]]) -> std::io::Result<()> {
        self.inner.write_all_slices(parts)
    }
}

impl<S: Stream> Read for RealityServer<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<S: Stream> Write for RealityServer<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Dials the cover origin, hands it the hello the server read, and answers with
/// the splice. The dial is lazy on purpose: an authenticated client never costs
/// the real site a connection, and neither does a port scanner.
fn splice<S: Stream>(
    cfg: &RealityServerConfig,
    io: S,
    hello: &[u8],
    edges: Edges,
) -> Result<RealityAccept<S>, TlsError> {
    let Some(dest) = cfg.dest.as_deref() else {
        return Err(TlsError::Other(format!(
            "{}: refused, no cover origin configured",
            cfg.server_names.first().map_or("reality", String::as_str)
        )));
    };
    let refused = |why: &str| TlsError::Other(format!("reality: cover origin, {why}"));
    let mut target = TcpStream::connect(dest).map_err(|_| refused("unreachable"))?;
    if cfg.xver > 0 {
        write_proxy_protocol(&mut target, cfg.xver, edges)
            .map_err(|_| refused("proxy protocol"))?;
    }
    target.write_all(hello).map_err(|_| refused("hello"))?;
    target.flush().map_err(|_| refused("hello"))?;
    Ok(RealityAccept::Proxied(Proxied {
        client: io,
        target,
        upload: cfg.limit_fallback_upload,
        download: cfg.limit_fallback_download,
    }))
}

fn narrow(edge: &SocketAddr) -> [u8; 4] {
    match edge.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or_else(
            || v6.octets()[12..].try_into().unwrap_or([0; 4]),
            |v4| v4.octets(),
        ),
    }
}

fn wide(edge: &SocketAddr) -> [u8; 16] {
    match edge.ip() {
        std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        std::net::IpAddr::V6(v6) => v6.octets(),
    }
}

/// The same edge with an IPv4 address in its IPv4-mapped IPv6 form, so a `TCP6` line
/// never carries a bare dotted quad.
fn wide_socket(edge: SocketAddr) -> SocketAddr {
    let mapped = match edge.ip() {
        std::net::IpAddr::V4(v4) => std::net::IpAddr::V6(v4.to_ipv6_mapped()),
        std::net::IpAddr::V6(v6) => std::net::IpAddr::V6(v6),
    };
    SocketAddr::new(mapped, edge.port())
}

/// The PROXY-protocol header, either the text form or the binary one, written
/// before the hello so the cover origin sees who really connected.
pub fn write_proxy_protocol<W: Write>(
    target: &mut W,
    version: u8,
    edges: Edges,
) -> Result<(), std::io::Error> {
    match version {
        1 => {
            match (edges.local, edges.peer) {
                (Some(local), Some(peer)) => {
                    let family = if local.is_ipv4() && peer.is_ipv4() {
                        "TCP4"
                    } else {
                        "TCP6"
                    };
                    let (local, peer) = if family == "TCP6" {
                        (wide_socket(local), wide_socket(peer))
                    } else {
                        (local, peer)
                    };
                    // The longest line is two full IPv6 addresses and two ports.
                    let mut out = [0u8; 128];
                    let total = out.len();
                    let mut line: &mut [u8] = &mut out;
                    write!(
                        line,
                        "PROXY {family} {} {} {} {}\r\n",
                        local.ip(),
                        peer.ip(),
                        local.port(),
                        peer.port()
                    )
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "oversized proxy header",
                        )
                    })?;
                    let len = total - line.len();
                    target.write_all(&out[..len])
                }
                _ => target.write_all(b"PROXY UNKNOWN\r\n"),
            }
        }
        2 => {
            const MAGIC: [u8; 12] = [
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
            ];
            // Sixteen bytes of fixed head, then twelve for a v4 pair, thirty-six for a v6 one, and no port bytes at all with neither end known.
            let mut out = [0u8; 52];
            out[..12].copy_from_slice(&MAGIC);
            let (command, family, total) =
                if let (Some(local), Some(peer)) = (edges.local, edges.peer) {
                    let (family, near) = if local.is_ipv4() && peer.is_ipv4() {
                        out[16..20].copy_from_slice(&narrow(&local));
                        out[20..24].copy_from_slice(&narrow(&peer));
                        (0x11u8, 24usize)
                    } else {
                        out[16..32].copy_from_slice(&wide(&local));
                        out[32..48].copy_from_slice(&wide(&peer));
                        (0x21, 48)
                    };
                    out[near..near + 2].copy_from_slice(&local.port().to_be_bytes());
                    out[near + 2..near + 4].copy_from_slice(&peer.port().to_be_bytes());
                    (0x21, family, near + 4)
                } else {
                    (0x20, 0x30, 28)
                };
            out[12] = command;
            out[13] = family;
            out[14..16].copy_from_slice(
                &u16::try_from(total - 16)
                    .expect("one proxy header is never sixty-four kilobytes")
                    .to_be_bytes(),
            );
            target.write_all(&out[..total])
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unsupported proxy protocol version",
        )),
    }
}

struct Replay<S> {
    prefix: Vec<u8>,
    at: usize,
    io: S,
}

impl<S> Replay<S> {
    fn new(io: S) -> Self {
        Self {
            prefix: Vec::new(),
            at: 0,
            io,
        }
    }

    fn has_pending(&self) -> bool {
        self.at < self.prefix.len()
    }

    /// The socket under the replay: past the handshake the record layer is the
    /// caller's, and a relay's split reader reads this handle parked outside
    /// the session lock.
    fn transport(&self) -> &S {
        &self.io
    }

    fn set_prefix(&mut self, bytes: Vec<u8>) {
        self.prefix = bytes;
        self.at = 0;
    }

    fn into_inner(self) -> S {
        self.io
    }
}

impl<S: Read> Read for Replay<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(rest) = self.prefix.get(self.at..) {
            if !rest.is_empty() {
                let n = rest.len().min(buf.len());
                buf[..n].copy_from_slice(&rest[..n]);
                self.at += n;
                return Ok(n);
            }
        }
        self.io.read(buf)
    }
}

impl<S: Write> Write for Replay<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.io.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.io.flush()
    }
}

impl<S: super::RecordAlignment> super::RecordAlignment for Replay<S> {
    fn engage_record_alignment(&mut self) {
        self.io.engage_record_alignment();
    }

    fn disarm_record_alignment(&mut self) {
        self.io.disarm_record_alignment();
    }
}

/// Reads from the socket in TLS-record-sized bites once engaged, so the session
/// never buffers bytes past the record it is decrypting and a Vision direct-mode
/// unwrap finds every byte after the last framed record still in the kernel.
pub struct RecordLimiter<S> {
    io: S,
    header: [u8; 5],
    header_len: usize,
    payload_remaining: usize,
    align: bool,
    track: bool,
    prefix: Vec<u8>,
    at: usize,
}

impl<S> std::fmt::Debug for RecordLimiter<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordLimiter").finish_non_exhaustive()
    }
}

impl<S> RecordLimiter<S> {
    pub fn get_ref(&self) -> &S {
        &self.io
    }

    pub fn new(io: S) -> Self {
        Self {
            io,
            header: [0; 5],
            header_len: 0,
            payload_remaining: 0,
            align: true,
            track: true,
            prefix: Vec::new(),
            at: 0,
        }
    }

    pub fn new_open(io: S) -> Self {
        Self {
            io,
            header: [0; 5],
            header_len: 0,
            payload_remaining: 0,
            align: false,
            track: true,
            prefix: Vec::new(),
            at: 0,
        }
    }

    /// The bytes a peek already read, replayed before the socket so the engine sees the whole hello.
    pub fn set_prefix(&mut self, bytes: Vec<u8>) {
        self.prefix = bytes;
        self.at = 0;
    }

    fn into_inner(self) -> S {
        self.io
    }
}

impl<S> super::RecordAlignment for RecordLimiter<S> {
    fn engage_record_alignment(&mut self) {
        self.align = true;
        self.track = true;
    }

    fn disarm_record_alignment(&mut self) {
        self.align = false;
        self.track = false;
    }
}

impl<S: Read> Read for RecordLimiter<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let limit = if !self.track || !self.align {
            buf.len()
        } else if self.header_len < self.header.len() {
            buf.len().min(self.header.len() - self.header_len)
        } else {
            buf.len().min(self.payload_remaining)
        };
        if self.at < self.prefix.len() {
            let n = (self.prefix.len() - self.at).min(limit);
            buf[..n].copy_from_slice(&self.prefix[self.at..self.at + n]);
            self.at += n;
            if self.track {
                self.observe(&buf[..n]);
            }
            return Ok(n);
        }
        if !self.track {
            return self.io.read(buf);
        }
        let n = self.io.read(&mut buf[..limit])?;
        self.observe(&buf[..n]);
        Ok(n)
    }
}

impl<S: Write> Write for RecordLimiter<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.io.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.io.flush()
    }
}

impl<S: Read> RecordLimiter<S> {
    fn observe(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            if self.header_len < self.header.len() {
                let len = (self.header.len() - self.header_len).min(bytes.len());
                self.header[self.header_len..self.header_len + len].copy_from_slice(&bytes[..len]);
                self.header_len += len;
                bytes = &bytes[len..];
                if self.header_len < self.header.len() {
                    return;
                }
                self.payload_remaining =
                    usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
                if self.payload_remaining == 0 {
                    self.header_len = 0;
                }
            } else {
                let len = bytes.len().min(self.payload_remaining);
                bytes = &bytes[len..];
                self.payload_remaining -= len;
                if self.payload_remaining == 0 {
                    self.header_len = 0;
                }
            }
        }
    }
}

#[derive(Debug)]
struct ClientHello {
    session_id: (usize, usize),
    random: [u8; 32],
    server_name: Option<(usize, usize)>,
    peer_key: [u8; 32],
}

/// Where the handshake body lives: a hello that arrives in one record is read
/// out of the record stream itself, and only a split hello is gathered aside.
#[derive(Debug)]
enum Body {
    Inline { len: usize },
    Split(Vec<u8>),
}

fn read_client_hello<S: Read>(io: &mut S) -> Result<(Vec<u8>, Body, ClientHello), Refused> {
    let mut raw: Vec<u8> = Vec::new();
    let mut split: Vec<u8> = Vec::new();
    let mut header = [0u8; 5];
    let mut first = true;
    loop {
        if read_to_fill(io, &mut header) != header.len() {
            return Err((TlsError::Closed, raw));
        }
        if header[0] != 0x16 {
            raw.extend_from_slice(&header);
            return Err((
                TlsError::Other("reality: expected a handshake record".to_owned()),
                raw,
            ));
        }
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if len > MAX_RECORD {
            raw.extend_from_slice(&header);
            return Err((
                TlsError::Other("reality: oversized handshake record".to_owned()),
                raw,
            ));
        }
        let at = raw.len();
        // the read fills the spare capacity or abandons it, so nothing uninitialised is ever part of the buffer
        raw.reserve(5 + len);
        raw.extend_from_slice(&header);
        let grown: &mut [u8] =
            unsafe { core::slice::from_raw_parts_mut(raw.as_mut_ptr().add(at + 5), len) };
        let filled = read_to_fill(io, grown);
        unsafe { raw.set_len(at + 5 + filled) };
        if filled < len {
            return Err((TlsError::Closed, raw));
        }
        if first {
            first = false;
            if let Some(whole) = hello_is_whole(&raw[5..]) {
                // the last record may carry past the declared handshake length, and that tail is not part of the hello
                let hello = match parse_client_hello(&raw[5..5 + whole]) {
                    Ok(hello) => hello,
                    Err(why) => return Err((why, raw)),
                };
                return Ok((raw, Body::Inline { len: whole }, hello));
            }
            split.extend_from_slice(&raw[5..]);
        } else {
            split.extend_from_slice(&raw[at + 5..]);
            if let Some(whole) = hello_is_whole(&split) {
                split.truncate(whole);
                let hello = match parse_client_hello(&split) {
                    Ok(hello) => hello,
                    Err(why) => return Err((why, raw)),
                };
                return Ok((raw, Body::Split(split), hello));
            }
            if split.len() > MAX_HELLO {
                return Err((
                    TlsError::Other("reality: oversized ClientHello".to_owned()),
                    raw,
                ));
            }
        }
    }
}

/// Why the hello was refused, beside every byte the reader took from the peer before the break:
/// a refusal that consumed anything splices those bytes on, which is what the reference does with
/// a hello it cannot authenticate.
type Refused = (TlsError, Vec<u8>);

pub(crate) fn read_to_fill<R: Read>(io: &mut R, buf: &mut [u8]) -> usize {
    let mut at = 0;
    while at < buf.len() {
        match io.read(&mut buf[at..]) {
            Ok(0) => break,
            Ok(n) => at += n,
            Err(error) if waiting(&error) => {}
            Err(_) => break,
        }
    }
    at
}

fn waiting(error: &std::io::Error) -> bool {
    TlsError::is_timeout(error)
}

fn hello_is_whole(bytes: &[u8]) -> Option<usize> {
    if bytes.first()? != &0x01 || bytes.len() < 4 {
        return None;
    }
    let want = 4 + u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]) as usize;
    (bytes.len() >= want).then_some(want)
}

/// Whether the hello authenticates: no reason is carried, the caller splices either way.
fn authenticate(
    cfg: &RealityServerConfig,
    body: &mut [u8],
    hello: &ClientHello,
    now_ms: u64,
) -> Option<[u8; 32]> {
    if hello.session_id.1 != 32 {
        return None;
    }
    let name: &[u8] = hello
        .server_name
        .and_then(|(at, len)| body.get(at..at + len))
        .unwrap_or_default();
    if !cfg
        .server_names
        .iter()
        .any(|allowed| allowed.as_bytes() == name)
    {
        return None;
    }

    let shared = x25519_dalek::x25519(cfg.private_key, hello.peer_key);
    if shared == [0u8; 32] {
        return None;
    }
    let auth_key = auth_key(&shared, &hello.random)?;

    // The session id is both the sealed blob and the only thing the AAD wants zeroed, so the blob rides on the stack and the buffer authenticates itself: no second copy of the hello is made to build the AAD.
    let (at, len) = hello.session_id;
    let ciphertext: [u8; 32] = body[at..at + len]
        .try_into()
        .expect("the session id is 32 bytes");
    let mut opened = [0u8; 16];
    let mut tag = [0u8; 16];
    opened.copy_from_slice(&ciphertext[..16]);
    tag.copy_from_slice(&ciphertext[16..]);
    body[at..at + len].fill(0);
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&auth_key).ok()?;
    let decryption = cipher.decrypt_inout_detached(
        &aes_gcm::Nonce::try_from(&hello.random[20..]).expect("length"),
        body,
        (&mut opened[..]).into(),
        &aes_gcm::Tag::try_from(&tag[..]).expect("length"),
    );
    // The splice and the replay both read the buffer after, so the blob goes back.
    body[at..at + len].copy_from_slice(&ciphertext);
    decryption.ok()?;
    let plain = opened;

    let client_ver = [plain[0], plain[1], plain[2]];
    if cfg.min_client_ver.is_some_and(|lo| client_ver < lo)
        || cfg.max_client_ver.is_some_and(|hi| client_ver > hi)
    {
        return None;
    }
    let short_id = std::array::from_fn(|i| plain[8 + i]);
    if !cfg.short_ids.contains(&short_id) {
        return None;
    }
    if let Some(skew) = cfg.max_time_skew {
        let sent = u64::from(u32::from_be_bytes([plain[4], plain[5], plain[6], plain[7]])) * 1000;
        if now_ms.abs_diff(sent) > u64::try_from(skew.as_millis()).unwrap_or(u64::MAX) {
            return None;
        }
    }
    Some(auth_key)
}

fn first_name(cfg: &RealityServerConfig) -> &str {
    cfg.server_names.first().map_or("", String::as_str)
}

fn parse_client_hello(body: &[u8]) -> Result<ClientHello, TlsError> {
    let bad = || TlsError::Other("reality: malformed ClientHello".to_owned());
    let mut at = 4 + 2;
    let random = body
        .get(at..at + 32)
        .and_then(|r| <[u8; 32]>::try_from(r).ok())
        .ok_or_else(bad)?;
    at += 32;
    let session_id_len = usize::from(*body.get(at).ok_or_else(bad)?);
    at += 1;
    if body.get(at..at + session_id_len).is_none() {
        return Err(bad());
    }
    let session_id = (at, session_id_len);
    at += session_id_len;
    let suites_len = usize::from(u16::from_be_bytes(
        body.get(at..at + 2)
            .and_then(|b| <[u8; 2]>::try_from(b).ok())
            .ok_or_else(bad)?,
    ));
    at += 2 + suites_len;
    let compression_len = usize::from(*body.get(at).ok_or_else(bad)?);
    at += 1 + compression_len;
    let ext_len = usize::from(u16::from_be_bytes(
        body.get(at..at + 2)
            .and_then(|b| <[u8; 2]>::try_from(b).ok())
            .ok_or_else(bad)?,
    ));
    at += 2;
    if body.get(at..at + ext_len).is_none() {
        return Err(bad());
    }

    let mut hello = ClientHello {
        session_id,
        random,
        server_name: None,
        peer_key: [0u8; 32],
    };
    let mut has_tls13 = false;
    let mut key_share = None;
    for (kind, ext) in extensions(body, at, ext_len) {
        match kind {
            0x0000 => hello.server_name = server_name_at(body, ext),
            0x002b => has_tls13 = offers_tls13(ext),
            0x0033 => key_share = x25519_share(ext),
            _ => {}
        }
    }
    if !has_tls13 {
        return Err(TlsError::Other(
            "reality: ClientHello does not offer TLS 1.3".to_owned(),
        ));
    }
    hello.peer_key = key_share.ok_or_else(|| {
        TlsError::Other("reality: ClientHello carries no X25519 share".to_owned())
    })?;
    Ok(hello)
}

fn extensions(bytes: &[u8], at: usize, len: usize) -> impl Iterator<Item = (u16, &[u8])> {
    let end = at + len;
    (at..end).scan(at, move |cursor, _| {
        let head = bytes.get(*cursor..*cursor + 4)?;
        let kind = u16::from_be_bytes([head[0], head[1]]);
        let size = usize::from(u16::from_be_bytes([head[2], head[3]]));
        let body = bytes.get(*cursor + 4..*cursor + 4 + size)?;
        *cursor += 4 + size;
        Some((kind, body))
    })
}

/// The SNI as offsets into the hello, so matching it allocates and copies nothing.
fn server_name_at(full: &[u8], body: &[u8]) -> Option<(usize, usize)> {
    let base = body.as_ptr() as usize - full.as_ptr() as usize;
    let mut at = 2usize;
    while at < body.len() {
        let kind = *body.get(at)?;
        at += 1;
        let len = usize::from(u16::from_be_bytes([*body.get(at)?, *body.get(at + 1)?]));
        at += 2;
        let name_at = at;
        at = at.checked_add(len)?;
        let name = body.get(name_at..name_at + len)?;
        if kind == 0 {
            return std::str::from_utf8(name)
                .ok()
                .map(|_| (base + name_at, len));
        }
    }
    None
}

/// Whether the `supported_versions` body lists TLS 1.3, read straight out of
/// the list rather than collected first.
fn offers_tls13(body: &[u8]) -> bool {
    let Some(&len) = body.first() else {
        return false;
    };
    body.get(1..1 + usize::from(len))
        .unwrap_or_default()
        .as_chunks::<2>()
        .0
        .iter()
        .any(|chunk| u16::from_be_bytes(*chunk) == TLS13)
}

fn x25519_share(body: &[u8]) -> Option<[u8; 32]> {
    let hybrid_len = MLKEM768_KEY_LEN + 32;
    let mut plain = None;
    let mut hybrid = None;
    let mut list = Cursor::new(body, 2);
    while !list.empty() {
        let group = list.u16()?;
        let share = list.slice()?;
        match (group, share.len()) {
            (GROUP_X25519, 32) if plain.is_none() => {
                plain = Some(<[u8; 32]>::try_from(share).ok()?);
            }
            (GROUP_X25519_MLKEM768, len) if len == hybrid_len && hybrid.is_none() => {
                hybrid = Some(<[u8; 32]>::try_from(&share[MLKEM768_KEY_LEN..]).ok()?);
            }
            (GROUP_X25519_MLKEM768_DRAFT, len) if len == hybrid_len && hybrid.is_none() => {
                hybrid = Some(<[u8; 32]>::try_from(&share[..32]).ok()?);
            }
            _ => {}
        }
    }
    plain.or(hybrid)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8], at: usize) -> Self {
        Self { bytes, at }
    }

    fn empty(&self) -> bool {
        self.at >= self.bytes.len()
    }

    fn u16(&mut self) -> Option<u16> {
        let head = self.bytes.get(self.at..self.at + 2)?;
        self.at += 2;
        Some(u16::from_be_bytes([head[0], head[1]]))
    }

    fn slice(&mut self) -> Option<&'a [u8]> {
        let len = usize::from(self.u16()?);
        let body = self.bytes.get(self.at..self.at + len)?;
        self.at += len;
        Some(body)
    }
}

/// One distinguished name: the RDN sequence holding one common-name attribute.
fn distinguished_name(out: &mut Vec<u8>, name: &str) {
    wrap(out, 0x30, |out| {
        wrap(out, 0x31, |out| {
            wrap(out, 0x30, |out| {
                item(out, 0x06, &[0x55, 0x04, 0x03]);
                item(out, 0x0c, name.as_bytes());
            });
        });
    });
}

/// The `AlgorithmIdentifier` for Ed25519, named wherever it appears.
fn algorithm(out: &mut Vec<u8>) {
    wrap(out, 0x30, |out| out.extend_from_slice(&OID_ED25519));
}

/// The bound certificate's buffer size, placeholders included: the deepest
/// nesting holds five four-byte placeholders against two-byte finals or more.
fn certificate_capacity(name_len: usize) -> usize {
    fn tlv(body: usize) -> usize {
        body + 1
            + if body < 0x80 {
                1
            } else if body < 0x100 {
                2
            } else {
                3
            }
    }
    let distinguished = tlv(tlv(tlv(tlv(name_len) + 5)));
    let validity = tlv(tlv(13) + tlv(13));
    let public = tlv(7 + tlv(33));
    let signed = tlv(tlv(65));
    let body = tlv(tlv(1)) + tlv(1) + 7 + distinguished + validity + distinguished + public;
    tlv(tlv(body) + 7 + signed) + 10
}

/// A leaf bound to one authentication key. The proof is the last sixty-four
/// bytes, which is what the oracle in the tests reads.
fn bound_certificate(auth_key: &[u8; 32], name: &str) -> Vec<u8> {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, auth_key);
    let proof = ring::hmac::sign(&key, public_key());
    let key = public_key();

    let mut der = Vec::with_capacity(certificate_capacity(name.len()));
    wrap(&mut der, 0x30, |der| {
        wrap(der, 0x30, |der| {
            item(der, 0xa0, &[0x02, 0x01, 0x02]);
            item(der, 0x02, &[0x01]);
            algorithm(der);
            distinguished_name(der, name);
            wrap(der, 0x30, |der| {
                item(der, 0x17, b"260101000000Z");
                item(der, 0x17, b"491231235959Z");
            });
            distinguished_name(der, name);
            wrap(der, 0x30, |der| {
                algorithm(der);
                wrap(der, 0x03, |der| {
                    // the BIT STRING's unused-bits byte, then the key itself
                    der.push(0x00);
                    der.extend_from_slice(key);
                });
            });
        });
        algorithm(der);
        wrap(der, 0x03, |der| {
            der.push(0x00);
            der.extend_from_slice(proof.as_ref());
        });
    });
    debug_assert_eq!(&der[der.len() - SIGNATURE_LEN..], proof.as_ref());
    der
}

/// One element with no children of its own.
fn item(out: &mut Vec<u8>, tag: u8, body: &[u8]) {
    out.push(tag);
    let mut head = [0u8; 4];
    let taken = length_into(&mut head, body.len());
    out.extend_from_slice(&head[..taken]);
    out.extend_from_slice(body);
}

/// The shortest DER form of `len`, and how many bytes of `dst` it took.
fn length_into(dst: &mut [u8; 4], len: usize) -> usize {
    if len < 0x80 {
        dst[0] = len as u8;
        1
    } else if len < 0x100 {
        dst[0] = 0x81;
        dst[1] = len as u8;
        2
    } else {
        dst[0] = 0x82;
        dst[1..3].copy_from_slice(&(len as u16).to_be_bytes());
        3
    }
}

/// Writes `body` into `out` under `tag` and patches the length in afterwards, so
/// one certificate is one buffer rather than one buffer per element.
fn wrap(out: &mut Vec<u8>, tag: u8, body: impl FnOnce(&mut Vec<u8>)) {
    let at = out.len();
    out.extend_from_slice(&[tag, 0x82, 0, 0]);
    body(out);
    let len = out.len() - at - 4;
    let mut head = [0u8; 4];
    let taken = length_into(&mut head, len);
    let after = at + taken + 1;
    out.copy_within(at + 4.., after);
    out[at] = tag;
    out[at + 1..after].copy_from_slice(&head[..taken]);
    out.truncate(after + len);
}

fn public_key() -> &'static [u8; 32] {
    static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(&pkcs8())
            .expect("the fixed seed is a PKCS#8 Ed25519 key ring accepts");
        <[u8; 32]>::try_from(pair.public_key().as_ref()).expect("an Ed25519 key is 32 bytes")
    })
}

fn ed25519_pkcs8() -> Vec<u8> {
    static DOC: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    DOC.get_or_init(pkcs8).clone()
}

fn pkcs8() -> Vec<u8> {
    let mut out = PKCS8_ED25519_SEED_HEADER.to_vec();
    out.extend_from_slice(&ED25519_SEED);
    out
}

/// The key both ends seal and verify with: `HKDF-SHA256(salt = random[..20], ikm = shared, info = "REALITY")`.
fn auth_key(shared: &[u8; 32], random: &[u8; 32]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(Some(&random[..20]), shared)
        .expand(b"REALITY", &mut out)
        .ok()?;
    Some(out)
}

/// Everything the client needs to open one REALITY connection.
#[derive(Debug, Clone)]
pub struct RealityClientConfig {
    pub server_name: String,
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    /// The parrot whose hello carries the seal, as `tlsSettings.fingerprint` names it.
    pub fingerprint: String,
    /// The `realitySettings.masterKeyLog` file this dial appends its traffic secrets to, or `None`.
    pub key_log: Option<std::sync::Arc<crate::tls::MasterKeyLog>>,
}

/// The version reported in the sealed session id, the pinned Xray-core release.
const CLIENT_VERSION: [u8; 3] = [26, 10, 10];

/// An authenticated REALITY client session: the same stream shape as every other TLS provider.
pub struct RealityClientSession<S: Stream> {
    inner: crate::tls::shaped::Session<S>,
}

impl<S: Stream> std::fmt::Debug for RealityClientSession<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityClientSession")
            .finish_non_exhaustive()
    }
}

impl<S: Stream> RealityClientSession<S> {
    pub fn get_ref(&self) -> &S {
        self.inner.get_ref()
    }

    /// Seals the session id into the named parrot's hello and runs the handshake.
    /// A peer that answers with any other certificate is the cover origin, so the
    /// handshake fails and no proxy byte is ever sent into it. The clock rides
    /// along because the core stays deterministic: the caller owns time.
    pub fn connect(cfg: &RealityClientConfig, now: u32, io: S) -> Result<Self, TlsError> {
        let profile = crate::tls::shaped::Fingerprint::resolve(&cfg.fingerprint)
            .and_then(crate::tls::shaped::Fingerprint::reality_profile)
            .ok_or_else(|| {
                TlsError::Other(format!(
                    "reality: fingerprint {:?} shapes no TLS 1.3 hello",
                    cfg.fingerprint
                ))
            })?;
        let mut hello = crate::tls::shaped::hello::Hello::build(
            profile,
            &cfg.server_name,
            &[],
            false,
            &[],
            None,
        )?;
        let secret = hello.auth_secret().ok_or_else(|| {
            TlsError::Other("reality: the hello carries no X25519 share".to_owned())
        })?;
        let shared = x25519_dalek::x25519(secret, cfg.public_key);
        if shared == [0u8; 32] {
            return Err(TlsError::Other(
                "reality: shared secret was all zero".to_owned(),
            ));
        }
        let auth_key = auth_key(&shared, &hello.random)
            .ok_or_else(|| TlsError::Other("reality: hkdf expand failed".to_owned()))?;
        hello.zero_session();
        let sealed = seal_session_id(
            &auth_key,
            &hello.random,
            CLIENT_VERSION,
            now,
            cfg.short_id,
            &hello.msg,
        );
        hello.seal_session(sealed);
        let verifier = std::sync::Arc::new(RealityVerifier::new(auth_key));
        let mut session = Self {
            inner: crate::tls::shaped::Session::with_hello(
                profile,
                cfg.server_name.clone(),
                verifier,
                hello,
                io,
            )?,
        };
        session.inner.set_key_log(cfg.key_log.clone());
        session.handshake()?;
        Ok(session)
    }
}

impl<S: Stream> TlsProvider for RealityClientSession<S> {
    fn name() -> &'static str {
        "utls"
    }

    fn suites(&self) -> Vec<String> {
        self.inner.suites()
    }

    fn closed(&self) -> bool {
        self.inner.closed()
    }

    fn handshake(&mut self) -> Result<(), TlsError> {
        self.inner.handshake()
    }

    fn open(&mut self, ciphertext: &[u8], buf: &mut [u8]) -> std::io::Result<(usize, usize)> {
        self.inner.open(ciphertext, buf)
    }

    fn alpn(&self) -> Option<&[u8]> {
        self.inner.alpn()
    }

    fn peer_leaf(&self) -> Option<&[u8]> {
        self.inner.peer_leaf()
    }

    fn seal_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> std::io::Result<usize> {
        self.inner.seal_into(plaintext, out)
    }

    fn seal_slices_into(&mut self, parts: &[&[u8]], out: &mut Vec<u8>) -> std::io::Result<()> {
        self.inner.seal_slices_into(parts, out)
    }
}

impl<S: Stream + super::RecordAlignment> super::RecordAlignment for RealityClientSession<S> {
    fn engage_record_alignment(&mut self) {
        self.inner.engage_record_alignment();
    }

    fn disarm_record_alignment(&mut self) {
        self.inner.disarm_record_alignment();
    }

    fn write_all_slices(&mut self, parts: &[&[u8]]) -> std::io::Result<()> {
        self.inner.write_all_slices(parts)
    }
}

impl<S: Stream> Read for RealityClientSession<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<S: Stream> Write for RealityClientSession<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// The 16-byte plaintext sealed into the session id: version, reserved, clock, short id.
fn session_plaintext(version: [u8; 3], now: u32, short_id: [u8; 8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..3].copy_from_slice(&version);
    out[4..8].copy_from_slice(&now.to_be_bytes());
    out[8..16].copy_from_slice(&short_id);
    out
}

/// Seals the short id over the zeroed hello as AAD: 16 bytes plus the 16-byte tag.
fn seal_session_id(
    auth_key: &[u8; 32],
    random: &[u8; 32],
    version: [u8; 3],
    now: u32,
    short_id: [u8; 8],
    aad: &[u8],
) -> [u8; 32] {
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(auth_key)
        .expect("a 32-byte auth key is always a valid AES-256 key");
    let sealed = cipher
        .encrypt(
            &aes_gcm::Nonce::try_from(&random[20..]).expect("length"),
            aes_gcm::aead::Payload {
                msg: &session_plaintext(version, now, short_id),
                aad,
            },
        )
        .expect("sealing 16 bytes cannot fail");
    sealed
        .try_into()
        .expect("a 16-byte plaintext seals to 32 bytes")
}

/// The HMAC the bound leaf carries: anything else is the cover origin, never proxied.
#[derive(Debug)]
struct RealityVerifier {
    auth_key: [u8; 32],
}

impl RealityVerifier {
    fn new(auth_key: [u8; 32]) -> Self {
        Self { auth_key }
    }
}

impl rustls::client::danger::ServerCertVerifier for RealityVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let Some((public, proof)) = parse_leaf(end_entity.as_ref()) else {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        };
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, &self.auth_key);
        ring::hmac::verify(&key, &public, &proof)
            .map(|()| rustls::client::danger::ServerCertVerified::assertion())
            .map_err(|_| {
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                )
            })
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let bad = || rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature);
        if dss.scheme != rustls::SignatureScheme::ED25519 {
            return Err(bad());
        }
        let (public, _) = parse_leaf(cert.as_ref()).ok_or_else(bad)?;
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public)
            .verify(message, dss.signature())
            .map(|()| rustls::client::danger::HandshakeSignatureValid::assertion())
            .map_err(|_| bad())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}

/// The leaf's Ed25519 key and its 64-byte proof, or `None` when the bytes are not DER.
fn parse_leaf(der: &[u8]) -> Option<([u8; 32], [u8; 64])> {
    let (_, tbs, signature) = signed_parts(der)?;
    let public = spki_key(tbs)?;
    Some((public, signature))
}

/// The signed body and the signature value of an outer `Certificate` sequence.
fn signed_parts(der: &[u8]) -> Option<(usize, &[u8], [u8; 64])> {
    let (header, len) = der_len(der)?;
    if der.first() != Some(&0x30) || der.len() < header + len {
        return None;
    }
    let mut at = header;
    let (tbs_header, tbs_len) = der_len(&der[at..])?;
    if der.get(at) != Some(&0x30) {
        return None;
    }
    let tbs = der.get(at..at + tbs_header + tbs_len)?;
    at += tbs_header + tbs_len;
    let (alg_header, alg_len) = der_len(&der[at..])?;
    at += alg_header + alg_len;
    let (sig_header, sig_len) = der_len(&der[at..])?;
    if der.get(at) != Some(&0x03) {
        return None;
    }
    let body = der.get(at + sig_header..at + sig_header + sig_len)?;
    if body.first() != Some(&0x00) || body.len() != 65 {
        return None;
    }
    Some((at, tbs, body[1..].try_into().ok()?))
}

/// The 32-byte key in the first Ed25519 `SubjectPublicKeyInfo` under the signed body.
fn spki_key(tbs: &[u8]) -> Option<[u8; 32]> {
    let mut rest = tbs;
    loop {
        let mut at = rest
            .windows(OID_ED25519.len())
            .position(|w| w == OID_ED25519)?;
        at += OID_ED25519.len();
        let candidate = rest.get(at..)?;
        if candidate.first() == Some(&0x03) {
            if let Some((header, len)) = der_len(candidate) {
                if let Some(body) = candidate.get(header..header + len) {
                    if body.first() == Some(&0x00) && body.len() == 33 {
                        return body[1..].try_into().ok();
                    }
                }
            }
        }
        rest = rest.get(at + 1..)?;
    }
}

/// One DER length prefix: the header that carries it, then the value length.
fn der_len(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.get(1)?;
    if first < 0x80 {
        Some((2, usize::from(first)))
    } else if first == 0x81 {
        Some((3, usize::from(*bytes.get(2)?)))
    } else if first == 0x82 {
        Some((
            4,
            usize::from(u16::from_be_bytes([*bytes.get(2)?, *bytes.get(3)?])),
        ))
    } else {
        None
    }
}

#[cfg(test)]
fn proof_at(der: &[u8]) -> &[u8] {
    &der[der.len() - SIGNATURE_LEN..]
}

#[cfg(test)]
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 0x80 {
        out.push(body.len() as u8);
    } else if body.len() < 0x100 {
        out.push(0x81);
        out.push(body.len() as u8);
    } else {
        out.push(0x82);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|part| part.len()).sum());
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::RecordAlignment as _;
    use std::io::ErrorKind;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    const SERVER_PRIVATE: [u8; 32] = [
        0x69, 0x20, 0xca, 0xab, 0x2b, 0x4d, 0xe3, 0x7d, 0xfc, 0xfe, 0xbf, 0x60, 0x8b, 0x2a, 0x43,
        0x1c, 0x0e, 0xbb, 0xae, 0x26, 0x93, 0x9a, 0x9c, 0x01, 0x9e, 0x06, 0x1e, 0x8a, 0x0b, 0x4e,
        0x6b, 0x91,
    ];
    const SHORT_ID: [u8; 8] = [1, 35, 69, 103, 137, 171, 205, 239];
    const SNI: &str = "www.google.com";

    fn settings() -> RealityServerConfig {
        RealityServerConfig {
            private_key: SERVER_PRIVATE,
            short_ids: vec![SHORT_ID],
            server_names: vec![SNI.to_owned()],
            max_time_skew: None,
            ..RealityServerConfig::default()
        }
    }

    fn hello_body(random: &[u8; 32], share: &[u8; 32], sni: &str) -> Vec<u8> {
        let mut ext = Vec::new();
        ext.extend_from_slice(&tlv_header(0x0000, &name_list(sni)));
        ext.extend_from_slice(&tlv_header(0x002b, &[2, 0x03, 0x04]));
        ext.extend_from_slice(&tlv_header(0x000a, &[0x00, 0x02, 0x00, 0x1d]));
        // No uTLS profile offers 0x0807, but the bound leaf is Ed25519 and a server only negotiates a listed scheme, so the helper lists it.
        ext.extend_from_slice(&tlv_header(
            0x000d,
            &[0x00, 0x06, 0x04, 0x03, 0x08, 0x04, 0x08, 0x07],
        ));
        let mut one = Vec::new();
        one.extend_from_slice(&GROUP_X25519.to_be_bytes());
        one.extend_from_slice(&32u16.to_be_bytes());
        one.extend_from_slice(share);
        let mut shares = u16::try_from(one.len()).unwrap().to_be_bytes().to_vec();
        shares.extend_from_slice(&one);
        ext.extend_from_slice(&tlv_header(0x0033, &shares));
        let ext_len = u16::try_from(ext.len()).unwrap();

        let mut body = Vec::new();
        body.extend_from_slice(&[0x01, 0, 0, 0]);
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(random);
        body.push(32);
        body.extend_from_slice(&[0u8; 32]);
        let suites: [u8; 6] = [0x13, 0x01, 0x13, 0x02, 0x13, 0x03];
        body.extend_from_slice(&u16::try_from(suites.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&suites);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&ext_len.to_be_bytes());
        body.extend_from_slice(&ext);
        let len = u32::try_from(body.len() - 4).unwrap();
        body[1..4].copy_from_slice(&len.to_be_bytes()[1..]);
        body
    }

    fn tlv_header(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut out = kind.to_be_bytes().to_vec();
        out.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn name_list(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0);
        out.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
        out.extend_from_slice(name.as_bytes());
        let mut list = u16::try_from(out.len()).unwrap().to_be_bytes().to_vec();
        list.extend_from_slice(&out);
        list
    }

    fn seal(
        body: &mut Vec<u8>,
        random: &[u8; 32],
        client_private: &[u8; 32],
        short_id: [u8; 8],
        now: u32,
    ) -> [u8; 32] {
        let mut server_public = [0u8; 32];
        server_public[0] = 9;
        let server_public = x25519_dalek::x25519(SERVER_PRIVATE, server_public);
        let shared = x25519_dalek::x25519(*client_private, server_public);
        let mut auth_key = [0u8; 32];
        hkdf::Hkdf::<sha2::Sha256>::new(Some(&random[..20]), &shared)
            .expand(b"REALITY", &mut auth_key)
            .unwrap();

        let mut plain = Vec::new();
        plain.extend_from_slice(&[26, 9, 30, 0]);
        plain.extend_from_slice(&now.to_be_bytes());
        plain.extend_from_slice(&short_id);
        let sealed = aes_gcm::Aes256Gcm::new_from_slice(&auth_key)
            .unwrap()
            .encrypt(
                &aes_gcm::Nonce::try_from(&random[20..]).expect("length"),
                Payload {
                    msg: &plain,
                    aad: body,
                },
            )
            .unwrap();
        assert_eq!(sealed.len(), 32);
        body[39..71].copy_from_slice(&sealed);
        auth_key
    }

    fn record(body: &[u8]) -> Vec<u8> {
        let mut out = vec![0x16, 0x03, 0x01];
        out.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    /// How long the cover origin is given to hand back what it was sent, which
    /// is the only boundary on reading a splice whose peer has nothing more to
    /// say.
    const COVER_WAIT: Duration = Duration::from_millis(400);

    struct Verdict {
        authenticated: bool,
        dialled: usize,
        cover: Vec<u8>,
    }

    fn offer(cfg: &RealityServerConfig, now_ms: u64, hello: &[u8]) -> Verdict {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let cover = TcpListener::bind("127.0.0.1:0").expect("binds");
        let mut cfg = cfg.clone();
        cfg.dest = Some(cover.local_addr().expect("addr").to_string());
        let settings = cfg.clone();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            RealityServer::accept(&settings, now_ms, stream, Edges::default()).ok()
        });
        let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        client.write_all(hello).expect("writes");
        client.flush().expect("flushes");
        let _ = client.shutdown(std::net::Shutdown::Write);
        let answer = server.join().expect("joins");
        let authenticated = matches!(answer, Some(RealityAccept::Session(_)));
        let mut dialled = 0;
        let mut seen = Vec::new();
        // A splice that returned is queued only once the peer's final ack lands, so wait for it.
        let spliced = matches!(answer, Some(RealityAccept::Proxied(_)));
        cover.set_nonblocking(true).expect("nonblocking");
        for _ in 0..COVER_WAIT.as_millis() / 2 {
            match cover.accept() {
                Ok((mut site, _)) => {
                    dialled += 1;
                    site.set_nonblocking(false).expect("blocking");
                    site.set_read_timeout(Some(COVER_WAIT)).expect("timeout");
                    let mut once = [0u8; 4096];
                    loop {
                        match site.read(&mut once) {
                            Ok(0) | Err(_) => break,
                            Ok(took) => seen.extend_from_slice(&once[..took]),
                        }
                    }
                    break;
                }
                Err(error) if spliced && error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
        Verdict {
            authenticated,
            dialled,
            cover: seen,
        }
    }

    fn accepted(now_ms: u64, bytes: &[u8]) -> bool {
        offer(&settings(), now_ms, bytes).authenticated
    }

    fn offer_with(cfg: &RealityServerConfig, now_ms: u64, bytes: &[u8]) -> Verdict {
        offer(cfg, now_ms, bytes)
    }

    fn refused_with(cfg: &RealityServerConfig, now_ms: u64, bytes: &[u8]) -> bool {
        !offer(cfg, now_ms, bytes).authenticated
    }

    fn good_hello() -> Vec<u8> {
        let client_private = [0x11u8; 32];
        let random: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
        let mut base = [0u8; 32];
        base[0] = 9;
        let share = x25519_dalek::x25519(client_private, base);
        let mut body = hello_body(&random, &share, SNI);
        seal(&mut body, &random, &client_private, SHORT_ID, 1_700_000_000);
        record(&body)
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn an_authenticated_hello_is_accepted() {
        assert!(accepted(0, &good_hello()));
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn every_unauthenticated_hello_is_refused() {
        let client_private = [0x11u8; 32];
        let random: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
        let mut base = [0u8; 32];
        base[0] = 9;
        let share = x25519_dalek::x25519(client_private, base);
        let wrong_short = [9u8; 8];
        let mut other = wrong_short;
        let build = |sni: &str, short: &[u8; 8]| {
            let mut body = hello_body(&random, &share, sni);
            seal(&mut body, &random, &client_private, *short, 1_700_000_000);
            record(&body)
        };

        assert!(!offer(&settings(), 0, &build("evil.example", &SHORT_ID)).authenticated);
        assert!(!offer(&settings(), 0, &build(SNI, &wrong_short)).authenticated);

        for at in [39usize, 50, 71, 100, 160] {
            let mut bytes = build(SNI, &SHORT_ID);
            let spot = at.min(bytes.len() - 1);
            bytes[spot] ^= 0x40;
            assert!(
                !offer(&settings(), 0, &bytes).authenticated,
                "byte {spot} was not covered"
            );
        }
        other[0] = 0;
        assert_ne!(other, wrong_short);

        assert!(!offer(&settings(), 0, b"not a tls record at all").authenticated);
        assert!(!offer(&settings(), 0, &[]).authenticated);
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn an_authenticated_hello_costs_the_cover_origin_nothing() {
        let verdict = offer(&settings(), 0, &good_hello());
        assert!(verdict.authenticated);
        assert_eq!(verdict.dialled, 0, "the cover origin must not be dialled");
        assert_eq!(verdict.cover.len(), 0);
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn an_unauthenticated_hello_is_spliced_into_the_cover_origin_byte_for_byte() {
        let mut bytes = good_hello();
        let spot = 71.min(bytes.len() - 1);
        bytes[spot] ^= 0x40;
        let verdict = offer(&settings(), 0, &bytes);
        assert!(!verdict.authenticated);
        assert_eq!(verdict.dialled, 1);
        assert_eq!(
            verdict.cover, bytes,
            "the cover origin must see the hello the server read"
        );
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_peer_that_sends_nothing_costs_the_cover_origin_nothing() {
        let verdict = offer(&settings(), 0, &[]);
        assert!(!verdict.authenticated);
        assert_eq!(
            verdict.dialled, 0,
            "an empty connection is a scanner, not a TLS client"
        );
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_hello_that_cannot_be_parsed_still_reaches_the_cover_origin() {
        // The reference splices whatever it cannot authenticate, so a peer whose hello trips a parse rule sees its own site answer rather than a closed socket: the close is both the detectable break and the hang, and only the bytes the server read go ahead with it.
        let mut truncated = good_hello();
        truncated.truncate(truncated.len() - 8);
        for (bytes, seen) in [
            (b"not a tls record at all".to_vec(), 5usize),
            (vec![0x16, 0x03, 0x01, 0xFF, 0xF8, 0x00], 5),
            (truncated.clone(), truncated.len()),
        ] {
            let verdict = offer(&settings(), 0, &bytes);
            assert!(
                !verdict.authenticated,
                "{} bytes authenticated",
                bytes.len()
            );
            assert_eq!(verdict.dialled, 1, "{} bytes dialled nothing", bytes.len());
            assert_eq!(
                verdict.cover,
                bytes[..seen],
                "{} bytes sent {} to the cover origin",
                bytes.len(),
                verdict.cover.len()
            );
        }
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_refused_hello_with_no_cover_origin_is_dropped_not_dialled() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            RealityServer::accept(&settings(), 0, stream, Edges::default()).is_ok()
        });
        let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let mut hello = good_hello();
        let spot = 71.min(hello.len() - 1);
        hello[spot] ^= 0x40;
        client.write_all(&hello).expect("writes");
        client.flush().expect("flushes");
        assert!(!server.join().expect("joins"));
        client
            .set_read_timeout(Some(COVER_WAIT))
            .expect("sets a read timeout");
        let mut silence = [0u8; 8];
        assert!(matches!(client.read(&mut silence), Ok(0) | Err(_)));
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn the_proxy_protocol_header_precedes_the_hello_on_the_cover_origin() {
        let mut bytes = good_hello();
        let spot = 71.min(bytes.len() - 1);
        bytes[spot] ^= 0x40;
        for (xver, head) in [(1u8, b"PROXY " as &[u8]), (2u8, &[0x0d, 0x0a])] {
            let mut cfg = settings();
            cfg.xver = xver;
            let verdict = offer(&cfg, 0, &bytes);
            assert_eq!(verdict.dialled, 1, "version {xver} never dialled");
            assert!(
                verdict.cover.starts_with(head),
                "version {xver} wrote no recognizable header"
            );
            let after = verdict.cover.len() - bytes.len();
            assert_eq!(&verdict.cover[after..], &bytes[..]);
        }
    }

    #[test]
    fn a_tcp6_text_header_writes_a_v4_edge_in_mapped_form() {
        let edges = Edges {
            local: Some("10.0.0.1:1234".parse().expect("local")),
            peer: Some("[2001:db8::1]:80".parse().expect("peer")),
        };
        let mut out = Vec::new();
        write_proxy_protocol(&mut out, 1, edges).expect("writes a header");
        assert_eq!(
            out, b"PROXY TCP6 ::ffff:10.0.0.1 2001:db8::1 1234 80\r\n",
            "a TCP6 line carries no bare dotted quad"
        );
    }

    #[cfg_attr(miri, ignore = "needs a loopback TCP socket")]
    #[test]
    fn the_text_proxy_header_names_both_ends_of_the_client_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let edges = Edges::of(&stream);
        assert!(edges.peer.is_some() && edges.local.is_some());
        assert_ne!(edges.peer, edges.local);
        let (mut site, _) = listener.accept().expect("accepts");
        write_proxy_protocol(&mut site, 1, edges).expect("writes a header");
        drop(site);
        let mut sink = stream;
        sink.set_read_timeout(Some(COVER_WAIT)).expect("timeout");
        let mut head = [0u8; 64];
        let mut got = Vec::new();
        while let Ok(took) = sink.read(&mut head) {
            if took == 0 {
                break;
            }
            got.extend_from_slice(&head[..took]);
            if got.contains(&b'\n') {
                break;
            }
        }
        let line = String::from_utf8_lossy(&got);
        assert!(
            line.starts_with("PROXY TCP4 127.0.0.1 127.0.0.1 "),
            "{line}"
        );
        assert!(line.ends_with("\r\n"));
    }

    #[cfg_attr(miri, ignore = "needs a loopback TCP socket")]
    #[test]
    fn the_binary_proxy_header_is_a_fixed_rectangular_twenty_eight_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let listening = listener.local_addr().expect("addr").port();
        let stream = TcpStream::connect(("127.0.0.1", listening)).expect("connects");
        let client = stream.local_addr().expect("addr").port();
        let (mut site, _) = listener.accept().expect("accepts");
        write_proxy_protocol(&mut site, 2, Edges::of(&stream)).expect("writes a header");
        drop(site);
        let mut sink = stream;
        sink.set_read_timeout(Some(COVER_WAIT)).expect("timeout");
        let mut head = [0u8; 28];
        let mut got = 0;
        while got < head.len() {
            match sink.read(&mut head[got..]) {
                Ok(0) | Err(_) => break,
                Ok(took) => got += took,
            }
        }
        assert_eq!(got, 28, "the header is a fixed twenty-eight bytes");
        assert_eq!(
            &head[..12],
            &[0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a]
        );
        assert_eq!(head[12], 0x21, "the version-and-command byte is 1.3");
        assert_eq!(head[13], 0x11, "the family is TCP over IPv4");
        assert_eq!(
            u16::from_be_bytes([head[14], head[15]]),
            12,
            "the length counts the two addresses and the two ports"
        );
        assert_eq!(&head[16..20], &[127, 0, 0, 1], "the source address");
        assert_eq!(&head[20..24], &[127, 0, 0, 1], "the destination address");
        assert_eq!(
            u16::from_be_bytes([head[24], head[25]]),
            client,
            "the source port"
        );
        assert_eq!(
            u16::from_be_bytes([head[26], head[27]]),
            listening,
            "the destination port"
        );
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_short_id_is_zero_padded_to_eight_bytes() {
        let cfg = RealityServerConfig {
            short_ids: vec![[1, 35, 69, 103, 0, 0, 0, 0]],
            ..settings()
        };
        let client_private = [0x22u8; 32];
        let random: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(5));
        let mut base = [0u8; 32];
        base[0] = 9;
        let share = x25519_dalek::x25519(client_private, base);
        let mut body = hello_body(&random, &share, SNI);
        seal(
            &mut body,
            &random,
            &client_private,
            [1, 35, 69, 103, 0, 0, 0, 0],
            1_700_000_000,
        );
        assert!(offer_with(&cfg, 0, &record(&body)).authenticated);
        assert!(!offer_with(&settings(), 0, &record(&body)).authenticated);
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_sub_second_clock_gate_does_not_refuse_every_hello() {
        let cfg = RealityServerConfig {
            max_time_skew: Some(Duration::from_millis(250)),
            ..settings()
        };
        let client_private = [0x44u8; 32];
        let random: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(9));
        let mut base = [0u8; 32];
        base[0] = 9;
        let share = x25519_dalek::x25519(client_private, base);
        let now = 1_788_000_000u64;
        let mut body = hello_body(&random, &share, SNI);
        seal(
            &mut body,
            &random,
            &client_private,
            SHORT_ID,
            u32::try_from(now).unwrap(),
        );
        assert!(offer_with(&cfg, now * 1000 + 100, &record(&body)).authenticated);
        assert!(!offer_with(&cfg, now * 1000 + 900, &record(&body)).authenticated);
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn the_client_version_gate_bites_only_when_it_is_set() {
        let client_private = [0x55u8; 32];
        let random: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(1));
        let mut base = [0u8; 32];
        base[0] = 9;
        let share = x25519_dalek::x25519(client_private, base);
        let mut body = hello_body(&random, &share, SNI);
        seal(&mut body, &random, &client_private, SHORT_ID, 1_700_000_000);
        let hello = record(&body);
        assert!(accepted(0, &hello), "no version gate must refuse nothing");
        let low = RealityServerConfig {
            min_client_ver: Some([27, 0, 0]),
            ..settings()
        };
        assert!(refused_with(&low, 0, &hello));
        let high = RealityServerConfig {
            max_client_ver: Some([1, 8, 1]),
            ..settings()
        };
        assert!(refused_with(&high, 0, &hello));
        let wide = RealityServerConfig {
            min_client_ver: Some([1, 0, 0]),
            max_client_ver: Some([30, 0, 0]),
            ..settings()
        };
        assert!(offer_with(&wide, 0, &hello).authenticated);
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn the_clock_gate_is_off_by_default_and_bites_when_set() {
        let cfg = RealityServerConfig {
            max_time_skew: Some(Duration::from_millis(1_500)),
            ..settings()
        };
        let client_private = [0x33u8; 32];
        let random: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(2));
        let mut base = [0u8; 32];
        base[0] = 9;
        let share = x25519_dalek::x25519(client_private, base);
        let now = 1_788_000_000u64;
        let stale = u32::try_from(now - 3600).unwrap();
        let mut body = hello_body(&random, &share, SNI);
        seal(&mut body, &random, &client_private, SHORT_ID, stale);
        assert!(refused_with(&cfg, now * 1000, &record(&body)));
        let mut body = hello_body(&random, &share, SNI);
        seal(
            &mut body,
            &random,
            &client_private,
            SHORT_ID,
            u32::try_from(now).unwrap(),
        );
        assert!(offer_with(&cfg, now * 1000, &record(&body)).authenticated);
    }

    #[test]
    fn the_x25519_share_is_found_in_every_group_that_carries_one() {
        let key = [0x5au8; 32];
        let mut shares = Vec::new();
        shares.extend_from_slice(&GROUP_X25519.to_be_bytes());
        shares.extend_from_slice(&32u16.to_be_bytes());
        shares.extend_from_slice(&key);
        let mut list = u16::try_from(shares.len()).unwrap().to_be_bytes().to_vec();
        list.extend_from_slice(&shares);
        assert_eq!(x25519_share(&list), Some(key));

        let mut hybrid = vec![0xa5u8; MLKEM768_KEY_LEN];
        hybrid.extend_from_slice(&key);
        let mut shares = GROUP_X25519_MLKEM768.to_be_bytes().to_vec();
        shares.extend_from_slice(&u16::try_from(hybrid.len()).unwrap().to_be_bytes());
        shares.extend_from_slice(&hybrid);
        let mut list = u16::try_from(shares.len()).unwrap().to_be_bytes().to_vec();
        list.extend_from_slice(&shares);
        assert_eq!(x25519_share(&list), Some(key));

        let mut draft = key.to_vec();
        draft.extend_from_slice(&[0xa5u8; MLKEM768_KEY_LEN]);
        let mut shares = GROUP_X25519_MLKEM768_DRAFT.to_be_bytes().to_vec();
        shares.extend_from_slice(&u16::try_from(draft.len()).unwrap().to_be_bytes());
        shares.extend_from_slice(&draft);
        let mut list = u16::try_from(shares.len()).unwrap().to_be_bytes().to_vec();
        list.extend_from_slice(&shares);
        assert_eq!(x25519_share(&list), Some(key));

        assert_eq!(x25519_share(&[0, 0]), None);
    }

    #[test]
    fn a_plain_share_is_preferred_over_a_hybrid_one() {
        let plain = [0x11u8; 32];
        let hybrid_key = [0x22u8; 32];
        assert_ne!(plain, hybrid_key);
        let mut hybrid = vec![0xa5u8; MLKEM768_KEY_LEN];
        hybrid.extend_from_slice(&hybrid_key);
        let mut shares = GROUP_X25519_MLKEM768.to_be_bytes().to_vec();
        shares.extend_from_slice(&u16::try_from(hybrid.len()).unwrap().to_be_bytes());
        shares.extend_from_slice(&hybrid);
        shares.extend_from_slice(&GROUP_X25519.to_be_bytes());
        shares.extend_from_slice(&32u16.to_be_bytes());
        shares.extend_from_slice(&plain);
        let mut list = u16::try_from(shares.len()).unwrap().to_be_bytes().to_vec();
        list.extend_from_slice(&shares);
        assert_eq!(x25519_share(&list), Some(plain));
        let _ = hybrid_key;
    }

    #[cfg_attr(
        miri,
        ignore = "reaches ring's C and assembly, which Miri cannot interpret"
    )]
    #[test]
    fn the_fixed_seed_derives_one_stable_public_key() {
        assert_eq!(public_key().len(), 32);
        assert_ne!(public_key(), &[0u8; 32]);
    }

    #[cfg_attr(
        miri,
        ignore = "reaches ring's C and assembly, which Miri cannot interpret"
    )]
    #[test]
    fn an_authenticated_hello_allocates_one_buffer_for_the_whole_certificate() {
        assert_ne!(
            public_key(),
            &[0u8; 32],
            "warming the key wins the init race"
        );
        let (der, counts) = crate::alloc_count::measure(|| bound_certificate(&[3u8; 32], SNI));
        assert_eq!(
            counts.allocs, 1,
            "one buffer for the whole certificate: {counts:?}"
        );
        assert_eq!(der, oracle_certificate(&[3u8; 32], SNI));
        assert!(
            der.len() <= der.capacity(),
            "the buffer was sized for the certificate"
        );
    }

    #[cfg_attr(
        miri,
        ignore = "reaches ring's C and assembly, which Miri cannot interpret"
    )]
    #[test]
    fn authenticating_a_hello_copies_nothing_out_of_the_hello() {
        let bytes = good_hello();
        let body = &bytes[5..];
        let mut dribble = Dribble::of(&bytes);
        let (mut raw, heard, hello) = read_client_hello(&mut dribble).expect("reads whole");
        assert_eq!(raw, bytes, "the record stream is kept whole");
        let Body::Inline { len: whole } = heard else {
            panic!("one record stays inline");
        };
        assert_eq!(whole, body.len());
        let (at, session) = hello.session_id;
        assert!(
            at + session <= whole,
            "the session id lies inside the hello"
        );
        let cfg = settings();
        let before = raw[5..5 + whole].to_vec();
        let (auth_key, counts) =
            crate::alloc_count::measure(|| authenticate(&cfg, &mut raw[5..5 + whole], &hello, 0));
        assert_eq!(
            counts.allocs, 0,
            "the sealed blob, the tag and the AAD all ride on the stack: {counts:?}"
        );
        assert_eq!(
            raw[5..5 + whole],
            before[..],
            "the zeroed session id is restored"
        );
        assert_eq!(raw, bytes, "the record stream is untouched");
        assert_ne!(auth_key.expect("authenticates"), [0u8; 32]);
    }

    #[cfg_attr(
        miri,
        ignore = "reaches ring's C and assembly, which Miri cannot interpret"
    )]
    #[test]
    fn the_certificate_is_the_bytes_the_element_oracle_builds() {
        let auth_key = [3u8; 32];
        assert_ne!(
            public_key(),
            &[0u8; 32],
            "warming the key wins the init race"
        );
        let names = [
            "",
            "a",
            SNI,
            "a-host-name-that-is-long-enough-to-need-the-two-byte-length-form.example",
            &"n".repeat(200),
        ];
        for name in names {
            let (der, counts) = crate::alloc_count::measure(|| bound_certificate(&auth_key, name));
            assert_eq!(
                counts.allocs, 1,
                "one buffer at every length form: {counts:?}"
            );
            assert_eq!(der, oracle_certificate(&auth_key, name), "name {name:?}");
        }
        for key in [[0u8; 32], [0xffu8; 32], [7u8; 32]] {
            let long = "x".repeat(300);
            let (der, counts) = crate::alloc_count::measure(|| bound_certificate(&key, &long));
            assert_eq!(
                counts.allocs, 1,
                "one buffer at every length form: {counts:?}"
            );
            assert_eq!(der, oracle_certificate(&key, &long));
        }
    }

    /// The certificate as the element-at-a-time builder wrote it, kept as the
    /// oracle the single-buffer emitter is checked against.
    fn oracle_certificate(auth_key: &[u8; 32], name: &str) -> Vec<u8> {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, auth_key);
        let proof = ring::hmac::sign(&key, public_key());

        let algorithm = tlv(0x30, &OID_ED25519);
        let who = oracle_name(name);
        let validity = tlv(
            0x30,
            &sequence(&[&tlv(0x17, b"260101000000Z"), &tlv(0x17, b"491231235959Z")]),
        );
        let spki = tlv(
            0x30,
            &sequence(&[&algorithm, &tlv(0x03, &sequence(&[&[0x00], public_key()]))]),
        );
        let tbs = tlv(
            0x30,
            &sequence(&[
                &tlv(0xa0, &tlv(0x02, &[0x02])),
                &tlv(0x02, &[0x01]),
                &algorithm,
                &who,
                &validity,
                &who,
                &spki,
            ]),
        );
        tlv(
            0x30,
            &sequence(&[
                &tbs,
                &algorithm,
                &tlv(0x03, &sequence(&[&[0x00], proof.as_ref()])),
            ]),
        )
    }

    fn oracle_name(name: &str) -> Vec<u8> {
        let attribute = tlv(
            0x30,
            &sequence(&[&tlv(0x06, &[0x55, 0x04, 0x03]), &tlv(0x0c, name.as_bytes())]),
        );
        tlv(0x30, &sequence(&[&tlv(0x31, &attribute)]))
    }

    #[cfg_attr(
        miri,
        ignore = "reaches ring's C and assembly, which Miri cannot interpret"
    )]
    #[test]
    fn the_certificate_is_well_formed_der_carrying_the_proof_last() {
        let auth_key = [3u8; 32];
        let der = bound_certificate(&auth_key, SNI);
        assert!(walk_der(&der));
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, &auth_key);
        assert_eq!(
            proof_at(&der),
            ring::hmac::sign(&key, public_key()).as_ref(),
        );
        assert_eq!(proof_at(&der).len(), SIGNATURE_LEN);
        assert!(der.windows(OID_ED25519.len()).any(|w| w == OID_ED25519));
    }

    #[cfg_attr(
        miri,
        ignore = "reaches ring's C and assembly, which Miri cannot interpret"
    )]
    #[test]
    fn the_certificate_differs_per_auth_key() {
        let a = bound_certificate(&[1u8; 32], SNI);
        let b = bound_certificate(&[2u8; 32], SNI);
        assert_ne!(proof_at(&a), proof_at(&b));
        assert_eq!(a.len(), b.len());
    }

    #[cfg_attr(
        miri,
        ignore = "reaches ring's C and assembly, which Miri cannot interpret"
    )]
    #[test]
    fn the_private_key_is_a_pkcs8_document_ring_accepts() {
        let der = ed25519_pkcs8();
        assert_eq!(der.len(), PKCS8_ED25519_SEED_HEADER.len() + 32);
        assert!(ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der).is_ok());
    }

    fn walk_der(bytes: &[u8]) -> bool {
        let mut at = 0;
        while at < bytes.len() {
            let Some((tag, header, total)) = element(&bytes[at..]) else {
                return false;
            };
            if tag & 0x20 != 0 && !walk_der(&bytes[at + header..at + total]) {
                return false;
            }
            at += total;
        }
        at > 0 && at == bytes.len()
    }

    fn element(bytes: &[u8]) -> Option<(u8, usize, usize)> {
        let (&tag, &first) = (bytes.first()?, bytes.get(1)?);
        assert_ne!(tag, 0, "a `DER` element has a tag");
        let (header, len) = match first {
            len if len < 0x80 => (2usize, usize::from(len)),
            0x81 => (3, usize::from(*bytes.get(2)?)),
            0x82 => (
                4,
                usize::from(u16::from_be_bytes([*bytes.get(2)?, *bytes.get(3)?])),
            ),
            _ => return None,
        };
        let total = header.checked_add(len)?;
        (total <= bytes.len()).then_some((tag, header, total))
    }

    #[cfg_attr(
        miri,
        ignore = "reaches ring's C and assembly, which Miri cannot interpret"
    )]
    #[test]
    fn the_der_walker_rejects_a_truncated_certificate() {
        assert!(walk_der(&bound_certificate(&[4u8; 32], SNI)));
        assert!(!walk_der(&[0x30, 0x05, 0x02, 0x01, 0x01]));
        assert!(!walk_der(&[0x30]));
        assert!(!walk_der(&[]));
    }

    #[cfg_attr(
        miri,
        ignore = "reaches ring's C and assembly, which Miri cannot interpret"
    )]
    #[test]
    fn the_private_key_is_one_rustls_can_sign_with() {
        let key = rustls::crypto::ring::sign::any_supported_type(
            &rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                ed25519_pkcs8(),
            )),
        )
        .expect("rustls accepts the Ed25519 key");
        assert_eq!(key.algorithm(), rustls::SignatureAlgorithm::ED25519);
        let spki = key
            .public_key()
            .expect("a signing key publishes its public half");
        assert_eq!(spki.as_ref().len(), 44, "an `Ed25519` `SPKI` is 44 bytes");
        assert_eq!(&spki.as_ref()[12..], public_key().as_slice());
    }

    #[cfg_attr(
        miri,
        ignore = "reaches ring's C and assembly, which Miri cannot interpret"
    )]
    #[test]
    fn the_reality_certificate_verify_answers_ed25519_the_peer_never_offered() {
        let inner = rustls::crypto::ring::sign::any_supported_type(
            &rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                ed25519_pkcs8(),
            )),
        )
        .expect("rustls accepts the Ed25519 key");
        let forced = crate::tls::rustls_backend::RealitySigningKey { inner };
        let offered = [
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ];
        let signer = rustls::sign::SigningKey::choose_scheme(&forced, &offered)
            .expect("REALITY answers Ed25519 unconditionally");
        assert_eq!(
            rustls::sign::Signer::scheme(&*signer),
            rustls::SignatureScheme::ED25519
        );
        let proof = rustls::sign::Signer::sign(&*signer, b"handshake transcript").expect("signs");
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key())
            .verify(b"handshake transcript", &proof)
            .expect("verifies against the bound leaf");
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn the_replayed_prefix_is_the_record_the_server_consumed() {
        let cfg = settings();
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            RealityServer::accept(&cfg, 0, stream, Edges::default()).map(|_| ())
        });
        let bytes = good_hello();
        let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        client.write_all(&bytes).expect("writes");
        server.join().expect("joins").expect("authenticates");
        assert_eq!(bytes[0], 0x16);
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn an_authenticated_session_sends_no_tickets_after_the_handshake() {
        fn flight(hello: &[u8], serve: impl FnOnce(TcpStream) + Send + 'static) -> Vec<u8> {
            let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
            let port = listener.local_addr().expect("addr").port();
            let server = thread::spawn(move || {
                let (stream, _) = listener.accept().expect("accepts");
                stream.set_read_timeout(Some(COVER_WAIT)).expect("timeout");
                serve(stream);
            });
            let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            client.set_read_timeout(Some(COVER_WAIT)).expect("timeout");
            client.write_all(hello).expect("writes");
            let mut flight = Vec::new();
            let mut probe = [0u8; 4096];
            loop {
                match client.read(&mut probe) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => flight.extend_from_slice(&probe[..n]),
                }
            }
            server.join().expect("joins");
            flight
        }

        fn records(flight: &[u8]) -> Vec<(u8, usize)> {
            let mut at = 0;
            let mut out = Vec::new();
            while at < flight.len() {
                let kind = flight[at];
                let len = usize::from(u16::from_be_bytes([flight[at + 3], flight[at + 4]]));
                at += 5 + len;
                out.push((kind, len));
            }
            out
        }

        let flight = flight(&good_hello(), |stream| {
            let accepted = RealityServer::accept(&settings(), 0, stream, Edges::default())
                .expect("authenticates");
            let mut session = match accepted {
                RealityAccept::Session(session) => session,
                RealityAccept::Proxied(_) => panic!("the hello authenticates"),
            };
            assert!(session.handshake().is_err(), "the client never finishes");
        });
        assert_eq!(
            records(&flight),
            [(0x16u8, 122usize), (0x14, 1), (0x17, 373)],
            "ServerHello, one dummy cipher change, one encrypted flight, nothing after"
        );
        // rustls emits tickets only once the client's Finished arrives, which no test peer can send without forking the transcript, so the count is pinned where it is set and the flight above shows the wire stalls.
        let forged = || super::super::TlsServerConfig {
            alpn: Vec::new(),
            min_version: None,
            max_version: None,
            cipher_suites: Vec::new(),
            curves: Vec::new(),
            certs: vec![super::super::CertEntry {
                cert_chain: vec![bound_certificate(&[9u8; 32], SNI)],
                key_der: ed25519_pkcs8(),
                key_kind: super::super::ServerKeyKind::Pkcs8,
                reload: None,
                ocsp: None,
            }],
            send_tickets: false,
            reject_unknown_sni: false,
            server_config_cache: std::sync::Arc::default(),
            ech_server_keys: None,
            master_key_log: None,
            kernel_tx: false,
            kernel_rx: false,
        };
        let plain = super::super::TlsServerConfig {
            send_tickets: true,
            server_config_cache: std::sync::Arc::default(),
            ..forged()
        };
        let without = crate::tls::rustls_backend::server_config(forged()).expect("identity");
        assert_eq!(without.send_tls13_tickets, 0, "REALITY arrivals carry none");
        let with = crate::tls::rustls_backend::server_config(plain).expect("identity");
        assert_eq!(
            with.send_tls13_tickets, 2,
            "plain TLS keeps the default two"
        );
    }

    /// A `Read` that answers `WouldBlock` once and then dribbles one byte at a
    /// time, so the hello reader is driven through its wait path deterministically.
    struct Dribble {
        bytes: Vec<u8>,
        at: usize,
        blocked: bool,
    }

    impl Dribble {
        fn of(bytes: &[u8]) -> Self {
            Self {
                bytes: bytes.to_vec(),
                at: 0,
                blocked: false,
            }
        }
    }

    impl Read for Dribble {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.blocked {
                self.blocked = true;
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            if self.at >= self.bytes.len() {
                return Ok(0);
            }
            buf[0] = self.bytes[self.at];
            self.at += 1;
            Ok(1)
        }
    }

    #[test]
    fn reading_a_single_record_hello_allocates_one_buffer() {
        let bytes = good_hello();
        let mut dribble = Dribble::of(&bytes);
        let ((raw, body, hello), counts) =
            crate::alloc_count::measure(|| read_client_hello(&mut dribble).expect("reads whole"));
        assert_eq!(
            counts.allocs, 1,
            "the body is read out of the record stream: {counts:?}"
        );
        assert_eq!(raw, bytes);
        let Body::Inline { len } = body else {
            panic!("one record stays inline");
        };
        assert_eq!(&raw[5..5 + len], &bytes[5..]);
        assert_eq!(hello.session_id.1, 32);
    }

    #[test]
    fn a_hello_in_two_records_behind_a_timeout_is_read_whole() {
        let bytes = good_hello();
        let body = &bytes[5..];
        let half = body.len() / 2;
        let mut split = vec![0x16, 0x03, 0x01];
        split.extend_from_slice(&u16::try_from(half).unwrap().to_be_bytes());
        split.extend_from_slice(&body[..half]);
        let mut second = vec![0x16, 0x03, 0x01];
        second.extend_from_slice(&u16::try_from(body.len() - half).unwrap().to_be_bytes());
        second.extend_from_slice(&body[half..]);
        split.extend_from_slice(&second);
        let mut dribble = Dribble::of(&split);
        let ((raw, heard, hello), counts) =
            crate::alloc_count::measure(|| read_client_hello(&mut dribble).expect("reads whole"));
        assert_eq!(raw, split);
        let Body::Split(gathered) = heard else {
            panic!("two records gather aside");
        };
        assert_eq!(gathered, body);
        assert_eq!(hello.session_id.1, 32);
        assert_eq!(
            counts.allocs, 4,
            "one stream plus one gather, each grown once: {counts:?}"
        );
    }

    #[test]
    fn record_bounded_reads_never_swallow_the_bytes_after_a_record() {
        fn record(kind: u8, payload: &[u8]) -> Vec<u8> {
            let mut out = vec![kind, 0x03, 0x03];
            out.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
            out.extend_from_slice(payload);
            out
        }
        let mut wire = record(0x16, &[1u8; 100]);
        wire.extend_from_slice(&record(0x17, &[2u8; 1000]));
        wire.extend_from_slice(b"raw tail that is no record at all");
        let mut limited = RecordLimiter::new(&wire[..]);
        let mut first = [0u8; 4096];
        let n = limited.read(&mut first).expect("reads the header");
        assert_eq!(n, 5, "one read stops at the header end");
        let n = limited.read(&mut first[n..]).expect("reads the payload");
        assert_eq!(n, 100, "the next read stops at the record end");
        let mut got = 105;
        while got < 110 {
            let n = limited.read(&mut first[got..]).expect("reads");
            assert!(n > 0, "a record-bounded read always progresses");
            got += n;
        }
        assert_eq!(got, 110, "the first record arrives whole and alone");
        assert_eq!(&first[..3], &[0x16, 0x03, 0x03]);
        let mut rest = Vec::new();
        limited.read_to_end(&mut rest).expect("reads");
        assert_eq!(rest.len(), wire.len() - 110);
        let mut whole = first[..110].to_vec();
        whole.extend_from_slice(&rest);
        assert_eq!(whole, wire, "every byte is still delivered");
    }

    #[test]
    fn a_disarmed_limiter_stops_bounding_reads() {
        fn record(kind: u8, payload: &[u8]) -> Vec<u8> {
            let mut out = vec![kind, 0x03, 0x03];
            out.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
            out.extend_from_slice(payload);
            out
        }
        let mut wire = record(0x16, &[1u8; 100]);
        wire.extend_from_slice(&record(0x17, &[2u8; 200]));
        let mut limited = RecordLimiter::new(&wire[..]);
        limited.disarm_record_alignment();
        let mut both = [0u8; 4096];
        let n = limited.read(&mut both).expect("reads");
        assert_eq!(n, wire.len(), "two records arrive in one read");
        assert_eq!(&both[..n], &wire[..]);
    }

    #[test]
    fn an_open_limiter_passes_everything_through_and_tracks_behind() {
        fn record(kind: u8, payload: &[u8]) -> Vec<u8> {
            let mut out = vec![kind, 0x03, 0x03];
            out.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
            out.extend_from_slice(payload);
            out
        }
        let mut wire = record(0x16, &[1u8; 100]);
        wire.extend_from_slice(&record(0x17, &[2u8; 1000]));
        let mut limited = RecordLimiter::new_open(&wire[..]);
        let mut first = [0u8; 4096];
        let n = limited.read(&mut first).expect("reads");
        assert_eq!(n, wire.len(), "open reads are never capped");
        assert_eq!(&first[..n], &wire[..]);
        let mut limited = RecordLimiter::new_open(&wire[..]);
        let mut half = [0u8; 50];
        let mut got = 0;
        while got < 150 {
            let n = limited.read(&mut half).expect("reads");
            assert!(n > 0, "a tracking read always progresses");
            got += n;
        }
        assert_eq!(got, 150);
        limited.engage_record_alignment();
        let mut rest = [0u8; 4096];
        let n = limited.read(&mut rest).expect("reads");
        assert_eq!(n, 960, "engaging mid-record caps at that record end");
        let n = limited.read(&mut rest).expect("reads");
        assert_eq!(n, 0, "nothing past the last record is swallowed early");
    }

    fn client_config(public: [u8; 32]) -> RealityClientConfig {
        RealityClientConfig {
            server_name: SNI.to_owned(),
            public_key: public,
            short_id: SHORT_ID,
            fingerprint: "chrome".to_owned(),
            key_log: None,
        }
    }

    fn server_public() -> [u8; 32] {
        x25519_dalek::x25519(SERVER_PRIVATE, x25519_dalek::X25519_BASEPOINT_BYTES)
    }

    #[test]
    fn the_seal_replaces_only_the_session_id() {
        let profile = crate::tls::shaped::Fingerprint::resolve("chrome")
            .and_then(crate::tls::shaped::Fingerprint::profile)
            .expect("chrome is a parrot");
        let mut hello =
            crate::tls::shaped::hello::Hello::build(profile, SNI, &[], false, &[], None)
                .expect("builds");
        assert_eq!(
            &hello.msg[39..71],
            &hello.session_id[..],
            "the server reads the id at this offset"
        );
        let before = hello.msg.clone();
        hello.zero_session();
        assert_eq!(
            &hello.msg[39..71],
            &[0u8; 32][..],
            "the AAD carries a zeroed id"
        );
        hello.seal_session([0x77u8; 32]);
        assert_eq!(&hello.msg[39..71], &[0x77u8; 32][..]);
        for (at, (old, new)) in before.iter().zip(hello.msg.iter()).enumerate() {
            if !(39..71).contains(&at) {
                assert_eq!(old, new, "byte {at} moved");
            }
        }
    }

    #[test]
    fn client_seal_matches_the_test_oracle_byte_for_byte() {
        let random = [0x5au8; 32];
        let secret = [0x11u8; 32];
        let mut base = [0u8; 32];
        base[0] = 9;
        let body = hello_body(&random, &x25519_dalek::x25519(secret, base), SNI);
        let version = [26u8, 9, 30];
        let now = 1_700_000_000u32;
        let shared = x25519_dalek::x25519(secret, x25519_dalek::x25519(SERVER_PRIVATE, base));
        let auth = auth_key(&shared, &random).expect("derives");
        let sealed = seal_session_id(&auth, &random, version, now, SHORT_ID, &body);
        let mut oracle = body.clone();
        seal(&mut oracle, &random, &secret, SHORT_ID, now);
        assert_eq!(&oracle[39..71], &sealed, "the seal is the oracle's bytes");
        assert_eq!(&body[39..71], &[0u8; 32], "the AAD hello stays zeroed");
    }

    #[cfg_attr(
        miri,
        ignore = "reaches ring's C and assembly, which Miri cannot interpret"
    )]
    #[test]
    fn the_leaf_parser_reads_the_bound_certificate() {
        let der = bound_certificate(&[3u8; 32], SNI);
        let (public, proof) = parse_leaf(&der).expect("parses");
        assert_eq!(&public, public_key());
        assert_eq!(&proof[..], proof_at(&der));
        assert!(parse_leaf(&[]).is_none());
        assert!(parse_leaf(b"not a certificate").is_none());
        assert!(parse_leaf(&der[..der.len() - 1]).is_none());
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_client_handshake_echoes_through_the_server() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("timeout");
            let accepted =
                RealityServer::accept(&settings(), 0, stream, Edges::default()).expect("accepts");
            let mut session = match accepted {
                RealityAccept::Session(session) => session,
                RealityAccept::Proxied(_) => panic!("the client authenticates"),
            };
            session.handshake().expect("handshakes");
            let mut buf = [0u8; 4];
            session.read_exact(&mut buf).expect("reads");
            session.write_all(&buf).expect("echoes");
            session.flush().expect("flushes");
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        let mut client =
            RealityClientSession::connect(&client_config(server_public()), 1_700_000_000, stream)
                .expect("dials");
        client.write_all(b"ping").expect("writes");
        client.flush().expect("flushes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("reads");
        assert_eq!(&back, b"ping");
        server.join().expect("joins");
    }

    /// A poll that splits an application record must resume it: the client stages the ciphertext
    /// it already read, so the next read decodes the record instead of a body as a header.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_client_record_split_by_a_poll_timeout_is_resumed_not_lost() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct StallOnce {
            io: TcpStream,
            arm: Arc<AtomicUsize>,
            seen: usize,
        }

        impl Read for StallOnce {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let left = self.arm.load(Ordering::SeqCst);
                if left != 0 {
                    self.seen += 1;
                    if self.seen == left {
                        self.arm.store(0, Ordering::SeqCst);
                        return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
                    }
                }
                self.io.read(buf)
            }
        }

        impl Write for StallOnce {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.io.write(buf)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                self.io.flush()
            }
        }

        let payload = vec![0x5au8; 8_192];
        let expected = payload.clone();
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("timeout");
            let accepted =
                RealityServer::accept(&settings(), 0, stream, Edges::default()).expect("accepts");
            let mut session = match accepted {
                RealityAccept::Session(session) => session,
                RealityAccept::Proxied(_) => panic!("the client authenticates"),
            };
            session.handshake().expect("handshakes");
            let mut request = [0u8; 16];
            session.read_exact(&mut request).expect("reads");
            session.write_all(&payload).expect("writes");
            session.write_all(b"tail").expect("writes");
            session.flush().expect("flushes");
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        let arm = Arc::new(AtomicUsize::new(0));
        let limiter = RecordLimiter::new(StallOnce {
            io: stream,
            arm: Arc::clone(&arm),
            seen: 0,
        });
        let mut client =
            RealityClientSession::connect(&client_config(server_public()), 1_700_000_000, limiter)
                .expect("dials");
        client.write_all(&[0u8; 16]).expect("writes");
        client.flush().expect("flushes");
        arm.store(2, Ordering::SeqCst);
        let mut back = Vec::new();
        let mut buf = vec![0u8; 16_384];
        loop {
            match client.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => back.extend_from_slice(&buf[..n]),
                Err(error) if TlsError::is_timeout(&error) => {}
                Err(error) => panic!("reads the record: {error}"),
            }
        }
        assert_eq!(back.len(), expected.len() + b"tail".len());
        assert_eq!(&back[..expected.len()], &expected[..]);
        assert_eq!(&back[expected.len()..], b"tail");
        drop(client);
        server.join().expect("joins");
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_client_with_a_wrong_key_is_refused_before_any_proxy_byte() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("timeout");
            let _ = RealityServer::accept(&settings(), 0, stream, Edges::default());
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        let wrong = client_config([0x9du8; 32]);
        assert!(
            RealityClientSession::connect(&wrong, 1_700_000_000, stream).is_err(),
            "an unauthenticated server must fail the handshake, never carry proxy traffic"
        );
        server.join().expect("joins");
    }
}

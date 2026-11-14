use crate::b64;
use std::fmt;

/// A socket descriptor the kernel record layer can be installed on.
#[cfg(unix)]
pub type RawFd = std::os::fd::RawFd;
/// A socket descriptor the kernel record layer can be installed on.
#[cfg(not(unix))]
pub type RawFd = i32;

pub(crate) mod ktls;

pub trait Stream: std::io::Read + std::io::Write {}
impl<T: std::io::Read + std::io::Write> Stream for T {}

/// The trust anchors a dial verifies with, as DER certificates behind one allocation: a config names them, it does not own a copy of them, so a dial costs a reference count rather than the whole platform store.
pub type Anchors = std::sync::Arc<[Vec<u8>]>;

/// A Psiphon obfuscated-ticket shared secret. `Debug` never prints the key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ObfuscatedTicket([u8; 32]);

impl ObfuscatedTicket {
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }

    /// Encodes and encrypts one state around a caller-supplied secret and creation time.
    pub fn encode(
        &self,
        secret: &[u8],
        tls13: bool,
        ems: bool,
        created: u64,
    ) -> Result<Vec<u8>, TlsError> {
        shaped::ticket::encode_state(&self.0, secret, tls13, ems, created)
    }
}

impl fmt::Debug for ObfuscatedTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ObfuscatedTicket(redacted)")
    }
}

#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct TlsConfig {
    pub server_name: String,
    /// The `ALPN` list a client offers, behind one allocation: a config names it once, and the client's own cache keys on it, so a per-dial copy was a vector of vectors paid on every handshake.
    pub alpn: std::sync::Arc<[Vec<u8>]>,
    pub roots: Anchors,
    /// Leaf keys to accept: a chain that verified must still hold one, and a
    /// chain this device cannot build is verified against the pinned leaf as its
    /// own anchor. Empty pins nothing and refuses nothing, which is the default
    /// because a lane with no pins is the ordinary case.
    pub pins: crate::foxy::pin::Pins,
    /// The `cipher_suites` ids a client advertises, in `crypto/tls` order, from xray's
    /// `tlsSettings.cipherSuites`, behind one allocation: the config names the order once and
    /// the cache keys on it per dial, so a copy would be a heap buffer on every handshake.
    /// Empty means the config named none, so the backend keeps its stock ordering; see
    /// `cipher_suites` for how a non-empty list is built.
    pub cipher_suites: std::sync::Arc<[u16]>,
    /// The key-exchange groups a hello offers, in the order xray's `tlsSettings.curvePreferences`
    /// names them, behind one allocation like the suite list. Empty keeps the build's own order:
    /// the shaped hello's profile shares, or ring's three curves.
    pub curves: std::sync::Arc<[u16]>,
    /// The lowest protocol version a dial may negotiate, as xray's `tlsSettings.minVersion`
    /// spells it. `None` keeps the backend's default floor.
    pub min_version: Option<u16>,
    /// The highest protocol version a dial may negotiate, as xray's `tlsSettings.maxVersion`
    /// spells it. `None` keeps the backend's default ceiling.
    pub max_version: Option<u16>,
    /// Accept the peer chain as presented, keeping only the handshake signature that binds
    /// it to the key exchange: xray's `allowInsecure`, read by a masquerade cover's
    /// `masq_url_insecure` origin and by an outbound that names it. `false` is the default
    /// because verifying is the ordinary case, and an unchecked chain is a deliberate,
    /// bounded exception rather than a mode.
    pub insecure: bool,
    /// Ride the ticket a server hands out on the next dial: xray's `enableSessionResumption`, off by default as the reference leaves it.
    pub resumption: bool,
    /// SHA-256 digests over whole certificates (`pinnedPeerCertSha256`): a digest matching
    /// the leaf's DER accepts the handshake on the pin alone, one matching an intermediate's
    /// verifies the chain with that certificate as the only root and the server name alongside.
    /// Empty pins nothing, so the ordinary chain verifier stands.
    pub cert_pins: std::sync::Arc<[[u8; 32]]>,
    /// The names `verifyPeerCertByName` checks the chain against instead of the SNI, in config
    /// order: the reference turns its own name check off and verifies once per listed name.
    /// Empty keeps the connection's server name, the ordinary case.
    pub verify_names: std::sync::Arc<[String]>,
    /// The browser hello to shape, or `None` to keep the stock rustls hello.
    pub fingerprint: Option<shaped::Fingerprint>,
    /// The ECH config list a client encrypts its inner hello with, fetched or decoded
    /// before the dial; `None` keeps the hello plaintext.
    pub ech_config_list: Option<std::sync::Arc<[u8]>>,
    /// Whether the carrier is a WebSocket or `HTTPUpgrade`: xray's parrots then force
    /// the outer ALPN to `http/1.1` so the upgrade reads as an ordinary browser.
    pub websocket: bool,
    /// The `masterKeyLog` file every handshake of this config appends its traffic secrets to, or
    /// `None` to log none, the ordinary case.
    pub master_key_log: Option<std::sync::Arc<MasterKeyLog>>,
    /// The client identity a dial presents when the server sends `CertificateRequest`: the
    /// `tlsSettings.certificates` entry that names a key. xray builds that pair but its client
    /// never sends it, so this is the sing-box client certificate an outbound opts into.
    pub client_cert: Option<std::sync::Arc<CertEntry>>,
    /// The `ClientHello` random to send instead of a fresh one, for a protocol that authenticates
    /// itself in that field (Psiphon TLS-OSSH). Only the shaped session can carry it; the stock
    /// rustls builder draws its own and cannot be overridden.
    pub client_random: Option<[u8; 32]>,
    /// Omit the legacy 32-byte session id from a shaped hello, as Psiphon's
    /// `NoDefaultTLSSessionIDProbability` makes uTLS do for a randomized profile.
    pub omit_session_id: bool,
    /// An exact RFC 7685 padding extension body length, moved to the front of a shaped hello as
    /// Psiphon's `TLSPadding` does. `None` keeps each preset's own padding rule.
    pub padding: Option<u16>,
    /// The shared secret for a client-made obfuscated session ticket, as Psiphon's
    /// `ObfuscatedSessionTicketKey` names one.
    pub obfuscated_ticket: Option<ObfuscatedTicket>,
    /// Linux kernel TLS for the TX direction: the record layer encrypts after the handshake.
    pub kernel_tx: bool,
    /// Linux kernel TLS for the RX direction: the kernel decrypts after the handshake.
    pub kernel_rx: bool,
}

/// Whether a client build can offer a group a config named: the shaped hello draws its own key
/// shares, including the ML-KEM hybrid, while the stock rustls provider is ring's three curves.
pub fn curve_supported(group: u16, shaped: bool) -> bool {
    let stock = [shaped::keys::P256, shaped::keys::P384, shaped::keys::X25519];
    stock.contains(&group) || (shaped && group == shaped::keys::X25519_MLKEM768)
}

/// xray's `masterKeyLog`: the traffic secrets of every handshake on the config, one NSS line each,
/// appended to one file so a capture of the session decrypts offline.
#[derive(Debug)]
pub struct MasterKeyLog {
    path: String,
    state: std::sync::Mutex<(std::fs::File, Vec<u8>)>,
}

impl MasterKeyLog {
    /// xray's `os.OpenFile(path, O_CREATE|O_RDWR|O_APPEND, 0o600)`: `None` when the path cannot be
    /// opened, which the reference reports and then carries on without.
    pub fn open(path: &str) -> Option<Self> {
        let mut options = std::fs::OpenOptions::new();
        options.create(true).read(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options.open(path).ok()?;
        // 193 bytes is the longest line: a 30-byte label, a 32-byte random and a 48-byte SHA-384 secret.
        Some(Self {
            path: std::fs::canonicalize(path).map_or_else(
                |_| path.to_owned(),
                |path| path.to_string_lossy().into_owned(),
            ),
            state: std::sync::Mutex::new((file, Vec::with_capacity(208))),
        })
    }
}

impl MasterKeyLog {
    /// The file this log appends its NSS lines to.
    pub fn path(&self) -> &str {
        &self.path
    }

    pub(crate) fn log_line(&self, line: &str) {
        use std::io::Write as _;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (file, buffer) = &mut *state;
        buffer.clear();
        buffer.extend_from_slice(line.as_bytes());
        buffer.push(b'\n');
        let _ = file.write_all(buffer);
    }
}

impl rustls::KeyLog for MasterKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        use std::io::Write as _;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (file, line) = &mut *state;
        line.clear();
        line.extend_from_slice(label.as_bytes());
        line.push(b' ');
        push_hex(line, client_random);
        line.push(b' ');
        push_hex(line, secret);
        line.push(b'\n');
        // Go's key-log writer drops its write error the same way: logging never fails a handshake.
        let _ = file.write_all(line);
    }
}

/// Lowercase hex, two digits per byte, onto a line that already holds the room.
fn push_hex(line: &mut Vec<u8>, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    line.reserve(bytes.len() * 2);
    for byte in bytes {
        line.push(DIGITS[usize::from(byte >> 4)]);
        line.push(DIGITS[usize::from(byte & 0x0f)]);
    }
}

pub trait TlsProvider: std::io::Read + std::io::Write {
    fn name() -> &'static str
    where
        Self: Sized;

    fn suites(&self) -> Vec<String>;

    fn handshake(&mut self) -> Result<(), TlsError>;

    fn alpn(&self) -> Option<&[u8]>;

    /// Whether the peer's close has already been read: a read now reports the end without
    /// touching the transport, even when the peer keeps TCP open after TLS shutdown.
    fn closed(&self) -> bool {
        false
    }

    /// The server name the front's hello named, once the handshake has read
    /// it: a fallback row that names its fronts is routed by it. A provider
    /// that heard no name, or one on the client side, answers `None`.
    fn sni(&self) -> Option<&[u8]> {
        None
    }

    /// The leaf certificate the peer presented, once the handshake has
    /// completed. A provider that cannot reach it answers `None` rather than
    /// failing, because a lane with pins needs it and one without does not.
    fn peer_leaf(&self) -> Option<&[u8]> {
        None
    }

    /// The OCSP response the peer stapled to its chain, once the handshake has
    /// completed. Only the Boring lane can reach it; the stock lanes hand the
    /// bytes to their verifier instead, so they answer `None`.
    fn peer_ocsp(&self) -> Option<&[u8]> {
        None
    }

    /// Whether this session's config asked the kernel to carry a direction. A host
    /// without Linux kTLS still answers the request, and `enable_ktls` refuses it.
    fn wants_ktls(&self) -> bool {
        false
    }

    /// Whether the kernel now decrypts this session's reads.
    fn kernel_rx(&self) -> bool {
        false
    }

    /// Hands one direction to the kernel after the handshake. A direction that is
    /// not offloaded keeps the same traffic-secret epoch here, so a `KeyUpdate` moves
    /// both together.
    fn enable_ktls(&mut self, fd: RawFd) -> std::io::Result<()> {
        let _ = fd;
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    /// The ciphertext the caller read from the transport is decrypted, and the plaintext comes
    /// out: the caller read the transport itself, so the wait for the peer's bytes happened
    /// outside this session's lock, and only the decryption is under it. The plaintext's length
    /// and the ciphertext's length come back together, because a session takes only what its
    /// own buffer has room for and the rest is the caller's to feed again. A provider that
    /// reads its own transport has no use for this and says so.
    fn open(&mut self, ciphertext: &[u8], buf: &mut [u8]) -> std::io::Result<(usize, usize)> {
        let _ = (ciphertext, buf);
        Err(std::io::Error::other(
            "this provider reads its own transport",
        ))
    }

    /// The plaintext is encrypted under this session's lock into the caller's buffer, and the
    /// ciphertext leaves for the transport only after the lock is dropped: a peer that stopped
    /// draining this direction then parks that transport write alone instead of the decryption
    /// the other direction needs. A provider that writes its own transport falls back to `write`.
    fn seal_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> std::io::Result<usize> {
        let _ = out;
        std::io::Write::write(self, plaintext)
    }

    /// Several slices sealed in one call, so a caller's frame reaches the session as the
    /// segments it was handed rather than a copy staged into one buffer.
    fn seal_slices_into(&mut self, parts: &[&[u8]], out: &mut Vec<u8>) -> std::io::Result<()> {
        for part in parts {
            let mut left = *part;
            while !left.is_empty() {
                let wrote = self.seal_into(left, out)?;
                if wrote == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
                }
                left = &left[wrote..];
            }
        }
        Ok(())
    }
}

/// Stops the socket reads behind a session at TLS record ends once Vision can go direct, so the unwrap finds every following byte still in the kernel.
pub trait RecordAlignment {
    fn engage_record_alignment(&mut self) {}

    /// Stops bounding and tracking reads: a session that never goes direct pays no per-read bookkeeping.
    fn disarm_record_alignment(&mut self) {}

    /// Write several slices in one completion, so the bytes go out together and the alignment read happens once.
    fn write_all_slices(&mut self, parts: &[&[u8]]) -> std::io::Result<()>
    where
        Self: std::io::Write,
    {
        for part in parts {
            std::io::Write::write_all(self, part)?;
        }
        Ok(())
    }
}

// A bare socket keeps every byte in the kernel, so there is nothing to bound.
impl RecordAlignment for std::net::TcpStream {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsError {
    Timeout,
    /// Why the chain was refused, carried by the kind: folding a variant into `Other` to hold a message erases the kind, and a caller that cannot match a refused chain cannot act on it — it cannot tell the user, and it cannot stop retrying an edge no retry will make trusted.
    BadCertificate(String),
    Closed,
    NoSharedCipher,
    /// The server refused the ECH offer and named the list to offer next.
    EchRetry(std::sync::Arc<[u8]>),
    Other(String),
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("handshake timed out"),
            Self::BadCertificate(why) => write!(f, "certificate did not verify: {why}"),
            Self::Closed => f.write_str("connection closed by peer"),
            Self::NoSharedCipher => f.write_str("no shared cipher suite"),
            Self::EchRetry(_) => f.write_str("the server asked for another ECH config"),
            Self::Other(why) => write!(f, "backend error: {why}"),
        }
    }
}

impl std::error::Error for TlsError {}

impl TlsError {
    /// Whether an I/O error is a timeout: the socket said so, or the stack behind it did.
    /// A `TlsError::Timeout` reaches a caller wrapped in an `io::Error` of another kind,
    /// so the kind alone does not answer it.
    #[must_use]
    pub fn is_timeout(error: &std::io::Error) -> bool {
        use std::io::ErrorKind::{TimedOut, WouldBlock};
        // A timed-out overlapped socket read surfaces as `ERROR_IO_PENDING` on Windows, not as `TimedOut`; a relay that read it as an end drops a live flow.
        let pending = cfg!(windows) && error.raw_os_error() == Some(997);
        matches!(error.kind(), TimedOut | WouldBlock)
            || pending
            || error
                .get_ref()
                .and_then(|source| source.downcast_ref::<TlsError>())
                .is_some_and(|mapped| matches!(mapped, TlsError::Timeout))
    }
}

#[test]
fn a_pending_overlapped_read_is_an_idle_wait_on_windows() {
    let pending = std::io::Error::from_raw_os_error(997);
    assert_eq!(TlsError::is_timeout(&pending), cfg!(windows));
    #[cfg(windows)]
    assert_eq!(TlsError::from(pending), TlsError::Timeout);
}

/// Fills `buf` from `stream`: a `dyn Read` may answer short, and a poll quantum the
/// socket reports as a timeout is not an answer, so the loop asks again.
pub fn read_exact(stream: &mut dyn std::io::Read, mut buf: &mut [u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        match stream.read(buf) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            Ok(n) => buf = &mut buf[n..],
            Err(error) if TlsError::is_timeout(&error) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

impl From<TlsError> for std::io::Error {
    fn from(e: TlsError) -> Self {
        std::io::Error::other(e)
    }
}

impl From<std::io::Error> for TlsError {
    fn from(e: std::io::Error) -> Self {
        if TlsError::is_timeout(&e) {
            return Self::Timeout;
        }
        match e.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => Self::Timeout,
            std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe => Self::Closed,
            _ => Self::Other(e.to_string()),
        }
    }
}

/// One `certificates` entry: the chain it serves and the key that signs for it.
#[derive(Debug, Clone)]
pub struct CertEntry {
    pub cert_chain: Vec<Vec<u8>>,
    pub key_der: Vec<u8>,
    pub key_kind: ServerKeyKind,
    /// The files a path-backed entry was read from and the interval xray's ticker re-reads
    /// them at; `None` for an inline entry, which has nothing to re-read.
    pub reload: Option<CertReload>,
    /// The `ocspStapling` interval the block names and the response it last fetched, when the
    /// block names one; `None` serves the chain with no status.
    pub ocsp: Option<OcspStaple>,
}

/// The `ocspStapling` interval a block names and the OCSP response it last fetched for its
/// chain: xray's ticker re-fetches on that interval, and only swaps the staple when the bytes
/// change, so a steady responder never rebuilds the listener.
#[derive(Debug, Clone)]
pub struct OcspStaple {
    pub interval: std::time::Duration,
    pub response: Option<Vec<u8>>,
}

impl PartialEq for CertEntry {
    /// The bytes two entries serve, which a reload ticker can change; the reader function is the
    /// same resolution for every entry, so its address carries no difference.
    fn eq(&self, other: &Self) -> bool {
        self.cert_chain == other.cert_chain
            && self.key_der == other.key_der
            && self.key_kind == other.key_kind
            && match (&self.reload, &other.reload) {
                (None, None) => true,
                (Some(ours), Some(theirs)) => {
                    ours.certificate == theirs.certificate
                        && ours.key == theirs.key
                        && ours.interval == theirs.interval
                }
                _ => false,
            }
            && match (&self.ocsp, &other.ocsp) {
                (None, None) => true,
                (Some(ours), Some(theirs)) => {
                    ours.interval == theirs.interval && ours.response == theirs.response
                }
                _ => false,
            }
    }
}

/// xray's hot-reload ticker: `ocspStapling` seconds when the block names it, 3600 otherwise.
#[derive(Debug, Clone)]
pub struct CertReload {
    pub certificate: String,
    pub key: String,
    pub interval: std::time::Duration,
    pub read: CertReader,
}

/// How a reload re-reads one file: the same resolution a config's path goes through.
pub type CertReader = fn(&str) -> Option<Vec<u8>>;

#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct TlsServerConfig {
    /// The identities the listener serves, in the order the block lists them: the SNI
    /// resolver takes the first whose names match, so element 0 is the fallback.
    pub certs: Vec<CertEntry>,
    /// The protocols to offer, in preference order. Empty means no ALPN, which
    /// is what a server that only ever carries one protocol leaves it at.
    pub alpn: Vec<Vec<u8>>,
    /// The lowest protocol version the listener may negotiate, as the `0x0303`
    /// spelling xray's `tlsSettings.minVersion` uses. `None` keeps the backend's
    /// default floor.
    pub min_version: Option<u16>,
    /// The highest protocol version the listener may negotiate, as the `0x0304`
    /// spelling xray's `tlsSettings.maxVersion` uses. `None` keeps the backend's
    /// default ceiling.
    pub max_version: Option<u16>,
    /// The TLS 1.2 suites the listener may negotiate, in preference order, from
    /// xray's `tlsSettings.cipherSuites`. Empty keeps the backend's stock set;
    /// a non-empty list admits only the suites it names.
    pub cipher_suites: Vec<u16>,
    /// The key-exchange groups the listener may negotiate, in the order xray's
    /// `tlsSettings.curvePreferences` names them. Empty keeps the backend's stock order.
    pub curves: Vec<u16>,
    /// Whether to send TLS 1.3 session tickets. REALITY declines them, as both
    /// references do, so an authenticated handshake is followed by no records.
    pub send_tickets: bool,
    /// Whether an SNI no certificate name matches aborts the handshake.
    pub reject_unknown_sni: bool,
    /// Memoised server-config builds, one per identity kind.
    pub server_config_cache: crate::tls::rustls_backend::ServerConfigCache,
    /// ECH server keys as the xray TLV: `u16 key || u16 config`, repeated.
    pub ech_server_keys: Option<std::sync::Arc<[u8]>>,
    /// The `masterKeyLog` file this listener's handshakes append to, or `None` to log none.
    pub master_key_log: Option<std::sync::Arc<MasterKeyLog>>,
    /// Linux kernel TLS for the TX direction: the record layer encrypts after the handshake.
    pub kernel_tx: bool,
    /// Linux kernel TLS for the RX direction: the kernel decrypts after the handshake.
    pub kernel_rx: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerKeyKind {
    Pkcs8,
    Sec1,
    Pkcs1,
}

impl TlsServerConfig {
    /// The `rustls` server config for a plain TLS identity, built once per config.
    pub fn server_config(&self) -> Result<std::sync::Arc<rustls::ServerConfig>, TlsError> {
        crate::tls::rustls_backend::cached_server_config(self, false)
    }

    /// The `rustls` server config for a REALITY identity, built once per config.
    pub fn reality_server_config(&self) -> Result<std::sync::Arc<rustls::ServerConfig>, TlsError> {
        crate::tls::rustls_backend::cached_server_config(self, true)
    }

    /// The `BoringSSL` context an ECH listener answers with, unbuilt so a QUIC lane can hand it
    /// to quiche: both carry the same certificate, key and ECH key set.
    pub fn ech_server_context_builder(&self) -> Result<boring::ssl::SslContextBuilder, TlsError> {
        let keys = self
            .ech_server_keys
            .as_deref()
            .ok_or_else(|| TlsError::Other("ech server identity has no keys".to_owned()))?;
        crate::tls::rustls_backend::ech_server_context_builder(self, keys)
    }

    /// The interval xray's ticker fires at, if any entry re-reads files or re-fetches a staple.
    pub fn reload_interval(&self) -> Option<std::time::Duration> {
        self.certs
            .iter()
            .filter_map(|entry| entry.reload.as_ref())
            .map(|reload| reload.interval)
            .chain(
                self.certs
                    .iter()
                    .filter_map(|entry| entry.ocsp.as_ref())
                    .map(|ocsp| ocsp.interval),
            )
            .min()
    }

    /// The identities the listener serves now: what the last `renew` landed, or the config it
    /// was built from when none landed yet.
    pub fn served_entries(&self) -> Vec<CertEntry> {
        self.server_config_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .served
            .clone()
            .unwrap_or_else(|| self.certs.clone())
    }

    /// Swap the live listener onto identities re-read from disk; `false` when a read failed
    /// or the bytes match what the listener already serves.
    pub fn renew(&self) -> bool {
        // The fetch runs outside the cache lock, which only guards the snapshot and the landing.
        let served = {
            let guard = self
                .server_config_cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.served.clone().unwrap_or_else(|| self.certs.clone())
        };
        let Some(entries) = self.reread(&served) else {
            return false;
        };
        let config = if crate::tls::legacy::needed(&self.cipher_suites) {
            None
        } else {
            let mut fresh = self.clone();
            fresh.certs.clone_from(&entries);
            match crate::tls::rustls_backend::server_config(fresh) {
                Ok(config) => Some(std::sync::Arc::new(config)),
                Err(_) => return false,
            }
        };
        let mut guard = self
            .server_config_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Another renew landed while we fetched: the listener serves it, so ours must not roll it back.
        let landing = guard.served.clone().unwrap_or_else(|| self.certs.clone());
        if landing != served {
            return false;
        }
        guard.served = Some(entries);
        guard.legacy = None;
        guard.ech = None;
        guard.plain = config;
        true
    }

    /// The identities as their files read now and their staples re-fetch now, or `None` when a
    /// read failed or nothing changed.
    fn reread(&self, served: &[CertEntry]) -> Option<Vec<CertEntry>> {
        let mut entries = Vec::with_capacity(self.certs.len());
        let mut changed = false;
        for (index, entry) in self.certs.iter().enumerate() {
            let mut entry = entry.clone();
            if let Some(reload) = &entry.reload {
                let parsed = parse_pem_entry(
                    &(reload.read)(&reload.certificate)?,
                    &(reload.read)(&reload.key)?,
                )
                .ok()?;
                changed |= served.get(index).is_none_or(|was| {
                    was.cert_chain != parsed.cert_chain || was.key_der != parsed.key_der
                });
                entry.cert_chain = parsed.cert_chain;
                entry.key_der = parsed.key_der;
                entry.key_kind = parsed.key_kind;
            }
            if let Some(ocsp) = &mut entry.ocsp {
                let fetched = ocsp::staple_for(&entry.cert_chain);
                // A failed fetch keeps the served response, not the startup one it would roll back to.
                ocsp.response = fetched.or_else(|| {
                    served
                        .get(index)
                        .and_then(|was| was.ocsp.as_ref())
                        .and_then(|was| was.response.clone())
                });
                // The comparison is the served response, fallback included, so a steady cache never rebuilds.
                changed |= served.get(index).is_none_or(|was| {
                    ocsp.response.as_ref()
                        != was.ocsp.as_ref().and_then(|was| was.response.as_ref())
                });
            }
            entries.push(entry);
        }
        changed.then_some(entries)
    }
}

pub fn parse_pem_identity(cert_pem: &[u8], key_pem: &[u8]) -> Result<TlsServerConfig, TlsError> {
    Ok(TlsServerConfig {
        alpn: Vec::new(),
        min_version: None,
        max_version: None,
        cipher_suites: Vec::new(),
        curves: Vec::new(),
        certs: vec![parse_pem_entry(cert_pem, key_pem)?],
        send_tickets: true,
        reject_unknown_sni: false,
        server_config_cache: std::sync::Arc::default(),
        ech_server_keys: None,
        master_key_log: None,
        kernel_tx: false,
        kernel_rx: false,
    })
}

/// One identity from a PEM pair: its whole chain, the key that signs for it, and the shape that key names.
pub fn parse_pem_entry(cert_pem: &[u8], key_pem: &[u8]) -> Result<CertEntry, TlsError> {
    let cert_chain = pem_blocks(cert_pem, "CERTIFICATE");
    if cert_chain.is_empty() {
        return Err(TlsError::Other(
            "tls certificate file holds no CERTIFICATE block".to_owned(),
        ));
    }
    // The label a key block carries is the writer's, not the key's: xray writes every minted key under `RSA PRIVATE KEY` whichever algorithm fed it, so the DER itself names the kind the parser takes.
    for label in ["PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"] {
        if let Some(key_der) = pem_blocks(key_pem, label).into_iter().next() {
            // xray's `X509KeyPair` refuses a key that does not sign for the leaf; the entry is skipped rather than poisoning the names the other identities answer.
            if !signs_for(&cert_chain[0], &key_der) {
                return Err(TlsError::Other(
                    "tls key does not match the certificate".to_owned(),
                ));
            }
            return Ok(CertEntry {
                cert_chain,
                key_kind: key_kind(&key_der).unwrap_or(ServerKeyKind::Pkcs1),
                key_der,
                reload: None,
                ocsp: None,
            });
        }
    }
    Err(TlsError::Other(
        "tls key file holds no recognized private-key block".to_owned(),
    ))
}

/// Whether a private key's public half is the leaf's own subject key, the pair `X509KeyPair` holds together.
fn signs_for(cert_der: &[u8], key_der: &[u8]) -> bool {
    let Ok(cert) = boring::x509::X509::from_der(cert_der) else {
        return false;
    };
    let Ok(key) = boring::pkey::PKey::private_key_from_der(key_der) else {
        return false;
    };
    let Ok(cert_public) = cert.public_key() else {
        return false;
    };
    matches!(
        (cert_public.public_key_to_der(), key.public_key_to_der()),
        (Ok(cert_key), Ok(key_public)) if cert_key == key_public
    )
}

/// The DER shape a key names: PKCS#8 is version `0` before an algorithm `SEQUENCE`, PKCS#1 is an
/// `INTEGER` modulus there, SEC 1 an `OCTET STRING` — the shapes these bytes carry whatever label
/// the writer chose.
fn key_kind(der: &[u8]) -> Option<ServerKeyKind> {
    /// One DER element past `at`, as its tag and the offset where it ends.
    fn element(der: &[u8], at: usize) -> Option<(u8, usize)> {
        let body = at + 2;
        let header = usize::from(*der.get(at + 1)?);
        let end = match header.checked_sub(0x80) {
            Some(count) if (1..8).contains(&count) => {
                let mut length = 0usize;
                for &byte in der.get(body..body + count)? {
                    length = length.checked_mul(256)?.checked_add(usize::from(byte))?;
                }
                body.checked_add(count)?.checked_add(length)?
            }
            _ => body.checked_add(header)?,
        };
        (end <= der.len()).then_some((*der.get(at)?, end))
    }
    if element(der, 0)?.0 != 0x30 {
        // A shape the probes do not name is rustls's to refuse, and the plain PKCS#1 slot is where that refusal reads.
        return Some(ServerKeyKind::Pkcs1);
    }
    Some(match element(der, element(der, 2)?.1)?.0 {
        0x04 => ServerKeyKind::Sec1,
        0x30 => ServerKeyKind::Pkcs8,
        _ => ServerKeyKind::Pkcs1,
    })
}

fn pem_blocks(pem: &[u8], label: &str) -> Vec<Vec<u8>> {
    let open = format!("-----BEGIN {label}-----");
    let shut = format!("-----END {label}-----");
    let Ok(text) = std::str::from_utf8(pem) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut rest = text;
    while let Some((_, after)) = rest.split_once(open.as_str()) {
        let Some((body, tail)) = after.split_once(shut.as_str()) else {
            break;
        };
        let Some(der) = b64::decode(body.as_bytes()) else {
            rest = tail;
            continue;
        };
        out.push(der);
        rest = tail;
    }
    out
}

pub mod cipher_suites;
mod ech;
mod hpke;
pub(crate) mod ocsp;

/// The OCSP response bytes to staple for a served chain, fetched from the leaf's responder.
pub fn ocsp_staple_for(chain: &[Vec<u8>]) -> Option<Vec<u8>> {
    ocsp::staple_for(chain)
}

/// The ECH config list a client config names, decoded from base64 or a PEM `ECH CONFIGS` block.
pub fn decode_ech_config(text: &str) -> Result<Vec<u8>, String> {
    ech::decode_source(text, "ECH CONFIGS")
}

/// A single ECH config wrapped as the one-entry list every client expects.
pub fn normalize_ech_config_list(bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    ech::normalize_config_list(bytes)
}

/// The ECH server keys a listener config names, decoded from base64 or a PEM `ECH KEYS` block.
pub fn decode_ech_keys(text: &str) -> Result<Vec<u8>, String> {
    let bytes = ech::decode_source(text, "ECH KEYS")?;
    ech::parse_server_keys(&bytes)?;
    Ok(bytes)
}

mod legacy;
mod rustls_backend;
pub use rustls_backend::{
    quic_server_context_builder, verify_cert_pinned, RustlsProvider, RustlsServerProvider,
};

pub mod shaped;
pub use shaped::Fingerprint;

/// The client session a config names: a shaped hello under its own record layer when
/// a fingerprint shapes it, the stock rustls connection otherwise.
pub enum ClientSession<S: Stream> {
    Stock(Box<RustlsProvider<S>>),
    Shaped(Box<shaped::Session<S>>),
    Legacy(Box<legacy::Session<S>>),
}

impl<S: Stream> std::fmt::Debug for ClientSession<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stock(session) => std::fmt::Debug::fmt(session, f),
            Self::Shaped(session) => std::fmt::Debug::fmt(session, f),
            Self::Legacy(session) => std::fmt::Debug::fmt(session, f),
        }
    }
}

impl<S: Stream> ClientSession<S> {
    pub fn get_ref(&self) -> &S {
        match self {
            Self::Stock(session) => session.get_ref(),
            Self::Shaped(session) => session.get_ref(),
            Self::Legacy(session) => session.get_ref(),
        }
    }

    /// Whether a relay may read this session's transport itself and hand it only the ciphertext.
    /// The `BoringSSL` path owns its transport, so it stays on the shared shape.
    pub fn separates_ciphertext(&self) -> bool {
        !matches!(self, Self::Legacy(_)) && !self.kernel_rx()
    }
}

impl<S: Stream> TlsProvider for ClientSession<S> {
    fn name() -> &'static str
    where
        Self: Sized,
    {
        "client"
    }

    fn suites(&self) -> Vec<String> {
        match self {
            Self::Stock(session) => session.suites(),
            Self::Shaped(session) => session.suites(),
            Self::Legacy(session) => session.suites(),
        }
    }

    fn handshake(&mut self) -> Result<(), TlsError> {
        match self {
            Self::Stock(session) => session.handshake(),
            Self::Shaped(session) => session.handshake(),
            Self::Legacy(session) => session.handshake(),
        }
    }

    fn alpn(&self) -> Option<&[u8]> {
        match self {
            Self::Stock(session) => session.alpn(),
            Self::Shaped(session) => session.alpn(),
            Self::Legacy(session) => session.alpn(),
        }
    }

    fn closed(&self) -> bool {
        match self {
            Self::Stock(session) => session.closed(),
            Self::Shaped(session) => session.closed(),
            Self::Legacy(session) => session.closed(),
        }
    }

    fn peer_leaf(&self) -> Option<&[u8]> {
        match self {
            Self::Stock(session) => session.peer_leaf(),
            Self::Shaped(session) => session.peer_leaf(),
            Self::Legacy(session) => session.peer_leaf(),
        }
    }

    fn peer_ocsp(&self) -> Option<&[u8]> {
        match self {
            Self::Stock(session) => session.peer_ocsp(),
            Self::Shaped(session) => session.peer_ocsp(),
            Self::Legacy(session) => session.peer_ocsp(),
        }
    }

    fn wants_ktls(&self) -> bool {
        match self {
            Self::Stock(session) => session.wants_ktls(),
            Self::Shaped(session) => session.wants_ktls(),
            Self::Legacy(session) => session.wants_ktls(),
        }
    }

    fn kernel_rx(&self) -> bool {
        match self {
            Self::Stock(session) => session.kernel_rx(),
            Self::Shaped(session) => session.kernel_rx(),
            Self::Legacy(session) => session.kernel_rx(),
        }
    }

    fn enable_ktls(&mut self, fd: RawFd) -> std::io::Result<()> {
        match self {
            Self::Stock(session) => session.enable_ktls(fd),
            Self::Shaped(session) => session.enable_ktls(fd),
            Self::Legacy(session) => session.enable_ktls(fd),
        }
    }

    fn open(&mut self, ciphertext: &[u8], buf: &mut [u8]) -> std::io::Result<(usize, usize)> {
        match self {
            Self::Stock(session) => session.open(ciphertext, buf),
            Self::Shaped(session) => session.open(ciphertext, buf),
            Self::Legacy(session) => session.open(ciphertext, buf),
        }
    }

    fn seal_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> std::io::Result<usize> {
        match self {
            Self::Stock(session) => session.seal_into(plaintext, out),
            Self::Shaped(session) => session.seal_into(plaintext, out),
            Self::Legacy(session) => session.seal_into(plaintext, out),
        }
    }

    fn seal_slices_into(&mut self, parts: &[&[u8]], out: &mut Vec<u8>) -> std::io::Result<()> {
        match self {
            Self::Stock(session) => session.seal_slices_into(parts, out),
            Self::Shaped(session) => session.seal_slices_into(parts, out),
            Self::Legacy(session) => session.seal_slices_into(parts, out),
        }
    }
}

impl<S: Stream + RecordAlignment> RecordAlignment for ClientSession<S> {
    fn engage_record_alignment(&mut self) {
        match self {
            Self::Stock(session) => session.engage_record_alignment(),
            Self::Shaped(session) => session.engage_record_alignment(),
            Self::Legacy(session) => session.engage_record_alignment(),
        }
    }

    fn disarm_record_alignment(&mut self) {
        match self {
            Self::Stock(session) => session.disarm_record_alignment(),
            Self::Shaped(session) => session.disarm_record_alignment(),
            Self::Legacy(session) => session.disarm_record_alignment(),
        }
    }

    fn write_all_slices(&mut self, parts: &[&[u8]]) -> std::io::Result<()> {
        match self {
            Self::Stock(session) => session.write_all_slices(parts),
            Self::Shaped(session) => session.write_all_slices(parts),
            Self::Legacy(session) => session.write_all_slices(parts),
        }
    }
}

impl<S: Stream> std::io::Read for ClientSession<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Stock(session) => session.read(buf),
            Self::Shaped(session) => session.read(buf),
            Self::Legacy(session) => session.read(buf),
        }
    }
}

impl<S: Stream> std::io::Write for ClientSession<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Stock(session) => session.write(buf),
            Self::Shaped(session) => session.write(buf),
            Self::Legacy(session) => session.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Stock(session) => session.flush(),
            Self::Shaped(session) => session.flush(),
            Self::Legacy(session) => session.flush(),
        }
    }
}

pub mod reality;
pub use reality::{
    write_proxy_protocol, Edges, Proxied, RateLimit, RealityAccept, RealityClientConfig,
    RealityClientSession, RealityServer, RealityServerConfig,
};

pub fn connect<S: Stream + RecordAlignment>(
    cfg: &TlsConfig,
    io: S,
) -> Result<ClientSession<S>, TlsError> {
    match shaped::profile_of(cfg) {
        Some(_) => Ok(ClientSession::Shaped(Box::new(shaped::Session::connect(
            cfg, io,
        )?))),
        // A list both backends lack, or both versions, rides the stock hello, which appends a real ECH slot.
        None if shaped::needs_stock_hello(&cfg.cipher_suites)
            || cipher_suites::mixed(&cfg.cipher_suites) =>
        {
            Ok(ClientSession::Shaped(Box::new(
                shaped::Session::connect_stock(cfg, io)?,
            )))
        }
        // The legacy lane carries no ECH, so an ECH config keeps the rustls lane.
        None if cfg.ech_config_list.is_none() && legacy::dial_needed(&cfg.cipher_suites) => Ok(
            ClientSession::Legacy(Box::new(legacy::Session::connect(cfg, io)?)),
        ),
        None => Ok(ClientSession::Stock(Box::new(RustlsProvider::connect(
            cfg, io,
        )?))),
    }
}

pub fn accept<S: Stream + Send>(
    cfg: &TlsServerConfig,
    io: S,
) -> Result<RustlsServerProvider<reality::RecordLimiter<S>>, TlsError> {
    let mut io = io;
    let mut prefix = None;
    let shaped = if cipher_suites::shaped_listener(&cfg.cipher_suites, cfg.min_version) {
        if cfg.max_version.unwrap_or(0x0304) <= 0x0303 || cfg.ech_server_keys.is_some() {
            true
        } else {
            let (bytes, delegate) = shaped::server::peek_hello(&mut io).map_err(|error| {
                TlsError::Other(format!("tls: reading the client hello: {error}"))
            })?;
            prefix = Some(bytes);
            !delegate
        }
    } else {
        false
    };
    let mut limiter = reality::RecordLimiter::new_open(io);
    if let Some(bytes) = prefix {
        limiter.set_prefix(bytes);
    }
    RustlsServerProvider::accept_decided(cfg.clone(), limiter, shaped)
}

pub fn active_backends() -> &'static [&'static str] {
    &["rustls", "boring"]
}

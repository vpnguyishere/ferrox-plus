//! The TLS 1.2 suites `BoringSSL` carries and ring does not: ECDHE and static-RSA CBC, and 3DES.
//!
//! A config that names one of these ids cannot be served by rustls, whose provider has no CBC and
//! no RSA key exchange, so a dial or a listener that names one moves the whole handshake to
//! `BoringSSL`. The cipher list keeps the config's order, which is what puts the reference's ids on
//! the wire in its order; `BoringSSL` still adds its fixed TLS 1.3 trio in front of them, where
//! `crypto/tls` appends that trio after the TLS 1.2 list.

use super::{MasterKeyLog, Stream, TlsConfig, TlsError, TlsProvider, TlsServerConfig};
use boring::ssl::{
    HandshakeError, MidHandshakeSslStream, Ssl, SslContext, SslContextBuilder, SslMethod,
    SslSession, SslStream, SslVerifyMode, SslVersion,
};
use std::sync::{Arc, Mutex, OnceLock};

/// The ids `BoringSSL` can negotiate, as its own cipher names. An id outside this table is one no
/// backend here can carry, and `set_cipher_list` would silently drop it.
pub(crate) fn suite_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0xc009 => "ECDHE-ECDSA-AES128-SHA",
        0xc00a => "ECDHE-ECDSA-AES256-SHA",
        0xc013 => "ECDHE-RSA-AES128-SHA",
        0xc014 => "ECDHE-RSA-AES256-SHA",
        0xc023 => "ECDHE-ECDSA-AES128-SHA256",
        0xc027 => "ECDHE-RSA-AES128-SHA256",
        0x002f => "AES128-SHA",
        0x0035 => "AES256-SHA",
        0x009c => "AES128-GCM-SHA256",
        0x009d => "AES256-GCM-SHA384",
        0x000a => "DES-CBC3-SHA",
        0xc02b => "ECDHE-ECDSA-AES128-GCM-SHA256",
        0xc02c => "ECDHE-ECDSA-AES256-GCM-SHA384",
        0xcca9 => "ECDHE-ECDSA-CHACHA20-POLY1305",
        0xc02f => "ECDHE-RSA-AES128-GCM-SHA256",
        0xc030 => "ECDHE-RSA-AES256-GCM-SHA384",
        0xcca8 => "ECDHE-RSA-CHACHA20-POLY1305",
        _ => return None,
    })
}

/// Whether a list names a suite this backend reaches only through `BoringSSL`.
pub(crate) fn needed(ids: &[u16]) -> bool {
    ids.iter()
        .any(|&id| suite_name(id).is_some() && !super::rustls_backend::carries(id))
}

/// Whether a dial must take this lane: a named TLS 1.2-only list writes the reference's field
/// without rustls's SCSV, and this lane keeps the session cache `enableSessionResumption` asks for.
pub(crate) fn dial_needed(ids: &[u16]) -> bool {
    (!ids.is_empty()
        && super::cipher_suites::offers_tls12(ids)
        && !super::cipher_suites::offers_tls13(ids))
        || needed(ids)
}

/// The cipher names for a config's list, in its order. Names `BoringSSL` cannot parse are skipped
/// here rather than failing the build: the same ids `needed` validated are the ones that matter.
pub(crate) fn cipher_list(ids: &[u16]) -> String {
    let mut list = String::with_capacity(ids.len() * 28);
    for name in ids.iter().filter_map(|&id| suite_name(id)) {
        if !list.is_empty() {
            list.push(':');
        }
        list.push_str(name);
    }
    list
}

pub(crate) fn version(value: u16) -> Result<SslVersion, TlsError> {
    match value {
        0x0303 => Ok(SslVersion::TLS1_2),
        0x0304 => Ok(SslVersion::TLS1_3),
        other => Err(TlsError::Other(format!(
            "tls suite {} names no protocol version",
            format_args!("{other:#06x}")
        ))),
    }
}

/// The protocol bounds a listener's config names, clamped onto the pair this backend carries.
fn server_versions(cfg: &TlsServerConfig) -> Result<(SslVersion, SslVersion), TlsError> {
    let floor = cfg.min_version.unwrap_or(0x0303).max(0x0303);
    let ceiling = cfg.max_version.unwrap_or(0x0304).min(0x0304);
    if floor > ceiling {
        return Err(TlsError::Other(
            "tls server version bounds name no supported protocol".to_owned(),
        ));
    }
    Ok((version(floor)?, version(ceiling)?))
}

/// The curves a config names, as `BoringSSL`'s own names. A group this backend cannot carry is
/// skipped, and a list it carries none of leaves the stock order.
fn curve_list(ids: &[u16]) -> String {
    let mut list = String::with_capacity(ids.len() * 7);
    for name in ids.iter().filter_map(|&id| match id {
        0x0017 => Some("P-256"),
        0x0018 => Some("P-384"),
        0x0019 => Some("P-521"),
        0x001d => Some("X25519"),
        _ => None,
    }) {
        if !list.is_empty() {
            list.push(':');
        }
        list.push_str(name);
    }
    list
}

fn alpn_wire(protocols: &[Vec<u8>]) -> Result<Vec<u8>, TlsError> {
    let mut wire = Vec::with_capacity(protocols.iter().map(|p| p.len() + 1).sum());
    for protocol in protocols {
        let Ok(len) = u8::try_from(protocol.len()) else {
            return Err(TlsError::Other("alpn protocol is too long".to_owned()));
        };
        wire.push(len);
        wire.extend_from_slice(protocol);
    }
    Ok(wire)
}

fn error_stack(error: &boring::error::ErrorStack) -> TlsError {
    TlsError::Other(format!("boring tls: {error}"))
}

/// What selects a cached client context: the same material a rustls build keys on (anchors, pins,
/// suite order, curves) plus the host the verify callback captures, the `ALPN` list, the client
/// identity and the key-log handle.
#[derive(Clone)]
struct Key {
    material: super::rustls_backend::MaterialKey,
    server_name: String,
    alpn: Arc<[Vec<u8>]>,
    client_cert: Option<Arc<super::CertEntry>>,
    master_key_log: Option<Arc<MasterKeyLog>>,
}

/// The same inputs a context is cached under, so a stored session is only offered to the context
/// that minted it.
fn key(cfg: &TlsConfig) -> Key {
    Key {
        material: super::rustls_backend::MaterialKey::of(cfg),
        server_name: cfg.server_name.clone(),
        alpn: Arc::clone(&cfg.alpn),
        client_cert: cfg.client_cert.clone(),
        master_key_log: cfg.master_key_log.clone(),
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.material == other.material
            && self.server_name == other.server_name
            && self.alpn == other.alpn
            && match (&self.client_cert, &other.client_cert) {
                (None, None) => true,
                (Some(ours), Some(theirs)) => Arc::ptr_eq(ours, theirs) || ours == theirs,
                _ => false,
            }
            && match (&self.master_key_log, &other.master_key_log) {
                (None, None) => true,
                (Some(ours), Some(theirs)) => Arc::ptr_eq(ours, theirs),
                _ => false,
            }
    }
}

impl Eq for Key {}

type Contexts = Vec<(Key, Arc<SslContext>)>;

static CONTEXTS: OnceLock<Mutex<Contexts>> = OnceLock::new();

const CONTEXTS_MAX: usize = 32;

type Sessions = Vec<(Key, SslSession)>;

static SESSIONS: OnceLock<Mutex<Sessions>> = OnceLock::new();

const SESSIONS_MAX: usize = 32;

/// The session a prior dial to this key left, moved to the back so the cap drops the coldest.
fn take_session(key: &Key) -> Option<SslSession> {
    let all = SESSIONS.get_or_init(Default::default);
    let mut kept = all.lock().expect("one session at a time");
    let at = kept.iter().position(|(stored, _)| stored == key)?;
    let entry = kept.remove(at);
    let hit = entry.1.clone();
    kept.push(entry);
    Some(hit)
}

/// Keeps the session a completed handshake minted, replacing the key's older one.
fn keep_session(key: &Key, session: SslSession) {
    let all = SESSIONS.get_or_init(Default::default);
    let mut kept = all.lock().expect("one session at a time");
    if let Some(at) = kept.iter().position(|(stored, _)| stored == key) {
        kept.remove(at);
    } else if kept.len() == SESSIONS_MAX {
        kept.remove(0);
    }
    kept.push((key.clone(), session));
}

/// The `BoringSSL` context a legacy dial builds its hello from, cached per input set because
/// `BoringSSL` parses every trust anchor when a context is built.
fn context(cfg: &TlsConfig) -> Result<Arc<SslContext>, TlsError> {
    let key = key(cfg);
    let all = CONTEXTS.get_or_init(Default::default);
    let mut kept = all.lock().expect("one build at a time");
    if let Some(at) = kept.iter().position(|(stored, _)| *stored == key) {
        let entry = kept.remove(at);
        let hit = Arc::clone(&entry.1);
        kept.push(entry);
        return Ok(hit);
    }
    drop(kept);
    let built = Arc::new(build_context(cfg)?);
    let mut kept = all.lock().expect("one build at a time");
    if let Some(at) = kept.iter().position(|(stored, _)| *stored == key) {
        let entry = kept.remove(at);
        let hit = Arc::clone(&entry.1);
        kept.push(entry);
        return Ok(hit);
    }
    if kept.len() == CONTEXTS_MAX {
        kept.remove(0);
    }
    kept.push((key, Arc::clone(&built)));
    Ok(built)
}

/// Builds the `BoringSSL` context for one config, capped at TLS 1.2 when the list names no TLS 1.3 id.
fn build_context(cfg: &TlsConfig) -> Result<SslContext, TlsError> {
    let name = rustls::pki_types::ServerName::try_from(cfg.server_name.clone())
        .map_err(|e| TlsError::Other(format!("tls server name: {e}")))?;
    let verifier = super::rustls_backend::verifier(cfg)?;
    let mut builder = SslContextBuilder::new(SslMethod::tls()).map_err(|e| error_stack(&e))?;
    // The callback owns verification, so the mode only decides that a peer certificate is asked for.
    builder.set_verify(SslVerifyMode::PEER);
    builder.set_cert_verify_callback(move |store| {
        // This callback replaces the built-in verification, so the leaf is being verified and the chain is the peer's.
        let Some(leaf) = store.cert().and_then(|cert| cert.to_der().ok()) else {
            return false;
        };
        let mut rest = Vec::new();
        if let Some(chain) = store.untrusted().or_else(|| store.chain()) {
            for cert in chain {
                if let Ok(der) = cert.to_der() {
                    if der != leaf {
                        rest.push(rustls::pki_types::CertificateDer::from(der));
                    }
                }
            }
        }
        verifier
            .verify_server_cert(
                &rustls::pki_types::CertificateDer::from(leaf),
                &rest,
                &name,
                &[],
                rustls::pki_types::UnixTime::now(),
            )
            .is_ok()
    });
    if !cfg.alpn.is_empty() {
        builder
            .set_alpn_protos(&alpn_wire(&cfg.alpn)?)
            .map_err(|e| error_stack(&e))?;
    }
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|e| error_stack(&e))?;
    // No TLS 1.3 id means the reference's max is below 1.3; the cap drops BoringSSL's fixed trio.
    if !crate::tls::cipher_suites::offers_tls13(&cfg.cipher_suites) {
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_2))
            .map_err(|e| error_stack(&e))?;
    }
    let curves = curve_list(&cfg.curves);
    if !curves.is_empty() {
        builder
            .set_curves_list(&curves)
            .map_err(|e| error_stack(&e))?;
    }
    builder
        .set_cipher_list(&cipher_list(&cfg.cipher_suites))
        .map_err(|e| error_stack(&e))?;
    if let Some(entry) = &cfg.client_cert {
        let leaf = entry
            .cert_chain
            .first()
            .ok_or_else(|| TlsError::Other("client identity has no certificate".to_owned()))?;
        let leaf = boring::x509::X509::from_der(leaf).map_err(|e| error_stack(&e))?;
        builder
            .set_certificate(&leaf)
            .map_err(|e| error_stack(&e))?;
        for cert in entry.cert_chain.iter().skip(1) {
            builder
                .add_extra_chain_cert(
                    boring::x509::X509::from_der(cert).map_err(|e| error_stack(&e))?,
                )
                .map_err(|e| error_stack(&e))?;
        }
        let key = boring::pkey::PKey::private_key_from_der(&entry.key_der)
            .map_err(|e| error_stack(&e))?;
        builder.set_private_key(&key).map_err(|e| error_stack(&e))?;
        builder.check_private_key().map_err(|e| error_stack(&e))?;
    }
    if let Some(log) = cfg.master_key_log.clone() {
        builder.set_keylog_callback(move |_, line| log.log_line(line));
    }
    Ok(builder.build())
}

/// The listener context a legacy accept builds its session from: the served identities, `ALPN`,
/// `SNI` rule, tickets and key log, with the protocol bounds and cipher list the config names.
pub(crate) fn server_context(cfg: &TlsServerConfig) -> Result<Arc<SslContext>, TlsError> {
    let mut guard = cfg
        .server_config_cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // A reload tick leaves the new identities in the cache, as the plain slot reads them.
    let served = guard.served.clone().unwrap_or_else(|| cfg.certs.clone());
    if let Some((built_for, ctx)) = guard.legacy.as_ref() {
        if built_for == &served {
            return Ok(Arc::clone(ctx));
        }
    }
    let mut fresh = cfg.clone();
    fresh.certs.clone_from(&served);
    let mut builder = super::rustls_backend::server_identity_builder(&fresh)?;
    let (floor, ceiling) = server_versions(cfg)?;
    builder
        .set_min_proto_version(Some(floor))
        .map_err(|e| error_stack(&e))?;
    builder
        .set_max_proto_version(Some(ceiling))
        .map_err(|e| error_stack(&e))?;
    builder
        .set_cipher_list(&cipher_list(&cfg.cipher_suites))
        .map_err(|e| error_stack(&e))?;
    builder
        .set_session_id_context(b"ferrox-legacy")
        .map_err(|e| error_stack(&e))?;
    let built = Arc::new(builder.build());
    guard.legacy = Some((served, Arc::clone(&built)));
    Ok(built)
}

/// A dial whose suite list only `BoringSSL` can carry: the context is cached, the session owns its
/// transport, and its handshake keeps the mid-handshake stream across a poll timeout.
pub struct Session<S: Stream> {
    handshake: Option<MidHandshakeSslStream<S>>,
    stream: Option<SslStream<S>>,
    leaf: Vec<u8>,
    suites: Vec<u16>,
    resume: Option<Key>,
    eof: bool,
    failure: Option<String>,
}

impl<S: Stream> std::fmt::Debug for Session<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LegacySession")
            .field("alpn", &self.alpn())
            .field("is_handshaking", &self.stream.is_none())
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}

impl<S: Stream> Session<S> {
    pub fn connect(cfg: &TlsConfig, io: S) -> Result<Self, TlsError> {
        let ctx = context(cfg)?;
        let mut ssl = Ssl::new(&ctx).map_err(|e| error_stack(&e))?;
        let resume = cfg.resumption.then(|| key(cfg));
        if let Some(session) = resume.as_ref().and_then(take_session) {
            // SAFETY: the session and the context are keyed by the same inputs, so the context minted it.
            unsafe { ssl.set_session(&session) }.map_err(|e| error_stack(&e))?;
        }
        // A literal address names no virtual host, so it reaches the transport without SNI.
        if rustls::pki_types::ServerName::try_from(cfg.server_name.clone())
            .is_ok_and(|name| matches!(name, rustls::pki_types::ServerName::DnsName(_)))
        {
            ssl.set_hostname(&cfg.server_name)
                .map_err(|e| error_stack(&e))?;
        }
        Ok(Self {
            handshake: Some(ssl.setup_connect(io)),
            stream: None,
            leaf: Vec::new(),
            suites: cfg.cipher_suites.to_vec(),
            resume,
            eof: false,
            failure: None,
        })
    }

    pub(crate) fn get_ref(&self) -> &S {
        match (&self.stream, &self.handshake) {
            (Some(stream), _) => stream.get_ref(),
            (None, Some(handshake)) => handshake.get_ref(),
            (None, None) => unreachable!("a session holds its transport until it is dropped"),
        }
    }

    /// Whether the last handshake rode the session the same key stored.
    #[cfg(test)]
    pub(crate) fn session_reused(&self) -> bool {
        self.stream
            .as_ref()
            .is_some_and(|stream| stream.ssl().session_reused())
    }

    fn stream(&mut self) -> std::io::Result<&mut SslStream<S>> {
        if self.stream.is_none() {
            self.handshake().map_err(std::io::Error::other)?;
        }
        self.stream
            .as_mut()
            .ok_or_else(|| std::io::Error::other("tls handshake is not complete"))
    }
}

impl<S: Stream> TlsProvider for Session<S> {
    fn name() -> &'static str {
        "boring"
    }

    fn suites(&self) -> Vec<String> {
        self.suites.iter().map(|id| format!("{id:#06x}")).collect()
    }

    fn handshake(&mut self) -> Result<(), TlsError> {
        if let Some(why) = &self.failure {
            return Err(TlsError::Other(why.clone()));
        }
        if self.stream.is_some() {
            return Ok(());
        }
        let Some(mid) = self.handshake.take() else {
            return Ok(());
        };
        match mid.handshake() {
            Ok(done) => {
                self.leaf = done
                    .ssl()
                    .peer_certificate()
                    .and_then(|cert| cert.to_der().ok())
                    .unwrap_or_default();
                if let Some(key) = &self.resume {
                    if let Some(session) = done.ssl().session() {
                        keep_session(key, session.to_owned());
                    }
                }
                self.stream = Some(done);
                Ok(())
            }
            Err(HandshakeError::WouldBlock(mid)) => {
                self.handshake = Some(mid);
                Err(TlsError::Timeout)
            }
            Err(HandshakeError::Failure(mid)) => {
                if mid.error().would_block()
                    || mid.error().io_error().is_some_and(TlsError::is_timeout)
                {
                    self.handshake = Some(mid);
                    return Err(TlsError::Timeout);
                }
                let why = format!("boring tls handshake: {}", mid.error());
                self.handshake = Some(mid);
                self.failure = Some(why.clone());
                Err(TlsError::Other(why))
            }
            Err(HandshakeError::SetupFailure(error)) => {
                let why = format!("boring tls setup: {error}");
                self.failure = Some(why.clone());
                Err(TlsError::Other(why))
            }
        }
    }

    fn alpn(&self) -> Option<&[u8]> {
        self.stream
            .as_ref()
            .and_then(|stream| stream.ssl().selected_alpn_protocol())
    }

    fn closed(&self) -> bool {
        self.eof
    }

    fn peer_leaf(&self) -> Option<&[u8]> {
        (!self.leaf.is_empty()).then_some(self.leaf.as_slice())
    }
}

impl<S: Stream> std::io::Read for Session<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.stream()?.read(buf) {
            Ok(0) => {
                self.eof = true;
                Ok(0)
            }
            other => other,
        }
    }
}

impl<S: Stream> std::io::Write for Session<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream()?.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream()?.flush()
    }
}

impl<S: Stream + super::RecordAlignment> super::RecordAlignment for Session<S> {
    fn engage_record_alignment(&mut self) {
        match (&mut self.stream, &mut self.handshake) {
            (Some(stream), _) => stream.get_mut().engage_record_alignment(),
            (None, Some(handshake)) => handshake.get_mut().engage_record_alignment(),
            (None, None) => {}
        }
    }

    fn disarm_record_alignment(&mut self) {
        match (&mut self.stream, &mut self.handshake) {
            (Some(stream), _) => stream.get_mut().disarm_record_alignment(),
            (None, Some(handshake)) => handshake.get_mut().disarm_record_alignment(),
            (None, None) => {}
        }
    }
}

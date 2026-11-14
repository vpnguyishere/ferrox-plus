use super::{RawFd, Stream, TlsConfig, TlsError, TlsProvider};
use sha2::Digest;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex, OnceLock};

type RootStore = rustls::RootCertStore;

/// The ring provider every identity shares: building it spends two vectors.
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    static PROVIDER: std::sync::OnceLock<Arc<rustls::crypto::CryptoProvider>> =
        std::sync::OnceLock::new();
    Arc::clone(PROVIDER.get_or_init(|| Arc::new(rustls::crypto::ring::default_provider())))
}

/// Whether ring's provider has a suite, which decides if a named id can stay on the rustls path.
pub(crate) fn carries(id: u16) -> bool {
    provider()
        .cipher_suites
        .iter()
        .any(|suite| u16::from(suite.suite()) == id)
}

/// A config that names TLS 1.2 suites admits only those, in its order: TLS 1.3
/// suites are fixed by the protocol and stay whatever the config says.
fn order_cipher_suites(provider: &mut rustls::crypto::CryptoProvider, order: &[u16]) {
    provider.cipher_suites.retain(|suite| {
        let id = u16::from(suite.suite());
        matches!(id, 0x1301..=0x1305) || order.contains(&id)
    });
    provider.cipher_suites.sort_by_key(|suite| {
        let id = u16::from(suite.suite());
        order
            .iter()
            .position(|&want| want == id)
            .unwrap_or(usize::MAX)
    });
}

/// A config that names curves offers only those, in its order; one the provider cannot carry is
/// absent rather than replaced by a stock group, the same rule the suite order follows. A list the
/// provider carries none of leaves the stock order, since a hello with no group handshakes with
/// nobody.
fn order_kx_groups(provider: &mut rustls::crypto::CryptoProvider, order: &[u16]) {
    let named: Vec<&'static dyn rustls::crypto::SupportedKxGroup> = order
        .iter()
        .filter_map(|&want| {
            provider
                .kx_groups
                .iter()
                .copied()
                .find(|group| u16::from(group.name()) == want)
        })
        .collect();
    if !named.is_empty() {
        provider.kx_groups = named;
    }
}

pub struct RustlsProvider<S: Stream> {
    conn: rustls::ClientConnection,
    io: S,
    eof: bool,
    ktls_tx: bool,
    ktls_rx: bool,
    captured: Option<Arc<Mutex<Captured>>>,
    ktls: Option<crate::tls::ktls::Layer>,
    hsbuf: Vec<u8>,
}

impl<S: Stream> std::fmt::Debug for RustlsProvider<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustlsProvider")
            .field("alpn", &self.conn.alpn_protocol())
            .field("is_handshaking", &self.conn.is_handshaking())
            .finish_non_exhaustive()
    }
}

/// The stock chain verifier with a leaf-pin check bolted on the end, so pinning
/// narrows what already verified — and, when the store this device has cannot
/// build the chain of a key it does pin, stands in for that store with the leaf
/// as its own anchor. `Debug` is derived because the crate denies its absence.
#[derive(Debug)]
struct Pinned {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    pins: crate::foxy::pin::Pins,
}

/// The reference's `pinnedPeerCertSha256` verifier: a digest matching the leaf's DER accepts
/// the handshake on the pin alone, one matching an intermediate's stands the pinned
/// certificate in as the only trust root and the chain and server name still verify — the
/// same gate `verifyChain` draws, with the standard verifier skipped because the pin is the
/// whole contract.
#[derive(Debug)]
struct CertPinned {
    cert_pins: Arc<[[u8; 32]]>,
    names: Arc<[String]>,
}

impl CertPinned {
    fn holds(&self, certificate: &rustls::pki_types::CertificateDer<'_>) -> bool {
        let digest: [u8; 32] = sha2::Sha256::digest(certificate.as_ref()).into();
        self.cert_pins.contains(&digest)
    }
}

/// A chain verified against one name: the connection's server name, or each `verifyPeerCertByName`
/// entry in turn, where the first name the chain answers accepts it.
fn named(
    verifier: &dyn rustls::client::danger::ServerCertVerifier,
    end_entity: &rustls::pki_types::CertificateDer<'_>,
    intermediates: &[rustls::pki_types::CertificateDer<'_>],
    server_name: &rustls::pki_types::ServerName<'_>,
    ocsp_response: &[u8],
    now: rustls::pki_types::UnixTime,
    names: &[String],
) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
    if names.is_empty() {
        return verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );
    }
    for name in names {
        let Ok(name) = rustls::pki_types::ServerName::try_from(name.clone()) else {
            continue;
        };
        if verifier
            .verify_server_cert(end_entity, intermediates, &name, ocsp_response, now)
            .is_ok()
        {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }
    }
    Err(rustls::Error::InvalidCertificate(
        rustls::CertificateError::ApplicationVerificationFailure,
    ))
}

/// The reference's `verifyPeerCertByName`: with that field set it skips its own name check and
/// verifies the chain once per listed name, so the SNI the hello carried is not the name trusted.
#[derive(Debug)]
struct Named {
    inner: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    names: Arc<[String]>,
}

impl rustls::client::danger::ServerCertVerifier for Named {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        named(
            self.inner.as_ref(),
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
            &self.names,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

impl rustls::client::danger::ServerCertVerifier for CertPinned {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if self.holds(end_entity) {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }
        for intermediate in intermediates {
            if !self.holds(intermediate) {
                continue;
            }
            // The pinned certificate acts as the only root, exactly as the reference's pinned-CA path does; the chain and the name still check, and a certificate that cannot anchor is refused rather than retried.
            let anchor = anchored(intermediate)?;
            return named(
                anchor.as_ref(),
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
                &self.names,
            )
            .or(Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )));
        }
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ))
    }

    // A pin needs no anchor, so the provider's own algorithms answer the messages the webpki path does.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The leaf as the only trust anchor, so a pinned edge still gets the name and validity checks a chain this device cannot build would otherwise skip.
fn anchored(
    leaf: &rustls::pki_types::CertificateDer<'_>,
) -> Result<Arc<rustls::client::WebPkiServerVerifier>, rustls::Error> {
    let mut roots = RootStore::empty();
    roots.add(leaf.clone())?;
    rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
        .build()
        .map_err(|e| rustls::Error::General(format!("pinned anchor: {e}")))
}
/// Verifies a chain a backend read itself, for a pin set that backend could not hand to a verifier: a leaf digest accepts on the pin alone, an intermediate's anchors the chain with the server name still checked. Used by the QUIC lanes, whose library exposes no verifier hook.
#[must_use]
pub fn verify_cert_pinned(
    chain: &[Vec<u8>],
    cert_pins: &Arc<[[u8; 32]]>,
    server_name: &str,
) -> bool {
    let Some((leaf, rest)) = chain.split_first() else {
        return false;
    };
    let Ok(name) = rustls::pki_types::ServerName::try_from(server_name.to_owned()) else {
        return false;
    };
    let leaf = rustls::pki_types::CertificateDer::from(leaf.as_slice());
    let intermediates: Vec<_> = rest
        .iter()
        .map(|cert| rustls::pki_types::CertificateDer::from(cert.as_slice()))
        .collect();
    let verifier = CertPinned {
        cert_pins: cert_pins.clone(),
        names: std::sync::Arc::default(),
    };
    rustls::client::danger::ServerCertVerifier::verify_server_cert(
        &verifier,
        &leaf,
        &intermediates,
        &name,
        &[],
        rustls::pki_types::UnixTime::now(),
    )
    .is_ok()
}

impl rustls::client::danger::ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let pinned = self.pins.holds(end_entity);
        if let Err(error) = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            // The operator pinned this key, so the key is the authority a stale device store withholds; everything else about the certificate is still checked.
            if !pinned {
                return Err(error);
            }
            anchored(end_entity)?.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )?;
        }
        if pinned {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// The cover-site verifier a `masq_url_insecure` origin names: it trusts the peer chain
/// exactly as presented, which is what the reference's `allowInsecure` means — a
/// masquerade cover dials an arbitrary public site to look convincing and must not fail on
/// a store this edge cannot reach. It is the one bounded place a certificate is taken on
/// faith: the relayed lane refuses `allowInsecure` outright and so never reaches this type.
#[derive(Debug)]
struct Unverified;

impl rustls::client::danger::ServerCertVerifier for Unverified {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The expensive halves of a client config, shared by every dial that names the same trust anchors, pins, ALPN list and suite order: parsing an anchor and building a verifier are per-config work, not per-connection work.
struct Material {
    roots: Arc<RootStore>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    /// The plain chain verifier a shaped session checks against, built on the first shaped dial: a stock config reaches the same check through rustls's own lazy verifier.
    chain: OnceLock<Result<Arc<rustls::client::WebPkiServerVerifier>, String>>,
    /// Present only when the config pins: the `Pinned` wrapper around the chain verifier, holding the keys a verified chain must still carry.
    verifier: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>>,
}

/// The config fields `build_material` reads. ALPN is not one of them because the anchors and the suite order do not depend on it, and the server name is not one either: it reaches the connection, not the config.
#[derive(Clone, Eq)]
pub(crate) struct MaterialKey {
    roots: crate::tls::Anchors,
    pins: crate::foxy::pin::Pins,
    cert_pins: Arc<[[u8; 32]]>,
    verify_names: Arc<[String]>,
    cipher_suites: std::sync::Arc<[u16]>,
    curves: Arc<[u16]>,
    /// The mode decides whether a named verifier exists, so it belongs to the material it selects.
    insecure: bool,
}

/// Two anchor lists name the same trust when one allocation answers for both, which is what sharing them by reference makes the ordinary case; comparing their bytes is a walk of every certificate the platform trusts, and only a set read twice can reach it.
fn same_roots(ours: &crate::tls::Anchors, theirs: &crate::tls::Anchors) -> bool {
    Arc::ptr_eq(ours, theirs) || ours == theirs
}

impl PartialEq for MaterialKey {
    fn eq(&self, other: &Self) -> bool {
        same_roots(&self.roots, &other.roots)
            && self.pins == other.pins
            && self.cert_pins.as_ref() == other.cert_pins.as_ref()
            && self.verify_names == other.verify_names
            && self.cipher_suites == other.cipher_suites
            && self.curves == other.curves
            && self.insecure == other.insecure
    }
}

impl MaterialKey {
    pub(crate) fn of(cfg: &TlsConfig) -> Self {
        Self {
            roots: Arc::clone(&cfg.roots),
            pins: cfg.pins.clone(),
            cert_pins: Arc::clone(&cfg.cert_pins),
            verify_names: Arc::clone(&cfg.verify_names),
            cipher_suites: Arc::clone(&cfg.cipher_suites),
            curves: Arc::clone(&cfg.curves),
            insecure: cfg.insecure,
        }
    }
}

/// Every set of inputs this process has dialed with; a config comes from a config file, so the set is the number of remotes, and it is capped rather than trusted to stay small.
const MATERIALS_MAX: usize = 32;

/// A build, and the three inputs that select it.
type Materials = Vec<(MaterialKey, Arc<Material>)>;

static MATERIALS: OnceLock<Mutex<Materials>> = OnceLock::new();

/// Parses the anchors, orders the suites and builds the verifier a config named, once per set of inputs.
fn build_material(cfg: &TlsConfig) -> Result<Material, TlsError> {
    let mut roots = RootStore::empty();
    for der in cfg.roots.iter() {
        roots
            .add(rustls::pki_types::CertificateDer::from(der.as_slice()))
            .map_err(|e| TlsError::BadCertificate(format!("trust anchor: {e}")))?;
    }
    let roots = Arc::new(roots);

    let mut provider = (*provider()).clone();
    if !cfg.cipher_suites.is_empty() {
        // The ring backend's set is a subset of `crypto/tls`'s, so a named suite it cannot reach is absent rather than replaced by a stock one.
        order_cipher_suites(&mut provider, &cfg.cipher_suites);
    }
    if !cfg.curves.is_empty() {
        order_kx_groups(&mut provider, &cfg.curves);
    }
    let provider = Arc::new(provider);

    let chain = OnceLock::new();
    let names = Arc::clone(&cfg.verify_names);
    let verifier = if !cfg.cert_pins.is_empty() {
        // No anchor work: a cert-pin verdict never needs the webpki chain builder.
        Some(Arc::new(CertPinned {
            cert_pins: Arc::clone(&cfg.cert_pins),
            names,
        })
            as Arc<dyn rustls::client::danger::ServerCertVerifier>)
    } else if !cfg.pins.is_empty() {
        let plain = build_chain(&roots, &provider)?;
        let _ = chain.set(Ok(Arc::clone(&plain)));
        let pinned: Arc<dyn rustls::client::danger::ServerCertVerifier> = Arc::new(Pinned {
            inner: plain,
            pins: cfg.pins.clone(),
        });
        Some(if names.is_empty() {
            pinned
        } else {
            Arc::new(Named {
                inner: pinned,
                names,
            })
        })
    } else if !cfg.insecure && !names.is_empty() {
        // A named chain is the whole contract the way a pin is, so `insecure` outranks it.
        let plain = build_chain(&roots, &provider)?;
        let _ = chain.set(Ok(Arc::clone(&plain)));
        Some(Arc::new(Named {
            inner: plain,
            names,
        })
            as Arc<dyn rustls::client::danger::ServerCertVerifier>)
    } else {
        None
    };
    Ok(Material {
        roots,
        provider,
        chain,
        verifier,
    })
}

/// What selects a cached client config: a material, the `ALPN` list the builder writes into it, and whether the verifier is the unverified one. The server name stays out — it reaches the connection, not the config.
struct ConfigKey {
    material: MaterialKey,
    /// The `ALPN` list, shared rather than copied: the key is built on every dial, and copying the list into it allocated a vector of vectors per lookup for a list that never changes.
    alpn: std::sync::Arc<[Vec<u8>]>,
    insecure: bool,
    /// The resumption mode is baked into the built config as its session store, so two configs that differ only here must not share one.
    resumption: bool,
    /// The ECH config list, which rustls bakes into the built config rather than reading per connection.
    ech: Option<std::sync::Arc<[u8]>>,
    /// The protocol window rustls bakes into the built config.
    min_version: Option<u16>,
    max_version: Option<u16>,
    /// The `masterKeyLog` handle rustls bakes into the config: two configs naming different files must not share a build, so the handle's identity is what the key holds.
    master_key_log: Option<Arc<super::MasterKeyLog>>,
    /// The client identity rustls bakes into the config's resolver, swapped by value when the bytes differ.
    client_cert: Option<Arc<super::CertEntry>>,
}

impl PartialEq for ConfigKey {
    fn eq(&self, other: &Self) -> bool {
        self.material == other.material
            && self.alpn == other.alpn
            && self.insecure == other.insecure
            && self.resumption == other.resumption
            && self.ech == other.ech
            && self.min_version == other.min_version
            && self.max_version == other.max_version
            && match (&self.master_key_log, &other.master_key_log) {
                (None, None) => true,
                (Some(ours), Some(theirs)) => Arc::ptr_eq(ours, theirs),
                _ => false,
            }
            && match (&self.client_cert, &other.client_cert) {
                (None, None) => true,
                (Some(ours), Some(theirs)) => Arc::ptr_eq(ours, theirs) || ours == theirs,
                _ => false,
            }
    }
}

impl Eq for ConfigKey {}

type Configs = Vec<(ConfigKey, Arc<rustls::ClientConfig>)>;

static CONFIGS: OnceLock<Mutex<Configs>> = OnceLock::new();

/// The client config the cache above keeps one of: the material's provider and roots, the named `ALPN`, and the verifier the config forces.
fn build_config(cfg: &TlsConfig, built: &Material) -> Result<rustls::ClientConfig, TlsError> {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&built.provider));
    let builder = match cfg.ech_config_list.as_ref() {
        Some(list) => {
            if cfg.max_version.is_some_and(|version| version < 0x0304) {
                return Err(TlsError::Other(
                    "ech: a client maximum below TLS 1.3 cannot carry ECH".to_owned(),
                ));
            }
            let ech = rustls::client::EchConfig::new(
                rustls::pki_types::EchConfigListBytes::from(list.as_ref()),
                &super::hpke::SUITES,
            )
            .map_err(|e| TlsError::Other(format!("ech config: {e}")))?;
            builder
                .with_ech(rustls::client::EchMode::Enable(ech))
                .map_err(|e| TlsError::Other(format!("ech: {e}")))?
        }
        None => match protocol_versions(cfg.min_version, cfg.max_version, "client")? {
            Some(versions) => builder.with_protocol_versions(&versions),
            None => builder.with_safe_default_protocol_versions(),
        }
        .map_err(|e| TlsError::Other(format!("rustls protocol versions: {e}")))?,
    };
    let roots = builder.with_root_certificates(Arc::clone(&built.roots));
    let mut config = match &cfg.client_cert {
        Some(entry) => {
            let chain = entry
                .cert_chain
                .iter()
                .map(|der| rustls::pki_types::CertificateDer::from(der.clone()))
                .collect();
            roots
                .with_client_auth_cert(chain, key_of(entry))
                .map_err(|e| TlsError::BadCertificate(format!("client certificate: {e}")))?
        }
        None => roots.with_no_client_auth(),
    };
    config.alpn_protocols.clear();
    config.alpn_protocols.extend(cfg.alpn.iter().cloned());
    // xray hands Go an empty session cache unless the config names one, so a stock dial keeps no ticket by default.
    config.resumption = if cfg.resumption {
        rustls::client::Resumption::in_memory_sessions(256)
    } else {
        rustls::client::Resumption::disabled()
    };
    if let Some(verifier) = &built.verifier {
        config
            .dangerous()
            .set_certificate_verifier(Arc::clone(verifier));
    } else if cfg.insecure {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(Unverified));
    }
    if let Some(log) = &cfg.master_key_log {
        let log: Arc<dyn rustls::KeyLog> = log.clone();
        config.key_log = log;
    }
    Ok(config)
}

/// The parts a client config is built from, memoised per the anchors, pins and suite order a config names: the same three inputs get one build, whatever host or ALPN dials next. A pin-based verifier must keep its pointer across dials for rustls to resume, so a hit moves its entry to the back and the cap drops only the least-recently-used.
fn material(cfg: &TlsConfig) -> Result<Arc<Material>, TlsError> {
    let key = MaterialKey::of(cfg);
    let all = MATERIALS.get_or_init(Default::default);
    let mut kept = all.lock().expect("one build at a time");
    let at = kept.iter().position(|(k, _)| *k == key);
    if let Some(at) = at {
        let entry = kept.remove(at);
        let hit = Arc::clone(&entry.1);
        kept.push(entry);
        return Ok(hit);
    }
    drop(kept);
    let built = Arc::new(build_material(cfg)?);
    let mut kept = all.lock().expect("one build at a time");
    // A dial that raced this build may have stored the same key first, and one key keeps one entry.
    if let Some(at) = kept.iter().position(|(k, _)| *k == key) {
        let entry = kept.remove(at);
        let hit = Arc::clone(&entry.1);
        kept.push(entry);
        return Ok(hit);
    }
    if kept.len() == MATERIALS_MAX {
        kept.remove(0);
    }
    kept.push((key, Arc::clone(&built)));
    Ok(built)
}

/// The verifier a shaped session checks a server against: the same `Unverified`, pinned or chain choice a stock config makes, without a `ClientConfig` around it.
pub(crate) fn verifier(
    cfg: &TlsConfig,
) -> Result<Arc<dyn rustls::client::danger::ServerCertVerifier>, TlsError> {
    // A certificate pin is the whole contract, so it outranks `allowInsecure`: the pin check runs and the skip is only what remains of it.
    let built = material(cfg)?;
    if let Some(verifier) = &built.verifier {
        return Ok(Arc::clone(verifier));
    }
    if cfg.insecure {
        return Ok(Arc::new(Unverified));
    }
    let chain = built.chain.get_or_init(|| {
        build_chain(&built.roots, &built.provider).map_err(|error| error.to_string())
    });
    match chain {
        Ok(chain) => Ok(Arc::clone(chain) as Arc<dyn rustls::client::danger::ServerCertVerifier>),
        Err(why) => Err(TlsError::BadCertificate(why.clone())),
    }
}

fn build_chain(
    roots: &Arc<RootStore>,
    provider: &Arc<rustls::crypto::CryptoProvider>,
) -> Result<Arc<rustls::client::WebPkiServerVerifier>, TlsError> {
    rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::clone(roots),
        Arc::clone(provider),
    )
    .build()
    .map_err(|e| TlsError::BadCertificate(format!("chain: {e}")))
}

/// One build per (material, alpn, `insecure`), kept for the life of the process: rustls resumes only under a pointer-equal certificate verifier, so a config rebuilt for each dial discards the ticket the last dial stored, and every flow after the first pays for a full handshake again. At the cap the least-recently-used entry goes, and a hit moves its entry to the back: clearing the whole cache would drop the stores holding every edge's ticket at once, which is the very loss this cache exists to prevent.
fn client_config(cfg: &TlsConfig) -> Result<Arc<rustls::ClientConfig>, TlsError> {
    let key = ConfigKey {
        material: MaterialKey::of(cfg),
        alpn: std::sync::Arc::clone(&cfg.alpn),
        insecure: cfg.insecure,
        resumption: cfg.resumption,
        ech: cfg.ech_config_list.clone(),
        min_version: cfg.min_version,
        max_version: cfg.max_version,
        master_key_log: cfg.master_key_log.clone(),
        client_cert: cfg.client_cert.clone(),
    };
    let all = CONFIGS.get_or_init(Default::default);
    let mut kept = all.lock().expect("one build at a time");
    let at = kept.iter().position(|(k, _)| *k == key);
    if let Some(at) = at {
        let entry = kept.remove(at);
        let hit = Arc::clone(&entry.1);
        kept.push(entry);
        return Ok(hit);
    }
    drop(kept);
    let material = material(cfg)?;
    let built = Arc::new(build_config(cfg, &material)?);
    let mut kept = all.lock().expect("one build at a time");
    if let Some(at) = kept.iter().position(|(k, _)| *k == key) {
        let entry = kept.remove(at);
        let hit = Arc::clone(&entry.1);
        kept.push(entry);
        return Ok(hit);
    }
    if kept.len() == MATERIALS_MAX {
        kept.remove(0);
    }
    kept.push((key, Arc::clone(&built)));
    Ok(built)
}

/// The TLS 1.3 traffic secrets a kTLS install needs, captured from rustls's key log.
#[derive(Default)]
struct Captured {
    client: Option<Vec<u8>>,
    server: Option<Vec<u8>>,
}

/// Forwards to the configured key log and keeps the two traffic secrets; a buffered connection
/// exposes only key and IV, and a `KeyUpdate` needs the secret the next generation expands from.
struct CaptureKeyLog {
    inner: Arc<dyn rustls::KeyLog>,
    captured: Arc<Mutex<Captured>>,
}

impl std::fmt::Debug for CaptureKeyLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptureKeyLog").finish_non_exhaustive()
    }
}

impl rustls::KeyLog for CaptureKeyLog {
    fn will_log(&self, label: &str) -> bool {
        matches!(label, "CLIENT_TRAFFIC_SECRET_0" | "SERVER_TRAFFIC_SECRET_0")
            || self.inner.will_log(label)
    }

    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        if let Ok(mut captured) = self.captured.lock() {
            match label {
                "CLIENT_TRAFFIC_SECRET_0" => captured.client = Some(secret.to_vec()),
                "SERVER_TRAFFIC_SECRET_0" => captured.server = Some(secret.to_vec()),
                _ => {}
            }
        }
        if self.inner.will_log(label) {
            self.inner.log(label, client_random, secret);
        }
    }
}

fn captured_client_config(
    cfg: &TlsConfig,
) -> Result<(Arc<rustls::ClientConfig>, Arc<Mutex<Captured>>), TlsError> {
    let base = client_config(cfg)?;
    let captured = Arc::new(Mutex::new(Captured::default()));
    let mut config = (*base).clone();
    config.key_log = Arc::new(CaptureKeyLog {
        inner: config.key_log.clone(),
        captured: Arc::clone(&captured),
    });
    Ok((Arc::new(config), captured))
}

fn captured_server_config(
    cfg: &super::TlsServerConfig,
) -> Result<(Arc<rustls::ServerConfig>, Arc<Mutex<Captured>>), TlsError> {
    let base = cfg.server_config()?;
    let captured = Arc::new(Mutex::new(Captured::default()));
    let mut config = (*base).clone();
    config.key_log = Arc::new(CaptureKeyLog {
        inner: config.key_log.clone(),
        captured: Arc::clone(&captured),
    });
    Ok((Arc::new(config), captured))
}

fn ktls_material(
    suite: rustls::CipherSuite,
    secret: Vec<u8>,
) -> std::io::Result<crate::tls::ktls::Material> {
    use crate::tls::ktls::{Cipher, Material};
    use crate::tls::shaped::kdf::Hash;
    let (cipher, hash) = match suite {
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256 => (Cipher::Aes128Gcm, Hash::Sha256),
        rustls::CipherSuite::TLS13_AES_256_GCM_SHA384 => (Cipher::Aes256Gcm, Hash::Sha384),
        rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => {
            (Cipher::ChaCha20Poly1305, Hash::Sha256)
        }
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("ktls: suite {other:?} is not TLS 1.3"),
            ))
        }
    };
    Ok(Material {
        cipher,
        hash,
        secret,
        seq: 0,
    })
}

/// The subset of a rustls connection a handshake driver needs.
trait RecordDriver {
    fn is_handshaking(&self) -> bool;
    fn wants_write(&self) -> bool;
    fn write_tls(&mut self, wr: &mut dyn Write) -> std::io::Result<usize>;
    fn read_tls(&mut self, rd: &mut dyn Read) -> std::io::Result<usize>;
    fn process_new_packets(&mut self) -> Result<rustls::IoState, rustls::Error>;
}

impl RecordDriver for rustls::ClientConnection {
    fn is_handshaking(&self) -> bool {
        rustls::CommonState::is_handshaking(self)
    }
    fn wants_write(&self) -> bool {
        rustls::CommonState::wants_write(self)
    }
    fn write_tls(&mut self, wr: &mut dyn Write) -> std::io::Result<usize> {
        rustls::ConnectionCommon::write_tls(self, wr)
    }
    fn read_tls(&mut self, rd: &mut dyn Read) -> std::io::Result<usize> {
        rustls::ConnectionCommon::read_tls(self, rd)
    }
    fn process_new_packets(&mut self) -> Result<rustls::IoState, rustls::Error> {
        rustls::ConnectionCommon::process_new_packets(self)
    }
}

impl RecordDriver for rustls::ServerConnection {
    fn is_handshaking(&self) -> bool {
        rustls::CommonState::is_handshaking(self)
    }
    fn wants_write(&self) -> bool {
        rustls::CommonState::wants_write(self)
    }
    fn write_tls(&mut self, wr: &mut dyn Write) -> std::io::Result<usize> {
        rustls::ConnectionCommon::write_tls(self, wr)
    }
    fn read_tls(&mut self, rd: &mut dyn Read) -> std::io::Result<usize> {
        rustls::ConnectionCommon::read_tls(self, rd)
    }
    fn process_new_packets(&mut self) -> Result<rustls::IoState, rustls::Error> {
        rustls::ConnectionCommon::process_new_packets(self)
    }
}

/// Reads one whole TLS record into `buf`, keeping a partial record across a timeout.
fn read_record<R: Read + ?Sized>(io: &mut R, buf: &mut Vec<u8>) -> Result<(), TlsError> {
    let mut chunk = [0u8; 4096];
    while buf.len() < 5 {
        let want = 5 - buf.len();
        match io.read(&mut chunk[..want]) {
            Ok(0) => return Err(TlsError::Closed),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(error) => return Err(recover(error)),
        }
    }
    let len = usize::from(u16::from_be_bytes([buf[3], buf[4]]));
    let total = 5 + len;
    while buf.len() < total {
        let want = (total - buf.len()).min(chunk.len());
        match io.read(&mut chunk[..want]) {
            Ok(0) => return Err(TlsError::Closed),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(error) => return Err(recover(error)),
        }
    }
    Ok(())
}

/// Drives a handshake one TLS record at a time, so no post-handshake record is consumed from the
/// socket: the kernel must decrypt it after `setsockopt`.
fn drive_records<C: RecordDriver, S: Stream>(
    conn: &mut C,
    io: &mut S,
    buf: &mut Vec<u8>,
) -> Result<(), TlsError> {
    while conn.is_handshaking() {
        while conn.wants_write() {
            if conn.write_tls(io).map_err(recover)? == 0 {
                break;
            }
        }
        if !conn.is_handshaking() {
            break;
        }
        read_record(io, buf)?;
        let mut cursor = std::io::Cursor::new(&buf[..]);
        conn.read_tls(&mut cursor).map_err(recover)?;
        conn.process_new_packets()
            .map_err(|error| map_error(&error))?;
        buf.clear();
    }
    while conn.wants_write() {
        if conn.write_tls(io).map_err(recover)? == 0 {
            break;
        }
    }
    Ok(())
}

impl<S: Stream> RustlsProvider<S> {
    pub fn connect(cfg: &TlsConfig, io: S) -> Result<Self, TlsError> {
        let name = rustls::pki_types::ServerName::try_from(cfg.server_name.clone())
            .map_err(|e| TlsError::Other(format!("rustls server name: {e}")))?;
        let (config, captured) = if cfg.kernel_tx || cfg.kernel_rx {
            let (config, captured) = captured_client_config(cfg)?;
            (config, Some(captured))
        } else {
            (client_config(cfg)?, None)
        };
        let conn = rustls::ClientConnection::new(config, name).map_err(|e| map_error(&e))?;
        Ok(Self {
            conn,
            io,
            eof: false,
            ktls_tx: cfg.kernel_tx,
            ktls_rx: cfg.kernel_rx,
            captured,
            ktls: None,
            hsbuf: Vec::new(),
        })
    }

    /// A connection whose hello was fixed before the handshake: REALITY seals
    /// its tag into the session id, so the stock random hello cannot go out.
    pub fn from_connection(conn: rustls::ClientConnection, io: S) -> Self {
        Self {
            conn,
            io,
            eof: false,
            ktls_tx: false,
            ktls_rx: false,
            captured: None,
            ktls: None,
            hsbuf: Vec::new(),
        }
    }

    #[cfg(test)]
    fn tls13_tickets(&self) -> u32 {
        self.conn.tls13_tickets_received()
    }

    /// Whether this session did a full handshake or rode a ticket: the only public witness of resumption, because rustls hands a resumed session its cached chain.
    #[cfg(test)]
    fn handshake_kind(&self) -> Option<rustls::HandshakeKind> {
        self.conn.handshake_kind()
    }

    fn drive(&mut self) -> Result<(), TlsError> {
        if self.ktls.is_some() {
            return Ok(());
        }
        if self.ktls_tx || self.ktls_rx {
            return drive_records(&mut self.conn, &mut self.io, &mut self.hsbuf);
        }
        while self.conn.is_handshaking() {
            if let Err(e) = self.conn.complete_io(&mut self.io) {
                return Err(recover(e));
            }
        }
        Ok(())
    }

    pub fn get_ref(&self) -> &S {
        &self.io
    }

    /// Whether this session's only way to make progress is a socket read: `false` while a record's
    /// plaintext still sits in the layer, which a read takes without touching the socket.
    pub fn wants_read(&self) -> bool {
        self.conn.wants_read()
    }

    /// Whether the peer's close has already been read.
    pub fn closed(&self) -> bool {
        self.eof || self.ktls.as_ref().is_some_and(crate::tls::ktls::Layer::eof)
    }

    fn install_ktls(&mut self, fd: RawFd) -> std::io::Result<()> {
        if self.ktls.is_some() || (!self.ktls_tx && !self.ktls_rx) {
            return Ok(());
        }
        if self.conn.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "ktls: the handshake did not settle on TLS 1.3",
            ));
        }
        let suite = self
            .conn
            .negotiated_cipher_suite()
            .ok_or_else(|| std::io::Error::other("ktls: no negotiated suite"))?
            .suite();
        let captured = self
            .captured
            .as_ref()
            .ok_or_else(|| std::io::Error::other("ktls: no captured traffic secrets"))?;
        let (client, server) = {
            let captured = captured
                .lock()
                .map_err(|_| std::io::Error::other("ktls: captured secrets were poisoned"))?;
            (captured.client.clone(), captured.server.clone())
        };
        let tx = ktls_material(
            suite,
            client.ok_or_else(|| std::io::Error::other("ktls: no client traffic secret"))?,
        )?;
        let rx = ktls_material(
            suite,
            server.ok_or_else(|| std::io::Error::other("ktls: no server traffic secret"))?,
        )?;
        self.ktls = Some(crate::tls::ktls::Layer::new(
            fd,
            self.ktls_tx,
            self.ktls_rx,
            tx,
            rx,
        )?);
        Ok(())
    }

    /// Writes two slices as one TLS record: the fragmenter sees `head` and `tail`
    /// in that order in one call, which is the record a concatenated write would
    /// have produced, so the payload's staging copy is spent rather than the
    /// record being split in two.
    pub fn write_parts(&mut self, head: &[u8], mut tail: &[u8]) -> std::io::Result<()> {
        self.drive()?;
        if let Some(layer) = &mut self.ktls {
            return layer.write_all(&mut self.io, &[head, tail]);
        }
        let mut head = head;
        let want = head.len() + tail.len();
        let mut written = 0usize;
        while written < want {
            let slices = [std::io::IoSlice::new(head), std::io::IoSlice::new(tail)];
            let wrote = std::io::Write::write_vectored(&mut self.conn.writer(), &slices)?;
            if wrote == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
            }
            written += wrote;
            let spent = wrote.min(head.len());
            head = &head[spent..];
            tail = &tail[wrote - spent..];
        }
        // The record goes out here, and nothing is waited for: `send_pending` owns the idle answer.
        self.send_pending()?;
        Ok(())
    }
}

impl<S: Stream + super::RecordAlignment> super::RecordAlignment for RustlsProvider<S> {
    fn engage_record_alignment(&mut self) {
        self.io.engage_record_alignment();
    }

    fn disarm_record_alignment(&mut self) {
        self.io.disarm_record_alignment();
    }

    fn write_all_slices(&mut self, parts: &[&[u8]]) -> std::io::Result<()> {
        const CHUNK: usize = 32 * 1024;
        self.drive()?;
        if let Some(layer) = &mut self.ktls {
            return layer.write_all(&mut self.io, parts);
        }
        if parts.iter().map(|part| part.len()).sum::<usize>() <= CHUNK {
            coalesce(&mut self.conn.writer(), parts)?;
            return self.send_pending();
        }
        let mut batch: Vec<&[u8]> = Vec::with_capacity(parts.len() + 1);
        let mut room = CHUNK;
        for part in parts {
            let mut rest = *part;
            while !rest.is_empty() {
                let take = rest.len().min(room);
                batch.push(&rest[..take]);
                rest = &rest[take..];
                room -= take;
                if room == 0 {
                    coalesce(&mut self.conn.writer(), &batch)?;
                    self.send_pending()?;
                    batch.clear();
                    room = CHUNK;
                }
            }
        }
        if !batch.is_empty() {
            coalesce(&mut self.conn.writer(), &batch)?;
        }
        self.send_pending()
    }
}

impl<S: Stream> TlsProvider for RustlsProvider<S> {
    fn name() -> &'static str {
        "rustls"
    }

    fn suites(&self) -> Vec<String> {
        rustls::crypto::ring::ALL_CIPHER_SUITES
            .iter()
            .map(|cs| format!("{:?}", cs.suite()))
            .collect()
    }

    fn handshake(&mut self) -> Result<(), TlsError> {
        self.drive()
    }

    fn alpn(&self) -> Option<&[u8]> {
        self.conn.alpn_protocol()
    }

    fn peer_leaf(&self) -> Option<&[u8]> {
        self.conn
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(rustls::pki_types::CertificateDer::as_ref)
    }

    fn seal_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> std::io::Result<usize> {
        self.drive()?;
        if let Some(layer) = &mut self.ktls {
            return layer.seal_into(&[plaintext], out);
        }
        let len = self.conn.writer().write(plaintext)?;
        self.drain_into(out)?;
        Ok(len)
    }

    fn seal_slices_into(&mut self, parts: &[&[u8]], out: &mut Vec<u8>) -> std::io::Result<()> {
        self.drive()?;
        if let Some(layer) = &mut self.ktls {
            layer.seal_into(parts, out)?;
            return Ok(());
        }
        coalesce(&mut self.conn.writer(), parts)?;
        self.drain_into(out)
    }

    fn open(&mut self, ciphertext: &[u8], buf: &mut [u8]) -> std::io::Result<(usize, usize)> {
        if let Some(layer) = &mut self.ktls {
            return layer.open(ciphertext, buf);
        }
        // The plaintext the layer holds comes out first: its room is finite, and the ciphertext that follows waits for it.
        let plain = match self.conn.reader().read(buf) {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => 0,
            Ok(0) => {
                if !buf.is_empty() {
                    self.eof = true;
                }
                0
            }
            outcome => outcome?,
        };
        if plain > 0 {
            return Ok((plain, 0));
        }
        // A handshake may leave ciphertext in the layer with no new input, so the empty slice still processes it.
        let taken = if ciphertext.is_empty() {
            0
        } else {
            let mut cursor = std::io::Cursor::new(ciphertext);
            self.conn.read_tls(&mut cursor).map_err(recover)?
        };
        self.conn
            .process_new_packets()
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        // A peer's key update is answered into the queue here and leaves with the next seal: a read never writes the transport.
        let plain = match self.conn.reader().read(buf) {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => 0,
            Ok(0) => {
                if !buf.is_empty() {
                    self.eof = true;
                }
                0
            }
            outcome => outcome?,
        };
        Ok((plain, taken))
    }

    fn wants_ktls(&self) -> bool {
        self.ktls_tx || self.ktls_rx
    }

    fn kernel_rx(&self) -> bool {
        self.ktls
            .as_ref()
            .is_some_and(crate::tls::ktls::Layer::rx_offloaded)
    }

    fn enable_ktls(&mut self, fd: RawFd) -> std::io::Result<()> {
        self.install_ktls(fd)
    }

    fn closed(&self) -> bool {
        self.eof || self.ktls.as_ref().is_some_and(crate::tls::ktls::Layer::eof)
    }
}

impl<S: Stream> Read for RustlsProvider<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(layer) = &mut self.ktls {
            return layer.read(&mut self.io, buf);
        }
        loop {
            self.drive()?;
            match self.conn.reader().read(buf) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if let Err(io_error) = self.conn.complete_io(&mut self.io) {
                        if matches!(
                            io_error.kind(),
                            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                        ) {
                            return Err(io_error);
                        }
                        return Err(recover(io_error).into());
                    }
                }
                Ok(0) => {
                    if !buf.is_empty() {
                        self.eof = true;
                    }
                    return Ok(0);
                }
                outcome => return outcome,
            }
        }
    }
}

impl<S: Stream> RustlsProvider<S> {
    /// Every record this session has queued goes into the caller's buffer, in wire order, so the
    /// caller sends them after the session's lock drops.
    fn drain_into(&mut self, out: &mut Vec<u8>) -> std::io::Result<()> {
        while self.conn.wants_write() {
            let wrote = self.conn.write_tls(out)?;
            if wrote == 0 {
                break;
            }
        }
        Ok(())
    }

    /// The ciphertext this session has queued goes out, and nothing comes in: `complete_io` reads as well as it writes, so a write that used it waited for a record the peer had not sent — a socket read per frame, up to the read quantum, under the relay's lock.
    fn flush_pending(&mut self) -> std::io::Result<()> {
        while self.conn.wants_write() {
            let wrote = self.conn.write_tls(&mut self.io)?;
            if wrote == 0 {
                break;
            }
        }
        self.io.flush()
    }

    /// A write's own ciphertext out, with the idle answer a peer that sent nothing is: the call is the write's, so a socket that answered EAGAIN is not its failure.
    fn send_pending(&mut self) -> std::io::Result<()> {
        match self.flush_pending() {
            Err(error) if !idle(&error) => Err(recover(error).into()),
            _ => Ok(()),
        }
    }
}

impl<S: Stream> Write for RustlsProvider<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.drive()?;
        if let Some(layer) = &mut self.ktls {
            return layer.write(&mut self.io, buf);
        }
        let len = self.conn.writer().write(buf)?;
        self.send_pending()?;
        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.drive()?;
        if let Some(layer) = &mut self.ktls {
            return layer.flush(&mut self.io);
        }
        self.conn.writer().flush()?;
        self.send_pending()?;
        Ok(())
    }
}

enum ServerInner<S: Stream> {
    Rustls {
        conn: Box<rustls::ServerConnection>,
        io: S,
    },
    Boring {
        handshake: Option<boring::ssl::MidHandshakeSslStream<S>>,
        stream: Option<boring::ssl::SslStream<S>>,
        failure: Option<String>,
        ech: bool,
    },
    Shaped(Box<crate::tls::shaped::server::Server<S>>),
}

pub struct RustlsServerProvider<S: Stream> {
    inner: ServerInner<S>,
    eof: bool,
    ktls_tx: bool,
    ktls_rx: bool,
    captured: Option<Arc<Mutex<Captured>>>,
    ktls: Option<crate::tls::ktls::Layer>,
    hsbuf: Vec<u8>,
}

impl<S: Stream> std::fmt::Debug for RustlsServerProvider<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.inner {
            ServerInner::Rustls { conn, .. } => f
                .debug_struct("RustlsServerProvider")
                .field("alpn", &conn.alpn_protocol())
                .field("is_handshaking", &conn.is_handshaking())
                .finish_non_exhaustive(),
            ServerInner::Boring {
                stream, failure, ..
            } => {
                let alpn = stream
                    .as_ref()
                    .and_then(|stream| stream.ssl().selected_alpn_protocol());
                f.debug_struct("RustlsServerProvider")
                    .field("alpn", &alpn)
                    .field("is_handshaking", &stream.is_none())
                    .field("failure", failure)
                    .finish_non_exhaustive()
            }
            ServerInner::Shaped(server) => f
                .debug_struct("RustlsServerProvider")
                .field("alpn", &server.alpn())
                .field("suite", &server.suite())
                .finish_non_exhaustive(),
        }
    }
}

impl<S: Stream> RustlsServerProvider<S> {
    #[allow(clippy::needless_pass_by_value)]
    pub fn accept(cfg: super::TlsServerConfig, io: S) -> Result<Self, TlsError> {
        let shaped = crate::tls::cipher_suites::shaped_server(
            &cfg.cipher_suites,
            cfg.min_version,
            cfg.max_version,
        );
        Self::accept_decided(cfg, io, shaped)
    }

    /// `shaped` is the caller's verdict, because a `ClientHello` peek is what tells a TLS 1.2 client
    /// from one that offers TLS 1.3 on a listener that also offers TLS 1.3.
    pub(crate) fn accept_decided(
        cfg: super::TlsServerConfig,
        io: S,
        shaped: bool,
    ) -> Result<Self, TlsError> {
        let (ktls_tx, ktls_rx) = (cfg.kernel_tx, cfg.kernel_rx);
        if cfg.ech_server_keys.is_some() {
            let ctx = cached_ech_server_context(&cfg)?;
            let mut ssl = boring::ssl::Ssl::new(&ctx).map_err(|error| boring_error(&error))?;
            if let Some(response) = cfg
                .served_entries()
                .first()
                .and_then(|entry| entry.ocsp.as_ref())
                .and_then(|ocsp| ocsp.response.as_ref())
                .cloned()
            {
                ssl.set_ocsp_status(&response).ok();
            }
            return Ok(Self::plain(ServerInner::Boring {
                handshake: Some(ssl.setup_accept(io)),
                stream: None,
                failure: None,
                ech: true,
            }));
        }
        if shaped {
            return Ok(Self::plain(ServerInner::Shaped(Box::new(
                crate::tls::shaped::server::Server::new(cfg, io),
            ))));
        }
        if crate::tls::legacy::needed(&cfg.cipher_suites) {
            let ctx = crate::tls::legacy::server_context(&cfg)?;
            let mut ssl = boring::ssl::Ssl::new(&ctx).map_err(|error| boring_error(&error))?;
            if let Some(response) = cfg
                .served_entries()
                .first()
                .and_then(|entry| entry.ocsp.as_ref())
                .and_then(|ocsp| ocsp.response.as_ref())
                .cloned()
            {
                ssl.set_ocsp_status(&response).ok();
            }
            return Ok(Self::plain(ServerInner::Boring {
                handshake: Some(ssl.setup_accept(io)),
                stream: None,
                failure: None,
                ech: false,
            }));
        }
        let (config, captured) = if ktls_tx || ktls_rx {
            let (config, captured) = captured_server_config(&cfg)?;
            (config, Some(captured))
        } else {
            (cfg.server_config()?, None)
        };
        let conn = Box::new(rustls::ServerConnection::new(config).map_err(|e| map_error(&e))?);
        Ok(Self {
            inner: ServerInner::Rustls { conn, io },
            eof: false,
            ktls_tx,
            ktls_rx,
            captured,
            ktls: None,
            hsbuf: Vec::new(),
        })
    }

    fn plain(inner: ServerInner<S>) -> Self {
        Self {
            inner,
            eof: false,
            ktls_tx: false,
            ktls_rx: false,
            captured: None,
            ktls: None,
            hsbuf: Vec::new(),
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn accept_reality(cfg: super::TlsServerConfig, io: S) -> Result<Self, TlsError> {
        let conn = Box::new(
            rustls::ServerConnection::new(cfg.reality_server_config()?)
                .map_err(|e| map_error(&e))?,
        );
        Ok(Self::plain(ServerInner::Rustls { conn, io }))
    }

    fn handshake(&mut self) -> Result<(), TlsError> {
        if self.ktls.is_some() {
            return Ok(());
        }
        let Self {
            inner,
            ktls_tx,
            ktls_rx,
            hsbuf,
            ..
        } = self;
        if *ktls_tx || *ktls_rx {
            if let ServerInner::Rustls { conn, io } = inner {
                return drive_records(&mut **conn, io, hsbuf);
            }
        }
        match inner {
            ServerInner::Rustls { conn, io } => {
                while conn.is_handshaking() {
                    if let Err(e) = conn.complete_io(io) {
                        return Err(recover(e));
                    }
                }
                Ok(())
            }
            ServerInner::Boring {
                handshake,
                stream,
                failure,
                ..
            } => {
                if let Some(why) = failure {
                    return Err(TlsError::Other(why.clone()));
                }
                if stream.is_some() {
                    return Ok(());
                }
                let Some(mid) = handshake.take() else {
                    return Ok(());
                };
                match mid.handshake() {
                    Ok(done) => {
                        *stream = Some(done);
                        Ok(())
                    }
                    Err(boring::ssl::HandshakeError::WouldBlock(mid)) => {
                        *handshake = Some(mid);
                        Err(TlsError::Timeout)
                    }
                    Err(boring::ssl::HandshakeError::Failure(mid)) => {
                        let why = format!("boring tls handshake: {}", mid.error());
                        *handshake = Some(mid);
                        *failure = Some(why.clone());
                        Err(TlsError::Other(why))
                    }
                    Err(boring::ssl::HandshakeError::SetupFailure(error)) => {
                        let why = format!("boring tls setup: {error}");
                        *failure = Some(why.clone());
                        Err(TlsError::Other(why))
                    }
                }
            }
            ServerInner::Shaped(server) => server.handshake(),
        }
    }

    /// Whether this session owns its transport rather than handing the caller its ciphertext.
    pub fn owns_transport(&self) -> bool {
        matches!(
            self.inner,
            ServerInner::Boring { .. } | ServerInner::Shaped(_)
        )
    }

    fn install_ktls(&mut self, fd: RawFd) -> std::io::Result<()> {
        if self.ktls.is_some() || (!self.ktls_tx && !self.ktls_rx) {
            return Ok(());
        }
        let ServerInner::Rustls { conn, .. } = &self.inner else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "ktls: this listener's backend cannot hand its records to the kernel",
            ));
        };
        if conn.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "ktls: the handshake did not settle on TLS 1.3",
            ));
        }
        let suite = conn
            .negotiated_cipher_suite()
            .ok_or_else(|| std::io::Error::other("ktls: no negotiated suite"))?
            .suite();
        let captured = self
            .captured
            .as_ref()
            .ok_or_else(|| std::io::Error::other("ktls: no captured traffic secrets"))?;
        let (client, server) = {
            let captured = captured
                .lock()
                .map_err(|_| std::io::Error::other("ktls: captured secrets were poisoned"))?;
            (captured.client.clone(), captured.server.clone())
        };
        let tx = ktls_material(
            suite,
            server.ok_or_else(|| std::io::Error::other("ktls: no server traffic secret"))?,
        )?;
        let rx = ktls_material(
            suite,
            client.ok_or_else(|| std::io::Error::other("ktls: no client traffic secret"))?,
        )?;
        self.ktls = Some(crate::tls::ktls::Layer::new(
            fd,
            self.ktls_tx,
            self.ktls_rx,
            tx,
            rx,
        )?);
        Ok(())
    }

    /// The suite the shaped listener negotiated, for a test that pins the reference's pick.
    #[cfg(test)]
    pub(crate) fn suite(&self) -> Option<u16> {
        match &self.inner {
            ServerInner::Shaped(server) => server.suite(),
            _ => None,
        }
    }

    /// Whether this session is the ECH path.
    pub fn is_ech(&self) -> bool {
        matches!(self.inner, ServerInner::Boring { ech: true, .. })
    }

    /// Whether the client offered ECH and the server accepted it.
    pub fn ech_accepted(&self) -> bool {
        match &self.inner {
            ServerInner::Boring {
                stream: Some(stream),
                ech: true,
                ..
            } => stream.ssl().ech_accepted(),
            _ => false,
        }
    }
}

impl<S: Stream + super::RecordAlignment> super::RecordAlignment for RustlsServerProvider<S> {
    fn engage_record_alignment(&mut self) {
        match &mut self.inner {
            ServerInner::Rustls { io, .. } => io.engage_record_alignment(),
            ServerInner::Boring {
                stream: Some(stream),
                ..
            } => stream.get_mut().engage_record_alignment(),
            ServerInner::Boring {
                handshake: Some(handshake),
                ..
            } => handshake.get_mut().engage_record_alignment(),
            ServerInner::Boring { .. } => {}
            ServerInner::Shaped(server) => server.engage_record_alignment(),
        }
    }

    fn disarm_record_alignment(&mut self) {
        match &mut self.inner {
            ServerInner::Rustls { io, .. } => io.disarm_record_alignment(),
            ServerInner::Boring {
                stream: Some(stream),
                ..
            } => stream.get_mut().disarm_record_alignment(),
            ServerInner::Boring {
                handshake: Some(handshake),
                ..
            } => handshake.get_mut().disarm_record_alignment(),
            ServerInner::Boring { .. } => {}
            ServerInner::Shaped(server) => server.disarm_record_alignment(),
        }
    }

    fn write_all_slices(&mut self, parts: &[&[u8]]) -> std::io::Result<()> {
        self.handshake()?;
        if let Some(layer) = &mut self.ktls {
            if let ServerInner::Rustls { io, .. } = &mut self.inner {
                return layer.write_all(io, parts);
            }
        }
        match &mut self.inner {
            ServerInner::Rustls { conn, io } => {
                coalesce(&mut conn.writer(), parts)?;
                while conn.wants_write() {
                    let wrote = conn.write_tls(&mut *io)?;
                    if wrote == 0 {
                        break;
                    }
                }
                match io.flush() {
                    Err(error) if !idle(&error) => Err(recover(error).into()),
                    _ => Ok(()),
                }
            }
            ServerInner::Boring {
                stream: Some(stream),
                ..
            } => {
                for part in parts {
                    stream.write_all(part)?;
                }
                stream.flush()
            }
            ServerInner::Boring { .. } => {
                Err(std::io::Error::other("tls handshake is not complete"))
            }
            ServerInner::Shaped(server) => server.write_all_slices(parts),
        }
    }
}

/// Hand `parts` to a rustls writer in one `write_vectored` so the fragmenter sees one payload and emits one record; iterating `write_all` per part would emit one record per part.
///
/// The framer hands at most `uuid | head | payload | padding` — four segments — the
/// camouflage head gather hands five, and a CONNECT request is seven runs of literal and
/// caller text, so they are laid out on the stack like [`RustlsProvider::write_parts`] does
/// its two, rather than spending one heap `Vec<IoSlice>` on every framed write.
fn coalesce<W: Write + ?Sized>(writer: &mut W, parts: &[&[u8]]) -> std::io::Result<()> {
    let mut stack = [
        std::io::IoSlice::new(&[]),
        std::io::IoSlice::new(&[]),
        std::io::IoSlice::new(&[]),
        std::io::IoSlice::new(&[]),
        std::io::IoSlice::new(&[]),
        std::io::IoSlice::new(&[]),
        std::io::IoSlice::new(&[]),
    ];
    if parts.len() <= stack.len() {
        let mut kept = 0;
        for part in parts.iter().copied().filter(|part| !part.is_empty()) {
            stack[kept] = std::io::IoSlice::new(part);
            kept += 1;
        }
        return write_segments(writer, &mut stack[..kept]);
    }
    // A provider handed more segments than the framer produces still goes out in one call.
    let mut heap: Vec<std::io::IoSlice<'_>> = parts
        .iter()
        .copied()
        .filter(|part| !part.is_empty())
        .map(std::io::IoSlice::new)
        .collect();
    write_segments(writer, heap.as_mut_slice())
}

/// Push the segments out in as few `write_vectored` calls as the writer will take,
/// advancing past each one the writer consumes whole.
fn write_segments<W: Write + ?Sized>(
    writer: &mut W,
    mut rest: &mut [std::io::IoSlice<'_>],
) -> std::io::Result<()> {
    while !rest.is_empty() {
        let wrote = writer.write_vectored(rest)?;
        if wrote == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
        }
        std::io::IoSlice::advance_slices(&mut rest, wrote);
    }
    Ok(())
}

/// The rustls config an identity produces, so tests pin wire behavior here.
#[derive(Default)]
pub struct ServerConfigCacheInner {
    pub plain: Option<std::sync::Arc<rustls::ServerConfig>>,
    pub reality: Option<std::sync::Arc<rustls::ServerConfig>>,
    /// The ECH listener context, with the identities it was built for.
    pub ech: Option<(
        Vec<super::CertEntry>,
        std::sync::Arc<boring::ssl::SslContext>,
    )>,
    /// The legacy listener context, with the identities it was built for.
    pub legacy: Option<(
        Vec<super::CertEntry>,
        std::sync::Arc<boring::ssl::SslContext>,
    )>,
    /// The identities the listener currently serves, so a re-read compares against them.
    pub served: Option<Vec<super::CertEntry>>,
}

impl std::fmt::Debug for ServerConfigCacheInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfigCacheInner")
            .finish_non_exhaustive()
    }
}

pub type ServerConfigCache = std::sync::Arc<std::sync::Mutex<ServerConfigCacheInner>>;

/// The identities a listener serves, in block order: the first whose names match the SNI wins,
/// element 0 answers an empty or unmatched hello unless `reject` is set.
#[derive(Debug)]
struct IdentityResolver {
    identities: Vec<(Arc<rustls::sign::CertifiedKey>, Vec<String>)>,
    reject: bool,
}

impl rustls::server::ResolvesServerCert for IdentityResolver {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let sni = hello.server_name().unwrap_or("");
        if !self.reject && (self.identities.len() == 1 || sni.is_empty()) {
            return self.identities.first().map(|(key, _)| Arc::clone(key));
        }
        if let Some((key, _)) = self
            .identities
            .iter()
            .find(|(_, names)| sni_matches(names, sni))
        {
            return Some(Arc::clone(key));
        }
        if self.reject {
            return None;
        }
        self.identities.first().map(|(key, _)| Arc::clone(key))
    }
}

/// xray matches the exact name or a certificate's `*.suffix`, which covers one label only.
pub(crate) fn sni_matches(names: &[String], sni: &str) -> bool {
    let wildcard = match sni.find('.') {
        Some(at) => format!("*{}", &sni[at..]),
        None => "*".to_owned(),
    };
    names
        .iter()
        .any(|name| name.eq_ignore_ascii_case(sni) || name.eq_ignore_ascii_case(&wildcard))
}

/// The names xray compares an SNI against: the leaf's DNS SANs and subject common name.
pub(crate) fn certificate_names(leaf: &[u8]) -> Vec<String> {
    let Ok(cert) = boring::x509::X509::from_der(leaf) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    if let Some(sans) = cert.subject_alt_names() {
        for san in sans {
            if let Some(name) = san.dnsname() {
                names.push(name.to_ascii_lowercase());
            }
        }
    }
    for entry in cert
        .subject_name()
        .entries_by_nid(boring::nid::Nid::COMMONNAME)
    {
        if let Ok(name) = entry.data().as_utf8() {
            names.push(name.to_string().to_ascii_lowercase());
        }
    }
    names
}

/// The chain a served identity presents, leaf first.
fn chain_of(chain: Vec<Vec<u8>>) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    chain
        .into_iter()
        .map(rustls::pki_types::CertificateDer::from)
        .collect()
}

/// The signing key a served identity holds, in the shape its DER names.
pub(crate) fn key_of(entry: &super::CertEntry) -> rustls::pki_types::PrivateKeyDer<'static> {
    use super::ServerKeyKind as Kind;
    match entry.key_kind {
        Kind::Pkcs8 => rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(entry.key_der.clone()),
        ),
        Kind::Sec1 => rustls::pki_types::PrivateKeyDer::Sec1(
            rustls::pki_types::PrivateSec1KeyDer::from(entry.key_der.clone()),
        ),
        Kind::Pkcs1 => rustls::pki_types::PrivateKeyDer::Pkcs1(
            rustls::pki_types::PrivatePkcs1KeyDer::from(entry.key_der.clone()),
        ),
    }
}

/// One ticket key per process, rotating on ring's six-hour schedule: a ticket carries its session sealed under this key, so a listener keeps no per-session state and a certificate reload does not strand the tickets it handed out before it.
fn ticket_key() -> Option<Arc<dyn rustls::server::ProducesTickets>> {
    static KEY: OnceLock<Option<Arc<dyn rustls::server::ProducesTickets>>> = OnceLock::new();
    KEY.get_or_init(|| rustls::crypto::ring::Ticketer::new().ok())
        .clone()
}

pub(crate) fn server_config(cfg: super::TlsServerConfig) -> Result<rustls::ServerConfig, TlsError> {
    let crypto_provider = provider();
    let mut ordered = (*crypto_provider).clone();
    if !cfg.cipher_suites.is_empty() {
        order_cipher_suites(&mut ordered, &cfg.cipher_suites);
    }
    if !cfg.curves.is_empty() {
        order_kx_groups(&mut ordered, &cfg.curves);
    }
    let versions = server_versions(cfg.min_version, cfg.max_version)?;
    let builder = rustls::ServerConfig::builder_with_provider(Arc::new(ordered));
    let builder = match versions.as_deref() {
        Some(versions) => builder.with_protocol_versions(versions),
        None => builder.with_safe_default_protocol_versions(),
    }
    .map_err(|e| TlsError::Other(format!("rustls protocol versions: {e}")))?;
    let mut config = if cfg.certs.len() == 1 && !cfg.reject_unknown_sni {
        let entry = cfg.certs.into_iter().next().expect("one identity");
        let key = key_of(&entry);
        match entry.ocsp.and_then(|ocsp| ocsp.response) {
            Some(response) => builder
                .with_no_client_auth()
                .with_single_cert_with_ocsp(chain_of(entry.cert_chain), key, response)
                .map_err(|e| TlsError::Other(format!("rustls server identity: {e}")))?,
            None => builder
                .with_no_client_auth()
                .with_single_cert(chain_of(entry.cert_chain), key)
                .map_err(|e| TlsError::Other(format!("rustls server identity: {e}")))?,
        }
    } else {
        let mut identities = Vec::with_capacity(cfg.certs.len());
        for entry in cfg.certs {
            let names = entry
                .cert_chain
                .first()
                .map(|leaf| certificate_names(leaf))
                .unwrap_or_default();
            let key = key_of(&entry);
            let mut key = rustls::sign::CertifiedKey::from_der(
                chain_of(entry.cert_chain),
                key,
                crypto_provider.as_ref(),
            )
            .map_err(|e| TlsError::Other(format!("rustls server identity: {e}")))?;
            key.ocsp = entry.ocsp.and_then(|ocsp| ocsp.response);
            identities.push((Arc::new(key), names));
        }
        builder
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(IdentityResolver {
                identities,
                reject: cfg.reject_unknown_sni,
            }))
    };
    config.alpn_protocols.clear();
    config.alpn_protocols.extend(cfg.alpn.iter().cloned());
    // rustls sends two tickets by default; REALITY arrivals carry none.
    config.send_tls13_tickets = if cfg.send_tickets { 2 } else { 0 };
    if cfg.send_tickets {
        if let Some(key) = ticket_key() {
            config.ticketer = key;
        }
    }
    if let Some(log) = &cfg.master_key_log {
        let log: Arc<dyn rustls::KeyLog> = log.clone();
        config.key_log = log;
    }
    Ok(config)
}

/// The protocol versions a session may negotiate: xray clamps Go's versions onto
/// what this backend carries, so a floor below 1.2 starts at 1.2 and a ceiling
/// above 1.3 stops at 1.3. No bounds keeps the backend's default pair.
fn protocol_versions(
    min: Option<u16>,
    max: Option<u16>,
    role: &str,
) -> Result<Option<Vec<&'static rustls::SupportedProtocolVersion>>, TlsError> {
    if min.is_none() && max.is_none() {
        return Ok(None);
    }
    let floor = min.unwrap_or(0x0303).max(0x0303);
    let ceiling = max.unwrap_or(0x0304).min(0x0304);
    if floor > ceiling {
        return Err(TlsError::Other(format!(
            "tls {role} version bounds name no supported protocol"
        )));
    }
    let mut versions = Vec::with_capacity(2);
    if floor == 0x0303 {
        versions.push(&rustls::version::TLS12);
    }
    if ceiling == 0x0304 {
        versions.push(&rustls::version::TLS13);
    }
    Ok(Some(versions))
}

fn server_versions(
    min: Option<u16>,
    max: Option<u16>,
) -> Result<Option<Vec<&'static rustls::SupportedProtocolVersion>>, TlsError> {
    protocol_versions(min, max, "server")
}

pub(crate) fn cached_server_config(
    cfg: &super::TlsServerConfig,
    reality: bool,
) -> Result<std::sync::Arc<rustls::ServerConfig>, TlsError> {
    let mut guard = cfg
        .server_config_cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let slot = if reality {
        &mut guard.reality
    } else {
        &mut guard.plain
    };
    if let Some(cached) = slot.as_ref() {
        return Ok(std::sync::Arc::clone(cached));
    }
    let built = std::sync::Arc::new(if reality {
        reality_server_config(cfg.clone())?
    } else {
        server_config(cfg.clone())?
    });
    *slot = Some(std::sync::Arc::clone(&built));
    if !reality {
        guard.served = Some(cfg.certs.clone());
    }
    Ok(built)
}

/// The signing key REALITY answers with: every reference forces `Ed25519` for
/// `CertificateVerify` without consulting the peer's offered schemes.
#[derive(Debug)]
pub(crate) struct RealitySigningKey {
    pub(crate) inner: Arc<dyn rustls::sign::SigningKey>,
}

impl rustls::sign::SigningKey for RealitySigningKey {
    fn choose_scheme(
        &self,
        _offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        self.inner
            .choose_scheme(&[rustls::SignatureScheme::ED25519])
    }

    fn public_key(&self) -> Option<rustls::pki_types::SubjectPublicKeyInfoDer<'_>> {
        self.inner.public_key()
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ED25519
    }
}

/// The rustls config a REALITY identity produces: the same chain, key, `ALPN`
/// and ticket count as `server_config`, except the key always answers `Ed25519`.
pub(crate) fn reality_server_config(
    cfg: super::TlsServerConfig,
) -> Result<rustls::ServerConfig, TlsError> {
    let entry = cfg
        .certs
        .into_iter()
        .next()
        .ok_or_else(|| TlsError::Other("server identity has no certificate".to_owned()))?;
    let key_der = key_of(&entry);
    let certs = chain_of(entry.cert_chain);
    let inner = provider()
        .key_provider
        .load_private_key(key_der)
        .map_err(|e| TlsError::Other(format!("rustls server identity: {e}")))?;
    let ocsp = entry.ocsp.as_ref().and_then(|ocsp| ocsp.response.clone());
    let mut key = rustls::sign::CertifiedKey::new(certs, Arc::new(RealitySigningKey { inner }));
    key.ocsp = ocsp;
    key.keys_match()
        .map_err(|e| TlsError::Other(format!("rustls server identity: {e}")))?;
    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError::Other(format!("rustls protocol versions: {e}")))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(key)));
    config.alpn_protocols.clear();
    config.alpn_protocols.extend(cfg.alpn.iter().cloned());
    // rustls sends two tickets by default; REALITY arrivals carry none.
    config.send_tls13_tickets = if cfg.send_tickets { 2 } else { 0 };
    if cfg.send_tickets {
        if let Some(key) = ticket_key() {
            config.ticketer = key;
        }
    }
    if let Some(log) = &cfg.master_key_log {
        let log: Arc<dyn rustls::KeyLog> = log.clone();
        config.key_log = log;
    }
    Ok(config)
}

impl<S: Stream> TlsProvider for RustlsServerProvider<S> {
    fn name() -> &'static str {
        "rustls"
    }

    fn suites(&self) -> Vec<String> {
        match &self.inner {
            ServerInner::Shaped(server) => server.suites(),
            _ => rustls::crypto::ring::ALL_CIPHER_SUITES
                .iter()
                .map(|cs| format!("{:?}", cs.suite()))
                .collect(),
        }
    }

    fn handshake(&mut self) -> Result<(), TlsError> {
        self.handshake()
    }

    fn alpn(&self) -> Option<&[u8]> {
        match &self.inner {
            ServerInner::Rustls { conn, .. } => conn.alpn_protocol(),
            ServerInner::Boring {
                stream: Some(stream),
                ..
            } => stream.ssl().selected_alpn_protocol(),
            ServerInner::Boring { .. } => None,
            ServerInner::Shaped(server) => server.alpn(),
        }
    }

    fn sni(&self) -> Option<&[u8]> {
        match &self.inner {
            ServerInner::Rustls { conn, .. } => conn.server_name().map(str::as_bytes),
            ServerInner::Boring {
                stream: Some(stream),
                ..
            } => stream
                .ssl()
                .servername_raw(boring::ssl::NameType::HOST_NAME),
            ServerInner::Boring { .. } => None,
            ServerInner::Shaped(server) => server.sni(),
        }
    }

    fn seal_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> std::io::Result<usize> {
        self.handshake()?;
        if let Some(layer) = &mut self.ktls {
            return layer.seal_into(&[plaintext], out);
        }
        match &mut self.inner {
            ServerInner::Rustls { conn, .. } => {
                let len = conn.writer().write(plaintext)?;
                while conn.wants_write() {
                    let wrote = conn.write_tls(out)?;
                    if wrote == 0 {
                        break;
                    }
                }
                Ok(len)
            }
            ServerInner::Boring {
                stream: Some(stream),
                ..
            } => {
                let len = std::io::Write::write(stream, plaintext)?;
                stream.flush()?;
                Ok(len)
            }
            ServerInner::Boring { .. } => {
                Err(std::io::Error::other("tls handshake is not complete"))
            }
            ServerInner::Shaped(server) => Ok(std::io::Write::write(server, plaintext)?),
        }
    }

    fn seal_slices_into(&mut self, parts: &[&[u8]], out: &mut Vec<u8>) -> std::io::Result<()> {
        self.handshake()?;
        if let Some(layer) = &mut self.ktls {
            layer.seal_into(parts, out)?;
            return Ok(());
        }
        match &mut self.inner {
            ServerInner::Rustls { conn, .. } => {
                coalesce(&mut conn.writer(), parts)?;
                while conn.wants_write() {
                    let wrote = conn.write_tls(out)?;
                    if wrote == 0 {
                        break;
                    }
                }
                Ok(())
            }
            ServerInner::Boring {
                stream: Some(stream),
                ..
            } => {
                for part in parts {
                    stream.write_all(part)?;
                }
                stream.flush()
            }
            ServerInner::Boring { .. } => {
                Err(std::io::Error::other("tls handshake is not complete"))
            }
            ServerInner::Shaped(server) => server.write_all_slices(parts),
        }
    }

    fn open(&mut self, ciphertext: &[u8], buf: &mut [u8]) -> std::io::Result<(usize, usize)> {
        if let Some(layer) = &mut self.ktls {
            return layer.open(ciphertext, buf);
        }
        match &mut self.inner {
            ServerInner::Rustls { conn, .. } => {
                let plain = match conn.reader().read(buf) {
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => 0,
                    Ok(0) => {
                        if !buf.is_empty() {
                            self.eof = true;
                        }
                        0
                    }
                    outcome => outcome?,
                };
                if plain > 0 {
                    return Ok((plain, 0));
                }
                // A handshake may leave ciphertext in the layer with no new input, so the empty slice still processes it.
                let taken = if ciphertext.is_empty() {
                    0
                } else {
                    let mut cursor = std::io::Cursor::new(ciphertext);
                    conn.read_tls(&mut cursor).map_err(recover)?
                };
                conn.process_new_packets()
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
                // A key update waits for the next seal rather than a transport write under this lock.
                let plain = match conn.reader().read(buf) {
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => 0,
                    Ok(0) => {
                        if !buf.is_empty() {
                            self.eof = true;
                        }
                        0
                    }
                    outcome => outcome?,
                };
                Ok((plain, taken))
            }
            ServerInner::Boring { .. } | ServerInner::Shaped(_) => Err(std::io::Error::other(
                "this session reads its own transport",
            )),
        }
    }

    fn wants_ktls(&self) -> bool {
        self.ktls_tx || self.ktls_rx
    }

    fn kernel_rx(&self) -> bool {
        self.ktls
            .as_ref()
            .is_some_and(crate::tls::ktls::Layer::rx_offloaded)
    }

    fn enable_ktls(&mut self, fd: RawFd) -> std::io::Result<()> {
        self.install_ktls(fd)
    }

    fn closed(&self) -> bool {
        self.eof
            || self.ktls.as_ref().is_some_and(crate::tls::ktls::Layer::eof)
            || match &self.inner {
                ServerInner::Shaped(server) => server.closed(),
                _ => false,
            }
    }
}

impl<S: Stream> Read for RustlsServerProvider<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.handshake()?;
        if let Some(layer) = &mut self.ktls {
            if let ServerInner::Rustls { io, .. } = &mut self.inner {
                return layer.read(io, buf);
            }
        }
        match &mut self.inner {
            ServerInner::Rustls { conn, io } => loop {
                match conn.reader().read(buf) {
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if let Err(io_error) = conn.complete_io(&mut *io) {
                            if matches!(
                                io_error.kind(),
                                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                            ) {
                                return Err(io_error);
                            }
                            return Err(recover(io_error).into());
                        }
                    }
                    outcome => return outcome,
                }
            },
            ServerInner::Boring {
                stream: Some(stream),
                ..
            } => match stream.read(buf) {
                Ok(0) => {
                    self.eof = true;
                    Ok(0)
                }
                outcome => outcome,
            },
            ServerInner::Boring { .. } => {
                Err(std::io::Error::other("tls handshake is not complete"))
            }
            ServerInner::Shaped(server) => match server.read(buf) {
                Ok(0) => {
                    self.eof = true;
                    Ok(0)
                }
                outcome => outcome,
            },
        }
    }
}

impl<S: Stream> RustlsServerProvider<S> {
    /// The transport this session reads and writes, for a relay that would read it itself and hand the session only the ciphertext.
    pub fn get_ref(&self) -> &S {
        match &self.inner {
            ServerInner::Rustls { io, .. } => io,
            ServerInner::Boring {
                stream: Some(stream),
                ..
            } => stream.get_ref(),
            ServerInner::Boring {
                handshake: Some(handshake),
                ..
            } => handshake.get_ref(),
            ServerInner::Boring { .. } => unreachable!("an ech session always owns a transport"),
            ServerInner::Shaped(server) => server.get_ref(),
        }
    }
}

impl<S: Stream> Write for RustlsServerProvider<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.handshake()?;
        if let Some(layer) = &mut self.ktls {
            if let ServerInner::Rustls { io, .. } = &mut self.inner {
                return layer.write(io, buf);
            }
        }
        match &mut self.inner {
            ServerInner::Rustls { conn, io } => {
                let len = conn.writer().write(buf)?;
                while conn.wants_write() {
                    let wrote = conn.write_tls(&mut *io)?;
                    if wrote == 0 {
                        break;
                    }
                }
                match io.flush() {
                    Err(error) if !idle(&error) => Err(recover(error).into()),
                    _ => Ok(len),
                }
            }
            ServerInner::Boring {
                stream: Some(stream),
                ..
            } => stream.write(buf),
            ServerInner::Boring { .. } => {
                Err(std::io::Error::other("tls handshake is not complete"))
            }
            ServerInner::Shaped(server) => server.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.handshake()?;
        if let Some(layer) = &mut self.ktls {
            if let ServerInner::Rustls { io, .. } = &mut self.inner {
                return layer.flush(io);
            }
        }
        match &mut self.inner {
            ServerInner::Rustls { conn, io } => {
                conn.writer().flush()?;
                while conn.wants_write() {
                    let wrote = conn.write_tls(&mut *io)?;
                    if wrote == 0 {
                        break;
                    }
                }
                match io.flush() {
                    Err(error) if !idle(&error) => Err(recover(error).into()),
                    _ => Ok(()),
                }
            }
            ServerInner::Boring {
                stream: Some(stream),
                ..
            } => stream.flush(),
            ServerInner::Boring { .. } => {
                Err(std::io::Error::other("tls handshake is not complete"))
            }
            ServerInner::Shaped(server) => server.flush(),
        }
    }
}

fn boring_error(error: &boring::error::ErrorStack) -> TlsError {
    TlsError::Other(format!("boring tls: {error}"))
}

fn cached_ech_server_context(
    cfg: &super::TlsServerConfig,
) -> Result<Arc<boring::ssl::SslContext>, TlsError> {
    let mut guard = cfg
        .server_config_cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let current = guard.served.as_deref().unwrap_or(&cfg.certs);
    if let Some((built_for, cached)) = guard.ech.as_ref() {
        if built_for.as_slice() == current {
            return Ok(Arc::clone(cached));
        }
    }
    let keys = cfg
        .ech_server_keys
        .as_deref()
        .ok_or_else(|| TlsError::Other("ech server identity has no keys".to_owned()))?;
    let served = current.to_vec();
    let mut fresh = cfg.clone();
    fresh.certs.clone_from(&served);
    let built = Arc::new(ech_server_context(&fresh, keys)?);
    guard.ech = Some((served, Arc::clone(&built)));
    Ok(built)
}

fn ech_server_context(
    cfg: &super::TlsServerConfig,
    keys: &[u8],
) -> Result<boring::ssl::SslContext, TlsError> {
    Ok(ech_server_context_builder(cfg, keys)?.build())
}

/// The builder behind an ECH-serving context: a TLS listener builds it, and a QUIC lane hands
/// it to quiche, so both answer the same key set and the same certificate.
pub(crate) fn ech_server_context_builder(
    cfg: &super::TlsServerConfig,
    keys: &[u8],
) -> Result<boring::ssl::SslContextBuilder, TlsError> {
    let mut builder = server_identity_builder(cfg)?;
    let ceiling = cfg.max_version.unwrap_or(0x0304).min(0x0304);
    if ceiling < 0x0304 {
        return Err(TlsError::Other(
            "an ECH listener cannot cap its maximum below TLS 1.3".to_owned(),
        ));
    }
    builder
        .set_max_proto_version(Some(crate::tls::legacy::version(ceiling)?))
        .map_err(|error| boring_error(&error))?;
    let parsed = crate::tls::ech::parse_server_keys(keys).map_err(TlsError::Other)?;
    let mut ech = boring::ssl::SslEchKeys::builder().map_err(|error| boring_error(&error))?;
    for key in parsed {
        let hpke = boring::hpke::HpkeKey::dhkem_p256_sha256(&key.private_key)
            .map_err(|error| boring_error(&error))?;
        // `BoringSSL` refuses a set with no retry config; every xray key can answer a rejected offer.
        ech.add_key(true, &key.config, hpke)
            .map_err(|error| boring_error(&error))?;
    }
    builder
        .set_ech_keys(&ech.build())
        .map_err(|error| boring_error(&error))?;
    Ok(builder)
}

/// A QUIC server's TLS context: the identity, ALPN and the SNI rule, ready for quiche.
pub fn quic_server_context_builder(
    cfg: &super::TlsServerConfig,
) -> Result<boring::ssl::SslContextBuilder, TlsError> {
    server_identity_builder(cfg)
}

pub(crate) fn server_identity_builder(
    cfg: &super::TlsServerConfig,
) -> Result<boring::ssl::SslContextBuilder, TlsError> {
    let first = cfg
        .certs
        .first()
        .ok_or_else(|| TlsError::Other("server identity has no certificate".to_owned()))?;
    let mut builder = identity_builder(first)?;
    server_settings(&mut builder, cfg)?;
    if cfg.certs.len() > 1 || cfg.reject_unknown_sni {
        let mut names = Vec::with_capacity(cfg.certs.len());
        let mut statuses: Vec<Option<Vec<u8>>> = Vec::with_capacity(cfg.certs.len());
        for entry in &cfg.certs {
            names.push(certificate_names(entry.cert_chain.first().ok_or_else(
                || TlsError::Other("server identity has no certificate".to_owned()),
            )?));
            statuses.push(entry.ocsp.as_ref().and_then(|ocsp| ocsp.response.clone()));
        }
        let mut contexts = Vec::with_capacity(cfg.certs.len().saturating_sub(1));
        for entry in cfg.certs.iter().skip(1) {
            let mut context = identity_builder(entry)?;
            server_settings(&mut context, cfg)?;
            contexts.push(context.build());
        }
        let reject = cfg.reject_unknown_sni;
        builder.set_servername_callback(move |ssl, alert| {
            use boring::ssl::{NameType, SniError};
            let sni = ssl.servername(NameType::HOST_NAME).unwrap_or("");
            // Which identity answered decides which staple rides, by the same index.
            if !reject && (names.len() == 1 || sni.is_empty()) {
                if let Some(Some(response)) = statuses.first() {
                    ssl.set_ocsp_status(response).ok();
                }
                return Ok(());
            }
            if let Some((at, _)) = names
                .iter()
                .enumerate()
                .find(|(_, names)| sni_matches(names, sni))
            {
                if at == 0 {
                    if let Some(Some(response)) = statuses.first() {
                        ssl.set_ocsp_status(response).ok();
                    }
                    return Ok(());
                }
                if ssl.set_ssl_context(&contexts[at - 1]).is_err() {
                    *alert = boring::ssl::SslAlert::INTERNAL_ERROR;
                    return Err(SniError::ALERT_FATAL);
                }
                if let Some(Some(response)) = statuses.get(at) {
                    ssl.set_ocsp_status(response).ok();
                }
                return Ok(());
            }
            if reject {
                *alert = boring::ssl::SslAlert::UNRECOGNIZED_NAME;
                return Err(SniError::ALERT_FATAL);
            }
            Ok(())
        });
    }
    Ok(builder)
}

fn identity_builder(entry: &super::CertEntry) -> Result<boring::ssl::SslContextBuilder, TlsError> {
    use boring::ssl::{SslContextBuilder, SslMethod, SslVerifyMode};
    let mut chain = entry.cert_chain.iter();
    let leaf = chain
        .next()
        .ok_or_else(|| TlsError::Other("server identity has no certificate".to_owned()))?;
    let mut builder =
        SslContextBuilder::new(SslMethod::tls()).map_err(|error| boring_error(&error))?;
    builder.set_verify(SslVerifyMode::NONE);
    // The context switch: status rides per connection, set by the accept path or the callback.
    if entry
        .ocsp
        .as_ref()
        .is_some_and(|ocsp| ocsp.response.is_some())
    {
        builder.enable_ocsp_stapling();
    }
    let leaf = boring::x509::X509::from_der(leaf).map_err(|error| boring_error(&error))?;
    builder
        .set_certificate(&leaf)
        .map_err(|error| boring_error(&error))?;
    for cert in chain {
        builder
            .add_extra_chain_cert(
                boring::x509::X509::from_der(cert).map_err(|error| boring_error(&error))?,
            )
            .map_err(|error| boring_error(&error))?;
    }
    let key = boring::pkey::PKey::private_key_from_der(&entry.key_der)
        .map_err(|error| boring_error(&error))?;
    builder
        .set_private_key(&key)
        .map_err(|error| boring_error(&error))?;
    builder
        .check_private_key()
        .map_err(|error| boring_error(&error))?;
    Ok(builder)
}

fn server_settings(
    builder: &mut boring::ssl::SslContextBuilder,
    cfg: &super::TlsServerConfig,
) -> Result<(), TlsError> {
    use boring::ssl::SslVersion;
    if !cfg.alpn.is_empty() {
        let wanted = cfg.alpn.clone();
        builder.set_alpn_select_callback(move |_, client| {
            for want in &wanted {
                let mut at = 0;
                while at < client.len() {
                    let len = usize::from(client[at]);
                    let Some(protocol) = client.get(at + 1..at + 1 + len) else {
                        return Err(boring::ssl::AlpnError::NOACK);
                    };
                    if protocol == want.as_slice() {
                        return Ok(protocol);
                    }
                    at += 1 + len;
                }
            }
            Err(boring::ssl::AlpnError::NOACK)
        });
    }
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|error| boring_error(&error))?;
    let curves = crate::tls::legacy::curve_list(&cfg.curves);
    if !curves.is_empty() {
        builder
            .set_curves_list(&curves)
            .map_err(|error| boring_error(&error))?;
    }
    if !cfg.send_tickets {
        builder.set_options(boring::ssl::SslOptions::NO_TICKET);
    }
    if let Some(log) = cfg.master_key_log.clone() {
        builder.set_keylog_callback(move |_, line| log.log_line(line));
    }
    Ok(())
}

/// Whether an error is the socket's poll grain expiring with nothing in it,
/// which `complete_io` reports because it reads as well as it writes.
fn idle(error: &std::io::Error) -> bool {
    TlsError::is_timeout(error)
}

fn recover(e: std::io::Error) -> TlsError {
    if e.kind() == std::io::ErrorKind::InvalidData {
        if let Some(inner) = e.get_ref().and_then(|s| s.downcast_ref::<rustls::Error>()) {
            return map_error(inner);
        }
    }
    TlsError::from(e)
}

fn map_error(e: &rustls::Error) -> TlsError {
    use rustls::Error as E;
    if let E::PeerIncompatible(rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(
        Some(configs),
    )) = e
    {
        if !configs.is_empty() {
            use rustls::internal::msgs::codec::Codec as _;
            let mut list = Vec::new();
            configs.encode(&mut list);
            return TlsError::EchRetry(list.into());
        }
    }
    match e {
        // An untrusted chain, a name that does not match and an expired certificate are three different problems and the caller can act on each; the why rides with the kind, so matching the kind does not cost the why.
        E::InvalidCertificate(why) => TlsError::BadCertificate(format!("{why:?}")),
        E::InvalidCertRevocationList(why) => TlsError::BadCertificate(format!("{why:?}")),
        E::NoCertificatesPresented => TlsError::BadCertificate("no certificate".to_owned()),
        E::UnsupportedNameType => TlsError::BadCertificate("unsupported name type".to_owned()),
        E::NoApplicationProtocol
        | E::AlertReceived(rustls::AlertDescription::NoApplicationProtocol)
        | E::PeerIncompatible(_)
        | E::PeerMisbehaved(_)
        | E::BadMaxFragmentSize => TlsError::NoSharedCipher,

        E::DecryptError
        | E::EncryptError
        | E::InvalidMessage(_)
        | E::InappropriateMessage { .. }
        | E::InappropriateHandshakeMessage { .. }
        | E::HandshakeNotComplete
        | E::PeerSentOversizedRecord
        | E::AlertReceived(rustls::AlertDescription::CloseNotify) => TlsError::Closed,

        E::AlertReceived(other) => TlsError::Other(format!("rustls alert: {other:?}")),

        E::FailedToGetCurrentTime
        | E::FailedToGetRandomBytes
        | E::InvalidEncryptedClientHello(_)
        | E::InconsistentKeys(_)
        | E::General(_)
        | E::Other(_) => TlsError::Other(format!("rustls: {e:?}")),

        _ => TlsError::Other(format!("rustls: unmapped error {e:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::shaped::keys;
    use crate::tls::shaped::record;
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    const HANDSHAKE: u8 = 22;
    const CCS: u8 = 20;
    const APPLICATION: u8 = 23;

    #[test]
    fn a_verifier_that_skips_the_chain_still_rejects_a_forged_handshake_signature() {
        use rustls::client::danger::ServerCertVerifier as _;
        use rustls::internal::msgs::codec::{Codec as _, Reader};

        let mut encoded = Vec::with_capacity(68);
        encoded.extend_from_slice(&0x0403u16.to_be_bytes());
        encoded.extend_from_slice(&64u16.to_be_bytes());
        encoded.extend_from_slice(&[0u8; 64]);
        let mut reader = Reader::init(&encoded);
        let dss = rustls::DigitallySignedStruct::read(&mut reader).unwrap();
        let cert = rustls::pki_types::CertificateDer::from(ANCHOR);
        assert!(Unverified
            .verify_tls13_signature(b"message", &cert, &dss)
            .is_err());
        assert!(Unverified
            .verify_tls12_signature(b"message", &cert, &dss)
            .is_err());
    }

    const ANCHOR: &[u8] = &[
        0x30, 0x82, 0x01, 0x6c, 0x30, 0x82, 0x01, 0x11, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14,
        0x6d, 0x8e, 0xc2, 0xf5, 0x42, 0x91, 0xda, 0xdb, 0x05, 0xc9, 0xb2, 0x00, 0x71, 0x8b, 0xfb,
        0x6a, 0x20, 0xf4, 0xa1, 0xf8, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04,
        0x03, 0x02, 0x30, 0x13, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x08,
        0x74, 0x6c, 0x73, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x36, 0x31,
        0x30, 0x30, 0x33, 0x31, 0x32, 0x34, 0x38, 0x30, 0x32, 0x5a, 0x18, 0x0f, 0x32, 0x30, 0x36,
        0x36, 0x30, 0x39, 0x32, 0x33, 0x31, 0x32, 0x34, 0x38, 0x30, 0x32, 0x5a, 0x30, 0x13, 0x31,
        0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x08, 0x74, 0x6c, 0x73, 0x2e, 0x74,
        0x65, 0x73, 0x74, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
        0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
        0xe7, 0xc8, 0xba, 0x65, 0x0f, 0xe6, 0x76, 0xe9, 0x05, 0x43, 0xd0, 0x8a, 0x63, 0xd4, 0xc4,
        0xee, 0x19, 0x31, 0xbb, 0x2d, 0x39, 0xce, 0xd1, 0xb1, 0x9a, 0xc7, 0x5a, 0xf1, 0x34, 0x98,
        0x5e, 0xe4, 0x87, 0x83, 0xfe, 0x38, 0x68, 0x71, 0xbc, 0xef, 0xfa, 0x47, 0x67, 0x10, 0x69,
        0x58, 0x0b, 0x2c, 0xc5, 0xa5, 0xc8, 0xcf, 0xba, 0x0a, 0x7a, 0x8e, 0x14, 0x7d, 0x97, 0x3e,
        0xef, 0x18, 0x38, 0x94, 0xa3, 0x41, 0x30, 0x3f, 0x30, 0x1e, 0x06, 0x03, 0x55, 0x1d, 0x11,
        0x04, 0x17, 0x30, 0x15, 0x82, 0x08, 0x74, 0x6c, 0x73, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x82,
        0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x1d, 0x06, 0x03, 0x55,
        0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x04, 0x37, 0x6a, 0x70, 0x40, 0x98, 0x48, 0xaf, 0x75,
        0xc5, 0xa8, 0x24, 0x77, 0xca, 0xe1, 0x2c, 0x0d, 0xf1, 0xee, 0x5a, 0x30, 0x0a, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21,
        0x00, 0xae, 0x33, 0xd8, 0x61, 0xdc, 0x06, 0xf9, 0x8b, 0x76, 0x18, 0xe9, 0xe7, 0x5d, 0xe2,
        0x57, 0x8e, 0x84, 0x33, 0x43, 0x0a, 0x43, 0x7b, 0x7b, 0xb9, 0x05, 0xa3, 0xd8, 0x27, 0xfd,
        0xa4, 0x51, 0x2e, 0x02, 0x21, 0x00, 0xda, 0x81, 0x2e, 0x43, 0x7c, 0xf6, 0xe8, 0x0a, 0x09,
        0x47, 0xb4, 0x81, 0x81, 0xa2, 0x38, 0x17, 0x55, 0x0f, 0xeb, 0x95, 0x8b, 0x66, 0x78, 0x21,
        0x05, 0x95, 0xb1, 0xf2, 0xe1, 0x67, 0x0d, 0x3e,
    ];

    const ANCHOR_KEY: &[u8] = &[
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30,
        0x6b, 0x02, 0x01, 0x01, 0x04, 0x20, 0x32, 0x0d, 0x8c, 0x13, 0x2e, 0x2a, 0x61, 0x40, 0xf4,
        0x9c, 0x2b, 0xa1, 0x5a, 0x13, 0x8c, 0x28, 0xef, 0xcc, 0x66, 0x47, 0xde, 0xdd, 0x5a, 0x6d,
        0x60, 0x5e, 0x01, 0x73, 0xda, 0x6a, 0x21, 0x0a, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0xe7,
        0xc8, 0xba, 0x65, 0x0f, 0xe6, 0x76, 0xe9, 0x05, 0x43, 0xd0, 0x8a, 0x63, 0xd4, 0xc4, 0xee,
        0x19, 0x31, 0xbb, 0x2d, 0x39, 0xce, 0xd1, 0xb1, 0x9a, 0xc7, 0x5a, 0xf1, 0x34, 0x98, 0x5e,
        0xe4, 0x87, 0x83, 0xfe, 0x38, 0x68, 0x71, 0xbc, 0xef, 0xfa, 0x47, 0x67, 0x10, 0x69, 0x58,
        0x0b, 0x2c, 0xc5, 0xa5, 0xc8, 0xcf, 0xba, 0x0a, 0x7a, 0x8e, 0x14, 0x7d, 0x97, 0x3e, 0xef,
        0x18, 0x38, 0x94,
    ];

    fn client(name: &str, alpn: &[&[u8]]) -> TlsConfig {
        TlsConfig {
            server_name: name.to_owned(),
            alpn: std::sync::Arc::from(alpn.iter().map(|p| p.to_vec()).collect::<Vec<_>>()),
            roots: vec![ANCHOR.to_vec()].into(),
            pins: crate::foxy::pin::Pins::default(),
            cert_pins: std::sync::Arc::default(),
            verify_names: std::sync::Arc::default(),
            cipher_suites: std::sync::Arc::default(),
            curves: std::sync::Arc::default(),
            insecure: false,
            resumption: false,
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

    fn serve(listener: &TcpListener) {
        let cert = rustls::pki_types::CertificateDer::from(ANCHOR.to_vec());
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(ANCHOR_KEY.to_vec()),
        );
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("server versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server cert");
        config.alpn_protocols = vec![b"test-only".to_vec()];
        let (mut stream, _) = listener.accept().expect("accepts");
        let mut conn = rustls::ServerConnection::new(Arc::new(config)).expect("server session");
        let mut tls = rustls::Stream::new(&mut conn, &mut stream);
        let mut buf = [0u8; 4];
        if tls.read_exact(&mut buf).is_err() {
            return;
        }
        let _ = tls.write_all(&buf);
    }

    /// A stock rustls server over one accepted stream that echoes `rounds` four-byte frames.
    fn echo_rounds(listener: &TcpListener, rounds: usize) {
        let cert = rustls::pki_types::CertificateDer::from(ANCHOR.to_vec());
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(ANCHOR_KEY.to_vec()),
        );
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("server versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server cert");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let (mut stream, _) = listener.accept().expect("accepts");
        let mut conn = rustls::ServerConnection::new(Arc::new(config)).expect("server session");
        let mut tls = rustls::Stream::new(&mut conn, &mut stream);
        for _ in 0..rounds {
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf)
                .unwrap_or_else(|e| panic!("server read: {e:?}"));
            tls.write_all(&buf).expect("writes");
        }
    }

    fn case(dial: impl FnOnce(TcpStream)) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(|| serve(&listener));
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            dial(stream);
        });
    }

    /// Two dialled sessions to the same server, each answered by its own `serve`: a lane that resumed across them would show it in what the second one was handed.
    fn twice(mut dial: impl FnMut(TcpStream, TcpStream)) {
        let first = TcpListener::bind("127.0.0.1:0").expect("binds");
        let second = TcpListener::bind("127.0.0.1:0").expect("binds");
        let (first_port, second_port) = (
            first.local_addr().expect("addr").port(),
            second.local_addr().expect("addr").port(),
        );
        thread::scope(|scope| {
            scope.spawn(|| serve(&first));
            scope.spawn(|| serve(&second));
            let a = TcpStream::connect(("127.0.0.1", first_port)).expect("connects");
            let b = TcpStream::connect(("127.0.0.1", second_port)).expect("connects");
            dial(a, b);
        });
    }

    /// The `cipher_suites` field of a captured `ClientHello` record: skip the 5-byte record and
    /// 4-byte handshake headers, the legacy version and random, then the session id, and read
    /// the length-prefixed suite list — the same span the Go oracle dumps.
    fn hello_cipher_suites(record: &[u8]) -> &[u8] {
        assert_eq!(record[0], 0x16, "handshake record");
        assert_eq!(record[5], 0x01, "ClientHello");
        let body = &record[9..];
        let sid_len = usize::from(body[2 + 32]);
        let at = 2 + 32 + 1 + sid_len;
        let cs_len = usize::from(body[at]) << 8 | usize::from(body[at + 1]);
        &body[at..at + 2 + cs_len]
    }

    fn hello_extensions(record: &[u8]) -> Vec<(u16, &[u8])> {
        assert_eq!(record[0], 0x16, "handshake record");
        let record_len = usize::from(record[3]) << 8 | usize::from(record[4]);
        let handshake = &record[5..5 + record_len];
        assert_eq!(handshake[0], 0x01, "ClientHello");
        let body_len = usize::from(handshake[1]) << 16
            | usize::from(handshake[2]) << 8
            | usize::from(handshake[3]);
        let body = &handshake[4..4 + body_len];
        let mut at = 2 + 32;
        at += 1 + usize::from(body[at]);
        at += 2 + (usize::from(body[at]) << 8 | usize::from(body[at + 1]));
        at += 1 + usize::from(body[at]);
        let ext_len = usize::from(body[at]) << 8 | usize::from(body[at + 1]);
        at += 2;
        let end = at + ext_len;
        let mut out = Vec::new();
        while at < end {
            let kind = u16::from_be_bytes([body[at], body[at + 1]]);
            let len = usize::from(body[at + 2]) << 8 | usize::from(body[at + 3]);
            out.push((kind, &body[at + 4..at + 4 + len]));
            at += 4 + len;
        }
        out
    }

    #[cfg_attr(miri, ignore = "assembles a real hello through ring")]
    #[test]
    fn a_configured_ech_list_carries_the_inner_name_only_in_the_payload() {
        let (list, _keys) = crate::tls::ech::generate("public.test", 3).expect("generates");
        let mut cfg = client("hidden.test", &[]);
        cfg.ech_config_list = Some(list.into());
        let config = client_config(&cfg).expect("builds");
        let mut conn = rustls::ClientConnection::new(
            config,
            rustls::pki_types::ServerName::try_from("hidden.test").expect("name"),
        )
        .expect("session");
        let mut record = Vec::new();
        conn.write_tls(&mut record).expect("hello goes out");
        assert_eq!(conn.ech_status(), rustls::client::EchStatus::Offered);
        let extensions = hello_extensions(&record);
        let (_, ech) = extensions
            .iter()
            .find(|(kind, _)| *kind == 0xfe0d)
            .expect("ech extension");
        assert_eq!(ech[0], 0, "ClientHelloOuter");
        assert_eq!(ech[5], 3, "config id");
        assert_eq!(
            usize::from(ech[6]) << 8 | usize::from(ech[7]),
            32,
            "x25519 enc"
        );
        let (_, sni) = extensions
            .iter()
            .find(|(kind, _)| *kind == 0x0000)
            .expect("sni extension");
        assert!(
            sni.windows(b"public.test".len())
                .any(|window| window == b"public.test"),
            "the outer name is the public one"
        );
        assert!(
            !sni.windows(b"hidden.test".len())
                .any(|window| window == b"hidden.test"),
            "the inner name is not on the outside"
        );
    }

    #[test]
    fn a_malformed_ech_list_refuses_the_dial_instead_of_falling_back() {
        let mut cfg = client("hidden.test", &[]);
        cfg.ech_config_list = Some(vec![0, 1, 2].into());
        assert!(client_config(&cfg).is_err());
    }

    #[cfg_attr(miri, ignore = "assembles a real hello through ring")]
    #[test]
    fn a_crafted_list_reorders_the_dialer_hello_to_the_reference() {
        // The reference TLS 1.3 field is `0x1301,0x1302,0x1303`; ring's stock provider offers `0x1302,0x1301,0x1303`.
        let preset =
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        let crafted = crate::tls::cipher_suites::hello_ids(
            &crate::tls::cipher_suites::parse(preset),
            0x0304,
            0x0304,
            true,
        );
        let mut cfg = client("tls.test", &[]);
        cfg.cipher_suites = crafted.into();
        let config = client_config(&cfg).expect("builds");
        let mut conn = rustls::ClientConnection::new(
            config,
            rustls::pki_types::ServerName::try_from("tls.test").expect("name"),
        )
        .expect("session");
        let mut record = Vec::new();
        conn.write_tls(&mut record).expect("hello goes out");
        let got = hello_cipher_suites(&record);
        let want = crate::tls::cipher_suites::field_bytes(&[0x1301, 0x1302, 0x1303]);
        assert_eq!(
            got,
            want.as_slice(),
            "dialer hello matches the crypto/tls field"
        );
    }

    /// A named TLS 1.2-only list rides the legacy lane, which writes the reference's field and
    /// appends no `0x00ff` SCSV.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and BoringSSL's assembly behind it"
    )]
    #[test]
    fn a_tls12_list_keeps_the_reference_ids_and_order_on_the_wire() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let capture = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut head = [0u8; 5];
            stream.read_exact(&mut head).expect("record header");
            let len = usize::from(u16::from_be_bytes([head[3], head[4]]));
            let mut record = head.to_vec();
            record.resize(5 + len, 0);
            stream.read_exact(&mut record[5..]).expect("record body");
            record
        });
        let preset =
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
        let crafted = crate::tls::cipher_suites::hello_ids(
            &crate::tls::cipher_suites::parse(preset),
            0x0301,
            0x0303,
            true,
        );
        let mut cfg = client("tls.test", &[]);
        cfg.cipher_suites = crafted.into();
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let mut session = crate::tls::connect(&cfg, stream).expect("dials");
        assert!(
            matches!(&session, crate::tls::ClientSession::Legacy(_)),
            "a named TLS 1.2-only list rides the legacy lane"
        );
        let _ = session.handshake();
        let record = capture.join().expect("joins");
        let want = crate::tls::cipher_suites::field_bytes(&cfg.cipher_suites);
        assert_eq!(
            hello_cipher_suites(&record),
            want.as_slice(),
            "the dialer field is the reference's, with no SCSV"
        );
    }

    /// An ECH offer on a stock fingerprint still writes the configured TLS 1.2 ids, including a
    /// CBC one, and appends no SCSV: the offer rides the shaped hello rather than rustls's lane.
    #[cfg_attr(miri, ignore = "needs a loopback socket")]
    #[test]
    fn an_ech_list_keeps_the_configured_ids_without_an_scsv() {
        let (list, _keys) = crate::tls::ech::generate("public.test", 3).expect("generates");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let capture = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut head = [0u8; 5];
            stream.read_exact(&mut head).expect("record header");
            let len = usize::from(u16::from_be_bytes([head[3], head[4]]));
            let mut record = head.to_vec();
            record.resize(5 + len, 0);
            stream.read_exact(&mut record[5..]).expect("record body");
            record
        });
        let mut cfg = client("hidden.test", &[]);
        cfg.fingerprint = Some(crate::tls::Fingerprint::stock());
        cfg.ech_config_list = Some(list.into());
        cfg.cipher_suites = crate::tls::cipher_suites::hello_ids(
            &crate::tls::cipher_suites::parse("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
            0x0303,
            0x0304,
            true,
        )
        .into();
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let mut session = crate::tls::connect(&cfg, stream).expect("dials");
        assert!(
            matches!(&session, crate::tls::ClientSession::Shaped(_)),
            "an ECH offer with a TLS 1.2 id rides the shaped stock hello"
        );
        let _ = session.handshake();
        let record = capture.join().expect("joins");
        let want = crate::tls::cipher_suites::field_bytes(&cfg.cipher_suites);
        assert_eq!(
            hello_cipher_suites(&record),
            want.as_slice(),
            "the ECH hello keeps the CBC id and appends no SCSV"
        );
    }

    /// The same stock hello with an ECH offer finishes the handshake, so routing it off rustls's
    /// lane does not trade the CBC field for a broken offer.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and BoringSSL's assembly behind it"
    )]
    #[test]
    fn an_ech_offer_rides_the_stock_shaped_hello() {
        let (list, keys) = crate::tls::ech::generate("public.test", 3).expect("generates");
        let mut identity = plain_identity();
        identity.ech_server_keys = Some(keys.into());
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(|| {
                let (stream, _) = listener.accept().expect("accepts");
                let mut server = crate::tls::accept(&identity, stream).expect("accepts");
                server.handshake().expect("handshakes");
                assert!(server.ech_accepted(), "the offer was accepted");
                let mut buf = [0u8; 4];
                server.read_exact(&mut buf).expect("reads");
                server.write_all(&buf).expect("writes");
                server.flush().expect("flushes");
            });
            let mut cfg = client("tls.test", &[]);
            cfg.fingerprint = Some(crate::tls::Fingerprint::stock());
            cfg.ech_config_list = Some(list.into());
            cfg.cipher_suites = crate::tls::cipher_suites::hello_ids(
                &crate::tls::cipher_suites::parse("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
                0x0303,
                0x0304,
                true,
            )
            .into();
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let mut session = crate::tls::connect(&cfg, stream).expect("dials");
            assert!(matches!(&session, crate::tls::ClientSession::Shaped(_)));
            session.handshake().expect("handshakes");
            session.write_all(b"ping").expect("writes");
            session.flush().expect("flushes");
            let mut buf = [0u8; 4];
            session.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
        });
    }

    /// The provider's reachable set: the TLS 1.3 trio and ring's six TLS 1.2 AEAD suites, no CBC or static-RSA id.
    #[test]
    fn the_reachable_set_is_the_tls13_trio_and_ring_s_six_tls12_aead_suites() {
        let ids: Vec<u16> = provider()
            .cipher_suites
            .iter()
            .map(|suite| u16::from(suite.suite()))
            .collect();
        assert_eq!(ids.len(), 9, "three TLS 1.3 and six TLS 1.2 AEAD suites");
        for id in [0x1301, 0x1302, 0x1303] {
            assert!(ids.contains(&id), "TLS 1.3 suite {id:#06x}");
        }
        for id in [0xc02b, 0xc02c, 0xcca9, 0xc02f, 0xc030, 0xcca8] {
            assert!(ids.contains(&id), "TLS 1.2 AEAD suite {id:#06x}");
        }
        for id in [
            0xc009, 0xc00a, 0xc013, 0xc014, 0xc023, 0xc027, 0x002f, 0x0035, 0x009c, 0x009d,
        ] {
            assert!(
                !ids.contains(&id),
                "ring has no CBC or static-RSA suite ({id:#06x})"
            );
        }
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_shaped_chrome_handshake_reaches_a_stock_server() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let cert = rustls::pki_types::CertificateDer::from(ANCHOR.to_vec());
            let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(ANCHOR_KEY.to_vec()),
            );
            let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("server versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("server cert");
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut conn = rustls::ServerConnection::new(Arc::new(config)).expect("server session");
            let mut tls = rustls::Stream::new(&mut conn, &mut stream);
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf)
                .unwrap_or_else(|e| panic!("server read: {e:?}"));
            tls.write_all(&buf).expect("writes");
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let mut cfg = client("tls.test", &[]);
        cfg.fingerprint = Some(crate::tls::Fingerprint::default());
        let mut session = crate::tls::connect(&cfg, stream).expect("dials");
        session.handshake().expect("handshakes");
        assert_eq!(session.alpn(), Some(b"http/1.1".as_slice()));
        session.write_all(b"ping").expect("writes");
        session.flush().expect("flushes");
        let mut buf = [0u8; 4];
        session.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"ping");
        server.join().expect("joins");
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_shaped_chrome_handshake_answers_a_client_certificate_request() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let mut roots = RootStore::empty();
            roots
                .add(rustls::pki_types::CertificateDer::from(ANCHOR.to_vec()))
                .expect("root");
            // Asks for a client certificate and accepts an anonymous client, Go's RequestCert policy.
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                provider(),
            )
            .allow_unauthenticated()
            .build()
            .expect("client verifier");
            let cert = rustls::pki_types::CertificateDer::from(ANCHOR.to_vec());
            let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(ANCHOR_KEY.to_vec()),
            );
            let mut config = rustls::ServerConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .expect("server versions")
                .with_client_cert_verifier(verifier)
                .with_single_cert(vec![cert], key)
                .expect("server cert");
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut conn = rustls::ServerConnection::new(Arc::new(config)).expect("server session");
            {
                let mut tls = rustls::Stream::new(&mut conn, &mut stream);
                let mut buf = [0u8; 4];
                tls.read_exact(&mut buf)
                    .unwrap_or_else(|e| panic!("server read: {e:?}"));
                tls.write_all(&buf).expect("writes");
                tls.flush().expect("flushes");
            }
            // Reading the ping means the dial's flight went through, with no certificate in it.
            assert!(conn.peer_certificates().is_none());
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let mut cfg = client("tls.test", &[]);
        cfg.fingerprint = Some(crate::tls::Fingerprint::default());
        let mut session = crate::tls::connect(&cfg, stream).expect("dials");
        session.handshake().expect("handshakes");
        assert_eq!(session.alpn(), Some(b"http/1.1".as_slice()));
        session.write_all(b"ping").expect("writes");
        session.flush().expect("flushes");
        let mut buf = [0u8; 4];
        session.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"ping");
        server.join().expect("joins");
    }

    fn client_identity() -> Arc<crate::tls::CertEntry> {
        Arc::new(
            crate::tls::parse_pem_entry(
                &anchor_pem("CERTIFICATE", ANCHOR),
                &anchor_pem("PRIVATE KEY", ANCHOR_KEY),
            )
            .expect("the fixture is one identity"),
        )
    }

    /// A listener that demands a client certificate and answers one echo: the peer leaf it
    /// verified, or none when the dial presented no chain.
    fn serve_requiring_client_cert(listener: &TcpListener, tls12: bool) -> Vec<u8> {
        let mut roots = RootStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(ANCHOR.to_vec()))
            .expect("client root");
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider(),
        )
        .build()
        .expect("client verifier");
        let cert = rustls::pki_types::CertificateDer::from(ANCHOR.to_vec());
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(ANCHOR_KEY.to_vec()),
        );
        let versions: &[&'static rustls::SupportedProtocolVersion] = if tls12 {
            &[&rustls::version::TLS12]
        } else {
            &[&rustls::version::TLS13]
        };
        let mut config = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(versions)
            .expect("server versions")
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![cert], key)
            .expect("server cert");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let (mut stream, _) = listener.accept().expect("accepts");
        let mut conn = rustls::ServerConnection::new(Arc::new(config)).expect("server session");
        {
            let mut tls = rustls::Stream::new(&mut conn, &mut stream);
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf)
                .unwrap_or_else(|e| panic!("server read: {e:?}"));
            tls.write_all(&buf).expect("writes");
            tls.flush().expect("flushes");
        }
        conn.peer_certificates()
            .and_then(|chain| chain.first().map(|leaf| leaf.as_ref().to_vec()))
            .unwrap_or_default()
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_shaped_tls13_dial_presents_a_configured_client_certificate() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || serve_requiring_client_cert(&listener, false));
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let mut cfg = client("tls.test", &[]);
        cfg.fingerprint = Some(crate::tls::Fingerprint::default());
        cfg.client_cert = Some(client_identity());
        let mut session = crate::tls::connect(&cfg, stream).expect("dials");
        session.handshake().expect("handshakes");
        session.write_all(b"ping").expect("writes");
        session.flush().expect("flushes");
        let mut buf = [0u8; 4];
        session.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"ping");
        assert_eq!(server.join().expect("joins"), ANCHOR);
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_shaped_tls12_dial_presents_a_configured_client_certificate() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || serve_requiring_client_cert(&listener, true));
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let mut cfg = client("tls.test", &[]);
        cfg.fingerprint = Some(crate::tls::Fingerprint::default());
        cfg.client_cert = Some(client_identity());
        let mut session = crate::tls::connect(&cfg, stream).expect("dials");
        session.handshake().expect("handshakes");
        session.write_all(b"ping").expect("writes");
        session.flush().expect("flushes");
        let mut buf = [0u8; 4];
        session.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"ping");
        assert_eq!(server.join().expect("joins"), ANCHOR);
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_stock_dial_presents_a_configured_client_certificate() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || serve_requiring_client_cert(&listener, false));
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let mut cfg = client("tls.test", &[]);
        cfg.client_cert = Some(client_identity());
        let mut session = crate::tls::connect(&cfg, stream).expect("dials");
        session.handshake().expect("handshakes");
        session.write_all(b"ping").expect("writes");
        session.flush().expect("flushes");
        let mut buf = [0u8; 4];
        session.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"ping");
        assert_eq!(server.join().expect("joins"), ANCHOR);
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_shaped_record_relays_without_allocating_once_the_handshake_is_done() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || echo_rounds(&listener, 3));
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let mut cfg = client("tls.test", &[]);
        cfg.fingerprint = Some(crate::tls::Fingerprint::default());
        let mut session = crate::tls::connect(&cfg, stream).expect("dials");
        session.handshake().expect("handshakes");
        session.write_all(b"ping").expect("writes");
        let mut buf = [0u8; 4];
        session.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"ping");
        for _ in 0..2 {
            let ((), counts) = crate::alloc_count::measure(|| {
                session
                    .write_all(std::hint::black_box(b"ping"))
                    .expect("writes");
                let mut buf = [0u8; 4];
                session.read_exact(&mut buf).expect("reads");
                assert_eq!(&buf, b"ping");
            });
            assert_eq!(
                counts.allocs, 0,
                "a relayed record takes no heap once its buffers are warm: {counts:?}"
            );
        }
        server.join().expect("joins");
    }

    /// A carrier hands the session ciphertext and its own window: each record lands in that
    /// window directly, its plaintext neither staged nor reallocated, however many relay.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_carrier_record_lands_in_the_callers_window_without_a_stage() {
        const WARM: usize = 8;
        const MEASURED: usize = 8;
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || echo_rounds(&listener, WARM + MEASURED + 1));
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let mut cfg = client("tls.test", &[]);
        cfg.fingerprint = Some(crate::tls::Fingerprint::default());
        let crate::tls::ClientSession::Shaped(mut session) =
            crate::tls::connect(&cfg, stream).expect("dials")
        else {
            panic!("a fingerprint dials the shaped session");
        };
        session.handshake().expect("handshakes");
        let held = session.plain_buffer().to_vec();
        let capacity = session.plain_capacity();
        let mut sealed = Vec::new();
        let mut scratch = [0u8; 1024];
        let mut window = [0u8; 64];
        let mut relay = |session: &mut crate::tls::shaped::Session<TcpStream>,
                         sealed: &mut Vec<u8>| {
            sealed.clear();
            session.seal_into(b"ping", sealed).expect("seals");
            session
                .get_ref()
                .write_all(sealed)
                .expect("sends the record");
            let mut got = 0;
            while got < 4 {
                let read = session.get_ref().read(&mut scratch).expect("reads");
                assert!(read > 0, "the server answers every round");
                let (plain, consumed) = session
                    .open(&scratch[..read], &mut window[got..])
                    .expect("opens");
                assert_eq!(consumed, read, "a carrier chunk is consumed whole");
                got += plain;
            }
            assert_eq!(&window[..4], b"ping", "the caller's window hears the frame");
        };
        for _ in 0..WARM {
            relay(&mut session, &mut sealed);
        }
        let ((), counts) = crate::alloc_count::measure(|| {
            for _ in 0..MEASURED {
                relay(&mut session, &mut sealed);
            }
        });
        assert_eq!(
            counts.allocs, 0,
            "a carrier record takes no heap once its buffers are warm: {counts:?}"
        );
        assert_eq!(
            session.plain_buffer(),
            held.as_slice(),
            "a carrier record with room in the window stages no plaintext"
        );
        assert_eq!(
            session.plain_capacity(),
            capacity,
            "the plaintext buffer does not grow with the relay"
        );
        sealed.clear();
        session.seal_into(b"ping", &mut sealed).expect("seals");
        session
            .get_ref()
            .write_all(&sealed)
            .expect("sends the record");
        let read = session.get_ref().read(&mut scratch).expect("reads");
        let (first, consumed) = session
            .open(&scratch[..read], &mut window[..2])
            .expect("opens");
        assert_eq!(
            (first, consumed),
            (2, read),
            "a window smaller than the record holds the rest"
        );
        let (second, consumed) = session.open(&[], &mut window[2..]).expect("opens");
        assert_eq!(
            (second, consumed),
            (2, 0),
            "the held half follows before any more ciphertext"
        );
        assert_eq!(&window[..4], b"ping", "the frame keeps its order");
        server.join().expect("joins");
    }

    /// A TLS 1.2 listener of our own, keyed to the suite its constructor names rather than only the
    /// AEAD rows rustls serves. It hashes the extended master secret only when the hello offered it,
    /// appends the `ClientKeyExchange` before hashing that transcript, and refuses a `Finished`
    /// that did not.
    struct Tls12Server {
        suite: u16,
        group: u16,
        ask_cert: bool,
        rng: ring::rand::SystemRandom,
        signing: ring::signature::EcdsaKeyPair,
        ephemeral: Option<keys::Share>,
        server_random: [u8; 32],
        client_random: [u8; 32],
        session_id: Vec<u8>,
        transcript: Vec<u8>,
        master: Vec<u8>,
        ems: bool,
        read_dir: Option<record::Direction>,
        write_dir: Option<record::Direction>,
        pending: Vec<u8>,
        feed: Vec<u8>,
    }

    impl Tls12Server {
        fn new(suite: u16, group: u16, ask_cert: bool) -> Self {
            let rng = ring::rand::SystemRandom::new();
            let signing = ring::signature::EcdsaKeyPair::from_pkcs8(
                &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                ANCHOR_KEY,
                &rng,
            )
            .expect("signing key");
            let mut ephemeral = keys::generate(&[group], false).expect("an ephemeral key");
            Self {
                suite,
                group,
                ask_cert,
                rng,
                signing,
                ephemeral: Some(ephemeral.pop().expect("one group")),
                server_random: [0x42; 32],
                client_random: [0u8; 32],
                session_id: Vec::new(),
                transcript: Vec::new(),
                master: Vec::new(),
                ems: false,
                read_dir: None,
                write_dir: None,
                pending: Vec::new(),
                feed: Vec::new(),
            }
        }

        fn process(&mut self) {
            let mut at = 0;
            while self.pending.len() - at >= 5 {
                let len = usize::from(u16::from_be_bytes([
                    self.pending[at + 3],
                    self.pending[at + 4],
                ]));
                if self.pending.len() - at - 5 < len {
                    break;
                }
                let kind = self.pending[at];
                let body = self.pending[at + 5..at + 5 + len].to_vec();
                at += 5 + len;
                self.record(kind, body);
            }
            self.pending.drain(..at);
        }

        fn record(&mut self, kind: u8, mut body: Vec<u8>) {
            match kind {
                CCS => {}
                HANDSHAKE if self.read_dir.is_some() => {
                    let (start, len) =
                        record::open12(self.read_dir.as_mut().expect("read keys"), kind, &mut body)
                            .expect("client record opens");
                    self.handshake(&body[start..start + len]);
                }
                HANDSHAKE => self.handshake(&body),
                APPLICATION => {
                    let (start, len) =
                        record::open12(self.read_dir.as_mut().expect("read keys"), kind, &mut body)
                            .expect("application record opens");
                    assert_eq!(
                        &body[start..start + len],
                        b"ping",
                        "the client's frame opens whole"
                    );
                    let mut out = Vec::new();
                    record::seal12(
                        self.write_dir.as_mut().expect("write keys"),
                        APPLICATION,
                        &body[start..start + len],
                        &mut out,
                    )
                    .expect("seals");
                    self.feed.extend_from_slice(&out);
                }
                other => panic!("unexpected record {other}"),
            }
        }

        fn handshake(&mut self, msg: &[u8]) {
            match msg[0] {
                1 => self.client_hello(msg),
                11 => self.transcript.extend_from_slice(msg),
                16 => self.client_key_exchange(msg),
                20 => self.client_finished(msg),
                other => panic!("unexpected handshake message {other}"),
            }
        }

        fn client_hello(&mut self, msg: &[u8]) {
            let mut c = Cursor::new(&msg[4..]);
            c.u16();
            self.client_random.copy_from_slice(c.take(32));
            self.session_id = c.vec8().to_vec();
            let suites = c.vec16();
            assert!(
                suites
                    .as_chunks::<2>()
                    .0
                    .contains(&self.suite.to_be_bytes()),
                "the hello offers the suite the server names"
            );
            c.vec8();
            let mut ems = false;
            let mut alpn = false;
            let mut ext = Cursor::new(c.vec16());
            while ext.at < ext.bytes.len() {
                let kind = ext.u16();
                let value = ext.vec16();
                match kind {
                    0x0017 => ems = true,
                    0x0010 => {
                        let mut list = Cursor::new(value);
                        let mut protos = Cursor::new(list.vec16());
                        while protos.at < protos.bytes.len() {
                            alpn |= protos.vec8() == b"http/1.1";
                        }
                    }
                    _ => {}
                }
            }
            assert!(alpn, "the hello offers http/1.1");
            self.ems = ems;
            self.transcript.extend_from_slice(msg);

            let mut hello = Vec::new();
            hello.extend_from_slice(&[0x03, 0x03]);
            hello.extend_from_slice(&self.server_random);
            hello.push(self.session_id.len() as u8);
            hello.extend_from_slice(&self.session_id);
            hello.extend_from_slice(&self.suite.to_be_bytes());
            hello.push(0);
            let mut ext = Vec::new();
            if self.ems {
                ext.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
            }
            ext.extend_from_slice(&[0x00, 0x10, 0x00, 0x0b, 0x00, 0x09, 0x08]);
            ext.extend_from_slice(b"http/1.1");
            hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
            hello.extend_from_slice(&ext);
            let hello = hs_message(2, &hello);

            let mut cert = Vec::new();
            cert.extend_from_slice(&(ANCHOR.len() as u32).to_be_bytes()[1..]);
            cert.extend_from_slice(ANCHOR);
            let mut chain = Vec::new();
            chain.extend_from_slice(&(cert.len() as u32).to_be_bytes()[1..]);
            chain.extend_from_slice(&cert);
            let chain = hs_message(11, &chain);

            let params = {
                let share = self.ephemeral.as_ref().expect("one key exchange");
                let mut params = vec![3];
                params.extend_from_slice(&self.group.to_be_bytes());
                params.push(share.data.len() as u8);
                params.extend_from_slice(&share.data);
                params
            };
            let mut signed = Vec::with_capacity(64 + params.len());
            signed.extend_from_slice(&self.client_random);
            signed.extend_from_slice(&self.server_random);
            signed.extend_from_slice(&params);
            let signature = self.signing.sign(&self.rng, &signed).expect("signs");
            let mut exchange = params;
            exchange.extend_from_slice(&[0x04, 0x03]);
            exchange.extend_from_slice(&(signature.as_ref().len() as u16).to_be_bytes());
            exchange.extend_from_slice(signature.as_ref());
            let exchange = hs_message(12, &exchange);
            let request = hs_message(13, &[0x01, 0x40, 0x00, 0x00]);
            let done = hs_message(14, &[]);

            let mut parts: Vec<&[u8]> = vec![&hello, &chain, &exchange];
            if self.ask_cert {
                parts.push(&request);
            }
            parts.push(&done);
            let mut flight = Vec::new();
            for part in parts {
                self.transcript.extend_from_slice(part);
                flight.extend_from_slice(part);
            }
            self.push_record(HANDSHAKE, &flight);
        }

        fn client_key_exchange(&mut self, msg: &[u8]) {
            let mut c = Cursor::new(&msg[4..]);
            let peer = c.vec8().to_vec();
            self.transcript.extend_from_slice(msg);
            let private = self.ephemeral.take().expect("one key exchange");
            let shared = private.agree(&peer).expect("agrees");
            let suite = record::Suite::from_id(self.suite).expect("suite");
            let session_hash = self.ems.then(|| suite.hash().hash(&self.transcript));
            let (master, directions) = crate::tls::shaped::tls12::keys(
                suite,
                &shared,
                &self.client_random,
                &self.server_random,
                session_hash.as_deref(),
            );
            self.read_dir = Some(directions.client);
            self.write_dir = Some(directions.server);
            self.master = master;
        }

        fn client_finished(&mut self, msg: &[u8]) {
            let suite = record::Suite::from_id(self.suite).expect("suite");
            let expected = crate::tls::shaped::tls12::finished(
                suite,
                &self.master,
                b"client finished",
                &self.transcript,
            );
            assert_eq!(
                &msg[4..],
                expected.as_slice(),
                "the client hashed its ClientKeyExchange into the extended master secret"
            );
            self.transcript.extend_from_slice(msg);
            let verify = crate::tls::shaped::tls12::finished(
                suite,
                &self.master,
                b"server finished",
                &self.transcript,
            );
            self.push_record(CCS, &[1]);
            let mut out = Vec::new();
            record::seal12(
                self.write_dir.as_mut().expect("write keys"),
                HANDSHAKE,
                &hs_message(20, &verify),
                &mut out,
            )
            .expect("seals");
            self.feed.extend_from_slice(&out);
        }

        fn push_record(&mut self, kind: u8, body: &[u8]) {
            self.feed.push(kind);
            self.feed.extend_from_slice(&[0x03, 0x03]);
            self.feed
                .extend_from_slice(&(body.len() as u16).to_be_bytes());
            self.feed.extend_from_slice(body);
        }
    }

    impl std::io::Read for Tls12Server {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.feed.len().min(buf.len());
            buf[..n].copy_from_slice(&self.feed[..n]);
            self.feed.drain(..n);
            Ok(n)
        }
    }

    impl std::io::Write for Tls12Server {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.pending.extend_from_slice(buf);
            self.process();
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Frames one handshake message the way the shaped client's parser expects it.
    fn hs_message(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + body.len());
        out.push(kind);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        out.extend_from_slice(body);
        out
    }

    /// The fixture's own reader: the shaped client's is private to its module.
    struct Cursor<'a> {
        bytes: &'a [u8],
        at: usize,
    }

    impl<'a> Cursor<'a> {
        fn new(bytes: &'a [u8]) -> Self {
            Self { bytes, at: 0 }
        }

        fn take(&mut self, n: usize) -> &'a [u8] {
            let end = self.at + n;
            assert!(end <= self.bytes.len(), "truncated handshake");
            let out = &self.bytes[self.at..end];
            self.at = end;
            out
        }

        fn u8(&mut self) -> u8 {
            self.take(1)[0]
        }

        fn u16(&mut self) -> u16 {
            let bytes = self.take(2);
            u16::from_be_bytes([bytes[0], bytes[1]])
        }

        fn vec8(&mut self) -> &'a [u8] {
            let len = usize::from(self.u8());
            self.take(len)
        }

        fn vec16(&mut self) -> &'a [u8] {
            let len = usize::from(self.u16());
            self.take(len)
        }
    }

    /// One shaped dial per TLS 1.2 record shape — an AEAD, a CBC block, an RC4 stream — each relayed
    /// one frame both ways. The RC4 preset carries no `key_share`, so its point is drawn at the
    /// curve the `ServerKeyExchange` names, from that hello's `supported_groups`, and the CBC dial
    /// also asks for a client certificate, which the walk answers with an empty one.
    #[cfg_attr(miri, ignore = "assembles real handshake bytes through ring")]
    #[test]
    fn a_shaped_dial_finishes_every_tls12_record_shape() {
        let shapes = [
            ("chrome", 0xc02bu16, keys::X25519, false),
            ("helloios_13", 0xc009, keys::X25519, true),
            ("360", 0xc007, keys::P256, false),
        ];
        for (preset, suite, group, ask_cert) in shapes {
            let mut cfg = client("tls.test", &[]);
            cfg.fingerprint =
                Some(crate::tls::Fingerprint::resolve(preset).expect("a preset name"));
            let mut session = crate::tls::shaped::Session::connect(
                &cfg,
                Tls12Server::new(suite, group, ask_cert),
            )
            .unwrap_or_else(|e| panic!("{preset} at {suite:#06x}: {e}"));
            session
                .handshake()
                .unwrap_or_else(|e| panic!("{preset} at {suite:#06x} did not finish: {e}"));
            assert_eq!(session.alpn(), Some(b"http/1.1".as_slice()));
            assert_eq!(session.peer_leaf(), Some(ANCHOR));
            session.write_all(b"ping").expect("writes");
            session.flush().expect("flushes");
            let mut buf = [0u8; 4];
            session
                .read_exact(&mut buf)
                .unwrap_or_else(|e| panic!("{preset} at {suite:#06x} could not open a frame: {e}"));
            assert_eq!(&buf, b"ping", "one frame each way behind {suite:#06x}");
        }
    }

    /// One shaped listener and one shaped dial over a pair of queues, so a poll quantum can be
    /// injected on either side of the listener's handshake without a socket.
    struct Wire {
        to_server: std::rc::Rc<std::cell::RefCell<Vec<u8>>>,
        to_client: std::rc::Rc<std::cell::RefCell<Vec<u8>>>,
        write_budget: std::rc::Rc<std::cell::Cell<Option<usize>>>,
        read_budget: std::rc::Rc<std::cell::Cell<Option<usize>>>,
        fired: std::rc::Rc<std::cell::Cell<bool>>,
    }

    impl Read for Wire {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let mut queued = self.to_server.borrow_mut();
            if queued.is_empty() {
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            let mut take = queued.len().min(buf.len());
            if let Some(left) = self.read_budget.get() {
                if left == 0 {
                    self.read_budget.set(None);
                    self.fired.set(true);
                    return Err(std::io::ErrorKind::WouldBlock.into());
                }
                take = take.min(left);
                self.read_budget.set(Some(left - take));
            }
            buf[..take].copy_from_slice(&queued[..take]);
            queued.drain(..take);
            Ok(take)
        }
    }

    impl Write for Wire {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut take = buf.len();
            if let Some(left) = self.write_budget.get() {
                if left == 0 {
                    self.write_budget.set(None);
                    self.fired.set(true);
                    return Err(std::io::ErrorKind::WouldBlock.into());
                }
                take = take.min(left);
                self.write_budget.set(Some(left - take));
            }
            self.to_client.borrow_mut().extend_from_slice(&buf[..take]);
            Ok(take)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct ClientWire {
        to_server: std::rc::Rc<std::cell::RefCell<Vec<u8>>>,
        to_client: std::rc::Rc<std::cell::RefCell<Vec<u8>>>,
        server: crate::tls::shaped::server::Server<Wire>,
    }

    impl ClientWire {
        fn drive(&mut self) {
            let _ = self.server.handshake();
        }
    }

    impl Read for ClientWire {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let to_client = std::rc::Rc::clone(&self.to_client);
            if to_client.borrow().is_empty() {
                self.drive();
            }
            let mut queued = to_client.borrow_mut();
            if queued.is_empty() {
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            let take = queued.len().min(buf.len());
            buf[..take].copy_from_slice(&queued[..take]);
            queued.drain(..take);
            Ok(take)
        }
    }

    impl Write for ClientWire {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.to_server.borrow_mut().extend_from_slice(buf);
            self.drive();
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn shaped_listener() -> crate::tls::TlsServerConfig {
        crate::tls::TlsServerConfig {
            certs: vec![crate::tls::CertEntry {
                cert_chain: vec![ANCHOR.to_vec()],
                key_der: ANCHOR_KEY.to_vec(),
                key_kind: crate::tls::ServerKeyKind::Pkcs8,
                reload: None,
                ocsp: None,
            }],
            alpn: Vec::new(),
            min_version: None,
            max_version: None,
            cipher_suites: vec![0xc02b],
            curves: Vec::new(),
            send_tickets: false,
            reject_unknown_sni: false,
            server_config_cache: std::sync::Arc::default(),
            ech_server_keys: None,
            master_key_log: None,
            kernel_tx: false,
            kernel_rx: false,
        }
    }

    fn shaped_dial(
        write: Option<usize>,
        read: Option<usize>,
    ) -> (ClientWire, std::rc::Rc<std::cell::Cell<bool>>) {
        let to_server = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let to_client = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let write_budget = std::rc::Rc::new(std::cell::Cell::new(write));
        let read_budget = std::rc::Rc::new(std::cell::Cell::new(read));
        let fired = std::rc::Rc::new(std::cell::Cell::new(false));
        let wire = Wire {
            to_server: std::rc::Rc::clone(&to_server),
            to_client: std::rc::Rc::clone(&to_client),
            write_budget: std::rc::Rc::clone(&write_budget),
            read_budget: std::rc::Rc::clone(&read_budget),
            fired: std::rc::Rc::clone(&fired),
        };
        let server = crate::tls::shaped::server::Server::new(shaped_listener(), wire);
        let client = ClientWire {
            to_server,
            to_client,
            server,
        };
        (client, fired)
    }

    fn shaped_session(client: ClientWire) -> crate::tls::shaped::Session<ClientWire> {
        let mut cfg = shaped_client_config();
        cfg.fingerprint = Some(crate::tls::Fingerprint::resolve("chrome").expect("chrome"));
        crate::tls::shaped::Session::connect(&cfg, client).expect("connects")
    }

    fn shaped_client_config() -> TlsConfig {
        client("tls.test", &[])
    }

    #[cfg_attr(miri, ignore = "assembles real handshake bytes through ring")]
    #[test]
    fn a_shaped_handshake_resumes_after_a_partial_flight_write() {
        let (client, fired) = shaped_dial(Some(20), None);
        let mut session = shaped_session(client);
        session
            .handshake()
            .expect("resumes after the write timeout");
        assert!(fired.get(), "the write budget must have fired");
        assert_eq!(session.peer_leaf(), Some(ANCHOR));
    }

    /// A stapling shaped listener answers a shaped client: the `CertificateStatus` between the
    /// chain and the exchange is consumed, not read as unexpected.
    #[cfg_attr(miri, ignore = "assembles real handshake bytes through ring")]
    #[test]
    fn a_shaped_client_consumes_a_stapled_chains_status() {
        let to_server = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let to_client = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let wire = Wire {
            to_server: std::rc::Rc::clone(&to_server),
            to_client: std::rc::Rc::clone(&to_client),
            write_budget: std::rc::Rc::new(std::cell::Cell::new(None)),
            read_budget: std::rc::Rc::new(std::cell::Cell::new(None)),
            fired: std::rc::Rc::new(std::cell::Cell::new(false)),
        };
        let mut listener = shaped_listener();
        listener.certs[0].ocsp = Some(garbage_staple());
        let server = crate::tls::shaped::server::Server::new(listener, wire);
        let client = ClientWire {
            to_server,
            to_client,
            server,
        };
        let mut session = shaped_session(client);
        session
            .handshake()
            .expect("consumes the certificate status");
        assert_eq!(session.peer_leaf(), Some(ANCHOR));
    }

    #[cfg_attr(miri, ignore = "assembles real handshake bytes through ring")]
    #[test]
    fn a_shaped_handshake_resumes_after_a_partial_flight_read() {
        let (client, fired) = shaped_dial(None, Some(10));
        // The first read the listener makes is the ClientHello; stop it mid-record.
        let mut session = shaped_session(client);
        session.handshake().expect("resumes after the read timeout");
        assert!(fired.get(), "the read budget must have fired");
        assert_eq!(session.peer_leaf(), Some(ANCHOR));
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn handshake_connects_and_echoes() {
        case(|stream| {
            let mut client = crate::tls::connect(&client("tls.test", &[b"test-only"]), stream)
                .expect("configures");
            client.handshake().expect("handshakes");
            assert_eq!(client.alpn(), Some(b"test-only".as_slice()));
            assert!(client.suites().len() > 1);
            client.write_all(b"ping").expect("writes");
            client.flush().expect("flushes");
            let mut buf = [0u8; 4];
            client.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
        });
    }

    /// Parsing an anchor and building a verifier is work a config names, not a connection needs: two dials naming the same anchors, pins and suite order share one build, and any input that differs gets its own.
    #[test]
    fn the_parts_a_config_is_built_from_are_built_once() {
        let built = material(&client("one.test", &[b"test-only"])).expect("builds");
        let other_name = material(&client("two.test", &[b"nope"])).expect("builds");
        assert!(
            Arc::ptr_eq(&built, &other_name),
            "a new host or ALPN asks for no new anchors"
        );

        let mut pinned = client("one.test", &[b"test-only"]);
        pinned.pins = crate::foxy::pin::Pins::parse([
            "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
        ]);
        let with_pin = material(&pinned).expect("builds");
        assert!(
            !Arc::ptr_eq(&built, &with_pin),
            "a pinned verifier is not an unpinned one"
        );

        let mut reordered = client("one.test", &[b"test-only"]);
        reordered.cipher_suites = vec![0x1302].into();
        let other_order = material(&reordered).expect("builds");
        assert!(
            !Arc::ptr_eq(&built, &other_order),
            "a named suite order is a different provider"
        );

        let mut no_anchor = client("one.test", &[b"test-only"]);
        no_anchor.roots = Vec::new().into();
        let empty = material(&no_anchor).expect("builds");
        assert!(
            !Arc::ptr_eq(&built, &empty),
            "a dial that names no anchor stores a different store"
        );
    }

    /// A material built for an insecure config has no verifier, so a later secure caller naming the same anchors and names must not reuse it: the key carries the mode that decided whether the verifier exists.
    #[test]
    fn an_insecure_material_does_not_stand_in_for_a_named_secure_one() {
        let mut insecure = client("connection.test", &[b"test-only"]);
        insecure.verify_names = std::sync::Arc::from(["cache-mode.test".to_owned()]);
        insecure.insecure = true;
        let mut secure = insecure.clone();
        secure.insecure = false;

        let unchecked = material(&insecure).expect("builds");
        let checked = material(&secure).expect("builds");
        assert!(
            unchecked.verifier.is_none(),
            "an insecure config checks no name"
        );
        assert!(
            checked.verifier.is_some(),
            "a secure config keeps its configured names when an insecure config built first"
        );
    }

    /// A repeat dial asks the config cache with the suite order it already named: the key must share that list rather than copy it, so a hit costs no heap buffer.
    #[test]
    fn a_repeat_dial_keys_the_config_without_copying_the_suite_order() {
        let mut cfg = client("one.test", &[b"test-only"]);
        cfg.cipher_suites = vec![0x1302, 0x1301, 0x1303].into();
        let first = client_config(&cfg).expect("first config builds");
        let (again, counts) =
            crate::alloc_count::measure(|| client_config(&cfg).expect("repeat config builds"));
        assert!(Arc::ptr_eq(&first, &again), "the repeat dial hit the cache");
        assert_eq!(
            counts.allocs, 0,
            "the key shares the suite order: {counts:?}"
        );
    }

    /// The shared parts do not invent a shared server: a ticket one listener left is unknown to the other, so the second dial here is handed a chain again — two listeners, not one edge, is what this shape keeps true.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_second_dial_with_the_same_config_still_fetches_the_chain() {
        let cfg = client("tls.test", &[b"test-only"]);
        twice(|first, second| {
            let mut echo = [0u8; 4];
            let mut a = crate::tls::connect(&cfg, first).expect("first configures");
            a.handshake().expect("handshakes");
            a.write_all(b"ping").expect("writes");
            a.flush().expect("flushes");
            a.read_exact(&mut echo).expect("echoes");
            let mut b = crate::tls::connect(&cfg, second).expect("second configures");
            b.handshake().expect("handshakes");
            b.write_all(b"ping").expect("writes");
            b.flush().expect("flushes");
            b.read_exact(&mut echo).expect("echoes");
            assert!(
                a.peer_leaf().is_some() && b.peer_leaf().is_some(),
                "both dials were handed a chain, so neither rode the other's session"
            );
        });
    }

    /// The test edge: a chain both dials trust, and a ticket maker that keeps nothing between them.
    fn edge_config() -> rustls::ServerConfig {
        let cert = rustls::pki_types::CertificateDer::from(ANCHOR.to_vec());
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(ANCHOR_KEY.to_vec()),
        );
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("server versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server cert");
        config.alpn_protocols = vec![b"test-only".to_vec()];
        // A builder's config tickets statefully through one shared store, and `take` spends a stored session at first use, so the second dial's offer would already be consumed: a stateless ticketer carries the secret inside the ticket itself.
        config.ticketer = rustls::crypto::ring::Ticketer::new().expect("edge ticketer");
        config
    }

    /// One dial to the edge on a config the caller holds: both dials of the resumption witness must ride one `Arc`, which is what rustls compares for its verifier and its store.
    fn dial(
        config: &Arc<rustls::ClientConfig>,
        name: &rustls::pki_types::ServerName<'static>,
        port: u16,
    ) -> RustlsProvider<TcpStream> {
        let io = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let mut tls = RustlsProvider::<TcpStream>::from_connection(
            rustls::ClientConnection::new(Arc::clone(config), name.clone()).expect("session"),
            io,
        );
        tls.handshake().expect("handshakes");
        tls.write_all(b"ping").expect("writes");
        tls.read_exact(&mut [0u8; 4]).expect("echoes");
        tls
    }

    /// One edge, two dials: a resumed TLS 1.3 handshake carries no certificate, which rustls reports as `HandshakeKind::Resumed` while still handing the session its cached chain.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn the_second_dial_to_one_edge_resumes() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            // One ticket maker behind both accepts: only this listener can open the ticket the first dial left.
            let config = Arc::new(edge_config());
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("accepts");
                let mut conn =
                    rustls::ServerConnection::new(Arc::clone(&config)).expect("server session");
                let mut tls = rustls::Stream::new(&mut conn, &mut stream);
                let mut buf = [0u8; 4];
                if tls.read_exact(&mut buf).is_ok() {
                    let _ = tls.write_all(&buf);
                }
            }
        });
        // "localhost" rather than the shared "tls.test": the session store keys on the name, and a ticket a parallel test's listener left would be handed to this second dial.
        let mut cfg = client("localhost", &[b"test-only"]);
        // A config that names no store keeps no ticket, so this witness has to name one.
        cfg.resumption = true;
        // Both dials ride one cached config: rustls gates resumption on the verifier and store a config holds, so a cache miss here sinks the whole witness.
        let kept = client_config(&cfg).expect("first config builds");
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("a dns name");
        let a = dial(&kept, &name, port);
        assert_eq!(
            a.handshake_kind(),
            Some(rustls::HandshakeKind::Full),
            "the first dial had no ticket to offer"
        );
        assert!(a.peer_leaf().is_some(), "the first dial verified a chain");
        // The stock rustls server hands more than one ticket per session: the witness is that the first dial left the config's own store with one to lend.
        assert!(a.tls13_tickets() >= 1, "the first dial was handed a ticket");
        // A parallel suite could push the config cache to its cap between the dials; if this lapsed, the miss below is eviction's, not the resume path's.
        assert!(
            Arc::ptr_eq(
                &kept,
                &client_config(&cfg).expect("config after the first dial")
            ),
            "the cache held the first dial's config across that dial"
        );
        drop(a);
        let b = dial(&kept, &name, port);
        assert_eq!(
            b.handshake_kind(),
            Some(rustls::HandshakeKind::Resumed),
            "the second dial carried no chain: it resumed"
        );
        assert!(
            b.peer_leaf().is_some(),
            "a resumed session keeps the chain it cached"
        );
        drop(b);
        server.join().expect("joins");
    }

    /// A client that names a store rides the ticket a served stream hands out: the reference's Go server tickets by default, so a served edge here must hand one out too.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_served_stream_hands_a_ticket_the_next_dial_rides() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            // One identity behind both accepts: a listener rebuilds nothing between streams, so the ticket the first hands out must open on the second.
            let identity = plain_identity();
            for _ in 0..2 {
                let (stream, _) = listener.accept().expect("accepts");
                let mut served = crate::tls::accept(&identity, stream).expect("serves");
                served.handshake().expect("served handshake");
                let mut buf = [0u8; 4];
                if served.read_exact(&mut buf).is_ok() {
                    let _ = served.write_all(&buf);
                }
            }
        });
        let mut cfg = client("localhost", &[b"test-only"]);
        cfg.resumption = true;
        let kept = client_config(&cfg).expect("first config builds");
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("a dns name");
        let a = dial(&kept, &name, port);
        assert_eq!(
            a.handshake_kind(),
            Some(rustls::HandshakeKind::Full),
            "the first dial had no ticket to offer"
        );
        assert!(a.tls13_tickets() >= 1, "the served stream handed a ticket");
        drop(a);
        let b = dial(&kept, &name, port);
        assert_eq!(
            b.handshake_kind(),
            Some(rustls::HandshakeKind::Resumed),
            "the listener's ticket let the second dial skip the chain"
        );
        drop(b);
        server.join().expect("joins");
    }

    /// A config that names no resumption keeps no ticket even against a listener that hands one out, which is the reference's default.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_config_that_names_no_resumption_keeps_no_ticket() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let identity = plain_identity();
            for _ in 0..2 {
                let (stream, _) = listener.accept().expect("accepts");
                let mut served = crate::tls::accept(&identity, stream).expect("serves");
                served.handshake().expect("served handshake");
                let mut buf = [0u8; 4];
                if served.read_exact(&mut buf).is_ok() {
                    let _ = served.write_all(&buf);
                }
            }
        });
        let cfg = client("localhost", &[b"test-only"]);
        let kept = client_config(&cfg).expect("first config builds");
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("a dns name");
        let a = dial(&kept, &name, port);
        assert!(a.tls13_tickets() >= 1, "the listener offered a ticket");
        drop(a);
        let b = dial(&kept, &name, port);
        assert_eq!(
            b.handshake_kind(),
            Some(rustls::HandshakeKind::Full),
            "a config that names no resumption carries no ticket"
        );
        drop(b);
        server.join().expect("joins");
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn mismatched_certificate_name_fails() {
        case(|stream| {
            let mut client = crate::tls::connect(&client("wrong.test", &[b"test-only"]), stream)
                .expect("configures");
            let err = client.handshake().expect_err("wrong name must fail");
            // The kind carries the why: a caller matches a certificate refusal without losing which certificate problem it is.
            let TlsError::BadCertificate(why) = &err else {
                panic!("a name mismatch is a certificate refusal, not {err}");
            };
            assert!(why.contains("NotValidForName"), "{why}");
        });
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn refused_alpn_fails() {
        case(|stream| {
            let mut client =
                crate::tls::connect(&client("tls.test", &[b"nope"]), stream).expect("configures");
            let err = client.handshake().expect_err("refused ALPN must fail");
            assert!(
                matches!(err, TlsError::NoSharedCipher),
                "refused ALPN mapped to {err:?}"
            );
        });
    }

    fn anchor_pem(label: &str, der: &[u8]) -> Vec<u8> {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut body = String::new();
        for chunk in der.chunks(3) {
            let mut word = 0u32;
            for &byte in chunk {
                word = (word << 8) | u32::from(byte);
            }
            word <<= 8 * (3 - chunk.len());
            for i in 0..=chunk.len() {
                body.push(TABLE[((word >> (18 - 6 * i)) & 0x3F) as usize] as char);
            }
            for _ in chunk.len() + 1..4 {
                body.push('=');
            }
        }
        let mut pem = format!("-----BEGIN {label}-----\n");
        for line in body.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).expect("base64 is ascii"));
            pem.push('\n');
        }
        pem.push_str("-----END ");
        pem.push_str(label);
        pem.push_str("-----\n");
        pem.into_bytes()
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn server_accepts_through_the_interface_and_echoes() {
        let cert_pem = anchor_pem("CERTIFICATE", ANCHOR);
        let key_pem = anchor_pem("PRIVATE KEY", ANCHOR_KEY);
        let identity = crate::tls::parse_pem_identity(&cert_pem, &key_pem).expect("parses");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(|| {
                let (stream, _) = listener.accept().expect("accepts");
                let mut server = crate::tls::accept(&identity, stream).expect("accepts");
                server.handshake().expect("handshakes");
                assert_eq!(server.alpn(), None);
                let mut buf = [0u8; 4];
                server.read_exact(&mut buf).expect("reads");
                server.write_all(&buf).expect("writes");
                server.flush().expect("flushes");
            });
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let mut client =
                crate::tls::connect(&client("tls.test", &[]), stream).expect("configures");
            client.handshake().expect("handshakes");
            client.write_all(b"ping").expect("writes");
            client.flush().expect("flushes");
            let mut buf = [0u8; 4];
            client.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
        });
    }

    #[test]
    fn an_sni_matches_an_exact_or_one_label_wildcard_name() {
        let names = vec!["tls.test".to_owned(), "*.wild.test".to_owned()];
        assert!(sni_matches(&names, "tls.test"));
        assert!(sni_matches(&names, "TLS.TEST"));
        assert!(sni_matches(&names, "a.wild.test"));
        assert!(!sni_matches(&names, "a.b.wild.test"));
        assert!(!sni_matches(&names, "other.test"));
    }

    /// The kernel path is the only place a kTLS claim can be observed: both directions
    /// leave userspace, and the bytes still reach the peer and come back.
    #[cfg(target_os = "linux")]
    #[cfg_attr(miri, ignore = "needs the Linux kernel TLS interface")]
    #[test]
    fn a_ktls_loopback_carries_both_directions() {
        use std::os::fd::AsRawFd as _;

        let mut identity = plain_identity();
        identity.kernel_tx = true;
        identity.kernel_rx = true;
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(|| {
                let (stream, _) = listener.accept().expect("accepts");
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                    .expect("timeout");
                let mut server = RustlsServerProvider::accept(identity, stream).expect("accepts");
                server.handshake().expect("handshakes");
                server
                    .enable_ktls(server.get_ref().as_raw_fd())
                    .expect("the server hands both directions to the kernel");
                let mut ping = [0u8; 4];
                server
                    .read_exact(&mut ping)
                    .expect("reads the kernel plaintext");
                server.write_all(&ping).expect("writes through the kernel");
            });
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .expect("timeout");
            let mut cfg = client("tls.test", &[]);
            cfg.kernel_tx = true;
            cfg.kernel_rx = true;
            let mut client = RustlsProvider::connect(&cfg, stream).expect("connects");
            client.handshake().expect("handshakes");
            client
                .enable_ktls(client.get_ref().as_raw_fd())
                .expect("the client hands both directions to the kernel");
            client
                .write_all(b"ping")
                .expect("writes through the kernel");
            let mut back = [0u8; 4];
            client
                .read_exact(&mut back)
                .expect("reads the kernel plaintext");
            assert_eq!(&back, b"ping");
        });
    }

    fn plain_identity() -> crate::tls::TlsServerConfig {
        let cert_pem = anchor_pem("CERTIFICATE", ANCHOR);
        let key_pem = anchor_pem("PRIVATE KEY", ANCHOR_KEY);
        crate::tls::parse_pem_identity(&cert_pem, &key_pem).expect("parses")
    }

    fn stock_client_with(
        versions: &[&'static rustls::SupportedProtocolVersion],
        provider: rustls::crypto::CryptoProvider,
    ) -> rustls::ClientConfig {
        let mut roots = RootStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(ANCHOR.to_vec()))
            .expect("anchor");
        rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(versions)
            .expect("client versions")
            .with_root_certificates(roots)
            .with_no_client_auth()
    }

    fn stock_client(
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> rustls::ClientConfig {
        stock_client_with(versions, rustls::crypto::ring::default_provider())
    }

    fn stock_session(config: rustls::ClientConfig) -> rustls::ClientConnection {
        rustls::ClientConnection::new(
            Arc::new(config),
            rustls::pki_types::ServerName::try_from("tls.test").expect("name"),
        )
        .expect("client session")
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_tls_ceiling_refuses_a_newer_client() {
        let mut identity = plain_identity();
        identity.max_version = Some(0x0303);
        let server_config = identity.server_config().expect("server config");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(|| {
                let (mut stream, _) = listener.accept().expect("accepts");
                let mut server = rustls::ServerConnection::new(server_config).expect("session");
                let _ = server.complete_io(&mut stream);
            });
            let mut client = stock_session(stock_client(&[&rustls::version::TLS13]));
            let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            assert!(
                client.complete_io(&mut stream).is_err(),
                "a listener with maxVersion 1.2 must refuse a TLS 1.3 client"
            );
        });
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_client_version_ceiling_refuses_a_newer_listener() {
        let mut identity = plain_identity();
        identity.min_version = Some(0x0304);
        let server_config = identity.server_config().expect("server config");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(|| {
                let (mut stream, _) = listener.accept().expect("accepts");
                let mut server = rustls::ServerConnection::new(server_config).expect("session");
                let _ = server.complete_io(&mut stream);
            });
            let mut cfg = client("tls.test", &[]);
            cfg.max_version = Some(0x0303);
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let mut session = crate::tls::connect(&cfg, stream).expect("dials");
            assert!(
                session.handshake().is_err(),
                "a client with maxVersion 1.2 must refuse a TLS 1.3 listener"
            );
        });
    }

    #[test]
    fn a_configured_server_curve_orders_the_listener_provider() {
        let mut identity = plain_identity();
        identity.curves = vec![0x0017];
        let config = identity.server_config().expect("server config");
        let groups: Vec<u16> = config
            .crypto_provider()
            .kx_groups
            .iter()
            .map(|group| u16::from(group.name()))
            .collect();
        assert_eq!(groups, vec![0x0017], "the named curve is the only group");
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_tls_floor_and_suite_reach_the_negotiation() {
        let mut identity = plain_identity();
        identity.min_version = Some(0x0303);
        identity.max_version = Some(0x0303);
        identity.cipher_suites = vec![0xc02b];
        let server_config = identity.server_config().expect("server config");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(|| {
                let (mut stream, _) = listener.accept().expect("accepts");
                let mut server = rustls::ServerConnection::new(server_config).expect("session");
                server.complete_io(&mut stream).expect("handshakes");
            });
            let mut provider = rustls::crypto::ring::default_provider();
            provider
                .cipher_suites
                .retain(|suite| u16::from(suite.suite()) == 0xc02b);
            let mut client = stock_session(stock_client_with(&[&rustls::version::TLS12], provider));
            let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            client.complete_io(&mut stream).expect("handshakes");
            assert_eq!(
                client.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_2),
                "a minVersion 1.2 listener accepts a TLS 1.2 client"
            );
            assert_eq!(
                client.negotiated_cipher_suite().map(|suite| suite.suite()),
                Some(rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
                "the configured suite is the one negotiated"
            );
        });
    }

    fn garbage_staple() -> crate::tls::OcspStaple {
        crate::tls::OcspStaple {
            interval: std::time::Duration::from_secs(7),
            response: Some(b"not an OCSP response".to_vec()),
        }
    }

    /// The control the three staple tests share: no `ocspStapling` answers a stock client.
    #[cfg_attr(miri, ignore = "needs a loopback socket")]
    #[test]
    fn an_unstapled_identity_answers_a_stock_client() {
        let identity = plain_identity();
        let server_config = identity.server_config().expect("server config");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(|| {
                let (mut stream, _) = listener.accept().expect("accepts");
                let mut server = rustls::ServerConnection::new(server_config).expect("session");
                server.complete_io(&mut stream).expect("handshakes");
            });
            let mut client = stock_session(stock_client(&[&rustls::version::TLS13]));
            let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            client.complete_io(&mut stream).expect("handshakes");
        });
    }

    /// A verifier that reports the OCSP response the server sent: the staple's own witness,
    /// since the stock webpki verifier traces it without checking its bytes.
    #[derive(Debug)]
    struct StapleWitness {
        inner: Arc<dyn rustls::client::danger::ServerCertVerifier>,
        seen: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    }

    impl rustls::client::danger::ServerCertVerifier for StapleWitness {
        fn verify_server_cert(
            &self,
            end_entity: &rustls::pki_types::CertificateDer<'_>,
            intermediates: &[rustls::pki_types::CertificateDer<'_>],
            server_name: &rustls::pki_types::ServerName<'_>,
            ocsp_response: &[u8],
            now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            *self.seen.lock().expect("witness") = Some(ocsp_response.to_vec());
            self.inner.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            self.inner.verify_tls12_signature(message, cert, dss)
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            self.inner.verify_tls13_signature(message, cert, dss)
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.inner.supported_verify_schemes()
        }
    }

    /// A stapled identity answers with `CertificateStatus`: the witness reports the bytes.
    #[cfg_attr(miri, ignore = "needs a loopback socket")]
    #[test]
    fn a_stapled_identity_reaches_the_client_and_is_checked() {
        let mut identity = plain_identity();
        identity.certs[0].ocsp = Some(garbage_staple());
        let server_config = identity.server_config().expect("server config");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let seen = Arc::new(std::sync::Mutex::new(None));
        let seen_later = Arc::clone(&seen);
        thread::scope(|scope| {
            scope.spawn(|| {
                let (mut stream, _) = listener.accept().expect("accepts");
                let mut server = rustls::ServerConnection::new(server_config).expect("session");
                server.complete_io(&mut stream).expect("handshakes");
            });
            let mut roots = RootStore::empty();
            roots
                .add(rustls::pki_types::CertificateDer::from(ANCHOR.to_vec()))
                .expect("anchor");
            let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
                rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
                    .build()
                    .expect("verifier")
                    as Arc<dyn rustls::client::danger::ServerCertVerifier>;
            let mut anchor_roots = RootStore::empty();
            anchor_roots
                .add(rustls::pki_types::CertificateDer::from(ANCHOR.to_vec()))
                .expect("anchor");
            let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("client versions")
            .with_root_certificates(anchor_roots)
            .with_no_client_auth();
            client_config
                .dangerous()
                .set_certificate_verifier(Arc::new(StapleWitness {
                    inner: verifier,
                    seen: seen_later,
                }));
            let mut client = rustls::ClientConnection::new(
                Arc::new(client_config),
                rustls::pki_types::ServerName::try_from("tls.test").expect("name"),
            )
            .expect("client session");
            let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            client.complete_io(&mut stream).expect("handshakes");
        });
        assert_eq!(
            seen.lock().expect("witness").as_deref(),
            Some(&b"not an OCSP response"[..]),
            "the client saw the staple the server sent"
        );
    }

    /// One stock client that reports whatever OCSP response the server sends.
    fn witness_session(seen: Arc<std::sync::Mutex<Option<Vec<u8>>>>) -> rustls::ClientConnection {
        let mut roots = RootStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(ANCHOR.to_vec()))
            .expect("anchor");
        let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
            rustls::client::WebPkiServerVerifier::builder(Arc::new(roots.clone()))
                .build()
                .expect("verifier")
                as Arc<dyn rustls::client::danger::ServerCertVerifier>;
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("client versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(StapleWitness {
                inner: verifier,
                seen,
            }));
        rustls::ClientConnection::new(
            Arc::new(config),
            rustls::pki_types::ServerName::try_from("tls.test").expect("name"),
        )
        .expect("client session")
    }

    /// The shaped TLS 1.2 listener answers with the same status after its chain, and the
    /// witness reports the bytes it sent.
    #[cfg_attr(miri, ignore = "needs a loopback socket")]
    #[test]
    fn a_shaped_listener_staples_and_a_stock_tls12_client_checks_it() {
        let mut identity = plain_identity();
        identity.certs[0].ocsp = Some(garbage_staple());
        identity.max_version = Some(0x0303);
        identity.cipher_suites = vec![0xc02b, 0x1301];
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let seen = Arc::new(std::sync::Mutex::new(None));
        let seen_later = Arc::clone(&seen);
        thread::scope(|scope| {
            scope.spawn(move || {
                let (stream, _) = listener.accept().expect("accepts");
                let mut server = RustlsServerProvider::accept(identity, stream).expect("settles");
                let _ = server.handshake();
            });
            let mut client = witness_session(seen_later);
            let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            client.complete_io(&mut stream).expect("handshakes");
        });
        assert_eq!(
            seen.lock().expect("witness").as_deref(),
            Some(&b"not an OCSP response"[..]),
            "the shaped staple reached the client verbatim"
        );
    }

    /// The legacy listener answers through its own context, and its staple reaches a stock
    /// client the same way.
    #[cfg_attr(miri, ignore = "needs a loopback socket")]
    #[test]
    fn a_legacy_listener_staples_and_a_boring_client_reads_it() {
        let mut identity = plain_identity();
        identity.certs[0].ocsp = Some(garbage_staple());
        identity.cipher_suites = vec![0xc009];
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(move || {
                let (stream, _) = listener.accept().expect("accepts");
                let mut server = RustlsServerProvider::accept(identity, stream).expect("settles");
                let _ = server.handshake();
            });
            let mut config = client("tls.test", &[]);
            config.cipher_suites = vec![0xc009].into();
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let mut session = crate::tls::connect(&config, stream).expect("dials");
            session.handshake().expect("handshakes");
            assert_eq!(
                session.peer_ocsp(),
                Some(&b"not an OCSP response"[..]),
                "the legacy staple reached the client verbatim"
            );
        });
    }

    /// The other role of the field: a dial naming a TLS 1.2 AEAD suite negotiates it against a listener admitting only that suite.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_tls12_dial_negotiates_the_configured_suite() {
        let mut identity = plain_identity();
        identity.min_version = Some(0x0303);
        identity.max_version = Some(0x0303);
        identity.cipher_suites = vec![0xc02b];
        let server_config = identity.server_config().expect("server config");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(|| {
                let (mut stream, _) = listener.accept().expect("accepts");
                let mut server = rustls::ServerConnection::new(server_config).expect("session");
                server.complete_io(&mut stream).expect("handshakes");
                assert_eq!(
                    server.protocol_version(),
                    Some(rustls::ProtocolVersion::TLSv1_2),
                    "the dial dropped to the listener's floor"
                );
                assert_eq!(
                    server.negotiated_cipher_suite().map(|suite| suite.suite()),
                    Some(rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
                    "the suite the dial's config named is the one negotiated"
                );
            });
            let mut cfg = client("tls.test", &[]);
            cfg.cipher_suites = vec![0xc02b].into();
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let mut session = crate::tls::connect(&cfg, stream).expect("dials");
            session.handshake().expect("handshakes");
        });
    }

    /// A self-signed RSA leaf, the identity a static-RSA suite signs under.
    fn rsa_identity() -> crate::tls::CertEntry {
        let key = boring::pkey::PKey::from_rsa(boring::rsa::Rsa::generate(2048).expect("rsa key"))
            .expect("pkey");
        let mut name = boring::x509::X509NameBuilder::new().expect("name");
        name.append_entry_by_nid(boring::nid::Nid::COMMONNAME, "tls.test")
            .expect("common name");
        let name = name.build();
        let mut cert = boring::x509::X509Builder::new().expect("builder");
        cert.set_version(2).expect("version");
        cert.set_subject_name(&name).expect("subject");
        cert.set_issuer_name(&name).expect("issuer");
        cert.set_pubkey(&key).expect("pubkey");
        cert.set_not_before(&boring::asn1::Asn1Time::days_from_now(0).expect("from"))
            .expect("not before");
        cert.set_not_after(&boring::asn1::Asn1Time::days_from_now(30).expect("to"))
            .expect("not after");
        cert.sign(&key, boring::hash::MessageDigest::sha256())
            .expect("signs");
        crate::tls::CertEntry {
            cert_chain: vec![cert.build().to_der().expect("der")],
            key_der: key.private_key_to_der_pkcs8().expect("pkcs8"),
            key_kind: crate::tls::ServerKeyKind::Pkcs8,
            reload: None,
            ocsp: None,
        }
    }

    fn ecdsa_identity() -> crate::tls::CertEntry {
        let group = boring::ec::EcGroup::from_curve_name(boring::nid::Nid::X9_62_PRIME256V1)
            .expect("group");
        let key = boring::ec::EcKey::generate(&group).expect("ec key");
        let key = boring::pkey::PKey::from_ec_key(key).expect("pkey");
        let mut name = boring::x509::X509NameBuilder::new().expect("name");
        name.append_entry_by_nid(boring::nid::Nid::COMMONNAME, "tls.test")
            .expect("common name");
        let name = name.build();
        let mut cert = boring::x509::X509Builder::new().expect("builder");
        cert.set_version(2).expect("version");
        cert.set_subject_name(&name).expect("subject");
        cert.set_issuer_name(&name).expect("issuer");
        cert.set_pubkey(&key).expect("pubkey");
        cert.set_not_before(&boring::asn1::Asn1Time::days_from_now(0).expect("from"))
            .expect("not before");
        cert.set_not_after(&boring::asn1::Asn1Time::days_from_now(30).expect("to"))
            .expect("not after");
        cert.sign(&key, boring::hash::MessageDigest::sha256())
            .expect("signs");
        crate::tls::CertEntry {
            cert_chain: vec![cert.build().to_der().expect("der")],
            key_der: key.private_key_to_der_pkcs8().expect("pkcs8"),
            key_kind: crate::tls::ServerKeyKind::Pkcs8,
            reload: None,
            ocsp: None,
        }
    }

    #[test]
    fn the_legacy_lane_covers_the_cbc_and_static_rsa_ids_ring_has_not() {
        for id in [
            0xc009, 0xc00a, 0xc013, 0xc014, 0xc023, 0xc027, 0x002f, 0x0035, 0x009c, 0x009d, 0x000a,
        ] {
            assert!(crate::tls::legacy::suite_name(id).is_some(), "{id:#06x}");
            assert!(!carries(id), "ring has no suite for {id:#06x}");
            assert!(
                crate::tls::legacy::needed(&[id]),
                "{id:#06x} needs the legacy lane"
            );
        }
        for id in [0x1301, 0xc02b, 0xc02c, 0xcca9, 0xc02f, 0xc030, 0xcca8] {
            assert!(
                !crate::tls::legacy::needed(&[id]),
                "{id:#06x} stays on rustls"
            );
        }
        assert!(
            !crate::tls::legacy::needed(&[]),
            "no list keeps the stock path"
        );
        for id in [0x003c, 0xc012, 0x0005, 0xc007, 0xc011] {
            assert!(crate::tls::legacy::suite_name(id).is_none(), "{id:#06x}");
            assert!(
                !crate::tls::legacy::needed(&[id]),
                "{id:#06x} reaches no lane"
            );
        }
    }

    /// The dial's hello carries the reference's TLS 1.2 field exactly when the list offers no
    /// TLS 1.3: capping `BoringSSL` at 1.2 drops its fixed trio, so nothing precedes the list.
    #[cfg_attr(miri, ignore = "needs a loopback socket")]
    #[test]
    fn a_legacy_dial_offers_the_reference_cipher_ids_in_order() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let capture = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut head = [0u8; 5];
            stream.read_exact(&mut head).expect("record header");
            let len = usize::from(u16::from_be_bytes([head[3], head[4]]));
            let mut record = head.to_vec();
            record.resize(5 + len, 0);
            stream.read_exact(&mut record[5..]).expect("record body");
            record
        });
        let mut cfg = client("tls.test", &[]);
        cfg.cipher_suites = vec![0xc009, 0xc013, 0x002f, 0x0035, 0xc02b].into();
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let mut session = crate::tls::connect(&cfg, stream).expect("dials");
        let _ = session.handshake();
        let record = capture.join().expect("joins");
        let want = crate::tls::cipher_suites::field_bytes(&cfg.cipher_suites);
        assert_eq!(
            hello_cipher_suites(&record),
            want.as_slice(),
            "a TLS 1.2-only list is the reference field byte for byte"
        );
    }

    /// A list naming both halves is neither stock lane's: `BoringSSL` leads with its trio and
    /// rustls appends the TLS 1.2 list before it, so the stock shaped hello writes the derived
    /// field verbatim.
    #[cfg_attr(miri, ignore = "needs a loopback socket")]
    #[test]
    fn a_mixed_list_keeps_the_reference_order_on_the_wire() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let capture = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut head = [0u8; 5];
            stream.read_exact(&mut head).expect("record header");
            let len = usize::from(u16::from_be_bytes([head[3], head[4]]));
            let mut record = head.to_vec();
            record.resize(5 + len, 0);
            stream.read_exact(&mut record[5..]).expect("record body");
            record
        });
        let mut cfg = client("tls.test", &[]);
        cfg.cipher_suites = crate::tls::cipher_suites::hello_ids(
            &crate::tls::cipher_suites::parse(
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            ),
            0x0303,
            0x0304,
            true,
        )
        .into();
        assert_eq!(
            &*cfg.cipher_suites,
            &[0xc02f, 0xc013, 0x1301, 0x1302, 0x1303]
        );
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let mut session = crate::tls::connect(&cfg, stream).expect("dials");
        assert!(
            matches!(&session, crate::tls::ClientSession::Shaped(_)),
            "a mixed list rides the stock shaped hello"
        );
        let _ = session.handshake();
        let record = capture.join().expect("joins");
        let want = crate::tls::cipher_suites::field_bytes(&cfg.cipher_suites);
        assert_eq!(
            hello_cipher_suites(&record),
            want.as_slice(),
            "a mixed list is the reference field byte for byte"
        );
    }

    /// The mixed-list dial rides the shaped stock hello and still finishes a TLS 1.2 handshake
    /// on the CBC id the list carries.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and BoringSSL's assembly behind it"
    )]
    #[test]
    fn a_mixed_list_negotiates_a_tls12_suite() {
        let mut identity = plain_identity();
        identity.min_version = Some(0x0303);
        identity.max_version = Some(0x0303);
        identity.cipher_suites = vec![0xc009];
        let ctx = crate::tls::legacy::server_context(&identity).expect("context");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(|| {
                let (stream, _) = listener.accept().expect("accepts");
                let ssl = boring::ssl::Ssl::new(&ctx).expect("ssl");
                let mut server = ssl.accept(stream).expect("handshakes");
                assert_eq!(
                    server
                        .ssl()
                        .current_cipher()
                        .map(boring::ssl::SslCipherRef::protocol_id),
                    Some(0xc009),
                    "the listener negotiated the mixed list's CBC id"
                );
                let mut buf = [0u8; 4];
                server.read_exact(&mut buf).expect("reads");
                server.write_all(&buf).expect("writes");
                server.flush().expect("flushes");
            });
            let mut cfg = client("tls.test", &[]);
            cfg.cipher_suites = crate::tls::cipher_suites::hello_ids(
                &crate::tls::cipher_suites::parse(
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
                ),
                0x0303,
                0x0304,
                true,
            )
            .into();
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let mut session = crate::tls::connect(&cfg, stream).expect("dials");
            session.handshake().expect("handshakes");
            session.write_all(b"ping").expect("writes");
            session.flush().expect("flushes");
            let mut buf = [0u8; 4];
            session.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
        });
    }

    /// The dial's role: a list naming a CBC suite reaches a listener that admits only that suite.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and BoringSSL's assembly behind it"
    )]
    #[test]
    fn a_legacy_dial_negotiates_a_cbc_suite() {
        let mut identity = plain_identity();
        identity.min_version = Some(0x0303);
        identity.max_version = Some(0x0303);
        identity.cipher_suites = vec![0xc009];
        let ctx = crate::tls::legacy::server_context(&identity).expect("context");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(|| {
                let (stream, _) = listener.accept().expect("accepts");
                let ssl = boring::ssl::Ssl::new(&ctx).expect("ssl");
                let mut server = ssl.accept(stream).expect("handshakes");
                assert_eq!(
                    server
                        .ssl()
                        .current_cipher()
                        .map(boring::ssl::SslCipherRef::protocol_id),
                    Some(0xc009),
                    "the listener negotiated the CBC suite"
                );
                let mut buf = [0u8; 4];
                server.read_exact(&mut buf).expect("reads");
                server.write_all(&buf).expect("writes");
                server.flush().expect("flushes");
            });
            let mut cfg = client("tls.test", &[]);
            cfg.cipher_suites = vec![0xc009].into();
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let mut session = crate::tls::connect(&cfg, stream).expect("dials");
            session.handshake().expect("handshakes");
            session.write_all(b"ping").expect("writes");
            session.flush().expect("flushes");
            let mut buf = [0u8; 4];
            session.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
        });
    }

    /// A named TLS 1.2-only list rides the legacy lane, and `enableSessionResumption` makes the
    /// second dial reuse the session the first one stored.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and BoringSSL's assembly behind it"
    )]
    #[test]
    fn a_legacy_dial_resumes_a_tls12_session() {
        let mut identity = plain_identity();
        identity.min_version = Some(0x0303);
        identity.max_version = Some(0x0303);
        identity.cipher_suites = vec![0xc02b];
        let ctx = crate::tls::legacy::server_context(&identity).expect("context");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(|| {
                for _ in 0..2 {
                    let (stream, _) = listener.accept().expect("accepts");
                    let ssl = boring::ssl::Ssl::new(&ctx).expect("ssl");
                    let mut server = ssl.accept(stream).expect("handshakes");
                    let mut buf = [0u8; 4];
                    server.read_exact(&mut buf).expect("reads");
                    server.write_all(&buf).expect("writes");
                    server.flush().expect("flushes");
                }
            });
            let mut cfg = client("tls.test", &[]);
            cfg.cipher_suites = vec![0xc02b].into();
            cfg.resumption = true;
            let reused = |cfg: &TlsConfig| {
                let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
                let mut session = crate::tls::connect(cfg, stream).expect("dials");
                session.handshake().expect("handshakes");
                session.write_all(b"ping").expect("writes");
                session.flush().expect("flushes");
                let mut buf = [0u8; 4];
                session.read_exact(&mut buf).expect("reads");
                match &session {
                    crate::tls::ClientSession::Legacy(session) => session.session_reused(),
                    _ => panic!("a named TLS 1.2-only list rides the legacy lane"),
                }
            };
            assert!(!reused(&cfg), "the first dial had no session to offer");
            assert!(
                reused(&cfg),
                "the second dial reused the first one's session"
            );
        });
    }

    /// Two hosts with the same material do not share a dial context: the verify callback captures
    /// one name, so a second host must build its own and reject this certificate.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and BoringSSL's assembly behind it"
    )]
    #[test]
    fn a_legacy_context_is_not_shared_across_server_names() {
        let mut identity = plain_identity();
        identity.min_version = Some(0x0303);
        identity.max_version = Some(0x0303);
        identity.cipher_suites = vec![0xc009];
        let ctx = crate::tls::legacy::server_context(&identity).expect("context");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(|| {
                for _ in 0..2 {
                    let Ok((stream, _)) = listener.accept() else {
                        return;
                    };
                    let ssl = boring::ssl::Ssl::new(&ctx).expect("ssl");
                    if let Ok(mut server) = ssl.accept(stream) {
                        let mut buf = [0u8; 4];
                        let _ = server.read(&mut buf);
                    }
                }
            });
            let mut cfg = client("tls.test", &[]);
            cfg.cipher_suites = vec![0xc009].into();
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let mut session = crate::tls::connect(&cfg, stream).expect("dials");
            session.handshake().expect("the matching name verifies");
            drop(session);

            cfg.server_name = "other.test".to_owned();
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let mut session = crate::tls::connect(&cfg, stream).expect("dials");
            assert!(
                session.handshake().is_err(),
                "a context built for tls.test must not verify other.test"
            );
        });
    }

    /// A listener pinned to TLS 1.2 serves the five ids neither ring nor the legacy lane carries,
    /// with the suite selected in the reference's global preference order.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_shaped_listener_serves_the_five_ids_neither_backend_has() {
        let identity = crate::tls::TlsServerConfig {
            certs: vec![rsa_identity()],
            alpn: Vec::new(),
            min_version: Some(0x0303),
            max_version: Some(0x0303),
            cipher_suites: vec![0x003c, 0xc012, 0x0005, 0xc007, 0xc011],
            curves: Vec::new(),
            send_tickets: false,
            reject_unknown_sni: false,
            server_config_cache: std::sync::Arc::default(),
            ech_server_keys: None,
            master_key_log: None,
            kernel_tx: false,
            kernel_rx: false,
        };
        for id in [0x003c, 0xc012, 0x0005, 0xc007, 0xc011] {
            let mut bound = identity.clone();
            bound.certs = vec![if id == 0xc007 {
                ecdsa_identity()
            } else {
                rsa_identity()
            }];
            bound.cipher_suites = vec![id];
            let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
            let port = listener.local_addr().expect("addr").port();
            thread::scope(|scope| {
                scope.spawn(|| {
                    let (stream, _) = listener.accept().expect("accepts");
                    let mut server = crate::tls::accept(&bound, stream).expect("accepts");
                    server.handshake().expect("handshakes");
                    assert_eq!(
                        server.suite(),
                        Some(id),
                        "the listener negotiated the configured suite"
                    );
                    let mut buf = [0u8; 4];
                    server.read_exact(&mut buf).expect("reads");
                    server.write_all(&buf).expect("writes");
                    server.flush().expect("flushes");
                });
                let mut cfg = client("tls.test", &[]);
                cfg.insecure = true;
                cfg.cipher_suites = vec![id].into();
                let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
                let mut session = crate::tls::connect(&cfg, stream).expect("dials");
                session.handshake().expect("handshakes");
                session.write_all(b"ping").expect("writes");
                session.flush().expect("flushes");
                let mut buf = [0u8; 4];
                session.read_exact(&mut buf).expect("reads");
                assert_eq!(&buf, b"ping");
            });
        }
    }

    /// A listener that also offers TLS 1.3 reads the hello first: the five go to the shaped engine
    /// for a TLS 1.2 client, and a client that offers TLS 1.3 goes to the engine that carries it.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_mixed_max_listener_peeks_the_hello_before_choosing_an_engine() {
        let identity = crate::tls::TlsServerConfig {
            certs: vec![rsa_identity()],
            alpn: Vec::new(),
            min_version: Some(0x0303),
            max_version: Some(0x0304),
            cipher_suites: vec![0x003c, 0xc012, 0x0005, 0xc007, 0xc011],
            curves: Vec::new(),
            send_tickets: false,
            reject_unknown_sni: false,
            server_config_cache: std::sync::Arc::default(),
            ech_server_keys: None,
            master_key_log: None,
            kernel_tx: false,
            kernel_rx: false,
        };
        let serve = |bound: &crate::tls::TlsServerConfig, offer: Vec<u16>| {
            let bound = bound.clone();
            let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
            let port = listener.local_addr().expect("addr").port();
            thread::scope(|scope| {
                let server = scope.spawn(move || {
                    let (stream, _) = listener.accept().expect("accepts");
                    let mut server = crate::tls::accept(&bound, stream).expect("accepts");
                    server.handshake().expect("handshakes");
                    let suite = server.suite();
                    let mut buf = [0u8; 4];
                    server.read_exact(&mut buf).expect("reads");
                    server.write_all(&buf).expect("writes");
                    server.flush().expect("flushes");
                    suite
                });
                let mut cfg = client("tls.test", &[]);
                cfg.insecure = true;
                cfg.cipher_suites = offer.into();
                let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
                let mut session = crate::tls::connect(&cfg, stream).expect("dials");
                session.handshake().expect("handshakes");
                session.write_all(b"ping").expect("writes");
                session.flush().expect("flushes");
                let mut buf = [0u8; 4];
                session.read_exact(&mut buf).expect("reads");
                assert_eq!(&buf, b"ping");
                server.join().expect("server")
            })
        };
        let mut twelve = identity.clone();
        twelve.certs = vec![rsa_identity()];
        assert_eq!(serve(&twelve, vec![0x003c]), Some(0x003c));
        let mut thirteen = identity;
        thirteen.certs = vec![rsa_identity()];
        assert_eq!(serve(&thirteen, vec![0x1301, 0x1302, 0x1303, 0x003c]), None);
    }

    /// The listener's role: a config naming a static-RSA suite answers an RSA identity.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and BoringSSL's assembly behind it"
    )]
    #[test]
    fn a_legacy_listener_negotiates_static_rsa() {
        let identity = crate::tls::TlsServerConfig {
            certs: vec![rsa_identity()],
            alpn: Vec::new(),
            min_version: Some(0x0303),
            max_version: Some(0x0303),
            cipher_suites: vec![0x002f],
            curves: Vec::new(),
            send_tickets: true,
            reject_unknown_sni: false,
            server_config_cache: std::sync::Arc::default(),
            ech_server_keys: None,
            master_key_log: None,
            kernel_tx: false,
            kernel_rx: false,
        };
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(|| {
                let (stream, _) = listener.accept().expect("accepts");
                let mut server = crate::tls::accept(&identity, stream).expect("accepts");
                server.handshake().expect("handshakes");
                let mut buf = [0u8; 4];
                server.read_exact(&mut buf).expect("reads");
                server.write_all(&buf).expect("writes");
                server.flush().expect("flushes");
            });
            let mut builder = boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls())
                .expect("context");
            builder.set_verify(boring::ssl::SslVerifyMode::NONE);
            builder
                .set_min_proto_version(Some(boring::ssl::SslVersion::TLS1_2))
                .expect("floor");
            builder
                .set_max_proto_version(Some(boring::ssl::SslVersion::TLS1_2))
                .expect("ceiling");
            builder.set_cipher_list("AES128-SHA").expect("list");
            let ctx = builder.build();
            let mut ssl = boring::ssl::Ssl::new(&ctx).expect("ssl");
            ssl.set_hostname("tls.test").expect("name");
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let mut client = ssl.connect(stream).expect("handshakes");
            assert_eq!(
                client
                    .ssl()
                    .current_cipher()
                    .map(boring::ssl::SslCipherRef::protocol_id),
                Some(0x002f),
                "the listener negotiated the static-RSA suite"
            );
            client.write_all(b"ping").expect("writes");
            client.flush().expect("flushes");
            let mut buf = [0u8; 4];
            client.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
        });
    }

    #[test]
    fn a_floor_below_tls12_starts_at_tls12() {
        let versions = server_versions(Some(0x0301), Some(0x0304))
            .expect("supported")
            .expect("bounded");
        assert_eq!(versions.len(), 2);
        assert!(server_versions(Some(0x0304), Some(0x0303)).is_err());
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn ech_server_accepts_the_offer_and_echoes() {
        let (list, keys) = crate::tls::ech::generate("public.test", 3).expect("generates");
        let cert_pem = anchor_pem("CERTIFICATE", ANCHOR);
        let key_pem = anchor_pem("PRIVATE KEY", ANCHOR_KEY);
        let mut identity = crate::tls::parse_pem_identity(&cert_pem, &key_pem).expect("parses");
        identity.ech_server_keys = Some(keys.into());
        identity.reject_unknown_sni = true;
        identity.alpn = vec![b"http/1.1".to_vec(), b"h2".to_vec()];
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(|| {
                let (stream, _) = listener.accept().expect("accepts");
                let mut server = crate::tls::accept(&identity, stream).expect("accepts");
                server.handshake().expect("handshakes");
                assert!(server.ech_accepted(), "the offer was accepted");
                assert_eq!(
                    server.alpn(),
                    Some(&b"http/1.1"[..]),
                    "the server's list wins when the client offers both"
                );
                let mut buf = [0u8; 4];
                server.read_exact(&mut buf).expect("reads");
                server.write_all(&buf).expect("writes");
                server.flush().expect("flushes");
            });
            let mut cfg = client("tls.test", &[b"h2", b"http/1.1"]);
            cfg.ech_config_list = Some(list.into());
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let mut client = crate::tls::connect(&cfg, stream).expect("configures");
            client.handshake().expect("handshakes");
            client.write_all(b"ping").expect("writes");
            client.flush().expect("flushes");
            let mut buf = [0u8; 4];
            client.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
        });
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn ech_server_records_the_master_key_log() {
        let (list, keys) = crate::tls::ech::generate("public.test", 3).expect("generates");
        let cert_pem = anchor_pem("CERTIFICATE", ANCHOR);
        let key_pem = anchor_pem("PRIVATE KEY", ANCHOR_KEY);
        let mut identity = crate::tls::parse_pem_identity(&cert_pem, &key_pem).expect("parses");
        identity.ech_server_keys = Some(keys.into());
        let path =
            std::env::temp_dir().join(format!("ferrox-ech-keylog-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let named = path.to_string_lossy().into_owned();
        identity.master_key_log = Some(Arc::new(
            crate::tls::MasterKeyLog::open(&named).expect("opens"),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(|| {
                let (stream, _) = listener.accept().expect("accepts");
                let mut server = crate::tls::accept(&identity, stream).expect("accepts");
                server.handshake().expect("handshakes");
                assert!(server.ech_accepted(), "the offer was accepted");
                let mut buf = [0u8; 4];
                server.read_exact(&mut buf).expect("reads");
                server.write_all(&buf).expect("writes");
                server.flush().expect("flushes");
            });
            let mut cfg = client("tls.test", &[b"h2", b"http/1.1"]);
            cfg.ech_config_list = Some(list.into());
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let mut client = crate::tls::connect(&cfg, stream).expect("configures");
            client.handshake().expect("handshakes");
            client.write_all(b"ping").expect("writes");
            client.flush().expect("flushes");
            let mut buf = [0u8; 4];
            client.read_exact(&mut buf).expect("reads");
        });
        let log = std::fs::read_to_string(&path).expect("the log the config named");
        let _ = std::fs::remove_file(&path);
        assert!(
            log.lines()
                .any(|line| line.starts_with("SERVER_HANDSHAKE_TRAFFIC_SECRET ")),
            "the ECH listener's secrets are written: {log:?}"
        );
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn ech_server_accepts_an_aes_256_only_offer() {
        let (list, keys) = crate::tls::ech::generate_with_suites(
            "public.test",
            4,
            &[(
                crate::tls::ech::KDF_SHA256,
                crate::tls::ech::AEAD_AES_256_GCM,
            )],
        )
        .expect("generates");
        let cert_pem = anchor_pem("CERTIFICATE", ANCHOR);
        let key_pem = anchor_pem("PRIVATE KEY", ANCHOR_KEY);
        let mut identity = crate::tls::parse_pem_identity(&cert_pem, &key_pem).expect("parses");
        identity.ech_server_keys = Some(keys.into());
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(|| {
                let (stream, _) = listener.accept().expect("accepts");
                let mut server = crate::tls::accept(&identity, stream).expect("accepts");
                server.handshake().expect("handshakes");
                assert!(server.ech_accepted(), "the aes-256 offer was accepted");
                let mut buf = [0u8; 4];
                server.read_exact(&mut buf).expect("reads");
                server.write_all(&buf).expect("writes");
                server.flush().expect("flushes");
            });
            let mut cfg = client("tls.test", &[]);
            cfg.ech_config_list = Some(list.into());
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let mut client = crate::tls::connect(&cfg, stream).expect("configures");
            client.handshake().expect("handshakes");
            client.write_all(b"ping").expect("writes");
            client.flush().expect("flushes");
            let mut buf = [0u8; 4];
            client.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
        });
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn ech_server_still_answers_a_client_that_does_not_offer_it() {
        let (_, keys) = crate::tls::ech::generate("public.test", 3).expect("generates");
        let cert_pem = anchor_pem("CERTIFICATE", ANCHOR);
        let key_pem = anchor_pem("PRIVATE KEY", ANCHOR_KEY);
        let mut identity = crate::tls::parse_pem_identity(&cert_pem, &key_pem).expect("parses");
        identity.ech_server_keys = Some(keys.into());
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(|| {
                let (stream, _) = listener.accept().expect("accepts");
                let mut server = crate::tls::accept(&identity, stream).expect("accepts");
                server.handshake().expect("handshakes");
                assert!(!server.ech_accepted(), "no offer means no acceptance");
                let mut buf = [0u8; 4];
                server.read_exact(&mut buf).expect("reads");
                server.write_all(&buf).expect("writes");
                server.flush().expect("flushes");
            });
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let mut client =
                crate::tls::connect(&client("tls.test", &[]), stream).expect("configures");
            client.handshake().expect("handshakes");
            client.write_all(b"ping").expect("writes");
            client.flush().expect("flushes");
            let mut buf = [0u8; 4];
            client.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
        });
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn an_idle_peer_refuses_the_handshake_instead_of_spinning_it() {
        let cert_pem = anchor_pem("CERTIFICATE", ANCHOR);
        let key_pem = anchor_pem("PRIVATE KEY", ANCHOR_KEY);
        let identity = crate::tls::parse_pem_identity(&cert_pem, &key_pem).expect("parses");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        thread::scope(|scope| {
            scope.spawn(|| {
                let (stream, _) = listener.accept().expect("accepts");
                stream
                    .set_read_timeout(Some(std::time::Duration::from_millis(50)))
                    .expect("times out");
                let mut server = crate::tls::accept(&identity, stream).expect("accepts");
                let _ = done_tx.send(server.handshake());
            });
            // Silent past the old spin, which never ended: the refusal arrives first.
            let idle = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let refused = done_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("the handshake refuses an idle peer");
            assert!(
                matches!(refused, Err(TlsError::Timeout)),
                "idleness refuses as {refused:?}"
            );
            drop(idle);
        });
    }

    #[test]
    fn pem_identity_rejects_blocks_it_does_not_know() {
        assert!(crate::tls::parse_pem_identity(b"nothing here", b"nothing here").is_err());
        let cert_pem = anchor_pem("CERTIFICATE", ANCHOR);
        assert!(crate::tls::parse_pem_identity(&cert_pem, b"nothing here").is_err());
    }

    /// A socket that counts the reads that reach it and the bytes each one carried.
    struct ReadCounter {
        inner: TcpStream,
        calls: Arc<AtomicUsize>,
        bytes: Arc<AtomicUsize>,
        sizes: Arc<Mutex<Vec<usize>>>,
    }

    impl Read for ReadCounter {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            // Counted before the call: a read that answers `WouldBlock` with nothing in it is the wait these rows name, and counting only reads that returned would hide it.
            self.calls.fetch_add(1, Ordering::Relaxed);
            let n = self.inner.read(buf)?;
            self.bytes.fetch_add(n, Ordering::Relaxed);
            self.sizes.lock().expect("locks").push(n);
            Ok(n)
        }
    }

    impl Write for ReadCounter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.inner.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    impl super::super::RecordAlignment for ReadCounter {}

    /// A flush that also read waited for a record the peer had not sent, and the relay holds
    /// the session's lock through that wait. The count is exact: the peer never sends, so
    /// every read the session makes is one this tree asked for.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_flush_does_not_read_the_transport() {
        let cert_pem = anchor_pem("CERTIFICATE", ANCHOR);
        let key_pem = anchor_pem("PRIVATE KEY", ANCHOR_KEY);
        let identity = crate::tls::parse_pem_identity(&cert_pem, &key_pem).expect("parses");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let calls = Arc::new(AtomicUsize::new(0));
        let bytes = Arc::new(AtomicUsize::new(0));
        let sizes = Arc::new(Mutex::new(Vec::new()));
        thread::scope(|scope| {
            scope.spawn(move || {
                let (stream, _) = listener.accept().expect("accepts");
                let mut server = crate::tls::accept(&identity, stream).expect("accepts");
                server.handshake().expect("handshakes");
                // The peer writes and nothing answers, so no record ever arrives here.
                let mut buf = [0u8; 64];
                loop {
                    match server.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            });
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let counter = ReadCounter {
                inner: stream,
                calls: Arc::clone(&calls),
                bytes: Arc::clone(&bytes),
                sizes: Arc::clone(&sizes),
            };
            let mut client =
                crate::tls::connect(&client("tls.test", &[]), counter).expect("configures");
            client.handshake().expect("handshakes");
            let before = calls.load(Ordering::Relaxed);
            client.write_all(b"payload").expect("writes");
            client.flush().expect("flushes");
            let after = calls.load(Ordering::Relaxed);
            assert_eq!(
                after - before,
                0,
                "the flush read the transport {after} times where it had read {before}"
            );
        });
    }

    /// The write's half of the same rule, and the zero-length write is its edge: a call that
    /// queues no record gives `complete_io` nothing to send, which is the state where it reads.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_write_does_not_read_the_transport() {
        let cert_pem = anchor_pem("CERTIFICATE", ANCHOR);
        let key_pem = anchor_pem("PRIVATE KEY", ANCHOR_KEY);
        let identity = crate::tls::parse_pem_identity(&cert_pem, &key_pem).expect("parses");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let calls = Arc::new(AtomicUsize::new(0));
        let bytes = Arc::new(AtomicUsize::new(0));
        let sizes = Arc::new(Mutex::new(Vec::new()));
        thread::scope(|scope| {
            scope.spawn(move || {
                let (stream, _) = listener.accept().expect("accepts");
                let mut server = crate::tls::accept(&identity, stream).expect("accepts");
                server.handshake().expect("handshakes");
                // The peer never answers, so the only record on the wire is the client's own.
                let mut buf = [0u8; 64];
                loop {
                    match server.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            });
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let counter = ReadCounter {
                inner: stream,
                calls: Arc::clone(&calls),
                bytes: Arc::clone(&bytes),
                sizes: Arc::clone(&sizes),
            };
            let mut client =
                RustlsProvider::connect(&client("tls.test", &[]), counter).expect("configures");
            client.handshake().expect("handshakes");
            // The relay's own arm for a shared session, so a read inside the window costs one counted grain rather than a parked thread.
            client
                .io
                .inner
                .set_read_timeout(Some(std::time::Duration::from_millis(1)))
                .expect("arms a grain");
            let before = calls.load(Ordering::Relaxed);
            let wrote = client.write(b"payload").expect("writes");
            let empty = client.write(&[]).expect("an empty write shows nothing");
            let after = calls.load(Ordering::Relaxed);
            assert_eq!(wrote, 7);
            assert_eq!(empty, 0);
            assert_eq!(
                after - before,
                0,
                "the write read the transport {after} times where it had read {before}"
            );
        });
    }

    /// A relay-sized write is larger than rustls's 64 KiB output buffer; the writer must
    /// drain between partial writes instead of returning `WriteZero` on the next retry.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_relay_sized_write_crosses_the_tls_buffer() {
        use crate::tls::{RecordAlignment as _, TlsProvider as _};

        let cert_pem = anchor_pem("CERTIFICATE", ANCHOR);
        let key_pem = anchor_pem("PRIVATE KEY", ANCHOR_KEY);
        let identity = crate::tls::parse_pem_identity(&cert_pem, &key_pem).expect("parses");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let payload = vec![0x5a; 80 * 1024];
        thread::scope(|scope| {
            scope.spawn(move || {
                let (stream, _) = listener.accept().expect("accepts");
                let mut server = crate::tls::accept(&identity, stream).expect("accepts");
                server.handshake().expect("handshakes");
                thread::sleep(std::time::Duration::from_millis(100));
            });
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let mut client =
                RustlsProvider::connect(&client("tls.test", &[]), stream).expect("configures");
            client.handshake().expect("handshakes");
            client
                .write_all_slices(&[&payload])
                .expect("a relay-sized write");
            client.flush().expect("flushes");
            assert!(
                !client.conn.wants_write(),
                "the write left TLS records queued"
            );
        });
    }

    /// A served session stops on the peer's close the same way a dialled one does: the
    /// `close_notify` carries no plaintext, so the EOF has to be the session's own state.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_server_session_reports_the_peers_close_notify() {
        use crate::tls::TlsProvider as _;

        let cert_pem = anchor_pem("CERTIFICATE", ANCHOR);
        let key_pem = anchor_pem("PRIVATE KEY", ANCHOR_KEY);
        let identity = crate::tls::parse_pem_identity(&cert_pem, &key_pem).expect("parses");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (done, waited) = std::sync::mpsc::channel();
        let (ready, dialled) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(20)))
                .expect("timeout");
            let mut server = RustlsServerProvider::accept(identity, stream).expect("accepts");
            server.handshake().expect("handshakes");
            ready.send(()).expect("signals the handshake");
            let mut header = [0u8; 5];
            server
                .get_ref()
                .read_exact(&mut header)
                .expect("reads the alert head");
            let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
            let mut wire = vec![0u8; 5 + len];
            wire[..5].copy_from_slice(&header);
            server
                .get_ref()
                .read_exact(&mut wire[5..])
                .expect("reads the alert");
            let mut plain = [0u8; 8];
            let (read, taken) = server.open(&wire, &mut plain).expect("opens");
            assert_eq!(read, 0, "`close_notify` carries no plaintext");
            assert_eq!(taken, wire.len(), "the whole alert was consumed");
            assert!(server.closed(), "the peer's close is reported");
            done.send(()).expect("signals the dial");
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let mut client = crate::tls::connect(&client("tls.test", &[]), stream).expect("dials");
        client.handshake().expect("handshakes");
        dialled.recv().expect("the server handshook");
        let crate::tls::ClientSession::Stock(provider) = &mut client else {
            panic!("the test dials the stock session");
        };
        provider.conn.send_close_notify();
        let mut wire = Vec::new();
        provider.drain_into(&mut wire).expect("drains");
        provider.io.write_all(&wire).expect("sends");
        provider.io.flush().expect("flushes");
        waited.recv().expect("the server read the close");
        server.join().expect("joins");
    }

    /// The answer's half of the write rule: a server session's write pushes the records it
    /// framed and leaves the request's bytes to whichever call is reading them. The count is
    /// exact: the peer answers nothing, so every read the session makes is one this tree asked for.
    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_server_answer_write_does_not_read_the_transport() {
        let cert_pem = anchor_pem("CERTIFICATE", ANCHOR);
        let key_pem = anchor_pem("PRIVATE KEY", ANCHOR_KEY);
        let identity = crate::tls::parse_pem_identity(&cert_pem, &key_pem).expect("parses");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let calls = Arc::new(AtomicUsize::new(0));
        let bytes = Arc::new(AtomicUsize::new(0));
        let sizes = Arc::new(Mutex::new(Vec::new()));
        thread::scope(|scope| {
            scope.spawn(move || {
                let (stream, _) = listener.accept().expect("accepts");
                let counter = ReadCounter {
                    inner: stream,
                    calls: Arc::clone(&calls),
                    bytes: Arc::clone(&bytes),
                    sizes: Arc::clone(&sizes),
                };
                let mut server = RustlsServerProvider::accept(identity.clone(), counter)
                    .expect("accepts a session");
                server.handshake().expect("handshakes");
                // The relay's own arm for a shared session, so a read inside the window costs one counted grain rather than a parked thread.
                server
                    .get_ref()
                    .inner
                    .set_read_timeout(Some(std::time::Duration::from_millis(1)))
                    .expect("arms a grain");
                let before = calls.load(Ordering::Relaxed);
                server.write_all(b"answer").expect("answers");
                server.flush().expect("flushes");
                let after = calls.load(Ordering::Relaxed);
                assert_eq!(
                    after - before,
                    0,
                    "the answer read the transport {after} times where it had read {before}"
                );
            });
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let mut client = crate::tls::connect(&client("tls.test", &[]), stream).expect("dials");
            client.handshake().expect("handshakes");
            let mut sink = [0u8; 64];
            while matches!(client.read(&mut sink), Ok(read) if read > 0) {}
        });
    }

    /// Counts the segments a coalesced write reached the writer with, allocating nothing itself
    /// so it can sit inside the measurement window.
    struct SegmentRecorder {
        calls: usize,
        bytes: usize,
    }

    impl Write for SegmentRecorder {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes += buf.len();
            Ok(buf.len())
        }
        fn write_vectored(&mut self, bufs: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> {
            self.calls += 1;
            let n = bufs.iter().map(|slice| slice.len()).sum();
            self.bytes += n;
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The four segments the Vision framer hands go out in one record off the stack: no heap
    /// buffer per framed write, which is the allocation the old `collect::<Vec<_>>` paid for.
    #[test]
    fn the_framer_path_coalesces_without_a_heap_buffer() {
        let uuid = [0xabu8; 16];
        let head = [0u8; 5];
        let payload: Vec<u8> = (0..1400).map(|i| i as u8).collect();
        let padding = [0u8; 200];
        let parts: [&[u8]; 4] = [&uuid[..], &head[..], payload.as_slice(), &padding[..]];
        let mut recorder = SegmentRecorder { calls: 0, bytes: 0 };
        // The parts are assembled outside the window; only `coalesce` runs inside it.
        let (result, counts) = crate::alloc_count::measure(|| coalesce(&mut recorder, &parts));
        result.expect("coalesces");
        assert_eq!(
            counts.allocs, 0,
            "four segments ride the stack, counted {counts:?}"
        );
        assert_eq!(recorder.calls, 1, "one `write_vectored`, so one record");
        assert_eq!(recorder.bytes, 16 + 5 + 1400 + 200);
    }

    /// The camouflage head gather is one piece wider than the framer — `GET `, the path, the
    /// middle, the host, the trailer — and a repeated dial cycle still enters the allocator zero
    /// times: the fifth run rides the stack too, where it once bought a `Vec<IoSlice>` per dial.
    #[test]
    fn the_camouflage_gather_coalesces_without_a_heap_buffer() {
        let before = b"GET ";
        let path = "/camouflage";
        let middle = b" HTTP/1.1\r\nHost: ";
        let host = "oracle.example";
        let after = b"\r\nConnection: keep-alive\r\n\r\n";
        let parts: [&[u8]; 5] = [before, path.as_bytes(), middle, host.as_bytes(), after];
        let mut recorder = SegmentRecorder { calls: 0, bytes: 0 };
        // Three dials' gathers inside one window: a reclaim that stopped firing would show as a rising count.
        let (result, counts) = crate::alloc_count::measure(|| {
            let mut last = Ok(());
            for _ in 0..3 {
                last = coalesce(&mut recorder, &parts);
            }
            last
        });
        result.expect("coalesces");
        assert_eq!(
            counts.allocs, 0,
            "five segments ride the stack over every dial, counted {counts:?}"
        );
        assert_eq!(
            recorder.calls, 3,
            "one `write_vectored` per gather, so one record each"
        );
        assert_eq!(
            recorder.bytes,
            3 * (before.len() + path.len() + middle.len() + host.len() + after.len())
        );
    }

    /// A CONNECT request is seven runs of literal and caller text — wider than the camouflage
    /// gather — and a repeated open still enters the allocator zero times: the request rides the
    /// stack into one `write_vectored`, so no buffer is built to hold it first.
    #[test]
    fn the_connect_request_gathers_without_a_heap_buffer() {
        let parts = crate::foxy::connect_request(
            "example.com:443",
            crate::foxy::BEARER_HEAD,
            "pass.jwt.value",
        );
        let want: usize = parts.iter().map(|part| part.len()).sum();
        let mut recorder = SegmentRecorder { calls: 0, bytes: 0 };
        // Three opens inside one window: a reclaim that stopped firing would show as a rising count.
        let (result, counts) = crate::alloc_count::measure(|| {
            let mut last = Ok(());
            for _ in 0..3 {
                last = coalesce(&mut recorder, &parts);
            }
            last
        });
        result.expect("coalesces");
        assert_eq!(
            counts.allocs, 0,
            "seven segments ride the stack over every open, counted {counts:?}"
        );
        assert_eq!(
            recorder.calls, 3,
            "one `write_vectored` per request, so one record each"
        );
        assert_eq!(
            recorder.bytes,
            3 * want,
            "the bytes the concatenated request carried, unchanged"
        );
    }

    /// Past the stack bound the same segments still go out in one call, and empty runs never
    /// reach the writer where a zero-length slice would stall `advance_slices`.
    #[test]
    fn a_wide_segment_list_and_empty_runs_still_coalesce_in_one_call() {
        let a = [1u8; 3];
        let b = [2u8; 4];
        let empty: [u8; 0] = [];
        let parts: [&[u8]; 8] = [
            &a[..],
            &empty[..],
            &b[..],
            &empty[..],
            &a[..],
            &b[..],
            &a[..],
            &empty[..],
        ];
        let mut recorder = SegmentRecorder { calls: 0, bytes: 0 };
        coalesce(&mut recorder, &parts).expect("coalesces");
        assert_eq!(recorder.bytes, 3 + 4 + 3 + 4 + 3, "empty runs are dropped");
        assert_eq!(recorder.calls, 1, "one record even past the stack bound");
    }
}

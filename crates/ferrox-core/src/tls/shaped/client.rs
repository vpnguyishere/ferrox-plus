// The shaped client handshake: a browser hello out, both TLS versions' flights back under keys this module owns.
use super::hello::{Hello, TLS12};
use super::kdf::{self, Hash};
use super::record::{self, Direction, Suite};
use super::{Fingerprint, Profile};
use crate::tls::{RecordAlignment, Stream, TlsConfig, TlsError, TlsProvider};
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(crate) const HANDSHAKE: u8 = 22;
const ALERT: u8 = 21;
pub(crate) const CCS: u8 = 20;
pub(crate) const APPLICATION: u8 = 23;
pub(crate) const MAX_RECORD: usize = 16384 + 256;
const RECORD_READ: usize = 16384;
pub(crate) const MAX_HANDSHAKE: usize = 1 << 20;
const MAX_PLAINTEXT: usize = 16384;
/// How long a shaped handshake may spend waiting for its peer, matching the KCP path's read deadline.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// The one deadline a shaped handshake runs under, on either side.
pub(crate) fn handshake_deadline() -> Instant {
    Instant::now() + HANDSHAKE_TIMEOUT
}

/// How long an immediate `WouldBlock` waits before the handshake asks again; a transport with a read timeout has already waited, a nonblocking one has not.
const WOULD_BLOCK_RETRY: Duration = Duration::from_millis(1);

/// The `HelloRetryRequest` random, which names the message without a new type.
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Version {
    Tls13,
    Tls12,
}

/// One shaped client session: the same stream shape as every other TLS provider,
/// with the record keys and transcript in this type rather than a rustls connection.
pub struct Session<S: Stream> {
    io: S,
    verifier: Arc<dyn ServerCertVerifier>,
    server_name: ServerName<'static>,
    profile: &'static Profile,
    hello: Option<Hello>,
    handshake_deadline: Option<Instant>,
    client_random: [u8; 32],
    transcript: Vec<u8>,
    version: Option<Version>,
    suite: Option<Suite>,
    read_key: Option<Direction>,
    write_key: Option<Direction>,
    server12: Option<Direction>,
    client12: Option<Direction>,
    alpn: Option<Vec<u8>>,
    leaf: Option<Vec<u8>>,
    done: bool,
    eof: bool,
    ccs_sent: bool,
    hs: Vec<u8>,
    plain: Vec<u8>,
    plain_at: usize,
    plain_end: usize,
    inbuf: Vec<u8>,
    in_at: usize,
    reply: Vec<u8>,
    out: Vec<u8>,
    key_log: Option<Arc<dyn rustls::KeyLog>>,
    client_cert: Option<ClientIdentity>,
}

/// The identity a shaped dial presents when a server asks: the chain in presentation order and the
/// signing key its DER names, resolved once per session so the answer costs one signature.
struct ClientIdentity {
    chain: Vec<Vec<u8>>,
    key: Arc<dyn rustls::sign::SigningKey>,
}

impl ClientIdentity {
    fn new(entry: &crate::tls::CertEntry) -> Result<Self, TlsError> {
        let key = rustls::crypto::ring::sign::any_supported_type(
            &crate::tls::rustls_backend::key_of(entry),
        )
        .map_err(|e| TlsError::BadCertificate(format!("client key: {e}")))?;
        Ok(Self {
            chain: entry.cert_chain.clone(),
            key,
        })
    }

    /// The signer for a scheme the server offered, or `None` when the key cannot speak one.
    fn signer<'a>(
        &'a self,
        offered: &[u16],
        tls13: bool,
    ) -> Option<Box<dyn rustls::sign::Signer + 'a>> {
        use rustls::SignatureScheme as S;
        let defaults: &[u16] = if tls13 {
            &[0x0403, 0x0503, 0x0807, 0x0804, 0x0805, 0x0806]
        } else {
            &[
                0x0403, 0x0503, 0x0603, 0x0807, 0x0401, 0x0501, 0x0601, 0x0804, 0x0805, 0x0806,
            ]
        };
        let listed = if offered.is_empty() {
            if !tls13 {
                return None;
            }
            defaults
        } else {
            offered
        };
        let schemes: Vec<S> = listed
            .iter()
            .map(|id| S::from(*id))
            .filter(|scheme| {
                !tls13
                    || !matches!(
                        scheme,
                        S::RSA_PKCS1_SHA1
                            | S::RSA_PKCS1_SHA256
                            | S::RSA_PKCS1_SHA384
                            | S::RSA_PKCS1_SHA512
                            | S::ECDSA_SHA1_Legacy
                    )
            })
            .collect();
        self.key.choose_scheme(&schemes)
    }
}

impl<S: Stream> std::fmt::Debug for Session<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("profile", &self.profile.name)
            .field("alpn", &self.alpn)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl<S: Stream> Session<S> {
    /// Builds the shaped hello; the handshake that puts it on the wire runs when
    /// `handshake` is called, exactly as the stock provider's connection waits.
    pub(crate) fn connect(cfg: &TlsConfig, io: S) -> Result<Self, TlsError> {
        let Some(profile) = cfg.fingerprint.and_then(Fingerprint::profile) else {
            return Err(TlsError::Other(
                "shaped: a stock fingerprint has no shaped session".to_owned(),
            ));
        };
        Self::with_profile(profile, cfg, io, false)
    }

    /// The stock hello a config's `cipherSuites` rides when ring and `BoringSSL` carry none of it:
    /// Go's own extension table, with the config's list in place of a preset's.
    pub(crate) fn connect_stock(cfg: &TlsConfig, io: S) -> Result<Self, TlsError> {
        let profile = if crate::tls::cipher_suites::offers_tls13(&cfg.cipher_suites) {
            &super::GO_STOCK
        } else {
            &super::GO_STOCK_12
        };
        Self::with_profile(profile, cfg, io, true)
    }

    /// The one builder both the preset and the stock hellos share.
    fn with_profile(
        profile: &'static Profile,
        cfg: &TlsConfig,
        io: S,
        stock: bool,
    ) -> Result<Self, TlsError> {
        let mut hello = Hello::build(
            profile,
            &cfg.server_name,
            if stock { &[] } else { &cfg.alpn },
            !stock && cfg.websocket,
            &cfg.curves,
            cfg.client_random,
        )?;
        if stock {
            if !cfg.cipher_suites.is_empty() {
                hello.set_ciphers(&cfg.cipher_suites);
            }
            hello.set_alpn(&cfg.alpn);
        }
        if let Some(padding) = cfg.padding {
            hello.set_padding(usize::from(padding));
        }
        if let Some(list) = &cfg.ech_config_list {
            hello.enable_ech(list)?;
        }
        let verifier = crate::tls::rustls_backend::verifier(cfg)?;
        let mut session = Self::with_hello(profile, cfg.server_name.clone(), verifier, hello, io)?;
        session.set_key_log(cfg.master_key_log.clone());
        session.client_cert = cfg
            .client_cert
            .as_deref()
            .map(ClientIdentity::new)
            .transpose()?;
        Ok(session)
    }

    /// The `masterKeyLog` this session hands its secrets to, set after a caller-built hello as REALITY sets it.
    pub(crate) fn set_key_log(&mut self, log: Option<Arc<crate::tls::MasterKeyLog>>) {
        self.key_log = log.map(|log| {
            let log: Arc<dyn rustls::KeyLog> = log;
            log
        });
    }

    /// A session over a hello the caller built and sealed, as REALITY does.
    pub(crate) fn with_hello(
        profile: &'static Profile,
        server_name: String,
        verifier: Arc<dyn ServerCertVerifier>,
        hello: Hello,
        io: S,
    ) -> Result<Self, TlsError> {
        let server_name = ServerName::try_from(server_name)
            .map_err(|e| TlsError::Other(format!("tls server name: {e}")))?;
        Ok(Self {
            io,
            verifier,
            server_name,
            profile,
            hello: Some(hello),
            handshake_deadline: None,
            client_random: [0u8; 32],
            transcript: Vec::new(),
            version: None,
            suite: None,
            read_key: None,
            write_key: None,
            server12: None,
            client12: None,
            alpn: None,
            leaf: None,
            done: false,
            eof: false,
            ccs_sent: false,
            hs: Vec::new(),
            plain: Vec::new(),
            plain_at: 0,
            plain_end: 0,
            inbuf: Vec::new(),
            in_at: 0,
            reply: Vec::new(),
            out: Vec::new(),
            key_log: None,
            client_cert: None,
        })
    }

    /// Hands each secret this session derives to the config's `masterKeyLog`, as rustls's own dial does.
    fn log_secrets(&self, secrets: &[(&str, &[u8])]) {
        let Some(log) = &self.key_log else {
            return;
        };
        for (label, secret) in secrets {
            log.log(label, &self.client_random, secret);
        }
    }

    pub(crate) fn get_ref(&self) -> &S {
        &self.io
    }

    pub(crate) fn closed(&self) -> bool {
        self.eof
    }

    /// The plaintext buffer, which a carrier record with room in the caller's window never stages into.
    #[cfg(test)]
    pub(crate) fn plain_buffer(&self) -> &[u8] {
        &self.plain
    }

    /// The plaintext buffer's capacity, which a relayed record must not grow.
    #[cfg(test)]
    pub(crate) fn plain_capacity(&self) -> usize {
        self.plain.capacity()
    }

    /// Runs the shaped handshake, reading against one absolute deadline from the first call.
    fn run(&mut self) -> Result<(), TlsError> {
        if self.done {
            return Ok(());
        }
        if self.handshake_deadline.is_none() {
            self.handshake_deadline = Some(Instant::now() + HANDSHAKE_TIMEOUT);
        }
        if self
            .handshake_deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(TlsError::Timeout);
        }
        let mut hello = self
            .hello
            .take()
            .ok_or_else(|| TlsError::Other("shaped: handshake already ran".to_owned()))?;
        let ech = hello.ech_inner().is_some();
        self.client_random = hello.random;
        self.send_plain(HANDSHAKE, &hello.msg, [0x03, 0x01])?;
        self.transcript.extend_from_slice(if ech {
            hello.ech_inner().expect("checked")
        } else {
            &hello.msg
        });
        let mut msg = self.next_handshake()?;
        if msg[0] != 2 {
            return Err(unexpected(msg[0]));
        }
        let mut sh = ServerHello::parse(&msg[4..])?;
        if !hello.offers_cipher(sh.suite) {
            return Err(TlsError::NoSharedCipher);
        }
        if sh.hrr {
            let suite = Suite::from_id(sh.suite)
                .filter(|suite| suite.is_tls13())
                .ok_or(TlsError::NoSharedCipher)?;
            if ech {
                self.ech_retry_accepted(&hello, &sh, &msg, suite)?;
            } else {
                let first = std::mem::take(&mut self.transcript);
                let mut transcript = message_hash(suite.hash(), &first);
                transcript.extend_from_slice(&msg);
                self.transcript = transcript;
            }
            let group = sh
                .hrr_group
                .ok_or_else(|| TlsError::Other("retry request names no group".to_owned()))?;
            self.send_ccs()?;
            hello = hello.retry(group, sh.cookie.as_deref())?;
            self.send_plain(HANDSHAKE, &hello.msg, [0x03, 0x03])?;
            self.transcript.extend_from_slice(if ech {
                hello.ech_inner().expect("retry keeps the offer")
            } else {
                &hello.msg
            });
            msg = self.next_handshake()?;
            if msg[0] != 2 {
                return Err(unexpected(msg[0]));
            }
            sh = ServerHello::parse(&msg[4..])?;
            if !hello.offers_cipher(sh.suite) {
                return Err(TlsError::NoSharedCipher);
            }
            if sh.hrr {
                return Err(TlsError::Other(
                    "a second retry request is not allowed".to_owned(),
                ));
            }
        }
        if ech {
            if sh.version != 0x0304 {
                return Err(ech_rejected(&hello, sh.ech.as_deref()));
            }
            let suite = Suite::from_id(sh.suite)
                .filter(|suite| suite.is_tls13())
                .ok_or(TlsError::NoSharedCipher)?;
            self.ech_accepted(&hello, &msg, suite, sh.ech.as_deref())?;
        }
        self.transcript.extend_from_slice(&msg);
        self.suite = Suite::from_id(sh.suite);
        match sh.version {
            0x0304 => self.run13(&mut hello, &mut sh),
            0x0303 => self.run12(&mut hello, &mut sh),
            _ => Err(TlsError::NoSharedCipher),
        }?;
        self.check_alpn(&hello, &mut sh)?;
        self.done = true;
        self.handshake_deadline = None;
        Ok(())
    }

    fn ech_retry_accepted(
        &mut self,
        hello: &Hello,
        sh: &ServerHello,
        msg: &[u8],
        suite: Suite,
    ) -> Result<(), TlsError> {
        let confirmation = sh.ech.as_deref().ok_or_else(|| ech_rejected(hello, None))?;
        if confirmation.len() != 8 {
            return Err(TlsError::Other(
                "ech: the retry confirmation is not eight bytes".to_owned(),
            ));
        }
        let inner = hello.ech_inner().expect("checked");
        let mut transcript = message_hash(suite.hash(), inner);
        transcript.extend_from_slice(&hrr_without_confirmation(msg)?);
        let derived = confirmation_secret(
            suite.hash(),
            &hello.ech_inner_random().expect("checked"),
            &transcript,
            b"hrr ech accept confirmation",
        );
        if derived != confirmation {
            return Err(ech_rejected(hello, None));
        }
        self.client_random = hello.ech_inner_random().expect("checked");
        let mut transcript = message_hash(suite.hash(), inner);
        transcript.extend_from_slice(msg);
        self.transcript = transcript;
        Ok(())
    }

    fn ech_accepted(
        &mut self,
        hello: &Hello,
        msg: &[u8],
        suite: Suite,
        retry: Option<&[u8]>,
    ) -> Result<(), TlsError> {
        let mut transcript = self.transcript.clone();
        let mut hello_conf = msg.to_vec();
        hello_conf[30..38].fill(0);
        transcript.extend_from_slice(&hello_conf);
        let derived = confirmation_secret(
            suite.hash(),
            &hello.ech_inner_random().expect("checked"),
            &transcript,
            b"ech accept confirmation",
        );
        if derived != msg[30..38] {
            return Err(ech_rejected(hello, retry));
        }
        self.client_random = hello.ech_inner_random().expect("checked");
        Ok(())
    }

    fn check_alpn(&mut self, hello: &Hello, sh: &mut ServerHello) -> Result<(), TlsError> {
        if let Some(pick) = sh.alpn.take() {
            if !hello.offers_alpn(&pick) {
                return Err(TlsError::Other(
                    "server selected an ALPN protocol we did not offer".to_owned(),
                ));
            }
            self.alpn = Some(pick);
        }
        Ok(())
    }

    fn run13(&mut self, hello: &mut Hello, sh: &mut ServerHello) -> Result<(), TlsError> {
        self.version = Some(Version::Tls13);
        let suite = Suite::from_id(sh.suite)
            .filter(|suite| suite.is_tls13())
            .ok_or(TlsError::NoSharedCipher)?;
        let (group, peer) = sh
            .share
            .as_ref()
            .ok_or_else(|| TlsError::Other("server hello carries no key share".to_owned()))?;
        let shared = hello.agree(*group, peer)?;
        let hash = suite.hash();
        let zeros = vec![0u8; hash.len()];
        let early = kdf::extract(hash, &zeros, &zeros);
        let derived = kdf::derive(hash, &early, b"derived", &[]);
        let handshake_secret = kdf::extract(hash, &derived, &shared);
        let client_hs = kdf::derive(hash, &handshake_secret, b"c hs traffic", &self.transcript);
        let server_hs = kdf::derive(hash, &handshake_secret, b"s hs traffic", &self.transcript);
        let derived2 = kdf::derive(hash, &handshake_secret, b"derived", &[]);
        let master = kdf::extract(hash, &derived2, &zeros);
        self.log_secrets(&[
            ("CLIENT_HANDSHAKE_TRAFFIC_SECRET", &client_hs),
            ("SERVER_HANDSHAKE_TRAFFIC_SECRET", &server_hs),
        ]);
        self.read_key = Some(Direction::tls13(suite, &server_hs));
        self.send_ccs()?;

        let msg = self.next_expect(8)?;
        self.transcript.extend_from_slice(&msg);
        sh.alpn = encrypted_extensions(&msg[4..])?;

        // A TLS 1.3 server interleaves its CertificateRequest ahead of its own Certificate.
        let mut asked = None;
        let mut msg = self.next_handshake()?;
        if msg[0] == 13 {
            asked = Some(certificate_request13(&msg[4..])?);
            self.transcript.extend_from_slice(&msg);
            msg = self.next_expect(11)?;
        } else if msg[0] != 11 {
            return Err(unexpected(msg[0]));
        }
        let chain = certificates13(&msg[4..])?;
        self.verify_chain(&chain)?;
        self.transcript.extend_from_slice(&msg);

        let msg = self.next_expect(15)?;
        let signed = std::mem::take(&mut self.transcript);
        self.verify_certificate_verify(&msg[4..], &signed, true)?;
        self.transcript = signed;
        self.transcript.extend_from_slice(&msg);

        let msg = self.next_expect(20)?;
        let expected =
            kdf::verify_data(hash, &kdf::finished_key(hash, &server_hs), &self.transcript);
        if msg[4..] != expected[..] {
            return Err(TlsError::Other("server Finished did not verify".to_owned()));
        }
        self.transcript.extend_from_slice(&msg);

        // Both application secrets take the transcript only through the server's Finished.
        let server_ap = kdf::derive(hash, &master, b"s ap traffic", &self.transcript);
        let client_ap = kdf::derive(hash, &master, b"c ap traffic", &self.transcript);
        self.log_secrets(&[
            ("CLIENT_TRAFFIC_SECRET_0", &client_ap),
            ("SERVER_TRAFFIC_SECRET_0", &server_ap),
        ]);
        self.read_key = Some(Direction::tls13(suite, &server_ap));
        self.write_key = Some(Direction::tls13(suite, &client_hs));

        if let Some((context, offered)) = &asked {
            // The answer's bytes count in our own Finished hash, whether it carries a chain or not.
            let (certificate, verify) = match &self.client_cert {
                Some(identity) => identity.flight13(context, offered, &self.transcript, hash),
                None => (certificate_answer13(context), None),
            };
            self.send_encrypted(HANDSHAKE, &certificate)?;
            self.transcript.extend_from_slice(&certificate);
            if let Some(verify) = &verify {
                self.send_encrypted(HANDSHAKE, verify)?;
                self.transcript.extend_from_slice(verify);
            }
        }

        let verify = kdf::verify_data(hash, &kdf::finished_key(hash, &client_hs), &self.transcript);
        let mut finished = Vec::with_capacity(4 + verify.len());
        finished.push(20);
        finished.extend_from_slice(&(verify.len() as u32).to_be_bytes()[1..]);
        finished.extend_from_slice(&verify);
        self.send_encrypted(HANDSHAKE, &finished)?;
        self.transcript.extend_from_slice(&finished);
        self.write_key = Some(Direction::tls13(suite, &client_ap));
        Ok(())
    }

    fn run12(&mut self, hello: &mut Hello, sh: &mut ServerHello) -> Result<(), TlsError> {
        self.version = Some(Version::Tls12);
        let suite = Suite::from_id(sh.suite)
            .filter(|suite| !suite.is_tls13())
            .ok_or(TlsError::NoSharedCipher)?;
        let msg = self.next_expect(11)?;
        let chain = certificates12(&msg[4..])?;
        self.verify_chain(&chain)?;
        self.transcript.extend_from_slice(&msg);

        // A static-RSA suite has no ServerKeyExchange: the leaf's own key carries the pre-master.
        let share = if suite.is_rsa() {
            None
        } else {
            let msg = self.next_expect(12)?;
            let (group, peer, signed_at) = server_key_exchange(&msg[4..])?;
            let mut signed = Vec::with_capacity(64 + signed_at);
            signed.extend_from_slice(&self.client_random);
            signed.extend_from_slice(&sh.random);
            signed.extend_from_slice(&msg[4..4 + signed_at]);
            self.verify_certificate_verify(&msg[4 + signed_at..], &signed, false)?;
            self.transcript.extend_from_slice(&msg);
            Some((group, peer))
        };
        let mut msg = self.next_handshake()?;
        let asked = (msg[0] == 13)
            .then(|| certificate_request12(&msg[4..]))
            .transpose()?;
        if asked.is_some() {
            self.transcript.extend_from_slice(&msg);
            msg = self.next_handshake()?;
        }
        if msg[0] != 14 {
            return Err(unexpected(msg[0]));
        }
        self.transcript.extend_from_slice(&msg);
        let mut presenting = false;
        if let Some(offered) = &asked {
            presenting = self.send_certificate12(offered)?;
        }

        let (pre_master, exchange) = match share {
            Some((group, peer)) => {
                let (public, shared) = match hello.share_public(group) {
                    Some(public) => (public.to_vec(), hello.agree(group, &peer)?),
                    None => hello.ephemeral(group, &peer)?,
                };
                let mut exchange = Vec::with_capacity(1 + public.len());
                exchange.push(public.len() as u8);
                exchange.extend_from_slice(&public);
                (shared, exchange)
            }
            None => rsa_exchange(
                self.leaf
                    .as_ref()
                    .ok_or_else(|| TlsError::BadCertificate("no leaf to key".to_owned()))?,
            )?,
        };
        let cke = message(16, &exchange);
        self.send_plain(HANDSHAKE, &cke, [0x03, 0x03])?;
        self.transcript.extend_from_slice(&cke);

        // RFC 7627 hashes the ClientKeyExchange into the EMS transcript, as Go does after writing it.
        let hash = suite.hash();
        let session_hash = sh.ems.then(|| hash.hash(&self.transcript));

        // The certificate's proof follows the key exchange, over the transcript that now holds both.
        if presenting {
            if let Some(offered) = &asked {
                self.send_client_verify12(offered)?;
            }
        }

        let (master, directions) = super::tls12::keys(
            suite,
            &pre_master,
            &self.client_random,
            &sh.random,
            session_hash.as_deref(),
        );

        self.log_secrets(&[("CLIENT_RANDOM", &master)]);
        self.client12 = Some(directions.client);
        self.server12 = Some(directions.server);
        self.send_ccs()?;
        self.write_key = self.client12.take();

        let verify = super::tls12::finished(suite, &master, b"client finished", &self.transcript);
        let finished = message(20, &verify);
        self.send_encrypted(HANDSHAKE, &finished)?;
        self.transcript.extend_from_slice(&finished);

        let mut msg = self.next_handshake()?;
        while msg[0] == 4 {
            self.transcript.extend_from_slice(&msg);
            msg = self.next_handshake()?;
        }
        if msg[0] != 20 {
            return Err(unexpected(msg[0]));
        }
        let expected = super::tls12::finished(suite, &master, b"server finished", &self.transcript);
        if msg[4..] != expected[..] {
            return Err(TlsError::Other("server Finished did not verify".to_owned()));
        }
        self.transcript.extend_from_slice(&msg);
        Ok(())
    }

    fn next_expect(&mut self, kind: u8) -> Result<Vec<u8>, TlsError> {
        let msg = self.next_handshake()?;
        if msg[0] != kind {
            return Err(unexpected(msg[0]));
        }
        Ok(msg)
    }

    fn send_ccs(&mut self) -> Result<(), TlsError> {
        if self.ccs_sent {
            return Ok(());
        }
        self.ccs_sent = true;
        self.send_plain(CCS, &[1], [0x03, 0x03])
    }

    fn send_plain(&mut self, kind: u8, body: &[u8], version: [u8; 2]) -> Result<(), TlsError> {
        let mut out = Vec::with_capacity(5 + body.len());
        out.push(kind);
        out.extend_from_slice(&version);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        self.io.write_all(&out)?;
        Ok(())
    }

    /// The TLS 1.2 certificate a client-auth request draws, sent after the flight's `ServerHelloDone`:
    /// the configured chain, or the empty one when the key cannot sign for a scheme the server names.
    fn send_certificate12(&mut self, offered: &[u16]) -> Result<bool, TlsError> {
        let certificate = self.client_cert.as_ref().and_then(|identity| {
            identity
                .signer(offered, false)
                .map(|_| certificate_chain(&identity.chain, None))
        });
        let presenting = certificate.is_some();
        let certificate = certificate.unwrap_or_else(certificate_empty);
        self.send_plain(HANDSHAKE, &certificate, [0x03, 0x03])?;
        self.transcript.extend_from_slice(&certificate);
        Ok(presenting)
    }

    /// The TLS 1.2 proof of the certificate, over the transcript that now holds the key exchange too.
    fn send_client_verify12(&mut self, offered: &[u16]) -> Result<(), TlsError> {
        let Some(identity) = &self.client_cert else {
            return Ok(());
        };
        let verify = identity
            .verify12(offered, &self.transcript)
            .ok_or_else(|| TlsError::BadCertificate("client certificate proof".to_owned()))?;
        self.send_plain(HANDSHAKE, &verify, [0x03, 0x03])?;
        self.transcript.extend_from_slice(&verify);
        Ok(())
    }

    fn send_encrypted(&mut self, kind: u8, body: &[u8]) -> Result<(), TlsError> {
        let mut out = Vec::with_capacity(5 + body.len() + 16);
        let tls12 = self.version == Some(Version::Tls12);
        let keys = self
            .write_key
            .as_mut()
            .ok_or_else(|| TlsError::Other("no write keys".to_owned()))?;
        if tls12 {
            record::seal12(keys, kind, body, &mut out)?;
        } else {
            record::seal13(keys, kind, body, &mut out)?;
        }
        self.io.write_all(&out)?;
        Ok(())
    }

    /// Reads one record's body into `plain`, decrypts it in place, and leaves its content pending there.
    fn read_record(&mut self) -> Result<u8, TlsError> {
        let deadline = self.handshake_deadline;
        let mut header = [0u8; 5];
        exact_until(&mut self.io, &mut header, deadline)?;
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if len > MAX_RECORD {
            return Err(TlsError::Other(
                "record exceeds the maximum length".to_owned(),
            ));
        }
        self.plain_at = 0;
        self.plain_end = 0;
        if self.plain.len() < len {
            self.plain.resize(len, 0);
        }
        exact_until(&mut self.io, &mut self.plain[..len], deadline)?;
        let Self {
            read_key,
            server12,
            version,
            plain,
            ..
        } = self;
        let (kind, start, bytes) =
            decrypt(read_key, server12, *version, header, &mut plain[..len])?;
        self.plain_at = start;
        self.plain_end = start + bytes;
        Ok(kind)
    }

    /// The pending plaintext, which every record and carrier chunk leaves in `plain`.
    fn pending(&self) -> &[u8] {
        &self.plain[self.plain_at..self.plain_end]
    }

    fn take_pending(&mut self) {
        self.plain_at = 0;
        self.plain_end = 0;
    }

    /// Copies pending plaintext into `buf` and moves the cursor, reclaiming the buffer when drained.
    fn deliver(&mut self, buf: &mut [u8]) -> usize {
        let n = (self.plain_end - self.plain_at).min(buf.len());
        buf[..n].copy_from_slice(&self.plain[self.plain_at..self.plain_at + n]);
        self.plain_at += n;
        if self.plain_at == self.plain_end {
            self.take_pending();
        }
        n
    }

    fn next_handshake(&mut self) -> Result<Vec<u8>, TlsError> {
        loop {
            if self.hs.len() >= 4 {
                let len = u32::from_be_bytes([0, self.hs[1], self.hs[2], self.hs[3]]) as usize;
                if len > MAX_HANDSHAKE {
                    return Err(TlsError::Other("handshake message is too long".to_owned()));
                }
                if self.hs.len() >= 4 + len {
                    return Ok(self.hs.drain(..4 + len).collect());
                }
            }
            match self.read_record()? {
                HANDSHAKE => {
                    let (at, end) = (self.plain_at, self.plain_end);
                    self.hs.extend_from_slice(&self.plain[at..end]);
                    self.take_pending();
                }
                CCS => {}
                ALERT => return Err(alert(self.pending())),
                other => return Err(unexpected(other)),
            }
        }
    }

    fn verify_chain(&mut self, chain: &[&[u8]]) -> Result<(), TlsError> {
        let leaf = *chain
            .first()
            .ok_or_else(|| TlsError::BadCertificate("empty certificate chain".to_owned()))?;
        let intermediates: Vec<CertificateDer<'_>> = chain[1..]
            .iter()
            .copied()
            .map(CertificateDer::from)
            .collect();
        self.verifier
            .verify_server_cert(
                &CertificateDer::from(leaf),
                &intermediates,
                &self.server_name,
                &[],
                UnixTime::now(),
            )
            .map_err(|error| TlsError::BadCertificate(error.to_string()))?;
        self.leaf = Some(leaf.to_vec());
        Ok(())
    }

    /// Checks a `CertificateVerify` (TLS 1.3) or `ServerKeyExchange` signature (TLS 1.2)
    /// against the leaf's key, over bytes the caller names.
    fn verify_certificate_verify(
        &self,
        body: &[u8],
        signed: &[u8],
        tls13: bool,
    ) -> Result<(), TlsError> {
        let mut r = Reader::new(body);
        let scheme = r.u16()?;
        let signature = r.vec16()?;
        if tls13 && matches!(scheme, 0x0201 | 0x0401 | 0x0501 | 0x0601) {
            return Err(TlsError::BadCertificate(
                "TLS 1.3 forbids RSA PKCS#1 signatures".to_owned(),
            ));
        }
        let supported = self.verifier.supported_verify_schemes();
        if !supported
            .iter()
            .any(|offered| u16::from(*offered) == scheme)
        {
            return Err(TlsError::BadCertificate(format!(
                "server used an unoffered signature scheme {scheme:#06x}"
            )));
        }
        let leaf = self
            .leaf
            .as_deref()
            .ok_or_else(|| TlsError::BadCertificate("no leaf certificate".to_owned()))?;
        let content = if tls13 {
            let mut content = vec![0x20u8; 64];
            content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
            content.push(0);
            content.extend_from_slice(&self.suite.map_or(Hash::Sha256, Suite::hash).hash(signed));
            content
        } else {
            signed.to_vec()
        };
        verify_signature(leaf, scheme, &content, signature)
    }

    #[allow(
        clippy::uninit_vec,
        reason = "the read reports the bytes it wrote, and only those join the length"
    )]
    fn pump(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        loop {
            if self.plain_at < self.plain_end {
                return Ok(self.deliver(buf));
            }
            if self.eof {
                return Ok(0);
            }
            if self.inbuf.is_empty()
                && self.version == Some(Version::Tls13)
                && buf.len() >= RECORD_READ
            {
                let filled = self.read_direct(buf)?;
                if filled > 0 {
                    return Ok(filled);
                }
                continue;
            }
            let filled = self.process_inbuf(buf)?;
            if filled > 0 {
                return Ok(filled);
            }
            let at = self.inbuf.len();
            self.inbuf.reserve(RECORD_READ);
            // SAFETY: the room is spare capacity, and the length below covers only the bytes `read` reports writing.
            let room = unsafe {
                std::slice::from_raw_parts_mut(self.inbuf.as_mut_ptr().add(at), RECORD_READ)
            };
            match self.io.read(room) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(0);
                }
                Ok(n) => unsafe { self.inbuf.set_len(at + n) },
                Err(error) if TlsError::is_timeout(&error) => return Err(TlsError::Timeout),
                Err(error) => return Err(TlsError::from(error)),
            }
        }
    }

    /// Keeps the ciphertext a poll split already consumed, so the next read resumes the record.
    fn stage(&mut self, head: &[u8], body: &[u8], error: TlsError) -> Result<usize, TlsError> {
        if error == TlsError::Timeout {
            self.inbuf.extend_from_slice(head);
            self.inbuf.extend_from_slice(body);
        }
        Err(error)
    }

    /// Reads one record into the window that will hold it: a TLS 1.3 application body is decrypted
    /// where the transport wrote it, so the plaintext the caller gets costs no second buffer.
    fn read_direct(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        let mut header = [0u8; 5];
        let n = match self.io.read_vectored(&mut [
            std::io::IoSliceMut::new(&mut header),
            std::io::IoSliceMut::new(buf),
        ]) {
            Ok(0) => {
                self.eof = true;
                return Ok(0);
            }
            Ok(n) => n,
            Err(error) if TlsError::is_timeout(&error) => return Err(TlsError::Timeout),
            Err(error) => return Err(TlsError::from(error)),
        };
        let mut got = n.saturating_sub(5);
        if n < 5 {
            let (filled, result) = exact_before(&mut self.io, &mut header[n..]);
            match result {
                Ok(()) => {}
                Err(TlsError::Closed) => {
                    self.eof = true;
                    return Ok(0);
                }
                Err(error) => return self.stage(&header[..n + filled], &[], error),
            }
            got = 0;
        }
        let mut body_at = 0usize;
        let mut filled = 0usize;
        let mut first = Some(header);
        loop {
            let header = if let Some(header) = first.take() {
                header
            } else if got - body_at < 5 {
                break;
            } else {
                let header = header_at(buf, body_at);
                body_at += 5;
                header
            };
            let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
            if len > MAX_RECORD {
                return Err(TlsError::Other(
                    "record exceeds the maximum length".to_owned(),
                ));
            }
            if got - body_at < len {
                // The first record completes where it lies; a later record's tail is staged.
                if filled != 0 || body_at != 0 || len > buf.len() {
                    self.inbuf.extend_from_slice(&header);
                    self.inbuf.extend_from_slice(&buf[body_at..got]);
                    return Ok(filled);
                }
                let (body, result) = exact_before(&mut self.io, &mut buf[got..len]);
                if let Err(error) = result {
                    if error != TlsError::Closed {
                        return self.stage(&header, &buf[..got + body], error);
                    }
                    self.eof = true;
                    return Ok(filled);
                }
                got = len;
            }
            let (kind, start, bytes) = decrypt(
                &mut self.read_key,
                &mut self.server12,
                self.version,
                header,
                &mut buf[body_at..body_at + len],
            )?;
            let plain = body_at + start;
            match kind {
                APPLICATION => {
                    if filled != plain {
                        buf.copy_within(plain..plain + bytes, filled);
                    }
                    filled += bytes;
                }
                HANDSHAKE => {
                    self.hs.extend_from_slice(&buf[plain..plain + bytes]);
                    self.post_handshake()?;
                }
                ALERT => {
                    let error = alert(&buf[plain..plain + bytes]);
                    if error != TlsError::Closed {
                        return Err(error);
                    }
                    self.eof = true;
                    return Ok(filled);
                }
                CCS => {}
                other => return Err(unexpected(other)),
            }
            body_at += len;
        }
        if body_at < got {
            self.inbuf.extend_from_slice(&buf[body_at..got]);
        }
        Ok(filled)
    }

    fn post_handshake(&mut self) -> Result<(), TlsError> {
        loop {
            if self.hs.len() < 4 {
                return Ok(());
            }
            let len = u32::from_be_bytes([0, self.hs[1], self.hs[2], self.hs[3]]) as usize;
            if len > MAX_HANDSHAKE {
                return Err(TlsError::Other("handshake message is too long".to_owned()));
            }
            if self.hs.len() < 4 + len {
                return Ok(());
            }
            let (kind, request) = (self.hs[0], self.hs.get(4).copied() == Some(1));
            // A ticket's body is dropped unread; a KeyUpdate reads one byte. Neither needs a copy.
            self.hs.drain(..4 + len);
            match kind {
                4 => {}
                24 => self.key_update(request)?,
                other => return Err(unexpected(other)),
            }
        }
    }

    fn key_update(&mut self, request: bool) -> Result<(), TlsError> {
        let Self {
            read_key,
            write_key,
            reply,
            ..
        } = self;
        read_key
            .as_mut()
            .ok_or_else(|| TlsError::Other("key update before keys".to_owned()))?
            .update();
        if request {
            let update = message(24, &[0]);
            let write = write_key
                .as_mut()
                .ok_or_else(|| TlsError::Other("key update before keys".to_owned()))?;
            write.update();
            record::seal13(write, HANDSHAKE, &update, reply)?;
        }
        Ok(())
    }

    /// Decrypts every whole record straight from the caller's chunk into the caller's window, so a
    /// roomy window costs one body copy and no staged ciphertext, and returns the bytes delivered.
    fn process_direct(&mut self, ciphertext: &[u8], buf: &mut [u8]) -> Result<usize, TlsError> {
        let mut at = 0usize;
        let mut filled = 0usize;
        loop {
            if ciphertext.len() - at < 5 {
                break;
            }
            let header = header_at(ciphertext, at);
            let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
            if len > MAX_RECORD {
                return Err(TlsError::Other(
                    "record exceeds the maximum length".to_owned(),
                ));
            }
            if ciphertext.len() - at - 5 < len {
                break;
            }
            at += 5 + len;
            let body = &ciphertext[at - len..at];
            let (kind, bytes) = if header[0] == CCS {
                if self.version == Some(Version::Tls12) {
                    if let Some(keys) = self.server12.take() {
                        self.read_key = Some(keys);
                    }
                }
                (CCS, 0)
            } else {
                match self.read_key.as_mut() {
                    None => {
                        buf[filled..filled + len].copy_from_slice(body);
                        (header[0], len)
                    }
                    Some(keys) if self.version == Some(Version::Tls13) => {
                        if header[0] == ALERT {
                            buf[filled..filled + len].copy_from_slice(body);
                            (ALERT, len)
                        } else if header[0] != APPLICATION {
                            return Err(unexpected(header[0]));
                        } else {
                            record::open13_into(keys, header, body, &mut buf[filled..])?
                        }
                    }
                    Some(keys) => (
                        header[0],
                        record::open12_into(keys, header[0], body, &mut buf[filled..])?,
                    ),
                }
            };
            match kind {
                APPLICATION => filled += bytes,
                HANDSHAKE => {
                    self.hs.extend_from_slice(&buf[filled..filled + bytes]);
                    self.post_handshake()?;
                }
                ALERT => {
                    let error = alert(&buf[filled..filled + bytes]);
                    if error == TlsError::Closed {
                        self.eof = true;
                    } else {
                        return Err(error);
                    }
                }
                CCS => {}
                other => return Err(unexpected(other)),
            }
        }
        if at < ciphertext.len() {
            self.inbuf.extend_from_slice(&ciphertext[at..]);
        }
        Ok(filled)
    }

    /// Decrypts every whole record in `inbuf`, copying application data straight into `buf` and
    /// staging only what does not fit, and returns the bytes delivered.
    fn process_inbuf(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        let mut filled = 0usize;
        loop {
            let at = self.in_at;
            if self.inbuf.len() - at < 5 {
                break;
            }
            let header = header_at(&self.inbuf, at);
            let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
            if len > MAX_RECORD {
                return Err(TlsError::Other(
                    "record exceeds the maximum length".to_owned(),
                ));
            }
            if self.inbuf.len() - at - 5 < len {
                break;
            }
            self.in_at = at + 5 + len;
            let Self {
                inbuf,
                read_key,
                server12,
                version,
                ..
            } = self;
            let (kind, start, bytes) = decrypt(
                read_key,
                server12,
                *version,
                header,
                &mut inbuf[at + 5..at + 5 + len],
            )?;
            let plain = &inbuf[at + 5 + start..at + 5 + start + bytes];
            match kind {
                APPLICATION => {
                    let room = buf.len() - filled;
                    let take = plain.len().min(room);
                    buf[filled..filled + take].copy_from_slice(&plain[..take]);
                    filled += take;
                    if take < plain.len() {
                        if self.plain_at == self.plain_end {
                            self.plain_at = 0;
                            self.plain_end = 0;
                        }
                        let begin = self.plain_end;
                        let end = begin + (plain.len() - take);
                        if self.plain.len() < end {
                            self.plain.resize(end, 0);
                        }
                        self.plain[begin..end].copy_from_slice(&plain[take..]);
                        self.plain_end = end;
                    }
                }
                HANDSHAKE => {
                    self.hs.extend_from_slice(plain);
                    self.post_handshake()?;
                }
                ALERT => {
                    if alert(plain) == TlsError::Closed {
                        self.eof = true;
                    } else {
                        return Err(alert(plain));
                    }
                }
                CCS => {}
                other => return Err(unexpected(other)),
            }
        }
        if self.in_at == self.inbuf.len() {
            self.inbuf.clear();
            self.in_at = 0;
        } else if self.in_at > 0 {
            self.inbuf.drain(..self.in_at);
            self.in_at = 0;
        }
        Ok(filled)
    }

    fn seal_parts(&mut self, parts: &[&[u8]], out: &mut Vec<u8>) -> Result<(), TlsError> {
        if !self.reply.is_empty() {
            out.append(&mut self.reply);
        }
        let version = self.version;
        let keys = self
            .write_key
            .as_mut()
            .ok_or_else(|| TlsError::Other("no write keys".to_owned()))?;
        seal_chunks(parts, out, |chunk, out| match version {
            Some(Version::Tls12) => record::seal12_parts(keys, APPLICATION, chunk, out),
            _ => record::seal13_parts(keys, APPLICATION, chunk, out),
        })
    }

    /// Seals `parts` into the session's own write buffer and sends it, so a relay write after the first costs no allocation.
    fn seal_out(&mut self, parts: &[&[u8]]) -> std::io::Result<()> {
        let mut out = std::mem::take(&mut self.out);
        out.clear();
        let sent = self
            .seal_parts(parts, &mut out)
            .map_err(std::io::Error::other)
            .and_then(|()| self.io.write_all(&out));
        self.out = out;
        sent
    }

    fn flush_reply(&mut self) -> std::io::Result<()> {
        if !self.reply.is_empty() {
            self.io.write_all(&self.reply)?;
            self.reply.clear();
        }
        Ok(())
    }
}

/// The chunks a frame seals into: one record while the whole frame fits the record's plaintext
/// budget, and a split at the budget otherwise, so a gathered write keeps its one-record shape.
pub(crate) fn seal_chunks(
    parts: &[&[u8]],
    out: &mut Vec<u8>,
    mut seal: impl FnMut(&[&[u8]], &mut Vec<u8>) -> Result<(), TlsError>,
) -> Result<(), TlsError> {
    if !parts.is_empty()
        && parts.iter().all(|part| !part.is_empty())
        && parts.iter().map(|part| part.len()).sum::<usize>() <= MAX_PLAINTEXT
    {
        return seal(parts, out);
    }
    let mut chunk: Vec<&[u8]> = Vec::new();
    let mut held = 0usize;
    for part in parts {
        let mut rest = *part;
        while !rest.is_empty() {
            let room = MAX_PLAINTEXT - held;
            if rest.len() <= room {
                chunk.push(rest);
                held += rest.len();
                if held == MAX_PLAINTEXT {
                    seal(&chunk, out)?;
                    chunk.clear();
                    held = 0;
                }
                break;
            }
            let (lead, tail) = rest.split_at(room);
            chunk.push(lead);
            seal(&chunk, out)?;
            chunk.clear();
            held = 0;
            rest = tail;
        }
    }
    if !chunk.is_empty() {
        seal(&chunk, out)?;
    }
    Ok(())
}

impl<S: Stream> TlsProvider for Session<S> {
    fn name() -> &'static str {
        "utls"
    }

    fn suites(&self) -> Vec<String> {
        self.profile
            .ciphers
            .iter()
            .map(|id| format!("{id:#06x}"))
            .collect()
    }

    fn handshake(&mut self) -> Result<(), TlsError> {
        self.run()
    }

    fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    fn closed(&self) -> bool {
        self.eof
    }

    fn peer_leaf(&self) -> Option<&[u8]> {
        self.leaf.as_deref()
    }

    fn open(&mut self, ciphertext: &[u8], buf: &mut [u8]) -> std::io::Result<(usize, usize)> {
        if !self.done {
            return Err(std::io::Error::other("shaped: handshake incomplete"));
        }
        if self.plain_at < self.plain_end {
            return Ok((self.deliver(buf), 0));
        }
        if ciphertext.is_empty() {
            return Ok((0, 0));
        }
        if self.inbuf.is_empty() && buf.len() >= ciphertext.len() {
            let filled = self
                .process_direct(ciphertext, buf)
                .map_err(std::io::Error::other)?;
            return Ok((filled, ciphertext.len()));
        }
        self.inbuf.extend_from_slice(ciphertext);
        let filled = self.process_inbuf(buf).map_err(std::io::Error::other)?;
        Ok((filled, ciphertext.len()))
    }

    fn seal_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> std::io::Result<usize> {
        if !self.done {
            return Err(std::io::Error::other("shaped: handshake incomplete"));
        }
        self.seal_parts(&[plaintext], out)
            .map_err(std::io::Error::other)?;
        Ok(plaintext.len())
    }

    fn seal_slices_into(&mut self, parts: &[&[u8]], out: &mut Vec<u8>) -> std::io::Result<()> {
        if !self.done {
            return Err(std::io::Error::other("shaped: handshake incomplete"));
        }
        self.seal_parts(parts, out).map_err(std::io::Error::other)
    }
}

impl<S: Stream + RecordAlignment> RecordAlignment for Session<S> {
    fn engage_record_alignment(&mut self) {
        self.io.engage_record_alignment();
    }

    fn disarm_record_alignment(&mut self) {
        self.io.disarm_record_alignment();
    }

    fn write_all_slices(&mut self, parts: &[&[u8]]) -> std::io::Result<()> {
        if !self.done {
            self.run().map_err(std::io::Error::other)?;
        }
        self.flush_reply()?;
        self.seal_out(parts)
    }
}

impl<S: Stream> Read for Session<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.done {
            self.run().map_err(std::io::Error::other)?;
        }
        self.flush_reply()?;
        self.pump(buf).map_err(std::io::Error::other)
    }
}

impl<S: Stream> Write for Session<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.done {
            self.run().map_err(std::io::Error::other)?;
        }
        self.seal_out(&[buf])?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.io.flush()
    }
}

/// A server hello, both versions' fields in one parse.
struct ServerHello {
    random: [u8; 32],
    suite: u16,
    version: u16,
    share: Option<(u16, Vec<u8>)>,
    hrr_group: Option<u16>,
    cookie: Option<Vec<u8>>,
    alpn: Option<Vec<u8>>,
    ech: Option<Vec<u8>>,
    ems: bool,
    hrr: bool,
}

impl ServerHello {
    fn parse(body: &[u8]) -> Result<Self, TlsError> {
        let mut r = Reader::new(body);
        let legacy = r.u16()?;
        let random: [u8; 32] = r
            .take(32)?
            .try_into()
            .map_err(|_| TlsError::Other("short server random".to_owned()))?;
        let _session_id = r.vec8()?;
        let suite = r.u16()?;
        let _compression = r.u8()?;
        let hrr = random == HRR_RANDOM;
        let mut out = Self {
            random,
            suite,
            version: legacy,
            share: None,
            hrr_group: None,
            cookie: None,
            alpn: None,
            ech: None,
            ems: false,
            hrr,
        };
        if r.done() {
            return Ok(out);
        }
        let extensions = r.vec16()?;
        let mut ext = Reader::new(extensions);
        while !ext.done() {
            let kind = ext.u16()?;
            let value = ext.vec16()?;
            match kind {
                0x002b => {
                    let mut v = Reader::new(value);
                    out.version = v.u16()?;
                }
                0x0033 => {
                    let mut v = Reader::new(value);
                    if hrr {
                        out.hrr_group = Some(v.u16()?);
                    } else {
                        let group = v.u16()?;
                        out.share = Some((group, v.vec16()?.to_vec()));
                    }
                }
                0x002c => {
                    let mut v = Reader::new(value);
                    out.cookie = Some(v.vec16()?.to_vec());
                }
                0x0010 => {
                    let mut v = Reader::new(value);
                    let list = v.vec16()?;
                    let mut first = Reader::new(list);
                    out.alpn = Some(first.vec8()?.to_vec());
                }
                0x0017 => out.ems = true,
                0xfe0d => out.ech = Some(value.to_vec()),
                _ => {}
            }
        }
        Ok(out)
    }
}

/// The ALPN pick an encrypted extensions message carries, if any.
fn encrypted_extensions(body: &[u8]) -> Result<Option<Vec<u8>>, TlsError> {
    let mut r = Reader::new(body);
    let extensions = r.vec16()?;
    let mut ext = Reader::new(extensions);
    while !ext.done() {
        let kind = ext.u16()?;
        let value = ext.vec16()?;
        if kind == 0x0010 {
            let mut v = Reader::new(value);
            let mut first = Reader::new(v.vec16()?);
            return Ok(Some(first.vec8()?.to_vec()));
        }
    }
    Ok(None)
}

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    pub(crate) fn done(&self) -> bool {
        self.at >= self.bytes.len()
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], TlsError> {
        let end = self
            .at
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| TlsError::Other("truncated handshake".to_owned()))?;
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, TlsError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, TlsError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn u24(&mut self) -> Result<usize, TlsError> {
        let bytes = self.take(3)?;
        Ok(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) as usize)
    }

    pub(crate) fn vec8(&mut self) -> Result<&'a [u8], TlsError> {
        let len = usize::from(self.u8()?);
        self.take(len)
    }

    pub(crate) fn vec16(&mut self) -> Result<&'a [u8], TlsError> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }

    /// A three-byte length prefix, as a certificate list carries.
    pub(crate) fn vec24(&mut self) -> Result<&'a [u8], TlsError> {
        let len = self.u24()?;
        self.take(len)
    }
}

/// The chain a TLS 1.3 `Certificate` carries, each entry borrowed from `body`; TLS 1.3 wraps every entry
/// in its own extensions, which the walk reads past.
fn certificates13(body: &[u8]) -> Result<Vec<&[u8]>, TlsError> {
    let mut r = Reader::new(body);
    let context = r.u8()?;
    r.take(usize::from(context))?;
    let list = r.vec24()?;
    let mut list = Reader::new(list);
    let mut chain = Vec::new();
    while !list.done() {
        chain.push(list.vec24()?);
        let _extensions = list.vec16()?;
    }
    if chain.is_empty() {
        return Err(TlsError::BadCertificate(
            "server sent no certificate".to_owned(),
        ));
    }
    Ok(chain)
}

/// The chain a TLS 1.2 `Certificate` carries, borrowed the same way; TLS 1.2 has no per-entry extensions.
fn certificates12(body: &[u8]) -> Result<Vec<&[u8]>, TlsError> {
    let mut r = Reader::new(body);
    let list = r.vec24()?;
    let mut list = Reader::new(list);
    let mut chain = Vec::new();
    while !list.done() {
        chain.push(list.vec24()?);
    }
    if chain.is_empty() {
        return Err(TlsError::BadCertificate(
            "server sent no certificate".to_owned(),
        ));
    }
    Ok(chain)
}

fn server_key_exchange(body: &[u8]) -> Result<(u16, Vec<u8>, usize), TlsError> {
    let mut r = Reader::new(body);
    let curve_type = r.u8()?;
    if curve_type != 3 {
        return Err(TlsError::NoSharedCipher);
    }
    let group = r.u16()?;
    let peer = r.vec8()?.to_vec();
    let signed_at = r.at;
    Ok((group, peer, signed_at))
}

fn message_hash(hash: Hash, message: &[u8]) -> Vec<u8> {
    let digest = hash.hash(message);
    let mut out = Vec::with_capacity(4 + digest.len());
    out.push(254);
    out.extend_from_slice(&(digest.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(&digest);
    out
}

fn confirmation_secret(hash: Hash, random: &[u8; 32], transcript: &[u8], label: &[u8]) -> [u8; 8] {
    let secret = kdf::extract(hash, &[], random);
    let mut out = [0u8; 8];
    kdf::expand_label(hash, &secret, label, &hash.hash(transcript), &mut out);
    out
}

fn hrr_without_confirmation(msg: &[u8]) -> Result<Vec<u8>, TlsError> {
    let mut out = msg.to_vec();
    if out.len() < 4 + 2 + 32 + 1 {
        return Err(TlsError::Other("short retry request".to_owned()));
    }
    let mut at = 4 + 2 + 32;
    let session = usize::from(out[at]);
    at += 1 + session;
    at += 2 + 1;
    if out.len() < at + 2 {
        return Err(TlsError::Other("short retry extensions".to_owned()));
    }
    let end = at + 2 + (usize::from(out[at]) << 8 | usize::from(out[at + 1]));
    at += 2;
    while at < end {
        if out.len() < at + 4 {
            return Err(TlsError::Other("short retry extension".to_owned()));
        }
        let kind = u16::from_be_bytes([out[at], out[at + 1]]);
        let len = usize::from(out[at + 2]) << 8 | usize::from(out[at + 3]);
        if kind == 0xfe0d {
            let body = at + 4;
            if len != 8 || out.len() < body + len {
                return Err(TlsError::Other(
                    "ech: the retry confirmation is not eight bytes".to_owned(),
                ));
            }
            out[body..body + len].fill(0);
            return Ok(out);
        }
        at += 4 + len;
    }
    Err(TlsError::Other(
        "ech: the retry request carries no confirmation".to_owned(),
    ))
}

fn ech_rejected(hello: &Hello, retry: Option<&[u8]>) -> TlsError {
    match retry {
        Some(list) if list.len() > 2 => TlsError::EchRetry(list.to_vec().into()),
        _ => TlsError::Other(format!(
            "ech: the server did not accept the offer for {}",
            hello.ech_public_name().unwrap_or("its public name")
        )),
    }
}

fn certificate_empty() -> Vec<u8> {
    message(11, &[0, 0, 0])
}

impl ClientIdentity {
    /// The TLS 1.3 answer to a `CertificateRequest`: the chain, then the `CertificateVerify` that
    /// binds it to the key. The empty chain answers when the key cannot sign for an offered scheme.
    fn flight13(
        &self,
        context: &[u8],
        offered: &[u16],
        transcript: &[u8],
        hash: Hash,
    ) -> (Vec<u8>, Option<Vec<u8>>) {
        let Some(signer) = self.signer(offered, true) else {
            return (certificate_answer13(context), None);
        };
        let certificate = certificate_chain(&self.chain, Some(context));
        let mut to_sign = Vec::with_capacity(64 + 34 + hash.len());
        to_sign.extend_from_slice(&[0x20; 64]);
        to_sign.extend_from_slice(b"TLS 1.3, client CertificateVerify");
        to_sign.push(0);
        let mut hashed = transcript.to_vec();
        hashed.extend_from_slice(&certificate);
        to_sign.extend_from_slice(&hash.hash(&hashed));
        let Ok(signature) = signer.sign(&to_sign) else {
            return (certificate_answer13(context), None);
        };
        let verify = signature_message(u16::from(signer.scheme()), &signature);
        (certificate, Some(verify))
    }

    /// The TLS 1.2 `CertificateVerify` over the transcript that already holds the certificate and
    /// the key exchange, or `None` when the key cannot sign for an offered scheme.
    fn verify12(&self, offered: &[u16], transcript: &[u8]) -> Option<Vec<u8>> {
        let signer = self.signer(offered, false)?;
        let signature = signer.sign(transcript).ok()?;
        Some(signature_message(u16::from(signer.scheme()), &signature))
    }
}

/// A TLS 1.3 `CertificateRequest`: its context, which the answer echoes, and the signature schemes
/// it offers, empty when the request names none.
fn certificate_request13(body: &[u8]) -> Result<(Vec<u8>, Vec<u16>), TlsError> {
    let truncated = || TlsError::Other("truncated CertificateRequest".to_owned());
    let (&len, rest) = body.split_first().ok_or_else(truncated)?;
    let len = usize::from(len);
    let rest = rest.get(len..).ok_or_else(truncated)?;
    let context = body[1..=len].to_vec();
    let (&[high, low], extensions) = rest.split_first_chunk::<2>().ok_or_else(truncated)?;
    let len = usize::from(u16::from_be_bytes([high, low]));
    let extensions = extensions.get(..len).ok_or_else(truncated)?;
    Ok((context, signature_schemes(extensions)?))
}

/// A TLS 1.2 `CertificateRequest`: the signature schemes it offers for the certificate types it
/// names, as Go filters them, and the protocol's own list when it names no schemes.
fn certificate_request12(body: &[u8]) -> Result<Vec<u16>, TlsError> {
    let truncated = || TlsError::Other("truncated CertificateRequest".to_owned());
    let (&types, rest) = body.split_first().ok_or_else(truncated)?;
    let types = rest.get(..usize::from(types)).ok_or_else(truncated)?;
    let rest = &rest[types.len()..];
    let listed = match rest.split_first_chunk::<2>() {
        Some((&[high, low], rest)) => {
            let len = usize::from(u16::from_be_bytes([high, low]));
            rest.get(..len).ok_or_else(truncated)?
        }
        None => &[
            0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01,
        ][..],
    };
    let rsa = types.contains(&0x01);
    let ecdsa = types.contains(&0x40);
    Ok(listed
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_be_bytes(*pair))
        .filter(|scheme| match *scheme {
            0x0401 | 0x0501 | 0x0601 | 0x0804 | 0x0805 | 0x0806 => rsa,
            0x0403 | 0x0503 | 0x0603 | 0x0807 => ecdsa,
            _ => false,
        })
        .collect())
}

/// The `signature_algorithms` extension inside a TLS 1.3 `CertificateRequest`'s extension list.
fn signature_schemes(extensions: &[u8]) -> Result<Vec<u16>, TlsError> {
    let truncated = || TlsError::Other("truncated CertificateRequest".to_owned());
    let mut at = 0;
    while at + 4 <= extensions.len() {
        let kind = u16::from_be_bytes([extensions[at], extensions[at + 1]]);
        let len = usize::from(u16::from_be_bytes([extensions[at + 2], extensions[at + 3]]));
        let body = extensions.get(at + 4..at + 4 + len).ok_or_else(truncated)?;
        if kind == 13 {
            let (&[high, low], listed) = body.split_first_chunk::<2>().ok_or_else(truncated)?;
            let len = usize::from(u16::from_be_bytes([high, low]));
            let listed = listed.get(..len).ok_or_else(truncated)?;
            return Ok(listed
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_be_bytes(*pair))
                .collect());
        }
        at += 4 + len;
    }
    Ok(Vec::new())
}

/// A `Certificate` message: the TLS 1.3 request context when the caller names one, then the chain
/// in presentation order, each entry length-prefixed by three bytes.
fn certificate_chain(chain: &[Vec<u8>], context: Option<&[u8]>) -> Vec<u8> {
    let extensions = usize::from(context.is_some()) * 2;
    let listed: usize = chain.iter().map(|der| 3 + der.len() + extensions).sum();
    let mut body = Vec::with_capacity(1 + context.map_or(0, <[u8]>::len) + 3 + listed);
    if let Some(context) = context {
        body.push(context.len() as u8);
        body.extend_from_slice(context);
    }
    body.extend_from_slice(&(listed as u32).to_be_bytes()[1..]);
    for der in chain {
        body.extend_from_slice(&(der.len() as u32).to_be_bytes()[1..]);
        body.extend_from_slice(der);
        if context.is_some() {
            body.extend_from_slice(&[0, 0]);
        }
    }
    message(11, &body)
}

/// A `CertificateVerify` or `Certificate` message body: the scheme, then the signature it names.
fn signature_message(scheme: u16, signature: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + signature.len());
    body.extend_from_slice(&scheme.to_be_bytes());
    body.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    body.extend_from_slice(signature);
    message(15, &body)
}

/// The TLS 1.3 answer to a `CertificateRequest` when `TlsConfig` carries no client certificate: the
/// request's own context ahead of a zero-length chain, so the server reads it as anonymous.
fn certificate_answer13(context: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + context.len());
    out.push(11);
    out.extend_from_slice(&((4 + context.len()) as u32).to_be_bytes()[1..]);
    out.push(context.len() as u8);
    out.extend_from_slice(context);
    out.extend_from_slice(&[0, 0, 0]);
    out
}

/// Random bytes, shaped as the reference's padding reader asks for: the caller re-rolls what it rejects.
fn fill(buf: &mut [u8]) -> Result<(), TlsError> {
    getrandom::fill(buf).map_err(|e| TlsError::Other(format!("random: {e}")))
}

/// The static-RSA pre-master and the exchange that carries it: no `ServerKeyExchange` sends a share,
/// so the client draws the secret and encrypts it to the leaf's own key.
fn rsa_exchange(leaf: &[u8]) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    let key = subject_public_key(leaf)?;
    if key.algorithm != OID_RSA {
        return Err(TlsError::BadCertificate(
            "a static-RSA suite without an RSA leaf".to_owned(),
        ));
    }
    let (modulus, exponent) = super::rsa::public_key(key.key)
        .ok_or_else(|| TlsError::BadCertificate("malformed RSA key".to_owned()))?;
    // The pre-master repeats the hello's own version in its first two bytes, and the rest is random.
    let mut secret = vec![0u8; 48];
    secret[..2].copy_from_slice(&TLS12.to_be_bytes());
    fill(&mut secret[2..])?;
    let mut cipher = Vec::with_capacity(modulus.len());
    super::rsa::encrypt(modulus, exponent, &secret, &mut fill, &mut cipher)?;
    let mut exchange = Vec::with_capacity(2 + cipher.len());
    exchange.extend_from_slice(&(cipher.len() as u16).to_be_bytes());
    exchange.extend_from_slice(&cipher);
    Ok((secret, exchange))
}

pub(crate) fn message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(kind);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(body);
    out
}

fn unexpected(kind: u8) -> TlsError {
    TlsError::Other(format!("unexpected handshake message {kind}"))
}

fn header_at(bytes: &[u8], at: usize) -> [u8; 5] {
    bytes[at..at + 5]
        .try_into()
        .expect("five-byte record header")
}

/// Opens one record in place and returns its content type with the plaintext range inside `body`.
fn decrypt(
    read_key: &mut Option<Direction>,
    server12: &mut Option<Direction>,
    version: Option<Version>,
    header: [u8; 5],
    body: &mut [u8],
) -> Result<(u8, usize, usize), TlsError> {
    if header[0] == CCS {
        if version == Some(Version::Tls12) {
            if let Some(keys) = server12.take() {
                *read_key = Some(keys);
            }
        }
        return Ok((CCS, 0, 0));
    }
    let Some(keys) = read_key.as_mut() else {
        return Ok((header[0], 0, body.len()));
    };
    if version != Some(Version::Tls13) {
        return record::open12(keys, header[0], body)
            .map(|(start, bytes)| (header[0], start, bytes));
    }
    if header[0] == ALERT {
        return Ok((ALERT, 0, body.len()));
    }
    if header[0] != APPLICATION {
        return Err(unexpected(header[0]));
    }
    record::open13(keys, header, body).map(|(kind, bytes)| (kind, 0, bytes))
}

/// Fills `buf` from the transport, reporting the bytes it filled before a poll expiry: the
/// caller stages them, so the record resumes instead of decoding its own tail as a header.
fn exact_before<S: Read>(io: &mut S, buf: &mut [u8]) -> (usize, Result<(), TlsError>) {
    let mut filled = 0;
    while filled < buf.len() {
        match io.read(&mut buf[filled..]) {
            Ok(0) => return (filled, Err(TlsError::Closed)),
            Ok(n) => filled += n,
            Err(error) if TlsError::is_timeout(&error) => {
                return (filled, Err(TlsError::Timeout));
            }
            Err(error) => return (filled, Err(TlsError::from(error))),
        }
    }
    (filled, Ok(()))
}

/// Fills `buf` from the transport; a handshake's deadline lets a poll-quantum expiry wait for the peer instead of failing a hello that is already on the wire.
pub(crate) fn exact_until<S: Read>(
    io: &mut S,
    mut buf: &mut [u8],
    deadline: Option<Instant>,
) -> Result<(), TlsError> {
    while !buf.is_empty() {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(TlsError::Timeout);
        }
        match io.read(buf) {
            Ok(0) => return Err(TlsError::Closed),
            Ok(n) => buf = &mut buf[n..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if TlsError::is_timeout(&error) => {
                if deadline.is_none() {
                    return Err(TlsError::Timeout);
                }
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    std::thread::sleep(WOULD_BLOCK_RETRY);
                }
            }
            Err(error) => return Err(TlsError::from(error)),
        }
    }
    Ok(())
}

fn alert(body: &[u8]) -> TlsError {
    match body.get(1) {
        Some(0) => TlsError::Closed,
        Some(description) => TlsError::Other(format!("peer alert {description}")),
        None => TlsError::Other("truncated alert".to_owned()),
    }
}

/// The leaf's `SubjectPublicKeyInfo`, reduced to what the signature schemes need.
struct PublicKey<'a> {
    algorithm: &'a [u8],
    key: &'a [u8],
}

fn subject_public_key(der: &[u8]) -> Result<PublicKey<'_>, TlsError> {
    let bad = || TlsError::BadCertificate("malformed certificate key".to_owned());
    let (tag, certificate, _) = tlv(der).ok_or_else(bad)?;
    if tag != 0x30 {
        return Err(bad());
    }
    let (tag, mut tbs, _) = tlv(certificate).ok_or_else(bad)?;
    if tag != 0x30 {
        return Err(bad());
    }
    if tbs.first() == Some(&0xa0) {
        tbs = tlv(tbs).ok_or_else(bad)?.2;
    }
    // serial, signature, issuer, validity, subject — the fields ahead of the key.
    for wanted in [0x02, 0x30, 0x30, 0x30, 0x30] {
        let (tag, _, rest) = tlv(tbs).ok_or_else(bad)?;
        if tag != wanted {
            return Err(bad());
        }
        tbs = rest;
    }
    let (tag, spki, _) = tlv(tbs).ok_or_else(bad)?;
    if tag != 0x30 {
        return Err(bad());
    }
    let (tag, algorithm, rest) = tlv(spki).ok_or_else(bad)?;
    if tag != 0x30 {
        return Err(bad());
    }
    let (tag, oid, _) = tlv(algorithm).ok_or_else(bad)?;
    if tag != 0x06 {
        return Err(bad());
    }
    let (tag, bits, _) = tlv(rest).ok_or_else(bad)?;
    if tag != 0x03 || bits.first() != Some(&0) {
        return Err(bad());
    }
    Ok(PublicKey {
        algorithm: oid,
        key: &bits[1..],
    })
}

pub(super) fn tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let first = *input.get(1)?;
    let (len, header) = if first & 0x80 == 0 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 3 {
            return None;
        }
        let mut len = 0usize;
        for byte in input.get(2..2 + count)? {
            len = (len << 8) | usize::from(*byte);
        }
        (len, 2 + count)
    };
    let value = input.get(header..header + len)?;
    Some((tag, value, &input[header + len..]))
}

const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];

fn verify_signature(
    leaf: &[u8],
    scheme: u16,
    content: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    let key = subject_public_key(leaf)?;
    let algorithm: &'static dyn ring::signature::VerificationAlgorithm = match scheme {
        0x0403 if key.algorithm == OID_EC => &ring::signature::ECDSA_P256_SHA256_ASN1,
        0x0503 if key.algorithm == OID_EC => &ring::signature::ECDSA_P384_SHA384_ASN1,
        0x0807 if key.algorithm == OID_ED25519 => &ring::signature::ED25519,
        0x0201 if key.algorithm == OID_RSA => {
            &ring::signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY
        }
        0x0401 if key.algorithm == OID_RSA => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        0x0501 if key.algorithm == OID_RSA => &ring::signature::RSA_PKCS1_2048_8192_SHA384,
        0x0601 if key.algorithm == OID_RSA => &ring::signature::RSA_PKCS1_2048_8192_SHA512,
        0x0804 if key.algorithm == OID_RSA => &ring::signature::RSA_PSS_2048_8192_SHA256,
        0x0805 if key.algorithm == OID_RSA => &ring::signature::RSA_PSS_2048_8192_SHA384,
        0x0806 if key.algorithm == OID_RSA => &ring::signature::RSA_PSS_2048_8192_SHA512,
        other => {
            return Err(TlsError::BadCertificate(format!(
                "unsupported signature scheme {other:#06x}"
            )))
        }
    };
    ring::signature::UnparsedPublicKey::new(algorithm, key.key)
        .verify(content, signature)
        .map_err(|_| TlsError::BadCertificate("handshake signature did not verify".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::shaped::profiles;
    use crate::tls::shaped::Fingerprint;
    use rustls::client::danger::HandshakeSignatureValid;
    use rustls::DigitallySignedStruct;
    use rustls::SignatureScheme;
    use std::io::{Read, Write};

    struct Sink;

    impl Read for Sink {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn session(version: Version, suite: Suite, read: Direction, write: Direction) -> Session<Sink> {
        session_on(Sink, version, suite, read, write)
    }

    fn session_on<S: Stream>(
        io: S,
        version: Version,
        suite: Suite,
        read: Direction,
        write: Direction,
    ) -> Session<S> {
        let cfg = TlsConfig {
            insecure: true,
            resumption: true,
            ..TlsConfig::default()
        };
        Session {
            io,
            verifier: crate::tls::rustls_backend::verifier(&cfg).expect("verifier"),
            server_name: ServerName::try_from("tls.test".to_owned()).expect("name"),
            profile: profiles::profile("chrome").expect("chrome profile"),
            hello: None,
            handshake_deadline: None,
            client_random: [0; 32],
            transcript: Vec::new(),
            version: Some(version),
            suite: Some(suite),
            read_key: Some(read),
            write_key: Some(write),
            server12: None,
            client12: None,
            alpn: None,
            leaf: None,
            done: true,
            eof: false,
            ccs_sent: false,
            hs: Vec::new(),
            plain: Vec::new(),
            plain_at: 0,
            plain_end: 0,
            inbuf: Vec::new(),
            in_at: 0,
            reply: Vec::new(),
            out: Vec::new(),
            key_log: None,
            client_cert: None,
        }
    }

    /// A close already read with the data is reported as the end, not hidden behind a
    /// socket the peer kept open for more.
    #[cfg_attr(miri, ignore = "reaches ring's CPUID FFI through the record KDF")]
    #[test]
    fn a_received_close_is_reported() {
        let suite = Suite::Aes128GcmSha256;
        let secret = [9u8; 32];
        let mut session = session(
            Version::Tls13,
            suite,
            Direction::tls13(suite, &secret),
            Direction::tls13(suite, &secret),
        );
        session.eof = true;
        assert!(session.closed());
    }

    #[cfg_attr(miri, ignore = "reaches ring's CPUID FFI through the record KDF")]
    #[test]
    fn a_roomy_tls13_chunk_lands_record_by_record_in_the_callers_window() {
        let suite = Suite::Aes128GcmSha256;
        let secret = [9u8; 32];
        let mut session = session(
            Version::Tls13,
            suite,
            Direction::tls13(suite, &secret),
            Direction::tls13(suite, &secret),
        );
        let mut sender = Direction::tls13(suite, &secret);
        let mut wire = Vec::new();
        record::seal13(&mut sender, APPLICATION, b"one", &mut wire).expect("seals");
        record::seal13(&mut sender, APPLICATION, b"two", &mut wire).expect("seals");
        let mut window = [0u8; 128];
        let (got, consumed) = session.open(&wire, &mut window).expect("opens");
        assert_eq!((got, consumed), (6, wire.len()));
        assert_eq!(&window[..6], b"onetwo");
        assert_eq!(session.plain_buffer(), [], "a roomy window stages nothing");
    }

    /// A TLS 1.3 record read through `Read` lands in the caller's window: the bytes past the
    /// plaintext are the record's own decrypted tail, not the untouched window a staged copy leaves.
    #[cfg_attr(miri, ignore = "reaches ring's CPUID FFI through the record KDF")]
    #[test]
    fn a_tls13_record_is_read_where_it_lands() {
        let suite = Suite::Aes128GcmSha256;
        let secret = [9u8; 32];
        let mut sender = Direction::tls13(suite, &secret);
        let mut wire = Vec::new();
        record::seal13(&mut sender, APPLICATION, b"in place", &mut wire).expect("seals");
        let body = wire.len() - 5;
        let mut session = session_on(
            Server(wire, 0),
            Version::Tls13,
            suite,
            Direction::tls13(suite, &secret),
            Direction::tls13(suite, &secret),
        );
        let mut window = vec![0xabu8; RECORD_READ];
        let got = session.read(&mut window).expect("reads");
        assert_eq!((got, &window[..got]), (8, b"in place".as_slice()));
        assert!(
            window[got..body].iter().any(|&byte| byte != 0xab),
            "the record was decrypted in the window, not copied out of a staging buffer"
        );
        assert_eq!(
            session.plain_buffer(),
            [],
            "a body that fits stages nothing"
        );
    }

    /// A window narrower than the record takes what it holds and leaves the rest pending.
    #[cfg_attr(miri, ignore = "reaches ring's CPUID FFI through the record KDF")]
    #[test]
    fn a_narrow_window_drains_the_record_from_the_staging_buffer() {
        let suite = Suite::Aes128GcmSha256;
        let secret = [9u8; 32];
        let mut sender = Direction::tls13(suite, &secret);
        let mut wire = Vec::new();
        record::seal13(&mut sender, APPLICATION, b"in place", &mut wire).expect("seals");
        let mut session = session_on(
            Server(wire, 0),
            Version::Tls13,
            suite,
            Direction::tls13(suite, &secret),
            Direction::tls13(suite, &secret),
        );
        let mut window = [0u8; 4];
        assert_eq!(session.read(&mut window).expect("reads"), 4);
        assert_eq!(&window, b"in p");
        assert_eq!(session.read(&mut window).expect("reads"), 4);
        assert_eq!(&window, b"lace");
    }

    struct Vectored {
        wire: Vec<u8>,
        at: usize,
        calls: std::cell::Cell<usize>,
    }

    impl Read for Vectored {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let n = (self.wire.len() - self.at).min(out.len());
            out[..n].copy_from_slice(&self.wire[self.at..self.at + n]);
            self.at += n;
            Ok(n)
        }

        fn read_vectored(
            &mut self,
            bufs: &mut [std::io::IoSliceMut<'_>],
        ) -> std::io::Result<usize> {
            self.calls.set(self.calls.get() + 1);
            let mut moved = 0;
            for buf in bufs {
                let n = (self.wire.len() - self.at).min(buf.len());
                buf[..n].copy_from_slice(&self.wire[self.at..self.at + n]);
                self.at += n;
                moved += n;
                if self.at == self.wire.len() {
                    break;
                }
            }
            Ok(moved)
        }
    }

    impl Write for Vectored {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A record the transport can hand over whole costs one vectored read, and its body is the
    /// window the caller gets back rather than a copy of a second buffer.
    #[cfg_attr(miri, ignore = "reaches ring's CPUID FFI through the record KDF")]
    #[test]
    fn a_pulled_record_lands_in_one_vectored_read() {
        let suite = Suite::Aes128GcmSha256;
        let secret = [9u8; 32];
        let mut sender = Direction::tls13(suite, &secret);
        let mut wire = Vec::new();
        record::seal13(&mut sender, APPLICATION, b"in place", &mut wire).expect("seals");
        let mut session = session_on(
            Vectored {
                wire,
                at: 0,
                calls: std::cell::Cell::new(0),
            },
            Version::Tls13,
            suite,
            Direction::tls13(suite, &secret),
            Direction::tls13(suite, &secret),
        );
        let mut window = vec![0u8; RECORD_READ];
        assert_eq!(session.read(&mut window).expect("reads"), 8);
        assert_eq!(&window[..8], b"in place");
        assert_eq!(session.io.calls.get(), 1, "one vectored read per record");
        assert_eq!(session.plain_buffer(), []);
    }

    #[cfg_attr(miri, ignore = "reaches ring's CPUID FFI through the record KDF")]
    #[test]
    fn a_tls13_record_split_across_chunks_is_staged_and_then_lands() {
        let suite = Suite::ChaCha20Sha256;
        let secret = [11u8; 32];
        let mut session = session(
            Version::Tls13,
            suite,
            Direction::tls13(suite, &secret),
            Direction::tls13(suite, &secret),
        );
        let mut sender = Direction::tls13(suite, &secret);
        let mut wire = Vec::new();
        record::seal13(&mut sender, APPLICATION, b"three", &mut wire).expect("seals");
        let cut = wire.len() - 3;
        let mut window = [0u8; 128];
        let (got, consumed) = session.open(&wire[..cut], &mut window).expect("opens");
        assert_eq!((got, consumed), (0, cut));
        let (got, consumed) = session.open(&wire[cut..], &mut window).expect("opens");
        assert_eq!((got, consumed), (5, wire.len() - cut));
        assert_eq!(&window[..5], b"three");
        assert_eq!(session.plain_buffer(), []);
    }

    #[cfg_attr(miri, ignore = "reaches ring's CPUID FFI through the record KDF")]
    #[test]
    fn a_roomy_tls12_gcm_chunk_opens_behind_its_explicit_nonce() {
        let suite = Suite::EcdheAes128GcmSha256;
        let key = [3u8; 16];
        let iv = [5u8; 4];
        let mut session = session(
            Version::Tls12,
            suite,
            Direction::tls12(suite, &key, &[], &iv),
            Direction::tls12(suite, &key, &[], &iv),
        );
        let mut sender = Direction::tls12(suite, &key, &[], &iv);
        let mut wire = Vec::new();
        record::seal12(&mut sender, APPLICATION, b"one", &mut wire).expect("seals");
        record::seal12(&mut sender, APPLICATION, b"two", &mut wire).expect("seals");
        let mut window = [0u8; 128];
        let (got, consumed) = session.open(&wire, &mut window).expect("opens");
        assert_eq!((got, consumed), (6, wire.len()));
        assert_eq!(&window[..6], b"onetwo");
        assert_eq!(session.plain_buffer(), []);
    }

    #[cfg_attr(miri, ignore = "reaches ring's CPUID FFI through the record KDF")]
    #[test]
    fn a_roomy_tls12_chacha_chunk_opens_without_an_explicit_nonce() {
        let suite = Suite::EcdheChaCha20Sha256;
        let key = [3u8; 32];
        let iv = [5u8; 12];
        let mut session = session(
            Version::Tls12,
            suite,
            Direction::tls12(suite, &key, &[], &iv),
            Direction::tls12(suite, &key, &[], &iv),
        );
        let mut sender = Direction::tls12(suite, &key, &[], &iv);
        let mut wire = Vec::new();
        record::seal12(&mut sender, APPLICATION, b"four", &mut wire).expect("seals");
        let mut window = [0u8; 128];
        let (got, consumed) = session.open(&wire, &mut window).expect("opens");
        assert_eq!((got, consumed), (4, wire.len()));
        assert_eq!(&window[..4], b"four");
        assert_eq!(session.plain_buffer(), []);
    }

    #[cfg_attr(miri, ignore = "reaches ring's CPUID FFI through the record KDF")]
    #[test]
    fn a_roomy_tls12_cbc_chunk_opens_past_its_iv_and_mac() {
        let suite = Suite::EcdheAes128CbcSha;
        let (key, mac_key, iv) = ([3u8; 16], [4u8; 20], [0u8; 16]);
        let mut session = session(
            Version::Tls12,
            suite,
            Direction::tls12(suite, &key, &mac_key, &iv),
            Direction::tls12(suite, &key, &mac_key, &iv),
        );
        let mut sender = Direction::tls12(suite, &key, &mac_key, &iv);
        let mut wire = Vec::new();
        record::seal12(&mut sender, APPLICATION, b"one", &mut wire).expect("seals");
        record::seal12(&mut sender, APPLICATION, b"twoo", &mut wire).expect("seals");
        let mut window = [0u8; 128];
        let (got, consumed) = session.open(&wire, &mut window).expect("opens");
        assert_eq!((got, consumed), (7, wire.len()));
        assert_eq!(&window[..7], b"onetwoo");
        assert_eq!(session.plain_buffer(), []);
    }

    /// A handshake flight past the handshake is walked where it lies and takes no heap: a ticket's
    /// body is dropped unread and a `KeyUpdate` reads its one byte, so nothing is copied out to be
    /// looked at.
    #[cfg_attr(miri, ignore = "reaches ring's CPUID FFI through the record KDF")]
    #[test]
    fn a_post_handshake_flight_is_read_where_it_lies() {
        let suite = Suite::Aes128GcmSha256;
        let secret = [9u8; 32];
        let mut session = session(
            Version::Tls13,
            suite,
            Direction::tls13(suite, &secret),
            Direction::tls13(suite, &secret),
        );
        session.hs = std::hint::black_box(message(4, &[7u8; 40]));
        let ((), counts) =
            crate::alloc_count::measure(|| session.post_handshake().expect("drops the ticket"));
        assert_eq!(session.hs.len(), 0, "the ticket is consumed");
        assert_eq!(session.reply.len(), 0, "a ticket asks for no answer");
        assert_eq!(
            counts.allocs, 0,
            "the flight is read where it lies: {counts:?}"
        );
    }

    /// A `Certificate`'s chain is walked where it lies: every entry the parse returns is the record's own
    /// byte range, so neither version copies a DER out to look at it.
    #[test]
    fn a_certificate_chain_is_read_where_the_record_lies() {
        let leaf = [1u8, 2, 3, 4, 5];
        let issuer = [6u8, 7, 8, 9, 10, 11, 12, 13, 14];
        let mut body = vec![0];
        body.extend_from_slice(&[0, 0, 24]);
        body.extend_from_slice(&[0, 0, 5]);
        body.extend_from_slice(&leaf);
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&[0, 0, 9]);
        body.extend_from_slice(&issuer);
        body.extend_from_slice(&[0, 0]);
        let chain = certificates13(&body).expect("reads the chain");
        assert_eq!(chain.len(), 2, "both entries are there");
        assert_eq!(chain[0], leaf.as_slice(), "the leaf is first");
        assert_eq!(
            chain[0].as_ptr(),
            body[7..].as_ptr(),
            "the leaf is the record's own range"
        );
        assert_eq!(
            chain[1].as_ptr(),
            body[17..].as_ptr(),
            "the issuer is the record's own range"
        );

        let mut body12 = Vec::new();
        body12.extend_from_slice(&[0, 0, 20]);
        body12.extend_from_slice(&[0, 0, 5]);
        body12.extend_from_slice(&leaf);
        body12.extend_from_slice(&[0, 0, 9]);
        body12.extend_from_slice(&issuer);
        let chain = certificates12(&body12).expect("reads the chain");
        assert_eq!(chain[1], issuer.as_slice(), "1.2 needs no extensions");
        assert_eq!(
            chain[0].as_ptr(),
            body12[6..].as_ptr(),
            "1.2 reads in place too"
        );
        assert_eq!(
            chain[1].as_ptr(),
            body12[14..].as_ptr(),
            "and so does its issuer"
        );
    }
    #[derive(Debug)]
    struct Unverified;

    impl ServerCertVerifier for Unverified {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            Vec::new()
        }
    }

    struct Server(Vec<u8>, usize);

    impl Read for Server {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let left = &self.0[self.1..];
            let take = left.len().min(out.len());
            out[..take].copy_from_slice(&left[..take]);
            self.1 += take;
            Ok(take)
        }
    }

    impl Write for Server {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn accepting_server_hello(hello: &Hello) -> Vec<u8> {
        let inner = hello.ech_inner().expect("inner").to_vec();
        let random = hello.ech_inner_random().expect("random");
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x22; 32]);
        body.push(0);
        body.extend_from_slice(&[0x13, 0x01, 0]);
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        extensions.extend_from_slice(&[0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
        extensions.extend_from_slice(&[0x44; 32]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut zeroed = body.clone();
        zeroed[2 + 24..2 + 32].fill(0);
        let mut transcript = inner;
        transcript.extend_from_slice(&message(2, &zeroed));
        let confirmation = confirmation_secret(
            Hash::Sha256,
            &random,
            &transcript,
            b"ech accept confirmation",
        );
        body[2 + 24..2 + 32].copy_from_slice(&confirmation);
        let message = message(2, &body);
        let mut record = vec![HANDSHAKE, 0x03, 0x01];
        record.extend_from_slice(&(message.len() as u16).to_be_bytes());
        record.extend_from_slice(&message);
        record
    }

    fn ech_session(list: &[u8], server: impl FnOnce(&Hello) -> Vec<u8>) -> Session<Server> {
        let profile = Fingerprint::default().profile().expect("profile");
        let mut hello =
            Hello::build(profile, "hidden.test", &[], false, &[], None).expect("builds");
        hello.enable_ech(list).expect("ech");
        let server = server(&hello);
        Session::with_hello(
            profile,
            "hidden.test".to_owned(),
            Arc::new(Unverified),
            hello,
            Server(server, 0),
        )
        .expect("session")
    }

    #[cfg_attr(miri, ignore = "uses the OS random source")]
    #[test]
    fn an_accepted_offer_uses_the_inner_transcript() {
        let (list, _) = crate::tls::ech::generate("public.test", 7).expect("generates");
        let mut session = ech_session(&list, accepting_server_hello);
        let error = session.handshake().unwrap_err().to_string();
        assert!(
            !error.contains("did not accept"),
            "the confirming hello must be accepted: {error}"
        );
    }

    #[cfg_attr(miri, ignore = "uses the OS random source")]
    #[test]
    fn an_accepted_offer_logs_the_inner_random() {
        let (list, _) = crate::tls::ech::generate("public.test", 7).expect("generates");
        let mut session = ech_session(&list, accepting_server_hello);
        let (inner, outer) = {
            let hello = session.hello.as_ref().expect("hello");
            (hello.ech_inner_random().expect("inner"), hello.random)
        };
        assert_ne!(inner, outer, "the inner random is not the outer one");
        let path = std::env::temp_dir().join(format!(
            "ferrox-shaped-ech-keylog-{}.log",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let named = path.to_string_lossy().into_owned();
        let log = crate::tls::MasterKeyLog::open(&named).expect("opens");
        session.set_key_log(Some(Arc::new(log)));
        let error = session
            .handshake()
            .expect_err("the fixture ends after ServerHello");
        assert_eq!(error, TlsError::Closed);
        let text = std::fs::read_to_string(&path).expect("the log the session named");
        let _ = std::fs::remove_file(&path);
        let line = text
            .lines()
            .find(|line| line.starts_with("CLIENT_HANDSHAKE_TRAFFIC_SECRET "))
            .unwrap_or_else(|| panic!("the handshake secret is written: {text:?}"));
        let random = line.split(' ').nth(1).expect("a random field");
        assert_eq!(random, crate::foxy::account::hex_encode(&inner));
        assert_ne!(random, crate::foxy::account::hex_encode(&outer));
    }

    #[cfg_attr(miri, ignore = "uses the OS random source")]
    #[test]
    fn a_non_confirming_offer_is_refused() {
        let (list, _) = crate::tls::ech::generate("public.test", 7).expect("generates");
        let mut session = ech_session(&list, |hello| {
            let mut server = accepting_server_hello(hello);
            let tail = server.len() - 8;
            server[tail..].fill(0);
            server
        });
        let error = session.handshake().unwrap_err().to_string();
        assert!(
            error.contains("did not accept"),
            "a hello that does not confirm must be refused: {error}"
        );
    }

    /// A server may only select a suite the hello offered, not merely one this tree implements.
    #[test]
    fn a_server_may_not_select_an_unoffered_suite() {
        let profile = Fingerprint::default().profile().expect("profile");
        let mut hello = Hello::build(profile, "tls.test", &[], false, &[], None).expect("builds");
        hello.set_ciphers(&[0xc02b, 0xc02c, 0x1301, 0x1302, 0x1303]);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x11; 32]);
        body.push(0);
        body.extend_from_slice(&[0xc0, 0x09]);
        body.push(0);
        body.extend_from_slice(&[0, 0]);
        let message = message(2, &body);
        let mut record = vec![HANDSHAKE, 0x03, 0x03];
        record.extend_from_slice(&(message.len() as u16).to_be_bytes());
        record.extend_from_slice(&message);
        let mut session = Session::with_hello(
            profile,
            "tls.test".to_owned(),
            Arc::new(Unverified),
            hello,
            Server(record, 0),
        )
        .expect("session");
        assert_eq!(session.handshake(), Err(TlsError::NoSharedCipher));
    }

    #[cfg_attr(miri, ignore = "uses the OS random source")]
    #[test]
    fn a_retry_without_a_confirmation_is_refused() {
        let (list, _) = crate::tls::ech::generate("public.test", 7).expect("generates");
        let mut session = ech_session(&list, |_| {
            let mut body = vec![0x03, 0x03];
            body.extend_from_slice(&HRR_RANDOM);
            body.push(0);
            body.extend_from_slice(&[0x13, 0x01, 0, 0, 0]);
            let message = message(2, &body);
            let mut record = vec![HANDSHAKE, 0x03, 0x01];
            record.extend_from_slice(&(message.len() as u16).to_be_bytes());
            record.extend_from_slice(&message);
            record
        });
        let error = session.handshake().unwrap_err().to_string();
        assert!(
            error.contains("did not accept"),
            "a retry that ignores the offer must be refused: {error}"
        );
    }

    #[cfg_attr(miri, ignore = "reaches ring's CPUID FFI through the transcript hash")]
    #[test]
    fn the_ech_confirmation_matches_the_reference_schedule() {
        let random = [0x11u8; 32];
        let transcript = b"test transcript";
        assert_eq!(
            confirmation_secret(
                Hash::Sha256,
                &random,
                transcript,
                b"ech accept confirmation"
            ),
            [0x31, 0x5e, 0x4d, 0x20, 0x59, 0x21, 0x87, 0xf1]
        );
        assert_eq!(
            confirmation_secret(
                Hash::Sha256,
                &random,
                transcript,
                b"hrr ech accept confirmation"
            ),
            [0xb3, 0xf3, 0xe4, 0x43, 0x38, 0x4f, 0x04, 0x30]
        );
    }

    #[test]
    fn a_retry_confirmation_is_zeroed_in_the_transcript() {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&HRR_RANDOM);
        body.push(0);
        body.extend_from_slice(&[0x13, 0x01, 0]);
        let mut extensions = vec![0xfe, 0x0d, 0x00, 0x08];
        extensions.extend_from_slice(&[1u8; 8]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let msg = message(2, &body);
        let zeroed = hrr_without_confirmation(&msg).expect("confirmation");
        assert_eq!(&zeroed[zeroed.len() - 8..], &[0u8; 8]);
        assert_eq!(&zeroed[..zeroed.len() - 8], &msg[..msg.len() - 8]);

        let mut missing = msg.clone();
        let at = missing.len() - 12;
        missing[at..at + 2].copy_from_slice(&[0x00, 0x2c]);
        assert!(hrr_without_confirmation(&missing).is_err());
    }

    #[cfg_attr(miri, ignore = "reaches ring's CPUID FFI through the record KDF")]
    #[test]
    fn a_record_split_by_a_timeout_is_resumed_not_lost() {
        let suite = Suite::Aes128GcmSha256;
        let secret = [7u8; 32];
        let mut sender = Direction::tls13(suite, &secret);
        let mut wire = Vec::new();
        record::seal13(&mut sender, APPLICATION, b"hello", &mut wire).expect("seals");
        let mut subject = session_on(
            SplitRead {
                wire,
                at: 0,
                stall_at: 3,
                stalled: false,
            },
            Version::Tls13,
            suite,
            Direction::tls13(suite, &secret),
            Direction::tls13(suite, &secret),
        );

        let mut buf = [0u8; 16];
        let first = subject
            .read(&mut buf)
            .expect_err("the split record times out");
        assert!(
            TlsError::is_timeout(&first),
            "the first read is the timeout"
        );
        let n = subject.read(&mut buf).expect("the record resumes");
        assert_eq!(&buf[..n], b"hello");
    }

    /// The roomy path lands the record in the caller's window; a poll that splits its header or
    /// body leaves the bytes already consumed behind it, so the next read resumes rather than
    /// decoding a body as a header.
    #[cfg_attr(miri, ignore = "reaches ring's CPUID FFI through the record KDF")]
    #[test]
    fn a_landed_record_split_by_a_timeout_is_resumed_not_lost() {
        let suite = Suite::Aes128GcmSha256;
        let secret = [7u8; 32];
        let mut sender = Direction::tls13(suite, &secret);
        let mut wire = Vec::new();
        record::seal13(&mut sender, APPLICATION, b"hello", &mut wire).expect("seals");
        for stall_at in [3usize, 5, 7, 12] {
            let mut subject = session_on(
                SplitRead {
                    wire: wire.clone(),
                    at: 0,
                    stall_at,
                    stalled: false,
                },
                Version::Tls13,
                suite,
                Direction::tls13(suite, &secret),
                Direction::tls13(suite, &secret),
            );
            let mut buf = vec![0u8; RECORD_READ];
            let first = subject
                .read(&mut buf)
                .expect_err("the split record times out");
            assert!(
                TlsError::is_timeout(&first),
                "stall {stall_at}: the first read is the timeout"
            );
            let n = subject.read(&mut buf).expect("the record resumes");
            assert_eq!(&buf[..n], b"hello", "stall {stall_at}");
        }
    }

    #[cfg_attr(miri, ignore = "reaches ring's CPUID FFI through the record KDF")]
    #[test]
    fn a_handshake_record_split_by_a_timeout_is_resumed_not_lost() {
        let mut wire = vec![HANDSHAKE, 0x03, 0x03, 0x00, 0x04];
        wire.extend_from_slice(&[1, 2, 3, 4]);
        let mut subject = session_on(
            SplitRead {
                wire,
                at: 0,
                stall_at: 7,
                stalled: false,
            },
            Version::Tls13,
            Suite::Aes128GcmSha256,
            Direction::tls13(Suite::Aes128GcmSha256, &[0u8; 32]),
            Direction::tls13(Suite::Aes128GcmSha256, &[0u8; 32]),
        );
        subject.read_key = None;
        subject.done = false;
        subject.handshake_deadline = Some(Instant::now() + HANDSHAKE_TIMEOUT);
        assert_eq!(
            subject.read_record().expect("the handshake record resumes"),
            HANDSHAKE
        );
        assert_eq!(subject.pending(), &[1, 2, 3, 4]);
    }

    #[test]
    #[cfg_attr(miri, ignore = "reaches ring's CPUID FFI through the record KDF")]
    fn a_handshake_past_its_deadline_stops_at_the_next_timeout() {
        let mut wire = vec![HANDSHAKE, 0x03, 0x03, 0x00, 0x04];
        wire.extend_from_slice(&[1, 2, 3, 4]);
        let mut subject = session_on(
            SplitRead {
                wire,
                at: 0,
                stall_at: 7,
                stalled: false,
            },
            Version::Tls13,
            Suite::Aes128GcmSha256,
            Direction::tls13(Suite::Aes128GcmSha256, &[0u8; 32]),
            Direction::tls13(Suite::Aes128GcmSha256, &[0u8; 32]),
        );
        subject.read_key = None;
        subject.done = false;
        subject.handshake_deadline = Some(
            Instant::now()
                .checked_sub(Duration::from_secs(1))
                .expect("one second before now"),
        );
        let error = subject
            .read_record()
            .expect_err("a handshake past its deadline refuses");
        assert_eq!(
            error,
            TlsError::Timeout,
            "the refusal is the handshake's timeout"
        );
    }

    #[test]
    fn a_would_block_waits_before_asking_again() {
        struct AlwaysWouldBlock {
            reads: usize,
        }

        impl Read for AlwaysWouldBlock {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                self.reads += 1;
                Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
            }
        }

        let mut stream = AlwaysWouldBlock { reads: 0 };
        let mut buf = [0u8; 1];
        let error = exact_until(
            &mut stream,
            &mut buf,
            Some(Instant::now() + Duration::from_millis(20)),
        )
        .expect_err("the deadline expires");
        assert_eq!(error, TlsError::Timeout);
        assert!(
            stream.reads < 100,
            "{} reads in 20 ms is a spin",
            stream.reads
        );
    }

    struct SplitRead {
        wire: Vec<u8>,
        at: usize,
        stall_at: usize,
        stalled: bool,
    }

    impl Read for SplitRead {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.at == self.stall_at && !self.stalled {
                self.stalled = true;
                return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "poll"));
            }
            let end = if self.at < self.stall_at {
                self.stall_at
            } else {
                self.wire.len()
            };
            let n = (end - self.at).min(buf.len());
            buf[..n].copy_from_slice(&self.wire[self.at..self.at + n]);
            self.at += n;
            Ok(n)
        }
    }

    impl Write for SplitRead {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The record read lands where the record is decrypted from: a stack chunk would have been a second
    /// buffer, zeroed for the full window and then copied into `inbuf`, which only a pointer can see.
    #[cfg_attr(miri, ignore = "reaches ring's CPUID FFI through the record KDF")]
    #[test]
    fn a_record_read_fills_the_inbuf_it_decrypts_from() {
        let suite = Suite::Aes128GcmSha256;
        let secret = [13u8; 32];
        let mut sender = Direction::tls13(suite, &secret);
        let mut wire = Vec::new();
        record::seal13(&mut sender, APPLICATION, b"seven", &mut wire).expect("seals");
        let per_read = wire.len();
        record::seal13(&mut sender, APPLICATION, b"eight", &mut wire).expect("seals");
        let mut subject = session_on(
            Recorder {
                wire,
                per_read,
                base: std::cell::Cell::new(std::ptr::null()),
                len: std::cell::Cell::new(0),
            },
            Version::Tls13,
            suite,
            Direction::tls13(suite, &secret),
            Direction::tls13(suite, &secret),
        );

        let mut buf = [0u8; 16];
        let n = subject.read(&mut buf).expect("the first record lands");
        assert_eq!(&buf[..n], b"seven");
        let base = subject.inbuf.as_ptr();
        let capacity = subject.inbuf.capacity();
        assert_eq!(
            subject.io.len.get(),
            RECORD_READ,
            "the room is one record window"
        );
        assert_eq!(
            subject.io.base.get(),
            base,
            "the read wrote at the vector's own base"
        );

        let n = subject.read(&mut buf).expect("the second record lands");
        assert_eq!(&buf[..n], b"eight");
        assert_eq!(
            subject.io.base.get(),
            base,
            "the next record reuses the same room"
        );
        assert_eq!(
            subject.inbuf.capacity(),
            capacity,
            "the staging vector did not grow between records"
        );
    }

    struct Recorder {
        wire: Vec<u8>,
        per_read: usize,
        base: std::cell::Cell<*const u8>,
        len: std::cell::Cell<usize>,
    }

    impl Read for Recorder {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.base.set(buf.as_ptr());
            self.len.set(buf.len());
            let n = self.per_read.min(buf.len()).min(self.wire.len());
            buf[..n].copy_from_slice(&self.wire[..n]);
            self.wire.drain(..n);
            Ok(n)
        }
    }

    impl Write for Recorder {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A relay write hands its record out of the session's own buffer, kept across writes: a fresh
    /// `Vec` per call is one allocation on every write and a different base each time.
    #[cfg_attr(miri, ignore = "reaches ring's CPUID FFI through the record KDF")]
    #[test]
    fn a_warm_write_seals_into_the_buffer_it_already_owns() {
        let suite = Suite::Aes128GcmSha256;
        let secret = [17u8; 32];
        let mut subject = session_on(
            Tap {
                base: std::cell::Cell::new(std::ptr::null()),
            },
            Version::Tls13,
            suite,
            Direction::tls13(suite, &secret),
            Direction::tls13(suite, &secret),
        );
        let payload = [0x5Au8; 8192];
        subject
            .write_all_slices(&[&b"head"[..], &payload[..], &b"tail"[..]])
            .expect("the first write opens the buffer");
        let capacity = subject.out.capacity();
        assert_eq!(
            subject.out.len(),
            5 + b"head".len() + payload.len() + b"tail".len() + 1 + 16,
            "the slices are sealed into one record"
        );

        let (_, counts) = crate::alloc_count::measure(|| {
            subject.write_all_slices(&[&b"head"[..], &payload[..], &b"tail"[..]])
        });
        assert_eq!(counts.allocs, 0, "a warm write opens no buffer");
        assert_eq!(
            subject.out.capacity(),
            capacity,
            "and does not grow the one it has"
        );
        assert_eq!(
            subject.io.base.get(),
            subject.out.as_ptr(),
            "the record went out from that buffer"
        );

        let (_, counts) =
            crate::alloc_count::measure(|| subject.write(&payload).expect("a single slice"));
        assert_eq!(counts.allocs, 0, "the single-slice write shares it");
    }

    struct Tap {
        base: std::cell::Cell<*const u8>,
    }

    impl Read for Tap {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for Tap {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.base.set(buf.as_ptr());
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl RecordAlignment for Tap {}

    #[test]
    fn a_tls12_request_keeps_only_the_schemes_its_certificate_types_allow() {
        let body = [2, 0x01, 0x40, 0, 4, 0x04, 0x03, 0x04, 0x01];
        assert_eq!(
            certificate_request12(&body).expect("a request"),
            [0x0403, 0x0401]
        );
        let rsa_only = [1, 0x01, 0, 4, 0x04, 0x03, 0x04, 0x01];
        assert_eq!(
            certificate_request12(&rsa_only).expect("a request"),
            [0x0401]
        );
        let none = [0, 0, 4, 0x04, 0x03, 0x04, 0x01];
        assert_eq!(
            certificate_request12(&none).expect("a request"),
            Vec::<u16>::new()
        );
    }
}

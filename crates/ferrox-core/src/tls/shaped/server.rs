// The shaped TLS 1.2 listener: the suites a stock Go server would pick, with the flight and the record layer it builds itself.
use super::client::{
    message, seal_chunks, Reader, APPLICATION, CCS, HANDSHAKE, MAX_HANDSHAKE, MAX_RECORD,
};
use super::keys;
use super::record::{self, Direction, Suite};
use super::tls12;
use crate::tls::{Stream, TlsError, TlsServerConfig};
use boring::hash::MessageDigest;
use boring::pkey::{PKey, Private};
use boring::rsa::Padding;
use boring::sign::{RsaPssSaltlen, Signer};
use ring::rand::{SecureRandom as _, SystemRandom};
use std::io::{Read, Write};

/// The curve preference a stock Go server walks for an ECDHE key exchange; the hybrid group is
/// TLS 1.3 only and cannot fill a TLS 1.2 point.
const CURVES: [u16; 4] = [0x001d, 0x0017, 0x0018, 0x0019];

/// A parsed `ClientHello`: the fields a TLS 1.2 full handshake reads.
struct Hello {
    version: u16,
    random: [u8; 32],
    session: Vec<u8>,
    ciphers: Vec<u16>,
    sni: Option<String>,
    groups: Vec<u16>,
    sigalgs: Vec<u16>,
    alpn: Vec<Vec<u8>>,
    ems: bool,
    point_formats: bool,
    versions: Option<Vec<u16>>,
    secure: bool,
}

impl Hello {
    fn parse(body: &[u8]) -> Result<Self, TlsError> {
        let mut r = Reader::new(body);
        let version = r.u16()?;
        let random: [u8; 32] = r
            .take(32)?
            .try_into()
            .map_err(|_| TlsError::Other("short client random".to_owned()))?;
        let session = r.vec8()?.to_vec();
        let ciphers = ids16(r.vec16()?)?;
        if r.vec8()? != [0] {
            return Err(TlsError::Other(
                "the client offered no null compression".to_owned(),
            ));
        }
        let mut out = Self {
            version,
            random,
            session,
            ciphers,
            sni: None,
            groups: Vec::new(),
            sigalgs: Vec::new(),
            alpn: Vec::new(),
            ems: false,
            point_formats: true,
            versions: None,
            secure: false,
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
                0x0000 => {
                    let mut v = Reader::new(value);
                    let list = v.vec16()?;
                    let mut names = Reader::new(list);
                    if names.u8()? == 0 {
                        out.sni = Some(String::from_utf8_lossy(names.vec16()?).into_owned());
                    }
                }
                0x000a => {
                    let mut v = Reader::new(value);
                    out.groups = ids16(v.vec16()?)?;
                }
                0x000b => {
                    let mut v = Reader::new(value);
                    let formats = v.vec8()?;
                    out.point_formats = formats.is_empty() || formats.contains(&0);
                }
                0x000d => {
                    let mut v = Reader::new(value);
                    out.sigalgs = ids16(v.vec16()?)?;
                }
                0x0010 => {
                    let mut v = Reader::new(value);
                    let list = v.vec16()?;
                    let mut names = Reader::new(list);
                    while !names.done() {
                        out.alpn.push(names.vec8()?.to_vec());
                    }
                }
                0x0017 => out.ems = true,
                0x002b => {
                    let mut v = Reader::new(value);
                    out.versions = Some(ids16(v.vec8()?)?);
                }
                0xff01 => out.secure = true,
                _ => {}
            }
        }
        Ok(out)
    }

    /// The version a listener pinned above TLS 1.2 may still negotiate here, and the one the
    /// reference sends when it does: a `supported_versions` without `0x0303` leaves none.
    fn tls12(&self) -> Result<(), TlsError> {
        if self.version < 0x0303 {
            return Err(TlsError::Other(
                "the client does not offer TLS 1.2".to_owned(),
            ));
        }
        if let Some(versions) = &self.versions {
            if !versions.contains(&0x0303) {
                return Err(TlsError::NoSharedCipher);
            }
        }
        Ok(())
    }

    fn secure(&self) -> bool {
        self.secure || self.ciphers.contains(&0x00ff)
    }
}

/// The pre-master secret a TLS 1.2 RSA key exchange always carries.
const PRE_MASTER: usize = 48;

/// The raw records a hello may occupy before the peek hands the connection to the other engine.
const MAX_PEEK: usize = MAX_HANDSHAKE + 5 * MAX_RECORD;

/// The raw records that carried the `ClientHello`, and whether it offers a version newer than TLS 1.2.
/// A listener that also offers TLS 1.3 replays those bytes to the other engine; a hello this peek
/// cannot read is replayed too, so the engine that owned the connection before still answers it.
pub(crate) fn peek_hello<R: Read>(io: &mut R) -> Result<(Vec<u8>, bool), TlsError> {
    let until = Some(super::client::handshake_deadline());
    let mut raw = Vec::new();
    let mut handshake = Vec::new();
    loop {
        let mut header = [0u8; 5];
        super::client::exact_until(io, &mut header, until)?;
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let at = raw.len();
        raw.extend_from_slice(&header);
        if header[0] != HANDSHAKE || len > MAX_RECORD || raw.len() + len > MAX_PEEK {
            return Ok((raw, true));
        }
        raw.resize(at + 5 + len, 0);
        super::client::exact_until(io, &mut raw[at + 5..], until)?;
        handshake.extend_from_slice(&raw[at + 5..]);
        if handshake.len() < 4 {
            continue;
        }
        let body = u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]]) as usize;
        if body > MAX_HANDSHAKE {
            return Ok((raw, true));
        }
        if handshake.len() < 4 + body {
            continue;
        }
        return match Hello::parse(&handshake[4..4 + body]) {
            Ok(hello) => Ok((
                raw,
                hello.version >= 0x0304
                    || hello.versions.as_ref().is_some_and(|versions| {
                        versions.iter().any(|&id| {
                            id >= 0x0304 && !(id & 0x0f0f == 0x0a0a && id >> 8 == id & 0x00ff)
                        })
                    }),
            )),
            Err(_) => Ok((raw, true)),
        };
    }
}

/// Where a shaped handshake stands, so a poll timeout resumes it instead of starting over.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Hello,
    KeyExchange,
    Ccs,
    Finished,
    ServerFinished,
    Done,
}

/// One listener session: the handshake is driven on the first read or write, then every
/// record seals and opens here, because this lane owns its transport like the Boring one.
pub(crate) struct Server<S: Stream> {
    io: S,
    cfg: TlsServerConfig,
    done: bool,
    failure: Option<String>,
    read: Option<Direction>,
    write: Option<Direction>,
    key: Option<PKey<Private>>,
    transcript: Vec<u8>,
    rec: Vec<u8>,
    rec_have: usize,
    hs: Vec<u8>,
    hs_at: usize,
    plain_at: usize,
    plain_end: usize,
    out: Vec<u8>,
    pending: Vec<u8>,
    pending_at: usize,
    eof: bool,
    sni: Option<Vec<u8>>,
    alpn: Option<Vec<u8>>,
    suite: Option<u16>,
    phase: Phase,
    client_random: [u8; 32],
    client_version: u16,
    ems: bool,
    own_random: [u8; 32],
    share: Option<keys::Share>,
    master: Option<Vec<u8>>,
}

impl<S: Stream> Server<S> {
    pub(crate) fn new(cfg: TlsServerConfig, io: S) -> Self {
        Self {
            io,
            cfg,
            done: false,
            failure: None,
            read: None,
            write: None,
            key: None,
            transcript: Vec::new(),
            rec: Vec::new(),
            rec_have: 0,
            hs: Vec::new(),
            hs_at: 0,
            plain_at: 0,
            plain_end: 0,
            out: Vec::new(),
            pending: Vec::new(),
            pending_at: 0,
            eof: false,
            sni: None,
            alpn: None,
            suite: None,
            phase: Phase::Hello,
            client_random: [0u8; 32],
            client_version: 0,
            ems: false,
            own_random: [0u8; 32],
            share: None,
            master: None,
        }
    }

    pub(crate) fn handshake(&mut self) -> Result<(), TlsError> {
        if self.done {
            return Ok(());
        }
        if let Some(why) = &self.failure {
            return Err(TlsError::Other(why.clone()));
        }
        match self.run() {
            Ok(()) => {
                self.done = true;
                Ok(())
            }
            // A poll quantum is not a failure; the record buffer keeps the partial read.
            Err(TlsError::Timeout) => Err(TlsError::Timeout),
            Err(error) => {
                self.failure = Some(error.to_string());
                Err(error)
            }
        }
    }

    fn run(&mut self) -> Result<(), TlsError> {
        self.flush()?;
        if self.phase == Phase::Hello {
            self.run_hello()?;
        }
        if self.phase == Phase::KeyExchange {
            self.run_key_exchange()?;
        }
        if self.phase == Phase::Ccs {
            self.expect_ccs()?;
            self.phase = Phase::Finished;
        }
        if self.phase == Phase::Finished {
            self.run_finished()?;
        }
        if self.phase == Phase::ServerFinished {
            self.run_server_finished()?;
        }
        Ok(())
    }

    fn run_hello(&mut self) -> Result<(), TlsError> {
        let hello_message = self.next_plain(1)?;
        let hello = Hello::parse(&hello_message[4..])?;
        hello.tls12()?;
        self.sni = hello.sni.as_ref().map(|name| name.as_bytes().to_vec());

        let cert = self.pick_cert(hello.sni.as_deref())?;
        let key = PKey::private_key_from_der(&self.cfg.certs[cert].key_der)
            .map_err(|error| TlsError::Other(format!("server key: {error}")))?;
        let rsa = key.rsa().is_ok();
        let suite_id = crate::tls::cipher_suites::server_pick(
            &self.cfg.cipher_suites,
            &hello.ciphers,
            crate::tls::cipher_suites::aesgcm_preferred(&hello.ciphers),
            |id| ecdsa(id) != rsa,
        )
        .ok_or(TlsError::NoSharedCipher)?;
        let suite = Suite::from_id(suite_id)
            .filter(|suite| !suite.is_tls13())
            .ok_or(TlsError::NoSharedCipher)?;
        self.key = Some(key);
        self.suite = Some(suite_id);
        self.alpn = pick_alpn(&self.cfg.alpn, &hello.alpn);

        let mut random = [0u8; 32];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| TlsError::Other("server random".to_owned()))?;

        let share = if suite.is_rsa() {
            None
        } else {
            let group = CURVES
                .iter()
                .copied()
                .find(|group| hello.groups.is_empty() || hello.groups.contains(group))
                .ok_or(TlsError::NoSharedCipher)?;
            let mut shares = keys::generate(&[group], false)
                .map_err(|why| TlsError::Other(format!("server share: {why}")))?;
            Some(shares.pop().ok_or(TlsError::NoSharedCipher)?)
        };

        let mut flight = self.server_hello(&hello, suite_id, &random, share.is_some());
        let mut transcript = Vec::new();
        transcript.extend_from_slice(&hello_message);
        transcript.extend_from_slice(&flight);
        let certificate = certificate_message(&self.cfg.certs[cert].cert_chain);
        transcript.extend_from_slice(&certificate);
        flight.extend_from_slice(&certificate);
        if let Some(share) = &share {
            let exchange = self.key_exchange(&hello, share, &random)?;
            transcript.extend_from_slice(&exchange);
            flight.extend_from_slice(&exchange);
        }
        let done = message(14, &[]);
        transcript.extend_from_slice(&done);
        flight.extend_from_slice(&done);
        self.queue_plain(HANDSHAKE, &flight);

        self.transcript = transcript;
        self.client_random = hello.random;
        self.client_version = hello.version;
        self.ems = hello.ems;
        self.own_random = random;
        self.share = share;
        self.phase = Phase::KeyExchange;
        self.flush()
    }

    fn run_key_exchange(&mut self) -> Result<(), TlsError> {
        let suite = self
            .suite
            .and_then(Suite::from_id)
            .ok_or(TlsError::NoSharedCipher)?;
        let cke = self.next_plain(16)?;
        self.transcript.extend_from_slice(&cke);
        let pre_master = match self.share.take() {
            Some(share) => {
                let mut r = Reader::new(&cke[4..]);
                let peer = r.vec8()?;
                share
                    .agree(peer)
                    .map_err(|why| TlsError::Other(format!("server agree: {why}")))?
            }
            None => self.rsa_pre_master(&cke[4..])?,
        };
        let session_hash = self.ems.then(|| suite.hash().hash(&self.transcript));
        let (master, directions) = tls12::keys(
            suite,
            &pre_master,
            &self.client_random,
            &self.own_random,
            session_hash.as_deref(),
        );
        if let Some(log) = &self.cfg.master_key_log {
            rustls::KeyLog::log(log.as_ref(), "CLIENT_RANDOM", &self.client_random, &master);
        }
        self.read = Some(directions.client);
        self.write = Some(directions.server);
        self.master = Some(master);
        self.phase = Phase::Ccs;
        Ok(())
    }

    fn run_finished(&mut self) -> Result<(), TlsError> {
        let finished = self.next_encrypted(20)?;
        let expected = {
            let suite = self
                .suite
                .and_then(Suite::from_id)
                .ok_or(TlsError::NoSharedCipher)?;
            let master = self
                .master
                .as_ref()
                .ok_or_else(|| TlsError::Other("no master secret".to_owned()))?;
            tls12::finished(suite, master, b"client finished", &self.transcript)
        };
        if finished[4..] != expected[..] {
            return Err(TlsError::Other("client Finished did not verify".to_owned()));
        }
        self.transcript.extend_from_slice(&finished);
        self.phase = Phase::ServerFinished;
        Ok(())
    }

    fn run_server_finished(&mut self) -> Result<(), TlsError> {
        let verify = {
            let suite = self
                .suite
                .and_then(Suite::from_id)
                .ok_or(TlsError::NoSharedCipher)?;
            let master = self
                .master
                .as_ref()
                .ok_or_else(|| TlsError::Other("no master secret".to_owned()))?;
            tls12::finished(suite, master, b"server finished", &self.transcript)
        };
        self.queue_plain(CCS, &[1]);
        let done = message(20, &verify);
        self.queue_encrypted(HANDSHAKE, &done)?;
        self.transcript.extend_from_slice(&done);
        self.phase = Phase::Done;
        self.flush()
    }

    fn pick_cert(&self, sni: Option<&str>) -> Result<usize, TlsError> {
        if let Some(name) = sni {
            if let Some(at) = self.cfg.certs.iter().position(|entry| {
                entry.cert_chain.first().is_some_and(|leaf| {
                    crate::tls::rustls_backend::sni_matches(
                        &crate::tls::rustls_backend::certificate_names(leaf),
                        name,
                    )
                })
            }) {
                return Ok(at);
            }
            if self.cfg.reject_unknown_sni {
                return Err(TlsError::Other(
                    "no certificate matches the server name".to_owned(),
                ));
            }
        }
        if self.cfg.certs.is_empty() {
            return Err(TlsError::Other(
                "the listener serves no identity".to_owned(),
            ));
        }
        Ok(0)
    }

    fn server_hello(&self, hello: &Hello, suite: u16, random: &[u8; 32], ecdhe: bool) -> Vec<u8> {
        let mut ext = Vec::new();
        if hello.secure() {
            extension(&mut ext, 0xff01, &[0]);
        }
        if hello.ems {
            extension(&mut ext, 0x0017, &[]);
        }
        if ecdhe && hello.point_formats {
            extension(&mut ext, 0x000b, &[1, 0]);
        }
        if let Some(alpn) = &self.alpn {
            let mut body = Vec::with_capacity(3 + alpn.len());
            body.extend_from_slice(&((alpn.len() + 1) as u16).to_be_bytes());
            body.push(alpn.len() as u8);
            body.extend_from_slice(alpn);
            extension(&mut ext, 0x0010, &body);
        }
        let mut body = Vec::with_capacity(64 + ext.len());
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(random);
        body.push(hello.session.len() as u8);
        body.extend_from_slice(&hello.session);
        body.extend_from_slice(&suite.to_be_bytes());
        body.push(0);
        if !ext.is_empty() {
            body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
            body.extend_from_slice(&ext);
        }
        message(2, &body)
    }

    fn key_exchange(
        &self,
        hello: &Hello,
        share: &keys::Share,
        random: &[u8; 32],
    ) -> Result<Vec<u8>, TlsError> {
        let mut params = Vec::with_capacity(4 + share.data.len());
        params.push(3);
        params.extend_from_slice(&share.group.to_be_bytes());
        params.push(share.data.len() as u8);
        params.extend_from_slice(&share.data);
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| TlsError::Other("no server key".to_owned()))?;
        let scheme = pick_sigalg(key, &hello.sigalgs)
            .ok_or_else(|| TlsError::Other("no signature scheme".to_owned()))?;
        let mut signed = Vec::with_capacity(64 + params.len());
        signed.extend_from_slice(&hello.random);
        signed.extend_from_slice(random);
        signed.extend_from_slice(&params);
        let signature = sign(key, scheme, &signed)?;
        let mut body = params;
        body.extend_from_slice(&scheme.to_be_bytes());
        body.extend_from_slice(&(signature.len() as u16).to_be_bytes());
        body.extend_from_slice(&signature);
        Ok(message(12, &body))
    }

    fn rsa_pre_master(&self, body: &[u8]) -> Result<Vec<u8>, TlsError> {
        let mut r = Reader::new(body);
        let encrypted = r.vec16()?;
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| TlsError::Other("no server key".to_owned()))?;
        let rsa = key
            .rsa()
            .map_err(|error| TlsError::Other(format!("server key: {error}")))?;
        let mut fallback = [0u8; PRE_MASTER];
        SystemRandom::new()
            .fill(&mut fallback)
            .map_err(|_| TlsError::Other("rsa fallback".to_owned()))?;
        let size = rsa.size() as usize;
        if encrypted.len() != size {
            return Ok(fallback.to_vec());
        }
        let mut out = vec![0u8; size];
        if rsa
            .private_decrypt(encrypted, &mut out, Padding::NONE)
            .is_err()
        {
            return Ok(fallback.to_vec());
        }
        Ok(pkcs1_pre_master(&out, &fallback, self.client_version))
    }

    fn next_plain(&mut self, want: u8) -> Result<Vec<u8>, TlsError> {
        loop {
            if let Some(msg) = self.take_handshake()? {
                if msg[0] != want {
                    return Err(TlsError::Other(format!(
                        "expected handshake {}, got {}",
                        want, msg[0]
                    )));
                }
                return Ok(msg);
            }
            let (kind, body) = self.record()?;
            match kind {
                HANDSHAKE => self.hs.extend_from_slice(&body),
                21 => return Err(alert(&body)),
                _ => {
                    return Err(TlsError::Other(format!(
                        "expected handshake, got record {kind}"
                    )))
                }
            }
        }
    }

    fn next_encrypted(&mut self, want: u8) -> Result<Vec<u8>, TlsError> {
        loop {
            if let Some(msg) = self.take_handshake()? {
                if msg[0] != want {
                    return Err(TlsError::Other(format!(
                        "expected handshake {}, got {}",
                        want, msg[0]
                    )));
                }
                return Ok(msg);
            }
            let (kind, mut body) = self.record()?;
            match kind {
                HANDSHAKE => {
                    let keys = self
                        .read
                        .as_mut()
                        .ok_or_else(|| TlsError::Other("no read keys".to_owned()))?;
                    let (at, len) = record::open12(keys, HANDSHAKE, &mut body)?;
                    self.hs.extend_from_slice(&body[at..at + len]);
                }
                21 => {
                    let mut plain = vec![0u8; body.len()];
                    let keys = self
                        .read
                        .as_mut()
                        .ok_or_else(|| TlsError::Other("no read keys".to_owned()))?;
                    let len = record::open12_into(keys, 21, &body, &mut plain)?;
                    return Err(alert(&plain[..len]));
                }
                _ => return Err(TlsError::Other("unexpected record".to_owned())),
            }
        }
    }

    fn take_handshake(&mut self) -> Result<Option<Vec<u8>>, TlsError> {
        if self.hs.len() - self.hs_at < 4 {
            return Ok(None);
        }
        let len = u24(&self.hs[self.hs_at + 1..])?;
        if len > MAX_HANDSHAKE {
            return Err(TlsError::Other("handshake message is too long".to_owned()));
        }
        if self.hs.len() - self.hs_at < 4 + len {
            return Ok(None);
        }
        let msg = self.hs[self.hs_at..self.hs_at + 4 + len].to_vec();
        self.hs_at += 4 + len;
        if self.hs_at == self.hs.len() {
            self.hs.clear();
            self.hs_at = 0;
        }
        Ok(Some(msg))
    }

    fn expect_ccs(&mut self) -> Result<(), TlsError> {
        let (kind, body) = self.record()?;
        match kind {
            CCS if body == [1] => Ok(()),
            CCS => Err(TlsError::Other("bad change cipher spec".to_owned())),
            21 => Err(alert(&body)),
            _ => Err(TlsError::Other("expected change cipher spec".to_owned())),
        }
    }

    fn record(&mut self) -> Result<(u8, Vec<u8>), TlsError> {
        let kind = self.fill_record()?;
        Ok((kind, self.rec.split_off(5)))
    }

    fn fill_record(&mut self) -> Result<u8, TlsError> {
        if self.rec_have < 5 {
            self.rec.resize(5, 0);
            while self.rec_have < 5 {
                let read = match self.io.read(&mut self.rec[self.rec_have..5]) {
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    result => result?,
                };
                if read == 0 {
                    return Err(TlsError::Closed);
                }
                self.rec_have += read;
            }
        }
        let len = usize::from(u16::from_be_bytes([self.rec[3], self.rec[4]]));
        if len > MAX_RECORD {
            self.rec_have = 0;
            return Err(TlsError::Other(
                "record exceeds the maximum length".to_owned(),
            ));
        }
        self.rec.resize(5 + len, 0);
        while self.rec_have < self.rec.len() {
            let read = match self.io.read(&mut self.rec[self.rec_have..]) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if read == 0 {
                return Err(TlsError::Closed);
            }
            self.rec_have += read;
        }
        self.rec_have = 0;
        Ok(self.rec[0])
    }

    fn queue_plain(&mut self, kind: u8, body: &[u8]) {
        self.pending.push(kind);
        self.pending.extend_from_slice(&[0x03, 0x03]);
        self.pending
            .extend_from_slice(&(body.len() as u16).to_be_bytes());
        self.pending.extend_from_slice(body);
    }

    fn queue_encrypted(&mut self, kind: u8, body: &[u8]) -> Result<(), TlsError> {
        let keys = self
            .write
            .as_mut()
            .ok_or_else(|| TlsError::Other("no write keys".to_owned()))?;
        record::seal12(keys, kind, body, &mut self.pending)?;
        Ok(())
    }

    /// Writes the queued flight from where a timeout left it, so a partial write is resumed rather
    /// than reframed, and the phase that produced it is never replayed.
    fn flush(&mut self) -> Result<(), TlsError> {
        while self.pending_at < self.pending.len() {
            match self.io.write(&self.pending[self.pending_at..]) {
                Ok(0) => return Err(TlsError::Closed),
                Ok(written) => self.pending_at += written,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.kind() == std::io::ErrorKind::TimedOut =>
                {
                    return Err(TlsError::Timeout);
                }
                Err(error) => return Err(TlsError::from(error)),
            }
        }
        self.pending.clear();
        self.pending_at = 0;
        Ok(())
    }

    fn seal(&mut self, parts: &[&[u8]]) -> std::io::Result<()> {
        self.handshake().map_err(std::io::Error::other)?;
        let mut out = std::mem::take(&mut self.out);
        out.clear();
        let sealed = {
            let keys = self
                .write
                .as_mut()
                .ok_or_else(|| TlsError::Other("no write keys".to_owned()))?;
            seal_parts(keys, parts, &mut out)
        };
        let sent = sealed
            .map_err(std::io::Error::other)
            .and_then(|()| self.io.write_all(&out))
            .and_then(|()| self.io.flush());
        self.out = out;
        sent
    }

    pub(crate) fn suites(&self) -> Vec<String> {
        self.cfg
            .cipher_suites
            .iter()
            .map(|id| format!("{id:#06x}"))
            .collect()
    }

    pub(crate) fn write_all_slices(&mut self, parts: &[&[u8]]) -> std::io::Result<()> {
        self.seal(parts)
    }

    pub(crate) fn get_ref(&self) -> &S {
        &self.io
    }

    pub(crate) fn closed(&self) -> bool {
        self.eof
    }

    pub(crate) fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    pub(crate) fn sni(&self) -> Option<&[u8]> {
        self.sni.as_deref()
    }

    pub(crate) fn suite(&self) -> Option<u16> {
        self.suite
    }
}

/// RFC 5246's `EM = 0x00 || 0x02 || PS || 0x00 || M`, with `M` always 48 bytes: the last 48 bytes
/// are the premaster only when the prefix, a non-empty `PS`, the separator and the
/// `ClientHello` version all check out. The checks and the fallback selection are
/// branchless, so a bad padding looks like a good one.
fn pkcs1_pre_master(block: &[u8], fallback: &[u8; PRE_MASTER], client_version: u16) -> Vec<u8> {
    if block.len() < PRE_MASTER + 11 {
        return fallback.to_vec();
    }
    let separator = block.len() - PRE_MASTER - 1;
    let message = &block[block.len() - PRE_MASTER..];
    let [hi, lo] = client_version.to_be_bytes();
    let mut good = u8::from(block[0] == 0)
        & u8::from(block[1] == 2)
        & u8::from(block[separator] == 0)
        & u8::from(message[0] == hi)
        & u8::from(message[1] == lo);
    for &byte in &block[2..separator] {
        good &= u8::from(byte != 0);
    }
    let mask = 0u8.wrapping_sub(good);
    let mut secret = Vec::with_capacity(PRE_MASTER);
    for at in 0..PRE_MASTER {
        secret.push((message[at] & mask) | (fallback[at] & !mask));
    }
    secret
}

impl<S: Stream> Read for Server<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.handshake().map_err(std::io::Error::other)?;
        loop {
            if self.plain_at < self.plain_end {
                let n = (self.plain_end - self.plain_at).min(buf.len());
                buf[..n].copy_from_slice(&self.rec[self.plain_at..self.plain_at + n]);
                self.plain_at += n;
                return Ok(n);
            }
            if self.eof {
                return Ok(0);
            }
            let kind = self.fill_record().map_err(std::io::Error::other)?;
            match kind {
                APPLICATION => {
                    let keys = self
                        .read
                        .as_mut()
                        .ok_or_else(|| std::io::Error::other("no read keys"))?;
                    let (at, len) = record::open12(keys, APPLICATION, &mut self.rec[5..])
                        .map_err(std::io::Error::other)?;
                    self.plain_at = 5 + at;
                    self.plain_end = 5 + at + len;
                }
                21 => {
                    let keys = self
                        .read
                        .as_mut()
                        .ok_or_else(|| std::io::Error::other("no read keys"))?;
                    let (at, len) = record::open12(keys, 21, &mut self.rec[5..])
                        .map_err(std::io::Error::other)?;
                    if len < 2 {
                        return Err(std::io::Error::other("truncated alert"));
                    }
                    if self.rec[5 + at + 1] == 0 {
                        self.eof = true;
                        return Ok(0);
                    }
                    return Err(std::io::Error::other(alert(
                        &self.rec[5 + at..5 + at + len],
                    )));
                }
                _ => return Err(std::io::Error::other(format!("unexpected record {kind}"))),
            }
        }
    }
}

impl<S: Stream> Write for Server<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.seal(&[buf])?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.io.flush()
    }
}

impl<S: Stream + crate::tls::RecordAlignment> crate::tls::RecordAlignment for Server<S> {
    fn engage_record_alignment(&mut self) {
        self.io.engage_record_alignment();
    }

    fn disarm_record_alignment(&mut self) {
        self.io.disarm_record_alignment();
    }

    fn write_all_slices(&mut self, parts: &[&[u8]]) -> std::io::Result<()> {
        self.seal(parts)
    }
}

/// The chunks a frame seals into, shared with the client so both lanes split at the same budget.
fn seal_parts(keys: &mut Direction, parts: &[&[u8]], out: &mut Vec<u8>) -> Result<(), TlsError> {
    seal_chunks(parts, out, |chunk, out| {
        record::seal12_parts(keys, APPLICATION, chunk, out)
    })
}

/// Whether the suite authenticates with an ECDSA leaf, so an RSA certificate cannot key it.
fn ecdsa(id: u16) -> bool {
    matches!(
        id,
        0xc007 | 0xc009 | 0xc00a | 0xc023 | 0xcca9 | 0xc02b | 0xc02c
    )
}

/// The certificate's first signature scheme the client offered, in the order a Go server tries them.
fn pick_sigalg(key: &PKey<Private>, offered: &[u16]) -> Option<u16> {
    let want: &[u16] = if key.rsa().is_ok() {
        &[0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0201]
    } else {
        match key.bits() {
            384 => &[0x0503, 0x0603, 0x0403, 0x0203],
            521 => &[0x0603, 0x0503, 0x0403, 0x0203],
            _ => &[0x0403, 0x0503, 0x0603, 0x0203],
        }
    };
    want.iter().copied().find(|id| offered.contains(id))
}

/// The `ServerKeyExchange` proof a TLS 1.2 client verifies, over the two randoms and the params.
fn sign(key: &PKey<Private>, scheme: u16, data: &[u8]) -> Result<Vec<u8>, TlsError> {
    let (digest, pss) = match scheme {
        0x0201 | 0x0203 => (MessageDigest::sha1(), false),
        0x0804 => (MessageDigest::sha256(), true),
        0x0805 => (MessageDigest::sha384(), true),
        0x0806 => (MessageDigest::sha512(), true),
        0x0501 | 0x0503 => (MessageDigest::sha384(), false),
        0x0601 | 0x0603 => (MessageDigest::sha512(), false),
        _ => (MessageDigest::sha256(), false),
    };
    let mut signer = Signer::new(digest, key)
        .map_err(|error| TlsError::Other(format!("server signer: {error}")))?;
    if pss {
        signer
            .set_rsa_padding(Padding::PKCS1_PSS)
            .and_then(|()| signer.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH))
            .map_err(|error| TlsError::Other(format!("server signer: {error}")))?;
    }
    signer
        .sign_oneshot_to_vec(data)
        .map_err(|error| TlsError::Other(format!("server signature: {error}")))
}

/// The server's first protocol the client offered, which is the order a Go server negotiates in.
fn pick_alpn(server: &[Vec<u8>], client: &[Vec<u8>]) -> Option<Vec<u8>> {
    server
        .iter()
        .find(|protocol| client.contains(protocol))
        .cloned()
}

fn certificate_message(chain: &[Vec<u8>]) -> Vec<u8> {
    let mut list = Vec::new();
    for cert in chain {
        u24_push(&mut list, cert.len());
        list.extend_from_slice(cert);
    }
    let mut body = Vec::with_capacity(3 + list.len());
    u24_push(&mut body, list.len());
    body.extend_from_slice(&list);
    message(11, &body)
}

fn extension(out: &mut Vec<u8>, kind: u16, body: &[u8]) {
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
}

fn ids16(bytes: &[u8]) -> Result<Vec<u16>, TlsError> {
    let mut r = Reader::new(bytes);
    let mut out = Vec::new();
    while !r.done() {
        out.push(r.u16()?);
    }
    Ok(out)
}

fn u24(bytes: &[u8]) -> Result<usize, TlsError> {
    if bytes.len() < 3 {
        return Err(TlsError::Other("truncated handshake".to_owned()));
    }
    Ok(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) as usize)
}

fn u24_push(out: &mut Vec<u8>, len: usize) {
    out.extend_from_slice(&(len as u32).to_be_bytes()[1..]);
}

fn alert(body: &[u8]) -> TlsError {
    match body {
        [2, 0] => TlsError::Closed,
        [_, description] => TlsError::Other(format!("peer alert {description}")),
        _ => TlsError::Other("truncated alert".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn hello(bytes: &[u8]) -> Hello {
        Hello::parse(bytes).expect("hello")
    }

    #[test]
    fn the_client_hello_fields_are_read_in_place() {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x11; 32]);
        body.push(0);
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&[0x00, 0x3c, 0x13, 0x01]);
        body.push(1);
        body.push(0);
        let mut ext = Vec::new();
        extension(&mut ext, 0x0017, &[]);
        extension(&mut ext, 0xff01, &[0]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let parsed = hello(&body);
        assert_eq!(parsed.ciphers, vec![0x003c, 0x1301]);
        assert!(parsed.ems && parsed.secure());
        assert!(parsed.tls12().is_ok());
    }

    #[test]
    fn a_supported_versions_without_12_has_no_shared_version() {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x22; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        let list = vec![2, 0x03, 0x04];
        let mut ext = Vec::new();
        extension(&mut ext, 0x002b, &list);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        assert!(matches!(
            hello(&body).tls12(),
            Err(TlsError::NoSharedCipher)
        ));
    }

    fn client_hello(versions: &[u16]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x33; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x00, 0x3c]);
        body.push(1);
        body.push(0);
        let mut list = Vec::with_capacity(1 + versions.len() * 2);
        list.push((versions.len() * 2) as u8);
        for id in versions {
            list.extend_from_slice(&id.to_be_bytes());
        }
        let mut ext = Vec::new();
        extension(&mut ext, 0x002b, &list);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut message = vec![1];
        u24_push(&mut message, body.len());
        message.extend_from_slice(&body);
        let mut record = vec![HANDSHAKE, 3, 3];
        record.extend_from_slice(&(message.len() as u16).to_be_bytes());
        record.extend_from_slice(&message);
        record
    }

    #[test]
    fn a_grease_version_does_not_delegate_a_tls12_hello() {
        let mut io = std::io::Cursor::new(client_hello(&[0x0a0a, 0x0303]));
        let (_, delegate) = peek_hello(&mut io).expect("peek");
        assert!(!delegate);
        let mut io = std::io::Cursor::new(client_hello(&[0x0a0a, 0x0304, 0x0303]));
        let (_, delegate) = peek_hello(&mut io).expect("peek");
        assert!(delegate);
    }

    enum Step {
        Bytes(Vec<u8>),
        WouldBlock,
    }

    struct Trickle {
        steps: Vec<Step>,
        at: usize,
    }

    impl Trickle {
        fn new(steps: Vec<Step>) -> Self {
            Self { steps, at: 0 }
        }
    }

    impl Read for Trickle {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            loop {
                match self.steps.get_mut(self.at) {
                    None => return Ok(0),
                    Some(Step::Bytes(bytes)) => {
                        if bytes.is_empty() {
                            self.at += 1;
                            continue;
                        }
                        let n = bytes.len().min(buf.len());
                        buf[..n].copy_from_slice(&bytes[..n]);
                        bytes.drain(..n);
                        return Ok(n);
                    }
                    Some(Step::WouldBlock) => {
                        self.at += 1;
                        return Err(std::io::ErrorKind::WouldBlock.into());
                    }
                }
            }
        }
    }

    impl Write for Trickle {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn empty_config() -> TlsServerConfig {
        TlsServerConfig {
            certs: Vec::new(),
            alpn: Vec::new(),
            min_version: None,
            max_version: None,
            cipher_suites: Vec::new(),
            send_tickets: false,
            reject_unknown_sni: false,
            server_config_cache: std::sync::Arc::default(),
            ech_server_keys: None,
            master_key_log: None,
        }
    }

    #[test]
    fn a_record_read_resumes_after_a_timeout() {
        let record = [APPLICATION, 3, 3, 0, 2, 0xaa, 0xbb];
        let io = Trickle::new(vec![
            Step::Bytes(vec![APPLICATION, 3]),
            Step::WouldBlock,
            Step::Bytes(vec![3, 0, 2, 0xaa, 0xbb]),
        ]);
        let mut server = Server::new(empty_config(), io);
        assert!(matches!(server.fill_record(), Err(TlsError::Timeout)));
        assert_eq!(server.fill_record().expect("resumes"), APPLICATION);
        assert_eq!(server.rec, record);
    }

    #[test]
    fn a_pkcs1_premaster_is_only_taken_from_the_fixed_tail() {
        let fallback = [0x77; PRE_MASTER];
        let mut block = vec![0x11u8; 256];
        block[0] = 0;
        block[1] = 2;
        block[256 - PRE_MASTER - 1] = 0;
        let mut message: Vec<u8> = (0..PRE_MASTER as u8).collect();
        message[0] = 0x03;
        message[1] = 0x03;
        block[256 - PRE_MASTER..].copy_from_slice(&message);
        assert_eq!(pkcs1_pre_master(&block, &fallback, 0x0303), message);

        let mut bad = block.clone();
        bad[2] = 0;
        assert_eq!(pkcs1_pre_master(&bad, &fallback, 0x0303), fallback.to_vec());

        let mut bad = block.clone();
        bad[256 - PRE_MASTER - 1] = 1;
        assert_eq!(pkcs1_pre_master(&bad, &fallback, 0x0303), fallback.to_vec());

        let mut bad = block.clone();
        bad[1] = 3;
        assert_eq!(pkcs1_pre_master(&bad, &fallback, 0x0303), fallback.to_vec());

        let mut bad = block;
        bad[256 - PRE_MASTER] = 0x03;
        bad[256 - PRE_MASTER + 1] = 0x04;
        assert_eq!(pkcs1_pre_master(&bad, &fallback, 0x0303), fallback.to_vec());
    }

    #[test]
    fn a_handshake_resumes_after_a_timeout_in_the_client_hello() {
        let hello = client_hello(&[0x0303]);
        let (head, tail) = hello.split_at(7);
        let io = Trickle::new(vec![
            Step::Bytes(head.to_vec()),
            Step::WouldBlock,
            Step::Bytes(tail.to_vec()),
        ]);
        let mut server = Server::new(empty_config(), io);
        assert!(matches!(server.handshake(), Err(TlsError::Timeout)));
        assert!(matches!(
            server.handshake(),
            Err(TlsError::Other(why)) if why.contains("identity")
        ));
    }
}

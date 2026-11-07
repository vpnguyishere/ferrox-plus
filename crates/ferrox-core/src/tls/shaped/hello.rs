// The shaped ClientHello: a pinned parrot's ciphers, extension order and bodies, with the GREASE, key shares, ECH cover and padding a browser draws.
use super::keys::{self, Share};
use super::{Body, Ext, Profile, GREASE};
use crate::tls::hpke::Sealer;
use crate::tls::TlsError;
use rustls::crypto::hpke::HpkeSealer as _;

/// The version this hello's legacy field names, which a static-RSA premaster repeats.
pub(super) const TLS12: u16 = 0x0303;
const PAD: u16 = 0x0015;
const ALPN: u16 = 0x0010;

/// A built hello and everything a retry has to keep: the same random, session id,
/// GREASE, ECH cover and ALPN, with only the key share the server asked for.
pub(crate) struct Hello {
    pub msg: Vec<u8>,
    pub random: [u8; 32],
    pub session_id: [u8; 32],
    pub shares: Vec<Share>,
    profile: &'static Profile,
    /// A config's `cipherSuites` list, which the stock hello puts where a preset's table would.
    ciphers: Option<Vec<u16>>,
    /// The groups a config's `curvePreferences` names, in its order: `None` keeps the profile's
    /// own list and shares, the hello a browser would send.
    groups: Option<Vec<u16>>,
    grease: [u16; 5],
    alpn: Option<&'static [&'static [u8]]>,
    /// A stock hello's config-named ALPN list, which Go puts where the preset's table would.
    stock_alpn: Option<Vec<Vec<u8>>>,
    sni: Option<String>,
    ech: Option<Vec<u8>>,
    /// A config-named padding extension body length, placed first as Psiphon does; `None`
    /// keeps the preset's own `BoringSSL` padding rule.
    padding: Option<usize>,
    offer: Option<EchOffer>,
    /// A fixture build: fixed entropy, table order, and a fixed ECH payload length.
    canonical: bool,
}

struct EchOffer {
    config_id: u8,
    suite: (u16, u16),
    enc: [u8; 32],
    sealer: Sealer,
    inner_random: [u8; 32],
    inner_name: Option<String>,
    transcript: Vec<u8>,
    maximum_name_length: usize,
}

#[derive(Clone, Copy)]
struct Prepared<'a> {
    version: u16,
    random: &'a [u8; 32],
    session_id: &'a [u8],
    ciphers: &'a [u16],
    message_len: usize,
    shares: &'a [Share],
}

impl Hello {
    /// Builds one hello from a profile and the config's overrides.
    pub(crate) fn build(
        profile: &'static Profile,
        server_name: &str,
        alpn: &[Vec<u8>],
        websocket: bool,
        curves: &[u16],
        client_random: Option<[u8; 32]>,
    ) -> Result<Self, TlsError> {
        // One draw for the whole hello: its random, its session id, five GREASE pairs.
        let mut seed = [0u8; 74];
        getrandom::fill(&mut seed).map_err(entropy)?;
        let (blocks, draws) = seed.as_chunks::<32>();
        let (random, session_id) = (client_random.unwrap_or(blocks[0]), blocks[1]);
        let mut grease = [0u16; 5];
        for (slot, pair) in grease.iter_mut().zip(draws.as_chunks::<2>().0) {
            *slot = u16::from_le_bytes(*pair);
        }
        let grease = distinct_grease(grease);
        // A config that names curves offers those and no profile group beside them, drawing a share for each in its order.
        let (profile_groups, profile_reuse) = share_spec(profile);
        let (groups, reuse) = if curves.is_empty() || profile_groups.is_empty() {
            (profile_groups, profile_reuse)
        } else {
            (curves, false)
        };
        let shares = keys::generate(groups, reuse).map_err(TlsError::Other)?;
        let mut hello = Self {
            msg: Vec::new(),
            random,
            session_id,
            shares,
            profile,
            ciphers: None,
            groups: (!curves.is_empty()).then(|| curves.to_vec()),
            grease,
            alpn: alpn_override(alpn, websocket),
            stock_alpn: None,
            sni: sni_name(server_name).map(str::to_owned),
            ech: ech_body(profile, false),
            padding: None,
            offer: None,
            canonical: false,
        };
        hello.msg = hello.encode(None);
        Ok(hello)
    }

    /// Move or add the RFC 7685 padding extension at the front of the extension list with
    /// an exact body length, capped so the hello stays in one 2^14-byte record.
    pub(crate) fn set_padding(&mut self, padding: usize) {
        self.padding = Some(padding.min(0x3000));
        self.msg = self.encode(None);
    }

    /// Replaces the hello's cipher list, the field a config's `cipherSuites` owns.
    pub(crate) fn set_ciphers(&mut self, ciphers: &[u16]) {
        self.ciphers = Some(ciphers.to_vec());
        self.msg = self.encode(None);
    }

    /// The list this hello puts on the wire: the config's, else the profile's.
    fn cipher_table(&self) -> &[u16] {
        self.ciphers.as_deref().unwrap_or(self.profile.ciphers)
    }

    /// Whether this hello offered `id`, so a server may select it.
    pub(crate) fn offers_cipher(&self, id: u16) -> bool {
        self.cipher_table().contains(&id)
    }

    /// Replaces the hello's ALPN table with the config's list.
    pub(crate) fn set_alpn(&mut self, alpn: &[Vec<u8>]) {
        if !alpn.is_empty() {
            self.stock_alpn = Some(alpn.to_vec());
            self.msg = self.encode(None);
        }
    }

    /// Replaces the GREASE cover with a real ECH offer sealed to the named config.
    pub(crate) fn enable_ech(&mut self, list: &[u8]) -> Result<(), TlsError> {
        use crate::tls::ech;
        let configs = ech::parse_config_list(list).map_err(TlsError::Other)?;
        let picked = configs.iter().find_map(|config| {
            if config.kem_id != ech::KEM_X25519 || config.has_unknown_mandatory_extension() {
                return None;
            }
            let name = std::str::from_utf8(config.public_name).ok()?;
            if name.is_empty()
                || name.parse::<std::net::IpAddr>().is_ok()
                || rustls::pki_types::DnsName::try_from(name.to_owned()).is_err()
            {
                return None;
            }
            config.suites().find_map(|suite| match suite {
                (ech::KDF_SHA256, ech::AEAD_AES_128_GCM) => {
                    Some((config, suite, &crate::tls::hpke::AES128_GCM))
                }
                (ech::KDF_SHA256, ech::AEAD_AES_256_GCM) => {
                    Some((config, suite, &crate::tls::hpke::AES256_GCM))
                }
                (ech::KDF_SHA256, ech::AEAD_CHACHA20_POLY1305) => {
                    Some((config, suite, &crate::tls::hpke::CHACHA20_POLY1305))
                }
                _ => None,
            })
        });
        let (config, suite, hpke) =
            picked.ok_or_else(|| TlsError::Other("ech: no supported config".to_owned()))?;
        let public_name = std::str::from_utf8(config.public_name)
            .map_err(|_| TlsError::Other("ech: public name is not utf-8".to_owned()))?
            .to_owned();
        let mut info = Vec::with_capacity(8 + config.encoded_len());
        info.extend_from_slice(b"tls ech\0");
        config.encode_into(&mut info);
        let public_key: [u8; 32] = config
            .public_key
            .try_into()
            .map_err(|_| TlsError::Other("ech: public key is not 32 bytes".to_owned()))?;
        let (enc, sealer) = hpke
            .setup_sealer_owned(&info, &public_key)
            .map_err(|e| TlsError::Other(format!("ech: hpke: {e}")))?;
        let mut inner_random = [0u8; 32];
        getrandom::fill(&mut inner_random).map_err(entropy)?;
        let mut offer = EchOffer {
            config_id: config.id,
            suite,
            enc,
            sealer,
            inner_random,
            inner_name: self.sni.clone(),
            transcript: Vec::new(),
            maximum_name_length: match config.maximum_name_length {
                0 => 255,
                length => usize::from(length),
            },
        };
        self.sni = Some(public_name);
        let msg = self.seal_offer(&mut offer, &self.shares, None, false)?;
        self.msg = msg;
        self.offer = Some(offer);
        Ok(())
    }

    /// Seals the inner hello into the outer cover and returns the framed outer hello.
    fn seal_offer(
        &self,
        offer: &mut EchOffer,
        shares: &[Share],
        cookie: Option<&[u8]>,
        retry: bool,
    ) -> Result<Vec<u8>, TlsError> {
        let (encoded, transcript) = self.inner_hello(offer, shares, cookie);
        offer.transcript = transcript;
        let enc: &[u8] = if retry { &[] } else { &offer.enc };
        let cover = ech_cover(offer.suite, offer.config_id, enc, encoded.len() + 16);
        let entries =
            self.extension_entries(shares, cookie, self.sni.as_deref(), Some(&cover), true);
        if entries.last().map(|entry| entry.kind) != Some(0xfe0d) {
            return Err(TlsError::Other(
                "ech: profile has no ECH payload".to_owned(),
            ));
        }
        let mut outer = self.encode_body(
            TLS12,
            &self.random,
            &self.session_id,
            entries,
            false,
            shares,
        );
        let ciphertext = offer
            .sealer
            .seal(&outer[4..], &encoded)
            .map_err(|e| TlsError::Other(format!("ech: seal: {e}")))?;
        let at = outer
            .len()
            .checked_sub(ciphertext.len())
            .ok_or_else(|| TlsError::Other("ech: payload length moved".to_owned()))?;
        outer[at..].copy_from_slice(&ciphertext);
        Ok(outer)
    }

    /// The inner hello and its transcript, both framed where they are written.
    fn inner_hello(
        &self,
        offer: &EchOffer,
        shares: &[Share],
        cookie: Option<&[u8]>,
    ) -> (Vec<u8>, Vec<u8>) {
        const TLS13: [u8; 3] = [2, 0x03, 0x04];
        const INNER_ECH: [u8; 1] = [1];
        let mut entries = self.extension_entries(
            shares,
            cookie,
            offer.inner_name.as_deref(),
            Some(&INNER_ECH),
            true,
        );
        for entry in &mut entries {
            if entry.kind == 0x002b {
                entry.source = Source::Fixed(&TLS13);
                entry.len = TLS13.len();
            }
        }
        if !entries.iter().any(|entry| entry.kind == 0x002b) {
            entries.push(Entry::new(
                0x002b,
                TLS13.len(),
                false,
                Source::Fixed(&TLS13),
            ));
        }
        let ciphers = self.cipher_values(true);
        let message_len = Self::pad_prepared(&mut entries, ciphers.len(), 0, None);
        let head = Prepared {
            version: TLS12,
            random: &offer.inner_random,
            session_id: &[],
            ciphers: &ciphers,
            message_len,
            shares,
        };
        let transcript = self.encode_prepared(
            Prepared {
                session_id: &self.session_id,
                message_len: message_len + self.session_id.len(),
                ..head
            },
            &entries,
            true,
        );
        let mut encoded = self.encode_prepared(head, &entries, false);
        let name_pad = match offer.inner_name.as_deref() {
            Some(name) => offer.maximum_name_length.saturating_sub(name.len()),
            None => offer.maximum_name_length + 9,
        };
        encoded.extend(std::iter::repeat_n(0, name_pad));
        let pad = 31 - ((encoded.len() - 1) % 32);
        encoded.extend(std::iter::repeat_n(0, pad));
        (encoded, transcript)
    }

    /// The second hello a `HelloRetryRequest` asks for: one fresh share for the group
    /// the server named, and its cookie echoed when one came.
    pub(crate) fn retry(&mut self, group: u16, cookie: Option<&[u8]>) -> Result<Self, TlsError> {
        if !self.offers(group) {
            return Err(TlsError::Other(format!(
                "server asked for an unoffered retry group {group:#06x}"
            )));
        }
        if self.shares.iter().any(|share| share.group == group) {
            return Err(TlsError::Other(format!(
                "server asked for a retry group the hello already sent {group:#06x}"
            )));
        }
        let shares = keys::generate(&[group], false).map_err(TlsError::Other)?;
        let (msg, offer) = match self.offer.take() {
            Some(mut offer) => (
                self.seal_offer(&mut offer, &shares, cookie, true)?,
                Some(offer),
            ),
            None => (self.encode_with(&shares, cookie), None),
        };
        Ok(Self {
            msg,
            random: self.random,
            session_id: self.session_id,
            shares,
            profile: self.profile,
            ciphers: self.ciphers.clone(),
            groups: self.groups.clone(),
            grease: self.grease,
            alpn: self.alpn,
            stock_alpn: self.stock_alpn.clone(),
            sni: self.sni.clone(),
            ech: self.ech.clone(),
            padding: self.padding,
            offer,
            canonical: self.canonical,
        })
    }

    /// The X25519 secret a REALITY auth key is built from, in the order the server reads.
    pub(crate) fn auth_secret(&self) -> Option<[u8; 32]> {
        let plain = self
            .shares
            .iter()
            .find(|share| share.group == keys::X25519)
            .and_then(Share::auth_secret);
        plain.or_else(|| {
            self.shares
                .iter()
                .find(|share| {
                    matches!(
                        share.group,
                        keys::X25519_MLKEM768 | keys::X25519_MLKEM768_DRAFT
                    )
                })
                .and_then(Share::auth_secret)
        })
    }

    /// The public share this hello carries for a group, before `agree` consumes it.
    pub(crate) fn share_public(&self, group: u16) -> Option<&[u8]> {
        self.shares
            .iter()
            .find(|share| share.group == group)
            .map(|share| share.data.as_slice())
    }

    /// Whether the first hello advertised a group: a configured list replaces the profile's.
    fn offers(&self, group: u16) -> bool {
        match &self.groups {
            Some(groups) => groups.contains(&group),
            None => self
                .profile
                .exts
                .iter()
                .any(|ext| matches!(&ext.body, Body::Groups(groups) if groups.contains(&group))),
        }
    }

    /// The ECDHE point and secret for a TLS 1.2 `ClientKeyExchange` on a curve the hello committed
    /// no `key_share` to, drawn only when that curve is in the hello's advertised groups.
    pub(crate) fn ephemeral(
        &self,
        group: u16,
        peer: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
        if !self.offers(group) {
            return Err(TlsError::NoSharedCipher);
        }
        let mut pool = keys::generate(&[group], false).map_err(TlsError::Other)?;
        let mut share = pool.pop().expect("one group");
        let point = std::mem::take(&mut share.data);
        let shared = share.agree(peer).map_err(TlsError::Other)?;
        Ok((point, shared))
    }

    /// The secret agreement for the group the server selected, consuming that share.
    pub(crate) fn agree(&mut self, group: u16, peer: &[u8]) -> Result<Vec<u8>, TlsError> {
        let at = self
            .shares
            .iter()
            .position(|share| share.group == group)
            .ok_or_else(|| {
                TlsError::Other(format!("server selected an unoffered group {group:#06x}"))
            })?;
        self.shares.remove(at).agree(peer).map_err(TlsError::Other)
    }

    /// Whether the hello offered a protocol: a configured list or the preset's own table,
    /// checked where either lies so a server's pick costs no copy.
    pub(crate) fn offers_alpn(&self, pick: &[u8]) -> bool {
        if let Some(list) = &self.stock_alpn {
            return list.iter().any(|name| name.as_slice() == pick);
        }
        if let Some(list) = self.alpn {
            return list.contains(&pick);
        }
        for ext in self.profile.exts {
            if let Body::Alpn(body) = &ext.body {
                return alpn_has(body, pick);
            }
        }
        false
    }

    /// The 16-byte sealed session id replaces the random one in place, at the
    /// handshake message's fixed session-id offset (4 header + 2 version + 32 random + 1).
    pub(crate) fn seal_session(&mut self, sealed: [u8; 32]) {
        self.session_id = sealed;
        self.msg[39..71].copy_from_slice(&sealed);
    }

    /// Clears the session id so the REALITY seal covers an all-zero id, as xray zeroes it.
    pub(crate) fn zero_session(&mut self) {
        self.session_id = [0u8; 32];
        self.msg[39..71].fill(0);
    }

    pub(crate) fn ech_inner(&self) -> Option<&[u8]> {
        self.offer.as_ref().map(|offer| offer.transcript.as_slice())
    }

    pub(crate) fn ech_inner_random(&self) -> Option<[u8; 32]> {
        self.offer.as_ref().map(|offer| offer.inner_random)
    }

    /// The public name a real offer sends in the outer hello.
    pub(crate) fn ech_public_name(&self) -> Option<&str> {
        self.offer.as_ref()?;
        self.sni.as_deref()
    }

    /// Encodes the message with the current shares and cookie.
    fn encode(&self, cookie: Option<&[u8]>) -> Vec<u8> {
        self.encode_with(&self.shares, cookie)
    }

    /// The hello's own length ahead of its extensions: version, random, session id, cipher list
    /// and the one compression method. The padding extension is sized from it, and the message
    /// is reserved to it, so neither pass guesses at the width.
    fn fixed_len(&self) -> usize {
        2 + 32 + 1 + self.session_id.len() + 2 + 2 * self.cipher_table().len() + 1 + 1
    }

    /// Two walks of one body rule and two buffers: the first runs every walk into a width, so the
    /// message's total is known before its first byte, and the second runs the same walks into that
    /// message. No extension body carries a buffer of its own and no body rule is written twice.
    fn encode_with(&self, shares: &[Share], cookie: Option<&[u8]>) -> Vec<u8> {
        let mut entries = self.extension_entries(
            shares,
            cookie,
            self.sni.as_deref(),
            self.ech.as_deref(),
            false,
        );
        self.pad_entries(&mut entries);
        let ext_len: usize = entries.iter().map(|entry| 4 + entry.len).sum();
        let body = self.fixed_len() + 2 + ext_len;
        let mut msg = Vec::with_capacity(body + 4);
        msg.push(1);
        msg.extend_from_slice(&(body as u32).to_be_bytes()[1..]);
        msg.extend_from_slice(&TLS12.to_be_bytes());
        msg.extend_from_slice(&self.random);
        msg.push(self.session_id.len() as u8);
        msg.extend_from_slice(&self.session_id);
        msg.extend_from_slice(&(2 * self.cipher_table().len() as u16).to_be_bytes());
        for &cipher in self.cipher_table() {
            msg.extend_from_slice(&grease_or(cipher, &self.grease, 0).to_be_bytes());
        }
        msg.extend_from_slice(&[1, 0]);
        msg.extend_from_slice(&(ext_len as u16).to_be_bytes());
        for entry in &entries {
            msg.extend_from_slice(&entry.kind.to_be_bytes());
            msg.extend_from_slice(&(entry.len as u16).to_be_bytes());
            self.write_body(&entry.source, shares, &mut msg);
        }
        msg
    }

    fn cipher_values(&self, tls13_only: bool) -> Vec<u16> {
        self.cipher_table()
            .iter()
            .filter(|&&c| !tls13_only || matches!(c, 0x1301..=0x1303))
            .map(|&c| grease_or(c, &self.grease, 0))
            .collect()
    }

    fn encode_body(
        &self,
        version: u16,
        random: &[u8; 32],
        session_id: &[u8],
        mut entries: Vec<Entry>,
        tls13_only: bool,
        shares: &[Share],
    ) -> Vec<u8> {
        let ciphers = self.cipher_values(tls13_only);
        // The outer hello is the visible one, so the configured padding goes there once.
        let message_len =
            Self::pad_prepared(&mut entries, ciphers.len(), session_id.len(), self.padding);
        let head = Prepared {
            version,
            random,
            session_id,
            ciphers: &ciphers,
            message_len,
            shares,
        };
        self.encode_prepared(head, &entries, true)
    }

    /// The hello body, or the framed handshake message when `frame` is set: the header is reserved
    /// before the first body byte, so the caller's message is never copied behind a new one.
    fn encode_prepared(&self, head: Prepared<'_>, entries: &[Entry], frame: bool) -> Vec<u8> {
        let ext_len: usize = entries.iter().map(|entry| 4 + entry.len).sum();
        let mut body = Vec::with_capacity(if frame {
            head.message_len
        } else {
            head.message_len - 4
        });
        if frame {
            body.resize(4, 0);
        }
        body.extend_from_slice(&head.version.to_be_bytes());
        body.extend_from_slice(head.random);
        body.push(head.session_id.len() as u8);
        body.extend_from_slice(head.session_id);
        body.extend_from_slice(&(2 * head.ciphers.len() as u16).to_be_bytes());
        for cipher in head.ciphers {
            body.extend_from_slice(&cipher.to_be_bytes());
        }
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(ext_len as u16).to_be_bytes());
        for entry in entries {
            body.extend_from_slice(&entry.kind.to_be_bytes());
            body.extend_from_slice(&(entry.len as u16).to_be_bytes());
            self.write_body(&entry.source, head.shares, &mut body);
        }
        if frame {
            let length = (body.len() - 4) as u32;
            body[0] = 1;
            body[1..4].copy_from_slice(&length.to_be_bytes()[1..]);
        }
        body
    }

    fn extension_entries<'a>(
        &'a self,
        shares: &[Share],
        cookie: Option<&'a [u8]>,
        sni: Option<&'a str>,
        ech: Option<&'a [u8]>,
        ech_last: bool,
    ) -> Vec<Entry<'a>> {
        let mut entries: Vec<Entry<'a>> = Vec::with_capacity(self.profile.exts.len() + 1);
        let mut grease_exts = 0usize;
        for ext in self.profile.exts {
            if let Some(entry) = self.entry(ext, shares, &mut grease_exts, sni, ech) {
                entries.push(entry);
            }
        }
        if let Some(cookie) = cookie {
            let at = entries.len().saturating_sub(1);
            let source = Source::Cookie(cookie);
            let len = self.width_of(&source, shares);
            entries.insert(at, Entry::new(0x002c, len, false, source));
        }

        if self.profile.shuffle && !self.canonical {
            shuffle(&mut entries);
        }

        // xray appends the forced ALPN after the preset's extensions, and patches it in place when the preset carries one.
        if let Some(list) = self.alpn {
            if !entries.iter().any(|entry| entry.kind == ALPN) {
                let source = Source::Alpn(list);
                let len = self.width_of(&source, shares);
                entries.push(Entry::new(ALPN, len, true, source));
            }
        }

        // RFC 9849 makes real ECH the last extension; the uTLS GREASE cover keeps the preset's slot.
        if ech_last {
            if let Some(at) = entries.iter().position(|entry| entry.kind == 0xfe0d) {
                let entry = entries.remove(at);
                entries.push(entry);
            }
        }
        entries
    }

    fn entry<'a>(
        &'a self,
        ext: &'a Ext,
        shares: &[Share],
        grease_exts: &mut usize,
        sni: Option<&'a str>,
        ech: Option<&'a [u8]>,
    ) -> Option<Entry<'a>> {
        let (kind, invariant, source) = match &ext.body {
            Body::Grease => {
                let slot = (*grease_exts).min(1);
                *grease_exts += 1;
                (
                    grease_value(&self.grease, 2 + slot),
                    true,
                    Source::Zeros(slot),
                )
            }
            Body::Sni => (0x0000, false, Source::Name(sni?)),
            Body::Pad => (PAD, true, Source::Zeros(0)),
            Body::Groups(groups) => (
                0x000a,
                false,
                Source::Groups(self.groups.as_deref().unwrap_or(groups)),
            ),
            Body::Sigalgs(values) => (0x000d, false, Source::Sigalgs(values)),
            Body::Alpn(table) => {
                let source = match (&self.stock_alpn, self.alpn) {
                    (Some(list), _) => Source::StockAlpn(list),
                    (None, Some(list)) => Source::Alpn(list),
                    (None, None) => {
                        if table.is_empty() {
                            return None;
                        }
                        Source::Fixed(table)
                    }
                };
                (ALPN, false, source)
            }
            Body::Versions(values) => (0x002b, false, Source::Versions(values)),
            Body::KeyShare { .. } if shares.is_empty() => return None,
            Body::KeyShare { .. } => (0x0033, false, Source::Shares),
            Body::Ech { .. } => (0xfe0d, false, Source::Fixed(ech?)),
            Body::Raw(body) => (ext.kind, false, Source::Fixed(body)),
        };
        let len = self.width_of(&source, shares);
        Some(Entry::new(kind, len, invariant, source))
    }

    /// The width one body walk writes, so the message is reserved to its exact total before the
    /// first byte and the bytes themselves land in the walk that follows.
    fn width_of(&self, source: &Source<'_>, shares: &[Share]) -> usize {
        let mut width = Width(0);
        self.write_body(source, shares, &mut width);
        width.0
    }

    /// The one rule for a body's bytes, run twice. A zeros body names its own count, so the GREASE
    /// draw and the padding length carry through Chrome's shuffle without a second walk's state.
    fn write_body<W: Sink>(&self, source: &Source<'_>, shares: &[Share], out: &mut W) {
        match *source {
            Source::Zeros(count) => out.zeros(count),
            Source::Name(name) => sni_body(out, name),
            Source::Groups(groups) => {
                uint16_list(out, groups, |g| grease_or(g, &self.grease, 1));
            }
            Source::Sigalgs(values) => uint16_list(out, values, |v| v),
            Source::Versions(values) => {
                uint8_list(out, values, |v| grease_or(v, &self.grease, 4));
            }
            Source::Alpn(list) => alpn_body(out, list),
            Source::StockAlpn(list) => stock_alpn_body(out, list),
            Source::Fixed(body) => out.put(body),
            Source::Shares => key_share_body(out, shares),
            Source::Cookie(value) => {
                out.put(&(value.len() as u16).to_be_bytes());
                out.put(value);
            }
        }
    }

    fn pad_entries(&self, entries: &mut Vec<Entry<'_>>) -> usize {
        Self::pad_prepared(
            entries,
            self.cipher_table().len(),
            self.session_id.len(),
            self.padding,
        )
    }

    fn pad_prepared(
        entries: &mut Vec<Entry<'_>>,
        ciphers: usize,
        session: usize,
        padding: Option<usize>,
    ) -> usize {
        let header = 2 + 32 + 1 + session + 2 + 2 * ciphers + 1 + 1;
        if let Some(len) = padding {
            entries.retain(|entry| entry.kind != PAD);
            entries.insert(0, Entry::new(PAD, len, true, Source::Zeros(len)));
        } else {
            let unpadded = header
                + 4
                + entries
                    .iter()
                    .filter(|entry| entry.kind != PAD)
                    .map(|entry| 4 + entry.len)
                    .sum::<usize>()
                + 2;
            let pad = boring_padding(unpadded);
            entries.retain(|entry| entry.kind != PAD || pad.is_some());
            if let Some(len) = pad {
                if let Some(entry) = entries.iter_mut().find(|entry| entry.kind == PAD) {
                    entry.source = Source::Zeros(len);
                    entry.len = len;
                }
            }
        }
        header + 4 + entries.iter().map(|entry| 4 + entry.len).sum::<usize>() + 2
    }

    /// The table order as a canonical hello: zero random, session id, GREASE
    /// draws and share material, so a fixture can name every wire byte.
    #[cfg(test)]
    pub(crate) fn canonical(profile: &'static Profile, server_name: &str) -> Self {
        let (groups, _) = share_spec(profile);
        let mut hello = Self {
            msg: Vec::new(),
            random: [0u8; 32],
            session_id: [0u8; 32],
            shares: keys::canonical(groups),
            profile,
            ciphers: None,
            groups: None,
            grease: distinct_grease([0; 5]),
            alpn: None,
            stock_alpn: None,
            sni: sni_name(server_name).map(str::to_owned),
            ech: ech_body(profile, true),
            padding: None,
            offer: None,
            canonical: true,
        };
        hello.msg = hello.encode(None);
        hello
    }
}

/// One extension's place in the hello: its kind on the wire, the width its body measured, whether
/// Chrome's shuffle may move it, and which bytes the second walk writes into the message.
struct Entry<'a> {
    kind: u16,
    len: usize,
    invariant: bool,
    source: Source<'a>,
}

impl<'a> Entry<'a> {
    fn new(kind: u16, len: usize, invariant: bool, source: Source<'a>) -> Self {
        Self {
            kind,
            len,
            invariant,
            source,
        }
    }
}

/// The bytes behind an entry, resolved from the table: a count of zeros the walk names itself, a
/// value the hello holds, or one of the preset's lists.
enum Source<'a> {
    Zeros(usize),
    Name(&'a str),
    Groups(&'a [u16]),
    Sigalgs(&'a [u16]),
    Versions(&'a [u16]),
    Alpn(&'a [&'a [u8]]),
    StockAlpn(&'a [Vec<u8>]),
    Fixed(&'a [u8]),
    Shares,
    Cookie(&'a [u8]),
}

/// Where a body walk puts its bytes: the message, or a width that only adds up what the same walk
/// writes, so no extension needs a buffer before the message has one.
trait Sink {
    fn put(&mut self, bytes: &[u8]);
    fn zeros(&mut self, count: usize);
}

impl Sink for Vec<u8> {
    fn put(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }

    fn zeros(&mut self, count: usize) {
        self.resize(self.len() + count, 0);
    }
}

/// The count a walk writes. Every body is measured by this sink and then written by the message
/// sink, which is why the message can be reserved to its exact total before its first byte.
struct Width(usize);

impl Sink for Width {
    fn put(&mut self, bytes: &[u8]) {
        self.0 += bytes.len();
    }

    fn zeros(&mut self, count: usize) {
        self.0 += count;
    }
}

fn share_spec(profile: &Profile) -> (&'static [u16], bool) {
    for ext in profile.exts {
        if let Body::KeyShare { groups, reuse } = &ext.body {
            return (groups, *reuse);
        }
    }
    (&[], false)
}

/// uTLS moves the second extension off the first when the two draws collide.
fn distinct_grease(mut grease: [u16; 5]) -> [u16; 5] {
    if grease_value(&grease, 2) == grease_value(&grease, 3) {
        grease[3] ^= 0x1010;
    }
    grease
}

fn grease_or(value: u16, grease: &[u16; 5], slot: usize) -> u16 {
    if value == GREASE {
        grease_value(grease, slot)
    } else {
        value
    }
}

fn grease_value(grease: &[u16; 5], slot: usize) -> u16 {
    // The masked nibble carries through and the fixed low nibble keeps the value nonzero.
    let value = u16::from((grease[slot] & 0x00f0) as u8 | 0x0a);
    value | (value << 8)
}

fn uint16_list<W: Sink>(out: &mut W, values: &[u16], each: impl Fn(u16) -> u16) {
    out.put(&((values.len() * 2) as u16).to_be_bytes());
    for value in values {
        out.put(&each(*value).to_be_bytes());
    }
}

fn uint8_list<W: Sink>(out: &mut W, values: &[u16], each: impl Fn(u16) -> u16) {
    out.put(&((values.len() * 2) as u8).to_be_bytes());
    for value in values {
        out.put(&each(*value).to_be_bytes());
    }
}

fn key_share_body<W: Sink>(out: &mut W, shares: &[Share]) {
    let total: usize = shares.iter().map(|share| 4 + share.data.len()).sum();
    out.put(&(total as u16).to_be_bytes());
    for share in shares {
        out.put(&share.group.to_be_bytes());
        out.put(&(share.data.len() as u16).to_be_bytes());
        out.put(&share.data);
    }
}

fn sni_body<W: Sink>(out: &mut W, name: &str) {
    out.put(&((name.len() + 3) as u16).to_be_bytes());
    out.zeros(1);
    out.put(&(name.len() as u16).to_be_bytes());
    out.put(name.as_bytes());
}

fn sni_name(name: &str) -> Option<&str> {
    let mut host = name;
    if host.len() > 1 && host.starts_with('[') && host.ends_with(']') {
        host = &host[1..host.len() - 1];
    }
    if let Some(at) = host.rfind('%') {
        if at > 0 {
            host = &host[..at];
        }
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let name = name.trim_end_matches('.');
    (!name.is_empty()).then_some(name)
}

/// A protocol list as an ALPN body: the list's width, then each name behind its own length byte.
fn alpn_body<W: Sink>(out: &mut W, list: &[&[u8]]) {
    let protocols: usize = list.iter().map(|proto| proto.len() + 1).sum();
    out.put(&(protocols as u16).to_be_bytes());
    for &proto in list {
        out.put(&[proto.len() as u8]);
        out.put(proto);
    }
}

/// The same body from a config's owned protocol list.
fn stock_alpn_body<W: Sink>(out: &mut W, list: &[Vec<u8>]) {
    let protocols: usize = list.iter().map(|proto| proto.len() + 1).sum();
    out.put(&(protocols as u16).to_be_bytes());
    for proto in list {
        out.put(&[proto.len() as u8]);
        out.put(proto);
    }
}

/// Whether a wire ALPN body lists a protocol, walked where it lies so a pick costs no copy.
fn alpn_has(body: &[u8], pick: &[u8]) -> bool {
    if body.len() < 2 {
        return false;
    }
    let end = (2 + usize::from(u16::from_be_bytes([body[0], body[1]]))).min(body.len());
    let mut at = 2;
    while at < end {
        let Some(&len) = body.get(at) else {
            return false;
        };
        let len = usize::from(len);
        at += 1;
        let Some(name) = body.get(at..at + len) else {
            return false;
        };
        if name == pick {
            return true;
        }
        at += len;
    }
    false
}

/// xray's rule for a WebSocket- or HTTPUpgrade-carried hello: force the outer
/// ALPN to `http/1.1` unless the config named exactly `h2` then `http/1.1`.
/// Every other carrier keeps the parrot's own ALPN list, as uTLS does.
fn alpn_override(alpn: &[Vec<u8>], websocket: bool) -> Option<&'static [&'static [u8]]> {
    const BOTH: [&[u8]; 2] = [b"h2", b"http/1.1"];
    const HTTP11: [&[u8]; 1] = [b"http/1.1"];
    if !websocket {
        return None;
    }
    let both = alpn.len() == 2 && alpn[0].as_slice() == BOTH[0] && alpn[1].as_slice() == BOTH[1];
    if both {
        Some(&BOTH)
    } else {
        Some(&HTTP11)
    }
}

#[cfg(test)]
fn handshake(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(body.len() + 4);
    msg.push(kind);
    msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    msg.extend_from_slice(body);
    msg
}

/// Builds one ECH cover with the picked suite, config id, encapsulation and zero payload length.
fn ech_cover(suite: (u16, u16), config_id: u8, enc: &[u8], payload_len: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(12 + enc.len() + payload_len);
    body.push(0);
    body.extend_from_slice(&suite.0.to_be_bytes());
    body.extend_from_slice(&suite.1.to_be_bytes());
    body.push(config_id);
    body.extend_from_slice(&(enc.len() as u16).to_be_bytes());
    body.extend_from_slice(enc);
    body.extend_from_slice(&(payload_len as u16).to_be_bytes());
    body.resize(body.len() + payload_len, 0);
    body
}

/// uTLS's GREASE ECH cover: the picked suite, a random config id, 32 bytes of
/// X25519 encapsulation and a payload one tag longer than a candidate length.
/// The header and the payload are one buffer reserved to their sum, and the payload
/// is randomised where it lies rather than staged in a zero-filled buffer beside it.
fn ech_body(profile: &Profile, canonical: bool) -> Option<Vec<u8>> {
    let mut spec = None;
    for ext in profile.exts {
        if let Body::Ech { suites, payloads } = &ext.body {
            spec = Some((suites, payloads));
            break;
        }
    }
    let (suites, payloads) = spec?;
    let (suite, config_id, enc, payload_len) = if canonical {
        (suites[0], 0u8, [0u8; 32], usize::from(payloads[0]) + 16)
    } else {
        // One 37-byte read carries the suite pick, the config id, the length pick and the 32-byte encapsulation.
        let mut draw = [0u8; 37];
        getrandom::fill(&mut draw).ok()?;
        let mut enc = [0u8; 32];
        enc.copy_from_slice(&draw[5..]);
        let suite = suites[usize::from(u16::from_le_bytes([draw[0], draw[1]])) % suites.len()];
        let config_id = draw[2];
        let len = usize::from(
            payloads[usize::from(u16::from_le_bytes([draw[3], draw[4]])) % payloads.len()],
        ) + 16;
        (suite, config_id, enc, len)
    };
    // 42 = content type, suite and KEM, config id, encapsulation length and bytes, payload length.
    let mut body = Vec::with_capacity(42 + payload_len);
    body.push(0);
    body.extend_from_slice(&suite.to_be_bytes());
    body.push(config_id);
    body.extend_from_slice(&(enc.len() as u16).to_be_bytes());
    body.extend_from_slice(&enc);
    body.extend_from_slice(&(payload_len as u16).to_be_bytes());
    let at = body.len();
    body.resize(at + payload_len, 0);
    if !canonical {
        getrandom::fill(&mut body[at..]).ok()?;
    }
    Some(body)
}

/// Chrome's positional shuffle: only the extensions between the fixed GREASE and
/// padding ends move, so the invariant ends stay where the browser puts them.
/// Two bytes per pick, from a stack pool that refills itself, so the order costs
/// neither a heap buffer nor a draw per swap.
fn shuffle(entries: &mut [Entry<'_>]) {
    let n = entries.len();
    if n < 2 {
        return;
    }
    let mut picks = [0u8; 32];
    let mut ready = picks.len();
    for i in (1..n).rev() {
        if ready + 2 > picks.len() {
            if getrandom::fill(&mut picks).is_err() {
                return;
            }
            ready = 0;
        }
        let pick = usize::from(u16::from_le_bytes([picks[ready], picks[ready + 1]]));
        ready += 2;
        let j = pick % (i + 1);
        if entries[i].invariant || entries[j].invariant {
            continue;
        }
        entries.swap(i, j);
    }
}

/// `BoringSSL`'s padding: only a hello that lands just past one byte and just short
/// of 512 bytes is padded, to exactly 512.
fn boring_padding(unpadded: usize) -> Option<usize> {
    if unpadded > 0xff && unpadded < 0x200 {
        let len = 0x200 - unpadded;
        Some(if len >= 5 { len - 4 } else { 1 })
    } else {
        None
    }
}

fn entropy(error: getrandom::Error) -> TlsError {
    TlsError::Other(format!("no entropy: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::shaped::Fingerprint;
    use rustls::crypto::hpke::Hpke as _;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut text = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(text, "{byte:02x}");
        }
        text
    }

    /// The extension TLVs of a `ClientHello` body, in wire order.
    #[test]
    fn a_supplied_client_random_is_the_hello_random() {
        let profile = Fingerprint::resolve("chrome")
            .expect("a preset name resolves")
            .profile()
            .expect("a shaped profile");
        let random = [0x5a; 32];
        let hello = Hello::build(profile, "example.com", &[], false, &[], Some(random))
            .expect("a shaped dial hello");
        assert_eq!(hello.random, random);
        assert_eq!(&hello.msg[6..38], &random);
    }

    #[test]
    fn a_configured_padding_is_first_and_exact() {
        let profile = Fingerprint::resolve("chrome")
            .expect("a preset name resolves")
            .profile()
            .expect("a shaped profile");
        let mut hello = Hello::build(profile, "example.com", &[], false, &[], None)
            .expect("a shaped dial hello");
        hello.set_padding(77);
        let entries = extensions(&hello.msg[4..]);
        assert_eq!(kind(entries[0]), 0x0015);
        assert_eq!(entries[0].len(), 4 + 77);
        assert!(entries[0][4..].iter().all(|byte| *byte == 0));
        assert_eq!(
            entries.iter().filter(|entry| kind(entry) == 0x0015).count(),
            1
        );
    }

    #[test]
    fn a_padding_over_one_record_is_capped() {
        let profile = Fingerprint::resolve("chrome")
            .expect("a preset name resolves")
            .profile()
            .expect("a shaped profile");
        let mut hello = Hello::build(profile, "example.com", &[], false, &[], None)
            .expect("a shaped dial hello");
        hello.set_padding(0xffff);
        let entries = extensions(&hello.msg[4..]);
        assert_eq!(kind(entries[0]), 0x0015);
        assert_eq!(entries[0].len(), 4 + 0x3000);
        assert!(hello.msg.len() < 0x4000);
    }

    #[test]
    fn a_configured_padding_is_not_repeated_on_the_ech_outer_hello() {
        let (list, _) = crate::tls::ech::generate("public.test", 7).expect("generates");
        let profile = Fingerprint::resolve("chrome")
            .expect("a preset name resolves")
            .profile()
            .expect("a shaped profile");
        let mut hello = Hello::build(profile, "example.com", &[], false, &[], None)
            .expect("a shaped dial hello");
        hello.set_padding(0x3000);
        hello.enable_ech(&list).expect("ech");
        let entries = extensions(&hello.msg[4..]);
        assert_eq!(kind(entries[0]), 0x0015);
        assert_eq!(entries[0].len(), 4 + 0x3000);
        assert!(hello.msg.len() < 0x4000);
    }

    fn extensions(body: &[u8]) -> Vec<&[u8]> {
        let at = 2 + 32;
        let mut at = at + 1 + usize::from(body[at]);
        let ciphers = usize::from(u16::from_be_bytes([body[at], body[at + 1]]));
        at += 2 + ciphers;
        at += 1 + usize::from(body[at]);
        let total = usize::from(u16::from_be_bytes([body[at], body[at + 1]]));
        at += 2;
        let end = at + total;
        let mut out = Vec::new();
        while at < end {
            let len = usize::from(u16::from_be_bytes([body[at + 2], body[at + 3]]));
            out.push(&body[at..at + 4 + len]);
            at += 4 + len;
        }
        assert_eq!(at, end, "extension vector length");
        out
    }

    fn kind(ext: &[u8]) -> u16 {
        u16::from_be_bytes([ext[0], ext[1]])
    }

    fn open_inner(body: &[u8], outer: &[u8], keys: &[u8]) -> Vec<u8> {
        let enc_len = usize::from(outer[10]) << 8 | usize::from(outer[11]);
        let enc = &outer[12..12 + enc_len];
        let at = 12 + enc_len;
        let payload_len = usize::from(outer[at]) << 8 | usize::from(outer[at + 1]);
        let payload = &outer[at + 2..at + 2 + payload_len];
        let mut aad = body.to_vec();
        let payload_at = aad
            .windows(payload.len())
            .position(|window| window == payload)
            .expect("payload");
        aad[payload_at..payload_at + payload.len()].fill(0);
        let server_key = crate::tls::ech::parse_server_keys(keys)
            .expect("keys")
            .remove(0);
        let hpke = match u16::from_be_bytes([outer[7], outer[8]]) {
            1 => &crate::tls::hpke::AES128_GCM,
            2 => &crate::tls::hpke::AES256_GCM,
            3 => &crate::tls::hpke::CHACHA20_POLY1305,
            other => panic!("unexpected suite {other}"),
        };
        let mut info = b"tls ech\0".to_vec();
        info.extend_from_slice(&server_key.config);
        hpke.open(
            &rustls::crypto::hpke::EncapsulatedSecret(enc.to_vec()),
            &info,
            &aad,
            payload,
            &rustls::crypto::hpke::HpkePrivateKey::from(server_key.private_key),
        )
        .expect("opens")
    }

    /// A real `enable_ech` offer parses the list in place, builds the HPKE info and both hello
    /// frames where they are written, and stages only the cover's payload and the sealed bytes.
    #[cfg_attr(miri, ignore = "uses the OS random source")]
    #[test]
    fn an_enable_ech_offer_parses_in_place() {
        let (list, _keys) = crate::tls::ech::generate("public.test", 7).expect("generates");
        let profile = Fingerprint::default().profile().expect("profile");
        let mut hello =
            Hello::build(profile, "hidden.test", &[], false, &[], None).expect("builds");
        let (enabled, counts) = crate::alloc_count::measure(|| hello.enable_ech(&list));
        enabled.expect("ech");
        assert_eq!(counts.allocs, 17, "the full offer cost: {counts:?}");
        assert_eq!(
            counts.zeroed, 0,
            "the payload is filled in place: {counts:?}"
        );
    }

    #[cfg_attr(miri, ignore = "uses the OS random source")]
    #[test]
    fn a_profile_without_an_ech_slot_is_refused() {
        let (list, _keys) = crate::tls::ech::generate("public.test", 7).expect("generates");
        let profile = Fingerprint::resolve("hellochrome_58")
            .expect("a preset name resolves")
            .profile()
            .expect("a shaped profile");
        let mut hello =
            Hello::build(profile, "hidden.test", &[], false, &[], None).expect("builds");
        hello.set_padding(0x3000);
        assert!(hello.enable_ech(&list).is_err());
    }

    #[cfg_attr(miri, ignore = "uses the OS random source")]
    #[test]
    fn an_aes_256_only_config_seals_the_inner_hello() {
        let (list, keys) = crate::tls::ech::generate_with_suites(
            "public.test",
            8,
            &[(
                crate::tls::ech::KDF_SHA256,
                crate::tls::ech::AEAD_AES_256_GCM,
            )],
        )
        .expect("generates");
        let profile = Fingerprint::default().profile().expect("profile");
        let mut hello =
            Hello::build(profile, "hidden.test", &[], false, &[], None).expect("builds");
        hello.enable_ech(&list).expect("ech");

        let body = &hello.msg[4..];
        let outer = extensions(body)
            .into_iter()
            .find(|ext| kind(ext) == 0xfe0d)
            .expect("ech extension");
        assert_eq!(u16::from_be_bytes([outer[7], outer[8]]), 2, "aes-256-gcm");
        let inner = open_inner(body, outer, &keys);
        assert!(
            inner
                .windows(b"hidden.test".len())
                .any(|window| window == b"hidden.test"),
            "the inner hello carries the real name"
        );
    }

    #[cfg_attr(miri, ignore = "uses the OS random source")]
    #[test]
    fn a_real_ech_offer_hides_the_inner_name_under_the_public_one() {
        let (list, keys) = crate::tls::ech::generate("public.test", 7).expect("generates");
        let profile = Fingerprint::default().profile().expect("profile");
        let mut hello =
            Hello::build(profile, "hidden.test", &[], false, &[], None).expect("builds");
        hello.enable_ech(&list).expect("ech");

        let body = &hello.msg[4..];
        let outer_exts = extensions(body);
        let outer = outer_exts
            .iter()
            .find(|ext| kind(ext) == 0xfe0d)
            .expect("ech extension");
        assert_eq!(kind(outer_exts.last().expect("extensions")), 0xfe0d);
        assert_eq!(outer[4], 0, "ClientHelloOuter");
        assert_eq!(outer[9], 7, "config id");
        let enc_len = usize::from(outer[10]) << 8 | usize::from(outer[11]);
        assert_eq!(enc_len, 32, "x25519 encapsulation");
        let sni = outer_exts
            .iter()
            .find(|ext| kind(ext) == 0x0000)
            .expect("sni");
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

        let inner = open_inner(body, outer, &keys);
        assert_eq!(inner[0], 0x03, "inner legacy version");
        assert_eq!(inner[1], 0x03, "inner legacy version");
        assert_eq!(inner[34], 0, "inner session id is empty");
        let cipher_len = usize::from(inner[35]) << 8 | usize::from(inner[36]);
        assert!(cipher_len > 0, "the inner hello offers TLS 1.3 ciphers");
        for cipher in inner[37..37 + cipher_len].as_chunks::<2>().0 {
            let id = u16::from_be_bytes(*cipher);
            assert!(
                matches!(id, 0x1301..=0x1303),
                "the inner hello offers only TLS 1.3 ciphers"
            );
        }
        assert!(
            inner
                .windows(b"hidden.test".len())
                .any(|window| window == b"hidden.test"),
            "the inner hello carries the real name"
        );
        let inner_exts = extensions(&inner);
        assert_eq!(kind(inner_exts.last().expect("extensions")), 0xfe0d);
        assert_eq!(inner_exts.last().expect("extensions")[4], 1, "ECH inner");
        let versions = inner_exts
            .iter()
            .find(|ext| kind(ext) == 0x002b)
            .expect("supported versions");
        assert_eq!(
            &versions[4..],
            &[2, 0x03, 0x04],
            "the inner hello offers 1.3 only"
        );

        assert_eq!(inner.len() % 32, 0, "the inner payload is padded");
        let mut at = 2 + 32;
        at += 1 + usize::from(inner[at]);
        let ciphers = usize::from(u16::from_be_bytes([inner[at], inner[at + 1]]));
        at += 2 + ciphers;
        at += 1 + usize::from(inner[at]);
        let exts = usize::from(u16::from_be_bytes([inner[at], inner[at + 1]]));
        let body = at + 2 + exts;
        let mut expected = inner[..34].to_vec();
        expected.push(32);
        expected.extend_from_slice(&hello.session_id);
        expected.extend_from_slice(&inner[35..body]);
        expected = handshake(1, &expected);
        let transcript = hello.ech_inner().expect("inner transcript");
        assert_eq!(
            transcript, expected,
            "the transcript is the inner hello under the outer id"
        );
        let inner_random = hello.ech_inner_random().expect("inner random");
        let retry = hello
            .retry(crate::tls::shaped::keys::P256, None)
            .expect("retries");
        assert!(retry.ech_inner().is_some(), "a retry re-seals the offer");
        assert_eq!(
            retry.ech_inner_random().expect("retry random"),
            inner_random,
            "a retry keeps the inner random"
        );
        let retry_exts = extensions(&retry.msg[4..]);
        let retry_ech = retry_exts
            .iter()
            .find(|ext| kind(ext) == 0xfe0d)
            .expect("ech extension");
        assert_eq!(retry_ech[10], 0, "a retry carries no encapsulation");
        assert_eq!(retry_ech[11], 0, "a retry carries no encapsulation");
    }

    #[test]
    fn a_retry_outside_the_configured_groups_is_refused() {
        let profile = Fingerprint::resolve("chrome")
            .expect("a preset name resolves")
            .profile()
            .expect("a shaped profile");
        let mut hello = Hello::build(profile, "example.com", &[], false, &[keys::X25519], None)
            .expect("a shaped dial hello");
        assert!(
            hello.retry(keys::P256, None).is_err(),
            "a retry for a group curvePreferences does not name"
        );
    }

    #[test]
    fn a_retry_for_a_group_the_first_hello_sent_is_refused() {
        let profile = Fingerprint::resolve("chrome")
            .expect("a preset name resolves")
            .profile()
            .expect("a shaped profile");
        let mut hello = Hello::build(profile, "example.com", &[], false, &[], None)
            .expect("a shaped dial hello");
        assert!(
            hello.retry(keys::X25519, None).is_err(),
            "a retry for a group the first hello already sent"
        );
    }

    fn invariant(kind: u16) -> bool {
        kind & 0x0f0f == 0x0a0a || kind == 0x0015 || kind == 0x0029
    }

    /// Replay the uTLS oracle: every xray name that shapes a hello must emit the reference's bytes, or where Chrome shuffles its extension multiset, invariant slots and the body ahead of them.
    #[test]
    fn oracle_replay_matches_utls() {
        let script = include_str!("../../../../../scripts/utls-oracle/script.txt");
        let expected = include_str!("../../../../../scripts/utls-oracle/expected.txt");
        let cases: Vec<(&str, &str)> = script
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| {
                let fields: Vec<&str> = line.split_whitespace().collect();
                (fields[0], fields[1])
            })
            .collect();
        let golden: Vec<&str> = expected
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();
        assert_eq!(cases.len(), golden.len(), "script and golden differ");
        let mut seen: Vec<usize> = Vec::new();
        for ((name, id), want) in cases.iter().zip(&golden) {
            let fields: Vec<&str> = want.split_whitespace().collect();
            assert_eq!(fields[1], *name, "golden order");
            let profile = Fingerprint::resolve(name)
                .expect("a preset name resolves")
                .profile()
                .expect("a shaped profile");
            let pointer = std::ptr::from_ref(profile) as usize;
            if !seen.contains(&pointer) {
                seen.push(pointer);
            }
            assert_eq!(profile.shuffle, fields[0] == "SH", "{name} shuffle flag");
            let hello = Hello::canonical(profile, "example.com");
            let body = &hello.msg[4..];
            let exts = extensions(body);
            if fields[0] == "CH" {
                assert_eq!(hex(body), fields[2], "{name} ({id})");
            } else {
                let fixed: Vec<usize> = exts
                    .iter()
                    .enumerate()
                    .filter(|(_, ext)| invariant(kind(ext)))
                    .map(|(at, _)| at)
                    .collect();
                let want_fixed: Vec<usize> = fields[3]
                    .split(',')
                    .map(|at| at.parse().expect("an index"))
                    .collect();
                assert_eq!(fixed, want_fixed, "{name} invariant positions");
                let tail: usize = exts.iter().map(|ext| ext.len()).sum();
                assert_eq!(
                    hex(&body[..body.len() - tail]),
                    fields[4],
                    "{name} ({id}) the body ahead of the extensions"
                );
                let mut sorted = exts.clone();
                sorted.sort();
                let joined: Vec<u8> = sorted.iter().flat_map(|ext| ext.iter().copied()).collect();
                assert_eq!(hex(&joined), fields[2], "{name} ({id}) extension multiset");
            }
        }
        assert_eq!(cases.len(), 50, "every xray name is covered");
        assert_eq!(seen.len(), 31, "the names resolve to 31 distinct presets");
    }

    /// The hello's own bytes cost one heap buffer, reserved to their exact length before the first
    /// write, beside the one list that orders the extensions: 2 allocations for a Chrome hello,
    /// where a body buffer each cost 18. Every width comes from the same walk that writes the body.
    #[test]
    fn a_shaped_hello_writes_into_one_buffer() {
        let profile = Fingerprint::resolve("chrome")
            .expect("a preset name resolves")
            .profile()
            .expect("a shaped profile");
        let hello = Hello::canonical(profile, "example.com");
        let (msg, counts) = crate::alloc_count::measure(|| hello.encode(None));
        assert_eq!(hex(&msg), hex(&hello.msg), "the replayed bytes");
        assert_eq!(
            msg.len(),
            msg.capacity(),
            "no slack after the exact reserve"
        );
        assert_eq!(
            counts.allocs, 2,
            "one list and one message for the hello: {counts:?}"
        );
    }

    /// Chrome's shuffle reads its picks off the stack, so a shuffled preset's order
    /// costs no heap buffer between the width pass and the write pass.
    #[test]
    fn the_shuffle_draws_its_picks_without_a_heap_buffer() {
        let profile = Fingerprint::resolve("hellochrome_106_shuffle")
            .expect("a preset name resolves")
            .profile()
            .expect("a shaped profile");
        assert!(profile.shuffle, "the preset is one Chrome shuffles");
        let hello = Hello::canonical(profile, "example.com");
        let mut entries = hello.extension_entries(
            &hello.shares,
            None,
            hello.sni.as_deref(),
            hello.ech.as_deref(),
            false,
        );
        let ((), counts) = crate::alloc_count::measure(|| shuffle(&mut entries));
        assert_eq!(counts.allocs, 0, "the picks are a stack pool: {counts:?}");
    }

    /// A server's ALPN pick is checked where the offer lies, so neither a preset's table
    /// nor a carrier's forced list is copied out to answer it.
    #[test]
    fn an_alpn_pick_is_checked_without_a_copy() {
        let profile = Fingerprint::resolve("360")
            .expect("a preset name resolves")
            .profile()
            .expect("a shaped profile");
        let hello = Hello::canonical(profile, "example.com");
        let (offered, counts) = crate::alloc_count::measure(|| hello.offers_alpn(b"spdy/3.1"));
        assert!(offered, "the preset's table names the protocol");
        assert!(!hello.offers_alpn(b"h2"), "and not one it omits");
        assert_eq!(counts.allocs, 0, "the table is walked in place: {counts:?}");
        let dial = Hello::build(profile, "example.com", &[b"h2".to_vec()], true, &[], None)
            .expect("a shaped dial hello");
        let (offered, counts) = crate::alloc_count::measure(|| dial.offers_alpn(b"http/1.1"));
        assert!(offered, "the carrier's forced list names the protocol");
        assert!(!dial.offers_alpn(b"h2"), "and not the one it replaced");
        assert_eq!(counts.allocs, 0, "the list is walked in place: {counts:?}");
        let pair = [b"h2".to_vec(), b"http/1.1".to_vec()];
        let (forced, counts) = crate::alloc_count::measure(|| alpn_override(&pair, true));
        let forced = forced.expect("a websocket carrier forces a list");
        assert_eq!(forced.len(), 2, "the caller's own pair is kept");
        assert_eq!(counts.allocs, 0, "the forced list is a static: {counts:?}");
    }

    /// The stock table is Go's shape at both version ceilings: ALPN between the signature
    /// algorithms and `supported_versions`, the hybrid share and its X25519 fallback above 1.2,
    /// and neither share nor hybrid group at a 1.2 ceiling.
    #[test]
    fn the_stock_table_is_go_shape_at_both_version_ceilings() {
        let mut tls13 = Hello::build(
            &crate::tls::shaped::GO_STOCK,
            "example.com",
            &[],
            false,
            &[],
            None,
        )
        .expect("the stock hello builds");
        tls13.set_alpn(&[b"h2".to_vec(), b"http/1.1".to_vec()]);
        let exts = extensions(&tls13.msg[4..]);
        let kinds: Vec<u16> = exts.iter().map(|ext| kind(ext)).collect();
        let alpn = kinds
            .iter()
            .position(|&kind| kind == ALPN)
            .expect("the config names ALPN");
        assert_eq!(kinds[alpn - 1], 0x000d, "after the signature algorithms");
        assert_eq!(kinds[alpn + 1], 0x002b, "and before supported_versions");
        assert!(tls13.offers_alpn(b"h2"), "the config's list is the offer");
        let share = exts
            .iter()
            .find(|ext| kind(ext) == 0x0033)
            .expect("a TLS 1.3 hello shares");
        let body = &share[4..];
        let mut at = 2;
        let mut named = Vec::new();
        while at + 4 <= body.len() {
            named.push(u16::from_be_bytes([body[at], body[at + 1]]));
            at += 4 + usize::from(u16::from_be_bytes([body[at + 2], body[at + 3]]));
        }
        assert_eq!(named, [0x11ec, 0x001d], "the hybrid, then its fallback");

        let tls12 = Hello::build(
            &crate::tls::shaped::GO_STOCK_12,
            "example.com",
            &[],
            false,
            &[],
            None,
        )
        .expect("the TLS 1.2 stock hello builds");
        let exts = extensions(&tls12.msg[4..]);
        assert!(
            exts.iter().all(|ext| kind(ext) != 0x0033),
            "no key share below 1.3"
        );
        assert!(
            exts.iter().all(|ext| kind(ext) != ALPN),
            "no ALPN unless the config names one"
        );
        let groups = exts
            .iter()
            .find(|ext| kind(ext) == 0x000a)
            .expect("the hello names its groups");
        assert!(
            !groups.windows(2).any(|pair| pair == [0x11, 0xec]),
            "the hybrid group stays off a TLS 1.2 hello"
        );
        let versions = exts
            .iter()
            .find(|ext| kind(ext) == 0x002b)
            .expect("the hello names its versions");
        assert_eq!(&versions[4..], &[0x02, 0x03, 0x03], "1.2 only");
    }

    /// A dial's own hello — random draws, Chrome's shuffle, a carrier's forced ALPN and a retry's
    /// cookie — is the walk no golden byte names, and it still closes exactly on the vector it
    /// measured: every width below is the one the same walk wrote its bytes into.
    #[test]
    fn a_shuffled_hello_with_a_cookie_and_a_forced_alpn_stays_exactly_sized() {
        let profile = Fingerprint::resolve("chrome")
            .expect("a preset name resolves")
            .profile()
            .expect("a shaped profile");
        let mut hello = Hello::build(
            profile,
            "example.com",
            &[b"http/1.1".to_vec()],
            true,
            &[],
            None,
        )
        .expect("a shaped dial hello");
        let retry = hello
            .retry(keys::P256, Some(&[7, 6, 5]))
            .expect("a retry hello");
        let exts = extensions(&retry.msg[4..]);
        let cookie = exts
            .iter()
            .find(|ext| kind(ext) == 0x002c)
            .expect("the cookie echoes back");
        assert_eq!(
            cookie[2..],
            [0, 5, 0, 3, 7, 6, 5],
            "the cookie's width beside its bytes"
        );
        let alpn = exts
            .iter()
            .find(|ext| kind(ext) == ALPN)
            .expect("the carrier names its protocol");
        assert_eq!(
            alpn[2..],
            [0, 11, 0, 9, 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'],
            "the forced ALPN's width beside its bytes"
        );
    }

    /// The GREASE ECH cover a dial ships is one buffer reserved to its own length,
    /// where a grown header beside a staged payload cost five.
    #[test]
    fn an_ech_cover_is_written_into_one_buffer() {
        let profile = Fingerprint::resolve("chrome")
            .expect("a preset name resolves")
            .profile()
            .expect("a shaped profile");
        let (cover, counts) = crate::alloc_count::measure(|| ech_body(profile, false));
        let cover = cover.expect("a profile that offers ECH builds a cover");
        assert_eq!(counts.allocs, 1, "one buffer for the cover: {counts:?}");
        assert_eq!(
            counts.zeroed, 0,
            "the payload is filled in place, not staged: {counts:?}"
        );
        assert_eq!(
            cover.len(),
            cover.capacity(),
            "no slack after the exact reserve"
        );
    }
}

// The shaped client's record layer: both versions' framing over ring's AEADs and TLS 1.2's MAC-then-encrypt.
use super::kdf::{self, Hash, Mac};
use crate::shadowsocks::Rc4 as Keystream;
use crate::tls::TlsError;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hmac;

/// An AES-CBC block: the width a CBC suite's explicit IV, its padding unit and its MAC floor share.
const BLOCK: usize = 16;

/// A 3DES-CBC block, the width Go's two `3DES_EDE_CBC` rows pad and carry an IV at.
const DES_BLOCK: usize = 8;

/// The suites a shaped hello can key: three TLS 1.3 AEADs and TLS 1.2's AEAD, CBC, 3DES and RC4
/// rows, each TLS 1.2 name carrying the key exchange that fills its pre-master.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Suite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    ChaCha20Sha256,
    EcdheAes128GcmSha256,
    EcdheAes256GcmSha384,
    EcdheChaCha20Sha256,
    EcdheAes128CbcSha,
    EcdheAes256CbcSha,
    EcdheAes128CbcSha256,
    Ecdhe3DesCbcSha,
    EcdheRc4Sha,
    RsaAes128GcmSha256,
    RsaAes256GcmSha384,
    RsaAes128CbcSha,
    RsaAes256CbcSha,
    RsaAes128CbcSha256,
    Rsa3DesCbcSha,
    RsaRc4Sha,
}

impl Suite {
    pub(crate) fn from_id(id: u16) -> Option<Self> {
        Some(match id {
            0x1301 => Self::Aes128GcmSha256,
            0x1302 => Self::Aes256GcmSha384,
            0x1303 => Self::ChaCha20Sha256,
            0xc02b | 0xc02f => Self::EcdheAes128GcmSha256,
            0xc02c | 0xc030 => Self::EcdheAes256GcmSha384,
            0xcca9 | 0xcca8 => Self::EcdheChaCha20Sha256,
            0xc009 | 0xc013 => Self::EcdheAes128CbcSha,
            0xc00a | 0xc014 => Self::EcdheAes256CbcSha,
            0xc023 | 0xc027 => Self::EcdheAes128CbcSha256,
            0xc012 => Self::Ecdhe3DesCbcSha,
            0xc007 | 0xc011 => Self::EcdheRc4Sha,
            0x009c => Self::RsaAes128GcmSha256,
            0x009d => Self::RsaAes256GcmSha384,
            0x002f => Self::RsaAes128CbcSha,
            0x0035 => Self::RsaAes256CbcSha,
            0x003c => Self::RsaAes128CbcSha256,
            0x000a => Self::Rsa3DesCbcSha,
            0x0005 => Self::RsaRc4Sha,
            _ => return None,
        })
    }

    pub(crate) fn is_tls13(self) -> bool {
        matches!(
            self,
            Self::Aes128GcmSha256 | Self::Aes256GcmSha384 | Self::ChaCha20Sha256
        )
    }

    /// The suite whose pre-master the client encrypts to the leaf's key: no `ServerKeyExchange`, no share.
    pub(crate) fn is_rsa(self) -> bool {
        matches!(
            self,
            Self::RsaAes128GcmSha256
                | Self::RsaAes256GcmSha384
                | Self::RsaAes128CbcSha
                | Self::RsaAes256CbcSha
                | Self::RsaAes128CbcSha256
                | Self::Rsa3DesCbcSha
                | Self::RsaRc4Sha
        )
    }

    /// The suite whose records pad and chain on an eight-byte block rather than a sixteen-byte one.
    pub(crate) fn is_des(self) -> bool {
        matches!(self, Self::Ecdhe3DesCbcSha | Self::Rsa3DesCbcSha)
    }

    /// The suite whose records are MAC-then-encrypt on a stream, so no IV in the key block or the record and no padding at all.
    pub(crate) fn is_rc4(self) -> bool {
        matches!(self, Self::EcdheRc4Sha | Self::RsaRc4Sha)
    }

    /// The PRF and handshake hash. The reference moves this to SHA-384 only for a suite flagged
    /// `SHA384`, which no CBC suite is; a CBC suite's SHA-1 MAC is a separate choice.
    pub(crate) fn hash(self) -> Hash {
        match self {
            Self::Aes256GcmSha384 | Self::EcdheAes256GcmSha384 | Self::RsaAes256GcmSha384 => {
                Hash::Sha384
            }
            _ => Hash::Sha256,
        }
    }

    pub(crate) fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256
            | Self::EcdheAes128GcmSha256
            | Self::EcdheAes128CbcSha
            | Self::EcdheAes128CbcSha256
            | Self::RsaAes128GcmSha256
            | Self::RsaAes128CbcSha
            | Self::RsaAes128CbcSha256
            | Self::EcdheRc4Sha
            | Self::RsaRc4Sha => 16,
            Self::Ecdhe3DesCbcSha | Self::Rsa3DesCbcSha => 24,
            _ => 32,
        }
    }

    /// The record MAC of a MAC-then-encrypt suite, and none for an AEAD one.
    pub(crate) fn mac(self) -> Option<Mac> {
        match self {
            Self::EcdheAes128CbcSha
            | Self::EcdheAes256CbcSha
            | Self::RsaAes128CbcSha
            | Self::RsaAes256CbcSha
            | Self::Ecdhe3DesCbcSha
            | Self::Rsa3DesCbcSha
            | Self::EcdheRc4Sha
            | Self::RsaRc4Sha => Some(Mac::Sha1),
            Self::EcdheAes128CbcSha256 | Self::RsaAes128CbcSha256 => Some(Mac::Sha256),
            _ => None,
        }
    }

    /// A TLS 1.2 key block's per-direction IV: four bytes for GCM's explicit nonce, twelve for
    /// `ChaCha`'s XOR nonce, a whole block for the IV a CBC record carries in the clear, none for a stream.
    pub(crate) fn iv_len(self) -> usize {
        match self {
            Self::EcdheAes128GcmSha256
            | Self::EcdheAes256GcmSha384
            | Self::RsaAes128GcmSha256
            | Self::RsaAes256GcmSha384 => 4,
            Self::ChaCha20Sha256 | Self::EcdheChaCha20Sha256 => 12,
            Self::Ecdhe3DesCbcSha | Self::Rsa3DesCbcSha => DES_BLOCK,
            Self::EcdheRc4Sha | Self::RsaRc4Sha => 0,
            _ => BLOCK,
        }
    }

    fn gcm(self) -> bool {
        matches!(
            self,
            Self::Aes128GcmSha256
                | Self::Aes256GcmSha384
                | Self::EcdheAes128GcmSha256
                | Self::EcdheAes256GcmSha384
                | Self::RsaAes128GcmSha256
                | Self::RsaAes256GcmSha384
        )
    }
}

/// One direction's keys and record counter: a sequence number reused under one key loses the record layer's integrity.
#[allow(
    clippy::large_enum_variant,
    reason = "seal and open reach the key of every record; boxing a half puts a chase on that path"
)]
pub(crate) enum Direction {
    Aead(Aead),
    Cbc(Cbc<Aes>),
    Tdes(Cbc<Tdes>),
    Rc4(Rc4),
}

impl Direction {
    /// TLS 1.3 keys from a traffic secret: `HKDF-Expand-Label(secret, "key"/"iv", "", ...)`.
    pub(crate) fn tls13(suite: Suite, secret: &[u8]) -> Self {
        Self::Aead(Aead::tls13(suite, secret))
    }

    /// TLS 1.2 keys from one direction's slices of the expanded block. The MAC key is empty for
    /// an AEAD suite, which puts its tag inside the record rather than in front of the padding,
    /// and a CBC suite ignores the block's IV because every record carries its own in the clear.
    pub(crate) fn tls12(suite: Suite, key: &[u8], mac: &[u8], iv: &[u8]) -> Self {
        match suite.mac() {
            Some(kind) if suite.is_rc4() => Self::Rc4(Rc4::new(kind, key, mac)),
            Some(kind) if suite.is_des() => Self::Tdes(Cbc::new(kind, key, mac)),
            Some(kind) => Self::Cbc(Cbc::new(kind, key, mac)),
            None => Self::Aead(Aead::tls12(suite, key, iv)),
        }
    }

    /// The traffic secret a kernel offload installs, when this is a TLS 1.3 direction.
    pub(crate) fn ktls_material(&self) -> Option<(crate::tls::ktls::Cipher, Hash, Vec<u8>, u64)> {
        let Self::Aead(keys) = self else {
            return None;
        };
        if !keys.tls13 {
            return None;
        }
        let cipher = match keys.suite {
            Suite::Aes128GcmSha256 => crate::tls::ktls::Cipher::Aes128Gcm,
            Suite::Aes256GcmSha384 => crate::tls::ktls::Cipher::Aes256Gcm,
            Suite::ChaCha20Sha256 => crate::tls::ktls::Cipher::ChaCha20Poly1305,
            _ => return None,
        };
        Some((cipher, keys.hash, keys.secret.clone(), keys.seq))
    }

    /// Rebuilds a direction at a counter a caller already reached, for a layer taking over mid-stream.
    pub(crate) fn tls13_at(suite: Suite, secret: &[u8], seq: u64) -> Self {
        let mut direction = Self::tls13(suite, secret);
        if let Self::Aead(keys) = &mut direction {
            keys.seq = seq;
        }
        direction
    }

    /// The next traffic secret of a TLS 1.3 direction; TLS 1.2 has no key update.
    pub(crate) fn update(&mut self) {
        if let Self::Aead(keys) = self {
            keys.update();
        }
    }
}

/// An AEAD direction: the traffic key, the fixed half of its nonce, and the counter that tells two records apart.
pub(crate) struct Aead {
    key: LessSafeKey,
    iv: [u8; 12],
    seq: u64,
    suite: Suite,
    tls13: bool,
    hash: Hash,
    secret: Vec<u8>,
}

impl Aead {
    fn tls13(suite: Suite, secret: &[u8]) -> Self {
        let hash = suite.hash();
        let mut key = vec![0u8; suite.key_len()];
        kdf::expand_label(hash, secret, b"key", b"", &mut key);
        let mut iv = [0u8; 12];
        kdf::expand_label(hash, secret, b"iv", b"", &mut iv);
        Self {
            key: keyed(suite, &key),
            iv,
            seq: 0,
            suite,
            tls13: true,
            hash,
            secret: secret.to_vec(),
        }
    }

    fn tls12(suite: Suite, key: &[u8], iv: &[u8]) -> Self {
        let mut fixed = [0u8; 12];
        fixed[..iv.len()].copy_from_slice(iv);
        Self {
            key: keyed(suite, key),
            iv: fixed,
            seq: 0,
            suite,
            tls13: false,
            hash: suite.hash(),
            secret: Vec::new(),
        }
    }

    fn update(&mut self) {
        let mut next = vec![0u8; self.secret.len()];
        kdf::expand_label(self.hash, &self.secret, b"traffic upd", b"", &mut next);
        let suite = self.suite;
        let mut key = vec![0u8; suite.key_len()];
        kdf::expand_label(self.hash, &next, b"key", b"", &mut key);
        let mut iv = [0u8; 12];
        kdf::expand_label(self.hash, &next, b"iv", b"", &mut iv);
        self.key = keyed(suite, &key);
        self.iv = iv;
        self.seq = 0;
        self.secret = next;
    }

    fn nonce(&self, seq: u64) -> [u8; 12] {
        let mut nonce = self.iv;
        if self.tls13 || !self.suite.gcm() {
            // One big-endian XOR is the same bytes as eight, and a TLS 1.3 nonce is the IV under the counter.
            let iv = u64::from_be_bytes(nonce[4..].try_into().expect("eight-byte IV tail"));
            nonce[4..].copy_from_slice(&(iv ^ seq).to_be_bytes());
        } else {
            nonce[4..].copy_from_slice(&seq.to_be_bytes());
        }
        nonce
    }

    /// Seals `plain` in place at `out[at..]` and appends the tag.
    fn seal(&mut self, aad: &[u8], at: usize, out: &mut Vec<u8>) -> Result<(), TlsError> {
        let nonce = Nonce::assume_unique_for_key(self.nonce(self.seq));
        self.seq = self.seq.wrapping_add(1);
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(aad), &mut out[at..])
            .map_err(|_| TlsError::Other("record seal failed".to_owned()))?;
        out.extend_from_slice(tag.as_ref());
        Ok(())
    }

    fn open<'a>(&mut self, aad: &[u8], body: &'a mut [u8]) -> Result<&'a mut [u8], TlsError> {
        let nonce = Nonce::assume_unique_for_key(self.nonce(self.seq));
        self.seq = self.seq.wrapping_add(1);
        self.key
            .open_in_place(nonce, Aad::from(aad), body)
            .map_err(|_| TlsError::Other("record failed authentication".to_owned()))
    }

    /// A TLS 1.2 GCM record: the sender picks the explicit nonce, so the wire bytes complete the IV.
    fn open_explicit<'a>(
        &mut self,
        aad: &[u8],
        explicit: [u8; 8],
        body: &'a mut [u8],
    ) -> Result<&'a mut [u8], TlsError> {
        let mut nonce = self.iv;
        nonce[4..].copy_from_slice(&explicit);
        let nonce = Nonce::assume_unique_for_key(nonce);
        self.seq = self.seq.wrapping_add(1);
        self.key
            .open_in_place(nonce, Aad::from(aad), body)
            .map_err(|_| TlsError::Other("record failed authentication".to_owned()))
    }

    fn seal12_parts(
        &mut self,
        kind: u8,
        parts: &[&[u8]],
        out: &mut Vec<u8>,
    ) -> Result<(), TlsError> {
        let len: usize = parts.iter().map(|part| part.len()).sum();
        let explicit = if self.suite.gcm() { 8 } else { 0 };
        let aad = self.aad12(kind, len);
        let seq = self.seq.to_be_bytes();
        let at = out.len();
        let total = (len + explicit + 16) as u16;
        out.reserve(5 + explicit + len + 16);
        out.extend_from_slice(&[kind, 0x03, 0x03, (total >> 8) as u8, total as u8]);
        if explicit != 0 {
            out.extend_from_slice(&seq);
        }
        for part in parts {
            out.extend_from_slice(part);
        }
        self.seal(&aad, at + 5 + explicit, out)
    }

    fn open12(&mut self, kind: u8, body: &mut [u8]) -> Result<(usize, usize), TlsError> {
        let explicit = if self.suite.gcm() { 8 } else { 0 };
        if body.len() < explicit + 16 {
            return Err(TlsError::Other("short TLS 1.2 record".to_owned()));
        }
        let aad = self.aad12(kind, body.len() - explicit - 16);
        let (start, len) = if self.suite.gcm() {
            let nonce: [u8; 8] = body[..8].try_into().expect("eight-byte explicit nonce");
            (8, self.open_explicit(&aad, nonce, &mut body[8..])?.len())
        } else {
            (0, self.open(&aad, &mut body[..])?.len())
        };
        Ok((start, len))
    }

    /// The same record opened into the caller's buffer, its explicit nonce left behind on the wire.
    fn open12_into(&mut self, kind: u8, body: &[u8], out: &mut [u8]) -> Result<usize, TlsError> {
        let explicit = if self.suite.gcm() { 8 } else { 0 };
        if body.len() < explicit + 16 {
            return Err(TlsError::Other("short TLS 1.2 record".to_owned()));
        }
        let n = body.len() - explicit;
        let aad = self.aad12(kind, n - 16);
        out[..n].copy_from_slice(&body[explicit..]);
        let len = if explicit == 8 {
            let nonce: [u8; 8] = body[..8].try_into().expect("eight-byte explicit nonce");
            self.open_explicit(&aad, nonce, &mut out[..n])?.len()
        } else {
            self.open(&aad, &mut out[..n])?.len()
        };
        Ok(len)
    }

    /// The additional data a TLS 1.2 record authenticates: its counter, type, version and plaintext length.
    fn aad12(&self, kind: u8, plain_len: usize) -> [u8; 13] {
        let mut aad = [0u8; 13];
        aad[..8].copy_from_slice(&self.seq.to_be_bytes());
        aad[8] = kind;
        aad[9..11].copy_from_slice(&[0x03, 0x03]);
        aad[11..].copy_from_slice(&(plain_len as u16).to_be_bytes());
        aad
    }
}

/// A TLS 1.2 CBC direction: the block cipher, the HMAC its record's front carries, and the counter both sign.
pub(crate) struct Cbc<C: Chain> {
    block: C,
    mac: Mac,
    mac_key: hmac::Key,
    seq: u64,
}

impl<C: Chain> Cbc<C> {
    fn new(mac: Mac, key: &[u8], mac_key: &[u8]) -> Self {
        Self {
            block: C::new(key),
            mac,
            mac_key: mac.key(mac_key),
            seq: 0,
        }
    }

    /// MAC-then-encrypt as RFC 5246 lays it out: the header the MAC signs names the
    /// plaintext, and the wire header names that plus the MAC, the padding and the clear IV.
    fn seal(&mut self, kind: u8, parts: &[&[u8]], out: &mut Vec<u8>) -> Result<(), TlsError> {
        let width = C::WIDTH;
        let len: usize = parts.iter().map(|part| part.len()).sum();
        let mac_len = self.mac.len();
        let pad = width - (len + mac_len) % width;
        let at = out.len();
        out.reserve(5 + width + len + mac_len + pad);
        out.extend_from_slice(&[kind, 0x03, 0x03, (len >> 8) as u8, len as u8]);
        let mut iv = [0u8; BLOCK];
        let iv = &mut iv[..width];
        getrandom::fill(iv).map_err(|e| TlsError::Other(format!("record IV: {e}")))?;
        out.extend_from_slice(iv);
        let body = out.len();
        for part in parts {
            out.extend_from_slice(part);
        }
        let seq = self.seq.to_be_bytes();
        self.seq = self.seq.wrapping_add(1);
        let tag = kdf::sign(&self.mac_key, &[&seq, &out[at..at + 5], &out[body..]]);
        out.extend_from_slice(tag.as_ref());
        out.resize(out.len() + pad, (pad - 1) as u8);
        self.block.encrypt(&iv[..], &mut out[body..]);
        let total = (out.len() - at - 5) as u16;
        out[at + 3..at + 5].copy_from_slice(&total.to_be_bytes());
        Ok(())
    }

    /// Opens a CBC record body in place: the plaintext starts one block in, behind the clear IV.
    fn open(&mut self, kind: u8, body: &mut [u8]) -> Result<(usize, usize), TlsError> {
        let width = C::WIDTH;
        self.content_len(body.len())?;
        let mut iv = [0u8; BLOCK];
        iv[..width].copy_from_slice(&body[..width]);
        self.block.decrypt(&iv[..width], &mut body[width..]);
        Ok((width, self.authenticate(kind, &body[width..])?))
    }

    /// The same record opened straight off the wire into the caller's buffer: the IV and the
    /// block behind each one stay where they are, so nothing is staged before it is decrypted.
    fn open_into(&mut self, kind: u8, body: &[u8], out: &mut [u8]) -> Result<usize, TlsError> {
        let content = self.content_len(body.len())?;
        self.block.decrypt_into(body, &mut out[..content]);
        self.authenticate(kind, &out[..content])
    }

    /// The blocks a CBC body carries past its IV: whole of them, and enough for an HMAC and a pad byte.
    fn content_len(&self, wire: usize) -> Result<usize, TlsError> {
        if wire < C::WIDTH + self.mac.len() + 1 || !wire.is_multiple_of(C::WIDTH) {
            return Err(TlsError::Other("short TLS 1.2 CBC record".to_owned()));
        }
        Ok(wire - C::WIDTH)
    }

    /// The padding-and-MAC tail read back off a decrypted record, returning the payload length.
    fn authenticate(&mut self, kind: u8, content: &[u8]) -> Result<usize, TlsError> {
        let mac_len = self.mac.len();
        let pad = padding(content, mac_len);
        let plain = content.len() - mac_len - pad;
        let seq = self.seq.to_be_bytes();
        self.seq = self.seq.wrapping_add(1);
        let header = [kind, 0x03, 0x03, (plain >> 8) as u8, plain as u8];
        let expected = kdf::sign(&self.mac_key, &[&seq, &header, &content[..plain]]);
        tag_is(expected.as_ref(), &content[plain..plain + mac_len])?;
        Ok(plain)
    }
}

/// A TLS 1.2 RC4-SHA direction: the keystream its records continue, the HMAC each carries at its tail, and the counter that signs it.
pub(crate) struct Rc4 {
    stream: Keystream,
    mac: Mac,
    mac_key: hmac::Key,
    seq: u64,
}

impl Rc4 {
    fn new(mac: Mac, key: &[u8], mac_key: &[u8]) -> Self {
        Self {
            stream: Keystream::new(key).expect("a TLS 1.2 stream key schedules"),
            mac,
            mac_key: mac.key(mac_key),
            seq: 0,
        }
    }

    /// MAC-then-encrypt as Go's stream case lays it out: payload and MAC through the keystream together, no IV ahead and no pad behind.
    fn seal(&mut self, kind: u8, parts: &[&[u8]], out: &mut Vec<u8>) {
        let len: usize = parts.iter().map(|part| part.len()).sum();
        let at = out.len();
        out.reserve(5 + len + self.mac.len());
        out.extend_from_slice(&[kind, 0x03, 0x03, (len >> 8) as u8, len as u8]);
        let body = out.len();
        for part in parts {
            out.extend_from_slice(part);
        }
        let seq = self.seq.to_be_bytes();
        self.seq = self.seq.wrapping_add(1);
        let tag = kdf::sign(&self.mac_key, &[&seq, &out[at..at + 5], &out[body..]]);
        out.extend_from_slice(tag.as_ref());
        let total = (out.len() - at - 5) as u16;
        out[at + 3..at + 5].copy_from_slice(&total.to_be_bytes());
        self.stream.crypt(&mut out[body..]);
    }

    /// Opens a stream record in place: the keystream runs over payload and MAC together, so the plaintext is what the MAC leaves behind.
    fn open(&mut self, kind: u8, body: &mut [u8]) -> Result<(usize, usize), TlsError> {
        self.content_len(body.len())?;
        self.stream.crypt(body);
        Ok((0, self.authenticate(kind, body)?))
    }

    /// The same record read off the wire into the caller's window, which one body copy fills before the keystream runs over it.
    fn open_into(&mut self, kind: u8, body: &[u8], out: &mut [u8]) -> Result<usize, TlsError> {
        self.content_len(body.len())?;
        out[..body.len()].copy_from_slice(body);
        self.stream.crypt(&mut out[..body.len()]);
        self.authenticate(kind, &out[..body.len()])
    }

    /// A stream record is its payload and its MAC: the MAC's length is the only floor, and there is no block to be a multiple of.
    fn content_len(&self, wire: usize) -> Result<(), TlsError> {
        if wire < self.mac.len() {
            return Err(TlsError::Other("short TLS 1.2 RC4 record".to_owned()));
        }
        Ok(())
    }

    /// The MAC read off the end of a decrypted record, returning the payload length.
    fn authenticate(&mut self, kind: u8, content: &[u8]) -> Result<usize, TlsError> {
        let plain = content.len() - self.mac.len();
        let seq = self.seq.to_be_bytes();
        self.seq = self.seq.wrapping_add(1);
        let header = [kind, 0x03, 0x03, (plain >> 8) as u8, plain as u8];
        let expected = kdf::sign(&self.mac_key, &[&seq, &header, &content[..plain]]);
        tag_is(expected.as_ref(), &content[plain..])?;
        Ok(plain)
    }
}

/// Every MAC byte reaches this fold, so a wrong padding length or stream position fails the tag rather than branching on a secret.
fn tag_is(got: &[u8], want: &[u8]) -> Result<(), TlsError> {
    let mut fold = got.len() ^ want.len();
    for (got, want) in got.iter().zip(want) {
        fold |= usize::from(got ^ want);
    }
    if fold != 0 {
        return Err(TlsError::Other("record failed authentication".to_owned()));
    }
    Ok(())
}

/// The block cipher of a MAC-then-encrypt direction: the width its records pad and chain on, and
/// the three walks a body goes through. `Cbc` is monomorphized per implementor, so each width is a
/// constant in the walk rather than a field read per record.
pub(crate) trait Chain {
    const WIDTH: usize;

    fn new(key: &[u8]) -> Self;

    fn encrypt(&self, iv: &[u8], body: &mut [u8]);

    fn decrypt(&self, iv: &[u8], body: &mut [u8]);

    fn decrypt_into(&self, wire: &[u8], dst: &mut [u8]);
}

/// The AES schedule of a CBC direction, expanded once for the session rather than per record.
#[allow(
    clippy::large_enum_variant,
    reason = "every block of a record goes through this schedule; boxing the wider half puts a chase inside the cipher"
)]
pub(crate) enum Aes {
    Aes128(aes::Aes128),
    Aes256(aes::Aes256),
}

/// A block as the AES backend takes it. Both widths share it, so one batch feeds either key.
type Typed = aes::cipher::Block<aes::Aes128>;

/// The blocks one backend call permutes: AES-NI and `ARMv8` run this many `aesdec` chains side by
/// side, and a decryption never waits for the block before it.
const PAR: usize = 8;

/// The CBC XOR of a permuted block with the wire block behind it.
fn xor(left: &[u8], right: &[u8]) -> [u8; BLOCK] {
    let mut out = [0u8; BLOCK];
    for (slot, (got, mask)) in out.iter_mut().zip(left.iter().zip(right)) {
        *slot = got ^ mask;
    }
    out
}

impl Chain for Aes {
    const WIDTH: usize = BLOCK;

    fn new(key: &[u8]) -> Self {
        use aes::cipher::KeyInit;
        match key.len() {
            16 => {
                Self::Aes128(aes::Aes128::new_from_slice(key).expect("a sixteen-byte key expands"))
            }
            32 => Self::Aes256(
                aes::Aes256::new_from_slice(key).expect("a thirty-two-byte key expands"),
            ),
            _ => panic!("the key block names its own length"),
        }
    }

    /// CBC over whole blocks: each one chains through the cipher, forward from the record's IV.
    fn encrypt(&self, iv: &[u8], body: &mut [u8]) {
        match self {
            Self::Aes128(key) => forward(key, iv, body),
            Self::Aes256(key) => forward(key, iv, body),
        }
    }

    /// CBC over whole blocks: forward chains the ciphertext through the cipher, back chains the
    /// wire block, not the one it just decrypted. The batch permutes the stack copy, so the block
    /// behind each result is still the wire — taken from the top down, the write never reaches it.
    fn decrypt(&self, iv: &[u8], body: &mut [u8]) {
        let mut typed = std::array::from_fn(|_| Typed::from([0u8; BLOCK]));
        let mut prev = <[u8; BLOCK]>::try_from(iv).expect("a CBC record carries a whole-block IV");
        let mut blocks = body.as_chunks_mut::<BLOCK>().0;
        while !blocks.is_empty() {
            let count = blocks.len().min(PAR);
            let (group, rest) = blocks.split_at_mut(count);
            blocks = rest;
            for (slot, src) in typed[..count].iter_mut().zip(group.iter()) {
                *slot = (*src).into();
            }
            let carry = group[count - 1];
            self.permutation(&mut typed, count);
            for index in (1..count).rev() {
                let (head, slot) = group.split_at_mut(index);
                slot[0] = xor(&typed[index], &head[index - 1]);
            }
            group[0] = xor(&typed[0], &prev);
            prev = carry;
        }
    }

    /// The same chain read straight off the wire: the block behind each result stays where it is,
    /// so a CBC record reaches the caller's buffer without its ciphertext being staged first.
    fn decrypt_into(&self, wire: &[u8], dst: &mut [u8]) {
        let mut typed = std::array::from_fn(|_| Typed::from([0u8; BLOCK]));
        let blocks = dst.as_chunks_mut::<BLOCK>().0;
        let cipher = wire[BLOCK..].as_chunks::<BLOCK>().0;
        let masks = wire[..wire.len() - BLOCK].as_chunks::<BLOCK>().0;
        let mut at = 0;
        while at < blocks.len() {
            let count = (blocks.len() - at).min(PAR);
            for (slot, src) in typed[..count].iter_mut().zip(cipher[at..].iter()) {
                *slot = (*src).into();
            }
            self.permutation(&mut typed, count);
            for (slot, (plain, mask)) in blocks[at..][..count]
                .iter_mut()
                .zip(typed[..count].iter().zip(&masks[at..]))
            {
                *slot = xor(plain, mask);
            }
            at += count;
        }
    }
}

impl Aes {
    /// Up to `PAR` blocks through the backend in one call, the short tail inside the same call.
    fn permutation(&self, typed: &mut [Typed; PAR], count: usize) {
        use aes::cipher::BlockCipherDecrypt;
        match self {
            Self::Aes128(key) => key.decrypt_blocks(&mut typed[..count]),
            Self::Aes256(key) => key.decrypt_blocks(&mut typed[..count]),
        }
    }
}

/// The forward CBC chain of one key width, so the key's arm is chosen once per record and no branch
/// stands between the blocks of a write that must chain each ciphertext into the next.
fn forward<C: aes::cipher::BlockCipherEncrypt<BlockSize = aes::cipher::consts::U16>>(
    cipher: &C,
    iv: &[u8],
    body: &mut [u8],
) {
    let mut prev = <[u8; BLOCK]>::try_from(iv).expect("a CBC record carries a whole-block IV");
    for chunk in body.as_chunks_mut::<BLOCK>().0 {
        let mut typed = Typed::from(*chunk);
        for (slot, byte) in typed.iter_mut().zip(prev) {
            *slot ^= byte;
        }
        cipher.encrypt_block(&mut typed);
        *chunk = typed.into();
        prev = *chunk;
    }
}

/// The 3DES-EDE schedule of a CBC direction whose block is eight bytes, as Go's two `3DES` rows take it.
pub(crate) struct Tdes(des::TdesEde3);

/// A block as the 3DES backend takes it: this cipher permutes one at a time, so no batch feeds it.
type DesTyped = des::cipher::Block<des::TdesEde3>;

impl Chain for Tdes {
    const WIDTH: usize = DES_BLOCK;

    fn new(key: &[u8]) -> Self {
        use des::cipher::KeyInit;
        Self(
            des::TdesEde3::new_from_slice(key)
                .expect("a twenty-four-byte key expands to three schedules"),
        )
    }

    fn encrypt(&self, iv: &[u8], body: &mut [u8]) {
        use des::cipher::BlockCipherEncrypt;
        let mut prev =
            <[u8; DES_BLOCK]>::try_from(iv).expect("a CBC record carries a whole-block IV");
        for chunk in body.as_chunks_mut::<DES_BLOCK>().0 {
            let mut typed: DesTyped = (*chunk).into();
            for (slot, byte) in typed.iter_mut().zip(prev) {
                *slot ^= byte;
            }
            self.0.encrypt_block(&mut typed);
            *chunk = typed.into();
            prev = *chunk;
        }
    }

    fn decrypt(&self, iv: &[u8], body: &mut [u8]) {
        use des::cipher::BlockCipherDecrypt;
        let mut prev =
            <[u8; DES_BLOCK]>::try_from(iv).expect("a CBC record carries a whole-block IV");
        for chunk in body.as_chunks_mut::<DES_BLOCK>().0 {
            let carry = *chunk;
            let mut typed: DesTyped = carry.into();
            self.0.decrypt_block(&mut typed);
            chunk.copy_from_slice(&typed);
            for (slot, byte) in chunk.iter_mut().zip(prev) {
                *slot ^= byte;
            }
            prev = carry;
        }
    }

    fn decrypt_into(&self, wire: &[u8], dst: &mut [u8]) {
        use des::cipher::BlockCipherDecrypt;
        let blocks = dst.as_chunks_mut::<DES_BLOCK>().0;
        let cipher = wire[DES_BLOCK..].as_chunks::<DES_BLOCK>().0;
        let masks = wire[..wire.len() - DES_BLOCK].as_chunks::<DES_BLOCK>().0;
        for (slot, (src, mask)) in blocks.iter_mut().zip(cipher.iter().zip(masks)) {
            let mut typed: DesTyped = (*src).into();
            self.0.decrypt_block(&mut typed);
            slot.copy_from_slice(&typed);
            for (byte, prev) in slot.iter_mut().zip(mask) {
                *byte ^= prev;
            }
        }
    }
}

/// The padding a CBC record's last byte names, folded to none of it when any byte disagrees.
/// The walk covers a public count — the record's own length — so the secret padding picks no branch.
fn padding(content: &[u8], mac_len: usize) -> usize {
    let pad = usize::from(*content.last().expect("a record at least one block long"));
    let mut fold = 0u8;
    for index in 0..256.min(content.len()) {
        let mask = 0u8.wrapping_sub((index <= pad) as u8);
        fold |= (content[content.len() - 1 - index] & mask) ^ ((pad as u8) & mask);
    }
    let mask = 0u8.wrapping_sub((content.len() - mac_len < pad + 1) as u8);
    let wrong = fold | mask;
    let ok = ((wrong | wrong.wrapping_neg()) >> 7) ^ 1;
    (pad & usize::from(ok).wrapping_neg()) + 1
}

fn keyed(suite: Suite, key: &[u8]) -> LessSafeKey {
    let algorithm = match suite {
        Suite::Aes128GcmSha256 | Suite::EcdheAes128GcmSha256 | Suite::RsaAes128GcmSha256 => {
            &ring::aead::AES_128_GCM
        }
        Suite::Aes256GcmSha384 | Suite::EcdheAes256GcmSha384 | Suite::RsaAes256GcmSha384 => {
            &ring::aead::AES_256_GCM
        }
        Suite::ChaCha20Sha256 | Suite::EcdheChaCha20Sha256 => &ring::aead::CHACHA20_POLY1305,
        suite => unreachable!("{suite:?} keys no AEAD"),
    };
    let unbound = UnboundKey::new(algorithm, key).expect("the key block names its own length");
    LessSafeKey::new(unbound)
}

/// The AEAD framing of a direction: TLS 1.3 has no MAC-then-encrypt suite, so one here is a bug, not a wire case.
fn aead(keys: &mut Direction) -> &mut Aead {
    match keys {
        Direction::Aead(keys) => keys,
        Direction::Cbc(_) | Direction::Tdes(_) | Direction::Rc4(_) => {
            unreachable!("TLS 1.3 frames no MAC-then-encrypt record")
        }
    }
}

/// Frames and seals one TLS 1.3 record whose plaintext is `plain` with `kind` as its inner type.
pub(crate) fn seal13(
    keys: &mut Direction,
    kind: u8,
    plain: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), TlsError> {
    seal13_parts(keys, kind, &[plain], out)
}

/// The same record with the plaintext handed as segments, so a framed write never stages a copy.
pub(crate) fn seal13_parts(
    keys: &mut Direction,
    kind: u8,
    parts: &[&[u8]],
    out: &mut Vec<u8>,
) -> Result<(), TlsError> {
    let keys = aead(keys);
    let len: usize = parts.iter().map(|part| part.len()).sum();
    let at = out.len();
    let total = (len + 1 + 16) as u16;
    out.reserve(5 + len + 1 + 16);
    out.extend_from_slice(&[23, 0x03, 0x03, (total >> 8) as u8, total as u8]);
    for part in parts {
        out.extend_from_slice(part);
    }
    out.push(kind);
    let aad = [out[at], out[at + 1], out[at + 2], out[at + 3], out[at + 4]];
    keys.seal(&aad, at + 5, out)
}

/// Decrypts in place and returns the inner type and the plaintext length at the front of `body`.
pub(crate) fn open13(
    keys: &mut Direction,
    header: [u8; 5],
    body: &mut [u8],
) -> Result<(u8, usize), TlsError> {
    let keys = aead(keys);
    let at = {
        let plain = keys.open(&header, body)?;
        plain
            .iter()
            .rposition(|&byte| byte != 0)
            .ok_or_else(|| TlsError::Other("record has no inner type".to_owned()))?
    };
    Ok((body[at], at))
}

/// The same open into a caller's buffer: the body lands at the front of `out` and the
/// plaintext stays there, so a relay never stages the ciphertext and copies it again.
pub(crate) fn open13_into(
    keys: &mut Direction,
    header: [u8; 5],
    body: &[u8],
    out: &mut [u8],
) -> Result<(u8, usize), TlsError> {
    let keys = aead(keys);
    out[..body.len()].copy_from_slice(body);
    let at = {
        let plain = keys.open(&header, &mut out[..body.len()])?;
        plain
            .iter()
            .rposition(|&byte| byte != 0)
            .ok_or_else(|| TlsError::Other("record has no inner type".to_owned()))?
    };
    Ok((out[at], at))
}

/// Seals one TLS 1.2 record of `kind`.
pub(crate) fn seal12(
    keys: &mut Direction,
    kind: u8,
    plain: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), TlsError> {
    seal12_parts(keys, kind, &[plain], out)
}

pub(crate) fn seal12_parts(
    keys: &mut Direction,
    kind: u8,
    parts: &[&[u8]],
    out: &mut Vec<u8>,
) -> Result<(), TlsError> {
    match keys {
        Direction::Aead(keys) => keys.seal12_parts(kind, parts, out),
        Direction::Cbc(keys) => keys.seal(kind, parts, out),
        Direction::Tdes(keys) => keys.seal(kind, parts, out),
        Direction::Rc4(keys) => {
            keys.seal(kind, parts, out);
            Ok(())
        }
    }
}

/// Opens one TLS 1.2 record body in place and returns the plaintext's offset and length: a GCM
/// record leaves its explicit nonce in front and a CBC record its IV and MAC, and in neither
/// case does the plaintext move over them.
pub(crate) fn open12(
    keys: &mut Direction,
    kind: u8,
    body: &mut [u8],
) -> Result<(usize, usize), TlsError> {
    match keys {
        Direction::Aead(keys) => keys.open12(kind, body),
        Direction::Cbc(keys) => keys.open(kind, body),
        Direction::Tdes(keys) => keys.open(kind, body),
        Direction::Rc4(keys) => keys.open(kind, body),
    }
}

/// The TLS 1.2 body opened to the front of `out`, over the explicit nonce or IV that the wire
/// carries ahead of it: a relay gets the plaintext without staging the ciphertext a second time.
pub(crate) fn open12_into(
    keys: &mut Direction,
    kind: u8,
    body: &[u8],
    out: &mut [u8],
) -> Result<usize, TlsError> {
    match keys {
        Direction::Aead(keys) => keys.open12_into(kind, body, out),
        Direction::Cbc(keys) => keys.open_into(kind, body, out),
        Direction::Tdes(keys) => keys.open_into(kind, body, out),
        Direction::Rc4(keys) => keys.open_into(kind, body, out),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(miri, ignore = "reaches ring's CPUID FFI through the record KDF")]
    #[test]
    fn a_tls12_gcm_record_opens_behind_its_explicit_nonce() {
        let suite = Suite::EcdheAes128GcmSha256;
        let (key, iv) = ([7u8; 16], [9u8; 4]);
        let mut sender = Direction::tls12(suite, &key, &[], &iv);
        let mut receiver = Direction::tls12(suite, &key, &[], &iv);
        let mut wire = Vec::new();
        seal12(&mut sender, 23, b"ping", &mut wire).expect("seals");
        let (header, body) = wire.split_at_mut(5);
        assert_eq!(&body[..8], &[0u8; 8], "the explicit nonce leads the body");
        let (start, len) = open12(&mut receiver, header[0], body).expect("opens");
        assert_eq!(
            (start, len),
            (8, 4),
            "the plaintext stays where the nonce left it"
        );
        assert_eq!(&body[..8], &[0u8; 8], "the nonce is not written over");
        assert_eq!(&body[start..start + len], b"ping");
    }

    #[cfg_attr(miri, ignore = "reaches ring's CPUID FFI through the record KDF")]
    #[test]
    fn a_tls12_cbc_record_pads_to_the_rfc_length_and_open_back() {
        let suite = Suite::EcdheAes128CbcSha;
        let (key, mac_key, iv) = ([7u8; 16], [8u8; 20], [0u8; BLOCK]);
        let mut sender = Direction::tls12(suite, &key, &mac_key, &iv);
        let mut receiver = Direction::tls12(suite, &key, &mac_key, &iv);
        let mut wire = Vec::new();
        seal12(&mut sender, 23, b"ping", &mut wire).expect("seals");
        // IV, payload and MAC need eight pad bytes to reach whole blocks, so the body is 48.
        assert_eq!(
            wire.len(),
            5 + BLOCK + 24 + 8,
            "the record is the length the reference gives it"
        );
        assert_eq!(
            u16::from_be_bytes([wire[3], wire[4]]) as usize,
            BLOCK + 24 + 8,
            "and its header names that"
        );
        let (header, body) = wire.split_at_mut(5);
        let (start, len) = open12(&mut receiver, header[0], body).expect("opens");
        assert_eq!((start, len), (BLOCK, 4), "the IV leads the plaintext");
        assert_eq!(&body[start..start + len], b"ping");

        let mut forged = wire.clone();
        let kind = forged[0];
        *forged.last_mut().expect("a whole block") ^= 0xff;
        let (_, body) = forged.split_at_mut(5);
        let mut once = Direction::tls12(suite, &key, &mac_key, &iv);
        assert!(
            open12(&mut once, kind, body).is_err(),
            "a forged padding length fails the MAC, not a branch on the secret"
        );
    }

    #[cfg_attr(miri, ignore = "reaches ring's CPUID FFI through the record KDF")]
    #[test]
    fn a_tls12_cbc_record_past_one_batch_opens_the_same_both_ways() {
        let suite = Suite::EcdheAes256CbcSha;
        let (key, mac_key, iv) = ([7u8; 32], [8u8; 20], [0u8; BLOCK]);
        let plain = [0x5au8; 200];
        let mut sender = Direction::tls12(suite, &key, &mac_key, &iv);
        let mut wire = Vec::new();
        seal12(&mut sender, 23, &plain, &mut wire).expect("seals");
        // Fourteen blocks: one full batch and a tail, so every mask comes from a block this call has not written.
        assert_eq!(
            wire.len(),
            5 + BLOCK + 14 * BLOCK,
            "the record is that wide"
        );
        let (header, body) = wire.split_at(5);
        let mut window = [0u8; 512];
        let mut direct = Direction::tls12(suite, &key, &mac_key, &iv);
        let got = open12_into(&mut direct, header[0], body, &mut window).expect("opens the window");
        let mut staged = wire.clone();
        let (header, body) = staged.split_at_mut(5);
        let mut inplace = Direction::tls12(suite, &key, &mac_key, &iv);
        let (start, same) = open12(&mut inplace, header[0], body).expect("opens in place");
        assert_eq!((got, same), (plain.len(), plain.len()));
        assert_eq!(&window[..got], &plain[..]);
        assert_eq!(&body[start..start + same], &plain[..]);
    }

    #[cfg_attr(miri, ignore = "reaches ring's CPUID FFI through the record KDF")]
    #[test]
    fn a_tls12_3des_record_pads_to_its_own_block_and_open_back() {
        let suite = Suite::Ecdhe3DesCbcSha;
        let (key, mac_key, iv) = ([7u8; 24], [8u8; 20], [0u8; DES_BLOCK]);
        let plain = [0x5au8; 12];
        let mut sender = Direction::tls12(suite, &key, &mac_key, &iv);
        let mut wire = Vec::new();
        seal12(&mut sender, 23, &plain, &mut wire).expect("seals");
        // Twelve payload plus twenty MAC are four blocks at this width, so a whole pad follows and the body is 40 where AES's width makes it 48.
        assert_eq!(
            wire.len(),
            5 + DES_BLOCK + 40,
            "the record pads and carries an IV at the width this suite's block has"
        );
        assert_eq!(
            u16::from_be_bytes([wire[3], wire[4]]) as usize,
            DES_BLOCK + 40,
            "and its header names that"
        );

        let (header, body) = wire.split_at(5);
        let mut window = [0u8; 64];
        let mut direct = Direction::tls12(suite, &key, &mac_key, &iv);
        let got = open12_into(&mut direct, header[0], body, &mut window).expect("opens the window");
        let mut staged = wire.clone();
        let (header, body) = staged.split_at_mut(5);
        let mut inplace = Direction::tls12(suite, &key, &mac_key, &iv);
        let (start, same) = open12(&mut inplace, header[0], body).expect("opens in place");
        assert_eq!(
            (got, same),
            (plain.len(), plain.len()),
            "both walks read it"
        );
        assert_eq!(&window[..got], &plain[..]);
        assert_eq!(&body[start..start + same], &plain[..]);
        assert_eq!(start, DES_BLOCK, "the plaintext starts behind the IV");

        let mut forged = wire.clone();
        let kind = forged[0];
        *forged.last_mut().expect("a whole block") ^= 0xff;
        let (_, body) = forged.split_at_mut(5);
        let mut once = Direction::tls12(suite, &key, &mac_key, &iv);
        assert!(
            open12(&mut once, kind, body).is_err(),
            "a forged padding length fails the MAC, not a branch on the secret"
        );
    }

    #[cfg_attr(miri, ignore = "reaches ring's CPUID FFI through the record KDF")]
    #[test]
    fn a_tls12_rc4_record_carries_its_mac_and_no_iv() {
        let suite = Suite::EcdheRc4Sha;
        let (key, mac_key) = ([7u8; 16], [8u8; 20]);
        let plain = [0x5au8; 12];
        let mut sender = Direction::tls12(suite, &key, &mac_key, &[]);
        let mut wire = Vec::new();
        seal12(&mut sender, 23, &plain, &mut wire).expect("seals");
        // The body is the payload with its MAC behind it and nothing else: no IV in front, no padding.
        assert_eq!(
            wire.len(),
            5 + plain.len() + 20,
            "the record is the payload plus the MAC"
        );
        assert_eq!(
            u16::from_be_bytes([wire[3], wire[4]]) as usize,
            plain.len() + 20,
            "and its header names that"
        );

        let mut mirror = Direction::tls12(suite, &key, &mac_key, &[]);
        let mut again = Vec::new();
        seal12(&mut mirror, 23, &plain, &mut again).expect("seals");
        assert_eq!(
            wire, again,
            "at the same stream position the record is fixed"
        );
        let mut next = Vec::new();
        seal12(&mut sender, 23, &plain, &mut next).expect("seals a second record");
        assert_ne!(
            wire[5..],
            next[5..],
            "the stream never restarts, so the same payload one record later is other bytes"
        );

        let (header, body) = wire.split_at(5);
        let mut window = [0u8; 64];
        let mut direct = Direction::tls12(suite, &key, &mac_key, &[]);
        let got = open12_into(&mut direct, header[0], body, &mut window).expect("opens the window");
        let mut staged = wire.clone();
        let (header, body) = staged.split_at_mut(5);
        let mut inplace = Direction::tls12(suite, &key, &mac_key, &[]);
        let (start, same) = open12(&mut inplace, header[0], body).expect("opens in place");
        assert_eq!(
            (got, same),
            (plain.len(), plain.len()),
            "both walks read it"
        );
        assert_eq!(
            start, 0,
            "the plaintext is at the front, where the keystream ran"
        );
        assert_eq!(&window[..got], &plain[..]);
        assert_eq!(&body[start..start + same], &plain[..]);

        let mut counted = Vec::with_capacity(64);
        let mut writer = Direction::tls12(suite, &key, &mac_key, &[]);
        let ((), counts) = crate::alloc_count::measure(|| {
            seal12(&mut writer, 23, &plain, &mut counted).expect("seals");
        });
        assert_eq!(&counted, &wire, "the counted seal writes the gated record");
        assert_eq!(
            counts.allocs, 0,
            "a stream record takes no heap: {counts:?}"
        );

        let mut forged = wire.clone();
        let kind = forged[0];
        *forged.last_mut().expect("a MAC byte") ^= 0xff;
        let (_, body) = forged.split_at_mut(5);
        let mut once = Direction::tls12(suite, &key, &mac_key, &[]);
        assert!(
            open12(&mut once, kind, body).is_err(),
            "the tail is the MAC, so a flip there fails it"
        );
    }

    #[test]
    fn a_chacha_secret_exports_and_rekeys_as_chacha() {
        let secret = [3u8; 32];
        let mut direction = Direction::tls13(Suite::ChaCha20Sha256, &secret);
        let (cipher, ..) = direction.ktls_material().expect("a TLS 1.3 secret");
        assert_eq!(cipher, crate::tls::ktls::Cipher::ChaCha20Poly1305);
        direction.update();
        let (cipher, ..) = direction.ktls_material().expect("the next TLS 1.3 secret");
        assert_eq!(cipher, crate::tls::ktls::Cipher::ChaCha20Poly1305);
    }
}

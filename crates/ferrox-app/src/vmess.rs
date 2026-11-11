use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, UdpSocket};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::conn::Connection;
use crate::proxy::lane_pool::Next;
use crate::proxy::{read_exact, under_handshake};

const AUTH_LEN: usize = 16;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 2;
const MAX_PLAIN: usize = 8192;
const FRAMES_PER_WRITE: usize = 16;
const READ_PLAIN: usize = MAX_PLAIN * FRAMES_PER_WRITE;
// The widest frame we seal: a full payload, its tag, and the padding the mask draw allows.
const MAX_WIRE: usize = MAX_PLAIN + TAG_LEN + 63;
// Two batches per refill: the batch is still one write, but a carrier read can answer two.
const WIRE_BATCHES: usize = 2;
const WIRE_LEN: usize = (FRAMES_PER_WRITE * WIRE_BATCHES + 1) * (MAX_WIRE + SIZE_FIELD);
const OPT_STREAM: u8 = 0x01;
const OPT_MASK: u8 = 0x04;
const OPT_PAD: u8 = 0x08;
const OPT_AUTH_LEN: u8 = 0x10;

/// The grace after a peer half-close, long enough for a target that answers late.
const REPLY_IDLE: Duration = Duration::from_secs(30);

/// A sealed size field: the two plain octets and their tag, what `AEADChunkSizeParser`
/// reads when the request asks for an authenticated length.
const SIZE_FIELD: usize = HEADER_LEN + TAG_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cipher {
    Auto,
    Aes,
    Chacha,
    None,
}

impl Cipher {
    pub(crate) fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Self::Aes,
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => Self::Chacha,
            "none" => Self::None,
            _ => Self::Auto,
        }
    }
    fn code(self) -> u8 {
        match self.resolve() {
            Self::Aes => 3,
            Self::None => 5,
            // A machine with no hardware AES has already become ChaCha here.
            Self::Auto | Self::Chacha => 4,
        }
    }
    /// Resolve the "auto" negotiation the way the reference does: AES-128-GCM where the machine has hardware for it, ChaCha20-Poly1305 where it does not; a concrete cipher is its own answer so this is idempotent, and the header byte and the payload flows both go through it and cannot diverge.
    fn resolve(self) -> Self {
        match self {
            Self::Auto if ferrox_core::aesgcm::has_hardware_support() => Self::Aes,
            Self::Auto => Self::Chacha,
            other => other,
        }
    }
    fn from_code(value: u8) -> Option<Self> {
        match value {
            3 => Some(Self::Aes),
            4 => Some(Self::Chacha),
            5 => Some(Self::None),
            _ => None,
        }
    }
}

/// An auth id is valid 120 s either side of the clock, so the window that refuses its replay has to outlast both halves of that span.
const REPLAY_SPAN: u64 = 240;

fn replay_seen(id: &[u8; AUTH_LEN]) -> bool {
    static WINDOW: OnceLock<Mutex<crate::proxy::Replay>> = OnceLock::new();
    let mut key = [0u8; 32];
    key[..AUTH_LEN].copy_from_slice(id);
    let mut guard = WINDOW
        .get_or_init(|| Mutex::new(crate::proxy::Replay::new(REPLAY_SPAN)))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.seen(&key, now_secs())
}

/// How long xray's session history remembers a session id, and how often it sweeps the expired.
const SESSION_LIFETIME: u64 = 180;
const SESSION_SWEEP: u64 = 30;

/// Sessions one sweep can be holding at once: the flood bound the sweep interval alone leaves open.
const SESSION_KEYS: usize = 64 * 1024;

/// Whether the session this header opens was already admitted: the user, the request body key
/// and the request body IV, the reference's session id, refused while it is still live. The
/// history is partitioned by user, so one account cannot spend the admission another needs.
fn session_seen(user: &[u8; 16], key: &[u8; 16], iv: &[u8; 16]) -> bool {
    static HISTORY: OnceLock<Mutex<SessionHistory>> = OnceLock::new();
    let mut session = [0u8; 32];
    session[..16].copy_from_slice(key);
    session[16..].copy_from_slice(iv);
    let mut guard = HISTORY
        .get_or_init(|| Mutex::new(SessionHistory::new(now_secs())))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.seen(user, &session, now_secs())
}

struct SessionHistory {
    by_account: std::collections::HashMap<[u8; 16], std::collections::HashMap<[u8; 32], u64>>,
    swept: u64,
}

impl SessionHistory {
    fn new(now: u64) -> Self {
        Self {
            by_account: std::collections::HashMap::new(),
            swept: now,
        }
    }

    /// Whether this account's session was admitted before inside the lifetime; the clock is the
    /// caller's, so the bounds are testable without waiting on it.
    fn seen(&mut self, user: &[u8; 16], session: &[u8; 32], now: u64) -> bool {
        if now.wrapping_sub(self.swept) >= SESSION_SWEEP {
            self.by_account.retain(|_, live| {
                live.retain(|_, expires| *expires > now);
                live.shrink_to_fit();
                !live.is_empty()
            });
            self.swept = now;
        }
        let live = self.by_account.entry(*user).or_default();
        if live.get(session).is_some_and(|expires| *expires > now) {
            return true;
        }
        // A flood cannot grow one account past the cap, so a full one refuses a new session.
        if !live.contains_key(session) && live.len() >= SESSION_KEYS {
            return true;
        }
        live.insert(*session, now + SESSION_LIFETIME);
        false
    }
}

fn hmac_pads(key: &[u8]) -> ([u8; 64], [u8; 64]) {
    use sha2::Digest as _;
    let mut flat = [0u8; 64];
    if key.len() > 64 {
        flat[..32].copy_from_slice(&sha2::Sha256::digest(key));
    } else {
        flat[..key.len()].copy_from_slice(key);
    }
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for i in 0..64 {
        inner[i] ^= flat[i];
        outer[i] ^= flat[i];
    }
    (inner, outer)
}

struct Hmac {
    inner: sha2::Sha256,
    outer: sha2::Sha256,
    fresh_inner: sha2::Sha256,
    fresh_outer: sha2::Sha256,
}

impl Hmac {
    fn fresh(key: &[u8]) -> Self {
        use sha2::Digest as _;
        let (ipad, opad) = hmac_pads(key);
        let mut inner = sha2::Sha256::new();
        let mut outer = sha2::Sha256::new();
        inner.update(ipad);
        outer.update(opad);
        Self {
            fresh_inner: inner.clone(),
            fresh_outer: outer.clone(),
            inner,
            outer,
        }
    }
    fn push(&mut self, data: &[u8]) {
        use sha2::Digest as _;
        self.inner.update(data);
    }
    fn restart(&mut self) {
        self.inner = self.fresh_inner.clone();
        self.outer = self.fresh_outer.clone();
    }
    fn digest(&mut self) -> [u8; 32] {
        use sha2::Digest as _;
        let mid = self.inner.clone().finalize();
        let mut outer = self.outer.clone();
        outer.update(mid);
        outer.finalize().into()
    }
}

fn kdf_digest(root: &mut Hmac, path: &[&[u8]], level: usize) -> [u8; 32] {
    if level == 0 {
        return root.digest();
    }
    let mid = kdf_digest(root, path, level - 1);
    root.restart();
    for layer in &path[..level - 1] {
        root.push(&hmac_pads(layer).0);
    }
    root.push(&hmac_pads(path[level - 1]).1);
    root.push(&mid);
    kdf_digest(root, path, level - 1)
}

fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut root = Hmac::fresh(b"VMess AEAD KDF");
    for layer in path {
        root.push(&hmac_pads(layer).0);
    }
    root.push(key);
    kdf_digest(&mut root, path, path.len())
}

fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    kdf(key, path)[..16].try_into().unwrap()
}

fn md5_two(first: &[u8], second: &[u8]) -> [u8; 16] {
    let mut input = [0u8; 52];
    let head = first.len().min(input.len());
    let tail = second.len().min(input.len() - head);
    input[..head].copy_from_slice(&first[..head]);
    input[head..head + tail].copy_from_slice(&second[..tail]);
    md5::compute(&input[..head + tail]).0
}

fn instruction_key(uuid: &[u8; 16]) -> [u8; 16] {
    md5_two(uuid, b"c48619fe-8f02-49e0-b9e9-edf763e17e21")
}

fn chacha_key(key: &[u8; 16]) -> [u8; 32] {
    let first = md5::compute(key).0;
    let second = md5::compute(first).0;
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&first);
    out[16..].copy_from_slice(&second);
    out
}

// Linear over GF(2): eight bytes decompose into eight table-folded contributions.
const fn crc_tables() -> [[u32; 256]; 8] {
    let mut tables = [[0u32; 256]; 8];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
            bit += 1;
        }
        tables[0][i] = crc;
        i += 1;
    }
    let mut k = 1usize;
    while k < 8 {
        let mut i = 0usize;
        while i < 256 {
            let crc = tables[k - 1][i];
            tables[k][i] = tables[0][(crc & 0xff) as usize] ^ (crc >> 8);
            i += 1;
        }
        k += 1;
    }
    tables
}

const CRC_TABLES: [[u32; 256]; 8] = crc_tables();

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    let (groups, rest) = data.as_chunks::<8>();
    for chunk in groups {
        let low = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) ^ crc;
        let high = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
        crc = CRC_TABLES[7][(low & 0xff) as usize]
            ^ CRC_TABLES[6][((low >> 8) & 0xff) as usize]
            ^ CRC_TABLES[5][((low >> 16) & 0xff) as usize]
            ^ CRC_TABLES[4][(low >> 24) as usize]
            ^ CRC_TABLES[3][(high & 0xff) as usize]
            ^ CRC_TABLES[2][((high >> 8) & 0xff) as usize]
            ^ CRC_TABLES[1][((high >> 16) & 0xff) as usize]
            ^ CRC_TABLES[0][(high >> 24) as usize];
    }
    for &byte in rest {
        crc = (crc >> 8) ^ CRC_TABLES[0][((crc ^ u32::from(byte)) & 0xff) as usize];
    }
    !crc
}

fn fnv1a(data: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for &byte in data {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}

fn random_into(buf: &mut [u8]) -> bool {
    getrandom::fill(buf).is_ok()
}

pub(crate) struct PadSource {
    buf: [u8; 2048],
    at: usize,
}

impl PadSource {
    pub(crate) fn fresh() -> Option<Self> {
        let mut buf = [0u8; 2048];
        if !random_into(&mut buf) {
            return None;
        }
        Some(Self { buf, at: 0 })
    }

    fn take(&mut self, n: usize) -> Option<&[u8]> {
        debug_assert!(n <= 64, "padding is at most 63 bytes");
        if self.at + n > self.buf.len() {
            if !random_into(&mut self.buf) {
                return None;
            }
            self.at = 0;
        }
        let bytes = &self.buf[self.at..self.at + n];
        self.at += n;
        Some(bytes)
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[derive(Clone)]
struct AuthKey(aes::Aes128);

impl std::fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthKey").finish_non_exhaustive()
    }
}

impl AuthKey {
    fn new(instruction: &[u8; 16]) -> Self {
        use aes::cipher::KeyInit as _;
        let bytes = kdf16(instruction, &[b"AES Auth ID Encryption"]);
        Self(aes::Aes128::new_from_slice(&bytes).expect("sixteen bytes is a key"))
    }

    fn seal(&self, block: &mut [u8; 16]) {
        use aes::cipher::BlockCipherEncrypt as _;
        self.0.encrypt_block(block.into());
    }

    fn open(&self, block: &mut [u8; 16]) {
        use aes::cipher::BlockCipherDecrypt as _;
        self.0.decrypt_block(block.into());
    }
}

type CachedUserKeys = ([u8; 16], AuthKey);

type UserKeyCache = std::collections::HashMap<[u8; 16], CachedUserKeys>;

fn cached_keys(uuid: &[u8; 16]) -> CachedUserKeys {
    static CACHE: OnceLock<Mutex<UserKeyCache>> = OnceLock::new();
    let mut guard = CACHE
        .get_or_init(|| Mutex::new(UserKeyCache::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(found) = guard.get(uuid) {
        return found.clone();
    }
    let instruction = instruction_key(uuid);
    let key = AuthKey::new(&instruction);
    let entry = (instruction, key);
    if guard.len() >= 64 {
        guard.clear();
    }
    guard.insert(*uuid, entry.clone());
    entry
}

fn seal_header(key: &[u8; 16], nonce: &[u8; 12], plain: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    use aes_gcm::aead::AeadInOut as _;
    use aes_gcm::KeyInit as _;
    let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).ok()?;
    let mut body = plain.to_vec();
    let tag = cipher
        .encrypt_inout_detached(
            &aes_gcm::Nonce::try_from(&nonce[..]).expect("length"),
            aad,
            (&mut body[..]).into(),
        )
        .ok()?;
    body.extend_from_slice(&tag);
    Some(body)
}

fn open_header_into<'a>(
    key: &[u8; 16],
    nonce: &[u8; 12],
    sealed: &[u8],
    aad: &[u8],
    out: &'a mut [u8],
) -> Option<&'a [u8]> {
    use aes_gcm::aead::AeadInOut as _;
    use aes_gcm::KeyInit as _;
    let split = sealed.len().checked_sub(TAG_LEN)?;
    let body = out.get_mut(..split)?;
    body.copy_from_slice(&sealed[..split]);
    let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).ok()?;
    cipher
        .decrypt_inout_detached(
            &aes_gcm::Nonce::try_from(&nonce[..]).expect("length"),
            aad,
            (&mut body[..]).into(),
            &aes_gcm::Tag::try_from(&sealed[split..]).expect("length"),
        )
        .ok()?;
    Some(body)
}

fn open_header(key: &[u8; 16], nonce: &[u8; 12], sealed: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    let mut body = vec![0u8; sealed.len().checked_sub(TAG_LEN)?];
    open_header_into(key, nonce, sealed, aad, &mut body)?;
    Some(body)
}

fn response_material(data_iv: &[u8; 16], data_key: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    use sha2::Digest as _;
    let iv: [u8; 16] = sha2::Sha256::digest(data_iv)[..16].try_into().unwrap();
    let key: [u8; 16] = sha2::Sha256::digest(data_key)[..16].try_into().unwrap();
    (key, iv)
}

fn response_prefix(response_key: &[u8; 16], response_iv: &[u8; 16], auth: u8) -> Option<Vec<u8>> {
    let len_key = kdf16(response_key, &[b"AEAD Resp Header Len Key"]);
    let len_full = kdf(response_iv, &[b"AEAD Resp Header Len IV"]);
    let len_nonce: [u8; 12] = len_full[..12].try_into().unwrap();
    let mut out = seal_header(&len_key, &len_nonce, &[0, 4], &[])?;
    let body_key = kdf16(response_key, &[b"AEAD Resp Header Key"]);
    let body_full = kdf(response_iv, &[b"AEAD Resp Header IV"]);
    let body_nonce: [u8; 12] = body_full[..12].try_into().unwrap();
    out.extend_from_slice(&seal_header(&body_key, &body_nonce, &[auth, 0, 0, 0], &[])?);
    Some(out)
}

fn make_auth_id(key: &AuthKey) -> Option<[u8; 16]> {
    let mut plain = [0u8; 16];
    plain[..8].copy_from_slice(&now_secs().to_be_bytes());
    if !random_into(&mut plain[8..12]) {
        return None;
    }
    let checksum = crc32(&plain[..12]).to_be_bytes();
    plain[12..].copy_from_slice(&checksum);
    key.seal(&mut plain);
    Some(plain)
}

fn valid_auth_id(key: &AuthKey, auth_id: &[u8; 16]) -> bool {
    let mut plain = *auth_id;
    key.open(&mut plain);
    if crc32(&plain[..12]) != u32::from_be_bytes(plain[12..].try_into().unwrap()) {
        return false;
    }
    u64::from_be_bytes(plain[..8].try_into().unwrap()).abs_diff(now_secs()) <= 120
}

struct Shake {
    reader: shake::Shake128Reader,
    padding: bool,
    masked: bool,
    bytes: [u8; 64],
    at: usize,
}

impl Shake {
    fn fresh(iv: &[u8; 16], padding: bool, masked: bool) -> Self {
        use sha3::digest::{ExtendableOutput as _, Update as _};
        let mut shake = shake::Shake128::default();
        shake.update(iv);
        Self {
            reader: shake.finalize_xof(),
            padding,
            masked,
            bytes: [0u8; 64],
            at: 64,
        }
    }
    fn refill(&mut self) {
        sha3::digest::XofReader::read(&mut self.reader, &mut self.bytes);
        self.at = 0;
    }
    fn draw(&mut self) -> u16 {
        if self.at + 2 > self.bytes.len() {
            self.refill();
        }
        let bytes = [self.bytes[self.at], self.bytes[self.at + 1]];
        self.at += 2;
        u16::from_be_bytes(bytes)
    }
    fn pad_len(&mut self) -> u16 {
        if self.padding {
            self.draw() % 64
        } else {
            0
        }
    }
    fn pad_and_mask(&mut self, wire: u16) -> (usize, u16) {
        if self.padding {
            if self.at + 4 > self.bytes.len() {
                self.refill();
            }
            let bytes = &self.bytes[self.at..self.at + 4];
            let pad = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]) % 64);
            let mask = u16::from_be_bytes([bytes[2], bytes[3]]);
            self.at += 4;
            (pad, mask ^ wire)
        } else {
            (0, self.draw() ^ wire)
        }
    }
    fn pad_only(&mut self, wire: u16) -> (usize, u16) {
        (usize::from(self.draw() % 64), wire)
    }
    fn draws(&mut self) -> (u16, u16) {
        if self.padding {
            if self.at + 4 > self.bytes.len() {
                self.refill();
            }
            let bytes = &self.bytes[self.at..self.at + 4];
            let draws = (
                u16::from_be_bytes([bytes[0], bytes[1]]),
                u16::from_be_bytes([bytes[2], bytes[3]]),
            );
            self.at += 4;
            draws
        } else {
            (0, self.draw())
        }
    }
}

enum Aead {
    Aes(ferrox_core::aesgcm::Aes128Gcm),
    Chacha([u8; 32]),
    Plain,
}

/// The sealed size field's parser, where the mask draw would be: its key is
/// `KDF16(body_key, "auth_len")` (the same second AEAD per cipher the reference builds,
/// `proxy/vmess/encoding/server.go`), its nonce the body's shape with a counter of its own.
struct SizeAead {
    aead: Aead,
    nonce: [u8; 12],
    counter: u16,
}

impl SizeAead {
    fn fresh(key: &[u8; 16], cipher: Cipher, iv: &[u8; 16]) -> Option<Self> {
        let len_key = kdf16(key, &[b"auth_len"]);
        let aead = match cipher {
            Cipher::Aes => Aead::Aes(ferrox_core::aesgcm::Aes128Gcm::new(&len_key)),
            Cipher::Chacha => Aead::Chacha(chacha_key(&len_key)),
            // No cipher the reference seals a length with, so no authenticated length.
            _ => return None,
        };
        let mut nonce = [0u8; 12];
        nonce[2..].copy_from_slice(&iv[2..12]);
        Some(Self {
            aead,
            nonce,
            counter: 0,
        })
    }
    /// The wire's 18 bytes open to the frame's total: the two plain octets are sealed here (`AEADChunkSizeParser::Decode`) and the overhead is added back.
    fn unseal_len(&mut self, sealed: &mut [u8; SIZE_FIELD]) -> Option<u16> {
        let (size, tag) = sealed.split_at_mut(HEADER_LEN);
        let tag: [u8; TAG_LEN] = <[u8; TAG_LEN]>::try_from(tag).ok()?;
        self.nonce[..2].copy_from_slice(&self.counter.to_be_bytes());
        let nonce = &self.nonce;
        let plain = match &self.aead {
            Aead::Aes(aes) => {
                aes.open_in_place(nonce, b"", size, &tag)?;
                size
            }
            Aead::Chacha(key) => {
                ferrox_core::aead::chacha20_poly1305_decrypt_in_place(key, nonce, b"", size, &tag)?;
                size
            }
            Aead::Plain => return None,
        };
        self.counter = self.counter.wrapping_add(1);
        Some(u16::from_be_bytes([plain[0], plain[1]]).wrapping_add(TAG_LEN as u16))
    }
    /// The wire's 18 bytes seal the frame's body total less the tag, the shape the reference's encoder writes (`AEADChunkSizeParser::Encode`) and its nonce steps beside the body's.
    fn seal_len(&mut self, total: u16, sealed: &mut [u8; SIZE_FIELD]) {
        let mut plain = total.wrapping_sub(TAG_LEN as u16).to_be_bytes();
        self.nonce[..2].copy_from_slice(&self.counter.to_be_bytes());
        let nonce = &self.nonce;
        let tag = match &self.aead {
            Aead::Aes(aes) => aes.seal_in_place(nonce, b"", &mut plain),
            Aead::Chacha(key) => {
                ferrox_core::aead::chacha20_poly1305_seal_in_place(key, nonce, b"", &mut plain)
            }
            Aead::Plain => return,
        };
        sealed[..HEADER_LEN].copy_from_slice(&plain);
        sealed[HEADER_LEN..].copy_from_slice(&tag);
        self.counter = self.counter.wrapping_add(1);
    }
}

pub(crate) struct Flow {
    cipher: Cipher,
    aead: Aead,
    nonce: [u8; 12],
    counter: u16,
    shake: Option<Shake>,
    /// The sealed size field when the request asks for an authenticated length: the
    /// size parser leaves the mask draw for an AEAD of its own (`proxy/vmess/encoding/server.go`),
    /// its key derived `KDF16(key, "auth_len")` and its nonce counting beside the body's.
    len_seal: Option<SizeAead>,
    /// Whether this direction closes with the zero-length marker. The reference's
    /// `NoTerminationSignal` account turns it off for that side (`proxy/vmess/{inbound,outbound}`).
    end_marker: bool,
}

impl Flow {
    /// The size field's plain octets, unsealed where the parser's own AEAD would put them.
    fn unseal_len(&mut self, sealed: &mut [u8; SIZE_FIELD]) -> Option<u16> {
        self.len_seal.as_mut()?.unseal_len(sealed)
    }
    /// The next frame's padding, drawn before its length the way the reference's
    /// `NextPaddingLen` runs before the size parser (`common/crypto/auth.go:128`).
    fn pad_len(&mut self) -> usize {
        self.shake
            .as_mut()
            .map_or(0, |sizes| usize::from(sizes.pad_len()))
    }
    fn fresh(
        cipher: Cipher,
        key: &[u8; 16],
        iv: &[u8; 16],
        options: u8,
        mask_seed: &[u8; 16],
    ) -> Option<Self> {
        let masking = options & OPT_MASK != 0;
        let padding = options & OPT_PAD != 0;
        // Padding is drawn from the masking size parser, so a padded request without the mask bit has no generator the reference can build either (`proxy/vmess/encoding/server.go`).
        if padding && !masking {
            return None;
        }
        let auth_len = options & OPT_AUTH_LEN != 0;
        let actual = cipher.resolve();
        let aead = match actual {
            Cipher::Aes => Aead::Aes(ferrox_core::aesgcm::Aes128Gcm::new(key)),
            Cipher::Chacha => Aead::Chacha(chacha_key(key)),
            Cipher::None => Aead::Plain,
            Cipher::Auto => return None,
        };
        // A sealed length replaces the mask draw, never the padding draw: the reference keeps its SHAKE generator for padding after it swaps the size parser for the AEAD.
        let shake = (padding || (masking && !auth_len))
            .then(|| Shake::fresh(mask_seed, padding, masking && !auth_len));
        let mut nonce = [0u8; 12];
        nonce[2..].copy_from_slice(&iv[2..12]);
        Some(Self {
            cipher: actual,
            aead,
            nonce,
            counter: 0,
            shake,
            len_seal: None,
            end_marker: true,
        })
    }
    /// How many octets the next frame's size field takes on the wire.
    fn size_field(&self) -> usize {
        if self.len_seal.is_some() {
            SIZE_FIELD
        } else {
            HEADER_LEN
        }
    }
    #[cfg(test)]
    fn nonce(&mut self) -> &[u8; 12] {
        self.nonce[..2].copy_from_slice(&self.counter.to_be_bytes());
        &self.nonce
    }
    fn seal_onto(&mut self, plain: &[u8], out: &mut Vec<u8>) {
        self.nonce[..2].copy_from_slice(&self.counter.to_be_bytes());
        let nonce = &self.nonce;
        match &self.aead {
            Aead::Plain => out.extend_from_slice(plain),
            Aead::Aes(_) | Aead::Chacha(_) => {
                let at = out.len();
                out.reserve(plain.len() + TAG_LEN);
                // SAFETY: the reserve is at least `plain.len()` bytes; the seal writes every byte it is handed before anything reads them; the length is claimed only after the tag is appended.
                let dst = out.spare_capacity_mut();
                let d = dst.as_ptr() as usize;
                let (p, len) = (plain.as_ptr() as usize, plain.len());
                debug_assert!(
                    p + len <= d || d + len <= p,
                    "seal_from reads plaintext and writes the caller's staging; those must not overlap"
                );
                let tag = match &self.aead {
                    Aead::Aes(aes) => aes.seal_from_uninit(nonce, b"", plain, &mut dst[..len]),
                    Aead::Chacha(key) => ferrox_core::aead::chacha20_poly1305_seal_from_uninit(
                        key,
                        nonce,
                        b"",
                        plain,
                        &mut dst[..len],
                    ),
                    Aead::Plain => unreachable!("the arm above rules the plain leg out"),
                };
                unsafe { out.set_len(at + plain.len()) };
                out.extend_from_slice(&tag);
            }
        }
        // Wraps past 65535 like the reference's `GenerateChunkNonce`; see the method page.
        self.counter = self.counter.wrapping_add(1);
    }
    fn open_chunk(&mut self, chunk: &mut [u8]) -> Option<usize> {
        let plain_len = match &self.aead {
            Aead::Aes(aes) => {
                if chunk.len() < TAG_LEN {
                    return None;
                }
                self.nonce[..2].copy_from_slice(&self.counter.to_be_bytes());
                let nonce = &self.nonce;
                let split = chunk.len() - TAG_LEN;
                let (body, tag) = chunk.split_at_mut(split);
                let tag: &[u8; TAG_LEN] = <&[u8; TAG_LEN]>::try_from(&*tag).ok()?;
                aes.open_in_place(nonce, b"", body, tag)?;
                split
            }
            Aead::Chacha(key) => {
                if chunk.len() < TAG_LEN {
                    return None;
                }
                self.nonce[..2].copy_from_slice(&self.counter.to_be_bytes());
                let nonce = &self.nonce;
                let split = chunk.len() - TAG_LEN;
                let (body, tag) = chunk.split_at_mut(split);
                let tag: &[u8; TAG_LEN] = <&[u8; TAG_LEN]>::try_from(&*tag).ok()?;
                ferrox_core::aead::chacha20_poly1305_decrypt_in_place(key, nonce, b"", body, tag)?;
                split
            }
            Aead::Plain => chunk.len(),
        };
        self.counter = self.counter.wrapping_add(1);
        Some(plain_len)
    }
}

fn encode_target(out: &mut Vec<u8>, target: &crate::proxy::Destination) {
    out.extend_from_slice(&target.port().to_be_bytes());
    target.push_addr(out, 3, 2);
}

fn decode_target(header: &[u8], cursor: &mut usize) -> Option<SocketAddr> {
    let port = u16::from_be_bytes(header.get(*cursor..*cursor + 2)?.try_into().ok()?);
    let rest = &header[*cursor + 2..];
    let kind = match rest.first()? {
        1 => crate::proxy::AddrKind::V4,
        2 => crate::proxy::AddrKind::Domain,
        3 => crate::proxy::AddrKind::V6,
        _ => return None,
    };
    let (body, used) = crate::proxy::parse_addr_body(rest, kind)?;
    *cursor += 2 + used;
    Some(match body {
        crate::proxy::AddrBody::V4(ip) => SocketAddr::new(std::net::IpAddr::V4(ip.into()), port),
        crate::proxy::AddrBody::V6(ip) => SocketAddr::new(std::net::IpAddr::V6(ip.into()), port),
        crate::proxy::AddrBody::Domain(host) => crate::proxy::resolve_endpoint(host, port)?,
    })
}

type RequestParts = (Vec<u8>, [u8; 16], [u8; 16], u8);

/// The framing bits the reference's outbound sets: chunk stream, a masked size, padding, and
/// the authenticated-length experiment on top when the account asks for it
/// (`proxy/vmess/outbound/outbound.go:104-119`). The experiment has no key under `none`.
fn framing_options(cipher: Cipher, auth_len: bool) -> Option<u8> {
    if auth_len && cipher.resolve() == Cipher::None {
        return None;
    }
    Some(OPT_STREAM | OPT_MASK | OPT_PAD | if auth_len { OPT_AUTH_LEN } else { 0 })
}

fn request_bytes(
    uuid: &[u8; 16],
    cipher: Cipher,
    auth_len: bool,
    target: &crate::proxy::Destination,
    cmd: u8,
) -> Option<RequestParts> {
    let (instruction, auth_key) = cached_keys(uuid);
    let auth_id = make_auth_id(&auth_key)?;
    let mut rand = [0u8; 16 + 16 + 1 + 8 + 1];
    if !random_into(&mut rand) {
        return None;
    }
    let mut data_iv = [0u8; 16];
    let mut data_key = [0u8; 16];
    data_iv.copy_from_slice(&rand[..16]);
    data_key.copy_from_slice(&rand[16..32]);
    let auth = [rand[32]];
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&rand[33..41]);
    let pad_len = usize::from(rand[41] % 16);
    let options = framing_options(cipher, auth_len)?;
    let mut clear = Vec::with_capacity(64);
    clear.push(1);
    clear.extend_from_slice(&data_iv);
    clear.extend_from_slice(&data_key);
    clear.push(auth[0]);
    clear.push(options);
    clear.push((pad_len as u8) << 4 | cipher.code());
    clear.push(0);
    clear.push(cmd);
    encode_target(&mut clear, target);
    if pad_len > 0 {
        let mut pad = [0u8; 15];
        if !random_into(&mut pad[..pad_len]) {
            return None;
        }
        clear.extend_from_slice(&pad[..pad_len]);
    }
    clear.extend_from_slice(&fnv1a(&clear).to_be_bytes());
    let len_key = kdf16(
        &instruction,
        &[b"VMess Header AEAD Key_Length", &auth_id, &nonce],
    );
    let len_full = kdf(
        &instruction,
        &[b"VMess Header AEAD Nonce_Length", &auth_id, &nonce],
    );
    let len_nonce: [u8; 12] = len_full[..12].try_into().unwrap();
    let sealed_len = seal_header(
        &len_key,
        &len_nonce,
        &(clear.len() as u16).to_be_bytes(),
        &auth_id,
    )?;
    let head_key = kdf16(&instruction, &[b"VMess Header AEAD Key", &auth_id, &nonce]);
    let head_full = kdf(
        &instruction,
        &[b"VMess Header AEAD Nonce", &auth_id, &nonce],
    );
    let head_nonce: [u8; 12] = head_full[..12].try_into().unwrap();
    let sealed_head = seal_header(&head_key, &head_nonce, &clear, &auth_id)?;
    let mut request = Vec::with_capacity(16 + 18 + 8 + sealed_head.len());
    request.extend_from_slice(&auth_id);
    request.extend_from_slice(&sealed_len);
    request.extend_from_slice(&nonce);
    request.extend_from_slice(&sealed_head);
    Some((request, data_key, data_iv, auth[0]))
}

fn read_wire_len(stream: &mut dyn Read, recv: &mut Flow) -> Option<(usize, usize)> {
    if recv.len_seal.is_some() {
        let mut sealed = [0u8; SIZE_FIELD];
        read_exact(stream, &mut sealed).ok()?;
        let padding = recv.pad_len();
        return Some((usize::from(recv.unseal_len(&mut sealed)?), padding));
    }
    let mut prefix = [0u8; HEADER_LEN];
    read_exact(stream, &mut prefix).ok()?;
    Some(masked_len(recv, u16::from_be_bytes(prefix)))
}

/// A frame's total and padding from the length on the wire. The mask draw is once per frame,
/// so a pump that peeks a length has to be able to keep this answer.
fn masked_len(recv: &mut Flow, wire: u16) -> (usize, usize) {
    match recv.shake.as_mut() {
        None => (usize::from(wire), 0),
        Some(sizes) => {
            let (padding, total) = if sizes.masked {
                sizes.pad_and_mask(wire)
            } else {
                sizes.pad_only(wire)
            };
            (usize::from(total), padding)
        }
    }
}

/// One frame's sealed bytes in hand: drop the padding, open the rest in place, and say how
/// many plain bytes are left. Zero is the stream's end marker; `None` refuses the frame.
fn open_body(recv: &mut Flow, body: &mut [u8], padding: usize) -> Option<usize> {
    if body.len() <= padding {
        return Some(0);
    }
    let payload = body.len() - padding;
    if payload
        < match recv.cipher {
            Cipher::None => 0,
            _ => TAG_LEN,
        }
    {
        return None;
    }
    recv.open_chunk(&mut body[..payload])
}

pub(crate) fn write_frame(
    stream: &mut dyn Write,
    send: &mut Flow,
    plain: &[u8],
    staging: &mut Vec<u8>,
    pad: &mut PadSource,
) -> bool {
    staging.clear();
    write_frame_into(stream, send, plain, staging, pad)
}

/// Stages one `VMess` frame into `staging` and writes it, so the plaintext path can reuse its buffer.
fn write_frame_into(
    stream: &mut dyn Write,
    send: &mut Flow,
    plain: &[u8],
    staging: &mut Vec<u8>,
    pad: &mut PadSource,
) -> bool {
    if !stage_frame(send, plain, staging, pad) {
        return false;
    }
    write_frames(stream, staging)
}

fn stage_frame(send: &mut Flow, plain: &[u8], staging: &mut Vec<u8>, pad: &mut PadSource) -> bool {
    let at = staging.len();
    let (padding, mask_raw, masked) = match send.shake.as_mut() {
        None => (0, 0, false),
        Some(s) => {
            let (pad_raw, mask_raw) = if s.masked { s.draws() } else { (s.draw(), 0) };
            (usize::from(pad_raw % 64), mask_raw, true)
        }
    };
    let tag = if send.cipher == Cipher::None {
        0
    } else {
        TAG_LEN
    };
    let total = plain.len() + tag + padding;
    if total > u16::MAX as usize {
        staging.truncate(at);
        return false;
    }
    if let Some(seal) = send.len_seal.as_mut() {
        // The size field the sealed parser writes, in place of the two masked octets.
        let mut field = [0u8; SIZE_FIELD];
        seal.seal_len(total as u16, &mut field);
        staging.extend_from_slice(&field);
    } else {
        let wire = if masked {
            mask_raw ^ total as u16
        } else {
            total as u16
        };
        staging.extend_from_slice(&wire.to_be_bytes());
    }
    send.seal_onto(plain, staging);
    if padding > 0 {
        let Some(bytes) = pad.take(padding) else {
            staging.truncate(at);
            return false;
        };
        staging.extend_from_slice(bytes);
    }
    true
}

fn stage_frames(
    stream: &mut dyn Write,
    send: &mut Flow,
    plain: &[u8],
    staging: &mut Vec<u8>,
    pad: &mut PadSource,
) -> bool {
    staging.clear();
    stage_frames_into(stream, send, plain, staging, pad)
}

/// Stages up to `FRAMES_PER_WRITE` frames of one read into `staging` and writes them together.
fn stage_frames_into(
    stream: &mut dyn Write,
    send: &mut Flow,
    plain: &[u8],
    staging: &mut Vec<u8>,
    pad: &mut PadSource,
) -> bool {
    if plain.is_empty() {
        if !stage_frame(send, plain, staging, pad) {
            return false;
        }
    } else {
        let mut rest = plain;
        for _ in 0..FRAMES_PER_WRITE {
            let (frame, tail) = rest.split_at(MAX_PLAIN.min(rest.len()));
            if !stage_frame(send, frame, staging, pad) {
                return false;
            }
            rest = tail;
            if rest.is_empty() {
                break;
            }
        }
        // A read wider than FRAMES_PER_WRITE frames reaches here with bytes left: writing them would be a truncated frame stream on the wire, so refuse; `pump_relay` clamps to READ_PLAIN so nothing reaches it today, and a caller that did would rather close than corrupt.
        if !rest.is_empty() {
            return false;
        }
    }
    write_frames(stream, staging)
}

fn write_frames(stream: &mut dyn Write, staging: &[u8]) -> bool {
    if stream.write_all(staging).is_err() {
        return false;
    }
    stream.flush().is_ok()
}

pub(crate) fn read_frame<'a>(
    stream: &mut dyn Read,
    recv: &mut Flow,
    scratch: &'a mut Vec<u8>,
) -> Option<&'a [u8]> {
    let (total, padding) = read_wire_len(stream, recv)?;
    if total <= padding {
        let mut discard = [0u8; 64];
        let mut left = total;
        while left > 0 {
            let take = left.min(discard.len());
            read_exact(stream, &mut discard[..take]).ok()?;
            left -= take;
        }
        scratch.clear();
        return Some(&scratch[..0]);
    }
    if scratch.len() < total {
        crate::proxy::grow_scratch(scratch, total);
    }
    read_exact(stream, &mut scratch[..total]).ok()?;
    let len = open_body(recv, &mut scratch[..total], padding)?;
    Some(&scratch[..len])
}

/// A carrier read a window at a time, for the leg that keeps its frames apart.
///
/// [`read_frame`] asks for a frame's two length octets and then for its body, and a bare socket
/// answers each ask with its own syscall copying only what was asked, so every datagram on the leg
/// pays for two — the first of them moving two bytes. A relay batch cannot be read this way
/// because a window hides how much it holds, which is why [`Wire`] holds the sealed bytes itself;
/// a frame per packet has no batch to hide, so it reads through here.
///
/// The window is the relay pool's own 16 KiB [`crate::proxy::RelayBuf`]: initialised storage a busy
/// lane hands from one datagram direction to the next instead of allocating per direction.
pub(crate) struct Buffered<R: Read> {
    carrier: R,
    held: crate::proxy::RelayBuf,
    at: usize,
    end: usize,
}

impl<R: Read> Buffered<R> {
    #[must_use]
    pub(crate) fn new(carrier: R) -> Self {
        Self {
            carrier,
            held: crate::proxy::RelayBuf::with_window(crate::proxy::RELAY_SMALL_BUFFER),
            at: 0,
            end: 0,
        }
    }
}

impl<R: Read> Read for Buffered<R> {
    fn read(&mut self, dst: &mut [u8]) -> std::io::Result<usize> {
        if self.at == self.end {
            // The window moves only on a read that answered: `read_exact` retries a poll expiry, and a cursor reset before the ask would replay the bytes the last window already served.
            let end = self.carrier.read(self.held.as_mut())?;
            self.at = 0;
            self.end = end;
        }
        let take = (self.end - self.at).min(dst.len());
        let held = self.held.as_mut();
        dst[..take].copy_from_slice(&held[self.at..self.at + take]);
        self.at += take;
        Ok(take)
    }
}

/// What one decode step of a [`Wire`] did.
enum Frame {
    /// A frame opened in place at `at`, `len` plain bytes long.
    Decoded { at: usize, len: usize },
    /// Nothing more can open without a wait; send the batch already gathered.
    Idle,
    /// The stream is over: its marker frame, an EOF, or a frame that will not open.
    Last,
}

/// What [`Wire::step`] handed back: plaintext by position, a wait the lane returns to, or the end.
enum Opened {
    Batch { at: usize, len: usize },
    Idle,
    End,
}

/// The receive half of a relay. Sealed bytes and the plaintext gathered from them share one
/// buffer, so the pump can tell without asking the carrier that a batch of frames is already
/// here and leave the whole batch in one write — which a `BufReader` hides, and one frame per
/// `write` pays for in syscalls and in the segments the peer then has to deliver.
pub(crate) struct Wire<R> {
    carrier: R,
    held: Vec<u8>,
    /// The next frame's header.
    start: usize,
    /// One past the last sealed byte read.
    end: usize,
    /// Where this batch's plaintext starts in `held`.
    front: usize,
    /// How many plaintext bytes this batch holds from `front`.
    plain: usize,
    /// A frame whose length is drawn but whose bytes have not all arrived.
    waiting: Option<(usize, usize)>,
    last: bool,
    /// The last frame opened was the zero-length marker, not a carrier end.
    marker: bool,
    /// A frame could not be authenticated, or the carrier ended inside one.
    failed: bool,
}

impl<R: Read> Wire<R> {
    fn new(carrier: R) -> Self {
        Self {
            carrier,
            held: crate::proxy::unfilled(WIRE_LEN),
            start: 0,
            end: 0,
            front: 0,
            plain: 0,
            waiting: None,
            last: false,
            marker: false,
            failed: false,
        }
    }

    /// Whether the peer said this direction is over with its marker frame, rather than the
    /// carrier ending under it.
    fn ended_by_marker(&self) -> bool {
        self.marker
    }

    /// Whether the end was a frame that would not open, rather than the carrier's own FIN.
    fn corrupt(&self) -> bool {
        self.failed
    }

    /// One step of the relay: open up to `FRAMES_PER_WRITE` frames, waiting only for the first,
    /// and hand back their plaintext as one slice starting where the first of them opened. A wait
    /// with nothing yet gathered is `Idle` so the lane can come back to it.
    fn step(&mut self, recv: &mut Flow) -> Opened {
        if self.last {
            return Opened::End;
        }
        self.compact();
        self.plain = 0;
        let mut decoded = 0;
        while decoded < FRAMES_PER_WRITE {
            match self.frame(recv, decoded == 0) {
                Frame::Decoded { at, len } => {
                    if decoded == 0 {
                        self.front = at;
                    } else {
                        self.held.copy_within(at..at + len, self.front + self.plain);
                    }
                    self.plain += len;
                    decoded += 1;
                }
                Frame::Idle => break,
                Frame::Last => {
                    self.last = true;
                    break;
                }
            }
        }
        if decoded > 0 {
            return Opened::Batch {
                at: self.front,
                len: self.plain,
            };
        }
        if self.last {
            Opened::End
        } else {
            Opened::Idle
        }
    }

    /// The blocking shape: wait out an idle step, so a caller outside a lane never sees one.
    fn batch(&mut self, recv: &mut Flow) -> Option<&[u8]> {
        loop {
            match self.step(recv) {
                Opened::Idle => {}
                Opened::End => return None,
                Opened::Batch { at, len } => return Some(&self.held[at..at + len]),
            }
        }
    }

    /// The carrier before the first frame opens, where a response header waits for its bytes.
    fn carrier(&mut self) -> &mut R {
        &mut self.carrier
    }

    /// Keeps the carrier's control frames (window grants, pings) flowing after its data half ended, so the opposite lane's wait still finishes.
    fn pump_control(&mut self) -> Option<bool>
    where
        R: crate::proxy::RelayPoll,
    {
        self.carrier.pump_control()
    }

    fn buffered(&self) -> usize {
        self.end - self.start
    }

    /// Drop the frames the batch that just went out was made of.
    fn compact(&mut self) {
        if self.start > 0 {
            self.held.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
    }

    /// Read until `want` bytes are buffered. False when the carrier is not to be asked, or
    /// when it has said it has no more.
    #[allow(
        clippy::uninit_vec,
        reason = "the room past the old length is claimed, not written, and the read below writes every byte it reports"
    )]
    fn fill(&mut self, want: usize, block: bool) -> bool {
        if want > self.held.len() - self.start {
            // A peer that seals a wider chunk than we do gets one bigger buffer, not a refusal.
            self.held.reserve(self.start + want - self.held.len());
            // SAFETY: the room past the old length is claimed, not written, and the read below writes every byte it reports.
            unsafe { self.held.set_len(self.start + want) };
        }
        while self.buffered() < want {
            if !block {
                return false;
            }
            match self.carrier.read(&mut self.held[self.end..]) {
                Ok(0) => {
                    self.last = true;
                    return false;
                }
                Ok(read) => self.end += read,
                // A lane's read polls the carrier, and hands the wait back rather than spinning on it.
                Err(ref error)
                    if crate::proxy::is_timeout(error)
                        || error.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    if crate::proxy::relay_step_owns_poll() {
                        return false;
                    }
                }
                Err(_) => {
                    self.failed = true;
                    self.last = true;
                    return false;
                }
            }
        }
        true
    }

    fn frame(&mut self, recv: &mut Flow, block: bool) -> Frame {
        let width = recv.size_field();
        let (total, padding) = if let Some(sizes) = self.waiting {
            sizes
        } else {
            if self.buffered() < width && !self.fill(width, block) {
                if self.last && self.buffered() > 0 {
                    self.failed = true;
                }
                return if self.last { Frame::Last } else { Frame::Idle };
            }
            let sizes = if width == SIZE_FIELD {
                let mut sealed = [0u8; SIZE_FIELD];
                sealed.copy_from_slice(&self.held[self.start..self.start + SIZE_FIELD]);
                let padding = recv.pad_len();
                recv.unseal_len(&mut sealed)
                    .map(|total| (usize::from(total), padding))
            } else {
                let mut prefix = [0u8; HEADER_LEN];
                prefix.copy_from_slice(&self.held[self.start..self.start + HEADER_LEN]);
                Some(masked_len(recv, u16::from_be_bytes(prefix)))
            };
            let Some(sizes) = sizes else {
                self.failed = true;
                return Frame::Last;
            };
            self.waiting = Some(sizes);
            sizes
        };
        if self.buffered() < width + total && !self.fill(width + total, block) {
            if self.last {
                self.failed = true;
            }
            return if self.last { Frame::Last } else { Frame::Idle };
        }
        self.waiting = None;
        let body = self.start + width;
        let Some(len) = open_body(recv, &mut self.held[body..body + total], padding) else {
            self.failed = true;
            return Frame::Last;
        };
        self.start = body + total;
        if len == 0 {
            self.marker = true;
            return Frame::Last;
        }
        Frame::Decoded { at: body, len }
    }
}

impl<R: Read> Read for Wire<R> {
    fn read(&mut self, dst: &mut [u8]) -> std::io::Result<usize> {
        if self.buffered() > 0 {
            let take = self.buffered().min(dst.len());
            dst[..take].copy_from_slice(&self.held[self.start..self.start + take]);
            self.start += take;
            return Ok(take);
        }
        self.carrier.read(dst)
    }
}

pub(crate) type ClientSession = (Flow, Flow, [u8; 16], [u8; 16], u8);

pub(crate) type ClientRequest = (Vec<u8>, Flow, Flow, [u8; 16], [u8; 16], u8);

pub(crate) fn client_request(
    id: &[u8; 16],
    cipher: Cipher,
    auth_len: bool,
    no_termination: bool,
    target: &crate::proxy::Destination,
    cmd: u8,
) -> Option<ClientRequest> {
    let (request, data_key, data_iv, auth) = request_bytes(id, cipher, auth_len, target, cmd)?;
    let (response_key, response_iv) = response_material(&data_iv, &data_key);
    let options = framing_options(cipher, auth_len)?;
    let actual = cipher.resolve();
    let mut send = Flow::fresh(actual, &data_key, &data_iv, options, &data_iv)?;
    let mut recv = Flow::fresh(actual, &response_key, &response_iv, options, &response_iv)?;
    if auth_len {
        // Both directions seal their size with the request body's pair, the shape the reference's server and client use (`proxy/vmess/encoding/{client,server}.go`).
        send.len_seal = Some(SizeAead::fresh(&data_key, actual, &data_iv)?);
        recv.len_seal = Some(SizeAead::fresh(&data_key, actual, &data_iv)?);
    }
    send.end_marker = !no_termination;
    Some((request, send, recv, response_key, response_iv, auth))
}

pub(crate) fn client_handshake(
    uplink: &mut Connection,
    id: &[u8; 16],
    cipher: Cipher,
    auth_len: bool,
    no_termination: bool,
    target: &crate::proxy::Destination,
) -> Option<ClientSession> {
    let (request, send, recv, response_key, response_iv, auth) =
        client_request(id, cipher, auth_len, no_termination, target, 1)?;
    if uplink.write_all(&request).is_err() {
        return None;
    }
    Some((send, recv, response_key, response_iv, auth))
}

pub(crate) fn read_response(
    stream: &mut dyn Read,
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
    auth: u8,
) -> bool {
    let ok = read_response_header(stream, response_key, response_iv, auth);
    if ok && crate::proxy::echo_trace_on() {
        crate::proxy::echo_trace("response ok");
    }
    ok
}

fn read_response_header(
    stream: &mut dyn Read,
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
    auth: u8,
) -> bool {
    let mut sealed_len = [0u8; 2 + TAG_LEN];
    if read_exact(stream, &mut sealed_len).is_err() {
        return false;
    }
    let Some(body_len) = response_len(response_key, response_iv, &sealed_len) else {
        return false;
    };
    let mut sealed_body = [0u8; 64 + TAG_LEN];
    if read_exact(stream, &mut sealed_body[..body_len + TAG_LEN]).is_err() {
        return false;
    }
    response_body(
        response_key,
        response_iv,
        &sealed_body[..body_len + TAG_LEN],
        auth,
    )
}

fn response_len(
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
    sealed: &[u8; 2 + TAG_LEN],
) -> Option<usize> {
    let len_key = kdf16(response_key, &[b"AEAD Resp Header Len Key"]);
    let len_full = kdf(response_iv, &[b"AEAD Resp Header Len IV"]);
    let len_nonce: [u8; 12] = len_full[..12].try_into().unwrap();
    let mut len_plain = [0u8; 2];
    open_header_into(&len_key, &len_nonce, sealed, &[], &mut len_plain)?;
    let body_len = usize::from(u16::from_be_bytes([len_plain[0], len_plain[1]]));
    (body_len <= 64).then_some(body_len)
}

fn response_body(response_key: &[u8; 16], response_iv: &[u8; 16], sealed: &[u8], auth: u8) -> bool {
    let body_key = kdf16(response_key, &[b"AEAD Resp Header Key"]);
    let body_full = kdf(response_iv, &[b"AEAD Resp Header IV"]);
    let body_nonce: [u8; 12] = body_full[..12].try_into().unwrap();
    let mut body_plain = [0u8; 64];
    let Some(clear_body) = open_header_into(&body_key, &body_nonce, sealed, &[], &mut body_plain)
    else {
        return false;
    };
    clear_body.len() == 4 && clear_body[0] == auth
}

/// What one step of [`Answer`] did: the header is open, it needs another step, or it will not open.
enum AnswerStep {
    Done,
    Idle,
    Failed,
}

/// The lazy server's response header, resumed across steps: a lane hands back the wait with the
/// bytes it already has rather than spinning inside `read_exact` for the rest.
struct Answer {
    key: [u8; 16],
    iv: [u8; 16],
    auth: u8,
    sealed: [u8; 64 + TAG_LEN],
    got: usize,
    need: usize,
    body: bool,
}

impl Answer {
    fn new((key, iv, auth): PendingResponse) -> Self {
        Self {
            key,
            iv,
            auth,
            sealed: [0u8; 64 + TAG_LEN],
            got: 0,
            need: 2 + TAG_LEN,
            body: false,
        }
    }

    fn step(&mut self, stream: &mut dyn Read) -> AnswerStep {
        loop {
            if self.got == self.need {
                if self.body {
                    return if response_body(
                        &self.key,
                        &self.iv,
                        &self.sealed[..self.need],
                        self.auth,
                    ) {
                        AnswerStep::Done
                    } else {
                        AnswerStep::Failed
                    };
                }
                let Some(body_len) = response_len(
                    &self.key,
                    &self.iv,
                    self.sealed[..self.need].try_into().unwrap(),
                ) else {
                    return AnswerStep::Failed;
                };
                self.body = true;
                self.got = 0;
                self.need = body_len + TAG_LEN;
                continue;
            }
            match stream.read(&mut self.sealed[self.got..self.need]) {
                Ok(0) => return AnswerStep::Failed,
                Ok(read) => self.got += read,
                Err(ref error)
                    if crate::proxy::is_timeout(error)
                        || error.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    return if crate::proxy::relay_step_owns_poll() {
                        AnswerStep::Idle
                    } else {
                        continue;
                    };
                }
                Err(_) => return AnswerStep::Failed,
            }
        }
    }
}

fn read_open_header(
    stream: &mut dyn Read,
    instruction: &[u8; 16],
    auth_id: &[u8; AUTH_LEN],
) -> Option<Vec<u8>> {
    let mut sealed_len = [0u8; 2 + TAG_LEN];
    read_exact(stream, &mut sealed_len).ok()?;
    let mut nonce = [0u8; 8];
    read_exact(stream, &mut nonce).ok()?;
    let len_key = kdf16(
        instruction,
        &[b"VMess Header AEAD Key_Length", auth_id, &nonce],
    );
    let len_full = kdf(
        instruction,
        &[b"VMess Header AEAD Nonce_Length", auth_id, &nonce],
    );
    let len_nonce: [u8; 12] = len_full[..12].try_into().unwrap();
    let clear_len = open_header(&len_key, &len_nonce, &sealed_len, auth_id)?;
    if clear_len.len() != 2 {
        return None;
    }
    let head_len = usize::from(u16::from_be_bytes([clear_len[0], clear_len[1]]));
    if !(38..=4096).contains(&head_len) {
        return None;
    }
    let mut sealed_head = crate::proxy::unfilled(head_len + TAG_LEN);
    read_exact(stream, &mut sealed_head).ok()?;
    let head_key = kdf16(instruction, &[b"VMess Header AEAD Key", auth_id, &nonce]);
    let head_full = kdf(instruction, &[b"VMess Header AEAD Nonce", auth_id, &nonce]);
    let head_nonce: [u8; 12] = head_full[..12].try_into().unwrap();
    open_header(&head_key, &head_nonce, &sealed_head, auth_id)
}
fn decode_header(header: &[u8]) -> Option<(SocketAddr, Flow, Flow, Vec<u8>, u8)> {
    if header.len() < 38 || header[0] != 1 || header[34] & OPT_STREAM == 0 {
        return None;
    }
    let cmd = header[37];
    if cmd != 1 && cmd != 2 {
        return None;
    }
    let cipher = Cipher::from_code(header[35] & 0x0f)?;
    let options = header[34];
    // Padding is drawn from the masking size parser, so the reference cannot build the generator without the mask bit either (`proxy/vmess/encoding/server.go`).
    if options & OPT_PAD != 0 && options & OPT_MASK == 0 {
        return None;
    }
    // A body without a cipher leaves the sealed size with no key to seal against, and the reference refuses the option there (`proxy/vmess/encoding/server.go`).
    if options & OPT_AUTH_LEN != 0 && cipher.resolve() == Cipher::None {
        return None;
    }
    let mut cursor = 38;
    let target = decode_target(header, &mut cursor)?;
    let margin = usize::from(header[35] >> 4);
    if cursor + margin + 4 > header.len() {
        return None;
    }
    cursor += margin;
    if fnv1a(&header[..cursor])
        != u32::from_be_bytes(header[cursor..cursor + 4].try_into().unwrap())
    {
        return None;
    }
    let data_iv: [u8; 16] = header[1..17].try_into().unwrap();
    let data_key: [u8; 16] = header[17..33].try_into().unwrap();
    let auth = header[33];
    let (response_key, response_iv) = response_material(&data_iv, &data_key);
    let prefix = response_prefix(&response_key, &response_iv, auth)?;
    let mut recv = Flow::fresh(cipher, &data_key, &data_iv, options, &data_iv)?;
    let mut send = Flow::fresh(cipher, &response_key, &response_iv, options, &response_iv)?;
    // The body AEAD rides the response material, the sealed size rides the request's keys (`proxy/vmess/encoding/server.go` `EncodeResponseBody`): both directions derive the size AEAD from the request body key and IV.
    if options & OPT_AUTH_LEN != 0 {
        let actual = cipher.resolve();
        recv.len_seal = Some(SizeAead::fresh(&data_key, actual, &data_iv)?);
        send.len_seal = Some(SizeAead::fresh(&data_key, actual, &data_iv)?);
    }
    Some((target, send, recv, prefix, cmd))
}
/// The accounts one vmess inbound serves. A mutation lands on the next handshake; a flow already
/// admitted keeps running, so `AlterInbound` never drops a session.
#[derive(Debug, Default)]
pub(crate) struct Users {
    entries: std::sync::Mutex<Vec<User>>,
}

/// One vmess account: the id the wire names, the email that names it to `RemoveUser`, and its level.
#[derive(Clone, Debug)]
pub(crate) struct User {
    pub(crate) level: u32,
    pub(crate) email: String,
    pub(crate) id: [u8; 16],
    /// The account's `NoTerminationSignal` experiment: its side of the session ends without
    /// the zero-length marker (`proxy/vmess/inbound/inbound.go:217`).
    pub(crate) no_termination: bool,
}

pub(crate) type UsersRef = std::sync::Arc<Users>;

impl Users {
    pub(crate) fn with(entries: Vec<User>) -> UsersRef {
        std::sync::Arc::new(Self {
            entries: std::sync::Mutex::new(entries),
        })
    }

    pub(crate) fn single(id: [u8; 16]) -> UsersRef {
        Self::with(vec![User {
            level: 0,
            email: String::new(),
            id,
            no_termination: false,
        }])
    }

    fn snapshot(&self) -> Vec<User> {
        self.entries.lock().map(|e| e.clone()).unwrap_or_default()
    }

    fn authenticate(&self, auth_id: &[u8; AUTH_LEN]) -> Option<([u8; 16], User)> {
        let entries = self.entries.lock().ok()?;
        entries.iter().find_map(|user| {
            let (instruction, auth_key) = cached_keys(&user.id);
            (valid_auth_id(&auth_key, auth_id) && !replay_seen(auth_id))
                .then(|| (instruction, user.clone()))
        })
    }

    pub(crate) fn add(&self, user: User) -> bool {
        let Ok(mut entries) = self.entries.lock() else {
            return false;
        };
        if entries.iter().any(|held| held.id == user.id) {
            return false;
        }
        entries.push(user);
        true
    }

    pub(crate) fn remove_email(&self, email: &str) -> bool {
        let Ok(mut entries) = self.entries.lock() else {
            return false;
        };
        let before = entries.len();
        entries.retain(|held| held.email != email);
        entries.len() != before
    }

    pub(crate) fn list(&self) -> Vec<User> {
        self.snapshot()
    }
}

pub(crate) fn accept_request(stream: &mut dyn Read, users: &Users) -> Option<Accepted> {
    let mut auth_id = [0u8; AUTH_LEN];
    if read_exact(stream, &mut auth_id).is_err() {
        eprintln!("trace vmess-auth-read-fail");
        return None;
    }
    eprintln!("trace vmess-auth {:02x?}", auth_id);
    let Some((instruction, user)) = users.authenticate(&auth_id) else {
        eprintln!("trace vmess-auth-mismatch");
        return None;
    };
    eprintln!("trace vmess-auth-ok want={:02x?}", user.id);
    let Some(header) = read_open_header(stream, &instruction, &auth_id) else {
        eprintln!("trace vmess-open-header-fail");
        return None;
    };
    let Some((target, mut send, recv, prefix, cmd)) = decode_header(&header) else {
        eprintln!(
            "trace vmess-decode-header-fail len={} first={:02x?}",
            header.len(),
            &header[..header.len().min(8)]
        );
        return None;
    };
    let data_iv: [u8; 16] = header[1..17].try_into().unwrap();
    let data_key: [u8; 16] = header[17..33].try_into().unwrap();
    if session_seen(&user.id, &data_key, &data_iv) {
        eprintln!("trace vmess-dup");
        return None;
    }
    send.end_marker = !user.no_termination;
    let meter = crate::stats::user(&user.email, user.level);
    Some(Accepted {
        target,
        send,
        recv,
        prefix,
        cmd,
        user: meter,
    })
}

/// The relay leg's read window: a read fills every byte the leg reads, so the zero pass
/// in front of it was work generated and thrown away.
fn relay_window() -> Vec<u8> {
    crate::proxy::unfilled(READ_PLAIN)
}

pub(crate) fn pump_relay_carried<R, W>(
    plain: &Connection,
    reader: R,
    writer: W,
    close: &Close,
    send: Flow,
    recv: Flow,
    pending: Option<PendingResponse>,
) -> Option<std::sync::Arc<crate::proxy::RelayFinish>>
where
    R: Read + Send + 'static + crate::proxy::RelayPoll,
    W: Write + Send + 'static,
{
    pump_relay_carried_with_finish(
        plain, reader, writer, close, send, recv, pending, None, None,
    )
}

/// The carried pump with the carrier's own write-side finish: a clean target EOF ends the request, and a markerless one under `NoTerminationSignal` leaves the carrier FIN as the only end the peer sees.
#[allow(clippy::too_many_arguments)]
pub(crate) fn pump_relay_carried_with_finish<R, W>(
    plain: &Connection,
    reader: R,
    writer: W,
    close: &Close,
    send: Flow,
    recv: Flow,
    pending: Option<PendingResponse>,
    head: Option<Vec<u8>>,
    finish: Option<Close>,
) -> Option<std::sync::Arc<crate::proxy::RelayFinish>>
where
    R: Read + Send + 'static + crate::proxy::RelayPoll,
    W: Write + Send + 'static,
{
    let mut plain_read = plain.try_clone().ok()?;
    let mut plain_write = plain.try_clone().ok()?;
    // Both legs poll the plain socket, so a lane hands the wait back instead of parking on it.
    let _ = plain_read.set_read_timeout(Some(crate::budgets::RELAY_POLL));
    let flow = crate::proxy::RelayFinish::new(false, std::sync::Arc::clone(close), None);
    let mut writer = writer;
    let mut send = send;
    let mut pad = PadSource::fresh();
    let mut staging = Vec::with_capacity(FRAMES_PER_WRITE * (MAX_WIRE + HEADER_LEN));
    let mut buf = relay_window();
    let mut head = head;
    let forward_flow = std::sync::Arc::clone(&flow);
    let forward_close = std::sync::Arc::clone(close);
    crate::proxy::lane_pool::submit(
        Box::new(move || {
            let Some(pad) = pad.as_mut() else {
                return Next::Done;
            };
            let (next, clean) = forward_step(
                &mut plain_read,
                &mut buf,
                &mut writer,
                &mut send,
                &mut staging,
                &mut head,
                pad,
                &forward_close,
                &forward_flow,
            );
            if next == Next::Idle {
                crate::proxy::note_wait_idle(REPLY_IDLE);
                crate::proxy::note_wait_finish(&forward_flow);
            }
            if next == Next::Done {
                if clean {
                    if let Some(finish) = finish.as_ref() {
                        finish();
                    }
                    // A clean target EOF leaves the upload direction writing to this socket.
                    let _ = plain_read.shutdown(Shutdown::Read);
                } else {
                    let _ = plain_read.shutdown(Shutdown::Both);
                }
            }
            next
        }),
        Box::new(crate::proxy::stream_lane_done(&flow)),
    );
    let mut recv = recv;
    // The carrier polls too: a download step with nothing yet must hand the lane back, or every worker parks inside a carrier read.
    let mut reader = reader;
    reader.arm_relay_poll();
    let mut reader = Wire::new(reader);
    // A lazy server sends the prefix with its first data, so the forward lane runs beside this wait.
    let mut answer = pending.map(Answer::new);
    let mut first = true;
    let backward_flow = std::sync::Arc::clone(&flow);
    let backward_close = std::sync::Arc::clone(close);
    crate::proxy::lane_pool::submit(
        Box::new(move || {
            let next = backward_step(
                &mut reader,
                &mut answer,
                &mut recv,
                &mut plain_write,
                &backward_close,
                &backward_flow,
                &mut first,
            );
            if next == Next::Idle {
                crate::proxy::note_wait_idle(REPLY_IDLE);
                crate::proxy::note_wait_finish(&backward_flow);
            }
            next
        }),
        Box::new(crate::proxy::stream_lane_done(&flow)),
    );
    Some(flow)
}

/// One step of the plain leg: read what the target sent, stage it into frames, and hand the lane
/// back a wait when the socket has nothing yet. The flag is true only for the target's clean EOF.
#[allow(clippy::too_many_arguments)]
fn forward_step(
    plain_read: &mut Connection,
    buf: &mut [u8],
    writer: &mut dyn Write,
    send: &mut Flow,
    staging: &mut Vec<u8>,
    head: &mut Option<Vec<u8>>,
    pad: &mut PadSource,
    close: &Close,
    flow: &crate::proxy::RelayFinish,
) -> (Next, bool) {
    match plain_read.read(buf) {
        Ok(0) => {
            // A clean end tells the peer this direction is done; the other direction keeps relaying.
            staging.clear();
            if let Some(prefix) = head.take() {
                staging.extend_from_slice(&prefix);
            }
            let clean = if send.end_marker {
                write_frame_into(writer, send, &[], staging, pad)
            } else {
                staging.is_empty() || write_frames(writer, staging)
            };
            if !clean {
                close();
            }
            (Next::Done, clean)
        }
        Ok(read) => {
            let traced = crate::proxy::echo_trace_on();
            if traced {
                crate::proxy::echo_trace("relay fwd first read");
            }
            let mut at = 0;
            let mut ok = true;
            while at < read {
                let end = (at + READ_PLAIN).min(read);
                let staged = match head.take() {
                    Some(prefix) => {
                        staging.clear();
                        staging.extend_from_slice(&prefix);
                        stage_frames_into(writer, send, &buf[at..end], staging, pad)
                    }
                    None => stage_frames(writer, send, &buf[at..end], staging, pad),
                };
                if !staged {
                    ok = false;
                    break;
                }
                at = end;
            }
            if traced {
                crate::proxy::echo_trace(if ok {
                    "relay fwd first send ok"
                } else {
                    "relay fwd first send failed"
                });
            }
            if ok {
                flow.mark_progress();
                (Next::More, false)
            } else {
                close();
                (Next::Done, false)
            }
        }
        Err(ref error) if crate::proxy::is_timeout(error) => {
            if flow.ended_and_idle(REPLY_IDLE) {
                (Next::Done, false)
            } else {
                (Next::Idle, false)
            }
        }
        Err(_) => {
            close();
            (Next::Done, false)
        }
    }
}

/// One step of the carrier leg: open the lazy server's response header first, then write what the
/// frames it opens carry, and half-close on the peer's marker rather than on an EOF.
fn backward_step<R: Read + crate::proxy::RelayPoll>(
    reader: &mut Wire<R>,
    answer: &mut Option<Answer>,
    recv: &mut Flow,
    out: &mut Connection,
    close: &Close,
    flow: &crate::proxy::RelayFinish,
    first: &mut bool,
) -> Next {
    if let Some(waiting) = answer.as_mut() {
        match waiting.step(reader.carrier()) {
            AnswerStep::Done => *answer = None,
            AnswerStep::Idle => {
                // Parks past the grace are due at once, so a pending answer spends the grace here.
                if !flow.ended_and_idle(REPLY_IDLE) {
                    return Next::Idle;
                }
                close();
                let _ = out.shutdown(Shutdown::Both);
                return Next::Done;
            }
            AnswerStep::Failed => {
                close();
                let _ = out.shutdown(Shutdown::Both);
                return Next::Done;
            }
        }
    }
    match reader.step(recv) {
        Opened::Idle => {
            if flow.ended_and_idle(REPLY_IDLE) {
                Next::Done
            } else {
                Next::Idle
            }
        }
        Opened::End => {
            if reader.corrupt() {
                // A frame that will not open ends both directions.
                close();
                let _ = out.shutdown(Shutdown::Both);
                return Next::Done;
            }
            // A marker or a clean carrier FIN ends this direction only.
            let _ = out.shutdown(Shutdown::Write);
            if flow.ended() {
                return Next::Done;
            }
            // The opposite lane may still be waiting on the peer's window, which only this half reads.
            match reader.pump_control() {
                Some(retry) if retry => Next::Retry,
                Some(_) => Next::Idle,
                None => Next::Done,
            }
        }
        Opened::Batch { at, len } => {
            if crate::proxy::echo_trace_on() && *first {
                crate::proxy::echo_trace("relay bwd first read");
                *first = false;
            }
            if out.write_all(&reader.held[at..at + len]).is_ok() {
                if len > 0 {
                    flow.mark_progress();
                }
                Next::More
            } else {
                close();
                let _ = out.shutdown(Shutdown::Both);
                Next::Done
            }
        }
    }
}

pub(crate) struct Accepted {
    pub(crate) target: SocketAddr,
    pub(crate) send: Flow,
    pub(crate) recv: Flow,
    pub(crate) prefix: Vec<u8>,
    pub(crate) cmd: u8,
    pub(crate) user: crate::stats::Meter,
}
pub(crate) type Close = std::sync::Arc<dyn Fn() + Send + Sync>;

pub(crate) fn accept_request_bounded(reader: &mut dyn Read, users: &Users) -> Option<Accepted> {
    let mut bounded = crate::proxy::HandshakeDeadline {
        inner: reader,
        until: std::time::Instant::now() + crate::budgets::handshake(),
    };
    accept_request(&mut bounded, users)
}

pub(crate) fn serve_decoded<R, W>(
    reader: R,
    writer: W,
    close: &Close,
    decoded: Option<Accepted>,
    freedom: bool,
) where
    R: Read + Send + 'static + crate::proxy::RelayPoll,
    W: Write + Send + 'static,
{
    serve_decoded_impl(reader, writer, close, decoded, freedom, None, false, None);
}

/// The gRPC carrier reads a hunk shorter than 2 KiB only at stream end, so the response header rides
/// the first body write instead of leaving alone in a hunk the peer's reader would park on.
pub(crate) fn serve_decoded_deferred<R, W>(
    reader: R,
    writer: W,
    close: &Close,
    decoded: Option<Accepted>,
    freedom: bool,
    abort: Option<Abort>,
) where
    R: Read + Send + 'static + crate::proxy::RelayPoll,
    W: Write + Send + 'static,
{
    serve_decoded_impl(reader, writer, close, decoded, freedom, None, true, abort);
}

/// [`serve_decoded`] with the carrier's write-side finish for the clean EOF `NoTerminationSignal` leaves markerless.
pub(crate) fn serve_decoded_with_finish<R, W>(
    reader: R,
    writer: W,
    close: &Close,
    decoded: Option<Accepted>,
    freedom: bool,
    finish: Option<Close>,
) where
    R: Read + Send + 'static + crate::proxy::RelayPoll,
    W: Write + Send + 'static,
{
    serve_decoded_impl(reader, writer, close, decoded, freedom, finish, false, None);
}

/// A rejection frees the request stream before answering: a close alone leaves its queue registered for the connection's life.
type Abort = Box<dyn FnOnce() + Send>;

fn abandon(close: &Close, abort: &mut Option<Abort>) {
    if let Some(abort) = abort.take() {
        abort();
    }
    close();
}

/// Runs a decoded request over its uplink; `defer_prefix` holds the response head for the first body frame.
#[allow(clippy::too_many_arguments)]
fn serve_decoded_impl<R, W>(
    reader: R,
    mut writer: W,
    close: &Close,
    decoded: Option<Accepted>,
    freedom: bool,
    finish: Option<Close>,
    defer_prefix: bool,
    mut abort: Option<Abort>,
) where
    R: Read + Send + 'static + crate::proxy::RelayPoll,
    W: Write + Send + 'static,
{
    let Some(Accepted {
        target,
        send,
        recv,
        prefix,
        cmd,
        user,
    }) = decoded
    else {
        abandon(close, &mut abort);
        return;
    };
    if !freedom || !matches!(cmd, 1 | 2) {
        abandon(close, &mut abort);
        return;
    }
    crate::accesslog::record_current(&target);
    match cmd {
        1 => {
            let Ok(uplink) = crate::conn::dial_tcp(&target, Duration::from_secs(8)) else {
                abandon(close, &mut abort);
                return;
            };
            let uplink = uplink.with_meter(user.reversed());
            let head = if defer_prefix {
                Some(prefix)
            } else {
                if !write_prefix(&mut writer, &prefix) {
                    abandon(close, &mut abort);
                    return;
                }
                None
            };
            pump_relay_carried_with_finish(
                &uplink, reader, writer, close, send, recv, None, head, finish,
            );
        }
        2 => serve_udp_carried(
            reader, writer, close, &mut abort, &target, &prefix, send, recv, &user,
        ),
        _ => {}
    }
}

fn write_prefix<W: Write>(writer: &mut W, prefix: &[u8]) -> bool {
    prefix.is_empty() || (writer.write_all(prefix).is_ok() && writer.flush().is_ok())
}

#[allow(clippy::too_many_arguments)]
fn serve_udp_carried<R, W>(
    reader: R,
    mut writer: W,
    close: &Close,
    abort: &mut Option<Abort>,
    target: &SocketAddr,
    prefix: &[u8],
    send: Flow,
    recv: Flow,
    user: &crate::stats::Meter,
) where
    R: Read + Send + 'static + crate::proxy::RelayPoll,
    W: Write + Send + 'static,
{
    let bind = if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let Ok(udp) = UdpSocket::bind(bind) else {
        abandon(close, abort);
        return;
    };
    if udp.connect(target).is_err() {
        abandon(close, abort);
        return;
    }
    if !write_prefix(&mut writer, prefix) {
        abandon(close, abort);
        return;
    }
    crate::proxy::pump_vmess_udp(reader, writer, close, &udp, send, recv, user);
}

pub(crate) fn serve_ws(stream: Connection, path: &str, users: &Users, freedom: bool) {
    let Some((mut reader, writer)) = crate::ws::accept(stream, path) else {
        return;
    };
    let decoded = accept_request(&mut reader, users);
    let closer = writer.clone();
    let close: Close = std::sync::Arc::new(move || closer.close());
    serve_decoded(reader, writer, &close, decoded, freedom);
}

pub(crate) fn serve_ws_split<R, W>(
    reader: R,
    writer: W,
    path: &str,
    users: &Users,
    freedom: bool,
    close: &Close,
) where
    R: Read + Send + 'static + crate::proxy::RelayPoll,
    W: crate::proxy::FrameWrite + Send + 'static,
{
    let Some((mut reader, writer)) = crate::ws::accept_split(reader, writer, path) else {
        return;
    };
    let decoded = accept_request_bounded(&mut reader, users);
    let closer = writer.clone();
    let shutdown = std::sync::Arc::clone(close);
    let close: Close = std::sync::Arc::new(move || {
        closer.close();
        shutdown();
    });
    serve_decoded(reader, writer, &close, decoded, freedom);
}

#[cfg(test)]
pub(crate) fn serve_grpc(stream: Connection, path: &str, users: &Users, freedom: bool) {
    serve_grpc_with(
        stream,
        &crate::config::GrpcSettings::path(path),
        users,
        freedom,
    );
}

#[cfg(test)]
pub(crate) fn serve_grpc_with(
    stream: Connection,
    settings: &crate::config::GrpcSettings,
    users: &Users,
    freedom: bool,
) {
    let Some((mut reader, writer)) = crate::grpc::accept_with(stream, settings) else {
        return;
    };
    let decoded = under_handshake(&mut reader, |read| accept_request(read, users));
    let closer = writer.clone();
    let close: Close = std::sync::Arc::new(move || closer.close());
    serve_decoded_deferred(reader, writer, &close, decoded, freedom, None);
}

/// Serves a TLS or REALITY gRPC listener as one muxed connection, arming the writer clock first.
pub(crate) fn serve_grpc_muxed_split<R, W>(
    reader: R,
    mut writer: W,
    settings: &crate::config::GrpcSettings,
    users: &crate::vmess::UsersRef,
    freedom: bool,
) where
    R: Read + Send + 'static,
    W: crate::proxy::FrameWrite + Send + 'static,
{
    crate::proxy::FrameWrite::arm_write(&mut writer, crate::budgets::RELAY_POLL);
    crate::grpc::serve_muxed_vmess(reader, writer, settings, users, freedom);
}

/// Serves a plaintext gRPC listener as one muxed connection, with the socket read clock armed for the demux.
pub(crate) fn serve_grpc_muxed_with(
    stream: Connection,
    settings: &crate::config::GrpcSettings,
    users: &crate::vmess::UsersRef,
    freedom: bool,
) {
    let Ok(write) = stream.try_clone() else {
        return;
    };
    let _ = stream.set_read_timeout(Some(crate::budgets::RELAY_POLL));
    crate::grpc::serve_muxed_vmess_conn(
        stream,
        crate::grpc::Tail::new(Box::new(write)),
        settings,
        users,
        freedom,
    );
}

/// One gRPC stream of a shared connection: the demux has already answered the HTTP/2 head, so this
/// decodes the `VMess` header and runs the same codec and relay the single-stream carrier does, on
/// its own reader and writer pair. Closing here sends the stream's end, never the connection's.
pub(crate) fn serve_grpc_muxed(
    mut reader: crate::grpc::GrpcReader<crate::grpc::BodyFrames>,
    writer: crate::grpc::GrpcWriter,
    users: &Users,
    freedom: bool,
    opened: &std::sync::atomic::AtomicBool,
) {
    reader.arm_mux_poll();
    let decoded = under_handshake(&mut reader, |read| accept_request(read, users));
    if let Some(Accepted { cmd, .. }) = &decoded {
        if freedom && matches!(*cmd, 1 | 2) {
            opened.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
    let reset = reader.reset_handle();
    let closer = writer.clone();
    let close: Close = std::sync::Arc::new(move || closer.close());
    serve_decoded_deferred(
        reader,
        writer,
        &close,
        decoded,
        freedom,
        Some(Box::new(reset)),
    );
}

#[cfg(test)]
pub(crate) fn serve_xhttp(stream: Connection, path: &str, users: &Users, freedom: bool) {
    let Some((mut reader, writer)) = crate::xhttp::accept(stream, path) else {
        return;
    };
    let decoded = accept_request(&mut reader, users);
    let closer = writer.clone();
    let close: Close = std::sync::Arc::new(move || closer.finish());
    serve_decoded(reader, writer, &close, decoded, freedom);
}

pub(crate) fn serve_xhttp_settings(
    stream: Connection,
    settings: &crate::xhttp::XhttpSettings,
    users: &Users,
    freedom: bool,
) {
    let Ok(read) = stream.try_clone() else {
        return;
    };
    let Ok(closer) = stream.try_clone() else {
        return;
    };
    let close: Close = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    serve_xhttp_split(read, stream, settings, users, freedom, &close);
}

pub(crate) fn serve_xhttp_split<R, W>(
    reader: R,
    writer: W,
    settings: &crate::xhttp::XhttpSettings,
    users: &Users,
    freedom: bool,
    close: &Close,
) where
    R: Read + Send + 'static + crate::proxy::RelayPoll,
    W: crate::proxy::FrameWrite + Send + 'static,
{
    let Some((reader, writer)) =
        crate::xhttp::accept_split_with_settings(reader, writer, settings, None)
    else {
        return;
    };
    serve_xhttp_accepted(reader, writer, users, freedom, close);
}

/// The session above an xHTTP carrier an accept already split: an h2 stream and an H1 request both
/// leave the same pair, so the request decode and relay are shared.
pub(crate) fn serve_xhttp_accepted(
    reader: Box<dyn crate::proxy::WindowRead + Send>,
    writer: crate::xhttp::XhttpWriter,
    users: &Users,
    freedom: bool,
    close: &Close,
) {
    // The h2 reader sleeps through poll timeouts, so the handshake claims the poll and a silent stream ends at its budget.
    let mut reader = crate::proxy::HandshakeRead::new(reader, crate::budgets::handshake());
    let decoded = accept_request(&mut reader, users);
    reader.disarm();
    if decoded.is_none() {
        eprintln!("trace vmess-decode-refused");
        writer.abort();
        close();
        return;
    }
    let closer = writer.clone();
    let shutdown = std::sync::Arc::clone(close);
    let close: Close = std::sync::Arc::new(move || {
        closer.finish();
        shutdown();
    });
    serve_decoded(reader, writer, &close, decoded, freedom);
}

pub(crate) fn serve_httpheader(stream: Connection, path: &str, users: &Users, freedom: bool) {
    let Some((mut reader, write)) = crate::httpheader::accept(stream, path) else {
        return;
    };
    let decoded = accept_request(&mut reader, users);
    let Ok(closer) = write.try_clone() else {
        return;
    };
    let close: Close = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    serve_decoded(reader, write, &close, decoded, freedom);
}

pub(crate) fn serve_httpheader_split<R, W>(
    reader: R,
    writer: W,
    path: &str,
    users: &Users,
    freedom: bool,
    close: &Close,
) where
    R: Read + Send + 'static + crate::proxy::RelayPoll,
    W: Write + Send + 'static,
{
    let Some((mut reader, writer)) = crate::httpheader::accept_split(reader, writer, path) else {
        return;
    };
    let decoded = accept_request_bounded(&mut reader, users);
    serve_decoded(reader, writer, close, decoded, freedom);
}

pub(crate) fn serve_httpupgrade(
    stream: Connection,
    path: &str,
    host: &str,
    users: &Users,
    freedom: bool,
) {
    let Some((mut reader, write)) = crate::httpupgrade::accept(stream, path, host) else {
        return;
    };
    let decoded = accept_request(&mut reader, users);
    let Ok(closer) = write.try_clone() else {
        return;
    };
    let close: Close = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    serve_decoded(reader, write, &close, decoded, freedom);
}

pub(crate) fn serve_httpupgrade_split<R, W>(
    reader: R,
    writer: W,
    path: &str,
    host: &str,
    users: &Users,
    freedom: bool,
    close: &Close,
) where
    R: Read + Send + 'static + crate::proxy::RelayPoll,
    W: Write + Send + 'static,
{
    let Some((mut reader, writer)) = crate::httpupgrade::accept_split(reader, writer, path, host)
    else {
        return;
    };
    let decoded = accept_request_bounded(&mut reader, users);
    serve_decoded(reader, writer, close, decoded, freedom);
}

pub(crate) fn serve_raw_split<R, W>(
    mut reader: R,
    writer: W,
    users: &Users,
    freedom: bool,
    close: &Close,
) where
    R: Read + Send + 'static + crate::proxy::RelayPoll,
    W: Write + Send + 'static,
{
    let decoded = accept_request_bounded(&mut reader, users);
    serve_decoded(reader, writer, close, decoded, freedom);
}

pub(crate) fn serve_kcp<R, W>(mut reader: R, writer: W, users: &Users, freedom: bool, close: &Close)
where
    R: Read + Send + 'static + crate::proxy::RelayPoll,
    W: Write + Send + 'static,
{
    let decoded = accept_request_bounded(&mut reader, users);
    serve_decoded(reader, writer, close, decoded, freedom);
}

pub(crate) fn serve(mut stream: Connection, users: &Users, freedom: bool) {
    // Bound the opening request read like the raw VLESS handshake, then restore the relay's blocking reads.
    let budget = crate::budgets::handshake();
    let _ = stream.set_read_timeout(Some(budget));
    let request = {
        let mut bounded = crate::proxy::HandshakeDeadline {
            inner: &mut stream,
            until: std::time::Instant::now() + budget,
        };
        accept_request(&mut bounded, users)
    };
    let _ = stream.set_read_timeout(None);
    let Some(Accepted {
        target,
        send,
        recv,
        prefix,
        cmd,
        user,
    }) = request
    else {
        return;
    };
    if !freedom {
        return;
    }
    crate::accesslog::record_current(&target);
    if cmd == 2 {
        crate::proxy::spawn_carried(move || {
            serve_vmess_udp(stream, &target, send, recv, &prefix, &user);
        });
        return;
    }
    if cmd != 1 {
        return;
    }
    let Ok(uplink) = crate::conn::dial_tcp(&target, Duration::from_secs(8)) else {
        return;
    };
    let uplink = uplink.with_meter(user.reversed());
    if stream.write_all(&prefix).is_err() {
        return;
    }
    let Ok(reader) = stream.try_clone() else {
        return;
    };
    let Ok(closer) = stream.try_clone() else {
        return;
    };
    let close: Close = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    pump_relay_carried(&uplink, reader, stream, &close, send, recv, None);
}

pub(crate) fn serve_vmess_udp(
    mut stream: Connection,
    target: &SocketAddr,
    send: Flow,
    recv: Flow,
    prefix: &[u8],
    user: &crate::stats::Meter,
) {
    let bind = if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let Ok(udp) = UdpSocket::bind(bind) else {
        return;
    };
    if udp.connect(target).is_err() {
        return;
    }
    if stream.write_all(prefix).is_err() {
        return;
    }
    let Ok(reader) = stream.try_clone() else {
        return;
    };
    let Ok(closer) = stream.try_clone() else {
        return;
    };
    let close: Close = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    crate::proxy::pump_vmess_udp(reader, stream, &close, &udp, send, recv, user);
}

pub(crate) type PendingResponse = ([u8; 16], [u8; 16], u8);

pub(crate) fn pump_relay(
    plain: &Connection,
    sealed: &Connection,
    send: Flow,
    recv: Flow,
    pending: Option<PendingResponse>,
) {
    let Ok(plain_read) = plain.try_clone() else {
        return;
    };
    let Ok(sealed_write) = sealed.try_clone() else {
        return;
    };
    let Ok(sealed_read) = sealed.try_clone() else {
        return;
    };
    let Ok(plain_write) = plain.try_clone() else {
        return;
    };
    let mut plain_read = plain_read;
    let mut sealed_write = sealed_write;
    let mut plain_write = plain_write;
    let mut send = send;
    let mut buf = relay_window();
    let done = thread::spawn(move || {
        let mut staging = Vec::with_capacity(FRAMES_PER_WRITE * (MAX_WIRE + HEADER_LEN));
        let Some(mut pad) = PadSource::fresh() else {
            return;
        };
        let mut ended = false;
        while let Ok(read) = plain_read.read(&mut buf) {
            if read == 0 {
                ended = !send.end_marker
                    || write_frame(&mut sealed_write, &mut send, &[], &mut staging, &mut pad);
                break;
            }
            let mut at = 0;
            let mut ok = true;
            while at < read {
                let end = (at + READ_PLAIN).min(read);
                if !stage_frames(
                    &mut sealed_write,
                    &mut send,
                    &buf[at..end],
                    &mut staging,
                    &mut pad,
                ) {
                    ok = false;
                    break;
                }
                at = end;
            }
            if !ok {
                break;
            }
        }
        // A clean end tells the peer this direction is done; the other direction keeps relaying.
        if ended {
            let _ = sealed_write.shutdown(Shutdown::Write);
        } else {
            let _ = sealed_write.shutdown(Shutdown::Both);
        }
    });
    let mut recv = recv;
    let mut sealed_reader = Wire::new(sealed_read);
    if let Some((response_key, response_iv, auth)) = pending {
        if !read_response(&mut sealed_reader, &response_key, &response_iv, auth) {
            let _ = sealed.shutdown(Shutdown::Both);
            let _ = plain_write.shutdown(Shutdown::Both);
            let _ = done.join();
            return;
        }
    }
    while let Some(chunk) = sealed_reader.batch(&mut recv) {
        if plain_write.write_all(chunk).is_err() {
            break;
        }
    }
    if sealed_reader.ended_by_marker() {
        // The marker ends this direction only: half-close its peer and keep the other direction.
        let _ = plain_write.shutdown(Shutdown::Write);
        let _ = done.join();
    } else {
        // Carrier EOF or a frame that will not open ends both directions; releasing the target's read unblocks the forward thread before the join.
        let _ = sealed.shutdown(Shutdown::Both);
        let _ = plain_write.shutdown(Shutdown::Both);
        let _ = done.join();
        return;
    }
    let _ = sealed.shutdown(Shutdown::Both);
    let _ = plain_write.shutdown(Shutdown::Both);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::Arc;

    #[test]
    fn a_frame_coalesced_behind_its_header_still_arrives() {
        // The stall this guards against is silent on both ends: the server decodes the header and the dial waits for the echo while the ping frame sits in bytes a decode already consumed — no socket, no scheduler, so a loss here fails every run instead of one run in nine.
        let id = [0x77u8; 16];
        let target: SocketAddr = "127.0.0.1:1".parse().expect("addr");
        let Some((request, mut send, _recv, _, _, _)) = client_request(
            &id,
            Cipher::Auto,
            false,
            false,
            &crate::proxy::Destination::from(target),
            1,
        ) else {
            panic!("builds a request");
        };
        let mut staging = Vec::with_capacity(16 * 1024);
        let mut pad = PadSource::fresh().expect("entropy");
        let mut frame = Vec::new();
        assert!(write_frame(
            &mut frame,
            &mut send,
            b"ping",
            &mut staging,
            &mut pad
        ));
        let mut cursor = Cursor::new([request, frame].concat());
        let Some(Accepted {
            target: got,
            recv: mut take,
            cmd,
            ..
        }) = accept_request(&mut cursor, &Users::single(id))
        else {
            panic!("decodes a header");
        };
        assert_eq!(cmd, 1);
        assert_eq!(got, target);
        let mut scratch = Vec::with_capacity(16 * 1024);
        let Some(back) = read_frame(&mut cursor, &mut take, &mut scratch) else {
            panic!("reads a coalesced frame");
        };
        assert_eq!(back, b"ping");
    }

    #[test]
    fn a_second_account_authenticates_on_the_same_inbound() {
        let first = [0x31u8; 16];
        let second = [0x32u8; 16];
        let target: SocketAddr = "127.0.0.1:1".parse().expect("addr");
        let request = client_request(
            &second,
            Cipher::Auto,
            false,
            false,
            &crate::proxy::Destination::from(target),
            1,
        )
        .expect("builds a request")
        .0;
        let users = Users::with(vec![
            User {
                level: 0,
                email: "first@example.com".to_owned(),
                id: first,
                no_termination: false,
            },
            User {
                level: 0,
                email: "second@example.com".to_owned(),
                id: second,
                no_termination: false,
            },
        ]);
        let mut cursor = Cursor::new(request);
        assert!(accept_request(&mut cursor, &users).is_some());
    }

    #[test]
    fn instruction_splits_uuid_and_magic() {
        let uuid = [0x11u8; 16];
        assert_ne!(instruction_key(&uuid), uuid);
        assert_eq!(instruction_key(&uuid), instruction_key(&uuid));
    }

    #[test]
    fn auth_ids_round_trip_and_reject_damage() {
        let instruction = instruction_key(&[0x22u8; 16]);
        let key = AuthKey::new(&instruction);
        let id = make_auth_id(&key).expect("makes");
        assert!(valid_auth_id(&key, &id));
        let mut bad = id;
        bad[0] ^= 1;
        assert!(!valid_auth_id(&key, &bad));
    }

    #[test]
    fn headers_open_that_seal_sealed() {
        let key = [0x33u8; 16];
        let nonce = [0x44u8; 12];
        let sealed = seal_header(&key, &nonce, b"length-is-framing", b"aad").expect("seals");
        let back = open_header(&key, &nonce, &sealed, b"aad").expect("opens");
        assert_eq!(back, b"length-is-framing");
        let mut cut = sealed.clone();
        cut.pop();
        assert!(open_header(&key, &nonce, &cut, b"aad").is_none());
    }

    #[test]
    fn frames_carry_an_echo_both_ways() {
        let cipher = Cipher::Chacha;
        let key = [0x55u8; 16];
        let iv = [0x66u8; 16];
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let mut send = Flow::fresh(cipher, &key, &iv, options, &iv).expect("sends");
        let mut recv = Flow::fresh(cipher, &key, &iv, options, &iv).expect("recvs");
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let writer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut scratch = Vec::new();
            let chunk = read_frame(&mut stream, &mut recv, &mut scratch).expect("reads");
            chunk.to_vec()
        });
        let mut reader = Connection::connect(("127.0.0.1", port)).expect("connects");
        let mut staging = Vec::new();
        let mut pad = PadSource::fresh().expect("entropy");
        assert!(write_frame(
            &mut reader,
            &mut send,
            b"ping",
            &mut staging,
            &mut pad
        ));
        assert_eq!(writer.join().expect("joins"), b"ping");
    }

    /// Silence past the budget is death, not scheduling: a peer that opens the connection and never sends must not pin the raw `VMess` handshake thread forever.
    #[test]
    fn a_silent_peer_cannot_pin_a_raw_vmess_handshake() {
        crate::budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let id = [0x11u8; 16];
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = crate::budgets::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve(stream, &Users::single(id), true);
            let _ = done_tx.send(());
        });
        let _peer = Connection::connect(addr).expect("connects");
        let returned = done_rx.recv_timeout(crate::budgets::handshake() + Duration::from_secs(5));
        crate::budgets::clear();
        returned.expect("the bounded request read returns instead of pinning the thread");
        serving.join().expect("joins");
    }

    #[test]
    fn vmess_carries_over_the_ws_carrier_both_ways() {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds echo");
        let echo_port = echo.local_addr().expect("echo addr").port();
        thread::spawn(move || {
            for stream in echo.incoming().take(1) {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 256];
                if let Ok(n) = stream.read(&mut buf) {
                    let _ = stream.write_all(&buf[..n]);
                }
            }
        });

        let id = [0x5au8; 16];
        let path = "/vmess-ws";
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server_id = id;
        let server_path = path.to_string();
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_ws(stream, &server_path, &Users::single(server_id), true);
        });

        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("target");
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, writer) =
            crate::ws::connect(stream, &format!("127.0.0.1:{port}"), path, 0, &[], &[], 0)
                .expect("carries");

        let (request, data_key, data_iv, auth) = request_bytes(
            &id,
            Cipher::Chacha,
            false,
            &crate::proxy::Destination::from(target),
            1,
        )
        .expect("request");
        assert!(writer.send(&request), "request goes out as one message");

        let (response_key, response_iv) = response_material(&data_iv, &data_key);
        assert!(
            read_response(&mut reader, &response_key, &response_iv, auth),
            "the server's response header opens over the carrier"
        );

        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let mut send =
            Flow::fresh(Cipher::Chacha, &data_key, &data_iv, options, &data_iv).expect("sends");
        let mut recv = Flow::fresh(
            Cipher::Chacha,
            &response_key,
            &response_iv,
            options,
            &response_iv,
        )
        .expect("recvs");

        let mut sink = writer;
        let mut staging = Vec::new();
        let mut pad = PadSource::fresh().expect("entropy");
        let mut scratch = Vec::new();

        assert!(
            write_frame(&mut sink, &mut send, b"ping", &mut staging, &mut pad),
            "a sealed frame goes out over the carrier"
        );
        let back = read_frame(&mut reader, &mut recv, &mut scratch).expect("reads");
        assert_eq!(back, b"ping", "the echo came back through the carrier");
    }

    fn vmess_over_byte_carrier(
        path: &str,
        serve: impl FnOnce(Connection, [u8; 16]) + Send + 'static,
        connect: impl FnOnce(Connection) -> Option<(Box<dyn Read + Send>, Box<dyn Write + Send>)>,
    ) {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds echo");
        let echo_port = echo.local_addr().expect("echo addr").port();
        thread::spawn(move || {
            for stream in echo.incoming().take(1) {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 256];
                if let Ok(n) = stream.read(&mut buf) {
                    let _ = stream.write_all(&buf[..n]);
                }
            }
        });

        let id = [0x5au8; 16];
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve(stream, id);
        });

        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("target");
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut writer) = connect(stream).expect("carries");

        let (request, data_key, data_iv, auth) = request_bytes(
            &id,
            Cipher::Chacha,
            false,
            &crate::proxy::Destination::from(target),
            1,
        )
        .expect("request");
        writer.write_all(&request).expect("requests");
        writer.flush().expect("flushes");

        let (response_key, response_iv) = response_material(&data_iv, &data_key);
        assert!(
            read_response(&mut reader, &response_key, &response_iv, auth),
            "the server's response header opens over {path}"
        );

        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let mut send =
            Flow::fresh(Cipher::Chacha, &data_key, &data_iv, options, &data_iv).expect("sends");
        let mut recv = Flow::fresh(
            Cipher::Chacha,
            &response_key,
            &response_iv,
            options,
            &response_iv,
        )
        .expect("recvs");

        let mut staging = Vec::new();
        let mut pad = PadSource::fresh().expect("entropy");
        let mut scratch = Vec::new();
        assert!(
            write_frame(&mut writer, &mut send, b"ping", &mut staging, &mut pad),
            "a sealed frame goes out over {path}"
        );
        let back = read_frame(&mut reader, &mut recv, &mut scratch).expect("reads");
        assert_eq!(back, b"ping", "the echo came back through {path}");
    }

    #[test]
    fn vmess_carries_over_the_xhttp_carrier_both_ways() {
        vmess_over_byte_carrier(
            "/vmess-xhttp",
            |stream, id| serve_xhttp(stream, "/vmess-xhttp", &Users::single(id), true),
            |stream| {
                let (reader, writer) = crate::xhttp::connect(
                    stream,
                    "127.0.0.1",
                    "/vmess-xhttp",
                    &[],
                    &"X".repeat(500),
                )?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(writer) as Box<dyn Write + Send>,
                ))
            },
        );
    }

    #[test]
    fn vmess_carries_behind_the_http_camouflage_both_ways() {
        vmess_over_byte_carrier(
            "/vmess-camouflage",
            |stream, id| serve_httpheader(stream, "/vmess-camouflage", &Users::single(id), true),
            |stream| {
                let (reader, writer) =
                    crate::httpheader::connect(stream, "127.0.0.1", "/vmess-camouflage", &[])?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(writer) as Box<dyn Write + Send>,
                ))
            },
        );
    }

    /// A vmess inbound over gRPC whose peer answers the head and never sends its first hunk releases the serve thread: the carrier puts its clock away with the head, so the auth id reads under its own.
    #[test]
    fn a_silent_peer_cannot_pin_a_grpc_vmess_request() {
        crate::budgets::apply(&crate::config::Budgets {
            handshake: Some(Duration::from_millis(250)),
            ..Default::default()
        });
        let id = [0x5bu8; 16];
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let serving = crate::budgets::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_grpc(stream, "/p", &Users::single(id), true);
            let _ = done_tx.send(());
        });
        let stream = Connection::connect(addr).expect("connects");
        let (_reader, _writer) = crate::grpc::connect(stream, "127.0.0.1", "/p").expect("dials");
        let returned = done_rx.recv_timeout(crate::budgets::handshake() + Duration::from_secs(5));
        crate::budgets::clear();
        returned.expect("the bounded request read returns instead of pinning the thread");
        serving.join().expect("joins");
    }

    #[test]
    fn vmess_carries_over_the_grpc_tunnel_both_ways() {
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds echo");
        let echo_port = echo.local_addr().expect("echo addr").port();
        thread::spawn(move || {
            for stream in echo.incoming().take(1) {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 256];
                if let Ok(n) = stream.read(&mut buf) {
                    let _ = stream.write_all(&buf[..n]);
                }
            }
        });
        let id = [0x5au8; 16];
        let path = "/TunnelService/Tun";
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_grpc(stream, path, &Users::single(id), true);
        });
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("target");
        let stream = Connection::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut writer) =
            crate::grpc::connect(stream, "127.0.0.1", path).expect("carries");
        let (request, data_key, data_iv, auth) = request_bytes(
            &id,
            Cipher::Chacha,
            false,
            &crate::proxy::Destination::from(target),
            1,
        )
        .expect("request");
        assert!(writer.send(&request));
        let (response_key, response_iv) = response_material(&data_iv, &data_key);
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let mut send =
            Flow::fresh(Cipher::Chacha, &data_key, &data_iv, options, &data_iv).expect("sends");
        let mut recv = Flow::fresh(
            Cipher::Chacha,
            &response_key,
            &response_iv,
            options,
            &response_iv,
        )
        .expect("recvs");
        let mut staging = Vec::new();
        let mut pad = PadSource::fresh().expect("entropy");
        let mut scratch = Vec::new();
        assert!(write_frame(
            &mut writer,
            &mut send,
            b"ping",
            &mut staging,
            &mut pad
        ));
        // The header rides the first body hunk, so the upload opens the answer.
        assert!(read_response(
            &mut reader,
            &response_key,
            &response_iv,
            auth
        ));
        let back = read_frame(&mut reader, &mut recv, &mut scratch).expect("reads");
        assert_eq!(back, b"ping");
    }

    #[test]
    fn crc32_is_the_bit_at_a_time_loop_folded() {
        fn bit_at_a_time(data: &[u8]) -> u32 {
            let mut crc = !0u32;
            for &byte in data {
                crc ^= u32::from(byte);
                for _ in 0..8 {
                    crc = if crc & 1 == 1 {
                        (crc >> 1) ^ 0xedb8_8320
                    } else {
                        crc >> 1
                    };
                }
            }
            !crc
        }

        for a in 0..=255u8 {
            assert_eq!(crc32(&[a]), bit_at_a_time(&[a]), "single byte {a}");
        }
        for len in 0..=40usize {
            let data: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(97).wrapping_add(13))
                .collect();
            assert_eq!(crc32(&data), bit_at_a_time(&data), "length {len}");
        }
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    /// Counts `write` calls and keeps the bytes, so a syscall row is observed rather than inferred: a `Vec` sink cannot tell one write from four.
    #[derive(Default)]
    struct CountingWriter {
        writes: usize,
        bytes: Vec<u8>,
    }

    impl Write for CountingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.writes += 1;
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_batch_on_the_wire_is_the_frames_written_one_at_a_time() {
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let key = [0x3cu8; 16];
        let iv: [u8; 16] = std::array::from_fn(|i| 0x10u8.wrapping_add(i as u8));
        for &run_len in &[
            1usize,
            2,
            63,
            64,
            4096,
            MAX_PLAIN,
            MAX_PLAIN + 1,
            (FRAMES_PER_WRITE - 1) * MAX_PLAIN,
            FRAMES_PER_WRITE * MAX_PLAIN - 1,
            FRAMES_PER_WRITE * MAX_PLAIN,
            FRAMES_PER_WRITE * MAX_PLAIN + 1,
            READ_PLAIN,
        ] {
            let body: Vec<u8> = (0..run_len)
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
                .collect();

            let chunks: Vec<&[u8]> = body.chunks(MAX_PLAIN).take(FRAMES_PER_WRITE).collect();
            let mut send = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
            let mut staging = Vec::new();
            let mut pad = PadSource::fresh().expect("entropy");
            let mut apart = Vec::new();
            for frame in &chunks {
                staging.clear();
                assert!(stage_frame(&mut send, frame, &mut staging, &mut pad));
                apart.extend_from_slice(&staging);
            }

            let mut batched = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
            let mut whole = Vec::new();
            let mut batch_pad = PadSource::fresh().expect("entropy");
            let mut sink = CountingWriter::default();
            let staged = stage_frames(&mut sink, &mut batched, &body, &mut whole, &mut batch_pad);
            if run_len > READ_PLAIN {
                assert!(!staged, "run of {run_len} is over the batch bound");
                assert_eq!(sink.writes, 0, "run of {run_len}: nothing reached the wire");
                continue;
            }
            assert!(staged, "run of {run_len} is inside the bound");
            let frames = chunks.len();
            assert_eq!(
                sink.writes,
                usize::from(frames > 0),
                "run of {run_len}: {frames} frames must cost exactly one write"
            );

            let mut mask = Shake::fresh(&iv, true, true);
            let (mut a, mut b) = (0usize, 0usize);
            for (frame, chunk) in chunks.iter().enumerate() {
                if run_len > READ_PLAIN {
                    break;
                }
                let padding = usize::from(mask.pad_len());
                let wire = u16::from_be_bytes([apart[a], apart[a + 1]]);
                assert_eq!(
                    wire,
                    u16::from_be_bytes([whole[b], whole[b + 1]]),
                    "run of {run_len}: frame {frame} length prefix"
                );
                let masked = usize::from(mask.draw() ^ wire);
                let sealed = masked - padding;
                assert_eq!(
                    chunk.len() + TAG_LEN,
                    sealed,
                    "run of {run_len}: frame {frame} sealed length"
                );
                assert_eq!(
                    &apart[a + 2..a + 2 + sealed],
                    &whole[b + 2..b + 2 + sealed],
                    "run of {run_len}: frame {frame} sealed body"
                );
                a += 2 + masked;
                b += 2 + masked;
            }
            assert_eq!(
                a,
                apart.len(),
                "the one-at-a-time run is exactly its frames"
            );
            assert_eq!(b, whole.len(), "the batch is exactly the same frames");
        }
    }

    /// The sealed batch is the buffer the webSocket carrier writes: the frame's payload starts at
    /// the staging buffer's own base, so no second buffer takes the bytes on their way out.
    #[test]
    fn a_sealed_batch_reaches_a_web_socket_carrier_where_it_lies() {
        #[derive(Clone, Default)]
        struct Seen(std::sync::Arc<std::sync::Mutex<Vec<(usize, usize)>>>);

        impl std::io::Write for Seen {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                Ok(data.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl crate::proxy::FrameWrite for Seen {
            fn write_slices(&mut self, parts: &[&[u8]]) -> bool {
                let payload = parts.get(1).copied().unwrap_or(&[]);
                self.0
                    .lock()
                    .expect("the record is not poisoned")
                    .push((payload.as_ptr() as usize, payload.len()));
                true
            }
        }

        let seen = Seen::default();
        let (_, mut writer) = crate::ws::split_halves(
            std::io::empty(),
            seen.clone(),
            Vec::new(),
            Vec::new(),
            0,
            false,
        );
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let key = [0x3cu8; 16];
        let iv: [u8; 16] = std::array::from_fn(|i| 0x10u8.wrapping_add(i as u8));
        let mut send = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
        let body: Vec<u8> = (0..READ_PLAIN)
            .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
            .collect();
        let mut staging = Vec::new();
        let mut pad = PadSource::fresh().expect("entropy");
        assert!(stage_frames(
            &mut writer,
            &mut send,
            &body,
            &mut staging,
            &mut pad
        ));
        let base = staging.as_ptr() as usize;
        let capacity = staging.capacity();
        let recorded = seen.0.lock().expect("the record is not poisoned").clone();
        assert_eq!(recorded.len(), 1, "one batch is one carrier write");
        let (payload, len) = recorded[0];
        assert_eq!(len, staging.len(), "the whole batch left");
        assert_eq!(
            payload, base,
            "the payload is the staging buffer itself, not a copy of it"
        );
        assert_eq!(
            staging.capacity(),
            capacity,
            "and it did not grow to send it"
        );
    }

    /// A webSocket carrier opens its shared state and nothing sized by a batch: the staging
    /// buffer the relay already keeps is the one that goes out, and the counting allocator is
    /// the witness for the batch-sized one that is not opened.
    #[test]
    fn a_web_socket_carrier_opens_no_batch_buffer() {
        struct NoWrite;

        impl std::io::Write for NoWrite {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                Ok(data.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl crate::proxy::FrameWrite for NoWrite {
            fn write_slices(&mut self, _parts: &[&[u8]]) -> bool {
                true
            }
        }

        let (_, counts) = ferrox_core::alloc_count::measure(|| {
            crate::ws::split_halves(std::io::empty(), NoWrite, Vec::new(), Vec::new(), 0, false)
        });
        assert!(
            counts.bytes <= 1024,
            "the carrier opened {} bytes, a batch buffer is 132384",
            counts.bytes
        );
    }

    /// `stage_frames` stages at most `FRAMES_PER_WRITE` frames: a wider read must refuse before any of the batch reaches the stream, because exiting the loop with bytes left and returning true would put a truncated frame sequence on the wire.
    #[test]
    fn a_read_wider_than_one_batch_is_refused_not_truncated() {
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let key = [0x3cu8; 16];
        let iv: [u8; 16] = std::array::from_fn(|i| 0x10u8.wrapping_add(i as u8));
        for extra in [1usize, MAX_PLAIN] {
            let plain: Vec<u8> = (0..(READ_PLAIN + extra))
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
                .collect();
            let mut send = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
            let mut staging = Vec::new();
            let mut pad = PadSource::fresh().expect("entropy");
            let mut sink = CountingWriter::default();
            assert!(
                !stage_frames(&mut sink, &mut send, &plain, &mut staging, &mut pad),
                "a read of {} bytes must be refused, not truncated",
                plain.len()
            );
            assert_eq!(
                sink.writes, 0,
                "nothing of a refused batch may reach the wire"
            );
        }

        // and one byte under the bound still works, or the refusal is not a bound
        for len in [READ_PLAIN - 1, READ_PLAIN] {
            let plain: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
                .collect();
            let mut send = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
            let mut staging = Vec::new();
            let mut pad = PadSource::fresh().expect("entropy");
            let mut sink = CountingWriter::default();
            assert!(
                stage_frames(&mut sink, &mut send, &plain, &mut staging, &mut pad),
                "{len} bytes is exactly the bound and must stage"
            );
            assert_eq!(sink.writes, 1, "{len} bytes is one write");
        }
    }

    #[test]
    fn an_aes_batch_is_the_frames_written_one_at_a_time() {
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let key = [0x3cu8; 16];
        let iv: [u8; 16] = std::array::from_fn(|i| 0x10u8.wrapping_add(i as u8));
        for run_len in [
            1usize,
            MAX_PLAIN,
            FRAMES_PER_WRITE * MAX_PLAIN - 1,
            FRAMES_PER_WRITE * MAX_PLAIN,
        ] {
            let body: Vec<u8> = (0..run_len)
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
                .collect();
            let chunks: Vec<&[u8]> = body.chunks(MAX_PLAIN).take(FRAMES_PER_WRITE).collect();
            let mut send = Flow::fresh(Cipher::Aes, &key, &iv, options, &iv).expect("sends");
            let mut staging = Vec::new();
            let mut pad = PadSource::fresh().expect("entropy");
            let mut apart = Vec::new();
            for frame in &chunks {
                staging.clear();
                assert!(stage_frame(&mut send, frame, &mut staging, &mut pad));
                apart.extend_from_slice(&staging);
            }

            let mut batched = Flow::fresh(Cipher::Aes, &key, &iv, options, &iv).expect("sends");
            let mut whole = Vec::new();
            let mut batch_pad = PadSource::fresh().expect("entropy");
            let mut sink = CountingWriter::default();
            assert!(
                stage_frames(&mut sink, &mut batched, &body, &mut whole, &mut batch_pad),
                "run of {run_len}: staged"
            );
            let mut mask = Shake::fresh(&iv, true, true);
            let (mut a, mut b) = (0usize, 0usize);
            for chunk in &chunks {
                let padding = usize::from(mask.pad_len());
                assert_eq!(
                    apart[a..a + 2],
                    whole[b..b + 2],
                    "run of {run_len}: length prefix"
                );
                let wire = u16::from_be_bytes([apart[a], apart[a + 1]]);
                let masked = usize::from(mask.draw() ^ wire);
                let sealed = masked - padding;
                assert_eq!(chunk.len() + TAG_LEN, sealed, "run of {run_len}: sealed");
                assert_eq!(
                    apart[a + 2..a + 2 + sealed],
                    whole[b + 2..b + 2 + sealed],
                    "run of {run_len}: sealed body"
                );
                a += 2 + masked;
                b += 2 + masked;
            }
            assert_eq!(a, apart.len(), "run of {run_len}: frames are the batch");
            assert_eq!(b, whole.len(), "run of {run_len}: batch is the frames");
            assert_eq!(
                sink.writes,
                usize::from(!chunks.is_empty()),
                "run of {run_len}: one write"
            );
        }
    }

    #[test]
    fn frames_reuse_the_callers_buffers() {
        let cipher = Cipher::Chacha;
        let key = [0x77u8; 16];
        let iv = [0x88u8; 16];
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let mut send = Flow::fresh(cipher, &key, &iv, options, &iv).expect("sends");
        let mut recv = Flow::fresh(cipher, &key, &iv, options, &iv).expect("recvs");
        let lens = [1usize, 4, 63, 64, 65, 512, 1500, 4096];
        let payloads: Vec<Vec<u8>> = lens
            .iter()
            .map(|n| {
                (0..*n)
                    .map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
                    .collect()
            })
            .collect();

        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let reader = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut scratch = Vec::with_capacity(MAX_PLAIN + TAG_LEN + 64);
            let addr = scratch.as_ptr() as usize;
            let cap = scratch.capacity();
            let mut got = Vec::new();
            for want in &lens {
                let was_at = scratch.as_ptr() as usize;
                let had = scratch.capacity();
                let chunk = read_frame(&mut stream, &mut recv, &mut scratch).expect("reads");
                assert_eq!(chunk.len(), *want, "plaintext length");
                assert_eq!(
                    chunk.as_ptr() as usize,
                    was_at,
                    "the plaintext was copied out of the caller's buffer"
                );
                assert_eq!(was_at, addr, "the read buffer moved: read_frame allocated");
                assert_eq!(had, cap, "the read buffer grew: read_frame allocated");
                got.extend_from_slice(chunk);
            }
            got
        });

        let mut uplink = Connection::connect(("127.0.0.1", port)).expect("connects");
        let mut staging = Vec::with_capacity(MAX_PLAIN + TAG_LEN + 2 + 64);
        let mut pad = PadSource::fresh().expect("entropy");
        let addr = staging.as_ptr() as usize;
        let cap = staging.capacity();
        let mut want = Vec::new();
        for plain in &payloads {
            assert!(write_frame(
                &mut uplink,
                &mut send,
                plain,
                &mut staging,
                &mut pad
            ));
            assert_eq!(
                staging.as_ptr() as usize,
                addr,
                "the write buffer moved: write_frame allocated"
            );
            assert_eq!(
                staging.capacity(),
                cap,
                "the write buffer grew: write_frame allocated"
            );
            want.extend_from_slice(plain);
        }
        assert_eq!(reader.join().expect("joins"), want);
    }

    #[test]
    fn a_frame_window_reads_the_carrier_once_for_a_batch_of_datagrams() {
        let lens: Vec<usize> = (500..510).collect();
        let (sealed, plain, mut recv) = frames(&lens);
        let mut carrier = Sealed {
            held: sealed.clone(),
            at: 0,
            grain: usize::MAX,
            reads: 0,
        };
        let mut windowed = Buffered::new(&mut carrier);
        assert_eq!(
            windowed.held.size(),
            crate::proxy::RELAY_SMALL_BUFFER,
            "the leg reads through the pool's own window, not a size of its own"
        );
        let mut got = Vec::new();
        let mut sizes = Vec::new();
        let mut scratch = Vec::new();
        while let Some(chunk) = read_frame(&mut windowed, &mut recv, &mut scratch) {
            sizes.push(chunk.len());
            got.extend_from_slice(chunk);
        }
        assert_eq!(sizes, lens, "every datagram stayed its own frame");
        assert_eq!(got, plain, "and the window opened the whole wire, in order");
        assert_eq!(
            carrier.reads, 2,
            "one read fills the window for all ten frames and one says the carrier is over"
        );

        let mut bare = Sealed {
            held: sealed,
            at: 0,
            grain: usize::MAX,
            reads: 0,
        };
        let (_, _, mut second) = frames(&lens);
        let mut had = 0;
        let mut back = Vec::new();
        while let Some(chunk) = read_frame(&mut bare, &mut second, &mut scratch) {
            had += 1;
            back.extend_from_slice(chunk);
        }
        assert_eq!(had, lens.len(), "the window opened what it did not read");
        assert_eq!(back, plain);
        assert_eq!(
            bare.reads,
            2 * lens.len() + 1,
            "without the window the same wire asks twice per frame: the length, then the body"
        );
    }

    #[test]
    fn a_frame_window_serves_the_frames_that_straddle_its_refills() {
        let lens: Vec<usize> = (500..510).collect();
        let (sealed, plain, mut recv) = frames(&lens);
        let mut carrier = Sealed {
            held: sealed,
            at: 0,
            grain: 700,
            reads: 0,
        };
        let mut windowed = Buffered::new(&mut carrier);
        let mut got = Vec::new();
        let mut sizes = Vec::new();
        let mut scratch = Vec::new();
        while let Some(chunk) = read_frame(&mut windowed, &mut recv, &mut scratch) {
            sizes.push(chunk.len());
            got.extend_from_slice(chunk);
        }
        assert_eq!(
            sizes, lens,
            "a frame cut across a refill still ends at its own length"
        );
        assert_eq!(got, plain);
        assert!(
            carrier.reads > 2,
            "the carrier handed short reads, so the window refilled"
        );
    }

    #[test]
    fn a_refill_that_parks_serves_no_stale_bytes() {
        // The leg's carrier is a poll-armed socket, and `read_exact` asks again after an expiry rather than ending the leg, so a refill that waits must leave the window exactly where it was.
        struct Stalling {
            held: Vec<u8>,
            at: usize,
            grain: usize,
            waits: usize,
            reads: usize,
        }

        impl Read for Stalling {
            fn read(&mut self, dst: &mut [u8]) -> std::io::Result<usize> {
                self.reads += 1;
                if self.reads == self.waits {
                    return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
                }
                let take = self.grain.min(self.held.len() - self.at).min(dst.len());
                dst[..take].copy_from_slice(&self.held[self.at..self.at + take]);
                self.at += take;
                Ok(take)
            }
        }

        let lens: Vec<usize> = (500..510).collect();
        let (sealed, plain, mut recv) = frames(&lens);
        let mut carrier = Stalling {
            held: sealed,
            at: 0,
            grain: 700,
            waits: 2,
            reads: 0,
        };
        let mut windowed = Buffered::new(&mut carrier);
        let mut got = Vec::new();
        let mut sizes = Vec::new();
        let mut scratch = Vec::new();
        while let Some(chunk) = read_frame(&mut windowed, &mut recv, &mut scratch) {
            sizes.push(chunk.len());
            got.extend_from_slice(chunk);
        }
        assert_eq!(
            sizes, lens,
            "the window refilled after the wait and lost no frame"
        );
        assert_eq!(
            got, plain,
            "a refill that waited replayed no byte the first window had already served"
        );
        assert!(
            carrier.reads > 2,
            "the wait is the second ask, and the wire only ends after the refill that follows it"
        );
    }

    #[test]
    fn the_datagram_pump_reads_the_carrier_through_its_window() {
        // The pumps are what the row is about: a datagram leg that framed every packet with its own two asks would read the carrier twice per frame however the window is built.
        struct Counted {
            held: Vec<u8>,
            at: usize,
            reads: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        }

        impl Read for Counted {
            fn read(&mut self, dst: &mut [u8]) -> std::io::Result<usize> {
                self.reads
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let take = (self.held.len() - self.at).min(dst.len());
                dst[..take].copy_from_slice(&self.held[self.at..self.at + take]);
                self.at += take;
                Ok(take)
            }
        }

        let lens: Vec<usize> = (500..510).collect();
        let (sealed, plain, _recv) = frames(&lens);
        let target = UdpSocket::bind("127.0.0.1:0").expect("binds the target");
        let target_addr = target.local_addr().expect("addr");
        target
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("arms the read");
        let reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let carrier = Counted {
            held: sealed,
            at: 0,
            reads: std::sync::Arc::clone(&reads),
        };
        let key = [0x55u8; 16];
        let iv = [0x66u8; 16];
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let send = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
        let (_, _, recv) = frames(&lens);
        let close: Close = std::sync::Arc::new(|| {});
        let udp = UdpSocket::bind("127.0.0.1:0").expect("binds the uplink");
        udp.connect(target_addr).expect("connects");
        let meter = crate::stats::Meter::default();
        crate::proxy::pump_vmess_udp(carrier, Vec::new(), &close, &udp, send, recv, &meter);

        let mut sizes = Vec::new();
        let mut got = Vec::new();
        let mut buf = vec![0u8; 65535];
        for _ in &lens {
            let n = target.recv(&mut buf).expect("a datagram arrives");
            sizes.push(n);
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(sizes, lens, "one VMess frame per datagram, in order");
        assert_eq!(got, plain);
        assert_eq!(
            reads.load(std::sync::atomic::Ordering::Relaxed),
            2,
            "the pump asked the carrier for the window once, and once more to learn it is over"
        );
        assert_eq!(
            udp.read_timeout().expect("the read window the pump armed"),
            Some(crate::budgets::RELAY_POLL),
            "the lane waits in the kernel for a datagram instead of sleeping between polls"
        );
    }

    #[test]
    fn kdf_is_stable_and_keyed() {
        let a = kdf(b"key", &[b"path"]);
        assert_eq!(a, kdf(b"key", &[b"path"]));
        assert_ne!(a, kdf(b"other", &[b"path"]));
        assert_ne!(a, kdf(b"key", &[b"other"]));
    }

    #[test]
    fn kdf_matches_the_oracle_vectors() {
        fn hex(bytes: &[u8]) -> String {
            let mut out = String::new();
            for b in bytes {
                out.push("0123456789abcdef".as_bytes()[(b >> 4) as usize] as char);
                out.push("0123456789abcdef".as_bytes()[(b & 15) as usize] as char);
            }
            out
        }
        assert_eq!(
            hex(&md5::compute(b"abc").0),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            hex(&kdf(b"key", &[b"path"])),
            "f5952ea326376193226ffe760d8aa2ad8587c6a0cc7c32efeda02eb0b5d430ed"
        );
        assert_eq!(
            hex(&kdf(
                b"key",
                &[
                    b"VMess Header AEAD Key_Length",
                    b"authid1234567890",
                    b"nonce123"
                ]
            )),
            "fa9ff42e922d36e727fe11148c5bfae1e57feb2a8bc5671be1014e8a5554c70a"
        );
        assert_eq!(
            hex(&kdf16(b"test-instruction-16", &[b"AES Auth ID Encryption"])),
            "a69474c1eddf8c94283389cc76ac64be"
        );
        let uuid: [u8; 16] = [
            0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3,
            0x08, 0x11,
        ];
        assert_eq!(
            hex(&instruction_key(&uuid)),
            "b50d916ac0cec067981af8e5f38a758f"
        );
    }

    #[test]
    fn handshake_relay_round_trips() {
        use std::io::{Read as _, Write as _};
        let id = [0xabu8; 16];
        let echo = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let server = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = server.accept().expect("accepts");
            super::serve(stream, &Users::single(id), true);
        });
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let mut uplink = Connection::connect(("127.0.0.1", port)).expect("connects");
        let (mut send, mut recv, response_key, response_iv, auth) = super::client_handshake(
            &mut uplink,
            &id,
            Cipher::Auto,
            false,
            false,
            &crate::proxy::Destination::from(target),
        )
        .expect("handshakes");
        assert!(super::read_response(
            &mut uplink,
            &response_key,
            &response_iv,
            auth
        ));
        let mut staging = Vec::new();
        let mut pad = PadSource::fresh().expect("entropy");
        assert!(write_frame(
            &mut uplink,
            &mut send,
            b"ping",
            &mut staging,
            &mut pad
        ));
        let mut scratch = Vec::new();
        let back = read_frame(&mut uplink, &mut recv, &mut scratch).expect("reads");
        assert_eq!(back, b"ping");
    }

    #[test]
    fn response_prefix_is_stable() {
        let prefix = response_prefix(&[0x71u8; 16], &[0x72u8; 16], 0xAB).expect("prefixes");
        assert_eq!(prefix.len(), 38);
        assert_eq!(
            prefix,
            [
                0xab, 0xe4, 0x1f, 0x65, 0xdb, 0xa0, 0x80, 0xd4, 0xcc, 0x9d, 0x50, 0xd3, 0x0a, 0xda,
                0x8b, 0x09, 0xaa, 0x89, 0x82, 0xf9, 0xa8, 0xfe, 0x3d, 0xf3, 0x20, 0xc3, 0x7b, 0x61,
                0xcd, 0x45, 0x4e, 0x47, 0x98, 0x8d, 0x4a, 0xf9, 0x11, 0xd7,
            ]
        );
    }

    #[test]
    fn a_response_header_reads_without_allocating() {
        let key = [0x71u8; 16];
        let iv = [0x72u8; 16];
        let wire = response_prefix(&key, &iv, 0xAB).expect("prefixes");
        let mut reader = std::io::Cursor::new(wire);
        let (opened, counts) = ferrox_core::alloc_count::measure(|| {
            super::read_response_header(&mut reader, &key, &iv, 0xAB)
        });
        assert!(opened, "the sealed header opens");
        assert_eq!(counts.allocs, 0, "the response header is read on the stack");
    }

    #[test]
    fn batched_draws_keep_the_reference_stream() {
        use sha3::digest::{ExtendableOutput as _, Update as _, XofReader as _};
        let iv = [0x4du8; 16];
        for (padding, masked) in [(false, true), (true, true), (true, false)] {
            let mut raw = shake::Shake128::default();
            raw.update(&iv);
            let mut raw = raw.finalize_xof();
            let mut wrapped = Shake::fresh(&iv, padding, masked);
            for _ in 0..200 {
                if padding {
                    if masked {
                        let mut want = [0u8; 4];
                        raw.read(&mut want);
                        assert_eq!(
                            wrapped.draws(),
                            (
                                u16::from_be_bytes([want[0], want[1]]),
                                u16::from_be_bytes([want[2], want[3]])
                            )
                        );
                    } else {
                        let mut want = [0u8; 2];
                        raw.read(&mut want);
                        assert_eq!(
                            wrapped.draw(),
                            u16::from_be_bytes(want),
                            "an authenticated length draws only padding"
                        );
                    }
                } else {
                    let mut want = [0u8; 2];
                    raw.read(&mut want);
                    assert_eq!(wrapped.draws(), (0, u16::from_be_bytes(want)));
                }
            }
        }
    }

    #[test]
    fn frames_seal_to_stable_bytes() {
        let cases = [
            (
                Cipher::Chacha,
                [
                    0x15, 0xe6, 0x71, 0x0e, 0x43, 0x79, 0x84, 0x37, 0x1c, 0xc5, 0xf6, 0x4d, 0xd4,
                    0x8f, 0x7c, 0xc4, 0x58, 0x69, 0xc8, 0xeb, 0xec,
                ],
            ),
            (
                Cipher::Aes,
                [
                    0xc9, 0x02, 0x32, 0x56, 0x14, 0x1e, 0xff, 0x1c, 0xe0, 0xfc, 0x09, 0xbf, 0x9f,
                    0xc1, 0xa9, 0x16, 0xfc, 0xeb, 0x35, 0xbd, 0x5a,
                ],
            ),
        ];
        for (cipher, golden) in cases {
            let mut flow = Flow::fresh(
                cipher,
                &[0x55u8; 16],
                &[0x66u8; 16],
                OPT_STREAM,
                &[0x66u8; 16],
            )
            .expect("fresh");
            let mut sealed = Vec::new();
            flow.seal_onto(b"hello", &mut sealed);
            assert_eq!(sealed, golden);
            let mut recv = Flow::fresh(
                cipher,
                &[0x55u8; 16],
                &[0x66u8; 16],
                OPT_STREAM,
                &[0x66u8; 16],
            )
            .expect("fresh");
            let back = recv.open_chunk(&mut sealed).expect("opens");
            assert_eq!(&sealed[..back], b"hello");
        }
    }

    #[test]
    fn seal_open_round_trips_every_length_and_cipher() {
        let lens = [
            0, 1, 2, 15, 16, 17, 31, 32, 63, 64, 65, 127, 128, 255, 256, 1000, 1023, 1024, 4095,
            4096, 8191, 8192, 8193, 16383, 16384, 20000,
        ];
        for cipher in [Cipher::Chacha, Cipher::Aes, Cipher::None] {
            let tag = if cipher == Cipher::None { 0 } else { TAG_LEN };
            for &len in &lens {
                let plain: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                let mut send = Flow::fresh(
                    cipher,
                    &[0x55u8; 16],
                    &[0x66u8; 16],
                    OPT_STREAM,
                    &[0x66u8; 16],
                )
                .expect("sends");
                let mut recv = Flow::fresh(
                    cipher,
                    &[0x55u8; 16],
                    &[0x66u8; 16],
                    OPT_STREAM,
                    &[0x66u8; 16],
                )
                .expect("recvs");
                let mut sealed = Vec::new();
                send.seal_onto(&plain, &mut sealed);
                assert_eq!(sealed.len(), plain.len() + tag);
                let back = recv.open_chunk(&mut sealed).expect("opens");
                assert_eq!(back, plain.len());
                assert_eq!(&sealed[..back], &plain[..]);
            }
        }
    }

    #[test]
    fn masked_frames_carry_every_length() {
        let lens = [0, 1, 100, 8191, 8192, 8193, 20000];
        for cipher in [Cipher::Chacha, Cipher::Aes, Cipher::None] {
            let options = OPT_STREAM | OPT_MASK | OPT_PAD;
            let payloads: Vec<Vec<u8>> = lens
                .iter()
                .map(|&len| (0..len).map(|i| (i % 251) as u8).collect())
                .collect();
            let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
            let port = listener.local_addr().expect("addr").port();
            let writer = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accepts");
                let mut recv =
                    Flow::fresh(cipher, &[0x55u8; 16], &[0x66u8; 16], options, &[0x66u8; 16])
                        .expect("recvs");
                let mut all = Vec::new();
                let mut scratch = Vec::new();
                for _ in &lens {
                    let chunk = read_frame(&mut stream, &mut recv, &mut scratch).expect("reads");
                    all.extend_from_slice(chunk);
                }
                all
            });
            let mut uplink = Connection::connect(("127.0.0.1", port)).expect("connects");
            let mut send =
                Flow::fresh(cipher, &[0x55u8; 16], &[0x66u8; 16], options, &[0x66u8; 16])
                    .expect("sends");
            let mut want = Vec::new();
            let mut staging = Vec::new();
            let mut pad = PadSource::fresh().expect("entropy");
            for plain in &payloads {
                assert!(write_frame(
                    &mut uplink,
                    &mut send,
                    plain,
                    &mut staging,
                    &mut pad
                ));
                want.extend_from_slice(plain);
            }
            assert_eq!(writer.join().expect("joins"), want);
        }
    }

    #[test]
    fn counters_advance_one_per_frame_at_any_offset() {
        for cipher in [Cipher::Chacha, Cipher::Aes] {
            for &at in &[0u16, 1, 255, 256, 1000, 32767, 32768, 65533, 65534, 65535] {
                let mut send = Flow::fresh(
                    cipher,
                    &[0x55u8; 16],
                    &[0x66u8; 16],
                    OPT_STREAM,
                    &[0x66u8; 16],
                )
                .expect("sends");
                let mut recv = Flow::fresh(
                    cipher,
                    &[0x55u8; 16],
                    &[0x66u8; 16],
                    OPT_STREAM,
                    &[0x66u8; 16],
                )
                .expect("recvs");
                send.counter = at;
                recv.counter = at;
                let mut first = [0u8; 12];
                first.copy_from_slice(send.nonce());
                let mut sealed = Vec::new();
                send.seal_onto(b"ping", &mut sealed);
                let back = recv.open_chunk(&mut sealed).expect("opens");
                assert_eq!(&sealed[..back], b"ping");
                assert_eq!(send.counter, at.wrapping_add(1));
                assert_eq!(recv.counter, at.wrapping_add(1));
                assert_ne!(send.nonce(), &first);
            }
        }
    }

    #[test]
    fn counter_wrap_matches_the_reference() {
        for cipher in [Cipher::Chacha, Cipher::Aes] {
            let mut send = Flow::fresh(
                cipher,
                &[0x55u8; 16],
                &[0x66u8; 16],
                OPT_STREAM,
                &[0x66u8; 16],
            )
            .expect("fresh");
            let mut recv = Flow::fresh(
                cipher,
                &[0x55u8; 16],
                &[0x66u8; 16],
                OPT_STREAM,
                &[0x66u8; 16],
            )
            .expect("fresh");
            send.counter = u16::MAX;
            recv.counter = u16::MAX;
            let mut sealed = Vec::new();
            send.seal_onto(b"ping", &mut sealed);
            assert_eq!(send.counter, 0);
            let back = recv.open_chunk(&mut sealed).expect("opens across the wrap");
            assert_eq!(&sealed[..back], b"ping");
            assert_eq!(recv.counter, 0);
            let mut sealed = Vec::new();
            send.seal_onto(b"pong", &mut sealed);
            let back = recv.open_chunk(&mut sealed).expect("opens after the wrap");
            assert_eq!(&sealed[..back], b"pong");
        }
    }

    #[test]
    fn wire_codes_and_security_words_map_exactly() {
        assert_eq!(Cipher::from_code(3), Some(Cipher::Aes));
        assert_eq!(Cipher::from_code(4), Some(Cipher::Chacha));
        assert_eq!(Cipher::from_code(5), Some(Cipher::None));
        for code in [0, 1, 2, 6, 7, 255] {
            assert!(Cipher::from_code(code).is_none());
        }
        assert_eq!(Cipher::parse("auto"), Cipher::Auto);
        assert_eq!(Cipher::parse("AUTO"), Cipher::Auto);
        assert_eq!(Cipher::parse("aes-128-gcm"), Cipher::Aes);
        assert_eq!(Cipher::parse("AES-128-GCM"), Cipher::Aes);
        assert_eq!(Cipher::parse("chacha20-poly1305"), Cipher::Chacha);
        assert_eq!(Cipher::parse("chacha20-ietf-poly1305"), Cipher::Chacha);
        assert_eq!(Cipher::parse("none"), Cipher::None);
        assert_eq!(Cipher::parse("NONE"), Cipher::None);
        assert_eq!(Cipher::parse("garbage"), Cipher::Auto);
        assert_eq!(Cipher::parse(""), Cipher::Auto);
    }

    /// The invariant the "auto" resolution must not break: whichever cipher a machine resolves for the header byte, the payload flows seal with the same one — a peer reads the byte and decrypts the body to match — and it holds whether this runner resolves "auto" to AES or to `ChaCha`.
    #[test]
    fn the_header_cipher_byte_matches_the_flow_cipher() {
        for cipher in [Cipher::Auto, Cipher::Aes, Cipher::Chacha] {
            let flow = Flow::fresh(
                cipher,
                &[0x55u8; 16],
                &[0x66u8; 16],
                OPT_STREAM,
                &[0x66u8; 16],
            )
            .expect("fresh");
            assert_eq!(
                Cipher::from_code(cipher.code()),
                Some(flow.cipher),
                "{cipher:?} header byte and flow cipher disagree"
            );
        }
    }

    #[test]
    fn tampered_seals_do_not_open() {
        for cipher in [Cipher::Chacha, Cipher::Aes] {
            let key = [0x33u8; 16];
            let nonce = [0x44u8; 12];
            let sealed = seal_header(&key, &nonce, b"length-is-framing", b"aad").expect("seals");
            for at in [0, sealed.len() / 2, sealed.len() - 1] {
                let mut cut = sealed.clone();
                cut[at] ^= 1;
                assert!(open_header(&key, &nonce, &cut, b"aad").is_none());
            }
            assert!(open_header(&key, &nonce, &sealed, b"wrong").is_none());
            assert!(open_header(&[0x34u8; 16], &nonce, &sealed, b"aad").is_none());
            assert!(open_header(&key, &nonce, &sealed[..sealed.len() - 1], b"aad").is_none());
            let mut send = Flow::fresh(
                cipher,
                &[0x55u8; 16],
                &[0x66u8; 16],
                OPT_STREAM,
                &[0x66u8; 16],
            )
            .expect("sends");
            let mut frame = Vec::new();
            send.seal_onto(b"ping", &mut frame);
            let mut recv = Flow::fresh(
                cipher,
                &[0x55u8; 16],
                &[0x66u8; 16],
                OPT_STREAM,
                &[0x66u8; 16],
            )
            .expect("recvs");
            frame[0] ^= 1;
            assert!(recv.open_chunk(&mut frame).is_none());
        }
    }

    #[test]
    fn expired_auth_ids_are_refused() {
        let instruction = instruction_key(&[0x22u8; 16]);
        let key = AuthKey::new(&instruction);
        let seal = |ago: u64| {
            let mut plain = [0u8; 16];
            plain[..8].copy_from_slice(&now_secs().saturating_sub(ago).to_be_bytes());
            plain[8..12].copy_from_slice(&[9u8, 8, 7, 6]);
            let checksum = crc32(&plain[..12]).to_be_bytes();
            plain[12..].copy_from_slice(&checksum);
            key.seal(&mut plain);
            plain
        };
        assert!(valid_auth_id(&key, &seal(0)));
        assert!(valid_auth_id(&key, &seal(119)));
        assert!(!valid_auth_id(&key, &seal(121)));
        assert!(!valid_auth_id(&key, &seal(3600)));
    }

    #[test]
    fn replays_close_on_second_use() {
        let id = [0x77u8; AUTH_LEN];
        assert!(!replay_seen(&id));
        assert!(replay_seen(&id));
    }

    #[test]
    fn the_window_refuses_a_replay_for_its_span_and_forgets_after_two() {
        let mut window = crate::proxy::Replay::new(REPLAY_SPAN);
        let key = [0x5eu8; 32];
        assert!(
            !window.seen(&key, 10_000),
            "a first sighting is not a replay"
        );
        assert!(
            window.seen(&key, 10_000 + REPLAY_SPAN - 1),
            "the span the auth id is valid for is refused"
        );
        assert!(
            window.seen(&key, 10_000 + REPLAY_SPAN),
            "the rotation that moves the key out of the window is the one after it"
        );
        assert!(
            !window.seen(&key, 10_000 + 2 * REPLAY_SPAN),
            "two spans of quiet empty the window"
        );
    }

    #[test]
    fn the_history_refuses_a_session_within_its_lifetime() {
        let mut history = SessionHistory::new(10_000);
        let user = [0x11u8; 16];
        let session = [0x42u8; 32];
        assert!(!history.seen(&user, &session, 10_000), "a first sighting");
        assert!(
            history.seen(&user, &session, 10_000 + SESSION_LIFETIME - 1),
            "inside the lifetime"
        );
        assert!(
            !history.seen(&user, &session, 10_000 + SESSION_LIFETIME),
            "the lifetime forgets it"
        );
    }

    #[test]
    fn the_history_names_the_user_and_the_body_material() {
        let mut history = SessionHistory::new(10_000);
        let user = [0x11u8; 16];
        let session = [0x42u8; 32];
        assert!(!history.seen(&user, &session, 10_000));
        for part in [0usize, 16] {
            let mut other = session;
            other[part] ^= 1;
            assert!(
                !history.seen(&user, &other, 10_000),
                "partition {part} is a different session"
            );
            assert!(history.seen(&user, &other, 10_000));
        }
        let mut other_user = user;
        other_user[0] ^= 1;
        assert!(
            !history.seen(&other_user, &session, 10_000),
            "another account holds another history"
        );
        assert!(history.seen(&user, &session, 10_000));
    }

    #[test]
    fn one_account_cannot_spend_another_accounts_histories() {
        let mut history = SessionHistory::new(10_000);
        let user = [0x11u8; 16];
        for index in 0..SESSION_KEYS {
            let mut session = [0u8; 32];
            session[..8].copy_from_slice(&(index as u64).to_be_bytes());
            assert!(!history.seen(&user, &session, 10_000));
        }
        let mut fresh = [0u8; 32];
        fresh[0] = 0xff;
        assert!(
            history.seen(&user, &fresh, 10_000),
            "a full history refuses its own new session"
        );
        let other_user = [0x22u8; 16];
        assert!(
            !history.seen(&other_user, &fresh, 10_000),
            "another account still has its own admission"
        );
        assert!(
            history.seen(&other_user, &fresh, 10_000),
            "and that account holds its record"
        );
    }

    #[test]
    fn the_history_sweeps_its_expired_entries() {
        let mut history = SessionHistory::new(10_000);
        let user = [0x11u8; 16];
        let session = [0x33u8; 32];
        assert!(!history.seen(&user, &session, 10_000));
        assert!(
            history.seen(&user, &session, 10_000 + SESSION_LIFETIME - 1),
            "still live at the edge"
        );
        assert_eq!(history.by_account[&user].len(), 1);
        assert!(!history.seen(&user, &session, 10_000 + SESSION_LIFETIME));
        assert_eq!(
            history.by_account[&user].len(),
            1,
            "the sweep frees before the fresh insert"
        );
        assert!(
            history.by_account[&user].capacity() < 64,
            "the sweep shrinks the map toward what it holds"
        );
    }

    #[test]
    fn the_window_holds_two_rotations_at_most() {
        let mut window = crate::proxy::Replay::new(REPLAY_SPAN);
        let first = [0u8; 32];
        assert!(!window.seen(&first, 5_000));
        for index in 1..=2 * crate::proxy::REPLAY_KEYS {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&(index as u64).to_be_bytes());
            window.seen(&key, 5_000);
            assert!(
                window.held() <= 2 * crate::proxy::REPLAY_KEYS,
                "{index} keys"
            );
        }
        assert!(
            !window.seen(&first, 5_000),
            "a flood rotates the oldest keys out without the clock moving"
        );
    }

    #[test]
    fn clear_headers_decode_and_reject() {
        let target: SocketAddr = "127.0.0.1:8080".parse().expect("addr");
        let mut header = vec![1u8];
        header.extend_from_slice(&[0x01u8; 16]);
        header.extend_from_slice(&[0x02u8; 16]);
        header.push(0x03);
        header.push(OPT_STREAM | OPT_MASK | OPT_PAD);
        header.push(0x04);
        header.push(0);
        header.push(1);
        header.extend_from_slice(&target.port().to_be_bytes());
        header.push(1);
        header.extend_from_slice(&[127, 0, 0, 1]);
        header.extend_from_slice(&fnv1a(&header).to_be_bytes());
        let (got, _send, _recv, prefix, cmd) = decode_header(&header).expect("decodes");
        assert_eq!(got, target);
        assert_eq!(cmd, 1);
        assert_eq!(prefix.len(), 38);
        let mut bad = header.clone();
        bad[0] = 2;
        assert!(decode_header(&bad).is_none());
        let mut udp = header.clone();
        udp[37] = 2;
        let cut = udp.len() - 4;
        let sum = fnv1a(&udp[..cut]);
        udp[cut..].copy_from_slice(&sum.to_be_bytes());
        let (got, _, _, _, cmd) = decode_header(&udp).expect("decodes udp");
        assert_eq!(got, target);
        assert_eq!(cmd, 2);
        let mut bad = header.clone();
        bad[37] = 5;
        assert!(decode_header(&bad).is_none());
        let mut bad = header.clone();
        bad[35] = 0x07;
        assert!(decode_header(&bad).is_none());
        let mut bad = header.clone();
        bad[34] &= !OPT_STREAM;
        assert!(decode_header(&bad).is_none());
        let mut bad = header.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(decode_header(&bad).is_none());
        let mut bad = header.clone();
        bad[35] = 0xF4;
        assert!(decode_header(&bad).is_none());
        assert!(decode_header(&header[..header.len() - 1]).is_none());
    }

    #[test]
    fn the_option_byte_has_four_named_bits() {
        let target: SocketAddr = "127.0.0.1:8080".parse().expect("addr");
        let header = |cipher: u8, options: u8| {
            let mut header = vec![1u8];
            header.extend_from_slice(&[0x01u8; 16]);
            header.extend_from_slice(&[0x02u8; 16]);
            header.push(0x03);
            header.push(options);
            header.push(cipher);
            header.push(0);
            header.push(1);
            header.extend_from_slice(&target.port().to_be_bytes());
            header.push(1);
            header.extend_from_slice(&[127, 0, 0, 1]);
            header.extend_from_slice(&fnv1a(&header).to_be_bytes());
            header
        };
        // The bit names a framing both directions carry: a frame's size field is the sealed 18 octets, not the two masked ones.
        for options in [
            OPT_STREAM | OPT_AUTH_LEN | OPT_MASK,
            OPT_STREAM | OPT_AUTH_LEN | OPT_MASK | OPT_PAD,
        ] {
            let (_, send, recv, _, _) = decode_header(&header(0x04, options)).expect("decodes");
            assert_eq!(send.size_field(), SIZE_FIELD);
            assert_eq!(recv.size_field(), SIZE_FIELD);
        }
        // Padding is drawn from the masking parser, so without the mask bit the reference has no generator to build.
        assert!(
            decode_header(&header(0x04, OPT_STREAM | OPT_AUTH_LEN | OPT_PAD)).is_none(),
            "padding without a mask"
        );
        assert!(
            decode_header(&header(0x04, OPT_STREAM | OPT_PAD)).is_none(),
            "padding without a mask, authenticated length off"
        );
        // A body without a cipher leaves the sealed size without a key, and the reference refuses the option there too.
        assert!(decode_header(&header(0x05, OPT_STREAM | OPT_AUTH_LEN)).is_none());
        // A 2-octet size field stays the way the bit has always framed it.
        let (_, send, recv, _, _) =
            decode_header(&header(0x04, OPT_STREAM | OPT_MASK | OPT_PAD)).expect("decodes");
        assert_eq!(send.size_field(), HEADER_LEN);
        assert_eq!(recv.size_field(), HEADER_LEN);
    }

    #[test]
    fn an_authenticated_length_peer_is_read_like_any_other() {
        let target: SocketAddr = "127.0.0.1:8080".parse().expect("addr");
        let header = |cipher: u8, options: u8| {
            let mut header = vec![1u8];
            header.extend_from_slice(&[0x01u8; 16]);
            header.extend_from_slice(&[0x02u8; 16]);
            header.push(0x03);
            header.push(options);
            header.push(cipher);
            header.push(0);
            header.push(1);
            header.extend_from_slice(&target.port().to_be_bytes());
            header.push(1);
            header.extend_from_slice(&[127, 0, 0, 1]);
            header.extend_from_slice(&fnv1a(&header).to_be_bytes());
            header
        };
        let payload: Vec<u8> = (0..300).map(|k| k as u8).collect();
        for cipher in [Cipher::Aes, Cipher::Chacha] {
            for options in [
                OPT_STREAM | OPT_AUTH_LEN,
                OPT_STREAM | OPT_AUTH_LEN | OPT_MASK,
                OPT_STREAM | OPT_AUTH_LEN | OPT_MASK | OPT_PAD,
            ] {
                let mut send = Flow::fresh(cipher, &[0x02; 16], &[0x01; 16], options, &[0x01; 16])
                    .expect("sends");
                send.len_seal = SizeAead::fresh(&[0x02; 16], cipher, &[0x01; 16]);
                let mut sealed = Vec::new();
                let mut pad = PadSource::fresh().expect("entropy");
                assert!(
                    stage_frame(&mut send, &payload, &mut sealed, &mut pad),
                    "payload"
                );
                assert!(stage_frame(&mut send, &[], &mut sealed, &mut pad), "marker");
                let mut recv = Flow::fresh(cipher, &[0x02; 16], &[0x01; 16], options, &[0x01; 16])
                    .expect("recvs");
                recv.len_seal = SizeAead::fresh(&[0x02; 16], cipher, &[0x01; 16]);
                let mut read = &sealed[..];
                {
                    let mut scratch = Vec::new();
                    let opened = read_frame(&mut read, &mut recv, &mut scratch).expect("opens");
                    assert_eq!(opened, &payload, "the plain bytes behind the sealed size");
                    let marker = read_frame(&mut read, &mut recv, &mut scratch).expect("ends");
                    assert!(marker.is_empty(), "the zero body is the end");
                }
                let carrier = Sealed {
                    held: sealed.clone(),
                    at: 0,
                    grain: usize::MAX,
                    reads: 0,
                };
                let (_writes, got) = drain(&mut Wire::new(carrier), &mut {
                    let mut wire_recv =
                        Flow::fresh(cipher, &[0x02; 16], &[0x01; 16], options, &[0x01; 16])
                            .expect("recvs");
                    wire_recv.len_seal = SizeAead::fresh(&[0x02; 16], cipher, &[0x01; 16]);
                    wire_recv
                });
                assert_eq!(got, payload, "the wire opens the same frames");

                // The staged framing is a server's response framing here: the body AEAD rides the response material while the sealed size rides the request's keys (`proxy/vmess/encoding/server.go` `EncodeResponseBody`), so a peer sealing the size with the wrong pair cannot open it.
                let head = header(cipher.code(), options);
                let (_, mut srv, _, _, _) = decode_header(&head).expect("decodes");
                let (response_key, response_iv) = response_material(&[0x01; 16], &[0x02; 16]);
                let mut peer =
                    Flow::fresh(cipher, &response_key, &response_iv, options, &response_iv)
                        .expect("peer");
                peer.len_seal = SizeAead::fresh(&[0x02; 16], cipher, &[0x01; 16]);
                let mut staged = Vec::new();
                let mut pad = PadSource::fresh().expect("entropy");
                assert!(
                    stage_frame(&mut srv, &payload, &mut staged, &mut pad),
                    "staged"
                );
                let mut read = &staged[..];
                let mut scratch = Vec::new();
                let opened = read_frame(&mut read, &mut peer, &mut scratch).expect("opens");
                assert_eq!(
                    opened, &payload,
                    "the request's keys seal the response sizes"
                );
                let mut wrong =
                    Flow::fresh(cipher, &response_key, &response_iv, options, &response_iv)
                        .expect("peer");
                wrong.len_seal = SizeAead::fresh(&response_key, cipher, &response_iv);
                let mut read = &staged[..];
                assert!(
                    read_frame(&mut read, &mut wrong, &mut Vec::new()).is_none(),
                    "the size field will not open under the response pair"
                );
            }
        }
    }

    #[test]
    fn the_client_asks_for_the_authenticated_length_experiment() {
        let target: SocketAddr = "127.0.0.1:8080".parse().expect("addr");
        let target = crate::proxy::Destination::from(target);
        for cipher in [Cipher::Aes, Cipher::Chacha] {
            for auth_len in [false, true] {
                for no_termination in [false, true] {
                    let (_, send, recv, _, _, _) =
                        client_request(&[0x31; 16], cipher, auth_len, no_termination, &target, 1)
                            .expect("the client builds the account's framing");
                    let width = if auth_len { SIZE_FIELD } else { HEADER_LEN };
                    assert_eq!(send.size_field(), width, "{cipher:?} {auth_len}");
                    assert_eq!(recv.size_field(), width, "{cipher:?} {auth_len}");
                    assert_eq!(
                        send.end_marker, !no_termination,
                        "the account's termination signal rides the sending flow"
                    );
                }
            }
        }
        assert!(
            client_request(&[0x31; 16], Cipher::None, true, false, &target, 1).is_none(),
            "the authenticated length has no key under none"
        );
    }

    #[test]
    fn requests_open_to_their_own_lengths_and_targets() {
        let uuid = [0xabu8; 16];
        let targets = [
            "127.0.0.1:8080".parse::<SocketAddr>().expect("addr"),
            "[::1]:443".parse::<SocketAddr>().expect("addr"),
        ];
        for cipher in [Cipher::Auto, Cipher::Aes, Cipher::Chacha, Cipher::None] {
            for target in targets {
                let (request, _, _, _) = request_bytes(
                    &uuid,
                    cipher,
                    false,
                    &crate::proxy::Destination::from(target),
                    1,
                )
                .expect("builds");
                assert!(request.len() > 42 + TAG_LEN);
                let instruction = instruction_key(&uuid);
                let auth_id: [u8; AUTH_LEN] = request[..AUTH_LEN].try_into().expect("auth");
                let nonce = &request[16 + 18..16 + 18 + 8];
                let len_key = kdf16(
                    &instruction,
                    &[b"VMess Header AEAD Key_Length", &auth_id, nonce],
                );
                let len_full = kdf(
                    &instruction,
                    &[b"VMess Header AEAD Nonce_Length", &auth_id, nonce],
                );
                let len_nonce: [u8; 12] = len_full[..12].try_into().expect("nonce");
                let clear_len =
                    open_header(&len_key, &len_nonce, &request[16..34], &auth_id).expect("opens");
                assert_eq!(
                    usize::from(u16::from_be_bytes([clear_len[0], clear_len[1]])),
                    request.len() - 42 - TAG_LEN
                );
                let head_key = kdf16(&instruction, &[b"VMess Header AEAD Key", &auth_id, nonce]);
                let head_full = kdf(&instruction, &[b"VMess Header AEAD Nonce", &auth_id, nonce]);
                let head_nonce: [u8; 12] = head_full[..12].try_into().expect("nonce");
                let clear =
                    open_header(&head_key, &head_nonce, &request[42..], &auth_id).expect("opens");
                let (got, _, _, _, _) = decode_header(&clear).expect("decodes");
                assert_eq!(got, target);
            }
        }
    }

    #[test]
    fn garbage_short_and_wrong_user_close_fast() {
        let id = [0xabu8; 16];
        let server = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in server.incoming().take(3) {
                let Ok(stream) = stream else { continue };
                thread::spawn(move || super::serve(stream, &Users::single(id), true));
            }
        });
        let mut refused = 0;
        for body in [
            vec![0u8; 16],
            request_bytes(
                &[0xccu8; 16],
                Cipher::Auto,
                false,
                &"127.0.0.1:1".parse().expect("addr"),
                1,
            )
            .expect("builds")
            .0,
            request_bytes(
                &id,
                Cipher::Auto,
                false,
                &"127.0.0.1:1".parse().expect("addr"),
                1,
            )
            .expect("builds")
            .0[..20]
                .to_vec(),
        ] {
            let mut stream = Connection::connect(("127.0.0.1", port)).expect("connects");
            stream.write_all(&body).expect("writes");
            let _ = stream.shutdown(std::net::Shutdown::Write);
            let mut back = [0u8; 1];
            match stream.read(&mut back) {
                Ok(0) | Err(_) => refused += 1,
                Ok(_) => {}
            }
        }
        assert_eq!(refused, 3);
    }

    #[test]
    fn the_chacha_data_frames_are_the_crate_it_replaced() {
        use chacha20poly1305::aead::AeadInOut;
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _, Nonce};

        let data_key = [0x3cu8; 16];
        let data_iv: [u8; 16] = std::array::from_fn(|i| 0x10u8.wrapping_add(i as u8));
        let options = OPT_STREAM | OPT_MASK;

        let want_key: [u8; 32] = [
            0x8c, 0xad, 0xb9, 0xb0, 0x5f, 0xd7, 0x0f, 0x16, 0xab, 0x6b, 0xea, 0xd8, 0x48, 0x90,
            0x14, 0x5d, 0xf7, 0xa8, 0xe4, 0xab, 0xb4, 0x63, 0x92, 0x9f, 0x06, 0x32, 0x00, 0xed,
            0x60, 0x0b, 0xf6, 0xa5,
        ];
        assert_eq!(
            chacha_key(&data_key),
            want_key,
            "the data key is md5(key) then md5 of that, concatenated"
        );

        for len in (0..=40usize).chain([63, 64, 65, 127, 128, 129, 1024, 4096]) {
            let plain: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(61).wrapping_add(5))
                .collect();

            let mut flow = Flow::fresh(Cipher::Chacha, &data_key, &data_iv, options, &data_iv)
                .expect("a chacha flow");
            let cipher = ChaCha20Poly1305::new_from_slice(&want_key).expect("crate key");

            for frame in 0..3u8 {
                let nonce = flow.nonce();
                let mut want_nonce = [0u8; 12];
                want_nonce[..2].copy_from_slice(&(frame as u16).to_be_bytes());
                want_nonce[2..].copy_from_slice(&data_iv[2..12]);
                assert_eq!(
                    *nonce, want_nonce,
                    "frame {frame}: counter then the iv tail"
                );
                let mut ours = Vec::new();
                flow.seal_onto(&plain, &mut ours);

                let mut want = plain.clone();
                let want_tag = cipher
                    .encrypt_inout_detached(
                        &Nonce::try_from(&want_nonce[..]).expect("length"),
                        b"",
                        (&mut want[..]).into(),
                    )
                    .expect("crate seals");
                assert_eq!(
                    ours,
                    [want.as_slice(), want_tag.as_slice()].concat(),
                    "length {len} frame {frame} is the crate's bytes"
                );

                let mut recv = Flow::fresh(Cipher::Chacha, &data_key, &data_iv, options, &data_iv)
                    .expect("a chacha flow");
                for _ in 0..frame {
                    recv.counter += 1;
                }
                let n = recv.open_chunk(&mut ours).expect("opens");
                assert_eq!(n, len, "length {len} frame {frame} opens to its own length");
                assert_eq!(
                    &recv.nonce[2..],
                    &data_iv[2..12],
                    "opening does not disturb the iv"
                );
            }
        }
    }

    /// A carrier that hands over what it holds, `grain` bytes per read, and counts the asks.
    /// An in-memory one, because over a socket the scheduler decides how many frames arrive
    /// together and a count there is a measurement of the machine, not of this code.
    struct Sealed {
        held: Vec<u8>,
        at: usize,
        grain: usize,
        reads: usize,
    }

    impl crate::proxy::RelayPoll for Sealed {
        /// Memory never waits, so there is no poll to arm.
        fn arm_relay_poll(&mut self) {}
    }

    impl Read for Sealed {
        fn read(&mut self, dst: &mut [u8]) -> std::io::Result<usize> {
            self.reads += 1;
            let take = self.grain.min(self.held.len() - self.at).min(dst.len());
            dst[..take].copy_from_slice(&self.held[self.at..self.at + take]);
            self.at += take;
            Ok(take)
        }
    }

    /// Frames sealed exactly as the write side seals them, with the plaintext they carry.
    fn frames(lens: &[usize]) -> (Vec<u8>, Vec<u8>, Flow) {
        frames_with(lens, OPT_STREAM | OPT_MASK | OPT_PAD)
    }

    fn frames_with(lens: &[usize], options: u8) -> (Vec<u8>, Vec<u8>, Flow) {
        let key = [0x55u8; 16];
        let iv = [0x66u8; 16];
        let mut send = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
        let mut recv = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("recvs");
        if options & OPT_AUTH_LEN != 0 {
            let seal = || SizeAead::fresh(&key, Cipher::Chacha, &iv).expect("a size aead");
            send.len_seal = Some(seal());
            recv.len_seal = Some(seal());
        }
        let mut pad = PadSource::fresh().expect("entropy");
        let mut sealed = Vec::new();
        let mut plain = Vec::new();
        for (i, &len) in lens.iter().enumerate() {
            let body: Vec<u8> = (0..len).map(|k| (k as u8).wrapping_add(i as u8)).collect();
            assert!(
                stage_frame(&mut send, &body, &mut sealed, &mut pad),
                "seals {i}"
            );
            plain.extend_from_slice(&body);
        }
        (sealed, plain, recv)
    }

    /// Drain a pump the way a relay does, counting the writes its batches would become.
    fn drain(wire: &mut Wire<Sealed>, recv: &mut Flow) -> (usize, Vec<u8>) {
        let mut writes = 0;
        let mut got = Vec::new();
        while let Some(batch) = wire.batch(recv) {
            if batch.is_empty() {
                continue;
            }
            writes += 1;
            got.extend_from_slice(batch);
        }
        (writes, got)
    }

    /// The flow's windows are not zeroed: the wire's receive window and the relay leg's
    /// read window are both read targets, so the zero pass in front of them was work
    /// generated and thrown away. The counting allocator's `zeroed` counter is the witness.
    #[test]
    fn the_flows_windows_are_not_zero_filled() {
        let (sealed, _plain, _recv) = frames(&[1000; 3]);
        let carrier = Sealed {
            held: sealed,
            at: 0,
            grain: usize::MAX,
            reads: 0,
        };
        let (wire, counts) = ferrox_core::alloc_count::measure(|| Wire::new(carrier));
        assert_eq!(counts.zeroed, 0, "the wire's window is not zeroed");
        assert_eq!(counts.allocs, 1, "the wire's window is the only allocation");
        assert_eq!(
            counts.bytes, WIRE_LEN,
            "and it is the window the wire reads into"
        );
        drop(wire);
        let (window, counts) = ferrox_core::alloc_count::measure(relay_window);
        assert_eq!(counts.zeroed, 0, "the relay leg's window is not zeroed");
        assert_eq!(
            counts.allocs, 1,
            "the relay leg's window is the only allocation"
        );
        assert_eq!(
            counts.bytes, READ_PLAIN,
            "and it is the window the leg reads into"
        );
        drop(window);
    }

    #[test]
    fn a_batch_of_frames_leaves_the_pump_in_one_write() {
        for options in [
            OPT_STREAM | OPT_MASK | OPT_PAD,
            OPT_STREAM | OPT_MASK | OPT_PAD | OPT_AUTH_LEN,
        ] {
            let (sealed, plain, mut recv) =
                frames_with(&vec![MAX_PLAIN; FRAMES_PER_WRITE * 2 + 1], options);
            let carrier = Sealed {
                held: sealed,
                at: 0,
                grain: usize::MAX,
                reads: 0,
            };
            let mut wire = Wire::new(carrier);
            let (writes, got) = drain(&mut wire, &mut recv);
            assert_eq!(
                writes, 3,
                "a batch takes at most FRAMES_PER_WRITE frames, so they leave as {FRAMES_PER_WRITE}, {FRAMES_PER_WRITE} and 1"
            );
            assert_eq!(got, plain, "and every byte of them, in order");
            assert_eq!(
                wire.carrier.reads, 2,
                "the stream is read once, plus the read that finds its end"
            );
        }
    }

    #[test]
    fn a_dribbled_carrier_still_offers_one_frame_and_loses_nothing() {
        let (sealed, plain, mut recv) = frames(&[1000; 9]);
        let carrier = Sealed {
            held: sealed,
            at: 0,
            grain: 3,
            reads: 0,
        };
        let mut wire = Wire::new(carrier);
        let (writes, got) = drain(&mut wire, &mut recv);
        assert_eq!(
            writes, 9,
            "a carrier that gives three bytes at a time never holds a second frame, so nothing waits"
        );
        assert_eq!(got, plain, "and the bytes are the same bytes");
    }

    #[test]
    fn a_one_frame_batch_is_handed_over_where_it_opened() {
        let (sealed, plain, mut recv) = frames(&[1000; 3]);
        let carrier = Sealed {
            held: sealed,
            at: 0,
            grain: 3,
            reads: 0,
        };
        let mut wire = Wire::new(carrier);
        let base = wire.held.as_ptr() as usize;
        let limit = base + wire.held.len();
        let mut got = Vec::new();
        while let Some(batch) = wire.batch(&mut recv) {
            if batch.is_empty() {
                continue;
            }
            let at = batch.as_ptr() as usize;
            assert!(at > base, "a one-frame batch was gathered to the front");
            assert!(
                at + batch.len() <= limit,
                "the batch left the pump's buffer"
            );
            got.extend_from_slice(batch);
        }
        assert_eq!(got, plain);
    }

    #[test]
    fn the_pump_gathers_into_its_own_buffer_and_never_moves_it() {
        let (sealed, plain, mut recv) = frames(&[1000; 3]);
        let head: [u8; HEADER_LEN] = sealed[..HEADER_LEN].try_into().expect("a size field");
        let carrier = Sealed {
            held: sealed,
            at: 0,
            grain: usize::MAX,
            reads: 0,
        };
        let mut wire = Wire::new(carrier);
        let cap = wire.held.capacity();
        let base = wire.held.as_ptr() as usize;
        let mut batches = 0;
        let mut got = Vec::new();
        while let Some(batch) = wire.batch(&mut recv) {
            if batch.is_empty() {
                continue;
            }
            let (front, len) = (batch.as_ptr() as usize, batch.len());
            got.extend_from_slice(batch);
            assert_eq!(
                front,
                base + HEADER_LEN,
                "the batch was moved to the front instead of gathered where its first frame opened"
            );
            assert_eq!(
                &wire.held[..HEADER_LEN],
                &head,
                "the first frame still sits behind the batch, so nothing relocated it"
            );
            assert_eq!(
                wire.held.as_ptr() as usize,
                base,
                "the pump moved its buffer"
            );
            assert_eq!(wire.held.capacity(), cap, "the pump grew its buffer");
            assert_eq!(got.len(), len, "and the whole batch was handed over");
            batches += 1;
        }
        assert_eq!(batches, 1, "three frames together are one write");
        assert_eq!(got, plain);
    }

    #[test]
    fn an_end_marker_mid_batch_sends_what_the_batch_already_holds() {
        let (mut sealed, plain, mut recv) = frames(&[1000, 1000]);
        let key = [0x55u8; 16];
        let iv = [0x66u8; 16];
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let mut send = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
        let mut pad = PadSource::fresh().expect("entropy");
        assert!(
            stage_frame(&mut send, &[], &mut sealed, &mut pad),
            "seals the marker"
        );
        let carrier = Sealed {
            held: sealed,
            at: 0,
            grain: usize::MAX,
            reads: 0,
        };
        let mut wire = Wire::new(carrier);
        let (writes, got) = drain(&mut wire, &mut recv);
        assert_eq!(
            writes, 1,
            "the two frames that came first are not lost to the marker"
        );
        assert_eq!(got, plain);
    }

    #[test]
    fn only_the_marker_marks_a_stream_as_ended_by_its_peer() {
        let (sealed, plain, mut recv) = frames(&[4]);
        let mut wire = Wire::new(Sealed {
            held: sealed,
            at: 0,
            grain: usize::MAX,
            reads: 0,
        });
        let (_, got) = drain(&mut wire, &mut recv);
        assert_eq!(got, plain);
        assert!(
            !wire.ended_by_marker(),
            "a carrier that ends is not the peer's marker"
        );

        let key = [0x55u8; 16];
        let iv = [0x66u8; 16];
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let mut sender = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
        let mut pad = PadSource::fresh().expect("entropy");
        let mut marker = Vec::new();
        assert!(
            stage_frame(&mut sender, &[], &mut marker, &mut pad),
            "seals the marker"
        );
        let mut recv = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("recvs");
        let mut wire = Wire::new(Sealed {
            held: marker,
            at: 0,
            grain: usize::MAX,
            reads: 0,
        });
        assert_eq!(drain(&mut wire, &mut recv).1, Vec::<u8>::new());
        assert!(
            wire.ended_by_marker(),
            "the zero-length frame is the peer's end"
        );
    }

    /// A write half the relay seals into, kept so the test can open it after the pump returns.
    struct Collected(std::sync::Arc<Mutex<Vec<u8>>>);

    impl Write for Collected {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("lock").extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A not-ready answer read is a wait, not a failed handshake: the same step resumes it.
    #[test]
    fn a_not_ready_answer_read_resumes_instead_of_failing() {
        struct Late(Vec<u8>, bool);

        impl Read for Late {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                if !self.1 {
                    self.1 = true;
                    return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
                }
                let read = buffer.len().min(self.0.len());
                buffer[..read].copy_from_slice(&self.0[..read]);
                self.0.drain(..read);
                Ok(read)
            }
        }

        let key = [0x31u8; 16];
        let iv = [0x32u8; 16];
        let auth = 5;
        let prefix = response_prefix(&key, &iv, auth).expect("seals the answer");
        let mut answer = Answer::new((key, iv, auth));
        assert!(
            matches!(answer.step(&mut Late(prefix, false)), AnswerStep::Done),
            "a WouldBlock read failed the answer instead of resuming it"
        );
    }

    #[test]
    fn a_peer_that_ends_its_upload_with_the_marker_still_gets_the_download() {
        let key = [0x55u8; 16];
        let iv = [0x66u8; 16];
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let mut sender = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
        let mut pad = PadSource::fresh().expect("entropy");
        let mut marker = Vec::new();
        assert!(
            stage_frame(&mut sender, &[], &mut marker, &mut pad),
            "seals the upload marker"
        );
        let send = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
        let recv = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("recvs");

        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let target = thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accepts");
            let mut buf = [0u8; 16];
            let mut uploaded = 0usize;
            loop {
                match socket.read(&mut buf) {
                    Ok(0) => break,
                    Ok(read) => uploaded += read,
                    Err(error) => panic!("target read: {error:?}"),
                }
            }
            assert_eq!(
                uploaded, 0,
                "the upload ended at its marker, not with bytes"
            );
            socket.write_all(b"pong").expect("writes");
            let _ = socket.shutdown(std::net::Shutdown::Write);
        });

        let uplink = Connection::connect(("127.0.0.1", port)).expect("connects");
        let out = std::sync::Arc::new(Mutex::new(Vec::new()));
        let carrier = Sealed {
            held: marker,
            at: 0,
            grain: usize::MAX,
            reads: 0,
        };
        let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(|| {});
        pump_relay_carried(
            &uplink,
            carrier,
            Collected(std::sync::Arc::clone(&out)),
            &close,
            send,
            recv,
            None,
        )
        .expect("clones the plain socket")
        .wait();
        target.join().expect("joins");

        let mut answer = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("answers");
        let mut wire = Wire::new(Cursor::new(out.lock().expect("lock").clone()));
        let mut got = Vec::new();
        while let Some(batch) = wire.batch(&mut answer) {
            got.extend_from_slice(batch);
        }
        assert_eq!(
            got, b"pong",
            "the download survives the upload's marker and arrives after it"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_live_vmess_session_costs_no_thread() {
        if !crate::conn::in_a_quiet_process("vmess::tests::a_live_vmess_session_costs_no_thread") {
            return;
        }
        let key = [0x91u8; 16];
        let iv = [0x92u8; 16];
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(|| {});
        // Warm the lane pool: a session that finds it built adds no worker of its own.
        {
            let (plain, peer) = socket_pair();
            let (sealed, client) = socket_pair();
            let writer = sealed.try_clone().expect("clones the carrier");
            let send = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
            let recv = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("recvs");
            let flow = pump_relay_carried(&plain, sealed, writer, &close, send, recv, None)
                .expect("clones the plain socket");
            drop(peer);
            drop(client);
            flow.wait();
        }
        let before = crate::conn::live_threads();
        let mut held = Vec::new();
        for _ in 0..8 {
            let (plain, peer) = socket_pair();
            let (sealed, client) = socket_pair();
            let writer = sealed.try_clone().expect("clones the carrier");
            let send = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
            let recv = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("recvs");
            let flow = pump_relay_carried(&plain, sealed, writer, &close, send, recv, None)
                .expect("clones the plain socket");
            held.push((flow, peer, client));
        }
        let after = crate::conn::live_threads();
        assert!(
            after - before < 8,
            "eight live sessions added {} threads",
            after - before
        );
        drop(held);
    }

    fn socket_pair() -> (Connection, Connection) {
        let listener = crate::conn::test_bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let dialled = Connection::connect(("127.0.0.1", port)).expect("connects");
        let (accepted, _) = listener.accept().expect("accepts");
        (dialled, accepted)
    }

    #[test]
    fn a_peer_that_ends_its_download_with_the_marker_still_takes_the_upload() {
        let key = [0x55u8; 16];
        let iv = [0x66u8; 16];
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let mut sender = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
        let mut pad = PadSource::fresh().expect("entropy");
        let mut marker = Vec::new();
        assert!(
            stage_frame(&mut sender, &[], &mut marker, &mut pad),
            "seals the download marker"
        );
        let send = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
        let recv = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("recvs");

        let (plain, mut client) = socket_pair();
        let (sealed, mut server) = socket_pair();
        let relay = thread::spawn(move || pump_relay(&plain, &sealed, send, recv, None));

        server.write_all(&marker).expect("writes the marker");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("arms");
        let mut byte = [0u8; 1];
        assert_eq!(
            client.read(&mut byte).expect("reads the half-close"),
            0,
            "the marker ends the download"
        );

        let _ = client.write_all(b"ping");
        let _ = client.shutdown(Shutdown::Write);

        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("arms");
        let mut uploader = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("recvs");
        let mut scratch = Vec::new();
        let upload =
            read_frame(&mut server, &mut uploader, &mut scratch).expect("the upload survives");
        assert_eq!(upload, b"ping");
        let end = read_frame(&mut server, &mut uploader, &mut scratch).expect("the upload marker");
        assert_eq!(end, b"");
        relay.join().expect("joins");
    }

    struct DelayedSealed {
        inner: Sealed,
        delay: Duration,
        armed: bool,
    }

    impl Read for DelayedSealed {
        fn read(&mut self, dst: &mut [u8]) -> std::io::Result<usize> {
            if !self.armed {
                thread::sleep(self.delay);
                self.armed = true;
            }
            self.inner.read(dst)
        }
    }

    impl crate::proxy::RelayPoll for DelayedSealed {
        fn arm_relay_poll(&mut self) {}
    }

    #[test]
    fn a_target_that_ends_its_download_still_takes_the_upload() {
        let key = [0x55u8; 16];
        let iv = [0x66u8; 16];
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let mut sender = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
        let mut pad = PadSource::fresh().expect("entropy");
        let mut upload = Vec::new();
        assert!(
            stage_frame(&mut sender, b"ping", &mut upload, &mut pad),
            "seals the upload"
        );
        assert!(
            stage_frame(&mut sender, &[], &mut upload, &mut pad),
            "seals the upload marker"
        );

        let (plain, mut target) = socket_pair();
        target
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("arms");
        target
            .shutdown(Shutdown::Write)
            .expect("the target ends its download");

        let out = std::sync::Arc::new(Mutex::new(Vec::new()));
        let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(|| {});
        let send = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
        let recv = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("recvs");
        let flow = pump_relay_carried(
            &plain,
            DelayedSealed {
                inner: Sealed {
                    held: upload,
                    at: 0,
                    grain: usize::MAX,
                    reads: 0,
                },
                delay: Duration::from_millis(500),
                armed: false,
            },
            Collected(std::sync::Arc::clone(&out)),
            &close,
            send,
            recv,
            None,
        )
        .expect("clones the plain socket");
        flow.wait();

        let mut got = [0u8; 4];
        target
            .read_exact(&mut got)
            .expect("the upload survives the target's clean end");
        assert_eq!(&got, b"ping");
    }

    #[test]
    fn an_account_without_the_termination_signal_ends_without_the_marker() {
        let key = [0x55u8; 16];
        let iv = [0x66u8; 16];
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        for no_termination in [false, true] {
            let (mut plain, mut target) = socket_pair();
            plain
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("arms");
            target.write_all(b"x").expect("writes the download");
            target.shutdown(Shutdown::Write).expect("ends the download");

            let out = std::sync::Arc::new(Mutex::new(Vec::new()));
            let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(|| {});
            let flow = crate::proxy::RelayFinish::new(false, std::sync::Arc::clone(&close), None);
            let mut send = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
            send.end_marker = !no_termination;
            let mut buf = relay_window();
            let mut staging = Vec::new();
            let mut pad = PadSource::fresh().expect("entropy");
            let mut writer = Collected(std::sync::Arc::clone(&out));
            let mut done = false;
            let mut deferred = None;
            for _ in 0..4 {
                let (next, _) = forward_step(
                    &mut plain,
                    &mut buf,
                    &mut writer,
                    &mut send,
                    &mut staging,
                    &mut deferred,
                    &mut pad,
                    &close,
                    &flow,
                );
                if next == Next::Done {
                    done = true;
                    break;
                }
            }
            assert!(done, "the clean end is a Done step");

            let held = out.lock().expect("lock").clone();
            let mut peer = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("recvs");
            let mut wire = Wire::new(Sealed {
                held,
                at: 0,
                grain: usize::MAX,
                reads: 0,
            });
            let mut got = Vec::new();
            while let Some(batch) = wire.batch(&mut peer) {
                got.extend_from_slice(batch);
            }
            assert_eq!(got, b"x", "the payload arrives either way");
            assert_eq!(
                wire.ended_by_marker(),
                !no_termination,
                "only an account that keeps the signal closes with the marker"
            );
        }
    }

    #[test]
    fn the_relay_carries_both_directions() {
        let key = [0x77u8; 16];
        let iv = [0x88u8; 16];
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let send = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
        let recv = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("recvs");
        let (plain, mut target) = socket_pair();
        let (sealed, mut client) = socket_pair();
        let relay = thread::spawn(move || pump_relay(&plain, &sealed, send, recv, None));

        let mut uploader = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("seals");
        let mut pad = PadSource::fresh().expect("entropy");
        let mut wire = Vec::new();
        assert!(
            stage_frame(&mut uploader, b"hello", &mut wire, &mut pad),
            "seals the upload"
        );
        client.write_all(&wire).expect("writes the upload");

        let mut buf = [0u8; 5];
        target
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("arms");
        target.read_exact(&mut buf).expect("reads the upload");
        assert_eq!(&buf, b"hello");

        target.write_all(b"world").expect("writes the download");
        target.shutdown(Shutdown::Write).expect("ends the download");

        let mut decoder = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("opens");
        let mut scratch = Vec::new();
        let download =
            read_frame(&mut client, &mut decoder, &mut scratch).expect("reads the download");
        assert_eq!(download, b"world");

        client.shutdown(Shutdown::Write).expect("ends the upload");
        relay.join().expect("joins");
    }

    /// A silent h2 stream authenticates under the handshake clock: its reader polls, and the handler
    /// ends at the budget instead of waiting the relay stall for a body that never comes.
    #[test]
    fn a_silent_h2_request_ends_at_the_handshake_budget() {
        struct Silent(Arc<std::sync::atomic::AtomicBool>);

        impl Read for Silent {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                assert!(
                    crate::proxy::relay_step_owns_poll(),
                    "an h2 authentication read ran outside the poll"
                );
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
                Err(std::io::ErrorKind::WouldBlock.into())
            }
        }

        impl crate::proxy::WindowRead for Silent {
            fn read_window(&mut self) -> std::io::Result<crate::proxy::Window<'_>> {
                unreachable!("authentication reads through Read")
            }
        }

        struct Sink;

        impl std::io::Write for Sink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl crate::proxy::FrameWrite for Sink {
            fn write_slices(&mut self, _: &[&[u8]]) -> bool {
                true
            }
        }

        let polled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let close: Close = Arc::new({
            let closed = Arc::clone(&closed);
            move || closed.store(true, std::sync::atomic::Ordering::SeqCst)
        });
        let _cap = crate::budgets::cap_handshake(Duration::from_millis(20));
        let began = std::time::Instant::now();
        serve_xhttp_accepted(
            Box::new(Silent(Arc::clone(&polled))),
            crate::xhttp::XhttpWriter::new(Sink),
            &Users::single([0x55u8; 16]),
            true,
            &close,
        );
        assert!(polled.load(std::sync::atomic::Ordering::SeqCst));
        assert!(closed.load(std::sync::atomic::Ordering::SeqCst));
        assert!(began.elapsed() < Duration::from_secs(2));
    }
}

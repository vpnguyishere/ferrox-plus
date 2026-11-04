use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

use aes::Aes256;
use chacha20poly1305::aead::AeadInOut as _;
use ctr::cipher::{KeyIvInit as _, StreamCipher as _};
use ml_kem::kem::{Decapsulate as _, Kem as _, Key as MlKemKey};
use ml_kem::KeyExport as _;
use ml_kem::{EncapsulationKey768, MlKem768};
use x25519_dalek::{PublicKey, StaticSecret};

const HEADER_LEN: usize = 5;
const TAG_LEN: usize = 16;
const MAX_RECORD_PLAINTEXT: usize = 8192;
const MAX_BATCH_PLAINTEXT: usize = 8 * MAX_RECORD_PLAINTEXT;
const MIN_RECORD: usize = 1 + TAG_LEN;
const MAX_RECORD: usize = 16640;
const X25519_LEN: usize = 32;
const MLKEM_EK_LEN: usize = 1184;
const MLKEM_CT_LEN: usize = 1088;
const MAX_NONCE: [u8; 12] = [0xff; 12];

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn random_bytes<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|_| io::Error::other("no entropy"))?;
    Ok(bytes)
}

fn rand_between(from: u32, to: u32) -> u32 {
    let (from, to) = if from > to { (to, from) } else { (from, to) };
    if from == to {
        return from;
    }
    rand::random_range(from..to)
}

fn encode_length(len: usize) -> [u8; 2] {
    [(len >> 8) as u8, len as u8]
}

fn decode_length(bytes: &[u8]) -> usize {
    (usize::from(bytes[0]) << 8) | usize::from(bytes[1])
}

fn decode_header(header: &[u8]) -> Option<usize> {
    let len = (usize::from(header[3]) << 8) | usize::from(header[4]);
    if header[..3] != [23, 3, 3] || !(MIN_RECORD..=MAX_RECORD).contains(&len) {
        return None;
    }
    Some(len)
}

fn inc_nonce(nonce: &mut [u8; 12]) {
    for byte in nonce.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

enum Cipher {
    Aes(crate::aesgcm::Aes256Gcm),
    ChaCha(Box<chacha20poly1305::ChaCha20Poly1305>),
}

struct Aead {
    cipher: Cipher,
    nonce: [u8; 12],
}

impl Aead {
    fn with_cipher(context: &[u8], key: &[u8], aes: bool) -> Self {
        let derived = derive_key(context, key);
        let cipher = if aes {
            Cipher::Aes(crate::aesgcm::Aes256Gcm::new(&derived))
        } else {
            use chacha20poly1305::KeyInit as _;
            Cipher::ChaCha(Box::new(
                chacha20poly1305::ChaCha20Poly1305::new_from_slice(&derived)
                    .expect("a 32-byte key is valid ChaCha20-Poly1305"),
            ))
        };
        Self {
            cipher,
            nonce: [0; 12],
        }
    }

    fn new(context: &[u8], key: &[u8]) -> Self {
        Self::with_cipher(context, key, crate::aesgcm::has_hardware_support())
    }

    fn derive(&self, context: &[u8], key: &[u8]) -> Self {
        Self::with_cipher(context, key, matches!(self.cipher, Cipher::Aes(_)))
    }

    fn is_aes(&self) -> bool {
        matches!(self.cipher, Cipher::Aes(_))
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        inc_nonce(&mut self.nonce);
        self.nonce
    }

    fn seal_into(
        &mut self,
        nonce: Option<[u8; 12]>,
        plaintext: &[u8],
        aad: &[u8],
        out: &mut Vec<u8>,
    ) {
        let nonce = nonce.unwrap_or_else(|| self.next_nonce());
        let start = out.len();
        out.extend_from_slice(plaintext);
        let tag = match &self.cipher {
            Cipher::Aes(cipher) => cipher.seal_in_place(&nonce, aad, &mut out[start..]),
            Cipher::ChaCha(cipher) => {
                let tag = cipher
                    .encrypt_inout_detached(
                        &chacha20poly1305::Nonce::try_from(&nonce[..]).expect("length"),
                        aad,
                        (&mut out[start..]).into(),
                    )
                    .expect("AEAD seal cannot fail for these sizes");
                let mut bytes = [0u8; TAG_LEN];
                bytes.copy_from_slice(&tag);
                bytes
            }
        };
        out.extend_from_slice(&tag);
    }

    fn open_in_place(
        &mut self,
        nonce: Option<[u8; 12]>,
        sealed: &mut [u8],
        aad: &[u8],
    ) -> io::Result<()> {
        let nonce = nonce.unwrap_or_else(|| self.next_nonce());
        if sealed.len() < TAG_LEN {
            return Err(invalid("VLESS encryption record is shorter than its tag"));
        }
        let split = sealed.len() - TAG_LEN;
        let (body, tag) = sealed.split_at_mut(split);
        let mut tag_bytes = [0u8; TAG_LEN];
        tag_bytes.copy_from_slice(tag);
        match &self.cipher {
            Cipher::Aes(cipher) => {
                if cipher
                    .open_in_place(&nonce, aad, body, &tag_bytes)
                    .is_none()
                {
                    return Err(invalid("VLESS encryption record failed authentication"));
                }
            }
            Cipher::ChaCha(cipher) => cipher
                .decrypt_inout_detached(
                    &chacha20poly1305::Nonce::try_from(&nonce[..]).expect("length"),
                    aad,
                    (&mut body[..]).into(),
                    &chacha20poly1305::Tag::try_from(&tag_bytes[..]).expect("length"),
                )
                .map_err(|_| invalid("VLESS encryption record failed authentication"))?,
        }
        Ok(())
    }
}

fn new_ctr(key: &[u8], iv: &[u8]) -> Aes256Ctr {
    let derived = derive_key(b"VLESS", key);
    Aes256Ctr::new_from_slices(&derived, &iv[..16]).expect("32-byte key and 16-byte iv")
}

#[derive(Clone)]
enum NfsKey {
    X25519([u8; 32]),
    MlKem(Box<EncapsulationKey768>),
}

impl NfsKey {
    fn relay_len(&self) -> usize {
        match self {
            NfsKey::X25519(_) => X25519_LEN,
            NfsKey::MlKem(_) => MLKEM_CT_LEN,
        }
    }
}

#[derive(Clone)]
pub struct ClientConfig {
    keys: Vec<NfsKey>,
    key_bytes: Vec<Vec<u8>>,
    hash32s: Vec<[u8; 32]>,
    relays_len: usize,
    xor_mode: u8,
    zero_rtt: bool,
    padding_lens: Vec<[u32; 3]>,
    padding_gaps: Vec<[u32; 3]>,
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("keys", &self.keys.len())
            .field("xor_mode", &self.xor_mode)
            .field("zero_rtt", &self.zero_rtt)
            .finish_non_exhaustive()
    }
}

impl ClientConfig {
    pub fn parse(value: &str) -> Result<Self, String> {
        use base64::Engine as _;
        let parts: Vec<&str> = value.split('.').collect();
        if parts.len() < 4 || parts[0] != "mlkem768x25519plus" {
            return Err(format!("unsupported VLESS encryption {value:?}"));
        }
        let xor_mode = match parts[1] {
            "native" => 0,
            "xorpub" => 1,
            "random" => 2,
            other => return Err(format!("unknown VLESS encryption mode {other:?}")),
        };
        let zero_rtt = match parts[2] {
            "1rtt" => false,
            "0rtt" => true,
            other => return Err(format!("unknown VLESS encryption RTT {other:?}")),
        };
        let mut padding = Vec::new();
        let mut key_bytes = Vec::new();
        for token in &parts[3..] {
            if token.len() < 20 {
                if !key_bytes.is_empty() {
                    return Err("VLESS encryption padding must come before the keys".into());
                }
                padding.push(*token);
                continue;
            }
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(token)
                .map_err(|_| "VLESS encryption key is not base64url".to_string())?;
            if bytes.len() != X25519_LEN && bytes.len() != MLKEM_EK_LEN {
                return Err(format!(
                    "VLESS encryption key is {} bytes; expected 32 or 1184",
                    bytes.len()
                ));
            }
            key_bytes.push(bytes);
        }
        if key_bytes.is_empty() {
            return Err("VLESS encryption has no key".into());
        }

        let mut keys = Vec::with_capacity(key_bytes.len());
        let mut hash32s = Vec::with_capacity(key_bytes.len());
        let mut relays_len = 0usize;
        for bytes in &key_bytes {
            if bytes.len() == X25519_LEN {
                keys.push(NfsKey::X25519(bytes.as_slice().try_into().unwrap()));
                relays_len += X25519_LEN + 32;
            } else {
                let encoded: MlKemKey<EncapsulationKey768> = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| "ML-KEM-768 key has the wrong length".to_string())?;
                let key = EncapsulationKey768::new(&encoded)
                    .map_err(|_| "ML-KEM-768 key is invalid".to_string())?;
                keys.push(NfsKey::MlKem(Box::new(key)));
                relays_len += MLKEM_CT_LEN + 32;
            }
            hash32s.push(*blake3::hash(bytes).as_bytes());
        }
        relays_len -= 32;

        let (padding_lens, padding_gaps) = parse_padding(&padding.join("."))?;
        Ok(Self {
            keys,
            key_bytes,
            hash32s,
            relays_len,
            xor_mode,
            zero_rtt,
            padding_lens,
            padding_gaps,
        })
    }

    /// The client a server string names: the inbound's public keys drive the dial's
    /// encapsulation, so a loopback re-inject runs the same handshake its listener expects.
    pub fn from_server(value: &str) -> Result<Self, String> {
        let server = ServerConfig::parse(value)?;
        let mut keys = Vec::with_capacity(server.public_keys.len());
        for bytes in &server.public_keys {
            if bytes.len() == X25519_LEN {
                keys.push(NfsKey::X25519(
                    bytes.as_slice().try_into().expect("32 bytes"),
                ));
            } else {
                let encoded: MlKemKey<EncapsulationKey768> = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| "ML-KEM-768 public key has the wrong length".to_string())?;
                let key = EncapsulationKey768::new(&encoded)
                    .map_err(|_| "ML-KEM-768 public key is invalid".to_string())?;
                keys.push(NfsKey::MlKem(Box::new(key)));
            }
        }
        Ok(Self {
            keys,
            key_bytes: server.public_keys,
            hash32s: server.hash32s,
            relays_len: server.relays_len,
            xor_mode: server.xor_mode,
            zero_rtt: false,
            padding_lens: server.padding_lens,
            padding_gaps: server.padding_gaps,
        })
    }
}

enum ServerKey {
    X25519(StaticSecret),
    MlKem(Box<ml_kem::DecapsulationKey768>),
}

pub struct ServerConfig {
    keys: Vec<ServerKey>,
    public_keys: Vec<Vec<u8>>,
    hash32s: Vec<[u8; 32]>,
    relays_len: usize,
    xor_mode: u8,
    seconds_from: i64,
    seconds_to: i64,
    padding_lens: Vec<[u32; 3]>,
    padding_gaps: Vec<[u32; 3]>,
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("keys", &self.keys.len())
            .field("xor_mode", &self.xor_mode)
            .finish_non_exhaustive()
    }
}

impl ServerConfig {
    pub fn parse(value: &str) -> Result<Self, String> {
        use base64::Engine as _;
        let parts: Vec<&str> = value.split('.').collect();
        if parts.len() < 4 || parts[0] != "mlkem768x25519plus" {
            return Err("unsupported VLESS decryption".into());
        }
        let xor_mode = match parts[1] {
            "native" => 0,
            "xorpub" => 1,
            "random" => 2,
            other => return Err(format!("unknown VLESS decryption mode {other:?}")),
        };
        let seconds = parts[2].strip_suffix('s').unwrap_or(parts[2]);
        let (seconds_from, seconds_to) = match seconds.split_once('-') {
            Some((from, to)) => (from, to),
            None => (seconds, "0"),
        };
        let number = |text: &str| {
            text.parse::<i64>()
                .ok()
                .filter(|seconds| *seconds >= 0)
                .ok_or_else(|| {
                    format!(
                        "VLESS decryption ticket time {:?} is not a number",
                        parts[2]
                    )
                })
        };
        let (seconds_from, seconds_to) = (number(seconds_from)?, number(seconds_to)?);

        let mut padding = Vec::new();
        let mut keys = Vec::new();
        let mut public_keys = Vec::new();
        let mut hash32s = Vec::new();
        let mut relays_len = 0usize;
        for token in &parts[3..] {
            if token.len() < 20 {
                if !keys.is_empty() {
                    return Err("VLESS decryption padding must come before the keys".into());
                }
                padding.push(*token);
                continue;
            }
            let bytes = zeroize::Zeroizing::new(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(token)
                    .map_err(|_| "VLESS decryption key is not base64url".to_string())?,
            );
            let (key, public) = match bytes.len() {
                32 => {
                    let secret = StaticSecret::from(
                        <[u8; 32]>::try_from(bytes.as_slice()).expect("32 bytes"),
                    );
                    let public = PublicKey::from(&secret).as_bytes().to_vec();
                    relays_len += X25519_LEN + 32;
                    (ServerKey::X25519(secret), public)
                }
                64 => {
                    let seed = ml_kem::Seed::try_from(bytes.as_slice())
                        .map_err(|_| "ML-KEM-768 seed has the wrong length".to_string())?;
                    let key = ml_kem::DecapsulationKey768::from_seed(seed);
                    let encoded = key.encapsulation_key().to_bytes();
                    let public: Vec<u8> = AsRef::<[u8]>::as_ref(&encoded).to_vec();
                    relays_len += MLKEM_CT_LEN + 32;
                    (ServerKey::MlKem(Box::new(key)), public)
                }
                other => {
                    return Err(format!(
                        "VLESS decryption key is {other} bytes; expected 32 or 64"
                    ))
                }
            };
            hash32s.push(*blake3::hash(&public).as_bytes());
            public_keys.push(public);
            keys.push(key);
        }
        if keys.is_empty() {
            return Err("VLESS decryption has no key".into());
        }
        relays_len -= 32;
        let (padding_lens, padding_gaps) = parse_padding(&padding.join("."))?;
        Ok(Self {
            keys,
            public_keys,
            hash32s,
            relays_len,
            xor_mode,
            seconds_from,
            seconds_to,
            padding_lens,
            padding_gaps,
        })
    }
}

type Padding = (Vec<[u32; 3]>, Vec<[u32; 3]>);

fn parse_padding(padding: &str) -> Result<Padding, String> {
    let mut lens = Vec::new();
    let mut gaps = Vec::new();
    if padding.is_empty() {
        return Ok((lens, gaps));
    }
    let mut max_len = 0u64;
    for (i, group) in padding.split('.').enumerate() {
        let fields: Vec<&str> = group.split('-').collect();
        if fields.len() < 3 || fields[..3].iter().any(|field| field.is_empty()) {
            return Err(format!("invalid VLESS padding group {group:?}"));
        }
        let mut y = [0u32; 3];
        for (slot, field) in y.iter_mut().zip(&fields[..3]) {
            *slot = field
                .parse()
                .map_err(|_| format!("invalid VLESS padding group {group:?}"))?;
        }
        if i == 0 && (y[0] < 100 || y[1] < 18 + 17 || y[2] < 18 + 17) {
            return Err("the first VLESS padding length must not be smaller than 35".into());
        }
        if i % 2 == 0 {
            max_len += u64::from(y[1].max(y[2]));
            lens.push(y);
        } else {
            gaps.push(y);
        }
    }
    if max_len > 18 + 65535 {
        return Err("total VLESS padding must not exceed 65553 bytes".into());
    }
    Ok((lens, gaps))
}

fn create_padding(
    padding_lens: &[[u32; 3]],
    padding_gaps: &[[u32; 3]],
) -> (usize, Vec<usize>, Vec<std::time::Duration>) {
    let default_lens = [[100, 111, 1111], [50, 0, 3333]];
    let default_gaps = [[75, 0, 111]];
    let (lens_spec, gaps_spec): (&[[u32; 3]], &[[u32; 3]]) = if padding_lens.is_empty() {
        (&default_lens, &default_gaps)
    } else {
        (padding_lens, padding_gaps)
    };
    let mut total = 0usize;
    let mut lens = Vec::with_capacity(lens_spec.len());
    for y in lens_spec {
        let len = if y[0] >= rand_between(0, 100) {
            rand_between(y[1], y[2]) as usize
        } else {
            0
        };
        lens.push(len);
        total += len;
    }
    let gaps = gaps_spec
        .iter()
        .map(|y| {
            let ms = if y[0] >= rand_between(0, 100) {
                rand_between(y[1], y[2])
            } else {
                0
            };
            std::time::Duration::from_millis(u64::from(ms))
        })
        .collect();
    (total, lens, gaps)
}

struct Ticket {
    expires: i64,
    pfs_key: Vec<u8>,
    value: [u8; 16],
}

impl Drop for Ticket {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.pfs_key.zeroize();
        self.value.zeroize();
    }
}

/// Seconds since the Unix epoch, supplied by the host: `ferrox-core` reads no clock.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

pub struct Client {
    config: ClientConfig,
    ticket: Mutex<Option<Ticket>>,
    clock: Clock,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Client {
    pub fn new(config: ClientConfig) -> Arc<Self> {
        Self::with_clock(config, Arc::new(|| 0))
    }

    /// A client whose tickets are timed by the host's clock.
    pub fn with_clock(config: ClientConfig, clock: Clock) -> Arc<Self> {
        Arc::new(Self {
            config,
            ticket: Mutex::new(None),
            clock,
        })
    }

    fn valid_ticket(&self) -> Option<(Vec<u8>, [u8; 16])> {
        let guard = self
            .ticket
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .as_ref()
            .filter(|ticket| (self.clock)() < ticket.expires)
            .map(|ticket| (ticket.pfs_key.clone(), ticket.value))
    }

    fn expire_ticket(&self, pfs_key: &[u8]) {
        let mut guard = self
            .ticket
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard
            .as_ref()
            .is_some_and(|ticket| ticket.pfs_key == pfs_key)
        {
            *guard = None;
        }
    }

    #[allow(clippy::too_many_lines)]
    pub fn handshake<S: Read + Write>(
        self: &Arc<Self>,
        mut inner: S,
    ) -> io::Result<EncryptedStream<S>> {
        let config = &self.config;
        let iv_and_relays_len = 16 + config.relays_len;
        let mut hello = vec![0u8; iv_and_relays_len];
        getrandom::fill(&mut hello[..16]).map_err(|_| io::Error::other("no entropy"))?;
        let iv: [u8; 16] = hello[..16].try_into().unwrap();

        let mut nfs_key = Vec::new();
        let mut last_ctr: Option<Aes256Ctr> = None;
        let mut offset = 16usize;
        for (j, key) in config.keys.iter().enumerate() {
            let index = key.relay_len();
            let relay = &mut hello[offset..];
            match key {
                NfsKey::X25519(public) => {
                    let secret = StaticSecret::from(random_bytes::<32>()?);
                    relay[..32].copy_from_slice(PublicKey::from(&secret).as_bytes());
                    let shared = secret.diffie_hellman(&PublicKey::from(*public));
                    if !shared.was_contributory() {
                        return Err(invalid("VLESS encryption X25519 key is degenerate"));
                    }
                    nfs_key = shared.as_bytes().to_vec();
                }
                NfsKey::MlKem(public) => {
                    let (ciphertext, shared) =
                        public.encapsulate_deterministic(&random_bytes()?.into());
                    relay[..MLKEM_CT_LEN].copy_from_slice(ciphertext.as_ref());
                    nfs_key = AsRef::<[u8]>::as_ref(&shared).to_vec();
                }
            }
            if config.xor_mode > 0 {
                new_ctr(&config.key_bytes[j], &iv).apply_keystream(&mut relay[..index]);
            }
            if let Some(ctr) = last_ctr.as_mut() {
                ctr.apply_keystream(&mut relay[..32]);
            }
            if j == config.keys.len() - 1 {
                break;
            }
            let mut ctr = new_ctr(&nfs_key, &iv);
            relay[index..index + 32].copy_from_slice(&config.hash32s[j + 1]);
            ctr.apply_keystream(&mut relay[index..index + 32]);
            last_ctr = Some(ctr);
            offset += index + 32;
        }
        let mut nfs_aead = Aead::new(&iv, &nfs_key);

        if config.zero_rtt {
            if let Some((pfs_key, ticket)) = self.valid_ticket() {
                nfs_aead.seal_into(None, &encode_length(32), &[], &mut hello);
                nfs_aead.seal_into(None, &ticket, &[], &mut hello);
                let ticket_context = hello[iv_and_relays_len + 18..].to_vec();
                let mut united_key = pfs_key.clone();
                united_key.extend_from_slice(&nfs_key);
                let aead = Aead::new(&ticket_context, &united_key);
                let out_ctr = (config.xor_mode == 2).then(|| new_ctr(&united_key, &iv));
                let in_ctr = (config.xor_mode == 2).then(|| new_ctr(&united_key, &iv));
                let skip = hello.len();
                let mut stream =
                    EncryptedStream::new(inner, united_key, aead, None, ReadStage::ServerRandom);
                stream.set_out_mask(HeaderMask::new(out_ctr, skip));
                if let Some(in_ctr) = in_ctr {
                    stream.set_in_mask(HeaderMask::new(Some(in_ctr), 0));
                }
                stream.set_zero_rtt(Arc::clone(self), pfs_key);
                stream.set_pre_write(hello);
                return Ok(stream);
            }
        }

        let pfs_len = MLKEM_EK_LEN + X25519_LEN;
        nfs_aead.seal_into(None, &encode_length(pfs_len + TAG_LEN), &[], &mut hello);
        let decapsulation_key = MlKem768::generate_keypair().0;
        let encapsulation_key = decapsulation_key.encapsulation_key().to_bytes();
        let x25519_secret = StaticSecret::from(random_bytes::<32>()?);
        let mut pfs_public = Vec::with_capacity(pfs_len);
        pfs_public.extend_from_slice(encapsulation_key.as_ref());
        pfs_public.extend_from_slice(PublicKey::from(&x25519_secret).as_bytes());
        nfs_aead.seal_into(None, &pfs_public, &[], &mut hello);

        let (padding_len, mut piece_lens, gaps) =
            create_padding(&config.padding_lens, &config.padding_gaps);
        let padding_len = padding_len.max(18);
        nfs_aead.seal_into(None, &encode_length(padding_len - 18), &[], &mut hello);
        let zeros = vec![0u8; padding_len - 18 - TAG_LEN];
        nfs_aead.seal_into(None, &zeros, &[], &mut hello);

        piece_lens[0] += hello.len() - padding_len;
        let mut sent = 0usize;
        for (i, len) in piece_lens.iter().enumerate() {
            if *len > 0 {
                inner.write_all(&hello[sent..sent + len])?;
                inner.flush()?;
                sent += len;
            }
            if let Some(gap) = gaps.get(i) {
                if !gap.is_zero() {
                    std::thread::sleep(*gap);
                }
            }
        }

        let mut server_pfs = vec![0u8; MLKEM_CT_LEN + X25519_LEN + TAG_LEN];
        inner.read_exact(&mut server_pfs)?;
        nfs_aead.open_in_place(Some(MAX_NONCE), &mut server_pfs, &[])?;
        let mlkem_key = decapsulation_key
            .decapsulate_slice(&server_pfs[..MLKEM_CT_LEN])
            .map_err(|_| invalid("ML-KEM-768 decapsulation failed"))?;
        let peer_x25519: [u8; 32] = server_pfs[MLKEM_CT_LEN..MLKEM_CT_LEN + 32]
            .try_into()
            .unwrap();
        let x25519_key = x25519_secret.diffie_hellman(&PublicKey::from(peer_x25519));
        if !x25519_key.was_contributory() {
            return Err(invalid("VLESS encryption server X25519 key is degenerate"));
        }
        let mut pfs_key = Vec::with_capacity(64);
        pfs_key.extend_from_slice(AsRef::<[u8]>::as_ref(&mlkem_key));
        pfs_key.extend_from_slice(x25519_key.as_bytes());
        let mut united_key = pfs_key.clone();
        united_key.extend_from_slice(&nfs_key);
        let aead = Aead::new(&pfs_public, &united_key);
        let mut peer_aead = Aead::new(&server_pfs[..MLKEM_CT_LEN + X25519_LEN], &united_key);

        let mut ticket = [0u8; 32];
        inner.read_exact(&mut ticket)?;
        peer_aead.open_in_place(None, &mut ticket, &[])?;
        let seconds = decode_length(&ticket);
        if config.zero_rtt && seconds > 0 {
            let mut guard = self
                .ticket
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *guard = Some(Ticket {
                expires: (self.clock)() + i64::try_from(seconds).unwrap_or(i64::MAX),
                pfs_key: pfs_key.clone(),
                value: ticket[..16].try_into().unwrap(),
            });
        }

        let mut length = [0u8; 18];
        inner.read_exact(&mut length)?;
        peer_aead.open_in_place(None, &mut length, &[])?;
        let server_padding = decode_length(&length);

        let mut stream = EncryptedStream::new(
            inner,
            united_key,
            aead,
            Some(peer_aead),
            ReadStage::ServerPadding(server_padding),
        );
        if config.xor_mode == 2 {
            stream.set_out_mask(HeaderMask::new(Some(new_ctr(stream.united_key(), &iv)), 0));
            stream.set_in_mask(HeaderMask::new(
                Some(new_ctr(stream.united_key(), &ticket[..16])),
                server_padding,
            ));
        }
        Ok(stream)
    }
}

struct Session {
    pfs_key: Vec<u8>,
    seen: HashSet<[u8; 32]>,
}

#[derive(Default)]
struct Tickets {
    expires: BinaryHeap<Reverse<(i64, [u8; 16])>>,
    sessions: HashMap<[u8; 16], Session>,
}

impl Tickets {
    fn sweep(&mut self, now: i64) {
        while let Some(Reverse((expires, ticket))) = self.expires.peek().copied() {
            if expires > now {
                break;
            }
            self.expires.pop();
            self.sessions.remove(&ticket);
        }
    }
}

pub struct Server {
    config: ServerConfig,
    tickets: Mutex<Tickets>,
    clock: Clock,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Server {
    pub fn new(config: ServerConfig) -> Arc<Self> {
        Self::with_clock(config, Arc::new(|| 0))
    }

    /// A server whose ticket lifetime is read from the host's clock.
    pub fn with_clock(config: ServerConfig, clock: Clock) -> Arc<Self> {
        Arc::new(Self {
            config,
            tickets: Mutex::new(Tickets::default()),
            clock,
        })
    }

    #[allow(clippy::too_many_lines)]
    pub fn handshake<S: Read + Write>(&self, mut inner: S) -> io::Result<EncryptedStream<S>> {
        let config = &self.config;
        let iv_and_relays_len = 16 + config.relays_len;
        let mut hello = vec![0u8; iv_and_relays_len];
        inner.read_exact(&mut hello)?;
        let iv: [u8; 16] = hello[..16].try_into().unwrap();

        let mut nfs_key = Vec::new();
        let mut last_ctr: Option<Aes256Ctr> = None;
        let mut offset = 16usize;
        for (j, key) in config.keys.iter().enumerate() {
            let index = match key {
                ServerKey::X25519(_) => X25519_LEN,
                ServerKey::MlKem(_) => MLKEM_CT_LEN,
            };
            if let Some(ctr) = last_ctr.as_mut() {
                ctr.apply_keystream(&mut hello[offset..offset + 32]);
            }
            if config.xor_mode > 0 {
                new_ctr(&config.public_keys[j], &iv)
                    .apply_keystream(&mut hello[offset..offset + index]);
            }
            match key {
                ServerKey::X25519(secret) => {
                    let peer: [u8; 32] = hello[offset..offset + 32].try_into().unwrap();
                    if peer[31] > 127 {
                        return Err(invalid(
                            "VLESS encryption: the peer's X25519 key has its top bit set",
                        ));
                    }
                    let shared = secret.diffie_hellman(&PublicKey::from(peer));
                    if !shared.was_contributory() {
                        return Err(invalid("VLESS encryption X25519 key is degenerate"));
                    }
                    nfs_key = shared.as_bytes().to_vec();
                }
                ServerKey::MlKem(key) => {
                    let shared = key
                        .decapsulate_slice(&hello[offset..offset + MLKEM_CT_LEN])
                        .map_err(|_| invalid("ML-KEM-768 decapsulation failed"))?;
                    nfs_key = AsRef::<[u8]>::as_ref(&shared).to_vec();
                }
            }
            if j == config.keys.len() - 1 {
                break;
            }
            offset += index;
            let mut ctr = new_ctr(&nfs_key, &iv);
            ctr.apply_keystream(&mut hello[offset..offset + 32]);
            if hello[offset..offset + 32] != config.hash32s[j + 1] {
                return Err(invalid(
                    "VLESS encryption: unexpected key hash in the relay chain",
                ));
            }
            offset += 32;
            last_ctr = Some(ctr);
        }

        let mut encrypted_length = [0u8; 18];
        inner.read_exact(&mut encrypted_length)?;
        let mut opened = None;
        for aes in [true, false] {
            let mut nfs_aead = Aead::with_cipher(&iv, &nfs_key, aes);
            let mut length = encrypted_length;
            if nfs_aead.open_in_place(None, &mut length, &[]).is_ok() {
                opened = Some((nfs_aead, decode_length(&length), aes));
                break;
            }
        }
        let Some((mut nfs_aead, length, aes)) = opened else {
            return Err(invalid(
                "VLESS encryption first flight failed authentication",
            ));
        };

        if length == 32 {
            return self.resume(inner, &iv, &nfs_key, nfs_aead, aes);
        }
        if length < MLKEM_EK_LEN + X25519_LEN + TAG_LEN {
            return Err(invalid("VLESS encryption first flight is too short"));
        }
        let mut pfs_in = vec![0u8; length];
        inner.read_exact(&mut pfs_in)?;
        nfs_aead.open_in_place(None, &mut pfs_in, &[])?;
        let peer_pfs = &pfs_in[..MLKEM_EK_LEN + X25519_LEN];
        let encoded: MlKemKey<EncapsulationKey768> = peer_pfs[..MLKEM_EK_LEN]
            .try_into()
            .map_err(|_| invalid("ML-KEM-768 key from the client is invalid"))?;
        let encapsulation_key = EncapsulationKey768::new(&encoded)
            .map_err(|_| invalid("ML-KEM-768 key from the client is invalid"))?;
        let (ciphertext, mlkem_key) =
            encapsulation_key.encapsulate_deterministic(&random_bytes()?.into());
        let x25519_secret = StaticSecret::from(random_bytes::<32>()?);
        let peer_x25519: [u8; 32] = peer_pfs[MLKEM_EK_LEN..].try_into().unwrap();
        let x25519_key = x25519_secret.diffie_hellman(&PublicKey::from(peer_x25519));
        if !x25519_key.was_contributory() {
            return Err(invalid("VLESS encryption client X25519 key is degenerate"));
        }
        let mut pfs_key = Vec::with_capacity(64);
        pfs_key.extend_from_slice(AsRef::<[u8]>::as_ref(&mlkem_key));
        pfs_key.extend_from_slice(x25519_key.as_bytes());
        let mut pfs_public: Vec<u8> = AsRef::<[u8]>::as_ref(&ciphertext).to_vec();
        pfs_public.extend_from_slice(PublicKey::from(&x25519_secret).as_bytes());
        let mut united_key = pfs_key.clone();
        united_key.extend_from_slice(&nfs_key);
        let mut aead = Aead::with_cipher(&pfs_public, &united_key, aes);
        let peer_aead = Aead::with_cipher(peer_pfs, &united_key, aes);

        let mut ticket = [0u8; 16];
        getrandom::fill(&mut ticket).map_err(|_| io::Error::other("no entropy"))?;
        let seconds = if config.seconds_to == 0 {
            config.seconds_from * i64::from(rand_between(50, 100)) / 100
        } else {
            i64::from(rand_between(
                config.seconds_from as u32,
                config.seconds_to as u32,
            ))
        };
        ticket[..2].copy_from_slice(&encode_length(seconds as usize));
        if seconds > 0 {
            let now = (self.clock)();
            let expires = now.saturating_add(seconds);
            let mut tickets = self
                .tickets
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            tickets.sweep(now);
            tickets.sessions.insert(
                ticket,
                Session {
                    pfs_key: pfs_key.clone(),
                    seen: HashSet::new(),
                },
            );
            tickets.expires.push(Reverse((expires, ticket)));
        }

        let mut server_hello = Vec::new();
        nfs_aead.seal_into(Some(MAX_NONCE), &pfs_public, &[], &mut server_hello);
        aead.seal_into(None, &ticket, &[], &mut server_hello);
        let (padding_len, mut piece_lens, gaps) =
            create_padding(&config.padding_lens, &config.padding_gaps);
        let padding_len = padding_len.max(18);
        aead.seal_into(
            None,
            &encode_length(padding_len - 18),
            &[],
            &mut server_hello,
        );
        let zeros = vec![0u8; padding_len - 18 - TAG_LEN];
        aead.seal_into(None, &zeros, &[], &mut server_hello);

        piece_lens[0] += server_hello.len() - padding_len;
        let mut sent = 0usize;
        for (i, len) in piece_lens.iter().enumerate() {
            if *len > 0 {
                inner.write_all(&server_hello[sent..sent + len])?;
                inner.flush()?;
                sent += len;
            }
            if let Some(gap) = gaps.get(i) {
                if !gap.is_zero() {
                    std::thread::sleep(*gap);
                }
            }
        }

        let mut padding_length = [0u8; 18];
        inner.read_exact(&mut padding_length)?;
        nfs_aead.open_in_place(None, &mut padding_length, &[])?;
        let mut padding = vec![0u8; decode_length(&padding_length)];
        inner.read_exact(&mut padding)?;
        nfs_aead.open_in_place(None, &mut padding, &[])?;

        let mut stream =
            EncryptedStream::new(inner, united_key, aead, Some(peer_aead), ReadStage::Records);
        if config.xor_mode == 2 {
            stream.set_out_mask(HeaderMask::new(
                Some(new_ctr(stream.united_key(), &ticket)),
                0,
            ));
            stream.set_in_mask(HeaderMask::new(Some(new_ctr(stream.united_key(), &iv)), 0));
        }
        Ok(stream)
    }

    fn resume<S: Read + Write>(
        &self,
        mut inner: S,
        iv: &[u8; 16],
        nfs_key: &[u8],
        mut nfs_aead: Aead,
        aes: bool,
    ) -> io::Result<EncryptedStream<S>> {
        let config = &self.config;
        if config.seconds_from == 0 && config.seconds_to == 0 {
            return Err(invalid("VLESS encryption: 0-RTT is not allowed here"));
        }
        let mut encrypted_ticket = [0u8; 32];
        inner.read_exact(&mut encrypted_ticket)?;
        let mut ticket = encrypted_ticket;
        nfs_aead.open_in_place(None, &mut ticket, &[])?;
        let ticket: [u8; 16] = ticket[..16].try_into().unwrap();
        let nfs_id: [u8; 32] = nfs_key
            .try_into()
            .map_err(|_| invalid("VLESS encryption first-flight key has the wrong length"))?;
        let pfs_key = {
            let now = (self.clock)();
            let mut tickets = self
                .tickets
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            tickets.sweep(now);
            match tickets.sessions.get_mut(&ticket) {
                None => None,
                Some(session) => {
                    if !session.seen.insert(nfs_id) {
                        return Err(invalid("VLESS encryption: replayed 0-RTT first flight"));
                    }
                    Some(session.pfs_key.clone())
                }
            }
        };
        let Some(pfs_key) = pfs_key else {
            let mut noise = vec![0u8; rand_between(1279, 2279) as usize];
            loop {
                getrandom::fill(&mut noise).map_err(|_| io::Error::other("no entropy"))?;
                if decode_header(&noise[..HEADER_LEN]).is_none() {
                    break;
                }
            }
            let _ = inner.write_all(&noise);
            return Err(invalid("VLESS encryption: unknown or expired ticket"));
        };
        let mut united_key = pfs_key;
        united_key.extend_from_slice(nfs_key);
        let pre_write = random_bytes::<16>()?;
        let aead = Aead::with_cipher(&pre_write, &united_key, aes);
        let peer_aead = Aead::with_cipher(&encrypted_ticket, &united_key, aes);
        let mut stream =
            EncryptedStream::new(inner, united_key, aead, Some(peer_aead), ReadStage::Records);
        stream.set_pre_write(pre_write.to_vec());
        if config.xor_mode == 2 {
            stream.set_out_mask(HeaderMask::new(
                Some(new_ctr(stream.united_key(), &pre_write)),
                pre_write.len(),
            ));
            stream.set_in_mask(HeaderMask::new(Some(new_ctr(stream.united_key(), iv)), 0));
        }
        Ok(stream)
    }
}

struct HeaderMask {
    ctr: Option<Aes256Ctr>,
    skip: usize,
    header: [u8; HEADER_LEN],
    have: usize,
}

impl HeaderMask {
    fn new(ctr: Option<Aes256Ctr>, skip: usize) -> Self {
        Self {
            ctr,
            skip,
            header: [0; HEADER_LEN],
            have: 0,
        }
    }

    fn apply(&mut self, mut bytes: &mut [u8], outgoing: bool) {
        let Some(ctr) = self.ctr.as_mut() else {
            return;
        };
        loop {
            if bytes.len() <= self.skip {
                self.skip -= bytes.len();
                return;
            }
            bytes = &mut std::mem::take(&mut bytes)[self.skip..];
            self.skip = 0;
            let need = HEADER_LEN - self.have;
            let take = need.min(bytes.len());
            if !outgoing {
                ctr.apply_keystream(&mut bytes[..take]);
            }
            self.header[self.have..self.have + take].copy_from_slice(&bytes[..take]);
            if outgoing {
                ctr.apply_keystream(&mut bytes[..take]);
            }
            if take < need {
                self.have += take;
                return;
            }
            self.have = 0;
            self.skip = if self.header[..3] == [23, 3, 3] {
                (usize::from(self.header[3]) << 8) | usize::from(self.header[4])
            } else {
                0
            };
            bytes = &mut std::mem::take(&mut bytes)[take..];
        }
    }
}

enum ReadStage {
    ServerRandom,
    ServerPadding(usize),
    Records,
}

/// The key both directions derive from; the value inside the `Arc` zeroes itself when the last handle goes.
struct KeyBytes(Vec<u8>);

impl KeyBytes {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for KeyBytes {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.0.zeroize();
    }
}

struct UnitedKey(Arc<KeyBytes>);

impl UnitedKey {
    fn new(bytes: Vec<u8>) -> Self {
        Self(Arc::new(KeyBytes(bytes)))
    }

    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Clone for UnitedKey {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

/// The read half of a sealed session: its own AEAD state, mask and buffered record.
struct ReadSide {
    united_key: UnitedKey,
    aes: bool,
    peer_aead: Option<Aead>,
    in_mask: HeaderMask,
    read_stage: ReadStage,
    zero_rtt: Option<(Arc<Client>, Vec<u8>)>,
    wire: Vec<u8>,
    wire_pos: usize,
    /// The decrypted record still owed to the caller, as a range of `wire`: the plaintext is the
    /// ciphertext's own bytes, so a record is unmasked and opened where it landed and read from there.
    plain_from: usize,
    plain_to: usize,
    header: Option<[u8; HEADER_LEN]>,
    direct: bool,
}

impl ReadSide {
    /// The octets of one read into the wire buffer's spare capacity, so a record crosses user space
    /// once; the tail is handed to `read` whole and truncated to what it reports, as the head reader does.
    #[allow(
        clippy::uninit_vec,
        reason = "the tail is handed straight to `read`, and every path truncates it first"
    )]
    fn pull<S: Read>(&mut self, inner: &mut S) -> io::Result<()> {
        let base = self.wire.len();
        if self.wire.capacity() == base {
            self.wire.reserve(MAX_RECORD);
        }
        let room = (self.wire.capacity() - base).min(MAX_RECORD);
        unsafe { self.wire.set_len(base + room) }
        let read = inner.read(&mut self.wire[base..]);
        match read {
            Ok(0) => {
                self.wire.truncate(base);
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "failed to fill whole buffer",
                ))
            }
            Ok(n) => {
                self.wire.truncate(base + n);
                Ok(())
            }
            Err(error) => {
                self.wire.truncate(base);
                Err(error)
            }
        }
    }

    /// The offset the next `len` wire octets start at, once they have all arrived: the bytes already
    /// taken stay in `wire`, so a retry resumes where the inner reader stopped instead of reading a
    /// record header twice. Only reached with no plaintext owed, so the prefix is reclaimable here.
    fn take_wire<S: Read>(&mut self, inner: &mut S, len: usize) -> io::Result<usize> {
        if self.wire_pos > 0 {
            if self.wire_pos == self.wire.len() {
                self.wire.clear();
                self.wire_pos = 0;
            } else if self.wire_pos >= 8192 {
                let left = self.wire.len() - self.wire_pos;
                self.wire.copy_within(self.wire_pos.., 0);
                self.wire.truncate(left);
                self.wire_pos = 0;
            }
        }
        self.plain_from = 0;
        self.plain_to = 0;
        while self.wire.len() - self.wire_pos < len {
            if let Err(error) = self.pull(inner) {
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
        Ok(self.wire_pos)
    }

    fn fill_input<S: Read>(&mut self, inner: &mut S) -> io::Result<()> {
        match self.read_stage {
            ReadStage::ServerRandom => {
                let at = self.take_wire(inner, 16)?;
                let random: [u8; 16] = self.wire[at..at + 16]
                    .try_into()
                    .map_err(|_| invalid("VLESS encryption server random is short"))?;
                self.wire_pos = at + 16;
                self.peer_aead = Some(Aead::with_cipher(
                    &random,
                    self.united_key.as_slice(),
                    self.aes,
                ));
                if self.in_mask.ctr.is_some() {
                    self.in_mask =
                        HeaderMask::new(Some(new_ctr(self.united_key.as_slice(), &random)), 0);
                }
                self.read_stage = ReadStage::Records;
                self.fill_input(inner)
            }
            ReadStage::ServerPadding(len) => {
                let at = self.take_wire(inner, len)?;
                self.wire_pos = at + len;
                self.in_mask.apply(&mut self.wire[at..at + len], false);
                let peer = self
                    .peer_aead
                    .as_mut()
                    .ok_or_else(|| invalid("VLESS encryption is missing its peer key"))?;
                peer.open_in_place(None, &mut self.wire[at..at + len], &[])?;
                self.read_stage = ReadStage::Records;
                self.fill_input(inner)
            }
            ReadStage::Records => {
                let header = if let Some(header) = self.header {
                    header
                } else {
                    let at = self.take_wire(inner, HEADER_LEN)?;
                    let mut header: [u8; HEADER_LEN] = self.wire[at..at + HEADER_LEN]
                        .try_into()
                        .map_err(|_| invalid("VLESS encryption record header is short"))?;
                    self.wire_pos = at + HEADER_LEN;
                    self.in_mask.apply(&mut header, false);
                    if decode_header(&header).is_none() {
                        if let Some((owner, pfs_key)) = self.zero_rtt.take() {
                            owner.expire_ticket(&pfs_key);
                            return Err(io::Error::new(
                                io::ErrorKind::ConnectionReset,
                                "VLESS encryption ticket expired; a new handshake is needed",
                            ));
                        }
                        return Err(invalid("invalid VLESS encryption record header"));
                    }
                    self.zero_rtt = None;
                    self.header = Some(header);
                    header
                };
                let len = decode_header(&header)
                    .ok_or_else(|| invalid("invalid VLESS encryption record header"))?;
                let at = self.take_wire(inner, len)?;
                self.header = None;
                self.wire_pos = at + len;
                self.in_mask.apply(&mut self.wire[at..at + len], false);
                let peer = self
                    .peer_aead
                    .as_mut()
                    .ok_or_else(|| invalid("VLESS encryption is missing its peer key"))?;
                let next = (peer.nonce == MAX_NONCE)
                    .then(|| peer.derive(&self.wire[at..at + len], self.united_key.as_slice()));
                let result = peer.open_in_place(None, &mut self.wire[at..at + len], &header);
                if let Some(next) = next {
                    *peer = next;
                }
                result?;
                self.plain_from = at;
                self.plain_to = at + len - TAG_LEN;
                Ok(())
            }
        }
    }

    fn read<S: Read>(&mut self, inner: &mut S, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.plain_from < self.plain_to {
            let n = (self.plain_to - self.plain_from).min(buf.len());
            buf[..n].copy_from_slice(&self.wire[self.plain_from..self.plain_from + n]);
            self.plain_from += n;
            return Ok(n);
        }
        if self.direct {
            if self.wire_pos < self.wire.len() {
                let available = &self.wire[self.wire_pos..];
                let n = available.len().min(buf.len());
                buf[..n].copy_from_slice(&available[..n]);
                self.wire_pos += n;
                if self.wire_pos == self.wire.len() {
                    self.wire.clear();
                    self.wire_pos = 0;
                }
                self.in_mask.apply(&mut buf[..n], false);
                return Ok(n);
            }
            let n = inner.read(buf)?;
            self.in_mask.apply(&mut buf[..n], false);
            return Ok(n);
        }
        self.fill_input(inner)?;
        let n = (self.plain_to - self.plain_from).min(buf.len());
        buf[..n].copy_from_slice(&self.wire[self.plain_from..self.plain_from + n]);
        self.plain_from += n;
        Ok(n)
    }
}

/// The write half of a sealed session: its own AEAD state and mask.
struct WriteSide {
    united_key: UnitedKey,
    aead: Aead,
    out_mask: HeaderMask,
    pre_write: Vec<u8>,
    out: Vec<u8>,
    direct: bool,
}

impl WriteSide {
    fn write<W: Write>(&mut self, inner: &mut W, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let take = buf.len().min(MAX_BATCH_PLAINTEXT);
        self.out.clear();
        if self.direct {
            self.out.extend_from_slice(&buf[..take]);
            self.out_mask.apply(&mut self.out, true);
            inner.write_all(&self.out)?;
            return Ok(take);
        }
        self.out.append(&mut self.pre_write);
        let mut at = 0;
        while at < take {
            let n = (take - at).min(MAX_RECORD_PLAINTEXT);
            let header_at = self.out.len();
            let len = n + TAG_LEN;
            let header = [23, 3, 3, (len >> 8) as u8, len as u8];
            self.out.extend_from_slice(&header);
            let rekey = self.aead.nonce == MAX_NONCE;
            self.aead
                .seal_into(None, &buf[at..at + n], &header, &mut self.out);
            if rekey {
                self.aead = self
                    .aead
                    .derive(&self.out[header_at..], self.united_key.as_slice());
            }
            at += n;
        }
        self.out_mask.apply(&mut self.out, true);
        inner.write_all(&self.out)?;
        Ok(take)
    }
}

pub struct EncryptedStream<S> {
    inner: S,
    read: ReadSide,
    write: WriteSide,
}

impl<S> std::fmt::Debug for EncryptedStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedStream")
            .field("direct", &self.read.direct)
            .finish_non_exhaustive()
    }
}

impl<S> EncryptedStream<S> {
    fn new(
        inner: S,
        united_key: Vec<u8>,
        aead: Aead,
        peer_aead: Option<Aead>,
        read_stage: ReadStage,
    ) -> Self {
        let key = UnitedKey::new(united_key);
        let aes = aead.is_aes();
        Self {
            inner,
            read: ReadSide {
                united_key: key.clone(),
                aes,
                peer_aead,
                in_mask: HeaderMask::new(None, 0),
                read_stage,
                zero_rtt: None,
                wire: Vec::new(),
                wire_pos: 0,
                plain_from: 0,
                plain_to: 0,
                header: None,
                direct: false,
            },
            write: WriteSide {
                united_key: key,
                aead,
                out_mask: HeaderMask::new(None, 0),
                pre_write: Vec::new(),
                out: Vec::new(),
                direct: false,
            },
        }
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn enter_direct_mode(&mut self) {
        self.read.direct = true;
        self.write.direct = true;
    }

    fn set_out_mask(&mut self, mask: HeaderMask) {
        self.write.out_mask = mask;
    }

    fn set_in_mask(&mut self, mask: HeaderMask) {
        self.read.in_mask = mask;
    }

    fn set_pre_write(&mut self, bytes: Vec<u8>) {
        self.write.pre_write = bytes;
    }

    fn set_zero_rtt(&mut self, owner: Arc<Client>, pfs_key: Vec<u8>) {
        self.read.zero_rtt = Some((owner, pfs_key));
    }

    fn united_key(&self) -> &[u8] {
        self.write.united_key.as_slice()
    }
}

impl<S: Read> Read for EncryptedStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read.read(&mut self.inner, buf)
    }
}

impl<S: Write> Write for EncryptedStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write.write(&mut self.inner, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// The independently sealed halves a split stream yields.
pub type EncryptedHalves<R, W> = (EncryptedReader<R>, EncryptedWriter<W>);

/// A stream that carries independent halves, so sealing can split without one lock.
pub trait SplitIo {
    type Reader;
    type Writer;

    fn split_io(self) -> Option<(Self::Reader, Self::Writer)>;
}

impl<S: SplitIo> EncryptedStream<S> {
    pub fn into_split(self) -> Option<EncryptedHalves<S::Reader, S::Writer>> {
        let Self { inner, read, write } = self;
        let (reader, writer) = inner.split_io()?;
        Some((
            EncryptedReader {
                inner: reader,
                side: read,
            },
            EncryptedWriter {
                inner: writer,
                side: write,
            },
        ))
    }
}

pub struct EncryptedReader<R> {
    inner: R,
    side: ReadSide,
}

impl<R> std::fmt::Debug for EncryptedReader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedReader")
            .field("direct", &self.side.direct)
            .finish_non_exhaustive()
    }
}

impl<R> EncryptedReader<R> {
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    pub fn enter_direct_mode(&mut self) {
        self.side.direct = true;
    }
}

impl<R: Read> Read for EncryptedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.side.read(&mut self.inner, buf)
    }
}

pub struct EncryptedWriter<W> {
    inner: W,
    side: WriteSide,
}

impl<W> std::fmt::Debug for EncryptedWriter<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedWriter")
            .field("direct", &self.side.direct)
            .finish_non_exhaustive()
    }
}

impl<W> EncryptedWriter<W> {
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    pub fn enter_direct_mode(&mut self) {
        self.side.direct = true;
    }
}

impl<W: Write> Write for EncryptedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.side.write(&mut self.inner, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub fn generate_pair(mlkem: bool, mode: &str, rtt: &str, seconds: &str) -> (String, String) {
    use base64::Engine as _;
    let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let (public, private) = if mlkem {
        let seed = random_bytes::<64>().expect("entropy");
        let key = ml_kem::DecapsulationKey768::from_seed(
            ml_kem::Seed::try_from(&seed[..]).expect("64 bytes"),
        );
        let encoded = key.encapsulation_key().to_bytes();
        (encode(AsRef::<[u8]>::as_ref(&encoded)), encode(&seed))
    } else {
        let secret = StaticSecret::from(random_bytes::<32>().expect("entropy"));
        (
            encode(PublicKey::from(&secret).as_bytes()),
            encode(secret.as_bytes()),
        )
    };
    (
        format!("mlkem768x25519plus.{mode}.{rtt}.{public}"),
        format!("mlkem768x25519plus.{mode}.{seconds}.{private}"),
    )
}

const BLAKE3_IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];
const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
const CHUNK_START: u32 = 1;
const CHUNK_END: u32 = 2;
const PARENT: u32 = 4;
const ROOT: u32 = 8;
const DERIVE_KEY_CONTEXT: u32 = 32;

fn blake3_g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

fn blake3_compress(
    cv: &[u32; 8],
    block: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut state = [0u32; 16];
    state[..8].copy_from_slice(cv);
    state[8..12].copy_from_slice(&BLAKE3_IV[..4]);
    state[12] = counter as u32;
    state[13] = (counter >> 32) as u32;
    state[14] = block_len;
    state[15] = flags;
    let mut message = *block;
    for round in 0..7 {
        blake3_g(&mut state, 0, 4, 8, 12, message[0], message[1]);
        blake3_g(&mut state, 1, 5, 9, 13, message[2], message[3]);
        blake3_g(&mut state, 2, 6, 10, 14, message[4], message[5]);
        blake3_g(&mut state, 3, 7, 11, 15, message[6], message[7]);
        blake3_g(&mut state, 0, 5, 10, 15, message[8], message[9]);
        blake3_g(&mut state, 1, 6, 11, 12, message[10], message[11]);
        blake3_g(&mut state, 2, 7, 8, 13, message[12], message[13]);
        blake3_g(&mut state, 3, 4, 9, 14, message[14], message[15]);
        if round < 6 {
            let mut permuted = [0u32; 16];
            for (slot, index) in MSG_PERMUTATION.iter().enumerate() {
                permuted[slot] = message[*index];
            }
            message = permuted;
        }
    }
    let mut out = [0u32; 16];
    for i in 0..8 {
        out[i] = state[i] ^ state[i + 8];
        out[i + 8] = state[i + 8] ^ cv[i];
    }
    out
}

struct Blake3Output {
    cv: [u32; 8],
    block: [u32; 16],
    block_len: u32,
    counter: u64,
    flags: u32,
}

impl Blake3Output {
    fn cv(&self) -> [u32; 8] {
        let out = blake3_compress(
            &self.cv,
            &self.block,
            self.counter,
            self.block_len,
            self.flags,
        );
        out[..8].try_into().unwrap()
    }
}

fn blake3_block(bytes: &[u8]) -> [u32; 16] {
    let mut block = [0u32; 16];
    for (i, byte) in bytes.iter().enumerate() {
        block[i / 4] |= u32::from(*byte) << (8 * (i % 4));
    }
    block
}

fn blake3_chunk_output(chunk: &[u8], key: &[u32; 8], counter: u64, flags: u32) -> Blake3Output {
    let blocks = chunk.len().div_ceil(64).max(1);
    let mut cv = *key;
    for block_index in 0..blocks - 1 {
        let start = block_index * 64;
        let block = blake3_block(&chunk[start..start + 64]);
        let out = blake3_compress(
            &cv,
            &block,
            counter,
            64,
            flags | (CHUNK_START * u32::from(block_index == 0)),
        );
        cv.copy_from_slice(&out[..8]);
    }
    let last_start = (blocks - 1) * 64;
    let last = &chunk[last_start..];
    let mut last_flags = flags | CHUNK_END;
    if blocks == 1 {
        last_flags |= CHUNK_START;
    }
    Blake3Output {
        cv,
        block: blake3_block(last),
        block_len: last.len() as u32,
        counter,
        flags: last_flags,
    }
}

fn blake3_parent_output(
    left: &[u32; 8],
    right: &[u32; 8],
    key: &[u32; 8],
    flags: u32,
) -> Blake3Output {
    let mut block = [0u32; 16];
    block[..8].copy_from_slice(left);
    block[8..].copy_from_slice(right);
    Blake3Output {
        cv: *key,
        block,
        block_len: 64,
        counter: 0,
        flags: flags | PARENT,
    }
}

fn blake3_hash(input: &[u8], key: &[u32; 8], flags: u32) -> [u8; 32] {
    let chunks = input.len().div_ceil(1024).max(1);
    let mut nodes = Vec::with_capacity(chunks);
    for chunk in 0..chunks {
        let start = chunk * 1024;
        let end = (start + 1024).min(input.len());
        nodes.push(blake3_chunk_output(
            &input[start..end],
            key,
            chunk as u64,
            flags,
        ));
    }
    while nodes.len() > 1 {
        let mut parents = Vec::with_capacity(nodes.len().div_ceil(2));
        for pair in nodes.chunks(2) {
            if pair.len() == 1 {
                parents.push(Blake3Output {
                    cv: pair[0].cv,
                    block: pair[0].block,
                    block_len: pair[0].block_len,
                    counter: pair[0].counter,
                    flags: pair[0].flags,
                });
            } else {
                parents.push(blake3_parent_output(
                    &pair[0].cv(),
                    &pair[1].cv(),
                    key,
                    flags,
                ));
            }
        }
        nodes = parents;
    }
    let root = &nodes[0];
    let out = blake3_compress(
        &root.cv,
        &root.block,
        root.counter,
        root.block_len,
        root.flags | ROOT,
    );
    let mut bytes = [0u8; 32];
    for (i, word) in out[..8].iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

fn derive_key(context: &[u8], material: &[u8]) -> [u8; 32] {
    use blake3::hazmat::HasherExt as _;
    let context_key = blake3_hash(context, &BLAKE3_IV, DERIVE_KEY_CONTEXT);
    let mut hasher = blake3::Hasher::new_from_context_key(&context_key);
    hasher.update(material);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_context_derive_matches_the_crate() {
        for context in ["VLESS", "xray", "a longer context string for blake3"] {
            assert_eq!(
                derive_key(context.as_bytes(), b"material"),
                blake3::derive_key(context, b"material")
            );
        }
    }

    #[test]
    fn padding_groups_are_alternating() {
        let (lens, gaps) = parse_padding("100-111-1111.50-0-3333").unwrap();
        assert_eq!(lens, vec![[100, 111, 1111]]);
        assert_eq!(gaps, vec![[50, 0, 3333]]);
        assert!(parse_padding("99-35-35").is_err());
    }

    #[test]
    fn pair_round_trips_every_mode() {
        for mlkem in [false, true] {
            for mode in ["native", "xorpub", "random"] {
                let (encryption, decryption) = generate_pair(mlkem, mode, "0rtt", "600s");
                ClientConfig::parse(&encryption).unwrap();
                ServerConfig::parse(&decryption).unwrap();
            }
        }
    }

    #[cfg(unix)]
    fn exchange(mode: &str, zero_rtt: bool) {
        use std::os::unix::net::UnixStream;
        let (encryption, decryption) =
            generate_pair(false, mode, if zero_rtt { "0rtt" } else { "1rtt" }, "600s");
        let server = Server::new(ServerConfig::parse(&decryption).unwrap());
        let client = Client::new(ClientConfig::parse(&encryption).unwrap());
        let (a, b) = UnixStream::pair().unwrap();
        let server_thread = std::thread::spawn(move || {
            let mut stream = server.handshake(b).unwrap();
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"hello");
            stream.write_all(b"world").unwrap();
            stream.flush().unwrap();
        });
        let mut stream = client.handshake(a).unwrap();
        stream.write_all(b"hello").unwrap();
        stream.flush().unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"world");
        server_thread.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_server_derived_client_exchanges_bytes() {
        use std::os::unix::net::UnixStream;
        let (_, decryption) = generate_pair(true, "native", "1rtt", "600s");
        let server = Server::new(ServerConfig::parse(&decryption).unwrap());
        let client = Client::new(ClientConfig::from_server(&decryption).unwrap());
        let (a, b) = UnixStream::pair().unwrap();
        let server_thread = std::thread::spawn(move || {
            let mut stream = server.handshake(b).unwrap();
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"hello");
            stream.write_all(b"world").unwrap();
            stream.flush().unwrap();
        });
        let mut stream = client.handshake(a).unwrap();
        stream.write_all(b"hello").unwrap();
        stream.flush().unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"world");
        server_thread.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn native_one_rtt_exchanges_bytes() {
        exchange("native", false);
    }

    #[cfg(unix)]
    #[test]
    fn random_one_rtt_exchanges_bytes() {
        exchange("random", false);
    }

    #[cfg(unix)]
    #[test]
    fn random_zero_rtt_exchanges_bytes() {
        exchange("random", true);
    }

    #[cfg(unix)]
    #[test]
    fn a_sealed_record_allocates_nothing_on_the_steady_path() {
        use std::io::Write as _;
        use std::os::unix::net::UnixStream;

        let (encryption, decryption) = generate_pair(false, "native", "1rtt", "600s");
        let server = Server::new(ServerConfig::parse(&decryption).unwrap());
        let client = Client::new(ClientConfig::parse(&encryption).unwrap());
        let (a, b) = UnixStream::pair().unwrap();
        let payload = [0x5au8; 300];
        let rounds = 64usize;
        let writer = std::thread::spawn(move || {
            let mut stream = server.handshake(b).unwrap();
            for _ in 0..rounds {
                stream.write_all(&payload).unwrap();
            }
            stream.flush().unwrap();
        });
        let mut stream = client.handshake(a).unwrap();
        let mut buf = [0u8; 300];
        stream.read_exact(&mut buf).unwrap();
        stream.read.wire.reserve(16 * 1024);
        let ((), counts) = crate::alloc_count::measure(|| {
            for _ in 1..rounds {
                stream.read_exact(&mut buf).unwrap();
            }
        });
        assert_eq!(
            (counts.allocs, counts.bytes, counts.zeroed),
            (0, 0, 0),
            "a record read reuses its buffers"
        );
        writer.join().unwrap();
    }

    /// The record is opened where the wire octets landed: after a window of records the buffer's own
    /// pointer is the one it started at and its capacity has not grown, so a second buffer able to hold
    /// a record cannot have appeared, and the read path cannot have reallocated the one it has.
    #[cfg(unix)]
    #[test]
    fn a_record_is_opened_in_the_buffer_it_landed_in() {
        use std::io::Write as _;
        use std::os::unix::net::UnixStream;

        let (encryption, decryption) = generate_pair(false, "native", "1rtt", "600s");
        let server = Server::new(ServerConfig::parse(&decryption).unwrap());
        let client = Client::new(ClientConfig::parse(&encryption).unwrap());
        let (a, b) = UnixStream::pair().unwrap();
        let payload = [0x5au8; MAX_RECORD_PLAINTEXT];
        let rounds = 8usize;
        let writer = std::thread::spawn(move || {
            let mut stream = server.handshake(b).unwrap();
            for _ in 0..rounds {
                stream.write_all(&payload).unwrap();
            }
            stream.flush().unwrap();
        });
        let mut stream = client.handshake(a).unwrap();
        let mut buf = [0u8; 256];
        let window = MAX_RECORD_PLAINTEXT / buf.len();
        for _ in 0..window {
            stream.read_exact(&mut buf).unwrap();
        }
        let base = stream.read.wire.as_ptr();
        let steady = stream.read.wire.capacity();
        let ((), counts) = crate::alloc_count::measure(|| {
            for _ in 1..rounds {
                for _ in 0..window {
                    stream.read_exact(&mut buf).unwrap();
                }
            }
        });
        assert_eq!(stream.read.wire.as_ptr(), base, "the record's buffer moved");
        assert_eq!(
            stream.read.wire.capacity(),
            steady,
            "the record's buffer grew"
        );
        assert_eq!(
            (counts.allocs, counts.bytes, counts.zeroed),
            (0, 0, 0),
            "a record read reuses the buffer it landed in"
        );
        writer.join().unwrap();
    }

    /// Every record size the framing writes, written in uneven chunks and read through a window smaller
    /// than a record, so the plaintext cursor that advances by the caller's window is what is swept.
    #[cfg(unix)]
    #[test]
    fn a_record_of_any_size_reads_back_the_octets_that_were_written() {
        use std::io::Write as _;
        use std::os::unix::net::UnixStream;

        const SIZES: &[usize] = &[1, 2, 15, 16, 17, 21, 300, 8191, 8192, 8193, 16384, 32768];
        const CHUNKS: &[usize] = &[1, 7, 300, MAX_RECORD_PLAINTEXT];
        fn body(size: usize) -> Vec<u8> {
            (0..size)
                .map(|at| (at as u8).wrapping_mul(37).wrapping_add(11))
                .collect()
        }
        let (encryption, decryption) = generate_pair(false, "native", "1rtt", "600s");
        let server = Server::new(ServerConfig::parse(&decryption).unwrap());
        let client = Client::new(ClientConfig::parse(&encryption).unwrap());
        let (a, b) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            let mut stream = server.handshake(b).unwrap();
            for &size in SIZES {
                let bytes = body(size);
                let mut at = 0;
                let mut chunk = 0;
                while at < size {
                    let take = CHUNKS[chunk % CHUNKS.len()].min(size - at);
                    stream.write_all(&bytes[at..at + take]).unwrap();
                    at += take;
                    chunk += 1;
                }
                stream.flush().unwrap();
            }
        });
        let mut stream = client.handshake(a).unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 13];
        for &size in SIZES {
            while got.len() < size {
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0, "a record of {size} ended {} octets in", got.len());
                got.extend_from_slice(&buf[..n]);
            }
            assert_eq!(got.as_slice(), body(size).as_slice(), "a record of {size}");
            got.clear();
        }
        writer.join().unwrap();
    }

    /// A batch of records is sealed into the same staging buffer and handed to the socket once,
    /// so the peer's reads are not woken per 8 KiB record; the bytes are the ones the same
    /// records make one at a time.
    #[test]
    fn a_batched_record_write_is_one_call_and_the_same_bytes() {
        use std::io::Write as _;

        struct Sink {
            calls: usize,
            wire: Vec<u8>,
        }

        impl Write for Sink {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.calls += 1;
                self.wire.extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        fn stream() -> EncryptedStream<Sink> {
            let key = vec![7u8; 32];
            EncryptedStream::new(
                Sink {
                    calls: 0,
                    wire: Vec::new(),
                },
                key.clone(),
                Aead::new(b"record batch", &key),
                None,
                ReadStage::Records,
            )
        }

        let payload: Vec<u8> = (0..MAX_BATCH_PLAINTEXT)
            .map(|at| (at as u8).wrapping_mul(31).wrapping_add(5))
            .collect();
        let mut batched = stream();
        batched.write_all(&payload).unwrap();
        assert_eq!(batched.get_ref().calls, 1, "one write for the whole batch");
        assert_eq!(
            batched.get_ref().wire.len(),
            8 * (HEADER_LEN + MAX_RECORD_PLAINTEXT + TAG_LEN),
            "the batch is eight records"
        );

        let mut singles = stream();
        for chunk in payload.chunks(MAX_RECORD_PLAINTEXT) {
            singles.write_all(chunk).unwrap();
        }
        assert_eq!(singles.get_ref().calls, 8);
        assert_eq!(
            batched.get_ref().wire,
            singles.get_ref().wire,
            "batching adds no byte and no rekey step"
        );
    }

    /// A masked batch leaves the unmasked prefix alone, masks every record with the same keystream,
    /// and reads back through a matching masked reader.
    #[test]
    fn a_masked_batched_record_write_is_one_call_and_reads_back() {
        use std::io::{Cursor, Read as _, Write as _};

        struct Sink {
            calls: usize,
            wire: Vec<u8>,
        }

        impl Write for Sink {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.calls += 1;
                self.wire.extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        fn masked(key: &[u8], pre_write: &[u8]) -> EncryptedStream<Sink> {
            let mut stream = EncryptedStream::new(
                Sink {
                    calls: 0,
                    wire: Vec::new(),
                },
                key.to_vec(),
                Aead::with_cipher(pre_write, key, false),
                None,
                ReadStage::Records,
            );
            stream.set_pre_write(pre_write.to_vec());
            stream.set_out_mask(HeaderMask::new(
                Some(new_ctr(key, pre_write)),
                pre_write.len(),
            ));
            stream
        }

        let key = vec![7u8; 32];
        let pre_write = vec![0x5a; 16];
        let payload: Vec<u8> = (0..MAX_BATCH_PLAINTEXT)
            .map(|at| (at as u8).wrapping_mul(31).wrapping_add(5))
            .collect();

        let mut batched = masked(&key, &pre_write);
        batched.write_all(&payload).unwrap();
        assert_eq!(batched.get_ref().calls, 1, "one write for the whole batch");
        assert_eq!(
            batched.get_ref().wire.len(),
            pre_write.len() + 8 * (HEADER_LEN + MAX_RECORD_PLAINTEXT + TAG_LEN),
            "the batch is eight masked records after the unmasked prefix"
        );

        let mut singles = masked(&key, &pre_write);
        for chunk in payload.chunks(MAX_RECORD_PLAINTEXT) {
            singles.write_all(chunk).unwrap();
        }
        assert_eq!(singles.get_ref().calls, 8);
        assert_eq!(
            batched.get_ref().wire,
            singles.get_ref().wire,
            "masking a batch adds no byte and skips the same prefix"
        );

        let wire = batched.get_ref().wire.clone();
        let mut reader = EncryptedStream::new(
            Cursor::new(wire),
            key.clone(),
            Aead::with_cipher(&pre_write, &key, false),
            None,
            ReadStage::ServerRandom,
        );
        reader.set_in_mask(HeaderMask::new(Some(new_ctr(&key, &pre_write)), 0));
        let mut got = vec![0u8; payload.len()];
        reader.read_exact(&mut got).unwrap();
        assert_eq!(got, payload, "the masked batch reads back its plaintext");
    }

    #[test]
    fn a_record_write_allocates_nothing_after_warmup() {
        use std::io::Write as _;

        struct Sink;
        impl Write for Sink {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let key = vec![7u8; 32];
        let mut stream = EncryptedStream::new(
            Sink,
            key.clone(),
            Aead::new(b"record write", &key),
            None,
            ReadStage::Records,
        );
        let buf = [0x33u8; 300];
        stream.write_all(&buf).unwrap();
        let ((), counts) = crate::alloc_count::measure(|| {
            for _ in 0..64 {
                stream.write_all(&buf).unwrap();
            }
        });
        assert_eq!(
            (counts.allocs, counts.bytes, counts.zeroed),
            (0, 0, 0),
            "a record write reuses its staging buffer"
        );
    }

    /// The header read and the body read are separate `read` calls; a poll timeout
    /// between them must resume the body, not hand the header back as plaintext.
    #[test]
    fn a_timeout_between_a_record_header_and_its_body_does_not_leak_the_header() {
        use std::io::Write as _;

        struct SplitRead {
            wire: Vec<u8>,
            at: usize,
            reads: usize,
        }

        impl Read for SplitRead {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.reads += 1;
                if self.reads == 2 {
                    return Err(io::Error::from(io::ErrorKind::WouldBlock));
                }
                let take = if self.reads == 1 {
                    HEADER_LEN.min(buf.len())
                } else {
                    (self.wire.len() - self.at).min(buf.len())
                };
                buf[..take].copy_from_slice(&self.wire[self.at..self.at + take]);
                self.at += take;
                Ok(take)
            }
        }

        let key = vec![7u8; 32];
        let context = b"record header timeout";
        let plaintext = [0x5au8; 300];
        let mut wire = Vec::new();
        EncryptedStream::new(
            &mut wire,
            key.clone(),
            Aead::new(context, &key),
            None,
            ReadStage::Records,
        )
        .write_all(&plaintext)
        .unwrap();

        let mut stream = EncryptedStream::new(
            SplitRead {
                wire,
                at: 0,
                reads: 0,
            },
            key.clone(),
            Aead::new(context, &key),
            Some(Aead::new(context, &key)),
            ReadStage::Records,
        );
        let mut buf = [0u8; 300];
        let first = stream.read(&mut buf);
        assert_eq!(
            first.as_ref().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(
            &buf[..n],
            &plaintext,
            "a retried read resumes the body, not the record header"
        );
    }
}

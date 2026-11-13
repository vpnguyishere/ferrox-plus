//! The client half of Psiphon's obfuscated server lists (OSL) and server alerts.

use crate::json::{self, Json};
use crate::psiphon_ssh::ServerRequests;
use crypto_secretbox::aead::{Aead, KeyInit};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

/// The seeded SLOKs, keyed by ID, with a durable copy under the lane's state directory.
pub(crate) struct SlokStore {
    path: Option<PathBuf>,
    keys: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
}

impl SlokStore {
    pub(crate) fn open(path: Option<PathBuf>) -> Arc<Self> {
        let keys = path
            .as_deref()
            .and_then(|path| std::fs::read_to_string(path).ok())
            .map(|text| load(&text))
            .unwrap_or_default();
        Arc::new(Self {
            path,
            keys: Mutex::new(keys),
        })
    }

    pub(crate) fn get(&self, id: &[u8]) -> Option<Vec<u8>> {
        self.keys.lock().ok()?.get(id).cloned()
    }

    fn seed(&self, id: Vec<u8>, key: Vec<u8>) -> bool {
        if id.is_empty() || key.len() != KEY_LEN {
            return true;
        }
        match self.keys.lock() {
            Ok(mut keys) => keys.insert(id, key).is_some(),
            Err(_) => true,
        }
    }

    fn clear(&self) {
        if let Ok(mut keys) = self.keys.lock() {
            keys.clear();
        }
    }

    fn save(&self) {
        let Some(path) = self.path.as_deref() else {
            return;
        };
        let Ok(keys) = self.keys.lock() else {
            return;
        };
        let mut text = String::new();
        for (id, key) in keys.iter() {
            text.push_str(&ferrox_core::b64::encode(id));
            text.push(' ');
            text.push_str(&ferrox_core::b64::encode(key));
            text.push('\n');
        }
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut temporary = path.as_os_str().to_owned();
        temporary.push(format!(".{}.tmp", std::process::id()));
        let temporary = PathBuf::from(temporary);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let Ok(mut file) = options.open(&temporary) else {
            return;
        };
        if file.write_all(text.as_bytes()).is_err() {
            let _ = std::fs::remove_file(&temporary);
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        drop(file);
        if std::fs::rename(&temporary, path).is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
    }
}

fn load(text: &str) -> HashMap<Vec<u8>, Vec<u8>> {
    let mut keys = HashMap::new();
    for line in text.lines() {
        let Some((id, key)) = line.split_once(' ') else {
            continue;
        };
        let Some(id) = ferrox_core::b64::decode(id.as_bytes()) else {
            continue;
        };
        let Some(key) = ferrox_core::b64::decode(key.as_bytes()) else {
            continue;
        };
        if !id.is_empty() && key.len() == KEY_LEN {
            keys.insert(id, key);
        }
    }
    keys
}

/// The server-initiated SSH requests a Psiphon client must answer.
pub(crate) struct ServerEvents {
    pub(crate) sloks: Arc<SlokStore>,
    pub(crate) seeded: Arc<AtomicBool>,
    pub(crate) emit_alerts: bool,
    pub(crate) emit_sloks: bool,
}

impl ServerRequests for ServerEvents {
    fn handle(&self, name: &[u8], payload: &[u8]) -> Result<Vec<u8>, String> {
        match name {
            b"psiphon-osl" => self.osl(payload),
            b"psiphon-alert" => self.alert(payload),
            _ => Err(format!(
                "psiphon ssh: unexpected server request {}",
                String::from_utf8_lossy(name)
            )),
        }
    }
}

impl ServerEvents {
    fn osl(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let text = std::str::from_utf8(payload)
            .map_err(|_| "psiphon osl: request is not UTF-8".to_owned())?;
        let request =
            json::parse(text).map_err(|_| "psiphon osl: request is not JSON".to_owned())?;
        let mut changed = false;
        if request
            .get("clear_local_sloks")
            .and_then(Json::as_bool)
            .unwrap_or(false)
        {
            self.sloks.clear();
            changed = true;
        }
        let Some(sloks) = request
            .get("seed_payload")
            .and_then(|seed| seed.get("SLOKs"))
            .and_then(Json::as_arr)
        else {
            if changed {
                self.sloks.save();
            }
            return Ok(Vec::new());
        };
        for slok in sloks {
            let Some(id) = slok
                .get("ID")
                .and_then(Json::as_str)
                .and_then(|value| ferrox_core::b64::decode(value.as_bytes()))
            else {
                continue;
            };
            let Some(key) = slok
                .get("Key")
                .and_then(Json::as_str)
                .and_then(|value| ferrox_core::b64::decode(value.as_bytes()))
            else {
                continue;
            };
            let duplicate = self.sloks.seed(id.clone(), key);
            if !duplicate {
                changed = true;
                self.seeded.store(true, Ordering::Release);
            }
            if self.emit_sloks {
                eprintln!(
                    "psiphon: SLOK {} duplicate={duplicate}",
                    ferrox_core::b64::encode(&id)
                );
            }
        }
        if changed {
            self.sloks.save();
        }
        Ok(Vec::new())
    }

    fn alert(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let text = std::str::from_utf8(payload)
            .map_err(|_| "psiphon alert: request is not UTF-8".to_owned())?;
        let alert =
            json::parse(text).map_err(|_| "psiphon alert: request is not JSON".to_owned())?;
        if self.emit_alerts {
            let reason = alert.get("reason").and_then(Json::as_str).unwrap_or("");
            let subject = alert.get("subject").and_then(Json::as_str).unwrap_or("");
            eprintln!("psiphon: server alert: {reason}: {subject}");
            if let Some(actions) = alert.get("action").and_then(Json::as_arr) {
                for action in actions.iter().filter_map(Json::as_str) {
                    eprintln!("psiphon: server alert action: {action}");
                }
            }
        }
        Ok(Vec::new())
    }
}

/// One OSL registry entry: the file ID and the shares that reconstruct its key.
pub(crate) struct FileSpec {
    pub(crate) id: Vec<u8>,
    pub(crate) md5: Option<[u8; 16]>,
    shares: KeyShares,
}

impl FileSpec {
    /// Whether enough seeded SLOKs are present to reconstruct this file's key.
    pub(crate) fn seeded(&self, lookup: &dyn Fn(&[u8]) -> Option<Vec<u8>>) -> bool {
        self.shares
            .reassemble(lookup, false)
            .is_ok_and(|key| key.is_some())
    }
}

struct KeyShares {
    threshold: usize,
    boxed: Vec<Vec<u8>>,
    slok_ids: Vec<Vec<u8>>,
    children: Vec<KeyShares>,
}

impl KeyShares {
    fn reassemble(
        &self,
        lookup: &dyn Fn(&[u8]) -> Option<Vec<u8>>,
        unbox: bool,
    ) -> Result<Option<Vec<u8>>, String> {
        let by_id = !self.slok_ids.is_empty();
        let by_child = !self.children.is_empty();
        if (by_id && (by_child || self.slok_ids.len() != self.boxed.len()))
            || (by_child && self.children.len() != self.boxed.len())
            || self.threshold == 0
        {
            return Err("psiphon osl: malformed key shares".to_owned());
        }
        let mut shares: Vec<Option<Vec<u8>>> = vec![None; self.boxed.len()];
        let mut count = 0usize;
        if by_id {
            for (index, id) in self.slok_ids.iter().enumerate() {
                if count >= self.threshold {
                    break;
                }
                let Some(key) = lookup(id) else {
                    continue;
                };
                count += 1;
                if unbox {
                    shares[index] = Some(open(&key, &self.boxed[index])?);
                }
            }
        } else {
            for (index, child) in self.children.iter().enumerate() {
                if count >= self.threshold {
                    break;
                }
                let Some(key) = child.reassemble(lookup, unbox)? else {
                    continue;
                };
                count += 1;
                if unbox {
                    shares[index] = Some(open(&key, &self.boxed[index])?);
                }
            }
        }
        if count < self.threshold {
            return Ok(None);
        }
        if !unbox {
            return Ok(Some(Vec::new()));
        }
        Ok(Some(combine(&shares)))
    }
}

/// Authenticate and parse an OSL registry, keeping only well-formed file specs.
pub(crate) fn parse_registry(package: &[u8], public_key: &str) -> Result<Vec<FileSpec>, String> {
    let data = crate::psiphon::unpack(package, public_key)?;
    let decoded = ferrox_core::b64::decode(data.as_bytes())
        .ok_or_else(|| "psiphon osl: registry payload is not base64".to_owned())?;
    let registry = json::parse(&String::from_utf8_lossy(&decoded))
        .map_err(|_| "psiphon osl: registry is not JSON".to_owned())?;
    let Some(specs) = registry.get("FileSpecs").and_then(Json::as_arr) else {
        return Ok(Vec::new());
    };
    Ok(specs.iter().filter_map(parse_file_spec).collect())
}

fn parse_file_spec(spec: &Json) -> Option<FileSpec> {
    let id = spec
        .get("ID")
        .and_then(Json::as_str)
        .and_then(|value| ferrox_core::b64::decode(value.as_bytes()))?;
    let shares = parse_key_shares(spec.get("KeyShares")?)?;
    let md5 = match spec.get("MD5Sum") {
        None | Some(Json::Null) => None,
        Some(value) => {
            Some(<[u8; 16]>::try_from(ferrox_core::b64::decode(value.as_str()?.as_bytes())?).ok()?)
        }
    };
    Some(FileSpec { id, md5, shares })
}

fn parse_key_shares(shares: &Json) -> Option<KeyShares> {
    let threshold = shares.get("Threshold").and_then(Json::as_u32)? as usize;
    let boxed = parse_bytes(shares.get("BoxedShares")?)?;
    let slok_ids = match shares.get("SLOKIDs") {
        Some(Json::Null) | None => Vec::new(),
        Some(value) => parse_bytes(value)?,
    };
    let children = match shares.get("KeyShares") {
        Some(Json::Null) | None => Vec::new(),
        Some(value) => value
            .as_arr()?
            .iter()
            .map(parse_key_shares)
            .collect::<Option<Vec<_>>>()?,
    };
    Some(KeyShares {
        threshold,
        boxed,
        slok_ids,
        children,
    })
}

fn parse_bytes(value: &Json) -> Option<Vec<Vec<u8>>> {
    value
        .as_arr()?
        .iter()
        .map(|item| {
            item.as_str()
                .and_then(|item| ferrox_core::b64::decode(item.as_bytes()))
        })
        .collect()
}

/// Decrypt one OSL file and return its signed server-entry payload.
pub(crate) fn decrypt_osl(
    boxed: &[u8],
    spec: &FileSpec,
    lookup: &dyn Fn(&[u8]) -> Option<Vec<u8>>,
    public_key: &str,
) -> Result<String, String> {
    let key = spec
        .shares
        .reassemble(lookup, true)?
        .ok_or_else(|| "psiphon osl: file is not seeded".to_owned())?;
    let payload = open(&key, boxed)?;
    crate::psiphon::unpack(&payload, public_key)
}

fn open(key: &[u8], boxed: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != KEY_LEN {
        return Err("psiphon osl: key is not 32 bytes".to_owned());
    }
    let cipher = crypto_secretbox::XSalsa20Poly1305::new_from_slice(key)
        .map_err(|_| "psiphon osl: key is not 32 bytes".to_owned())?;
    let nonce = crypto_secretbox::Nonce::from_slice(&[0u8; NONCE_LEN]);
    cipher
        .decrypt(nonce, boxed)
        .map_err(|_| "psiphon osl: unbox failed".to_owned())
}

/// Lagrange interpolation at zero over GF(2^8) with the AES polynomial.
fn combine(shares: &[Option<Vec<u8>>]) -> Vec<u8> {
    let present: Vec<(u8, &[u8])> = shares
        .iter()
        .enumerate()
        .filter_map(|(index, share)| {
            share
                .as_deref()
                .map(|share| (u8::try_from(index + 1).unwrap_or(u8::MAX), share))
        })
        .collect();
    if present.len() == 1 {
        return present[0].1.to_vec();
    }
    let length = present
        .iter()
        .map(|(_, share)| share.len())
        .min()
        .unwrap_or(0);
    let mut secret = vec![0u8; length];
    for (at, byte) in secret.iter_mut().enumerate() {
        let points: Vec<(u8, u8)> = present.iter().map(|(x, share)| (*x, share[at])).collect();
        *byte = interpolate(&points);
    }
    secret
}

fn interpolate(points: &[(u8, u8)]) -> u8 {
    let mut value = 0u8;
    for (index, (ax, ay)) in points.iter().enumerate() {
        let mut weight = 1u8;
        for (other, (bx, _)) in points.iter().enumerate() {
            if index != other {
                weight = mul(weight, divide(*bx, *ax ^ *bx));
            }
        }
        value ^= mul(weight, *ay);
    }
    value
}

fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            product ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    product
}

fn divide(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    mul(a, inverse(b))
}

fn inverse(value: u8) -> u8 {
    let mut result = 1u8;
    let mut base = value;
    let mut exponent = 254u16;
    while exponent > 0 {
        if exponent & 1 != 0 {
            result = mul(result, base);
        }
        base = mul(base, base);
        exponent >>= 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shares(secret: &[u8], degree: u8) -> Vec<Option<Vec<u8>>> {
        let mut polynomial: Vec<Vec<u8>> = vec![secret.to_vec()];
        for coefficient in 1..=degree {
            polynomial.push(vec![coefficient; secret.len()]);
        }
        (1..=3u8)
            .map(|x| {
                let mut share = vec![0u8; secret.len()];
                for (at, byte) in share.iter_mut().enumerate() {
                    let mut value = 0u8;
                    for coefficient in polynomial.iter().rev() {
                        value = mul(value, x) ^ coefficient[at];
                    }
                    *byte = value;
                }
                Some(share)
            })
            .collect()
    }

    #[test]
    fn three_shares_recover_the_secret() {
        let secret: Vec<u8> = (0..32).collect();
        let all = shares(&secret, 2);
        assert_eq!(combine(&all), secret);
        assert_ne!(combine(&[all[0].clone(), all[2].clone(), None]), secret);
        let all = shares(&secret, 1);
        assert_eq!(combine(&[all[0].clone(), all[1].clone(), None]), secret);
    }

    #[cfg(unix)]
    #[test]
    fn the_slok_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory =
            std::env::temp_dir().join(format!("ferrox-osl-owner-{}", std::process::id()));
        let path = directory.join("osl-sloks");
        let store = SlokStore::open(Some(path.clone()));
        store.seed(b"id".to_vec(), vec![7u8; KEY_LEN]);
        store.save();
        let mode = std::fs::metadata(&path)
            .expect("slok file")
            .permissions()
            .mode()
            & 0o777;
        let _ = std::fs::remove_dir_all(&directory);
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn a_registry_file_spec_carries_its_md5_sum() {
        let md5 = ferrox_core::b64::encode(&[7u8; 16]);
        let text = format!(
            r#"{{"ID":"AQ==","MD5Sum":"{md5}","KeyShares":{{"Threshold":1,"BoxedShares":["Ag=="],"SLOKIDs":["Aw=="]}}}}"#
        );
        let spec = parse_file_spec(&json::parse(&text).expect("spec")).expect("file spec");
        assert_eq!(spec.md5, Some([7u8; 16]));
        let text = r#"{"ID":"AQ==","KeyShares":{"Threshold":1,"BoxedShares":["Ag=="],"SLOKIDs":["Aw=="]}}"#;
        let spec = parse_file_spec(&json::parse(text).expect("spec")).expect("file spec");
        assert_eq!(spec.md5, None);
        let text = r#"{"ID":"AQ==","MD5Sum":null,"KeyShares":{"Threshold":1,"BoxedShares":["Ag=="],"SLOKIDs":["Aw=="]}}"#;
        let spec = parse_file_spec(&json::parse(text).expect("spec")).expect("file spec");
        assert_eq!(spec.md5, None);
        let text = r#"{"ID":"AQ==","MD5Sum":"AQ==","KeyShares":{"Threshold":1,"BoxedShares":["Ag=="],"SLOKIDs":["Aw=="]}}"#;
        assert!(parse_file_spec(&json::parse(text).expect("spec")).is_none());
    }

    #[test]
    fn registry_shares_accept_null_slok_ids_and_children() {
        let text = r#"{"Threshold":1,"BoxedShares":["AQ=="],"SLOKIDs":null,"KeyShares":[{"Threshold":1,"BoxedShares":["Ag=="],"SLOKIDs":["Aw=="],"KeyShares":null}]}"#;
        let shares = json::parse(text).expect("shares");
        let shares = parse_key_shares(&shares).expect("key shares");
        assert_eq!(shares.slok_ids.len(), 0);
        assert_eq!(shares.children.len(), 1);
        assert_eq!(shares.children[0].slok_ids.len(), 1);
        assert_eq!(shares.children[0].children.len(), 0);
    }

    #[test]
    fn a_single_share_is_the_secret() {
        let secret = vec![7u8; 32];
        assert_eq!(combine(&[Some(secret.clone())]), secret);
    }

    #[test]
    fn an_osl_request_seeds_and_clears_sloks() {
        let store = SlokStore::open(None);
        let seeded = Arc::new(AtomicBool::new(false));
        let events = ServerEvents {
            sloks: Arc::clone(&store),
            seeded: Arc::clone(&seeded),
            emit_alerts: false,
            emit_sloks: false,
        };
        let id = ferrox_core::b64::encode(&[1u8; 16]);
        let key = ferrox_core::b64::encode(&[2u8; 32]);
        let payload = format!(r#"{{"seed_payload":{{"SLOKs":[{{"ID":"{id}","Key":"{key}"}}]}}}}"#);
        assert!(events.handle(b"psiphon-osl", payload.as_bytes()).is_ok());
        assert_eq!(store.get(&[1u8; 16]), Some(vec![2u8; 32]));
        assert!(seeded.load(Ordering::Acquire));
        assert!(events
            .handle(b"psiphon-osl", br#"{"clear_local_sloks":true}"#)
            .is_ok());
        assert_eq!(store.get(&[1u8; 16]), None);
    }

    #[test]
    fn an_alert_request_is_accepted_and_an_unknown_one_is_refused() {
        let events = ServerEvents {
            sloks: SlokStore::open(None),
            seeded: Arc::new(AtomicBool::new(false)),
            emit_alerts: false,
            emit_sloks: false,
        };
        assert!(events
            .handle(
                b"psiphon-alert",
                br#"{"reason":"r","subject":"s","action":["a"]}"#,
            )
            .is_ok());
        assert!(events.handle(b"unexpected", b"").is_err());
    }

    #[test]
    fn a_store_round_trips_through_its_file() {
        let path = std::env::temp_dir().join(format!("ferrox-osl-{}", std::process::id()));
        let store = SlokStore::open(Some(path.clone()));
        assert!(!store.seed(vec![1; 32], vec![2; 32]));
        store.save();
        drop(store);
        let reopened = SlokStore::open(Some(path.clone()));
        assert_eq!(reopened.get(&[1; 32]), Some(vec![2; 32]));
        let _ = std::fs::remove_file(path);
    }
}

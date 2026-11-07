//! The untunneled Psiphon tactics request: a NaCl-boxed, obfuscated JSON
//! round trip through a fronted-meek entry, and the broker specs it carries.

use crate::json::{self, Json};
use crate::psiphon_meek::{self, Meek};
use crate::psiphon_ssh::{derive_key, random, Identity, Proxy, Rc4, MAGIC, SEED_LENGTH};
use crypto_box::aead::{Aead, OsRng};
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use std::time::Duration;

const MAX_PADDING: usize = 256;
const MIN_PADDING: usize = SEED_LENGTH;
const REQUEST_NONCE: u8 = 1;
const RESPONSE_NONCE: u8 = 2;

/// The keys and front a server entry needs to answer a tactics request.
#[derive(Debug, Clone)]
pub(crate) struct Keys {
    pub(crate) public_key: String,
    pub(crate) obfuscated_key: String,
    pub(crate) meek: Meek,
}

/// One fronting address a broker spec names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Fronting {
    pub(crate) host: String,
    pub(crate) addresses: Vec<String>,
    pub(crate) disable_sni: bool,
}

/// One in-proxy broker a tactics payload names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Broker {
    pub(crate) public_key: String,
    pub(crate) root_secret: String,
    pub(crate) fronts: Vec<Fronting>,
}

/// The parts of a tactics payload this lane reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tactics {
    pub(crate) tag: String,
    pub(crate) ttl: String,
    pub(crate) brokers: Vec<Broker>,
    pub(crate) compartments: Vec<String>,
    pub(crate) stun_servers: Vec<String>,
}

impl Tactics {
    /// Fetch tactics from the first entry that advertises a tactics capability.
    pub(crate) fn fetch(
        server: &crate::psiphon_ssh::Server,
        identity: &Identity<'_>,
        timeout: Duration,
        proxy: Option<&Proxy>,
        dns: &crate::psiphon_dns::Config,
    ) -> Result<Self, String> {
        let keys = server
            .tactics
            .as_ref()
            .ok_or_else(|| "psiphon tactics: the entry has no tactics capability".to_owned())?;
        let keyword = ferrox_core::b64::decode(keys.obfuscated_key.as_bytes())
            .ok_or_else(|| "psiphon tactics: obfuscation key is not base64".to_owned())?;
        let request = api_params(identity);
        let mut obfuscator = Obfuscator::new(&keyword, MAX_PADDING)?;
        let (mut boxed, ephemeral) = seal(&keys.public_key, request.as_bytes(), REQUEST_NONCE)?;
        obfuscator.obfuscate(&mut boxed);
        let mut body = obfuscator.preamble.clone();
        body.extend_from_slice(&boxed);
        let mut reply =
            psiphon_meek::post(&keys.meek, "/", Some("tactics"), &body, timeout, proxy, dns)?;
        let boxed = open_preamble(&keyword, &mut reply)?;
        let plain = open(
            &keys.public_key,
            &ephemeral,
            &reply[boxed..],
            RESPONSE_NONCE,
        )?;
        parse_payload(&plain)
    }
}

/// A client-side obfuscator seed message, with the RC4 stream it starts.
struct Obfuscator {
    preamble: Vec<u8>,
    client: Rc4,
}

impl Obfuscator {
    fn new(keyword: &[u8], max_padding: usize) -> Result<Self, String> {
        if keyword.is_empty() {
            return Err("psiphon tactics: missing obfuscation key".to_owned());
        }
        let seed = random::<SEED_LENGTH>();
        let mut client = Rc4::new(&derive_key(&seed, keyword, b"client_to_server"));
        let span = max_padding.saturating_sub(MIN_PADDING) + 1;
        let padding_len = MIN_PADDING + usize::from(u16::from_be_bytes(random::<2>())) % span;
        let mut preamble = Vec::with_capacity(SEED_LENGTH + 8 + padding_len);
        preamble.extend_from_slice(&seed);
        preamble.extend_from_slice(&MAGIC.to_be_bytes());
        preamble.extend_from_slice(&u32::try_from(padding_len).unwrap_or(0).to_be_bytes());
        let mut padding = vec![0u8; padding_len];
        getrandom::fill(&mut padding)
            .map_err(|error| format!("psiphon tactics entropy: {error}"))?;
        preamble.extend_from_slice(&padding);
        client.apply(&mut preamble[SEED_LENGTH..]);
        Ok(Self { preamble, client })
    }

    fn obfuscate(&mut self, bytes: &mut [u8]) {
        self.client.apply(bytes);
    }
}

/// Strip the server's seed message and decrypt the boxed payload behind it, in place: the box
/// starts at the returned offset.
fn open_preamble(keyword: &[u8], reply: &mut [u8]) -> Result<usize, String> {
    let header_len = SEED_LENGTH + 8;
    if reply.len() < header_len {
        return Err("psiphon tactics: response is too short".to_owned());
    }
    let seed: [u8; SEED_LENGTH] = reply[..SEED_LENGTH]
        .try_into()
        .map_err(|_| "psiphon tactics: response seed".to_owned())?;
    let mut stream = Rc4::new(&derive_key(&seed, keyword, b"client_to_server"));
    let mut header = [0u8; 8];
    header.copy_from_slice(&reply[SEED_LENGTH..header_len]);
    stream.apply(&mut header);
    if header[..4] != MAGIC.to_be_bytes()[..] {
        return Err("psiphon tactics: response magic".to_owned());
    }
    let padding = u32::from_be_bytes(header[4..8].try_into().unwrap_or([0; 4])) as usize;
    let body = header_len
        .checked_add(padding)
        .filter(|start| *start <= reply.len())
        .ok_or_else(|| "psiphon tactics: response padding".to_owned())?;
    reply[SEED_LENGTH..header_len].copy_from_slice(&header);
    stream.apply(&mut reply[header_len..body]);
    stream.apply(&mut reply[body..]);
    Ok(body)
}

/// Box the request with the server's tactics public key, prepending the
/// ephemeral public key the response is sealed to.
fn seal(
    public_key: &str,
    plaintext: &[u8],
    nonce_byte: u8,
) -> Result<(Vec<u8>, SecretKey), String> {
    let key = ferrox_core::b64::decode(public_key.as_bytes())
        .ok_or_else(|| "psiphon tactics: request key is not base64".to_owned())?;
    let key = PublicKey::from_slice(&key)
        .map_err(|_| "psiphon tactics: request key is not 32 bytes".to_owned())?;
    let mut rng = OsRng;
    let secret = SecretKey::generate(&mut rng);
    let ephemeral = secret.public_key();
    let boxed = SalsaBox::new(&key, &secret);
    let nonce = nonce(nonce_byte);
    let cipher = boxed
        .encrypt(
            crypto_box::aead::Nonce::<SalsaBox>::from_slice(&nonce),
            plaintext,
        )
        .map_err(|_| "psiphon tactics: request encryption".to_owned())?;
    let mut payload = Vec::with_capacity(ephemeral.as_bytes().len() + cipher.len());
    payload.extend_from_slice(ephemeral.as_bytes());
    payload.extend_from_slice(&cipher);
    Ok((payload, secret))
}

/// Open the response with the request key and the ephemeral key that sealed
/// the request.
fn open(
    public_key: &str,
    ephemeral: &SecretKey,
    ciphertext: &[u8],
    nonce_byte: u8,
) -> Result<Vec<u8>, String> {
    let key = ferrox_core::b64::decode(public_key.as_bytes())
        .ok_or_else(|| "psiphon tactics: request key is not base64".to_owned())?;
    let key = PublicKey::from_slice(&key)
        .map_err(|_| "psiphon tactics: request key is not 32 bytes".to_owned())?;
    let boxed = SalsaBox::new(&key, ephemeral);
    let nonce = nonce(nonce_byte);
    boxed
        .decrypt(
            crypto_box::aead::Nonce::<SalsaBox>::from_slice(&nonce),
            ciphertext,
        )
        .map_err(|_| "psiphon tactics: response encryption".to_owned())
}

fn nonce(byte: u8) -> [u8; 24] {
    let mut bytes = [0u8; 24];
    bytes[0] = byte;
    bytes
}

fn api_params(identity: &Identity<'_>) -> String {
    let mut body = format!(
        r#"{{"session_id":"{}","propagation_channel_id":"{}","sponsor_id":"{}","client_version":"{}","client_platform":"{}","relay_protocol":"FRONTED-MEEK-OSSH","network_type":"unknown","stored_tactics_tag":"","speed_test_samples":[]"#,
        json_escape(identity.session_id),
        json_escape(identity.propagation),
        json_escape(identity.sponsor),
        json_escape(identity.version),
        json_escape(identity.platform)
    );
    if !identity.authorizations.is_empty() {
        body.push_str(r#","authorizations":["#);
        for (index, authorization) in identity.authorizations.iter().enumerate() {
            if index > 0 {
                body.push(',');
            }
            body.push('"');
            body.push_str(&json_escape(authorization));
            body.push('"');
        }
        body.push(']');
    }
    if !identity.client_features.is_empty() {
        body.push_str(r#","client_features":["#);
        for (index, feature) in identity.client_features.iter().enumerate() {
            if index > 0 {
                body.push(',');
            }
            body.push('"');
            body.push_str(&json_escape(feature));
            body.push('"');
        }
        body.push(']');
    }
    if let Some(region) = identity
        .egress_region
        .filter(|region| region.len() == 2 && region.bytes().all(|byte| byte.is_ascii_uppercase()))
    {
        body.push_str(r#","egress_region":"#);
        body.push('"');
        body.push_str(&json_escape(region));
        body.push('"');
    }
    if let Some(region) = identity.device_region {
        body.push_str(r#","device_region":"#);
        body.push('"');
        body.push_str(&json_escape(region));
        body.push('"');
    }
    body.push('}');
    body
}

fn parse_payload(payload: &[u8]) -> Result<Tactics, String> {
    let text = String::from_utf8_lossy(payload);
    let payload =
        json::parse(&text).map_err(|_| "psiphon tactics: response is not a payload".to_owned())?;
    let tag = payload
        .get("Tag")
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned();
    let Some(tactics) = payload.get("Tactics") else {
        return Ok(Tactics {
            tag,
            ttl: String::new(),
            brokers: Vec::new(),
            compartments: Vec::new(),
            stun_servers: Vec::new(),
        });
    };
    let ttl = tactics
        .get("TTL")
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned();
    let parameters = tactics.get("Parameters");
    let brokers = parameters
        .and_then(|parameters| parameters.get("InproxyBrokerSpecs"))
        .and_then(Json::as_arr)
        .map(|specs| specs.iter().filter_map(broker).collect())
        .unwrap_or_default();
    let compartments = parameters
        .and_then(|parameters| parameters.get("InproxyCommonCompartmentIDs"))
        .and_then(Json::as_arr)
        .map(|ids| {
            ids.iter()
                .filter_map(Json::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let stun_servers = parameters
        .and_then(|parameters| {
            parameters
                .get("InproxyClientSTUNServerAddresses")
                .or_else(|| parameters.get("InproxyClientSTUNServerAddressesRFC5780"))
                .or_else(|| parameters.get("InproxySTUNServerAddresses"))
                .or_else(|| parameters.get("InproxySTUNServerAddressesRFC5780"))
        })
        .and_then(Json::as_arr)
        .map(|addresses| {
            addresses
                .iter()
                .filter_map(Json::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Ok(Tactics {
        tag,
        ttl,
        brokers,
        compartments,
        stun_servers,
    })
}

fn broker(spec: &Json) -> Option<Broker> {
    let public_key = spec
        .get("BrokerPublicKey")
        .and_then(Json::as_str)
        .filter(|key| !key.is_empty())?
        .to_owned();
    let root_secret = spec
        .get("BrokerRootObfuscationSecret")
        .and_then(Json::as_str)
        .filter(|secret| !secret.is_empty())?
        .to_owned();
    let fronts = spec
        .get("BrokerFrontingSpecs")
        .and_then(Json::as_arr)
        .map(|specs| specs.iter().filter_map(fronting).collect())
        .unwrap_or_default();
    Some(Broker {
        public_key,
        root_secret,
        fronts,
    })
}

fn fronting(spec: &Json) -> Option<Fronting> {
    let host = spec.get("Host").and_then(Json::as_str)?.to_owned();
    let addresses = spec
        .get("Addresses")
        .and_then(Json::as_arr)
        .map(|addresses| {
            addresses
                .iter()
                .filter_map(Json::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let disable_sni = spec
        .get("DisableSNI")
        .and_then(Json::as_bool)
        .unwrap_or(false);
    Some(Fronting {
        host,
        addresses,
        disable_sni,
    })
}

fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch < ' ' => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", u32::from(ch));
            }
            ch => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// SSH authorizations reach the tactics API request.
    fn authorizations_reach_the_api_request() {
        let authorizations = vec!["a\"b".to_owned()];
        let identity = Identity {
            session_id: "00",
            authorizations: &authorizations,
            sponsor: "sponsor",
            propagation: "propagation",
            platform: "Android",
            version: "453",
            egress_region: None,
            device_region: None,
            device_location: None,
            client_features: &[],
            split_tunnel: false,
            split_tunnel_regions: &[],
        };
        assert!(api_params(&identity).contains(r#""authorizations":["a\"b"]"#));
    }

    #[test]
    fn a_preamble_encrypts_the_magic_and_padding() {
        let mut obfuscator = Obfuscator::new(b"key", MAX_PADDING).expect("obfuscator");
        let preamble = obfuscator.preamble.clone();
        let seed = &preamble[..SEED_LENGTH];
        let mut rest = preamble[SEED_LENGTH..].to_vec();
        let mut stream = Rc4::new(&derive_key(seed, b"key", b"client_to_server"));
        stream.apply(&mut rest);
        assert_eq!(&rest[..4], &MAGIC.to_be_bytes());
        let padding = u32::from_be_bytes(rest[4..8].try_into().expect("padding")) as usize;
        assert!((MIN_PADDING..=MAX_PADDING).contains(&padding));
        assert_eq!(rest.len(), 8 + padding);
        let mut body = b"body".to_vec();
        obfuscator.obfuscate(&mut body);
        stream.apply(&mut body);
        assert_eq!(body, b"body");
    }

    #[test]
    fn a_boxed_request_opens_into_a_boxed_response() {
        let mut rng = OsRng;
        let server_secret = SecretKey::generate(&mut rng);
        let server_public = ferrox_core::b64::encode(server_secret.public_key().as_bytes());
        let (request, client_secret) = seal(&server_public, b"hello", REQUEST_NONCE).expect("seal");
        let client_public = PublicKey::from_slice(&request[..32]).expect("ephemeral");
        let server_box = SalsaBox::new(&client_public, &server_secret);
        let plain = server_box
            .decrypt(
                crypto_box::aead::Nonce::<SalsaBox>::from_slice(&nonce(REQUEST_NONCE)),
                &request[32..],
            )
            .expect("request opens");
        assert_eq!(plain, b"hello");
        let response = server_box
            .encrypt(
                crypto_box::aead::Nonce::<SalsaBox>::from_slice(&nonce(RESPONSE_NONCE)),
                &b"world"[..],
            )
            .expect("response seals");
        assert_eq!(
            open(&server_public, &client_secret, &response, RESPONSE_NONCE).expect("open"),
            b"world"
        );
    }

    #[test]
    fn a_server_preamble_is_stripped_before_the_box() {
        let keyword = b"key";
        let mut client = Obfuscator::new(keyword, MAX_PADDING).expect("obfuscator");
        let mut body = b"box".to_vec();
        client.obfuscate(&mut body);
        let mut reply = client.preamble.clone();
        reply.extend_from_slice(&body);
        let (at, counts) = ferrox_core::alloc_count::measure(|| open_preamble(keyword, &mut reply));
        assert_eq!(&reply[at.expect("preamble")..], b"box");
        assert_eq!(counts.allocs, 0, "the reply is decrypted where it lies");
    }

    #[test]
    fn a_rejected_preamble_leaves_the_reply_untouched() {
        let keyword = b"key";
        let client = Obfuscator::new(keyword, MAX_PADDING).expect("obfuscator");
        let mut forged = client.preamble.clone();
        forged.extend_from_slice(b"box");
        forged[SEED_LENGTH] ^= 0xFF;
        let before = forged.clone();
        assert!(open_preamble(keyword, &mut forged).is_err());
        assert_eq!(forged, before, "a bad magic leaves the reply as it was");

        let seed = [0u8; SEED_LENGTH];
        let mut stream = Rc4::new(&derive_key(&seed, keyword, b"client_to_server"));
        let mut header = [0u8; 8];
        header[..4].copy_from_slice(&MAGIC.to_be_bytes());
        header[4..].copy_from_slice(&u32::MAX.to_be_bytes());
        stream.apply(&mut header);
        let mut overlong = seed.to_vec();
        overlong.extend_from_slice(&[0u8; 32]);
        overlong[SEED_LENGTH..SEED_LENGTH + 8].copy_from_slice(&header);
        let before = overlong.clone();
        assert!(open_preamble(keyword, &mut overlong).is_err());
        assert_eq!(overlong, before, "bad padding leaves the reply as it was");
    }

    #[test]
    fn a_payload_names_the_brokers_and_compartments() {
        let text = br#"{"Tag":"tag","Tactics":{"TTL":"1h","Parameters":{"InproxyBrokerSpecs":[{"BrokerPublicKey":"pk","BrokerRootObfuscationSecret":"rs","BrokerFrontingSpecs":[{"Host":"broker.example"}]}],"InproxyCommonCompartmentIDs":["c1","c2"],"InproxyClientSTUNServerAddresses":["192.0.2.10"]}}}"#;
        let tactics = parse_payload(text).expect("payload");
        assert_eq!(tactics.tag, "tag");
        assert_eq!(tactics.ttl, "1h");
        assert_eq!(
            tactics.brokers,
            vec![Broker {
                public_key: "pk".to_owned(),
                root_secret: "rs".to_owned(),
                fronts: vec![Fronting {
                    host: "broker.example".to_owned(),
                    addresses: Vec::new(),
                    disable_sni: false,
                }],
            }]
        );
        assert_eq!(tactics.compartments, vec!["c1".to_owned(), "c2".to_owned()]);
        assert_eq!(tactics.stun_servers, vec!["192.0.2.10".to_owned()]);
    }

    #[test]
    fn an_unchanged_payload_has_no_tactics() {
        let tactics = parse_payload(br#"{"Tag":"same"}"#).expect("payload");
        assert_eq!(tactics.tag, "same");
        assert_eq!(tactics.brokers, Vec::new());
    }
}

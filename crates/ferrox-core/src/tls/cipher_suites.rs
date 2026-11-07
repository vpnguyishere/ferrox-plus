//! The `tlsSettings.cipherSuites` list, turned into the exact `cipher_suites` field a
//! Go `crypto/tls` `ClientHello` puts on the wire — the reference the `PattNG` "unsafe"
//! fingerprint runs, because only that path builds the hello from `crypto/tls` rather
//! than a fixed uTLS template. xray-core parses the ':' list into `Config.CipherSuites`
//! (`transport/internet/tls/config.go`) and `crypto/tls` re-orders it by preference and
//! appends its TLS 1.3 suites (`handshake_client.go`); this module reproduces both steps.
//!
//! Byte-identity is gated by `oracle_replay_matches_go` against the Go reference captured
//! in `scripts/hello-oracle`. What this backend can put on its own wire is a separate,
//! narrower question: see `crate::tls::rustls_backend` and the method page for the
//! reachable-suite ceiling.

/// Wire version numbers, as `crypto/tls` compares them against `MinVersion`/`MaxVersion`.
const V12: u16 = 0x0303;
const V13: u16 = 0x0304;

/// The union of `crypto/tls` `CipherSuites()` and `InsecureCipherSuites()`: the names
/// xray-core maps a config token against. An unknown token is dropped, exactly as the
/// reference's `tls_xray` name lookup drops it.
const SUITES: &[(&str, u16)] = &[
    ("TLS_AES_128_GCM_SHA256", 0x1301),
    ("TLS_AES_256_GCM_SHA384", 0x1302),
    ("TLS_CHACHA20_POLY1305_SHA256", 0x1303),
    ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xc02b),
    ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 0xc02c),
    ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xc02f),
    ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 0xc030),
    ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 0xcca9),
    ("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0xcca8),
    ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 0xc009),
    ("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", 0xc00a),
    ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0xc013),
    ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 0xc014),
    ("TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009c),
    ("TLS_RSA_WITH_AES_256_GCM_SHA384", 0x009d),
    ("TLS_RSA_WITH_AES_128_CBC_SHA", 0x002f),
    ("TLS_RSA_WITH_AES_256_CBC_SHA", 0x0035),
    ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x000a),
    ("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", 0xc012),
    ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 0xc023),
    ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 0xc027),
    ("TLS_RSA_WITH_AES_128_CBC_SHA256", 0x003c),
    ("TLS_RSA_WITH_RC4_128_SHA", 0x0005),
    ("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", 0xc007),
    ("TLS_ECDHE_RSA_WITH_RC4_128_SHA", 0xc011),
];

/// `crypto/tls` `cipherSuitesPreferenceOrder`: the AES-hardware re-ordering the hello loop
/// walks. It holds only TLS 1.2 suites; the TLS 1.3 trio is appended separately.
const PREF_AES: &[u16] = &[
    0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, // AEAD w/ ECDHE
    0xc009, 0xc013, 0xc00a, 0xc014, // CBC w/ ECDHE
    0x009c, 0x009d, // AEAD w/o ECDHE
    0x002f, 0x0035, // CBC w/o ECDHE
    0xc012, 0x000a, // 3DES
    0xc023, 0xc027, 0x003c, // CBC_SHA256
    0xc007, 0xc011, 0x0005, // RC4
];

/// `crypto/tls` `cipherSuitesPreferenceOrderNoAES`: `ChaCha20` leads when the CPU has no
/// AES-GCM assembly.
const PREF_NOAES: &[u16] = &[
    0xcca9, 0xcca8, // ChaCha20Poly1305
    0xc02b, 0xc02f, 0xc02c, 0xc030, // AES-GCM w/ ECDHE
    0xc009, 0xc013, 0xc00a, 0xc014, // CBC w/ ECDHE
    0x009c, 0x009d, // AEAD w/o ECDHE
    0x002f, 0x0035, // CBC w/o ECDHE
    0xc012, 0x000a, // 3DES
    0xc023, 0xc027, 0x003c, // CBC_SHA256
    0xc007, 0xc011, 0x0005, // RC4
];

/// `defaultCipherSuitesTLS13` and its `NoAES` sibling: appended, in this order, whenever the
/// hello offers TLS 1.3.
const TLS13_AES: &[u16] = &[0x1301, 0x1302, 0x1303];
const TLS13_NOAES: &[u16] = &[0x1303, 0x1301, 0x1302];

/// `defaultCipherSuites()`: `cipherSuitesPreferenceOrder` minus the suites `crypto/tls`
/// disables without a `GODEBUG` (`disabledCipherSuites` = `CBC_SHA256` and `RC4`, `rsaKexCiphers`,
/// `tdesCiphers`). A config that named nothing (nil) falls back to exactly this set.
const DEFAULT_TLS12: &[u16] = &[
    0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014,
];

/// The suites carrying `crypto/tls`' `suiteTLS12` flag — `supportedOnlyTLS12`, dropped when
/// the hello's max version is below TLS 1.2. Every one appears only in the preference arrays.
const TLS12_ONLY: &[u16] = &[
    0xcca8, 0xcca9, 0xc02f, 0xc02b, 0xc030, 0xc02c, 0xc027, 0xc023, 0x009c, 0x009d, 0x003c,
];

/// Parse xray's ':'-joined `cipherSuites` string into ids, in config order, dropping any
/// name `crypto/tls` does not recognize. An empty result is the reference's nil list, which
/// [`hello_ids`] reads as the default set.
pub fn parse(list: &str) -> Vec<u16> {
    let mut out = Vec::new();
    for token in list.split(':') {
        let token = token.trim();
        if let Some(&(_, id)) = SUITES.iter().find(|(name, _)| *name == token) {
            out.push(id);
        }
    }
    out
}

/// The `cipher_suites` ids `crypto/tls` advertises for a parsed list between `min` and `max`
/// on a host with (`aes`) or without AES-GCM assembly. An empty `parsed` is the nil config,
/// which selects the default set.
pub fn hello_ids(parsed: &[u16], min: u16, max: u16, aes: bool) -> Vec<u16> {
    let preference = if aes { PREF_AES } else { PREF_NOAES };
    let config: &[u16] = if parsed.is_empty() {
        DEFAULT_TLS12
    } else {
        parsed
    };
    let mut out = Vec::with_capacity(config.len() + 3);
    // A hello that offers only TLS 1.3 drops the TLS 1.2 list entirely before the append, so the trio becomes the whole field.
    let only_13 = min >= V13;
    if !only_13 {
        out.extend(
            preference
                .iter()
                .copied()
                .filter(|id| config.contains(id) && !(max < V12 && TLS12_ONLY.contains(id))),
        );
    }
    if max >= V13 {
        out.extend_from_slice(if aes { TLS13_AES } else { TLS13_NOAES });
    }
    debug_assert!(
        out.len() <= 0xffff / 2,
        "cipher list must fit the 2-byte field length"
    );
    out
}

/// The field as it appears in the record: a 2-byte big-endian byte length, then each id
/// big-endian. This is the byte span the Go oracle dumps.
pub fn field_bytes(ids: &[u16]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(2 + 2 * ids.len());
    bytes.extend_from_slice(&((ids.len() * 2) as u16).to_be_bytes());
    for id in ids {
        bytes.extend_from_slice(&id.to_be_bytes());
    }
    bytes
}

/// Whether a derived field offers TLS 1.3: the trio the reference appends when its `maxVersion`
/// reaches 1.3, and the only TLS 1.3 ids `crypto/tls` ever puts in a configured list.
pub(crate) fn offers_tls13(ids: &[u16]) -> bool {
    ids.iter().any(|id| (0x1301..=0x1303).contains(id))
}

/// Whether a derived field offers a TLS 1.2 suite.
pub(crate) fn offers_tls12(ids: &[u16]) -> bool {
    ids.iter().any(|id| !(0x1301..=0x1303).contains(id))
}

/// Whether a list names both halves, where `BoringSSL` leads with the trio and rustls adds SCSV,
/// so neither stock lane writes the reference's field.
pub(crate) fn mixed(ids: &[u16]) -> bool {
    offers_tls13(ids) && ids.iter().any(|id| !(0x1301..=0x1303).contains(id))
}

/// The suites neither ring nor the legacy lane carries on either role.
const SHAPED_ONLY: [u16; 5] = [0x003c, 0xc012, 0x0005, 0xc007, 0xc011];

pub(crate) fn shaped_only(id: u16) -> bool {
    SHAPED_ONLY.contains(&id)
}

/// Whether a listener's configured list names an id only the shaped engine carries.
pub(crate) fn shaped_listener(ids: &[u16], min: Option<u16>) -> bool {
    min.unwrap_or(V12) <= V12 && ids.iter().any(|&id| shaped_only(id))
}

/// Whether a listener's derived suite list and version window leave the shaped engine the only
/// one that can serve: a shaped-only id, and a ceiling the reference would keep at TLS 1.2.
pub(crate) fn shaped_server(ids: &[u16], min: Option<u16>, max: Option<u16>) -> bool {
    shaped_listener(ids, min) && max.unwrap_or(V13) <= V12
}

/// `crypto/tls`'s `aesgcmPreferred`: the `AES-GCM` flag of the first known suite the client lists,
/// which moves a server to the `NoAES` order when a `ChaCha` or CBC suite leads.
pub(crate) fn aesgcm_preferred(client: &[u16]) -> bool {
    const AES: [u16; 8] = [
        0x1301, 0x1302, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0x009c, 0x009d,
    ];
    for &id in client {
        if AES.contains(&id) {
            return true;
        }
        if SUITES.iter().any(|&(_, known)| known == id) {
            return false;
        }
    }
    false
}

/// `crypto/tls`'s `pickCipherSuite` and `selectCipherSuite`: the global preference order
/// restricted to the configured list, then the first id the client offered that the certificate
/// can key.
pub(crate) fn server_pick(
    configured: &[u16],
    client: &[u16],
    aes: bool,
    key_ok: impl Fn(u16) -> bool,
) -> Option<u16> {
    let order = if aes { PREF_AES } else { PREF_NOAES };
    order
        .iter()
        .copied()
        .find(|id| configured.contains(id) && client.contains(id) && key_ok(*id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Replay the checked-in case script through the shipped builder and compare every
    /// emitted field to the Go reference. The fixture is embedded, not read, so this stays
    /// under Miri. The golden was captured on an AES-hardware host, so the AES branch is the
    /// one under test here; `version_12_only_suites_drop_below_1_2` and
    /// `no_aes_branch_prefers_chacha20` cover the paths the golden host cannot force.
    #[test]
    fn oracle_replay_matches_go() {
        let script = include_str!("../../../../scripts/hello-oracle/script.txt");
        let expected = include_str!("../../../../scripts/hello-oracle/expected.txt");
        let cases: Vec<&str> = script
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        let want: Vec<&str> = expected
            .lines()
            .filter_map(|l| l.strip_prefix("CS "))
            .collect();
        assert_eq!(
            cases.len(),
            want.len(),
            "script and golden case counts differ"
        );
        for (case, want) in cases.iter().zip(&want) {
            let parts: Vec<&str> = case.split_whitespace().collect();
            let list = if parts[0] == "-" { "" } else { parts[0] };
            let min = version(parts[1]);
            let max = version(parts[2]);
            let got = field_bytes(&hello_ids(&parse(list), min, max, true));
            assert_eq!(hex(&got), *want, "case: {case}");
        }
    }

    /// A max below TLS 1.2 hides the `suiteTLS12` suites and keeps the CBC/RC4/3DES ones,
    /// the one branch the AES-golden never walks.
    #[test]
    fn version_12_only_suites_drop_below_1_2() {
        let parsed = parse("TLS_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
        // 0x002f is CBC-with-ECDHE-free (up-to-1.2), 0xc02b is TLS-1.2-only and drops.
        assert_eq!(hello_ids(&parsed, 0x0301, 0x0302, true), vec![0x002f]);
    }

    /// On a host without AES-GCM assembly the `ChaCha20` suites lead and the TLS 1.3 trio
    /// re-orders, exactly the `NoAES` arrays; the AES host running the oracle cannot force it.
    #[test]
    fn no_aes_branch_prefers_chacha20() {
        let parsed = parse(
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        );
        assert_eq!(
            hello_ids(&parsed, V12, V13, false),
            vec![0xcca9, 0xc02b, 0x1303, 0x1301, 0x1302]
        );
    }

    /// A config that names nothing `crypto/tls` knows is the nil list, so the default set
    /// (preference order minus disabled/RSA/3DES) applies rather than an empty field.
    #[test]
    fn all_unknown_names_fall_back_to_the_default_set() {
        let parsed = parse("BOGUS_A:BOGUS_B");
        assert_eq!(parsed, [] as [u16; 0]);
        assert_eq!(hello_ids(&parsed, V12, V12, true), DEFAULT_TLS12);
    }

    fn version(text: &str) -> u16 {
        match text {
            "1.0" => 0x0301,
            "1.1" => 0x0302,
            "1.2" => V12,
            "1.3" => V13,
            other => panic!("bad version {other}"),
        }
    }
}

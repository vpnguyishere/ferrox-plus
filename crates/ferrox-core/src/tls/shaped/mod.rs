// A ClientHello shaped like a real browser's: the pinned uTLS parrots as data, and the handshake that carries them.
mod client;
pub(crate) mod hello;
pub(crate) mod kdf;
pub(crate) mod keys;
#[cfg(test)]
mod oracle;
mod profiles;
pub(crate) mod record;
mod rsa;
pub(crate) mod server;
pub(crate) mod ticket;
pub(crate) mod tls12;

pub(crate) use client::seal_chunks;
pub use client::Session;

use crate::tls::TlsConfig;
use std::borrow::Cow;
use std::sync::OnceLock;

/// The GREASE sentinel in a profile table: the builder draws a real value for it.
pub(crate) const GREASE: u16 = 0x0a0a;

#[derive(Clone, Copy, Debug)]
pub struct Profile {
    pub name: &'static str,
    pub ciphers: &'static [u16],
    pub shuffle: bool,
    pub exts: &'static [Ext],
}

impl Profile {
    /// uTLS's PSK profiles carry a `PreSharedKeyExtension` slot; a TLS 1.3 ticket rides only those.
    /// A custom profile's name is the config's, not uTLS's, so only its extension table can open the slot.
    fn offers_psk(&self) -> bool {
        self.exts.iter().any(|ext| ext.kind == 0x0029)
            || (self.name.contains("_psk")
                && Fingerprint::resolve(self.name)
                    .and_then(Fingerprint::profile)
                    .is_some_and(|stock| std::ptr::eq(stock, self)))
    }
}

#[derive(Debug)]
pub struct Ext {
    pub kind: u16,
    pub body: Body,
}

#[derive(Debug)]
pub enum Body {
    Grease,
    Sni,
    Pad,
    Groups(&'static [u16]),
    Sigalgs(&'static [u16]),
    Alpn(&'static [u8]),
    Versions(&'static [u16]),
    KeyShare {
        groups: &'static [u16],
        reuse: bool,
    },
    Ech {
        suites: &'static [u32],
        payloads: &'static [u16],
    },
    Raw(&'static [u8]),
}

/// A resolved fingerprint: `None` keeps the stock rustls hello, which is what
/// `unsafe` and `hellogolang` mean; a profile shapes every byte uTLS fixes.
#[derive(Clone, Copy, Debug)]
pub struct Fingerprint(Option<&'static Profile>);

impl PartialEq for Fingerprint {
    fn eq(&self, other: &Self) -> bool {
        match (self.0, other.0) {
            (Some(ours), Some(theirs)) => std::ptr::eq(ours, theirs),
            (None, None) => true,
            _ => false,
        }
    }
}

impl Eq for Fingerprint {}

impl Default for Fingerprint {
    fn default() -> Self {
        Self(Some(&profiles::P_CHROME))
    }
}

impl Fingerprint {
    /// The stock hello, by the two names uTLS gives it.
    pub const fn stock() -> Self {
        Self(None)
    }

    /// A caller-owned immutable profile as a fingerprint. The caller holds the
    /// storage for the process, so every dial shares the same table.
    #[must_use]
    pub const fn custom(profile: &'static Profile) -> Self {
        Self(Some(profile))
    }

    /// The profile's wire name, or `None` for the stock hello.
    #[must_use]
    pub fn name(self) -> Option<&'static str> {
        self.0.map(|profile| profile.name)
    }

    /// The xray default, widened to the spellings sing-box and zeronet accept: an empty
    /// name is Chrome, and a name no table knows is refused here rather than dialed as a hello no browser sends.
    pub fn resolve(name: &str) -> Option<Self> {
        let lower = name.trim();
        let lower = if lower.bytes().any(|byte| byte.is_ascii_uppercase()) {
            Cow::Owned(lower.to_ascii_lowercase())
        } else {
            Cow::Borrowed(lower)
        };
        let folded = if lower.contains(['-', '.']) {
            Cow::Owned(lower.replace(['-', '.'], "_"))
        } else {
            lower
        };
        // uTLS writes `hello<brand>`, so a separator after `hello` is the same name.
        let name = match folded.strip_prefix("hello_") {
            Some(rest) => Cow::Owned(format!("hello{rest}")),
            None => folded,
        };
        let name = name.as_ref();
        if name.is_empty()
            || name == "chrome"
            || matches!(
                name,
                "chrome_psk"
                    | "chrome_psk_shuffle"
                    | "chrome_padding_psk_shuffle"
                    | "chrome_pq"
                    | "chrome_pq_psk"
            )
        {
            return Some(Self::default());
        }
        if matches!(name, "unsafe" | "hellogolang" | "none" | "unshaped") {
            return Some(Self::stock());
        }
        if name == "random" {
            return Some(Self(Some(random_profile())));
        }
        if name == "randomized" {
            return Some(Self(Some(randomized(Some(true)))));
        }
        if name == "randomizednoalpn" {
            return Some(Self(Some(randomized(Some(false)))));
        }
        if name == "hellorandomized" {
            return Some(Self(Some(randomized(None))));
        }
        if name == "hellorandomizedalpn" {
            return Some(Self(Some(randomized(Some(true)))));
        }
        if name == "hellorandomizednoalpn" {
            return Some(Self(Some(randomized(Some(false)))));
        }
        if let Some(profile) = profiles::profile(name) {
            return Some(Self(Some(profile)));
        }
        // A preset's name without uTLS's `hello` prefix is the same preset, not a new shape.
        if !name.starts_with("hello") {
            let mut canonical = String::with_capacity(5 + name.len());
            canonical.push_str("hello");
            canonical.push_str(name);
            if let Some(profile) = profiles::profile(&canonical) {
                return Some(Self(Some(profile)));
            }
        }
        None
    }

    pub(crate) fn profile(self) -> Option<&'static Profile> {
        self.0
    }

    /// Whether this hello is uTLS's randomized generator, the one profile Psiphon's
    /// `NoDefaultTLSSessionIDProbability` may strip a session id from on TLS 1.3.
    pub fn is_randomized(self) -> bool {
        self.0.is_some_and(|profile| profile.name == "randomized")
    }

    /// REALITY needs TLS 1.3 suites and an X25519MLKEM768 share; android is the one preset without them.
    pub(crate) fn reality_profile(self) -> Option<&'static Profile> {
        self.0
            .map(|profile| profiles::reality_variant(profile).unwrap_or(profile))
    }

    /// Whether this fingerprint shapes its hello; the stock one dials rustls's own.
    pub fn is_shaped(self) -> bool {
        self.0.is_some()
    }
}

/// The eleven browser shapes xray draws `random` from once per process.
fn random_profile() -> &'static Profile {
    static PICK: OnceLock<&'static Profile> = OnceLock::new();
    PICK.get_or_init(|| {
        const POOL: [&str; 11] = [
            "hellofirefox_120",
            "hellofirefox_148",
            "hellochrome_120",
            "hellochrome_131",
            "hellochrome_133",
            "helloios_13",
            "helloios_14",
            "helloedge_106",
            "hellosafari_26_3",
            "hello360_11_0",
            "helloqq_11_1",
        ];
        let mut seed = [0u8; 8];
        let _ = getrandom::fill(&mut seed);
        let pick = usize::from(u16::from_le_bytes([seed[0], seed[1]])) % POOL.len();
        profiles::profile(POOL[pick]).expect("the pool names pinned profiles")
    })
}

/// A randomized spec is drawn once per process, as xray seeds its preset once:
/// uTLS reseeds per connection, so a spec generated per dial would leak one profile
/// per connection without making the hello any more random than its weights already do.
fn randomized(with_alpn: Option<bool>) -> &'static Profile {
    let generated = match with_alpn {
        Some(true) => &ALPN,
        Some(false) => &NO_ALPN,
        None => &AUTO,
    };
    generated.profile(with_alpn)
}

static ALPN: Generated = Generated::new();
static NO_ALPN: Generated = Generated::new();
static AUTO: Generated = Generated::new();

/// The drawn tables a generated profile borrows, held for the process so its slices are `'static`.
struct Drawn {
    ciphers: Vec<u16>,
    sigalgs: Vec<u16>,
    curves: Vec<u16>,
    shares: Vec<u16>,
    exts: OnceLock<Vec<Ext>>,
}

struct Generated {
    drawn: OnceLock<Drawn>,
    profile: OnceLock<Profile>,
}

impl Generated {
    const fn new() -> Self {
        Self {
            drawn: OnceLock::new(),
            profile: OnceLock::new(),
        }
    }

    fn profile(&'static self, mode: Option<bool>) -> &'static Profile {
        self.profile.get_or_init(|| {
            let with_alpn = mode.unwrap_or_else(|| Spec::new().chance(70));
            let drawn = self.drawn.get_or_init(draw);
            let exts = drawn.exts.get_or_init(|| build_exts(drawn, with_alpn));
            Profile {
                name: "randomized",
                ciphers: drawn.ciphers.as_slice(),
                shuffle: false,
                exts: exts.as_slice(),
            }
        })
    }
}

/// uTLS's randomized generator at the weights xray pins: TLS 1.3 always, X25519's
/// share first, and every optional extension behind its own coin.
fn draw() -> Drawn {
    let mut rng = Spec::new();
    let mut ciphers = vec![0x1301u16, 0x1302, 0x1303];
    rng.shuffle(&mut ciphers);
    let mut legacy = vec![
        0xc02bu16, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d,
    ];
    rng.shuffle(&mut legacy);
    let total = legacy.len();
    let mut kept = 1;
    for i in 1..total {
        // uTLS removes later ciphers more readily, never the first.
        if !rng.chance(40 * i / total) {
            legacy.swap(kept, i);
            kept += 1;
        }
    }
    legacy.truncate(kept);
    ciphers.extend_from_slice(&legacy);

    let mut sigalgs = vec![0x0403u16, 0x0401, 0x0503, 0x0501, 0x0201, 0x0601];
    if rng.chance(63) {
        sigalgs.push(0x0203);
    }
    if rng.chance(59) {
        sigalgs.push(0x0603);
    }
    sigalgs.push(0x0804);
    if rng.chance(90) {
        sigalgs.push(0x0805);
        sigalgs.push(0x0806);
    }
    rng.shuffle(&mut sigalgs);

    let mut curves = Vec::new();
    if rng.chance(71) {
        curves.push(keys::X25519_MLKEM768);
    }
    curves.extend_from_slice(&[keys::X25519, keys::P256, keys::P384]);

    let mut shares = vec![keys::X25519];
    if rng.chance(50) {
        shares.push(keys::P256);
    }
    if rng.chance(50) {
        shares.insert(0, keys::X25519_MLKEM768);
    }

    Drawn {
        ciphers,
        sigalgs,
        curves,
        shares,
        exts: OnceLock::new(),
    }
}

/// The extension list over a drawn table, its optional coins and shuffle included.
fn build_exts(drawn: &'static Drawn, with_alpn: bool) -> Vec<Ext> {
    let mut rng = Spec::new();
    let mut exts = vec![
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x0023,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(drawn.sigalgs.as_slice()),
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(drawn.curves.as_slice()),
        },
    ];
    if with_alpn {
        exts.push(Ext {
            kind: 0x0010,
            body: Body::Alpn(b"\x00\x0c\x02h2\x08http/1.1"),
        });
    }
    exts.push(Ext {
        kind: 0x0015,
        body: Body::Pad,
    });
    let optional = [
        (0x0005, 74, &[0x01, 0x00, 0x00, 0x00, 0x00][..]),
        (0x0012, 46, &[][..]),
        (0xff01, 75, &[0x00][..]),
        (0x0017, 77, &[][..]),
    ];
    for (kind, weight, body) in optional {
        if rng.chance(weight) {
            exts.push(Ext {
                kind,
                body: Body::Raw(body),
            });
        }
    }
    exts.push(Ext {
        kind: 0x0033,
        body: Body::KeyShare {
            groups: drawn.shares.as_slice(),
            reuse: false,
        },
    });
    exts.push(Ext {
        kind: 0x002d,
        body: Body::Raw(&[0x01, 0x01]),
    });
    let versions: &'static [u16] = if rng.chance(50) {
        &[0x0304, 0x0303, 0x0302, 0x0301]
    } else {
        &[0x0304, 0x0303]
    };
    exts.push(Ext {
        kind: 0x002b,
        body: Body::Versions(versions),
    });
    if with_alpn && rng.chance(33) {
        exts.push(Ext {
            kind: 0x44cd,
            body: Body::Raw(&[0x00, 0x03, 0x02, 0x68, 0x32]),
        });
    }
    rng.shuffle(&mut exts);
    exts
}

/// A SHAKE256 stream over a process seed, the same construction uTLS seeds its
/// spec generator with; the seed is fresh, so only the weights are shared.
struct Spec {
    xof: shake::Shake256Reader,
}

impl Spec {
    fn new() -> Self {
        use shake::{ExtendableOutput as _, Update as _, XofReader as _};
        let mut seed = [0u8; 32];
        let _ = getrandom::fill(&mut seed);
        let mut hash = shake::Shake256::default();
        hash.update(&seed);
        let mut xof = hash.finalize_xof();
        // A draw before the seed's own stretch keeps the stream independent of the first record.
        let mut warm = [0u8; 32];
        xof.read(&mut warm);
        Self { xof }
    }

    fn next(&mut self) -> u64 {
        use shake::XofReader as _;
        let mut bytes = [0u8; 8];
        self.xof.read(&mut bytes);
        u64::from_be_bytes(bytes)
    }

    fn below(&mut self, n: usize) -> usize {
        let bound = u64::try_from(n).expect("an index fits in u64");
        let zone = u64::MAX - (u64::MAX % bound);
        loop {
            let draw = self.next();
            if draw < zone {
                return usize::try_from(draw % bound).expect("a draw below the bound fits");
            }
        }
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below(i + 1);
            items.swap(i, j);
        }
    }
}

/// The profile a config's fingerprint selects, or `None` for the stock hello.
pub(crate) fn profile_of(cfg: &TlsConfig) -> Option<&'static Profile> {
    cfg.fingerprint.and_then(Fingerprint::profile)
}

/// The stock `crypto/tls` hello behind `unsafe`: no GREASE, no preset table, Go's extension order,
/// and the cipher list a config's `cipherSuites` overrides.
pub(crate) static GO_STOCK: Profile = Profile {
    name: "golang",
    ciphers: &[],
    shuffle: false,
    exts: &[
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0012,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x11ec, 0x001d, 0x0017, 0x0018, 0x0019]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603,
                0x0201, 0x0203,
            ]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[]),
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0304, 0x0303]),
        },
        Ext {
            kind: 0x0033,
            body: Body::KeyShare {
                groups: &[0x11ec, 0x001d],
                reuse: true,
            },
        },
    ],
};

/// The same table with TLS 1.2 the ceiling: no hybrid group, no key share, and the one version Go names.
pub(crate) static GO_STOCK_12: Profile = Profile {
    name: "golang",
    ciphers: &[],
    shuffle: false,
    exts: &[
        Ext {
            kind: 0x0000,
            body: Body::Sni,
        },
        Ext {
            kind: 0x000b,
            body: Body::Raw(&[0x01, 0x00]),
        },
        Ext {
            kind: 0xff01,
            body: Body::Raw(&[0x00]),
        },
        Ext {
            kind: 0x0017,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0012,
            body: Body::Raw(&[]),
        },
        Ext {
            kind: 0x0005,
            body: Body::Raw(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        },
        Ext {
            kind: 0x000a,
            body: Body::Groups(&[0x001d, 0x0017, 0x0018, 0x0019]),
        },
        Ext {
            kind: 0x000d,
            body: Body::Sigalgs(&[
                0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603,
                0x0201, 0x0203,
            ]),
        },
        Ext {
            kind: 0x0010,
            body: Body::Alpn(&[]),
        },
        Ext {
            kind: 0x002b,
            body: Body::Versions(&[0x0303]),
        },
    ],
};

/// Whether a list names an id neither ring nor `BoringSSL` carries, so only the stock shaped
/// hello can put it on the wire and negotiate it.
pub(crate) fn needs_stock_hello(ids: &[u16]) -> bool {
    ids.iter().any(|&id| {
        !crate::tls::rustls_backend::carries(id) && crate::tls::legacy::suite_name(id).is_none()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stock hello a config naming the five unreachable ids rides: Go's preference order,
    /// and the TLS 1.3 trio appended, exactly the field the oracle captured.
    #[test]
    fn the_stock_hello_carries_the_five_ids_neither_backend_has() {
        use crate::tls::cipher_suites::{field_bytes, hello_ids, parse};
        let list = "TLS_RSA_WITH_RC4_128_SHA:TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:TLS_ECDHE_RSA_WITH_RC4_128_SHA:TLS_RSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA";
        let ids = hello_ids(&parse(list), 0x0303, 0x0304, true);
        assert_eq!(
            ids,
            vec![0xc012, 0x003c, 0xc007, 0xc011, 0x0005, 0x1301, 0x1302, 0x1303]
        );
        let mut hello = hello::Hello::build(&GO_STOCK, "example.com", &[], false, &[], None)
            .expect("the stock hello builds");
        hello.set_ciphers(&ids);
        let msg = &hello.msg;
        let mut at = 4 + 2 + 32;
        at += 1 + usize::from(msg[at]);
        let len = usize::from(u16::from_be_bytes([msg[at], msg[at + 1]]));
        assert_eq!(&msg[at..at + 2 + len], field_bytes(&ids).as_slice());
    }

    /// Every accepted spelling resolves to a preset the oracle replays by name, so
    /// widening the vocabulary adds no bytes: this test holds the pointers, the oracle the preset.
    #[test]
    fn alternate_spellings_resolve_to_the_oracle_gated_profile() {
        for name in [
            " Chrome ",
            "CHROME",
            "chrome_psk",
            "chrome_psk_shuffle",
            "chrome_padding_psk_shuffle",
            "chrome_pq",
            "chrome_pq_psk",
            "chrome-133",
            "HelloChrome.133",
            "hello_chrome_133",
        ] {
            assert_eq!(
                Fingerprint::resolve(name),
                Some(Fingerprint::default()),
                "{name}"
            );
        }
        for (short, canonical) in [
            ("chrome_120", "hellochrome_120"),
            ("hello-chrome-120", "hellochrome_120"),
            ("hello_randomized", "hellorandomized"),
            ("chrome_120_pq", "hellochrome_120_pq"),
            ("chrome_106_shuffle", "hellochrome_106_shuffle"),
            ("firefox_120", "hellofirefox_120"),
            ("safari_16_0", "hellosafari_16_0"),
            ("edge_106", "helloedge_106"),
            ("ios_14", "helloios_14"),
            ("qq_11_1", "helloqq_11_1"),
            ("360_11_0", "hello360_11_0"),
            ("android_11_okhttp", "helloandroid_11_okhttp"),
        ] {
            assert_eq!(
                Fingerprint::resolve(short),
                Fingerprint::resolve(canonical),
                "{short}"
            );
        }
    }

    /// sing-box sends its PSK/PQ spellings as the plain Chrome hello, so this tree does too.
    #[test]
    fn sing_box_chrome_names_are_not_a_pq_preset() {
        assert_eq!(
            Fingerprint::resolve("chrome_pq"),
            Some(Fingerprint::default())
        );
        assert_ne!(
            Fingerprint::resolve("chrome_pq"),
            Fingerprint::resolve("hellochrome_120_pq")
        );
    }

    /// A custom profile's name is the config's, not uTLS's: only its extension table opens the PSK slot.
    #[test]
    fn a_custom_psk_name_without_the_extension_has_no_slot() {
        static SLOTS: [Ext; 1] = [Ext {
            kind: 0x0029,
            body: Body::Raw(&[]),
        }];
        let named = Profile {
            name: "fixture_psk",
            ciphers: &[],
            shuffle: false,
            exts: &[],
        };
        assert!(!named.offers_psk(), "a custom name alone opens nothing");
        let slotted = Profile {
            exts: &SLOTS,
            ..named
        };
        assert!(slotted.offers_psk(), "the extension table opens the slot");
        let stock = Fingerprint::resolve("hellochrome_112_psk_shuf")
            .and_then(Fingerprint::profile)
            .expect("a shaped preset");
        assert!(
            stock.offers_psk(),
            "uTLS's PSK parrots carry the slot by name"
        );
    }

    /// zeronet's stock spellings join uTLS's two, and an unknown name stays `None` so the
    /// config boundary can choose the reference's stock fallback.
    #[test]
    fn stock_spellings_resolve_and_unknown_names_do_not() {
        for name in ["none", "unshaped", "unsafe", "hellogolang"] {
            assert_eq!(
                Fingerprint::resolve(name),
                Some(Fingerprint::stock()),
                "{name}"
            );
        }
        assert_eq!(Fingerprint::resolve("not-a-browser"), None);
        assert_eq!(Fingerprint::resolve("hellofirefox_999"), None);
    }

    /// A name already in the table's spelling is read in place: normalization allocates only for
    /// input that has to change.
    #[test]
    fn a_table_spelling_resolves_without_a_heap_buffer() {
        for name in ["chrome", "firefox", "safari", "ios", "android", "360", "qq"] {
            let (resolved, counts) = crate::alloc_count::measure(|| Fingerprint::resolve(name));
            assert!(resolved.is_some(), "{name} names a preset");
            assert_eq!(counts.allocs, 0, "{name} resolves in place: {counts:?}");
        }
    }
}

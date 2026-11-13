//! The SSH transport the native `Psiphon` lane rides: a synchronous client for
//! the OSSH seed message, curve25519 key exchange, AES-128-CTR with
//! HMAC-SHA-256, password auth, and `direct-tcpip` channels.

use crate::psiphon_webrtc::{Conduit, Relay, WebRtcStream};
use ctr::cipher::{KeyIvInit, StreamCipher};
use ferrox_core::tls::{ClientSession, Fingerprint, TlsConfig, TlsProvider as _};
use ring::{digest, hmac, signature};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::io::{self, IoSlice, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, Instant};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

pub(crate) const MAGIC: u32 = 0x0BF5_CA7E;
pub(crate) const HASH_ITERATIONS: usize = 6000;
pub(crate) const SEED_LENGTH: usize = 16;
pub(crate) const KEY_LENGTH: usize = 16;
pub(crate) const MIN_PADDING: usize = 32;
pub(crate) const MAX_PADDING: usize = 8192;
const MAX_PACKET: usize = 256 * 1024;
pub(crate) const DEFAULT_CHANNEL_WINDOW: u32 = 2 * 1024 * 1024;
pub(crate) const CHANNEL_PACKET: u32 = 32 * 1024;
/// The reference's packet tunnel window is counted in 32 KiB packets; 0, or a
/// value outside 1..=128, uses its default of 16.
pub(crate) fn packet_tunnel_channel_window(count: Option<u64>) -> u32 {
    let count = count
        .filter(|count| (1..=128).contains(count))
        .unwrap_or(16);
    count as u32 * CHANNEL_PACKET
}
/// Channel ids are 0-based, so 0 is a server's first channel; this is the only value
/// that never names one.
const NO_CHANNEL: u32 = u32::MAX;
const WINDOW_ADJUST_AT: u64 = 256 * 1024;

/// Return credit at the cap, or at half the configured window when that comes first.
fn window_adjust_at(window: u32) -> u64 {
    WINDOW_ADJUST_AT.min(u64::from(window) / 2)
}
const IO_TIMEOUT: Duration = Duration::from_secs(120);

/// The reference's `SSHKeepAlive*` window: a jittered period, random padding,
/// an inactivity gate, and a reply deadline.
#[derive(Clone, Copy, Debug)]
pub(crate) struct KeepAlive {
    pub(crate) period_min: Duration,
    pub(crate) period_max: Duration,
    pub(crate) padding_min: usize,
    pub(crate) padding_max: usize,
    pub(crate) inactive: Duration,
    pub(crate) timeout: Duration,
}

impl KeepAlive {
    /// A period drawn uniformly from the configured window.
    fn period(&self) -> Duration {
        let span = self.period_max.saturating_sub(self.period_min);
        let unit = f64::from(u16::from_be_bytes(random::<2>())) / 65_536.0;
        self.period_min + span.mul_f64(unit)
    }

    /// A padding length drawn uniformly from the configured range.
    fn padding(&self) -> usize {
        let span = self.padding_max.saturating_sub(self.padding_min);
        self.padding_min + usize::from(u16::from_be_bytes(random::<2>())) % (span + 1)
    }
}
const MAX_IDENTIFICATION: usize = 1024;
const CLIENT_CAPABILITIES: &str = "server-requests";

/// The server-initiated requests a client answers after advertising the capability.
pub(crate) trait ServerRequests: Send + Sync {
    /// Answer one request; the returned bytes are the success payload.
    fn handle(&self, name: &[u8], payload: &[u8]) -> Result<Vec<u8>, String>;
}
/// One channel packet plus its header, padding and tag; a larger peer packet
/// grows the one buffer it needs instead of every pooled buffer.
const PACKET_CHUNK: usize = CHANNEL_PACKET as usize + 1024;
/// The pool holds a whole channel window plus the packets a flow is writing,
/// so a saturated download recycles buffers instead of allocating one per packet.
const PACKET_POOL: usize = (DEFAULT_CHANNEL_WINDOW / CHANNEL_PACKET) as usize + 8;
const ENTROPY: usize = 4096;
/// A Shadowsocks salt's length, the most a configured prefix may replace.
const SHADOWSOCKS_SALT: usize = 32;
/// The obfuscator preamble header: seed, magic value and padding length.
const OSSH_PREAMBLE_HEADER: usize = SEED_LENGTH + 8;
const OSSH_PREFIX_TERMINATOR: usize = 16;
const OSSH_PREFIX_MAX: usize = 65_536;
const OSSH_PREFIX_HEADER_MAX: usize = 4_096;

const MSG_DISCONNECT: u8 = 1;
const MSG_IGNORE: u8 = 2;
const MSG_DEBUG: u8 = 4;
const MSG_SERVICE_REQUEST: u8 = 5;
const MSG_SERVICE_ACCEPT: u8 = 6;
const MSG_KEXINIT: u8 = 20;
const MSG_NEWKEYS: u8 = 21;
const MSG_KEX_ECDH_INIT: u8 = 30;
const MSG_KEX_ECDH_REPLY: u8 = 31;
const MSG_USERAUTH_REQUEST: u8 = 50;
const MSG_USERAUTH_FAILURE: u8 = 51;
const MSG_USERAUTH_SUCCESS: u8 = 52;
const MSG_GLOBAL_REQUEST: u8 = 80;
const MSG_REQUEST_SUCCESS: u8 = 81;
const MSG_REQUEST_FAILURE: u8 = 82;
const MSG_CHANNEL_OPEN: u8 = 90;
const MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
const MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
/// The server classified this target as untunneled; dial it directly instead.
const CHANNEL_REJECT_SPLIT_TUNNEL: u32 = 0xFE00_0000;
const MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
const MSG_CHANNEL_DATA: u8 = 94;
const MSG_CHANNEL_EOF: u8 = 96;
const MSG_CHANNEL_CLOSE: u8 = 97;
const MSG_CHANNEL_REQUEST: u8 = 98;
const MSG_CHANNEL_SUCCESS: u8 = 99;
const MSG_CHANNEL_FAILURE: u8 = 100;

/// One transport below SSH: a TCP socket or an in-proxy WebRTC data channel.
pub(crate) enum Stream {
    Tcp(TcpStream),
    Fragment(crate::psiphon_fragment::FragmentStream),
    Quic(crate::psiphon_quic::QuicStream),
    Shadowsocks(crate::psiphon_shadowsocks::Stream<TcpStream>),
    ShadowsocksFragment(
        crate::psiphon_shadowsocks::Stream<crate::psiphon_fragment::FragmentStream>,
    ),
    WebRtcShadowsocks(crate::psiphon_shadowsocks::Stream<WebRtcStream>),
    WebRtc(WebRtcStream),
}

impl From<TcpStream> for Stream {
    fn from(socket: TcpStream) -> Self {
        Self::Tcp(socket)
    }
}

impl ferrox_core::tls::RecordAlignment for Stream {}

impl Stream {
    fn try_clone(&self) -> io::Result<Self> {
        match self {
            Self::Tcp(socket) => socket.try_clone().map(Self::Tcp),
            Self::Fragment(stream) => stream.try_clone().map(Self::Fragment),
            Self::Quic(stream) => Ok(Self::Quic(stream.clone())),
            Self::Shadowsocks(stream) => stream.try_clone().map(Self::Shadowsocks),
            Self::ShadowsocksFragment(stream) => stream.try_clone().map(Self::ShadowsocksFragment),
            Self::WebRtcShadowsocks(stream) => Ok(Self::WebRtcShadowsocks(stream.try_clone())),
            Self::WebRtc(stream) => Ok(Self::WebRtc(stream.clone())),
        }
    }

    fn set_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Tcp(socket) => socket
                .set_read_timeout(timeout)
                .and_then(|()| socket.set_write_timeout(timeout)),
            Self::Fragment(stream) => stream
                .set_read_timeout(timeout)
                .and_then(|()| stream.set_write_timeout(timeout)),
            Self::Quic(stream) => {
                stream.set_timeout(timeout);
                Ok(())
            }
            Self::Shadowsocks(stream) => stream.set_timeout(timeout),
            Self::ShadowsocksFragment(stream) => stream.set_timeout(timeout),
            Self::WebRtcShadowsocks(stream) => {
                stream.set_timeout(timeout);
                Ok(())
            }
            Self::WebRtc(stream) => {
                stream.set_timeout(timeout);
                Ok(())
            }
        }
    }

    /// Set or clear only the read timeout.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Tcp(socket) => socket.set_read_timeout(timeout),
            Self::Fragment(stream) => stream.set_read_timeout(timeout),
            Self::Quic(stream) => {
                stream.set_read_timeout(timeout);
                Ok(())
            }
            Self::Shadowsocks(stream) => stream.set_read_timeout(timeout),
            Self::ShadowsocksFragment(stream) => stream.set_read_timeout(timeout),
            Self::WebRtcShadowsocks(stream) => {
                stream.set_read_timeout(timeout);
                Ok(())
            }
            Self::WebRtc(stream) => {
                stream.set_read_timeout(timeout);
                Ok(())
            }
        }
    }

    fn shutdown(&self) -> io::Result<()> {
        match self {
            Self::Tcp(socket) => socket.shutdown(Shutdown::Both),
            Self::Fragment(stream) => stream.shutdown(Shutdown::Both),
            Self::Quic(stream) => {
                stream.shutdown();
                Ok(())
            }
            Self::Shadowsocks(stream) => stream.shutdown(),
            Self::ShadowsocksFragment(stream) => stream.shutdown(),
            Self::WebRtcShadowsocks(stream) => {
                stream.shutdown();
                Ok(())
            }
            Self::WebRtc(stream) => {
                stream.shutdown();
                Ok(())
            }
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(socket) => socket.read(buf),
            Self::Fragment(stream) => stream.read(buf),
            Self::Quic(stream) => stream.read(buf),
            Self::Shadowsocks(stream) => stream.read(buf),
            Self::ShadowsocksFragment(stream) => stream.read(buf),
            Self::WebRtcShadowsocks(stream) => stream.read(buf),
            Self::WebRtc(stream) => stream.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(socket) => socket.write(buf),
            Self::Fragment(stream) => stream.write(buf),
            Self::Quic(stream) => stream.write(buf),
            Self::Shadowsocks(stream) => stream.write(buf),
            Self::ShadowsocksFragment(stream) => stream.write(buf),
            Self::WebRtcShadowsocks(stream) => stream.write(buf),
            Self::WebRtc(stream) => stream.write(buf),
        }
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        match self {
            Self::Tcp(socket) => socket.write_vectored(bufs),
            Self::Fragment(stream) => stream.write_vectored(bufs),
            Self::Quic(stream) => stream.write_vectored(bufs),
            Self::Shadowsocks(stream) => stream.write_vectored(bufs),
            Self::ShadowsocksFragment(stream) => stream.write_vectored(bufs),
            Self::WebRtcShadowsocks(stream) => stream.write_vectored(bufs),
            Self::WebRtc(stream) => {
                let parts: Vec<&[u8]> = bufs.iter().map(|buf| &buf[..]).collect();
                stream.write_parts(&parts)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(socket) => socket.flush(),
            Self::Fragment(stream) => stream.flush(),
            Self::Quic(stream) => stream.flush(),
            Self::Shadowsocks(stream) => stream.flush(),
            Self::ShadowsocksFragment(stream) => stream.flush(),
            Self::WebRtcShadowsocks(stream) => stream.flush(),
            Self::WebRtc(stream) => stream.flush(),
        }
    }
}

/// The Shadowsocks port and keys a `SHADOWSOCKS-OSSH` variant dials.
#[derive(Debug, Clone)]
pub(crate) struct Shadowsocks {
    pub(crate) port: u16,
    pub(crate) key: String,
    pub(crate) obfuscation_key: Option<String>,
}

/// The parts of a signed server entry this transport dials.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct Server {
    pub(crate) host: String,
    pub(crate) address: IpAddr,
    pub(crate) port: u16,
    pub(crate) ssh_port: Option<u16>,
    pub(crate) quic: bool,
    pub(crate) quic_port: Option<u16>,
    pub(crate) quic_versions: Vec<String>,
    pub(crate) quic_noise: Option<String>,
    pub(crate) user: String,
    pub(crate) password: String,
    pub(crate) host_key: Vec<u8>,
    pub(crate) obfuscation_key: Option<String>,
    pub(crate) tls_obfuscation_key: Option<String>,
    pub(crate) meek_obfuscated_key: Option<String>,
    pub(crate) region: Option<String>,
    pub(crate) provider_id: Option<String>,
    pub(crate) fronting_provider_id: Option<String>,
    pub(crate) tag: String,
    pub(crate) web_server_secret: String,
    pub(crate) configuration_version: i32,
    /// Whether the protocol limit that selected this entry lets it take CDN
    /// scan candidates; a bare limit keeps the advertised fronting host.
    pub(crate) scan_cdn: bool,
    pub(crate) ssh_api: bool,
    pub(crate) direct: bool,
    pub(crate) tls: bool,
    pub(crate) tls_port: Option<u16>,
    pub(crate) ss: bool,
    pub(crate) shadowsocks: Option<Shadowsocks>,
    pub(crate) meek: Option<crate::psiphon_meek::Meek>,
    pub(crate) unfronted_meek: Option<crate::psiphon_meek::Meek>,
    pub(crate) inproxy_meek: Option<crate::psiphon_meek::Meek>,
    pub(crate) tactics: Option<crate::psiphon_tactics::Keys>,
    pub(crate) inproxy: Option<crate::psiphon_broker::Destination>,
    pub(crate) tls_inproxy: Option<crate::psiphon_broker::Destination>,
    pub(crate) inproxy_shadowsocks_key: Option<String>,
    pub(crate) channel_window: u32,
    pub(crate) packet_tunnel_channel_window: u32,
}

impl Server {
    /// The DSL tag: the network's explicit tag, else the reference's HMAC of
    /// the address under the web server secret.
    #[must_use]
    pub(crate) fn dsl_tag(&self) -> String {
        if !self.tag.is_empty() {
            return self.tag.clone();
        }
        if self.web_server_secret.is_empty() {
            return String::new();
        }
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.web_server_secret.as_bytes());
        ferrox_core::b64::encode(hmac::sign(&key, self.host.as_bytes()).as_ref())
    }

    /// The obfuscated shape when the entry carries an OSSH key or a meek front, plain SSH otherwise.
    #[must_use]
    pub(crate) fn obfuscated(&self) -> bool {
        self.ss || self.obfuscation_key.is_some() || self.meek.is_some()
    }

    /// The `SHADOWSOCKS-OSSH` sibling of an entry that also names another direct port.
    #[must_use]
    pub(crate) fn shadowsocks_variant(&self) -> Option<Self> {
        if self.ss || self.quic {
            return None;
        }
        let ss = self.shadowsocks.as_ref()?;
        let mut variant = self.clone();
        variant.ss = true;
        variant.quic = false;
        variant.quic_port = None;
        variant.direct = true;
        variant.port = ss.port;
        variant.obfuscation_key = ss
            .obfuscation_key
            .clone()
            .filter(|key| !key.is_empty())
            .or_else(|| self.obfuscation_key.clone());
        variant.tls = false;
        variant.tls_port = None;
        variant.meek = None;
        variant.unfronted_meek = None;
        variant.tactics = None;
        variant.inproxy = None;
        variant.tls_inproxy = None;
        Some(variant)
    }

    /// The `QUIC-OSSH` sibling of any direct entry that names a QUIC port.
    #[must_use]
    pub(crate) fn quic_variant(&self) -> Option<Self> {
        if self.quic {
            return None;
        }
        let port = self.quic_port?;
        let supported: Vec<&str> = if self.quic_versions.is_empty() {
            crate::psiphon_quic::SUPPORTED_QUIC_VERSIONS.to_vec()
        } else {
            self.quic_versions
                .iter()
                .map(String::as_str)
                .filter(|version| crate::psiphon_quic::SUPPORTED_QUIC_VERSIONS.contains(version))
                .collect()
        };
        if supported.is_empty() {
            return None;
        }
        let index = usize::from(random::<1>()[0]) % supported.len();
        let version = (*supported.get(index)?).to_owned();
        let mut variant = self.clone();
        variant.quic = true;
        variant.quic_versions = vec![version];
        variant.direct = true;
        variant.port = port;
        if variant.obfuscation_key.is_none() {
            variant.obfuscation_key = variant
                .tls_obfuscation_key
                .clone()
                .or_else(|| variant.meek_obfuscated_key.clone());
        }
        variant.tls = false;
        variant.tls_port = None;
        variant.ss = false;
        variant.shadowsocks = None;
        variant.meek = None;
        variant.unfronted_meek = None;
        variant.tactics = None;
        variant.inproxy = None;
        variant.tls_inproxy = None;
        Some(variant)
    }
}

/// The `ShadowsocksPrefixSpecs` transform: a generated byte prefix replaces the leading
/// salt bytes, selected by dial port and applied only when its probability lands.
#[derive(Clone, Debug, Default)]
pub(crate) struct ShadowsocksPrefix {
    pub(crate) probability: f64,
    pub(crate) specs: Vec<(String, String)>,
    pub(crate) scoped: Vec<(String, Vec<String>)>,
}

/// The `OSSHPrefixSpecs` transform: generated bytes and their terminator lead the seed
/// message, with the selected spec name carried in the encrypted prefix header.
#[derive(Clone, Debug, Default)]
pub(crate) struct OsshPrefix {
    pub(crate) probability: f64,
    pub(crate) specs: Vec<(String, String)>,
    pub(crate) scoped: Vec<(String, Vec<String>)>,
    pub(crate) split_min: Duration,
    pub(crate) split_max: Duration,
}

#[derive(Debug)]
pub(crate) struct OsshPrefixBytes {
    pub(crate) bytes: Vec<u8>,
    pub(crate) prefix_len: usize,
    pub(crate) name: String,
    pub(crate) split_min: Duration,
    pub(crate) split_max: Duration,
}

/// The trust anchors a Psiphon TLS dial verifies with, or none when the reference skips
/// verification. A named file is read when a dial needs it, as the reference reads it per dial;
/// its `Debug` never prints certificate bytes.
#[derive(Clone, Default)]
pub(crate) enum TlsRoots {
    #[default]
    System,
    Empty,
    File(String),
}

impl TlsRoots {
    /// The anchors this dial verifies with, reading a named file at the point the reference does.
    pub(crate) fn load(&self) -> Result<ferrox_core::tls::Anchors, String> {
        match self {
            Self::System => Ok(crate::quic::system_roots()),
            Self::Empty => Ok(Vec::new().into()),
            Self::File(path) => {
                let pem = std::fs::read(path)
                    .map_err(|error| format!("psiphon: trusted CA file {path}: {error}"))?;
                Ok(crate::quic::parse_ca_pem(&pem).into())
            }
        }
    }
}

impl std::fmt::Debug for TlsRoots {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::System => f.write_str("TlsRoots(system)"),
            Self::Empty => f.write_str("TlsRoots(empty)"),
            Self::File(path) => f.debug_tuple("TlsRootsFile").field(path).finish(),
        }
    }
}

/// The TLS shape a config can impose on the shaped `TLS-OSSH` hello: an exact padding
/// extension body and a host name chosen from a list or generated from a regex.
#[derive(Clone, Debug)]
pub(crate) struct TlsShape {
    pub(crate) min_padding: u16,
    pub(crate) max_padding: u16,
    pub(crate) sni_names: Vec<String>,
    pub(crate) transform_probability: f64,
    pub(crate) hostname_patterns: Vec<String>,
    pub(crate) limit_protocols: Vec<String>,
    pub(crate) profiles: Vec<Fingerprint>,
    /// `CustomTLSProfiles`: each accepted spec becomes one immutable profile.
    pub(crate) custom_profiles: Vec<Fingerprint>,
    /// `UseOnlyCustomTLSProfiles`, ignored when no custom profile survives a provider filter.
    pub(crate) use_only_custom_profiles: bool,
    /// `DisableFrontingProviderTLSProfiles`, keyed by fronting provider ID.
    pub(crate) disable_fronting_profiles: Vec<(String, Vec<String>)>,
    /// A `FrontedMeekDialOverrides` or `TLSProfile` choice that bypasses the draw.
    pub(crate) forced_profile: Option<Fingerprint>,
    pub(crate) randomized_probability: f64,
    pub(crate) shadowsocks_prefix: ShadowsocksPrefix,
    pub(crate) ossh_prefix: OsshPrefix,
    pub(crate) ossh_seed_transform: crate::psiphon_dns::ProtocolTransforms,
    pub(crate) quic_nonce_transform: crate::psiphon_dns::ProtocolTransforms,
    pub(crate) direct_http_transform: crate::psiphon_dns::ProtocolTransforms,
    pub(crate) fronted_http_transform: crate::psiphon_dns::ProtocolTransforms,
    pub(crate) obfuscated_min_padding: usize,
    pub(crate) obfuscated_max_padding: usize,
    pub(crate) fragmentor: crate::psiphon_fragment::Fragmentor,
    /// The chance a relay names its cookie with a cover word.
    pub(crate) meek_alternate_cookie_name: f64,
    /// The chance a relay draws a cover request content type.
    pub(crate) meek_alternate_content_type: f64,
    /// The chance a relay applies the request-shaping profile.
    pub(crate) meek_traffic_shaping: f64,
    /// The protocols that admit the request-shaping profile; empty admits all.
    pub(crate) meek_traffic_shaping_protocols: Vec<String>,
    /// The smallest shaped request cap.
    pub(crate) meek_min_limit_request: usize,
    /// The largest shaped request cap.
    pub(crate) meek_max_limit_request: usize,
    /// The chance a shaped connection drops after a successful round trip.
    pub(crate) meek_redial_tls: f64,
    /// The chance a meek relay pads its request and response payloads.
    pub(crate) meek_payload_padding: f64,
    /// The chance a padded empty request omits its padding entirely.
    pub(crate) meek_payload_padding_omit: f64,
    /// The smallest padding size.
    pub(crate) meek_payload_padding_min: usize,
    /// The largest padding size.
    pub(crate) meek_payload_padding_max: usize,
    /// The chance a randomized TLS 1.3 dial omits the legacy session id.
    pub(crate) no_default_tls_session_id_probability: f64,
    /// The chance a TLS-OSSH dial carries a client-made obfuscated ticket.
    pub(crate) obfuscated_ticket_probability: f64,
    /// The anchors a verified TLS dial uses: the system store, or the config's own file.
    pub(crate) roots: TlsRoots,
    /// The reference's `DisableSystemRootCAs`, which skips verification and forbids verify fields.
    pub(crate) disable_system_root_cas: bool,
    /// The chance a TLS dial splits its `ClientHello` at the SNI.
    pub(crate) tls_fragment_client_hello: f64,
    /// The protocols that admit `ClientHello` fragmentation; empty admits all.
    pub(crate) tls_fragment_client_hello_protocols: Vec<String>,
    /// The chance an HTTP dial draws a browser User-Agent.
    pub(crate) user_agent_probability: f64,
    /// The chance a QUIC dial attempts 0-RTT.
    pub(crate) quic_dial_early: f64,
    /// The chance a QUIC dial disables path-MTU discovery.
    pub(crate) quic_disable_path_mtu: f64,
    /// The chance a non-fronted QUIC dial carries a client-made obfuscated PSK.
    pub(crate) quic_obfuscated_psk: f64,
}

/// The reference defaults for one lane's TLS shape.
impl Default for TlsShape {
    fn default() -> Self {
        Self {
            min_padding: 0,
            max_padding: 0,
            sni_names: Vec::new(),
            transform_probability: 0.0,
            hostname_patterns: Vec::new(),
            limit_protocols: Vec::new(),
            profiles: Vec::new(),
            custom_profiles: Vec::new(),
            use_only_custom_profiles: false,
            disable_fronting_profiles: Vec::new(),
            forced_profile: None,
            randomized_probability: 0.0,
            shadowsocks_prefix: ShadowsocksPrefix::default(),
            ossh_prefix: OsshPrefix::default(),
            ossh_seed_transform: crate::psiphon_dns::ProtocolTransforms::default(),
            quic_nonce_transform: crate::psiphon_dns::ProtocolTransforms::default(),
            direct_http_transform: crate::psiphon_dns::ProtocolTransforms::default(),
            fronted_http_transform: crate::psiphon_dns::ProtocolTransforms::default(),
            obfuscated_min_padding: MIN_PADDING,
            obfuscated_max_padding: MAX_PADDING,
            fragmentor: crate::psiphon_fragment::Fragmentor::default(),
            meek_alternate_cookie_name: 0.5,
            meek_alternate_content_type: 0.5,
            meek_traffic_shaping: 1.0,
            meek_traffic_shaping_protocols: Vec::new(),
            meek_min_limit_request: crate::psiphon_meek::MAX_REQUEST_PAYLOAD,
            meek_max_limit_request: crate::psiphon_meek::MAX_REQUEST_PAYLOAD,
            meek_redial_tls: 0.0,
            meek_payload_padding: 0.0,
            meek_payload_padding_omit: 0.0,
            meek_payload_padding_min: 0,
            meek_payload_padding_max: 65_533,
            no_default_tls_session_id_probability: 0.5,
            obfuscated_ticket_probability: 0.5,
            roots: TlsRoots::default(),
            disable_system_root_cas: false,
            tls_fragment_client_hello: 0.0,
            tls_fragment_client_hello_protocols: Vec::new(),
            user_agent_probability: 0.5,
            quic_dial_early: 1.0,
            quic_disable_path_mtu: 0.0,
            quic_obfuscated_psk: 0.5,
        }
    }
}

fn profile_enabled(profile: Fingerprint, disabled: &[String]) -> bool {
    profile
        .name()
        .is_none_or(|name| !disabled.iter().any(|disabled| disabled == name))
}

impl TlsShape {
    /// The browser hello one dial presents: a configured parrot drawn uniformly, the
    /// reference's randomized shape when its coin lands, or the unshaped hello when nothing is allowed.
    pub(crate) fn fingerprint(&self, fronted: bool, provider: Option<&str>) -> Fingerprint {
        if let Some(profile) = self.forced_profile {
            return profile;
        }
        let disabled: &[String] = if fronted {
            provider
                .and_then(|provider| {
                    self.disable_fronting_profiles
                        .iter()
                        .find(|(key, _)| key == provider)
                })
                .map_or(&[], |(_, names)| names.as_slice())
        } else {
            &[]
        };
        let fallback = if profile_enabled(Fingerprint::default(), disabled) {
            Fingerprint::default()
        } else {
            Fingerprint::stock()
        };
        let custom: Vec<Fingerprint> = self
            .custom_profiles
            .iter()
            .copied()
            .filter(|profile| profile_enabled(*profile, disabled))
            .collect();
        let mut stock: Vec<Fingerprint> = if self.use_only_custom_profiles && !custom.is_empty() {
            Vec::new()
        } else if self.profiles.is_empty() {
            vec![fallback]
        } else {
            self.profiles
                .iter()
                .copied()
                .filter(|profile| profile_enabled(*profile, disabled))
                .collect()
        };
        if stock.is_empty() && custom.is_empty() {
            stock.push(fallback);
        }

        let draw = f64::from(u16::from_be_bytes(dial_random::<2>())) / 65_536.0;
        if !stock.is_empty()
            && self.randomized_probability > 0.0
            && draw < self.randomized_probability
        {
            if let Some(profile) = Fingerprint::resolve("randomized")
                .filter(|profile| profile_enabled(*profile, disabled))
            {
                return profile;
            }
        }

        let mut candidates = custom;
        candidates.extend(stock);
        let index = usize::from(dial_random::<1>()[0]) % candidates.len();
        candidates[index]
    }

    /// A configured profile by name, for a `FrontedMeekDialOverrides` or `TLSProfile` choice.
    pub(crate) fn named_profile(&self, name: &str) -> Option<Fingerprint> {
        self.custom_profiles
            .iter()
            .copied()
            .find(|profile| profile.name().is_some_and(|candidate| candidate == name))
            .or_else(|| Fingerprint::resolve(name))
    }

    /// The prefix one Shadowsocks salt starts with, or `None` to keep the salt random.
    pub(crate) fn shadowsocks_prefix(&self, port: &str) -> Option<Vec<u8>> {
        self.shadowsocks_prefix.generate(port)
    }

    /// The generated OSSH prefix for one dial, or `None` to write the bare seed message.
    pub(crate) fn ossh_prefix(&self, port: &str, keyword: &str) -> Option<OsshPrefixBytes> {
        self.ossh_prefix.generate(port, keyword)
    }

    /// Transform the OSSH seed in place before its RC4 keys are derived.
    pub(crate) fn ossh_seed(&self, seed: &mut [u8; SEED_LENGTH]) -> Result<(), String> {
        let selected = self.ossh_seed_transform.selected("");
        apply_seed_transform(selected.as_deref().map(Vec::as_slice), seed)
    }

    /// The HTTP transform this connection selected, scoped by fronting provider when fronted.
    pub(crate) fn http_transform(
        &self,
        fronted: bool,
        provider: Option<&str>,
    ) -> Option<std::sync::Arc<Vec<crate::psiphon_dns::Transform>>> {
        if fronted {
            self.fronted_http_transform.selected(provider.unwrap_or(""))
        } else {
            self.direct_http_transform.selected("")
        }
    }

    /// Whether this dial may fragment. An OSSH or Shadowsocks prefix suppresses the
    /// fragmentor unless `OSSHPrefixEnableFragmentor` turns it back on.
    pub(crate) fn may_fragment(&self, protocol: &str) -> bool {
        self.fragmentor.may_fragment(
            protocol,
            self.shadowsocks_prefix.configured() || self.ossh_prefix.configured(),
        )
    }

    /// The OSSH preamble padding for one dial: the reference's configurable window, with
    /// `MIN_PADDING..=MAX_PADDING` as the default carried by [`TlsShape::default`].
    pub(crate) fn obfuscated_padding(&self) -> usize {
        let low = self.obfuscated_min_padding.max(MIN_PADDING);
        let high = self.obfuscated_max_padding.max(low);
        if high == low {
            return low;
        }
        low + usize::from(u16::from_be_bytes(dial_random::<2>())) % (high - low + 1)
    }

    /// The padding body length for one dial, or `None` when no maximum is configured.
    pub(crate) fn padding(&self) -> Option<u16> {
        if self.max_padding == 0 {
            return None;
        }
        let low = self.min_padding.min(self.max_padding);
        let high = self.min_padding.max(self.max_padding);
        let span = u32::from(high - low) + 1;
        let draw = u32::from(u16::from_be_bytes(dial_random::<2>()));
        Some(low + u16::try_from(draw % span).unwrap_or(0))
    }

    /// The SNI for one dial: an explicit name, a generated one when the coin lands, or the
    /// server's own host, with a protocol limit applied first as the reference does.
    pub(crate) fn sni(&self, protocol: &str, server_name: &str) -> String {
        let allowed = self.limit_protocols.is_empty()
            || self
                .limit_protocols
                .iter()
                .any(|name| name.eq_ignore_ascii_case(protocol));
        if !allowed {
            return server_name.to_owned();
        }
        if !self.sni_names.is_empty() {
            let index = usize::from(dial_random::<1>()[0]) % self.sni_names.len();
            return self.sni_names[index].clone();
        }
        if self.transform_probability > 0.0 && !self.hostname_patterns.is_empty() {
            let draw = f64::from(u16::from_be_bytes(dial_random::<2>())) / 65_536.0;
            if draw < self.transform_probability {
                let index = usize::from(dial_random::<1>()[0]) % self.hostname_patterns.len();
                if let Some(name) = random_hostname(&self.hostname_patterns[index]) {
                    return name;
                }
            }
        }
        server_name.to_owned()
    }

    /// Whether this randomized TLS 1.3 dial omits its legacy session id, as uTLS does when
    /// Psiphon's `NoDefaultTLSSessionIDProbability` coin lands.
    pub(crate) fn omit_session_id(&self, fingerprint: Fingerprint) -> bool {
        if self.no_default_tls_session_id_probability <= 0.0 || !fingerprint.is_randomized() {
            return false;
        }
        let draw = f64::from(u16::from_be_bytes(dial_random::<2>())) / 65_536.0;
        draw < self.no_default_tls_session_id_probability
    }

    /// The shared key one dial's obfuscated ticket uses: the session-ticket feature always when the
    /// protocol names it, a TLS-OSSH dial when its coin lands, and nothing for every other lane.
    pub(crate) fn obfuscated_ticket(
        &self,
        protocol: &str,
        key: &str,
    ) -> Result<Option<ferrox_core::tls::ObfuscatedTicket>, String> {
        let upper = protocol.to_ascii_uppercase();
        let enabled = if upper.contains("UNFRONTED-MEEK-SESSION-TICKET") {
            true
        } else if upper == "TLS-OSSH" {
            let draw = f64::from(u16::from_be_bytes(dial_random::<2>())) / 65_536.0;
            draw < self.obfuscated_ticket_probability
        } else {
            false
        };
        if !enabled || key.is_empty() {
            return Ok(None);
        }
        ferrox_core::realm::hex_decode::<32>(key)
            .map(|key| Some(ferrox_core::tls::ObfuscatedTicket::new(key)))
            .ok_or_else(|| "psiphon tls: invalid obfuscated session ticket key".to_owned())
    }

    /// Whether this TLS dial splits its `ClientHello` at the SNI, when the
    /// protocol is admitted and the coin lands.
    pub(crate) fn fragment_client_hello(&self, protocol: &str) -> bool {
        if self.tls_fragment_client_hello <= 0.0 {
            return false;
        }
        if !self.tls_fragment_client_hello_protocols.is_empty()
            && !self
                .tls_fragment_client_hello_protocols
                .iter()
                .any(|name| name.eq_ignore_ascii_case(protocol))
        {
            return false;
        }
        let draw = f64::from(u16::from_be_bytes(dial_random::<2>())) / 65_536.0;
        draw < self.tls_fragment_client_hello
    }
}

impl ShadowsocksPrefix {
    /// Whether the prefix is applied at all, by probability and by a configured probe.
    fn configured(&self) -> bool {
        self.probability > 0.0 && !self.specs.is_empty()
    }

    fn generate(&self, port: &str) -> Option<Vec<u8>> {
        if self.probability <= 0.0 || self.specs.is_empty() {
            return None;
        }
        let draw = f64::from(u16::from_be_bytes(dial_random::<2>())) / 65_536.0;
        if draw >= self.probability {
            return None;
        }
        let scope = self
            .scoped
            .iter()
            .find(|(name, _)| name == port)
            .or_else(|| self.scoped.iter().find(|(name, _)| name.is_empty()))?;
        if scope.1.is_empty() {
            return None;
        }
        let name = &scope.1[usize::from(dial_random::<1>()[0]) % scope.1.len()];
        let (_, pattern) = self.specs.iter().find(|(spec, _)| spec == name)?;
        random_bytes(pattern, SHADOWSOCKS_SALT)
            .filter(|prefix| !prefix.is_empty() && prefix.len() <= SHADOWSOCKS_SALT)
    }
}

impl OsshPrefix {
    /// Whether the OSSH prefix is applied at all, by probability and by a configured probe.
    fn configured(&self) -> bool {
        self.probability > 0.0 && !self.specs.is_empty()
    }

    fn generate(&self, port: &str, keyword: &str) -> Option<OsshPrefixBytes> {
        if self.probability <= 0.0 || self.specs.is_empty() {
            return None;
        }
        let draw = f64::from(u16::from_be_bytes(dial_random::<2>())) / 65_536.0;
        if draw >= self.probability {
            return None;
        }
        let scope = self
            .scoped
            .iter()
            .find(|(name, _)| name == port)
            .or_else(|| self.scoped.iter().find(|(name, _)| name.is_empty()))?;
        if scope.1.is_empty() {
            return None;
        }
        let name = &scope.1[usize::from(dial_random::<1>()[0]) % scope.1.len()];
        if name.len() > OSSH_PREFIX_HEADER_MAX {
            return None;
        }
        let (_, pattern) = self.specs.iter().find(|(spec, _)| spec == name)?;
        let mut prefix = random_bytes(pattern, OSSH_PREFIX_MAX)?;
        let prefix_len = prefix.len();
        if prefix.len() < OSSH_PREAMBLE_HEADER {
            let mut padding = vec![0u8; OSSH_PREAMBLE_HEADER - prefix.len()];
            dial_fill(&mut padding);
            prefix.extend_from_slice(&padding);
        }
        let terminator = ossh_terminator(keyword, &prefix);
        prefix.extend_from_slice(&terminator);
        Some(OsshPrefixBytes {
            bytes: prefix,
            prefix_len,
            name: name.clone(),
            split_min: self.split_min,
            split_max: self.split_max,
        })
    }
}

/// The prefix terminator: an HKDF over the keyword, the prefix head and the direction.
fn ossh_terminator(keyword: &str, prefix: &[u8]) -> [u8; OSSH_PREFIX_TERMINATOR] {
    let hkdf = hkdf::Hkdf::<Sha256>::new(Some(&prefix[..OSSH_PREAMBLE_HEADER]), keyword.as_bytes());
    let mut terminator = [0u8; OSSH_PREFIX_TERMINATOR];
    hkdf.expand(b"client_to_server", &mut terminator)
        .expect("psiphon ssh prefix terminator");
    terminator
}

/// Apply a selected seed transform in place, refusing a replacement that changes the length.
pub(crate) fn apply_seed_transform(
    transforms: Option<&[crate::psiphon_dns::Transform]>,
    bytes: &mut [u8],
) -> Result<(), String> {
    let Some(transforms) = transforms else {
        return Ok(());
    };
    let transformed = crate::psiphon_dns::apply_hex_transform(transforms, bytes)
        .map_err(|error| format!("psiphon transform: {error}"))?;
    if transformed.len() != bytes.len() {
        return Err("psiphon transform: the replacement changed the length".to_owned());
    }
    bytes.copy_from_slice(&transformed);
    Ok(())
}

/// A uniform split delay in the configured window, or `None` when both ends are zero.
fn prefix_split(min: Duration, max: Duration) -> Option<Duration> {
    let low = u64::try_from(min.as_nanos()).unwrap_or(u64::MAX);
    let high = u64::try_from(max.as_nanos()).unwrap_or(u64::MAX).max(low);
    if high == 0 {
        return None;
    }
    let draw = u64::from_be_bytes(dial_random::<8>()) % (high - low + 1);
    Some(Duration::from_nanos(low + draw))
}

/// A best-effort byte generator for the prefix transform subset: literals, `\xNN` escapes,
/// `.`, byte classes and `?`, `*`, `+` or `{n,m}` quantifiers.
fn random_bytes(pattern: &str, limit: usize) -> Option<Vec<u8>> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = Vec::with_capacity(pattern.len());
    let mut at = 0;
    while at < chars.len() {
        let atom = match chars[at] {
            '^' | '$' => {
                at += 1;
                continue;
            }
            '\\' => {
                let (atom, next) = byte_escape(&chars, at + 1)?;
                at = next;
                atom
            }
            '[' => {
                let mut end = at + 1;
                while end < chars.len() && chars[end] != ']' {
                    end += 1;
                }
                if end == chars.len() {
                    return None;
                }
                let class = parse_byte_class(&chars[at + 1..end])?;
                at = end + 1;
                ByteAtom::Class(class)
            }
            '.' => {
                at += 1;
                ByteAtom::Class(vec![(0, 255)])
            }
            '(' | ')' | '|' | '*' | '+' | '?' | '{' | '}' => return None,
            literal => {
                let byte = char_byte_any(literal)?;
                at += 1;
                ByteAtom::Byte(byte)
            }
        };
        let (low, high, next) = quantifier(&chars, at);
        at = next;
        let span = u32::from(high.saturating_sub(low)) + 1;
        let count = if span == 1 {
            low
        } else {
            low + u16::from(dial_random::<1>()[0]) % u16::try_from(span).unwrap_or(1)
        };
        for _ in 0..count {
            match &atom {
                ByteAtom::Byte(byte) => out.push(*byte),
                ByteAtom::Class(ranges) => {
                    let width: u16 = ranges
                        .iter()
                        .map(|(low, high)| u16::from(high - low) + 1)
                        .sum();
                    let mut pick = u16::from_be_bytes(dial_random::<2>()) % width;
                    let mut byte = 0u8;
                    for (low, high) in ranges {
                        let span = u16::from(high - low) + 1;
                        if pick < span {
                            byte = low + u8::try_from(pick).unwrap_or(0);
                            break;
                        }
                        pick -= span;
                    }
                    out.push(byte);
                }
            }
        }
        if out.len() > limit {
            return None;
        }
    }
    Some(out)
}

enum ByteAtom {
    Byte(u8),
    Class(Vec<(u8, u8)>),
}

fn byte_escape(chars: &[char], at: usize) -> Option<(ByteAtom, usize)> {
    match *chars.get(at)? {
        'x' => {
            let high = chars.get(at + 1)?.to_digit(16)?;
            let low = chars.get(at + 2)?.to_digit(16)?;
            Some((ByteAtom::Byte(u8::try_from(high * 16 + low).ok()?), at + 3))
        }
        'n' => Some((ByteAtom::Byte(b'\n'), at + 1)),
        'r' => Some((ByteAtom::Byte(b'\r'), at + 1)),
        't' => Some((ByteAtom::Byte(b'\t'), at + 1)),
        'd' => Some((ByteAtom::Class(vec![(b'0', b'9')]), at + 1)),
        'w' => Some((
            ByteAtom::Class(vec![(b'0', b'9'), (b'A', b'Z'), (b'_', b'_'), (b'a', b'z')]),
            at + 1,
        )),
        's' => Some((ByteAtom::Class(vec![(b'\t', b'\r'), (b' ', b' ')]), at + 1)),
        literal => Some((ByteAtom::Byte(char_byte_any(literal)?), at + 1)),
    }
}

fn parse_byte_class(class: &[char]) -> Option<Vec<(u8, u8)>> {
    if class.first() == Some(&'^') {
        return None;
    }
    let mut ranges = Vec::with_capacity(class.len() / 3 + 1);
    let mut at = 0;
    while at < class.len() {
        let low = if class[at] == '\\' {
            let (atom, next) = byte_escape(class, at + 1)?;
            at = next;
            match atom {
                ByteAtom::Byte(byte) => byte,
                ByteAtom::Class(_) => return None,
            }
        } else {
            let byte = char_byte_any(class[at])?;
            at += 1;
            byte
        };
        if class.get(at) == Some(&'-') && at + 1 < class.len() {
            let high = if class[at + 1] == '\\' {
                let (atom, next) = byte_escape(class, at + 2)?;
                at = next;
                match atom {
                    ByteAtom::Byte(byte) => byte,
                    ByteAtom::Class(_) => return None,
                }
            } else {
                let byte = char_byte_any(class[at + 1])?;
                at += 2;
                byte
            };
            if low > high {
                return None;
            }
            ranges.push((low, high));
        } else {
            ranges.push((low, low));
        }
    }
    (!ranges.is_empty()).then_some(ranges)
}

fn char_byte_any(character: char) -> Option<u8> {
    u8::try_from(u32::from(character)).ok()
}

/// A best-effort generator for the regex subset `CustomHostNameRegexes` uses in practice:
/// literals, escapes, `.`, character classes and `?`, `*`, `+` or `{n,m}` quantifiers.
/// Generate one hostname from a regex-like pattern, or `None` when it cannot.
pub(crate) fn random_hostname(pattern: &str) -> Option<String> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len());
    let mut at = 0;
    while at < chars.len() {
        let atom = match chars[at] {
            '^' | '$' => {
                at += 1;
                continue;
            }
            '\\' => {
                let literal = *chars.get(at + 1)?;
                at += 2;
                Atom::Literal(literal)
            }
            '[' => {
                let mut end = at + 1;
                while end < chars.len() && chars[end] != ']' {
                    end += 1;
                }
                if end == chars.len() {
                    return None;
                }
                let class = parse_class(&chars[at + 1..end])?;
                at = end + 1;
                Atom::Class(class)
            }
            '.' => {
                at += 1;
                Atom::Class(vec![(b'a', b'z')])
            }
            '(' | ')' | '|' | '*' | '+' | '?' | '{' | '}' => return None,
            literal if literal.is_ascii_alphanumeric() || literal == '-' || literal == '_' => {
                at += 1;
                Atom::Literal(literal)
            }
            _ => return None,
        };
        let (low, high, next) = quantifier(&chars, at);
        at = next;
        let span = u32::from(high.saturating_sub(low)) + 1;
        let count = if span == 1 {
            low
        } else {
            low + u16::from(dial_random::<1>()[0]) % u16::try_from(span).unwrap_or(1)
        };
        for _ in 0..count {
            match &atom {
                Atom::Literal(literal) => out.push(*literal),
                Atom::Class(ranges) => {
                    let width: u16 = ranges
                        .iter()
                        .map(|(low, high)| u16::from(high - low) + 1)
                        .sum();
                    let mut pick = u16::from_be_bytes(dial_random::<2>()) % width;
                    let mut byte = b'?';
                    for (low, high) in ranges {
                        let span = u16::from(high - low) + 1;
                        if pick < span {
                            byte = low + u8::try_from(pick).unwrap_or(0);
                            break;
                        }
                        pick -= span;
                    }
                    out.push(char::from(byte));
                }
            }
        }
        if out.len() > 253 {
            return None;
        }
    }
    (!out.is_empty()).then_some(out)
}

enum Atom {
    Literal(char),
    Class(Vec<(u8, u8)>),
}

fn parse_class(class: &[char]) -> Option<Vec<(u8, u8)>> {
    if class.first() == Some(&'^') {
        return None;
    }
    let mut ranges = Vec::with_capacity(class.len() / 3 + 1);
    let mut at = 0;
    while at < class.len() {
        let low = char_byte(class[at])?;
        if class.get(at + 1) == Some(&'-') {
            let high = char_byte(*class.get(at + 2)?)?;
            if low > high {
                return None;
            }
            ranges.push((low, high));
            at += 3;
        } else {
            ranges.push((low, low));
            at += 1;
        }
    }
    (!ranges.is_empty()).then_some(ranges)
}

fn char_byte(character: char) -> Option<u8> {
    let byte = u8::try_from(u32::from(character)).ok()?;
    (byte.is_ascii_alphanumeric() || byte == b'-').then_some(byte)
}

fn quantifier(chars: &[char], at: usize) -> (u16, u16, usize) {
    match chars.get(at) {
        Some('?') => (0, 1, at + 1),
        Some('*') => (0, 8, at + 1),
        Some('+') => (1, 8, at + 1),
        Some('{') => {
            let mut end = at + 1;
            while end < chars.len() && chars[end] != '}' {
                end += 1;
            }
            let body: String = chars[at + 1..end.min(chars.len())].iter().collect();
            let next = (end + 1).min(chars.len());
            if let Some((low, high)) = body.split_once(',') {
                let low = low.parse::<u16>().unwrap_or(1).min(32);
                let high = high.parse::<u16>().unwrap_or(low).clamp(low, 32);
                (low, high, next)
            } else {
                let count = body.parse::<u16>().unwrap_or(1).min(32);
                (count, count, next)
            }
        }
        _ => (1, 1, at),
    }
}

/// The one hop before a server: HTTP CONNECT or a no-auth/username-password SOCKS5 handshake.
#[derive(Debug, Clone)]
pub(crate) struct Proxy {
    http: bool,
    host: String,
    port: u16,
    user: String,
    pass: String,
    dns: crate::psiphon_dns::Config,
}

impl Proxy {
    /// `http://`, `socks5://` or `socks5h://`, with optional `user:pass@` credentials.
    pub(crate) fn parse(text: &str, dns: &crate::psiphon_dns::Config) -> Result<Self, String> {
        let text = text.trim();
        let (http, rest) = text
            .strip_prefix("http://")
            .map(|rest| (true, rest))
            .or_else(|| text.strip_prefix("socks5://").map(|rest| (false, rest)))
            .or_else(|| text.strip_prefix("socks5h://").map(|rest| (false, rest)))
            .ok_or_else(|| {
                format!("psiphon: upstream proxy {text:?} is not http:// or socks5(h)://")
            })?;
        let (user, pass, authority) = match rest.rsplit_once('@') {
            Some((userinfo, authority)) => {
                let (user, pass) = userinfo.split_once(':').unwrap_or((userinfo, ""));
                (percent_decode(user), percent_decode(pass), authority)
            }
            None => (String::new(), String::new(), rest),
        };
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or_else(|| format!("psiphon: upstream proxy {text:?} names no port"))?;
        if host.is_empty() || host.contains('/') {
            return Err(format!("psiphon: upstream proxy {text:?} names no host"));
        }
        let host = host
            .strip_prefix('[')
            .and_then(|bare| bare.strip_suffix(']'))
            .unwrap_or(host)
            .to_owned();
        let port = port
            .parse::<u16>()
            .map_err(|_| format!("psiphon: upstream proxy {text:?} has no numeric port"))?;
        Ok(Self {
            http,
            host,
            port,
            user,
            pass,
            dns: dns.clone(),
        })
    }

    #[must_use]
    pub(crate) fn display(&self) -> String {
        format!(
            "{}://{}:{}",
            if self.http { "http" } else { "socks5" },
            self.host,
            self.port
        )
    }

    /// Dial the server through the hop, so the SSH socket itself is the tunnel's first leg.
    pub(crate) fn connect(
        &self,
        target: SocketAddr,
        timeout: Duration,
    ) -> Result<TcpStream, String> {
        self.connect_host(&target.ip().to_string(), target.port(), timeout)
    }

    /// Dial any host through the hop; SOCKS5 keeps a domain name for the proxy to resolve.
    pub(crate) fn connect_host(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<TcpStream, String> {
        if host.is_empty()
            || host.bytes().any(|byte| {
                byte.is_ascii_control()
                    || byte.is_ascii_whitespace()
                    || byte == b'/'
                    || byte == b'@'
            })
        {
            return Err("psiphon: upstream proxy host name is not valid".to_owned());
        }
        let mut last = String::new();
        for address in crate::psiphon_dns::resolve_with(&self.dns, &self.host, self.port)
            .map_err(|error| format!("psiphon: upstream proxy resolve {}: {error}", self.host))?
        {
            match TcpStream::connect_timeout(&address, timeout) {
                Ok(stream) => {
                    let _ = stream.set_read_timeout(Some(timeout));
                    let _ = stream.set_write_timeout(Some(timeout));
                    let mut stream = stream;
                    if self.http {
                        self.connect_http(&mut stream, host, port)?;
                    } else {
                        self.connect_socks(&mut stream, host, port)?;
                    }
                    return Ok(stream);
                }
                Err(error) => last = error.to_string(),
            }
        }
        Err(format!(
            "psiphon: upstream proxy {}: {last}",
            self.display()
        ))
    }

    fn connect_http(&self, stream: &mut TcpStream, host: &str, port: u16) -> Result<(), String> {
        let authority = authority_host(host, port);
        let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
        if !self.user.is_empty() || !self.pass.is_empty() {
            let encoded =
                ferrox_core::b64::encode(format!("{}:{}", self.user, self.pass).as_bytes());
            request.push_str("Proxy-Authorization: Basic ");
            request.push_str(&encoded);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        stream
            .write_all(request.as_bytes())
            .map_err(|error| format!("psiphon: upstream proxy write: {error}"))?;
        let mut head = Vec::with_capacity(128);
        loop {
            let mut byte = [0u8; 1];
            stream
                .read_exact(&mut byte)
                .map_err(|error| format!("psiphon: upstream proxy read: {error}"))?;
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
            if head.len() > 4096 {
                return Err("psiphon: upstream proxy answer is too long".to_owned());
            }
        }
        let text = String::from_utf8_lossy(&head);
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse::<u16>().ok());
        if !matches!(status, Some(200..=299)) {
            return Err(format!(
                "psiphon: upstream proxy refused {authority}: {}",
                text.lines().next().unwrap_or("no status")
            ));
        }
        Ok(())
    }

    fn connect_socks(&self, stream: &mut TcpStream, host: &str, port: u16) -> Result<(), String> {
        let auth = !self.user.is_empty() || !self.pass.is_empty();
        let greeting: &[u8] = if auth { &[5, 2, 0, 2] } else { &[5, 1, 0] };
        stream
            .write_all(greeting)
            .map_err(|error| format!("psiphon: upstream proxy greeting: {error}"))?;
        let mut method = [0u8; 2];
        stream
            .read_exact(&mut method)
            .map_err(|error| format!("psiphon: upstream proxy greeting: {error}"))?;
        if method[0] != 5 {
            return Err("psiphon: upstream proxy is not SOCKS5".to_owned());
        }
        match method[1] {
            0 => {}
            2 if auth => {
                let user = self.user.as_bytes();
                let pass = self.pass.as_bytes();
                let mut request = Vec::with_capacity(3 + user.len() + pass.len());
                request.push(1);
                request.push(u8::try_from(user.len()).unwrap_or(u8::MAX));
                request.extend_from_slice(user);
                request.push(u8::try_from(pass.len()).unwrap_or(u8::MAX));
                request.extend_from_slice(pass);
                stream
                    .write_all(&request)
                    .map_err(|error| format!("psiphon: upstream proxy auth: {error}"))?;
                let mut reply = [0u8; 2];
                stream
                    .read_exact(&mut reply)
                    .map_err(|error| format!("psiphon: upstream proxy auth: {error}"))?;
                if reply != [1, 0] {
                    return Err("psiphon: upstream proxy refused its credentials".to_owned());
                }
            }
            _ => return Err("psiphon: upstream proxy offers no usable method".to_owned()),
        }
        let mut request = Vec::with_capacity(22 + host.len());
        request.extend_from_slice(&[5, 1, 0]);
        match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(address)) => {
                request.push(1);
                request.extend_from_slice(&address.octets());
            }
            Ok(IpAddr::V6(address)) => {
                request.push(4);
                request.extend_from_slice(&address.octets());
            }
            Err(_) => {
                let length = u8::try_from(host.len())
                    .map_err(|_| "psiphon: upstream proxy host name is too long".to_owned())?;
                request.push(3);
                request.push(length);
                request.extend_from_slice(host.as_bytes());
            }
        }
        request.extend_from_slice(&port.to_be_bytes());
        stream
            .write_all(&request)
            .map_err(|error| format!("psiphon: upstream proxy request: {error}"))?;
        let mut head = [0u8; 4];
        stream
            .read_exact(&mut head)
            .map_err(|error| format!("psiphon: upstream proxy reply: {error}"))?;
        if head[0] != 5 || head[1] != 0 {
            return Err(format!(
                "psiphon: upstream proxy refused {}: status {}",
                authority_host(host, port),
                head[1]
            ));
        }
        // A domain-name bound address is a length byte plus up to 255 bytes, then the port.
        let mut bound = [0u8; 255 + 2];
        let skip = match head[3] {
            1 => 4,
            4 => 16,
            3 => {
                let mut length = [0u8; 1];
                stream
                    .read_exact(&mut length)
                    .map_err(|error| format!("psiphon: upstream proxy reply: {error}"))?;
                usize::from(length[0])
            }
            _ => return Err("psiphon: upstream proxy named no address".to_owned()),
        };
        stream
            .read_exact(&mut bound[..skip + 2])
            .map_err(|error| format!("psiphon: upstream proxy reply: {error}"))?;
        Ok(())
    }
}

fn authority_host(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            if let Some(hex) = bytes.get(at + 1..at + 3) {
                if let Some(byte) = hex_pair(hex[0], hex[1]) {
                    out.push(byte);
                    at += 3;
                    continue;
                }
            }
        }
        out.push(bytes[at]);
        at += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_pair(high: u8, low: u8) -> Option<u8> {
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    };
    Some((digit(high)? << 4) | digit(low)?)
}

/// One established SSH connection; clones of a channel share it.
static NEXT_SESSION_ID: AtomicUsize = AtomicUsize::new(1);

pub(crate) struct Session {
    inner: Arc<Inner>,
    id: usize,
    packet_tunnel_channel_window: u32,
}

type ApiReply = mpsc::Sender<Result<Vec<u8>, String>>;

struct Inner {
    writer: Mutex<PacketWriter>,
    channels: Mutex<HashMap<u32, Arc<ChannelState>>>,
    pool: Arc<Mutex<Vec<Vec<u8>>>>,
    channel_window: u32,
    next_channel: AtomicU32,
    closed: AtomicBool,
    closed_at: AtomicU64,
    socket: Stream,
    relay: Mutex<Option<Relay>>,
    opened_at: Instant,
    last_read: AtomicU64,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    burst: Mutex<crate::psiphon_burst::Burst>,
    burst_enabled: bool,
    pending_request: Mutex<Option<mpsc::Sender<bool>>>,
    pending_api: Mutex<Option<ApiReply>>,
    api_timed_out: AtomicBool,
    request_lock: Mutex<()>,
    requests: Option<Arc<dyn ServerRequests>>,
    server: String,
    protocol: &'static str,
    provider_id: Option<String>,
    region: Option<String>,
    fronting_provider_id: Option<String>,
    handshake: HandshakeState,
}

struct ChannelState {
    local: u32,
    remote: AtomicU32,
    remote_window: Mutex<u64>,
    remote_packet: AtomicU32,
    recv: Mutex<Recv>,
    cond: Condvar,
    window_cond: Condvar,
    open: Mutex<Option<mpsc::Sender<Result<OpenResult, String>>>>,
    pool: Arc<Mutex<Vec<Vec<u8>>>>,
}

/// How the server answered one `direct-tcpip` request.
enum OpenResult {
    Confirmed,
    SplitTunnel,
}

struct Recv {
    chunks: VecDeque<Chunk>,
    eof: bool,
    closed: bool,
    pending_adjust: u64,
    local_window: u64,
}

/// One received SSH packet, held open at the bytes the dispatcher has already named.
struct Chunk {
    buffer: Vec<u8>,
    start: usize,
    end: usize,
}

#[derive(Clone)]
pub(crate) struct Channel {
    session: Arc<Inner>,
    state: Arc<ChannelState>,
    deadline: Option<Instant>,
}

#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("server", &self.inner.server)
            .field("opened", &self.inner.opened_at.elapsed())
            .finish()
    }
}

#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("local", &self.state.local)
            .field("remote", &self.state.remote.load(Ordering::Acquire))
            .finish()
    }
}

/// The encoding an SSH API request uses: the reference's packed CBOR by default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ApiEncoding {
    Json,
    Cbor,
}

/// The fields the server's auth and handshake read, taken from the lane's settings.
pub(crate) struct Identity<'a> {
    pub(crate) session_id: &'a str,
    pub(crate) authorizations: &'a [String],
    pub(crate) sponsor: &'a str,
    pub(crate) propagation: &'a str,
    pub(crate) platform: &'a str,
    pub(crate) version: &'a str,
    pub(crate) egress_region: Option<&'a str>,
    pub(crate) device_region: Option<&'a str>,
    pub(crate) device_location: Option<&'a str>,
    pub(crate) client_features: &'a [String],
    pub(crate) split_tunnel: bool,
    pub(crate) split_tunnel_regions: &'a [String],
    pub(crate) api_encoding: ApiEncoding,
    pub(crate) compress_tactics: bool,
    pub(crate) disable_api: bool,
    pub(crate) ssh_algorithms: Option<&'a [String; 4]>,
}

/// The server's handshake reply: new server entries, client region, tactics and steering IP.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub(crate) struct HandshakeState {
    pub(crate) homepages: Vec<String>,
    pub(crate) upgrade_client_version: Option<String>,
    pub(crate) encoded_server_list: Vec<String>,
    pub(crate) client_region: Option<String>,
    pub(crate) client_address: Option<String>,
    pub(crate) server_timestamp: Option<String>,
    pub(crate) active_authorization_ids: Vec<String>,
    pub(crate) tactics_payload: Option<crate::json::Json>,
    pub(crate) steering_ip: Option<String>,
}

impl Session {
    /// Dial a server, negotiate the tunnel, and authenticate as the entry's user.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub(crate) fn connect(
        server: &Server,
        identity: &Identity<'_>,
        timeout: Duration,
        proxy: Option<&Proxy>,
        dns: &crate::psiphon_dns::Config,
        conduit: Option<&Conduit>,
        keepalive: Option<KeepAlive>,
        shape: &TlsShape,
        limit_meek_buffers: bool,
        requests: Option<Arc<dyn ServerRequests>>,
        burst: Option<crate::psiphon_burst::Config>,
    ) -> Result<Self, String> {
        let (stream, mut relay, protocol, relay_protocol) =
            if let (Some(conduit), Some(destination)) = (conduit, server.inproxy.as_ref()) {
                let (stream, relay) = conduit.open(server.address, destination, identity)?;
                let base = destination.base_protocol();
                let stream = match base {
                    "QUIC-OSSH" => Stream::Quic(crate::psiphon_quic::QuicStream::connect_inproxy(
                        server, timeout, stream, shape,
                    )?),
                    "UNFRONTED-MEEK-OSSH"
                    | "UNFRONTED-MEEK-HTTPS-OSSH"
                    | "UNFRONTED-MEEK-SESSION-TICKET-OSSH"
                    | "FRONTED-MEEK-OSSH"
                    | "FRONTED-MEEK-HTTP-OSSH"
                    | "FRONTED-MEEK-QUIC-OSSH" => {
                        let mut meek = server
                            .inproxy_meek
                            .clone()
                            .or_else(|| server.unfronted_meek.clone())
                            .or_else(|| server.meek.clone())
                            .ok_or_else(|| {
                                format!("psiphon ssh: {base} entry has no meek config")
                            })?;
                        meek.https =
                            !matches!(base, "UNFRONTED-MEEK-OSSH" | "FRONTED-MEEK-HTTP-OSSH");
                        meek.quic = base == "FRONTED-MEEK-QUIC-OSSH";
                        meek.protocol = destination.protocol;
                        Stream::Tcp(crate::psiphon_meek::connect_inproxy(
                            stream,
                            &meek,
                            timeout,
                            limit_meek_buffers,
                        )?)
                    }
                    "TLS-OSSH" => tls_tunnel(
                        Stream::WebRtc(stream),
                        &server.host,
                        tls_passthrough_key(server),
                        server.meek_obfuscated_key.as_deref().unwrap_or(""),
                        timeout,
                        shape,
                        base,
                    )?,
                    "SHADOWSOCKS-OSSH" => {
                        let key = server
                            .shadowsocks
                            .as_ref()
                            .map(|shadowsocks| shadowsocks.key.as_str())
                            .or(server.inproxy_shadowsocks_key.as_deref())
                            .or(server.obfuscation_key.as_deref())
                            .filter(|key| !key.is_empty())
                            .ok_or_else(|| {
                                "psiphon ssh: in-proxy Shadowsocks entry has no key".to_owned()
                            })?;
                        let prefix = shape.shadowsocks_prefix(&server.port.to_string());
                        Stream::WebRtcShadowsocks(
                            crate::psiphon_shadowsocks::Stream::connect_webrtc(
                                stream,
                                key,
                                prefix.as_deref(),
                            ),
                        )
                    }
                    _ => Stream::WebRtc(stream),
                };
                (stream, Some(relay), destination.protocol, base)
            } else {
                let (stream, protocol) =
                    direct_stream(server, timeout, proxy, dns, shape, limit_meek_buffers)?;
                (stream, None, protocol, protocol)
            };

        let control = stream
            .try_clone()
            .map_err(|error| format!("psiphon ssh socket clone: {error}"))?;
        let pool = Arc::new(Mutex::new(Vec::new()));
        let (mut output, mut input) =
            split(stream, server, relay.is_some(), Arc::clone(&pool), shape)?;
        // An OSSH server reads the seed before it writes anything, so the client line goes first.
        let our_version = b"SSH-2.0-OpenSSH_9.6";
        write_all(&mut output, b"SSH-2.0-OpenSSH_9.6\r\n")?;
        let mut banner = Vec::with_capacity(256);
        let version = read_identification(&mut input, &mut banner)?;

        let kex = kex(
            &mut output,
            &mut input,
            our_version,
            &version,
            &server.host_key,
            identity.ssh_algorithms,
        )?;
        output.activate(kex.client_cipher.0, kex.client_cipher.1, kex.client_mac);
        input.activate(kex.server_cipher.0, kex.server_cipher.1, kex.server_mac);
        service(&mut output, &mut input)?;
        authenticate(
            &mut output,
            &mut input,
            server,
            identity.session_id,
            identity.sponsor,
        )?;
        // A Psiphon server refuses every port forward until this handshake completes.
        let handshake = if identity.disable_api {
            HandshakeState::default()
        } else {
            handshake(
                &mut output,
                &mut input,
                relay_protocol,
                identity,
                server.ssh_api,
                &mut relay,
                requests.as_deref(),
            )?
        };
        control
            .set_timeout(None)
            .map_err(|error| format!("psiphon ssh socket: {error}"))?;

        let opened_at = Instant::now();
        let inner = Arc::new(Inner {
            writer: Mutex::new(output),
            channels: Mutex::new(HashMap::new()),
            pool,
            channel_window: server.channel_window,
            next_channel: AtomicU32::new(1),
            closed: AtomicBool::new(false),
            closed_at: AtomicU64::new(u64::MAX),
            socket: control,
            relay: Mutex::new(relay),
            opened_at,
            last_read: AtomicU64::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            burst_enabled: burst.is_some(),
            burst: Mutex::new(crate::psiphon_burst::Burst::new(burst, opened_at)),
            pending_request: Mutex::new(None),
            pending_api: Mutex::new(None),
            api_timed_out: AtomicBool::new(false),
            request_lock: Mutex::new(()),
            requests,
            server: format!("{}:{}", server.host, server.port),
            protocol,
            provider_id: server.provider_id.clone(),
            region: server.region.clone(),
            fronting_provider_id: server.fronting_provider_id.clone(),
            handshake,
        });
        let read_inner = Arc::clone(&inner);
        std::thread::Builder::new()
            .name("psiphon-ssh".to_owned())
            .spawn(move || read_loop(read_inner, input))
            .map_err(|error| format!("psiphon ssh reader: {error}"))?;
        if let Some(keepalive) = keepalive {
            let keepalive_inner = Arc::downgrade(&inner);
            if let Err(error) = std::thread::Builder::new()
                .name("psiphon-ssh-keepalive".to_owned())
                .spawn(move || ssh_keepalive(&keepalive_inner, keepalive))
            {
                inner.close();
                return Err(format!("psiphon ssh keepalive: {error}"));
            }
        }
        Ok(Self {
            inner,
            id: NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed),
            packet_tunnel_channel_window: server.packet_tunnel_channel_window,
        })
    }

    /// Open one `direct-tcpip` channel, treating a split-tunnel classification as a refusal.
    pub(crate) fn open(&self, host: &str, port: u16) -> Result<Channel, String> {
        self.open_named(host, port, b"direct-tcpip")?
            .ok_or_else(|| {
                format!("psiphon ssh split-tunnels {host}:{port}; the caller has no direct path")
            })
    }

    /// Open a channel the server must tunnel even when split tunnel mode is on.
    pub(crate) fn open_tunneled(&self, host: &str, port: u16) -> Result<Channel, String> {
        self.open_named(host, port, b"direct-tcpip-no-split-tunnel@psiphon.ca")?
            .ok_or_else(|| {
                format!("psiphon ssh split-tunnels {host}:{port}; this channel must be tunneled")
            })
    }

    /// Open one `direct-tcpip` channel, or report that split tunnel sends it direct.
    pub(crate) fn open_split(&self, host: &str, port: u16) -> Result<Option<Channel>, String> {
        self.open_named(host, port, b"direct-tcpip")
    }

    /// Open the single packet tunnel channel, with its own wider window.
    pub(crate) fn open_packet_tunnel(&self) -> Result<Channel, String> {
        self.open_payload_with_window(
            crate::psiphon_packet_tunnel::CHANNEL,
            &[],
            "packet tunnel",
            self.packet_tunnel_channel_window,
        )?
        .ok_or_else(|| "psiphon ssh refused the packet tunnel channel".to_owned())
    }

    fn open_named(
        &self,
        host: &str,
        port: u16,
        channel_type: &[u8],
    ) -> Result<Option<Channel>, String> {
        let mut extra = Vec::with_capacity(host.len() + 16);
        put_str(&mut extra, host.as_bytes());
        put_u32(&mut extra, u32::from(port));
        put_str(&mut extra, b"127.0.0.1");
        put_u32(&mut extra, 0);
        self.open_payload(channel_type, &extra, &format!("{host}:{port}"))
    }

    /// Send a Psiphon API request through the tunnel and wait for its success payload.
    pub(crate) fn api_request(
        &self,
        name: &str,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        if self.is_closed() {
            return Err("psiphon ssh api: the session is closed".to_owned());
        }
        let _request = lock(&self.inner.request_lock);
        if self.is_closed() {
            return Err("psiphon ssh api: the session is closed".to_owned());
        }
        if self.inner.api_timed_out.load(Ordering::Acquire) {
            return Err("psiphon ssh api: an earlier request timed out".to_owned());
        }
        let (reply, wait) = mpsc::channel();
        *lock(&self.inner.pending_api) = Some(reply);
        let mut request = Vec::with_capacity(64 + name.len() + payload.len());
        request.push(MSG_GLOBAL_REQUEST);
        put_str(&mut request, name.as_bytes());
        request.push(1);
        request.extend_from_slice(payload);
        if let Err(error) = self.inner.send(&request) {
            let _ = lock(&self.inner.pending_api).take();
            return Err(error);
        }
        match wait.recv_timeout(timeout) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => {
                self.inner.api_timed_out.store(true, Ordering::Release);
                let _ = lock(&self.inner.pending_api).take();
                Err(format!("psiphon ssh api {name} timed out"))
            }
            Err(RecvTimeoutError::Disconnected) => {
                Err("psiphon ssh api: the session closed".to_owned())
            }
        }
    }

    /// The reference's liveness test: a random stream the server echoes and discards.
    pub(crate) fn liveness_test(
        &self,
        min_upstream: usize,
        max_upstream: usize,
        min_downstream: usize,
        max_downstream: usize,
        limit: Duration,
    ) -> Result<(), String> {
        let upstream = random_size(min_upstream, max_upstream);
        let downstream = random_size(min_downstream, max_downstream);
        let request = format!(r#"{{"u":{upstream},"d":{downstream}}}"#);
        let mut channel = self
            .open_payload(b"random@psiphon.ca", request.as_bytes(), "liveness stream")?
            .ok_or_else(|| "psiphon ssh refused the liveness stream".to_owned())?;
        channel.deadline = Some(Instant::now() + limit);
        let mut reader = channel.clone();
        let writer = std::thread::Builder::new()
            .name("psiphon-liveness".to_owned())
            .spawn(move || -> Result<(), String> {
                let mut writer = channel;
                let mut buf = [0u8; 4096];
                let mut left = upstream;
                while left > 0 {
                    let take = left.min(buf.len());
                    getrandom::fill(&mut buf[..take])
                        .map_err(|error| format!("psiphon liveness entropy: {error}"))?;
                    writer
                        .write_all(&buf[..take])
                        .map_err(|error| format!("psiphon liveness write: {error}"))?;
                    left -= take;
                }
                Ok(())
            })
            .map_err(|error| format!("psiphon liveness thread: {error}"))?;
        let mut buf = [0u8; 4096];
        let mut left = downstream;
        let mut failure = None;
        while left > 0 {
            let take = left.min(buf.len());
            match reader.read(&mut buf[..take]) {
                Ok(0) => {
                    failure = Some("psiphon liveness read: stream closed early".to_owned());
                    break;
                }
                Ok(read) => left -= read,
                Err(error) => {
                    failure = Some(format!("psiphon liveness read: {error}"));
                    break;
                }
            }
        }
        if failure.is_some() {
            self.close();
        }
        let joined = writer
            .join()
            .map_err(|_| "psiphon liveness writer panicked".to_owned())?;
        if failure.is_none() {
            reader.close();
        }
        if let Some(error) = failure {
            return Err(error);
        }
        joined?;
        Ok(())
    }

    /// The payload a probe sends on a freshly opened channel.
    fn open_payload(
        &self,
        channel_type: &[u8],
        extra: &[u8],
        target: &str,
    ) -> Result<Option<Channel>, String> {
        self.open_payload_with_window(channel_type, extra, target, self.inner.channel_window)
    }

    fn open_payload_with_window(
        &self,
        channel_type: &[u8],
        extra: &[u8],
        target: &str,
        channel_window: u32,
    ) -> Result<Option<Channel>, String> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err("psiphon ssh is closed".to_owned());
        }
        let local = self.inner.next_channel.fetch_add(1, Ordering::Relaxed);
        let state = Arc::new(ChannelState {
            local,
            remote: AtomicU32::new(NO_CHANNEL),
            remote_window: Mutex::new(0),
            remote_packet: AtomicU32::new(CHANNEL_PACKET),
            recv: Mutex::new(Recv {
                chunks: VecDeque::new(),
                eof: false,
                closed: false,
                pending_adjust: 0,
                local_window: u64::from(channel_window),
            }),
            cond: Condvar::new(),
            window_cond: Condvar::new(),
            open: Mutex::new(None),
            pool: Arc::clone(&self.inner.pool),
        });
        let (tx, rx) = mpsc::channel();
        *lock(&state.open) = Some(tx);
        lock(&self.inner.channels).insert(local, Arc::clone(&state));

        let mut payload = vec![MSG_CHANNEL_OPEN];
        put_str(&mut payload, channel_type);
        put_u32(&mut payload, local);
        put_u32(&mut payload, channel_window);
        put_u32(&mut payload, CHANNEL_PACKET);
        payload.extend_from_slice(extra);
        if let Err(why) = self.inner.send(&payload) {
            lock(&self.inner.channels).remove(&local);
            self.inner.close();
            return Err(why);
        }

        match rx.recv_timeout(Duration::from_secs(30)) {
            Ok(Ok(OpenResult::Confirmed)) => Ok(Some(Channel {
                session: Arc::clone(&self.inner),
                state,
                deadline: None,
            })),
            Ok(Ok(OpenResult::SplitTunnel)) => Ok(None),
            // A refusal names the target, not the tunnel, so the session stays open for other flows.
            Ok(Err(why)) => Err(why),
            Err(RecvTimeoutError::Timeout) => {
                self.inner.close();
                Err(format!("psiphon ssh channel to {target} timed out"))
            }
            Err(RecvTimeoutError::Disconnected) => {
                self.inner.retire(local, &state);
                Err(format!("psiphon ssh channel to {target} closed"))
            }
        }
    }

    /// End the connection and wake every channel waiting on it.
    pub(crate) fn close(&self) {
        self.inner.close();
    }

    #[must_use]
    pub(crate) fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    #[must_use]
    pub(crate) fn server(&self) -> &str {
        &self.inner.server
    }

    /// The tunnel's identity, so an older session cannot settle a newer entry.
    #[must_use]
    pub(crate) fn id(&self) -> usize {
        self.id
    }

    #[must_use]
    pub(crate) fn bytes_up(&self) -> u64 {
        self.inner.bytes_up.load(Ordering::Relaxed)
    }

    #[must_use]
    pub(crate) fn bytes_down(&self) -> u64 {
        self.inner.bytes_down.load(Ordering::Relaxed)
    }

    /// Time since the last packet read, measured from session open.
    #[must_use]
    pub(crate) fn idle(&self) -> Duration {
        self.inner.idle()
    }

    /// The session's age, frozen at close.
    #[must_use]
    pub(crate) fn age(&self) -> Duration {
        match self.inner.closed_at.load(Ordering::Relaxed) {
            u64::MAX => self.inner.opened_at.elapsed(),
            closed => Duration::from_millis(closed),
        }
    }

    #[must_use]
    pub(crate) fn protocol(&self) -> &'static str {
        self.inner.protocol
    }

    #[must_use]
    pub(crate) fn provider_id(&self) -> Option<&str> {
        self.inner.provider_id.as_deref()
    }

    #[must_use]
    pub(crate) fn region(&self) -> Option<&str> {
        self.inner.region.as_deref()
    }

    #[must_use]
    pub(crate) fn fronting_provider_id(&self) -> Option<&str> {
        self.inner.fronting_provider_id.as_deref()
    }

    #[must_use]
    pub(crate) fn handshake(&self) -> &HandshakeState {
        &self.inner.handshake
    }
}

/// A session nobody holds is a tunnel nobody reads; closing it ends the reader thread.
impl Drop for Session {
    fn drop(&mut self) {
        self.inner.close();
    }
}

/// Refresh NAT and tunnel liveness with a jittered `keepalive@openssh.com`,
/// closing the session when the server misses the reply deadline.
fn ssh_keepalive(inner: &Weak<Inner>, config: KeepAlive) {
    loop {
        std::thread::sleep(config.period());
        let Some(inner) = inner.upgrade() else {
            return;
        };
        if inner.closed.load(Ordering::Acquire) {
            return;
        }
        if inner.idle() < config.inactive {
            continue;
        }
        let _request = lock(&inner.request_lock);
        let padding = config.padding();
        let mut request = Vec::with_capacity(64 + padding);
        request.push(MSG_GLOBAL_REQUEST);
        put_str(&mut request, b"keepalive@openssh.com");
        request.push(1);
        let at = request.len();
        request.resize(at + padding, 0);
        if getrandom::fill(&mut request[at..]).is_err() {
            return;
        }
        let (reply, wait) = mpsc::channel();
        *lock(&inner.pending_request) = Some(reply);
        if inner.send(&request).is_err() {
            inner.close();
            return;
        }
        if let Ok(true) = wait.recv_timeout(config.timeout) {
        } else {
            let _ = lock(&inner.pending_request).take();
            inner.close();
            return;
        }
    }
}

impl Inner {
    fn send(&self, payload: &[u8]) -> Result<(), String> {
        let mut writer = lock(&self.writer);
        writer
            .send(payload)
            .map_err(|error| format!("psiphon ssh write: {error}"))
    }

    fn send_channel_data(&self, state: &ChannelState, data: &[u8]) -> Result<(), String> {
        let mut writer = lock(&self.writer);
        let remote = state.remote.load(Ordering::Acquire);
        if remote == NO_CHANNEL {
            return Err("psiphon channel closed".to_owned());
        }
        let result = writer.send_channel_data(remote, data);
        if result.is_err() {
            self.close();
        }
        result.map_err(|error| format!("psiphon ssh write: {error}"))
    }

    fn send_channel_data_in_place(
        &self,
        state: &ChannelState,
        data: &mut [u8],
    ) -> Result<(), String> {
        let mut writer = lock(&self.writer);
        let remote = state.remote.load(Ordering::Acquire);
        if remote == NO_CHANNEL {
            return Err("psiphon channel closed".to_owned());
        }
        let result = writer.send_channel_data_in_place(remote, data);
        if result.is_err() {
            self.close();
        }
        result.map_err(|error| format!("psiphon ssh write: {error}"))
    }

    /// A per-channel frame leaves only while the channel still names a remote id, read under the writer lock.
    fn send_framed(&self, state: &ChannelState, payload: &mut [u8]) -> bool {
        let mut writer = lock(&self.writer);
        let remote = state.remote.load(Ordering::Acquire);
        if remote == NO_CHANNEL || self.closed.load(Ordering::Acquire) {
            return false;
        }
        payload[1..5].copy_from_slice(&remote.to_be_bytes());
        let sent = writer.send(payload).is_ok();
        if !sent {
            self.close();
        }
        sent
    }

    /// End a channel: its remote id is retired and its close frame sent under one writer lock.
    fn close_channel(&self, state: &ChannelState) {
        let mut writer = lock(&self.writer);
        let remote = state.remote.swap(NO_CHANNEL, Ordering::AcqRel);
        if remote != NO_CHANNEL && !self.closed.load(Ordering::Acquire) {
            let _ = writer.send(&channel_close(remote));
        }
    }

    fn relay_round_trip(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let mut relay = lock(&self.relay);
        relay_round_trip(&mut relay, payload)
    }

    /// Record the read clock the keep-alive inactivity gate compares against.
    fn touch(&self) {
        let now = u64::try_from(self.opened_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_read.store(now, Ordering::Relaxed);
    }

    /// Time since the last packet read, measured from session open.
    pub(crate) fn idle(&self) -> Duration {
        let now = u64::try_from(self.opened_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        Duration::from_millis(now.saturating_sub(self.last_read.load(Ordering::Relaxed)))
    }

    /// The clock a burst update needs, or `None` when the monitor is disabled.
    fn burst_started(&self) -> Option<Instant> {
        self.burst_enabled.then(Instant::now)
    }

    /// Add an upstream write to the counters and the burst monitor.
    fn record_up(&self, started: Option<Instant>, bytes: u64) {
        self.bytes_up.fetch_add(bytes, Ordering::Relaxed);
        if let Some(started) = started {
            if let Ok(mut burst) = self.burst.lock() {
                burst.upstream(started, Instant::now(), bytes);
            }
        }
    }

    /// Add a downstream read to the counters and the burst monitor.
    fn record_down(&self, started: Option<Instant>, bytes: u64) {
        self.bytes_down.fetch_add(bytes, Ordering::Relaxed);
        if let Some(started) = started {
            if let Ok(mut burst) = self.burst.lock() {
                burst.downstream(started, Instant::now(), bytes);
            }
        }
    }

    /// Close the transport once, recording the age the replay target sees.
    fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let age = u64::try_from(self.opened_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.closed_at.store(age, Ordering::Relaxed);
        if let Ok(burst) = self.burst.lock() {
            if let Some(metrics) = burst.metrics() {
                eprintln!("psiphon: {} bursts:{metrics}", self.server);
            }
        }
        let _ = self.socket.shutdown();
        let _ = lock(&self.pending_request).take();
        if let Some(reply) = lock(&self.pending_api).take() {
            let _ = reply.send(Err("psiphon ssh closed".to_owned()));
        }
        let channels: Vec<Arc<ChannelState>> = lock(&self.channels)
            .drain()
            .map(|(_, state)| state)
            .collect();
        for state in channels {
            state.fail("psiphon ssh closed");
        }
    }

    /// Forget a channel that never answered, and close it if the confirmation raced the timeout.
    fn retire(&self, local: u32, state: &Arc<ChannelState>) {
        lock(&self.channels).remove(&local);
        self.close_channel(state);
    }
}

impl Channel {
    /// The SSH byte stream behind a local SOCKS flow.
    pub(crate) fn close(&self) {
        lock(&self.session.channels).remove(&self.state.local);
        self.session.close_channel(&self.state);
        self.state.fail("psiphon channel closed");
    }

    pub(crate) fn shutdown(&self) {
        let mut payload = [0u8; 5];
        payload[0] = MSG_CHANNEL_EOF;
        let _ = self.session.send_framed(&self.state, &mut payload);
    }

    fn adjust(&self, amount: u64) {
        if amount == 0 {
            return;
        }
        let mut payload = [0u8; 9];
        payload[0] = MSG_CHANNEL_WINDOW_ADJUST;
        payload[5..].copy_from_slice(&u32::try_from(amount).unwrap_or(u32::MAX).to_be_bytes());
        let _ = self.session.send_framed(&self.state, &mut payload);
    }
}

impl ChannelState {
    /// The peer ended the channel: refuse further writes, but let queued data drain to the reader.
    fn peer_closed(&self) {
        if let Some(tx) = lock(&self.open).take() {
            let _ = tx.send(Err("psiphon ssh closed the channel".to_owned()));
        }
        let mut recv = lock(&self.recv);
        recv.eof = true;
        recv.closed = true;
        drop(recv);
        self.cond.notify_all();
        self.window_cond.notify_all();
    }

    fn split_tunnel(&self) {
        if let Some(tx) = lock(&self.open).take() {
            let _ = tx.send(Ok(OpenResult::SplitTunnel));
        }
    }

    fn fail(&self, why: &str) {
        if let Some(tx) = lock(&self.open).take() {
            let _ = tx.send(Err(why.to_owned()));
        }
        let mut recv = lock(&self.recv);
        recv.eof = true;
        recv.closed = true;
        let mut pool = lock(&self.pool);
        while let Some(chunk) = recv.chunks.pop_front() {
            if pool.len() < PACKET_POOL {
                pool.push(chunk.buffer);
            }
        }
        drop(pool);
        drop(recv);
        self.cond.notify_all();
        self.window_cond.notify_all();
    }
}

/// Return a packet buffer to the shared pool.
fn recycle(pool: &Mutex<Vec<Vec<u8>>>, buffer: Vec<u8>) {
    let mut pool = lock(pool);
    if pool.len() < PACKET_POOL {
        pool.push(buffer);
    }
}

/// A received payload still inside its pooled packet buffer; writing it straight
/// to the client keeps the download path at one copy from the kernel, not two.
pub(crate) struct ChannelChunk {
    buffer: Vec<u8>,
    start: usize,
    end: usize,
}

impl ChannelChunk {
    #[must_use]
    pub(crate) fn data(&self) -> &[u8] {
        &self.buffer[self.start..self.end]
    }
}

impl Channel {
    /// The server this flow's tunnel landed on, for the pool distribution check.
    #[must_use]
    pub(crate) fn server(&self) -> &str {
        &self.session.server
    }

    /// The tunnel's identity, so two sessions on one server still count apart.
    #[must_use]
    pub(crate) fn session_id(&self) -> usize {
        Arc::as_ptr(&self.session) as usize
    }

    /// One queued chunk and the window credit it releases, without waiting.
    #[cfg(test)]
    fn take_chunk(&self) -> (Option<ChannelChunk>, u64) {
        let adjust_at = window_adjust_at(self.session.channel_window);
        let mut adjust = 0u64;
        let chunk = {
            let mut recv = lock(&self.state.recv);
            loop {
                let Some((start, end)) = recv.chunks.front().map(|front| (front.start, front.end))
                else {
                    break None;
                };
                if start >= end {
                    let spent = recv
                        .chunks
                        .pop_front()
                        .unwrap_or_else(|| unreachable!("the front chunk is the one just named"));
                    recycle(&self.state.pool, spent.buffer);
                    continue;
                }
                recv.pending_adjust += (end - start) as u64;
                if recv.pending_adjust >= adjust_at {
                    adjust += recv.pending_adjust;
                    recv.local_window += recv.pending_adjust;
                    recv.pending_adjust = 0;
                }
                break recv.chunks.pop_front();
            }
        };
        (
            chunk.map(|chunk| ChannelChunk {
                buffer: chunk.buffer,
                start: chunk.start,
                end: chunk.end,
            }),
            adjust,
        )
    }

    /// The next packet's payload without copying it out of the receive buffer.
    #[cfg(test)]
    pub(crate) fn next_chunk(&mut self) -> io::Result<Option<ChannelChunk>> {
        loop {
            let (chunk, adjust) = self.take_chunk();
            if adjust != 0 {
                self.adjust(adjust);
            }
            if chunk.is_some() {
                return Ok(chunk);
            }
            let mut recv = lock(&self.state.recv);
            if !recv.chunks.is_empty() {
                continue;
            }
            if recv.eof || recv.closed || self.session.closed.load(Ordering::Acquire) {
                return Ok(None);
            }
            let (guard, _) = self
                .state
                .cond
                .wait_timeout(recv, IO_TIMEOUT)
                .unwrap_or_else(PoisonError::into_inner);
            recv = guard;
            if recv.chunks.is_empty() && (recv.eof || recv.closed) {
                return Ok(None);
            }
        }
    }

    /// Wait for the first chunk, then take every queued chunk up to `limit` under one receive lock.
    pub(crate) fn next_batch(
        &mut self,
        batch: &mut Vec<ChannelChunk>,
        limit: usize,
    ) -> io::Result<bool> {
        let started = self.session.burst_started();
        let adjust_at = window_adjust_at(self.session.channel_window);
        loop {
            let (adjust, spent, bytes, eof) = {
                let mut recv = lock(&self.state.recv);
                let (adjust, spent, bytes) = take_batch(&mut recv, batch, limit, adjust_at);
                let eof = recv.eof || recv.closed || self.session.closed.load(Ordering::Acquire);
                (adjust, spent, bytes, eof)
            };
            if !spent.is_empty() {
                self.recycle_buffers(spent);
            }
            if adjust != 0 {
                self.adjust(adjust);
            }
            if bytes != 0 {
                self.session.record_down(started, bytes);
            }
            if !batch.is_empty() {
                return Ok(true);
            }
            if eof {
                return Ok(false);
            }
            let mut recv = lock(&self.state.recv);
            if !recv.chunks.is_empty() {
                continue;
            }
            if recv.eof || recv.closed || self.session.closed.load(Ordering::Acquire) {
                return Ok(false);
            }
            let (guard, _) = self
                .state
                .cond
                .wait_timeout(recv, IO_TIMEOUT)
                .unwrap_or_else(PoisonError::into_inner);
            recv = guard;
            if recv.chunks.is_empty() && (recv.eof || recv.closed) {
                return Ok(false);
            }
        }
    }

    /// Hand consumed chunks back to the packet pool under one lock.
    pub(crate) fn recycle_chunks(&self, chunks: impl Iterator<Item = ChannelChunk>) {
        self.recycle_buffers(chunks.map(|chunk| chunk.buffer));
    }

    /// Hand packet buffers back to the shared pool under one lock.
    fn recycle_buffers(&self, buffers: impl IntoIterator<Item = Vec<u8>>) {
        let mut pool = lock(&self.state.pool);
        for buffer in buffers {
            if pool.len() < PACKET_POOL {
                pool.push(buffer);
            }
        }
    }
}

/// Take queued payloads and the window credit they release, leaving empty buffers for recycling.
fn take_batch(
    recv: &mut Recv,
    batch: &mut Vec<ChannelChunk>,
    limit: usize,
    adjust_at: u64,
) -> (u64, Vec<Vec<u8>>, u64) {
    let mut adjust = 0u64;
    let mut bytes = 0u64;
    let mut spent = Vec::new();
    while batch.len() < limit {
        let Some(chunk) = recv.chunks.pop_front() else {
            break;
        };
        if chunk.start >= chunk.end {
            spent.push(chunk.buffer);
            continue;
        }
        let take = (chunk.end - chunk.start) as u64;
        recv.pending_adjust += take;
        bytes += take;
        if recv.pending_adjust >= adjust_at {
            adjust += recv.pending_adjust;
            recv.local_window += recv.pending_adjust;
            recv.pending_adjust = 0;
        }
        batch.push(ChannelChunk {
            buffer: chunk.buffer,
            start: chunk.start,
            end: chunk.end,
        });
    }
    (adjust, spent, bytes)
}

impl Read for Channel {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let started = self.session.burst_started();
        let mut adjust = 0u64;
        let adjust_at = window_adjust_at(self.session.channel_window);
        let mut drained = None;
        let take = loop {
            let mut recv = lock(&self.state.recv);
            if let Some(chunk) = recv.chunks.front_mut() {
                if chunk.start < chunk.end {
                    let take = (chunk.end - chunk.start).min(out.len());
                    out[..take].copy_from_slice(&chunk.buffer[chunk.start..chunk.start + take]);
                    let start = chunk.start + take;
                    let spent = start == chunk.end;
                    chunk.start = start;
                    recv.pending_adjust += u64::try_from(take).unwrap_or(0);
                    if recv.pending_adjust >= adjust_at {
                        adjust += recv.pending_adjust;
                        recv.local_window += recv.pending_adjust;
                        recv.pending_adjust = 0;
                    }
                    if spent {
                        let chunk = recv.chunks.pop_front().unwrap_or_else(|| {
                            unreachable!("the front chunk is the one just named")
                        });
                        match drained {
                            None => drained = Some(chunk.buffer),
                            Some(_) => recycle(&self.state.pool, chunk.buffer),
                        }
                    }
                    break take;
                }
                let chunk = recv
                    .chunks
                    .pop_front()
                    .unwrap_or_else(|| unreachable!("the front chunk is the one just named"));
                match drained {
                    None => drained = Some(chunk.buffer),
                    Some(_) => recycle(&self.state.pool, chunk.buffer),
                }
                continue;
            }
            if recv.eof || recv.closed || self.session.closed.load(Ordering::Acquire) {
                return Ok(0);
            }
            let wait = match self.deadline {
                Some(deadline) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(liveness_timeout());
                    }
                    remaining.min(IO_TIMEOUT)
                }
                None => IO_TIMEOUT,
            };
            let (guard, _) = self
                .state
                .cond
                .wait_timeout(recv, wait)
                .unwrap_or_else(PoisonError::into_inner);
            recv = guard;
            if recv.chunks.is_empty() && (recv.eof || recv.closed) {
                return Ok(0);
            }
        };
        if let Some(buffer) = drained {
            recycle(&self.state.pool, buffer);
        }
        if adjust != 0 {
            self.adjust(adjust);
        }
        self.session
            .record_down(started, u64::try_from(take).unwrap_or(0));
        Ok(take)
    }
}

impl Channel {
    fn take_window(&self, len: usize) -> io::Result<usize> {
        if self.state.remote.load(Ordering::Acquire) == NO_CHANNEL
            || self.session.closed.load(Ordering::Acquire)
        {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "psiphon channel closed",
            ));
        }
        loop {
            let mut window = lock(&self.state.remote_window);
            if *window > 0 {
                let packet = u64::from(self.state.remote_packet.load(Ordering::Relaxed));
                let take = len.min(usize::try_from((*window).min(packet)).unwrap_or(len));
                *window -= u64::try_from(take).unwrap_or(0);
                return Ok(take);
            }
            let wait = match self.deadline {
                Some(deadline) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(liveness_timeout());
                    }
                    remaining.min(IO_TIMEOUT)
                }
                None => IO_TIMEOUT,
            };
            let (guard, _) = self
                .state
                .window_cond
                .wait_timeout(window, wait)
                .unwrap_or_else(PoisonError::into_inner);
            window = guard;
            if self.state.remote.load(Ordering::Acquire) == NO_CHANNEL
                || self.session.closed.load(Ordering::Acquire)
            {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "psiphon channel closed",
                ));
            }
        }
    }

    pub(crate) fn write_in_place(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let started = self.session.burst_started();
        let take = self.take_window(buf.len())?;
        self.session
            .send_channel_data_in_place(&self.state, &mut buf[..take])
            .map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error))?;
        self.session
            .record_up(started, u64::try_from(take).unwrap_or(0));
        Ok(take)
    }
}

impl Write for Channel {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let started = self.session.burst_started();
        let take = self.take_window(buf.len())?;
        self.session
            .send_channel_data(&self.state, &buf[..take])
            .map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error))?;
        self.session
            .record_up(started, u64::try_from(take).unwrap_or(0));
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The error a liveness probe returns when its deadline passes.
fn liveness_timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "psiphon liveness deadline")
}

impl Drop for Channel {
    fn drop(&mut self) {
        if Arc::strong_count(&self.state) == 2 {
            let _ = lock(&self.session.channels).remove(&self.state.local);
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn tls_passthrough_key(server: &Server) -> &str {
    server
        .meek_obfuscated_key
        .as_deref()
        .or(server.obfuscation_key.as_deref())
        .unwrap_or("")
}

/// The reference proves knowledge of the meek obfuscated key in the `ClientHello` random, which
/// the server checks before it will speak `TLS-OSSH`; an invalid field is relayed to a decoy web
/// site. The key is HKDF-derived from the 20-minute time period, and the message's second half
/// is an HMAC over its nonce.
pub(crate) fn tls_passthrough(key: &str) -> Result<[u8; 32], String> {
    let period = 20 * 60u64;
    let rounded = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("psiphon tls clock: {error}"))?
        .as_secs()
        + period / 2)
        / period;
    let mut salt = b"passthrough-obfuscation-key".to_vec();
    salt.extend_from_slice(&rounded.to_le_bytes());
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt.as_slice()), key.as_bytes());
    let mut derived = [0u8; 32];
    hkdf.expand(&[], &mut derived)
        .map_err(|error| format!("psiphon tls passthrough key: {error}"))?;
    let mut message = [0u8; 32];
    getrandom::fill(&mut message[..16])
        .map_err(|error| format!("psiphon tls passthrough nonce: {error}"))?;
    let tag = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &derived),
        &message[..16],
    );
    message[16..].copy_from_slice(&tag.as_ref()[..16]);
    Ok(message)
}

/// Dial a direct or unfronted transport, wrapping it in TLS when the entry names TLS-OSSH.
fn direct_stream(
    server: &Server,
    timeout: Duration,
    proxy: Option<&Proxy>,
    dns: &crate::psiphon_dns::Config,
    shape: &TlsShape,
    limit_meek_buffers: bool,
) -> Result<(Stream, &'static str), String> {
    if server.quic {
        let stream = crate::psiphon_quic::QuicStream::connect(server, timeout, proxy, shape)?;
        return Ok((Stream::Quic(stream), "QUIC-OSSH"));
    }
    let address = SocketAddr::new(server.address, server.port);
    let tls = server.tls && server.meek.is_none() && !server.ss;
    let socket = match &server.meek {
        Some(meek) => crate::psiphon_meek::connect(meek, timeout, proxy, dns, limit_meek_buffers)?,
        None => direct_socket(address, server, timeout, proxy)?,
    };
    socket
        .set_read_timeout(Some(timeout))
        .and_then(|()| socket.set_write_timeout(Some(timeout)))
        .and_then(|()| socket.set_nodelay(true))
        .map_err(|error| format!("psiphon ssh socket: {error}"))?;
    let protocol = if server.ss {
        "SHADOWSOCKS-OSSH"
    } else if tls {
        "TLS-OSSH"
    } else {
        server.meek.as_ref().map_or_else(
            || {
                if server.obfuscation_key.is_some() {
                    "OSSH"
                } else {
                    "SSH"
                }
            },
            |meek| tunnel_protocol_base(meek.protocol),
        )
    };
    let stream = if server.ss {
        let key = server
            .shadowsocks
            .as_ref()
            .map(|ss| ss.key.as_str())
            .filter(|key| !key.is_empty())
            .ok_or_else(|| "psiphon ssh: shadowsocks entry has no key".to_owned())?;
        let prefix = shape.shadowsocks_prefix(&server.port.to_string());
        if shape.may_fragment(protocol) {
            Stream::ShadowsocksFragment(crate::psiphon_shadowsocks::Stream::connect_fragment(
                crate::psiphon_fragment::FragmentStream::new(socket, shape.fragmentor.clone()),
                key,
                prefix.as_deref(),
            ))
        } else {
            Stream::Shadowsocks(crate::psiphon_shadowsocks::Stream::connect(
                socket,
                key,
                prefix.as_deref(),
            ))
        }
    } else {
        let base = if server.meek.is_none() && shape.may_fragment(protocol) {
            Stream::Fragment(crate::psiphon_fragment::FragmentStream::new(
                socket,
                shape.fragmentor.clone(),
            ))
        } else {
            Stream::Tcp(socket)
        };
        if tls {
            tls_tunnel(
                base,
                &server.host,
                tls_passthrough_key(server),
                server.meek_obfuscated_key.as_deref().unwrap_or(""),
                timeout,
                shape,
                protocol,
            )?
        } else {
            base
        }
    };
    Ok((stream, protocol))
}

fn direct_socket(
    address: SocketAddr,
    server: &Server,
    timeout: Duration,
    proxy: Option<&Proxy>,
) -> Result<TcpStream, String> {
    match proxy {
        Some(proxy) => proxy
            .connect(address, timeout)
            .map_err(|error| format!("psiphon ssh proxy {}: {error}", proxy.display())),
        None => TcpStream::connect_timeout(&address, timeout)
            .map_err(|error| format!("psiphon ssh {}: {error}", server.host)),
    }
}

/// Poll interval for the loopback TLS relay: a direction with nothing to send yields so the
/// other one can, without a socket read waiting on the peer.
const TLS_POLL: Duration = Duration::from_millis(1);
const TLS_BUFFER: usize = 64 * 1024;
/// Decrypted bytes moved before the upload side is polled once, so a full download
/// does not pay the peer poll per TLS record while an interactive write still lands.
const TLS_DRAIN: usize = 1024 * 1024;

/// Wrap a stream in TLS and expose the decrypted bytes as a loopback TCP socket, so the SSH
/// framing below keeps one transport shape. The reference dials TLS-OSSH this way and then adds
/// the same OSSH seed layer; this relay removes the need for a second, concurrent TLS owner.
fn tls_tunnel(
    stream: Stream,
    server_name: &str,
    passthrough_key: &str,
    obfuscated_key: &str,
    timeout: Duration,
    shape: &TlsShape,
    protocol: &str,
) -> Result<Stream, String> {
    stream
        .set_timeout(Some(timeout))
        .map_err(|error| format!("psiphon tls socket: {error}"))?;
    // An IP literal omits SNI, matching the reference's default; a host name is sent as the SNI it is.
    let name = shape.sni(protocol, server_name);
    let fragment = name.parse::<IpAddr>().is_err() && shape.fragment_client_hello(protocol);
    let fingerprint = shape.fingerprint(false, None);
    let config = TlsConfig {
        server_name: name.clone(),
        roots: Vec::new().into(),
        insecure: true,
        fingerprint: Some(fingerprint),
        client_random: Some(tls_passthrough(passthrough_key)?),
        omit_session_id: shape.omit_session_id(fingerprint),
        padding: shape.padding(),
        obfuscated_ticket: shape.obfuscated_ticket(protocol, obfuscated_key)?,
        ..TlsConfig::default()
    };
    let stream = crate::psiphon_fragment::TlsHelloFragmentor::new(stream, fragment);
    let mut tls = ferrox_core::tls::connect(&config, stream)
        .map_err(|error| format!("psiphon tls {name}: {error}"))?;
    tls.handshake()
        .map_err(|error| format!("psiphon tls handshake {name}: {error}"))?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| format!("psiphon tls listener: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("psiphon tls listener: {error}"))?;
    let local = TcpStream::connect_timeout(&address, timeout)
        .map_err(|error| format!("psiphon tls loopback: {error}"))?;
    local
        .set_nodelay(true)
        .and_then(|()| local.set_read_timeout(Some(timeout)))
        .and_then(|()| local.set_write_timeout(Some(timeout)))
        .map_err(|error| format!("psiphon tls loopback: {error}"))?;
    std::thread::Builder::new()
        .name("psiphon-tls".to_owned())
        .spawn(move || match listener.accept() {
            Ok((peer, _)) => {
                if let Err(error) = relay_tls(tls, peer) {
                    eprintln!("psiphon: tls relay {name}: {error}");
                }
            }
            Err(error) => eprintln!("psiphon: tls accept: {error}"),
        })
        .map_err(|error| format!("psiphon tls thread: {error}"))?;
    Ok(Stream::Tcp(local))
}

fn relay_tls(
    mut tls: ClientSession<crate::psiphon_fragment::TlsHelloFragmentor<Stream>>,
    mut peer: TcpStream,
) -> io::Result<()> {
    tls.get_ref().inner().set_read_timeout(Some(TLS_POLL))?;
    peer.set_read_timeout(Some(TLS_POLL))?;
    peer.set_write_timeout(Some(IO_TIMEOUT))?;
    peer.set_nodelay(true)?;
    let mut up = vec![0u8; TLS_BUFFER];
    let mut down = vec![0u8; TLS_BUFFER];
    loop {
        // One peer poll per record capped a download at the poll interval; a bounded burst keeps upload responsive.
        let mut moved = 0usize;
        while moved < TLS_DRAIN {
            match tls.read(&mut down) {
                Ok(0) => return Ok(()),
                Ok(read) => {
                    if peer.write_all(&down[..read]).is_err() {
                        return Ok(());
                    }
                    moved += read;
                }
                Err(error) if idle(&error) => break,
                Err(_) => return Ok(()),
            }
        }
        match peer.read(&mut up) {
            Ok(0) => break,
            Ok(read) => {
                if tls
                    .write_all(&up[..read])
                    .and_then(|()| tls.flush())
                    .is_err()
                {
                    break;
                }
            }
            Err(error) if idle(&error) => {}
            Err(_) => break,
        }
    }
    Ok(())
}

fn idle(error: &io::Error) -> bool {
    io::ErrorKind::Interrupted == error.kind() || ferrox_core::tls::TlsError::is_timeout(error)
}

fn split(
    socket: Stream,
    server: &Server,
    relayed: bool,
    pool: Arc<Mutex<Vec<Vec<u8>>>>,
    shape: &TlsShape,
) -> Result<(PacketWriter, PacketReader), String> {
    let write = socket
        .try_clone()
        .map_err(|error| format!("psiphon ssh socket clone: {error}"))?;
    let obfuscated = if server.ss {
        false
    } else {
        match server.inproxy.as_ref().filter(|_| relayed) {
            Some(destination) => {
                let base = destination.base_protocol();
                base.contains("OSSH") && base != "SHADOWSOCKS-OSSH"
            }
            None => server.obfuscated(),
        }
    };
    if obfuscated {
        let key = match server
            .obfuscation_key
            .as_deref()
            .filter(|key| !key.is_empty())
        {
            Some(key) => key,
            None if server.ss => "",
            None => return Err("psiphon ssh: obfuscated entry has no key".to_owned()),
        };
        let prefix = shape.ossh_prefix(&server.port.to_string(), key);
        let mut seed = random::<SEED_LENGTH>();
        shape.ossh_seed(&mut seed)?;
        let client = Rc4::new(&derive_key(&seed, key.as_bytes(), b"client_to_server"));
        let remote = Rc4::new(&derive_key(&seed, key.as_bytes(), b"server_to_client"));
        let padding_len = shape.obfuscated_padding();
        let header_len = prefix.as_ref().map_or(0, |prefix| 4 + prefix.name.len());
        let prefix_len = prefix.as_ref().map_or(0, |prefix| prefix.bytes.len());
        let mut preamble =
            Vec::with_capacity(SEED_LENGTH + 8 + padding_len + header_len + prefix_len);
        if let Some(prefix) = &prefix {
            preamble.extend_from_slice(&prefix.bytes);
        }
        preamble.extend_from_slice(&seed);
        let magic_at = preamble.len();
        preamble.extend_from_slice(&MAGIC.to_be_bytes());
        preamble.extend_from_slice(&u32::try_from(padding_len).unwrap_or(0).to_be_bytes());
        let mut padding = vec![0u8; padding_len];
        dial_fill(&mut padding);
        preamble.extend_from_slice(&padding);
        if let Some(prefix) = &prefix {
            preamble.extend_from_slice(&1u16.to_be_bytes());
            preamble
                .extend_from_slice(&u16::try_from(prefix.name.len()).unwrap_or(0).to_be_bytes());
            preamble.extend_from_slice(prefix.name.as_bytes());
        }
        let mut client = client;
        client.apply(&mut preamble[magic_at..]);
        let mut write = write;
        if let Some(prefix) = &prefix {
            write
                .write_all(&preamble[..prefix.prefix_len])
                .map_err(|error| format!("psiphon ssh prefix: {error}"))?;
            if let Some(delay) = prefix_split(prefix.split_min, prefix.split_max) {
                std::thread::sleep(delay);
            }
            write
                .write_all(&preamble[prefix.prefix_len..])
                .map_err(|error| format!("psiphon ssh preamble: {error}"))?;
        } else {
            write
                .write_all(&preamble)
                .map_err(|error| format!("psiphon ssh preamble: {error}"))?;
        }
        Ok((
            PacketWriter::new(write, Some(client), None, None),
            PacketReader::new(socket, Some(remote), None, None, pool),
        ))
    } else {
        Ok((
            PacketWriter::new(write, None, None, None),
            PacketReader::new(socket, None, None, None, pool),
        ))
    }
}

/// Fill a buffer from system entropy.
pub(crate) fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).expect("psiphon: system entropy");
    bytes
}

thread_local! {
    static DIAL_RNG: std::cell::RefCell<Option<DialRng>> = const { std::cell::RefCell::new(None) };
}

/// The per-dial `ChaCha20` stream that makes shape draws replayable.
struct DialRng {
    seed: [u8; 32],
    cipher: chacha20::ChaCha20,
    block: [u8; 64],
    offset: usize,
}

impl DialRng {
    /// Start a `ChaCha20` stream at block zero for this dial seed.
    fn new(seed: [u8; 32]) -> Self {
        use chacha20::cipher::KeyIvInit;
        let cipher = chacha20::ChaCha20::new_from_slices(&seed, &[0u8; 12])
            .expect("psiphon: ChaCha20 key and nonce lengths are fixed");
        Self {
            seed,
            cipher,
            block: [0u8; 64],
            offset: 64,
        }
    }

    /// Read the next bytes of the dial stream.
    fn fill(&mut self, out: &mut [u8]) {
        use chacha20::cipher::StreamCipher;
        for byte in out {
            if self.offset == self.block.len() {
                self.block = [0u8; 64];
                self.cipher.apply_keystream(&mut self.block);
                self.offset = 0;
            }
            *byte = self.block[self.offset];
            self.offset += 1;
        }
    }
}

/// Restore the previous dial seed when a nested scope ends.
pub(crate) struct DialSeedScope {
    previous: Option<DialRng>,
    _not_send: std::marker::PhantomData<*const ()>,
}

impl Drop for DialSeedScope {
    fn drop(&mut self) {
        DIAL_RNG.with(|cell| {
            *cell.borrow_mut() = self.previous.take();
        });
    }
}

/// Make every dial-shape draw in this thread deterministic from `seed`.
pub(crate) fn dial_seed_scope(seed: [u8; 32]) -> DialSeedScope {
    let previous = DIAL_RNG.with(|cell| cell.borrow_mut().replace(DialRng::new(seed)));
    DialSeedScope {
        previous,
        _not_send: std::marker::PhantomData,
    }
}

/// The seed in force on this thread, so a relay thread can replay the same shape.
pub(crate) fn current_dial_seed() -> Option<[u8; 32]> {
    DIAL_RNG.with(|cell| cell.borrow().as_ref().map(|rng| rng.seed))
}

/// A dial-shape random value, or system entropy when no replay scope is active.
pub(crate) fn dial_random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    dial_fill(&mut bytes);
    bytes
}

/// Fill a dial-shape buffer, or system entropy when no replay scope is active.
pub(crate) fn dial_fill(bytes: &mut [u8]) {
    DIAL_RNG.with(|cell| {
        let mut guard = cell.borrow_mut();
        if let Some(rng) = guard.as_mut() {
            rng.fill(bytes);
        } else {
            getrandom::fill(bytes).expect("psiphon: system entropy");
        }
    });
}

/// A random payload size in the inclusive range.
fn random_size(min: usize, max: usize) -> usize {
    if max <= min {
        return min;
    }
    let span = u64::try_from(max - min)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    min + usize::try_from(u64::from_le_bytes(random::<8>()) % span).unwrap_or(0)
}

pub(crate) fn derive_key(seed: &[u8], keyword: &[u8], iv: &[u8]) -> [u8; KEY_LENGTH] {
    let mut hasher = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
    hasher.update(seed);
    hasher.update(keyword);
    hasher.update(iv);
    let mut digest = hasher.finish();
    for _ in 0..HASH_ITERATIONS {
        digest = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, digest.as_ref());
    }
    let mut key = [0u8; KEY_LENGTH];
    key.copy_from_slice(&digest.as_ref()[..KEY_LENGTH]);
    key
}

#[derive(Clone)]
pub(crate) struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub(crate) fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (index, byte) in s.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap_or(0);
        }
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, usize::from(j));
        }
        Self { s, i: 0, j: 0 }
    }

    pub(crate) fn apply(&mut self, bytes: &mut [u8]) {
        const BLOCK: usize = 16;
        let (blocks, tail) = bytes.as_chunks_mut::<BLOCK>();
        let mut block = [0u8; BLOCK];
        for chunk in blocks {
            self.keystream(&mut block);
            for (cell, key) in chunk.iter_mut().zip(block.iter()) {
                *cell ^= key;
            }
        }
        if !tail.is_empty() {
            self.keystream(&mut block[..tail.len()]);
            for (cell, key) in tail.iter_mut().zip(block.iter()) {
                *cell ^= key;
            }
        }
    }

    fn keystream(&mut self, out: &mut [u8]) {
        for cell in out.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[usize::from(self.i)]);
            self.s.swap(usize::from(self.i), usize::from(self.j));
            let k = self.s[usize::from(self.i)].wrapping_add(self.s[usize::from(self.j)]);
            *cell = self.s[usize::from(k)];
        }
    }
}

type AesCtr = ctr::Ctr128BE<aes::Aes128>;

/// Padding entropy drawn a page at a time, so a relayed megabyte is not a megabyte of `getrandom` calls.
struct Entropy {
    bytes: [u8; ENTROPY],
    at: usize,
}

impl Entropy {
    fn new() -> Self {
        Self {
            bytes: [0u8; ENTROPY],
            at: ENTROPY,
        }
    }

    fn fill(&mut self, out: &mut [u8]) -> io::Result<()> {
        if out.len() > ENTROPY {
            return getrandom::fill(out).map_err(|error| io::Error::other(error.to_string()));
        }
        if ENTROPY - self.at < out.len() {
            getrandom::fill(&mut self.bytes)
                .map_err(|error| io::Error::other(error.to_string()))?;
            self.at = 0;
        }
        out.copy_from_slice(&self.bytes[self.at..self.at + out.len()]);
        self.at += out.len();
        Ok(())
    }
}

struct PacketWriter {
    io: Stream,
    obfuscation: Option<Rc4>,
    cipher: Option<AesCtr>,
    mac: Option<HmacKey>,
    sequence: u32,
    block: usize,
    scratch: Vec<u8>,
    entropy: Entropy,
}

/// One received SSH packet, holding the pool buffer it was read into.
struct Packet {
    buffer: Vec<u8>,
    start: usize,
    end: usize,
}

impl Packet {
    fn kind(&self) -> Option<u8> {
        (self.start < self.end).then(|| self.buffer[self.start])
    }

    fn raw(&self) -> &[u8] {
        &self.buffer[self.start..self.end]
    }

    fn body(&self) -> &[u8] {
        self.buffer.get(self.start + 1..self.end).unwrap_or(&[])
    }
}

struct PacketReader {
    io: Stream,
    obfuscation: Option<Rc4>,
    cipher: Option<AesCtr>,
    mac: Option<HmacKey>,
    sequence: u32,
    block: usize,
    pool: Arc<Mutex<Vec<Vec<u8>>>>,
    spare: Option<Vec<u8>>,
    /// Bytes a banner read took past its newline, still obfuscated until `recv` applies the keystream.
    pending: Vec<u8>,
}

impl PacketWriter {
    /// Wrap a socket with optional obfuscation and packet crypto.
    fn new(
        io: impl Into<Stream>,
        obfuscation: Option<Rc4>,
        cipher: Option<AesCtr>,
        mac: Option<[u8; 32]>,
    ) -> Self {
        let io = io.into();
        let block = if cipher.is_some() { 16 } else { 8 };
        Self {
            io,
            obfuscation,
            cipher,
            mac: mac.map(|key| HmacKey::new(&key)),
            sequence: 0,
            block,
            scratch: Vec::new(),
            entropy: Entropy::new(),
        }
    }

    /// Start packet crypto after the key exchange.
    fn activate(&mut self, key: [u8; 16], iv: [u8; 16], mac: [u8; 32]) {
        self.cipher = Some(AesCtr::new(&key.into(), &iv.into()));
        self.mac = Some(HmacKey::new(&mac));
        self.block = 16;
    }

    /// OSSH is the wire only until the first `SSH_MSG_NEWKEYS` leaves this side.
    fn stop_obfuscation(&mut self) {
        self.obfuscation = None;
    }

    fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        let padding = padding_len(payload.len(), self.block);
        let packet_len = 5 + payload.len() + padding;
        self.begin_packet(packet_len, padding);
        self.scratch.extend_from_slice(payload);
        self.finish_packet(packet_len)
    }

    fn send_channel_data(&mut self, remote: u32, data: &[u8]) -> io::Result<()> {
        let payload_len = 9 + data.len();
        let padding = padding_len(payload_len, self.block);
        let packet_len = 5 + payload_len + padding;
        self.begin_packet(packet_len, padding);
        self.scratch.push(MSG_CHANNEL_DATA);
        self.scratch.extend_from_slice(&remote.to_be_bytes());
        self.scratch
            .extend_from_slice(&u32::try_from(data.len()).unwrap_or(0).to_be_bytes());
        self.scratch.extend_from_slice(data);
        self.finish_packet(packet_len)
    }

    /// The same channel packet, encrypted in the caller's read buffer and written with one vectored call.
    fn send_channel_data_in_place(&mut self, remote: u32, data: &mut [u8]) -> io::Result<()> {
        let payload_len = 9 + data.len();
        let padding = padding_len(payload_len, self.block);
        let packet_len = 5 + payload_len + padding;
        let mut head = [0u8; 14];
        head[..4].copy_from_slice(
            &u32::try_from(packet_len - 4)
                .map_err(|_| io::Error::other("ssh packet too long"))?
                .to_be_bytes(),
        );
        head[4] = u8::try_from(padding).map_err(|_| io::Error::other("ssh padding too long"))?;
        head[5] = MSG_CHANNEL_DATA;
        head[6..10].copy_from_slice(&remote.to_be_bytes());
        head[10..14].copy_from_slice(
            &u32::try_from(data.len())
                .map_err(|_| io::Error::other("ssh channel data too long"))?
                .to_be_bytes(),
        );
        let mut pad = [0u8; 64];
        if padding > pad.len() {
            return Err(io::Error::other("ssh padding too long"));
        }
        self.entropy.fill(&mut pad[..padding])?;
        let mut tag = [0u8; 32];
        let signed = self.mac.is_some();
        if let Some(mac) = self.mac.as_ref() {
            tag = mac.tag_parts(self.sequence, &[&head[..], data, &pad[..padding]]);
        }
        self.sequence = self.sequence.wrapping_add(1);
        if let Some(cipher) = self.cipher.as_mut() {
            cipher.apply_keystream(&mut head);
            cipher.apply_keystream(data);
            cipher.apply_keystream(&mut pad[..padding]);
        }
        if let Some(obfuscation) = self.obfuscation.as_mut() {
            obfuscation.apply(&mut head);
            obfuscation.apply(data);
            obfuscation.apply(&mut pad[..padding]);
            if signed {
                obfuscation.apply(&mut tag);
            }
        }
        let mut slices = [
            IoSlice::new(&head),
            IoSlice::new(data),
            IoSlice::new(&pad[..padding]),
            IoSlice::new(&tag),
        ];
        let count = if signed { 4 } else { 3 };
        write_vectored_all(&mut self.io, &mut slices[..count])
    }

    fn begin_packet(&mut self, packet_len: usize, padding: usize) {
        self.scratch.clear();
        self.scratch.reserve(packet_len + 32);
        self.scratch
            .extend_from_slice(&u32::try_from(packet_len - 4).unwrap_or(0).to_be_bytes());
        self.scratch.push(u8::try_from(padding).unwrap_or(0));
    }

    fn finish_packet(&mut self, packet_len: usize) -> io::Result<()> {
        let pad_start = self.scratch.len();
        self.scratch.resize(packet_len, 0);
        self.entropy.fill(&mut self.scratch[pad_start..])?;
        let tag = self
            .mac
            .as_ref()
            .map(|mac| mac.tag(self.sequence, &self.scratch[..packet_len]));
        self.sequence = self.sequence.wrapping_add(1);
        if let Some(cipher) = self.cipher.as_mut() {
            cipher.apply_keystream(&mut self.scratch[..packet_len]);
        }
        if let Some(tag) = tag {
            self.scratch.extend_from_slice(&tag);
        }
        let total = self.scratch.len();
        if let Some(obfuscation) = self.obfuscation.as_mut() {
            obfuscation.apply(&mut self.scratch[..total]);
        }
        self.io.write_all(&self.scratch[..total])
    }
}

impl PacketReader {
    /// Wrap a socket with optional obfuscation, packet crypto, and a recycle pool.
    fn new(
        io: impl Into<Stream>,
        obfuscation: Option<Rc4>,
        cipher: Option<AesCtr>,
        mac: Option<[u8; 32]>,
        pool: Arc<Mutex<Vec<Vec<u8>>>>,
    ) -> Self {
        let io = io.into();
        let block = if cipher.is_some() { 16 } else { 8 };
        Self {
            io,
            obfuscation,
            cipher,
            mac: mac.map(|key| HmacKey::new(&key)),
            sequence: 0,
            block,
            pool,
            spare: None,
            pending: Vec::new(),
        }
    }

    /// Start packet crypto after the key exchange.
    fn activate(&mut self, key: [u8; 16], iv: [u8; 16], mac: [u8; 32]) {
        self.cipher = Some(AesCtr::new(&key.into(), &iv.into()));
        self.mac = Some(HmacKey::new(&mac));
        self.block = 16;
    }

    /// The peer's first `SSH_MSG_NEWKEYS` is the last obfuscated packet in this direction.
    fn stop_obfuscation(&mut self) {
        self.obfuscation = None;
    }

    /// Return a packet buffer to the reader or its shared pool.
    fn recycle(&mut self, buffer: Vec<u8>) {
        if self.spare.is_none() {
            self.spare = Some(buffer);
        } else {
            recycle(&self.pool, buffer);
        }
    }

    /// Move bytes a banner read took past its newline into the front of `out`, so the packet that
    /// arrived in the same read is not read again from the socket.
    fn take_pending(&mut self, out: &mut [u8]) -> usize {
        let taken = self.pending.len().min(out.len());
        out[..taken].copy_from_slice(&self.pending[..taken]);
        self.pending.drain(..taken);
        taken
    }

    /// Read one packet into a pooled buffer; the caller hands it back or moves it to a channel.
    fn recv(&mut self) -> io::Result<Packet> {
        let mut buffer = self
            .spare
            .take()
            .or_else(|| lock(&self.pool).pop())
            .unwrap_or_default();
        if buffer.len() < PACKET_CHUNK {
            buffer.resize(PACKET_CHUNK, 0);
        }
        let taken = self.take_pending(&mut buffer[..self.block]);
        if taken < self.block {
            self.io.read_exact(&mut buffer[taken..self.block])?;
        }
        if let Some(obfuscation) = self.obfuscation.as_mut() {
            obfuscation.apply(&mut buffer[..self.block]);
        }
        if let Some(cipher) = self.cipher.as_mut() {
            cipher.apply_keystream(&mut buffer[..self.block]);
        }
        let length = u32::from_be_bytes(
            buffer[..4]
                .try_into()
                .map_err(|_| io::Error::other("short packet"))?,
        );
        let length = usize::try_from(length).map_err(|_| io::Error::other("packet too long"))?;
        let total = length + 4;
        // OSSH pads KEX packets to a random length, which is not a cipher-block multiple.
        if length < 5 || total < self.block || total > MAX_PACKET {
            return Err(io::Error::other("invalid ssh packet length"));
        }
        // The tag follows the packet bytes, so one read takes both and a packet costs two reads.
        let framed = total + if self.mac.is_some() { 32 } else { 0 };
        if buffer.len() < framed {
            buffer.resize(framed, 0);
        }
        let taken = self.take_pending(&mut buffer[self.block..framed]);
        if taken < framed - self.block {
            self.io
                .read_exact(&mut buffer[self.block + taken..framed])?;
        }
        if let Some(obfuscation) = self.obfuscation.as_mut() {
            obfuscation.apply(&mut buffer[self.block..total]);
        }
        if let Some(cipher) = self.cipher.as_mut() {
            cipher.apply_keystream(&mut buffer[self.block..total]);
        }
        if let Some(mac) = self.mac.as_ref() {
            if !constant_time_eq(
                &mac.tag(self.sequence, &buffer[..total]),
                &buffer[total..framed],
            ) {
                return Err(io::Error::other("ssh packet mac mismatch"));
            }
        }
        self.sequence = self.sequence.wrapping_add(1);
        let padding = usize::from(buffer[4]);
        if padding + 5 > total {
            return Err(io::Error::other("invalid ssh padding"));
        }
        Ok(Packet {
            buffer,
            start: 5,
            end: total - padding,
        })
    }
}

#[derive(Clone)]
struct HmacKey {
    context: hmac::Context,
}

impl HmacKey {
    /// Capture the keyed inner and outer SHA-256 states once; each tag clones them.
    fn new(key: &[u8]) -> Self {
        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        Self {
            context: hmac::Context::with_key(&key),
        }
    }

    fn tag(&self, sequence: u32, bytes: &[u8]) -> [u8; 32] {
        self.tag_parts(sequence, &[bytes])
    }

    fn tag_parts(&self, sequence: u32, parts: &[&[u8]]) -> [u8; 32] {
        let mut context = self.context.clone();
        context.update(&sequence.to_be_bytes());
        for part in parts {
            context.update(part);
        }
        tag_bytes(context.sign())
    }

    #[cfg(test)]
    fn mac(&self, bytes: &[u8]) -> [u8; 32] {
        let mut context = self.context.clone();
        context.update(bytes);
        tag_bytes(context.sign())
    }
}

fn tag_bytes(tag: hmac::Tag) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(tag.as_ref());
    bytes
}

fn write_vectored_all(io: &mut Stream, mut slices: &mut [IoSlice<'_>]) -> io::Result<()> {
    while !slices.is_empty() {
        let written = match io.write_vectored(slices) {
            Ok(written) => written,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "ssh packet write wrote zero bytes",
            ));
        }
        IoSlice::advance_slices(&mut slices, written);
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

fn padding_len(payload: usize, block: usize) -> usize {
    let mut padding = block - ((payload + 5) % block);
    if padding < 4 {
        padding += block;
    }
    padding
}

fn write_all(writer: &mut PacketWriter, bytes: &[u8]) -> Result<(), String> {
    let mut bytes = bytes.to_vec();
    if let Some(obfuscation) = writer.obfuscation.as_mut() {
        obfuscation.apply(&mut bytes);
    }
    writer
        .io
        .write_all(&bytes)
        .map_err(|error| format!("psiphon ssh write: {error}"))
}

/// Read the server banner, retaining bytes read past its newline.
fn read_identification(reader: &mut PacketReader, banner: &mut Vec<u8>) -> Result<Vec<u8>, String> {
    let mut chunk = [0u8; 512];
    let mut raw = [0u8; 512];
    banner.clear();
    loop {
        let read = match reader.io.read(&mut chunk) {
            Ok(0) => return Err("psiphon ssh closed before its banner".to_owned()),
            Ok(read) => read,
            Err(error) => return Err(format!("psiphon ssh banner: {error}")),
        };
        raw[..read].copy_from_slice(&chunk[..read]);
        let saved = reader.obfuscation.clone();
        if let Some(obfuscation) = reader.obfuscation.as_mut() {
            obfuscation.apply(&mut chunk[..read]);
        }
        let mut start = 0;
        while start < read {
            let Some(offset) = chunk[start..read].iter().position(|byte| *byte == b'\n') else {
                for &byte in &chunk[start..read] {
                    if byte != b'\r' {
                        banner.push(byte);
                    }
                    // The reference server writes padding lines up to 512 characters, 1024 with CRLF.
                    if banner.len() >= MAX_IDENTIFICATION {
                        return Err("psiphon ssh banner too long".to_owned());
                    }
                }
                break;
            };
            let end = start + offset;
            for &byte in &chunk[start..end] {
                if byte != b'\r' {
                    banner.push(byte);
                }
                if banner.len() >= MAX_IDENTIFICATION {
                    return Err("psiphon ssh banner too long".to_owned());
                }
            }
            if banner.starts_with(b"SSH-") {
                if let Some(mut saved) = saved {
                    saved.apply(&mut chunk[..=end]);
                    reader.obfuscation = Some(saved);
                }
                reader.pending.extend_from_slice(&raw[end + 1..read]);
                return Ok(banner.clone());
            }
            banner.clear();
            start = end + 1;
        }
    }
}

struct Keys {
    client_cipher: ([u8; 16], [u8; 16]),
    client_mac: [u8; 32],
    server_cipher: ([u8; 16], [u8; 16]),
    server_mac: [u8; 32],
}

#[allow(clippy::too_many_lines)]
fn kex(
    writer: &mut PacketWriter,
    reader: &mut PacketReader,
    client_version: &[u8],
    server_version: &[u8],
    expected_host_key: &[u8],
    algorithms: Option<&[String; 4]>,
) -> Result<Keys, String> {
    let [kex_name, cipher, mac, host_key] = match algorithms {
        Some(names) => (*names).clone(),
        None => [
            "curve25519-sha256,curve25519-sha256@libssh.org".to_owned(),
            "aes128-ctr".to_owned(),
            "hmac-sha2-256".to_owned(),
            "rsa-sha2-256,rsa-sha2-512,ssh-rsa,ssh-ed25519".to_owned(),
        ],
    };
    let mut kexinit = vec![MSG_KEXINIT];
    kexinit.extend_from_slice(&random::<16>());
    put_name_list(&mut kexinit, kex_name.as_bytes());
    put_name_list(&mut kexinit, host_key.as_bytes());
    put_name_list(&mut kexinit, cipher.as_bytes());
    put_name_list(&mut kexinit, cipher.as_bytes());
    put_name_list(&mut kexinit, mac.as_bytes());
    put_name_list(&mut kexinit, mac.as_bytes());
    put_name_list(&mut kexinit, b"none");
    put_name_list(&mut kexinit, b"none");
    put_name_list(&mut kexinit, b"");
    put_name_list(&mut kexinit, b"");
    kexinit.push(0);
    put_u32(&mut kexinit, 0);
    writer
        .send(&kexinit)
        .map_err(|error| format!("psiphon ssh kexinit: {error}"))?;

    let reply = loop {
        let packet = recv(reader)?;
        match packet.kind() {
            Some(MSG_KEXINIT) => break packet,
            Some(MSG_DISCONNECT | MSG_IGNORE | MSG_DEBUG) => {}
            Some(other) => return Err(format!("psiphon ssh expected kexinit, got {other}")),
            None => return Err("psiphon ssh empty packet".to_owned()),
        }
    };
    let host_key_algorithm = parse_kexinit(reply.raw(), expected_host_key)?;
    if !matches!(
        host_key_algorithm.as_str(),
        "rsa-sha2-256" | "rsa-sha2-512" | "ssh-rsa" | "ssh-ed25519"
    ) {
        return Err(format!(
            "psiphon ssh host key {host_key_algorithm} is not supported"
        ));
    }

    let secret = random::<32>();
    let public = x25519(secret, X25519_BASEPOINT_BYTES);
    let mut init = vec![MSG_KEX_ECDH_INIT];
    put_str(&mut init, &public);
    writer
        .send(&init)
        .map_err(|error| format!("psiphon ssh kex init: {error}"))?;

    let packet = loop {
        let packet = recv(reader)?;
        match packet.kind() {
            Some(MSG_KEX_ECDH_REPLY) => break packet,
            Some(MSG_IGNORE | MSG_DEBUG) => {}
            Some(other) => return Err(format!("psiphon ssh expected kex reply, got {other}")),
            None => return Err("psiphon ssh empty packet".to_owned()),
        }
    };
    let raw = packet.raw();
    let mut at = 1;
    let host_key = take_str_ok(raw, &mut at)?;
    let server_public = take_str_ok(raw, &mut at)?;
    let signature = take_str_ok(raw, &mut at)?;
    if host_key != expected_host_key {
        return Err("psiphon ssh host key does not match the signed entry".to_owned());
    }
    if server_public.len() != 32 {
        return Err("psiphon ssh server key is not curve25519".to_owned());
    }
    let server_public: [u8; 32] = server_public
        .try_into()
        .map_err(|_| "psiphon ssh server key is not curve25519")?;
    let shared = x25519(secret, server_public);
    if shared.iter().all(|byte| *byte == 0) {
        return Err("psiphon ssh server key has the wrong order".to_owned());
    }
    // The reference reads the X25519 output as a big-endian integer and encodes it as an mpint.
    let shared = mpint(&shared);
    let mut encoded_shared = Vec::new();
    put_str(&mut encoded_shared, &shared);

    let mut transcript = Vec::new();
    put_str(&mut transcript, client_version);
    put_str(&mut transcript, server_version);
    put_str(&mut transcript, &kexinit);
    put_str(&mut transcript, reply.raw());
    put_str(&mut transcript, host_key);
    put_str(&mut transcript, &public);
    put_str(&mut transcript, &server_public);
    put_str(&mut transcript, &shared);
    let exchange = Sha256::digest(&transcript);

    verify_host_key(host_key, &host_key_algorithm, signature, &exchange)?;

    writer
        .send(&[MSG_NEWKEYS])
        .map_err(|error| format!("psiphon ssh newkeys: {error}"))?;
    writer.stop_obfuscation();
    loop {
        let packet = recv(reader)?;
        match packet.kind() {
            Some(MSG_NEWKEYS) => break,
            Some(MSG_IGNORE | MSG_DEBUG) => {}
            Some(other) => return Err(format!("psiphon ssh expected newkeys, got {other}")),
            None => return Err("psiphon ssh empty packet".to_owned()),
        }
    }
    reader.stop_obfuscation();

    let derive = |letter: u8| {
        let mut hasher = Sha256::new();
        hasher.update(&encoded_shared);
        hasher.update(exchange);
        hasher.update([letter]);
        hasher.update(exchange);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    };
    let client_iv = derive(b'A');
    let server_iv = derive(b'B');
    let client_key = derive(b'C');
    let server_key = derive(b'D');
    let client_mac = derive(b'E');
    let server_mac = derive(b'F');
    let mut client_iv16 = [0u8; 16];
    let mut client_key16 = [0u8; 16];
    let mut server_iv16 = [0u8; 16];
    let mut server_key16 = [0u8; 16];
    client_iv16.copy_from_slice(&client_iv[..16]);
    client_key16.copy_from_slice(&client_key[..16]);
    server_iv16.copy_from_slice(&server_iv[..16]);
    server_key16.copy_from_slice(&server_key[..16]);
    Ok(Keys {
        client_cipher: (client_key16, client_iv16),
        client_mac,
        server_cipher: (server_key16, server_iv16),
        server_mac,
    })
}

fn parse_kexinit(packet: &[u8], expected_host_key: &[u8]) -> Result<String, String> {
    let mut at = 17;
    let kex = take_str_ok(packet, &mut at)?;
    let host_key = take_str_ok(packet, &mut at)?;
    let cipher_client = take_str_ok(packet, &mut at)?;
    let cipher_server = take_str_ok(packet, &mut at)?;
    let mac_client = take_str_ok(packet, &mut at)?;
    let mac_server = take_str_ok(packet, &mut at)?;
    let compress_client = take_str_ok(packet, &mut at)?;
    let compress_server = take_str_ok(packet, &mut at)?;
    for _ in 0..2 {
        take_str_ok(packet, &mut at)?;
    }
    if !kex
        .split(|byte| *byte == b',')
        .any(|name| name == b"curve25519-sha256" || name == b"curve25519-sha256@libssh.org")
    {
        return Err("psiphon ssh server does not offer curve25519-sha256".to_owned());
    }
    for (name, list) in [
        ("aes128-ctr", [cipher_client, cipher_server]),
        ("hmac-sha2-256", [mac_client, mac_server]),
        ("none", [compress_client, compress_server]),
    ] {
        for offered in list {
            if !offered
                .split(|byte| *byte == b',')
                .any(|item| item == name.as_bytes())
            {
                return Err(format!("psiphon ssh server does not offer {name}"));
            }
        }
    }
    let supported: &[&str] = if expected_host_key.starts_with(b"\0\0\0\x0bssh-ed25519") {
        &["ssh-ed25519"]
    } else {
        &["rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"]
    };
    for client in supported {
        if host_key
            .split(|byte| *byte == b',')
            .any(|name| name == client.as_bytes())
        {
            return Ok((*client).to_owned());
        }
    }
    Err("psiphon ssh server offers no supported host key".to_owned())
}

fn verify_host_key(
    key: &[u8],
    algorithm: &str,
    signature_blob: &[u8],
    message: &[u8],
) -> Result<(), String> {
    let mut at = 0;
    let key_type = take_str_ok(key, &mut at)?;
    let (public, ring_algorithm): (Vec<u8>, &dyn signature::VerificationAlgorithm) = match key_type
    {
        b"ssh-rsa" => {
            let e = take_str_ok(key, &mut at)?;
            let n = take_str_ok(key, &mut at)?;
            let der = rsa_der(n, e);
            let ring_algorithm = match algorithm {
                "rsa-sha2-512" => &signature::RSA_PKCS1_2048_8192_SHA512,
                "ssh-rsa" => &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
                _ => &signature::RSA_PKCS1_2048_8192_SHA256,
            };
            (der, ring_algorithm)
        }
        b"ssh-ed25519" => (take_str_ok(key, &mut at)?.to_vec(), &signature::ED25519),
        other => {
            return Err(format!(
                "psiphon ssh unsupported host key {}",
                String::from_utf8_lossy(other)
            ));
        }
    };

    let mut at = 0;
    let signature_algorithm = take_str_ok(signature_blob, &mut at)?;
    let signature = take_str_ok(signature_blob, &mut at)?;
    if signature_algorithm != algorithm.as_bytes() {
        return Err(format!(
            "psiphon ssh signature {} does not match {algorithm}",
            String::from_utf8_lossy(signature_algorithm)
        ));
    }
    signature::UnparsedPublicKey::new(ring_algorithm, public)
        .verify(message, signature)
        .map_err(|_| "psiphon ssh host key signature is invalid".to_owned())
}

fn rsa_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(n.len() + e.len() + 16);
    let mut body = Vec::with_capacity(n.len() + e.len() + 8);
    der_integer(&mut body, n);
    der_integer(&mut body, e);
    out.push(0x30);
    der_length(&mut out, body.len());
    out.extend_from_slice(&body);
    out
}

fn der_integer(out: &mut Vec<u8>, value: &[u8]) {
    out.push(0x02);
    der_length(out, value.len());
    out.extend_from_slice(value);
}

fn der_length(out: &mut Vec<u8>, length: usize) {
    if length < 128 {
        out.push(u8::try_from(length).unwrap_or(0));
    } else {
        let bytes = length.to_be_bytes();
        let first = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len() - 1);
        out.push(0x80 | u8::try_from(bytes.len() - first).unwrap_or(0));
        out.extend_from_slice(&bytes[first..]);
    }
}

fn service(writer: &mut PacketWriter, reader: &mut PacketReader) -> Result<(), String> {
    let mut request = vec![MSG_SERVICE_REQUEST];
    put_str(&mut request, b"ssh-userauth");
    writer
        .send(&request)
        .map_err(|error| format!("psiphon ssh service: {error}"))?;
    loop {
        let packet = recv(reader)?;
        match packet.kind() {
            Some(MSG_SERVICE_ACCEPT) => return Ok(()),
            Some(MSG_EXT_INFO | MSG_IGNORE | MSG_DEBUG | MSG_GLOBAL_REQUEST) => {}
            Some(other) => return Err(format!("psiphon ssh expected service accept, got {other}")),
            None => return Err("psiphon ssh empty packet".to_owned()),
        }
    }
}

const MSG_EXT_INFO: u8 = 7;

/// Authenticate the relay and open the session channel.
fn authenticate(
    writer: &mut PacketWriter,
    reader: &mut PacketReader,
    server: &Server,
    session_id: &str,
    sponsor: &str,
) -> Result<(), String> {
    let password = format!(
        r#"{{"SessionId":"{}","SshPassword":"{}","ClientCapabilities":["{}"],"SponsorId":"{}"}}"#,
        json_escape(session_id),
        json_escape(&server.password),
        CLIENT_CAPABILITIES,
        json_escape(sponsor)
    );
    let mut request = vec![MSG_USERAUTH_REQUEST];
    put_str(&mut request, server.user.as_bytes());
    put_str(&mut request, b"ssh-connection");
    put_str(&mut request, b"password");
    request.push(0);
    put_str(&mut request, password.as_bytes());
    writer
        .send(&request)
        .map_err(|error| format!("psiphon ssh auth: {error}"))?;
    loop {
        let packet = recv(reader)?;
        match packet.kind() {
            Some(MSG_USERAUTH_SUCCESS) => return Ok(()),
            Some(MSG_USERAUTH_FAILURE) => {
                return Err("psiphon ssh refused the server entry's password".to_owned());
            }
            Some(MSG_EXT_INFO | MSG_IGNORE | MSG_DEBUG | MSG_GLOBAL_REQUEST) => {}
            Some(other) => return Err(format!("psiphon ssh expected auth success, got {other}")),
            None => return Err("psiphon ssh empty packet".to_owned()),
        }
    }
}

/// The base tunnel protocol a CDN variant reports to the server.
fn tunnel_protocol_base(protocol: &'static str) -> &'static str {
    match protocol {
        "FRONTED-MEEK-CDN-OSSH" => "FRONTED-MEEK-OSSH",
        "FRONTED-MEEK-CDN-HTTP-OSSH" => "FRONTED-MEEK-HTTP-OSSH",
        "FRONTED-MEEK-CDN-QUIC-OSSH" => "FRONTED-MEEK-QUIC-OSSH",
        _ => protocol,
    }
}

/// The JSON body of the SSH Psiphon handshake.
fn handshake_body(relay_protocol: &str, identity: &Identity<'_>, relay: Option<&Relay>) -> String {
    let mut body = format!(
        r#"{{"propagation_channel_id":"{}","sponsor_id":"{}","client_version":"{}","client_platform":"{}","relay_protocol":"{}""#,
        json_escape(identity.propagation),
        json_escape(identity.sponsor),
        json_escape(identity.version),
        json_escape(identity.platform),
        json_escape(relay_protocol)
    );
    if let Some(region) = identity.egress_region {
        let _ = write!(body, r#","egress_region":"{}""#, json_escape(region));
    }
    if let Some(region) = identity.device_region {
        let _ = write!(body, r#","device_region":"{}""#, json_escape(region));
    }
    if let Some(location) = identity.device_location {
        let _ = write!(body, r#","device_location":"{}""#, json_escape(location));
    }
    if identity.split_tunnel {
        body.push_str(r#","split_tunnel":"1""#);
    }
    if !identity.split_tunnel_regions.is_empty() {
        body.push_str(r#","split_tunnel_regions":["#);
        for (index, region) in identity.split_tunnel_regions.iter().enumerate() {
            if index > 0 {
                body.push(',');
            }
            let _ = write!(body, "\"{}\"", json_escape(region));
        }
        body.push(']');
    }
    if !identity.authorizations.is_empty() {
        body.push_str(r#","authorizations":["#);
        for (index, authorization) in identity.authorizations.iter().enumerate() {
            if index > 0 {
                body.push(',');
            }
            let _ = write!(body, "\"{}\"", json_escape(authorization));
        }
        body.push(']');
    }
    if let Some(relay) = relay {
        let connection_id = ferrox_core::b64::encode(relay.connection_id());
        let packet = ferrox_core::b64::encode(relay.initial());
        let _ = write!(
            body,
            r#","inproxy_connection_id":"{}","inproxy_relay_packet":"{}""#,
            connection_id.trim_end_matches('='),
            packet.trim_end_matches('=')
        );
    }
    if !identity.client_features.is_empty() {
        body.push_str(r#","client_features":["#);
        for (index, feature) in identity.client_features.iter().enumerate() {
            if index > 0 {
                body.push(',');
            }
            let _ = write!(body, "\"{}\"", json_escape(feature));
        }
        body.push(']');
    }
    if identity.compress_tactics {
        body.push_str(r#","psiphon_api_response_version":"1""#);
    }
    body.push('}');
    body
}

/// The packed authorization list, following the reference's access-control struct.
fn packed_authorizations(authorizations: &[String]) -> Result<Vec<u8>, String> {
    let mut packed = Vec::with_capacity(authorizations.len());
    for authorization in authorizations {
        let decoded = ferrox_core::b64::decode(authorization.as_bytes())
            .ok_or_else(|| "psiphon authorization is not base64".to_owned())?;
        let text = std::str::from_utf8(&decoded)
            .map_err(|_| "psiphon authorization is not utf-8".to_owned())?;
        let json =
            crate::json::parse(text).map_err(|_| "psiphon authorization is not json".to_owned())?;
        let signed = json
            .get("Authorization")
            .ok_or_else(|| "psiphon authorization has no payload".to_owned())?;
        let bytes = |object: &crate::json::Json, key: &str| -> Result<Vec<u8>, String> {
            object
                .get(key)
                .and_then(crate::json::Json::as_str)
                .and_then(|value| ferrox_core::b64::decode(value.as_bytes()))
                .ok_or_else(|| format!("psiphon authorization has no {key}"))
        };
        let expires = signed
            .get("Expires")
            .and_then(crate::json::Json::as_str)
            .ok_or_else(|| "psiphon authorization has no expiry".to_owned())?;
        let access_type = signed
            .get("AccessType")
            .and_then(crate::json::Json::as_str)
            .ok_or_else(|| "psiphon authorization has no access type".to_owned())?;
        let mut entries = vec![
            (
                crate::psiphon_broker::Value::UInt(1),
                crate::psiphon_broker::Value::Bytes(bytes(signed, "ID")?),
            ),
            (
                crate::psiphon_broker::Value::UInt(2),
                crate::psiphon_broker::Value::Text(access_type.to_owned()),
            ),
            (
                crate::psiphon_broker::Value::UInt(4),
                crate::psiphon_broker::Value::Bytes(bytes(&json, "SigningKeyID")?),
            ),
            (
                crate::psiphon_broker::Value::UInt(5),
                crate::psiphon_broker::Value::Bytes(bytes(&json, "Signature")?),
            ),
        ];
        if expires != "0001-01-01T00:00:00Z" {
            entries.push((
                crate::psiphon_broker::Value::UInt(3),
                crate::psiphon_broker::Value::Text(expires.to_owned()),
            ));
        }
        entries.sort_by_key(|(key, _)| match key {
            crate::psiphon_broker::Value::UInt(key) => *key,
            _ => 0,
        });
        packed.push(crate::psiphon_broker::Value::Map(entries));
    }
    Ok(crate::psiphon_broker::encode(
        &crate::psiphon_broker::Value::Array(packed),
    ))
}

/// The packed CBOR SSH API request: integer keys and the fields the server reads from SSH.
fn packed_handshake_body(
    relay_protocol: &str,
    identity: &Identity<'_>,
    relay: Option<&Relay>,
) -> Result<Vec<u8>, String> {
    let mut entries = Vec::new();
    let mut push = |key: u64, value: crate::psiphon_broker::Value| {
        entries.push((crate::psiphon_broker::Value::UInt(key), value));
    };
    push(
        1,
        crate::psiphon_broker::Value::Bytes(packed_authorizations(identity.authorizations)?),
    );
    push(
        6,
        crate::psiphon_broker::Value::Bytes(
            crate::psiphon::hex_decode(identity.propagation)
                .ok_or_else(|| "psiphon propagation channel id is not hex".to_owned())?,
        ),
    );
    push(
        7,
        crate::psiphon_broker::Value::Bytes(
            crate::psiphon::hex_decode(identity.sponsor)
                .ok_or_else(|| "psiphon sponsor id is not hex".to_owned())?,
        ),
    );
    push(
        8,
        crate::psiphon_broker::Value::UInt(
            identity
                .version
                .parse()
                .map_err(|_| "psiphon client version is not a number".to_owned())?,
        ),
    );
    push(
        9,
        crate::psiphon_broker::Value::Text(identity.platform.to_owned()),
    );
    if !identity.client_features.is_empty() {
        push(
            10,
            crate::psiphon_broker::Value::Array(
                identity
                    .client_features
                    .iter()
                    .map(|feature| crate::psiphon_broker::Value::Text(feature.clone()))
                    .collect(),
            ),
        );
    }
    if let Some(region) = identity.device_region {
        push(12, crate::psiphon_broker::Value::Text(region.to_owned()));
    }
    if let Some(location) = identity.device_location {
        push(13, crate::psiphon_broker::Value::Text(location.to_owned()));
    }
    push(
        15,
        crate::psiphon_broker::Value::Text(relay_protocol.to_owned()),
    );
    if let Some(region) = identity.egress_region {
        push(43, crate::psiphon_broker::Value::Text(region.to_owned()));
    }
    if identity.split_tunnel {
        push(63, crate::psiphon_broker::Value::Text("1".to_owned()));
    }
    if !identity.split_tunnel_regions.is_empty() {
        push(
            64,
            crate::psiphon_broker::Value::Array(
                identity
                    .split_tunnel_regions
                    .iter()
                    .map(|region| crate::psiphon_broker::Value::Text(region.clone()))
                    .collect(),
            ),
        );
    }
    if let Some(relay) = relay {
        push(
            76,
            crate::psiphon_broker::Value::Bytes(relay.connection_id().to_vec()),
        );
        push(
            77,
            crate::psiphon_broker::Value::Bytes(relay.initial().to_vec()),
        );
    }
    if identity.compress_tactics {
        push(168, crate::psiphon_broker::Value::UInt(1));
    }
    entries.sort_by_key(|(key, _)| match key {
        crate::psiphon_broker::Value::UInt(key) => *key,
        _ => 0,
    });
    let mut payload = vec![0, 1];
    payload.extend_from_slice(&crate::psiphon_broker::encode(
        &crate::psiphon_broker::Value::Map(entries),
    ));
    Ok(payload)
}

#[allow(clippy::cast_precision_loss)]
fn cbor_value_json(value: &crate::psiphon_broker::Value) -> Option<crate::json::Json> {
    match value {
        crate::psiphon_broker::Value::Text(text) => Some(crate::json::Json::Str(text.clone())),
        crate::psiphon_broker::Value::Bytes(bytes) => std::str::from_utf8(bytes).ok().map(|text| {
            crate::json::parse(text).unwrap_or_else(|_| crate::json::Json::Str(text.to_owned()))
        }),
        crate::psiphon_broker::Value::Array(items) => Some(crate::json::Json::Arr(
            items.iter().filter_map(cbor_value_json).collect(),
        )),
        crate::psiphon_broker::Value::Bool(flag) => Some(crate::json::Json::Bool(*flag)),
        crate::psiphon_broker::Value::UInt(number) => Some(crate::json::Json::Num(*number as f64)),
        crate::psiphon_broker::Value::Int(number) => Some(crate::json::Json::Num(*number as f64)),
        crate::psiphon_broker::Value::Float(number) => Some(crate::json::Json::Num(*number)),
        crate::psiphon_broker::Value::Null => Some(crate::json::Json::Null),
        crate::psiphon_broker::Value::Map(_) => None,
    }
}

/// The integer-keyed CBOR handshake reply as the lane's own JSON.
fn cbor_handshake_json(body: &[u8]) -> Option<crate::json::Json> {
    let (value, used) = crate::psiphon_broker::decode(body)?;
    if used != body.len() {
        return None;
    }
    let mut pairs = Vec::new();
    if let crate::psiphon_broker::Value::Map(entries) = value {
        for (key, value) in entries {
            let crate::psiphon_broker::Value::UInt(key) = key else {
                continue;
            };
            let Some(name) = handshake_key_name(key) else {
                continue;
            };
            let Some(json) = cbor_value_json(&value) else {
                continue;
            };
            pairs.push((name.to_owned(), json));
        }
    } else {
        return None;
    }
    Some(crate::json::Json::Obj(pairs))
}

fn handshake_key_name(key: u64) -> Option<&'static str> {
    Some(match key {
        1 => "homepages",
        2 => "upgrade_client_version",
        3 => "page_view_regexes",
        4 => "https_request_regexes",
        5 => "encoded_server_list",
        6 => "client_region",
        7 => "client_address",
        8 => "server_timestamp",
        9 => "active_authorization_ids",
        10 => "tactics_payload",
        11 => "tactics_payload_compression",
        12 => "upstream",
        13 => "downstream",
        14 => "steering_ip",
        15 => "padding",
        _ => return None,
    })
}

/// The SSH API handshake every Psiphon server requires before it permits a port forward.
fn handshake(
    writer: &mut PacketWriter,
    reader: &mut PacketReader,
    relay_protocol: &str,
    identity: &Identity<'_>,
    ssh_api: bool,
    relay: &mut Option<Relay>,
    requests: Option<&dyn ServerRequests>,
) -> Result<HandshakeState, String> {
    let encoding = if ssh_api {
        identity.api_encoding
    } else {
        ApiEncoding::Json
    };
    let body = match encoding {
        ApiEncoding::Json => handshake_body(relay_protocol, identity, relay.as_ref()).into_bytes(),
        ApiEncoding::Cbor => packed_handshake_body(relay_protocol, identity, relay.as_ref())?,
    };
    let mut request = vec![MSG_GLOBAL_REQUEST];
    put_str(&mut request, b"psiphon-handshake");
    request.push(1);
    request.extend_from_slice(&body);
    writer
        .send(&request)
        .map_err(|error| format!("psiphon ssh handshake: {error}"))?;
    loop {
        let packet = recv(reader)?;
        match packet.kind() {
            Some(MSG_REQUEST_SUCCESS) => return Ok(parse_handshake(packet.body())),
            Some(MSG_REQUEST_FAILURE) => {
                return Err("psiphon ssh refused the tunnel handshake".to_owned());
            }
            Some(MSG_GLOBAL_REQUEST) => {
                let mut at = 0;
                let name = take_str(packet.body(), &mut at);
                let want_reply = packet.body().get(at).copied().unwrap_or(0);
                let payload = packet.body().get(at + 1..).unwrap_or(&[]);
                let reply = match name {
                    Some(b"psiphon-inproxy-relay") => relay_round_trip(relay, payload).map(Some),
                    Some(name) => match requests {
                        Some(requests) => requests.handle(name, payload).map(Some),
                        None => Err("psiphon ssh unexpected handshake request".to_owned()),
                    },
                    None => Err("psiphon ssh malformed handshake request".to_owned()),
                };
                match reply {
                    Ok(payload) if want_reply != 0 => {
                        let mut reply = vec![MSG_REQUEST_SUCCESS];
                        reply.extend_from_slice(payload.as_deref().unwrap_or(&[]));
                        writer
                            .send(&reply)
                            .map_err(|error| format!("psiphon ssh relay reply: {error}"))?;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        if want_reply != 0 {
                            let _ = writer.send(&[MSG_REQUEST_FAILURE]);
                        }
                        if name == Some(b"psiphon-inproxy-relay") {
                            return Err(error);
                        }
                        eprintln!("psiphon ssh: {error}");
                    }
                }
            }
            Some(MSG_EXT_INFO | MSG_IGNORE | MSG_DEBUG) => {}
            Some(other) => {
                return Err(format!("psiphon ssh expected handshake reply, got {other}"))
            }
            None => return Err("psiphon ssh empty packet".to_owned()),
        }
    }
}

/// The JSON or CBOR handshake reply; an empty or malformed body leaves every field empty.
fn parse_handshake(body: &[u8]) -> HandshakeState {
    let json = if body
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        == Some(b'{')
    {
        std::str::from_utf8(body)
            .ok()
            .and_then(|text| crate::json::parse(text).ok())
    } else {
        cbor_handshake_json(body)
    };
    let Some(json) = json else {
        return HandshakeState::default();
    };
    let strings = |key: &str| {
        json.get(key)
            .and_then(crate::json::Json::as_arr)
            .map(|items| {
                items
                    .iter()
                    .filter_map(crate::json::Json::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    let value = |key: &str| {
        json.get(key)
            .and_then(crate::json::Json::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    HandshakeState {
        homepages: strings("homepages"),
        upgrade_client_version: value("upgrade_client_version"),
        encoded_server_list: strings("encoded_server_list"),
        client_region: value("client_region"),
        client_address: value("client_address"),
        server_timestamp: value("server_timestamp"),
        active_authorization_ids: strings("active_authorization_ids"),
        tactics_payload: json.get("tactics_payload").cloned(),
        steering_ip: value("steering_ip"),
    }
}

fn relay_round_trip(relay: &mut Option<Relay>, payload: &[u8]) -> Result<Vec<u8>, String> {
    let packet = crate::psiphon_broker::relay_request_packet(payload)?;
    let relay = relay
        .as_mut()
        .ok_or_else(|| "psiphon ssh: no in-proxy relay".to_owned())?;
    let next = relay.relay(&packet)?;
    Ok(crate::psiphon_broker::relay_response(&next))
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
                let _ = write!(out, "\\u{:04x}", u32::from(ch));
            }
            ch => out.push(ch),
        }
    }
    out
}

/// What the dispatcher did with the packet buffer it was handed.
enum Dispatch {
    Recycle(Vec<u8>),
    Queued,
    Stop,
}

#[allow(clippy::needless_pass_by_value)]
fn read_loop(inner: Arc<Inner>, mut reader: PacketReader) {
    while let Ok(packet) = reader.recv() {
        inner.touch();
        match dispatch(&inner, packet) {
            Dispatch::Recycle(buffer) => reader.recycle(buffer),
            Dispatch::Queued => {}
            Dispatch::Stop => break,
        }
    }
    inner.close();
}

#[allow(clippy::too_many_lines)]
fn dispatch(inner: &Arc<Inner>, packet: Packet) -> Dispatch {
    let Some(kind) = packet.kind() else {
        return Dispatch::Stop;
    };
    let body = packet.body();
    match kind {
        MSG_CHANNEL_OPEN_CONFIRMATION => {
            let mut at = 0;
            let (Some(local), Some(remote), Some(window), Some(packet_size)) = (
                take_u32(body, &mut at),
                take_u32(body, &mut at),
                take_u32(body, &mut at),
                take_u32(body, &mut at),
            ) else {
                return Dispatch::Stop;
            };
            let Some(state) = lock(&inner.channels).get(&local).cloned() else {
                return Dispatch::Recycle(packet.buffer);
            };
            state.remote.store(remote, Ordering::Release);
            *lock(&state.remote_window) = u64::from(window);
            state.remote_packet.store(packet_size, Ordering::Release);
            if let Some(tx) = lock(&state.open).take() {
                let _ = tx.send(Ok(OpenResult::Confirmed));
            }
            state.cond.notify_all();
            state.window_cond.notify_all();
            Dispatch::Recycle(packet.buffer)
        }
        MSG_CHANNEL_OPEN_FAILURE => {
            let mut at = 0;
            let Some(local) = take_u32(body, &mut at) else {
                return Dispatch::Stop;
            };
            let reason = take_u32(body, &mut at).unwrap_or(0);
            let description = take_str(body, &mut at)
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                .unwrap_or_default();
            if let Some(state) = lock(&inner.channels).remove(&local) {
                if reason == CHANNEL_REJECT_SPLIT_TUNNEL {
                    state.split_tunnel();
                } else if description.is_empty() {
                    state.fail("psiphon ssh refused the channel");
                } else {
                    state.fail(&format!("psiphon ssh refused the channel: {description}"));
                }
            }
            Dispatch::Recycle(packet.buffer)
        }
        MSG_CHANNEL_WINDOW_ADJUST => {
            let mut at = 0;
            let (Some(local), Some(add)) = (take_u32(body, &mut at), take_u32(body, &mut at))
            else {
                return Dispatch::Stop;
            };
            if let Some(state) = by_local(inner, local) {
                *lock(&state.remote_window) += u64::from(add);
                state.window_cond.notify_all();
            }
            Dispatch::Recycle(packet.buffer)
        }
        MSG_CHANNEL_DATA => {
            let mut at = 0;
            let Some(local) = take_u32(body, &mut at) else {
                return Dispatch::Stop;
            };
            let Some(data) = take_str(body, &mut at) else {
                return Dispatch::Stop;
            };
            if data.is_empty() {
                return Dispatch::Recycle(packet.buffer);
            }
            let offset = packet.start + 1 + at - data.len();
            let end = offset + data.len();
            let data_len = data.len();
            let Some(state) = by_local(inner, local) else {
                return Dispatch::Recycle(packet.buffer);
            };
            let mut recv = lock(&state.recv);
            if data_len as u64 > recv.local_window {
                return Dispatch::Stop;
            }
            recv.local_window -= data_len as u64;
            let was_empty = recv.chunks.is_empty();
            recv.chunks.push_back(Chunk {
                buffer: packet.buffer,
                start: offset,
                end,
            });
            drop(recv);
            // A reader already draining does not need a wake per packet; only the transition does.
            if was_empty {
                state.cond.notify_one();
            }
            Dispatch::Queued
        }
        MSG_CHANNEL_EOF => {
            let mut at = 0;
            let Some(local) = take_u32(body, &mut at) else {
                return Dispatch::Stop;
            };
            if let Some(state) = by_local(inner, local) {
                lock(&state.recv).eof = true;
                state.cond.notify_all();
            }
            Dispatch::Recycle(packet.buffer)
        }
        MSG_CHANNEL_CLOSE => {
            let mut at = 0;
            let Some(local) = take_u32(body, &mut at) else {
                return Dispatch::Stop;
            };
            if let Some(state) = by_local(inner, local) {
                lock(&inner.channels).remove(&local);
                inner.close_channel(&state);
                state.peer_closed();
            }
            Dispatch::Recycle(packet.buffer)
        }
        MSG_CHANNEL_REQUEST => {
            let mut at = 0;
            let (Some(local), Some(request)) = (take_u32(body, &mut at), take_str(body, &mut at))
            else {
                return Dispatch::Stop;
            };
            let Some(want_reply) = body.get(at).copied() else {
                return Dispatch::Stop;
            };
            if want_reply != 0 {
                let kind = if matches!(request, b"exit-status" | b"exit-signal") {
                    MSG_CHANNEL_SUCCESS
                } else {
                    MSG_CHANNEL_FAILURE
                };
                if let Some(state) = by_local(inner, local) {
                    let mut payload = [0u8; 5];
                    payload[0] = kind;
                    let _ = inner.send_framed(&state, &mut payload);
                }
            }
            Dispatch::Recycle(packet.buffer)
        }
        MSG_GLOBAL_REQUEST => {
            let mut at = 0;
            let Some(name) = take_str(body, &mut at) else {
                return Dispatch::Stop;
            };
            let want_reply = body.get(at).copied().unwrap_or(0);
            let payload = body.get(at + 1..).unwrap_or(&[]);
            if name == b"psiphon-inproxy-relay" {
                match inner.relay_round_trip(payload) {
                    Ok(payload) if want_reply != 0 => {
                        let mut reply = vec![MSG_REQUEST_SUCCESS];
                        reply.extend_from_slice(&payload);
                        let _ = inner.send(&reply);
                    }
                    Ok(_) => {}
                    Err(_) => {
                        if want_reply != 0 {
                            let _ = inner.send(&[MSG_REQUEST_FAILURE]);
                        }
                        return Dispatch::Stop;
                    }
                }
            } else if let Some(requests) = inner.requests.as_deref() {
                match requests.handle(name, payload) {
                    Ok(payload) if want_reply != 0 => {
                        let mut reply = vec![MSG_REQUEST_SUCCESS];
                        reply.extend_from_slice(&payload);
                        let _ = inner.send(&reply);
                    }
                    Ok(_) => {}
                    Err(error) => {
                        if want_reply != 0 {
                            let _ = inner.send(&[MSG_REQUEST_FAILURE]);
                        }
                        eprintln!("psiphon ssh: {error}");
                    }
                }
            } else if want_reply != 0 {
                let _ = inner.send(&[MSG_REQUEST_FAILURE]);
            }
            Dispatch::Recycle(packet.buffer)
        }
        MSG_REQUEST_SUCCESS | MSG_REQUEST_FAILURE => {
            if let Some(reply) = lock(&inner.pending_api).take() {
                let result = if kind == MSG_REQUEST_SUCCESS {
                    Ok(body.to_vec())
                } else {
                    Err("psiphon ssh api request rejected".to_owned())
                };
                let _ = reply.send(result);
            } else if let Some(reply) = lock(&inner.pending_request).take() {
                let _ = reply.send(kind == MSG_REQUEST_SUCCESS);
            }
            Dispatch::Recycle(packet.buffer)
        }
        // Rekey is not implemented; a stalled session is worse than a reconnect.
        MSG_DISCONNECT | MSG_KEXINIT => Dispatch::Stop,
        _ => Dispatch::Recycle(packet.buffer),
    }
}

/// Every message from the server names the recipient, which is the channel id this side chose.
fn by_local(inner: &Inner, local: u32) -> Option<Arc<ChannelState>> {
    lock(&inner.channels).get(&local).cloned()
}

fn recv(reader: &mut PacketReader) -> Result<Packet, String> {
    reader
        .recv()
        .map_err(|error| format!("psiphon ssh read: {error}"))
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// A `channel close` addressed to the peer's channel id.
fn channel_close(remote: u32) -> [u8; 5] {
    let mut payload = [0u8; 5];
    payload[0] = MSG_CHANNEL_CLOSE;
    payload[1..].copy_from_slice(&remote.to_be_bytes());
    payload
}

fn put_str(out: &mut Vec<u8>, value: &[u8]) {
    put_u32(out, u32::try_from(value.len()).unwrap_or(0));
    out.extend_from_slice(value);
}

fn put_name_list(out: &mut Vec<u8>, value: &[u8]) {
    put_str(out, value);
}

fn take_u32(bytes: &[u8], at: &mut usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    let value = u32::from_be_bytes(bytes.get(*at..end)?.try_into().ok()?);
    *at = end;
    Some(value)
}

fn take_str<'a>(bytes: &'a [u8], at: &mut usize) -> Option<&'a [u8]> {
    let length = usize::try_from(take_u32(bytes, at)?).ok()?;
    let end = at.checked_add(length)?;
    let value = bytes.get(*at..end)?;
    *at = end;
    Some(value)
}

fn take_str_ok<'a>(bytes: &'a [u8], at: &mut usize) -> Result<&'a [u8], String> {
    take_str(bytes, at).ok_or_else(|| "psiphon ssh truncated message".to_owned())
}

fn mpint(value: &[u8]) -> Vec<u8> {
    let first = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len());
    let value = &value[first..];
    if value.is_empty() {
        return Vec::new();
    }
    if value[0] & 0x80 == 0 {
        return value.to_vec();
    }
    let mut out = Vec::with_capacity(value.len() + 1);
    out.push(0);
    out.extend_from_slice(value);
    out
}

#[cfg(test)]
pub(crate) fn test_channel_with_chunks(payloads: &[&[u8]]) -> Channel {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
    let peer = TcpStream::connect(listener.local_addr().expect("address")).expect("peer");
    let _ = listener.accept().expect("accept");
    let pool = Arc::new(Mutex::new(Vec::new()));
    let inner = Arc::new(Inner {
        writer: Mutex::new(PacketWriter::new(
            peer.try_clone().expect("clone"),
            None,
            None,
            None,
        )),
        channels: Mutex::new(HashMap::new()),
        pool: Arc::clone(&pool),
        channel_window: DEFAULT_CHANNEL_WINDOW,
        next_channel: AtomicU32::new(1),
        closed: AtomicBool::new(false),
        closed_at: AtomicU64::new(u64::MAX),
        socket: Stream::Tcp(peer),
        relay: Mutex::new(None),
        opened_at: Instant::now(),
        last_read: AtomicU64::new(0),
        bytes_up: AtomicU64::new(0),
        bytes_down: AtomicU64::new(0),
        burst: Mutex::new(crate::psiphon_burst::Burst::default()),
        burst_enabled: false,
        pending_request: Mutex::new(None),
        pending_api: Mutex::new(None),
        api_timed_out: AtomicBool::new(false),
        request_lock: Mutex::new(()),
        requests: None,
        server: "test".to_owned(),
        protocol: "SSH",
        provider_id: None,
        region: None,
        fronting_provider_id: None,
        handshake: HandshakeState::default(),
    });
    let state = Arc::new(ChannelState {
        local: 1,
        remote: AtomicU32::new(2),
        remote_window: Mutex::new(0),
        remote_packet: AtomicU32::new(CHANNEL_PACKET),
        recv: Mutex::new(Recv {
            chunks: VecDeque::new(),
            eof: false,
            closed: false,
            pending_adjust: 0,
            local_window: u64::from(DEFAULT_CHANNEL_WINDOW),
        }),
        cond: Condvar::new(),
        window_cond: Condvar::new(),
        open: Mutex::new(None),
        pool,
    });
    {
        let mut recv = lock(&state.recv);
        for payload in payloads {
            let mut buffer = vec![0u8; PACKET_CHUNK];
            buffer[8..8 + payload.len()].copy_from_slice(payload);
            recv.chunks.push_back(Chunk {
                buffer,
                start: 8,
                end: 8 + payload.len(),
            });
        }
        recv.eof = true;
    }
    Channel {
        session: inner,
        state,
        deadline: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn the_window_adjust_never_exceeds_half_the_configured_window() {
        assert_eq!(window_adjust_at(DEFAULT_CHANNEL_WINDOW), WINDOW_ADJUST_AT);
        assert_eq!(window_adjust_at(64 * 1024), 32 * 1024);
        assert_eq!(window_adjust_at(128 * 1024), 64 * 1024);
    }

    #[test]
    fn rc4_matches_the_known_vector() {
        let mut rc4 = Rc4::new(b"Key");
        let mut data = *b"Plaintext";
        rc4.apply(&mut data);
        assert_eq!(&data, b"\xBB\xF3\x16\xE8\xD9\x40\xAF\x0A\xD3");
    }

    /// Twelve vectors, block-aligned and remainder lengths, each checked against a standing-bytewise
    /// re-derivation so the split keystream/crypt halves cannot drift the stream.
    #[test]
    fn rc4_apply_matches_the_stream_across_every_length() {
        const LENS: [usize; 12] = [0, 1, 7, 8, 15, 16, 17, 31, 32, 33, 257, 4096];
        for key in [b"Key".as_slice(), b"Wiki".as_slice(), b"Secret".as_slice()] {
            for len in LENS {
                let plain = (0..len)
                    .map(|at| u8::try_from(at.wrapping_mul(37).wrapping_add(11)).unwrap_or(0))
                    .collect::<Vec<u8>>();
                // Reference: standing bytewise stream, drawn in one segment.
                let mut reference = Rc4::new(key);
                let mut expect = plain.clone();
                for byte in &mut expect {
                    reference.i = reference.i.wrapping_add(1);
                    reference.j = reference
                        .j
                        .wrapping_add(reference.s[usize::from(reference.i)]);
                    reference
                        .s
                        .swap(usize::from(reference.i), usize::from(reference.j));
                    let k = reference.s[usize::from(reference.i)]
                        .wrapping_add(reference.s[usize::from(reference.j)]);
                    *byte ^= reference.s[usize::from(k)];
                }
                // Production: block keystream folded over the payload.
                let mut rc4 = Rc4::new(key);
                let mut data = plain.clone();
                rc4.apply(&mut data);
                assert_eq!(data, expect, "key {key:?} len {len}");
                // Continuity: two shorter calls equal one long call on a fresh stream.
                let mut split = Rc4::new(key);
                let mut first = plain[..len / 2].to_vec();
                let mut second = plain[len / 2..].to_vec();
                split.apply(&mut first);
                split.apply(&mut second);
                let mut joined = first;
                joined.extend_from_slice(&second);
                assert_eq!(joined, expect, "split key {key:?} len {len}");
            }
        }
    }

    #[test]
    fn obfuscation_key_is_sha1_repeated_then_truncated() {
        let key = derive_key(&[0u8; 16], b"key", b"client_to_server");
        assert_eq!(
            key,
            [
                0x6f, 0xf2, 0x58, 0x8d, 0x20, 0x4c, 0x2a, 0x36, 0x59, 0x69, 0x29, 0x53, 0x23, 0x6a,
                0xdc, 0x4f
            ]
        );
    }

    #[test]
    fn a_packet_length_is_a_block_multiple_with_four_bytes_of_padding() {
        for block in [8usize, 16] {
            for payload in 0..=96 {
                let padding = padding_len(payload, block);
                assert!(padding >= 4, "block {block}, payload {payload}");
                assert_eq!((4 + 1 + payload + padding) % block, 0);
            }
        }
    }

    #[test]
    fn in_place_channel_data_round_trips_under_the_cipher_and_mac() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let peer = TcpStream::connect(listener.local_addr().expect("address")).expect("peer");
        let (socket, _) = listener.accept().expect("accept");
        let key = [7u8; 16];
        let iv = [9u8; 16];
        let mac = [3u8; 32];
        let mut writer = PacketWriter::new(socket, None, None, None);
        writer.activate(key, iv, mac);
        let pool = Arc::new(Mutex::new(Vec::new()));
        let mut reader = PacketReader::new(peer, None, None, None, pool);
        reader.activate(key, iv, mac);
        let mut data = *b"payload";
        writer
            .send_channel_data_in_place(42, &mut data)
            .expect("send");
        let packet = reader.recv().expect("packet");
        assert_eq!(packet.kind(), Some(MSG_CHANNEL_DATA));
        let body = packet.body();
        assert_eq!(&body[0..4], &42u32.to_be_bytes());
        assert_eq!(&body[8..], b"payload");
    }

    #[test]
    fn a_kex_packet_need_not_be_a_block_multiple() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let mut peer = TcpStream::connect(listener.local_addr().expect("address")).expect("peer");
        let (socket, _) = listener.accept().expect("accept");
        // The reference pads a plaintext KEX packet to a random length: total 11, not a multiple of 8.
        let mut wire = Vec::new();
        wire.extend_from_slice(&7u32.to_be_bytes());
        wire.push(4);
        wire.extend_from_slice(&[MSG_IGNORE, MSG_IGNORE]);
        wire.extend_from_slice(&[0u8; 4]);
        peer.write_all(&wire).expect("write");
        let pool = Arc::new(Mutex::new(Vec::new()));
        let mut reader = PacketReader::new(socket, None, None, None, pool);
        let packet = reader.recv().expect("packet");
        assert_eq!(packet.kind(), Some(MSG_IGNORE));
        assert_eq!(packet.body().len(), 1);
    }

    #[test]
    fn a_banner_read_keeps_the_packet_that_shared_its_syscall() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let mut peer = TcpStream::connect(listener.local_addr().expect("address")).expect("peer");
        let (socket, _) = listener.accept().expect("accept");
        let mut wire = Vec::new();
        wire.extend_from_slice(b"notice\r\nSSH-2.0-test\r\n");
        wire.extend_from_slice(&6u32.to_be_bytes());
        wire.push(4);
        wire.push(MSG_IGNORE);
        wire.extend_from_slice(&[0u8; 4]);
        peer.write_all(&wire).expect("write");
        let pool = Arc::new(Mutex::new(Vec::new()));
        let mut reader = PacketReader::new(socket, None, None, None, pool);
        let mut banner = Vec::new();
        assert_eq!(
            read_identification(&mut reader, &mut banner).expect("banner"),
            b"SSH-2.0-test"
        );
        let packet = reader.recv().expect("packet");
        assert_eq!(packet.kind(), Some(MSG_IGNORE));
    }

    #[test]
    fn an_obfuscated_banner_keeps_the_packet_keystream_in_step() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let mut peer = TcpStream::connect(listener.local_addr().expect("address")).expect("peer");
        let (socket, _) = listener.accept().expect("accept");
        let mut wire = Vec::new();
        wire.extend_from_slice(b"notice\r\nSSH-2.0-test\r\n");
        wire.extend_from_slice(&6u32.to_be_bytes());
        wire.push(4);
        wire.push(MSG_IGNORE);
        wire.extend_from_slice(&[0u8; 4]);
        let key = b"banner-key";
        Rc4::new(key).apply(&mut wire);
        peer.write_all(&wire).expect("write");
        let pool = Arc::new(Mutex::new(Vec::new()));
        let mut reader = PacketReader::new(socket, Some(Rc4::new(key)), None, None, pool);
        let mut banner = Vec::new();
        assert_eq!(
            read_identification(&mut reader, &mut banner).expect("banner"),
            b"SSH-2.0-test"
        );
        let packet = reader.recv().expect("packet");
        assert_eq!(packet.kind(), Some(MSG_IGNORE));
    }

    #[test]
    fn name_lists_keep_empty_members() {
        let mut out = Vec::new();
        put_name_list(&mut out, b"a,b");
        assert_eq!(out, [0, 0, 0, 3, b'a', b',', b'b']);
    }

    #[test]
    fn hmac_matches_the_known_vector() {
        let mac = HmacKey::new(&[0x0b; 20]);
        assert_eq!(
            mac.mac(b"Hi There"),
            [
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
                0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
                0x2e, 0x32, 0xcf, 0xf7
            ]
        );
    }

    #[test]
    fn password_json_escapes_every_field() {
        assert_eq!(json_escape("a\"b\\c\n"), "a\\\"b\\\\c\\n");
    }

    #[test]
    fn mpint_trims_and_signs() {
        assert_eq!(mpint(&[0, 0, 1]), [1]);
        assert_eq!(mpint(&[0x80]), [0, 0x80]);
        assert_eq!(mpint(&[0, 0]), Vec::<u8>::new());
    }

    #[test]
    fn rsa_der_is_a_sequence_of_two_integers() {
        let der = rsa_der(&[1, 0, 1], &[3]);
        assert_eq!(der[0], 0x30);
        assert_eq!(&der[2..], [0x02, 3, 1, 0, 1, 0x02, 1, 3]);
    }

    #[test]
    fn a_channel_write_respects_the_remote_packet() {
        assert_eq!(u64::from(CHANNEL_PACKET), 32 * 1024);
    }

    #[test]
    fn a_packet_tunnel_window_uses_its_own_default_and_range() {
        for count in [None, Some(0), Some(129)] {
            assert_eq!(packet_tunnel_channel_window(count), 16 * CHANNEL_PACKET);
        }
        for count in [1, 128] {
            assert_eq!(
                packet_tunnel_channel_window(Some(count)),
                count as u32 * CHANNEL_PACKET
            );
        }
    }

    #[test]
    fn padding_entropy_is_drawn_a_page_at_a_time() {
        let mut entropy = Entropy::new();
        let mut byte = [0u8; 16];
        for _ in 0..100 {
            entropy.fill(&mut byte).expect("entropy");
        }
        assert_eq!(
            entropy.at, 1600,
            "one refill fed forty packets short of a page"
        );
    }

    #[test]
    fn a_returned_packet_buffer_is_the_same_allocation() {
        let pool = Mutex::new(Vec::new());
        let buffer = vec![0u8; PACKET_CHUNK];
        let pointer = buffer.as_ptr();
        let capacity = buffer.capacity();
        recycle(&pool, buffer);
        let buffer = lock(&pool).pop().expect("the pool kept the buffer");
        assert_eq!(buffer.as_ptr(), pointer);
        assert_eq!(buffer.capacity(), capacity);
    }

    #[test]
    fn the_packet_pool_stops_at_its_ceiling() {
        let pool = Mutex::new(Vec::new());
        for _ in 0..PACKET_POOL + 8 {
            recycle(&pool, vec![0u8; PACKET_CHUNK]);
        }
        assert_eq!(lock(&pool).len(), PACKET_POOL);
    }

    #[test]
    fn a_channel_read_hands_its_packet_buffer_back_to_the_pool() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let peer = TcpStream::connect(listener.local_addr().expect("address")).expect("peer");
        let (_local, _) = listener.accept().expect("accept");
        let pool = Arc::new(Mutex::new(Vec::new()));
        let inner = Arc::new(Inner {
            writer: Mutex::new(PacketWriter::new(
                peer.try_clone().expect("clone"),
                None,
                None,
                None,
            )),
            channels: Mutex::new(HashMap::new()),
            pool: Arc::clone(&pool),
            channel_window: DEFAULT_CHANNEL_WINDOW,
            next_channel: AtomicU32::new(1),
            closed: AtomicBool::new(false),
            closed_at: AtomicU64::new(u64::MAX),
            socket: Stream::Tcp(peer),
            relay: Mutex::new(None),
            opened_at: Instant::now(),
            last_read: AtomicU64::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            burst: Mutex::new(crate::psiphon_burst::Burst::default()),
            burst_enabled: false,
            pending_request: Mutex::new(None),
            pending_api: Mutex::new(None),
            api_timed_out: AtomicBool::new(false),
            request_lock: Mutex::new(()),
            requests: None,
            server: "test".to_owned(),
            protocol: "SSH",
            provider_id: None,
            region: None,
            fronting_provider_id: None,
            handshake: HandshakeState::default(),
        });
        let state = Arc::new(ChannelState {
            local: 1,
            remote: AtomicU32::new(2),
            remote_window: Mutex::new(0),
            remote_packet: AtomicU32::new(CHANNEL_PACKET),
            recv: Mutex::new(Recv {
                chunks: VecDeque::new(),
                eof: false,
                closed: false,
                pending_adjust: 0,
                local_window: u64::from(DEFAULT_CHANNEL_WINDOW),
            }),
            cond: Condvar::new(),
            window_cond: Condvar::new(),
            open: Mutex::new(None),
            pool: Arc::clone(&pool),
        });
        let mut channel = Channel {
            session: Arc::clone(&inner),
            state: Arc::clone(&state),
            deadline: None,
        };
        let mut buffer = vec![0u8; PACKET_CHUNK];
        let pointer = buffer.as_ptr();
        buffer[8..13].copy_from_slice(b"hello");
        lock(&state.recv).chunks.push_back(Chunk {
            buffer,
            start: 8,
            end: 13,
        });
        let mut out = [0u8; 16];
        assert_eq!(channel.read(&mut out).expect("read"), 5);
        assert_eq!(&out[..5], b"hello");
        let buffer = lock(&pool).pop().expect("the packet buffer came back");
        assert_eq!(buffer.as_ptr(), pointer);
    }

    #[test]
    fn next_batch_drains_and_recycles() {
        let payloads: Vec<&[u8]> = (0..40).map(|_| &b"x"[..]).collect();
        let mut channel = test_channel_with_chunks(&payloads);
        let pool = Arc::clone(&channel.session.pool);
        let mut batch = Vec::new();
        assert!(channel.next_batch(&mut batch, 32).expect("batch"));
        assert_eq!(batch.len(), 32);
        channel.recycle_chunks(batch.drain(..));
        assert_eq!(lock(&pool).len(), 32);
        assert!(channel.next_batch(&mut batch, 32).expect("rest"));
        assert_eq!(batch.len(), 8);
        channel.recycle_chunks(batch.drain(..));
        assert_eq!(lock(&pool).len(), 40);
        assert!(!channel.next_batch(&mut batch, 32).expect("eof"));
    }

    #[test]
    fn a_channel_chunk_is_the_packet_allocation() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let peer = TcpStream::connect(listener.local_addr().expect("address")).expect("peer");
        let (_local, _) = listener.accept().expect("accept");
        let pool = Arc::new(Mutex::new(Vec::new()));
        let inner = Arc::new(Inner {
            writer: Mutex::new(PacketWriter::new(
                peer.try_clone().expect("clone"),
                None,
                None,
                None,
            )),
            channels: Mutex::new(HashMap::new()),
            pool: Arc::clone(&pool),
            channel_window: DEFAULT_CHANNEL_WINDOW,
            next_channel: AtomicU32::new(1),
            closed: AtomicBool::new(false),
            closed_at: AtomicU64::new(u64::MAX),
            socket: Stream::Tcp(peer),
            relay: Mutex::new(None),
            opened_at: Instant::now(),
            last_read: AtomicU64::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            burst: Mutex::new(crate::psiphon_burst::Burst::default()),
            burst_enabled: false,
            pending_request: Mutex::new(None),
            pending_api: Mutex::new(None),
            api_timed_out: AtomicBool::new(false),
            request_lock: Mutex::new(()),
            requests: None,
            server: "test".to_owned(),
            protocol: "SSH",
            provider_id: None,
            region: None,
            fronting_provider_id: None,
            handshake: HandshakeState::default(),
        });
        let state = Arc::new(ChannelState {
            local: 1,
            remote: AtomicU32::new(2),
            remote_window: Mutex::new(0),
            remote_packet: AtomicU32::new(CHANNEL_PACKET),
            recv: Mutex::new(Recv {
                chunks: VecDeque::new(),
                eof: false,
                closed: false,
                pending_adjust: 0,
                local_window: u64::from(DEFAULT_CHANNEL_WINDOW),
            }),
            cond: Condvar::new(),
            window_cond: Condvar::new(),
            open: Mutex::new(None),
            pool: Arc::clone(&pool),
        });
        let mut channel = Channel {
            session: Arc::clone(&inner),
            state: Arc::clone(&state),
            deadline: None,
        };
        let mut buffer = vec![0u8; PACKET_CHUNK];
        let pointer = buffer.as_ptr();
        let capacity = buffer.capacity();
        buffer[8..13].copy_from_slice(b"hello");
        lock(&state.recv).chunks.push_back(Chunk {
            buffer,
            start: 8,
            end: 13,
        });
        let chunk = channel.next_chunk().expect("chunk").expect("payload");
        assert_eq!(chunk.data(), b"hello");
        assert_eq!(chunk.data().as_ptr(), pointer.wrapping_add(8));
        channel.recycle_chunks(std::iter::once(chunk));
        let buffer = lock(&pool).pop().expect("the packet buffer came back");
        assert_eq!(buffer.as_ptr(), pointer);
        assert_eq!(buffer.capacity(), capacity);
    }

    #[test]
    fn a_server_message_names_this_side_s_channel() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let peer = TcpStream::connect(listener.local_addr().expect("address")).expect("peer");
        let (_local, _) = listener.accept().expect("accept");
        let pool = Arc::new(Mutex::new(Vec::new()));
        let inner = Arc::new(Inner {
            writer: Mutex::new(PacketWriter::new(
                peer.try_clone().expect("clone"),
                None,
                None,
                None,
            )),
            channels: Mutex::new(HashMap::new()),
            pool: Arc::clone(&pool),
            channel_window: DEFAULT_CHANNEL_WINDOW,
            next_channel: AtomicU32::new(2),
            closed: AtomicBool::new(false),
            closed_at: AtomicU64::new(u64::MAX),
            socket: Stream::Tcp(peer),
            relay: Mutex::new(None),
            opened_at: Instant::now(),
            last_read: AtomicU64::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            burst: Mutex::new(crate::psiphon_burst::Burst::default()),
            burst_enabled: false,
            pending_request: Mutex::new(None),
            pending_api: Mutex::new(None),
            api_timed_out: AtomicBool::new(false),
            request_lock: Mutex::new(()),
            requests: None,
            server: "test".to_owned(),
            protocol: "SSH",
            provider_id: None,
            region: None,
            fronting_provider_id: None,
            handshake: HandshakeState::default(),
        });
        let (tx, rx) = mpsc::channel();
        let state = Arc::new(ChannelState {
            local: 1,
            remote: AtomicU32::new(NO_CHANNEL),
            remote_window: Mutex::new(0),
            remote_packet: AtomicU32::new(CHANNEL_PACKET),
            recv: Mutex::new(Recv {
                chunks: VecDeque::new(),
                eof: false,
                closed: false,
                pending_adjust: 0,
                local_window: u64::from(DEFAULT_CHANNEL_WINDOW),
            }),
            cond: Condvar::new(),
            window_cond: Condvar::new(),
            open: Mutex::new(Some(tx)),
            pool: Arc::clone(&pool),
        });
        lock(&inner.channels).insert(1, Arc::clone(&state));

        let mut confirm = vec![MSG_CHANNEL_OPEN_CONFIRMATION];
        put_u32(&mut confirm, 1);
        put_u32(&mut confirm, 2);
        put_u32(&mut confirm, DEFAULT_CHANNEL_WINDOW);
        put_u32(&mut confirm, CHANNEL_PACKET);
        let end = confirm.len();
        assert!(matches!(
            dispatch(
                &inner,
                Packet {
                    buffer: confirm,
                    start: 0,
                    end
                }
            ),
            Dispatch::Recycle(_)
        ));
        assert_eq!(state.remote.load(Ordering::Acquire), 2);
        assert!(rx.recv_timeout(Duration::from_secs(1)).is_ok());

        let mut data = vec![MSG_CHANNEL_DATA];
        put_u32(&mut data, 1);
        put_str(&mut data, b"hi");
        let end = data.len();
        assert!(matches!(
            dispatch(
                &inner,
                Packet {
                    buffer: data,
                    start: 0,
                    end
                }
            ),
            Dispatch::Queued
        ));
        let mut channel = Channel {
            session: Arc::clone(&inner),
            state,
            deadline: None,
        };
        let mut out = [0u8; 2];
        channel.read_exact(&mut out).expect("read");
        assert_eq!(&out, b"hi");
    }

    #[test]
    fn a_server_close_keeps_the_data_it_already_sent() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let peer = TcpStream::connect(listener.local_addr().expect("address")).expect("peer");
        let (_local, _) = listener.accept().expect("accept");
        let pool = Arc::new(Mutex::new(Vec::new()));
        let inner = Arc::new(Inner {
            writer: Mutex::new(PacketWriter::new(
                peer.try_clone().expect("clone"),
                None,
                None,
                None,
            )),
            channels: Mutex::new(HashMap::new()),
            pool: Arc::clone(&pool),
            channel_window: DEFAULT_CHANNEL_WINDOW,
            next_channel: AtomicU32::new(2),
            closed: AtomicBool::new(false),
            closed_at: AtomicU64::new(u64::MAX),
            socket: Stream::Tcp(peer),
            relay: Mutex::new(None),
            opened_at: Instant::now(),
            last_read: AtomicU64::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            burst: Mutex::new(crate::psiphon_burst::Burst::default()),
            burst_enabled: false,
            pending_request: Mutex::new(None),
            pending_api: Mutex::new(None),
            api_timed_out: AtomicBool::new(false),
            request_lock: Mutex::new(()),
            requests: None,
            server: "test".to_owned(),
            protocol: "SSH",
            provider_id: None,
            region: None,
            fronting_provider_id: None,
            handshake: HandshakeState::default(),
        });
        let state = Arc::new(ChannelState {
            local: 1,
            remote: AtomicU32::new(2),
            remote_window: Mutex::new(0),
            remote_packet: AtomicU32::new(CHANNEL_PACKET),
            recv: Mutex::new(Recv {
                chunks: VecDeque::new(),
                eof: false,
                closed: false,
                pending_adjust: 0,
                local_window: u64::from(DEFAULT_CHANNEL_WINDOW),
            }),
            cond: Condvar::new(),
            window_cond: Condvar::new(),
            open: Mutex::new(None),
            pool: Arc::clone(&pool),
        });
        lock(&inner.channels).insert(1, Arc::clone(&state));

        let mut data = vec![MSG_CHANNEL_DATA];
        put_u32(&mut data, 1);
        put_str(&mut data, b"hi");
        let end = data.len();
        assert!(matches!(
            dispatch(
                &inner,
                Packet {
                    buffer: data,
                    start: 0,
                    end
                }
            ),
            Dispatch::Queued
        ));
        let mut close = vec![MSG_CHANNEL_CLOSE];
        put_u32(&mut close, 1);
        let end = close.len();
        assert!(matches!(
            dispatch(
                &inner,
                Packet {
                    buffer: close,
                    start: 0,
                    end
                }
            ),
            Dispatch::Recycle(_)
        ));

        let mut channel = Channel {
            session: Arc::clone(&inner),
            state,
            deadline: None,
        };
        let mut out = [0u8; 2];
        channel.read_exact(&mut out).expect("read the queued bytes");
        assert_eq!(&out, b"hi");
        assert_eq!(channel.read(&mut out).expect("eof"), 0);
        assert!(channel.write(b"late").is_err());
    }

    #[test]
    fn a_post_handshake_kexinit_reconnects_instead_of_stalling() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let peer = TcpStream::connect(listener.local_addr().expect("address")).expect("peer");
        let (_local, _) = listener.accept().expect("accept");
        let inner = Arc::new(Inner {
            writer: Mutex::new(PacketWriter::new(
                peer.try_clone().expect("clone"),
                None,
                None,
                None,
            )),
            channels: Mutex::new(HashMap::new()),
            pool: Arc::new(Mutex::new(Vec::new())),
            channel_window: DEFAULT_CHANNEL_WINDOW,
            next_channel: AtomicU32::new(1),
            closed: AtomicBool::new(false),
            closed_at: AtomicU64::new(u64::MAX),
            socket: Stream::Tcp(peer),
            relay: Mutex::new(None),
            opened_at: Instant::now(),
            last_read: AtomicU64::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            burst: Mutex::new(crate::psiphon_burst::Burst::default()),
            burst_enabled: false,
            pending_request: Mutex::new(None),
            pending_api: Mutex::new(None),
            api_timed_out: AtomicBool::new(false),
            request_lock: Mutex::new(()),
            requests: None,
            server: "test".to_owned(),
            protocol: "SSH",
            provider_id: None,
            region: None,
            fronting_provider_id: None,
            handshake: HandshakeState::default(),
        });
        assert!(matches!(
            dispatch(
                &inner,
                Packet {
                    buffer: vec![MSG_KEXINIT],
                    start: 0,
                    end: 1
                }
            ),
            Dispatch::Stop
        ));
    }

    #[test]
    fn a_closed_channel_sends_no_data_after_its_close() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let peer = TcpStream::connect(listener.local_addr().expect("address")).expect("peer");
        let (mut wire, _) = listener.accept().expect("accept");
        wire.set_read_timeout(Some(Duration::from_millis(200)))
            .expect("timeout");
        let pool = Arc::new(Mutex::new(Vec::new()));
        let inner = Arc::new(Inner {
            writer: Mutex::new(PacketWriter::new(
                peer.try_clone().expect("clone"),
                None,
                None,
                None,
            )),
            channels: Mutex::new(HashMap::new()),
            pool: Arc::clone(&pool),
            channel_window: DEFAULT_CHANNEL_WINDOW,
            next_channel: AtomicU32::new(2),
            closed: AtomicBool::new(false),
            closed_at: AtomicU64::new(u64::MAX),
            socket: Stream::Tcp(peer),
            relay: Mutex::new(None),
            opened_at: Instant::now(),
            last_read: AtomicU64::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            burst: Mutex::new(crate::psiphon_burst::Burst::default()),
            burst_enabled: false,
            pending_request: Mutex::new(None),
            pending_api: Mutex::new(None),
            api_timed_out: AtomicBool::new(false),
            request_lock: Mutex::new(()),
            requests: None,
            server: "test".to_owned(),
            protocol: "SSH",
            provider_id: None,
            region: None,
            fronting_provider_id: None,
            handshake: HandshakeState::default(),
        });
        let state = Arc::new(ChannelState {
            local: 1,
            remote: AtomicU32::new(2),
            remote_window: Mutex::new(u64::from(DEFAULT_CHANNEL_WINDOW)),
            remote_packet: AtomicU32::new(CHANNEL_PACKET),
            recv: Mutex::new(Recv {
                chunks: VecDeque::new(),
                eof: false,
                closed: false,
                pending_adjust: 0,
                local_window: u64::from(DEFAULT_CHANNEL_WINDOW),
            }),
            cond: Condvar::new(),
            window_cond: Condvar::new(),
            open: Mutex::new(None),
            pool: Arc::clone(&pool),
        });
        lock(&inner.channels).insert(1, Arc::clone(&state));
        let mut channel = Channel {
            session: Arc::clone(&inner),
            state,
            deadline: None,
        };
        channel.close();
        let mut head = [0u8; 4];
        wire.read_exact(&mut head).expect("packet length");
        let mut packet = vec![0u8; usize::try_from(u32::from_be_bytes(head)).expect("length")];
        wire.read_exact(&mut packet).expect("packet");
        assert_eq!(packet[1], MSG_CHANNEL_CLOSE);
        assert_eq!(
            u32::from_be_bytes([packet[2], packet[3], packet[4], packet[5]]),
            2
        );
        // The ended channel refuses a write and nothing follows the close on the wire.
        assert!(channel.write(b"late").is_err());
        let mut extra = [0u8; 8];
        match wire.read(&mut extra) {
            Ok(0) => {}
            Ok(read) => panic!("{read} bytes followed the close"),
            Err(error) => assert!(
                matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ),
                "{error}"
            ),
        }
    }

    #[test]
    fn a_cdn_tunnel_protocol_hands_its_base_name() {
        assert_eq!(
            tunnel_protocol_base("FRONTED-MEEK-CDN-OSSH"),
            "FRONTED-MEEK-OSSH"
        );
        assert_eq!(
            tunnel_protocol_base("FRONTED-MEEK-CDN-HTTP-OSSH"),
            "FRONTED-MEEK-HTTP-OSSH"
        );
        assert_eq!(
            tunnel_protocol_base("FRONTED-MEEK-CDN-QUIC-OSSH"),
            "FRONTED-MEEK-QUIC-OSSH"
        );
        assert_eq!(
            tunnel_protocol_base("UNFRONTED-MEEK-HTTPS-OSSH"),
            "UNFRONTED-MEEK-HTTPS-OSSH"
        );
    }

    #[test]
    fn the_cbor_handshake_uses_reference_keys_and_types() {
        let authorization = ferrox_core::b64::encode(
            br#"{"Authorization":{"ID":"AQID","AccessType":"test","Expires":"2030-01-02T03:04:05.123456789Z"},"SigningKeyID":"BAUG","Signature":"BwgJ"}"#,
        );
        let authorizations = [authorization];
        let features = vec!["coarse-location".to_owned()];
        let identity = Identity {
            session_id: "session",
            authorizations: &authorizations,
            sponsor: "07D1ACD69B3AC7A2",
            propagation: "EE0B7486ACAE75AA",
            platform: "Android",
            version: "453",
            egress_region: Some("IR"),
            device_region: Some("IR"),
            device_location: Some("w3g"),
            client_features: &features,
            split_tunnel: true,
            split_tunnel_regions: &["US".to_owned()],
            api_encoding: ApiEncoding::Cbor,
            compress_tactics: true,
            disable_api: false,
            ssh_algorithms: None,
        };
        let payload = packed_handshake_body("SSH", &identity, None).expect("packed handshake");
        assert_eq!(&payload[..2], &[0, 1]);
        let (value, used) = crate::psiphon_broker::decode(&payload[2..]).expect("cbor map");
        assert_eq!(used, payload.len() - 2);
        assert_eq!(value.get(5), None);
        assert_eq!(value.get(8), Some(&crate::psiphon_broker::Value::UInt(453)));
        assert_eq!(
            value.get(15),
            Some(&crate::psiphon_broker::Value::Text("SSH".to_owned()))
        );
        assert_eq!(
            value.get(43),
            Some(&crate::psiphon_broker::Value::Text("IR".to_owned()))
        );
        assert_eq!(
            value.get(63),
            Some(&crate::psiphon_broker::Value::Text("1".to_owned()))
        );
        assert_eq!(value.get(168), Some(&crate::psiphon_broker::Value::UInt(1)));
        let packed = match value.get(1) {
            Some(crate::psiphon_broker::Value::Bytes(bytes)) => bytes,
            other => panic!("authorizations: {other:?}"),
        };
        let (auths, used) = crate::psiphon_broker::decode(packed).expect("authorization array");
        assert_eq!(used, packed.len());
        let crate::psiphon_broker::Value::Array(items) = auths else {
            panic!("authorizations are not an array");
        };
        let Some(crate::psiphon_broker::Value::Map(auth)) = items.first() else {
            panic!("authorization is not a map");
        };
        assert_eq!(
            auth.iter()
                .find(|(key, _)| { key == &crate::psiphon_broker::Value::UInt(3) }),
            Some(&(
                crate::psiphon_broker::Value::UInt(3),
                crate::psiphon_broker::Value::Text("2030-01-02T03:04:05.123456789Z".to_owned())
            ))
        );
    }

    #[test]
    fn a_cbor_handshake_reply_maps_integer_keys() {
        let reply = crate::psiphon_broker::Value::Map(vec![
            (
                crate::psiphon_broker::Value::UInt(1),
                crate::psiphon_broker::Value::Array(vec![crate::psiphon_broker::Value::Text(
                    "https://example.test/".to_owned(),
                )]),
            ),
            (
                crate::psiphon_broker::Value::UInt(6),
                crate::psiphon_broker::Value::Text("IR".to_owned()),
            ),
            (
                crate::psiphon_broker::Value::UInt(7),
                crate::psiphon_broker::Value::Text("192.0.2.1".to_owned()),
            ),
        ]);
        let state = parse_handshake(&crate::psiphon_broker::encode(&reply));
        assert_eq!(state.homepages, vec!["https://example.test/".to_owned()]);
        assert_eq!(state.client_region.as_deref(), Some("IR"));
        assert_eq!(state.client_address.as_deref(), Some("192.0.2.1"));
    }

    #[test]
    fn the_handshake_carries_device_identity() {
        let features = vec!["coarse-location".to_owned(), "unsafe\"feature".to_owned()];
        let identity = Identity {
            session_id: "session",
            authorizations: &[],
            sponsor: "sponsor",
            propagation: "propagation",
            platform: "Android",
            version: "453",
            egress_region: Some("IR"),
            device_region: Some("IR"),
            device_location: Some("w3g"),
            client_features: &features,
            split_tunnel: true,
            split_tunnel_regions: &["US".to_owned(), "DE".to_owned()],
            api_encoding: ApiEncoding::Json,
            compress_tactics: false,
            disable_api: false,
            ssh_algorithms: None,
        };
        assert_eq!(
            handshake_body("UNFRONTED-MEEK-HTTPS-OSSH", &identity, None),
            r#"{"propagation_channel_id":"propagation","sponsor_id":"sponsor","client_version":"453","client_platform":"Android","relay_protocol":"UNFRONTED-MEEK-HTTPS-OSSH","egress_region":"IR","device_region":"IR","device_location":"w3g","split_tunnel":"1","split_tunnel_regions":["US","DE"],"client_features":["coarse-location","unsafe\"feature"]}"#
        );
    }

    #[test]
    fn the_handshake_omits_absent_device_identity() {
        let identity = Identity {
            session_id: "session",
            authorizations: &[],
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
            api_encoding: ApiEncoding::Json,
            compress_tactics: false,
            disable_api: false,
            ssh_algorithms: None,
        };
        assert_eq!(
            handshake_body("SSH", &identity, None),
            r#"{"propagation_channel_id":"propagation","sponsor_id":"sponsor","client_version":"453","client_platform":"Android","relay_protocol":"SSH"}"#
        );
    }

    #[test]
    fn a_hostname_regex_generates_the_shape_it_names() {
        let name = random_hostname(r"[a-z0-9]{5,10}\.example\.org").expect("host name");
        let label = name.strip_suffix(".example.org").expect("suffix");
        assert!((5..=10).contains(&label.len()), "{name}");
        assert!(label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()));
        assert!(random_hostname(r"(a|b)+").is_none());
    }

    /// A provider that disables every named hello gets the reference's unshaped fallback, not the one it disabled.
    #[test]
    fn a_disabled_profile_falls_back_to_the_stock_hello() {
        let chrome = Fingerprint::default();
        let name = chrome.name().expect("chrome is shaped").to_owned();
        let mut shape = TlsShape {
            disable_fronting_profiles: vec![("fronted".to_owned(), vec![name])],
            ..TlsShape::default()
        };
        assert_eq!(
            Fingerprint::stock(),
            shape.fingerprint(true, Some("fronted"))
        );
        shape.profiles = vec![chrome];
        assert_eq!(
            Fingerprint::stock(),
            shape.fingerprint(true, Some("fronted"))
        );
        assert_eq!(chrome, shape.fingerprint(false, None));
    }

    #[test]
    fn an_obfuscated_ticket_needs_the_coin_a_named_protocol_and_a_hex_key() {
        let key = "11".repeat(32);
        let mut shape = TlsShape {
            obfuscated_ticket_probability: 0.0,
            ..TlsShape::default()
        };
        assert_eq!(shape.obfuscated_ticket("TLS-OSSH", &key).unwrap(), None);
        assert_eq!(shape.obfuscated_ticket("TLS-OSSH", "").unwrap(), None);
        shape.obfuscated_ticket_probability = 1.0;
        assert_eq!(
            shape.obfuscated_ticket("TLS-OSSH", &key).unwrap(),
            Some(ferrox_core::tls::ObfuscatedTicket::new([0x11; 32]))
        );
        assert!(shape.obfuscated_ticket("TLS-OSSH", "zz").is_err());
        assert_eq!(
            shape.obfuscated_ticket("FRONTED-MEEK-OSSH", &key).unwrap(),
            None
        );
        shape.obfuscated_ticket_probability = 0.0;
        assert_eq!(
            shape
                .obfuscated_ticket("INPROXY-WEBRTC-UNFRONTED-MEEK-SESSION-TICKET-OSSH", &key)
                .unwrap(),
            Some(ferrox_core::tls::ObfuscatedTicket::new([0x11; 32]))
        );
    }

    #[test]
    fn a_lane_shape_limits_sni_to_its_protocol_and_range() {
        let shape = TlsShape {
            min_padding: 7,
            max_padding: 9,
            sni_names: vec!["cover.test".to_owned()],
            limit_protocols: vec!["TLS-OSSH".to_owned()],
            ..TlsShape::default()
        };
        assert_eq!(shape.sni("TLS-OSSH", "server.test"), "cover.test");
        assert_eq!(shape.sni("SSH", "server.test"), "server.test");
        for _ in 0..32 {
            assert!((7..=9).contains(&shape.padding().expect("padding")));
        }
    }

    #[test]
    fn an_upstream_proxy_url_names_its_scheme_and_credentials() {
        let proxy = Proxy::parse(
            "http://user:p%40ss@127.0.0.1:8080",
            &crate::psiphon_dns::Config::from_servers(&[]),
        )
        .expect("proxy");
        assert!(proxy.http);
        assert_eq!(proxy.host, "127.0.0.1");
        assert_eq!(proxy.port, 8080);
        assert_eq!(proxy.user, "user");
        assert_eq!(proxy.pass, "p@ss");
        assert!(Proxy::parse(
            "socks4://127.0.0.1:1",
            &crate::psiphon_dns::Config::from_servers(&[])
        )
        .is_err());
    }

    #[test]
    /// Every drawn period and padding stays inside the configured bounds.
    fn the_keepalive_window_stays_inside_its_bounds() {
        let keepalive = KeepAlive {
            period_min: Duration::from_millis(1),
            period_max: Duration::from_millis(2),
            padding_min: 3,
            padding_max: 5,
            inactive: Duration::from_millis(1),
            timeout: Duration::from_millis(1),
        };
        for _ in 0..1_000 {
            let period = keepalive.period();
            assert!(period >= Duration::from_millis(1));
            assert!(period <= Duration::from_millis(2));
            assert!((3..=5).contains(&keepalive.padding()));
        }
    }

    #[test]
    /// A handshake reply carries the server list, region, tactics and steering IP.
    fn a_handshake_reply_carries_the_server_list_and_steering_ip() {
        let body = br#"{
            "homepages": ["https://example.org/"],
            "upgrade_client_version": "999",
            "encoded_server_list": ["AAAA", "BBBB"],
            "client_region": "US",
            "client_address": "192.0.2.8",
            "server_timestamp": "2026-01-01T00:00:00Z",
            "active_authorization_ids": ["a1"],
            "tactics_payload": {"Tactics": {"x": 1}},
            "steering_ip": "192.0.2.4"
        }"#;
        let state = parse_handshake(body);
        assert_eq!(state.homepages, ["https://example.org/"]);
        assert_eq!(state.upgrade_client_version.as_deref(), Some("999"));
        assert_eq!(state.encoded_server_list, ["AAAA", "BBBB"]);
        assert_eq!(state.client_region.as_deref(), Some("US"));
        assert_eq!(state.client_address.as_deref(), Some("192.0.2.8"));
        assert_eq!(
            state.server_timestamp.as_deref(),
            Some("2026-01-01T00:00:00Z")
        );
        assert_eq!(state.active_authorization_ids, ["a1"]);
        assert!(state.tactics_payload.is_some());
        assert_eq!(state.steering_ip.as_deref(), Some("192.0.2.4"));
        assert_eq!(
            parse_handshake(b"not json").steering_ip,
            None,
            "a malformed reply leaves every field empty"
        );
    }
}

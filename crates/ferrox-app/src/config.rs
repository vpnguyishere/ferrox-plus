use crate::json::Json;
use ferrox_core::transport::EarlyData;
use std::sync::Arc;
use std::time::Duration;

pub(crate) fn inbound_reality_config(
    inbound: &Json,
) -> Option<ferrox_core::tls::RealityServerConfig> {
    let settings = inbound.get("streamSettings")?;
    if settings.get("security").and_then(Json::as_str) != Some("reality") {
        return None;
    }
    let reality = settings.get("realitySettings")?;
    let short_ids: Vec<[u8; 8]> = reality
        .get("shortIds")?
        .as_arr()?
        .iter()
        .filter_map(|item| item.as_str().and_then(short_id))
        .collect();
    if short_ids.is_empty() {
        return None;
    }
    let server_names: Vec<String> = reality
        .get("serverNames")?
        .as_arr()?
        .iter()
        .filter_map(|item| item.as_str())
        .map(str::to_owned)
        .collect();
    if server_names.is_empty() {
        return None;
    }
    Some(ferrox_core::tls::RealityServerConfig {
        private_key: reality.get("privateKey")?.as_str().and_then(key32)?,
        short_ids,
        server_names,
        max_time_skew: reality
            .get("maxTimeDiff")
            .and_then(as_whole)
            .map(Duration::from_millis),
        min_client_ver: reality
            .get("minClientVer")
            .and_then(Json::as_str)
            .and_then(client_ver),
        max_client_ver: reality
            .get("maxClientVer")
            .and_then(Json::as_str)
            .and_then(client_ver),
        limit_fallback_upload: reality.get("limitFallbackUpload").and_then(rate_limit),
        limit_fallback_download: reality.get("limitFallbackDownload").and_then(rate_limit),
        dest: reality
            .get("target")
            .or_else(|| reality.get("dest"))
            .and_then(Json::as_str)
            .filter(|d| !d.is_empty())
            .map(str::to_owned),
        xver: reality
            .get("xver")
            .and_then(as_uint)
            .and_then(|n| u8::try_from(n).ok())
            .unwrap_or(0),
        show: reality.get("show").and_then(Json::as_bool).unwrap_or(false),
    })
}

/// One fallback row: the dial a front's first bytes route to when they fail the vless header.
#[derive(Debug, Clone)]
pub(crate) struct Fallback {
    pub(crate) name: String,
    pub(crate) alpn: String,
    pub(crate) path: String,
    pub(crate) network: FallbackNetwork,
    pub(crate) xver: u8,
}

/// The dial a fallback row names, spelled the way the reference hands it to its dialer: the
/// strings stay as the config wrote them and resolve when the dial fires, so an address a
/// dying resolver cannot answer now still dials when one can.
#[derive(Debug, Clone)]
pub(crate) enum FallbackNetwork {
    Tcp {
        family: u8,
        host: String,
        port: u16,
    },
    Udp {
        family: u8,
        host: String,
        port: u16,
    },
    Unix {
        path: String,
    },
    /// `serve-ws-none` leaves `type` as `serve`, which the reference's dialer refuses on
    /// every attempt; the row is carried and the flow falls after its retry budget.
    NotDialable,
}

/// The decryption string an inbound names, if any.
pub(crate) fn server_decryption_string(inbound: &Json) -> Option<&str> {
    inbound
        .get("settings")
        .and_then(|settings| settings.get("decryption").and_then(Json::as_str))
}

pub(crate) fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        })
}

/// The decryption engine an inbound names, parsed the way the reference's build does.
pub(crate) fn server_decryption(
    inbound: &Json,
) -> Result<Option<std::sync::Arc<ferrox_core::vless_encryption::Server>>, String> {
    let decryption = inbound
        .get("settings")
        .and_then(|settings| settings.get("decryption").and_then(Json::as_str));
    let Some(decryption) = decryption else {
        return Ok(None);
    };
    if decryption.is_empty() {
        return Err(
            r#"VLESS settings: please add/set "decryption":"none" to every settings"#.into(),
        );
    }
    if decryption == "none" {
        return Ok(None);
    }
    let config = ferrox_core::vless_encryption::ServerConfig::parse(decryption)?;
    Ok(Some(ferrox_core::vless_encryption::Server::with_clock(
        config,
        std::sync::Arc::new(unix_seconds),
    )))
}
/// The fallbacks an inbound routes; an empty decryption refuses beside them.
pub(crate) fn server_fallbacks(inbound: &Json) -> Result<Option<Vec<Fallback>>, String> {
    let decryption = inbound
        .get("settings")
        .and_then(|settings| settings.get("decryption").and_then(Json::as_str));
    if let Some(decryption) = decryption {
        if decryption.is_empty() {
            return Err(
                r#"VLESS settings: please add/set "decryption":"none" to every settings"#.into(),
            );
        }
    }
    let rows = inbound
        .get("settings")
        .and_then(|settings| settings.get("fallbacks"))
        .and_then(Json::as_arr);
    let Some(rows) = rows else {
        return Ok(None);
    };
    if rows.is_empty() {
        return Ok(None);
    }
    let mut table = Vec::with_capacity(rows.len());
    for row in rows {
        let dest_text = fallback_dest_text(row.get("dest"));
        let kind = row.get("type").and_then(Json::as_str).unwrap_or("");
        let path = row.get("path").and_then(Json::as_str).unwrap_or("");
        if !path.is_empty() && !path.starts_with('/') {
            return Err(r#"VLESS fallbacks: "path" must be empty or start with "/""#.into());
        }
        let xver = row.get("xver").and_then(Json::as_u32).unwrap_or(0);
        if xver > 2 {
            return Err(
                r#"VLESS fallbacks: invalid PROXY protocol version, "xver" only accepts 0, 1, 2"#
                    .into(),
            );
        }
        let Some(network) = fallback_network(kind, &dest_text) else {
            return Err(r#"VLESS fallbacks: please fill in a valid value for every "dest""#.into());
        };
        table.push(Fallback {
            name: row.get("name").and_then(Json::as_str).unwrap_or("").into(),
            alpn: row.get("alpn").and_then(Json::as_str).unwrap_or("").into(),
            path: path.into(),
            network,
            xver: u8::try_from(xver).expect("the version is two at most"),
        });
    }
    Ok(Some(table))
}

impl Fallback {
    /// The row that owns a flow the front named with `front` and `alpn` and whose first read
    /// `first` holds: the reference's three-map walk, its two inheritance passes, and the scan
    /// for a request path, each in the order it takes them. Every miss refuses the flow, and
    /// the caller of a refused flow relays nothing.
    pub(crate) fn route<'a>(
        table: &'a [Fallback],
        front: &str,
        alpn: &str,
        first: &[u8],
    ) -> Option<&'a Fallback> {
        let mut groups = FallbackGroups::build(table);
        groups.inherit();
        let names = groups.names();
        let front = front.to_ascii_lowercase();
        let alpn = alpn.to_ascii_lowercase();
        let mut picked = front.as_str();
        // More table names than one, or none spelled as `""`: an unmatched front walks the longest name spelled inside it, and any miss walks as `""`.
        if (names.len() > 1 || !names.contains(&""))
            && !front.is_empty()
            && !names.contains(&front.as_str())
        {
            picked = names
                .iter()
                .filter(|name| !name.is_empty() && front.contains(*name))
                .max_by_key(|name| name.len())
                .copied()
                .unwrap_or("");
        }
        // A front no group spells shares the unnamed group, and one without that group is unserved.
        if !names.contains(&picked) {
            picked = "";
        }
        let group = groups.find(picked)?;
        // The alpn reads one map: the front's when the group grew it, `""` when it didn't.
        let ap = if group.alpns.iter().any(|map| map.alpn == alpn) {
            alpn.as_str()
        } else {
            ""
        };
        let cells = &group.alpns.iter().find(|map| map.alpn == ap)?.cells;
        // The scan runs when the group spells more paths than one or no `""` row fills the default; otherwise the `""` cell answers and the probe's bytes stay unread.
        let mut wanted: &[u8] = b"";
        if cells.len() > 1 || !cells.iter().any(|(path, _)| path.is_empty()) {
            let scanned = scanned_path(first);
            if cells.iter().any(|(path, _)| path.as_bytes() == scanned) {
                wanted = scanned;
            }
        }
        cells
            .iter()
            .rev()
            .find(|(path, _)| path.as_bytes() == wanted)
            .map(|(_, row)| *row)
    }
}

/// One name's alpn maps, the shape the reference's `fallbacks[name][alpn]` walks.
struct NamedFallbacks<'a> {
    name: &'a str,
    alpns: Vec<AlpnFallbacks<'a>>,
}

struct AlpnFallbacks<'a> {
    alpn: &'a str,
    cells: Vec<(&'a str, &'a Fallback)>,
}

/// The three maps one config's rows spell before the reference's inheritance passes.
struct FallbackGroups<'a> {
    groups: Vec<NamedFallbacks<'a>>,
}

impl<'a> FallbackGroups<'a> {
    fn build(table: &'a [Fallback]) -> Self {
        let mut groups: Vec<NamedFallbacks<'a>> = Vec::new();
        for row in table {
            let at = if let Some(at) = groups.iter().position(|g| g.name == row.name) {
                at
            } else {
                groups.push(NamedFallbacks {
                    name: row.name.as_str(),
                    alpns: Vec::new(),
                });
                groups.len() - 1
            };
            put_cell(alpn_map(&mut groups[at], row.alpn.as_str()), row);
        }
        Self { groups }
    }

    /// The two passes `New` runs after the insert: the unnamed group's alpn maps reach every
    /// named one, then a group's `""` rows fill its other maps, then the unnamed group's rows
    /// fill the same-alpn map of every named group where a path is missing.
    fn inherit(&mut self) {
        let Some(default) = self.groups.iter().position(|g| g.name.is_empty()) else {
            return;
        };
        let alpns: Vec<&'a str> = self.groups[default]
            .alpns
            .iter()
            .map(|map| map.alpn)
            .collect();
        for (at, group) in self.groups.iter_mut().enumerate() {
            if at == default {
                continue;
            }
            for alpn in &alpns {
                alpn_map(group, alpn);
            }
        }
        for group in &mut self.groups {
            let Some(shared) = group
                .alpns
                .iter()
                .find(|map| map.alpn.is_empty())
                .map(|map| map.cells.clone())
            else {
                continue;
            };
            for map in &mut group.alpns {
                if map.alpn.is_empty() {
                    continue;
                }
                fill(&mut map.cells, &shared);
            }
        }
        let shared: Vec<(&'a str, Vec<(&'a str, &'a Fallback)>)> = self.groups[default]
            .alpns
            .iter()
            .map(|map| (map.alpn, map.cells.clone()))
            .collect();
        for (at, group) in self.groups.iter_mut().enumerate() {
            if at == default {
                continue;
            }
            for (alpn, cells) in &shared {
                fill(alpn_map(group, alpn), cells);
            }
        }
    }

    fn names(&self) -> Vec<&'a str> {
        self.groups.iter().map(|group| group.name).collect()
    }

    fn find(&self, name: &str) -> Option<&NamedFallbacks<'a>> {
        self.groups.iter().find(|group| group.name == name)
    }
}

/// One alpn map in a name group, made on first use the way the reference's nested map insert does.
fn alpn_map<'g, 'a>(
    group: &'g mut NamedFallbacks<'a>,
    alpn: &'a str,
) -> &'g mut Vec<(&'a str, &'a Fallback)> {
    let at = if let Some(at) = group.alpns.iter().position(|map| map.alpn == alpn) {
        at
    } else {
        group.alpns.push(AlpnFallbacks {
            alpn,
            cells: Vec::new(),
        });
        group.alpns.len() - 1
    };
    &mut group.alpns[at].cells
}

/// Every path `shared` spells that `cells` does not, in the reference's map-fill shape.
fn fill<'a>(cells: &mut Vec<(&'a str, &'a Fallback)>, shared: &[(&'a str, &'a Fallback)]) {
    for (path, row) in shared {
        if !cells.iter().any(|(have, _)| have == path) {
            cells.push((path, row));
        }
    }
}

/// One path cell in a name group, spelled last wins, the way the reference's map insert
/// collapses duplicate rows.
fn put_cell<'a>(cells: &mut Vec<(&'a str, &'a Fallback)>, row: &'a Fallback) {
    match cells
        .iter_mut()
        .find(|(path, _)| *path == row.path.as_str())
    {
        Some(cell) => *cell = (row.path.as_str(), row),
        None => cells.push((row.path.as_str(), row)),
    }
}

/// The request path the probe's first bytes spell, over the window the reference looks in:
/// a `/` opened behind byte four and closed by a `?` or a space wins, the CR/LF or the
/// window's edge leaves the path unfound, and an unserved shape reads nothing at all.
fn scanned_path(first: &[u8]) -> &[u8] {
    if first.len() < 18 || first[4] == b'*' {
        return b"";
    }
    for i in 4..=8 {
        if first[i] == b'/' && first[i - 1] == b' ' {
            let mut found: &[u8] = b"";
            for j in i + 1..first.len().min(64) {
                match first[j] {
                    b'\r' | b'\n' => break,
                    b'?' | b' ' => {
                        found = &first[i..j];
                        break;
                    }
                    _ => {}
                }
            }
            return found;
        }
    }
    b""
}

/// A `dest` spells itself either as a string or as a bare port number; the number is the lonely
/// host the reference's dialer lands on `localhost`. A number that is not a port reads empty,
/// the way the reference's two unmarshals leave a `dest` that fits neither.
fn fallback_dest_text(node: Option<&Json>) -> String {
    match node {
        Some(Json::Str(text)) => text.clone(),
        Some(Json::Num(_)) => node
            .and_then(Json::as_port)
            .map(|port| port.to_string())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

/// The network kind a row resolves to, with the reference's own inference for an unnamed one.
fn fallback_network(kind: &str, dest: &str) -> Option<FallbackNetwork> {
    if !kind.is_empty() {
        return fallback_named_network(kind, dest);
    }
    if dest == "serve-ws-none" {
        return Some(FallbackNetwork::NotDialable);
    }
    if dest.starts_with('@') || dest.starts_with('/') {
        return fallback_named_network("unix", &pad_abstract(dest));
    }
    if let Ok(port) = dest.parse::<u16>() {
        return fallback_named_network("tcp", &format!("localhost:{port}"));
    }
    // A `host:port` name; anything the parser leaves behind is a dial the reference also fails.
    fallback_named_network("tcp", dest)
}

/// One spelled network kind with its address, in either the unix or the `host:port` family.
fn fallback_named_network(kind: &str, dest: &str) -> Option<FallbackNetwork> {
    if kind == "unix" {
        return Some(FallbackNetwork::Unix { path: dest.into() });
    }
    let (head, family) = match kind.as_bytes() {
        b"tcp" => (b't', 0),
        b"tcp4" => (b't', 4),
        b"tcp6" => (b't', 6),
        b"udp" => (b'u', 0),
        b"udp4" => (b'u', 4),
        b"udp6" => (b'u', 6),
        _ => return Some(FallbackNetwork::NotDialable),
    };
    let (host, port) = fallback_split_host_port(dest)?;
    Some(match head {
        b'u' => FallbackNetwork::Udp { family, host, port },
        _ => FallbackNetwork::Tcp { family, host, port },
    })
}

/// The `host` and `port` of a fallback address; a bracketed IPv6 literal keeps only its
/// interior, the way the reference's splitter hands its dialer an unbracketed host. A shape
/// the reference's dialer cannot split leaves nothing, which refuses at load time.
fn fallback_split_host_port(dest: &str) -> Option<(String, u16)> {
    let (host, port) = if let Some(close) = dest.rfind(']') {
        let open = dest[..close].find('[')?;
        let port = dest.get(close + 1..)?.strip_prefix(':')?;
        (dest[open + 1..close].to_owned(), port.to_owned())
    } else {
        let (host, port) = dest.rsplit_once(':')?;
        (host.to_owned(), port.to_owned())
    };
    Some((host, port.parse().ok()?))
}

/// The spell the reference reserves for an abstract unix name on its linuxish builds: an
/// `@@`dest is spelled as the kernel's full `sun_path`, zeros and all, one hundred and eight
/// bytes long, so the name the dialer takes behind the `@` matches the listener's own.
fn pad_abstract(dest: &str) -> String {
    if !dest.starts_with("@@") {
        return dest.into();
    }
    if !cfg!(any(target_os = "linux", target_os = "android")) {
        return dest.into();
    }
    let mut full = vec![0u8; 108];
    let body = &dest.as_bytes()[1..];
    let end = body.len().min(full.len());
    full[..end].copy_from_slice(&body[..end]);
    String::from_utf8_lossy(&full).into_owned()
}

fn client_ver(text: &str) -> Option<[u8; 3]> {
    let mut out = [0u8; 3];
    let mut at = 0;
    for part in text.split('.') {
        let value = part.parse::<u8>().ok()?;
        *out.get_mut(at)? = value;
        at += 1;
    }
    (at > 0).then_some(out)
}

fn rate_limit(node: &Json) -> Option<ferrox_core::tls::RateLimit> {
    Some(ferrox_core::tls::RateLimit {
        after_bytes: node.get("afterBytes").and_then(as_uint)?,
        bytes_per_sec: node.get("bytesPerSec").and_then(as_uint)?,
        burst_bytes_per_sec: node.get("burstBytesPerSec").and_then(as_uint)?,
    })
}

fn as_uint(node: &Json) -> Option<u64> {
    if let Json::Num(n) = node {
        if *n >= 0.0 && n.fract() == 0.0 {
            return u64::try_from(*n as i64).ok();
        }
    }
    None
}

/// Xray fills the eight bytes from the front and zero-pads the tail, so `a8` is `a8 00 ...`, never `00 ... a8`. An empty string is the all-zero short id.
fn short_id(hex: &str) -> Option<[u8; 8]> {
    let mut out = [0u8; 8];
    if hex.is_empty() {
        return Some(out);
    }
    if hex.len() > 16 || !hex.len().is_multiple_of(2) {
        return None;
    }
    for (i, pair) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        out[i] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

const B64URL: [u8; 256] = {
    let mut table = [0xff; 256];
    let mut at = 0;
    while at < 26 {
        table[b'A' as usize + at] = at as u8;
        table[b'a' as usize + at] = at as u8 + 26;
        at += 1;
    }
    at = 0;
    while at < 10 {
        table[b'0' as usize + at] = at as u8 + 52;
        at += 1;
    }
    table[b'-' as usize] = 62;
    table[b'_' as usize] = 63;
    table
};

fn key32(text: &str) -> Option<[u8; 32]> {
    let mut word = 0u32;
    let mut bits = 0;
    let mut out = [0u8; 32];
    let mut at = 0;
    for byte in text.bytes() {
        let value = B64URL[byte as usize];
        if value == 0xff {
            return None;
        }
        word = (word << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            *out.get_mut(at)? = (word >> bits) as u8;
            at += 1;
        }
    }
    (at == 32).then_some(out)
}

/// The byte count an unpadded urlsafe-base64 string decodes to: the two characters that leave one byte
/// and the three that leave two, a lone trailing character naming none, and `\r`/`\n` skipped as Go skips them.
fn b64url_len(text: &str) -> Option<usize> {
    let mut symbols = 0usize;
    for byte in text.bytes() {
        if byte == b'\r' || byte == b'\n' {
            continue;
        }
        if B64URL[byte as usize] == 0xff {
            return None;
        }
        symbols += 1;
    }
    match symbols % 4 {
        0 => Some(symbols / 4 * 3),
        2 => Some(symbols / 4 * 3 + 1),
        3 => Some(symbols / 4 * 3 + 2),
        _ => None,
    }
}

/// The ML-DSA-65 field a REALITY side names, checked as the reference's build checks it: the seed must differ
/// from `privateKey` and decode to 32 bytes, the verify key to 1952. The signature itself is not carried yet.
pub(crate) fn reality_mldsa(node: &Json, server: bool) -> Result<bool, String> {
    let Some(reality) = node
        .get("streamSettings")
        .filter(|settings| settings.get("security").and_then(Json::as_str) == Some("reality"))
        .and_then(|settings| settings.get("realitySettings"))
    else {
        return Ok(false);
    };
    let (field, length) = if server {
        ("mldsa65Seed", 32)
    } else {
        ("mldsa65Verify", 1952)
    };
    let text = match reality.get(field) {
        Some(Json::Str(text)) if !text.is_empty() => text,
        Some(Json::Str(_)) | None => return Ok(false),
        Some(_) => return Err(format!(r#""{field}" is not a string"#)),
    };
    if server {
        if let Some(private) = reality.get("privateKey").and_then(Json::as_str) {
            let decode = |value: &str| {
                let unwrapped: String = value
                    .chars()
                    .filter(|ch| !matches!(*ch, '\r' | '\n'))
                    .collect();
                key32(unwrapped.as_str())
            };
            if let Some(private) = decode(private) {
                if Some(private) == decode(text) {
                    return Err(
                        r#""mldsa65Seed" and "privateKey" can not be the same value"#.to_owned(),
                    );
                }
            }
        }
    }
    if b64url_len(text) != Some(length) {
        return Err(format!(
            r#"invalid "{field}": it does not decode to {length} bytes"#
        ));
    }
    eprintln!(
        r#"reality: "{field}" is checked, and the ML-DSA-65 binding it names is not carried"#
    );
    Ok(true)
}

fn as_whole(node: &Json) -> Option<u64> {
    match node {
        Json::Num(n) if *n >= 0.0 && n.fract() == 0.0 => Some(*n as u64),
        _ => None,
    }
}

pub(crate) fn inbound_tls_identity(
    inbound: &Json,
) -> Option<Arc<ferrox_core::tls::TlsServerConfig>> {
    let settings = inbound.get("streamSettings")?;
    if settings.get("security").and_then(Json::as_str) != Some("tls") {
        return None;
    }
    tls_identity_from_settings(settings)
}

/// The certificate list and TLS fields a stream's `streamSettings` names, without the security check: a carrier that owns its TLS (QUIC, hysteria) still serves the same list.
pub(crate) fn tls_identity_from_settings(
    settings: &Json,
) -> Option<Arc<ferrox_core::tls::TlsServerConfig>> {
    let ech = match ech_server_keys(settings) {
        Ok(keys) => keys,
        Err(why) => {
            eprintln!("ech: {why}; the inbound is refused, not served without it");
            return None;
        }
    };
    let certs = tls_cert_entries(settings)?;
    if certs.is_empty() {
        return None;
    }
    let mut identity = ferrox_core::tls::TlsServerConfig {
        certs,
        alpn: Vec::new(),
        min_version: None,
        max_version: None,
        cipher_suites: Vec::new(),
        send_tickets: true,
        reject_unknown_sni: false,
        server_config_cache: std::sync::Arc::default(),
        ech_server_keys: None,
        master_key_log: None,
    };
    let tls = settings.get("tlsSettings");
    identity.alpn = tls_alpn(tls);
    identity.min_version = tls_version(tls, "minVersion");
    identity.max_version = tls_version(tls, "maxVersion");
    identity.cipher_suites = tls_cipher_suites(tls);
    identity.reject_unknown_sni = tls
        .and_then(|tls| tls.get("rejectUnknownSni"))
        .and_then(Json::as_bool)
        .unwrap_or(false);
    identity.ech_server_keys = ech;
    if identity.ech_server_keys.is_some()
        && identity.max_version.is_some_and(|version| version < 0x0304)
    {
        eprintln!(
            "ech: an ECH listener cannot cap its maximum below TLS 1.3; the inbound is refused, not served without it"
        );
        return None;
    }
    identity.master_key_log = tls_master_key_log(tls);
    let identity = Arc::new(identity);
    start_cert_ticker(&identity);
    Some(identity)
}

/// xray's `setupOcspTicker`: a file-backed pair re-reads on its interval until the listener drops it.
fn start_cert_ticker(identity: &Arc<ferrox_core::tls::TlsServerConfig>) {
    let Some(period) = identity.reload_interval() else {
        return;
    };
    let identity = Arc::downgrade(identity);
    std::thread::spawn(move || loop {
        std::thread::sleep(period);
        let Some(identity) = identity.upgrade() else {
            return;
        };
        identity.renew();
    });
}

/// xray's certificate lookup: an absolute path is read as itself; a relative path is
/// resolved under `$XRAY_LOCATION_CERT` / `xray.location.cert`, defaulting to the
/// executable's directory, then under the working directory this tree has always served.
pub(crate) fn read_cert_file(path: &str) -> Option<Vec<u8>> {
    let path = std::path::Path::new(path);
    if path.is_absolute() {
        return std::fs::read(path).ok();
    }
    let location = std::env::var_os("XRAY_LOCATION_CERT")
        .or_else(|| std::env::var_os("xray.location.cert"))
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(std::path::Path::to_path_buf))
        });
    if let Some(bytes) = location.and_then(|dir| std::fs::read(dir.join(path)).ok()) {
        return Some(bytes);
    }
    std::fs::read(path).ok()
}

fn ech_server_keys(settings: &Json) -> Result<Option<Arc<[u8]>>, String> {
    let Some(keys) = settings
        .get("tlsSettings")
        .and_then(|tls| tls.get("echServerKeys"))
    else {
        return Ok(None);
    };
    if matches!(keys, Json::Null)
        || keys.as_arr().is_some_and(<[Json]>::is_empty)
        || keys.as_str() == Some("")
    {
        return Ok(None);
    }
    let Some(text) = keys.as_str() else {
        return Err("echServerKeys is not a string".to_owned());
    };
    ferrox_core::tls::decode_ech_keys(text)
        .map(Arc::from)
        .map(Some)
}

/// Every `certificates` entry xray would serve, in block order: `usage` other than
/// `encipherment` feeds no handshake, an entry with no key or an unparseable pair is skipped
/// the way xray warns and moves on, and a named file that cannot be read refuses the listener.
fn tls_cert_entries(settings: &Json) -> Option<Vec<ferrox_core::tls::CertEntry>> {
    let list = settings.get("tlsSettings")?.get("certificates")?.as_arr()?;
    let mut entries = Vec::with_capacity(list.len());
    for cert in list {
        if cert
            .get("usage")
            .and_then(Json::as_str)
            .is_some_and(|usage| {
                usage.eq_ignore_ascii_case("verify") || usage.eq_ignore_ascii_case("issue")
            })
        {
            continue;
        }
        let named = |field: &str| {
            cert.get(field)
                .and_then(Json::as_str)
                .filter(|path| !path.is_empty())
        };
        let certificate = named("certificateFile");
        let key = named("keyFile");
        let cert_pem = match certificate {
            Some(path) => read_cert_file(path)?,
            None => match inline_pem(cert, "certificate") {
                Some(pem) => pem,
                None => continue,
            },
        };
        let key_pem = match key {
            Some(path) => read_cert_file(path)?,
            None => match inline_pem(cert, "key") {
                Some(pem) => pem,
                None => continue,
            },
        };
        let Some(mut entry) = ferrox_core::tls::parse_pem_entry(&cert_pem, &key_pem).ok() else {
            continue;
        };
        let paths = certificate.zip(key);
        if let Some((certificate, key)) = paths {
            if !cert
                .get("oneTimeLoading")
                .and_then(Json::as_bool)
                .unwrap_or(false)
            {
                let seconds = cert
                    .get("ocspStapling")
                    .and_then(as_whole)
                    .filter(|seconds| *seconds != 0)
                    .unwrap_or(3600);
                entry.reload = Some(ferrox_core::tls::CertReload {
                    certificate: certificate.to_owned(),
                    key: key.to_owned(),
                    interval: Duration::from_secs(seconds),
                    read: read_cert_file,
                });
            }
        }
        // `ocspStapling` names the staple ticker too, so an inline entry staples without a file.
        let one_time = cert
            .get("oneTimeLoading")
            .and_then(Json::as_bool)
            .unwrap_or(false);
        let ocsp_interval = cert
            .get("ocspStapling")
            .and_then(as_whole)
            .filter(|seconds| *seconds != 0);
        if !one_time {
            if let Some(seconds) = ocsp_interval {
                let interval = Duration::from_secs(seconds);
                let response = ferrox_core::tls::ocsp_staple_for(&entry.cert_chain);
                if response.is_none() {
                    eprintln!("ocspStapling: no OCSP response for the served chain; serving without a staple");
                }
                entry.ocsp = Some(ferrox_core::tls::OcspStaple { interval, response });
            }
        }
        entries.push(entry);
    }
    Some(entries)
}

/// One inline PEM field, given as a string or as an array of lines.
fn inline_pem(entry: &Json, field: &str) -> Option<Vec<u8>> {
    let value = entry.get(field)?;
    if let Some(text) = value.as_str() {
        return Some(text.as_bytes().to_vec());
    }
    Some(
        value
            .as_arr()?
            .iter()
            .filter_map(Json::as_str)
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes(),
    )
}

/// The eight hex digits per group of an inbound id or an outbound server uuid, dashes optional.
pub(crate) fn uuid_bytes(text: &str) -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    let mut index = 0;
    let mut high: Option<u8> = None;
    for byte in text.bytes() {
        if byte == b'-' {
            continue;
        }
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        match high.take() {
            Some(h) => {
                if index >= 16 {
                    return None;
                }
                out[index] = (h << 4) | digit;
                index += 1;
            }
            None => high = Some(digit),
        }
    }
    if index == 16 && high.is_none() {
        Some(out)
    } else {
        None
    }
}

/// The 56-byte hex SHA-224 of the password that Trojan speaks on the wire, from the one derivation the link parser also reads.
pub(crate) fn trojan_key(password: &str) -> [u8; 56] {
    ferrox_core::trojan::key(password)
}

pub(crate) fn tls_ca_roots(outbound: &Json) -> Option<ferrox_core::tls::Anchors> {
    outbound
        .get("streamSettings")
        .and_then(|s| s.get("tlsSettings"))
        .and_then(|s| s.get("caCertFile"))
        .and_then(Json::as_str)
        .and_then(read_cert_file)
        .map(|pem| ferrox_core::tls::Anchors::from(crate::quic::parse_ca_pem(&pem)))
        .filter(|roots| !roots.is_empty())
}

/// Every certificate a `tlsSettings` names as a trust anchor: xray's `getCertPool` appends each
/// `certificates` entry's PEM to the client pool whatever its `usage`, and `caCertFile` is this
/// tree's one-field spelling of the same thing. A named file that cannot be read refuses the dial,
/// which is the reference's `TLSCertConfig.Build` error; an entry naming no certificate is skipped.
fn tls_named_anchors(tls: Option<&Json>) -> Result<Vec<Vec<u8>>, String> {
    let mut anchors = Vec::new();
    let file = |field: &str, path: &str| {
        read_cert_file(path).ok_or_else(|| format!("tlsSettings {field} `{path}` cannot be read"))
    };
    if let Some(path) = tls
        .and_then(|s| s.get("caCertFile"))
        .and_then(Json::as_str)
        .filter(|path| !path.is_empty())
    {
        anchors.extend(crate::quic::parse_ca_pem(&file("caCertFile", path)?));
    }
    let entries = tls
        .and_then(|s| s.get("certificates"))
        .and_then(Json::as_arr)
        .unwrap_or_default();
    for entry in entries {
        let pem = match entry
            .get("certificateFile")
            .and_then(Json::as_str)
            .filter(|path| !path.is_empty())
        {
            Some(path) => file("certificateFile", path)?,
            None => match inline_pem(entry, "certificate") {
                Some(pem) => pem,
                None => continue,
            },
        };
        anchors.extend(crate::quic::parse_ca_pem(&pem));
    }
    Ok(anchors)
}

/// The client identity an outbound presents when the server asks: the first `certificates` entry
/// that names a key and is not an authority entry. xray builds that pair but its client never sends
/// one, so a config that names it here opts into the sing-box client-certificate behaviour.
fn tls_client_cert(tls: Option<&Json>) -> Result<Option<Arc<ferrox_core::tls::CertEntry>>, String> {
    let entries = tls
        .and_then(|s| s.get("certificates"))
        .and_then(Json::as_arr)
        .unwrap_or_default();
    for entry in entries {
        let usage = entry
            .get("usage")
            .and_then(Json::as_str)
            .unwrap_or("encipherment");
        if !usage.eq_ignore_ascii_case("encipherment") {
            continue;
        }
        let key = match entry
            .get("keyFile")
            .and_then(Json::as_str)
            .filter(|path| !path.is_empty())
        {
            Some(path) => read_cert_file(path)
                .ok_or_else(|| format!("tlsSettings keyFile `{path}` cannot be read"))?,
            None => match inline_pem(entry, "key") {
                Some(key) => key,
                None => continue,
            },
        };
        let certificate = match entry
            .get("certificateFile")
            .and_then(Json::as_str)
            .filter(|path| !path.is_empty())
        {
            Some(path) => read_cert_file(path)
                .ok_or_else(|| format!("tlsSettings certificateFile `{path}` cannot be read"))?,
            None => inline_pem(entry, "certificate")
                .ok_or("tlsSettings certificate entry names a key but no certificate")?,
        };
        let parsed = ferrox_core::tls::parse_pem_entry(&certificate, &key)
            .map_err(|e| format!("tlsSettings client certificate: {e}"))?;
        return Ok(Some(Arc::new(parsed)));
    }
    Ok(None)
}

/// The names `verifyPeerCertByName` checks the peer chain against instead of the SNI: a comma
/// list, trimmed, empty entries skipped the way the reference's config build does.
fn tls_verify_names(settings: Option<&Json>) -> std::sync::Arc<[String]> {
    settings
        .and_then(|s| s.get("verifyPeerCertByName"))
        .and_then(Json::as_str)
        .map(|text| {
            text.split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
        .into()
}

/// xray's `curvePreferences`: the groups a hello offers, in the order named, under either spelling
/// of a `StringList` (a list, or one comma-separated string). A name the reference does not know
/// warns and drops, as its `ParseCurveName` does; one this build cannot carry warns and drops too,
/// leaving the build's own order when nothing is left rather than a hello with no groups.
fn tls_curves(tls: Option<&Json>, shaped: bool) -> Result<std::sync::Arc<[u16]>, String> {
    let Some(list) = tls.and_then(|s| s.get("curvePreferences")) else {
        return Ok(std::sync::Arc::default());
    };
    let names: Vec<&str> = match list {
        Json::Str(text) => text.split(',').map(str::trim).collect(),
        Json::Arr(items) => {
            let mut names = Vec::with_capacity(items.len());
            for item in items {
                names.push(
                    item.as_str()
                        .ok_or_else(|| "curvePreferences is not a list of strings".to_owned())?,
                );
            }
            names
        }
        _ => return Err("curvePreferences is not a list of strings".to_owned()),
    };
    let mut groups: Vec<u16> = Vec::with_capacity(names.len());
    for name in names.into_iter().filter(|name| !name.is_empty()) {
        let Some(group) = curve_id(name) else {
            eprintln!("unsupported curve name: {name}");
            continue;
        };
        if !ferrox_core::tls::curve_supported(group, shaped) {
            eprintln!("curvePreferences: {name} is not wired; the hello keeps its own groups");
            continue;
        }
        if !groups.contains(&group) {
            groups.push(group);
        }
    }
    Ok(groups.into())
}

/// The TLS group id an xray curve name stands for, lowercased as `ParseCurveName` compares them.
fn curve_id(name: &str) -> Option<u16> {
    Some(match name.to_ascii_lowercase().as_str() {
        "curvep256" => 0x0017,
        "curvep384" => 0x0018,
        "curvep521" => 0x0019,
        "x25519" => 0x001d,
        "x25519mlkem768" => 0x11ec,
        "secp256r1mlkem768" => 0x11eb,
        "secp384r1mlkem1024" => 0x11ed,
        _ => return None,
    })
}

/// The anchors a client verifies with: the platform store, plus every certificate the config
/// names. A config that names none keeps the store's one allocation, which is the ordinary case.
fn tls_client_roots(
    named: Vec<Vec<u8>>,
    system: ferrox_core::tls::Anchors,
) -> ferrox_core::tls::Anchors {
    if named.is_empty() {
        return system;
    }
    let mut all = Vec::with_capacity(system.len() + named.len());
    all.extend_from_slice(&system);
    all.extend(named);
    all.into()
}

fn tls_alpn(settings: Option<&Json>) -> Vec<Vec<u8>> {
    let Some(alpn) = settings.and_then(|s| s.get("alpn")) else {
        return Vec::new();
    };
    if let Some(single) = alpn.as_str() {
        if single.is_empty() {
            return Vec::new();
        }
        return vec![single.as_bytes().to_vec()];
    }
    let Some(items) = alpn.as_arr() else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(Json::as_str)
        .filter(|s| !s.is_empty())
        .map(|s| s.as_bytes().to_vec())
        .collect()
}

/// The `cipher_suites` field xray's `tlsSettings.cipherSuites` produces on the wire: the names
/// parse to ids, then `crypto/tls` re-orders them by preference and appends its TLS 1.3 suites
/// across the configured version range. Empty when the config names no known suite, which
/// leaves the backend's stock ordering in place.
fn tls_cipher_suites(settings: Option<&Json>) -> Vec<u16> {
    let Some(list) = settings
        .and_then(|s| s.get("cipherSuites"))
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
    else {
        return Vec::new();
    };
    let parsed = ferrox_core::tls::cipher_suites::parse(list);
    let min = tls_version(settings, "minVersion").unwrap_or(0x0301);
    let max = tls_version(settings, "maxVersion").unwrap_or(0x0304);
    ferrox_core::tls::cipher_suites::hello_ids(&parsed, min, max, true)
}

const INVALID_ECH: &[u8] = &[1, 1, 4, 5, 1, 4];

fn tls_ech_config(
    settings: Option<&Json>,
    server_name: &str,
) -> Result<Option<std::sync::Arc<[u8]>>, String> {
    let sockopt = crate::sockopt::parse(
        settings.and_then(|s| s.get("echSockopt").or_else(|| s.get("echSocketSettings"))),
    )?;
    let Some(text) = settings
        .and_then(|s| s.get("echConfigList"))
        .and_then(Json::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
    else {
        return Ok(None);
    };
    match crate::ech_dns::resolve(text, server_name, sockopt.as_ref()) {
        Ok(list) => Ok(Some(list.into())),
        Err(why) => {
            eprintln!("ech: {why}; the dial will fail");
            Ok(Some(INVALID_ECH.into()))
        }
    }
}

/// The ECH config a QUIC dial offers: xray has no QUIC transport, so this reads the TLS field it would have used and hands it to quiche's `BoringSSL` handshake.
pub(crate) fn quic_ech_config(
    outbound: &Json,
    address: &str,
) -> Result<Option<std::sync::Arc<[u8]>>, String> {
    let tls = outbound
        .get("streamSettings")
        .and_then(|s| s.get("tlsSettings"));
    let server_name = tls
        .and_then(|s| s.get("serverName"))
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(address);
    tls_ech_config(tls, server_name)
}

fn tls_version(settings: Option<&Json>, key: &str) -> Option<u16> {
    let text = settings.and_then(|s| s.get(key)).and_then(Json::as_str)?;
    match text.trim() {
        "1.0" => Some(0x0301),
        "1.1" => Some(0x0302),
        "1.2" => Some(0x0303),
        "1.3" => Some(0x0304),
        _ => None,
    }
}

/// The certificate digests a `pinnedPeerCertSha256` names: comma-separated hex, colons
/// stripped for the OpenSSL spelling, every entry exactly the thirty-two bytes a SHA-256 is.
fn cert_pinned_peer_cert_sha256(text: &str) -> Result<Vec<[u8; 32]>, String> {
    let mut pins = Vec::new();
    for entry in text.split(',') {
        let entry = entry.trim().replace(':', "");
        if entry.is_empty() {
            continue;
        }
        let mut pin = [0u8; 32];
        hex_slice(&entry, &mut pin)
            .map_err(|_| format!("pinnedPeerCertSha256 `{text}` is not hex"))?;
        pins.push(pin);
    }
    Ok(pins)
}

/// The big-endian hex of an entry into the caller's slice, the whole text or nothing.
fn hex_slice(text: &str, out: &mut [u8]) -> Result<(), u8> {
    fn nibble(byte: u8) -> Result<u8, u8> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            b'A'..=b'F' => Ok(byte - b'A' + 10),
            _ => Err(byte),
        }
    }
    let bytes = text.as_bytes();
    if bytes.len() != out.len() * 2 {
        return Err(0);
    }
    for (at, slot) in out.iter_mut().enumerate() {
        *slot = nibble(bytes[at * 2])? << 4 | nibble(bytes[at * 2 + 1])?;
    }
    Ok(())
}

pub(crate) fn outbound_tls(
    outbound: &Json,
    address: &str,
) -> Result<Arc<ferrox_core::tls::TlsConfig>, String> {
    let settings = outbound
        .get("streamSettings")
        .ok_or("no streamSettings in the outbound")?;
    if settings.get("security").and_then(Json::as_str) != Some("tls") {
        return Err("security is not tls".to_owned());
    }
    let tls = settings.get("tlsSettings");
    // xray honors `allowInsecure`, so we read the same field and dial the same verdict.
    let insecure = matches!(
        tls.and_then(|s| s.get("allowInsecure")),
        Some(Json::Bool(true))
    );
    let server_name = tls
        .and_then(|s| s.get("serverName"))
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(address)
        .to_owned();
    if server_name.is_empty() {
        return Err("no serverName".to_owned());
    }
    let alpn = tls_alpn(tls);
    // The reference pins comma-separated hex, colons stripped, one SHA-256 over a whole certificate; a pin is the whole contract, so no root and no name check follows a leaf pin.
    let cert_pins = tls
        .and_then(|s| s.get("pinnedPeerCertSha256"))
        .and_then(Json::as_str)
        .map(cert_pinned_peer_cert_sha256)
        .transpose()?
        .unwrap_or_default();
    let system_only = !matches!(
        tls.and_then(|s| s.get("disableSystemRoot")),
        Some(Json::Bool(true))
    );
    let named = tls_named_anchors(tls)?;
    let system = (!insecure && system_only && cert_pins.is_empty())
        .then(crate::quic::system_roots)
        .filter(|roots| !roots.is_empty())
        .unwrap_or_default();
    let roots = tls_client_roots(named, system);
    // The skip verifier reads no anchor, so an insecure dial needs none and loads none; a pin verifier answers from its own pins before any chain question, so it needs none either.
    if roots.is_empty() && !insecure && cert_pins.is_empty() {
        return Err(
            "no certificate authorities: no caCertFile or certificates, and the system roots are empty"
                .to_owned(),
        );
    }
    let ech_config_list = tls_ech_config(tls, &server_name)?;
    // xray's empty name is Chrome; a name no table knows is the config refusal it makes, not a stock hello.
    let fingerprint = match tls
        .and_then(|s| s.get("fingerprint"))
        .and_then(Json::as_str)
    {
        Some(name) => ferrox_core::tls::Fingerprint::resolve(name).ok_or_else(|| {
            format!(
                "unknown \"fingerprint\": {}",
                name.trim().to_ascii_lowercase()
            )
        })?,
        None => ferrox_core::tls::Fingerprint::default(),
    };
    let curves = tls_curves(tls, fingerprint.is_shaped())?;
    // xray leaves Go's session cache empty unless the config names one, so an unnamed store keeps no ticket.
    let resumption = matches!(
        tls.and_then(|s| s.get("enableSessionResumption")),
        Some(Json::Bool(true))
    );
    if resumption && fingerprint.is_shaped() {
        eprintln!(
            "enableSessionResumption: the shaped hello carries no ticket, so this dial keeps none"
        );
    }
    Ok(Arc::new(ferrox_core::tls::TlsConfig {
        server_name,
        alpn: alpn.into(),
        roots,
        pins: ferrox_core::foxy::pin::Pins::default(),
        cert_pins: std::sync::Arc::from(cert_pins),
        verify_names: tls_verify_names(tls),
        cipher_suites: tls_cipher_suites(tls).into(),
        curves,
        insecure,
        resumption,
        fingerprint: Some(fingerprint),
        ech_config_list,
        websocket: matches!(
            settings.get("network").and_then(Json::as_str),
            Some("ws" | "httpupgrade")
        ),
        master_key_log: tls_master_key_log(tls),
        client_cert: tls_client_cert(tls)?,
        client_random: None,
        padding: None,
    }))
}

/// xray's `masterKeyLog`: an empty name or `none` logs nothing, and a path that cannot be opened is
/// reported and the handshake proceeds without it.
fn tls_master_key_log(tls: Option<&Json>) -> Option<Arc<ferrox_core::tls::MasterKeyLog>> {
    let path = tls
        .and_then(|tls| tls.get("masterKeyLog"))
        .and_then(Json::as_str)
        .filter(|path| !path.is_empty() && *path != "none")?;
    let Some(log) = ferrox_core::tls::MasterKeyLog::open(path) else {
        eprintln!("masterKeyLog: {path} cannot be opened; the handshake logs nothing");
        return None;
    };
    Some(Arc::new(log))
}

/// The outbound REALITY identity: the decoy name, the server static key, the short id.
pub(crate) fn outbound_reality(
    outbound: &Json,
    address: &str,
) -> Option<Arc<ferrox_core::tls::RealityClientConfig>> {
    let settings = outbound.get("streamSettings")?;
    if settings.get("security").and_then(Json::as_str) != Some("reality") {
        return None;
    }
    let reality = settings.get("realitySettings")?;
    let server_name = reality
        .get("serverName")
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(address)
        .to_owned();
    if server_name.is_empty() {
        return None;
    }
    Some(Arc::new(ferrox_core::tls::RealityClientConfig {
        server_name,
        public_key: reality
            .get("password")
            .and_then(Json::as_str)
            .filter(|key| !key.is_empty())
            .or_else(|| reality.get("publicKey").and_then(Json::as_str))
            .and_then(key32)?,
        short_id: reality
            .get("shortId")
            .and_then(Json::as_str)
            .and_then(short_id)?,
        fingerprint: reality
            .get("fingerprint")
            .and_then(Json::as_str)
            .unwrap_or("chrome")
            .to_owned(),
        key_log: tls_master_key_log(Some(reality)),
    }))
}

pub(crate) fn kcp_config(settings: Option<&Json>) -> ferrox_core::kcp::Config {
    let base = ferrox_core::kcp::Config::default();
    let Some(kcp) = settings.and_then(|s| s.get("kcpSettings")) else {
        return base;
    };
    let num = |camel: &str, snake: &str| {
        kcp.get(camel)
            .or_else(|| kcp.get(snake))
            .and_then(Json::as_u32)
    };
    let mtu = num("mtu", "mtu").unwrap_or(base.mtu);
    let tti = num("tti", "tti").unwrap_or(base.tti);
    ferrox_core::kcp::Config {
        mtu: if mtu > ferrox_core::kcp::DATA_SEGMENT_OVERHEAD {
            mtu
        } else {
            base.mtu
        },
        tti: if (1..=1000).contains(&tti) {
            tti
        } else {
            base.tti
        },
        uplink_capacity: num("uplinkCapacity", "uplink_capacity").unwrap_or(base.uplink_capacity),
        downlink_capacity: num("downlinkCapacity", "downlink_capacity")
            .unwrap_or(base.downlink_capacity),
        cwnd_multiplier: num("cwndMultiplier", "cwnd_multiplier").unwrap_or(base.cwnd_multiplier),
        max_sending_window: num("maxSendingWindow", "max_sending_window")
            .unwrap_or(base.max_sending_window),
        mask: base.mask,
    }
}

pub(crate) fn sub_path(settings: Option<&Json>, key: &str) -> String {
    settings
        .and_then(|s| s.get(key))
        .and_then(|s| s.get("path"))
        .and_then(Json::as_str)
        .unwrap_or("/")
        .to_owned()
}
#[cfg(test)]
pub(crate) fn grpc_path(settings: Option<&Json>) -> String {
    grpc_names(settings).0
}

/// The two stream names one `serviceName` names: the call and its multi-mode peer.
fn grpc_names(settings: Option<&Json>) -> (String, String) {
    let service = settings
        .and_then(|s| s.get("grpcSettings"))
        .and_then(|s| s.get("serviceName"))
        .and_then(Json::as_str)
        .unwrap_or("");
    if service.is_empty() {
        return ("//Tun".to_owned(), "//TunMulti".to_owned());
    }
    if !service.starts_with('/') {
        let service = grpc_escape(service);
        return (format!("/{service}/Tun"), format!("/{service}/TunMulti"));
    }
    let last = service.rfind('/');
    let name_end = last.filter(|at| *at >= 1).unwrap_or(1);
    let name = service[1..name_end]
        .split('/')
        .map(grpc_escape)
        .collect::<Vec<_>>()
        .join("/");
    let ending = &service[last.map_or(1, |at| at + 1)..];
    let mut streams = ending.split('|');
    let tun = streams.next().unwrap_or("");
    let multi = streams.next().unwrap_or(tun);
    (
        format!("/{name}/{}", grpc_escape(tun)),
        format!("/{name}/{}", grpc_escape(multi)),
    )
}

fn multi_path(path: &str) -> String {
    path.strip_suffix("/Tun")
        .map_or_else(|| path.to_owned(), |head| format!("{head}/TunMulti"))
}

/// The gRPC settings one carrier names, with every field the reference reads.
#[derive(Debug, Clone, Default)]
pub(crate) struct GrpcSettings {
    pub(crate) path: String,
    pub(crate) multi_path: String,
    pub(crate) authority: String,
    pub(crate) user_agent: String,
    pub(crate) multi_mode: bool,
    pub(crate) idle_timeout: u32,
    pub(crate) health_check_timeout: u32,
    pub(crate) permit_without_stream: bool,
    pub(crate) initial_window_size: u32,
}

impl GrpcSettings {
    pub(crate) fn path(path: impl Into<String>) -> Self {
        let path = path.into();
        let multi_path = multi_path(&path);
        Self {
            path,
            multi_path,
            ..Self::default()
        }
    }

    fn from_json(settings: Option<&Json>) -> Self {
        let node = settings.and_then(|s| s.get("grpcSettings"));
        let (path, multi_path) = grpc_names(settings);
        let text = |key: &str| {
            node.and_then(|s| s.get(key))
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_owned()
        };
        let seconds = |key: &str| {
            node.and_then(|s| s.get(key))
                .and_then(as_uint)
                .and_then(|n| u32::try_from(n).ok())
                .unwrap_or(0)
        };
        Self {
            path,
            multi_path,
            authority: text("authority"),
            user_agent: text("userAgent"),
            multi_mode: node
                .and_then(|s| s.get("multiMode"))
                .and_then(Json::as_bool)
                .unwrap_or(false),
            idle_timeout: seconds("idleTimeout"),
            health_check_timeout: seconds("healthCheckTimeout"),
            permit_without_stream: node
                .and_then(|s| s.get("permitWithoutStream"))
                .and_then(Json::as_bool)
                .unwrap_or(false),
            initial_window_size: seconds("initialWindowsSize"),
        }
    }
}

/// Go's `url.PathEscape` for one segment, the way Xray escapes a service name.
fn grpc_escape(service: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(service.len());
    for byte in service.bytes() {
        let keep = byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'~' | b'$' | b'&' | b'+' | b':' | b'=' | b'@'
            );
        if keep {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX[usize::from(byte >> 4)] as char);
            out.push(HEX[usize::from(byte & 0x0f)] as char);
        }
    }
    out
}

/// The tcp-http request block the config names: `rawSettings` replaces `tcpSettings` whole when it is present, as the reference does before it builds the transport.
fn tcp_http_request(settings: Option<&Json>) -> Option<&Json> {
    let settings = settings?;
    let block = match settings.get("rawSettings") {
        Some(raw) if !matches!(raw, Json::Null) => raw,
        _ => settings.get("tcpSettings")?,
    };
    let header = block.get("header")?;
    if header.get("type").and_then(Json::as_str) != Some("http") {
        return None;
    }
    header.get("request")
}

pub(crate) fn tcp_http_path(settings: Option<&Json>) -> Option<String> {
    let request = tcp_http_request(settings)?;
    if let Some(paths) = request.get("path").and_then(Json::as_arr) {
        let first = paths.iter().find_map(Json::as_str);
        if let Some(path) = first {
            return Some(path.to_owned());
        }
    }
    if let Some(path) = request.get("path").and_then(Json::as_str) {
        return Some(path.to_owned());
    }
    Some("/".to_owned())
}

/// The headers and WebSocket heartbeat a carrier's settings carry. TCP-HTTP keeps its headers under the request block; every other carrier writes them beside the path.
pub(crate) fn carrier_headers(settings: Option<&Json>) -> (Vec<(String, String)>, u32) {
    let Some(settings) = settings else {
        return (Vec::new(), 0);
    };
    let network = settings.get("network").and_then(Json::as_str).unwrap_or("");
    let (headers, heartbeat) = match network {
        "ws" | "websocket" => {
            let block = settings.get("wsSettings");
            let heartbeat = block
                .and_then(|s| s.get("heartbeatPeriod"))
                .and_then(Json::as_u32)
                .unwrap_or(0);
            (block.and_then(|s| s.get("headers")), heartbeat)
        }
        "httpupgrade" => (
            settings
                .get("httpupgradeSettings")
                .and_then(|s| s.get("headers")),
            0,
        ),
        "xhttp" | "splithttp" => (
            settings
                .get("xhttpSettings")
                .or_else(|| settings.get("splithttpSettings"))
                .and_then(|s| s.get("headers")),
            0,
        ),
        "" | "raw" | "tcp" => (
            tcp_http_request(Some(settings)).and_then(|r| r.get("headers")),
            0,
        ),
        _ => (None, 0),
    };
    (masquerade_headers(headers), heartbeat)
}

/// A carrier header's value: a string, or xray's `StringList` form whose first entry is the value this tree sends.
fn header_value(value: &Json) -> Option<String> {
    value.as_str().map(str::to_owned).or_else(|| {
        value
            .as_arr()
            .and_then(|items| items.iter().find_map(Json::as_str))
            .map(str::to_owned)
    })
}

pub(crate) fn stream_security(node: &Json) -> &str {
    node.get("streamSettings")
        .and_then(|s| s.get("security"))
        .and_then(Json::as_str)
        .unwrap_or("")
}

/// Whether a listener's first bytes are the PROXY protocol's header. The reference carries the
/// flag per carrier and in `sockopt`; either spelling arms the same accept-side read.
pub(crate) fn accept_proxy_protocol(settings: Option<&Json>) -> bool {
    let Some(settings) = settings else {
        return false;
    };
    let network = settings.get("network").and_then(Json::as_str).unwrap_or("");
    let carrier = match network {
        "ws" | "websocket" => "wsSettings",
        "httpupgrade" => "httpupgradeSettings",
        "grpc" => "grpcSettings",
        "" | "raw" | "tcp" => "tcpSettings",
        _ => "",
    };
    let per_carrier = !carrier.is_empty()
        && settings
            .get(carrier)
            .and_then(|s| s.get("acceptProxyProtocol"))
            .and_then(Json::as_bool)
            .unwrap_or(false);
    let sockopt = settings
        .get("sockopt")
        .and_then(|s| s.get("acceptProxyProtocol"))
        .and_then(Json::as_bool)
        .unwrap_or(false);
    per_carrier || sockopt
}

pub(crate) fn vless_security_supported(sec: &str) -> bool {
    sec.is_empty() || sec == "none"
}

#[derive(Debug, Clone)]
pub(crate) enum Carrier {
    Raw(ferrox_core::finalmask::Chain),
    Ws {
        path: String,
        ed: u32,
    },
    HttpUpgrade {
        path: String,
        host: String,
    },
    Grpc(GrpcSettings),
    Xhttp {
        settings: Box<crate::xhttp::XhttpSettings>,
    },
    HttpHeader {
        path: String,
    },
    Quic,
    Kcp(ferrox_core::kcp::Config),
    Hysteria(ferrox_core::hysteria::Config),
    Masque,
    Xdrive {
        settings: Box<crate::xdrive::Settings>,
    },
    Http,
    Unknown {
        network: String,
    },
}

type Resolver = fn(Option<&Json>, &str) -> Carrier;

impl Carrier {
    /// The post-TLS write chain to put under a connection of this carrier, or `None` when the carrier
    /// needs none. The chain is the template: every connection clones it, so each counts its own
    /// writes from one.
    pub(crate) fn tcp_mask(&self) -> Option<&ferrox_core::finalmask::Chain> {
        match self {
            Carrier::Raw(chain) if !chain.is_empty() => Some(chain),
            _ => None,
        }
    }

    /// The gRPC dial settings, which carry both stream names and the head's fields.
    pub(crate) fn grpc_settings(&self) -> Option<&GrpcSettings> {
        match self {
            Carrier::Grpc(settings) => Some(settings),
            _ => None,
        }
    }

    /// The xHTTP dial settings, which carry the normalised request path.
    pub(crate) fn xhttp_settings(&self) -> Option<&crate::xhttp::XhttpSettings> {
        match self {
            Carrier::Xhttp { settings } => Some(settings),
            _ => None,
        }
    }

    /// Whether this carrier's serve path ends in the pooled relay instead of pinning a thread for the flow.
    pub(crate) fn tcp_stream(&self) -> bool {
        matches!(
            self,
            Carrier::Raw(_)
                | Carrier::Ws { .. }
                | Carrier::HttpUpgrade { .. }
                | Carrier::Grpc(_)
                | Carrier::Xhttp { .. }
                | Carrier::HttpHeader { .. }
        )
    }
}

// One row per network this tree recognises; a new method adds a row, not a match arm.
const CARRIERS: &[(&[&str], Resolver)] = &[
    (&["ws", "websocket"], resolve_ws),
    (&["httpupgrade"], resolve_httpupgrade),
    (&["grpc"], resolve_grpc),
    (&["xhttp", "splithttp"], resolve_xhttp),
    (&["quic"], resolve_quic),
    (&["kcp", "mkcp"], resolve_kcp),
    (&["hysteria"], resolve_hysteria),
    (&["masque"], resolve_masque),
    (&["xdrive"], resolve_xdrive),
    (&["http", "h2", "h3"], resolve_http),
    (&["", "raw", "tcp"], resolve_tcp_or_header),
];

pub(crate) fn stream_carrier(settings: Option<&Json>) -> Carrier {
    let network = settings
        .and_then(|s| s.get("network"))
        .and_then(Json::as_str)
        .unwrap_or("");
    let unknown = || Carrier::Unknown {
        network: network.to_owned(),
    };
    let carrier = CARRIERS
        .iter()
        .find(|(aliases, _)| aliases.contains(&network))
        .map_or_else(unknown, |(_, resolve)| resolve(settings, network));
    // The reference puts the chain on the TCP connection under whichever transport rides it; this tree arms it only where a carrier reaches that connection, so any other carrier refuses the config rather than dialling or serving it unmasked.
    if has_tcp_mask(settings) && !matches!(carrier, Carrier::Raw(_)) {
        return unknown();
    }
    carrier
}

/// Whether the transport asks for a post-TLS tcp mask chain at all.
pub(crate) fn has_tcp_mask(settings: Option<&Json>) -> bool {
    settings
        .and_then(|s| s.get("finalmask"))
        .and_then(|f| f.get("tcp"))
        .and_then(Json::as_arr)
        .is_some_and(|tcp| !tcp.is_empty())
}

fn resolve_ws(settings: Option<&Json>, _: &str) -> Carrier {
    let early = EarlyData::split(&sub_path(settings, "wsSettings"));
    Carrier::Ws {
        path: early.path,
        ed: early.budget,
    }
}

fn resolve_httpupgrade(settings: Option<&Json>, _: &str) -> Carrier {
    let early = EarlyData::split(&sub_path(settings, "httpupgradeSettings"));
    let host = settings
        .and_then(|s| s.get("httpupgradeSettings"))
        .and_then(|s| s.get("host"))
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned();
    Carrier::HttpUpgrade {
        path: early.path,
        host,
    }
}

fn resolve_grpc(settings: Option<&Json>, _: &str) -> Carrier {
    Carrier::Grpc(GrpcSettings::from_json(settings))
}

fn resolve_xhttp(settings: Option<&Json>, network: &str) -> Carrier {
    match crate::xhttp::XhttpSettings::from_json(settings) {
        Some(settings) => Carrier::Xhttp {
            settings: Box::new(settings),
        },
        None => Carrier::Unknown {
            network: network.to_owned(),
        },
    }
}

fn resolve_quic(_: Option<&Json>, _: &str) -> Carrier {
    Carrier::Quic
}

fn resolve_kcp(settings: Option<&Json>, network: &str) -> Carrier {
    let Some(mask) = kcp_mask(settings) else {
        return Carrier::Unknown {
            network: network.to_owned(),
        };
    };
    let mut config = kcp_config(settings);
    config.mask = mask;
    Carrier::Kcp(config)
}

/// The `finalmask.udp` chain for a KCP carrier, in wire order (outermost first). `Some(default)`
/// means no finalmask at all; `None` refuses the carrier — an unknown udp mask type, a gecko packet
/// size, a bad header name or an unpackable dns domain must never silently dial unmasked.
fn kcp_mask(settings: Option<&Json>) -> Option<ferrox_core::kcp::Mask> {
    use ferrox_core::kcp::{HeaderKind, Mask, Spec};
    let Some(udp) = settings
        .and_then(|s| s.get("finalmask"))
        .and_then(|f| f.get("udp"))
        .and_then(Json::as_arr)
    else {
        return Some(Mask::default());
    };
    let mut specs = Vec::with_capacity(udp.len());
    let mut headers = Vec::with_capacity(udp.len());
    for entry in udp {
        let conf = entry.get("settings");
        match entry
            .get("type")
            .and_then(Json::as_str)
            .map(str::to_lowercase)
            .as_deref()
        {
            Some("salamander") => {
                // A positive `packetSize` selects the reference's gecko lane, a fragmenting layer this mask is not.
                let gecko = match conf.and_then(|c| c.get("packetSize")) {
                    None | Some(Json::Null) => false,
                    Some(value) => int32_range(value).is_none_or(|range| range.high > 0),
                };
                if gecko {
                    return None;
                }
                let password = conf
                    .and_then(|c| c.get("password"))
                    .and_then(Json::as_str)
                    .unwrap_or("");
                specs.push(Spec::Salamander {
                    password: password.to_owned(),
                });
                headers.push(false);
            }
            Some("mkcp-legacy") => {
                let header = conf
                    .and_then(|c| c.get("header"))
                    .and_then(Json::as_str)
                    .unwrap_or("");
                let value = conf
                    .and_then(|c| c.get("value"))
                    .and_then(Json::as_str)
                    .unwrap_or("");
                specs.push(if header.is_empty() {
                    if value.is_empty() {
                        Spec::Original
                    } else {
                        Spec::Aes {
                            password: value.to_owned(),
                        }
                    }
                } else {
                    match header.to_lowercase().as_str() {
                        "dns" => Spec::HeaderDns {
                            domain: (if value.is_empty() {
                                "www.baidu.com"
                            } else {
                                value
                            })
                            .to_owned(),
                        },
                        "dtls" => Spec::Header(HeaderKind::Dtls),
                        "srtp" => Spec::Header(HeaderKind::Srtp),
                        "utp" => Spec::Header(HeaderKind::Utp),
                        "wechat" => Spec::Header(HeaderKind::Wechat),
                        "wireguard" => Spec::Header(HeaderKind::WireGuard),
                        _ => return None,
                    }
                });
                headers.push(true);
            }
            _ => return None,
        }
    }
    // A run of `mkcp-legacy` entries is written front-to-back from the reversed list, so its wire order is the reverse of its config order; a wrapper keeps its place.
    let mut at = 0;
    while at < specs.len() {
        if !headers[at] {
            at += 1;
            continue;
        }
        let mut end = at;
        while end < specs.len() && headers[end] {
            end += 1;
        }
        specs[at..end].reverse();
        at = end;
    }
    Mask::from_spec(&specs).ok()
}

fn resolve_hysteria(settings: Option<&Json>, network: &str) -> Carrier {
    hysteria_carrier(settings, network)
}

fn resolve_masque(_: Option<&Json>, _: &str) -> Carrier {
    Carrier::Masque
}

/// A folder the tree can reach, or no folder at all: an xdrive carrier that cannot name its store is refused rather than dialled at a default.
fn resolve_xdrive(settings: Option<&Json>, network: &str) -> Carrier {
    crate::xdrive::Settings::from_json(settings).map_or(
        Carrier::Unknown {
            network: network.to_owned(),
        },
        |settings| Carrier::Xdrive {
            settings: Box::new(settings),
        },
    )
}

fn resolve_http(_: Option<&Json>, _: &str) -> Carrier {
    Carrier::Http
}

fn resolve_tcp_or_header(settings: Option<&Json>, network: &str) -> Carrier {
    let Some(mask) = tcp_mask(settings) else {
        return Carrier::Unknown {
            network: network.to_owned(),
        };
    };
    match tcp_http_path(settings) {
        // A header masquerade plus a tcp mask is the pairing the reference answers with the refused `header-custom`.
        Some(_) if !mask.is_empty() => Carrier::Unknown {
            network: network.to_owned(),
        },
        Some(path) => Carrier::HttpHeader { path },
        None => Carrier::Raw(mask),
    }
}

/// The `finalmask.tcp` chain for a tcp carrier, in config order. `Some(empty)` means no finalmask at
/// all; `None` refuses the carrier — a tcp mask type this tree does not ship, or a fragment the
/// config cannot drive, must never dial or serve unmasked.
pub(crate) fn tcp_mask(settings: Option<&Json>) -> Option<ferrox_core::finalmask::Chain> {
    let Some(tcp) = settings
        .and_then(|s| s.get("finalmask"))
        .and_then(|f| f.get("tcp"))
        .and_then(Json::as_arr)
    else {
        return Some(ferrox_core::finalmask::Chain::default());
    };
    let mut chain = ferrox_core::finalmask::Chain::default();
    for entry in tcp {
        if entry
            .get("type")
            .and_then(Json::as_str)
            .map(str::to_lowercase)
            != Some("fragment".to_owned())
        {
            return None;
        }
        chain.push(fragment(entry.get("settings"))?);
    }
    Some(chain)
}

/// One `fragment` stage. `packets` picks the writes it cuts; `lengths` and `delays` fall back to
/// their singular spelling, and an unset one is the reference's zero range — a last width entry of 0,
/// which is a stage this tree refuses rather than one that would spin.
pub(crate) fn fragment(conf: Option<&Json>) -> Option<ferrox_core::finalmask::Fragment> {
    use ferrox_core::finalmask::Fragment;
    let packets = conf
        .and_then(|c| c.get("packets"))
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_lowercase();
    let (packets_from, packets_to) = match packets.as_str() {
        "tlshello" => (0, 1),
        "" => (0, 0),
        // The reference reads a window as a range and refuses a low end of 0, which would make every write a hello.
        other => {
            let window = range_text(other)?;
            if window.low == 0 {
                return None;
            }
            (window.low as u64, window.high as u64)
        }
    };
    let widths =
        range_list(conf, "lengths").or_else(|| Some(vec![single_range(conf, "length")?]))?;
    let waits = range_list(conf, "delays").or_else(|| {
        ["delay", "interval"]
            .into_iter()
            .find_map(|key| conf?.get(key).and_then(int32_range))
            .map_or_else(
                || Some(vec![ferrox_core::finalmask::Range::ordered(0, 0)]),
                |range| Some(vec![range]),
            )
    })?;
    Fragment::new(
        packets_from,
        packets_to,
        widths,
        waits,
        single_range(conf, "maxSplit")?,
    )
}

/// A `lengths`-style list, or `None` when the key is absent or empty and the singular spelling rules.
fn range_list(conf: Option<&Json>, key: &str) -> Option<Vec<ferrox_core::finalmask::Range>> {
    let items = conf?.get(key)?.as_arr()?;
    if items.is_empty() {
        return None;
    }
    items.iter().map(int32_range).collect()
}

/// A `length`-style single range, or the reference's zero range when the key is absent.
fn single_range(conf: Option<&Json>, key: &str) -> Option<ferrox_core::finalmask::Range> {
    match conf.and_then(|c| c.get(key)) {
        Some(value) => int32_range(value),
        None => Some(ferrox_core::finalmask::Range::ordered(0, 0)),
    }
}

/// One `Int32Range` as the reference reads it: a plain number, or a string that spells one.
fn int32_range(value: &Json) -> Option<ferrox_core::finalmask::Range> {
    use ferrox_core::finalmask::Range;
    match value {
        Json::Num(n) if n.fract() == 0.0 => Some(Range::ordered(*n as i64, *n as i64)),
        Json::Str(text) => range_text(text),
        _ => None,
    }
}

/// `ParseRangeString`: a single number, an empty string as `0`, or `a-b` in either order. A leading
/// dash belongs to the first end, so `"-114-514"` and `"-1919--810"` split after its second number.
/// Anything else is a spelling that errors upstream, so it refuses the mask here rather than becoming
/// a silent `0`.
fn range_text(text: &str) -> Option<ferrox_core::finalmask::Range> {
    use ferrox_core::finalmask::Range;
    if let Ok(single) = text.parse::<i64>() {
        return Some(Range::ordered(single, single));
    }
    if text.is_empty() {
        return Some(Range::ordered(0, 0));
    }
    let leading = text.starts_with('-');
    let mut parts = text.strip_prefix('-').unwrap_or(text).splitn(2, '-');
    let low = parts.next()?.parse::<i64>().ok()?;
    let high = parts.next()?.parse::<i64>().ok()?;
    Some(Range::ordered(if leading { -low } else { low }, high))
}

/// The hysteria protocol version a node names, as a number or a decimal string; absent when it names neither.
pub(crate) fn hysteria_version(node: Option<&Json>) -> Option<u32> {
    node.and_then(|value| {
        value
            .as_u32()
            .or_else(|| value.as_str().and_then(|text| text.parse::<u32>().ok()))
    })
}

/// A JSON integer, as a number or a decimal string; a fractional or non-numeric value names nothing.
fn as_i64(node: &Json) -> Option<i64> {
    match node {
        Json::Num(n) if n.fract() == 0.0 => Some(*n as i64),
        Json::Str(text) => text.trim().parse().ok(),
        _ => None,
    }
}

fn int_field(node: &Json, key: &str) -> Result<Option<i64>, String> {
    match node.get(key) {
        None | Some(Json::Null) => Ok(None),
        Some(value) => as_i64(value)
            .map(Some)
            .ok_or_else(|| format!("{key} is not an integer")),
    }
}

fn flag(node: &Json, key: &str) -> bool {
    node.get(key).and_then(Json::as_bool).unwrap_or(false)
}

/// `Bandwidth.Bps`: a decimal number with an optional byte or bit unit, converted to bytes per second exactly as the reference does.
fn bandwidth(node: &Json) -> Result<u64, String> {
    let text = match node {
        Json::Null => return Ok(0),
        // The reference spells a bandwidth as a string; a bare number is the same unitless bit rate.
        Json::Num(n) if *n >= 0.0 => return Ok(*n as u64 / 8),
        Json::Str(text) => text.trim().to_lowercase(),
        _ => return Err("bandwidth is not a number".to_owned()),
    };
    if text.is_empty() {
        return Ok(0);
    }
    let at = text
        .char_indices()
        .find(|(_, c)| !(c.is_ascii_digit() || *c == '.'))
        .map_or(text.len(), |(at, _)| at);
    let value: f64 = text[..at]
        .parse()
        .map_err(|_| format!("bandwidth `{text}` has no rate"))?;
    let unit = text[at..].trim();
    let multiplier: f64 = match unit {
        "" | "b" | "bps" => 1.0,
        "k" | "kb" | "kbps" => 1024.0,
        "m" | "mb" | "mbps" => 1024.0 * 1024.0,
        "g" | "gb" | "gbps" => 1024.0 * 1024.0 * 1024.0,
        "t" | "tb" | "tbps" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        other => return Err(format!("unsupported unit: {other}")),
    };
    Ok((value * multiplier) as u64 / 8)
}

/// `hysteriaSettings.udpIdleTimeout`: absent or 0 is the reference's 60-second default, anything else must lie in 2..=600.
pub(crate) fn hysteria_udp_idle(hy: Option<&Json>) -> Result<u64, String> {
    let Some(node) = hy.and_then(|h| h.get("udpIdleTimeout")) else {
        return Ok(60);
    };
    if matches!(node, Json::Null) {
        return Ok(60);
    }
    let Some(value) = as_i64(node) else {
        return Err("UdpIdleTimeout is not a number".to_owned());
    };
    if value == 0 {
        return Ok(60);
    }
    if !(2..=600).contains(&value) {
        return Err("UdpIdleTimeout must be between 2 and 600".to_owned());
    }
    Ok(value as u64)
}

/// The `finalmask.quicParams` block, validated under the reference's names and bounds; `None` when the stream names no block.
pub(crate) fn hysteria_quic_params(
    stream: Option<&Json>,
) -> Result<Option<ferrox_core::hysteria::QuicParams>, String> {
    use ferrox_core::hysteria::{BbrProfile, Congestion, QuicParams};
    let Some(node) = stream
        .and_then(|s| s.get("finalmask"))
        .and_then(|f| f.get("quicParams"))
    else {
        return Ok(None);
    };
    if matches!(node, Json::Null) {
        return Ok(None);
    }
    if !matches!(node, Json::Obj(_)) {
        return Err("quicParams is not an object".to_owned());
    }
    let named = |key: &str| -> Result<String, String> {
        match node.get(key) {
            None | Some(Json::Null) => Ok(String::new()),
            Some(value) => value
                .as_str()
                .map(str::to_lowercase)
                .ok_or_else(|| format!("{key} is not a string")),
        }
    };
    let profile_text = named("bbrProfile")?;
    let bbr_profile = match profile_text.as_str() {
        "" | "standard" => BbrProfile::Standard,
        "conservative" => BbrProfile::Conservative,
        "aggressive" => BbrProfile::Aggressive,
        _ => return Err("unknown bbr profile".to_owned()),
    };
    let up = match node.get("brutalUp") {
        Some(value) => bandwidth(value)?,
        None => 0,
    };
    let down = match node.get("brutalDown") {
        Some(value) => bandwidth(value)?,
        None => 0,
    };
    if up > 0 && up < 65536 {
        return Err("BrutalUp must be at least 65536 bytes per second".to_owned());
    }
    if down > 0 && down < 65536 {
        return Err("BrutalDown must be at least 65536 bytes per second".to_owned());
    }
    let congestion_text = named("congestion")?;
    let cc = match congestion_text.as_str() {
        "" | "brutal" => Some(Congestion::Brutal),
        "reno" => Some(Congestion::Reno),
        "bbr" => Some(Congestion::Bbr),
        "force-brutal" => {
            if up == 0 {
                return Err("force-brutal requires up".to_owned());
            }
            Some(Congestion::Brutal)
        }
        _ => {
            return Err(format!(
                "unknown congestion control: {congestion_text}, valid values: reno, bbr, brutal, force-brutal"
            ))
        }
    };
    let window = |key: &str| -> Result<u64, String> {
        let value = int_field(node, key)?.unwrap_or(0);
        if value != 0 && value < 16384 {
            return Err(format!("{key} must be at least 16384"));
        }
        Ok(value as u64)
    };
    let init_stream = window("initStreamReceiveWindow")?;
    let max_stream = window("maxStreamReceiveWindow")?;
    let init_connection = window("initConnectionReceiveWindow")?;
    let max_connection = window("maxConnectionReceiveWindow")?;
    let max_idle = int_field(node, "maxIdleTimeout")?.unwrap_or(0);
    if max_idle != 0 && !(4..=120).contains(&max_idle) {
        return Err("MaxIdleTimeout must be between 4 and 120".to_owned());
    }
    let keep_alive = int_field(node, "keepAlivePeriod")?.unwrap_or(0);
    if keep_alive != 0 && !(2..=60).contains(&keep_alive) {
        return Err("KeepAlivePeriod must be between 2 and 60".to_owned());
    }
    let max_incoming = int_field(node, "maxIncomingStreams")?.unwrap_or(0);
    if max_incoming != 0 && max_incoming < 8 {
        return Err("MaxIncomingStreams must be at least 8".to_owned());
    }
    Ok(Some(QuicParams {
        cc,
        bbr_profile,
        brutal_up: up,
        brutal_down: down,
        init_stream_window: init_stream,
        max_stream_window: max_stream,
        init_connection_window: init_connection,
        max_connection_window: max_connection,
        max_idle: max_idle as u64,
        keep_alive: keep_alive as u64,
        no_path_mtu: flag(node, "disablePathMTUDiscovery"),
        max_incoming_streams: max_incoming as u64,
        disable_stateless_reset: flag(node, "disableStatelessReset"),
    }))
}

fn hysteria_carrier(settings: Option<&Json>, network: &str) -> Carrier {
    use ferrox_core::hysteria::{Config, Congestion};
    let hy = settings.and_then(|s| s.get("hysteriaSettings"));
    let version = hysteria_version(hy.and_then(|h| h.get("version"))).unwrap_or(2);
    if version != 1 && version != 2 {
        return Carrier::Unknown {
            network: network.to_owned(),
        };
    }
    let auth = hy
        .and_then(|h| h.get("auth"))
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned();
    let mut cc = Congestion::parse(
        hy.and_then(|h| h.get("congestion"))
            .and_then(Json::as_str)
            .unwrap_or(""),
    );
    let quic = match hysteria_quic_params(settings) {
        Ok(quic) => quic,
        Err(why) => {
            eprintln!("hysteria quicParams: {why}; the carrier is refused");
            return Carrier::Unknown {
                network: network.to_owned(),
            };
        }
    };
    if let Some(params) = &quic {
        if let Some(named) = params.cc {
            cc = named;
        }
    }
    let udp_idle = match hysteria_udp_idle(hy) {
        Ok(idle) => idle,
        Err(why) => {
            eprintln!("hysteria udpIdleTimeout: {why}; the carrier is refused");
            return Carrier::Unknown {
                network: network.to_owned(),
            };
        }
    };
    let realm = match hysteria_realm(settings, hy) {
        Ok(realm) => realm,
        Err(why) => {
            eprintln!("hysteria realm: {why}; the carrier is refused");
            return Carrier::Unknown {
                network: network.to_owned(),
            };
        }
    };
    if version == 1 {
        // Version 1 names xplus directly: `tlsSettings.obfs` is the password, not a mask name.
        return Carrier::Hysteria(Config {
            version: 1,
            auth,
            cc,
            obfs_password: hysteria_v1_obfs(settings).unwrap_or_default(),
            hop: hysteria_hop(hy),
            gecko: None,
            udp_idle,
            quic,
            realm: realm.map(Box::new),
        });
    }
    // Salamander and its gecko fragmentation variant are the datagram obfuscations carried; any other named one, or one whose password is too short to mask with, is refused rather than silently sent in the clear.
    let obfs_password = match salamander_obfs(settings) {
        None => String::new(),
        Some(password) if ferrox_core::hysteria::Salamander::new(&password).is_some() => password,
        Some(_) => {
            return Carrier::Unknown {
                network: network.to_owned(),
            };
        }
    };
    // A gecko lane whose window cannot be read is refused, never carried as a plain salamander that would silently drop the fragmentation the config asked for.
    let Ok(gecko) = hysteria_gecko(settings) else {
        return Carrier::Unknown {
            network: network.to_owned(),
        };
    };
    Carrier::Hysteria(Config {
        version: 2,
        auth,
        cc,
        obfs_password,
        hop: hysteria_hop(hy),
        gecko,
        udp_idle,
        quic,
        realm: realm.map(Box::new),
    })
}

/// The v1 outbound config a transport names: auth, congestion, xplus password, hop, and the same `udpIdleTimeout`/`quicParams` the v2 lane reads.
pub(crate) fn hysteria_v1_config(
    stream: Option<&Json>,
) -> Result<ferrox_core::hysteria::Config, String> {
    use ferrox_core::hysteria::{Config, Congestion};
    let hy = stream.and_then(|s| s.get("hysteriaSettings"));
    let quic = hysteria_quic_params(stream)?;
    let mut cc = Congestion::parse(
        hy.and_then(|h| h.get("congestion"))
            .and_then(Json::as_str)
            .unwrap_or(""),
    );
    if let Some(named) = quic.as_ref().and_then(|params| params.cc) {
        cc = named;
    }
    Ok(Config {
        version: 1,
        auth: hy
            .and_then(|h| h.get("auth"))
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_owned(),
        cc,
        obfs_password: hysteria_v1_obfs(stream).unwrap_or_default(),
        hop: hysteria_hop(hy),
        gecko: None,
        udp_idle: hysteria_udp_idle(hy)?,
        quic,
        realm: hysteria_realm(stream, hy)?.map(Box::new),
    })
}

/// The xplus password a Hysteria v1 transport names: `tlsSettings.obfs` itself is the key.
fn hysteria_v1_obfs(stream: Option<&Json>) -> Option<String> {
    stream
        .and_then(|s| s.get("tlsSettings"))
        .and_then(|t| t.get("obfs"))
        .and_then(Json::as_str)
        .filter(|password| !password.is_empty())
        .map(str::to_owned)
}

/// The realm rendezvous a hysteria dial or serve knocks through STUN and punch, read from either
/// `hysteriaSettings.realm` (the sing-box spelling, `server_url` with `realm_id`) or
/// `finalmask.realm` and `finalmask.udp[type=realm]` (the xray spelling, `scheme`/`host`/`port` with
/// `ID`). A block that is present but names no origin, no slot or no STUN server is refused rather
/// than dialled direct — the peer it would punch is only reachable through the rendezvous. A
/// `port_mapping` block is carried through; the dialer warns where a gateway mapping is requested and
/// continues without a gateway address, as the reference does when its mapper fails to initialise.
#[allow(clippy::too_many_lines)]
pub(crate) fn hysteria_realm_for_stream(
    stream: Option<&Json>,
    hy: Option<&Json>,
) -> Result<Option<ferrox_core::realm::Config>, String> {
    hysteria_realm(stream, hy)
}

#[allow(clippy::too_many_lines)]
fn hysteria_realm(
    settings: Option<&Json>,
    hy: Option<&Json>,
) -> Result<Option<ferrox_core::realm::Config>, String> {
    use ferrox_core::realm::{Config, Family, PortMapping};
    let object = hy
        .and_then(|h| h.get("realm"))
        .or_else(|| {
            settings
                .and_then(|s| s.get("finalmask"))
                .and_then(|f| f.get("realm"))
        })
        .or_else(|| {
            settings
                .and_then(|s| s.get("finalmask"))
                .and_then(|f| f.get("udp"))
                .and_then(Json::as_arr)
                .and_then(|udp| {
                    udp.iter().find(|entry| {
                        entry
                            .get("type")
                            .and_then(Json::as_str)
                            .is_some_and(|t| t.eq_ignore_ascii_case("realm"))
                    })
                })
                .and_then(|entry| entry.get("settings"))
        });
    let Some(node) = object else {
        return Ok(None);
    };
    if salamander_obfs(settings).is_some()
        || hysteria_hop(hy).is_some()
        || hysteria_gecko(settings).is_ok_and(|gecko| gecko.is_some())
    {
        return Err("realm cannot ride salamander, gecko or a port hop yet; its punch bypasses the masked datagram demux".to_owned());
    }
    let field = |camel: &str, snake: &str| node.get(camel).or_else(|| node.get(snake));
    let url = field("server_url", "serverUrl")
        .and_then(Json::as_str)
        .map(str::to_owned);
    let (scheme_from_url, host_from_url, port_from_url) = match &url {
        Some(text) => {
            let (scheme, rest) = text.split_once("://").ok_or("server_url needs scheme://")?;
            let scheme = scheme.to_ascii_lowercase();
            if scheme != "http" && scheme != "https" {
                return Err("server_url scheme must be http or https".to_owned());
            }
            let hostport = rest.split('/').next().unwrap_or(rest);
            let default = if scheme == "https" { 443 } else { 80 };
            let split = if let Some(inner) = hostport.strip_prefix('[') {
                let (h, tail) = inner
                    .split_once(']')
                    .ok_or("server_url has an unclosed [")?;
                match tail.strip_prefix(':') {
                    Some(p) => Some((h, Some(p))),
                    None if tail.is_empty() => Some((h, None)),
                    None => return Err("server_url port must be a port".to_owned()),
                }
            } else {
                hostport.rsplit_once(':').map(|(h, p)| (h, Some(p)))
            };
            let (host, port) = if let Some((h, p)) = split {
                match p {
                    Some(p) => (
                        h.to_owned(),
                        p.parse::<u16>()
                            .map_err(|_| "server_url port must be a port".to_owned())?,
                    ),
                    None => (h.to_owned(), default),
                }
            } else {
                (hostport.to_owned(), default)
            };
            if host.is_empty() {
                return Err("server_url names no host".to_owned());
            }
            (Some(scheme), Some(host), Some(port))
        }
        None => (None, None, None),
    };
    let scheme = field("scheme", "scheme")
        .and_then(Json::as_str)
        .map(str::to_owned)
        .or(scheme_from_url)
        .unwrap_or_else(|| "http".to_owned());
    if scheme != "http" && scheme != "https" {
        return Err("realm scheme must be http or https".to_owned());
    }
    let host = field("host", "host")
        .and_then(Json::as_str)
        .map(str::to_owned)
        .or(host_from_url)
        .unwrap_or_default();
    if host.is_empty() {
        return Err("realm names no host".to_owned());
    }
    let port = field("port", "port")
        .and_then(Json::as_port)
        .or(port_from_url)
        .or_else(|| {
            field("port", "port")
                .and_then(Json::as_str)
                .and_then(|p| p.parse().ok())
        })
        .unwrap_or_else(|| if scheme == "https" { 443 } else { 80 });
    let id = field("realm_id", "realmId")
        .or_else(|| field("ID", "id"))
        .and_then(Json::as_str)
        .map(str::to_owned)
        .unwrap_or_default();
    if !ferrox_core::realm::valid_realm_id(&id) {
        return Err("realm id is missing or malformed".to_owned());
    }
    let token = field("token", "token")
        .and_then(Json::as_str)
        .map(str::to_owned)
        .unwrap_or_default();
    let mut stun_servers = Vec::new();
    if let Some(servers) = field("stun_servers", "stunServers") {
        if let Some(items) = servers.as_arr() {
            for item in items {
                if let Some(text) = item.as_str() {
                    let text = text.trim();
                    if !text.is_empty() {
                        stun_servers.push(text.to_owned());
                    }
                }
            }
        } else if let Some(text) = servers.as_str() {
            let text = text.trim();
            if !text.is_empty() {
                stun_servers.push(text.to_owned());
            }
        }
    }
    if stun_servers.is_empty() {
        return Err("realm names no STUN server".to_owned());
    }
    let family_value = field("ip_version", "ipVersion").or_else(|| field("IPMode", "ip_mode"));
    let family = match family_value.and_then(Json::as_i64) {
        Some(4) => Family::V4,
        Some(6) => Family::V6,
        None => match family_value.and_then(Json::as_str) {
            Some(text) => match text.trim().to_ascii_lowercase().as_str() {
                "4" | "v4" => Family::V4,
                "6" | "v6" => Family::V6,
                _ => Family::Dual,
            },
            None => Family::Dual,
        },
        _ => Family::Dual,
    };
    let port_mapping = field("port_mapping", "portMapping").and_then(|mapping| {
        let enabled = mapping
            .get("enabled")
            .and_then(Json::as_bool)
            .unwrap_or(false);
        if !enabled {
            return None;
        }
        let timeout_seconds = mapping
            .get("timeout")
            .and_then(duration_seconds)
            .unwrap_or(10);
        let lifetime_seconds = mapping
            .get("lifetime")
            .and_then(duration_seconds)
            .unwrap_or(600);
        Some(PortMapping {
            enabled: true,
            timeout: timeout_seconds,
            lifetime: lifetime_seconds,
        })
    });
    Ok(Some(Config {
        scheme,
        host,
        port,
        token,
        id,
        stun_servers,
        family,
        port_mapping,
    }))
}

/// A duration in seconds from a bare number or a number with an `s`/`ms` suffix; `None` when absent
/// or malformed, so the port-mapping caller falls back to its default.
fn duration_seconds(value: &Json) -> Option<u64> {
    if let Some(seconds) = value.as_i64() {
        return Some(seconds.max(0) as u64);
    }
    let text = value.as_str()?.trim();
    let (number, divisor) = if let Some(ms) = text.strip_suffix("ms") {
        (ms, 1000)
    } else if let Some(s) = text.strip_suffix('s') {
        (s, 1)
    } else {
        (text, 1)
    };
    number
        .trim()
        .parse::<u64>()
        .ok()
        .map(|seconds| seconds / divisor)
}

/// The port-hopping plan a hysteria dial rotates its server port on, read from its
/// `hysteriaSettings`. `serverPorts`/`mport` names the ports or `start-end` ranges —
/// an array of numbers/strings or one comma-separated string; `hopInterval` and
/// `hopIntervalMax` bound the stay in seconds (a bare number, or an `s`/`ms` suffix).
/// A malformed token is dropped rather than guessed at, and with nothing valid left
/// the dial stays on its fixed port: a hop is anti-blocking, not correctness, so it
/// never reroutes a flow to a port the config did not name. Field names take both the
/// camel and the snake spelling the reference's two JSON dialects use.
fn hysteria_hop(hy: Option<&Json>) -> Option<ferrox_core::hysteria::Hop> {
    use ferrox_core::hysteria::{Hop, PortRange};
    let hy = hy?;
    let field = |camel: &str, snake: &str| hy.get(camel).or_else(|| hy.get(snake));
    let spec = field("serverPorts", "server_ports").or_else(|| field("mport", "mport"))?;
    let mut ranges: Vec<PortRange> = Vec::new();
    if let Some(items) = spec.as_arr() {
        for item in items {
            push_port_spec(item.as_str(), &mut ranges);
            if let Some(port) = item.as_port() {
                ranges.push(PortRange {
                    start: port,
                    end: port,
                });
            }
        }
    } else if let Some(port) = spec.as_port() {
        ranges.push(PortRange {
            start: port,
            end: port,
        });
    } else {
        push_port_spec(spec.as_str(), &mut ranges);
    }
    if ranges.is_empty() {
        return None;
    }
    let low = stay_ms(field("hopInterval", "hop_interval")).unwrap_or(5_000);
    let high = stay_ms(field("hopIntervalMax", "hop_interval_max")).unwrap_or(low);
    Some(Hop {
        ranges,
        interval_ms: (low.min(high), low.max(high)),
    })
}

/// Append every `port` or `start-end` token of a comma-separated port spec; a token
/// that is not a valid nonzero port, or a backwards range, is skipped, never guessed.
fn push_port_spec(text: Option<&str>, ranges: &mut Vec<ferrox_core::hysteria::PortRange>) {
    use ferrox_core::hysteria::PortRange;
    let Some(text) = text else { return };
    for token in text.split(',') {
        let token = token.trim();
        match token.split_once('-') {
            Some((lo, hi)) => {
                let (Ok(start), Ok(end)) = (lo.trim().parse::<u16>(), hi.trim().parse::<u16>())
                else {
                    continue;
                };
                if start > 0 && start <= end {
                    ranges.push(PortRange { start, end });
                }
            }
            None => {
                if let Some(port) = token.parse::<u16>().ok().filter(|port| *port > 0) {
                    ranges.push(PortRange {
                        start: port,
                        end: port,
                    });
                }
            }
        }
    }
}

/// The next stay length in milliseconds: a bare number or string is seconds, an `s`
/// suffix is seconds, an `ms` suffix is milliseconds; `None` when absent or malformed.
fn stay_ms(value: Option<&Json>) -> Option<u64> {
    match value? {
        Json::Num(n) if n.fract() == 0.0 && *n >= 0.0 => Some(*n as u64 * 1000),
        Json::Str(text) => {
            let text = text.trim();
            if let Some(ms) = text.strip_suffix("ms") {
                ms.trim().parse::<u64>().ok()
            } else if let Some(s) = text.strip_suffix('s') {
                s.trim().parse::<u64>().ok().map(|secs| secs * 1000)
            } else {
                text.parse::<u64>().ok().map(|secs| secs * 1000)
            }
        }
        _ => None,
    }
}

/// The `obfs: salamander` (or `gecko`) password a hysteria transport names in its `tlsSettings`, or `None` for no obfuscation and `Some("")` for one this build cannot honour; the caller serves cleartext only for the first. Gecko masks each frame with salamander, so it shares this key.
pub(crate) fn salamander_obfs(stream: Option<&Json>) -> Option<String> {
    let tls = stream.and_then(|s| s.get("tlsSettings"));
    match tls.and_then(|t| t.get("obfs")).and_then(Json::as_str) {
        None | Some("") => None,
        Some("salamander" | "gecko") => Some(
            tls.and_then(|t| t.get("obfs-password"))
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_owned(),
        ),
        Some(_) => Some(String::new()),
    }
}

/// The `obfs: gecko` fragment window a hysteria transport names, `Ok(None)` when the
/// obfs is absent or another kind, `Ok(Some(window))` for a valid gecko, and `Err(())`
/// when gecko is named but its window is unusable — refused rather than carried as a
/// plain salamander that would silently drop the fragmentation. Bounds accept the
/// sing-box `min_packet_size`/`max_packet_size`, their camel spellings, and the
/// reference's `packetSize` range as an object or a two-element array.
fn hysteria_gecko(stream: Option<&Json>) -> Result<Option<ferrox_core::hysteria::Gecko>, ()> {
    let Some(tls) = stream.and_then(|s| s.get("tlsSettings")) else {
        return Ok(None);
    };
    if tls.get("obfs").and_then(Json::as_str) != Some("gecko") {
        return Ok(None);
    }
    let size = |keys: [&str; 2]| {
        keys.into_iter()
            .find_map(|key| tls.get(key))
            .and_then(Json::as_u32)
            .and_then(|value| u16::try_from(value).ok())
    };
    let (min, max) = match (
        size(["minPacketSize", "min_packet_size"]),
        size(["maxPacketSize", "max_packet_size"]),
    ) {
        (Some(min), Some(max)) => (min, max),
        (min, max) => {
            // Fall back to the reference's `packetSize` range, object or array form.
            let edge = |json: &Json, from: bool| {
                json.get(if from { "from" } else { "to" })
                    .or_else(|| json.as_arr().and_then(|a| a.get(usize::from(!from))))
                    .and_then(Json::as_u32)
                    .and_then(|value| u16::try_from(value).ok())
            };
            match tls.get("packetSize") {
                Some(range) => (
                    min.or_else(|| edge(range, true)).unwrap_or(0),
                    max.or_else(|| edge(range, false)).unwrap_or(0),
                ),
                None => (min.unwrap_or(0), max.unwrap_or(0)),
            }
        }
    };
    ferrox_core::hysteria::Gecko::new(min, max)
        .map(Some)
        .ok_or(())
}

/// The masquerade cover an inbound hysteria server answers a browser with, read from its `hysteriaSettings`. xray's JSON nests it under `masquerade`; the flat protobuf spellings stay as the second way. Absent, empty, or an unknown type falls back to the plain not-found, so only a configured cover ever changes what a browser sees.
pub(crate) fn masquerade_from_stream(stream: Option<&Json>) -> ferrox_core::hysteria::Masquerade {
    use ferrox_core::hysteria::Masquerade;
    let Some(hy) = stream.and_then(|s| s.get("hysteriaSettings")) else {
        return Masquerade::NotFound;
    };
    let nested = hy.get("masquerade");
    let field = |name: &str, camel: &str, snake: &str| {
        nested
            .and_then(|object| object.get(name))
            .or_else(|| hy.get(camel))
            .or_else(|| hy.get(snake))
    };
    let text =
        |name: &str, camel: &str, snake: &str| field(name, camel, snake).and_then(Json::as_str);
    let flag = |name: &str, camel: &str, snake: &str| {
        field(name, camel, snake)
            .and_then(Json::as_bool)
            .unwrap_or(false)
    };
    let kind = text("type", "masqType", "masq_type").unwrap_or_default();
    if kind.eq_ignore_ascii_case("file") {
        text("dir", "masqFile", "masq_file").map_or(Masquerade::NotFound, |dir| Masquerade::File {
            dir: dir.to_owned(),
        })
    } else if kind.eq_ignore_ascii_case("proxy") {
        text("url", "masqUrl", "masq_url").map_or(Masquerade::NotFound, |url| Masquerade::Proxy {
            url: url.to_owned(),
            rewrite_host: flag("rewriteHost", "masqUrlRewriteHost", "masq_url_rewrite_host"),
            x_forwarded: flag("xForwarded", "masqUrlXForwarded", "masq_url_x_forwarded"),
            insecure: flag("insecure", "masqUrlInsecure", "masq_url_insecure"),
        })
    } else if kind.eq_ignore_ascii_case("string") || kind.eq_ignore_ascii_case("response") {
        let status = field(
            "statusCode",
            "masqStringStatusCode",
            "masq_string_status_code",
        )
        .and_then(Json::as_u32)
        .filter(|code| *code != 0)
        .map_or(200, |code| code as u16);
        let body = text("content", "masqString", "masq_string")
            .unwrap_or_default()
            .as_bytes()
            .to_vec();
        let headers =
            masquerade_headers(field("headers", "masqStringHeaders", "masq_string_headers"));
        Masquerade::Response {
            status,
            headers,
            body,
        }
    } else {
        Masquerade::NotFound
    }
}

/// A response's headers in either dialect: xray's object maps names to values, while the flat form carries `Name: value` lines.
pub(crate) fn masquerade_headers(field: Option<&Json>) -> Vec<(String, String)> {
    match field {
        Some(Json::Obj(pairs)) => pairs
            .iter()
            .filter_map(|(name, value)| header_value(value).map(|value| (name.clone(), value)))
            .collect(),
        Some(Json::Arr(items)) => items
            .iter()
            .filter_map(Json::as_str)
            .filter_map(header_line)
            .collect(),
        _ => Vec::new(),
    }
}

/// One `Name: value` line from a masquerade response's header list, split on its first colon; a line naming nothing is dropped.
fn header_line(line: &str) -> Option<(String, String)> {
    let (name, value) = line.split_once(':')?;
    Some((name.trim().to_owned(), value.trim().to_owned()))
}

pub(crate) fn outbound_carrier(outbound: &Json, address: &str) -> (Carrier, String) {
    let settings = outbound.get("streamSettings");
    let carrier = stream_carrier(settings);
    // Only a REALITY stream-one session knows it dials H2 before the handshake, so only that arm is pooled here.
    if let Carrier::Xhttp { settings: xhttp } = &carrier {
        let reality_stream_one = settings
            .and_then(|node| node.get("security"))
            .and_then(Json::as_str)
            == Some("reality")
            && xhttp.mode == crate::xhttp::XhttpMode::StreamOne;
        if xhttp.xmux.is_some() && !reality_stream_one {
            eprintln!("xhttp: \"xmux\" bounds are checked, and this tree pools only a REALITY stream-one session, so an H1 or TLS-h2 dial keeps its own connection");
        }
    }
    let key = match &carrier {
        Carrier::Ws { .. } => "wsSettings",
        Carrier::HttpUpgrade { .. } => "httpupgradeSettings",
        Carrier::Grpc(_) => "grpcSettings",
        Carrier::Xhttp { .. } => "xhttpSettings",
        Carrier::HttpHeader { .. } => "tcpSettings",
        Carrier::Quic => "quicSettings",
        Carrier::Kcp(_) => "kcpSettings",
        Carrier::Hysteria(_) => "hysteriaSettings",
        Carrier::Masque => "masqueSettings",
        Carrier::Xdrive { .. } => "xdriveSettings",
        Carrier::Unknown { .. } | Carrier::Raw(_) | Carrier::Http => "",
    };
    let configured = carrier_headers(settings).0;
    let header_host = crate::headers::host(&configured);
    let carrier_host = settings
        .and_then(|s| s.get(key))
        .and_then(|s| s.get("host"))
        .and_then(Json::as_str);
    let tls_host = settings
        .and_then(|s| s.get("tlsSettings"))
        .and_then(|s| s.get("serverName"))
        .and_then(Json::as_str);
    // The header wins over the carrier's own host, which wins over the TLS name, which wins over the dialled address. Hysteria's QUIC handshake carries the TLS name as its authority, so it keeps the TLS name ahead of `hysteriaSettings.host`.
    let host = if matches!(carrier, Carrier::Hysteria(_)) {
        tls_host.or(carrier_host)
    } else {
        header_host.or(carrier_host).or(tls_host)
    }
    .unwrap_or(address)
    .to_owned();
    (carrier, host)
}

pub(crate) fn inbound_carrier(inbound: &Json) -> Carrier {
    stream_carrier(inbound.get("streamSettings"))
}

/// A wait the config restates; `None` keeps the constant beside the name in `budgets.rs`.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Budgets {
    pub(crate) dial: Option<Duration>,
    pub(crate) handshake: Option<Duration>,
    pub(crate) head_arrival: Option<Duration>,
    pub(crate) relay_join: Option<Duration>,
    pub(crate) relay_quantum: Option<Duration>,
    pub(crate) relay_stall: Option<Duration>,
    pub(crate) udp_idle: Option<Duration>,
    pub(crate) payload_grace: Option<Duration>,
    pub(crate) goaway_grace: Option<Duration>,
    pub(crate) sink_grace: Option<Duration>,
    pub(crate) carrier_probe: Option<Duration>,
}

/// The top-level `"budgets"` object, one name per wait. A name this tree does not know is refused rather than ignored, because a typo in a budget reads as the default it did not set.
pub(crate) fn budgets(root: &Json) -> Result<Budgets, String> {
    let mut out = Budgets::default();
    let Some(section) = root.get("budgets") else {
        return Ok(out);
    };
    let Json::Obj(pairs) = section else {
        return Err("`budgets` is not an object".to_owned());
    };
    for (key, value) in pairs {
        let slot = match key.as_str() {
            "dial" => &mut out.dial,
            "handshake" => &mut out.handshake,
            "headArrival" => &mut out.head_arrival,
            "relayJoin" => &mut out.relay_join,
            "relayQuantum" => &mut out.relay_quantum,
            "relayStall" => &mut out.relay_stall,
            "udpIdle" => &mut out.udp_idle,
            "payloadGrace" => &mut out.payload_grace,
            "goawayGrace" => &mut out.goaway_grace,
            "sinkGrace" => &mut out.sink_grace,
            "carrierProbe" => &mut out.carrier_probe,
            other => return Err(format!("unknown budget `{other}`")),
        };
        *slot = Some(duration(value, key)?);
    }
    Ok(out)
}

/// A Go `time.ParseDuration` string, in nanoseconds, for the xray fields that carry one. A
/// number is read as nanoseconds so the protobuf dialect reaches the same parser.
pub(crate) fn go_duration(value: &Json) -> Result<Option<i64>, String> {
    if let Json::Num(nanos) = value {
        return Ok(Some(*nanos as i64));
    }
    let Some(text) = value.as_str() else {
        return Ok(None);
    };
    let mut nanos = 0i64;
    let mut rest = text.trim();
    if rest.is_empty() {
        return Err("a duration is empty".to_owned());
    }
    if rest == "0" {
        return Ok(Some(0));
    }
    let negative = rest.starts_with('-');
    if negative || rest.starts_with('+') {
        rest = &rest[1..];
    }
    if rest.is_empty() {
        return Err(format!("duration {text:?} is malformed"));
    }
    while !rest.is_empty() {
        let end = rest
            .find(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
            .unwrap_or(rest.len());
        if end == 0 {
            return Err(format!("duration {text:?} is malformed"));
        }
        let amount: f64 = rest[..end]
            .parse()
            .map_err(|_| format!("duration {text:?} is malformed"))?;
        let unit = &rest[end..];
        let (name, scale) = [
            ("ns", 1.0),
            ("us", 1_000.0),
            ("\u{b5}s", 1_000.0),
            ("\u{3bc}s", 1_000.0),
            ("ms", 1_000_000.0),
            ("s", 1_000_000_000.0),
            ("m", 60_000_000_000.0),
            ("h", 3_600_000_000_000.0),
        ]
        .into_iter()
        .find(|(name, _)| unit.starts_with(name))
        .ok_or_else(|| format!("duration {text:?} names no unit"))?;
        let part = (amount * scale) as i64;
        nanos = nanos
            .checked_add(part)
            .ok_or_else(|| format!("duration {text:?} is too large"))?;
        rest = &unit[name.len()..];
    }
    if negative {
        nanos = -nanos;
    }
    Ok(Some(nanos))
}

/// `"30s"` or `"2500ms"`, and nothing else: a bare number is refused because the unit a wait is measured in is not the reader's guess.
fn duration(value: &Json, key: &str) -> Result<Duration, String> {
    let reject = |reason: String| format!("budget `{key}`: {reason}");
    let text = value
        .as_str()
        .ok_or_else(|| reject("expected a string like \"500ms\" or \"30s\"".to_owned()))?;
    let (digits, scale) = match text.strip_suffix("ms") {
        Some(digits) => (digits, 1),
        None => match text.strip_suffix('s') {
            Some(digits) => (digits, 1_000),
            None => return Err(reject(format!("{text:?} names no `ms` or `s` unit"))),
        },
    };
    let count: u64 = digits
        .trim()
        .parse()
        .map_err(|_| reject(format!("{text:?} is not a count")))?;
    if count == 0 {
        return Err(reject("a wait of none is not a budget".to_owned()));
    }
    count
        .checked_mul(scale)
        .map(Duration::from_millis)
        .ok_or_else(|| reject(format!("{text:?} is past a measurable wait")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json_path(path: &std::path::Path) -> String {
        format!(
            "\"{}\"",
            path.to_string_lossy()
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
        )
    }

    fn server_ech_key_tlv() -> Vec<u8> {
        let mut config = vec![0xfe, 0x0d, 0x00, 0x00];
        let mut contents = vec![7u8, 0x00, 0x20, 0x00, 0x20];
        contents.extend_from_slice(&[0x11; 32]);
        contents.extend_from_slice(&4u16.to_be_bytes());
        contents.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        contents.push(0);
        contents.push(b"public.test".len() as u8);
        contents.extend_from_slice(b"public.test");
        contents.extend_from_slice(&0u16.to_be_bytes());
        config[2..4].copy_from_slice(&(contents.len() as u16).to_be_bytes());
        config.extend_from_slice(&contents);
        let mut keys = Vec::new();
        keys.extend_from_slice(&32u16.to_be_bytes());
        keys.extend_from_slice(&[0x22; 32]);
        keys.extend_from_slice(&(config.len() as u16).to_be_bytes());
        keys.extend_from_slice(&config);
        keys
    }

    #[test]
    fn a_short_id_hex_fills_from_the_front() {
        assert_eq!(short_id("a8"), Some([0xa8, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(short_id("01020304"), Some([1, 2, 3, 4, 0, 0, 0, 0]));
        assert_eq!(short_id(""), Some([0, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(short_id("abc"), None);
    }

    #[test]
    fn accept_proxy_protocol_reads_the_carrier_and_sockopt_spellings() {
        let carrier =
            crate::json::parse(r#"{"network":"ws","wsSettings":{"acceptProxyProtocol":true}}"#)
                .expect("a carrier");
        assert!(accept_proxy_protocol(Some(&carrier)));
        let sockopt = crate::json::parse(
            r#"{"network":"raw","tcpSettings":{},"sockopt":{"acceptProxyProtocol":true}}"#,
        )
        .expect("sockopt");
        assert!(accept_proxy_protocol(Some(&sockopt)));
        let plain = crate::json::parse(r#"{"network":"raw"}"#).expect("plain");
        assert!(!accept_proxy_protocol(Some(&plain)));
        assert!(!accept_proxy_protocol(None));
    }

    #[test]
    fn reality_reads_the_references_aliases_and_empty_short_id() {
        let inbound = crate::json::parse(
            r#"{"streamSettings":{"security":"reality","realitySettings":{"privateKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","target":"cover.test:443","shortIds":[""],"serverNames":["www.example.com"]}}}"#,
        )
        .expect("a server");
        let server = inbound_reality_config(&inbound).expect("target and the empty short id");
        assert_eq!(server.dest.as_deref(), Some("cover.test:443"));
        assert_eq!(server.short_ids, vec![[0u8; 8]]);

        let mixed = crate::json::parse(
            r#"{"streamSettings":{"security":"reality","realitySettings":{"privateKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortIds":["","ab"],"serverNames":["www.example.com"]}}}"#,
        )
        .expect("a server with two short ids");
        assert_eq!(
            inbound_reality_config(&mixed)
                .expect("both short ids")
                .short_ids,
            vec![[0u8; 8], [0xab, 0, 0, 0, 0, 0, 0, 0]]
        );

        let outbound = crate::json::parse(
            r#"{"streamSettings":{"security":"reality","realitySettings":{"publicKey":"","password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","serverName":"www.example.com","shortId":""}}}"#,
        )
        .expect("a client");
        let client =
            outbound_reality(&outbound, "127.0.0.1").expect("password and the empty short id");
        assert_eq!(client.short_id, [0u8; 8]);

        let (key, counts) = ferrox_core::alloc_count::measure(|| {
            key32("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        });
        assert_eq!(key, Some([0u8; 32]));
        assert_eq!(counts.allocs, 0, "the key is decoded into its array");
    }

    #[test]
    fn reality_mldsa_checks_the_references_lengths_and_the_seed_alias() {
        let seed = "A".repeat(43);
        let private = "B".repeat(43);
        let server = |field: &str| {
            crate::json::parse(&format!(
                r#"{{"streamSettings":{{"security":"reality","realitySettings":{{"privateKey":"{private}"{field}}}}}}}"#
            ))
            .expect("a server")
        };
        let client = |field: &str| {
            crate::json::parse(&format!(
                r#"{{"streamSettings":{{"security":"reality","realitySettings":{{"publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortId":""{field}}}}}}}"#
            ))
            .expect("a client")
        };
        assert_eq!(
            reality_mldsa(&server(&format!(r#","mldsa65Seed":"{seed}""#)), true),
            Ok(true)
        );
        assert_eq!(reality_mldsa(&server(""), true), Ok(false));
        assert_eq!(
            reality_mldsa(&server(r#","mldsa65Seed":"""#), true),
            Ok(false)
        );
        // Go's decoder skips CR and LF, so a wrapped seed is the same seed.
        assert_eq!(
            reality_mldsa(
                &server(&format!(
                    r#","mldsa65Seed":"{}\n{}""#,
                    &seed[..21],
                    &seed[21..]
                )),
                true
            ),
            Ok(true)
        );
        assert_eq!(
            reality_mldsa(&server(&format!(r#","mldsa65Seed":"{private}""#)), true),
            Err(r#""mldsa65Seed" and "privateKey" can not be the same value"#.to_owned())
        );
        // A CR/LF-wrapped spelling decodes to the same 32 bytes, so the alias check compares bytes.
        assert_eq!(
            reality_mldsa(
                &server(&format!(
                    r#","mldsa65Seed":"{}\r\n{}""#,
                    &private[..21],
                    &private[21..]
                )),
                true
            ),
            Err(r#""mldsa65Seed" and "privateKey" can not be the same value"#.to_owned())
        );
        assert_eq!(
            reality_mldsa(&server(r#","mldsa65Seed":7"#), true),
            Err(r#""mldsa65Seed" is not a string"#.to_owned())
        );
        let short = "A".repeat(42);
        assert_eq!(
            reality_mldsa(&server(&format!(r#","mldsa65Seed":"{short}""#)), true),
            Err(r#"invalid "mldsa65Seed": it does not decode to 32 bytes"#.to_owned())
        );
        let verify = "A".repeat(2603);
        assert_eq!(
            reality_mldsa(&client(&format!(r#","mldsa65Verify":"{verify}""#)), false),
            Ok(true)
        );
        assert_eq!(
            reality_mldsa(&client(&format!(r#","mldsa65Verify":"{seed}""#)), false),
            Err(r#"invalid "mldsa65Verify": it does not decode to 1952 bytes"#.to_owned())
        );
        let tls = crate::json::parse(
            r#"{"streamSettings":{"security":"tls","tlsSettings":{"mldsa65Seed":"x"}}}"#,
        )
        .expect("tls");
        assert_eq!(reality_mldsa(&tls, true), Ok(false));

        let (decoded, counts) = ferrox_core::alloc_count::measure(|| b64url_len(&verify));
        assert_eq!(decoded, Some(1952));
        assert_eq!(counts.allocs, 0, "the length is counted, not the bytes");
    }

    #[test]
    fn a_hysteria_carrier_reads_the_udp_idle_and_the_quic_params() {
        use ferrox_core::hysteria::{BbrProfile, Congestion, QuicParams};
        let carrier = |text: &str| {
            stream_carrier(
                crate::json::parse(text)
                    .expect("parses")
                    .get("streamSettings"),
            )
        };
        let Carrier::Hysteria(config) = carrier(
            r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2, "udpIdleTimeout": 5}, "finalmask": {"quicParams": {"congestion": "brutal", "brutalUp": "10 mbps", "brutalDown": "10 mbps", "initStreamReceiveWindow": 65536, "maxIdleTimeout": 10, "keepAlivePeriod": 5, "maxIncomingStreams": 32}}}}"#,
        ) else {
            panic!("a tuned hysteria carrier");
        };
        assert_eq!(
            config.udp_idle, 5,
            "the association reaper takes the config"
        );
        let params = config.quic.expect("the block reaches the QUIC config");
        assert_eq!(params.cc, Some(Congestion::Brutal));
        assert_eq!(params.brutal_up, 10 * 1024 * 1024 / 8);
        assert_eq!(params.brutal_down, 10 * 1024 * 1024 / 8);
        assert_eq!(params.init_stream_window, 65536);
        assert_eq!(params.max_idle, 10);
        assert_eq!(params.keep_alive, 5);
        assert_eq!(params.max_incoming_streams, 32);
        assert_eq!(params.bbr_profile, BbrProfile::Standard);
        assert_eq!(
            QuicParams::stream_window(0, false),
            8 * 1024 * 1024,
            "an unset window is the reference's 8 MiB"
        );
        assert_eq!(
            QuicParams::stream_window(0, true),
            8 * 1024 * 1024 * 5 / 2,
            "an unset connection window is two and a half stream windows"
        );

        // Without the block nothing changes: the tree's fixed reaper and tuning stand.
        let Carrier::Hysteria(plain) = carrier(
            r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}}}"#,
        ) else {
            panic!("a plain hysteria carrier");
        };
        assert_eq!(plain.udp_idle, 60);
        assert_eq!(plain.quic, None);

        // A present block owns the congestion the way xray's does, its own default included; the stream's extra spelling applies only when no block names one.
        let cc_of = |text: &str| match carrier(text) {
            Carrier::Hysteria(config) => config.cc,
            other => panic!("a hysteria carrier, not {other:?}"),
        };
        assert_eq!(
            cc_of(
                r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2, "congestion": "reno"}, "finalmask": {"quicParams": {}}}}"#
            ),
            Congestion::Brutal,
            "an empty block is xray's default, not the stream's spelling"
        );
        assert_eq!(
            cc_of(
                r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2, "congestion": "reno"}, "finalmask": {"quicParams": {"congestion": "bbr"}}}}"#
            ),
            Congestion::Bbr,
            "the block's name wins"
        );
        let Carrier::Hysteria(empty) = carrier(
            r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}, "finalmask": {"quicParams": {}}}}"#,
        ) else {
            panic!("an empty block is carried");
        };
        assert_eq!(
            empty.quic.expect("the empty block still reaches the lane"),
            QuicParams {
                cc: Some(Congestion::Brutal),
                ..QuicParams::default()
            },
            "every unset field waits for the reference's default"
        );

        // The reference's bounds and names refuse the carrier rather than silently applying a default.
        for bad in [
            r#"{"network": "hysteria", "hysteriaSettings": {"version": 2, "udpIdleTimeout": 1}}"#,
            r#"{"network": "hysteria", "hysteriaSettings": {"version": 2, "udpIdleTimeout": 601}}"#,
            r#"{"network": "hysteria", "hysteriaSettings": {"version": 2}, "finalmask": {"quicParams": {"maxIdleTimeout": 3}}}"#,
            r#"{"network": "hysteria", "hysteriaSettings": {"version": 2}, "finalmask": {"quicParams": {"maxIdleTimeout": 121}}}"#,
            r#"{"network": "hysteria", "hysteriaSettings": {"version": 2}, "finalmask": {"quicParams": {"congestion": "vegas"}}}"#,
            r#"{"network": "hysteria", "hysteriaSettings": {"version": 2}, "finalmask": {"quicParams": {"congestion": "force-brutal"}}}"#,
            r#"{"network": "hysteria", "hysteriaSettings": {"version": 2}, "finalmask": {"quicParams": {"brutalUp": "1000"}}}"#,
            r#"{"network": "hysteria", "hysteriaSettings": {"version": 2}, "finalmask": {"quicParams": {"initStreamReceiveWindow": 100}}}"#,
            r#"{"network": "hysteria", "hysteriaSettings": {"version": 2}, "finalmask": {"quicParams": {"keepAlivePeriod": 1}}}"#,
            r#"{"network": "hysteria", "hysteriaSettings": {"version": 2}, "finalmask": {"quicParams": {"maxIncomingStreams": 7}}}"#,
            r#"{"network": "hysteria", "hysteriaSettings": {"version": 2}, "finalmask": {"quicParams": {"bbrProfile": "turbo"}}}"#,
        ] {
            let text = format!(r#"{{"streamSettings": {bad}}}"#);
            assert!(
                matches!(carrier(&text), Carrier::Unknown { .. }),
                "{text} must be refused"
            );
        }
    }

    #[test]
    fn a_hysteria_carrier_reads_a_null_quic_field_as_the_reference_zero() {
        use ferrox_core::hysteria::Congestion;
        let carrier = |text: &str| {
            stream_carrier(
                crate::json::parse(text)
                    .expect("parses")
                    .get("streamSettings"),
            )
        };
        let Carrier::Hysteria(null_idle) = carrier(
            r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2, "udpIdleTimeout": null}}}"#,
        ) else {
            panic!("a null idle is the default");
        };
        assert_eq!(null_idle.udp_idle, 60);
        let Carrier::Hysteria(null_block) = carrier(
            r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}, "finalmask": {"quicParams": null}}}"#,
        ) else {
            panic!("a null block is no block");
        };
        assert_eq!(null_block.quic, None);
        let Carrier::Hysteria(null_fields) = carrier(
            r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}, "finalmask": {"quicParams": {"congestion": null, "bbrProfile": null, "brutalUp": null, "maxIdleTimeout": null, "disablePathMTUDiscovery": null, "disableStatelessReset": null}}}}"#,
        ) else {
            panic!("null fields are zero values");
        };
        let params = null_fields.quic.expect("the block is present");
        assert_eq!(params.cc, Some(Congestion::Brutal));
        assert_eq!(params.max_idle, 0);
        assert_eq!(params.brutal_up, 0);
        assert!(!params.no_path_mtu);
        assert!(!params.disable_stateless_reset);
    }

    #[test]
    fn a_hysteria_carrier_carries_salamander_and_refuses_what_it_cannot_mask() {
        let carrier = |text: &str| {
            stream_carrier(
                crate::json::parse(text)
                    .expect("parses")
                    .get("streamSettings"),
            )
        };
        // A named salamander with a usable password reaches the wire as that password.
        let Carrier::Hysteria(config) = carrier(
            r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}, "tlsSettings": {"obfs": "salamander", "obfs-password": "gawrgura"}}}"#,
        ) else {
            panic!("a salamander carrier");
        };
        assert_eq!(config.obfs_password, "gawrgura", "the key the config named");
        // No obfs is cleartext, so the password stays empty.
        let Carrier::Hysteria(clear) = carrier(
            r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}}}"#,
        ) else {
            panic!("a v2 hysteria carrier");
        };
        assert_eq!(clear.obfs_password, "", "cleartext names no key");
        // A different named obfuscation is refused, not silently sent in the clear.
        assert!(matches!(
            carrier(
                r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}, "tlsSettings": {"obfs": "xray-obfs"}}}"#
            ),
            Carrier::Unknown { .. }
        ));
        // A salamander whose password is too short to mask with is refused for the same reason.
        assert!(matches!(
            carrier(
                r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}, "tlsSettings": {"obfs": "salamander", "obfs-password": "ab"}}}"#
            ),
            Carrier::Unknown { .. }
        ));
    }

    #[test]
    fn a_hysteria_carrier_reads_a_port_hopping_plan() {
        let planned = |text: &str| {
            let Carrier::Hysteria(config) = stream_carrier(
                crate::json::parse(text)
                    .expect("parses")
                    .get("streamSettings"),
            ) else {
                panic!("a v2 hysteria carrier");
            };
            config.hop
        };
        // A comma spec of a range and a lone port, bounded in seconds and one with a unit, expands to the sorted set the dial rotates over.
        let spec = r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2, "serverPorts": "20000-20002,443", "hopInterval": 5, "hopIntervalMax": "10s"}}}"#;
        let plan = planned(spec).expect("a plan");
        assert_eq!(plan.ports(), vec![443, 20_000, 20_001, 20_002]);
        assert_eq!(
            plan.interval_ms,
            (5_000, 10_000),
            "seconds reach the dial as ms"
        );
        // An array of numbers and range strings is the same plan; with no interval the stay defaults to a fixed five seconds.
        let arr = r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2, "serverPorts": [443, "9000-9001"]}}}"#;
        let plan = planned(arr).expect("a plan");
        assert_eq!(plan.ports(), vec![443, 9_000, 9_001]);
        assert_eq!(plan.interval_ms, (5_000, 5_000), "an absent stay is fixed");
        // A malformed port spec leaves no valid range, so the dial stays on its fixed port rather than routing to a port the config never named.
        assert!(
            planned(r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2, "serverPorts": "0,70000"}}}"#)
                .is_none(),
            "nothing valid means no hop"
        );
    }

    #[test]
    fn a_hysteria_carrier_reads_a_gecko_window() {
        use ferrox_core::hysteria::Gecko;
        let carrier = |text: &str| {
            stream_carrier(
                crate::json::parse(text)
                    .expect("parses")
                    .get("streamSettings"),
            )
        };
        // A gecko obfs with the sing-box bounds keeps its shared key and reaches the dial as that window.
        let Carrier::Hysteria(config) = carrier(
            r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}, "tlsSettings": {"obfs": "gecko", "obfs-password": "gawrgura", "min_packet_size": 600, "max_packet_size": 1000}}}"#,
        ) else {
            panic!("a gecko carrier");
        };
        assert_eq!(
            config.obfs_password, "gawrgura",
            "gecko masks with the shared key"
        );
        assert_eq!(
            config.gecko,
            Some(Gecko {
                min_pkt: 600,
                max_pkt: 1000
            })
        );
        // The reference's `packetSize` range, in object form, names the same window.
        let Carrier::Hysteria(range) = carrier(
            r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}, "tlsSettings": {"obfs": "gecko", "obfs-password": "gawrgura", "packetSize": {"from": 700, "to": 900}}}}"#,
        ) else {
            panic!("a gecko carrier");
        };
        assert_eq!(
            range.gecko,
            Some(Gecko {
                min_pkt: 700,
                max_pkt: 900
            }),
            "the camel form is the same window"
        );
        // A gecko that names no bounds takes the reference defaults.
        let Carrier::Hysteria(defaults) = carrier(
            r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}, "tlsSettings": {"obfs": "gecko", "obfs-password": "gawrgura"}}}"#,
        ) else {
            panic!("a gecko carrier");
        };
        assert_eq!(
            defaults.gecko,
            Gecko::new(0, 0),
            "an absent window is defaulted"
        );
        // A salamander obfs is not a gecko: the same key, no fragmentation window.
        let Carrier::Hysteria(salamander) = carrier(
            r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}, "tlsSettings": {"obfs": "salamander", "obfs-password": "gawrgura"}}}"#,
        ) else {
            panic!("a salamander carrier");
        };
        assert_eq!(salamander.gecko, None, "salamander never fragments");
        // A window past the largest frame is refused, not silently carried as a plain salamander.
        assert!(matches!(
            carrier(
                r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}, "tlsSettings": {"obfs": "gecko", "obfs-password": "gawrgura", "min_packet_size": 100, "max_packet_size": 5000}}}"#
            ),
            Carrier::Unknown { .. }
        ));
    }

    #[test]
    fn a_hysteria_carrier_reads_a_realm_rendezvous() {
        use ferrox_core::realm::Family;
        let realm = |text: &str| {
            let Carrier::Hysteria(config) = stream_carrier(
                crate::json::parse(text)
                    .expect("parses")
                    .get("streamSettings"),
            ) else {
                panic!("a hysteria carrier");
            };
            config.realm
        };
        // The sing-box spelling: one `server_url` plus `realm_id`, an ip version and a STUN list.
        let box_form = r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2, "realm": {"server_url": "https://realm.example.com:8443", "token": "tok", "realm_id": "slot-1", "stun_servers": ["stun.example.com:3478"], "ip_version": 4}}}}"#;
        let parsed = realm(box_form).expect("a realm");
        let parsed = &*parsed;
        assert_eq!(parsed.scheme, "https");
        assert_eq!(parsed.host, "realm.example.com");
        assert_eq!(parsed.port, 8443);
        assert_eq!(parsed.token, "tok");
        assert_eq!(parsed.id, "slot-1");
        assert_eq!(parsed.stun_servers, vec!["stun.example.com:3478"]);
        assert_eq!(parsed.family, Family::V4);
        // The xray spelling: `scheme`/`host`/`port` with `ID`, read from `finalmask.realm`.
        let xray_form = r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}, "finalmask": {"realm": {"scheme": "http", "host": "realm.example", "port": 8080, "token": "tok", "ID": "slot_2", "stun_servers": ["192.0.2.1"], "IPMode": "v6"}}}}"#;
        let parsed = realm(xray_form).expect("a realm");
        let parsed = &*parsed;
        assert_eq!(parsed.scheme, "http");
        assert_eq!(parsed.host, "realm.example");
        assert_eq!(parsed.port, 8080);
        assert_eq!(parsed.id, "slot_2");
        assert_eq!(parsed.family, Family::V6);
        // The udp chain's `type: realm` entry is the same dial through a third spelling.
        let chain_form = r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2}, "finalmask": {"udp": [{"type": "realm", "settings": {"scheme": "http", "host": "realm.example", "port": 80, "ID": "slot3", "stun_servers": ["198.51.100.1:3478"]}}]}}}"#;
        let parsed = realm(chain_form).expect("a realm");
        assert_eq!(parsed.as_ref().id, "slot3");
        assert_eq!(parsed.as_ref().family, Family::Dual);
        // A realm with no slot, no origin or no STUN server is refused rather than dialled direct.
        assert!(matches!(
            stream_carrier(
                crate::json::parse(r#"{"streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2, "realm": {"server_url": "https://realm.example", "stun_servers": ["stun.example"]}}}}"#)
                    .expect("parses")
                    .get("streamSettings"),
            ),
            Carrier::Unknown { .. }
        ));
    }

    #[test]
    fn a_hysteria_masquerade_reads_its_nested_json_object() {
        use ferrox_core::hysteria::Masquerade;
        let read = |json: &str| {
            let root = crate::json::parse(json).expect("parses");
            masquerade_from_stream(root.get("streamSettings"))
        };
        assert_eq!(
            read(
                r#"{"streamSettings": {"hysteriaSettings": {"masquerade": {"type": "FILE", "dir": "/var/www/cover"}}}}"#
            ),
            Masquerade::File {
                dir: "/var/www/cover".to_owned()
            }
        );
        assert_eq!(
            read(
                r#"{"streamSettings": {"hysteriaSettings": {"masquerade": {"type": "proxy", "url": "https://origin.example", "rewriteHost": true, "xForwarded": true, "insecure": true}}}}"#
            ),
            Masquerade::Proxy {
                url: "https://origin.example".to_owned(),
                rewrite_host: true,
                x_forwarded: true,
                insecure: true,
            }
        );
        assert_eq!(
            read(
                r#"{"streamSettings": {"hysteriaSettings": {"masquerade": {"type": "string", "content": "<html>cover</html>", "headers": {"content-type": "text/html", "x-frame-options": "DENY"}, "statusCode": 418}}}}"#
            ),
            Masquerade::Response {
                status: 418,
                headers: vec![
                    ("content-type".to_owned(), "text/html".to_owned()),
                    ("x-frame-options".to_owned(), "DENY".to_owned()),
                ],
                body: b"<html>cover</html>".to_vec(),
            }
        );
        assert_eq!(
            read(
                r#"{"streamSettings": {"hysteriaSettings": {"masqType": "file", "masqFile": "/tmp/cover"}}}"#
            ),
            Masquerade::File {
                dir: "/tmp/cover".to_owned()
            }
        );
    }

    #[test]
    fn tls_cipher_suites_carries_the_crafted_field() {
        let with = crate::json::parse(
            r#"{"tlsSettings": {"cipherSuites": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256","maxVersion":"1.3","minVersion":"1.3"}}"#,
        )
        .expect("parses")
        .get("tlsSettings")
        .cloned()
        .expect("tlsSettings");
        // A TLS 1.3-only hello is the reference trio, reordered into crypto/tls order.
        assert_eq!(tls_cipher_suites(Some(&with)), vec![0x1301, 0x1302, 0x1303]);
        // No cipherSuites means stock ordering, so the backend is left untouched.
        let none = crate::json::parse(r#"{"tlsSettings": {}}"#)
            .expect("parses")
            .get("tlsSettings")
            .cloned()
            .expect("tlsSettings");
        assert_eq!(tls_cipher_suites(Some(&none)), [] as [u16; 0]);
    }

    #[test]
    fn a_relative_certificate_resolves_under_xray_location_cert() {
        static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = ENV
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let minted = rcgen::generate_simple_self_signed(vec!["cert-location.test".to_owned()])
            .expect("mints");
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ferrox-cert-location-{}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("creates");
        let cert = format!("cert-location-{stamp}.pem");
        let key = format!("key-location-{stamp}.pem");
        std::fs::write(dir.join(&cert), minted.cert.pem()).expect("cert");
        std::fs::write(dir.join(&key), minted.signing_key.serialize_pem()).expect("key");
        let _env = crate::router::ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous = std::env::var_os("XRAY_LOCATION_CERT");
        std::env::set_var("XRAY_LOCATION_CERT", &dir);
        let config = crate::json::parse(&format!(
            r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{"certificates": [{{"certificateFile": "{cert}", "keyFile": "{key}"}}]}}}}}}"#
        ))
        .expect("parses");
        let identity = inbound_tls_identity(&config);
        match previous {
            Some(value) => std::env::set_var("XRAY_LOCATION_CERT", value),
            None => std::env::remove_var("XRAY_LOCATION_CERT"),
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            identity.is_some(),
            "a relative certificateFile must resolve under XRAY_LOCATION_CERT"
        );
    }

    #[test]
    fn inbound_tls_identity_reads_an_inline_certificate() {
        use base64::Engine as _;
        let minted =
            rcgen::generate_simple_self_signed(vec!["tls.test".to_owned()]).expect("mints");
        let keys = server_ech_key_tlv();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&keys);
        let lines_json = |pem: &str| -> String {
            pem.trim_end()
                .lines()
                .map(|line| format!("\"{line}\""))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let string_json = |pem: &str| -> String {
            format!(
                "\"{}\"",
                pem.trim_end().replace('\r', "").replace('\n', "\\n")
            )
        };
        // The array-of-lines spelling a REALITY decoy hands over.
        let array_form = crate::json::parse(&format!(
            r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{"certificates": [{{"certificate": [{}], "key": [{}]}}]}}}}}}"#,
            lines_json(&minted.cert.pem()),
            lines_json(&minted.signing_key.serialize_pem())
        ))
        .expect("parses");
        assert!(
            inbound_tls_identity(&array_form).is_some(),
            "an inline certificate/key array loads, so the inbound binds"
        );
        // The single-string spelling resolves to the same identity.
        let string_form = crate::json::parse(&format!(
            r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{"echServerKeys": "{encoded}", "certificates": [{{"certificate": {}, "key": {}}}]}}}}}}"#,
            string_json(&minted.cert.pem()),
            string_json(&minted.signing_key.serialize_pem())
        ))
        .expect("parses");
        let identity = inbound_tls_identity(&string_form).expect("an inline string loads too");
        assert_eq!(
            identity.ech_server_keys.as_deref(),
            Some(keys.as_slice()),
            "the inbound carries the parsed ECH keys into its TLS identity"
        );
    }

    #[test]
    fn a_carrier_that_owns_tls_reads_the_same_certificate_list() {
        let string_json = |pem: &str| -> String {
            format!(
                "\"{}\"",
                pem.trim_end().replace('\r', "").replace('\n', "\\n")
            )
        };
        let first =
            rcgen::generate_simple_self_signed(vec!["first.test".to_owned()]).expect("mints");
        let second =
            rcgen::generate_simple_self_signed(vec!["second.test".to_owned()]).expect("mints");
        let config = crate::json::parse(&format!(
            r#"{{"streamSettings": {{"tlsSettings": {{"certificates": [{{"certificate": {}, "key": {}}}, {{"certificate": {}, "key": {}}}]}}}}}}"#,
            string_json(&first.cert.pem()),
            string_json(&first.signing_key.serialize_pem()),
            string_json(&second.cert.pem()),
            string_json(&second.signing_key.serialize_pem())
        ))
        .expect("parses");
        let settings = config.get("streamSettings").expect("settings");
        let identity = tls_identity_from_settings(settings).expect("loads");
        assert_eq!(identity.certs.len(), 2);
        assert_eq!(
            identity.certs[0].cert_chain[0].as_slice(),
            first.cert.der().as_ref()
        );
        assert_eq!(
            identity.certs[1].cert_chain[0].as_slice(),
            second.cert.der().as_ref()
        );
    }

    fn inbound_tls_identity_with(
        settings: &str,
    ) -> (Arc<ferrox_core::tls::TlsServerConfig>, Vec<u8>) {
        let minted =
            rcgen::generate_simple_self_signed(vec!["tls.test".to_owned()]).expect("mints");
        let string_json = |pem: &str| -> String {
            format!(
                "\"{}\"",
                pem.trim_end().replace('\r', "").replace('\n', "\\n")
            )
        };
        let config = crate::json::parse(&format!(
            r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{{settings}, "certificates": [{{"certificate": {}, "key": {}}}]}}}}}}"#,
            string_json(&minted.cert.pem()),
            string_json(&minted.signing_key.serialize_pem())
        ))
        .expect("parses");
        let identity = inbound_tls_identity(&config).expect("the inline identity loads");
        (identity, minted.cert.der().as_ref().to_vec())
    }

    #[test]
    fn the_tls_listener_selects_the_configured_alpn() {
        use ferrox_core::tls::{TlsConfig, TlsProvider as _};
        let (identity, cert) = inbound_tls_identity_with(r#""alpn": ["h2"]"#);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let (stream, _) = listener.accept().expect("accepts");
                let mut server = ferrox_core::tls::accept(&identity, stream).expect("accepts");
                server.handshake().expect("handshakes");
            });
            let stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let config = TlsConfig {
                server_name: "tls.test".to_owned(),
                alpn: vec![b"h2".to_vec()].into(),
                roots: vec![cert].into(),
                ..TlsConfig::default()
            };
            let mut client = ferrox_core::tls::connect(&config, stream).expect("configures");
            client.handshake().expect("handshakes");
            assert_eq!(
                client.alpn(),
                Some(b"h2".as_slice()),
                "the listener advertises the configured ALPN"
            );
        });
    }

    fn tls_handshake(
        identity: &Arc<ferrox_core::tls::TlsServerConfig>,
        cert: Vec<u8>,
        sni: &str,
    ) -> (bool, bool) {
        use ferrox_core::tls::TlsProvider as _;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        std::thread::scope(|scope| {
            let server = scope.spawn(|| {
                let (stream, _) = listener.accept().expect("accepts");
                let Ok(mut server) = ferrox_core::tls::accept(identity, stream) else {
                    return false;
                };
                server.handshake().is_ok()
            });
            let stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let config = ferrox_core::tls::TlsConfig {
                server_name: sni.to_owned(),
                roots: vec![cert].into(),
                ..ferrox_core::tls::TlsConfig::default()
            };
            let client = ferrox_core::tls::connect(&config, stream)
                .is_ok_and(|mut client| client.handshake().is_ok());
            (server.join().expect("server thread"), client)
        })
    }

    #[test]
    fn a_tls_listener_refuses_an_unknown_sni_when_asked() {
        let (identity, cert) = inbound_tls_identity_with(r#""rejectUnknownSni": true"#);
        assert_eq!(
            tls_handshake(&identity, cert.clone(), "tls.test"),
            (true, true),
            "the certificate's own name still completes both sides"
        );
        assert_eq!(
            tls_handshake(&identity, cert, "other.test"),
            (false, false),
            "rejectUnknownSni aborts an SNI no certificate name matches"
        );
    }

    /// A private CA and the leaf it signs: the pair a config that names its own trust anchor carries.
    fn ca_and_leaf(host: &str) -> (String, rcgen::CertifiedKey<rcgen::KeyPair>) {
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "ferrox test ca");
        let ca_key = rcgen::KeyPair::generate().expect("ca key");
        let ca = ca_params.self_signed(&ca_key).expect("ca");
        let mut leaf_params = rcgen::CertificateParams::new(vec![host.to_owned()]).expect("params");
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, host);
        let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
        let leaf = leaf_params
            .signed_by(&leaf_key, &rcgen::Issuer::from_params(&ca_params, &ca_key))
            .expect("leaf");
        (
            ca.pem(),
            rcgen::CertifiedKey {
                cert: leaf,
                signing_key: leaf_key,
            },
        )
    }

    fn server_identity(
        leaf: &rcgen::CertifiedKey<rcgen::KeyPair>,
    ) -> Arc<ferrox_core::tls::TlsServerConfig> {
        server_identity_with(leaf, "")
    }

    /// The same identity with more `tlsSettings` fields, spelled as a JSON fragment that follows the certificates.
    fn server_identity_with(
        leaf: &rcgen::CertifiedKey<rcgen::KeyPair>,
        settings: &str,
    ) -> Arc<ferrox_core::tls::TlsServerConfig> {
        let string_json = |pem: &str| {
            format!(
                "\"{}\"",
                pem.trim_end().replace('\r', "").replace('\n', "\\n")
            )
        };
        let config = crate::json::parse(&format!(
            r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{"certificates": [{{"certificate": {}, "key": {}}}] {settings}}}}}}}"#,
            string_json(&leaf.cert.pem()),
            string_json(&leaf.signing_key.serialize_pem())
        ))
        .expect("parses");
        inbound_tls_identity(&config).expect("the leaf is an identity")
    }

    /// Whether an outbound built from this JSON verifies the listener: the config builds, the hello
    /// completes on both sides, and the peer answers.
    fn outbound_handshake(
        identity: &Arc<ferrox_core::tls::TlsServerConfig>,
        outbound: &Json,
    ) -> bool {
        use ferrox_core::tls::TlsProvider as _;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        std::thread::scope(|scope| {
            let server = scope.spawn(|| {
                let (stream, _) = listener.accept().expect("accepts");
                ferrox_core::tls::accept(identity, stream)
                    .is_ok_and(|mut server| server.handshake().is_ok())
            });
            let stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let client = outbound_tls(outbound, "127.0.0.1").is_ok_and(|config| {
                ferrox_core::tls::connect(&config, stream)
                    .is_ok_and(|mut client| client.handshake().is_ok())
            });
            client && server.join().expect("server thread")
        })
    }

    #[test]
    fn an_outbound_trusts_the_certificates_its_config_names() {
        let (ca_pem, leaf) = ca_and_leaf("tls.test");
        let (other_pem, _other) = ca_and_leaf("tls.test");
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ferrox-client-anchor-{}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("creates");
        let ca = dir.join("ca.pem");
        let other = dir.join("other.pem");
        std::fs::write(&ca, ca_pem).expect("the test ca");
        std::fs::write(&other, other_pem).expect("a second ca");
        let identity = server_identity(&leaf);
        let client = |path: &std::path::Path| {
            crate::json::parse(&format!(
                r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{"serverName": "tls.test", "disableSystemRoot": true, "certificates": [{{"certificateFile": {}}}]}}}}}}"#,
                json_path(path)
            ))
            .expect("parses")
        };
        let trusted = outbound_handshake(&identity, &client(&ca));
        let wrong = outbound_handshake(&identity, &client(&other));
        let missing = outbound_handshake(
            &identity,
            &crate::json::parse(
                r#"{"streamSettings": {"security": "tls", "tlsSettings": {"serverName": "tls.test", "disableSystemRoot": true}}}"#,
            )
            .expect("parses"),
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            trusted,
            "a certificates entry is a trust anchor, so the leaf's chain verifies"
        );
        assert!(
            !wrong,
            "a different CA's certificate does not anchor this chain"
        );
        assert!(
            !missing,
            "with no anchor at all the same listener is refused"
        );
    }

    #[test]
    fn an_outbound_reads_the_client_certificate_its_entry_names() {
        let (_ca_pem, leaf) = ca_and_leaf("tls.test");
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("ferrox-client-cert-{}-{stamp}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("creates");
        let cert = dir.join("client.pem");
        let key = dir.join("client.key");
        std::fs::write(&cert, leaf.cert.pem()).expect("the client cert");
        std::fs::write(&key, leaf.signing_key.serialize_pem()).expect("the client key");
        let outbound = |extra: &str| {
            crate::json::parse(&format!(
                r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{"serverName": "tls.test", "certificates": [{{"certificateFile": {}, "keyFile": {}{extra}}}]}}}}}}"#,
                json_path(&cert),
                json_path(&key)
            ))
            .expect("parses")
        };
        let tls = outbound_tls(&outbound(""), "127.0.0.1").expect("builds");
        let identity = tls.client_cert.as_ref().expect("a client identity");
        assert_eq!(
            identity.cert_chain,
            crate::quic::parse_ca_pem(leaf.cert.pem().as_bytes()),
            "the identity is the chain the entry names"
        );
        assert_eq!(
            identity.key_der,
            leaf.signing_key.serialize_der(),
            "the identity signs with the key the entry names"
        );
        let issuing =
            outbound_tls(&outbound(r#", "usage": "issue""#), "127.0.0.1").expect("builds");
        assert!(
            issuing.client_cert.is_none(),
            "an issuing authority is not a client identity"
        );
        let missing = crate::json::parse(&format!(
            r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{"serverName": "tls.test", "certificates": [{{"certificateFile": {}, "keyFile": "/no-such-dir/client.key"}}]}}}}}}"#,
            json_path(&cert)
        ))
        .expect("parses");
        assert!(
            outbound_tls(&missing, "127.0.0.1").is_err(),
            "a key file the config names but cannot read refuses the build, as xray's does"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_named_anchor_joins_the_platform_store() {
        let (ca_pem, _leaf) = ca_and_leaf("tls.test");
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ferrox-client-union-{}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("creates");
        let ca = dir.join("ca.pem");
        std::fs::write(&ca, ca_pem).expect("the test ca");
        let config = |disable: bool| {
            let outbound = crate::json::parse(&format!(
                r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{"serverName": "tls.test", "disableSystemRoot": {disable}, "certificates": [{{"certificateFile": {}}}]}}}}}}"#,
                json_path(&ca)
            ))
            .expect("parses");
            outbound_tls(&outbound, "127.0.0.1").expect("builds")
        };
        let strict = config(true);
        let union = config(false);
        let system = crate::quic::system_roots();
        let untouched = tls_client_roots(Vec::new(), std::sync::Arc::clone(&system));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            std::sync::Arc::ptr_eq(&untouched, &system),
            "a config that names no anchor keeps the store's one allocation"
        );
        assert_eq!(
            strict.roots.len(),
            1,
            "disableSystemRoot keeps the named anchor alone"
        );
        assert!(
            union.roots.iter().any(|der| der == &strict.roots[0]),
            "the named anchor survives the union"
        );
        assert_eq!(
            union.roots.len(),
            system.len() + 1,
            "the named anchor is appended to the store, not instead of it"
        );
    }

    /// A client that trusts `ca` by file and logs its secrets to `log`, with `extra` spliced among
    /// its `tlsSettings` fields.
    fn key_log_client(ca: &std::path::Path, log: &std::path::Path, extra: &str) -> Json {
        crate::json::parse(&format!(
            r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{"serverName": "tls.test", "disableSystemRoot": true, {extra}"certificates": [{{"certificateFile": {}}}], "masterKeyLog": {}}}}}}}"#,
            json_path(ca),
            json_path(log)
        ))
        .expect("parses")
    }

    /// Asserts `text` carries a `label` line and that every line is NSS form: the label, the client
    /// random and the secret, as lowercase hex.
    fn assert_nss_log(text: &str, label: &str, what: &str) {
        assert!(
            text.lines().any(|line| line.starts_with(label)),
            "{what}: {text}"
        );
        for line in text.lines() {
            let fields: Vec<&str> = line.split(' ').collect();
            assert_eq!(
                fields.len(),
                3,
                "NSS form is the label, the client random and the secret: {line}"
            );
            assert!(
                fields[1].len() == 64 && fields[2].len() >= 64,
                "a random is 32 bytes and a secret at least 32, as hex: {line}"
            );
            assert!(
                fields[1..].iter().all(|hex| hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
                "the bytes are lowercase hex: {line}"
            );
        }
    }

    /// xray's `masterKeyLog`: the handshake's traffic secrets land in the file the config names, in
    /// NSS form, so a capture decrypts offline; a path that cannot be opened is logged and the dial
    /// proceeds without it.
    #[test]
    fn a_master_key_log_records_the_secrets_the_config_names() {
        let (ca_pem, leaf) = ca_and_leaf("tls.test");
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ferrox-master-key-log-{}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("creates");
        let ca = dir.join("ca.pem");
        std::fs::write(&ca, ca_pem).expect("the test ca");
        let identity = server_identity(&leaf);
        let dial = |against: &Arc<ferrox_core::tls::TlsServerConfig>, name: &str, extra: &str| {
            let log = dir.join(name);
            let config = key_log_client(&ca, &log, extra);
            assert!(
                outbound_handshake(against, &config),
                "the dial completes with a key log"
            );
            std::fs::read_to_string(&log).expect("the log the config named")
        };
        let one = dial(&identity, "first.log", "");
        // A second outbound naming another file shares every other input, so a cache keyed without the log would hand it the first dial's logger.
        let two = dial(&identity, "second.log", "");
        // A named fingerprint of `unsafe` dials through stock rustls, the other client build a key log reaches.
        let stock = dial(&identity, "stock.log", r#""fingerprint": "unsafe", "#);
        // A server whose ceiling is TLS 1.2 makes the shaped hello run its own 1.2 flight.
        let tls12 = dial(
            &server_identity_with(&leaf, r#", "maxVersion": "1.2""#),
            "tls12.log",
            r#""fingerprint": "chrome", "#,
        );
        let server_log = dir.join("server.log");
        let listener = server_identity_with(
            &leaf,
            &format!(r#", "masterKeyLog": {}"#, json_path(&server_log)),
        );
        let _ = dial(&listener, "client-to-listener.log", "");
        let served = std::fs::read_to_string(&server_log).expect("the listener's log");
        let unopenable = key_log_client(&ca, &dir.join("no-such-dir").join("third.log"), "");
        let tolerated = outbound_handshake(&identity, &unopenable);
        let _ = std::fs::remove_dir_all(&dir);
        assert_nss_log(
            &one,
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET ",
            "the client's handshake secret is written",
        );
        assert_nss_log(
            &two,
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET ",
            "a second config logs to its own file, not the first dial's",
        );
        assert_nss_log(
            &stock,
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET ",
            "the stock rustls client writes its secrets too",
        );
        assert_nss_log(
            &tls12,
            "CLIENT_RANDOM ",
            "the shaped hello's TLS 1.2 flight logs its master secret",
        );
        assert_nss_log(
            &served,
            "SERVER_HANDSHAKE_TRAFFIC_SECRET ",
            "the listener's own secrets are written",
        );
        assert!(tolerated, "an unopenable log leaves the dial alone");
    }

    #[test]
    fn verify_peer_cert_by_name_checks_the_name_the_config_names() {
        let (ca_pem, leaf) = ca_and_leaf("a.test");
        let identity = server_identity(&leaf);
        let pem_json = |pem: &str| {
            format!(
                "\"{}\"",
                pem.trim_end().replace('\r', "").replace('\n', "\\n")
            )
        };
        let client = |names: Option<&str>| {
            let named = names
                .map(|names| format!(r#""verifyPeerCertByName": "{names}","#))
                .unwrap_or_default();
            crate::json::parse(&format!(
                r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{"serverName": "b.test", {named} "certificates": [{{"certificate": {}}}]}}}}}}"#,
                pem_json(&ca_pem)
            ))
            .expect("parses")
        };
        assert!(
            outbound_handshake(&identity, &client(Some("c.test, a.test"))),
            "the second listed name matches the leaf, so the chain verifies"
        );
        assert!(
            !outbound_handshake(&identity, &client(Some("c.test"))),
            "a chain none of the listed names names is refused"
        );
        assert!(
            !outbound_handshake(&identity, &client(None)),
            "without the field the hello's serverName is the name checked, and it does not match"
        );
    }

    /// xray's `pinnedPeerCertSha256`: the named digest is the whole trust contract, so a leaf it
    /// matches dials with no root store, and one it does not is the pin's refusal.
    #[test]
    fn a_config_carries_the_leaf_pin_it_names() {
        let (_ca, leaf) = ca_and_leaf("tls.test");
        let identity = server_identity(&leaf);
        let digest = ferrox_core::foxy::account::hex_encode(&{
            use sha2::Digest as _;
            sha2::Sha256::digest(leaf.cert.der())
        });
        let client = |pin: &str| {
            crate::json::parse(&format!(
                r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{"serverName": "tls.test", "disableSystemRoot": true, "pinnedPeerCertSha256": "{pin}"}}}}}}"#
            ))
            .expect("parses")
        };
        assert!(
            outbound_handshake(&identity, &client(&digest)),
            "a leaf digest anchors the chain with no root store"
        );
        let colons = digest
            .as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).expect("hex"))
            .collect::<Vec<_>>()
            .join(":");
        assert!(
            outbound_handshake(&identity, &client(&colons)),
            "the OpenSSL colon spelling is the same pin"
        );
        assert!(
            !outbound_handshake(&identity, &client(&"00".repeat(32))),
            "a digest the leaf does not match is refused"
        );
        let error = outbound_tls(&client("zz"), "127.0.0.1").expect_err("bad hex is refused");
        assert!(error.contains("pinnedPeerCertSha256"), "{error}");
    }

    /// xray refuses a `fingerprint` no table knows while the config builds; the same name stops this
    /// startup, and the spellings this tree widens to still build.
    #[test]
    fn an_unknown_fingerprint_is_refused_the_way_the_reference_refuses_it() {
        let config = |name: &str| {
            crate::json::parse(&format!(
                r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{"serverName": "tls.test", "allowInsecure": true, "fingerprint": "{name}"}}}}}}"#
            ))
            .expect("parses")
        };
        let error = outbound_tls(&config("Bogus"), "127.0.0.1").expect_err("a name no table knows");
        assert_eq!(error, r#"unknown "fingerprint": bogus"#);
        for known in ["", "chrome", "unsafe", "hello-firefox_120"] {
            assert!(
                outbound_tls(&config(known), "127.0.0.1").is_ok(),
                "`{known}` builds"
            );
        }
    }

    /// The `supported_groups` ids of a dial's `ClientHello`, read off the socket before the peer
    /// hangs up: the handshake ends in an error, but its first record is already on the wire.
    fn hello_groups(outbound: &Json) -> Vec<u16> {
        use ferrox_core::tls::TlsProvider as _;
        use std::io::Read as _;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let address = listener.local_addr().expect("addr");
        let captured = std::thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accepts");
            let mut head = [0u8; 5];
            peer.read_exact(&mut head).expect("record head");
            let mut record = head.to_vec();
            record.resize(5 + usize::from(u16::from_be_bytes([head[3], head[4]])), 0);
            peer.read_exact(&mut record[5..]).expect("record body");
            record
        });
        let config = outbound_tls(outbound, "127.0.0.1").expect("builds");
        let stream = std::net::TcpStream::connect(address).expect("connects");
        let _ =
            ferrox_core::tls::connect(&config, stream).and_then(|mut client| client.handshake());
        let record = captured.join().expect("capture thread");
        let body = &record[9..];
        let mut at = 2 + 32 + 1 + usize::from(body[2 + 32]);
        at += 2 + (usize::from(body[at]) << 8 | usize::from(body[at + 1]));
        at += 1 + usize::from(body[at]);
        let end = at + 2 + (usize::from(body[at]) << 8 | usize::from(body[at + 1]));
        at += 2;
        while at + 4 <= end {
            let kind = u16::from_be_bytes([body[at], body[at + 1]]);
            let len = usize::from(body[at + 2]) << 8 | usize::from(body[at + 3]);
            at += 4;
            if kind == 0x000a {
                return body[at + 2..at + len]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u16::from_be_bytes(*pair))
                    .collect();
            }
            at += len;
        }
        panic!("the hello offers no supported groups");
    }

    /// xray's `curvePreferences`: the hello offers the named groups, in the order named, on the
    /// shaped client and on the stock one, under either spelling of the list.
    #[test]
    fn a_configured_curve_list_shapes_the_hello_the_dial_sends() {
        let dial = |extra: &str| {
            let outbound = crate::json::parse(&format!(
                r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{"serverName": "tls.test", "allowInsecure": true, {extra}}}}}}}"#
            ))
            .expect("parses");
            hello_groups(&outbound)
        };
        assert_eq!(
            dial(r#""curvePreferences": ["curvep384", "x25519"]"#),
            vec![0x0018, 0x001d],
            "the shaped hello offers the named curves in the named order"
        );
        assert_eq!(
            dial(r#""fingerprint": "unsafe", "curvePreferences": "curvep256,x25519""#),
            vec![0x0017, 0x001d],
            "the stock client names the same list to rustls, from the comma spelling"
        );
        assert_eq!(
            dial(r#""curvePreferences": ["x25519mlkem768", "x25519"]"#),
            vec![0x11ec, 0x001d],
            "the shaped hello draws a share for the ML-KEM hybrid it can carry"
        );
        assert_eq!(
            dial(r#""fingerprint": "unsafe", "curvePreferences": ["x25519mlkem768", "x25519"]"#),
            vec![0x001d],
            "a group ring cannot carry is dropped, not replaced by a stock one"
        );
    }

    /// A group this build cannot carry is named in a warning and dropped, so the hello keeps the
    /// list the build would have offered anyway rather than an empty one no handshake survives.
    #[test]
    fn an_unwired_curve_name_leaves_the_build_its_own_groups() {
        let outbound = crate::json::parse(
            r#"{"streamSettings": {"security": "tls", "tlsSettings": {"serverName": "tls.test", "allowInsecure": true, "curvePreferences": ["curvep521"]}}}"#,
        )
        .expect("parses");
        let groups = hello_groups(&outbound);
        assert!(
            groups.contains(&0x001d),
            "an unwired name leaves the shaped hello its own groups: {groups:?}"
        );
        assert!(
            !groups.contains(&0x0019),
            "and never claims a group the hello carries no share for: {groups:?}"
        );
    }

    /// xray's `enableSessionResumption`: the store a dial keeps is the config's say-so, and an unnamed one keeps no ticket, which is the reference's default.
    #[test]
    fn a_config_carries_the_session_resumption_it_names() {
        let config = |extra: &str| {
            let outbound = crate::json::parse(&format!(
                r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{"serverName": "tls.test", "allowInsecure": true {extra}}}}}}}"#
            ))
            .expect("parses");
            outbound_tls(&outbound, "127.0.0.1")
                .expect("builds")
                .resumption
        };
        assert!(!config(""), "an unnamed store keeps no ticket");
        assert!(
            config(r#", "enableSessionResumption": true"#),
            "a named store rides the next dial"
        );
        assert!(
            !config(r#", "enableSessionResumption": false"#),
            "a false names no store"
        );
    }

    #[test]
    fn a_certificate_list_serves_the_name_its_sni_asks_for() {
        let first = rcgen::generate_simple_self_signed(vec!["a.test".to_owned()]).expect("mints");
        let second = rcgen::generate_simple_self_signed(vec!["b.test".to_owned()]).expect("mints");
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("ferrox-cert-list-{}-{stamp}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("creates");
        let first_cert = dir.join("a.pem");
        let first_key = dir.join("a.key");
        let second_cert = dir.join("b.pem");
        let second_key = dir.join("b.key");
        std::fs::write(&first_cert, first.cert.pem()).expect("cert a");
        std::fs::write(&first_key, first.signing_key.serialize_pem()).expect("key a");
        std::fs::write(&second_cert, second.cert.pem()).expect("cert b");
        std::fs::write(&second_key, second.signing_key.serialize_pem()).expect("key b");
        let config = |extra: &str| {
            crate::json::parse(&format!(
                r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{{extra}
                    "certificates": [{{"certificateFile": {}, "keyFile": {}}},
                                     {{"certificateFile": {}, "keyFile": {}}}]}}}}}}"#,
                json_path(&first_cert),
                json_path(&first_key),
                json_path(&second_cert),
                json_path(&second_key),
            ))
            .expect("parses")
        };
        let identity = inbound_tls_identity(&config("")).expect("both entries load");
        assert_eq!(identity.certs.len(), 2, "every listed entry is an identity");
        assert_eq!(
            tls_handshake(&identity, second.cert.der().to_vec(), "b.test"),
            (true, true),
            "the second entry answers its own name"
        );
        assert_eq!(
            tls_handshake(&identity, first.cert.der().to_vec(), "a.test"),
            (true, true),
            "the first entry answers its own name"
        );
        assert_eq!(
            tls_handshake(&identity, first.cert.der().to_vec(), "b.test"),
            (false, false),
            "the first entry does not answer b.test's name"
        );
        let rejecting = inbound_tls_identity(&config(r#""rejectUnknownSni": true,"#))
            .expect("both entries load");
        assert_eq!(
            tls_handshake(&rejecting, second.cert.der().to_vec(), "b.test"),
            (true, true),
            "the SNI rule reads the names of every entry, not only the first"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_entry_xray_cannot_load_is_skipped_not_refused() {
        let minted = rcgen::generate_simple_self_signed(vec!["a.test".to_owned()]).expect("mints");
        let wrong = rcgen::generate_simple_self_signed(vec!["c.test".to_owned()]).expect("mints");
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ferrox-cert-keyless-{}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("creates");
        let cert = dir.join("a.pem");
        let key = dir.join("a.key");
        let other_key = dir.join("c.key");
        std::fs::write(&cert, minted.cert.pem()).expect("cert");
        std::fs::write(&key, minted.signing_key.serialize_pem()).expect("key");
        std::fs::write(&other_key, wrong.signing_key.serialize_pem()).expect("other key");
        let config = crate::json::parse(&format!(
            r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{
                "certificates": [{{"certificateFile": {}}},
                                 {{"certificateFile": {}, "keyFile": {}}},
                                 {{"certificateFile": {}, "keyFile": {}}}]}}}}}}"#,
            json_path(&cert),
            json_path(&cert),
            json_path(&other_key),
            json_path(&cert),
            json_path(&key),
        ))
        .expect("parses");
        let identity = inbound_tls_identity(&config).expect("the keyed entry still loads");
        assert_eq!(
            identity.certs.len(),
            1,
            "an entry with no key, or a key that does not sign for its leaf, is skipped"
        );
        assert_eq!(
            tls_handshake(&identity, minted.cert.der().to_vec(), "a.test"),
            (true, true),
            "the listener serves the entries it could load"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_backed_listener_reloads_the_certificate_it_serves() {
        let first = rcgen::generate_simple_self_signed(vec!["a.test".to_owned()]).expect("mints");
        let renewed = rcgen::generate_simple_self_signed(vec!["a.test".to_owned()]).expect("mints");
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("ferrox-cert-reload-{}-{stamp}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("creates");
        let cert = dir.join("a.pem");
        let key = dir.join("a.key");
        std::fs::write(&cert, first.cert.pem()).expect("cert");
        std::fs::write(&key, first.signing_key.serialize_pem()).expect("key");
        let config = |extra: &str| {
            crate::json::parse(&format!(
                r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{
                    "certificates": [{{"certificateFile": {}, "keyFile": {}{extra}}}]}}}}}}"#,
                json_path(&cert),
                json_path(&key),
            ))
            .expect("parses")
        };
        let identity = inbound_tls_identity(&config(r#", "ocspStapling": 7"#))
            .expect("the file-backed identity loads");
        let reload = identity.certs[0].reload.as_ref().expect("a path reloads");
        assert_eq!(
            reload.interval,
            Duration::from_secs(7),
            "ocspStapling is the ticker"
        );
        let defaulted = inbound_tls_identity(&config("")).expect("the default interval loads");
        assert_eq!(
            defaulted.certs[0]
                .reload
                .as_ref()
                .map(|reload| reload.interval),
            Some(Duration::from_secs(3600)),
            "a path with no ocspStapling re-reads on xray's hourly ticker"
        );
        let once = inbound_tls_identity(&config(r#", "oneTimeLoading": true"#))
            .expect("the one-time identity loads");
        assert!(
            once.certs[0].reload.is_none(),
            "oneTimeLoading pins the identity it was read with"
        );
        assert!(
            once.certs[0].ocsp.is_none(),
            "oneTimeLoading pins the staple it loaded with too"
        );
        std::fs::write(&cert, renewed.cert.pem()).expect("new cert");
        std::fs::write(&key, renewed.signing_key.serialize_pem()).expect("new key");
        assert_eq!(
            tls_handshake(&identity, first.cert.der().to_vec(), "a.test"),
            (true, true),
            "the listener serves the bytes it loaded until the ticker re-reads them"
        );
        assert!(identity.renew(), "the re-read replaced the served chain");
        assert_eq!(
            tls_handshake(&identity, first.cert.der().to_vec(), "a.test"),
            (false, false),
            "the disk replaced the chain, so the old root no longer completes"
        );
        assert_eq!(
            tls_handshake(&identity, renewed.cert.der().to_vec(), "a.test"),
            (true, true),
            "after the re-read the listener presents the renewed certificate"
        );
        assert!(
            !identity.renew(),
            "an unchanged read leaves the listener alone"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_ocsp_stapling_entry_records_the_ticker_and_renews_with_it() {
        let minted = rcgen::generate_simple_self_signed(vec!["a.test".to_owned()]).expect("mints");
        let esc = |pem: &str| format!("\"{}\"", pem.replace('\r', "\\r").replace('\n', "\\n"));
        let config = crate::json::parse(&format!(
            r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{"certificates": [{{"certificate": {}, "key": {}, "ocspStapling": 9}}]}}}}}}"#,
            esc(&minted.cert.pem()),
            esc(&minted.signing_key.serialize_pem()),
        ))
        .expect("parses");
        let identity = inbound_tls_identity(&config).expect("the inline identity loads");
        let ocsp = identity.certs[0]
            .ocsp
            .as_ref()
            .expect("stapling is recorded");
        assert_eq!(
            ocsp.interval,
            Duration::from_secs(9),
            "the block's own interval is the staple's ticker"
        );
        assert_eq!(
            identity.reload_interval(),
            Some(Duration::from_secs(9)),
            "an inline entry still ticks"
        );
        assert!(
            !identity.renew(),
            "an unchanged chain with no responder swaps nothing"
        );
    }

    #[test]
    fn a_file_backed_listener_rereads_on_its_ticker() {
        let first = rcgen::generate_simple_self_signed(vec!["a.test".to_owned()]).expect("mints");
        let renewed = rcgen::generate_simple_self_signed(vec!["a.test".to_owned()]).expect("mints");
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("ferrox-cert-tick-{}-{stamp}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("creates");
        let cert = dir.join("a.pem");
        let key = dir.join("a.key");
        std::fs::write(&cert, first.cert.pem()).expect("cert");
        std::fs::write(&key, first.signing_key.serialize_pem()).expect("key");
        let config = crate::json::parse(&format!(
            r#"{{"streamSettings": {{"security": "tls", "tlsSettings": {{
                "certificates": [{{"certificateFile": {}, "keyFile": {},
                    "ocspStapling": 1}}]}}}}}}"#,
            json_path(&cert),
            json_path(&key),
        ))
        .expect("parses");
        let identity = inbound_tls_identity(&config).expect("the file-backed identity loads");
        assert_eq!(
            tls_handshake(&identity, first.cert.der().to_vec(), "a.test"),
            (true, true),
            "the listener starts on the pair it read"
        );
        std::fs::write(&cert, renewed.cert.pem()).expect("new cert");
        std::fs::write(&key, renewed.signing_key.serialize_pem()).expect("new key");
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut reloaded = false;
        while std::time::Instant::now() < deadline {
            if tls_handshake(&identity, renewed.cert.der().to_vec(), "a.test") == (true, true) {
                reloaded = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            reloaded,
            "the ocspStapling ticker re-read the pair and the listener serves the renewed chain"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    static RELOAD_PAIR: std::sync::Mutex<(Vec<u8>, Vec<u8>)> =
        std::sync::Mutex::new((Vec::new(), Vec::new()));
    static RELOAD_READS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn reloaded_pair(path: &str) -> Option<Vec<u8>> {
        RELOAD_READS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let pair = RELOAD_PAIR.lock().expect("pair");
        match path {
            "cert.pem" => Some(pair.0.clone()),
            "key.pem" => Some(pair.1.clone()),
            _ => None,
        }
    }

    #[test]
    fn a_ticker_reads_the_pair_once_and_rebuilds_only_on_a_change() {
        use std::sync::atomic::Ordering;
        let first = rcgen::generate_simple_self_signed(vec!["a.test".to_owned()]).expect("mints");
        let renewed = rcgen::generate_simple_self_signed(vec!["a.test".to_owned()]).expect("mints");
        let pair = |minted: &rcgen::CertifiedKey<rcgen::KeyPair>| {
            (
                minted.cert.pem().into_bytes(),
                minted.signing_key.serialize_pem().into_bytes(),
            )
        };
        *RELOAD_PAIR.lock().expect("pair") = pair(&first);
        RELOAD_READS.store(0, Ordering::SeqCst);
        let mut identity = ferrox_core::tls::parse_pem_identity(
            first.cert.pem().as_bytes(),
            first.signing_key.serialize_pem().as_bytes(),
        )
        .expect("loads");
        identity.certs[0].reload = Some(ferrox_core::tls::CertReload {
            certificate: "cert.pem".to_owned(),
            key: "key.pem".to_owned(),
            interval: Duration::from_secs(3600),
            read: reloaded_pair,
        });
        let identity = Arc::new(identity);
        assert!(
            !identity.renew(),
            "an unchanged pair leaves the listener alone"
        );
        assert_eq!(
            RELOAD_READS.load(Ordering::SeqCst),
            2,
            "a reload reads the certificate and the key once each"
        );
        let before = identity.server_config().expect("the first build serves");
        *RELOAD_PAIR.lock().expect("pair") = pair(&renewed);
        assert!(identity.renew(), "a changed pair rebuilds the identity");
        assert_eq!(
            RELOAD_READS.load(Ordering::SeqCst),
            4,
            "the changed reload reads the pair once more"
        );
        let after = identity.server_config().expect("the rebuilt config serves");
        assert!(
            !Arc::ptr_eq(&before, &after),
            "the rebuild replaced what the listener serves"
        );
        assert_eq!(
            tls_handshake(&identity, renewed.cert.der().to_vec(), "a.test"),
            (true, true),
            "the rebuilt identity presents the re-read certificate"
        );
        assert!(
            Arc::ptr_eq(&after, &identity.server_config().expect("cached")),
            "a handshake before the ticker serves the cached config"
        );
    }

    #[test]
    fn inbound_tls_identity_reads_the_version_bounds_and_suites() {
        let (identity, _) = inbound_tls_identity_with(
            r#""minVersion": "1.2", "maxVersion": "1.2", "cipherSuites": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256""#,
        );
        assert_eq!(identity.min_version, Some(0x0303));
        assert_eq!(identity.max_version, Some(0x0303));
        assert!(
            identity.cipher_suites.contains(&0xc02b),
            "the configured TLS 1.2 suite reaches the identity"
        );
    }

    #[test]
    fn an_absent_budgets_section_moves_no_wait() {
        let root = crate::json::parse(r#"{"inbounds": []}"#).expect("parses");
        assert_eq!(
            budgets(&root).expect("no section is no override"),
            Budgets::default(),
            "a config that names no wait leaves every one at its constant"
        );
    }

    #[test]
    fn a_budget_the_engine_cannot_act_on_is_refused_by_name() {
        for (json, because) in [
            (
                r#"{"budgets": {"dialTimeout": "5s"}}"#,
                "a name no site reads must not read as the default it did not set",
            ),
            (
                r#"{"budgets": {"dial": "500"}}"#,
                "the unit a wait is measured in is not the reader's guess",
            ),
            (
                r#"{"budgets": {"dial": "0ms"}}"#,
                "a wait of none is not a budget",
            ),
            (
                r#"{"budgets": {"dial": 500}}"#,
                "a count with no unit spelled is not a duration",
            ),
            (
                r#"{"budgets": {"dial": "9223372036854775807s"}}"#,
                "past a measurable wait is a typo, not a deadline",
            ),
            (
                r#"{"budgets": []}"#,
                "a section that is not an object names nothing",
            ),
        ] {
            let root = crate::json::parse(json).expect("parses as JSON");
            let error = budgets(&root).expect_err(because);
            assert!(error.contains("budget"), "{json}: {error}");
        }
    }

    #[test]
    fn a_base64_ech_config_is_normalized_and_a_bad_one_fails_closed() {
        use base64::Engine as _;
        let list = {
            let mut contents = vec![7u8, 0x00, 0x20, 0x00, 0x20];
            contents.extend_from_slice(&[0x11; 32]);
            contents.extend_from_slice(&4u16.to_be_bytes());
            contents.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
            contents.push(0);
            contents.push(b"public.test".len() as u8);
            contents.extend_from_slice(b"public.test");
            contents.extend_from_slice(&0u16.to_be_bytes());
            let mut config = vec![0xfe, 0x0d];
            config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
            config.extend_from_slice(&contents);
            let mut list = Vec::new();
            list.extend_from_slice(&(config.len() as u16).to_be_bytes());
            list.extend_from_slice(&config);
            list
        };
        let encoded = base64::engine::general_purpose::STANDARD.encode(&list);
        let settings =
            crate::json::parse(&format!(r#"{{"echConfigList":"{encoded}"}}"#)).expect("parses");
        let got = tls_ech_config(Some(&settings), "hidden.test")
            .expect("resolves")
            .expect("present");
        assert_eq!(got.as_ref(), list.as_slice());

        let malformed = crate::json::parse(r#"{"echConfigList":"not base64"}"#).expect("parses");
        let got = tls_ech_config(Some(&malformed), "hidden.test")
            .expect("fails closed")
            .expect("present");
        assert_eq!(got.as_ref(), [1, 1, 4, 5, 1, 4]);
    }

    #[test]
    fn ech_sockopt_is_read_under_xray_key_and_bad_options_refuse() {
        let settings = crate::json::parse(
            r#"{"echConfigList":"not base64","echSockopt":{"domainStrategy":"useipv4"}}"#,
        )
        .expect("parses");
        assert!(tls_ech_config(Some(&settings), "hidden.test")
            .expect("options parse")
            .is_some());

        let alias = crate::json::parse(
            r#"{"echConfigList":"not base64","echSocketSettings":{"tcpFastOpen":true}}"#,
        )
        .expect("parses");
        assert!(tls_ech_config(Some(&alias), "hidden.test")
            .expect("options parse")
            .is_some());

        let bad = crate::json::parse(
            r#"{"echConfigList":"not base64","echSockopt":{"domainStrategy":"nearest"}}"#,
        )
        .expect("parses");
        let error = tls_ech_config(Some(&bad), "hidden.test").expect_err("refuses");
        assert!(error.contains("domainStrategy"), "{error}");
    }

    #[test]
    fn a_quic_outbound_reads_the_ech_list_from_its_tls_settings() {
        let outbound = crate::json::parse(
            r#"{"streamSettings":{"network":"quic","security":"tls",
                "tlsSettings":{"echConfigList":"not base64"}}}"#,
        )
        .expect("parses");
        let got = quic_ech_config(&outbound, "hidden.test")
            .expect("parses options")
            .expect("names a list");
        assert_eq!(got.as_ref(), [1, 1, 4, 5, 1, 4]);
        let absent = crate::json::parse(
            r#"{"streamSettings":{"network":"quic","security":"tls","tlsSettings":{}}}"#,
        )
        .expect("parses");
        assert!(quic_ech_config(&absent, "hidden.test")
            .expect("parses options")
            .is_none());
    }

    #[test]
    fn server_side_ech_keys_are_parsed_and_malformed_forms_refused() {
        use base64::Engine as _;
        let keys = server_ech_key_tlv();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&keys);
        let with_keys = crate::json::parse(&format!(
            r#"{{"streamSettings":{{"tlsSettings":{{"echServerKeys":"{encoded}"}}}}}}"#
        ))
        .expect("parses");
        assert!(
            ech_server_keys(with_keys.get("streamSettings").expect("settings"))
                .expect("parses")
                .is_some()
        );
        let empty =
            crate::json::parse(r#"{"streamSettings":{"tlsSettings":{"echServerKeys":[]}}}"#)
                .expect("parses");
        assert!(
            ech_server_keys(empty.get("streamSettings").expect("settings"))
                .expect("empty is unset")
                .is_none()
        );
        let array =
            crate::json::parse(r#"{"streamSettings":{"tlsSettings":{"echServerKeys":["AAAA"]}}}"#)
                .expect("parses");
        assert!(
            ech_server_keys(array.get("streamSettings").expect("settings")).is_err(),
            "xray names a string, so an array is refused by name"
        );
        let malformed =
            crate::json::parse(r#"{"streamSettings":{"tlsSettings":{"echServerKeys":"not TLV"}}}"#)
                .expect("parses");
        assert!(
            ech_server_keys(malformed.get("streamSettings").expect("settings")).is_err(),
            "a string that is not a server-key TLV refuses the inbound"
        );
    }

    /// One inbound as the dialect names it, with the `settings` object spelled the loader reads.
    fn vless_settings(text: &str) -> Json {
        crate::json::parse(&format!(r#"{{"protocol":"vless","settings":{text}}}"#)).expect("parses")
    }

    /// The rows a settings object carries, spelled `{"decryption":"none","fallbacks":[…]}`.
    fn fallback_rows(text: &str) -> Vec<Fallback> {
        server_fallbacks(&vless_settings(&format!(
            r#"{{"decryption":"none","fallbacks":[{text}]}}"#
        )))
        .expect("serves")
        .expect("the rows the dialect carries")
    }

    #[test]
    fn the_fallback_verdicts_are_the_reference_s_own() {
        assert_eq!(
            fallback_rows(r#"{"dest":"127.0.0.1:8080"}"#).len(),
            1,
            "an unnamed decryption carries the rows it spells"
        );

        assert_eq!(
            server_fallbacks(&vless_settings(r#"{"decryption":""}"#)).expect_err("empty"),
            r#"VLESS settings: please add/set "decryption":"none" to every settings"#
        );
        assert_eq!(
            server_decryption(&vless_settings(r#"{"decryption":"always"}"#)).expect_err("engine"),
            "unsupported VLESS decryption"
        );

        // Rows beside `none` serve; an engine beside rows is the role's refusal, not this reader's.
        assert_eq!(
            fallback_rows(r#"{"dest":"127.0.0.1:8080"}"#).len(),
            1,
            "none carries the rows it names"
        );
        assert!(
            server_fallbacks(&vless_settings(
                r#"{"decryption":"always","fallbacks":[{"dest":"192.0.2.1:80"}]}"#
            ))
            .is_ok(),
            "the rows read, and the role refuses the pairing"
        );

        let path = r#"{"dest":"127.0.0.1:8080","path":"no"}"#;
        assert_eq!(
            server_fallbacks(&vless_settings(&format!(r#"{{"fallbacks":[{path}]}}"#)))
                .expect_err("path"),
            r#"VLESS fallbacks: "path" must be empty or start with "/""#
        );

        let tiny = r#"{"dest":"8080","xver":3}"#;
        assert_eq!(
            server_fallbacks(&vless_settings(&format!(r#"{{"fallbacks":[{tiny}]}}"#)))
                .expect_err("xver"),
            r#"VLESS fallbacks: invalid PROXY protocol version, "xver" only accepts 0, 1, 2"#
        );

        let unspelled = r#"{"dest":"not a dest"}"#;
        assert_eq!(
            server_fallbacks(&vless_settings(&format!(
                r#"{{"fallbacks":[{unspelled}]}}"#
            )))
            .expect_err("dest"),
            r#"VLESS fallbacks: please fill in a valid value for every "dest""#
        );

        // A number that is no port fits neither unmarshal the reference tries, so the row refuses.
        for number in ["99999", "-1", "1.5"] {
            assert_eq!(
                server_fallbacks(&vless_settings(&format!(
                    r#"{{"fallbacks":[{{"dest":{number}}}]}}"#
                )))
                .expect_err("dest"),
                r#"VLESS fallbacks: please fill in a valid value for every "dest""#,
                "the row whose dest is {number}"
            );
        }
    }

    #[test]
    fn the_fallback_dials_are_inferred_the_reference_s_way() {
        let unnamed = fallback_rows(r#"{"dest":"8080"}"#);
        assert!(
            matches!(
                &unnamed[0].network,
                FallbackNetwork::Tcp { family: 0, host, port } if host == "localhost" && *port == 8080
            ),
            "a bare port dials localhost"
        );
        assert!(
            matches!(
                fallback_rows(r#"{"dest":"[::1]:80","xver":1}"#)[0].network,
                FallbackNetwork::Tcp { family: 0, .. }
            ),
            "a bracketed literal keeps the same unbracketed dialer"
        );
        assert!(matches!(
            fallback_rows(r#"{"dest":"/tmp/app.sock"}"#)[0].network,
            FallbackNetwork::Unix { .. }
        ));
        assert!(matches!(
            fallback_rows(r#"{"dest":"@abs"}"#)[0].network,
            FallbackNetwork::Unix { .. }
        ));
        assert_eq!(
            server_fallbacks(&vless_settings(
                r#"{"fallbacks":[{"dest":"@abs","type":"tcp"}]}"#
            ))
            .expect_err("named tcp with an abstract name"),
            r#"VLESS fallbacks: please fill in a valid value for every "dest""#
        );
        assert!(matches!(
            fallback_rows(r#"{"dest":"serve-ws-none"}"#)[0].network,
            FallbackNetwork::NotDialable
        ));

        // The named kinds keep the family the spelling selects, `serve` included.
        for (kind, family, head) in [
            ("tcp6", 6u8, "2001:db8::1"),
            ("udp", 0u8, "127.0.0.1"),
            ("udp4", 4u8, "127.0.0.1"),
        ] {
            let rows = fallback_rows(&format!(r#"{{"dest":"{head}:8080","type":"{kind}"}}"#));
            let network = rows[0].network.clone();
            match &network {
                FallbackNetwork::Udp {
                    family: got, host, ..
                }
                | FallbackNetwork::Tcp {
                    family: got, host, ..
                } => {
                    assert_eq!(*got, family);
                    assert_eq!(host, head);
                }
                other => panic!("{other:?} is not the dial `{kind}` spells"),
            }
        }
        assert!(
            matches!(
                fallback_rows(r#"{"type":"serve","dest":"x"}"#)[0].network,
                FallbackNetwork::NotDialable
            ),
            "an unknown kind keeps the row, the dialer refusing every round"
        );
    }

    #[test]
    fn the_fallback_route_walks_the_reference_s_table() {
        let rows = fallback_rows(
            r#"
            {"dest":"127.0.0.1:1"},
            {"name":"apple","dest":"127.0.0.1:2"},
            {"name":"www.apple.com","dest":"127.0.0.1:3"},
            {"name":"web","alpn":"h2","dest":"127.0.0.1:4"},
            {"name":"web","alpn":"","path":"/api","dest":"127.0.0.1:5"},
            {"name":"web","alpn":"","dest":"127.0.0.1:6"}"#,
        );
        let dial = |picked: Option<&Fallback>| {
            picked.and_then(|row| match &row.network {
                FallbackNetwork::Tcp { port, .. } => Some(*port),
                _ => None,
            })
        };
        // The front without a name dials the unnamed row.
        assert_eq!(
            dial(Fallback::route(&rows, "", "", b"GET / HTTP/1.1")),
            Some(1)
        );

        // A name the table contains routes to the tightest spelling of it.
        assert_eq!(
            dial(Fallback::route(
                &rows,
                "www.apple.com",
                "",
                b"GET / HTTP/1.1"
            )),
            Some(3)
        );
        assert_eq!(
            dial(Fallback::route(&rows, "apple", "", b"GET / HTTP/1.1")),
            Some(2)
        );
        assert_eq!(
            dial(Fallback::route(&rows, "front.dev", "", b"GET / HTTP/1.1")),
            Some(1),
            "a name nothing in the table contains shares the unnamed cell"
        );

        // An alpn the exact cell spells beats the empty one.
        assert_eq!(
            dial(Fallback::route(&rows, "web", "h2", b"GET / HTTP/1.1")),
            Some(4)
        );

        // The first request line's path picks inside the empty-alpn cell, and the front's alpn falls to the group's `""` map the way the reference reads one.
        assert_eq!(
            dial(Fallback::route(
                &rows,
                "web",
                "http/1.1",
                b"GET /api?q=1 HTTP/1.1"
            )),
            Some(5)
        );
        assert_eq!(
            dial(Fallback::route(&rows, "web", "http/1.1", b"GET / HTTP/1.1")),
            Some(6)
        );

        // A group that spells neither the front's alpn nor `""` leaves the flow unserved.
        let only_h2 = fallback_rows(r#"{"name":"web","alpn":"h2","dest":"127.0.0.1:7"}"#);
        assert_eq!(
            dial(Fallback::route(
                &only_h2,
                "web",
                "http/1.1",
                b"GET / HTTP/1.1"
            )),
            None
        );

        // One unnamed row is every front's cover site, named or not.
        let only_default = fallback_rows(r#"{"dest":"127.0.0.1:8"}"#);
        assert_eq!(
            dial(Fallback::route(
                &only_default,
                "cover.example",
                "h2",
                b"GET / HTTP/1.1"
            )),
            Some(8),
            "a lone unnamed row answers a front the table never spells"
        );
    }

    #[test]
    fn the_unnamed_group_reaches_every_named_group_the_reference_way() {
        // The unnamed group's h2 map reaches a named group that spelled no h2 row, its own `""` row filling the default path.
        let rows = fallback_rows(
            r#"
            {"name":"","alpn":"h2","path":"/api","dest":"127.0.0.1:1"},
            {"name":"web","alpn":"","dest":"127.0.0.1:2"}"#,
        );
        let dial = |picked: Option<&Fallback>| {
            picked.and_then(|row| match &row.network {
                FallbackNetwork::Tcp { port, .. } => Some(*port),
                _ => None,
            })
        };
        assert_eq!(
            dial(Fallback::route(
                &rows,
                "web",
                "h2",
                b"GET /api?q=1 HTTP/1.1"
            )),
            Some(1),
            "the unnamed group's h2 path reaches the named group"
        );
        assert_eq!(
            dial(Fallback::route(&rows, "web", "h2", b"GET / HTTP/1.1")),
            Some(2),
            "the named group's own empty-alpn row fills the default path"
        );

        // An unnamed path reaches an unnamed front; the named group's path is not shared into it.
        let named_only = fallback_rows(
            r#"
            {"name":"web","alpn":"","path":"/api","dest":"127.0.0.1:3"},
            {"name":"","alpn":"","dest":"127.0.0.1:4"}"#,
        );
        assert_eq!(
            dial(Fallback::route(
                &named_only,
                "web",
                "",
                b"GET /api?q=1 HTTP/1.1"
            )),
            Some(3)
        );
        assert_eq!(
            dial(Fallback::route(
                &named_only,
                "cover.example",
                "",
                b"GET /api?q=1 HTTP/1.1"
            )),
            Some(4),
            "the named group's path does not leak into the unnamed one"
        );
    }

    #[test]
    fn carrier_headers_read_every_carrier_and_the_websocket_heartbeat() {
        let ws = crate::json::parse(
            r#"{"network":"ws","wsSettings":{"headers":{"X-Custom":"1"},"heartbeatPeriod":5}}"#,
        )
        .expect("ws");
        let (headers, heartbeat) = carrier_headers(Some(&ws));
        assert_eq!(headers, vec![("X-Custom".to_owned(), "1".to_owned())]);
        assert_eq!(heartbeat, 5);

        let upgrade = crate::json::parse(
            r#"{"network":"httpupgrade","httpupgradeSettings":{"headers":{"X-Upgrade":"1"}}}"#,
        )
        .expect("httpupgrade");
        assert_eq!(
            carrier_headers(Some(&upgrade)).0,
            vec![("X-Upgrade".to_owned(), "1".to_owned())]
        );

        let xhttp = crate::json::parse(
            r#"{"network":"xhttp","xhttpSettings":{"headers":{"X-Fetch":"1"}}}"#,
        )
        .expect("xhttp");
        assert_eq!(
            carrier_headers(Some(&xhttp)).0,
            vec![("X-Fetch".to_owned(), "1".to_owned())]
        );
    }

    #[test]
    fn raw_settings_replace_tcp_settings_whole() {
        let settings = crate::json::parse(
            r#"{"network":"raw","tcpSettings":{"header":{"type":"http","request":{"path":["/old"],"headers":{"X-Old":"1"}}}},"rawSettings":{"header":{"type":"http","request":{"path":["/new"],"headers":{"X-New":"1"}}}}}"#,
        )
        .expect("raw");
        assert_eq!(tcp_http_path(Some(&settings)).as_deref(), Some("/new"));
        assert_eq!(
            carrier_headers(Some(&settings)).0,
            vec![("X-New".to_owned(), "1".to_owned())]
        );

        let tcp = crate::json::parse(
            r#"{"network":"tcp","tcpSettings":{"header":{"type":"http","request":{"path":["/tcp"],"headers":{"X-Tcp":"1"}}}}}"#,
        )
        .expect("tcp");
        assert_eq!(tcp_http_path(Some(&tcp)).as_deref(), Some("/tcp"));
        assert_eq!(
            carrier_headers(Some(&tcp)).0,
            vec![("X-Tcp".to_owned(), "1".to_owned())]
        );
    }

    #[test]
    fn the_configured_host_wins_over_the_carrier_tls_and_address() {
        let outbound = crate::json::parse(
            r#"{"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"tls.example"},"wsSettings":{"host":"carrier.example","headers":{"Host":"header.example"}}}}"#,
        )
        .expect("outbound");
        assert_eq!(outbound_carrier(&outbound, "192.0.2.4").1, "header.example");

        let carrier = crate::json::parse(
            r#"{"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"tls.example"},"wsSettings":{"host":"carrier.example"}}}"#,
        )
        .expect("carrier");
        assert_eq!(outbound_carrier(&carrier, "192.0.2.4").1, "carrier.example");

        let tls = crate::json::parse(
            r#"{"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"tls.example"},"wsSettings":{}}}"#,
        )
        .expect("tls");
        assert_eq!(outbound_carrier(&tls, "192.0.2.4").1, "tls.example");

        let bare = crate::json::parse(r#"{"streamSettings":{"network":"ws"}}"#).expect("bare");
        assert_eq!(outbound_carrier(&bare, "192.0.2.4").1, "192.0.2.4");
    }
}

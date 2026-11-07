//! Xray-core's protobuf config, decoded into this tree's JSON AST.
//!
//! The pinned scenario suite builds a binary at run time and spawns it with
//! `-config=stdin: -format=pb` (`testing/scenarios/common_regular.go`), so the
//! conformance seam needs this wire form, not the JSON dialect. Only the
//! messages a scenario names are decoded, and every other field is refused by
//! name: a config that means more than this tree carries fails at start rather
//! than serving something smaller in silence.

use crate::json::Json;

#[cfg(test)]
pub(crate) fn to_json(bytes: &[u8]) -> Result<Json, String> {
    to_json_seeded(bytes).map(|(json, _)| json)
}

/// The config's handlers as they arrived, kept beside the JSON so the management API can list a
/// protobuf handler byte-for-byte instead of re-encoding one this tree never built.
#[derive(Default)]
pub(crate) struct Seed {
    pub(crate) inbounds: Vec<(String, Vec<u8>)>,
    pub(crate) outbounds: Vec<(String, Vec<u8>)>,
    pub(crate) api: Option<crate::commander::ApiConfig>,
    pub(crate) policy: Option<crate::policy::Config>,
    pub(crate) stats: bool,
}

pub(crate) fn to_json_seeded(bytes: &[u8]) -> Result<(Json, Seed), String> {
    let mut reader = Reader::new(bytes, "xray.core.Config");
    let mut inbounds = Vec::new();
    let mut outbounds = Vec::new();
    let mut seed = Seed::default();
    let mut routing = None;
    let mut dns = None;
    let mut observatory = None;
    let mut burst_observatory = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                let raw = reader.bytes()?;
                seed.inbounds.push((handler_tag(raw), raw.to_vec()));
                inbounds.extend(inbound(raw)?);
            }
            (2, 2) => {
                let raw = reader.bytes()?;
                seed.outbounds.push((handler_tag(raw), raw.to_vec()));
                outbounds.push(outbound(raw)?);
            }
            // The router's rules say which tagged outbound a flow goes to; every other app is xray's own object graph.
            (4, 2) => {
                let (name, value) = typed_message(reader.bytes()?)?;
                match name.as_str() {
                    "xray.app.router.Config" => {
                        if routing.is_some() {
                            return Err("xray.core.Config: two router apps".to_owned());
                        }
                        routing = Some(router_settings(value)?);
                    }
                    "xray.app.dns.Config" => {
                        if dns.is_some() {
                            return Err("xray.core.Config: two DNS apps".to_owned());
                        }
                        dns = Some(dns_settings(value)?);
                    }
                    "xray.app.commander.Config" => {
                        if seed.api.is_some() {
                            return Err("xray.core.Config: two commander apps".to_owned());
                        }
                        seed.api = Some(crate::commander::ApiConfig::from_proto(value)?);
                    }
                    "xray.app.policy.Config" => {
                        if seed.policy.is_some() {
                            return Err("xray.core.Config: two policy apps".to_owned());
                        }
                        seed.policy = Some(policy_settings(value)?);
                    }
                    "xray.app.stats.Config" => seed.stats = true,
                    "xray.app.observatory.Config" => {
                        if observatory.is_some() {
                            return Err("xray.core.Config: two observatory apps".to_owned());
                        }
                        observatory = Some(observatory_settings(value)?);
                    }
                    "xray.app.observatory.burst.Config" => {
                        if burst_observatory.is_some() {
                            return Err("xray.core.Config: two burst observatory apps".to_owned());
                        }
                        burst_observatory = Some(burst_observatory_settings(value)?);
                    }
                    _ => {}
                }
            }
            // Extensions wire xray's own object graph; nothing below reads them.
            (6, 2) => {
                reader.bytes()?;
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut pairs = vec![
        ("inbounds", Json::Arr(inbounds)),
        ("outbounds", Json::Arr(outbounds)),
    ];
    if let Some(routing) = routing {
        pairs.push(("routing", routing));
    }
    if let Some(dns) = dns {
        pairs.push(("dns", dns));
    }
    if seed.stats {
        pairs.push(("stats", Json::Obj(Vec::new())));
    }
    if let Some(observatory) = observatory {
        pairs.push(("observatory", observatory));
    }
    if let Some(burst_observatory) = burst_observatory {
        pairs.push(("burstObservatory", burst_observatory));
    }
    Ok((object(pairs), seed))
}

/// The tag a handler config names, so a listed handler keeps the name the seed was keyed by.
pub(crate) fn handler_tag(bytes: &[u8]) -> String {
    let mut reader = Reader::new(bytes, "handler tag");
    let Ok(Some((1, 2))) = reader.field() else {
        return String::new();
    };
    reader
        .bytes()
        .ok()
        .and_then(|tag| std::str::from_utf8(tag).ok())
        .unwrap_or("")
        .to_owned()
}

/// One inbound handler decodes to one JSON inbound per port it names: xray carries a whole
/// range in one handler, and this tree binds one port per inbound.
pub(crate) fn inbound(bytes: &[u8]) -> Result<Vec<Json>, String> {
    let mut reader = Reader::new(bytes, "xray.core.InboundHandlerConfig");
    let mut receiver = None;
    let mut settings = None;
    let mut tag = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            // A tag names the handler for the router's rules.
            (1, 2) => {
                tag = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| {
                            "xray.core.InboundHandlerConfig: the tag is not utf-8".to_owned()
                        })?
                        .to_owned(),
                );
            }
            (2, 2) => {
                let (name, value) = typed_message(reader.bytes()?)?;
                if name != "xray.app.proxyman.ReceiverConfig" {
                    return Err(format!("inbound receiver `{name}` is not carried"));
                }
                receiver = Some(receiver_config(value)?);
            }
            (3, 2) => settings = Some(typed_message(reader.bytes()?)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let (listen, ports, stream, sniffing, receive_original) =
        receiver.ok_or("xray.core.InboundHandlerConfig: no receiver settings")?;
    let (name, value) = settings.ok_or("xray.core.InboundHandlerConfig: no proxy settings")?;
    let (protocol, inbound_settings) = match name.as_str() {
        "xray.proxy.http.ServerConfig" => {
            http_settings(value)?;
            ("http", Json::Null)
        }
        "xray.proxy.dokodemo.Config" => ("dokodemo-door", dokodemo_settings(value)?),
        "xray.proxy.vmess.inbound.Config" => ("vmess", vmess_inbound_settings(value)?),
        "xray.proxy.vless.inbound.Config" => ("vless", vless_inbound_settings(value)?),
        "xray.proxy.shadowsocks.ServerConfig" => ("shadowsocks", ss_inbound_settings(value)?),
        "xray.proxy.shadowsocks_2022.ServerConfig" => {
            ("shadowsocks", ss2022_server_settings(value)?)
        }
        "xray.proxy.shadowsocks_2022.MultiUserServerConfig" => {
            ("shadowsocks", ss2022_multi_user_settings(value)?)
        }
        "xray.proxy.shadowsocks_2022.RelayServerConfig" => {
            ("shadowsocks", ss2022_relay_settings(value)?)
        }
        "xray.proxy.socks.ServerConfig" => ("socks", socks_inbound_settings(value)?),
        "xray.proxy.wireguard.DeviceConfig" => ("wireguard", wireguard_settings(value)?),
        "xray.proxy.masque.ServerConfig" => ("masque", masque_server_settings(value)?),
        _ => return Err(format!("inbound protocol `{name}` is not carried")),
    };
    Ok(ports
        .into_iter()
        .map(|port| {
            let mut pairs = vec![
                ("protocol", Json::Str(protocol.to_owned())),
                ("port", Json::Num(f64::from(port))),
                ("listen", Json::Str(listen.clone())),
                ("receiveOriginalDestination", Json::Bool(receive_original)),
            ];
            if let Some(tag) = &tag {
                pairs.push(("tag", Json::Str(tag.clone())));
            }
            if inbound_settings != Json::Null {
                pairs.push(("settings", inbound_settings.clone()));
            }
            if let Some(sniffing) = &sniffing {
                pairs.push(("sniffing", sniffing.clone()));
            }
            if let Some(stream) = &stream {
                pairs.push(("streamSettings", stream.clone()));
            }
            object(pairs)
        })
        .collect())
}

pub(crate) fn outbound(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.core.OutboundHandlerConfig");
    let mut settings = None;
    let mut tag = None;
    let mut sender = SenderConfig::default();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            // A tag names the handler for the router's rules.
            (1, 2) => {
                tag = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| {
                            "xray.core.OutboundHandlerConfig: the tag is not utf-8".to_owned()
                        })?
                        .to_owned(),
                );
            }
            // A comment describes the handler; nothing here reads it.
            (5, 2) => {
                reader.bytes()?;
            }
            (2, 2) => {
                let (name, value) = typed_message(reader.bytes()?)?;
                if name != "xray.app.proxyman.SenderConfig" {
                    return Err(format!("outbound sender `{name}` is not carried"));
                }
                sender = sender_config(value)?;
            }
            (3, 2) => settings = Some(typed_message(reader.bytes()?)?),
            (4, 0) => return Err(reader.uncarried("expire")),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let (name, value) = settings.ok_or("xray.core.OutboundHandlerConfig: no proxy settings")?;
    let mut pairs = match name.as_str() {
        "xray.proxy.freedom.Config" => {
            let mut pairs = vec![("protocol", Json::Str("freedom".to_owned()))];
            if let Some(settings) = freedom_settings(value)? {
                pairs.push(("settings", settings));
            }
            pairs
        }
        "xray.proxy.vmess.outbound.Config" => vec![
            ("protocol", Json::Str("vmess".to_owned())),
            ("settings", vmess_outbound_settings(value)?),
        ],
        "xray.proxy.vless.outbound.Config" => vec![
            ("protocol", Json::Str("vless".to_owned())),
            ("settings", vless_outbound_settings(value)?),
        ],
        "xray.proxy.shadowsocks.ClientConfig" => vec![
            ("protocol", Json::Str("shadowsocks".to_owned())),
            ("settings", ss_outbound_settings(value)?),
        ],
        "xray.proxy.shadowsocks_2022.ClientConfig" => vec![
            ("protocol", Json::Str("shadowsocks".to_owned())),
            ("settings", ss2022_outbound_settings(value)?),
        ],
        "xray.proxy.socks.ClientConfig" => vec![
            ("protocol", Json::Str("socks".to_owned())),
            ("settings", socks_outbound_settings(value)?),
        ],
        "xray.proxy.http.ClientConfig" => vec![
            ("protocol", Json::Str("http".to_owned())),
            ("settings", http_outbound_settings(value)?),
        ],
        "xray.proxy.blackhole.Config" => {
            let settings = blackhole_settings(value)?;
            let mut pairs = vec![("protocol", Json::Str("blackhole".to_owned()))];
            if settings != Json::Null {
                pairs.push(("settings", settings));
            }
            pairs
        }
        "xray.proxy.wireguard.DeviceConfig" => vec![
            ("protocol", Json::Str("wireguard".to_owned())),
            ("settings", wireguard_settings(value)?),
        ],
        "xray.proxy.masque.ClientConfig" => vec![
            ("protocol", Json::Str("masque".to_owned())),
            ("settings", masque_client_settings(value)?),
        ],
        _ => return Err(format!("outbound protocol `{name}` is not carried")),
    };
    if let Some(stream) = sender.stream {
        pairs.push(("streamSettings", stream));
    }
    if let Some(mux) = sender.mux {
        pairs.push(("mux", mux));
    }
    if let Some(tag) = tag {
        pairs.push(("tag", Json::Str(tag)));
    }
    Ok(object(pairs))
}

type ReceiverConfig = (String, Vec<u16>, Option<Json>, Option<Json>, bool);

fn receiver_config(bytes: &[u8]) -> Result<ReceiverConfig, String> {
    let mut reader = Reader::new(bytes, "xray.app.proxyman.ReceiverConfig");
    let mut ports = None;
    let mut listen = None;
    let mut stream = None;
    let mut sniffing = None;
    let mut receive_original = false;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => ports = Some(port_list(reader.bytes()?)?),
            (2, 2) => listen = Some(ip_or_domain(reader.bytes()?)?),
            (3, 2) => {
                // A receiver's stream settings are a bare `internet.StreamConfig`, not a typed wrapper.
                stream = Some(stream_settings(reader.bytes()?)?);
            }
            (4, 0) => receive_original = reader.varint()? != 0,
            (6, 2) => sniffing = Some(sniffing_settings(reader.bytes()?)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let ports = ports.ok_or("xray.app.proxyman.ReceiverConfig: no port list")?;
    // An absent listen means every interface in xray; this tree binds loopback unless told otherwise, and its JSON dialect reads the same default.
    Ok((
        listen.unwrap_or_else(|| "127.0.0.1".to_owned()),
        ports,
        stream,
        sniffing,
        receive_original,
    ))
}

/// `WireGuard`'s device config: the keys stay the strings the wire carried —
/// xray hands both hexadecimal and base64 to the same parser — and a user's
/// account is a peer, flattened into the JSON shape the config reader expects.
fn wireguard_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.wireguard.DeviceConfig");
    let mut secret = None;
    let mut endpoints = Vec::new();
    let mut peers = Vec::new();
    let mut users = Vec::new();
    let mut mtu = 0i32;
    let mut reserved = None;
    let mut is_client = false;
    let mut no_kernel_tun = false;
    let mut dns = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                secret = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| {
                            "xray.proxy.wireguard.DeviceConfig: the secret key is not utf-8"
                                .to_owned()
                        })?
                        .to_owned(),
                );
            }
            (2, 2) => endpoints.push(text(&mut reader, "endpoint")?),
            (3, 2) => peers.push(wireguard_peer(reader.bytes()?)?),
            (4, 0) => {
                mtu = i32::try_from(reader.varint()?).map_err(|_| {
                    "xray.proxy.wireguard.DeviceConfig: mtu is not an int32".to_owned()
                })?;
            }
            (5, 2) => users.push(wireguard_user(reader.bytes()?)?),
            (6, 2) => reserved = Some(reader.bytes()?.to_vec()),
            (8, 0) => is_client = reader.varint()? != 0,
            (9, 0) => no_kernel_tun = reader.varint()? != 0,
            (10, 2) => dns.push(text(&mut reader, "DNS")?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let secret = secret.ok_or("xray.proxy.wireguard.DeviceConfig: no secret key")?;
    let mut pairs = vec![("secretKey", Json::Str(secret))];
    if !endpoints.is_empty() {
        pairs.push((
            "endpoint",
            Json::Arr(endpoints.into_iter().map(Json::Str).collect()),
        ));
    }
    if !peers.is_empty() {
        pairs.push(("peers", Json::Arr(peers)));
    }
    if !users.is_empty() {
        pairs.push(("users", Json::Arr(users)));
    }
    if mtu > 0 {
        pairs.push(("mtu", Json::Num(f64::from(mtu))));
    }
    if let Some(reserved) = reserved.filter(|bytes| !bytes.is_empty()) {
        pairs.push((
            "reserved",
            Json::Arr(
                reserved
                    .into_iter()
                    .map(|byte| Json::Num(f64::from(byte)))
                    .collect(),
            ),
        ));
    }
    pairs.push(("isClient", Json::Bool(is_client)));
    pairs.push(("noKernelTun", Json::Bool(no_kernel_tun)));
    if !dns.is_empty() {
        pairs.push((
            "remoteDNS",
            Json::Arr(dns.into_iter().map(Json::Str).collect()),
        ));
    }
    Ok(object(pairs))
}

/// The MASQUE client's endpoint and the addresses it wants resolved on the far side.
fn masque_client_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.masque.ClientConfig");
    let mut server = None;
    let mut remote_dns = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => server = Some(masque_endpoint(reader.bytes()?)?),
            (2, 2) => remote_dns.push(account_text(&mut reader)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let (address, port, password) = server.ok_or("xray.proxy.masque.ClientConfig: no server")?;
    let mut pairs = vec![(
        "server",
        object(vec![
            ("address", Json::Str(address)),
            ("port", Json::Num(f64::from(port))),
        ]),
    )];
    if let Some(password) = password {
        pairs.push(("password", Json::Str(password)));
    }
    if !remote_dns.is_empty() {
        pairs.push((
            "remoteDNS",
            Json::Arr(remote_dns.into_iter().map(Json::Str).collect()),
        ));
    }
    Ok(object(pairs))
}

fn masque_endpoint(bytes: &[u8]) -> Result<(String, u16, Option<String>), String> {
    let mut reader = Reader::new(bytes, "xray.common.protocol.ServerEndpoint");
    let mut address = None;
    let mut port = None;
    let mut password = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => address = Some(ip_or_domain(reader.bytes()?)?),
            (2, 0) => {
                let value = reader.varint()?;
                port = Some(u16::try_from(value).map_err(|_| {
                    format!("xray.proxy.masque.ClientConfig: port {value} is above 65535")
                })?);
            }
            (3, 2) => password = masque_user_fields(reader.bytes()?)?.2,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok((
        address.ok_or("xray.proxy.masque.ClientConfig: the server has no address")?,
        port.ok_or("xray.proxy.masque.ClientConfig: the server has no port")?,
        password,
    ))
}

fn masque_password(bytes: &[u8]) -> Result<String, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.masque.Account");
    let mut password = String::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => password = account_text(&mut reader)?,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok(password)
}

/// The MASQUE server's accounts and the pools it assigns from.
fn masque_server_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.masque.ServerConfig");
    let mut users = Vec::new();
    let mut address = Vec::new();
    let mut mtu = 0u32;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => users.push(masque_user(reader.bytes()?)?),
            (2, 2) => address.push(account_text(&mut reader)?),
            (3, 0) => mtu = reader.varint()?.try_into().unwrap_or(u32::MAX),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut pairs = vec![
        ("users", Json::Arr(users)),
        (
            "address",
            Json::Arr(address.into_iter().map(Json::Str).collect()),
        ),
    ];
    if mtu > 0 {
        pairs.push(("mtu", Json::Num(f64::from(mtu))));
    }
    Ok(object(pairs))
}

fn masque_user_fields(bytes: &[u8]) -> Result<(u32, String, Option<String>), String> {
    let mut reader = Reader::new(bytes, "xray.common.protocol.User");
    let mut level = 0u32;
    let mut email = String::new();
    let mut password = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => level = reader.varint()?.try_into().unwrap_or(u32::MAX),
            (2, 2) => email = account_text(&mut reader)?,
            (3, 2) => {
                let (name, value) = typed_message(reader.bytes()?)?;
                if name != "xray.proxy.masque.Account" {
                    return Err(format!("masque account `{name}` is not carried"));
                }
                password = Some(masque_password(value)?);
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok((level, email, password))
}

fn masque_user(bytes: &[u8]) -> Result<Json, String> {
    let (level, email, password) = masque_user_fields(bytes)?;
    Ok(object(vec![
        ("email", Json::Str(email)),
        ("level", Json::Num(f64::from(level))),
        (
            "password",
            Json::Str(password.ok_or("xray.proxy.masque.ServerConfig: a user has no account")?),
        ),
    ]))
}

fn wireguard_peer(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.wireguard.PeerConfig");
    let mut public = None;
    let mut preshared = None;
    let mut endpoint = None;
    let mut keepalive = None;
    let mut allowed = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => public = Some(text(&mut reader, "public key")?),
            (2, 2) => preshared = Some(text(&mut reader, "pre-shared key")?),
            (3, 2) => endpoint = Some(text(&mut reader, "endpoint")?),
            (4, 2) => keepalive = Some(text(&mut reader, "keep alive")?),
            (5, 2) => allowed.push(text(&mut reader, "allowed IP")?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut pairs = vec![(
        "publicKey",
        Json::Str(public.ok_or("xray.proxy.wireguard.PeerConfig: no public key")?),
    )];
    if let Some(preshared) = preshared.filter(|key| !key.is_empty()) {
        pairs.push(("preSharedKey", Json::Str(preshared)));
    }
    if let Some(endpoint) = endpoint.filter(|endpoint| !endpoint.is_empty()) {
        pairs.push(("endpoint", Json::Str(endpoint)));
    }
    if let Some(keepalive) = keepalive.filter(|keepalive| !keepalive.is_empty()) {
        pairs.push(("keepAlive", Json::Str(keepalive)));
    }
    if !allowed.is_empty() {
        pairs.push((
            "allowedIPs",
            Json::Arr(allowed.into_iter().map(Json::Str).collect()),
        ));
    }
    Ok(object(pairs))
}

fn wireguard_user(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.common.protocol.User");
    let mut level = 0u32;
    let mut email = String::new();
    let mut account = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => level = reader.varint()?.try_into().unwrap_or(u32::MAX),
            (2, 2) => {
                let value = std::str::from_utf8(reader.bytes()?)
                    .map_err(|_| "xray.common.protocol.User: email is not utf-8".to_owned())?;
                email.push_str(value);
            }
            (3, 2) => {
                let (name, value) = typed_message(reader.bytes()?)?;
                if name != "xray.proxy.wireguard.PeerConfig" {
                    return Err(format!("wireguard account `{name}` is not carried"));
                }
                account = Some(wireguard_peer(value)?);
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let account = account.ok_or("xray.common.protocol.User: no account")?;
    Ok(object(vec![
        ("email", Json::Str(email)),
        ("level", Json::Num(f64::from(level))),
        ("account", account),
    ]))
}

fn text(reader: &mut Reader<'_>, what: &str) -> Result<String, String> {
    std::str::from_utf8(reader.bytes()?)
        .map(str::to_owned)
        .map_err(|_| format!("wireguard {what} is not utf-8"))
}

fn sniffing_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.app.proxyman.SniffingConfig");
    let mut enabled = false;
    let mut destination = Vec::new();
    let mut domains = Vec::new();
    let mut ips = Vec::new();
    let mut metadata_only = false;
    let mut route_only = false;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => enabled = reader.varint()? != 0,
            (2, 2) => destination.push(Json::Str(
                std::str::from_utf8(reader.bytes()?)
                    .map_err(|_| {
                        "xray.app.proxyman.SniffingConfig: a destination is not utf-8".to_owned()
                    })?
                    .to_owned(),
            )),
            (3, 2) => domains.push(Json::Str(domain_rule(reader.bytes()?)?)),
            (6, 2) => ips.push(Json::Str(ip_rule(reader.bytes()?)?)),
            (4, 0) => metadata_only = reader.varint()? != 0,
            (5, 0) => route_only = reader.varint()? != 0,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok(object(vec![
        ("enabled", Json::Bool(enabled)),
        ("destOverride", Json::Arr(destination)),
        ("domainsExcluded", Json::Arr(domains)),
        ("ipsExcluded", Json::Arr(ips)),
        ("metadataOnly", Json::Bool(metadata_only)),
        ("routeOnly", Json::Bool(route_only)),
    ]))
}

/// A sender's client-side stream policy: only its stream settings and multiplex switch are
/// carried, and a via policy names a shape this tree refuses by number.
fn sender_config(bytes: &[u8]) -> Result<SenderConfig, String> {
    let mut reader = Reader::new(bytes, "xray.app.proxyman.SenderConfig");
    let mut config = SenderConfig::default();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => return Err(reader.uncarried("the outbound's via address")),
            (2, 2) => {
                // A sender's stream settings are a bare `internet.StreamConfig`, not a typed wrapper.
                config.stream = Some(stream_settings(reader.bytes()?)?);
            }
            (4, 2) => config.mux = Some(multiplex_settings(reader.bytes()?)?),
            (5, 2) => return Err(reader.uncarried("the via cidr")),
            (6, 0) => return Err(reader.uncarried("the target domain strategy")),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok(config)
}

#[derive(Default)]
struct SenderConfig {
    stream: Option<Json>,
    mux: Option<Json>,
}

fn multiplex_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.app.proxyman.MultiplexingConfig");
    let mut enabled = false;
    let mut concurrency = 0i32;
    let mut xudp_concurrency = 0i32;
    let mut udp443 = String::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => enabled = reader.varint()? != 0,
            (2, 0) => concurrency = int32(reader.varint()?),
            (3, 0) => xudp_concurrency = int32(reader.varint()?),
            (4, 2) => {
                udp443 = String::from_utf8_lossy(reader.bytes()?).into_owned();
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok(object(vec![
        ("enabled", Json::Bool(enabled)),
        ("concurrency", Json::Num(f64::from(concurrency))),
        ("xudpConcurrency", Json::Num(f64::from(xudp_concurrency))),
        ("xudpProxyUDP443", Json::Str(udp443)),
    ]))
}

/// One protobuf `int32` out of its varint: a negative value arrives sign-extended across ten bytes, so the low 32 bits are the number.
fn int32(raw: u64) -> i32 {
    u32::try_from(raw & u64::from(u32::MAX))
        .expect("the mask narrows to 32 bits")
        .cast_signed()
}

/// xray's `SocketConfig` as far as a stream reads it: the system dial this tree puts under
/// `freedom` already resolves a name to an address, which is `USE_IP`; a transparent front's
/// `tproxy` mode is carried, its original-destination marker is read, and every other socket
/// option shapes a dial this tree does not carry and is refused by number.
fn socket_settings(bytes: &[u8]) -> Result<Option<Json>, String> {
    let mut reader = Reader::new(bytes, "xray.transport.internet.SocketConfig");
    let mut tproxy = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (3, 0) => {
                tproxy = match reader.varint()? {
                    0 => None,
                    1 => Some("tproxy"),
                    2 => Some("redirect"),
                    mode => {
                        return Err(reader.uncarried(&format!("socket tproxy mode {mode}")));
                    }
                };
            }
            (4, 0) => {
                reader.varint()?;
            }
            (8, 0) => {
                let strategy = reader.varint()?;
                if strategy > 1 {
                    return Err(reader.uncarried(&format!("socket domain strategy {strategy}")));
                }
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok(tproxy.map(|tproxy| object(vec![("tproxy", Json::Str(tproxy.to_owned()))])))
}

/// One stream policy as this tree's JSON dialect spells it: the network, and the security the
/// `security_type` name selects from the carried settings. An absent protocol name is xray's
/// own default (`tcp`), and a named security whose settings bytes are absent is that type's
/// zero value, which is how the reference reads it (`GetEffectiveSecuritySettings`).
fn stream_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.transport.internet.StreamConfig");
    let mut network = String::new();
    let mut transport_settings: Option<Json> = None;
    let mut security_type = String::new();
    let mut security: Option<(&'static str, Json)> = None;
    let mut sockopt = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (2, 2) => {
                let (json, name) = transport_config(reader.bytes()?)?;
                transport_settings = json;
                if !name.is_empty() {
                    network = name;
                }
            }
            (3, 2) => security_type = account_text(&mut reader)?,
            (4, 2) => {
                let (name, value) = typed_message(reader.bytes()?)?;
                // The named type's settings decide, as the reference's walk does; every other entry is read and dropped.
                if name == security_type {
                    security = Some(security_settings(&name, value)?);
                } else {
                    security_settings_exists(&name)?;
                }
            }
            (5, 2) => network = account_text(&mut reader)?,
            (6, 2) => sockopt = socket_settings(reader.bytes()?)?,
            (8..=12, _) => return Err(reader.uncarried("address, mask or quic policy on a stream")),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let network = if network.is_empty() {
        "tcp".to_owned()
    } else {
        network
    };
    if !matches!(network.as_str(), "tcp" | "masque" | "kcp" | "mkcp") {
        return Err(format!("network `{network}` is not carried"));
    }
    let mut pairs = vec![("network", Json::Str(network.clone()))];
    if let Some(sockopt) = sockopt {
        pairs.push(("sockopt", sockopt));
    }
    if let Some(settings) = transport_settings {
        let key = match network.as_str() {
            "masque" => "masqueSettings",
            "kcp" | "mkcp" => "kcpSettings",
            _ => "tcpSettings",
        };
        pairs.push((key, settings));
    }
    if let Some((kind, settings)) = security {
        pairs.push(("security", Json::Str(kind.to_owned())));
        if settings != Json::Null {
            let key = match kind {
                "tls" => "tlsSettings",
                _ => "realitySettings",
            };
            pairs.push((key, settings));
        }
    } else if !security_type.is_empty() {
        // A named security with no carried settings is that type's zero value: no certificates, no key — the kind's empty settings the reference builds too.
        pairs.push((
            "security",
            Json::Str(security_kind(&security_type)?.to_owned()),
        ));
    }
    Ok(object(pairs))
}

/// The dialect key a security type names: `tls` for one, `reality` for the other.
fn security_kind(security_type: &str) -> Result<&'static str, String> {
    match security_type {
        "xray.transport.internet.tls.Config" => Ok("tls"),
        "xray.transport.internet.reality.Config" => Ok("reality"),
        other => Err(format!("security `{other}` is not carried")),
    }
}

/// Whether a settings entry's name is one the dialect carries, for an entry the
/// `security_type` does not select: an uncarried one is still refused by name.
fn security_settings_exists(name: &str) -> Result<(), String> {
    security_kind(name).map(|_| ())
}

/// One transport's settings: the tree's raw tcp carrier reads none, so a named tcp config is
/// the `tcpSettings` key the dialect answers empty and a camouflaged header or a proxy
/// protocol verdict is a refusal by name. A masque config carries the host, path and headers
/// its request names.
fn transport_config(bytes: &[u8]) -> Result<(Option<Json>, String), String> {
    let mut reader = Reader::new(bytes, "xray.transport.internet.TransportConfig");
    let mut name = "tcp".to_owned();
    let mut settings = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (2, 2) => settings = Some(typed_message(reader.bytes()?)?),
            (3, 2) => name = account_text(&mut reader)?,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    match settings {
        None => Ok((None, name)),
        Some((message, value)) if message == "xray.transport.internet.tcp.Config" => {
            tcp_transport(value).map(|()| (None, name))
        }
        Some((message, value)) if message == "xray.transport.internet.masque.Config" => {
            let name = if name.is_empty() || name == "tcp" {
                "masque".to_owned()
            } else {
                name
            };
            masque_transport(value).map(|json| (Some(json), name))
        }
        Some((message, value)) if message == "xray.transport.internet.kcp.Config" => {
            let name = if name.is_empty() || name == "tcp" {
                "mkcp".to_owned()
            } else {
                name
            };
            kcp_transport(value).map(|json| (Some(json), name))
        }
        Some((message, _)) => Err(format!("transport settings `{message}` is not carried")),
    }
}

/// The KCP tunables the dialect spells in `kcpSettings`; every absent field is the
/// reference's zero value, which the dialect fills from its own defaults (`config::kcp_config`).
fn kcp_transport(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.transport.internet.kcp.Config");
    let mut values = [0u32; 6];
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1..=6, 0) => {
                values[field as usize - 1] = u32::try_from(reader.varint()?).map_err(|_| {
                    "xray.transport.internet.kcp.Config: a value is above 4294967295".to_owned()
                })?;
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let names = [
        "mtu",
        "tti",
        "uplinkCapacity",
        "downlinkCapacity",
        "cwndMultiplier",
        "maxSendingWindow",
    ];
    Ok(object(
        names
            .into_iter()
            .zip(values)
            .filter(|(_, value)| *value != 0)
            .map(|(name, value)| (name, Json::Num(f64::from(value))))
            .collect(),
    ))
}

fn tcp_transport(bytes: &[u8]) -> Result<(), String> {
    let mut reader = Reader::new(bytes, "xray.transport.internet.tcp.Config");
    let mut header = false;
    let mut proxy_protocol = false;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (2, 2) => {
                header = true;
                reader.bytes()?;
            }
            (3, 0) => proxy_protocol = reader.varint()? != 0,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    if header {
        return Err(
            "xray.transport.internet.tcp.Config: a camouflaged header is not carried".to_owned(),
        );
    }
    if proxy_protocol {
        return Err(
            "xray.transport.internet.tcp.Config: accept_proxy_protocol is not carried".to_owned(),
        );
    }
    Ok(())
}

fn masque_transport(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.transport.internet.masque.Config");
    let mut host = String::new();
    let mut path = String::new();
    let mut headers = Vec::new();
    let mut warp = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => host = account_text(&mut reader)?,
            (2, 2) => path = account_text(&mut reader)?,
            (3, 2) => headers.push(masque_header(reader.bytes()?)?),
            (4, 2) => warp = Some(masque_warp(reader.bytes()?)?),
            (5, 2) => {
                // One connection carries every flow here; the mux policy names how the reference splits it, not a wire byte.
                reader.bytes()?;
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut pairs = Vec::new();
    if !host.is_empty() {
        pairs.push(("host", Json::Str(host)));
    }
    if !path.is_empty() {
        pairs.push(("path", Json::Str(path)));
    }
    if !headers.is_empty() {
        pairs.push(("headers", Json::Arr(headers)));
    }
    if let Some(warp) = warp {
        pairs.push(("warp", warp));
    }
    Ok(object(pairs))
}

fn masque_warp(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.transport.internet.masque.Warp");
    let mut private_key = String::new();
    let mut public_key = String::new();
    let mut address = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => private_key = ferrox_core::b64::encode(reader.bytes()?),
            (2, 2) => public_key = ferrox_core::b64::encode(reader.bytes()?),
            (3, 2) => address.push(Json::Str(account_text(&mut reader)?)),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut pairs = Vec::new();
    if !private_key.is_empty() {
        pairs.push(("privateKey", Json::Str(private_key)));
    }
    if !public_key.is_empty() {
        pairs.push(("publicKey", Json::Str(public_key)));
    }
    if !address.is_empty() {
        pairs.push(("address", Json::Arr(address)));
    }
    Ok(object(pairs))
}

fn masque_header(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.transport.internet.masque.Config.HeadersEntry");
    let mut name = String::new();
    let mut value = String::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => name = account_text(&mut reader)?,
            (2, 2) => value = account_text(&mut reader)?,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok(object(vec![
        ("name", Json::Str(name)),
        ("value", Json::Str(value)),
    ]))
}

/// The security settings a stream names, keyed the dialect's spelling of the dial that reads it.
fn security_settings(name: &str, bytes: &[u8]) -> Result<(&'static str, Json), String> {
    match name {
        "xray.transport.internet.tls.Config" => tls_settings(bytes).map(|(_, json)| ("tls", json)),
        "xray.transport.internet.reality.Config" => {
            reality_settings(bytes).map(|(_, json)| ("reality", json))
        }
        other => Err(format!("security `{other}` is not carried")),
    }
}

/// A tls identity in the tree's `tlsSettings` spelling. The certificates xray carries arrive
/// as PEM text (`ParseCertificate` runs `ToPEM` before writing), but that helper labels every
/// key it mints `RSA PRIVATE KEY` however the DER is shaped, and this tree's identity parse
/// goes on the label, so the label is corrected to the kind the DER itself names.
fn tls_settings(bytes: &[u8]) -> Result<(&'static str, Json), String> {
    let mut reader = Reader::new(bytes, "xray.transport.internet.tls.Config");
    let mut certificates: Vec<Json> = Vec::new();
    let mut server_name = String::new();
    let mut alpn: Vec<String> = Vec::new();
    let mut disable_system_root = false;
    let mut min_version = String::new();
    let mut max_version = String::new();
    let mut cipher_suites = String::new();
    let mut fingerprint = String::new();
    let mut master_key_log = String::new();
    let mut reject_unknown_sni = false;
    let mut pinned: Vec<&[u8]> = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (2, 2) => certificates.push(tls_certificate(reader.bytes()?)?),
            (3, 2) => server_name = account_text(&mut reader)?,
            (4, 2) => {
                let protocol = account_text(&mut reader)?;
                if protocol == "fromMitm" {
                    return Err(
                        "xray.transport.internet.tls.Config: alpn `fromMitm` is not carried"
                            .to_owned(),
                    );
                }
                alpn.push(protocol);
            }
            // Session resumption keys no wire byte this tree does not write; the read-dropped field is how the bridge reads a newer bool.
            (5, 2) => {
                reader.bytes()?;
            }
            (6, 0) => disable_system_root = reader.varint()? != 0,
            (7, 2) => min_version = account_text(&mut reader)?,
            (8, 2) => max_version = account_text(&mut reader)?,
            (9, 2) => cipher_suites = account_text(&mut reader)?,
            (11, 2) => fingerprint = account_text(&mut reader)?,
            (12, 0) => reject_unknown_sni = reader.varint()? != 0,
            (15, 2) => master_key_log = account_text(&mut reader)?,
            (22, 2) => pinned.push(reader.bytes()?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut pairs = Vec::new();
    if !certificates.is_empty() {
        pairs.push(("certificates", Json::Arr(certificates)));
    }
    if !server_name.is_empty() {
        pairs.push(("serverName", Json::Str(server_name)));
    }
    if !alpn.is_empty() {
        pairs.push(("alpn", Json::Arr(alpn.into_iter().map(Json::Str).collect())));
    }
    if disable_system_root {
        pairs.push(("disableSystemRoot", Json::Bool(true)));
    }
    if !min_version.is_empty() {
        pairs.push(("minVersion", Json::Str(min_version)));
    }
    if !max_version.is_empty() {
        pairs.push(("maxVersion", Json::Str(max_version)));
    }
    if !cipher_suites.is_empty() {
        pairs.push(("cipherSuites", Json::Str(cipher_suites)));
    }
    if !fingerprint.is_empty() {
        pairs.push(("fingerprint", Json::Str(fingerprint)));
    }
    if !pinned.is_empty() {
        let text: Vec<String> = pinned.iter().map(|pin| hex(pin)).collect();
        pairs.push(("pinnedPeerCertSha256", Json::Str(text.join(","))));
    }
    if reject_unknown_sni {
        pairs.push(("rejectUnknownSni", Json::Bool(true)));
    }
    if !master_key_log.is_empty() {
        pairs.push(("masterKeyLog", Json::Str(master_key_log)));
    }
    Ok(("tlsSettings", object(pairs)))
}

/// One certificate entry. The reference carries both parts as PEM bytes (`ToPEM` on the
/// scenario wire), so they path through text; paths name files when values are unset.
fn tls_certificate(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.transport.internet.tls.Certificate");
    let mut certificate: Option<String> = None;
    let mut key: Option<String> = None;
    let mut certificate_path = String::new();
    let mut key_path = String::new();
    let mut usage = "encipherment";
    let mut ocsp_stapling = 0;
    let mut one_time_loading = false;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => certificate = Some(account_text(&mut reader)?),
            (2, 2) => key = Some(account_text(&mut reader)?),
            (3, 0) => {
                usage = match reader.varint()? {
                    0 => "encipherment",
                    1 => "verify",
                    2 => "issue",
                    other => {
                        return Err(format!(
                            "xray.transport.internet.tls.Certificate: usage {other} is not carried"
                        ));
                    }
                };
            }
            (4, 0) => ocsp_stapling = reader.varint()?,
            (5, 2) => certificate_path = account_text(&mut reader)?,
            (6, 2) => key_path = account_text(&mut reader)?,
            (7, 0) => one_time_loading = reader.varint()? != 0,
            // buildChain shapes a chain minted from an issuing CA; the tree serves listed identities only.
            (8, 0) => {
                reader.varint()?;
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    // xray fills the bytes and the path from one file; the path is what its ticker re-reads.
    let mut pairs = Vec::with_capacity(5);
    if certificate_path.is_empty() {
        if let Some(certificate) = certificate {
            pairs.push(("certificate", Json::Str(certificate)));
        }
    } else {
        pairs.push(("certificateFile", Json::Str(certificate_path)));
    }
    if key_path.is_empty() {
        if let Some(key) = key {
            pairs.push(("key", Json::Str(key)));
        }
    } else {
        pairs.push(("keyFile", Json::Str(key_path)));
    }
    if pairs.len() < 2 {
        return Err(
            "xray.transport.internet.tls.Certificate: no certificate bytes or paths".to_owned(),
        );
    }
    if usage != "encipherment" {
        pairs.push(("usage", Json::Str(usage.to_owned())));
    }
    if ocsp_stapling != 0 {
        pairs.push(("ocspStapling", exact_count(ocsp_stapling)?));
    }
    if one_time_loading {
        pairs.push(("oneTimeLoading", Json::Bool(true)));
    }
    Ok(object(pairs))
}

/// A reality identity in the tree's `realitySettings` spelling, both roles in one message: the
/// server's decoy and key, the client's own key, short id and hello fingerprint.
fn reality_settings(bytes: &[u8]) -> Result<(&'static str, Json), String> {
    let mut reader = Reader::new(bytes, "xray.transport.internet.reality.Config");
    let mut reality = RealityFields::default();
    while let Some((field, wire)) = reader.field()? {
        reality.read(&mut reader, field, wire)?;
    }
    reality.finish()
}

/// A reality config's fields as they parse: the server role fills `pairs` around the repeated
/// names and ids, the client role sets `client` for the role-collision verdict.
#[derive(Default)]
struct RealityFields {
    pairs: Vec<(&'static str, Json)>,
    server_names: Vec<String>,
    short_ids: Vec<String>,
    client: bool,
}

impl RealityFields {
    fn read(&mut self, reader: &mut Reader<'_>, field: u64, wire: u8) -> Result<(), String> {
        if field <= 13 {
            return self.server_role(reader, field, wire);
        }
        self.client_role(reader, field, wire)
    }

    fn server_role(&mut self, reader: &mut Reader<'_>, field: u64, wire: u8) -> Result<(), String> {
        match (field, wire) {
            (1, 0) => {
                if reader.varint()? != 0 {
                    self.pairs.push(("show", Json::Bool(true)));
                }
                Ok(())
            }
            (2, 2) => {
                let dest = account_text(reader)?;
                if !dest.is_empty() {
                    self.pairs.push(("dest", Json::Str(dest)));
                }
                Ok(())
            }
            (3, 2) => {
                let kind = account_text(reader)?;
                if !kind.is_empty() && kind != "tcp" {
                    return Err(format!(
                        "xray.transport.internet.reality.Config: decoy type `{kind}` is not carried"
                    ));
                }
                Ok(())
            }
            (4, 0) => {
                let xver = reader.varint()?;
                if xver > 2 {
                    return Err(
                        "xray.transport.internet.reality.Config: xver is above 2".to_owned()
                    );
                }
                if xver != 0 {
                    self.pairs.push(("xver", exact_count(xver)?));
                }
                Ok(())
            }
            (5, 2) => {
                let name = account_text(reader)?;
                if !name.is_empty() {
                    self.server_names.push(name);
                }
                Ok(())
            }
            (6, 2) => {
                self.pairs.push((
                    "privateKey",
                    Json::Str(b64url(reality_key("private", reader)?)),
                ));
                Ok(())
            }
            (7, 2) => {
                self.pairs
                    .push(("minClientVer", Json::Str(client_ver(reader.bytes()?)?)));
                Ok(())
            }
            (8, 2) => {
                self.pairs
                    .push(("maxClientVer", Json::Str(client_ver(reader.bytes()?)?)));
                Ok(())
            }
            (9, 0) => {
                let skew = reader.varint()?;
                if skew != 0 {
                    self.pairs.push(("maxTimeDiff", exact_count(skew)?));
                }
                Ok(())
            }
            (10, 2) => {
                let id = reader.bytes()?;
                self.short_ids.push(hex(id));
                Ok(())
            }
            (11, 2) => {
                self.pairs
                    .push(("mldsa65Seed", Json::Str(b64url(reader.bytes()?))));
                Ok(())
            }
            (12, 2) => {
                self.pairs
                    .push(("limitFallbackUpload", limit_fallback(reader.bytes()?)?));
                Ok(())
            }
            (13, 2) => {
                self.pairs
                    .push(("limitFallbackDownload", limit_fallback(reader.bytes()?)?));
                Ok(())
            }
            _ => Err(reader.refuse(field, wire)),
        }
    }

    fn client_role(&mut self, reader: &mut Reader<'_>, field: u64, wire: u8) -> Result<(), String> {
        match (field, wire) {
            (21, 2) => {
                let name = account_text(reader)?;
                if !name.is_empty() {
                    self.pairs.push(("fingerprint", Json::Str(name)));
                    self.client = true;
                }
                Ok(())
            }
            (22, 2) => {
                let name = account_text(reader)?;
                if !name.is_empty() {
                    self.pairs.push(("serverName", Json::Str(name)));
                    self.client = true;
                }
                Ok(())
            }
            (23, 2) => {
                self.pairs.push((
                    "publicKey",
                    Json::Str(b64url(reality_key("public", reader)?)),
                ));
                Ok(())
            }
            (24, 2) => {
                let id = reader.bytes()?;
                // The reference zero-pads the eight-byte id from the front, so a shorter id than the tree's one spelling keeps its own leading bytes.
                let mut padded = [0u8; 8];
                let len = id.len().min(8);
                padded[..len].copy_from_slice(&id[..len]);
                let short_id = if id.is_empty() {
                    String::new()
                } else {
                    hex(&padded)
                };
                self.pairs.push(("shortId", Json::Str(short_id)));
                self.client = true;
                Ok(())
            }
            (25, 2) => {
                self.pairs
                    .push(("mldsa65Verify", Json::Str(b64url(reader.bytes()?))));
                Ok(())
            }
            // The spider path shapes the hello's steal request, which this tree's reality client writes its own shape for (pinned against the reference).
            (26 | 27, _) => reader.skip(wire),
            (31, 2) => {
                let path = account_text(reader)?;
                if !path.is_empty() {
                    self.pairs.push(("masterKeyLog", Json::Str(path)));
                }
                Ok(())
            }
            _ => Err(reader.refuse(field, wire)),
        }
    }

    /// The repeated names and ids merge last so they stay last in the served object, and a
    /// client-set reality config carries only the client fields: naming the server's side
    /// together with the client's is not a config either role serves whole.
    fn finish(self) -> Result<(&'static str, Json), String> {
        let mut pairs = self.pairs;
        if !self.server_names.is_empty() {
            pairs.push((
                "serverNames",
                Json::Arr(self.server_names.into_iter().map(Json::Str).collect()),
            ));
        }
        if !self.short_ids.is_empty() {
            pairs.push((
                "shortIds",
                Json::Arr(self.short_ids.into_iter().map(Json::Str).collect()),
            ));
        }
        if self.client {
            const SERVER: [&str; 11] = [
                "dest",
                "xver",
                "serverNames",
                "shortIds",
                "maxTimeDiff",
                "minClientVer",
                "maxClientVer",
                "limitFallbackUpload",
                "limitFallbackDownload",
                "privateKey",
                "mldsa65Seed",
            ];
            // A client's `show` is the reference's one handshake-debug print, which this tree's dial trace already names; the pair goes nowhere.
            pairs.retain(|(name, _)| *name != "show");
            let named: Vec<&str> = SERVER
                .iter()
                .filter(|key| pairs.iter().any(|(name, _)| name == *key))
                .copied()
                .collect();
            if !named.is_empty() {
                return Err(format!(
                    "xray.transport.internet.reality.Config: a client reality config names server fields {}",
                    named.join(", ")
                ));
            }
        }
        Ok(("realitySettings", object(pairs)))
    }
}

/// A 32-byte reality key, whatever role it plays: xray's X25519 field length, so anything
/// else is refused rather than decoded into an unusable id.
fn reality_key<'a>(role: &str, reader: &mut Reader<'a>) -> Result<&'a [u8; 32], String> {
    reader.bytes()?.try_into().map_err(|_| {
        format!("xray.transport.internet.reality.Config: the {role} key is not 32 bytes")
    })
}

/// The JSON number a count spells exactly: a float mantissa stops at 2^53, and a count past
/// it is one the dialect cannot serve without lying, so the count is refused. The cast is
/// exact behind the guard, which is the whole point of the guard.
fn exact_count(value: u64) -> Result<Json, String> {
    const EXACT: u64 = 1 << 53;
    if value < EXACT {
        #[allow(clippy::cast_precision_loss)] // the guard above makes the cast exact
        return Ok(Json::Num(value as f64));
    }
    Err(format!(
        "{value} is past the count a JSON number spells exactly"
    ))
}

fn limit_fallback(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.transport.internet.reality.LimitFallback");
    let mut after = 0u64;
    let mut per_sec = 0u64;
    let mut burst = 0u64;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => after = reader.varint()?,
            (2, 0) => per_sec = reader.varint()?,
            (3, 0) => burst = reader.varint()?,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok(object(vec![
        ("afterBytes", exact_count(after)?),
        ("bytesPerSec", exact_count(per_sec)?),
        ("burstBytesPerSec", exact_count(burst)?),
    ]))
}

/// The dotted spelling of a client-version window: one `.a.b.c` per byte xray pins.
fn client_ver(bytes: &[u8]) -> Result<String, String> {
    let bytes: &[u8; 3] = bytes.try_into().map_err(|_| {
        "xray.transport.internet.reality.Config: a version window is not 3 bytes".to_owned()
    })?;
    Ok(format!("{}.{}.{}", bytes[0], bytes[1], bytes[2]))
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// `base64.RawURLEncoding`, the alphabet xray's REALITY key spellings read with.
fn b64url(bytes: &[u8]) -> String {
    ferrox_core::b64::encode(bytes)
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_owned()
}

/// The widest port range one inbound handler is expanded into. A range is bound one port per
/// inbound, so a wide one is a fan-out of listeners this tree would not choose to start.
const MAX_PORT_RANGE: u32 = 64;

fn port_list(bytes: &[u8]) -> Result<Vec<u16>, String> {
    let mut reader = Reader::new(bytes, "xray.common.net.PortList");
    let mut ports = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                let (from, to) = port_range(reader.bytes()?)?;
                if from == 0 {
                    return Err("xray.common.net.PortList: port 0 is not carried".to_owned());
                }
                if from > to {
                    return Err(format!(
                        "xray.common.net.PortList: the range {from}-{to} counts down"
                    ));
                }
                ports.extend(from..=to);
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    if ports.is_empty() {
        return Err("xray.common.net.PortList: no range".to_owned());
    }
    if ports.len() > MAX_PORT_RANGE as usize {
        return Err(format!(
            "xray.common.net.PortList: {} ports is a wider fan-out than {MAX_PORT_RANGE} binds",
            ports.len()
        ));
    }
    Ok(ports)
}

fn port_range(bytes: &[u8]) -> Result<(u16, u16), String> {
    let mut reader = Reader::new(bytes, "xray.common.net.PortRange");
    let mut from = 0;
    let mut to = 0;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => {
                let value = reader.varint()?;
                from = u16::try_from(value).map_err(|_| {
                    format!("xray.common.net.PortRange: port {value} is above 65535")
                })?;
            }
            (2, 0) => {
                let value = reader.varint()?;
                to = u16::try_from(value).map_err(|_| {
                    format!("xray.common.net.PortRange: port {value} is above 65535")
                })?;
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok((from, to))
}

fn ip_or_domain(bytes: &[u8]) -> Result<String, String> {
    let mut reader = Reader::new(bytes, "xray.common.net.IPOrDomain");
    let mut ip = None;
    let mut domain = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => ip = Some(reader.bytes()?),
            (2, 2) => {
                domain = Some(std::str::from_utf8(reader.bytes()?).map_err(|_| {
                    "xray.common.net.IPOrDomain: the domain is not utf-8".to_owned()
                })?);
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    match (ip, domain) {
        (Some(ip), None) => match ip.len() {
            4 => Ok(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).to_string()),
            16 => {
                let bytes: [u8; 16] = ip
                    .try_into()
                    .map_err(|_| "xray.common.net.IPOrDomain: a 16-byte address".to_owned())?;
                Ok(std::net::Ipv6Addr::from(bytes).to_string())
            }
            len => Err(format!(
                "xray.common.net.IPOrDomain: an address of {len} bytes is neither IPv4 nor IPv6"
            )),
        },
        (None, Some(domain)) if !domain.is_empty() => Ok(domain.to_owned()),
        (None, Some(_)) => Err("xray.common.net.IPOrDomain: an empty domain".to_owned()),
        (None, None) => Err("xray.common.net.IPOrDomain: no address".to_owned()),
        (Some(_), Some(_)) => Err("xray.common.net.IPOrDomain: both an ip and a domain".to_owned()),
    }
}

fn typed_message(bytes: &[u8]) -> Result<(String, &[u8]), String> {
    let mut reader = Reader::new(bytes, "xray.common.serial.TypedMessage");
    let mut name = None;
    let mut value = &[][..];
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                name = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| {
                            "xray.common.serial.TypedMessage: the type is not utf-8".to_owned()
                        })?
                        .to_owned(),
                );
            }
            (2, 2) => value = reader.bytes()?,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok((
        name.ok_or("xray.common.serial.TypedMessage: no type")?,
        value,
    ))
}

fn http_settings(bytes: &[u8]) -> Result<(), String> {
    let mut reader = Reader::new(bytes, "xray.proxy.http.ServerConfig");
    // Every field of the empty ServerConfig is a capability this tree lacks, so the first one set is the refusal.
    match reader.field()? {
        None => Ok(()),
        Some((2, 2)) => Err(reader.uncarried("an account map")),
        Some((3, 0)) => Err(reader.uncarried("allow_transparent")),
        Some((4, 0)) => Err(reader.uncarried("user_level")),
        Some((field, wire)) => Err(reader.refuse(field, wire)),
    }
}

/// Dokodemo-door forwards what it accepts to the address its config names, or to the
/// original destination a `follow_redirect` asks the kernel for; a `portMap` picks the
/// target per flow port.
fn dokodemo_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.dokodemo.Config");
    let mut address = None;
    let mut port = None;
    let mut port_map = Vec::new();
    let mut follow_redirect = false;
    let mut user_level = 0;
    let mut networks = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => address = Some(ip_or_domain(reader.bytes()?)?),
            (2, 0) => {
                let value = reader.varint()?;
                port = Some(u16::try_from(value).map_err(|_| {
                    format!("xray.proxy.dokodemo.Config: rewrite port {value} is above 65535")
                })?);
            }
            (3, 2) => port_map.push(dokodemo_port_map_entry(reader.bytes()?)?),
            (5, 0) => follow_redirect = reader.varint()? != 0,
            (6, 0) => {
                user_level = u32_value(reader.varint()?, "xray.proxy.dokodemo.Config: user level")?;
            }
            // A repeated enum arrives packed into one field or per field, and the packed payload carries no keys.
            (7, 2) => {
                let mut packed = Reader::new(reader.bytes()?, "xray.proxy.dokodemo.Config");
                while packed.more() {
                    networks.push(packed.varint()?);
                }
            }
            (7, 0) => networks.push(reader.varint()?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    if networks.is_empty() {
        return Err("xray.proxy.dokodemo.Config: no network allowed".to_owned());
    }
    let mut allowed = Vec::new();
    for value in &networks {
        allowed.push(match value {
            2 => "tcp",
            3 => "udp",
            4 => return Err(reader.uncarried("a unix dokodemo network")),
            other => {
                return Err(format!(
                    "xray.proxy.dokodemo.Config: network {other} is not carried"
                ))
            }
        });
    }
    let mut settings = Vec::new();
    if let Some(address) = address {
        settings.push(("address", Json::Str(address)));
    }
    if let Some(port) = port {
        settings.push(("port", Json::Num(f64::from(port))));
    }
    if !port_map.is_empty() {
        settings.push(("portMap", Json::Obj(port_map)));
    }
    if follow_redirect {
        settings.push(("followRedirect", Json::Bool(true)));
    }
    if user_level != 0 {
        settings.push(("userLevel", Json::Num(f64::from(user_level))));
    }
    settings.push(("network", Json::Str(allowed.join(","))));
    Ok(object(settings))
}

fn dokodemo_port_map_entry(bytes: &[u8]) -> Result<(String, Json), String> {
    let mut reader = Reader::new(bytes, "xray.proxy.dokodemo.Config.PortMapEntry");
    let mut key = String::new();
    let mut value = String::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                std::str::from_utf8(reader.bytes()?)
                    .map_err(|_| {
                        "xray.proxy.dokodemo.Config.PortMapEntry: the key is not utf-8".to_owned()
                    })?
                    .clone_into(&mut key);
            }
            (2, 2) => {
                std::str::from_utf8(reader.bytes()?)
                    .map_err(|_| {
                        "xray.proxy.dokodemo.Config.PortMapEntry: the value is not utf-8".to_owned()
                    })?
                    .clone_into(&mut value);
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    if key.is_empty() {
        return Err("xray.proxy.dokodemo.Config.PortMapEntry: no key".to_owned());
    }
    Ok((key, Json::Str(value)))
}

/// A vmess account: the user's uuid, the cipher it asks for when the config names one, and
/// the experiment string its `tests_enabled` field carries.
type VmessAccount = (String, Option<String>, Option<String>);
type VmessUser = (VmessAccount, u32, String);

/// A vmess inbound serves the clients its users name; xray's default level and the detour
/// inbound are router features nothing here reads.
fn vmess_inbound_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.vmess.inbound.Config");
    let mut clients = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                let (account, level, email) = vmess_user(reader.bytes()?)?;
                clients.push(vmess_client(account, level, email));
            }
            (2, 2) => return Err(reader.uncarried("the default user config")),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    if clients.is_empty() {
        return Err("xray.proxy.vmess.inbound.Config: no user".to_owned());
    }
    Ok(object(vec![("clients", Json::Arr(clients))]))
}

/// A vmess outbound dials the one endpoint its config names.
fn vmess_outbound_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.vmess.outbound.Config");
    let mut receiver = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => receiver = Some(server_endpoint(reader.bytes()?, vmess_user)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let (address, port, (account, level, email)) =
        receiver.ok_or("xray.proxy.vmess.outbound.Config: no receiver")?;
    Ok(object(vec![(
        "vnext",
        Json::Arr(vec![object(vec![
            ("address", Json::Str(address)),
            ("port", Json::Num(f64::from(port))),
            (
                "users",
                Json::Arr(vec![vmess_client(account, level, email)]),
            ),
        ])]),
    )]))
}

/// A blackhole outbound swallows the flow and answers the client with the
/// reference's own answer: nothing, the 403, or the bytes the config carries.
fn blackhole_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.blackhole.Config");
    let mut response = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => response = Some(blackhole_response(reader.bytes()?)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let Some(response) = response else {
        return Ok(Json::Null);
    };
    Ok(object(vec![("response", response)]))
}

/// `xray.proxy.blackhole.Response`: the answer's kind and the bytes a custom
/// answer carries. The bytes travel as base64, the shape this tree's own JSON
/// dialect reads them in.
fn blackhole_response(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.blackhole.Response");
    let mut kind = String::new();
    let mut data = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                kind.clear();
                kind.push_str(std::str::from_utf8(reader.bytes()?).map_err(|_| {
                    "xray.proxy.blackhole.Response: the type is not utf-8".to_owned()
                })?);
            }
            (2, 2) => data = reader.bytes()?.to_vec(),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut pairs = vec![("type", Json::Str(kind))];
    if !data.is_empty() {
        pairs.push((
            "customResponseData",
            Json::Str(ferrox_core::b64::encode(&data)),
        ));
    }
    Ok(object(pairs))
}

/// `xray.app.dns.Config` in the root dialect `dnsapp` reads: the name servers
/// in rule order, the static hosts, and the policy each scope carries.
fn dns_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.app.dns.Config");
    let mut servers = Vec::new();
    let mut hosts = Vec::new();
    let mut pairs = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (5, 2) => servers.push(dns_name_server(reader.bytes()?)?),
            (3, 2) => {
                let ip = reader.bytes()?;
                if !ip.is_empty() {
                    pairs.push(("clientIp", Json::Str(ip_text(ip, "xray.app.dns.Config")?)));
                }
            }
            (4, 2) => hosts.push(dns_host_mapping(reader.bytes()?)?),
            (6, 2) => {
                let tag = std::str::from_utf8(reader.bytes()?)
                    .map_err(|_| "xray.app.dns.Config: the tag is not utf-8".to_owned())?;
                if !tag.is_empty() {
                    pairs.push(("tag", Json::Str(tag.to_owned())));
                }
            }
            (8, 0) => pairs.push(("disableCache", Json::Bool(reader.varint()? != 0))),
            (12, 0) => pairs.push(("serveStale", Json::Bool(reader.varint()? != 0))),
            (13, 0) => {
                let value = reader.varint()?;
                pairs.push((
                    "serveExpiredTTL",
                    Json::Num(f64::from(u32_value(
                        value,
                        "xray.app.dns.Config: serveExpiredTTL",
                    )?)),
                ));
            }
            (9, 0) => pairs.push((
                "queryStrategy",
                Json::Str(strategy(reader.varint()?)?.to_owned()),
            )),
            (10, 0) => pairs.push(("disableFallback", Json::Bool(reader.varint()? != 0))),
            (11, 0) => pairs.push(("disableFallbackIfMatch", Json::Bool(reader.varint()? != 0))),
            (14, 0) => pairs.push(("enableParallelQuery", Json::Bool(reader.varint()? != 0))),
            (15, 2) => {
                let script = std::str::from_utf8(reader.bytes()?)
                    .map_err(|_| "xray.app.dns.Config: the script is not utf-8".to_owned())?;
                pairs.push(("script", Json::Str(script.to_owned())));
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut root = Vec::new();
    if !servers.is_empty() {
        root.push(("servers", Json::Arr(servers)));
    }
    if !hosts.is_empty() {
        root.push(("hosts", Json::Obj(hosts)));
    }
    root.extend(pairs);
    Ok(object(root))
}

#[allow(clippy::too_many_lines)]
fn dns_name_server(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.app.dns.NameServer");
    let mut address = None;
    let mut port = None;
    let mut domains = Vec::new();
    let mut expected = Vec::new();
    let mut unexpected = Vec::new();
    let mut client_ip = None;
    let mut skip_fallback = false;
    let mut act_prior = false;
    let mut act_unprior = false;
    let mut final_query = false;
    let mut query_strategy = 0;
    let mut tag = None;
    let mut policy_id = None;
    let mut timeout = None;
    let mut disable_cache = None;
    let mut serve_stale = None;
    let mut serve_expired = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                let (host, embedded) = endpoint_parts(reader.bytes()?)?;
                address = Some(host);
                port = embedded;
            }
            (2, 2) => domains.push(Json::Str(domain_rule(reader.bytes()?)?)),
            (3, 2) => expected.push(Json::Str(ip_rule(reader.bytes()?)?)),
            (13, 2) => unexpected.push(Json::Str(ip_rule(reader.bytes()?)?)),
            (5, 2) => {
                let ip = reader.bytes()?;
                if !ip.is_empty() {
                    client_ip = Some(ip_text(ip, "xray.app.dns.NameServer")?);
                }
            }
            (6, 0) => skip_fallback = reader.varint()? != 0,
            (7, 0) => query_strategy = reader.varint()?,
            (8, 0) => act_prior = reader.varint()? != 0,
            (14, 0) => act_unprior = reader.varint()? != 0,
            // An id labels the server for a script; a tag scopes the policy a parallel group shares.
            (9, 2) => {
                let found = std::str::from_utf8(reader.bytes()?)
                    .map_err(|_| "xray.app.dns.NameServer: the tag is not utf-8".to_owned())?;
                if !found.is_empty() {
                    tag = Some(found.to_owned());
                }
            }
            (18, 2) => {
                reader.bytes()?;
            }
            (17, 0) => {
                policy_id = Some(u32_value(
                    reader.varint()?,
                    "xray.app.dns.NameServer: policyID",
                )?);
            }
            (10, 0) => {
                timeout = Some(u32_value(
                    reader.varint()?,
                    "xray.app.dns.NameServer: timeoutMs",
                )?);
            }
            (11, 0) => disable_cache = Some(reader.varint()? != 0),
            (15, 0) => serve_stale = Some(reader.varint()? != 0),
            (16, 0) => {
                serve_expired = Some(u32_value(
                    reader.varint()?,
                    "xray.app.dns.NameServer: serveExpiredTTL",
                )?);
            }
            (12, 0) => final_query = reader.varint()? != 0,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let address = address.ok_or("xray.app.dns.NameServer: no address")?;
    let mut pairs = vec![("address", Json::Str(address))];
    if let Some(port) = port {
        pairs.push(("port", Json::Num(f64::from(port))));
    }
    if !domains.is_empty() {
        pairs.push(("domains", Json::Arr(domains)));
    }
    if act_prior || !expected.is_empty() {
        if act_prior {
            expected.push(Json::Str("*".to_owned()));
        }
        pairs.push(("expectedIPs", Json::Arr(expected)));
    }
    if act_unprior || !unexpected.is_empty() {
        if act_unprior {
            unexpected.push(Json::Str("*".to_owned()));
        }
        pairs.push(("unexpectedIPs", Json::Arr(unexpected)));
    }
    if let Some(client_ip) = client_ip {
        pairs.push(("clientIp", Json::Str(client_ip)));
    }
    if skip_fallback {
        pairs.push(("skipFallback", Json::Bool(true)));
    }
    if final_query {
        pairs.push(("finalQuery", Json::Bool(true)));
    }
    if let Some(tag) = tag {
        pairs.push(("tag", Json::Str(tag)));
    }
    if let Some(policy_id) = policy_id {
        pairs.push(("policyID", Json::Num(f64::from(policy_id))));
    }
    pairs.push((
        "queryStrategy",
        Json::Str(strategy(query_strategy)?.to_owned()),
    ));
    if let Some(timeout) = timeout.filter(|timeout| *timeout != 0) {
        pairs.push(("timeoutMs", Json::Num(f64::from(timeout))));
    }
    if let Some(disable_cache) = disable_cache {
        pairs.push(("disableCache", Json::Bool(disable_cache)));
    }
    if let Some(serve_stale) = serve_stale {
        pairs.push(("serveStale", Json::Bool(serve_stale)));
    }
    if let Some(serve_expired) = serve_expired {
        pairs.push(("serveExpiredTTL", Json::Num(f64::from(serve_expired))));
    }
    Ok(object(pairs))
}

/// `xray.common.net.Endpoint`: a network, an address and a port. A plain
/// address keeps its transport in the scheme this tree's loader reads.
fn endpoint_parts(bytes: &[u8]) -> Result<(String, Option<u16>), String> {
    let mut reader = Reader::new(bytes, "xray.common.net.Endpoint");
    let mut network = 0;
    let mut address = None;
    let mut port = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => network = reader.varint()?,
            (2, 2) => address = Some(ip_or_domain(reader.bytes()?)?),
            (3, 0) => {
                let value = reader.varint()?;
                port = Some(u16::try_from(value).map_err(|_| {
                    format!("xray.common.net.Endpoint: port {value} is above 65535")
                })?);
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let address = address.ok_or("xray.common.net.Endpoint: no address")?;
    let address = match network {
        0 | 3 => address,
        2 => {
            if !address.contains("://") && address != "localhost" && address != "fakedns" {
                format!("tcp://{address}")
            } else {
                address
            }
        }
        other => {
            return Err(format!(
                "xray.common.net.Endpoint: network {other} is not carried"
            ))
        }
    };
    Ok((address, port.filter(|port| *port != 0)))
}

/// `xray.common.geodata.DomainRule` as the `type:value` spelling `dnsapp`
/// parses, whether it names a geosite code or one custom rule.
fn domain_rule(bytes: &[u8]) -> Result<String, String> {
    let mut reader = Reader::new(bytes, "xray.common.geodata.DomainRule");
    let mut text = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => text = Some(geosite_rule(reader.bytes()?)?),
            (2, 2) => text = Some(domain_rule_custom(reader.bytes()?)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    text.ok_or_else(|| "xray.common.geodata.DomainRule: no value".to_owned())
}

fn geosite_rule(bytes: &[u8]) -> Result<String, String> {
    let mut reader = Reader::new(bytes, "xray.common.geodata.GeoSiteRule");
    let mut file = None;
    let mut code = None;
    let mut attrs = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                file = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| {
                            "xray.common.geodata.GeoSiteRule: the file is not utf-8".to_owned()
                        })?
                        .to_owned(),
                );
            }
            (2, 2) => {
                code = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| {
                            "xray.common.geodata.GeoSiteRule: the code is not utf-8".to_owned()
                        })?
                        .to_owned(),
                );
            }
            (3, 2) => {
                attrs = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| {
                            "xray.common.geodata.GeoSiteRule: the attrs are not utf-8".to_owned()
                        })?
                        .to_owned(),
                );
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let code = code.ok_or("xray.common.geodata.GeoSiteRule: no code")?;
    let text = match file.as_deref() {
        None | Some("") => format!("geosite:{code}"),
        Some(file) => format!("ext:{file}:{code}"),
    };
    Ok(match attrs {
        Some(attrs) if !attrs.is_empty() => format!("{text}@{attrs}"),
        _ => text,
    })
}

fn domain_rule_custom(bytes: &[u8]) -> Result<String, String> {
    let mut reader = Reader::new(bytes, "xray.common.geodata.Domain");
    let mut kind = 0;
    let mut value = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => kind = reader.varint()?,
            (2, 2) => {
                value = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| {
                            "xray.common.geodata.Domain: the value is not utf-8".to_owned()
                        })?
                        .to_owned(),
                );
            }
            // An attribute filters a geosite entry this tree does not read.
            (3, 2) => {
                reader.bytes()?;
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let value = value.ok_or("xray.common.geodata.Domain: no value")?;
    let prefix = match kind {
        0 => "keyword:",
        1 => "regexp:",
        2 => "domain:",
        3 => "full:",
        other => {
            return Err(format!(
                "xray.common.geodata.Domain: type {other} is not carried"
            ))
        }
    };
    Ok(format!("{prefix}{value}"))
}

fn dns_host_mapping(bytes: &[u8]) -> Result<(String, Json), String> {
    let mut reader = Reader::new(bytes, "xray.app.dns.Config.HostMapping");
    let mut domain = None;
    let mut ips = Vec::new();
    let mut proxied = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (2, 2) => domain = Some(domain_rule(reader.bytes()?)?),
            (3, 2) => ips.push(Json::Str(ip_text(
                reader.bytes()?,
                "xray.app.dns.Config.HostMapping",
            )?)),
            (4, 2) => {
                proxied = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| {
                            "xray.app.dns.Config.HostMapping: the domain is not utf-8".to_owned()
                        })?
                        .to_owned(),
                );
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let domain = domain.ok_or("xray.app.dns.Config.HostMapping: no domain")?;
    let value = match proxied {
        Some(domain) if !domain.is_empty() => Json::Str(domain),
        _ => match ips.len() {
            0 => Json::Arr(Vec::new()),
            1 => ips.remove(0),
            _ => Json::Arr(ips),
        },
    };
    Ok((domain, value))
}

fn strategy(value: u64) -> Result<&'static str, String> {
    match value {
        0 => Ok("UseIP"),
        1 => Ok("UseIP4"),
        2 => Ok("UseIP6"),
        3 => Ok("UseSys"),
        other => Err(format!(
            "xray.app.dns: query strategy {other} is not carried"
        )),
    }
}

fn u32_value(value: u64, message: &'static str) -> Result<u32, String> {
    u32::try_from(value).map_err(|_| format!("{message}: {value} is above 4294967295"))
}

fn ip_text(bytes: &[u8], message: &'static str) -> Result<String, String> {
    match bytes.len() {
        4 => Ok(std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string()),
        16 => {
            let octets: [u8; 16] = bytes
                .try_into()
                .map_err(|_| format!("{message}: a 16-byte address"))?;
            Ok(std::net::Ipv6Addr::from(octets).to_string())
        }
        len => Err(format!(
            "{message}: an address of {len} bytes is neither IPv4 nor IPv6"
        )),
    }
}

fn ip_rule(bytes: &[u8]) -> Result<String, String> {
    let mut reader = Reader::new(bytes, "xray.common.geodata.IPRule");
    let mut geoip = None;
    let mut custom = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => geoip = Some(geoip_rule(reader.bytes()?)?),
            (2, 2) => custom = Some(cidr_rule(reader.bytes()?)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    geoip
        .or(custom)
        .ok_or_else(|| "xray.common.geodata.IPRule: no rule".to_owned())
}

fn geoip_rule(bytes: &[u8]) -> Result<String, String> {
    let mut reader = Reader::new(bytes, "xray.common.geodata.GeoIPRule");
    let mut file = None;
    let mut code = None;
    let mut reverse = false;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                file = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| {
                            "xray.common.geodata.GeoIPRule: the file is not utf-8".to_owned()
                        })?
                        .to_owned(),
                );
            }
            (2, 2) => {
                code = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| {
                            "xray.common.geodata.GeoIPRule: the code is not utf-8".to_owned()
                        })?
                        .to_owned(),
                );
            }
            (3, 0) => reverse = reader.varint()? != 0,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let code = code.ok_or("xray.common.geodata.GeoIPRule: no code")?;
    let text = match file.as_deref() {
        None | Some("") => format!("geoip:{code}"),
        Some(file) => format!("ext:{file}:{code}"),
    };
    Ok(if reverse { format!("!{text}") } else { text })
}

fn cidr_rule(bytes: &[u8]) -> Result<String, String> {
    let mut reader = Reader::new(bytes, "xray.common.geodata.CIDRRule");
    let mut cidr = None;
    let mut reverse = false;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => cidr = Some(cidr_text(reader.bytes()?)?),
            (2, 0) => reverse = reader.varint()? != 0,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let cidr = cidr.ok_or("xray.common.geodata.CIDRRule: no cidr")?;
    Ok(if reverse { format!("!{cidr}") } else { cidr })
}

fn cidr_text(bytes: &[u8]) -> Result<String, String> {
    let mut reader = Reader::new(bytes, "xray.common.geodata.CIDR");
    let mut ip = None;
    let mut prefix = 0u32;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => ip = Some(ip_text(reader.bytes()?, "xray.common.geodata.CIDR")?),
            (2, 0) => {
                prefix = u32::try_from(reader.varint()?)
                    .map_err(|_| "xray.common.geodata.CIDR: prefix is above u32".to_owned())?;
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let ip = ip.ok_or("xray.common.geodata.CIDR: no address")?;
    Ok(format!("{ip}/{prefix}"))
}

/// The router app: the rules that send a flow to a tagged outbound, in the
/// shape this tree's own router reads.
fn router_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.app.router.Config");
    let mut rules = Vec::new();
    let mut strategy = None;
    let mut script = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => {
                let value = reader.varint()?;
                strategy = Some(match value {
                    0 => "AsIs",
                    2 => "IpIfNonMatch",
                    3 => "IpOnDemand",
                    other => return Err(reader.uncarried(&format!("the domain strategy {other}"))),
                });
            }
            (2, 2) => rules.push(router_rule(reader.bytes()?)?),
            (3, 2) => return Err(reader.uncarried("balancers")),
            (4, 2) => {
                script = std::str::from_utf8(reader.bytes()?)
                    .map_err(|_| {
                        "xray.app.router.Config: the routing script is not UTF-8".to_owned()
                    })
                    .map(str::to_owned)
                    .map(Some)?;
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut pairs = Vec::new();
    if let Some(strategy) = strategy {
        pairs.push(("domainStrategy", Json::Str(strategy.to_owned())));
    }
    if let Some(script) = script.filter(|script| !script.is_empty()) {
        pairs.push(("script", Json::Str(script)));
    }
    pairs.push(("rules", Json::Arr(rules)));
    Ok(object(pairs))
}

/// `RoutingService.AddRule`'s request: the router Config a call carries and whether its rules
/// append to the live table or replace it. The reference reads only `Rule` from that config.
pub(crate) fn add_rule_request(bytes: &[u8]) -> Result<(Vec<Json>, bool), String> {
    let mut reader = Reader::new(bytes, "xray.app.router.command.AddRuleRequest");
    let mut config = None;
    let mut append = false;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                let (name, value) = typed_message(reader.bytes()?)?;
                if name != "xray.app.router.Config" {
                    return Err("AddRule: config type error".to_owned());
                }
                config = Some(router_settings(value)?);
            }
            (2, 0) => append = reader.varint()? != 0,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let config = config.ok_or_else(|| "AddRule: config type error".to_owned())?;
    let rules = match config.get("rules") {
        Some(Json::Arr(rules)) => rules.clone(),
        _ => Vec::new(),
    };
    Ok((rules, append))
}

/// `xray.app.router.RoutingRule`: the outbound a flow goes to and every selector
/// this tree's router reads. The selectors it does not read stay refused by name.
fn router_rule(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.app.router.RoutingRule");
    let mut tag = None;
    let mut rule_tag = None;
    let mut domains = Vec::new();
    let mut ips = Vec::new();
    let mut ports = None;
    let mut networks = Vec::new();
    let mut source_ips = Vec::new();
    let mut source_ports = None;
    let mut inbound_tags = Vec::new();
    let mut local_ips = Vec::new();
    let mut local_ports = None;
    let mut local_os = Vec::new();
    let mut users = Vec::new();
    let mut vless_routes = None;
    let mut attributes = Vec::new();
    let mut processes = Vec::new();
    let mut webhook = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                tag = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| {
                            "xray.app.router.RoutingRule: the tag is not utf-8".to_owned()
                        })?
                        .to_owned(),
                );
            }
            (2, 2) => domains.push(Json::Str(domain_rule(reader.bytes()?)?)),
            (7, 2) => users.push(Json::Str(account_text(&mut reader)?)),
            (8, 2) => inbound_tags.push(Json::Str(account_text(&mut reader)?)),
            (9, 2) => return Err(reader.uncarried("a protocol rule")),
            (10, 2) => ips.push(Json::Str(ip_rule(reader.bytes()?)?)),
            (11, 2) => source_ips.push(Json::Str(ip_rule(reader.bytes()?)?)),
            (12, 2) => return Err(reader.uncarried("a balancer tag")),
            (13, 0) => networks.push(Json::Str(network_name(reader.varint()?)?.to_owned())),
            (13, 2) => {
                let mut packed = Reader::new(reader.bytes()?, "xray.common.net.Network");
                while packed.more() {
                    networks.push(Json::Str(network_name(packed.varint()?)?.to_owned()));
                }
            }
            (14, 2) => ports = Some(port_selector(reader.bytes()?)?),
            (15, 2) => attributes.push(attribute_entry(reader.bytes()?)?),
            (16, 2) => source_ports = Some(port_selector(reader.bytes()?)?),
            (17, 2) => local_ips.push(Json::Str(ip_rule(reader.bytes()?)?)),
            (18, 2) => local_ports = Some(port_selector(reader.bytes()?)?),
            (19, 2) => rule_tag = Some(account_text(&mut reader)?),
            (20, 2) => vless_routes = Some(port_selector(reader.bytes()?)?),
            (21, 2) => processes.push(Json::Str(account_text(&mut reader)?)),
            (22, 2) => webhook = Some(webhook_config(reader.bytes()?)?),
            (23, 2) => local_os.push(Json::Str(account_text(&mut reader)?)),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let tag = tag.ok_or("xray.app.router.RoutingRule: no outbound tag")?;
    let mut pairs = vec![("outboundTag", Json::Str(tag))];
    if let Some(rule_tag) = rule_tag {
        pairs.push(("ruleTag", Json::Str(rule_tag)));
    }
    for (key, values) in [
        ("domain", domains),
        ("ip", ips),
        ("sourceIP", source_ips),
        ("inboundTag", inbound_tags),
        ("localIP", local_ips),
        ("localOS", local_os),
        ("user", users),
        ("process", processes),
    ] {
        if !values.is_empty() {
            pairs.push((key, Json::Arr(values)));
        }
    }
    if !networks.is_empty() {
        let joined = networks
            .iter()
            .filter_map(Json::as_str)
            .collect::<Vec<_>>()
            .join(",");
        pairs.push(("network", Json::Str(joined)));
    }
    if let Some(ports) = ports {
        pairs.push(("port", Json::Str(ports)));
    }
    if let Some(source_ports) = source_ports {
        pairs.push(("sourcePort", Json::Str(source_ports)));
    }
    if let Some(local_ports) = local_ports {
        pairs.push(("localPort", Json::Str(local_ports)));
    }
    if let Some(vless_routes) = vless_routes {
        pairs.push(("vlessRoute", Json::Str(vless_routes)));
    }
    if !attributes.is_empty() {
        pairs.push(("attrs", Json::Obj(attribute_map(attributes))));
    }
    pairs.extend(webhook.map(|webhook| ("webhook", webhook)));
    Ok(object(pairs))
}

/// `xray.app.router.WebhookConfig`: the callback a rule fires once it has picked the flow's tag.
fn webhook_config(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.app.router.WebhookConfig");
    let mut url = None;
    let mut deduplication = None;
    let mut headers = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => url = Some(account_text(&mut reader)?),
            (2, 0) => deduplication = Some(reader.varint()?),
            (3, 2) => headers.push(attribute_entry(reader.bytes()?)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut pairs = Vec::new();
    if let Some(url) = url {
        pairs.push(("url", Json::Str(url)));
    }
    if let Some(deduplication) = deduplication {
        pairs.push(("deduplication", exact_count(deduplication)?));
    }
    if !headers.is_empty() {
        pairs.push(("headers", Json::Obj(headers)));
    }
    Ok(object(pairs))
}

/// A protobuf map keeps the last value a repeated key carries, so the entries collapse before the
/// selector reads them; the selector lowercases keys, so a repeated entry replaces the first one
/// even when the two spellings differ only in case.
fn attribute_map(entries: Vec<(String, Json)>) -> Vec<(String, Json)> {
    let mut map: Vec<(String, Json)> = Vec::with_capacity(entries.len());
    for entry in entries {
        match map
            .iter_mut()
            .find(|(name, _)| name.eq_ignore_ascii_case(&entry.0))
        {
            Some(slot) => *slot = entry,
            None => map.push(entry),
        }
    }
    map
}

/// One `RoutingRule.attributes` entry: the map's key and the regexp its value holds.
fn attribute_entry(bytes: &[u8]) -> Result<(String, Json), String> {
    let mut reader = Reader::new(bytes, "xray.app.router.RoutingRule.AttributesEntry");
    let mut key = None;
    let mut value = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => key = Some(account_text(&mut reader)?),
            (2, 2) => value = Some(account_text(&mut reader)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok((
        key.unwrap_or_default(),
        Json::Str(value.unwrap_or_default()),
    ))
}

fn network_name(value: u64) -> Result<&'static str, String> {
    match value {
        2 => Ok("tcp"),
        3 => Ok("udp"),
        4 => Err("xray.common.net.Network: a unix network is not carried".to_owned()),
        other => Err(format!(
            "xray.common.net.Network: network {other} is not carried"
        )),
    }
}

/// `xray.common.net.PortList` in the shape this tree's router reads: a range is
/// `from-to` and several are comma-separated.
fn port_selector(bytes: &[u8]) -> Result<String, String> {
    let mut reader = Reader::new(bytes, "xray.common.net.PortList");
    let mut parts = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                let (from, to) = port_range(reader.bytes()?)?;
                parts.push(if from == to {
                    from.to_string()
                } else {
                    format!("{from}-{to}")
                });
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    if parts.is_empty() {
        return Err("xray.common.net.PortList: no range".to_owned());
    }
    Ok(parts.join(","))
}

/// `common.protocol.ServerEndpoint`: an address, a port and the user that signs the dial.
/// Which account proto the user names is the caller's `user` reader's business.
fn server_endpoint<T>(
    bytes: &[u8],
    user: impl Fn(&[u8]) -> Result<T, String>,
) -> Result<(String, u16, T), String> {
    let mut reader = Reader::new(bytes, "xray.common.protocol.ServerEndpoint");
    let mut address = None;
    let mut port = None;
    let mut account = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => address = Some(ip_or_domain(reader.bytes()?)?),
            (2, 0) => {
                let value = reader.varint()?;
                port = Some(u16::try_from(value).map_err(|_| {
                    format!("xray.common.protocol.ServerEndpoint: port {value} is above 65535")
                })?);
            }
            (3, 2) => account = Some(user(reader.bytes()?)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok((
        address.ok_or("xray.common.protocol.ServerEndpoint: no address")?,
        port.ok_or("xray.common.protocol.ServerEndpoint: no port")?,
        account.ok_or("xray.common.protocol.ServerEndpoint: no user")?,
    ))
}

/// A `common.protocol.User` names its account as a typed message. Its level and email feed
/// xray's policy and stats, and the account set the inbound serves.
fn vmess_user(bytes: &[u8]) -> Result<VmessUser, String> {
    let mut reader = Reader::new(bytes, "xray.common.protocol.User");
    let mut account = None;
    let mut level = 0;
    let mut email = String::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => level = reader.varint()?.try_into().unwrap_or(u32::MAX),
            (2, 2) => {
                let value = std::str::from_utf8(reader.bytes()?)
                    .map_err(|_| "xray.common.protocol.User: email is not utf-8".to_owned())?;
                email.clear();
                email.push_str(value);
            }
            (3, 2) => {
                let (name, value) = typed_message(reader.bytes()?)?;
                if name != "xray.proxy.vmess.Account" {
                    return Err(format!("vmess account `{name}` is not carried"));
                }
                account = Some(vmess_account(value)?);
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok((
        account.ok_or("xray.common.protocol.User: no account".to_owned())?,
        level,
        email,
    ))
}

/// The account's uuid, and the cipher its client asks for when the config names one.
/// `tests_enabled` names the per-account experiments the reference enables by substring, the
/// authenticated length and the suppressed termination signal among them (`proxy/vmess/account.go:56`).
fn vmess_account(bytes: &[u8]) -> Result<VmessAccount, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.vmess.Account");
    let mut id = None;
    let mut security = None;
    let mut tests_enabled = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                id = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| "xray.proxy.vmess.Account: the id is not utf-8".to_owned())?
                        .to_owned(),
                );
            }
            (3, 2) => {
                let mut config =
                    Reader::new(reader.bytes()?, "xray.common.protocol.SecurityConfig");
                let mut value = 0;
                while let Some((field, wire)) = config.field()? {
                    match (field, wire) {
                        (1, 0) => value = config.varint()?,
                        _ => return Err(config.refuse(field, wire)),
                    }
                }
                security = Some(match value {
                    2 => "auto",
                    3 => "aes-128-gcm",
                    4 => "chacha20-poly1305",
                    other => {
                        return Err(format!(
                        "xray.common.protocol.SecurityConfig: security type {other} is not carried"
                    ))
                    }
                });
            }
            (4, 2) => {
                tests_enabled = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| {
                            "xray.proxy.vmess.Account: tests_enabled is not utf-8".to_owned()
                        })?
                        .to_owned(),
                );
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok((
        id.ok_or("xray.proxy.vmess.Account: no id")?,
        security.map(str::to_owned),
        tests_enabled,
    ))
}

fn vmess_client((id, security, tests_enabled): VmessAccount, level: u32, email: String) -> Json {
    let mut pairs = vec![("id", Json::Str(id))];
    if let Some(security) = security {
        pairs.push(("security", Json::Str(security)));
    }
    if let Some(tests_enabled) = tests_enabled {
        pairs.push(("testsEnabled", Json::Str(tests_enabled)));
    }
    if level != 0 {
        pairs.push(("level", Json::Num(f64::from(level))));
    }
    if !email.is_empty() {
        pairs.push(("email", Json::Str(email)));
    }
    object(pairs)
}

/// `xray.app.policy.Config`: the levels whose user traffic is kept and the system-level gates.
fn policy_settings(bytes: &[u8]) -> Result<crate::policy::Config, String> {
    let mut reader = Reader::new(bytes, "xray.app.policy.Config");
    let mut policy = crate::policy::Config::default();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                let (level, stats) = policy_level(reader.bytes()?)?;
                policy.levels.insert(
                    level,
                    crate::policy::Level {
                        stats,
                        ..Default::default()
                    },
                );
            }
            (2, 2) => policy.system = system_policy(reader.bytes()?)?,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok(policy)
}

fn policy_level(bytes: &[u8]) -> Result<(u32, crate::policy::Stats), String> {
    let mut reader = Reader::new(bytes, "xray.app.policy.Config.Level");
    let mut level = None;
    let mut stats = crate::policy::Stats::default();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => level = Some(reader.varint()?.try_into().unwrap_or(u32::MAX)),
            (2, 2) => stats = user_policy_stats(reader.bytes()?)?,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok((
        level.ok_or("xray.app.policy.Config: level entry has no key")?,
        stats,
    ))
}

fn user_policy_stats(bytes: &[u8]) -> Result<crate::policy::Stats, String> {
    let mut reader = Reader::new(bytes, "xray.app.policy.Policy");
    let mut stats = crate::policy::Stats::default();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1 | 3, 2) => {
                reader.bytes()?;
            }
            (2, 2) => stats = user_stats(reader.bytes()?)?,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok(stats)
}

fn user_stats(bytes: &[u8]) -> Result<crate::policy::Stats, String> {
    let mut reader = Reader::new(bytes, "xray.app.policy.Policy.Stats");
    let mut stats = crate::policy::Stats::default();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => stats.user_uplink = reader.varint()? != 0,
            (2, 0) => stats.user_downlink = reader.varint()? != 0,
            (3, 0) => stats.user_online = reader.varint()? != 0,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok(stats)
}

fn system_policy(bytes: &[u8]) -> Result<crate::policy::SystemStats, String> {
    let mut reader = Reader::new(bytes, "xray.app.policy.SystemPolicy");
    let mut stats = crate::policy::SystemStats::default();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => stats = system_stats(reader.bytes()?)?,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok(stats)
}

fn system_stats(bytes: &[u8]) -> Result<crate::policy::SystemStats, String> {
    let mut reader = Reader::new(bytes, "xray.app.policy.SystemPolicy.Stats");
    let mut stats = crate::policy::SystemStats::default();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => stats.inbound_uplink = reader.varint()? != 0,
            (2, 0) => stats.inbound_downlink = reader.varint()? != 0,
            (3, 0) => stats.outbound_uplink = reader.varint()? != 0,
            (4, 0) => stats.outbound_downlink = reader.varint()? != 0,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok(stats)
}

/// The pb strips the prefix, mode and seconds into separate fields; the JSON dialect reads one
/// string, so put them back. A full string that already carries the prefix is left as it came.
fn vless_stripped_encryption(
    keys: &[u8],
    xor_mode: u64,
    seconds: &str,
    padding: Option<&[u8]>,
) -> Result<String, String> {
    let keys = std::str::from_utf8(keys).map_err(|_| "not utf-8".to_owned())?;
    if keys.starts_with("mlkem768x25519plus.") {
        return Ok(keys.to_owned());
    }
    let mode = match xor_mode {
        0 => "native",
        1 => "xorpub",
        2 => "random",
        other => return Err(format!("VLESS encryption xorMode {other} is not carried")),
    };
    let mut full = format!("mlkem768x25519plus.{mode}.{seconds}.");
    if let Some(padding) = padding {
        if !padding.is_empty() {
            let padding = std::str::from_utf8(padding).map_err(|_| "not utf-8".to_owned())?;
            full.push_str(padding);
            full.push('.');
        }
    }
    full.push_str(keys);
    Ok(full)
}

/// A vless account: its uuid, and the two strings that shape the dial when the config names them.
type VlessAccount = (String, Option<String>, Option<String>, Option<String>);

/// A proto3 string, read as the utf-8 the reference writes it.
fn account_text(reader: &mut Reader<'_>) -> Result<String, String> {
    std::str::from_utf8(reader.bytes()?)
        .map(str::to_owned)
        .map_err(|_| "not utf-8".to_owned())
}

/// The uuid a vless session is keyed by, with the flow and encryption the account names.
/// `padding`, the reverse tunnel's message and the decryption test's fields are read and
/// dropped: the plain account carries none of what they shape, and an engine that turns them
/// on never reaches the settings' own gate.
fn vless_account(bytes: &[u8]) -> Result<VlessAccount, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.vless.Account");
    let mut id = None;
    let mut flow = None;
    let mut encryption = None;
    let mut xor_mode = 0u64;
    let mut seconds = 0u64;
    let mut padding = None;
    let mut reverse = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => id = Some(account_text(&mut reader)?),
            (2, 2) => flow = Some(account_text(&mut reader)?),
            (3, 2) => encryption = Some(reader.bytes()?.to_owned()),
            (4, 0) => xor_mode = reader.varint()?,
            (5, 0) => seconds = reader.varint()?,
            (6, 2) => padding = Some(reader.bytes()?.to_owned()),
            (7, 2) => reverse = Some(vless_reverse(reader.bytes()?)?),
            (8 | 9, 0) => {
                reader.varint()?;
            }
            (9, 2) => {
                reader.bytes()?;
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let encryption = match encryption {
        None => None,
        Some(keys) if keys == b"none" => Some("none".to_owned()),
        Some(keys) if keys.is_empty() => {
            return Err(r#"VLESS users: please add/set "encryption":"none" for every user"#.into())
        }
        Some(keys) => {
            let full = vless_stripped_encryption(
                &keys,
                xor_mode,
                if seconds > 0 { "0rtt" } else { "1rtt" },
                padding.as_deref(),
            )?;
            if ferrox_core::vless_encryption::ClientConfig::parse(&full).is_err() {
                return Err(format!(
                    r#"VLESS users: unsupported "encryption": {}"#,
                    String::from_utf8_lossy(&keys)
                ));
            }
            Some(full)
        }
    };
    Ok((
        id.ok_or("xray.proxy.vless.Account: no id".to_owned())?,
        encryption,
        flow,
        reverse,
    ))
}

/// The tag an account opens a reverse session under; its sniffing block names a sniffer this tree
/// does not run on a reverse stream, and the reference does not accept one on an inbound either.
fn vless_reverse(bytes: &[u8]) -> Result<String, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.vless.Reverse");
    let mut tag = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => tag = Some(account_text(&mut reader)?),
            (2, 2) => {
                reader.bytes()?;
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    tag.ok_or("xray.proxy.vless.Reverse: no tag".to_owned())
}

/// A `common.protocol.User` whose account is a vless one; level and email feed the policy and
/// stats nothing here reads.
fn vless_user(bytes: &[u8]) -> Result<VlessAccount, String> {
    let mut reader = Reader::new(bytes, "xray.common.protocol.User");
    let mut account = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => return Err(reader.uncarried("user level")),
            (2, 2) => return Err(reader.uncarried("user email")),
            (3, 2) => {
                let (name, value) = typed_message(reader.bytes()?)?;
                if name != "xray.proxy.vless.Account" {
                    return Err(format!("vless account `{name}` is not carried"));
                }
                account = Some(vless_account(value)?);
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    account.ok_or("xray.common.protocol.User: no account".to_owned())
}

/// The clients a vless inbound serves, with the fallback rows it names. A `decryption` past
/// `none` refuses with its verdict the way the reference's own build does — an empty spelling
/// too — while `xorMode`, the seconds window and `padding` ride along unheard.
fn vless_inbound_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.vless.inbound.Config");
    let mut clients = Vec::new();
    let mut fallbacks = Vec::new();
    let mut decryption = None;
    let mut xor_mode = 0u64;
    let mut seconds_from = 0u64;
    let mut seconds_to = 0u64;
    let mut padding = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                let (id, _, flow, reverse) = vless_user(reader.bytes()?)?;
                clients.push(vless_client(id, None, flow, reverse));
            }
            (2, 2) => fallbacks.push(vless_fallback(reader.bytes()?)?),
            (3, 2) => decryption = Some(reader.bytes()?.to_owned()),
            (4, 0) => xor_mode = reader.varint()?,
            (5, 0) => seconds_from = reader.varint()?,
            (6, 0) => seconds_to = reader.varint()?,
            (7, 2) => padding = Some(reader.bytes()?.to_owned()),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let decryption = match decryption {
        None => None,
        Some(shape) if shape == b"none" => None,
        Some(shape) if shape.is_empty() => {
            return Err(
                r#"VLESS settings: please add/set "decryption":"none" to every settings"#.into(),
            )
        }
        Some(keys) => {
            let seconds = if seconds_to > 0 {
                format!("{seconds_from}-{seconds_to}s")
            } else {
                format!("{seconds_from}s")
            };
            let full = vless_stripped_encryption(&keys, xor_mode, &seconds, padding.as_deref())?;
            if ferrox_core::vless_encryption::ServerConfig::parse(&full).is_err() {
                return Err(format!(
                    r#"VLESS settings: unsupported "decryption": {}"#,
                    String::from_utf8_lossy(&keys)
                ));
            }
            Some(full)
        }
    };
    if clients.is_empty() {
        return Err("xray.proxy.vless.inbound.Config: no user".to_owned());
    }
    let mut pairs = vec![("clients", Json::Arr(clients))];
    if !fallbacks.is_empty() {
        pairs.push(("fallbacks", Json::Arr(fallbacks)));
    }
    if let Some(decryption) = decryption {
        pairs.push(("decryption", Json::Str(decryption)));
    }
    Ok(object(pairs))
}

/// One fallback row spelled into the dialect's JSON, its fields as they arrived: an omitted
/// field takes the row's own default, and the dest stays the string the message carried, the
/// way the loader infers its dial behind.
fn vless_fallback(bytes: &[u8]) -> Result<Json, String> {
    const NAMES: [&str; 5] = ["name", "alpn", "path", "type", "dest"];
    let mut reader = Reader::new(bytes, "xray.proxy.vless.Fallback");
    let mut text: [Option<String>; 5] = Default::default();
    let mut xver = 0u64;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1..=5, 2) => {
                text[usize::try_from(field - 1).map_err(|_| "field".to_owned())?] =
                    Some(account_text(&mut reader)?);
            }
            (6, 0) => xver = reader.varint()?,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut pairs = Vec::new();
    for (at, name) in NAMES.iter().enumerate() {
        if let Some(value) = text[at].as_ref().filter(|value| !value.is_empty()) {
            pairs.push((*name, Json::Str(value.clone())));
        }
    }
    if xver != 0 {
        pairs.push((
            "xver",
            Json::Num(f64::from(
                u32::try_from(xver).map_err(|_| "xver".to_owned())?,
            )),
        ));
    }
    Ok(object(pairs))
}

/// A vless outbound dials the one endpoint its config names.
fn vless_outbound_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.vless.outbound.Config");
    let mut vnext = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => vnext = Some(server_endpoint(reader.bytes()?, vless_user)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let (address, port, (id, encryption, flow, reverse)) =
        vnext.ok_or("xray.proxy.vless.outbound.Config: no vnext")?;
    let mut pairs = vec![(
        "vnext",
        Json::Arr(vec![object(vec![
            ("address", Json::Str(address)),
            ("port", Json::Num(f64::from(port))),
            (
                "users",
                Json::Arr(vec![vless_client(id, encryption, flow, None)]),
            ),
        ])]),
    )];
    if let Some(tag) = reverse {
        pairs.push(("reverse", object(vec![("tag", Json::Str(tag))])));
    }
    Ok(object(pairs))
}

/// The account as this tree's JSON dialect names it; an inbound client carries no encryption.
fn vless_client(
    id: String,
    encryption: Option<String>,
    flow: Option<String>,
    reverse: Option<String>,
) -> Json {
    let mut pairs = vec![("id", Json::Str(id))];
    if let Some(encryption) = encryption {
        pairs.push(("encryption", Json::Str(encryption)));
    }
    if let Some(flow) = flow {
        pairs.push(("flow", Json::Str(flow)));
    }
    if let Some(tag) = reverse {
        pairs.push(("reverse", object(vec![("tag", Json::Str(tag))])));
    }
    object(pairs)
}

/// A shadowsocks account: its password, the AEAD cipher, and the email and level that name its stats.
struct SsAccount {
    password: String,
    method: &'static str,
    email: Option<String>,
    level: Option<u32>,
}

/// The four ciphers the pinned enum names beyond `UNKNOWN`, in the spellings `Method::parse` reads.
fn ss_cipher(value: u64) -> Result<&'static str, String> {
    match value {
        5 => Ok("aes-128-gcm"),
        6 => Ok("aes-256-gcm"),
        7 => Ok("chacha20-ietf-poly1305"),
        8 => Ok("xchacha20-ietf-poly1305"),
        other => Err(format!(
            "xray.proxy.shadowsocks.Account: cipher {other} is not carried"
        )),
    }
}

/// The password and cipher a `shadowsocks.Account` names; `iv_check` is read and ignored, as the reference ignores it.
fn ss_account(bytes: &[u8]) -> Result<SsAccount, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.shadowsocks.Account");
    let mut password = None;
    let mut cipher = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => password = Some(account_text(&mut reader)?),
            (2, 0) => cipher = Some(ss_cipher(reader.varint()?)?),
            (3, 0) => {
                reader.varint()?;
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok(SsAccount {
        password: password.ok_or("xray.proxy.shadowsocks.Account: no password".to_owned())?,
        method: cipher.ok_or("xray.proxy.shadowsocks.Account: no cipher".to_owned())?,
        email: None,
        level: None,
    })
}

/// A `common.protocol.User` whose account is a shadowsocks one: the level and email key its policy and stats.
fn ss_user(bytes: &[u8]) -> Result<SsAccount, String> {
    let mut reader = Reader::new(bytes, "xray.common.protocol.User");
    let mut account = None;
    let mut level = None;
    let mut email = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => level = Some(reader.varint()?.try_into().unwrap_or(u32::MAX)),
            (2, 2) => {
                email = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| "xray.common.protocol.User: email is not utf-8".to_owned())?
                        .to_owned(),
                );
            }
            (3, 2) => {
                let (name, value) = typed_message(reader.bytes()?)?;
                if name != "xray.proxy.shadowsocks.Account" {
                    return Err(format!("shadowsocks account `{name}` is not carried"));
                }
                account = Some(ss_account(value)?);
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut account = account.ok_or("xray.common.protocol.User: no account".to_owned())?;
    account.level = level;
    account.email = email;
    Ok(account)
}

/// The clients a shadowsocks inbound serves, one account per `users` entry, and the networks its config opened.
fn ss_inbound_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.shadowsocks.ServerConfig");
    let mut users = Vec::new();
    let mut networks = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => users.push(ss_user(reader.bytes()?)?),
            // A repeated enum arrives packed into one field or per field.
            (2, 2) => {
                let mut packed =
                    Reader::new(reader.bytes()?, "xray.proxy.shadowsocks.ServerConfig");
                while packed.more() {
                    networks.push(packed.varint()?);
                }
            }
            (2, 0) => networks.push(reader.varint()?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let clients: Vec<Json> = users
        .into_iter()
        .map(|account| {
            let mut pairs = vec![
                ("method", Json::Str(account.method.to_owned())),
                ("password", Json::Str(account.password)),
            ];
            if let Some(email) = account.email {
                pairs.push(("email", Json::Str(email)));
            }
            if let Some(level) = account.level {
                pairs.push(("level", Json::Num(f64::from(level))));
            }
            object(pairs)
        })
        .collect();
    let mut settings = vec![("users", Json::Arr(clients))];
    // Only tcp and udp reach a worker; a list that names neither opens nothing, as the reference's has no worker for it.
    let mut opened: Vec<&str> = Vec::new();
    if !networks.is_empty() {
        for network in &networks {
            let name = match network {
                2 => "tcp",
                3 => "udp",
                _ => continue,
            };
            if !opened.contains(&name) {
                opened.push(name);
            }
        }
        settings.push(("network", Json::Str(opened.join(","))));
    }
    Ok(object(settings))
}

/// A shadowsocks outbound dials the one server its config names.
fn ss_outbound_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.shadowsocks.ClientConfig");
    let mut server = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => server = Some(server_endpoint(reader.bytes()?, ss_user)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let (address, port, account) =
        server.ok_or("xray.proxy.shadowsocks.ClientConfig: no server")?;
    Ok(object(vec![(
        "servers",
        Json::Arr(vec![object(vec![
            ("address", Json::Str(address)),
            ("port", Json::Num(f64::from(port))),
            ("method", Json::Str(account.method.to_owned())),
            ("password", Json::Str(account.password)),
        ])]),
    )]))
}

/// The networks a 2022 config opens, from one packed list or repeated fields: only tcp and udp reach a worker, as in the legacy conversion.
fn ss2022_networks(items: &[u64]) -> Option<String> {
    if items.is_empty() {
        return None;
    }
    let mut opened: Vec<&str> = Vec::new();
    for network in items {
        let name = match network {
            2 => "tcp",
            3 => "udp",
            _ => continue,
        };
        if !opened.contains(&name) {
            opened.push(name);
        }
    }
    Some(opened.join(","))
}

/// The one key a `shadowsocks_2022.Account` carries.
fn ss2022_account(bytes: &[u8]) -> Result<String, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.shadowsocks_2022.Account");
    let mut key = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => key = Some(account_text(&mut reader)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    key.ok_or("xray.proxy.shadowsocks_2022.Account: no key".to_owned())
}

/// The one client key a `users` entry of a 2022 multi-user config names, with the email and level its policy and stats key: a `common.protocol.User` around a 2022 account.
fn ss2022_user(bytes: &[u8]) -> Result<(String, Option<String>, Option<u32>), String> {
    let mut reader = Reader::new(bytes, "xray.common.protocol.User");
    let mut key = None;
    let mut level = None;
    let mut email = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => level = Some(reader.varint()?.try_into().unwrap_or(u32::MAX)),
            (2, 2) => {
                email = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| "xray.common.protocol.User: email is not utf-8".to_owned())?
                        .to_owned(),
                );
            }
            (3, 2) => {
                let (name, value) = typed_message(reader.bytes()?)?;
                if name != "xray.proxy.shadowsocks_2022.Account" {
                    return Err(format!("shadowsocks 2022 account `{name}` is not carried"));
                }
                key = Some(ss2022_account(value)?);
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let key = key.ok_or("xray.common.protocol.User: no account".to_owned())?;
    Ok((key, email, level))
}

/// A single-password 2022 server: the method and PSK the JSON inbound reads directly.
fn ss2022_server_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.shadowsocks_2022.ServerConfig");
    let mut method = None;
    let mut key = None;
    let mut email = None;
    let mut level = None;
    let mut networks = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => method = Some(account_text(&mut reader)?),
            (2, 2) => key = Some(account_text(&mut reader)?),
            (3, 2) => {
                email = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| {
                            "xray.proxy.shadowsocks_2022.ServerConfig: email is not utf-8"
                                .to_owned()
                        })?
                        .to_owned(),
                );
            }
            (4, 0) => level = Some(reader.varint()?.try_into().unwrap_or(u32::MAX)),
            (5, 2) => {
                let mut packed =
                    Reader::new(reader.bytes()?, "xray.proxy.shadowsocks_2022.ServerConfig");
                while packed.more() {
                    networks.push(packed.varint()?);
                }
            }
            (5, 0) => networks.push(reader.varint()?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut pairs = vec![
        (
            "method",
            Json::Str(
                method.ok_or("xray.proxy.shadowsocks_2022.ServerConfig: no method".to_owned())?,
            ),
        ),
        (
            "password",
            Json::Str(key.ok_or("xray.proxy.shadowsocks_2022.ServerConfig: no key".to_owned())?),
        ),
    ];
    if let Some(email) = email {
        pairs.push(("email", Json::Str(email)));
    }
    if let Some(level) = level {
        pairs.push(("level", Json::Num(f64::from(level))));
    }
    if let Some(network) = ss2022_networks(&networks) {
        pairs.push(("network", Json::Str(network)));
    }
    Ok(object(pairs))
}

/// A 2022 multi-user server arrives as a master key and one account per user; the JSON inbound reads the same list as one colon-joined password.
fn ss2022_multi_user_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.shadowsocks_2022.MultiUserServerConfig");
    let mut method = None;
    let mut master = None;
    let mut users = Vec::new();
    let mut networks = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => method = Some(account_text(&mut reader)?),
            (2, 2) => master = Some(account_text(&mut reader)?),
            (3, 2) => users.push(ss2022_user(reader.bytes()?)?),
            (4, 2) => {
                let mut packed = Reader::new(
                    reader.bytes()?,
                    "xray.proxy.shadowsocks_2022.MultiUserServerConfig",
                );
                while packed.more() {
                    networks.push(packed.varint()?);
                }
            }
            (4, 0) => networks.push(reader.varint()?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut password = vec![master
        .ok_or("xray.proxy.shadowsocks_2022.MultiUserServerConfig: no master key".to_owned())?];
    password.extend(users.iter().map(|(key, _, _)| key.clone()));
    let mut pairs = vec![
        (
            "method",
            Json::Str(method.ok_or(
                "xray.proxy.shadowsocks_2022.MultiUserServerConfig: no method".to_owned(),
            )?),
        ),
        ("password", Json::Str(password.join(":"))),
    ];
    // The 2022 inbound keys each client off the encrypted identity header rather than this list, so the joined password stays the key ring and this array carries only each user's policy and stats identity.
    let identities: Vec<Json> = users
        .iter()
        .map(|(_, email, level)| {
            let mut id = Vec::new();
            if let Some(email) = email {
                id.push(("email", Json::Str(email.clone())));
            }
            if let Some(level) = level {
                id.push(("level", Json::Num(f64::from(*level))));
            }
            object(id)
        })
        .collect();
    if !identities.is_empty() {
        pairs.push(("users", Json::Arr(identities)));
    }
    if let Some(network) = ss2022_networks(&networks) {
        pairs.push(("network", Json::Str(network)));
    }
    Ok(object(pairs))
}

/// A 2022 relay server: the master key becomes the inbound's password and each destination keeps its own key, address and port.
fn ss2022_relay_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.shadowsocks_2022.RelayServerConfig");
    let mut method = None;
    let mut master = None;
    let mut destinations = Vec::new();
    let mut networks = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => method = Some(account_text(&mut reader)?),
            (2, 2) => master = Some(account_text(&mut reader)?),
            (3, 2) => destinations.push(ss2022_relay_destination(reader.bytes()?)?),
            (4, 2) => {
                let mut packed = Reader::new(
                    reader.bytes()?,
                    "xray.proxy.shadowsocks_2022.RelayServerConfig",
                );
                while packed.more() {
                    networks.push(packed.varint()?);
                }
            }
            (4, 0) => networks.push(reader.varint()?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut pairs = vec![
        (
            "method",
            Json::Str(
                method
                    .ok_or("xray.proxy.shadowsocks_2022.RelayServerConfig: no method".to_owned())?,
            ),
        ),
        (
            "password",
            Json::Str(master.ok_or(
                "xray.proxy.shadowsocks_2022.RelayServerConfig: no master key".to_owned(),
            )?),
        ),
        ("destinations", Json::Arr(destinations)),
    ];
    if let Some(network) = ss2022_networks(&networks) {
        pairs.push(("network", Json::Str(network)));
    }
    Ok(object(pairs))
}

/// One relay destination: its key, address and port, with the email and level the reference keys its policy and stats on.
fn ss2022_relay_destination(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.shadowsocks_2022.RelayDestination");
    let mut key = None;
    let mut address = None;
    let mut port = None;
    let mut email = None;
    let mut level = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => key = Some(account_text(&mut reader)?),
            (2, 2) => address = Some(ip_or_domain(reader.bytes()?)?),
            (3, 0) => {
                let value = reader.varint()?;
                port = Some(u16::try_from(value).map_err(|_| {
                    format!(
                        "xray.proxy.shadowsocks_2022.RelayDestination: port {value} is above 65535"
                    )
                })?);
            }
            (4, 2) => {
                email = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| {
                            "xray.proxy.shadowsocks_2022.RelayDestination: email is not utf-8"
                                .to_owned()
                        })?
                        .to_owned(),
                );
            }
            (5, 0) => level = Some(reader.varint()?.try_into().unwrap_or(u32::MAX)),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut pairs = vec![
        (
            "key",
            Json::Str(
                key.ok_or("xray.proxy.shadowsocks_2022.RelayDestination: no key".to_owned())?,
            ),
        ),
        (
            "address",
            Json::Str(
                address
                    .ok_or("xray.proxy.shadowsocks_2022.RelayDestination: no address".to_owned())?,
            ),
        ),
        (
            "port",
            Json::Num(f64::from(port.ok_or(
                "xray.proxy.shadowsocks_2022.RelayDestination: no port".to_owned(),
            )?)),
        ),
    ];
    if let Some(email) = email {
        pairs.push(("email", Json::Str(email)));
    }
    if let Some(level) = level {
        pairs.push(("level", Json::Num(f64::from(level))));
    }
    Ok(object(pairs))
}

/// A 2022 outbound dials the one server its config names: the same endpoint shape, with the method and key in the entry the JSON path reads.
fn ss2022_outbound_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.shadowsocks_2022.ClientConfig");
    let mut address = None;
    let mut port = None;
    let mut method = None;
    let mut key = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => address = Some(ip_or_domain(reader.bytes()?)?),
            (2, 0) => {
                let value = reader.varint()?;
                port = Some(u16::try_from(value).map_err(|_| {
                    format!("xray.proxy.shadowsocks_2022.ClientConfig: port {value} is above 65535")
                })?);
            }
            (3, 2) => method = Some(account_text(&mut reader)?),
            (4, 2) => key = Some(account_text(&mut reader)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok(object(vec![(
        "servers",
        Json::Arr(vec![object(vec![
            (
                "address",
                Json::Str(
                    address
                        .ok_or("xray.proxy.shadowsocks_2022.ClientConfig: no address".to_owned())?,
                ),
            ),
            (
                "port",
                Json::Num(f64::from(port.ok_or(
                    "xray.proxy.shadowsocks_2022.ClientConfig: no port".to_owned(),
                )?)),
            ),
            (
                "method",
                Json::Str(
                    method
                        .ok_or("xray.proxy.shadowsocks_2022.ClientConfig: no method".to_owned())?,
                ),
            ),
            (
                "password",
                Json::Str(
                    key.ok_or("xray.proxy.shadowsocks_2022.ClientConfig: no key".to_owned())?,
                ),
            ),
        ])]),
    )]))
}

/// A socks server: the authentication it asks for and the accounts it accepts.
///
/// The accounts arrive as a protobuf map — one entry per account, the name in the
/// first field and the password in the second. The address the server names and its
/// datagram switch are read and dropped: this front answers the relay address it
/// bound itself and always carries datagrams.
fn socks_inbound_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.socks.ServerConfig");
    let mut auth_type = 0u64;
    let mut accounts: Vec<Json> = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => auth_type = reader.varint()?,
            (2, 2) => {
                let (user, pass) = socks_account_entry(reader.bytes()?)?;
                accounts.push(object(vec![
                    ("user", Json::Str(user)),
                    ("pass", Json::Str(pass)),
                ]));
            }
            (3, 2) => {
                ip_or_domain(reader.bytes()?)?;
            }
            (4, 0) => {
                reader.varint()?;
            }
            (6, 0) => return Err(reader.uncarried("user_level")),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let auth = match auth_type {
        0 => "noauth",
        1 => "password",
        other => {
            return Err(format!(
                "xray.proxy.socks.ServerConfig: auth type {other} is not carried"
            ))
        }
    };
    let mut pairs = vec![("auth", Json::Str(auth.to_owned()))];
    if !accounts.is_empty() {
        pairs.push(("accounts", Json::Arr(accounts)));
    }
    Ok(object(pairs))
}

/// One entry of the account map: the name in the first field, the password in the second.
fn socks_account_entry(bytes: &[u8]) -> Result<(String, String), String> {
    let mut reader = Reader::new(bytes, "xray.proxy.socks.ServerConfig.accounts");
    let mut user = None;
    let mut pass = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => user = Some(account_text(&mut reader)?),
            (2, 2) => pass = Some(account_text(&mut reader)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok((
        user.ok_or("xray.proxy.socks.ServerConfig: an account with no name")?,
        pass.ok_or("xray.proxy.socks.ServerConfig: an account with no password")?,
    ))
}

/// A socks client dials the one endpoint its config names, with the credential it names.
fn socks_outbound_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.socks.ClientConfig");
    let mut server = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                server = Some(credential_endpoint(
                    reader.bytes()?,
                    "xray.proxy.socks.Account",
                )?);
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let (address, port, credential) = server.ok_or("xray.proxy.socks.ClientConfig: no server")?;
    Ok(client_servers(address, port, credential, Vec::new()))
}

/// A http client dials the one endpoint its config names, with the credential and the
/// headers it names.
fn http_outbound_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.http.ClientConfig");
    let mut server = None;
    let mut headers = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                server = Some(credential_endpoint(
                    reader.bytes()?,
                    "xray.proxy.http.Account",
                )?);
            }
            (2, 2) => headers.push(http_header(reader.bytes()?)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let (address, port, credential) = server.ok_or("xray.proxy.http.ClientConfig: no server")?;
    Ok(client_servers(address, port, credential, headers))
}

/// One client endpoint as the JSON `servers` entry the tree's hops read.
fn client_servers(
    address: String,
    port: u16,
    credential: Option<(String, String)>,
    headers: Vec<Json>,
) -> Json {
    let mut users = Vec::new();
    if let Some((user, pass)) = credential {
        users.push(object(vec![
            ("user", Json::Str(user)),
            ("pass", Json::Str(pass)),
        ]));
    }
    let mut server = vec![
        ("address", Json::Str(address)),
        ("port", Json::Num(f64::from(port))),
        ("users", Json::Arr(users)),
    ];
    if !headers.is_empty() {
        server.push(("headers", Json::Arr(headers)));
    }
    object(vec![("servers", Json::Arr(vec![object(server)]))])
}

/// One `xray.proxy.http.Header` as the JSON field the hop writes.
fn http_header(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.http.Header");
    let mut key = None;
    let mut value = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => key = Some(account_text(&mut reader)?),
            (2, 2) => value = Some(account_text(&mut reader)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok(object(vec![
        (
            "key",
            Json::Str(key.ok_or("xray.proxy.http.Header: no key")?),
        ),
        (
            "value",
            Json::Str(value.ok_or("xray.proxy.http.Header: no value")?),
        ),
    ]))
}

/// The endpoint a client dials: the address, the port, and the credential when the
/// config names one.
type ClientEndpoint = (String, u16, Option<(String, String)>);

/// `common.protocol.ServerEndpoint` for a client whose account is `kind`: the address,
/// the port, and the credential when the config names one. A client may name no
/// credential — a socks greeting then offers no authentication and a CONNECT carries
/// none.
fn credential_endpoint(bytes: &[u8], kind: &'static str) -> Result<ClientEndpoint, String> {
    let mut reader = Reader::new(bytes, "xray.common.protocol.ServerEndpoint");
    let mut address = None;
    let mut port = None;
    let mut credential = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => address = Some(ip_or_domain(reader.bytes()?)?),
            (2, 0) => {
                let value = reader.varint()?;
                port = Some(u16::try_from(value).map_err(|_| {
                    format!("xray.common.protocol.ServerEndpoint: port {value} is above 65535")
                })?);
            }
            (3, 2) => credential = Some(credential_user(reader.bytes()?, kind)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok((
        address.ok_or("xray.common.protocol.ServerEndpoint: no address")?,
        port.ok_or("xray.common.protocol.ServerEndpoint: no port")?,
        credential,
    ))
}

/// A `common.protocol.User` whose account is `kind`; level and email feed the policy
/// and the stats nothing here reads.
fn credential_user(bytes: &[u8], kind: &'static str) -> Result<(String, String), String> {
    let mut reader = Reader::new(bytes, "xray.common.protocol.User");
    let mut account = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => return Err(reader.uncarried("user level")),
            (2, 2) => return Err(reader.uncarried("user email")),
            (3, 2) => {
                let (name, value) = typed_message(reader.bytes()?)?;
                if name != kind {
                    return Err(format!("account `{name}` is not carried as `{kind}`"));
                }
                account = Some(credential_account(value, kind)?);
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    account.ok_or("xray.common.protocol.User: no account".to_owned())
}

/// The name and the password an HTTP or SOCKS account carries.
fn credential_account(bytes: &[u8], kind: &'static str) -> Result<(String, String), String> {
    let mut reader = Reader::new(bytes, kind);
    let mut user = None;
    let mut pass = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => user = Some(account_text(&mut reader)?),
            (2, 2) => pass = Some(account_text(&mut reader)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok((
        user.ok_or_else(|| format!("{kind}: no username"))?,
        pass.ok_or_else(|| format!("{kind}: no password"))?,
    ))
}

fn freedom_settings(bytes: &[u8]) -> Result<Option<Json>, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.freedom.Config");
    let mut redirect = None;
    let mut domain = None;
    let mut fragment = None;
    let mut proxy_protocol = None;
    let mut noises = Vec::new();
    let mut rules = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => domain = Some(freedom_domain_strategy(reader.varint()?)?),
            (3, 2) => redirect = destination_override(reader.bytes()?)?,
            (4, 0) => return Err(reader.uncarried("user_level")),
            (5, 2) => fragment = Some(freedom_fragment(reader.bytes()?)?),
            (6, 0) => {
                proxy_protocol = Some(u32_value(
                    reader.varint()?,
                    "xray.proxy.freedom.Config: proxy_protocol",
                )?);
            }
            (7, 2) => noises.push(freedom_noise(reader.bytes()?)?),
            (8, 2) => rules.push(freedom_final_rule(reader.bytes()?)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut pairs = Vec::new();
    if let Some(redirect) = redirect {
        pairs.push(("redirect", Json::Str(redirect)));
    }
    if let Some(domain) = domain {
        pairs.push(("domainStrategy", Json::Str(domain.to_owned())));
    }
    if let Some(proxy_protocol) = proxy_protocol {
        pairs.push(("proxyProtocol", Json::Num(f64::from(proxy_protocol))));
    }
    if let Some(fragment) = fragment {
        pairs.push(("fragment", fragment));
    }
    if !noises.is_empty() {
        pairs.push(("noises", Json::Arr(noises)));
    }
    if !rules.is_empty() {
        pairs.push(("finalRules", Json::Arr(rules)));
    }
    Ok((!pairs.is_empty()).then(|| object(pairs)))
}

fn freedom_domain_strategy(value: u64) -> Result<&'static str, String> {
    match value {
        0 => Ok("AsIs"),
        1 => Ok("UseIP"),
        2 => Ok("UseIPv4"),
        3 => Ok("UseIPv6"),
        4 => Ok("UseIPv4v6"),
        5 => Ok("UseIPv6v4"),
        6 => Ok("ForceIP"),
        7 => Ok("ForceIPv4"),
        8 => Ok("ForceIPv6"),
        9 => Ok("ForceIPv4v6"),
        10 => Ok("ForceIPv6v4"),
        other => Err(format!(
            "xray.transport.internet.DomainStrategy: strategy {other} is not carried"
        )),
    }
}

fn freedom_fragment(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.freedom.Fragment");
    let mut fields = [0u64; 8];
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1..=8, 0) => fields[field as usize - 1] = reader.varint()?,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let packets = match (fields[0], fields[1]) {
        (0, 1) => "tlshello".to_owned(),
        (0, _) => String::new(),
        (from, to) => freedom_range_text(from, to),
    };
    Ok(object(vec![
        ("packets", Json::Str(packets)),
        (
            "length",
            Json::Str(freedom_range_text(fields[2], fields[3])),
        ),
        (
            "interval",
            Json::Str(freedom_range_text(fields[4], fields[5])),
        ),
        (
            "maxSplit",
            Json::Str(freedom_range_text(fields[6], fields[7])),
        ),
    ]))
}

fn freedom_range_text(from: u64, to: u64) -> String {
    if from == to {
        from.to_string()
    } else {
        format!("{from}-{to}")
    }
}

fn freedom_noise(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.freedom.Noise");
    let mut length = (0u64, 0u64);
    let mut delay = (0u64, 0u64);
    let mut packet = None;
    let mut apply_to = String::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => length.0 = reader.varint()?,
            (2, 0) => length.1 = reader.varint()?,
            (3, 0) => delay.0 = reader.varint()?,
            (4, 0) => delay.1 = reader.varint()?,
            (5, 2) => packet = Some(reader.bytes()?),
            (6, 2) => {
                std::str::from_utf8(reader.bytes()?)
                    .map_err(|_| "xray.proxy.freedom.Noise: apply_to is not utf-8".to_owned())?
                    .clone_into(&mut apply_to);
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    // An explicit packet wins even when empty; otherwise zero length is empty and a range draws bytes.
    let (kind, text) = match packet {
        Some(packet) => ("hex", hex(packet)),
        None if length == (0, 0) => ("str", String::new()),
        None => ("rand", freedom_range_text(length.0, length.1)),
    };
    Ok(object(vec![
        ("type", Json::Str(kind.to_owned())),
        ("packet", Json::Str(text)),
        ("delay", Json::Str(freedom_range_text(delay.0, delay.1))),
        ("applyTo", Json::Str(apply_to)),
    ]))
}

fn freedom_final_rule(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.freedom.FinalRuleConfig");
    let mut action = "allow";
    let mut networks = Vec::new();
    let mut ports = None;
    let mut ips = Vec::new();
    let mut block_delay = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => {
                action = match reader.varint()? {
                    0 => "allow",
                    1 => "block",
                    other => {
                        return Err(format!(
                            "xray.proxy.freedom.FinalRuleConfig: action {other} is not carried"
                        ));
                    }
                };
            }
            (2, 0) => networks.push(freedom_network(reader.varint()?)),
            (2, 2) => {
                let mut packed = Reader::new(reader.bytes()?, "xray.common.net.Network");
                while packed.more() {
                    networks.push(freedom_network(packed.varint()?));
                }
            }
            (3, 2) => ports = Some(freedom_port_selector(reader.bytes()?)?),
            (4, 2) => ips.push(Json::Str(ip_rule(reader.bytes()?)?)),
            (5, 2) => {
                let (min, max) = freedom_range(reader.bytes()?)?;
                block_delay = Some(Json::Str(freedom_range_text(min, max)));
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut pairs = vec![("action", Json::Str(action.to_owned()))];
    if !networks.is_empty() {
        pairs.push((
            "network",
            Json::Arr(
                networks
                    .into_iter()
                    .map(|network| Json::Str(network.to_owned()))
                    .collect(),
            ),
        ));
    }
    if let Some(ports) = ports {
        pairs.push(("port", Json::Str(ports)));
    }
    if !ips.is_empty() {
        pairs.push(("ip", Json::Arr(ips)));
    }
    if let Some(block_delay) = block_delay {
        pairs.push(("blockDelay", block_delay));
    }
    Ok(object(pairs))
}

fn freedom_network(value: u64) -> &'static str {
    match value {
        2 => "tcp",
        3 => "udp",
        4 => "unix",
        _ => "unknown",
    }
}

fn freedom_port_selector(bytes: &[u8]) -> Result<String, String> {
    let mut reader = Reader::new(bytes, "xray.common.net.PortList");
    let mut parts = Vec::new();
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                let (from, to) = port_range(reader.bytes()?)?;
                parts.push(freedom_range_text(u64::from(from), u64::from(to)));
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok(parts.join(","))
}

fn freedom_range(bytes: &[u8]) -> Result<(u64, u64), String> {
    let mut reader = Reader::new(bytes, "xray.proxy.freedom.Range");
    let mut min = 0;
    let mut max = 0;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 0) => min = reader.varint()?,
            (2, 0) => max = reader.varint()?,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok((min, max))
}

/// The reference's freedom rewrite: an address, a port, or both, with the omitted half kept from
/// the flow. An empty address and a zero port are both unset, so they leave the request as it is.
fn destination_override(bytes: &[u8]) -> Result<Option<String>, String> {
    let mut reader = Reader::new(bytes, "xray.proxy.freedom.DestinationOverride");
    let mut server = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => server = Some(override_endpoint(reader.bytes()?)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let Some((address, port)) = server else {
        return Err("xray.proxy.freedom.DestinationOverride: no server".to_owned());
    };
    match (address, port) {
        (address, 0) if address.is_empty() => Ok(None),
        (address, 0) if address.contains(':') => Ok(Some(format!("[{address}]:0"))),
        (address, 0) => Ok(Some(format!("{address}:0"))),
        (address, port) if address.is_empty() => Ok(Some(format!(":{port}"))),
        (address, port) if address.contains(':') => Ok(Some(format!("[{address}]:{port}"))),
        (address, port) => Ok(Some(format!("{address}:{port}"))),
    }
}

fn override_endpoint(bytes: &[u8]) -> Result<(String, u16), String> {
    let mut reader = Reader::new(bytes, "xray.common.protocol.ServerEndpoint");
    let (mut address, mut port): (Option<String>, Option<u16>) = (None, None);
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => address = Some(ip_or_domain(reader.bytes()?)?),
            (2, 0) => {
                port = Some(u16::try_from(reader.varint()?).map_err(|_| {
                    "xray.common.protocol.ServerEndpoint: a port above 65535".to_owned()
                })?);
            }
            (3, 2) => return Err(reader.uncarried("server endpoint user")),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    Ok((address.unwrap_or_default(), port.unwrap_or(0)))
}

fn object(pairs: Vec<(&str, Json)>) -> Json {
    Json::Obj(
        pairs
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

/// One protobuf message reader, walked field by field to the message's end.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    message: &'static str,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8], message: &'static str) -> Self {
        Self {
            buf,
            pos: 0,
            message,
        }
    }

    /// Whether any bytes of the message are left, which is how a packed field's values end.
    pub(crate) fn more(&self) -> bool {
        self.pos < self.buf.len()
    }

    /// The next field number and wire type, or `None` at the message's end.
    pub(crate) fn field(&mut self) -> Result<Option<(u64, u8)>, String> {
        if self.pos == self.buf.len() {
            return Ok(None);
        }
        let key = self.varint()?;
        let (field, wire) = (key >> 3, (key & 7) as u8);
        if field == 0 {
            return Err(format!("{}: field number 0", self.message));
        }
        if !matches!(wire, 0 | 1 | 2 | 5) {
            return Err(format!(
                "{}: field {field} has wire type {wire}",
                self.message
            ));
        }
        Ok(Some((field, wire)))
    }

    pub(crate) fn varint(&mut self) -> Result<u64, String> {
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = *self
                .buf
                .get(self.pos)
                .ok_or_else(|| format!("{}: a varint runs past the message", self.message))?;
            self.pos += 1;
            if shift >= 64 {
                return Err(format!(
                    "{}: a varint is longer than ten bytes",
                    self.message
                ));
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }

    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], String> {
        let length = self.varint()?;
        let end = self
            .pos
            .checked_add(
                usize::try_from(length)
                    .map_err(|_| format!("{}: a length overflows", self.message))?,
            )
            .filter(|end| *end <= self.buf.len())
            .ok_or_else(|| {
                format!(
                    "{}: a length-delimited field runs past the message",
                    self.message
                )
            })?;
        let field = &self.buf[self.pos..end];
        self.pos = end;
        Ok(field)
    }

    /// Consumes one field this reader does not read, so a newer writer's field is skipped rather than refused.
    pub(crate) fn skip(&mut self, wire: u8) -> Result<(), String> {
        match wire {
            0 => {
                self.varint()?;
            }
            1 | 5 => {
                let width = if wire == 1 { 8 } else { 4 };
                self.pos = self
                    .pos
                    .checked_add(width)
                    .filter(|end| *end <= self.buf.len())
                    .ok_or_else(|| {
                        format!("{}: a fixed field runs past the message", self.message)
                    })?;
            }
            2 => {
                self.bytes()?;
            }
            _ => return Err(format!("{}: wire type {wire} is not carried", self.message)),
        }
        Ok(())
    }

    fn refuse(&self, field: u64, wire: u8) -> String {
        format!(
            "{}: field {field} (wire type {wire}) is not carried",
            self.message
        )
    }

    fn uncarried(&self, what: &str) -> String {
        format!("{}: {what} is not carried", self.message)
    }
}

/// `xray.app.observatory.Config`: the legacy probe loop, in the shape this
/// tree's own observatory reads.
fn observatory_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.app.observatory.Config");
    let mut selectors = Vec::new();
    let mut url = None;
    let mut interval = None;
    let mut concurrency = false;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (2, 2) => selectors.push(
                std::str::from_utf8(reader.bytes()?)
                    .map_err(|_| "xray.app.observatory.Config: a selector is not utf-8".to_owned())?
                    .to_owned(),
            ),
            (3, 2) => {
                url = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| {
                            "xray.app.observatory.Config: the URL is not utf-8".to_owned()
                        })?
                        .to_owned(),
                );
            }
            (4, 0) => interval = Some(reader.varint()?.cast_signed()),
            (5, 0) => concurrency = reader.varint()? != 0,
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut pairs = Vec::new();
    if !selectors.is_empty() {
        pairs.push((
            "subjectSelector",
            Json::Arr(selectors.into_iter().map(Json::Str).collect()),
        ));
    }
    if let Some(url) = url.filter(|url| !url.is_empty()) {
        pairs.push(("probeURL", Json::Str(url)));
    }
    if let Some(interval) = interval.filter(|nanos| *nanos != 0) {
        pairs.push(("probeInterval", Json::Str(format!("{interval}ns"))));
    }
    if concurrency {
        pairs.push(("enableConcurrency", Json::Bool(true)));
    }
    Ok(object(pairs))
}

/// `xray.app.observatory.burst.Config`: the sampled probe loop and its
/// required `HealthPingConfig`.
fn burst_observatory_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.app.observatory.burst.Config");
    let mut selectors = Vec::new();
    let mut ping = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (2, 2) => selectors.push(
                std::str::from_utf8(reader.bytes()?)
                    .map_err(|_| {
                        "xray.app.observatory.burst.Config: a selector is not utf-8".to_owned()
                    })?
                    .to_owned(),
            ),
            (3, 2) => ping = Some(healthping_settings(reader.bytes()?)?),
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut pairs = Vec::new();
    if !selectors.is_empty() {
        pairs.push((
            "subjectSelector",
            Json::Arr(selectors.into_iter().map(Json::Str).collect()),
        ));
    }
    pairs.push(("pingConfig", ping.unwrap_or_else(|| Json::Obj(Vec::new()))));
    Ok(object(pairs))
}

/// `xray.app.observatory.burst.HealthPingConfig`: the sampler's defaults,
/// destination, connectivity check, interval, window and method.
fn healthping_settings(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, "xray.app.observatory.burst.HealthPingConfig");
    let mut destination = None;
    let mut connectivity = None;
    let mut interval = None;
    let mut sampling = 0;
    let mut timeout = None;
    let mut method = None;
    while let Some((field, wire)) = reader.field()? {
        match (field, wire) {
            (1, 2) => {
                destination = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| {
                            "xray.app.observatory.burst.HealthPingConfig: the destination is not utf-8"
                                .to_owned()
                        })?
                        .to_owned(),
                );
            }
            (2, 2) => {
                connectivity = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| {
                            "xray.app.observatory.burst.HealthPingConfig: the connectivity URL is not utf-8"
                                .to_owned()
                        })?
                        .to_owned(),
                );
            }
            (3, 0) => interval = Some(reader.varint()?.cast_signed()),
            (4, 0) => {
                sampling = i32::try_from(reader.varint()?.cast_signed()).map_err(|_| {
                    "xray.app.observatory.burst.HealthPingConfig: sampling overflows".to_owned()
                })?;
            }
            (5, 0) => timeout = Some(reader.varint()?.cast_signed()),
            (6, 2) => {
                method = Some(
                    std::str::from_utf8(reader.bytes()?)
                        .map_err(|_| {
                            "xray.app.observatory.burst.HealthPingConfig: the method is not utf-8"
                                .to_owned()
                        })?
                        .to_owned(),
                );
            }
            _ => return Err(reader.refuse(field, wire)),
        }
    }
    let mut pairs = Vec::new();
    if let Some(destination) = destination.filter(|url| !url.is_empty()) {
        pairs.push(("destination", Json::Str(destination)));
    }
    if let Some(connectivity) = connectivity.filter(|url| !url.is_empty()) {
        pairs.push(("connectivity", Json::Str(connectivity)));
    }
    if let Some(interval) = interval.filter(|nanos| *nanos != 0) {
        pairs.push(("interval", Json::Str(format!("{interval}ns"))));
    }
    if sampling != 0 {
        pairs.push(("sampling", Json::Num(f64::from(sampling))));
    }
    if let Some(timeout) = timeout.filter(|nanos| *nanos != 0) {
        pairs.push(("timeout", Json::Str(format!("{timeout}ns"))));
    }
    if let Some(raw) = method {
        let method = raw.trim();
        if method.is_empty() {
            if !raw.is_empty() {
                pairs.push(("httpMethod", Json::Str("GET".to_owned())));
                pairs.push(("httpMethodBlank", Json::Bool(true)));
            }
        } else {
            pairs.push(("httpMethod", Json::Str(method.to_owned())));
        }
    }
    Ok(object(pairs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        while value >= 0x80 {
            out.push(value as u8 | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
        out
    }

    fn varint_field(field: u64, value: u64) -> Vec<u8> {
        let mut out = varint(field << 3);
        out.extend(varint(value));
        out
    }

    fn bytes_field(field: u64, value: &[u8]) -> Vec<u8> {
        let mut out = varint(field << 3 | 2);
        out.extend(varint(value.len() as u64));
        out.extend_from_slice(value);
        out
    }

    fn message(fields: &[Vec<u8>]) -> Vec<u8> {
        fields.concat()
    }

    fn typed(name: &str, value: &[u8]) -> Vec<u8> {
        message(&[bytes_field(1, name.as_bytes()), bytes_field(2, value)])
    }

    #[test]
    fn a_protobuf_sniffer_reaches_the_json_inbound() {
        let sniffing = message(&[
            varint_field(1, 1),
            bytes_field(2, b"tls"),
            varint_field(4, 1),
            varint_field(5, 1),
        ]);
        let range = message(&[varint_field(1, 1080), varint_field(2, 1080)]);
        let list = message(&[bytes_field(1, &range)]);
        let receiver = message(&[bytes_field(1, &list), bytes_field(6, &sniffing)]);
        let decoded = receiver_config(&receiver).expect("receiver");
        let sniffing = decoded.3.expect("sniffing");
        assert_eq!(sniffing.get("enabled"), Some(&Json::Bool(true)));
        assert_eq!(
            sniffing.get("destOverride"),
            Some(&Json::Arr(vec![Json::Str("tls".to_owned())]))
        );
        assert_eq!(sniffing.get("metadataOnly"), Some(&Json::Bool(true)));
        assert_eq!(sniffing.get("routeOnly"), Some(&Json::Bool(true)));
    }

    fn receiver(port: u64, listen: Option<&[u8]>) -> Vec<u8> {
        let range = message(&[varint_field(1, port), varint_field(2, port)]);
        let list = message(&[bytes_field(1, &range)]);
        let mut fields = vec![bytes_field(1, &list)];
        if let Some(ip) = listen {
            fields.push(bytes_field(2, &bytes_field(1, ip)));
        }
        message(&fields)
    }

    fn http_inbound(receiver: &[u8], settings: &[u8]) -> Vec<u8> {
        message(&[
            bytes_field(2, &typed("xray.app.proxyman.ReceiverConfig", receiver)),
            bytes_field(3, &typed("xray.proxy.http.ServerConfig", settings)),
        ])
    }

    fn freedom_outbound() -> Vec<u8> {
        // `FinalRules: []{{Action: Allow}}` — Allow is the proto3 default, so the entry is empty on the wire.
        let rules = bytes_field(8, &Vec::new());
        message(&[bytes_field(3, &typed("xray.proxy.freedom.Config", &rules))])
    }

    fn config(inbound: &[u8], outbound: &[u8]) -> Vec<u8> {
        message(&[bytes_field(1, inbound), bytes_field(2, outbound)])
    }

    fn http_scenario(port: u64) -> Vec<u8> {
        config(
            &http_inbound(&receiver(port, Some(&[127, 0, 0, 1])), &[]),
            &freedom_outbound(),
        )
    }

    fn receiver_range(from: u64, to: u64, listen: Option<&[u8]>) -> Vec<u8> {
        let range = message(&[varint_field(1, from), varint_field(2, to)]);
        let mut fields = vec![bytes_field(1, &bytes_field(1, &range))];
        if let Some(ip) = listen {
            fields.push(bytes_field(2, &bytes_field(1, ip)));
        }
        message(&fields)
    }

    fn dokodemo_inbound(receiver: &[u8], settings: &[u8]) -> Vec<u8> {
        message(&[
            bytes_field(2, &typed("xray.app.proxyman.ReceiverConfig", receiver)),
            bytes_field(3, &typed("xray.proxy.dokodemo.Config", settings)),
        ])
    }

    fn dokodemo(port: u64, networks: &[Vec<u8>]) -> Vec<u8> {
        let mut settings = vec![
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, port),
        ];
        settings.extend(networks.iter().cloned());
        dokodemo_inbound(&receiver(port, Some(&[127, 0, 0, 1])), &message(&settings))
    }

    fn vmess_account(id: &[u8], security: Option<u64>, tests_enabled: Option<&str>) -> Vec<u8> {
        let mut account = vec![bytes_field(1, id)];
        if let Some(value) = security {
            account.push(bytes_field(3, &varint_field(1, value)));
        }
        if let Some(text) = tests_enabled {
            account.push(bytes_field(4, text.as_bytes()));
        }
        typed("xray.proxy.vmess.Account", &message(&account))
    }

    fn vmess_user(account: &[u8]) -> Vec<u8> {
        bytes_field(3, account)
    }

    #[test]
    fn the_http_scenario_decodes_to_the_json_this_tree_serves() {
        let json = to_json(&http_scenario(5000)).expect("the pinned shape decodes");
        let inbounds = json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds");
        assert_eq!(inbounds.len(), 1);
        assert_eq!(
            inbounds[0].get("protocol").and_then(Json::as_str),
            Some("http")
        );
        assert_eq!(inbounds[0].get("port").and_then(Json::as_port), Some(5000));
        assert_eq!(
            inbounds[0].get("listen").and_then(Json::as_str),
            Some("127.0.0.1")
        );
        let outbounds = json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds");
        assert_eq!(
            outbounds[0].get("protocol").and_then(Json::as_str),
            Some("freedom")
        );
    }

    #[test]
    fn an_app_is_not_serving_state() {
        let mut bytes = http_scenario(5000);
        bytes.extend(bytes_field(4, &typed("xray.app.dispatcher.Config", &[])));
        let json = to_json(&bytes).expect("apps are skipped");
        assert_eq!(
            json.get("inbounds")
                .and_then(Json::as_arr)
                .map(<[Json]>::len),
            Some(1)
        );
    }

    fn endpoint(address: &[u8], port: u64, network: u64) -> Vec<u8> {
        message(&[
            varint_field(1, network),
            bytes_field(2, address),
            varint_field(3, port),
        ])
    }

    fn domain_rule(kind: u64, value: &[u8]) -> Vec<u8> {
        bytes_field(2, &message(&[varint_field(1, kind), bytes_field(2, value)]))
    }

    fn dns_app(settings: &[u8]) -> Vec<u8> {
        let mut bytes = http_scenario(5000);
        bytes.extend(bytes_field(4, &typed("xray.app.dns.Config", settings)));
        bytes
    }

    fn dns_config() -> Json {
        let server = message(&[
            bytes_field(1, &endpoint(&bytes_field(1, &[192, 0, 2, 8]), 53, 3)),
            bytes_field(2, &domain_rule(3, b"example.com")),
            bytes_field(9, b"server-in"),
            varint_field(17, 7),
            bytes_field(5, &[192, 0, 2, 4]),
            varint_field(6, 1),
            varint_field(7, 1),
            varint_field(10, 500),
            varint_field(11, 0),
            varint_field(12, 1),
            varint_field(15, 1),
            varint_field(16, 60),
        ]);
        let mapped = message(&[
            bytes_field(2, &domain_rule(3, b"host.test")),
            bytes_field(3, &[127, 0, 0, 1]),
        ]);
        let proxy = message(&[
            bytes_field(2, &domain_rule(3, b"alias.test")),
            bytes_field(4, b"real.test"),
        ]);
        let settings = message(&[
            bytes_field(5, &server),
            bytes_field(3, &[192, 0, 2, 9]),
            bytes_field(6, b"dns-in"),
            bytes_field(4, &mapped),
            bytes_field(4, &proxy),
            varint_field(8, 1),
            varint_field(12, 1),
            varint_field(13, 60),
            varint_field(9, 3),
            varint_field(10, 1),
            varint_field(11, 1),
            varint_field(14, 1),
        ]);
        to_json(&dns_app(&settings)).expect("the DNS app decodes")
    }

    #[test]
    fn the_dns_app_decodes_to_the_resolver_this_tree_builds() {
        let json = dns_config();
        let dns = json.get("dns").expect("dns");
        assert_eq!(
            dns.get("clientIp").and_then(Json::as_str),
            Some("192.0.2.9")
        );
        assert_eq!(dns.get("serveExpiredTTL").and_then(Json::as_u32), Some(60));
        assert_eq!(
            dns.get("queryStrategy").and_then(Json::as_str),
            Some("UseSys")
        );
        assert_eq!(
            dns.get("disableFallback").and_then(Json::as_bool),
            Some(true)
        );
        assert_eq!(
            dns.get("enableParallelQuery").and_then(Json::as_bool),
            Some(true)
        );
        assert_eq!(
            dns.get("hosts")
                .and_then(|hosts| hosts.get("full:host.test"))
                .and_then(Json::as_str),
            Some("127.0.0.1")
        );
        assert_eq!(
            dns.get("hosts")
                .and_then(|hosts| hosts.get("full:alias.test"))
                .and_then(Json::as_str),
            Some("real.test")
        );
        crate::dnsapp::Resolver::from_root(&json)
            .expect("the bridge's JSON builds a resolver")
            .expect("the resolver is present");
    }

    #[test]
    fn the_dns_name_server_decodes_to_the_fields_the_loader_reads() {
        let json = dns_config();
        let server = &json
            .get("dns")
            .and_then(|dns| dns.get("servers"))
            .and_then(Json::as_arr)
            .expect("servers")[0];
        assert_eq!(
            server.get("address").and_then(Json::as_str),
            Some("192.0.2.8")
        );
        assert_eq!(server.get("port").and_then(Json::as_port), Some(53));
        assert_eq!(
            server.get("clientIp").and_then(Json::as_str),
            Some("192.0.2.4")
        );
        assert_eq!(
            server.get("queryStrategy").and_then(Json::as_str),
            Some("UseIP4")
        );
        assert_eq!(server.get("timeoutMs").and_then(Json::as_u32), Some(500));
        assert_eq!(
            server.get("disableCache").and_then(Json::as_bool),
            Some(false)
        );
        assert_eq!(server.get("serveStale").and_then(Json::as_bool), Some(true));
        assert_eq!(
            server.get("serveExpiredTTL").and_then(Json::as_u32),
            Some(60)
        );
        assert_eq!(
            server.get("skipFallback").and_then(Json::as_bool),
            Some(true)
        );
        assert_eq!(server.get("finalQuery").and_then(Json::as_bool), Some(true));
        assert_eq!(
            server
                .get("domains")
                .and_then(Json::as_arr)
                .expect("domains")[0]
                .as_str(),
            Some("full:example.com")
        );
    }

    #[test]
    fn a_dns_scheme_stays_in_the_address_the_loader_reads() {
        let settings = message(&[bytes_field(
            5,
            &message(&[bytes_field(
                1,
                &endpoint(&bytes_field(2, b"https://dns.google/dns-query"), 0, 3),
            )]),
        )]);
        let json = to_json(&dns_app(&settings)).expect("the DNS app decodes");
        let server = &json
            .get("dns")
            .and_then(|dns| dns.get("servers"))
            .and_then(Json::as_arr)
            .expect("servers")[0];
        assert_eq!(
            server.get("address").and_then(Json::as_str),
            Some("https://dns.google/dns-query")
        );
        assert!(server.get("port").is_none());
    }

    #[test]
    fn a_dns_ip_filter_decodes_with_its_prior_flag() {
        let cidr = message(&[bytes_field(1, &[198, 51, 100, 0]), varint_field(2, 24)]);
        let custom = message(&[bytes_field(1, &cidr)]);
        let rule = message(&[bytes_field(2, &custom)]);
        let server = message(&[
            bytes_field(1, &endpoint(&bytes_field(1, &[192, 0, 2, 8]), 53, 3)),
            bytes_field(3, &rule),
            varint_field(8, 1),
        ]);
        let json =
            to_json(&dns_app(&message(&[bytes_field(5, &server)]))).expect("the DNS app decodes");
        let expected = json
            .get("dns")
            .and_then(|dns| dns.get("servers"))
            .and_then(Json::as_arr)
            .expect("servers")[0]
            .get("expectedIPs")
            .and_then(Json::as_arr)
            .expect("expectedIPs");
        assert_eq!(expected.len(), 2);
        assert_eq!(expected[0].as_str(), Some("198.51.100.0/24"));
        assert_eq!(expected[1].as_str(), Some("*"));
    }

    #[test]
    fn an_unread_field_is_refused_by_number() {
        let mut receiver = receiver(5000, Some(&[127, 0, 0, 1]));
        receiver.extend(varint_field(7, 1));
        let bytes = config(&http_inbound(&receiver, &[]), &freedom_outbound());
        let error = to_json(&bytes).expect_err("refused");
        assert!(error.contains("field 7"), "{error}");
    }

    #[test]
    fn a_receiver_stream_of_another_shape_is_refused_by_the_reader() {
        let mut receiver = receiver(5000, None);
        receiver.extend(bytes_field(3, &typed("xray.app.dispatcher.Config", &[])));
        let bytes = config(&http_inbound(&receiver, &[]), &freedom_outbound());
        let error = to_json(&bytes).expect_err("refused");
        assert!(
            error.contains("xray.transport.internet.StreamConfig"),
            "{error}"
        );
    }

    #[test]
    fn an_empty_stream_config_is_the_tcp_default() {
        let mut receiver = receiver(5000, None);
        receiver.extend(bytes_field(3, &[]));
        let json = to_json(&config(&http_inbound(&receiver, &[]), &freedom_outbound()))
            .expect("a stream with no fields decodes");
        let stream = json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("streamSettings")
            .expect("stream");
        assert_eq!(stream.get("network").and_then(Json::as_str), Some("tcp"));
        assert!(stream.get("security").is_none());
    }

    #[test]
    fn a_stream_socket_use_ip_policy_decodes_and_another_option_is_refused() {
        let policy = receiver_stream(5000, &bytes_field(6, &varint_field(8, 1)));
        to_json(&config(&http_inbound(&policy, &[]), &freedom_outbound()))
            .expect("the system dial is USE_IP");

        let marked = receiver_stream(5000, &bytes_field(6, &varint_field(1, 1)));
        let error = to_json(&config(&http_inbound(&marked, &[]), &freedom_outbound()))
            .expect_err("a mark is refused");
        assert!(
            error.contains("xray.transport.internet.SocketConfig"),
            "{error}"
        );
    }

    #[test]
    fn a_dokodemo_inbound_decodes_to_the_directive_this_tree_serves() {
        let json = to_json(&config(
            &dokodemo(8080, &[varint_field(7, 2)]),
            &freedom_outbound(),
        ))
        .expect("dokodemo decodes");
        let inbound = &json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0];
        assert_eq!(
            inbound.get("protocol").and_then(Json::as_str),
            Some("dokodemo-door")
        );
        let settings = inbound.get("settings").expect("rewrite settings");
        assert_eq!(
            settings.get("address").and_then(Json::as_str),
            Some("127.0.0.1")
        );
        assert_eq!(settings.get("port").and_then(Json::as_port), Some(8080));
        assert_eq!(settings.get("network").and_then(Json::as_str), Some("tcp"));
    }

    #[test]
    fn packed_and_per_field_networks_read_the_same() {
        let packed = config(
            &dokodemo(8080, &[bytes_field(7, &[2, 3])]),
            &freedom_outbound(),
        );
        let each = config(
            &dokodemo(8080, &[varint_field(7, 2), varint_field(7, 3)]),
            &freedom_outbound(),
        );
        for bytes in [packed, each] {
            let json = to_json(&bytes).expect("both shapes decode");
            let network = json
                .get("inbounds")
                .and_then(Json::as_arr)
                .expect("inbounds")[0]
                .get("settings")
                .expect("settings")
                .get("network")
                .and_then(Json::as_str);
            assert_eq!(network, Some("tcp,udp"));
        }
    }

    #[test]
    fn a_port_range_fans_out_to_one_inbound_per_port() {
        let settings = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, 8080),
            varint_field(7, 2),
        ]);
        let inbound = dokodemo_inbound(
            &receiver_range(42165, 42170, Some(&[127, 0, 0, 1])),
            &settings,
        );
        let json = to_json(&config(&inbound, &freedom_outbound())).expect("the range expands");
        let inbounds = json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds");
        assert_eq!(inbounds.len(), 6);
        assert_eq!(inbounds[0].get("port").and_then(Json::as_port), Some(42165));
        assert_eq!(inbounds[5].get("port").and_then(Json::as_port), Some(42170));
    }

    #[test]
    fn a_port_range_wider_than_the_fanout_is_refused() {
        let settings = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, 8080),
            varint_field(7, 2),
        ]);
        let inbound = dokodemo_inbound(&receiver_range(1000, 1100, None), &settings);
        let error = to_json(&config(&inbound, &freedom_outbound())).expect_err("refused");
        assert!(error.contains("wider fan-out"), "{error}");
    }

    #[test]
    fn a_receiver_marker_stays_independent_of_follow_redirect() {
        let range = message(&[varint_field(1, 8080), varint_field(2, 8080)]);
        let list = message(&[bytes_field(1, &range)]);
        let receiver = message(&[bytes_field(1, &list)]);
        let settings = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, 8080),
            varint_field(5, 1),
            varint_field(7, 2),
        ]);
        let json = to_json(&config(
            &dokodemo_inbound(&receiver, &settings),
            &freedom_outbound(),
        ))
        .expect("followRedirect decodes");
        let inbound = &json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0];
        assert_eq!(
            inbound
                .get("settings")
                .and_then(|settings| settings.get("followRedirect"))
                .and_then(Json::as_bool),
            Some(true)
        );
        assert_eq!(
            inbound
                .get("receiveOriginalDestination")
                .and_then(Json::as_bool),
            Some(false)
        );
    }

    #[test]
    fn a_dokodemo_port_map_decodes() {
        let entry = message(&[bytes_field(1, b"8080"), bytes_field(2, b"127.0.0.1:9090")]);
        let settings = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, 8080),
            bytes_field(3, &entry),
            varint_field(7, 2),
        ]);
        let json = to_json(&config(
            &dokodemo_inbound(&receiver(8080, None), &settings),
            &freedom_outbound(),
        ))
        .expect("portMap decodes");
        let port_map = json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("settings")
            .and_then(|settings| settings.get("portMap"))
            .expect("portMap");
        assert_eq!(
            port_map.get("8080").and_then(Json::as_str),
            Some("127.0.0.1:9090")
        );
    }

    #[test]
    fn a_dokodemo_user_level_decodes() {
        let settings = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, 8080),
            varint_field(6, 7),
            varint_field(7, 2),
        ]);
        let json = to_json(&config(
            &dokodemo_inbound(&receiver(8080, None), &settings),
            &freedom_outbound(),
        ))
        .expect("userLevel decodes");
        let level = json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("settings")
            .and_then(|settings| settings.get("userLevel"))
            .and_then(Json::as_u32);
        assert_eq!(level, Some(7));
    }

    #[test]
    fn a_dokodemo_follow_redirect_decodes() {
        let socket = message(&[varint_field(3, 2), varint_field(4, 1)]);
        let stream = message(&[bytes_field(6, &socket)]);
        let range = message(&[varint_field(1, 8080), varint_field(2, 8080)]);
        let list = message(&[bytes_field(1, &range)]);
        let receiver = message(&[
            bytes_field(1, &list),
            bytes_field(2, &bytes_field(1, &[127, 0, 0, 1])),
            bytes_field(3, &stream),
            varint_field(4, 1),
        ]);
        let settings = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, 8080),
            varint_field(5, 1),
            varint_field(7, 2),
        ]);
        let json = to_json(&config(
            &dokodemo_inbound(&receiver, &settings),
            &freedom_outbound(),
        ))
        .expect("followRedirect decodes");
        let inbound = &json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0];
        let follow = inbound
            .get("settings")
            .and_then(|settings| settings.get("followRedirect"))
            .and_then(Json::as_bool);
        assert_eq!(follow, Some(true));
        assert_eq!(
            inbound
                .get("receiveOriginalDestination")
                .and_then(Json::as_bool),
            Some(true)
        );
        let tproxy = inbound
            .get("streamSettings")
            .and_then(|settings| settings.get("sockopt"))
            .and_then(|sockopt| sockopt.get("tproxy"))
            .and_then(Json::as_str);
        assert_eq!(tproxy, Some("redirect"));
    }

    #[test]
    fn a_dokodemo_with_no_network_is_refused() {
        let error =
            to_json(&config(&dokodemo(8080, &[]), &freedom_outbound())).expect_err("refused");
        assert!(error.contains("no network"), "{error}");
    }

    #[test]
    fn an_account_map_is_refused() {
        let account = message(&[bytes_field(1, b"user"), bytes_field(2, b"pass")]);
        let settings = message(&[bytes_field(2, &account)]);
        let bytes = config(
            &http_inbound(&receiver(5000, None), &settings),
            &freedom_outbound(),
        );
        let error = to_json(&bytes).expect_err("refused");
        assert!(error.contains("account map"), "{error}");
    }

    #[test]
    fn a_freedom_destination_override_becomes_a_redirect() {
        let address = message(&[bytes_field(1, &[127, 0, 0, 1])]);
        let server = message(&[bytes_field(1, &address), varint_field(2, 8080)]);
        let override_message = message(&[bytes_field(1, &server)]);
        let settings = bytes_field(3, &override_message);
        let outbound = message(&[bytes_field(
            3,
            &typed("xray.proxy.freedom.Config", &settings),
        )]);
        let json = to_json(&config(
            &http_inbound(&receiver(5000, None), &[]),
            &outbound,
        ))
        .expect("freedom override decodes");
        let outbound = &json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0];
        let redirect = outbound
            .get("settings")
            .and_then(|settings| settings.get("redirect"))
            .and_then(Json::as_str);
        assert_eq!(redirect, Some("127.0.0.1:8080"));
    }

    #[test]
    fn a_freedom_address_only_override_keeps_the_requested_port() {
        let address = message(&[bytes_field(1, &[127, 0, 0, 1])]);
        let server = message(&[bytes_field(1, &address)]);
        let override_message = message(&[bytes_field(1, &server)]);
        let settings = bytes_field(3, &override_message);
        let outbound = message(&[bytes_field(
            3,
            &typed("xray.proxy.freedom.Config", &settings),
        )]);
        let json = to_json(&config(
            &http_inbound(&receiver(5000, None), &[]),
            &outbound,
        ))
        .expect("freedom override decodes");
        let redirect = json
            .get("outbounds")
            .and_then(Json::as_arr)
            .and_then(|outbounds| outbounds.first())
            .and_then(|outbound| outbound.get("settings"))
            .and_then(|settings| settings.get("redirect"))
            .and_then(Json::as_str);
        assert_eq!(redirect, Some("127.0.0.1:0"));
    }

    #[test]
    fn a_scoped_freedom_rule_becomes_a_final_rule() {
        let range = message(&[varint_field(1, 443), varint_field(2, 443)]);
        let ports = message(&[bytes_field(1, &range)]);
        let geoip = message(&[bytes_field(2, b"private")]);
        let ip = message(&[bytes_field(1, &geoip)]);
        let delay = message(&[varint_field(1, 0), varint_field(2, 0)]);
        let networks = [varint(2), varint(3)].concat();
        let rule = message(&[
            varint_field(1, 1),
            bytes_field(2, &networks),
            bytes_field(3, &ports),
            bytes_field(4, &ip),
            bytes_field(5, &delay),
        ]);
        let rules = bytes_field(8, &rule);
        let outbound = message(&[bytes_field(3, &typed("xray.proxy.freedom.Config", &rules))]);
        let json = to_json(&config(
            &http_inbound(&receiver(5000, None), &[]),
            &outbound,
        ))
        .expect("freedom final rule decodes");
        let rule = json
            .get("outbounds")
            .and_then(Json::as_arr)
            .and_then(|outbounds| outbounds.first())
            .and_then(|outbound| outbound.get("settings"))
            .and_then(|settings| settings.get("finalRules"))
            .and_then(Json::as_arr)
            .and_then(|rules| rules.first())
            .expect("the final rule");
        assert_eq!(rule.get("action").and_then(Json::as_str), Some("block"));
        assert_eq!(
            rule.get("network").and_then(Json::as_arr),
            Some(&[Json::Str("tcp".to_owned()), Json::Str("udp".to_owned())][..])
        );
        assert_eq!(rule.get("port").and_then(Json::as_str), Some("443"));
        assert_eq!(
            rule.get("ip").and_then(Json::as_arr),
            Some(&[Json::Str("geoip:private".to_owned())][..])
        );
        assert_eq!(rule.get("blockDelay").and_then(Json::as_str), Some("0"));
    }

    #[test]
    fn freedom_fragment_domain_and_proxy_protocol_are_carried() {
        let fragment = message(&[
            varint_field(1, 0),
            varint_field(2, 1),
            varint_field(3, 10),
            varint_field(4, 20),
            varint_field(5, 1),
            varint_field(6, 2),
            varint_field(7, 4),
            varint_field(8, 4),
        ]);
        let settings = message(&[
            varint_field(1, 2),
            bytes_field(5, &fragment),
            varint_field(6, 2),
        ]);
        let outbound = message(&[bytes_field(
            3,
            &typed("xray.proxy.freedom.Config", &settings),
        )]);
        let json = to_json(&config(
            &http_inbound(&receiver(5000, None), &[]),
            &outbound,
        ))
        .expect("freedom options decode");
        let settings = json
            .get("outbounds")
            .and_then(Json::as_arr)
            .and_then(|outbounds| outbounds.first())
            .and_then(|outbound| outbound.get("settings"))
            .expect("settings");
        assert_eq!(
            settings.get("domainStrategy").and_then(Json::as_str),
            Some("UseIPv4")
        );
        assert_eq!(
            settings.get("proxyProtocol").and_then(Json::as_u32),
            Some(2)
        );
        let fragment = settings.get("fragment").expect("fragment");
        assert_eq!(
            fragment.get("packets").and_then(Json::as_str),
            Some("tlshello")
        );
        assert_eq!(fragment.get("length").and_then(Json::as_str), Some("10-20"));
        assert_eq!(fragment.get("interval").and_then(Json::as_str), Some("1-2"));
        assert_eq!(fragment.get("maxSplit").and_then(Json::as_str), Some("4"));
    }

    #[test]
    fn a_zero_start_fragment_after_one_is_all_writes() {
        let fragment = message(&[varint_field(1, 0), varint_field(2, 2)]);
        let settings = bytes_field(5, &fragment);
        let outbound = message(&[bytes_field(
            3,
            &typed("xray.proxy.freedom.Config", &settings),
        )]);
        let json = to_json(&config(
            &http_inbound(&receiver(5000, None), &[]),
            &outbound,
        ))
        .expect("freedom fragment decodes");
        let packets = json
            .get("outbounds")
            .and_then(Json::as_arr)
            .and_then(|outbounds| outbounds.first())
            .and_then(|outbound| outbound.get("settings"))
            .and_then(|settings| settings.get("fragment"))
            .and_then(|fragment| fragment.get("packets"))
            .and_then(Json::as_str);
        assert_eq!(packets, Some(""));
    }

    #[test]
    fn a_freedom_noise_becomes_a_noise_entry() {
        let noise = message(&[bytes_field(5, &[0, 0xff]), bytes_field(6, b"ipv4")]);
        let settings = bytes_field(7, &noise);
        let outbound = message(&[bytes_field(
            3,
            &typed("xray.proxy.freedom.Config", &settings),
        )]);
        let json = to_json(&config(
            &http_inbound(&receiver(5000, None), &[]),
            &outbound,
        ))
        .expect("freedom noise decodes");
        let noise = json
            .get("outbounds")
            .and_then(Json::as_arr)
            .and_then(|outbounds| outbounds.first())
            .and_then(|outbound| outbound.get("settings"))
            .and_then(|settings| settings.get("noises"))
            .and_then(Json::as_arr)
            .and_then(|noises| noises.first())
            .expect("the noise");
        assert_eq!(noise.get("type").and_then(Json::as_str), Some("hex"));
        assert_eq!(noise.get("packet").and_then(Json::as_str), Some("00ff"));
        assert_eq!(noise.get("delay").and_then(Json::as_str), Some("0"));
        assert_eq!(noise.get("applyTo").and_then(Json::as_str), Some("ipv4"));
    }

    #[test]
    fn a_vmess_inbound_decodes_its_clients() {
        let account = vmess_account(b"bbbb-bbbb", Some(3), Some("AuthenticatedLength"));
        let settings = bytes_field(1, &vmess_user(&account));
        let inbound = message(&[
            bytes_field(
                2,
                &typed("xray.app.proxyman.ReceiverConfig", &receiver(5000, None)),
            ),
            bytes_field(3, &typed("xray.proxy.vmess.inbound.Config", &settings)),
        ]);
        let json = to_json(&config(&inbound, &freedom_outbound())).expect("vmess inbound decodes");
        let inbound = &json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0];
        assert_eq!(
            inbound.get("protocol").and_then(Json::as_str),
            Some("vmess")
        );
        let client = &inbound
            .get("settings")
            .expect("settings")
            .get("clients")
            .and_then(Json::as_arr)
            .expect("clients")[0];
        assert_eq!(client.get("id").and_then(Json::as_str), Some("bbbb-bbbb"));
        assert_eq!(
            client.get("security").and_then(Json::as_str),
            Some("aes-128-gcm")
        );
        assert_eq!(
            client.get("testsEnabled").and_then(Json::as_str),
            Some("AuthenticatedLength")
        );
    }

    #[test]
    fn a_kcp_stream_carries_its_tunables() {
        let kcp = message(&[
            varint_field(1, 1400),
            varint_field(2, 20),
            varint_field(3, 10),
            varint_field(4, 50),
            varint_field(5, 2),
            varint_field(6, 1_048_576),
        ]);
        let stream = message(&[
            bytes_field(
                2,
                &message(&[
                    bytes_field(2, &typed("xray.transport.internet.kcp.Config", &kcp)),
                    bytes_field(3, b"mkcp"),
                ]),
            ),
            bytes_field(5, b"mkcp"),
        ]);
        let account = vmess_account(b"bbbb-bbbb", None, None);
        let settings = bytes_field(1, &vmess_user(&account));
        let inbound = message(&[
            bytes_field(
                2,
                &typed(
                    "xray.app.proxyman.ReceiverConfig",
                    &receiver_stream(5000, &stream),
                ),
            ),
            bytes_field(3, &typed("xray.proxy.vmess.inbound.Config", &settings)),
        ]);
        let json = to_json(&config(&inbound, &freedom_outbound())).expect("kcp inbound decodes");
        let stream = json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("streamSettings")
            .expect("stream settings");
        assert_eq!(stream.get("network").and_then(Json::as_str), Some("mkcp"));
        let kcp = stream.get("kcpSettings").expect("kcp settings");
        assert_eq!(kcp.get("mtu").and_then(Json::as_u32), Some(1400));
        assert_eq!(kcp.get("uplinkCapacity").and_then(Json::as_u32), Some(10));
        assert_eq!(
            kcp.get("maxSendingWindow").and_then(Json::as_u32),
            Some(1_048_576)
        );
    }

    #[test]
    fn a_vmess_outbound_decodes_its_endpoint() {
        let account = vmess_account(b"cccc-cccc", None, None);
        let endpoint = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, 443),
            bytes_field(3, &vmess_user(&account)),
        ]);
        let outbound = message(&[bytes_field(
            3,
            &typed(
                "xray.proxy.vmess.outbound.Config",
                &bytes_field(1, &endpoint),
            ),
        )]);
        let json = to_json(&config(
            &http_inbound(&receiver(5000, None), &[]),
            &outbound,
        ))
        .expect("vmess outbound decodes");
        let server = &json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0]
            .get("settings")
            .expect("settings")
            .get("vnext")
            .and_then(Json::as_arr)
            .expect("vnext")[0];
        assert_eq!(
            server.get("address").and_then(Json::as_str),
            Some("127.0.0.1")
        );
        assert_eq!(server.get("port").and_then(Json::as_port), Some(443));
        assert_eq!(
            server.get("users").and_then(Json::as_arr).expect("users")[0]
                .get("id")
                .and_then(Json::as_str),
            Some("cccc-cccc")
        );
    }

    #[test]
    fn a_vmess_user_level_rides_into_the_client() {
        let user = message(&[
            varint_field(1, 2),
            vmess_user(&vmess_account(b"d", None, None)),
        ]);
        let settings = bytes_field(1, &user);
        let inbound = message(&[
            bytes_field(
                2,
                &typed("xray.app.proxyman.ReceiverConfig", &receiver(5000, None)),
            ),
            bytes_field(3, &typed("xray.proxy.vmess.inbound.Config", &settings)),
        ]);
        let root = to_json(&config(&inbound, &freedom_outbound())).expect("carries the level");
        let client = &root
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("settings")
            .and_then(|settings| settings.get("clients"))
            .and_then(Json::as_arr)
            .expect("clients")[0];
        assert_eq!(client.get("level").and_then(Json::as_u32), Some(2));
    }

    #[test]
    fn a_policy_app_keeps_the_user_and_inbound_uplink_counters() {
        let level = message(&[
            varint_field(1, 1),
            bytes_field(
                2,
                &message(&[bytes_field(
                    2,
                    &message(&[varint_field(1, 1), varint_field(2, 1)]),
                )]),
            ),
        ]);
        let system = message(&[bytes_field(1, &message(&[varint_field(1, 1)]))]);
        let policy = message(&[bytes_field(1, &level), bytes_field(2, &system)]);
        let mut bytes = http_scenario(5000);
        bytes.extend(bytes_field(4, &typed("xray.app.policy.Config", &policy)));
        let (_, seed) = to_json_seeded(&bytes).expect("policy app");
        let policy = seed.policy.expect("policy");
        let level = policy.levels.get(&1).expect("level");
        assert!(level.stats.user_uplink);
        assert!(level.stats.user_downlink);
        assert!(policy.system.inbound_uplink);
        assert!(!policy.system.inbound_downlink);
    }

    fn vless_account(id: &[u8], flow: Option<&[u8]>, encryption: Option<&[u8]>) -> Vec<u8> {
        vless_account_with(id, flow, encryption, None)
    }

    fn vless_account_with(
        id: &[u8],
        flow: Option<&[u8]>,
        encryption: Option<&[u8]>,
        reverse: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut account = vec![bytes_field(1, id)];
        if let Some(flow) = flow {
            account.push(bytes_field(2, flow));
        }
        if let Some(encryption) = encryption {
            account.push(bytes_field(3, encryption));
        }
        if let Some(tag) = reverse {
            account.push(bytes_field(7, &message(&[bytes_field(1, tag)])));
        }
        typed("xray.proxy.vless.Account", &message(&account))
    }

    fn vless_user(account: &[u8]) -> Vec<u8> {
        bytes_field(3, account)
    }

    fn vless_inbound(port: u64, settings: &[u8]) -> Vec<u8> {
        message(&[
            bytes_field(
                2,
                &typed("xray.app.proxyman.ReceiverConfig", &receiver(port, None)),
            ),
            bytes_field(3, &typed("xray.proxy.vless.inbound.Config", settings)),
        ])
    }

    /// The shape `TestVlessTCP` names: a vless inbound with its decryption string, a vless
    /// outbound dialling it.
    #[test]
    fn a_vless_scenario_decodes_both_sides() {
        let settings = message(&[
            bytes_field(1, &vless_user(&vless_account(b"aaaa-aaaa", None, None))),
            bytes_field(3, b"none"),
        ]);
        let endpoint = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, 443),
            bytes_field(
                3,
                &vless_user(&vless_account(
                    b"aaaa-aaaa",
                    Some(b"xtls-rprx-vision"),
                    Some(b"none"),
                )),
            ),
        ]);
        let outbound = message(&[bytes_field(
            3,
            &typed(
                "xray.proxy.vless.outbound.Config",
                &bytes_field(1, &endpoint),
            ),
        )]);
        let json =
            to_json(&config(&vless_inbound(5000, &settings), &outbound)).expect("vless decodes");
        let inbound = &json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0];
        assert_eq!(
            inbound.get("protocol").and_then(Json::as_str),
            Some("vless")
        );
        let client = &inbound
            .get("settings")
            .expect("settings")
            .get("clients")
            .and_then(Json::as_arr)
            .expect("clients")[0];
        assert_eq!(client.get("id").and_then(Json::as_str), Some("aaaa-aaaa"));
        assert!(
            inbound
                .get("settings")
                .expect("settings")
                .get("decryption")
                .is_none(),
            "the decryption string is read and dropped"
        );
        let user = &json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0]
            .get("settings")
            .expect("settings")
            .get("vnext")
            .and_then(Json::as_arr)
            .expect("vnext")[0]
            .get("users")
            .and_then(Json::as_arr)
            .expect("users")[0];
        assert_eq!(user.get("encryption").and_then(Json::as_str), Some("none"));
        assert_eq!(
            user.get("flow").and_then(Json::as_str),
            Some("xtls-rprx-vision")
        );
    }

    /// A fallback row the message carries reaches the dialect's settings, its fields as they
    /// came and a dest the loader infers its dial behind.
    #[test]
    fn a_fallback_row_arrives_from_the_bridge() {
        let settings = message(&[
            bytes_field(1, &vless_user(&vless_account(b"a", None, None))),
            bytes_field(
                2,
                &message(&[
                    bytes_field(1, b"web"),
                    bytes_field(2, b"h2"),
                    bytes_field(3, b"/api"),
                    bytes_field(5, b"127.0.0.1:8080"),
                    varint_field(6, 2),
                ]),
            ),
        ]);
        let json = to_json(&config(
            &vless_inbound(5000, &settings),
            &freedom_outbound(),
        ))
        .expect("vless decodes");
        let row = &json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("settings")
            .expect("settings")
            .get("fallbacks")
            .and_then(Json::as_arr)
            .expect("fallbacks")[0];
        assert_eq!(row.get("name").and_then(Json::as_str), Some("web"));
        assert_eq!(row.get("alpn").and_then(Json::as_str), Some("h2"));
        assert_eq!(row.get("path").and_then(Json::as_str), Some("/api"));
        assert_eq!(
            row.get("dest").and_then(Json::as_str),
            Some("127.0.0.1:8080")
        );
        assert_eq!(row.get("xver").and_then(Json::as_u32), Some(2));
    }

    #[test]
    fn a_vless_xor_mode_is_dropped_without_an_engine() {
        let settings = message(&[
            bytes_field(1, &vless_user(&vless_account(b"a", None, None))),
            varint_field(4, 1),
        ]);
        to_json(&config(
            &vless_inbound(5000, &settings),
            &freedom_outbound(),
        ))
        .expect("vless decodes");
    }

    #[test]
    fn an_engaged_decryption_is_refused() {
        let settings = message(&[
            bytes_field(1, &vless_user(&vless_account(b"a", None, None))),
            bytes_field(3, b"always"),
        ]);
        let error = to_json(&config(
            &vless_inbound(5000, &settings),
            &freedom_outbound(),
        ))
        .expect_err("refused");
        assert!(
            error.contains(r#"unsupported "decryption": always"#),
            "{error}"
        );
    }

    #[test]
    fn an_empty_decryption_spelling_is_refused() {
        let settings = message(&[
            bytes_field(1, &vless_user(&vless_account(b"a", None, None))),
            bytes_field(3, b""),
        ]);
        let error = to_json(&config(
            &vless_inbound(5000, &settings),
            &freedom_outbound(),
        ))
        .expect_err("refused");
        assert!(
            error.contains(r#"please add/set "decryption":"none""#),
            "{error}"
        );
    }

    /// The account's padding, reverse message and test seeds ride along unheard rather than
    /// refusing: a plain account serves both spellings.
    #[test]
    fn the_account_decryption_test_fields_ride_along_unheard() {
        let account = typed(
            "xray.proxy.vless.Account",
            &message(&[
                bytes_field(1, b"a"),
                bytes_field(6, b"padpad"),
                bytes_field(7, &bytes_field(1, b"tag")),
                varint_field(8, 1),
                varint_field(9, 7),
                bytes_field(9, &message(&[varint(7), varint(9)])),
            ]),
        );
        let settings = bytes_field(1, &vless_user(&account));
        let json = to_json(&config(
            &vless_inbound(5000, &settings),
            &freedom_outbound(),
        ))
        .expect("vless decodes");
        let client = &json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("settings")
            .expect("settings")
            .get("clients")
            .and_then(Json::as_arr)
            .expect("clients")[0];
        assert_eq!(client.get("id").and_then(Json::as_str), Some("a"));
    }

    #[test]
    fn a_stripped_mlkem_key_is_put_back_together_with_its_mode_and_seconds() {
        let (client, server) =
            ferrox_core::vless_encryption::generate_pair(false, "xorpub", "1rtt", "600");
        let public = client.rsplit('.').next().expect("public key");
        let private = server.rsplit('.').next().expect("private key");
        let settings = message(&[
            bytes_field(
                1,
                &vless_user(&vless_account_with(b"aaaa-aaaa", None, None, None)),
            ),
            bytes_field(3, private.as_bytes()),
            varint_field(4, 1),
            varint_field(5, 600),
        ]);
        let endpoint = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, 443),
            bytes_field(
                3,
                &vless_user(&typed(
                    "xray.proxy.vless.Account",
                    &message(&[
                        bytes_field(1, b"aaaa-aaaa"),
                        bytes_field(3, public.as_bytes()),
                        varint_field(4, 1),
                        varint_field(5, 1),
                    ]),
                )),
            ),
        ]);
        let outbound = message(&[bytes_field(
            3,
            &typed(
                "xray.proxy.vless.outbound.Config",
                &bytes_field(1, &endpoint),
            ),
        )]);
        let json =
            to_json(&config(&vless_inbound(5000, &settings), &outbound)).expect("vless decodes");
        let decryption = json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("settings")
            .and_then(|settings| settings.get("decryption"))
            .and_then(Json::as_str);
        assert_eq!(decryption, Some(server.replace(".600.", ".600s.").as_str()));
        let encryption = json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0]
            .get("settings")
            .and_then(|settings| settings.get("vnext"))
            .and_then(Json::as_arr)
            .expect("vnext")[0]
            .get("users")
            .and_then(Json::as_arr)
            .expect("users")[0]
            .get("encryption")
            .and_then(Json::as_str);
        assert_eq!(
            encryption,
            Some(client.replace(".1rtt.", ".0rtt.").as_str())
        );
    }

    #[test]
    fn a_vless_inbound_without_a_user_is_refused() {
        let error =
            to_json(&config(&vless_inbound(5000, &[]), &freedom_outbound())).expect_err("refused");
        assert!(error.contains("no user"), "{error}");
    }

    #[test]
    fn a_vless_reverse_tag_reaches_the_inbound_client_and_the_outbound_settings() {
        let settings = message(&[
            bytes_field(
                1,
                &vless_user(&vless_account_with(
                    b"aaaa-aaaa",
                    None,
                    None,
                    Some(b"portal"),
                )),
            ),
            bytes_field(3, b"none"),
        ]);
        let endpoint = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, 443),
            bytes_field(
                3,
                &vless_user(&vless_account_with(
                    b"aaaa-aaaa",
                    None,
                    Some(b"none"),
                    Some(b"portal"),
                )),
            ),
        ]);
        let outbound = message(&[bytes_field(
            3,
            &typed(
                "xray.proxy.vless.outbound.Config",
                &bytes_field(1, &endpoint),
            ),
        )]);
        let json =
            to_json(&config(&vless_inbound(5000, &settings), &outbound)).expect("vless decodes");
        let client = &json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("settings")
            .expect("settings")
            .get("clients")
            .and_then(Json::as_arr)
            .expect("clients")[0];
        assert_eq!(
            client
                .get("reverse")
                .and_then(|reverse| reverse.get("tag"))
                .and_then(Json::as_str),
            Some("portal")
        );
        let settings = json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0]
            .get("settings")
            .expect("settings");
        assert_eq!(
            settings
                .get("reverse")
                .and_then(|reverse| reverse.get("tag"))
                .and_then(Json::as_str),
            Some("portal")
        );
    }

    /// A `StreamConfig` as the vless TLS/REALITY scenarios carry it: the tcp transport, the
    /// security type its name selects, and the security's own settings message.
    fn tcp_stream(security_type: &str, security: &[u8]) -> Vec<u8> {
        message(&[
            bytes_field(
                2,
                &message(&[bytes_field(
                    2,
                    &typed("xray.transport.internet.tcp.Config", &[]),
                )]),
            ),
            bytes_field(3, security_type.as_bytes()),
            bytes_field(4, &typed(security_type, security)),
            bytes_field(5, b"tcp"),
        ])
    }

    fn receiver_stream(port: u64, stream: &[u8]) -> Vec<u8> {
        message(&[
            bytes_field(
                1,
                &bytes_field(1, &message(&[varint_field(1, port), varint_field(2, port)])),
            ),
            bytes_field(2, &bytes_field(1, &[127, 0, 0, 1])),
            bytes_field(3, stream),
        ])
    }

    /// The PEM text a fixture spells without a private-key block in the tree.
    fn fixture_key_text() -> String {
        let sides = ["PRIVATE", "KEY"];
        [
            format!("-----BEGIN {}-----", sides.join(" ")),
            "\nRw==\n".to_owned(),
            "-----END ".to_owned(),
            format!("{}-----\n", sides[1]),
        ]
        .join("")
    }

    /// A certificate entry's bytes are PEM text on the wire (the reference carries `ToPEM`
    /// bytes), so the served JSON strings are the bytes verbatim, whichever PEM they spell.
    #[test]
    fn a_vless_tls_receiver_serves_the_certificate_bytes_verbatim() {
        let certificate_text = "-----BEGIN CERTIFICATE-----\nQw==\n-----END CERTIFICATE-----\n";
        let key_text = fixture_key_text();
        let certificate = message(&[
            bytes_field(1, certificate_text.as_bytes()),
            bytes_field(2, key_text.as_bytes()),
        ]);
        let tcp = tcp_stream(
            "xray.transport.internet.tls.Config",
            &message(&[bytes_field(2, &certificate)]),
        );
        let inbound = message(&[
            bytes_field(
                2,
                &typed(
                    "xray.app.proxyman.ReceiverConfig",
                    &receiver_stream(5000, &tcp),
                ),
            ),
            bytes_field(
                3,
                &typed(
                    "xray.proxy.vless.inbound.Config",
                    &bytes_field(1, &vless_user(&vless_account(b"a", None, None))),
                ),
            ),
        ]);
        let json = to_json(&config(&inbound, &freedom_outbound())).expect("tls receiver decodes");
        let tls = json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("streamSettings")
            .and_then(|s| s.get("tlsSettings"))
            .and_then(|t| t.get("certificates"))
            .and_then(Json::as_arr)
            .and_then(|c| c.first())
            .expect("one certificate entry");
        let pem = tls
            .get("certificate")
            .and_then(Json::as_str)
            .expect("cert pem");
        assert_eq!(
            pem, certificate_text,
            "the cert bytes path through verbatim"
        );
        let key = tls.get("key").and_then(Json::as_str).expect("key text");
        assert_eq!(key, key_text, "the key bytes path through verbatim");
    }

    #[test]
    fn a_vless_tls_receiver_carries_its_certificate_policy() {
        let certificate_text = "-----BEGIN CERTIFICATE-----\nQw==\n-----END CERTIFICATE-----\n";
        let key_text = fixture_key_text();
        let certificate = message(&[
            bytes_field(1, certificate_text.as_bytes()),
            bytes_field(2, key_text.as_bytes()),
            varint_field(3, 1),
            varint_field(4, 7200),
            bytes_field(5, b"/etc/xray/cert.pem"),
            bytes_field(6, b"/etc/xray/key.pem"),
            varint_field(7, 1),
            varint_field(8, 1),
        ]);
        let tcp = tcp_stream(
            "xray.transport.internet.tls.Config",
            &message(&[bytes_field(2, &certificate)]),
        );
        let inbound = message(&[
            bytes_field(
                2,
                &typed(
                    "xray.app.proxyman.ReceiverConfig",
                    &receiver_stream(5000, &tcp),
                ),
            ),
            bytes_field(
                3,
                &typed(
                    "xray.proxy.vless.inbound.Config",
                    &bytes_field(1, &vless_user(&vless_account(b"a", None, None))),
                ),
            ),
        ]);
        let json = to_json(&config(&inbound, &freedom_outbound())).expect("tls receiver decodes");
        let tls = json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("streamSettings")
            .and_then(|s| s.get("tlsSettings"))
            .and_then(|t| t.get("certificates"))
            .and_then(Json::as_arr)
            .and_then(|c| c.first())
            .expect("one certificate entry");
        assert_eq!(
            tls.get("certificateFile").and_then(Json::as_str),
            Some("/etc/xray/cert.pem"),
            "the path wins over the bytes it was read from, so the ticker can re-read it"
        );
        assert_eq!(
            tls.get("keyFile").and_then(Json::as_str),
            Some("/etc/xray/key.pem"),
            "the key path wins the same way"
        );
        assert_eq!(
            tls.get("usage").and_then(Json::as_str),
            Some("verify"),
            "the usage enum reaches the dialect the identity parse reads"
        );
        assert_eq!(
            tls.get("ocspStapling"),
            Some(&Json::Num(7200.0)),
            "the ticker interval reaches the listener"
        );
        assert_eq!(
            tls.get("oneTimeLoading").and_then(Json::as_bool),
            Some(true),
            "a pinned identity stays the one the config loaded"
        );
    }

    #[test]
    fn a_vless_tls_receiver_carries_reject_unknown_sni() {
        let tcp = tcp_stream("xray.transport.internet.tls.Config", &varint_field(12, 1));
        let inbound = message(&[
            bytes_field(
                2,
                &typed(
                    "xray.app.proxyman.ReceiverConfig",
                    &receiver_stream(5000, &tcp),
                ),
            ),
            bytes_field(
                3,
                &typed(
                    "xray.proxy.vless.inbound.Config",
                    &bytes_field(1, &vless_user(&vless_account(b"a", None, None))),
                ),
            ),
        ]);
        let json = to_json(&config(&inbound, &freedom_outbound())).expect("tls receiver decodes");
        let tls = json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("streamSettings")
            .and_then(|s| s.get("tlsSettings"))
            .expect("tls settings");
        assert_eq!(
            tls.get("rejectUnknownSni").and_then(Json::as_bool),
            Some(true),
            "the protocol bool reaches the dialect the identity parse reads"
        );
    }

    /// The shape `TestVlessTls`'s client names: a sender whose stream pins the peer leaf by
    /// the SHA-256 over its whole DER, which is `pinnedPeerCertSha256` in this tree's dialect.
    #[test]
    fn a_vless_tls_client_names_its_pinned_certificate() {
        let pin = [0x55u8; 32];
        let type_name = "xray.transport.internet.tls.Config";
        let stream = tcp_stream(type_name, &bytes_field(22, &pin));
        let outbound = message(&[
            bytes_field(
                2,
                &typed("xray.app.proxyman.SenderConfig", &bytes_field(2, &stream)),
            ),
            bytes_field(
                3,
                &typed(
                    "xray.proxy.vless.outbound.Config",
                    &bytes_field(
                        1,
                        &message(&[
                            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
                            varint_field(2, 443),
                            bytes_field(
                                3,
                                &vless_user(&vless_account(b"aaaa-aaaa", None, Some(b"none"))),
                            ),
                        ]),
                    ),
                ),
            ),
        ]);
        let json = to_json(&config(&dokodemo(5000, &[varint_field(7, 2)]), &outbound))
            .expect("tls sender decodes");
        let stream = json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0]
            .get("streamSettings")
            .expect("stream");
        assert_eq!(stream.get("network").and_then(Json::as_str), Some("tcp"));
        assert_eq!(stream.get("security").and_then(Json::as_str), Some("tls"));
        let tls = stream.get("tlsSettings").expect("tls settings");
        assert_eq!(
            tls.get("pinnedPeerCertSha256").and_then(Json::as_str),
            Some("55".repeat(32).as_str()),
            "one pinned hash, comma-separated hex like the dialect spells it"
        );
    }

    /// The shape the REALITY scenarios name on the server: `show`, the decoy
    /// `www.google.com:443`, the server names it accepts, the base64url key, hex short ids.
    #[test]
    fn a_vless_reality_receiver_names_the_decoy_and_key() {
        let reality = message(&[
            varint_field(1, 1),
            bytes_field(2, b"www.google.com:443"),
            bytes_field(5, b"www.example.com"),
            bytes_field(6, &[0xab; 32]),
            bytes_field(10, &[0x01, 0x02]),
            bytes_field(11, &[0x9f; 32]),
        ]);
        let inbound = message(&[
            bytes_field(
                2,
                &typed(
                    "xray.app.proxyman.ReceiverConfig",
                    &receiver_stream(
                        5000,
                        &tcp_stream("xray.transport.internet.reality.Config", &reality),
                    ),
                ),
            ),
            bytes_field(
                3,
                &typed(
                    "xray.proxy.vless.inbound.Config",
                    &bytes_field(1, &vless_user(&vless_account(b"a", None, None))),
                ),
            ),
        ]);
        let json = to_json(&config(&inbound, &freedom_outbound())).expect("reality server decodes");
        let reality = json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("streamSettings")
            .and_then(|s| s.get("realitySettings"))
            .expect("reality settings");
        assert_eq!(reality.get("show"), Some(&Json::Bool(true)));
        assert_eq!(
            reality.get("dest").and_then(Json::as_str),
            Some("www.google.com:443")
        );
        assert_eq!(
            reality
                .get("serverNames")
                .and_then(Json::as_arr)
                .map(<[Json]>::len),
            Some(1)
        );
        assert_eq!(
            reality.get("privateKey").and_then(Json::as_str),
            Some(b64url(&[0xab; 32]).as_str())
        );
        assert_eq!(
            reality
                .get("shortIds")
                .and_then(Json::as_arr)
                .and_then(|ids| ids.first()),
            Some(&Json::Str("0102".to_owned()))
        );
        assert_eq!(
            reality.get("mldsa65Seed").and_then(Json::as_str),
            Some(b64url(&[0x9f; 32]).as_str())
        );
    }

    #[test]
    fn a_vless_reality_client_names_its_own_key_and_id() {
        let reality = message(&[
            varint_field(1, 1),
            bytes_field(21, b"chrome"),
            bytes_field(22, b"www.example.com"),
            bytes_field(23, &[0xcd; 32]),
            bytes_field(24, &[]),
            bytes_field(25, &[0x7e; 1952]),
            bytes_field(31, b"/tmp/reality.keys"),
        ]);
        let type_name = "xray.transport.internet.reality.Config";
        let endpoint = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, 443),
            bytes_field(3, &vless_user(&vless_account(b"a", None, Some(b"none")))),
        ]);
        let outbound = message(&[
            bytes_field(
                2,
                &typed(
                    "xray.app.proxyman.SenderConfig",
                    &bytes_field(2, &tcp_stream(type_name, &reality)),
                ),
            ),
            bytes_field(
                3,
                &typed(
                    "xray.proxy.vless.outbound.Config",
                    &bytes_field(1, &endpoint),
                ),
            ),
        ]);
        let json = to_json(&config(&dokodemo(5000, &[varint_field(7, 2)]), &outbound))
            .expect("reality client decodes");
        let reality = json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0]
            .get("streamSettings")
            .and_then(|s| s.get("realitySettings"))
            .expect("reality settings");
        assert_eq!(
            reality.get("fingerprint").and_then(Json::as_str),
            Some("chrome")
        );
        assert_eq!(
            reality.get("serverName").and_then(Json::as_str),
            Some("www.example.com")
        );
        assert_eq!(
            reality.get("publicKey").and_then(Json::as_str),
            Some(b64url(&[0xcd; 32]).as_str())
        );
        assert_eq!(reality.get("shortId").and_then(Json::as_str), Some(""));
        assert_eq!(
            reality.get("mldsa65Verify").and_then(Json::as_str),
            Some(b64url(&[0x7e; 1952]).as_str())
        );
        assert_eq!(
            reality.get("masterKeyLog").and_then(Json::as_str),
            Some("/tmp/reality.keys"),
            "the reality config's own key log rides field 31"
        );
        assert!(
            reality.get("dest").is_none()
                && reality.get("privateKey").is_none()
                && reality.get("show").is_none(),
            "a client reality config carries no server field, and its debug print rides no dial"
        );
    }

    #[test]
    fn a_client_reality_config_refuses_the_servers_mldsa_seed() {
        let reality = message(&[bytes_field(11, &[0x9f; 32]), bytes_field(24, &[])]);
        let type_name = "xray.transport.internet.reality.Config";
        let endpoint = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, 443),
            bytes_field(3, &vless_user(&vless_account(b"a", None, Some(b"none")))),
        ]);
        let outbound = message(&[
            bytes_field(
                2,
                &typed(
                    "xray.app.proxyman.SenderConfig",
                    &bytes_field(2, &tcp_stream(type_name, &reality)),
                ),
            ),
            bytes_field(
                3,
                &typed(
                    "xray.proxy.vless.outbound.Config",
                    &bytes_field(1, &endpoint),
                ),
            ),
        ]);
        let error = to_json(&config(&dokodemo(5000, &[varint_field(7, 2)]), &outbound))
            .expect_err("a client reality config names no server seed");
        assert!(error.contains("mldsa65Seed"), "{error}");
    }

    #[test]
    fn a_named_security_without_settings_is_the_zero_value() {
        let mut receiver = receiver(5000, None);
        receiver.extend(bytes_field(
            3,
            &message(&[
                bytes_field(3, b"xray.transport.internet.tls.Config"),
                bytes_field(5, b"tcp"),
            ]),
        ));
        let json = to_json(&config(&http_inbound(&receiver, &[]), &freedom_outbound()))
            .expect("a named security with no settings decodes");
        let stream = json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("streamSettings")
            .expect("stream");
        assert_eq!(stream.get("security").and_then(Json::as_str), Some("tls"));
        assert!(stream.get("tlsSettings").is_none());
    }

    fn ss_account(password: &[u8], cipher: u64) -> Vec<u8> {
        typed(
            "xray.proxy.shadowsocks.Account",
            &message(&[bytes_field(1, password), varint_field(2, cipher)]),
        )
    }

    fn ss_user(account: &[u8], level: Option<u64>) -> Vec<u8> {
        let mut user = Vec::new();
        if let Some(level) = level {
            user.push(varint_field(1, level));
        }
        user.push(bytes_field(3, account));
        message(&user)
    }

    fn ss_inbound(port: u64, settings: &[u8]) -> Vec<u8> {
        message(&[
            bytes_field(
                2,
                &typed("xray.app.proxyman.ReceiverConfig", &receiver(port, None)),
            ),
            bytes_field(3, &typed("xray.proxy.shadowsocks.ServerConfig", settings)),
        ])
    }

    #[test]
    fn a_sender_multiplex_switch_reaches_the_dial() {
        let endpoint = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, 443),
            bytes_field(3, &ss_user(&ss_account(b"shadowsocks-password", 6), None)),
        ]);
        let mux = message(&[
            varint_field(1, 1),
            varint_field(2, 8),
            varint_field(3, u64::from(u32::MAX)),
            bytes_field(4, b"skip"),
        ]);
        let outbound = message(&[
            bytes_field(
                2,
                &typed("xray.app.proxyman.SenderConfig", &bytes_field(4, &mux)),
            ),
            bytes_field(
                3,
                &typed(
                    "xray.proxy.shadowsocks.ClientConfig",
                    &bytes_field(1, &endpoint),
                ),
            ),
        ]);
        let json = to_json(&config(&dokodemo(5000, &[varint_field(7, 2)]), &outbound))
            .expect("the sender's mux decodes");
        let mux = json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0]
            .get("mux")
            .expect("the mux block");
        assert_eq!(
            mux.get("enabled").and_then(Json::as_bool),
            Some(true),
            "the client dials a mux session"
        );
        assert_eq!(
            mux.get("xudpConcurrency").and_then(Json::as_i64),
            Some(-1),
            "a negative xudp pool turns UDP muxing off"
        );
        assert_eq!(
            mux.get("xudpProxyUDP443").and_then(Json::as_str),
            Some("skip"),
            "the udp/443 policy reaches the dial"
        );
    }

    #[test]
    fn a_shadowsocks_scenario_decodes_both_sides() {
        let settings = message(&[
            bytes_field(
                1,
                &ss_user(&ss_account(b"shadowsocks-password", 6), Some(1)),
            ),
            bytes_field(2, &[2]),
        ]);
        let endpoint = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, 443),
            bytes_field(3, &ss_user(&ss_account(b"shadowsocks-password", 7), None)),
        ]);
        let outbound = message(&[bytes_field(
            3,
            &typed(
                "xray.proxy.shadowsocks.ClientConfig",
                &bytes_field(1, &endpoint),
            ),
        )]);
        let json = to_json(&config(&ss_inbound(5000, &settings), &outbound))
            .expect("shadowsocks decodes both sides");
        let server = &json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0];
        assert_eq!(
            server.get("protocol").and_then(Json::as_str),
            Some("shadowsocks")
        );
        let settings = server.get("settings").expect("settings");
        let clients = settings.get("users").and_then(Json::as_arr).expect("users");
        assert_eq!(clients.len(), 1);
        assert_eq!(
            clients[0].get("method").and_then(Json::as_str),
            Some("aes-256-gcm")
        );
        assert_eq!(
            clients[0].get("password").and_then(Json::as_str),
            Some("shadowsocks-password")
        );
        let client = &json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0]
            .get("settings")
            .expect("settings")
            .get("servers")
            .and_then(Json::as_arr)
            .expect("servers")[0];
        assert_eq!(
            client.get("address").and_then(Json::as_str),
            Some("127.0.0.1")
        );
        assert_eq!(client.get("port").and_then(Json::as_port), Some(443));
        assert_eq!(
            client.get("method").and_then(Json::as_str),
            Some("chacha20-ietf-poly1305")
        );
    }

    fn ss2022_account(key: &[u8]) -> Vec<u8> {
        typed("xray.proxy.shadowsocks_2022.Account", &bytes_field(1, key))
    }

    fn ss2022_user(key: &[u8]) -> Vec<u8> {
        message(&[bytes_field(3, &ss2022_account(key))])
    }

    fn ss2022_inbound(port: u64, name: &str, settings: &[u8]) -> Vec<u8> {
        message(&[
            bytes_field(
                2,
                &typed("xray.app.proxyman.ReceiverConfig", &receiver(port, None)),
            ),
            bytes_field(3, &typed(name, settings)),
        ])
    }

    #[test]
    fn a_shadowsocks_2022_scenario_decodes_both_roles() {
        let key = b"MDEyMzQ1Njc4OWFiY2RlZg==";
        let inbound = ss2022_inbound(
            5000,
            "xray.proxy.shadowsocks_2022.ServerConfig",
            &message(&[
                bytes_field(1, b"2022-blake3-aes-256-gcm"),
                bytes_field(2, key),
                bytes_field(5, &[3]),
            ]),
        );
        let endpoint = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, 443),
            bytes_field(3, b"2022-blake3-aes-128-gcm"),
            bytes_field(4, b"MDEyMzQ1Njc4OWFiY2RlZg=="),
        ]);
        let outbound = message(&[bytes_field(
            3,
            &typed("xray.proxy.shadowsocks_2022.ClientConfig", &endpoint),
        )]);
        let json = to_json(&config(&inbound, &outbound)).expect("2022 decodes both roles");
        let server = &json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0];
        assert_eq!(
            server.get("protocol").and_then(Json::as_str),
            Some("shadowsocks")
        );
        let settings = server.get("settings").expect("settings");
        assert_eq!(
            settings.get("method").and_then(Json::as_str),
            Some("2022-blake3-aes-256-gcm")
        );
        assert_eq!(
            settings.get("password").and_then(Json::as_str),
            Some("MDEyMzQ1Njc4OWFiY2RlZg==")
        );
        assert_eq!(settings.get("network").and_then(Json::as_str), Some("udp"));
        let client = &json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0]
            .get("settings")
            .expect("settings")
            .get("servers")
            .and_then(Json::as_arr)
            .expect("servers")[0];
        assert_eq!(
            client.get("address").and_then(Json::as_str),
            Some("127.0.0.1")
        );
        assert_eq!(client.get("port").and_then(Json::as_port), Some(443));
        assert_eq!(
            client.get("method").and_then(Json::as_str),
            Some("2022-blake3-aes-128-gcm")
        );
    }

    #[test]
    fn a_2022_multi_user_config_becomes_one_colon_password() {
        let settings = message(&[
            bytes_field(1, b"2022-blake3-aes-128-gcm"),
            bytes_field(2, b"bWFzdGVyLWtleQ=="),
            bytes_field(3, &ss2022_user(b"dXNlci1rZXktMQ==")),
            bytes_field(3, &ss2022_user(b"dXNlci1rZXktMg==")),
            bytes_field(4, &[2]),
        ]);
        let inbound = ss2022_inbound(
            5000,
            "xray.proxy.shadowsocks_2022.MultiUserServerConfig",
            &settings,
        );
        let json = to_json(&config(&inbound, &freedom_outbound())).expect("multi-user decodes");
        let settings = &json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("settings")
            .expect("settings");
        assert_eq!(
            settings.get("password").and_then(Json::as_str),
            Some("bWFzdGVyLWtleQ==:dXNlci1rZXktMQ==:dXNlci1rZXktMg=="),
            "the master and each client key join one colon list the inbound pins"
        );
        assert_eq!(settings.get("network").and_then(Json::as_str), Some("tcp"));
    }

    #[test]
    fn a_2022_relay_config_carries_each_destination() {
        let destination = message(&[
            bytes_field(1, b"ZGVzdC1rZXk="),
            bytes_field(2, &bytes_field(1, &[10, 0, 0, 1])),
            varint_field(3, 8443),
        ]);
        let settings = message(&[
            bytes_field(1, b"2022-blake3-aes-256-gcm"),
            bytes_field(2, b"bWFzdGVyLWtleQ=="),
            bytes_field(3, &destination),
        ]);
        let inbound = ss2022_inbound(
            5000,
            "xray.proxy.shadowsocks_2022.RelayServerConfig",
            &settings,
        );
        let json = to_json(&config(&inbound, &freedom_outbound())).expect("relay decodes");
        let settings = &json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("settings")
            .expect("settings");
        assert_eq!(
            settings.get("password").and_then(Json::as_str),
            Some("bWFzdGVyLWtleQ==")
        );
        let dests = settings
            .get("destinations")
            .and_then(Json::as_arr)
            .expect("destinations");
        assert_eq!(dests.len(), 1);
        assert_eq!(
            dests[0].get("key").and_then(Json::as_str),
            Some("ZGVzdC1rZXk=")
        );
        assert_eq!(
            dests[0].get("address").and_then(Json::as_str),
            Some("10.0.0.1")
        );
        assert_eq!(dests[0].get("port").and_then(Json::as_port), Some(8443));
    }

    #[test]
    fn a_2022_single_server_keeps_its_email_and_level() {
        let inbound = ss2022_inbound(
            5000,
            "xray.proxy.shadowsocks_2022.ServerConfig",
            &message(&[
                bytes_field(1, b"2022-blake3-aes-256-gcm"),
                bytes_field(2, b"MDEyMzQ1Njc4OWFiY2RlZg=="),
                bytes_field(3, b"operator@example.com"),
                varint_field(4, 7),
            ]),
        );
        let json = to_json(&config(&inbound, &freedom_outbound())).expect("server decodes");
        let settings = &json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("settings")
            .expect("settings");
        assert_eq!(
            settings.get("email").and_then(Json::as_str),
            Some("operator@example.com"),
            "the account email the inbound's identity reads survives decoding"
        );
        assert_eq!(settings.get("level").and_then(Json::as_u32), Some(7));
    }

    #[test]
    fn a_2022_multi_user_config_keeps_each_identity() {
        let user = |level: u64, email: &[u8], key: &[u8]| {
            message(&[
                varint_field(1, level),
                bytes_field(2, email),
                bytes_field(3, &ss2022_account(key)),
            ])
        };
        let settings = message(&[
            bytes_field(1, b"2022-blake3-aes-128-gcm"),
            bytes_field(2, b"bWFzdGVyLWtleQ=="),
            bytes_field(3, &user(3, b"alice@example.com", b"dXNlci1rZXktMQ==")),
            bytes_field(3, &user(5, b"bob@example.com", b"dXNlci1rZXktMg==")),
        ]);
        let inbound = ss2022_inbound(
            5000,
            "xray.proxy.shadowsocks_2022.MultiUserServerConfig",
            &settings,
        );
        let json = to_json(&config(&inbound, &freedom_outbound())).expect("multi-user decodes");
        let settings = &json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("settings")
            .expect("settings");
        assert_eq!(
            settings.get("password").and_then(Json::as_str),
            Some("bWFzdGVyLWtleQ==:dXNlci1rZXktMQ==:dXNlci1rZXktMg=="),
            "the keys still join the one list the 2022 inbound pins"
        );
        let users = settings
            .get("users")
            .and_then(Json::as_arr)
            .expect("per-user identities");
        assert_eq!(users.len(), 2);
        assert_eq!(
            users[0].get("email").and_then(Json::as_str),
            Some("alice@example.com")
        );
        assert_eq!(users[0].get("level").and_then(Json::as_u32), Some(3));
        assert_eq!(
            users[1].get("email").and_then(Json::as_str),
            Some("bob@example.com")
        );
        assert_eq!(users[1].get("level").and_then(Json::as_u32), Some(5));
    }

    #[test]
    fn a_2022_relay_destination_keeps_its_identity() {
        let destination = message(&[
            bytes_field(1, b"ZGVzdC1rZXk="),
            bytes_field(2, &bytes_field(1, &[10, 0, 0, 1])),
            varint_field(3, 8443),
            bytes_field(4, b"relay@example.com"),
            varint_field(5, 2),
        ]);
        let settings = message(&[
            bytes_field(1, b"2022-blake3-aes-256-gcm"),
            bytes_field(2, b"bWFzdGVyLWtleQ=="),
            bytes_field(3, &destination),
        ]);
        let inbound = ss2022_inbound(
            5000,
            "xray.proxy.shadowsocks_2022.RelayServerConfig",
            &settings,
        );
        let json = to_json(&config(&inbound, &freedom_outbound())).expect("relay decodes");
        let dests = &json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("settings")
            .expect("settings")
            .get("destinations")
            .and_then(Json::as_arr)
            .expect("destinations");
        assert_eq!(
            dests[0].get("email").and_then(Json::as_str),
            Some("relay@example.com")
        );
        assert_eq!(dests[0].get("level").and_then(Json::as_u32), Some(2));
    }

    #[test]
    fn a_2022_port_above_65535_is_rejected_not_clamped() {
        let inbound = ss2022_inbound(
            5000,
            "xray.proxy.shadowsocks_2022.ServerConfig",
            &message(&[
                bytes_field(1, b"2022-blake3-aes-256-gcm"),
                bytes_field(2, b"MDEyMzQ1Njc4OWFiY2RlZg=="),
            ]),
        );
        let endpoint = message(&[
            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
            varint_field(2, 70000),
            bytes_field(3, b"2022-blake3-aes-128-gcm"),
            bytes_field(4, b"MDEyMzQ1Njc4OWFiY2RlZg=="),
        ]);
        let outbound = message(&[bytes_field(
            3,
            &typed("xray.proxy.shadowsocks_2022.ClientConfig", &endpoint),
        )]);
        let error = to_json(&config(&inbound, &outbound)).expect_err("an above-range port refuses");
        assert!(error.contains("65535"), "outbound: {error}");

        let destination = message(&[
            bytes_field(1, b"ZGVzdC1rZXk="),
            bytes_field(2, &bytes_field(1, &[10, 0, 0, 1])),
            varint_field(3, 70000),
        ]);
        let settings = message(&[
            bytes_field(1, b"2022-blake3-aes-256-gcm"),
            bytes_field(2, b"bWFzdGVyLWtleQ=="),
            bytes_field(3, &destination),
        ]);
        let relay = ss2022_inbound(
            5000,
            "xray.proxy.shadowsocks_2022.RelayServerConfig",
            &settings,
        );
        let error = to_json(&config(&relay, &freedom_outbound()))
            .expect_err("an above-range relay port refuses");
        assert!(error.contains("65535"), "relay: {error}");
    }

    fn socks_account(user: &[u8], pass: &[u8]) -> Vec<u8> {
        typed(
            "xray.proxy.socks.Account",
            &message(&[bytes_field(1, user), bytes_field(2, pass)]),
        )
    }

    fn socks_user(account: &[u8]) -> Vec<u8> {
        bytes_field(3, account)
    }

    fn http_account(user: &[u8], pass: &[u8]) -> Vec<u8> {
        typed(
            "xray.proxy.http.Account",
            &message(&[bytes_field(1, user), bytes_field(2, pass)]),
        )
    }

    fn http_user(account: &[u8]) -> Vec<u8> {
        bytes_field(3, account)
    }

    fn socks_inbound(port: u64, auth_type: u64, accounts: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut settings = vec![varint_field(1, auth_type)];
        for (user, pass) in accounts {
            let entry = message(&[bytes_field(1, user), bytes_field(2, pass)]);
            settings.push(bytes_field(2, &entry));
        }
        message(&[
            bytes_field(
                2,
                &typed(
                    "xray.app.proxyman.ReceiverConfig",
                    &receiver(port, Some(&[127, 0, 0, 1])),
                ),
            ),
            bytes_field(
                3,
                &typed("xray.proxy.socks.ServerConfig", &message(&settings)),
            ),
        ])
    }

    /// The shape `TestSocksBridgeTCP` names: a socks server that asks for a password,
    /// and a socks client that offers one.
    #[test]
    fn a_socks_scenario_decodes_both_sides() {
        let outbound = message(&[bytes_field(
            3,
            &typed(
                "xray.proxy.socks.ClientConfig",
                &bytes_field(
                    1,
                    &message(&[
                        bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
                        varint_field(2, 5001),
                        bytes_field(
                            3,
                            &socks_user(&socks_account(b"Test Account", b"Test Password")),
                        ),
                    ]),
                ),
            ),
        )]);
        let json = to_json(&config(
            &socks_inbound(5000, 1, &[(b"Test Account", b"Test Password")]),
            &outbound,
        ))
        .expect("socks decodes both sides");
        let server = &json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0];
        assert_eq!(server.get("protocol").and_then(Json::as_str), Some("socks"));
        let settings = server.get("settings").expect("settings");
        assert_eq!(
            settings.get("auth").and_then(Json::as_str),
            Some("password")
        );
        let account = &settings
            .get("accounts")
            .and_then(Json::as_arr)
            .expect("accounts")[0];
        assert_eq!(
            account.get("user").and_then(Json::as_str),
            Some("Test Account")
        );
        assert_eq!(
            account.get("pass").and_then(Json::as_str),
            Some("Test Password")
        );
        let client = &json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0]
            .get("settings")
            .expect("settings")
            .get("servers")
            .and_then(Json::as_arr)
            .expect("servers")[0];
        assert_eq!(
            client.get("address").and_then(Json::as_str),
            Some("127.0.0.1")
        );
        assert_eq!(client.get("port").and_then(Json::as_port), Some(5001));
        let user = &client.get("users").and_then(Json::as_arr).expect("users")[0];
        assert_eq!(
            user.get("user").and_then(Json::as_str),
            Some("Test Account")
        );
        assert_eq!(
            user.get("pass").and_then(Json::as_str),
            Some("Test Password")
        );
    }

    /// The shape `TestSocksWithHttpRequest` names: a socks server that asks for a
    /// password, and a http client whose CONNECT offers it.
    #[test]
    fn a_socks_http_fallback_scenario_decodes_both_sides() {
        let outbound = message(&[bytes_field(
            3,
            &typed(
                "xray.proxy.http.ClientConfig",
                &message(&[
                    bytes_field(
                        1,
                        &message(&[
                            bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
                            varint_field(2, 5001),
                            bytes_field(
                                3,
                                &http_user(&http_account(b"Test Account", b"Test Password")),
                            ),
                        ]),
                    ),
                    bytes_field(
                        2,
                        &message(&[bytes_field(1, b"X-Test"), bytes_field(2, b"one")]),
                    ),
                ]),
            ),
        )]);
        let json = to_json(&config(
            &socks_inbound(5000, 1, &[(b"Test Account", b"Test Password")]),
            &outbound,
        ))
        .expect("the socks front and its http client decode");
        let server = &json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0];
        assert_eq!(server.get("protocol").and_then(Json::as_str), Some("socks"));
        let client = &json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0];
        assert_eq!(client.get("protocol").and_then(Json::as_str), Some("http"));
        let endpoint = &client
            .get("settings")
            .expect("settings")
            .get("servers")
            .and_then(Json::as_arr)
            .expect("servers")[0];
        assert_eq!(
            endpoint.get("address").and_then(Json::as_str),
            Some("127.0.0.1")
        );
        assert_eq!(endpoint.get("port").and_then(Json::as_port), Some(5001));
        let user = &endpoint.get("users").and_then(Json::as_arr).expect("users")[0];
        assert_eq!(
            user.get("user").and_then(Json::as_str),
            Some("Test Account")
        );
        assert_eq!(
            user.get("pass").and_then(Json::as_str),
            Some("Test Password")
        );
        let header = &endpoint
            .get("headers")
            .and_then(Json::as_arr)
            .expect("headers")[0];
        assert_eq!(header.get("key").and_then(Json::as_str), Some("X-Test"));
        assert_eq!(header.get("value").and_then(Json::as_str), Some("one"));
    }

    /// The blackhole outbound the pinned scenario suite names: a config with no
    /// response, and one with each answer the reference knows.
    #[test]
    fn a_blackhole_scenario_decodes_its_answers() {
        let silent = message(&[bytes_field(3, &typed("xray.proxy.blackhole.Config", &[]))]);
        let json = to_json(&config(&socks_inbound(5000, 0, &[]), &silent)).expect("decodes");
        let outbound = &json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0];
        assert_eq!(
            outbound.get("protocol").and_then(Json::as_str),
            Some("blackhole")
        );
        assert!(
            outbound.get("settings").is_none(),
            "a config with no response names no answer"
        );

        let http = message(&[bytes_field(
            3,
            &typed(
                "xray.proxy.blackhole.Config",
                &bytes_field(1, &message(&[bytes_field(1, b"http")])),
            ),
        )]);
        let json = to_json(&config(&socks_inbound(5000, 0, &[]), &http)).expect("decodes");
        let response = json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0]
            .get("settings")
            .expect("settings")
            .get("response")
            .expect("response");
        assert_eq!(response.get("type").and_then(Json::as_str), Some("http"));

        let custom = message(&[bytes_field(
            3,
            &typed(
                "xray.proxy.blackhole.Config",
                &bytes_field(
                    1,
                    &message(&[bytes_field(1, b"custom"), bytes_field(2, &[0, 1, 2])]),
                ),
            ),
        )]);
        let json = to_json(&config(&socks_inbound(5000, 0, &[]), &custom)).expect("decodes");
        let response = json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0]
            .get("settings")
            .expect("settings")
            .get("response")
            .expect("response");
        assert_eq!(response.get("type").and_then(Json::as_str), Some("custom"));
        assert_eq!(
            response.get("customResponseData").and_then(Json::as_str),
            Some("AAEC"),
            "the answer's bytes travel as base64"
        );
    }

    /// `xray.app.router.Config.script` is a path in the JSON the router parses.
    #[test]
    fn a_pb_router_script_keeps_its_path() {
        let router = message(&[bytes_field(4, b"/etc/xray/route.lua")]);
        let outbound = message(&[
            bytes_field(1, b"direct"),
            bytes_field(3, &typed("xray.proxy.blackhole.Config", &[])),
        ]);
        let config = message(&[
            bytes_field(1, &socks_inbound(5000, 0, &[])),
            bytes_field(2, &outbound),
            bytes_field(4, &typed("xray.app.router.Config", &router)),
        ]);
        let json = to_json(&config).expect("decodes");
        assert_eq!(
            json.get("routing")
                .and_then(|routing| routing.get("script"))
                .and_then(Json::as_str),
            Some("/etc/xray/route.lua")
        );
    }

    /// The router app the pinned blackhole scenario writes: a rule that sends
    /// the flow on one port to a tagged outbound, and the tags the rule names.
    #[test]
    fn a_router_rule_names_the_outbound_a_flow_goes_to() {
        let range = message(&[varint_field(1, 5001), varint_field(2, 5001)]);
        let ports = message(&[bytes_field(1, &range)]);
        let rule = message(&[bytes_field(1, b"blocked"), bytes_field(14, &ports)]);
        let router = message(&[bytes_field(2, &rule)]);
        let outbound = message(&[
            bytes_field(1, b"blocked"),
            bytes_field(3, &typed("xray.proxy.blackhole.Config", &[])),
        ]);
        let config = message(&[
            bytes_field(1, &socks_inbound(5000, 0, &[])),
            bytes_field(2, &outbound),
            bytes_field(4, &typed("xray.app.router.Config", &router)),
        ]);
        let json = to_json(&config).expect("decodes");
        let rules = json
            .get("routing")
            .expect("routing")
            .get("rules")
            .and_then(Json::as_arr)
            .expect("rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0].get("outboundTag").and_then(Json::as_str),
            Some("blocked")
        );
        assert_eq!(rules[0].get("port").and_then(Json::as_str), Some("5001"));
        let outbound = &json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0];
        assert_eq!(outbound.get("tag").and_then(Json::as_str), Some("blocked"));
        assert_eq!(
            outbound.get("protocol").and_then(Json::as_str),
            Some("blackhole")
        );
        // The rule reaches this tree's own router: the flow on that port goes to the outbound the rule names.
        let routing = crate::router::Routing::parse(&json)
            .expect("parses")
            .expect("routing");
        let flow = crate::router::Flow {
            network: crate::router::Network::Tcp,
            domain: None,
            ip: Some("127.0.0.1".parse().expect("addr")),
            port: Some(5001),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(routing.route(&flow), Some("blocked"));
    }

    /// A pb domain rule reaches the same router the JSON spelling does: the
    /// selector is decoded, not refused, and the flow lands on its outbound.
    #[test]
    fn a_pb_domain_rule_reaches_the_router() {
        let domain = message(&[varint_field(1, 3), bytes_field(2, b"x.com")]);
        let domain_rule = message(&[bytes_field(2, &domain)]);
        let rule = message(&[bytes_field(1, b"blocked"), bytes_field(2, &domain_rule)]);
        let router = message(&[bytes_field(2, &rule)]);
        let outbound = message(&[
            bytes_field(1, b"blocked"),
            bytes_field(3, &typed("xray.proxy.blackhole.Config", &[])),
        ]);
        let config = message(&[
            bytes_field(1, &socks_inbound(5000, 0, &[])),
            bytes_field(2, &outbound),
            bytes_field(4, &typed("xray.app.router.Config", &router)),
        ]);
        let json = to_json(&config).expect("decodes");
        let rules = json
            .get("routing")
            .expect("routing")
            .get("rules")
            .and_then(Json::as_arr)
            .expect("rules");
        assert_eq!(
            rules[0].get("domain"),
            Some(&Json::Arr(vec![Json::Str("full:x.com".to_owned())]))
        );
        let routing = crate::router::Routing::parse(&json)
            .expect("parses")
            .expect("routing");
        let flow = crate::router::Flow {
            network: crate::router::Network::Tcp,
            domain: Some("x.com"),
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: None,
            process: None,
        };
        assert_eq!(routing.route(&flow), Some("blocked"));
    }

    /// Every selector the JSON router reads survives the protobuf walk with the
    /// key and spelling that router expects.
    #[test]
    fn a_pb_rule_carries_every_selector_the_router_reads() {
        let custom_domain = message(&[bytes_field(
            2,
            &message(&[varint_field(1, 3), bytes_field(2, b"x.com")]),
        )]);
        let cidr = message(&[bytes_field(
            2,
            &message(&[bytes_field(
                1,
                &message(&[bytes_field(1, &[192, 0, 2, 0]), varint_field(2, 24)]),
            )]),
        )]);
        let source_cidr = message(&[bytes_field(
            2,
            &message(&[bytes_field(
                1,
                &message(&[bytes_field(1, &[198, 51, 100, 0]), varint_field(2, 24)]),
            )]),
        )]);
        let local_cidr = message(&[bytes_field(
            2,
            &message(&[bytes_field(
                1,
                &message(&[bytes_field(1, &[127, 0, 0, 1]), varint_field(2, 32)]),
            )]),
        )]);
        let port = |from: u64, to: u64| {
            message(&[bytes_field(
                1,
                &message(&[varint_field(1, from), varint_field(2, to)]),
            )])
        };
        let mut packed = varint(2);
        packed.extend(varint(3));
        let rule = message(&[
            bytes_field(1, b"blocked"),
            bytes_field(2, &custom_domain),
            bytes_field(7, b"a@x"),
            bytes_field(8, b"in"),
            bytes_field(10, &cidr),
            bytes_field(11, &source_cidr),
            bytes_field(13, &packed),
            bytes_field(14, &port(80, 80)),
            bytes_field(16, &port(1000, 1001)),
            bytes_field(17, &local_cidr),
            bytes_field(18, &port(443, 443)),
            bytes_field(19, b"r"),
            bytes_field(20, &port(0, 0)),
            bytes_field(23, b"linux"),
        ]);
        let router = message(&[bytes_field(2, &rule)]);
        let outbound = message(&[
            bytes_field(1, b"blocked"),
            bytes_field(3, &typed("xray.proxy.blackhole.Config", &[])),
        ]);
        let config = message(&[
            bytes_field(1, &socks_inbound(5000, 0, &[])),
            bytes_field(2, &outbound),
            bytes_field(4, &typed("xray.app.router.Config", &router)),
        ]);
        let json = to_json(&config).expect("decodes");
        let rule = &json
            .get("routing")
            .expect("routing")
            .get("rules")
            .and_then(Json::as_arr)
            .expect("rules")[0];
        let list = |key: &str| rule.get(key).and_then(Json::as_arr);
        assert_eq!(
            list("domain"),
            Some(&[Json::Str("full:x.com".to_owned())][..])
        );
        assert_eq!(
            list("ip"),
            Some(&[Json::Str("192.0.2.0/24".to_owned())][..])
        );
        assert_eq!(
            list("sourceIP"),
            Some(&[Json::Str("198.51.100.0/24".to_owned())][..])
        );
        assert_eq!(
            list("localIP"),
            Some(&[Json::Str("127.0.0.1/32".to_owned())][..])
        );
        assert_eq!(list("inboundTag"), Some(&[Json::Str("in".to_owned())][..]));
        assert_eq!(list("user"), Some(&[Json::Str("a@x".to_owned())][..]));
        assert_eq!(list("localOS"), Some(&[Json::Str("linux".to_owned())][..]));
        assert_eq!(rule.get("network").and_then(Json::as_str), Some("tcp,udp"));
        assert_eq!(rule.get("port").and_then(Json::as_str), Some("80"));
        assert_eq!(
            rule.get("sourcePort").and_then(Json::as_str),
            Some("1000-1001")
        );
        assert_eq!(rule.get("localPort").and_then(Json::as_str), Some("443"));
        assert_eq!(rule.get("ruleTag").and_then(Json::as_str), Some("r"));
        assert_eq!(rule.get("vlessRoute").and_then(Json::as_str), Some("0"));
        crate::router::Routing::parse(&json)
            .expect("parses")
            .expect("routing");
    }

    /// A pb attribute rule reaches the same router the JSON spelling does: the map entry is
    /// decoded into the selector and the flow it names lands on its outbound.
    #[test]
    fn a_pb_attribute_rule_reaches_the_router() {
        let attrs = message(&[bytes_field(1, b":method"), bytes_field(2, b"^PUT$")]);
        let rule = message(&[bytes_field(1, b"blocked"), bytes_field(15, &attrs)]);
        let router = message(&[bytes_field(2, &rule)]);
        let outbound = message(&[
            bytes_field(1, b"blocked"),
            bytes_field(3, &typed("xray.proxy.blackhole.Config", &[])),
        ]);
        let config = message(&[
            bytes_field(1, &socks_inbound(5000, 0, &[])),
            bytes_field(2, &outbound),
            bytes_field(4, &typed("xray.app.router.Config", &router)),
        ]);
        let json = to_json(&config).expect("decodes");
        assert_eq!(
            json.get("routing")
                .and_then(|routing| routing.get("rules"))
                .and_then(Json::as_arr)
                .and_then(|rules| rules[0].get("attrs")),
            Some(&Json::Obj(vec![(
                ":method".to_owned(),
                Json::Str("^PUT$".to_owned())
            )]))
        );
        let routing = crate::router::Routing::parse(&json)
            .expect("parses")
            .expect("routing");
        let mut attributes = crate::router::Attributes::new();
        attributes.push(":Method", std::borrow::Cow::Borrowed("PUT"));
        let flow = crate::router::Flow {
            network: crate::router::Network::Tcp,
            domain: None,
            ip: None,
            port: Some(443),
            source: None,
            source_port: 0,
            local: None,
            local_port: 0,
            vless_route: 0,
            inbound_tag: None,
            protocol: None,
            user: None,
            attrs: Some(&attributes),
            process: None,
        };
        assert_eq!(routing.route(&flow), Some("blocked"));
    }

    /// A protobuf map keeps the last value of a repeated key, so two `:method` entries leave one
    /// pattern: the PUT it names matches and the GET it replaced does not.
    #[test]
    fn a_pb_attribute_map_keeps_the_last_value_of_a_repeated_key() {
        let first = message(&[bytes_field(1, b":method"), bytes_field(2, b"^GET$")]);
        let last = message(&[bytes_field(1, b":method"), bytes_field(2, b"^PUT$")]);
        let rule = message(&[
            bytes_field(1, b"blocked"),
            bytes_field(15, &first),
            bytes_field(15, &last),
        ]);
        let router = message(&[bytes_field(2, &rule)]);
        let outbound = message(&[
            bytes_field(1, b"blocked"),
            bytes_field(3, &typed("xray.proxy.blackhole.Config", &[])),
        ]);
        let config = message(&[
            bytes_field(1, &socks_inbound(5000, 0, &[])),
            bytes_field(2, &outbound),
            bytes_field(4, &typed("xray.app.router.Config", &router)),
        ]);
        let json = to_json(&config).expect("decodes");
        assert_eq!(
            json.get("routing")
                .and_then(|routing| routing.get("rules"))
                .and_then(Json::as_arr)
                .and_then(|rules| rules[0].get("attrs")),
            Some(&Json::Obj(vec![(
                ":method".to_owned(),
                Json::Str("^PUT$".to_owned())
            )]))
        );
        let routing = crate::router::Routing::parse(&json)
            .expect("parses")
            .expect("routing");
        let route = |method: &'static str| {
            let mut attributes = crate::router::Attributes::new();
            attributes.push(":Method", std::borrow::Cow::Borrowed(method));
            let flow = crate::router::Flow {
                network: crate::router::Network::Tcp,
                domain: None,
                ip: None,
                port: Some(443),
                source: None,
                source_port: 0,
                local: None,
                local_port: 0,
                vless_route: 0,
                inbound_tag: None,
                protocol: None,
                user: None,
                attrs: Some(&attributes),
                process: None,
            };
            routing.route(&flow).map(str::to_owned)
        };
        assert_eq!(route("PUT"), Some("blocked".to_owned()));
        assert_eq!(route("GET"), None, "the replaced pattern is gone");
    }

    /// The reference lowercases attribute keys into one map, so a key repeated with a different
    /// spelling keeps the last value instead of adding a second pattern that can never both match.
    #[test]
    fn a_pb_attribute_map_collapses_case_differing_keys() {
        let first = message(&[bytes_field(1, b":method"), bytes_field(2, b"^GET$")]);
        let last = message(&[bytes_field(1, b":Method"), bytes_field(2, b"^PUT$")]);
        let rule = message(&[
            bytes_field(1, b"blocked"),
            bytes_field(15, &first),
            bytes_field(15, &last),
        ]);
        let router = message(&[bytes_field(2, &rule)]);
        let outbound = message(&[
            bytes_field(1, b"blocked"),
            bytes_field(3, &typed("xray.proxy.blackhole.Config", &[])),
        ]);
        let config = message(&[
            bytes_field(1, &socks_inbound(5000, 0, &[])),
            bytes_field(2, &outbound),
            bytes_field(4, &typed("xray.app.router.Config", &router)),
        ]);
        let json = to_json(&config).expect("decodes");
        assert_eq!(
            json.get("routing")
                .and_then(|routing| routing.get("rules"))
                .and_then(Json::as_arr)
                .and_then(|rules| rules[0].get("attrs")),
            Some(&Json::Obj(vec![(
                ":Method".to_owned(),
                Json::Str("^PUT$".to_owned())
            )]))
        );
        let routing = crate::router::Routing::parse(&json)
            .expect("parses")
            .expect("routing");
        let route = |method: &'static str| {
            let mut attributes = crate::router::Attributes::new();
            attributes.push(":Method", std::borrow::Cow::Borrowed(method));
            let flow = crate::router::Flow {
                network: crate::router::Network::Tcp,
                domain: None,
                ip: None,
                port: Some(443),
                source: None,
                source_port: 0,
                local: None,
                local_port: 0,
                vless_route: 0,
                inbound_tag: None,
                protocol: None,
                user: None,
                attrs: Some(&attributes),
                process: None,
            };
            routing.route(&flow).map(str::to_owned)
        };
        assert_eq!(route("PUT"), Some("blocked".to_owned()));
        assert_eq!(route("GET"), None, "the replaced pattern is gone");
    }

    /// A protobuf rule's `process` list reaches the rule table as the JSON field of the same name.
    #[test]
    fn a_pb_process_rule_reaches_the_router() {
        let rule = message(&[bytes_field(1, b"blocked"), bytes_field(21, b"self/")]);
        let router = message(&[bytes_field(2, &rule)]);
        let outbound = message(&[
            bytes_field(1, b"blocked"),
            bytes_field(3, &typed("xray.proxy.blackhole.Config", &[])),
        ]);
        let config = message(&[
            bytes_field(1, &socks_inbound(5000, 0, &[])),
            bytes_field(2, &outbound),
            bytes_field(4, &typed("xray.app.router.Config", &router)),
        ]);
        let json = to_json(&config).expect("decodes");
        assert_eq!(
            json.get("routing")
                .and_then(|routing| routing.get("rules"))
                .and_then(Json::as_arr)
                .and_then(|rules| rules[0].get("process")),
            Some(&Json::Arr(vec![Json::Str("self/".to_owned())]))
        );
        crate::router::Routing::parse(&json)
            .expect("parses")
            .expect("routing");
    }

    #[test]
    fn a_stats_app_enables_the_stats_manager() {
        let config = message(&[bytes_field(4, &typed("xray.app.stats.Config", &[]))]);
        let json = to_json(&config).expect("stats app");
        assert!(json.get("stats").is_some());
    }

    /// A protobuf burst app with no ping settings takes the nil-config defaults.
    #[test]
    fn a_burst_app_without_ping_settings_decodes_to_the_defaults() {
        let burst = message(&[bytes_field(2, b"proxy")]);
        let config = message(&[bytes_field(
            4,
            &typed("xray.app.observatory.burst.Config", &burst),
        )]);
        let json = to_json(&config).expect("the burst app decodes");
        let ping = json
            .get("burstObservatory")
            .and_then(|burst| burst.get("pingConfig"))
            .expect("the default sampler");
        assert!(matches!(ping, Json::Obj(pairs) if pairs.is_empty()));
    }

    /// A whitespace-only protobuf method decodes to `GET`, with a marker so the
    /// probe does not read the body the reference's empty method leaves alone.
    #[test]
    fn a_whitespace_ping_method_decodes_to_get_without_a_body() {
        let ping = message(&[bytes_field(6, b" ")]);
        let burst = message(&[bytes_field(3, &ping)]);
        let config = message(&[bytes_field(
            4,
            &typed("xray.app.observatory.burst.Config", &burst),
        )]);
        let json = to_json(&config).expect("the burst app decodes");
        let method = json
            .get("burstObservatory")
            .and_then(|burst| burst.get("pingConfig"))
            .and_then(|ping| ping.get("httpMethod"))
            .and_then(Json::as_str);
        assert_eq!(method, Some("GET"));
        let blank = json
            .get("burstObservatory")
            .and_then(|burst| burst.get("pingConfig"))
            .and_then(|ping| ping.get("httpMethodBlank"))
            .and_then(Json::as_bool);
        assert_eq!(blank, Some(true));
    }

    /// Both observatory apps decode to the keys the probe loop reads, so a
    /// protobuf config observes the same outbounds a JSON one does.
    #[test]
    fn the_observatory_apps_decode_to_the_probe_loop_settings() {
        let legacy = message(&[
            bytes_field(2, b"proxy"),
            bytes_field(3, b"https://example.com/generate_204"),
            varint_field(4, 30_000_000_000),
            varint_field(5, 1),
        ]);
        let ping = message(&[
            bytes_field(1, b"https://example.com/204"),
            bytes_field(2, b"https://example.com/direct"),
            varint_field(3, 20_000_000_000),
            varint_field(4, 4),
            varint_field(5, 2_000_000_000),
            bytes_field(6, b"GET"),
        ]);
        let burst = message(&[bytes_field(2, b"proxy"), bytes_field(3, &ping)]);
        let config = message(&[
            bytes_field(4, &typed("xray.app.observatory.Config", &legacy)),
            bytes_field(4, &typed("xray.app.observatory.burst.Config", &burst)),
        ]);
        let json = to_json(&config).expect("both observatory apps decode");
        let legacy = json.get("observatory").expect("the legacy app");
        assert_eq!(
            legacy
                .get("subjectSelector")
                .and_then(Json::as_arr)
                .and_then(|selectors| selectors[0].as_str()),
            Some("proxy")
        );
        assert_eq!(
            legacy.get("probeURL").and_then(Json::as_str),
            Some("https://example.com/generate_204")
        );
        assert_eq!(
            legacy.get("probeInterval").and_then(Json::as_str),
            Some("30000000000ns")
        );
        assert_eq!(
            legacy.get("enableConcurrency").and_then(Json::as_bool),
            Some(true)
        );
        let settings = json
            .get("burstObservatory")
            .and_then(|burst| burst.get("pingConfig"))
            .expect("the burst sampler");
        assert_eq!(
            settings.get("destination").and_then(Json::as_str),
            Some("https://example.com/204")
        );
        assert_eq!(
            settings.get("connectivity").and_then(Json::as_str),
            Some("https://example.com/direct")
        );
        assert_eq!(
            settings.get("interval").and_then(Json::as_str),
            Some("20000000000ns")
        );
        assert_eq!(settings.get("sampling").and_then(Json::as_u32), Some(4));
        assert_eq!(
            settings.get("timeout").and_then(Json::as_str),
            Some("2000000000ns")
        );
        assert_eq!(
            settings.get("httpMethod").and_then(Json::as_str),
            Some("GET")
        );
    }

    /// A negative `int32` arrives as a ten-byte varint and stays signed, so a
    /// sampling count the reference treats as "use the default" is not refused.
    #[test]
    fn negative_burst_sampling_keeps_its_sign() {
        let ping = message(&[varint_field(4, u64::MAX)]);
        let settings = healthping_settings(&ping).expect("a negative sampler decodes");
        assert!(matches!(
            settings.get("sampling"),
            Some(Json::Num(value)) if value.to_bits() == (-1.0f64).to_bits()
        ));
    }

    /// An app this tree does not read is xray's own object graph and is
    /// skipped, the way the bridge has always skipped it; the router is the one
    /// app that decides where a flow goes, so it is read.
    #[test]
    fn an_app_this_tree_does_not_read_is_skipped() {
        let config = message(&[
            bytes_field(1, &socks_inbound(5000, 0, &[])),
            bytes_field(2, &freedom_outbound()),
            bytes_field(4, &typed("xray.app.dns.Config", &[])),
        ]);
        to_json(&config).expect("the app is xray's own");
    }

    /// A socks server with no accounts asks for no authentication, the way the pinned
    /// `AuthType_NO_AUTH` server does.
    #[test]
    fn a_socks_server_without_a_password_decodes_to_no_auth() {
        let json = to_json(&config(&socks_inbound(5000, 0, &[]), &freedom_outbound()))
            .expect("socks decodes");
        let settings = json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("settings")
            .expect("settings");
        assert_eq!(settings.get("auth").and_then(Json::as_str), Some("noauth"));
        assert!(
            settings.get("accounts").is_none(),
            "a server with no account names none"
        );
    }

    /// A socks client may name no credential: the greeting then offers no
    /// authentication, the way the pinned `ClientConfig` without a user does.
    #[test]
    fn a_socks_client_without_a_credential_decodes_to_no_users() {
        let outbound = message(&[bytes_field(
            3,
            &typed(
                "xray.proxy.socks.ClientConfig",
                &bytes_field(
                    1,
                    &message(&[
                        bytes_field(1, &bytes_field(1, &[127, 0, 0, 1])),
                        varint_field(2, 5001),
                    ]),
                ),
            ),
        )]);
        let json =
            to_json(&config(&socks_inbound(5000, 0, &[]), &outbound)).expect("socks decodes");
        let client = &json
            .get("outbounds")
            .and_then(Json::as_arr)
            .expect("outbounds")[0]
            .get("settings")
            .expect("settings")
            .get("servers")
            .and_then(Json::as_arr)
            .expect("servers")[0];
        assert!(
            client
                .get("users")
                .and_then(Json::as_arr)
                .expect("users")
                .is_empty(),
            "a client with no credential names no user"
        );
    }

    #[test]
    fn a_socks_server_user_level_is_refused() {
        let settings = message(&[varint_field(1, 1), varint_field(6, 3)]);
        let error = to_json(&config(
            &message(&[
                bytes_field(
                    2,
                    &typed(
                        "xray.app.proxyman.ReceiverConfig",
                        &receiver(5000, Some(&[127, 0, 0, 1])),
                    ),
                ),
                bytes_field(3, &typed("xray.proxy.socks.ServerConfig", &settings)),
            ]),
            &freedom_outbound(),
        ))
        .expect_err("refused");
        assert!(error.contains("user_level"), "{error}");
    }

    #[test]
    fn a_shadowsocks_iv_check_is_ignored() {
        let account = typed(
            "xray.proxy.shadowsocks.Account",
            &message(&[bytes_field(1, b"a"), varint_field(2, 6), varint_field(3, 1)]),
        );
        let settings = bytes_field(1, &ss_user(&account, None));
        let json = to_json(&config(&ss_inbound(5000, &settings), &freedom_outbound()))
            .expect("iv_check decodes");
        let method = json
            .get("inbounds")
            .and_then(Json::as_arr)
            .and_then(|inbounds| inbounds.first())
            .and_then(|inbound| inbound.get("settings"))
            .and_then(|settings| settings.get("users"))
            .and_then(Json::as_arr)
            .and_then(|users| users.first())
            .and_then(|user| user.get("method"))
            .and_then(Json::as_str);
        assert_eq!(method, Some("aes-256-gcm"));
    }

    #[test]
    fn an_unknown_shadowsocks_cipher_is_refused() {
        let settings = message(&[
            bytes_field(1, &ss_user(&ss_account(b"a", 0), None)),
            bytes_field(2, &[2]),
        ]);
        let error = to_json(&config(&ss_inbound(5000, &settings), &freedom_outbound()))
            .expect_err("refused");
        assert!(error.contains("cipher 0"), "{error}");
    }

    #[test]
    fn a_shadowsocks_unix_network_opens_no_listener() {
        let settings = message(&[
            bytes_field(1, &ss_user(&ss_account(b"a", 6), None)),
            bytes_field(2, &[4]),
        ]);
        let json = to_json(&config(&ss_inbound(5000, &settings), &freedom_outbound()))
            .expect("a unix network decodes");
        let named = json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("settings")
            .and_then(|settings| settings.get("network"))
            .and_then(Json::as_str);
        assert_eq!(
            named,
            Some(""),
            "a unix-only list names no network this front carries, so it opens neither"
        );
    }

    #[test]
    fn a_shadowsocks_network_list_narrows_the_front() {
        let settings = message(&[
            bytes_field(1, &ss_user(&ss_account(b"a", 6), None)),
            bytes_field(2, &[2, 3]),
            bytes_field(2, &[2]),
        ]);
        let json = to_json(&config(&ss_inbound(5000, &settings), &freedom_outbound()))
            .expect("both networks decode");
        let named = json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0]
            .get("settings")
            .and_then(|settings| settings.get("network"))
            .and_then(Json::as_str);
        assert_eq!(named, Some("tcp,udp"), "each network named once, in order");
    }

    #[test]
    fn two_shadowsocks_users_decode_as_two_clients() {
        let settings = message(&[
            bytes_field(1, &ss_user(&ss_account(b"a", 6), None)),
            bytes_field(1, &ss_user(&ss_account(b"b", 6), None)),
            bytes_field(2, &[2]),
        ]);
        let json = to_json(&config(&ss_inbound(5000, &settings), &freedom_outbound()))
            .expect("both clients decode");
        let server = &json
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds")[0];
        let users = server
            .get("settings")
            .and_then(|settings| settings.get("users"))
            .and_then(Json::as_arr)
            .expect("users");
        assert_eq!(users.len(), 2, "one account per user, not the first");
        assert_eq!(
            users[1].get("password").and_then(Json::as_str),
            Some("b"),
            "the second client keeps its own password"
        );
    }

    #[test]
    fn a_shadowsocks_user_email_is_kept() {
        let user = message(&[
            bytes_field(2, b"who@example"),
            bytes_field(3, &ss_account(b"a", 6)),
        ]);
        let settings = bytes_field(1, &user);
        let json = to_json(&config(&ss_inbound(5000, &settings), &freedom_outbound()))
            .expect("email decodes");
        let email = json
            .get("inbounds")
            .and_then(Json::as_arr)
            .and_then(|inbounds| inbounds.first())
            .and_then(|inbound| inbound.get("settings"))
            .and_then(|settings| settings.get("users"))
            .and_then(Json::as_arr)
            .and_then(|users| users.first())
            .and_then(|user| user.get("email"))
            .and_then(Json::as_str);
        assert_eq!(email, Some("who@example"));
    }

    #[test]
    fn a_truncated_field_is_refused() {
        let mut bytes = http_scenario(5000);
        bytes.extend([0x0a, 0x05]);
        let error = to_json(&bytes).expect_err("refused");
        assert!(error.contains("runs past"), "{error}");
    }

    fn wg_peer() -> Vec<u8> {
        message(&[
            bytes_field(1, "33".repeat(32).as_bytes()),
            bytes_field(3, b"127.0.0.1:1234"),
            bytes_field(4, b"25"),
            bytes_field(5, b"0.0.0.0/0"),
            bytes_field(5, b"::/0"),
        ])
    }

    #[test]
    fn a_masque_client_carries_its_endpoint_and_remote_dns() {
        let address = message(&[bytes_field(2, b"example.com")]);
        let user = message(&[
            bytes_field(2, b"u@example.com"),
            bytes_field(
                3,
                &typed(
                    "xray.proxy.masque.Account",
                    &message(&[bytes_field(1, b"p")]),
                ),
            ),
        ]);
        let endpoint = message(&[
            bytes_field(1, &address),
            varint_field(2, 443),
            bytes_field(3, &user),
        ]);
        let settings = message(&[
            bytes_field(1, &endpoint),
            bytes_field(2, b"192.0.2.1"),
            bytes_field(2, b"192.0.2.2"),
        ]);
        let raw = message(&[bytes_field(
            3,
            &typed("xray.proxy.masque.ClientConfig", &settings),
        )]);
        let json = outbound(&raw).expect("the pinned shape decodes");
        assert_eq!(json.get("protocol").and_then(Json::as_str), Some("masque"));
        let settings = json.get("settings").expect("settings");
        let server = settings.get("server").expect("server");
        assert_eq!(
            server.get("address").and_then(Json::as_str),
            Some("example.com")
        );
        assert_eq!(server.get("port").and_then(Json::as_port), Some(443));
        assert_eq!(settings.get("password").and_then(Json::as_str), Some("p"));
        assert_eq!(
            settings.get("remoteDNS"),
            Some(&Json::Arr(vec![
                Json::Str("192.0.2.1".to_owned()),
                Json::Str("192.0.2.2".to_owned()),
            ]))
        );
    }

    #[test]
    fn a_masque_server_user_is_its_account_password() {
        let account = typed(
            "xray.proxy.masque.Account",
            &message(&[bytes_field(1, b"p")]),
        );
        let user = message(&[bytes_field(2, b"u@example.com"), bytes_field(3, &account)]);
        let settings = message(&[
            bytes_field(1, &user),
            bytes_field(2, b"10.14.0.1/24"),
            bytes_field(2, b"fd14::1/64"),
            varint_field(3, 1280),
        ]);
        let raw = message(&[
            bytes_field(
                2,
                &typed(
                    "xray.app.proxyman.ReceiverConfig",
                    &receiver(443, Some(&[0, 0, 0, 0])),
                ),
            ),
            bytes_field(3, &typed("xray.proxy.masque.ServerConfig", &settings)),
        ]);
        let json = inbound(&raw).expect("the pinned shape decodes");
        assert_eq!(json.len(), 1);
        assert_eq!(
            json[0].get("protocol").and_then(Json::as_str),
            Some("masque")
        );
        let settings = json[0].get("settings").expect("settings");
        assert_eq!(settings.get("mtu").and_then(Json::as_u32), Some(1280));
        let user = settings
            .get("users")
            .and_then(Json::as_arr)
            .and_then(|users| users.first())
            .expect("a user");
        assert_eq!(
            user.get("email").and_then(Json::as_str),
            Some("u@example.com")
        );
        assert_eq!(user.get("password").and_then(Json::as_str), Some("p"));
    }

    #[test]
    fn a_masque_transport_carries_its_host_path_and_headers() {
        let header = message(&[bytes_field(1, b"Authorization"), bytes_field(2, b"Basic x")]);
        let settings = message(&[
            bytes_field(1, b"example.com"),
            bytes_field(2, b"/.well-known/masque/ip/*/*/"),
            bytes_field(3, &header),
        ]);
        let raw = message(&[
            bytes_field(
                2,
                &typed("xray.transport.internet.masque.Config", &settings),
            ),
            bytes_field(3, b"masque"),
        ]);
        let (json, name) = transport_config(&raw).expect("the transport decodes");
        assert_eq!(name, "masque");
        let json = json.expect("masque settings");
        assert_eq!(json.get("host").and_then(Json::as_str), Some("example.com"));
        assert_eq!(
            json.get("path").and_then(Json::as_str),
            Some("/.well-known/masque/ip/*/*/")
        );
        assert_eq!(
            json.get("headers"),
            Some(&Json::Arr(vec![object(vec![
                ("name", Json::Str("Authorization".to_owned())),
                ("value", Json::Str("Basic x".to_owned())),
            ])]))
        );
    }

    #[test]
    fn a_masque_warp_block_carries_its_keys_as_base64() {
        let private = [0x30, 0x82, 0x01, 0x02];
        let public = [0x30, 0x59, 0x30, 0x13];
        let warp = message(&[
            bytes_field(1, &private),
            bytes_field(2, &public),
            bytes_field(3, b"172.16.0.2/32"),
        ]);
        let settings = message(&[bytes_field(4, &warp)]);
        let raw = message(&[
            bytes_field(
                2,
                &typed("xray.transport.internet.masque.Config", &settings),
            ),
            bytes_field(3, b"masque"),
        ]);
        let (json, _) = transport_config(&raw).expect("the transport decodes");
        let json = json.expect("masque settings");
        let warp = json.get("warp").expect("warp");
        assert_eq!(
            warp.get("privateKey").and_then(Json::as_str),
            Some(ferrox_core::b64::encode(&private).as_str())
        );
        assert_eq!(
            warp.get("publicKey").and_then(Json::as_str),
            Some(ferrox_core::b64::encode(&public).as_str())
        );
        assert_eq!(
            warp.get("address"),
            Some(&Json::Arr(vec![Json::Str("172.16.0.2/32".to_owned())]))
        );
    }

    #[test]
    fn a_wireguard_client_becomes_the_json_device_config() {
        let settings = message(&[
            bytes_field(1, "11".repeat(32).as_bytes()),
            bytes_field(2, b"10.0.0.2"),
            bytes_field(2, b"fd00::2"),
            bytes_field(3, &wg_peer()),
            varint_field(4, 1420),
            varint_field(8, 1),
            varint_field(9, 1),
        ]);
        let raw = message(&[bytes_field(
            3,
            &typed("xray.proxy.wireguard.DeviceConfig", &settings),
        )]);
        let json = outbound(&raw).expect("the pinned shape decodes");
        assert_eq!(
            json.get("protocol").and_then(Json::as_str),
            Some("wireguard")
        );
        let settings = json.get("settings").expect("settings");
        assert_eq!(settings.get("isClient"), Some(&Json::Bool(true)));
        let decoded = crate::wireguard::DeviceConfig::from_json(settings).expect("device config");
        assert_eq!(decoded.peers.len(), 1);
        assert_eq!(
            decoded.peers[0].endpoint.map(|endpoint| endpoint.port()),
            Some(1234)
        );
        assert_eq!(decoded.peers[0].keepalive, 25);
        assert!(decoded.peers[0].routes("192.0.2.1".parse().unwrap()));
        assert!(decoded.peers[0].routes("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn a_wireguard_server_user_is_a_peer_under_its_account() {
        let account = typed("xray.proxy.wireguard.PeerConfig", &wg_peer());
        let user = message(&[bytes_field(2, b"love@xray.com"), bytes_field(3, &account)]);
        let settings = message(&[
            bytes_field(1, "11".repeat(32).as_bytes()),
            bytes_field(5, &user),
            varint_field(8, 0),
        ]);
        let raw = message(&[
            bytes_field(
                2,
                &typed(
                    "xray.app.proxyman.ReceiverConfig",
                    &receiver(51820, Some(&[0, 0, 0, 0])),
                ),
            ),
            bytes_field(3, &typed("xray.proxy.wireguard.DeviceConfig", &settings)),
        ]);
        let json = inbound(&raw).expect("the pinned shape decodes");
        assert_eq!(json.len(), 1);
        assert_eq!(
            json[0].get("protocol").and_then(Json::as_str),
            Some("wireguard")
        );
        let decoded =
            crate::wireguard::DeviceConfig::from_json(json[0].get("settings").expect("settings"))
                .expect("device config");
        assert_eq!(decoded.peers.len(), 1);
        assert_eq!(decoded.peers[0].allowed.len(), 2);
    }

    #[test]
    fn a_wireguard_reserved_field_round_trips_as_three_bytes() {
        let settings = message(&[
            bytes_field(1, "11".repeat(32).as_bytes()),
            bytes_field(6, &[1, 2, 3]),
            bytes_field(3, &wg_peer()),
        ]);
        let json = wireguard_settings(&settings).expect("device config");
        assert_eq!(
            json.get("reserved"),
            Some(&Json::Arr(vec![
                Json::Num(1.0),
                Json::Num(2.0),
                Json::Num(3.0)
            ]))
        );
    }
}

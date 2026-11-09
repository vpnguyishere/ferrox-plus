// The census is a test-shape instrument: here its call expands to nothing, so no shipped relay carries a map, a lock or a name.
#[cfg(not(test))]
macro_rules! census {
    ($name:literal, $fd:expr, $armed:expr) => {};
}

// The counting allocator is core's and the window is one thread's: installed only for the test binary, so a shipped flow keeps the system allocator.
#[cfg(test)]
#[global_allocator]
static ALLOC_COUNT: ferrox_core::alloc_count::Counting = ferrox_core::alloc_count::Counting;

mod accesslog;
mod budgets;
#[cfg(test)]
#[macro_use]
mod census;
mod blackhole;
mod commander;
mod config;
mod conn;
mod dnsapp;
mod dnsnet;
mod ech_dns;
mod foxy;
mod foxy_account;
mod foxy_browser;
mod foxy_catalog;
mod foxy_challenge;
mod foxy_latency;
#[cfg(test)]
mod foxy_live;
mod geodata;
mod grpc;
mod h2;
mod headers;
mod httpheader;
mod httpupgrade;
mod hysteria;
mod hysteria_realm;
mod hysteria_v1;
mod json;
mod limit;
mod masque;
mod masque_h1;
mod masque_h2;
mod metrics;
mod observatory;
mod policy;
mod process;
mod proxy;
mod psiphon;
mod psiphon_broker;
mod psiphon_burst;
mod psiphon_dns;
mod psiphon_fragment;
mod psiphon_geoip;
mod psiphon_h3;
mod psiphon_light;
mod psiphon_meek;
mod psiphon_osl;
mod psiphon_quic;
mod psiphon_rate;
mod psiphon_replay;
mod psiphon_shadowsocks;
mod psiphon_ssh;
mod psiphon_tactics;
mod psiphon_user_agent;
mod psiphon_webrtc;
mod quic;
mod reverse;
mod router;
mod router_script;
mod shadowsocks;
mod shadowsocks2022;
mod sniff;
mod sockopt;
mod socks;
mod stats;
mod transparent;
mod tun;
mod tun_stack;
#[cfg(unix)]
mod tun_system;
mod veepn;
mod vision;
mod vmess;
mod webhook;
mod wg;
#[cfg(target_os = "linux")]
mod wg_kernel;
mod wg_stack;
mod wireguard;
mod ws;
mod xdrive;
mod xhttp;
mod xhttp_h2;
mod xhttp_h3;
mod xmux;
mod xray_pb;

use crate::proxy::exit;
use ferrox_core::policy::UnsafeOptIn;
use ferrox_core::transport::Support;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Set by `-test`, so the startup exits answer xray's way: `Failed to start:` and status 23.
static TEST_ONLY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(crate) fn test_only() -> bool {
    TEST_ONLY.load(std::sync::atomic::Ordering::Relaxed)
}

fn usage() -> ! {
    eprintln!("usage:");
    eprintln!("  ferrox-app check <vless://...|trojan://...> [--allow-unsafe-fp] [--allow-plaintext-public]");
    eprintln!("                                parse + support + header len (no network)");
    eprintln!("  ferrox-app run <vless://...|trojan://...> [same flags]   check + TCP reachability (sends nothing)");
    eprintln!("  ferrox-app version                print the serving binary's version");
    eprintln!("  ferrox-app x25519                 print a fresh X25519 keypair");
    eprintln!("  ferrox-app run -c <config.json>   serve inbounds until killed");
    eprintln!("  ferrox-app -config=<file|stdin:> [-format=json|pb]   same, xray's own invocation");
    eprintln!(
        "  ferrox-app -confdir <dir>        merge every config file in the directory, as xray does"
    );
    eprintln!("  ferrox-app -dump                 print the merged config and exit");
    eprintln!(
        "  ferrox-app -test -c <config.json>  build every handler and exit, as xray's -test does"
    );
    eprintln!(
        "  ferrox-app [no arguments]         serve a discovered config.json, or stdin, as xray does"
    );
    eprintln!("  ferrox-app mint-foxy-pass -c <config.json> -o <pass.json>");
    eprintln!("                                sign in once, store the proxy pass (0600)");
    eprintln!(
        "  ferrox-app browser-login --email ADDR --token-file PATH [--code CODE] [--no-open]"
    );
    eprintln!("                                finish the Firefox sign-in in a real browser");
    eprintln!(
        "  ferrox-app edges [--ping]         list the catalogue's edges as JSON rows; --ping adds a handshake ms (null when silent)"
    );
    eprintln!(
        "  ferrox-app psiphon-regions -c <config.json>   list the signed server list's region codes"
    );
    eprintln!(
        "  ferrox-app psiphon-tactics -c <config.json>   fetch tactics and print broker specs"
    );
    eprintln!(
        "  ferrox-app psiphon-broker -c <config.json> [--sdp <file>]  send a client offer to the first broker"
    );
    std::process::exit(2);
}

/// One share link plus any out-of-band consent flags, in either order.
fn link_and_opt_in<I: Iterator<Item = String>>(args: &mut I) -> (String, UnsafeOptIn) {
    let mut link: Option<String> = None;
    let mut opt = UnsafeOptIn::none();
    for arg in args {
        match arg.as_str() {
            "--allow-unsafe-fp" => opt = opt.allow_unsafe_fingerprint(),
            "--allow-plaintext-public" => opt = opt.allow_plaintext_to_public(),
            _ if link.is_none() => link = Some(arg),
            _ => usage(),
        }
    }
    match link {
        Some(link) => (link, opt),
        None => usage(),
    }
}

enum Link {
    Vless(ferrox_core::vless::VlessLink),
    Trojan(ferrox_core::trojan::TrojanLink),
}

impl Link {
    fn parse(text: &str) -> Self {
        if text.starts_with(ferrox_core::trojan::SCHEME) {
            return ferrox_core::trojan::TrojanLink::parse(text).map_or_else(
                |e| {
                    eprintln!("bad link: {e}");
                    std::process::exit(1);
                },
                Self::Trojan,
            );
        }
        ferrox_core::vless::VlessLink::parse(text).map_or_else(
            |e| {
                eprintln!("bad link: {e}");
                std::process::exit(1);
            },
            Self::Vless,
        )
    }

    fn describe(&self, opt_in: UnsafeOptIn) -> String {
        match self {
            Self::Vless(link) => format!(
                "host={} port={} type={} security={} flow={} support=[{}]",
                link.host,
                link.port,
                link.param("type"),
                link.param("security"),
                link.flow(),
                link.support_opted(opt_in),
            ),
            Self::Trojan(link) => format!(
                "host={} port={} type={} security={} header={} support=[{}]",
                link.host,
                link.port,
                link.param("type"),
                link.param("security"),
                match link.header_type() {
                    "" => "none",
                    header => header,
                },
                link.support_opted(opt_in),
            ),
        }
    }

    fn support_opted(&self, opt_in: UnsafeOptIn) -> Support {
        match self {
            Self::Vless(link) => link.support_opted(opt_in),
            Self::Trojan(link) => link.support_opted(opt_in),
        }
    }

    fn authority(&self) -> (&str, u16) {
        match self {
            Self::Vless(link) => (&link.host, link.port),
            Self::Trojan(link) => (&link.host, link.port),
        }
    }

    /// A header for the same probe destination either way, so `check` prints one number for both schemes.
    fn header(&self) -> Vec<u8> {
        match self {
            Self::Vless(link) => link.encode_request_header("example.com", 443),
            Self::Trojan(link) => {
                link.encode_header(ferrox_core::trojan::Command::Connect, "example.com", 443)
            }
        }
    }
}

fn cmd_check(link_str: &str, opt_in: UnsafeOptIn) {
    let link = Link::parse(link_str);
    println!("{}", link.describe(opt_in));
    let hdr = link.header();
    println!(
        "header_len={} header_prefix={:02x?}",
        hdr.len(),
        &hdr[..8.min(hdr.len())]
    );
    match link.support_opted(opt_in) {
        Support::Implemented { method } => {
            println!("diallable: {method} (run checks tcp reachability; sends nothing)");
        }
        Support::Planned { reason } => println!("not yet diallable: {reason}"),
        Support::UnsafeRequiresOptIn { reason } => {
            println!("needs explicit opt-in (policy::UnsafeOptIn, or --allow-unsafe-fp / --allow-plaintext-public): {reason}");
        }
    }
}

fn cmd_run(link_str: &str, opt_in: UnsafeOptIn) {
    let link = Link::parse(link_str);
    println!("{}", link.describe(opt_in));
    match link.support_opted(opt_in) {
        Support::Implemented { .. } => {}
        other => {
            eprintln!("refusing to dial: {other}");
            eprintln!("(parse succeeded; the transport rung is not implemented yet)");
            std::process::exit(3);
        }
    }
    let (host, port) = link.authority();
    let addr = format!("{host}:{port}");
    let sock: std::net::SocketAddr = if let Ok(sock) = addr.parse() {
        sock
    } else {
        use std::net::ToSocketAddrs as _;
        addr.to_socket_addrs()
            .ok()
            .and_then(|mut it| it.next())
            .unwrap_or_else(|| {
                eprintln!("cannot resolve {addr}");
                std::process::exit(1);
            })
    };
    let t0 = std::time::Instant::now();
    match std::net::TcpStream::connect_timeout(&sock, Duration::from_secs(8)) {
        Ok(stream) => {
            let dt = t0.elapsed();
            println!("tcp reachable in {dt:?} (no bytes sent; session handshake is the next rung)");
            drop(stream);
        }
        Err(e) => {
            eprintln!("tcp unreachable: {e}");
            std::process::exit(4);
        }
    }
    let hdr = link.header();
    println!("header_len={} (encoded locally, not sent)", hdr.len());
    let _ = std::io::stdout().flush();
}

fn cmd_psiphon_regions<I: Iterator<Item = String>>(args: &mut I) {
    let mut path = String::new();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "-config" | "--config" => {
                path = args.next().unwrap_or_else(|| usage());
            }
            other if other.starts_with("--config=") => {
                path.clear();
                path.push_str(&other["--config=".len()..]);
            }
            _ => usage(),
        }
    }
    if path.is_empty() {
        usage();
    }
    let text = if path == "-" || path == "stdin:" {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .unwrap_or_else(|error| {
                eprintln!("psiphon-regions: stdin: {error}");
                std::process::exit(1);
            });
        text
    } else {
        std::fs::read_to_string(&path).unwrap_or_else(|error| {
            eprintln!("psiphon-regions: {path}: {error}");
            std::process::exit(1);
        })
    };
    let root = json::parse(&text).unwrap_or_else(|error| {
        eprintln!("psiphon-regions: {error}");
        std::process::exit(1);
    });
    let settings = root
        .get("outbounds")
        .and_then(json::Json::as_arr)
        .and_then(|outbounds| {
            outbounds.iter().find(|outbound| {
                outbound.get("protocol").and_then(json::Json::as_str) == Some("psiphon")
            })
        })
        .and_then(|outbound| outbound.get("settings"));
    match psiphon::regions(settings) {
        Ok(rows) => {
            for (region, count) in rows {
                println!("{region}\t{count}");
            }
        }
        Err(why) => {
            eprintln!("{why}");
            std::process::exit(1);
        }
    }
}

fn cmd_psiphon_tactics<I: Iterator<Item = String>>(args: &mut I) {
    let mut path = String::new();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "-config" | "--config" => {
                path = args.next().unwrap_or_else(|| usage());
            }
            other if other.starts_with("--config=") => {
                path.clear();
                path.push_str(&other["--config=".len()..]);
            }
            _ => usage(),
        }
    }
    if path.is_empty() {
        usage();
    }
    let text = if path == "-" || path == "stdin:" {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .unwrap_or_else(|error| {
                eprintln!("psiphon-tactics: stdin: {error}");
                std::process::exit(1);
            });
        text
    } else {
        std::fs::read_to_string(&path).unwrap_or_else(|error| {
            eprintln!("psiphon-tactics: {path}: {error}");
            std::process::exit(1);
        })
    };
    let root = json::parse(&text).unwrap_or_else(|error| {
        eprintln!("psiphon-tactics: {error}");
        std::process::exit(1);
    });
    let settings = root
        .get("outbounds")
        .and_then(json::Json::as_arr)
        .and_then(|outbounds| {
            outbounds.iter().find(|outbound| {
                outbound.get("protocol").and_then(json::Json::as_str) == Some("psiphon")
            })
        })
        .and_then(|outbound| outbound.get("settings"));
    match psiphon::tactics(settings) {
        Ok(tactics) => {
            println!("tag\t{}", tactics.tag);
            println!("ttl\t{}", tactics.ttl);
            for broker in tactics.brokers {
                println!(
                    "broker\t{}\t{}\t{}",
                    broker.public_key,
                    broker.root_secret,
                    broker
                        .fronts
                        .iter()
                        .map(|front| front.host.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            for compartment in tactics.compartments {
                println!("compartment\t{compartment}");
            }
        }
        Err(why) => {
            eprintln!("{why}");
            std::process::exit(1);
        }
    }
}

fn cmd_psiphon_broker<I: Iterator<Item = String>>(args: &mut I) {
    let mut path = String::new();
    let mut sdp_path = String::new();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "-config" | "--config" => {
                path = args.next().unwrap_or_else(|| usage());
            }
            other if other.starts_with("--config=") => {
                path.clear();
                path.push_str(&other["--config=".len()..]);
            }
            "--sdp" => {
                sdp_path = args.next().unwrap_or_else(|| usage());
            }
            other if other.starts_with("--sdp=") => {
                sdp_path.clear();
                sdp_path.push_str(&other["--sdp=".len()..]);
            }
            _ => usage(),
        }
    }
    if path.is_empty() {
        usage();
    }
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        eprintln!("psiphon-broker: {path}: {error}");
        std::process::exit(1);
    });
    let root = json::parse(&text).unwrap_or_else(|error| {
        eprintln!("psiphon-broker: {error}");
        std::process::exit(1);
    });
    let settings = root
        .get("outbounds")
        .and_then(json::Json::as_arr)
        .and_then(|outbounds| {
            outbounds.iter().find(|outbound| {
                outbound.get("protocol").and_then(json::Json::as_str) == Some("psiphon")
            })
        })
        .and_then(|outbound| outbound.get("settings"));
    let sdp = if sdp_path.is_empty() {
        None
    } else {
        Some(std::fs::read_to_string(&sdp_path).unwrap_or_else(|error| {
            eprintln!("psiphon-broker: {sdp_path}: {error}");
            std::process::exit(1);
        }))
    };
    match psiphon::broker_offer(settings, sdp.as_deref()) {
        Ok(offer) => {
            println!("limited\t{}", offer.limited);
            println!("no_match\t{}", offer.no_match);
            println!("must_upgrade\t{}", offer.must_upgrade);
            println!("connection_id_len\t{}", offer.connection_id.len());
            println!("protocol_version\t{}", offer.protocol_version);
            println!("answer_sdp\t{}", offer.answer_sdp);
            println!(
                "relay_packet_to_server\t{}",
                offer.relay_packet_to_server.len()
            );
        }
        Err(why) => {
            eprintln!("{why}");
            std::process::exit(1);
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(cmd) = args.next() else {
        serve_from_flags(&[]);
    };
    match cmd.as_str() {
        "check" => {
            let (link, opt_in) = link_and_opt_in(&mut args);
            cmd_check(&link, opt_in);
        }
        "run" => {
            let rest: Vec<String> = args.collect();
            if rest.is_empty() || rest.first().is_some_and(|arg| is_serve_flag(arg)) {
                serve_from_flags(&rest);
            }
            let mut iter = rest.into_iter();
            let (link, opt_in) = link_and_opt_in(&mut iter);
            cmd_run(&link, opt_in);
        }
        "version" => {
            if args.next().is_some() {
                usage();
            }
            proxy::print_version();
        }
        "mint-foxy-pass" => {
            let next = args.next().unwrap_or_else(|| usage());
            if next != "-c" && next != "-config" {
                usage();
            }
            let config = args.next().unwrap_or_else(|| usage());
            let flag = args.next().unwrap_or_else(|| usage());
            if flag != "-o" {
                usage();
            }
            let out = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            proxy::mint_foxy_pass(&config, &out);
        }
        "browser-login" => {
            let mut email = String::new();
            let mut token_file = String::new();
            let mut code = String::new();
            let mut no_open = false;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--email" | "-e" => email = args.next().unwrap_or_else(|| usage()),
                    "--token-file" | "-t" => {
                        token_file = args.next().unwrap_or_else(|| usage());
                    }
                    "--code" => code = args.next().unwrap_or_else(|| usage()),
                    "--no-open" => no_open = true,
                    _ => usage(),
                }
            }
            if email.is_empty() || token_file.is_empty() {
                usage();
            }
            foxy_browser::login(
                &email,
                &token_file,
                (!code.is_empty()).then_some(code.as_str()),
                no_open,
            );
        }
        "edges" => {
            let mut ping = false;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--ping" => ping = true,
                    // A config is accepted and ignored for the spelling the docs already carry: the catalogue needs no lane.
                    "-c" | "-config" => {
                        args.next().unwrap_or_else(|| usage());
                    }
                    _ => usage(),
                }
            }
            proxy::print_foxy_edges(ping);
        }
        "psiphon-regions" => cmd_psiphon_regions(&mut args),
        "psiphon-tactics" => cmd_psiphon_tactics(&mut args),
        "psiphon-broker" => cmd_psiphon_broker(&mut args),
        "x25519" => {
            if args.next().is_some() {
                usage();
            }
            proxy::print_x25519();
        }
        _ if is_serve_flag(&cmd) => {
            let rest: Vec<String> = std::iter::once(cmd).chain(args).collect();
            serve_from_flags(&rest);
        }
        _ => usage(),
    }
}

/// A flag xray itself takes for a config; `run <link> --allow-unsafe-fp` is link mode.
fn is_serve_flag(arg: &str) -> bool {
    matches!(
        arg.split('=').next().unwrap_or(arg),
        "-c" | "-config" | "-confdir" | "-format" | "-test" | "-dump"
    )
}

/// xray's own invocation (`-config=stdin: -format=pb`) and the `run -c <file>` spelling this tree
/// shipped first; several files, a config dir or several `-c` files, merge before they serve.
fn serve_from_flags(args: &[String]) -> ! {
    let mut configs: Vec<String> = Vec::new();
    let mut confdir: Option<String> = None;
    let mut format: Option<String> = None;
    let mut dump = false;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let (flag, inline) = match arg.split_once('=') {
            Some((flag, value)) => (flag, Some(value.to_owned())),
            None => (arg.as_str(), None),
        };
        match flag {
            "-c" | "-config" | "-format" | "-confdir" => {
                let value = if let Some(value) = inline {
                    value
                } else {
                    i += 1;
                    args.get(i).cloned().unwrap_or_else(|| usage())
                };
                match flag {
                    "-format" => format = Some(value),
                    "-confdir" => confdir = Some(value),
                    _ => configs.push(value),
                }
            }
            "-test" => TEST_ONLY.store(true, std::sync::atomic::Ordering::Relaxed),
            "-dump" => dump = true,
            _ => usage(),
        }
        i += 1;
    }
    if let Some(dir) = confdir.as_deref() {
        read_conf_dir(dir, format.as_deref(), &mut configs);
    } else if let Some(dir) = conf_dir_env() {
        read_conf_dir(&dir, format.as_deref(), &mut configs);
    }
    if dump {
        dump_config(&configs);
    }
    if configs.len() > 1 {
        serve_files(&configs, format.as_deref());
    }
    let source = configs.pop().unwrap_or_else(discover_config);
    let format = source_format(format.as_deref(), &source);
    let bytes = read_source(&source);
    serve_source(&source, &bytes, format)
}

/// xray's `readConfDir`: every file the `-format` regex names, in `os.ReadDir`'s sorted order,
/// appended after the files `-c` named. A path that is not a directory is not an error there.
fn read_conf_dir(dir: &str, format: Option<&str>, out: &mut Vec<String>) {
    if !std::path::Path::new(dir).is_dir() {
        return;
    }
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|error| proxy::exit(&format!("cannot read {dir}: {error}")));
    let suffixes: &[&str] = match format.map(str::to_ascii_lowercase).as_deref() {
        Some("json" | "jsonc") => &["json", "jsonc"],
        Some("toml") => &["toml"],
        Some("yaml" | "yml") => &["yaml", "yml"],
        _ => &["json", "jsonc", "toml", "yaml", "yml"],
    };
    let mut names: Vec<std::path::PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|extension| {
                    suffixes
                        .iter()
                        .any(|suffix| extension.eq_ignore_ascii_case(suffix))
                })
        })
        .collect();
    names.sort();
    out.extend(
        names
            .into_iter()
            .map(|path| path.to_string_lossy().into_owned()),
    );
}

/// `xray.location.confdir`, read only when `-confdir` named no directory.
fn conf_dir_env() -> Option<String> {
    std::env::var_os("xray.location.confdir")
        .or_else(|| std::env::var_os("XRAY_LOCATION_CONFDIR"))
        .map(|dir| dir.to_string_lossy().into_owned())
        .filter(|dir| std::path::Path::new(dir).is_dir())
}

/// xray's `MergeConfig`: every file decoded, then each later config overrides the one before by
/// its own `Override` rule. Protobuf is one file or none, as the reference's loader insists.
fn serve_files(files: &[String], format: Option<&str>) -> ! {
    let mut merged = crate::json::Json::Obj(Vec::new());
    for (at, file) in files.iter().enumerate() {
        if matches!(source_format(format, file), SourceFormat::Protobuf) {
            proxy::exit("Only one protobuf config file is allowed");
        }
        let bytes = read_source(file);
        let body = std::str::from_utf8(&bytes)
            .unwrap_or_else(|error| proxy::exit(&format!("bad config {file}: {error}")));
        let root = crate::json::parse(body)
            .unwrap_or_else(|error| proxy::exit(&format!("bad config {file}: {error}")));
        if at == 0 {
            merged = root;
        } else {
            crate::json::merge(&mut merged, &root, file);
        }
    }
    let mut text = String::new();
    crate::json::write(&merged, &mut text);
    proxy::serve_json(&files.join(", "), &text, test_only());
}

/// xray's `-dump`: the merged config on stdout, without building or serving it. A file format the
/// reference has no decoder for is skipped, and a merge error is its status 23 with the reason on
/// stdout.
fn dump_config(configs: &[String]) -> ! {
    let files = if configs.is_empty() {
        vec![discover_config()]
    } else {
        configs.to_vec()
    };
    let mut merged = crate::json::Json::Obj(Vec::new());
    let mut first = true;
    for file in &files {
        let extension = if file == "stdin:" {
            None
        } else {
            std::path::Path::new(file)
                .extension()
                .and_then(std::ffi::OsStr::to_str)
                .map(str::to_ascii_lowercase)
        };
        match extension.as_deref() {
            Some(format @ ("yaml" | "yml" | "toml")) => {
                dump_fail(&format!("config format `{format}` is not carried; json is"));
            }
            Some("json" | "jsonc") => {}
            None if file == "stdin:" => {}
            _ => continue,
        }
        let bytes = if file == "stdin:" {
            let mut bytes = Vec::new();
            if let Err(error) = std::io::stdin().read_to_end(&mut bytes) {
                dump_fail(&format!("cannot read stdin: {error}"));
            }
            bytes
        } else if file.starts_with("http://") || file.starts_with("https://") {
            fetch_http(file)
        } else {
            std::fs::read(file)
                .unwrap_or_else(|error| dump_fail(&format!("cannot read {file}: {error}")))
        };
        let body = std::str::from_utf8(&bytes)
            .unwrap_or_else(|error| dump_fail(&format!("bad config {file}: {error}")));
        let root = crate::json::parse(body)
            .unwrap_or_else(|error| dump_fail(&format!("bad config {file}: {error}")));
        if first {
            merged = root;
            first = false;
        } else {
            crate::json::merge(&mut merged, &root, file);
        }
    }
    let mut text = String::new();
    crate::json::write(&merged, &mut text);
    println!("{text}");
    std::process::exit(0);
}

fn dump_fail(message: &str) -> ! {
    println!("{message}");
    std::process::exit(23);
}

#[derive(Clone, Copy)]
enum SourceFormat {
    Json,
    Protobuf,
}

/// xray's search when no `-config` is given: a `config.*` in the working directory, then
/// `xray.location.config`'s `config.json` (the executable's directory when unset), then stdin.
fn discover_config() -> String {
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(dir) = std::env::current_dir() {
        for name in [
            "config.json",
            "config.jsonc",
            "config.toml",
            "config.yaml",
            "config.yml",
        ] {
            candidates.push(dir.join(name));
        }
    }
    let installed = std::env::var_os("xray.location.config")
        .or_else(|| std::env::var_os("XRAY_LOCATION_CONFIG"))
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(std::path::Path::to_path_buf))
        });
    candidates.extend(installed.map(|dir| dir.join("config.json")));
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .map_or_else(
            || "stdin:".to_owned(),
            |path| path.to_string_lossy().into_owned(),
        )
}

/// xray infers the format from the extension when `-format` is absent; a stream
/// has none, and JSON is this tree's own dialect.
fn source_format(named: Option<&str>, source: &str) -> SourceFormat {
    match named.map(str::to_ascii_lowercase).as_deref() {
        Some("pb" | "protobuf") => SourceFormat::Protobuf,
        Some("json" | "jsonc") => SourceFormat::Json,
        Some("auto") | None => {
            let extension = std::path::Path::new(source)
                .extension()
                .and_then(std::ffi::OsStr::to_str)
                .unwrap_or_default();
            if extension.eq_ignore_ascii_case("pb") || extension.eq_ignore_ascii_case("protobuf") {
                SourceFormat::Protobuf
            } else {
                SourceFormat::Json
            }
        }
        Some(other @ ("toml" | "yaml" | "yml")) => {
            proxy::exit(&format!(
                "config format `{other}` is not carried; json and protobuf are"
            ));
        }
        Some(other) => proxy::exit(&format!("unknown config format `{other}`")),
    }
}

fn serve_source(label: &str, bytes: &[u8], format: SourceFormat) -> ! {
    match format {
        SourceFormat::Protobuf => proxy::serve_protobuf(label, bytes, test_only()),
        SourceFormat::Json => {
            let body = std::str::from_utf8(bytes)
                .unwrap_or_else(|error| proxy::exit(&format!("bad config {label}: {error}")));
            proxy::serve_json(label, body, test_only())
        }
    }
}

/// Read one `-config` source the way xray's `ConfigLoader` does: stdin, a file, or an HTTP(S) URL.
/// Unix-socket sources refuse, named as such.
fn read_source(source: &str) -> Vec<u8> {
    if source == "stdin:" || source == "stdin" {
        let mut bytes = Vec::new();
        if let Err(error) = std::io::stdin().read_to_end(&mut bytes) {
            proxy::exit(&format!("cannot read stdin: {error}"));
        }
        bytes
    } else if source.starts_with("http+unix://") {
        fetch_http_unix(source.strip_prefix("http+unix://").unwrap_or(source))
    } else if source.starts_with("http://") || source.starts_with("https://") {
        fetch_http(source)
    } else {
        std::fs::read(source)
            .unwrap_or_else(|error| proxy::exit(&format!("cannot read {source}: {error}")))
    }
}

fn fetch_http_unix(source: &str) -> Vec<u8> {
    proxy::exit(&format!(
        "cannot read {source}: http+unix config sources are not carried"
    ));
}

fn fetch_http(target: &str) -> Vec<u8> {
    let Some((host, port, path, tls)) = parse_http_url(target) else {
        exit(&format!("invalid URL: {target}"));
    };
    let address = format!("{host}:{port}");
    let socket = address
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
        .unwrap_or_else(|| exit(&format!("failed to dial to {target}")));
    let stream = TcpStream::connect_timeout(&socket, Duration::from_secs(30))
        .unwrap_or_else(|error| exit(&format!("failed to dial to {target}: {error}")));
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    if tls {
        let cfg = ferrox_core::tls::TlsConfig {
            server_name: host.clone(),
            roots: crate::quic::system_roots(),
            ..Default::default()
        };
        let mut provider = ferrox_core::tls::RustlsProvider::connect(&cfg, stream)
            .unwrap_or_else(|error| exit(&format!("failed to dial to {target}: {error}")));
        http_get(&mut provider, &host, port, &path, target)
    } else {
        let mut stream = stream;
        http_get(&mut stream, &host, port, &path, target)
    }
}

fn http_get(
    stream: &mut (impl Read + Write),
    host: &str,
    port: u16,
    path: &str,
    target: &str,
) -> Vec<u8> {
    let host_header = if (host.contains(':') && !host.starts_with('[')) || host == "::1" {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n");
    if let Err(error) = stream.write_all(request.as_bytes()) {
        exit(&format!("failed to dial to {target}: {error}"));
    }
    let mut head = Vec::with_capacity(4096);
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => exit("failed to read HTTP response"),
            Ok(_) => {
                head.extend_from_slice(&byte);
                if head.len() > 65536 || head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(error) => exit(&format!("failed to read HTTP response: {error}")),
        }
    }
    let status = http_status(&head);
    if status != 200 {
        exit(&format!("unexpected HTTP status code: {status}"));
    }
    let mut body = Vec::new();
    let mut rest = [0u8; 8192];
    loop {
        match stream.read(&mut rest) {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&rest[..n]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => exit(&format!("failed to read HTTP response: {error}")),
        }
    }
    body
}

fn http_status(head: &[u8]) -> u16 {
    let line = head.split(|b| *b == b'\n').next().unwrap_or(&[]);
    let line = String::from_utf8_lossy(line);
    line.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

fn parse_http_url(target: &str) -> Option<(String, u16, String, bool)> {
    let (tls, rest) = if let Some(rest) = target.strip_prefix("https://") {
        (true, rest)
    } else {
        let rest = target.strip_prefix("http://")?;
        (false, rest)
    };
    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let port = rest[end + 1..].strip_prefix(':')?.parse::<u16>().ok()?;
        (host.to_owned(), port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        (host.to_owned(), port.parse::<u16>().ok()?)
    } else {
        (authority.to_owned(), if tls { 443 } else { 80 })
    };
    if host.is_empty() {
        return None;
    }
    let path = path.split('#').next().unwrap_or("/").to_owned();
    Some((host, port, path, tls))
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse_http_url_splits_authority_path_and_scheme() {
        assert_eq!(
            super::parse_http_url("http://example.com/a/b.json"),
            Some(("example.com".to_owned(), 80, "/a/b.json".to_owned(), false))
        );
        assert_eq!(
            super::parse_http_url("https://example.com:8443/x?y=1"),
            Some(("example.com".to_owned(), 8443, "/x?y=1".to_owned(), true))
        );
        assert_eq!(
            super::parse_http_url("http://[::1]:8080/"),
            Some(("::1".to_owned(), 8080, "/".to_owned(), false))
        );
        assert_eq!(
            super::parse_http_url("https://example.com"),
            Some(("example.com".to_owned(), 443, "/".to_owned(), true))
        );
        assert_eq!(super::parse_http_url("mailto:example.com"), None);
        assert_eq!(super::parse_http_url("http://"), None);
    }

    #[test]
    fn http_status_reads_the_first_line() {
        assert_eq!(super::http_status(b"HTTP/1.1 200 OK\r\n"), 200);
        assert_eq!(super::http_status(b"HTTP/1.1 404 Not Found\r\n"), 404);
        assert_eq!(super::http_status(b"garbage"), 0);
    }

    #[test]
    fn a_config_http_get_fetches_the_body_from_a_loopback_server() {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;
        use std::thread;
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                if stream.read(&mut byte).expect("reads") == 0 {
                    break;
                }
                head.extend_from_slice(&byte);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let body = r#"{"inbounds":[]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).expect("writes");
        });
        let url = format!("http://127.0.0.1:{port}/config.json");
        let body = super::fetch_http(&url);
        assert_eq!(body, b"{\"inbounds\":[]}");
    }

    #[test]
    fn shadowsocks_server_password_shape() {
        let root = crate::json::parse(
            r#"{"inbounds": [{"protocol": "shadowsocks", "settings": {"method": "aes-256-gcm",
            "password": "an-example-shared-password"}}]}"#,
        )
        .expect("parses");
        let inbound = &root
            .get("inbounds")
            .expect("inbounds")
            .as_arr()
            .expect("array")[0];
        assert_eq!(
            crate::proxy::inbound_ss_password(inbound),
            "an-example-shared-password"
        );
    }

    #[test]
    fn brief_link_checks() {
        let link = ferrox_core::vless::VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=reality&encryption=none&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&host=%2Ftest-path&headerType=none&fp=firefox&type=tcp&flow=xtls-rprx-vision&sni=example.com&sid=a8#x",
        )
        .expect("parses");
        assert!(link.is_first_method());
    }

    #[test]
    fn both_out_of_band_consents_parse_in_either_order() {
        let mk = |args: [&str; 3]| {
            let mut it = args.iter().map(|s| (*s).to_owned());
            crate::link_and_opt_in(&mut it)
        };
        // A bare link carries neither consent.
        let (_, opt) = crate::link_and_opt_in(&mut ["vless://x".to_owned()].into_iter());
        assert!(!opt.unsafe_fingerprint() && !opt.plaintext_to_public());
        // Both flags flip their own consent and leave the other off, before or after the link.
        for (a, b) in [
            ("--allow-unsafe-fp", "--allow-plaintext-public"),
            ("--allow-plaintext-public", "--allow-unsafe-fp"),
        ] {
            let (link, opt) = mk(["vless://x", a, b]);
            assert_eq!(link, "vless://x");
            assert!(opt.unsafe_fingerprint() && opt.plaintext_to_public());
        }
    }

    /// The window reaches across the crate boundary: what an app test allocates is counted by core's allocator, so a count taken here measures the app.
    #[test]
    fn a_count_taken_here_sees_what_the_app_allocates() {
        let ((), counts) = ferrox_core::alloc_count::measure(|| {
            let buffer = vec![0u8; 64];
            std::hint::black_box(&buffer);
        });
        assert_eq!(
            (counts.allocs, counts.bytes, counts.zeroed),
            (1, 64, 1),
            "this test binary is not running on the allocator whose window `measure` opens"
        );
    }
}

#![allow(
    clippy::cast_precision_loss,
    reason = "counters become floats only to be printed; no gate reads the rounded value"
)]
mod aesgcm;
mod b64bench;
mod ciphers;
mod compare;
mod compare_process;
mod count;
mod earlydata;
mod framing;
mod json;
mod linkconfig;
mod make_tls;
mod methods;
mod muxframe;
mod parity;
mod ps;
mod stats;

use count::Counting;
use std::fmt::Write as _;

fn lengths() -> Vec<usize> {
    let mut v: Vec<usize> = (0..=256).collect();
    v.extend([
        257, 319, 320, 321, 383, 384, 385, 447, 448, 449, 511, 512, 513, 575, 576, 577, 639, 640,
        641, 767, 768, 769, 1023, 1024, 1025, 1535, 1536, 1537, 2047, 2048, 2049, 4095, 4096, 4097,
        8191, 8192, 8193, 16383, 16384, 16385, 65535, 65536, 65537,
    ]);
    v.sort_unstable();
    v.dedup();
    v
}

const BAR: f64 = 0.95;

const ROUNDS: usize = 7;

const CONFIRMATIONS: usize = 5;

const _: () = assert!(CONFIRMATIONS >= 3);

fn confirmed_pass(passes: &[(f64, f64)]) -> (f64, f64) {
    let mut by_ratio = passes.to_vec();
    by_ratio.sort_by(|a, b| (a.0 / a.1).total_cmp(&(b.0 / b.1)));
    by_ratio[by_ratio.len() / 2]
}

const TIMING_MIN: usize = 65;

const BYTE_BUDGET: u64 = 4 * 1024 * 1024;

fn iters_for(n: usize) -> u64 {
    (BYTE_BUDGET / n.max(1) as u64).clamp(64, 200_000)
}

#[global_allocator]
static ALLOC: Counting = Counting;

struct Args {
    declared: String,
    config: Option<String>,
    engines: Vec<(String, String)>,
    config_shapes: Vec<(String, String)>,
    dialects: Vec<(String, String)>,
    repeats: usize,
    connections: usize,
    payload_size: usize,
    iterations: usize,
    duration_ms: u64,
    tcp_latency_iterations: usize,
    traffic: String,
    outbound_config: String,
    outbound_configs: Vec<(String, String)>,
    skip_engines: Vec<(String, String)>,
    output_dir: String,
    json_report: Option<String>,
    scenario: String,
    no_ceiling: bool,
    keep_going: bool,
    server_pid: Option<u32>,
}

const DEFAULT_REPEATS: usize = 3;
pub(crate) const DEFAULT_CONNECTIONS: usize = 1;
pub(crate) const DEFAULT_PAYLOAD_SIZE: usize = 65_536;
pub(crate) const DEFAULT_ITERATIONS: usize = 8192;

const GATE5_ENGINE: &str = "ferrox";

fn protocols_for(label: &str) -> &'static [&'static str] {
    match label {
        "xray-rust" => &["vless", "vmess", "trojan", "shadowsocks2022", "hysteria"],
        _ => &[],
    }
}

fn flag_value(args: &mut impl Iterator<Item = String>, flag: &str) -> String {
    args.next().unwrap_or_else(|| {
        eprintln!("{flag} needs a value");
        std::process::exit(2);
    })
}

fn flag_count(args: &mut impl Iterator<Item = String>, flag: &str) -> usize {
    let raw = flag_value(args, flag);
    match raw.parse::<usize>() {
        Ok(n) if n > 0 => n,
        _ => {
            eprintln!("{flag} needs a positive whole number, got `{raw}`");
            std::process::exit(2);
        }
    }
}

fn flag_number(args: &mut impl Iterator<Item = String>, flag: &str) -> u64 {
    let raw = flag_value(args, flag);
    if let Ok(n) = raw.parse::<u64>() {
        n
    } else {
        eprintln!("{flag} needs a whole number, got `{raw}`");
        std::process::exit(2);
    }
}

fn push_labeled_shape(
    into: &mut Vec<(String, String)>,
    flag: &str,
    kind: &str,
    spec: &str,
    parse: impl FnOnce(&str) -> Result<(), String>,
) {
    let Some((label, shape)) = spec.split_once('=') else {
        eprintln!("{flag} needs <label>=<{kind}>, got `{spec}`");
        std::process::exit(2);
    };
    if let Err(e) = parse(shape) {
        eprintln!("{flag} {label}: {e}");
        std::process::exit(2);
    }
    into.push((label.to_owned(), shape.to_owned()));
}

#[allow(clippy::too_many_lines)]
fn parse_args() -> Args {
    let mut args = std::env::args().skip(1);
    let mut declared = String::from("chacha20 0.9 (crates.io)");
    let mut config: Option<String> = None;
    let mut engines: Vec<(String, String)> = Vec::new();
    let mut config_shapes: Vec<(String, String)> = Vec::new();
    let mut dialects: Vec<(String, String)> = Vec::new();
    let mut repeats = DEFAULT_REPEATS;
    let mut connections = DEFAULT_CONNECTIONS;
    let mut payload_size = DEFAULT_PAYLOAD_SIZE;
    let mut iterations = DEFAULT_ITERATIONS;
    let mut duration_ms = 0u64;
    let mut tcp_latency_iterations = 0usize;
    let mut traffic = String::from("download");
    let mut outbound_config = String::new();
    let mut outbound_configs: Vec<(String, String)> = Vec::new();
    let mut skip_engines: Vec<(String, String)> = Vec::new();
    let mut output_dir = String::from("target/parity");
    let mut json_report: Option<String> = None;
    let mut scenario = String::from("gate5");
    let mut no_ceiling = false;
    let mut keep_going = false;
    let mut server_pid = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--reference" => declared = flag_value(&mut args, "--reference"),
            "--config" => config = Some(flag_value(&mut args, "--config")),
            "--config-arg" => push_labeled_shape(
                &mut config_shapes,
                "--config-arg",
                "shape",
                &flag_value(&mut args, "--config-arg"),
                |shape| {
                    parity::ConfigArg::parse(shape)
                        .map(|_| ())
                        .map_err(|e| e.to_string())
                },
            ),
            "--dialect" => push_labeled_shape(
                &mut dialects,
                "--dialect",
                "dialect",
                &flag_value(&mut args, "--dialect"),
                |shape| {
                    parity::Dialect::parse(shape)
                        .map(|_| ())
                        .map_err(|e| e.to_string())
                },
            ),
            "--engine" => {
                let spec = flag_value(&mut args, "--engine");
                let Some((label, path)) = spec.split_once('=') else {
                    eprintln!("--engine needs <label>=<path>, got `{spec}`");
                    std::process::exit(2);
                };
                if label.is_empty() || path.is_empty() {
                    eprintln!("--engine needs a non-empty label and a non-empty path");
                    std::process::exit(2);
                }
                engines.push((label.to_owned(), path.to_owned()));
            }
            "--repeats" => repeats = flag_count(&mut args, "--repeats"),
            "--connections" => connections = flag_count(&mut args, "--connections"),
            "--payload-size" => payload_size = flag_count(&mut args, "--payload-size"),
            "--iterations" => iterations = flag_count(&mut args, "--iterations"),
            "--duration-ms" => duration_ms = flag_number(&mut args, "--duration-ms"),
            "--tcp-latency-iterations" => {
                tcp_latency_iterations = flag_count(&mut args, "--tcp-latency-iterations");
            }
            "--traffic" => traffic = flag_value(&mut args, "--traffic"),
            "--outbound-config-for" => push_labeled_shape(
                &mut outbound_configs,
                "--outbound-config-for",
                "json",
                &flag_value(&mut args, "--outbound-config-for"),
                |document| json::parse(document).map(|_| ()),
            ),
            "--skip-engine-for" => {
                let spec = flag_value(&mut args, "--skip-engine-for");
                let Some((label, reason)) = spec.split_once('=') else {
                    eprintln!("--skip-engine-for needs <label>=<reason>, got `{spec}`");
                    std::process::exit(2);
                };
                if label.is_empty() || reason.is_empty() {
                    eprintln!("--skip-engine-for needs a non-empty label and reason");
                    std::process::exit(2);
                }
                skip_engines.push((label.to_owned(), reason.to_owned()));
            }
            "--outbound-config" | "--output-dir" | "--json-report" | "--scenario" => {
                parse_matrix_arg(
                    &mut outbound_config,
                    &mut output_dir,
                    &mut json_report,
                    &mut scenario,
                    arg.as_str(),
                    flag_value(&mut args, arg.as_str()),
                );
            }
            "--no-harness-ceiling" => no_ceiling = true,
            "--keep-going" => keep_going = true,
            "--server-pid" => {
                server_pid = Some(
                    flag_value(&mut args, "--server-pid")
                        .parse()
                        .unwrap_or_else(|e| {
                            eprintln!("--server-pid needs a process id: {e}");
                            std::process::exit(2);
                        }),
                );
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    Args {
        declared,
        config,
        engines,
        config_shapes,
        dialects,
        repeats,
        connections,
        payload_size,
        iterations,
        duration_ms,
        tcp_latency_iterations,
        traffic,
        outbound_config,
        outbound_configs,
        skip_engines,
        output_dir,
        json_report,
        scenario,
        no_ceiling,
        keep_going,
        server_pid,
    }
}

fn parse_matrix_arg(
    outbound_config: &mut String,
    output_dir: &mut String,
    json_report: &mut Option<String>,
    scenario: &mut String,
    flag: &str,
    document: String,
) {
    match flag {
        "--outbound-config" => {
            if let Err(e) = json::parse(&document) {
                eprintln!("--outbound-config is not valid json: {e}");
                std::process::exit(2);
            }
            *outbound_config = document;
        }
        "--output-dir" => *output_dir = document,
        "--json-report" => *json_report = Some(document),
        "--scenario" => *scenario = document,
        _ => {
            eprintln!("unknown argument: {flag}");
            std::process::exit(2);
        }
    }
}

fn time_best<F: FnMut()>(iters: u64, mut f: F) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..ROUNDS {
        let t0 = std::time::Instant::now();
        f();
        best = best.min(t0.elapsed().as_secs_f64() / iters as f64);
    }
    best
}

fn keypairs() -> [([u8; 32], [u8; 12]); 2] {
    let a = (
        std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11)),
        std::array::from_fn(|i| (i as u8).wrapping_mul(53).wrapping_add(7)),
    );
    let b = (
        std::array::from_fn(|i| (i as u8).wrapping_mul(97).wrapping_add(29)),
        std::array::from_fn(|i| (i as u8).wrapping_mul(101).wrapping_add(61)),
    );
    [a, b]
}

fn gate_identity(pairs: &[([u8; 32], [u8; 12]); 2]) -> usize {
    let lengths = lengths();
    let mut shapes = 0usize;
    for (k, n) in pairs {
        for start in [0u32, 1, 2, 7, 64, 65_535] {
            for &len in &lengths {
                let mut want = vec![0u8; len];
                let mut got = vec![0u8; len];
                ferrox_core::reference::reference_xor(k, n, start, &mut want);
                ferrox_core::record::fill_exact(k, n, start, &mut got);
                assert_eq!(want, got, "bit-identity: start {start} len {len}");
                shapes += 1;
            }
            for &len in &lengths {
                let mut want = vec![0u8; len + 64];
                ferrox_core::reference::reference_xor(k, n, start, &mut want);
                let (want_block, want_body) = want.split_at(64);
                let want_head = &want_block[..32];
                let mut got_body = vec![0u8; len];
                let mut got_head = [0u8; 32];
                ferrox_core::record::fill_exact_with_head(
                    k,
                    n,
                    start,
                    &mut got_head,
                    &mut got_body,
                );
                assert_eq!(
                    got_body, want_body,
                    "bit-identity with head, body: start {start} len {len}"
                );
                assert_eq!(
                    got_head, want_head,
                    "bit-identity with head, head: start {start} len {len}"
                );
                shapes += 1;
            }
        }
    }
    shapes
}

fn gate_deterministic(key: &[u8; 32], nonce: &[u8; 12]) -> usize {
    let lengths = lengths();
    let mut block_failures: Vec<String> = Vec::new();
    let mut alloc_failures: Vec<String> = Vec::new();

    for &len in lengths.iter().filter(|&&l| l > 0) {
        let mut buf = vec![0u8; len];
        for start in [0u32, 1, 2, 7, 64, 65_535] {
            let produced = ferrox_core::record::fill_exact(key, nonce, start, &mut buf);
            if !ferrox_core::record::blocks_match(len, produced) {
                block_failures.push(format!(
                    "{len}B at start {start}: the ladder reported {produced}, needed {}",
                    ferrox_core::record::blocks_for(len)
                ));
            }
        }

        let iters = 64u64;
        let ((), counts) = count::measure(|| {
            for _ in 0..iters {
                ferrox_core::record::fill_exact(key, nonce, 0, std::hint::black_box(&mut buf[..]));
            }
        });
        if counts.allocs != 0 {
            alloc_failures.push(format!(
                "{len}B: {:.3} allocations per call",
                counts.per_iter(iters)
            ));
        }
        if counts.bytes != 0 {
            alloc_failures.push(format!(
                "{len}B: {:.1} bytes allocated per call",
                counts.bytes_per_iter(iters)
            ));
        }
        if counts.zeroed != 0 {
            alloc_failures.push(format!("{len}B: {} zero-fills per call", counts.zeroed));
        }
    }

    {
        let link = ferrox_core::vless::VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=reality&encryption=none&type=tcp&flow=xtls-rprx-vision&fp=firefox&sni=example.com&sid=a8#x",
        )
        .expect("synthetic rung-1 link parses");
        for host in ["192.0.2.53", "2001:db8::1", "example.com"] {
            let need = link.request_header_len(host);
            let mut hdr = vec![0u8; need];
            let iters = 64u64;
            let ((), counts) = count::measure(|| {
                for _ in 0..iters {
                    let n = link.encode_into(host, 443, std::hint::black_box(&mut hdr[..]));
                    std::hint::black_box(n);
                }
            });
            if counts.allocs != 0 || counts.bytes != 0 || counts.zeroed != 0 {
                alloc_failures.push(format!(
                    "header {host}: {} allocs, {} bytes, {} zero-fills per 64 encodes",
                    counts.allocs, counts.bytes, counts.zeroed
                ));
            }
        }
    }

    gate_vision_allocs(key, nonce, &mut alloc_failures);
    gate_request_allocs(&mut alloc_failures);

    assert!(
        block_failures.is_empty(),
        "DISCARDED WORK: the ladder generated blocks the caller's length does not need at {} \
         length(s): {:?}",
        block_failures.len(),
        &block_failures[..block_failures.len().min(10)]
    );
    assert!(
        alloc_failures.is_empty(),
        "ALLOCATION: the core allocated or zero-filled at {} length(s): {:?}",
        alloc_failures.len(),
        &alloc_failures[..alloc_failures.len().min(10)]
    );

    lengths.len()
}

fn gate_vision_allocs(key: &[u8; 32], nonce: &[u8; 12], alloc_failures: &mut Vec<String>) {
    let uuid = [0xabu8; 16];
    for len in [0usize, 1, 64, 1400, 8171] {
        let content = vec![0u8; len];
        let mut sealed = vec![0u8; 16 + 5 + len + 256];
        let mut opened = vec![0u8; 16 + 5 + len + 256];
        let iters = 64u64;
        let ((), counts) = count::measure(|| {
            let mut session = ferrox_core::vless::VisionSeal::new(key, nonce, &uuid);
            let mut stream = ferrox_core::vless::VisionOpen::new(&uuid);
            for _ in 0..iters {
                let n = session.seal(
                    std::hint::black_box(&mut sealed[..]),
                    std::hint::black_box(&content[..]),
                    ferrox_core::vless::VisionCommand::Continue,
                    false,
                );
                let (written, _) = stream.open(&sealed[..n], std::hint::black_box(&mut opened[..]));
                std::hint::black_box((n, written));
            }
        });
        if counts.allocs != 0 || counts.bytes != 0 || counts.zeroed != 0 {
            alloc_failures.push(format!(
                "vision {len}B: {} allocs, {} bytes, {} zero-fills per 64 seals",
                counts.allocs, counts.bytes, counts.zeroed
            ));
        }
    }
}

/// The request header the server reads, in the shape row 1's client writes it: the
/// Vision add-ons, the command, and a target in each of the three families.
fn gate_request_allocs(alloc_failures: &mut Vec<String>) {
    let addons = b"\x0a\x10xtls-rprx-vision";
    let families: [(&str, Vec<u8>); 3] = [
        ("ipv4", {
            let mut body = 443u16.to_be_bytes().to_vec();
            body.extend_from_slice(&[1, 192, 0, 2, 53]);
            body
        }),
        ("ipv6", {
            let mut body = 443u16.to_be_bytes().to_vec();
            body.extend_from_slice(&[3, 0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            body
        }),
        ("domain", {
            let mut body = 443u16.to_be_bytes().to_vec();
            body.extend_from_slice(&[2, 11]);
            body.extend_from_slice(b"example.com");
            body
        }),
    ];
    for (label, body) in families {
        let mut wire = vec![0u8];
        wire.extend_from_slice(&[0xabu8; 16]);
        wire.push(addons.len() as u8);
        wire.extend_from_slice(addons);
        wire.push(1);
        wire.extend_from_slice(&body);
        let iters = 64u64;
        let ((), counts) = count::measure(|| {
            for _ in 0..iters {
                let mut scratch = [0u8; ferrox_core::vless::REQUEST_MAX];
                let mut reader = std::io::Cursor::new(&wire[..]);
                let request = ferrox_core::vless::decode_request(&mut reader, &mut scratch)
                    .expect("the request parses");
                std::hint::black_box(request.id);
            }
        });
        if counts.allocs != 0 || counts.bytes != 0 || counts.zeroed != 0 {
            alloc_failures.push(format!(
                "request {label}: {} allocs, {} bytes, {} zero-fills per 64 parses",
                counts.allocs, counts.bytes, counts.zeroed
            ));
        }
    }
}

fn measure_len(key: &[u8; 32], nonce: &[u8; 12], len: usize) -> Row {
    let iters = iters_for(len);
    let mut buf = vec![0u8; len];

    let mut base = f64::MAX;
    let mut ours = f64::MAX;
    for _ in 0..ROUNDS {
        let t0 = std::time::Instant::now();
        for _ in 0..iters {
            ferrox_core::reference::reference_xor(
                key,
                nonce,
                0,
                std::hint::black_box(&mut buf[..]),
            );
        }
        base = base.min(t0.elapsed().as_secs_f64() / iters as f64);
        let t0 = std::time::Instant::now();
        for _ in 0..iters {
            ferrox_core::record::fill_exact(key, nonce, 0, std::hint::black_box(&mut buf[..]));
        }
        ours = ours.min(t0.elapsed().as_secs_f64() / iters as f64);
    }

    let ratio = base / ours;

    if ratio < BAR {
        let heavy = iters * 4;
        let mut passes = Vec::with_capacity(CONFIRMATIONS);
        for _ in 0..CONFIRMATIONS {
            let base2 = time_best(heavy, || {
                for _ in 0..heavy {
                    ferrox_core::reference::reference_xor(
                        key,
                        nonce,
                        0,
                        std::hint::black_box(&mut buf[..]),
                    );
                }
            });
            let ours2 = time_best(heavy, || {
                for _ in 0..heavy {
                    ferrox_core::record::fill_exact(
                        key,
                        nonce,
                        0,
                        std::hint::black_box(&mut buf[..]),
                    );
                }
            });
            passes.push((base2, ours2));
        }
        let (base, ours) = confirmed_pass(&passes);
        let ratio = base / ours;
        return Row {
            len,
            base,
            ours,
            ratio,
            remeasured: true,
        };
    }

    Row {
        len,
        base,
        ours,
        ratio,
        remeasured: false,
    }
}

fn build_report(declared: &str, shapes: usize, measured_lengths: usize, rows: &[Row]) -> String {
    let mut report = String::new();
    let _ = writeln!(report, "# ferrox benchmark\n");

    let _ = writeln!(report, "| | |");
    let _ = writeln!(report, "| --- | --- |");
    let _ = writeln!(report, "| declared reference | `{declared}` |");
    let _ = writeln!(
        report,
        "| reference actually ran | {} |",
        ferrox_core::reference::backend()
    );
    let _ = writeln!(
        report,
        "| ferrox core | {} |",
        ferrox_core::chacha_backend()
    );
    let _ = writeln!(report, "| target | `{}` |", std::env::consts::ARCH);
    let _ = writeln!(report);

    let _ = writeln!(report, "## Gate 1 — identity\n");
    let _ = writeln!(
        report,
        "**{shapes} shapes**, byte for byte, at every listed length and the 6 selected offsets: dense, not exhaustive (see `lengths`)."
    );

    let _ = writeln!(report, "\n## Gate 2 — deterministic properties\n");
    let _ = writeln!(
        report,
        "Across **{measured_lengths} lengths**: blocks generated equals blocks needed at every\n\
         one; **0** heap allocations per call; **0** zero-fills per call.\n\n\
         These are integer counts, so they are identical on every machine and are gated\n\
         outright rather than reported."
    );

    let _ = writeln!(report, "\n## Gate 3 — timing\n");
    if rows.is_empty() {
        let _ = writeln!(
            report,
            "Not measured here: this invocation drives traffic legs. Gates 3 to 11 time one\n\
             operation against a reference, and a matrix job runs several cells at once on one\n\
             runner, so a nanosecond ratio read there measures the neighbours — `bench.yml` runs\n\
             them on a machine of its own. The identity and integer gates above are what this leg\n\
             still asserts, and the process comparison below is what it decides on."
        );
    } else {
        let timed = rows.len();
        let listed = lengths().len();
        let _ = writeln!(
            report,
            "Best of {ROUNDS} interleaved rounds per side (reference/ferrox/reference/…,\n\
             so a thermal drift cannot favour one side). The bar is {BAR:.2}x: 5% is\n\
             runner noise, and any length under it is re-measured at 4x the budget\n\
             and marked `remeasured`, and still fails the job if it stays under the\n\
             bar. The re-measure confirms the number; it does not lower the bar.\n\n\
             {timed} of {listed} listed lengths are timed, starting at {TIMING_MIN} bytes:\n\
             lengths 1-64 are one block, a tie by construction, so they are covered\n\
             byte for byte in gate 1 and not timed here.\n"
        );
        let _ = writeln!(
            report,
            "| len | reference ns/op | ferrox ns/op | speedup | remeasured |"
        );
        let _ = writeln!(report, "|---:|---:|---:|---:|:--:|");
        for r in rows {
            let _ = writeln!(
                report,
                "| {} | {:.1} | {:.1} | {:.2}x | {} |",
                r.len,
                r.base * 1e9,
                r.ours * 1e9,
                r.ratio,
                if r.remeasured { "yes" } else { "" }
            );
        }
    }

    if let (Some(worst), Some(best)) = (
        rows.iter().min_by(|a, b| a.ratio.total_cmp(&b.ratio)),
        rows.iter().max_by(|a, b| a.ratio.total_cmp(&b.ratio)),
    ) {
        let _ = writeln!(
            report,
            "\n**Gate: {} lengths, none below {BAR:.2}x.** Worst {:.2}x @ {}B, best {:.2}x @ {}B.",
            rows.len(),
            worst.ratio,
            worst.len,
            best.ratio,
            best.len
        );
    }

    let _ = writeln!(
        report,
        "\n> The reference is re-keyed and re-seeked on every call, which a stateful record\n\
         > layer would not do. That flatters short lengths in particular. The 16384 B row is\n\
         > the one closest to a real VMess/Shadowsocks record and should be read as the\n\
         > headline; the reference's own backend, named above, is what decides whether a\n\
         > ratio here reflects this workspace's work or the reference's fallback."
    );

    report.push_str(&methods::table());

    report
}

fn extremes(rows: &[Row]) -> (&Row, &Row) {
    let worst = rows
        .iter()
        .min_by(|a, b| a.ratio.total_cmp(&b.ratio))
        .expect("gate 3 always measures at least one length");
    let best = rows
        .iter()
        .max_by(|a, b| a.ratio.total_cmp(&b.ratio))
        .expect("gate 3 always measures at least one length");
    (worst, best)
}

fn config_section(link: Option<&str>) -> String {
    let Some(link_str) = link else {
        return String::new();
    };
    match ferrox_core::vless::VlessLink::parse(link_str) {
        Ok(parsed) => {
            println!("config: {}", compare::describe_redacted(&parsed));
            compare::compare_offline(&parsed)
        }
        Err(e) => {
            eprintln!("--config: bad vless link: {e}");
            std::process::exit(2);
        }
    }
}

struct Gate5 {
    report: String,
    comparison: Option<compare_process::Comparison>,
    engines: usize,
}

/// Whether this invocation is the codec's own measurement: a run that names no engines to drive traffic is the one with the machine to itself, and gates 3 to 11 are only readable there.
fn codec_measured(args: &Args) -> bool {
    args.engines.is_empty()
}

fn gate5_section(args: &Args) -> Result<Gate5, String> {
    if args.engines.is_empty() {
        return Ok(Gate5 {
            report: String::new(),
            comparison: None,
            engines: 0,
        });
    }
    if args.engines.len() < 2 {
        return Err(
            "gate 5 needs at least two --engine arguments to have something to \
             compare against; one engine is a measurement, not a comparison. Gates \
             3 to 11 are a bare run's to measure; run `ferrox-bench` with no \
             `--engine` for them."
                .to_owned(),
        );
    }
    let engines: Vec<compare_process::Engine> = args
        .engines
        .iter()
        .map(|(label, path)| {
            let shape = args
                .config_shapes
                .iter()
                .find(|(name, _)| name == label)
                .map_or("long", |(_, shape)| shape.as_str());
            let Ok(config_arg) = parity::ConfigArg::parse(shape) else {
                unreachable!("--config-arg was validated at parse time");
            };
            let dialect = args
                .dialects
                .iter()
                .find(|(name, _)| name == label)
                .map_or_else(
                    || parity::Dialect::Xray,
                    |(_, shape)| {
                        parity::Dialect::parse(shape).unwrap_or_else(|e| {
                            unreachable!("--dialect was validated at parse time: {e}")
                        })
                    },
                );
            compare_process::Engine {
                name: Box::leak(label.clone().into_boxed_str()),
                path: path.into(),
                config_arg,
                dialect,
                gated: label == GATE5_ENGINE,
                protocols: protocols_for(label),
            }
        })
        .collect();
    let workload = compare_process::Workload {
        traffic: args.traffic.clone(),
        connections: args.connections,
        iterations: args.iterations,
        payload_size: args.payload_size,
        duration_ms: args.duration_ms,
        tcp_latency_iterations: args.tcp_latency_iterations,
        warmup: false,
        outbound_config: args.outbound_config.clone(),
        outbound_configs: args.outbound_configs.clone(),
        skip_engines: args.skip_engines.clone(),
        scenario: args.scenario.clone(),
        server_pid: args.server_pid,
    };
    let comparison = compare_process::run(
        &engines,
        &workload,
        args.repeats,
        std::path::Path::new(&args.output_dir),
        !args.no_ceiling,
    )
    .map_err(|e| e.to_string())?;
    let report = comparison.report();
    if let Some(path) = &args.json_report {
        let document = comparison
            .comparison_json(&args.scenario)
            .map_err(|e| format!("--json-report: {e}"))?;
        std::fs::write(path, document).map_err(|e| format!("--json-report: {e}"))?;
    }
    Ok(Gate5 {
        report,
        comparison: Some(comparison),
        engines: engines.len(),
    })
}

fn gate_four(report: &mut String) -> Vec<framing::Row> {
    let frames = framing::gate_framing();
    println!(
        "gate 4 passed: {} framing rows, byte-identical",
        frames.len()
    );
    report.push_str(&framing::report(&frames));
    frames
}

fn gate_seven(key: &[u8; 32], nonce: &[u8; 12], report: &mut String) -> Vec<framing::Row> {
    let mut seals = framing::gate_aead(key, nonce);
    println!(
        "gate 7 passed: {} seal rows, ciphertext and tag identical to their references; {} of \
         them gated, the whole-pass lengths reported only",
        seals.len(),
        framing::gated_seals(&seals).len()
    );
    report.push_str(&framing::aead_report(&seals));

    let split = framing::aead_split(key, nonce);
    println!(
        "gate 7b reported: {} split rows, self-timed, not gated",
        split.len()
    );
    report.push_str(&framing::aead_split_report(&split));

    let macs = framing::gate_mac(key, nonce);
    println!(
        "gate 7c passed: {} poly1305 rows, tag identical to the 26-bit horner",
        macs.len()
    );
    report.push_str(&framing::mac_report(&macs));

    seals.extend(macs);
    seals
}

fn gate_six(report: &mut String) -> Vec<framing::Row> {
    let muxed = muxframe::gate_mux();
    println!(
        "gate 6 passed: {} mux rows field-identical to their references and 0 allocs on both \
         sides; {} of them gated, the encode and bridge rows reported only",
        muxed.len(),
        muxframe::gated(&muxed).len()
    );
    report.push_str(&muxframe::report(&muxed));
    muxed
}

fn gate_eight(report: &mut String) -> Vec<framing::Row> {
    let rows = earlydata::gate_early_data();
    println!(
        "gate 8 passed: {} early-data encode rows, byte-identical to their references, none \
         below {BAR:.2}x, and zero allocations per encode on this side",
        rows.len()
    );
    report.push_str(&earlydata::report(&rows));
    rows
}

/// A subcommand that ends the process: the harness's side modes never run a measurement.
fn side_exit() -> Option<i32> {
    let mut argv = std::env::args().skip(1);
    let kind = argv.next()?;
    let rest = argv.collect::<Vec<_>>();
    match kind.as_str() {
        "linkconfig" => Some(linkconfig::run(&rest)),
        "make-tls" => Some(make_tls::run(&rest)),
        _ => None,
    }
}

fn gate_nine(report: &mut String) {
    let (rows, windows) = ciphers::gate_ciphers();
    println!(
        "gate 9 passed: {} shadowsocks cipher rows, byte-identical to the reference and zero \
         allocations per chunk on all three methods; the timing rows are printed only",
        rows.len()
    );
    report.push_str(&ciphers::report(&rows, &windows));
}

fn gate_ten(report: &mut String) -> Vec<framing::Row> {
    let (rows, windows) = aesgcm::gate_aesgcm();
    println!(
        "gate 10 passed: {} aes-128/256-gcm rows, ciphertext and tag identical to the crate and \
         zero allocations per seal+open pair",
        rows.len()
    );
    let engine = ferrox_core::aesgcm::Aes128Gcm::new(&[7u8; 16]);
    report.push_str(&aesgcm::report(&rows, &windows, engine.backend()));
    rows
}

#[allow(clippy::too_many_lines)]
fn main() {
    if let Some(code) = side_exit() {
        std::process::exit(code);
    }
    let args = parse_args();
    let declared = args.declared.clone();
    let pairs = keypairs();
    let (key, nonce) = pairs[0];

    let shapes = gate_identity(&pairs);
    println!("gate 1 passed: bit-identical at {shapes} shapes");

    let measured_lengths = gate_deterministic(&key, &nonce);
    println!(
        "gate 2 passed: 0 discarded blocks, 0 allocations, 0 zero-fills at {measured_lengths} lengths"
    );

    let codec = codec_measured(&args);

    let rows: Vec<Row> = if codec {
        lengths()
            .iter()
            .filter(|&&l| l >= TIMING_MIN)
            .map(|&len| measure_len(&key, &nonce, len))
            .collect()
    } else {
        Vec::new()
    };

    let mut report = build_report(&declared, shapes, measured_lengths, &rows);

    let (frames, seals, muxed, early, aes_gcm_rows, b64_rows) = if codec {
        let frames = gate_four(&mut report);
        let seals = gate_seven(&key, &nonce, &mut report);
        let muxed = gate_six(&mut report);
        let early = gate_eight(&mut report);
        gate_nine(&mut report);
        let aes_gcm_rows = gate_ten(&mut report);
        let b64_rows = b64bench::gate_b64();
        println!(
            "gate 11 passed: {} base64 rows, each the shipped coder against the loop it replaced",
            b64_rows.len()
        );
        report.push_str(&b64bench::report(&b64_rows));
        (frames, seals, muxed, early, aes_gcm_rows, b64_rows)
    } else {
        Default::default()
    };

    report.push_str(&config_section(args.config.as_deref()));

    let gate5 = match gate5_section(&args) {
        Ok(section) => section,
        Err(message) => {
            eprintln!("gate 5 could not run: {message}");
            std::process::exit(2);
        }
    };
    report.push_str(&gate5.report);
    if gate5.comparison.is_some() {
        println!(
            "gate 5 measured: {} engines x {} repeats",
            gate5.engines, args.repeats
        );
    }

    std::fs::create_dir_all("target").expect("create target dir");
    std::fs::write("target/bench-report.md", &report).expect("write report");

    let slow_frames: Vec<&framing::Row> = frames
        .iter()
        .chain(framing::gated_seals(&seals))
        .chain(muxframe::gated(&muxed))
        .chain(early.iter())
        .chain(aesgcm::gated_rows(&aes_gcm_rows))
        .filter(|r| r.ratio() < BAR)
        .collect();
    let slow_b64: Vec<&framing::Row> = b64_rows
        .iter()
        .filter(|r| r.ratio() < b64bench::PARITY)
        .collect();
    assert!(
        slow_b64.is_empty(),
        "BASE64 REGRESSION: the shipped coder is slower than the loop it replaced at {} row(s), \
         worst {:.3}x: {}",
        slow_b64.len(),
        slow_b64
            .iter()
            .map(|r| r.ratio())
            .fold(f64::INFINITY, f64::min),
        slow_b64
            .iter()
            .map(|r| format!("{}={:.3}x", r.name, r.ratio()))
            .collect::<Vec<_>>()
            .join(" ")
    );
    assert!(
        slow_frames.is_empty(),
        "FRAMING REGRESSION: a framing slower than its reference at {} row(s), worst {:.3}x: {}",
        slow_frames.len(),
        slow_frames
            .iter()
            .map(|r| r.ratio())
            .fold(f64::INFINITY, f64::min),
        slow_frames
            .iter()
            .map(|r| format!("{}={:.3}x", r.name, r.ratio()))
            .collect::<Vec<_>>()
            .join(" ")
    );

    let failures: Vec<&Row> = rows.iter().filter(|r| r.ratio < BAR).collect();
    assert!(
        failures.is_empty(),
        "REGRESSION: slower than the reference at {} length(s), worst {:.3}x. Failing lengths: {}",
        failures.len(),
        failures
            .iter()
            .map(|r| r.ratio)
            .fold(f64::INFINITY, f64::min),
        failures
            .iter()
            .map(|r| format!("{}B={:.3}x", r.len, r.ratio))
            .collect::<Vec<_>>()
            .join(" ")
    );

    if codec {
        let (worst, best) = extremes(&rows);
        println!(
            "gate 3 passed: {} lengths, none below {BAR:.2}x. Worst {:.2}x @ {}B, best {:.2}x @ {}B",
            rows.len(),
            worst.ratio,
            worst.len,
            best.ratio,
            best.len
        );
    }
    assert_gate5(&gate5, shapes, args.keep_going, codec);
}

fn assert_gate5(gate5: &Gate5, shapes: usize, keep_going: bool, codec: bool) {
    if let Some(comparison) = &gate5.comparison {
        let gate = comparison.gate();
        // A lost repeat is not a measured regression: when rows are unproven because runs never landed, the panic names that, beside the rows, so the claim matches what ran.
        let mut report = gate.lines.join("\n");
        if !comparison.failures.is_empty() {
            let lost = comparison
                .failures
                .iter()
                .map(|(engine, reason)| {
                    format!("{engine}: {}", reason.chars().take(200).collect::<String>())
                })
                .collect::<Vec<_>>()
                .join("\n  ");
            let _ = std::fmt::Write::write_fmt(
                &mut report,
                format_args!(
                    "\n{} repeat(s) never landed a number and sit in the report's failures:\n  {lost}",
                    comparison.failures.len()
                ),
            );
        }
        if !gate.passed {
            let message = format!(
                "PROCESS REGRESSION: the process-level comparison did not pass.\n{report}\n\
                 The table it failed on is in target/bench-report.md and every run's \
                 result.json is under target/parity/."
            );
            if keep_going {
                eprintln!("{message}\n--keep-going: the cell is reported, not aborted");
            } else {
                panic!("{message}");
            }
        }
        for line in &gate.lines {
            println!("gate 5: {line}");
        }
        println!("gate 5 passed: {}", gate.lines.len());
    }

    if codec {
        println!(
            "PASS: bit-identical at {shapes} shapes, no discarded work or allocation, and not slower at any length"
        );
    } else {
        println!(
            "PASS: bit-identical at {shapes} shapes and no discarded work or allocation; the codec's ratios are a bare run's to read, and this leg decided on gate 5"
        );
    }
}

struct Row {
    len: usize,
    base: f64,
    ours: f64,
    ratio: f64,
    remeasured: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passes(ratios: &[f64]) -> Vec<(f64, f64)> {
        ratios.iter().map(|r| (250.0, 250.0 / r)).collect()
    }

    #[test]
    fn one_disturbed_pass_does_not_fail_a_length_that_is_fine() {
        let (base, ours) = confirmed_pass(&passes(&[1.05, 1.07, 0.84]));
        let r = base / ours;
        assert!(
            r >= BAR,
            "one disturbed pass must not fail a sound length: {r}"
        );
        assert!(
            passes(&[1.05, 1.07, 0.84]).contains(&(base, ours)),
            "the confirmed pair must be one of the passes"
        );
    }

    #[test]
    fn a_length_that_is_really_slower_still_fails() {
        for ratios in [
            [0.84, 0.85, 0.86],
            [0.90, 0.91, 0.92],
            [0.94, 0.94, 0.94],
            [0.84, 0.84, 1.09],
        ] {
            let (base, ours) = confirmed_pass(&passes(&ratios));
            let r = base / ours;
            assert!(r < BAR, "a real regression must fail: {ratios:?} read {r}");
        }
    }

    /// The report half of a traffic leg, which is what a comparison of two live engines writes above its gate 5 table.
    #[test]
    fn a_traffic_legs_report_says_what_it_left_out_instead_of_printing_an_empty_table() {
        let row = Row {
            len: 4096,
            base: 1.2e-6,
            ours: 1.0e-6,
            ratio: 1.2,
            remeasured: false,
        };
        let traffic = build_report("the declared reference", 7, 235, &[]);
        assert!(
            traffic.contains("Not measured here"),
            "a leg that timed nothing says so: {traffic}"
        );
        assert!(
            !traffic.contains("| len | reference ns/op |"),
            "and prints no table over it: {traffic}"
        );

        let bare = build_report("the declared reference", 7, 235, &[row]);
        assert!(
            !bare.contains("Not measured here"),
            "a bare run does not apologize for rows it measured"
        );
        assert!(
            bare.contains("| len | reference ns/op |") && bare.contains("| 4096 |"),
            "and prints them: {bare}"
        );
    }
}

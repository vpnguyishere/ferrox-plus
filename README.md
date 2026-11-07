# Ferrox

FERROX — Fast Efficient Relay Router Overlay X. *ferro*, iron, for Rust; *X*, for Xray.

A from-scratch proxy core, **bit-identical to the implementations it replaces** and **verifiably not slower than any of them**.

## Goals

1. **Everything shipped is faster and leaner.** Bit-identical output, fewer operations, zero surviving copies, no allocation; counts prove, durations suggest.
2. **Drop-in replacement for Xray-core.** Run its pinned test suites unmodified against a Ferrox binary in CI, plus every suite with a seam to inject it through.
3. **Drop-in replacement for zeptun** (`tun2socks`): TUN to TCP/UDP/ICMP through a SOCKS5 or direct handler, `userspace`/`hybrid`/`system` stacks.
4. **Feature-complete where quiche, slipstream and aether are ahead** — QUIC/MASQUE, DNS-tunnel carriers, nested tunnels, multi-path schedulers, domain fronting.
5. **Spoof SNI without root.** DPI circumvention by injecting a fake TLS ClientHello with an allowlisted SNI ahead of the real handshake, via `VpnService` TUN plus a userspace TCP stack.

**The drop-in rule:** xray-core is the floor, not the ceiling. Anything a xray config can do must work here — and where xray has one way, we may have two (a cert path resolves against the working directory *and* against the executable's, as `xray-core` does). Ship more, refuse less, and never answer a config xray runs with a failure or a silently different verdict; when behaviour diverges, the fix is to accept both ways, faster and leaner, not to narrow.

**The ratio rule:** a cell is read against the engines in that same cell, never against a local run. Ferrox is never slower than a comparator at the same work, and at least 1.2x faster wherever the cell measures the same thing; a ratio under 1.0 is a defect to root-cause — name the leg that lost, the operation behind it, and the row that gates its removal — not variance to note. Counts prove, durations suggest, and the durations that decide are CI's.

## How it is built

- **One algorithm, four widths.** The record layer is one generic function over a `Lanes` trait — portable, NEON, SSE2, AVX2 — so backends execute the *same source*. The portable path is safe Rust (Miri-interpretable); the SIMD modules stay tiny.
- **Rewrite, not port.** The minimal subset covering the matrix, proven faster down to the parsing. No upstream line enters this tree.
- **Counts prove, durations suggest.** Instruction, allocation, copy and syscall counts are gated exact; each method page names the checker for every number. An unmeasured count is `UNBLESSED`, not a figure.
- **One TLS stack, one interface.** `TlsProvider` is implemented by rustls and *is* `Read + Write`, so nothing above depends on the stack underneath.
- **quiche is the default QUIC.** Any other QUIC backend must name the rung, the library and the measurement that won.
- **The reference is not as fast as it looks.** Comparators often ship SIMD behind a cfg nothing sets; every report prints both backends, and a ratio without both names is not a measurement.
- **Lints and operation counts are local; nothing connection-dependent is.** `./scripts/check.sh` runs before every push; benchmarks, parity, upstream suites and Miri are CI-only.
- **One automatic PR gate.** `ci` is the only workflow a change normally starts; `deps` and `pins` join it only when their own files move. Upstream, conformance, interop, baselines, exact counts and the full benchmark matrix are manual dispatch, and `main` is covered by schedules including the nightly standard matrix.
- **Fixed-worker readiness seam on raw TCP; pooled blocking relay on carrier legs.** Raw flows hand their descriptors to `min(cores, 8)` workers and the accept thread returns. Carrier legs hold a thread per parked leg; see [concurrency](docs/concurrency.md).

## What is checked

| claim | checked by |
| --- | --- |
| compiles | `ci.yml`: `cargo test --workspace` on linux x86_64, macos aarch64, windows x86_64; clippy clean |
| no test stalls unnoticed | `scripts/watch-test.sh` names the test that does not return and prints each thread's wait |
| bit-identical output | differential test against the pinned reference, run before any timing |
| no use-after-free, no leak | Miri weekly (safe paths); differential tests (SIMD) |
| no allocation, no zero-fill | counting global allocator, gated at exactly 0 |
| no work generated and discarded | ladder returns its blocks; gate 2 vs `ceil(len / 64)` |
| no operation added or removed | `scripts/count-ops.sh` against `scripts/expected-ops.txt` |
| not slower at any length ≥ 65 B | benchmark gate; one regressing length fails after a re-measure |
| upstream conformance | pinned suites run unmodified against `ferrox-app` |
| xray-core scenario coverage | `conformance.yml`: every `testing/scenarios` test against the binary |
| parsers never panic on untrusted bytes | seeded cases over every untrusted entry point |
| dependency licence and provenance | `deny.toml` + `scripts/check-dependency-policy.sh`; GPL/AGPL refused as dependencies |
| roadmap coherence | `ferrox-prompt check`: no duplicate id, no gate-less slice, no cycle |
| method pages match one manifest | `scripts/check-method-docs.sh` against `scripts/method-counts.txt` |
| no conflict left half-resolved | `scripts/check-merge-markers.sh` over every tracked file |
| change measured against what it touches | `scripts/check-ci-scope.sh` against each page's scope block — see [`docs/ci-scope.md`](docs/ci-scope.md) |

Not claimed: that this is the fastest implementation. What is built is the machinery that notices when it is not.

```bash
./scripts/check.sh    # fmt, clippy, docs, policy checks, counts, prompt library, tests
```

## Method pages

Every implemented method has a page under [`docs/function/`](docs/function) carrying four counts — **ops**, **syscalls**, **memory copies**, **time** — each naming its checker, a `graph TD` of the data path, and what was removed against Xray-core, sing-box and ZeroNet. Every number is a row in [`scripts/method-counts.txt`](scripts/method-counts.txt); `scripts/check-method-docs.sh` fails if a page and that file disagree in either direction.

```bash
printf '%s %s %s %s\n' '<doc>' '<key>' '<value>' '<checker>' >> scripts/method-counts.txt
./scripts/check-method-docs.sh
```

| method | page | syscalls | copies/byte | ops | time |
| --- | --- | --- | --- | --- | --- |
| record layer (ChaCha20) | [record-layer](docs/function/record-layer.md) | 0 | 0 (in place) | `UNBLESSED` | not measured |
| Shadowsocks AEAD | [shadowsocks](docs/function/shadowsocks.md) | 1 read + 1 write per 64 KiB | **0** | `UNBLESSED` | 1.394× xray-core throughput (CI) |
| Shadowsocks 2022 | [shadowsocks-2022](docs/function/shadowsocks-2022.md) | 1 write per 16 KiB read | 1 written, 0 read | `UNBLESSED` | not measured |
| VMess AEAD | [vmess](docs/function/vmess.md) | 1 write per 128 KiB batch | 1 written, 0 read | `UNBLESSED` | 2.34× xray-core throughput, 1.64× cpu per GiB (CI) |
| VLESS TCP | [vless](docs/function/vless.md) | 1 write per header | 1 (relay's own) | `UNBLESSED` | not measured |
| Trojan TCP | [trojan](docs/function/trojan.md) | 1 write per header | 1 (relay's own) | 1170 | not measured |
| XTLS Vision | [xtls-vision](docs/function/xtls-vision.md) | 0 framing after switch | 2 framed, 0 after | `UNBLESSED` | not measured |
| Mux.Cool + XUDP | [mux-cool](docs/function/mux-cool.md) | 1 write per uplink frame | 0 written, 1 read | `UNBLESSED` | not measured |
| WebSocket | [carrier-websocket](docs/function/carrier-websocket.md) | 1 read per 32 KiB window | 0 unmasked, 1 masked | `UNBLESSED` | not measured |
| HTTPUpgrade | [carrier-httpupgrade](docs/function/carrier-httpupgrade.md) | 1 read, 1 write | 1 (relay's own) | `UNBLESSED` | not measured |
| HTTP masquerade | [carrier-httpheader](docs/function/carrier-httpheader.md) | 1 read, 1 write | 1 (relay's own) | `UNBLESSED` | not measured |
| gRPC | [carrier-grpc](docs/function/carrier-grpc.md) | 1 write per 64 KiB read | 0 written, 1 read | `UNBLESSED` | not measured |
| Commander management API | [engine-api](docs/function/engine-api.md) | not measured | not measured | `UNBLESSED` | not measured |
| xHTTP | [carrier-xhttp](docs/function/carrier-xhttp.md) | 1 write per chunk | 1 written | `UNBLESSED` | not measured |
| QUIC | [carrier-quic](docs/function/carrier-quic.md) | 1 handshake per server | quiche's | `UNBLESSED` | `vless-quic-*` arm (CI) |
| Foxy lane (h1/h2/h3 + CONNECT-UDP) | [carrier-foxy](docs/function/carrier-foxy.md) | 1 write per DATA frame | 0 staged | `UNBLESSED` | not measured |
| VeePN lane (`Basic` CONNECT) | [carrier-veepn](docs/function/carrier-veepn.md) | 1 write per open | 0 staged: pair, request, region list | `UNBLESSED` | not measured (two local coder runs, no cell to reproduce them) |
| Psiphon lane (native SSH/OSSH, SOCKS + HTTP edges, upstream hop) | [carrier-psiphon](docs/function/carrier-psiphon.md) | 1 handshake per tunnel | 0 per flow clone | `UNBLESSED` | native vs console client, live (CI) |
| Hysteria v2 | [carrier-hysteria](docs/function/carrier-hysteria.md) | 1 handshake per pooled outbound | 0 extra on datagram lane | `UNBLESSED` | not measured |
| REALITY / TLS | [reality-tls](docs/function/reality-tls.md) | per handshake | per handshake | `UNBLESSED` | `vless-tls-raw-*` arm (CI) |
| KCP | [kcp](docs/function/kcp.md) | 1 sendto per segment | in place, pooled | `UNBLESSED` | not measured |
| dokodemo-door inbound | [front-dokodemo](docs/function/front-dokodemo.md) | 1 send + 1 recv per datagram; 1 recvmsg + 1 sendto per transparent datagram | 1 (the relay's own) + 1 reply socket per transparent `(client, original)` | `UNBLESSED` | not measured |
| health observatory + `leastPing`/`leastLoad` | [engine-observatory](docs/function/engine-observatory.md) | 1 dial per probe | 0 per sample put | `UNBLESSED` | not measured |
| healthcheck inbound | [front-healthcheck](docs/function/front-healthcheck.md) | 1 answer write | 0 (prebuilt) | `UNBLESSED` | not measured |
| SOCKS5 + SOCKS4, both roles | [socks](docs/function/socks.md) | 2–3 writes + 3–4 reads per dial | 1 (the relay's own) | `UNBLESSED` | not measured |
| Reverse tunnel (bridge + portal) | [reverse](docs/function/reverse.md) | 1 write per mux frame | 1 downlink, 0 uplink | `UNBLESSED` | not measured |

`ops` and `time` are `UNBLESSED`/not measured on every row — the honest state. `scripts/expected-ops.txt` records the exact blessed rows; `scripts/method-ops.txt` is the open list that `ops.yml` measures into the `method-ops` artefact. Every duration comes from a named CI runner (`bench.yml`, `parity.yml`, `compare.yml`, `speedtest.yml`, `benchmark-matrix.yml`); no page quotes a one-off result from a laptop behind a VPN. The per-server grid, its tables and its charts are in [`docs/benchmarks/matrix.md`](docs/benchmarks/matrix.md). A matrix run also publishes `table.md`, `table.csv` and `distribution.csv` in the small `benchmark-matrix-table-*` artifact, so the tables and repeat spread are downloadable without the image bundle; every workflow publishes a `result-*` artifact with the same status facts as the job summary.

## Connection methods

The target is a drop-in replacement for xray-core (same JSON, same share links, every protocol/transport/security it dials or serves), then a superset of sing-box, ZeroNet and LxBox. The rows below are the live matrix; [`docs/method-superset.md`](docs/method-superset.md) is the method-level ledger, gated by `scripts/check-method-superset.sh`.

`planned — high priority` marks a surface xray-core or a pinned reference runs and this tree does not carry yet, so the drop-in rule puts it ahead of a row that only widens the superset. `partial — high priority` marks the same gap inside a row that already carries part of the method. `not-scheduled` is the ledger's state for a reference surface parked behind another row, listed so the absence is not mistaken for coverage. Rows are numbered in reading order, with the audit gaps folded into the tables they belong to.

Each table A row carries two independent verdicts: `link` (what `VlessLink::support()` reports — `Implemented`, `Planned { reason }` or `UnsafeRequiresOptIn { reason }`) and `binary` (what `ferrox-app` actually dials or serves). `Support::Planned` means the roadmap owns the row. A `link` marked `Planned` is a route, not a dead end.

`ferrox-app run <vless://…>` is not a dialler: it refuses unless `Implemented`, opens one TCP connection, times it, sends nothing. Real traffic goes through `run -c config.json` (inbounds `vless`/`trojan`/`vmess`/`shadowsocks`/`socks`/`http`/`mixed` with a `freedom` outbound, or xray's `direct` spelling of it; an outbound this tree has not built (`amneziawg`) dials direct with one warning; xray's `-config=… -format=json|pb` is also accepted). `check <vless://…>` is offline. The `budgets` group restates ten wait bounds the engine arms per flow; unknown names, missing units or zero waits stop startup. Byte-loop cadences stay compile-time constants.

### A — proxy protocols

Rows 1–26 are the proxy-protocol world; rows 27–52 are the xray-core config surface and the audit gaps beside it. Pages carry the evidence.

| # | method | state | notes | supported today by |
| --- | --- | --- | --- | --- |
| 1 | VLESS TCP REALITY `xtls-rprx-vision` | implemented — both roles, raw + all carried carriers | link `vless-tcp-reality-vision`. Both roles on raw TCP with Vision; REALITY over every TCP carrier. A wrong key fails before any proxy byte. xray scenarios 5/5. | [vless](docs/function/vless.md) · [xtls-vision](docs/function/xtls-vision.md) · [reality-tls](docs/function/reality-tls.md) |
| 2 | VLESS TCP TLS (Vision optional) | implemented — both roles, raw + ws + httpUpgrade + gRPC + xhttp + http header + kcp + quic + hysteria | link `vless-tcp-tls`, `vless-tcp-tls-vision`. Both roles; serves every `tlsSettings.certificates` entry by SNI, including QUIC and Hysteria; Vision optional. | [reality-tls](docs/function/reality-tls.md) |
| 3 | VLESS TCP none | implemented | link `vless-tcp-none`. Both roles, TCP+UDP and Mux; fallback table and protobuf bridge; ML-KEM, reverse and all clients carried. | [vless](docs/function/vless.md) |
| 4 | VLESS/TROJAN `security=none` to public (PattNG) | implemented under opt-in | link `unsafe opt-in`. `--allow-plaintext-public` reads a consented cleartext session as the private `security=none` it is byte-for-byte; the veto stands without consent. Consent adds no VLESS byte. | [reality-tls](docs/function/reality-tls.md) |
| 5 | TROJAN TCP | implemented — both roles, raw + ws + httpUpgrade + gRPC + xhttp + http header + kcp + quic + hysteria, TCP and UDP; REALITY on the TCP carriers; mux on every Xray carrier | link `trojan://`. Both roles over every carried carrier, TCP+UDP; REALITY on TCP; Mux on every Xray carrier. | [trojan](docs/function/trojan.md) |
| 6 | VMess TCP (AEAD) | partial — high priority; raw + TLS over every dialled carrier, UDP both roles | Partial: raw/TLS over every dialled carrier and UDP both roles; both VMess framing sets; xray scenarios 3/3. | [vmess](docs/function/vmess.md) |
| 7 | Shadowsocks TCP/UDP | implemented — both roles, TCP + UDP + mux | Both roles, TCP+UDP+Mux; every dialled carrier; 2022 ciphers and KCP covered elsewhere. | [shadowsocks](docs/function/shadowsocks.md) |
| 8 | ShadowsocksR (SSR) protocol/obfs plugins | planned — superset row; xray-core has no SSR | Protocol variants `origin`, `auth_sha1_v4`, `auth_aes128_md5`; obfs `plain`, `http_simple`, `tls1.2_ticket_auth`; outbound-only in `yuhaiin`. | ShadowsocksR fork; `yuhaiin` outbound. Not pinned. |
| 9 | VLESS over ws | implemented | link `vless-ws`, `vless-ws-tls`. Both roles; TLS/REALITY sit outside the carrier. | [carrier-websocket](docs/function/carrier-websocket.md) |
| 10 | VLESS over xhttp | partial — H1 and stream-one H2, both roles | link `vless-xhttp`, `vless-xhttp-tls`. Both roles, all three modes; `xmux` read but pool open; H1 and stream-one H2 only. | [carrier-xhttp](docs/function/carrier-xhttp.md) |
| 11 | VLESS over gRPC | partial — both roles, full HTTP/2 + HPACK, path `/<service>/Tun`, multi-mode dial and path derivation carried, multi-mode writer batches elements into `MultiHunk` messages | link `vless-grpc`, `vless-grpc-tls`. Both roles, full HTTP/2+HPACK and multi-mode writer; authority fallback and custom-service stream remain open. | [carrier-grpc](docs/function/carrier-grpc.md) |
| 12 | VLESS over httpUpgrade | implemented | link `vless-httpupgrade`, `vless-httpupgrade-tls`. Both roles. | [carrier-httpupgrade](docs/function/carrier-httpupgrade.md) |
| 13 | VLESS http masquerade | implemented | link `vless-tcp`. Both roles; selected by `tcpSettings.header.type == "http"`. | [carrier-httpheader](docs/function/carrier-httpheader.md) |
| 14 | VLESS over QUIC | partial — both roles, VLESS TCP/UDP/mux and Trojan; 0-RTT and client migration remain row 72 | link `vless-quic`. Both roles, VLESS/Trojan TCP+UDP+Mux and peer migration; 0-RTT and client migration remain row 72. | [carrier-quic](docs/function/carrier-quic.md) |
| 15 | KCP / mKCP | partial — VLESS/VMess/Trojan/Shadowsocks both roles; Shadowsocks TLS on other carriers missing | link `vless-kcp`. VLESS/VMess/Trojan/Shadowsocks both roles, plain/TLS; Shadowsocks TLS on other carriers missing. | [kcp](docs/function/kcp.md) |
| 16 | `?ed=N` early data, ws | implemented, both roles | Both roles; one parse and one allocation per encode. | [carrier-websocket](docs/function/carrier-websocket.md) |
| 17 | `?ed=N` early data, httpUpgrade | implemented, both roles | Both roles; first payload rides the `GET`; only `ed=0` holds it. | [carrier-httpupgrade](docs/function/carrier-httpupgrade.md) |
| 18 | `cipherSuites` (PattNG) | implemented, both roles; a listener serves the five ids neither backend has to a TLS 1.2 client after a ClientHello peek, and the dialer field is byte-identical for a TLS 1.3-only list, a TLS 1.2-only list on the BoringSSL lane, and a mixed list on the stock shaped lane | Both roles: six TLS 1.2 AEAD ids and CBC/static-RSA through BoringSSL, which caps a TLS 1.2-only list at 1.2 so its field is the reference's; a mixed list rides the stock shaped hello so its trio stays after the TLS 1.2 ids; the five RC4/ECDHE-3DES/`003c` ids advertised by the stock dialer and served by the shaped lane, whose listener peeks the hello and delegates a TLS 1.3 client to the engine that carries it. | [tls-cipher-suites](docs/function/tls-cipher-suites.md) |
| 19 | `unsafe-*` fingerprints (PattNG) | implemented under opt-in | link `unsafe opt-in`. Unsafe opt-in; stock `crypto/tls` hello, byte-identical to no-`fp`. | [reality-tls](docs/function/reality-tls.md) |
| 20 | Hysteria v2 | partial, VLESS/Trojan both roles both shapes | link `vless-hysteria`. VLESS/Trojan both roles; salamander/gecko, masquerade, port-hop and pooling; realm/STUN missing. | [carrier-hysteria](docs/function/carrier-hysteria.md) |
| 21 | MASQUE CONNECT-IP (RFC 9484) | implemented — both roles; client and server over h3, h2, h1 and cleartext h2c, with `remoteDNS` and WARP | link `vless-masque` (separate slice). Both roles over h3/h2/h1/h2c; CONNECT-IP codec, remoteDNS and WARP. | [carrier-foxy](docs/function/carrier-foxy.md) |
| 22 | MASQUE CONNECT-UDP (RFC 9298) | implemented — both roles through the Foxy lane; not xray's `masque` transport | One capsule stream per UDP destination over h2/h3; h3 preferred, and h1 is never asked to carry a datagram. | [carrier-foxy](docs/function/carrier-foxy.md); RFC 9298; RFC 9297 capsules. |
| 23 | TUIC/AnyTLS/ShadowTLS/Snell/Naive/SSH/OpenConnect/OpenVPN | planned | link parse to `TransportKind::Other`. Parsed to `TransportKind::Other`; rows 121–129 own each. | — |
| 24 | Mux / XUDP / `multi` | partial — both roles on raw/ws/httpUpgrade/gRPC/xhttp/httpheader/KCP; Hysteria and xdrive keep direct | Both roles on raw/ws/httpUpgrade/gRPC/xhttp/httpheader/KCP; Hysteria and xdrive keep direct. | [mux-cool](docs/function/mux-cool.md) |
| 25 | HTTP proxy, both roles | implemented | Both roles; CONNECT and origin-form; outbound TLS/headers/basic auth. xray scenarios 4/4. | [http-proxy](docs/function/http-proxy.md) |
| 26 | SOCKS5 + SOCKS4/4a, both roles | implemented — CONNECT and UDP ASSOCIATE, RFC 1929 credential, SOCKS4/4a, HTTP fallback | xray scenarios 5/5. | [socks](docs/function/socks.md); Xray `proxy/socks`; sing-box `protocol/socks`; ZeroNet `socks.rs`. |
| 27 | dokodemo-door transparent inbound | partial — transparent TCP on Linux/macOS, UDP on Linux; FreeBSD TCP and `userLevel` missing | Both roles transparent TCP on Linux/macOS and UDP on Linux; FreeBSD TCP and `userLevel` missing. xray scenarios 2/2. | [front-dokodemo](docs/function/front-dokodemo.md) |
| 28 | blackhole sink outbound | partial — outbound | Outbound only; three answers; datagram association refused with `0x07`. | [blackhole](docs/function/blackhole.md) |
| 29 | DNS outbound | implemented — outbound; resolver rows are row 111 | Outbound only; pinned DNS bytes, rules, rewrite fields and hijack. | [dns-outbound](docs/function/dns-outbound.md) |
| 30 | loopback re-inject inbound | partial — TCP+UDP | Partial TCP+UDP; own sniffing on re-inject; named inbound second pass and protobuf missing. | [loopback](docs/function/loopback.md) |
| 31 | Shadowsocks-2022 ciphers | implemented — both roles, TCP+UDP, EIH multi-user, relay | Both roles, TCP+UDP, EIH multi-user and relay; conformance green. xray scenarios 4/4. | [shadowsocks-2022](docs/function/shadowsocks-2022.md) |
| 32 | TUN inbound (native) | partial — high priority; both roles, IPv4 TCP/UDP + echo | Partial both roles, IPv4 TCP/UDP+echo; ICMPv6, errors, GSO/GRO and privileged opens missing. | [front-tun](docs/function/front-tun.md) |
| 33 | Unix domain sockets | implemented, both roles, both hosts | Both roles and both hosts over `AF_UNIX`. | [unix](docs/function/unix.md) |
| 34 | finalmask post-TLS mask chain | partial, both roles (`fragment`) | Partial both roles; `fragment` only; other mask types planned. | [finalmask](docs/function/finalmask.md) |
| 35 | xdrive cloud-drive carrier | partial — high priority; both roles, three services | Partial both roles; local/template/Google Drive; Yandex and REALITY store missing. | [carrier-xdrive](docs/function/carrier-xdrive.md) |
| 36 | native HTTP/H2/H3 transport | planned | Parsed but never dialled; xray refuses these, the xHTTP gap row and rows 130 and 142 are the superset path. | — |
| 37 | VLESS `encryption=mlkem768x25519plus` | partial — both roles, raw + TLS + REALITY + carried, Vision on raw | link `vless-tcp-encryption`, `vless-tcp-tls-encryption`, `vless-tcp-reality-encryption`. Partial both roles; raw/TLS/REALITY and carried H1; Vision over carried encryption and xhttp H2 missing. | [vless](docs/function/vless.md) |
| 38 | `flow=xtls-rprx-vision-udp443` | implemented — outbound only | Outbound only; strips to Vision and widens the UDP 443 gate. | [vless](docs/function/vless.md) |
| 39 | REALITY client | partial — client dials raw + ws + httpUpgrade + gRPC + xhttp + http header | link `vless-tcp-reality-vision`. Client only; raw and every carried carrier; no REALITY over UDP. | [reality-tls](docs/function/reality-tls.md) |
| 40 | TLS client from config | implemented — vless/vmess/trojan/shadowsocks/socks/http over raw + carried carriers | link `vless-tcp-tls` + carriers. Client only; roots from config or system; vless/vmess/trojan/shadowsocks/socks/http over raw and carried carriers. SOCKS and HTTP outbounds dial the configured carrier instead of treating it as raw TLS; those two also keep TLS over KCP, and refuse `quic`, `hysteria`, `masque`, `xdrive` and unknown carriers rather than dialling them plain. | [tls-client](docs/function/tls-client.md) |
| 41 | uTLS fingerprints | implemented, client | Client only; 50 names onto 31 presets; psk and random families are not byte-gated. xray-rust interop 3/3. | [security-utls](docs/function/security-utls.md) |
| 42 | ECH | partial — TLS and QUIC both roles | Partial TLS/QUIC both roles; retry-list bytes differ; accepted offers are unchanged. | [security-ech](docs/function/security-ech.md) |
| 43 | transport stack as one shareable string | planned | Planned; pipe-separated stack in one share string. | — |
| 44 | Hysteria v1 | implemented — both roles, TCP and UDP, xplus and port hop | Both roles, TCP and UDP, xplus and port hop. | [carrier-hysteria](docs/function/carrier-hysteria.md) |
| 45 | Freedom outbound options | implemented — both roles | `domainStrategy`, `fragment`, `proxyProtocol`, `noises` and `finalRules` from JSON and xray protobuf; explicit rules only, the reference's inbound-derived default private block is not applied. | — |
| 46 | SOCKS front HTTP fallback | implemented — front and hop | The `socks` front hands a non-socks greeting to the HTTP front and checks the socks accounts; the HTTP client's protobuf decodes to the hop this tree dials. xray scenario 1/1. | [socks](docs/function/socks.md); [http-proxy](docs/function/http-proxy.md) |
| 47 | HTTP proxy chaining (`dialerProxy` over CONNECT) | planned — high priority | Planned high priority; HTTP CONNECT hop for `dialerProxy`. | [http-proxy](docs/function/http-proxy.md) |
| 48 | TLS min/max version, curves, `pinnedPeerCertSha256`, `rejectUnknownSNI`, `masterKeyLog` | planned — high priority | Planned high priority; TLS versions/curves/pins/rejectUnknownSNI/masterKeyLog. | — |
| 49 | OCSP stapling + anti-replay/time-window caches | planned — high priority | Planned high priority; OCSP stapling and anti-replay caches. | — |
| 50 | Browser dialer | planned | Planned; xray browser dialer. | — |
| 51 | kTLS | planned | Planned; Linux kTLS. | — |
| 52 | xHTTP over h2c and HTTP/3 | planned — high priority; H1 and stream-one H2 only | The reference serves h2c on a cleartext port and HTTP/3 on QUIC; this tree refuses h2c, has no H3, and refuses packet-up/stream-up on a negotiated H2 stream. | [carrier-xhttp](docs/function/carrier-xhttp.md) |

### B — PattNG and engine app surfaces

| # | method | state | notes | supported today by |
| --- | --- | --- | --- | --- |
| 53 | Engine sniffing (HTTP/TLS/QUIC/FakeDNS) | implemented — HTTP/TLS/QUIC/FakeDNS sniffers; second routing pass remains row 30 | — | Xray `app/dispatcher`; [page](docs/function/engine-sniffing-http-tls-quic-fakedns.md) |
| 54 | Stats, metrics, access log, policy levels | partial — reference counters, online map, access log and policies; Trojan/Shadowsocks KCP and non-VLESS xdrive user counters missing | — | Xray `app/stats`, `app/metrics`, `app/log`, `app/policy` |
| 55 | `PROXYCHAIN` ordered member list | planned (chaining, section G) | — | PattNG — at most one `AETHER` member per chain |
| 56 | `POLICYGROUP` / routing groups | planned | — | PattNG |
| 57 | Psiphon OSSH/SSH transport | implemented — OSSH seed, curve25519, AES-128-CTR + HMAC-SHA-256, password auth, `direct-tcpip` | App module `psiphon_ssh.rs`; `ferrox-core` holds only the bootstrap constants. The lane's SOCKS4/4a and SOCKS5 edge stays private with `DisableLocalSocksProxy` (ephemeral loopback, no configured listener). No pinned suite: `psiphon-live.yml` compares the console client. | [carrier-psiphon](docs/function/carrier-psiphon.md); `upstream/psiphon-tunnel-core/psiphon/common/crypto/ssh`; `crates/ferrox-app/src/psiphon_ssh.rs`. |
| 58 | Psiphon TLS-OSSH | implemented — shaped TLS, passthrough proof, RFC 7685 padding, SNI choice | App module `psiphon_ssh.rs`; the shaped hello rides the same OSSH seed and SSH session. | [carrier-psiphon](docs/function/carrier-psiphon.md); `psiphon/tlsTunnelConn.go`; `psiphon/common/obfuscator/passthrough.go`. |
| 59 | Psiphon fronted meek (HTTP/HTTPS) | implemented — loopback relay, version-4 NaCl cookie, one persistent TLS/HTTP front, per-connection cookie/content-type/request-cap shaping | App module `psiphon_meek.rs`; unfronted and CDN-fronted shapes share the same SSH handshake. | [carrier-psiphon](docs/function/carrier-psiphon.md); `psiphon/meekConn.go`; `psiphon/frontingDialParameters.go`. |
| 60 | Psiphon fronted meek over QUIC/H3 | implemented — HTTP/3 over quiche, same cookie and fronting SNI | App module `psiphon_h3.rs`; a limit without a plain QUIC version demotes an H3 front to its plain fronted capability. | [carrier-psiphon](docs/function/carrier-psiphon.md); `psiphon/meekConn.go`; `psiphon_h3.rs`. |
| 61 | Psiphon QUIC-OSSH + noise profiles | partial — QUICv1, randomized, obfuscated and decoy variants; exact seeded sequence and ticket obfuscation missing | App module `psiphon_quic.rs`; rustls sans-IO carries the ClientHello-random passthrough proof. | [carrier-psiphon](docs/function/carrier-psiphon.md); `psiphon/common/quic/quic.go`; `psiphon/common/noise/noise.go`. |
| 62 | Psiphon Shadowsocks-OSSH | implemented — `chacha20-ietf-poly1305`, random salt or configured prefix, in-proxy reuse | App module `psiphon_shadowsocks.rs`; direct and in-proxy shapes carry the same OSSH seed above the AEAD stream. | [carrier-psiphon](docs/function/carrier-psiphon.md); `psiphon/shadowsocksConn.go`; `psiphon/server/shadowsocks.go`. |
| 63 | Psiphon in-proxy WebRTC/conduit | implemented — broker Noise XK, DTLS/SCTP data channel, `psiphon-inproxy-relay` | App modules `psiphon_webrtc.rs` and `psiphon_broker.rs`; extracting this core out of `ferrox-app` remains open. | [carrier-psiphon](docs/function/carrier-psiphon.md); `psiphon/common/inproxy`; `psiphon_webrtc.rs`. |
| 64 | Psiphon udpgw (UDP gateway) | implemented — one SSH channel to `127.0.0.1:7300`, 16-bit flow ids, framed datagrams | App module `psiphon_ssh.rs`; every SOCKS UDP association gets a local relay socket. | [carrier-psiphon](docs/function/carrier-psiphon.md); `psiphon/udpgw.go`. |
| 65 | Pluggable transports via lyrebird (`obfs4`/`snowflake`/`webtunnel`/`meek`) | planned | — | PattNG, Aether |
| 66 | hev-socks5-tunnel TUN (`libhev-socks5-tunnel.so`) | implemented | Implemented client role; CONNECT + UDP ASSOCIATE with RFC 1929, driven by the native TUN front. | PattNG; [socks](docs/function/socks.md) |

### C — VPN / tunnel carriers

| # | method | state | notes | supported today by |
| --- | --- | --- | --- | --- |
| 67 | WireGuard (UDP) | implemented | Implemented both roles over smoltcp; Noise, timers, dual-stack, WARP, remoteDNS and kernel TUN; `TestWireguard` green. xray scenarios 1/1. | [wireguard](docs/function/wireguard.md) |
| 68 | AmneziaWG | planned | — | amneziawg-go, amnezia-client, mlmvpn |
| 69 | MASQUE CONNECT-IP over QUIC | implemented — both roles over h3, h2, h1 and cleartext h2c; transport `masque` | Implemented both roles over h3/h2/h1/h2c; address pool, `user`/`pass` auth, `{target}`/`{ipproto}` path templates, `xmux.hKeepAlivePeriod`, WARP, remoteDNS and ICMP limits. xray scenarios 6/6. | [carrier-masque](docs/function/carrier-masque.md) |
| 70 | MASQUE over HTTP/3 vs HTTP/2 | implemented — h3, h2, h1 and cleartext h2c, both roles | Implemented both roles over h3/h2/h1/h2c; shared TLS port, ALPN select. xray scenarios 6/6. | quiche; Aether; mqvpn |
| 71 | Multipath QUIC | planned | — | mqvpn, slipstream, quiche |
| 72 | quiche: QUIC + HTTP/3, 0-RTT, migration, key updates, batched datagrams | partial — key updates and peer path validation; 0-RTT and client migration unexposed; batched datagrams on Linux | Partial provider: key updates and peer path validation; 0-RTT and client migration unexposed; batched datagrams on Linux. | quiche |
| 73 | Multipath schedulers `minrtt`/`wlb`/`backup-fec` | planned | — | mqvpn |
| 74 | Hybrid TCP lane (local termination over an H3 stream) | planned | — | mqvpn |
| 75 | Reorder buffer + reinjection | planned | — | mqvpn |
| 76 | Nested WireGuard (`gool`, two hops) | planned | — | Aether |
| 77 | Nested MASQUE (`mim`, tunnel in a tunnel) | planned | — | Aether |
| 78 | TCP-over-DNS covert channel | planned | — | slipstream |
| 79 | Multi-resolver parallel + port-53 impersonation, DCUBIC/BBR | planned | — | slipstream |
| 80 | tun2socks engine (zeptun) | planned | zeptun; Leaf `proxy/tun/` (device front + smoltcp translator in one tree); a TUN device is the whole gap | zeptun; Leaf `proxy/tun/` |
| 81 | filter-driver transparent front (no TUN device) | planned | Leaf `proxy/nf/` — a Windows-only inbound that dlopens a filter-driver API (`nf_addRule`, `nf_free`) and feeds the captured flows straight into the tun2socks lane, with fake-DNS include/exclude lists deciding what is captured; rows 27 and 120 are the Linux spellings, and this is the third one — no device node, no route table | Leaf `proxy/nf/` |
| 82 | L2 bridge protocol | planned | sing-box `protocol/bridge`; pf/netlink/nft/WinDivert NAT. | sing-box `protocol/bridge` |
| 83 | Shared HTTP CONNECT/capsule transport | planned | sing-box `transport/http`; `carrier-singbox-http`. Behind HTTP-proxy, naive and masque. | sing-box `transport/http` |
| 84 | Device abstraction | planned | sing-box `transport/device`; `carrier-device`. Row 32 opens one TUN directly. | sing-box `transport/device` |

### D — DNS ways (learned from CottenDNS / MasterDnsVPN / Lantern Soar, not pinned)

| # | method | state | notes | supported today by |
| --- | --- | --- | --- | --- |
| 85 | DNS carriers UDP/TCP/DoT/DoH, per-resolver `auto` | planned | — | CottenDNS |
| 86 | Soar DNS tunnel (Lantern) | planned | TCP/53 through recursive resolvers to an authoritative zone; RFC 7766 pipelining, ChaCha20-Poly1305, QUIC-style packet numbers. | `getlantern/soar`, `getlantern/soar-rs`, `SPEC.md`; not pinned. |
| 87 | DNSCrypt resolver encryption | planned | Resolver-side encrypted DNS with a separate certificate and ephemeral key; not carried by xray-core's `app/dns`. | DNSCrypt v2; resolver implementations. Not pinned. |
| 88 | Oblivious DNS-over-HTTPS (RFC 9230) | planned | Splits the resolver path into an oblivious proxy and a target resolver, so no single hop sees both client and query. | RFC 9230. Not pinned. |
| 89 | Record-type rotation + QNAME reshaping + ID randomization | planned | — | CottenDNS |
| 90 | ARQ + ACK/NACK, adaptive duplication, Reed-Solomon FEC, MTU discovery, compression | planned | — | CottenDNS, MasterDnsVPN |
| 91 | Resolver balancing + health checks + failover | planned | — | CottenDNS, MasterDnsVPN |
| 92 | Local DNS service + cache + DNS-over-SOCKS5 + hijack guards | planned | — | CottenDNS, MasterDnsVPN |
| 93 | Server egress direct / upstream-SOCKS5 chaining + flood protection | planned | — | CottenDNS, MasterDnsVPN |
| 94 | Encryption methods 0–5 (none/XOR/ChaCha20/AES-GCM) + auto-detect | planned | — | CottenDNS |
| 95 | MasterDns protocol | planned | — | ZeroNet `zero-masterdns`; rows 85–94 are DNS tunnel carriers. |

### E — circumvention engines (learned from mlmvpn_android, not pinned)

| # | method | state | notes | supported today by |
| --- | --- | --- | --- | --- |
| 96 | SoftEther / L2TP + WireGuard via `kittoku`; VPN Gate relays | planned | — | mlmvpn |
| 97 | GST / EDG relay engines; GitHub Tunnel; OpenVPN with TunnelBear | planned | — | mlmvpn |
| 98 | MLM Adaptive Engine: per-app route learning + repair ladder | planned | — | mlmvpn |
| 99 | Config Studio + Config Arena | planned | — | mlmvpn |
| 100 | Game Booster: DNS/latency racing + DNS-only VPN | planned | — | mlmvpn |
| 101 | Sanction-domain smart routing | planned | — | mlmvpn |
| 102 | Server-less domain fronting | planned | mlmvpn; Outline SDK `transport/tls/` OuterName — SNI and `Host` name different sites (not pinned) | mlmvpn; Outline SDK `transport/tls/` |
| 103 | Serverless / mihomo / superdns / pdoq / http-injector / oblivion lanes | planned | configer | configer |
| 104 | Three-tier Emergency fallback | planned | — | mlmvpn |

### F — configer `https-proxy` + `foxy` lanes

| # | method | state | notes | supported today by |
| --- | --- | --- | --- | --- |
| 105 | Free HTTPS-proxy lane (token mint, proxy export) | planned | — | configer |
| 106 | Foxy lane: CONNECT over HTTP/1.1, HTTP/2 or HTTP/3, country-pinned, per-flow Bearer, failover, SPKI pins, split-tunnel | implemented — h1, h2 and h3; CONNECT and CONNECT-UDP | Implemented h1, h2 and h3 CONNECT/CONNECT-UDP; socket-proven per carrier. | configer; FoxyVPN |

### G — chaining

Today exactly one method dials per hop. The chaining engine builds stacks as an ordered list, each hop dialling through the previous hop's local SOCKS / HTTP CONNECT / TUN front (reusing the `mux.rs` 8-session cap and `global_id`). Reference rules: control plane stays DIRECT unless a hop chains; each hop names its own upstream; at most one core-needing member per chain; every hop verifies its exit; teardown before redial. A chain needing a capability its carrier lacks is not carried, with the reason, never silently downgraded.

### H — arti (Tor) + onionmasq

- `arti`: Aether carries `--tor`, `--tor-reverse` (MASQUE-H2 only, Tor is TCP-only) and `--tor-only` with bridges and `lyrebird` transports. Planned; nothing in this tree.
- `onionmasq`: the experimental TUN for Arti (userspace TCP/UDP over Tor on `onion0`). Planned as the Tor-family TUN lane.

### I — SNI spoofing without root

| # | method | state | notes | supported today by |
| --- | --- | --- | --- | --- |
| 107 | Fake-ClientHello SNI spoofing (DPI bypass, no root) | planned — nothing in CI checks it | `UAC-SNI-Spoofer-Android`, `sni-spoofing-rust` | `UAC-SNI-Spoofer-Android`; `sni-spoofing-rust` |

`VpnService` TUN plus a userspace TCP stack sends a fake ClientHello (spoofed SNI, wrong sequence number) first; DPI permits the flow, the real server discards the bad-seq packet, the legitimate handshake proceeds. A row keeps `planned` until its differential proof and benchmark gate are green.

### J — engine: routing, balancing, DNS, management (xray-core `app/`)

| # | method | state | notes | supported today by |
| --- | --- | --- | --- | --- |
| 108 | Routing rules + geosite/geoip | partial — high priority; routing/selectors, balancers, webhook and geodata guard; observatory row 117; second routing pass row 30; rule sets and scripts row 109 | — | Xray `app/router` + `app/geodata`; sing-box `route/`; ZeroNet `zero-router`; [page](docs/function/engine-router.md) |
| 109 | Routing rule sets + scripts | partial — inline and local rule sets plus Lua scripts; binary `.srs`, remote sets and script+rule mixing missing | — | Xray `app/router` + `common/lua`; sing-box `route/rule_set`; [page](docs/function/engine-router.md) |
| 110 | Balancers leastPing/leastLoad/roundRobin/random + urltest/selector | partial — high priority; four balancer strategies reading observatory row 117; urltest and selector planned | — | Xray `router/balancing.go`; sing-box `protocol/group/`; ZeroNet `zero-observatory` |
| 111 | Built-in DNS app (UDP/TCP/DoT/DoH/DoQ/FakeDNS/cache) | implemented — UDP/TCP/DoT/DoH/DoQ, cache, hosts, FakeDNS, filters and parallel groups; Lua script row 109 | xray scenarios 1/1. | Xray `app/dns`; sing-box `dns/`; ZeroNet `zero-dns`; [page](docs/function/engine-dns.md) |
| 112 | Reverse tunnel bridge/portal | partial | Partial: modern VLESS reverse both roles; freedom/blackhole only, no xhttp/QUIC/KCP/hysteria/xdrive. | Xray `app/reverse`; ZeroNet `reverse.rs`; xray-core-rust `xray-app-reverse` |
| 113 | Commander gRPC management API | partial — every service except `AddRule`/`RemoveRule` | xray commander 5/5. | Xray `app/commander`; [page](docs/function/engine-api.md) |
| 114 | Connection-planner ladder (climb on failure, earned descent) | planned — high priority | — | ZeroNet `zero-observatory`; Leaf `app/healthcheck.rs` (the per-outbound latency the balancers read) |
| 115 | Subnet scanner + server discovery | planned | — | ZeroNet `zero-scanner`, `zero-discovery` |
| 116 | Load-balancer healthcheck probe inbound | implemented — one exact path, `GET` or a `POST` body signature, and a fixed `200` body | Implemented: one exact path, GET or signed POST, fixed `200`. | Leaf `proxy/hc/`; [front-healthcheck](docs/function/front-healthcheck.md) |
| 117 | Observatory burst probes + healthcheck inbound | implemented — legacy and burst probes, `leastPing`/`leastLoad`, `hc` front | — | Xray `app/observatory`; [engine-observatory](docs/function/engine-observatory.md), [front-healthcheck](docs/function/front-healthcheck.md) |
| 118 | Tagged outbound | planned — high priority | — | xray `transport/internet/tagged`; `engine-tagged`. Row 108 tags inbounds, not outbound sockets. |

### K — sing-box-only protocols and transports

| # | method | state | notes | supported today by |
| --- | --- | --- | --- | --- |
| 119 | mixed (HTTP + SOCKS) inbound | implemented | — | sing-box `protocol/mixed/`; one-byte sniff between SOCKS and HTTP |
| 120 | redirect + tproxy inbounds | planned | — | sing-box `protocol/redirect/`; Leaf `proxy/redirect/` (the origin-destination spelling, inbound and outbound) |
| 121 | NaïveProxy | planned | — | sing-box `protocol/naive/`; LxBox `naive+https://` |
| 122 | AnyTLS | planned | — | sing-box `protocol/anytls/`; ZeroNet `anytls.rs`. Row 23 is the link parse |
| 123 | ShadowTLS | planned | — | sing-box `protocol/shadowtls/` |
| 124 | Snell | planned | — | sing-box `protocol/snell/` |
| 125 | SSH outbound | planned | — | sing-box `protocol/ssh/`; LxBox `ssh://` |
| 126 | TUIC v5 over QUIC | planned | — | sing-box `protocol/tuic/`; ZeroNet `tuic.rs`. LxBox `tuic://` |
| 127 | Tailscale endpoint (tsnet, MagicDNS, exit nodes) | planned | — | sing-box `protocol/tailscale/`; LxBox feature 030 |
| 128 | OpenConnect / OpenVPN endpoints | planned | — | sing-box `protocol/openconnect/`, `openvpn/` |
| 129 | cloudflared (Argo) inbound | planned | — | sing-box `protocol/cloudflare/` |
| 130 | Plain H2 + gRPC-lite transports | planned | — | sing-box `transport/v2rayhttp/`, `v2raygrpclite/`. Tree has full gRPC (row 11) |
| 131 | simple-obfs (http/tls) | planned | — | sing-box `transport/simple-obfs/`; Leaf `proxy/obfs/` (http + tls shapes) |
| 132 | SIP003 plugin manager | planned | — | sing-box `transport/sip003/`; LxBox `plugin`/`plugin_opts`; Leaf `OutboundSettings::Plugin` (an external transformer named by `path`+`args`) |
| 133 | Mux variants smux/yamux/h2mux | planned | — | sing-box `common/mux/`; Leaf `proxy/amux`, `proxy/mptp` (multipath TCP beside the muxes). Tree has mux-cool (row 24) |
| 134 | Hysteria2 multiport (`mport`/`server_ports`) | implemented — salamander/gecko, row 20 | Implemented: salamander/gecko, row 20. | ZeroNet; sing-box |
| 135 | carrier fronts as standalone stackable in/out objects | planned | — | Leaf `proxy/{tls,websocket,amux,quic,mptp}/` — each carrier is its own inbound and outbound protocol that chains to another by tag, not a `streamSettings` stanza inside one protocol's config; the same seat row 140's chain engine fills, and row 108's per-inbound tags read it |
| 136 | sing-box v2ray QUIC + dispatch transports | not-scheduled | — | sing-box `transport/v2rayquic`, `transport/v2ray`; `carrier-v2ray-quic`, `carrier-v2ray-dispatch`. The reference's own dispatcher and second QUIC spelling; row 130 owns v2ray HTTP/gRPC-lite; row 14 is QUIC. |

### L — ZeroNet + LxBox superset

| # | method | state | notes | supported today by |
| --- | --- | --- | --- | --- |
| 137 | WARP: auto-race WireGuard vs MASQUE + one-tap registration | planned | ZeroNet `warp.rs`; LxBox feature 015. Row 67 is the carrier | ZeroNet `warp.rs`; LxBox 015 |
| 138 | AmneziaWG 1.0–3.1 parameter set | planned | LxBox §8.5; ZeroNet `amnezia.rs`; amneziawg-go. Row 68 pointer | LxBox §8.5; ZeroNet `amnezia.rs`; amneziawg-go |
| 139 | Evasion on TCP/TLS (fragment, keepalive shaping, noise, fake-SNI) | planned | ZeroNet `zero-evasion/`; LxBox 016 | ZeroNet `zero-evasion/`; LxBox 016 |
| 140 | Detour graph + hop chains with cycle detection | planned (section G engine) | LxBox 006; Xray `dialerProxy`; sing-box `detour`; Leaf `proxy/chain/` | LxBox 006; Xray `dialerProxy`; sing-box `detour`; Leaf `proxy/chain/` |
| 141 | Import superset (Xray/sing-box JSON, WG INI, Amnezia `vpn://`, OpenVPN) | planned | LxBox 002 + `PROTOCOLS.md` §§9–11 | LxBox 002; `PROTOCOLS.md` §§9–11 |
| 142 | VLESS `flow`/`encryption` grammar + XHTTP full params | planned | LxBox 016; ZeroNet `xhttp.rs`. Rows 10 and 38 are the gaps. The three xhttp dial shapes, both packet placements and the app half-close have a working implementation on the local `option1` branch (`b37bbc9`, `5fda672`) — a port candidate, not a landed diff; [carrier-xhttp](docs/function/carrier-xhttp.md) names what a port owes | LxBox 016; ZeroNet `xhttp.rs`; [carrier-xhttp](docs/function/carrier-xhttp.md) |
| 143 | Config template + contract registry | planned | — | LxBox features 024/025 |
| 144 | FFI/JNI surface | planned | xray-rust `xray-ffi`, ZeroNet `zray-mobile`; `surface-ffi`. C ABI and JNI with panic containment. | xray-rust `xray-ffi`; ZeroNet `zray-mobile` |
| 145 | Fuzz targets | planned | xray-rust `fuzz`, ZeroNet `fuzz`; `surface-fuzz`. `check.sh` has no pinned fuzz harness. | xray-rust `fuzz`; ZeroNet `fuzz` |

### M — SlipNet tunnel types (learned from anonvector/SlipNet, not pinned)

| # | method | state | notes | supported today by |
| --- | --- | --- | --- | --- |
| 146 | DNSTT (KCP + Noise DNS tunneling) | planned | — | SlipNet `dnstt` |
| 147 | NoizDNS (DPI-resistant DNS tunneling) | planned | — | SlipNet `noizdns` |
| 148 | VayDNS (configurable wire format) | planned | — | SlipNet `vaydns` |
| 149 | `+ SSH` chaining over any tunnel | planned | — | SlipNet tunnel table. Row 125 standalone SSH |
| 150 | SSH over TLS / ws-wss / HTTP CONNECT | planned | — | SlipNet features |
| 151 | SSH payload injection + cipher selection | planned | — | SlipNet features |
| 152 | DoH lane (DNS-only, RFC 8484) | planned | — | SlipNet `DOH`. Row 111 is the resolver |
| 153 | DNS server scanner (EDNS, NXDOMAIN-hijack, country scan) | planned | — | SlipNet built-in scanner |

### N — ZeroNet server engine + xray-core-rust config deltas

| # | method | state | notes | supported today by |
| --- | --- | --- | --- | --- |
| 154 | PROXY protocol v1+v2 parsed on an inbound (`acceptProxyProtocol`) | planned — high priority | — | ZeroNet `proxy_protocol.rs`. Tree only writes the header into a REALITY `dest` |
| 155 | freedom `proxyProtocol: 1\|2` send + fallback `xver` parity | planned — high priority | — | ZeroNet freedom; xray `proxy/freedom` |
| 156 | REALITY `mldsa65Seed`/`mldsa65Verify` (post-quantum binding) | partial — high priority; fields validated, ML-DSA-65 signature not generated or checked | — | ZeroNet `xray_json.rs`; the oracle row waits on it |
| 157 | `customSockopt` raw setsockopt escape hatch | planned — high priority | — | ZeroNet `custom_sockopt.rs`; xray `sockopt` |
| 158 | Tunable dial params (`tcpCongestion`, `tcpUserTimeout`, `tcpFastOpen`, `dialerProxy`, `mark`, Happy-Eyeballs…) | planned — high priority | — | ZeroNet `parse_sockopt`; xray-core-rust `sockopt`; Outline SDK `transport/happyeyeballs.go` — the dual-stack race dial (not pinned). `tcpFastOpen` is xray's own sockopt: a stored kernel cookie lets the next SYN carry the ClientHello, one RTT back on every reconnect. Row 162 is the runtime-configurable *wait* surface |
| 159 | Tide down/up traffic-ratio shaping | planned | — | ZeroNet `tide/shape.rs`. Read as a superset rung beside row 139 |
| 160 | Fountain-coded carrier rendezvous over DoH TXT | planned | — | ZeroNet `rendezvous.rs` |
| 161 | Multi-file config layering (`-c` repeats, `-confdir`, tag-merge) | partial — JSON multi-file merge and `-dump`; YAML/TOML and remote sources wait row 163 | — | xray `conf.Config.Override`; ZeroNet `merge.rs` |
| 162 | Ten wait budgets (`dial`, `handshake`, `headArrival`, `relayJoin`, `relayQuantum`, `relayStall`, `udpIdle`, `payloadGrace`, `goawayGrace`, `carrierProbe`) | partial — every wait named and armed before the first inbound; splice/carrier-sink waits unarmed | Each wait named once (`budgets.rs`); unknown/missing-unit/zero refused by name. Missing: splice `pull`/`push` still read `armed=none`, an ordered carrier's upload sink has nothing to arm, and eight names have no census entry. Loop cadences stay constants | `budgets.rs` |
| 163 | Config formats + lint | planned | — | xray-rust `xray-conf` `vformat`/`lint`; `engine-config`. JSON5/YAML/TOML by extension; row 161 is merging. |

### O — client shaping, mobile service and the TUN edge

Rows 164–169 are the client-side gaps the FoxyVPN v1.0.7 release surfaces, read against the pinned trees; rows 170–174 are the DPI-evasion moves the Outline SDK `x/` module makes, learned from it without pinning it. Row 34 keeps the generic ClientHello mask and row 32 the native TUN; these rows are the parts neither reaches.

| # | method | state | notes | supported today by |
| --- | --- | --- | --- | --- |
| 164 | ClientHello fragmentation on the Foxy lane (first-byte and SNI-aware cut) | planned | — | FoxyVPN v1.0.7 `TlsClientHelloSplitter.kt`; ZeroNet `zero-evasion/src/fragment.rs` (`tlssni`). Generic `tlshello` re-framing ships row 34, but the Foxy lane's TCP carriers (rustls) arm neither cut and the h3 handshake is quiche's own |
| 165 | Custom tunnel MTU (576–9000) | planned | — | FoxyVPN v1.0.7 `SettingsStore.kt`/`HevSocks5TunnelConfig.kt`; sing-box `option/tun.go`; mqvpn `src/config.h` (`tun_mtu`). The native TUN honours `settings.mtu` (row 32); Foxy, tun2socks (row 80) and MASQUE (row 21) carry no MTU knob |
| 166 | Cellular keepalive and handover rebind | planned | — | FoxyVPN v1.0.7 h2 PING (3 s check, 15 s idle, 25 s timeout) and `NetworkCallback`; ZeroNet `zero-evasion/src/keepalive.rs`. The Foxy h2 lane acks a peer PING and sends none; no lane rebinds after a network change |
| 167 | QUIC congestion controller and pacing (CUBIC/BBR/BBR2) | planned | — | quiche `quiche/src/recovery/mod.rs`; ZeroNet `zero-transport/src/quic_shape.rs`; SlipStream `docs/protocol.md` (DCUBIC). Hysteria picks BBR; the Foxy h3 lane leaves quiche's CUBIC default and paces nothing |
| 168 | TUN stack and offloads (`userspace`/`system`/`hybrid`, GSO/GRO, multi-queue) | planned | — | zeptun `docs/wiki/Stacks.md`; sing-box `option/tun.go`; mqvpn `src/mqvpn_internal.h`; aether `aether/src/netstack.rs`; ZeroNet `zero-tun`. The tree opens one userspace device on one handler loop, without GSO/GRO |
| 169 | Split tunneling (per-app/per-UID and per-domain) | planned | — | sing-box `option/tun.go` (`include_package`/`exclude_package`); LxBox 011-SPLIT_TUNNELING; xray-rust `platform/android/README.md`; Leaf `ProcessNameMatcher` (a regex over the session's process name). Router field rules (row 108) carry no app identity |
| 170 | QUIC prelude: an unparseable Initial before every parseable one | planned | — | Outline SDK `x/quicprelude/` (not pinned) — decoy Initial-shaped datagrams precede each packet that may carry a QUIC ClientHello, judged from the header alone and remembered nowhere, so a middlebox that reads the SNI off the first Initial it can parse reaches no decision and matches nothing after it; rows 34 and 164 cut TCP streams, this is the h3 seat (rows 106 and 167) |
| 171 | In-flight TTL drop ("disorder") | planned | — | Outline SDK `x/disorder/` (not pinned) — the Nth write goes out with TTL 1, dies at the first hop, and the stack retransmits it with TTL restored; every byte lands but the observer's reassembly holds a hole that never fills. Rows 34 and 164 re-time writes, none drops one |
| 172 | Boot strategy race over resolvers and shaping | planned | — | Outline SDK `x/smart/` (not pinned) — a list of (DNS resolver × stream split × TLS-record frag) strategies raced against test domains at boot, the first that resolves *and* handshakes is kept, with an access-key fallback beneath; rows 116, 104 and 114 each own one tier of this, none races across the DNS and TCP/TLS layers at once |
| 173 | Interference probe that names what the network blocks | planned | — | Outline SDK `x/connectivity/` + `x/tools/test-connectivity/` (not pinned) — layered probes classify the failure (poisoned resolution, blackholed address, SNI reset, blocked TLS) so the user learns what is censored instead of "connection failed"; row 114's ladder is the engine that wants this verdict |
| 174 | Truncated-answer DNS front (force the retry onto TCP) | planned | — | Outline SDK `network/dnstruncate/` (not pinned) — a listener answers the client's UDP query with the TC bit set so the retry rides TCP, the one path the tunnel owns; row 111's app picks TCP for itself, this is the trick for apps whose resolver the engine does not own |

### P — seats of our own: speed, fairness and a verdict

Nothing on the pinned trees spells these; they are read off this engine's own seams. The aim is the three things a filtered connection is short of — a faster first byte, a fairer shared server, and an honest last word when a flow dies.

| # | method | state | notes | supported today by |
| --- | --- | --- | --- | --- |
| 175 | TLS resumption that survives a restart and the LRU | planned | `tls/rustls_backend.rs`: disk-backed resumption; early data refuses by name; 0-RTT is QUIC row 72. | `tls/rustls_backend.rs` |
| 176 | Carrier lane pre-warm pool | planned | the client holds K idle carrier sessions — dialled, handshaked, carrier-opened — hands one to the next flow and refills asynchronously, so a burst's first packet pays no TCP+TLS+carrier open. The xdrive per-store lane pool (row 35) and xhttp's kept-alive lane are the single-carrier precedents; this is the seat under every carrier at once | — |
| 177 | MPTCP carrier (`IPPROTO_MPTCP`, RFC 8684) | planned | a TCP-carrier flow that walks from wifi to cellular without a redial, in the kernel, with transparent fallback to plain TCP where MPTCP is absent (every Windows build takes the fallback). Row 166 rebinds at the app layer and row 71's MPQUIC needs a QUIC stack; Leaf's `mptp` (row 135) is userspace framing over several lanes, kernel MPTCP needs neither | Leaf `mptp` (carrier fronts, row 135) |
| 178 | Fail-closed TUN kill switch | planned | the native TUN (row 32) opens a device and touches no route table; the switch owns the routes it adds, pulls them when the lane they feed dies inside one budget tick (row 162), and reclaims them on exit — an app is never handed a dead tunnel that quietly falls back to bare egress. A keep-routes-on-failure escape hatch is not carried yet | native TUN row 32 |
| 179 | Weighted fair-share scheduler per user or inbound tag | planned | token buckets per authenticated user with an interactive priority band, so one user's bulk download cannot starve another's VoIP on a shared server. xray-core has no bandwidth fairness at all; row 159 shapes a down/up ratio, not people. The identity already exists — per-inbound tags ship in row 108 | per-inbound tags row 108 |
| 180 | Hot config reload with a drained old generation | planned | SIGHUP or the commander RPC (row 113 is that seat) swaps in a new generation: new dials read the new config, live sessions finish on the snapshot they dialled with, and the swap prints a per-tag diff. Today a config edit means a restart, and every flow dies with it | commander RPC row 113 |
| 181 | Close-verdict journal: why every flow ended, in one line | planned | `budgets.rs` names the ten waits (row 162); row 173 is the operator seat. The per-flow verdict is missing. | `budgets.rs`; interference probe row 173 |

### Conformance, per row

The oracle names live in `upstream/pins.toml`; `scripts/run-upstream-suite.sh` is the checker. Four pins are enabled — `zeronet` (9 `xray_oracle` tests), `xray-rust` (24 interop tests), `xray-rust-hysteria` (1 client test), `xray-core` (48 gated tests, launched via `go -overlay`); the other twelve print `SKIPPED` with the enabling rung. `conformance.yml` maps all 73 xray-core scenario tests family by family without gating; the map at this pin answers 43, with 21 failing and 9 carrying no verdict, and the gate names the 43 green scenario tests plus five commander tests, so an unserved family is a map row not a red job. Suites run in CI only; each remaining oracle row becomes a rung exactly when the feature it names ships.

Sixteen upstream pins, all resolving and re-derivable by `scripts/fetch-upstream.sh`, licence-clean for reading: `xray-core`, `sing-box`, `amneziawg-go`, `amnezia-client`, `xray-rust`, `xray-rust-hysteria`, `xray-core-rust`, `pattng`, `zeronet`, `mqvpn`, `aether`, `zeptun`, `slipstream`, `quiche`, `leaf`, `lxbox`. Read but not pinned: `CottenDNS`, `MasterDnsVPN`, `mlmvpn_android`, `SlipNet`, local `configer`. Pins naming the same commit of the same repo are read from one checkout: `xray-rust` clones it and `xray-rust-hysteria` links to it, which is what `upstream/manifest.toml` records as `shares`.

## Layout

```
crates/ferrox-core       record layer, ChaCha20, AES-GCM, TLS interface + rustls, protocol parsers, transport superset, failure taxonomy
crates/ferrox-bench      counting allocator, gates, benchmark report, comparator
crates/ferrox-app        ZeroNet-compatible app on ferrox-core (MIT)
crates/ferrox-prompt     roadmap advisor; reads prompts.md, the only place a slice is written down
docs/function            one page per connection method: counts, data-path graph, CI scope
upstream/                pins plus derived reading copies, re-fetched by scripts/fetch-upstream.sh
scripts/                 pin checking, upstream fetching, gate and policy checks, count manifests
```

## Driving this with an agent

The roadmap is `crates/ferrox-prompt/prompts.md`: reusable templates, each filled from the live matrix here and the pins in `upstream/pins.toml`.

```bash
cargo run -p ferrox-prompt -- next        # the slice, the reason, prompt → clipboard
cargo run -p ferrox-prompt -- issue 661 # a P0/P1 regression prompt, filled and copied
cargo run -p ferrox-prompt -- list        # roadmap progress and what is ready now
cargo run -p ferrox-prompt -- check       # is the library still coherent?
cargo run -p ferrox-prompt -- rows        # the matrix rows a slice can be about
```

`next` records each (template, matrix row) pair in `.ferrox/slices.log` and points the same template at the next outstanding row, walking the matrix toward completeness. A row can also be picked by hand: `render 1 --row A13` renders one template for one row, and `next --row A13` lets the advisor choose the template that draws it. Each handout names the worktree the slice runs in; create it with `scripts/new-worktree.sh`. Pinned checkouts under `upstream/` are for reading only; a duration is evidence only from a named runner.

## Contributing

```bash
./scripts/new-worktree.sh <name>      # worktree with a debug-only copy-on-write warm target
./scripts/claim-target.sh             # claim/re-clone this worktree's target from the seed
./scripts/link-shared-target.sh       # repair config/upstream links (--all claims every worktree)
./scripts/gc-target.sh --lean --apply # drop release/doc/incremental from worktrees
./scripts/gc-target.sh --apply        # reclaim dead incremental sessions and stranded target dirs
./scripts/fetch-upstream.sh           # only what the links missed
cargo run -p ferrox-prompt -- next    # the slice
./scripts/check.sh --fast             # fmt, clippy and tests while iterating
./scripts/check.sh                    # everything ci.yml runs, before the push

cargo run -p ferrox-bench -- --config 'vless://...'   # the comparison table for a link
cargo run -p ferrox-app -- check 'vless://...'        # parse offline; `run` dials TCP, sends nothing
```

Worktree first, so branches never share a working tree. Re-run the fetch whenever `upstream/pins.toml` changes under you.

## Licence

`MIT OR Apache-2.0` — see `LICENSE-MIT` and `LICENSE-APACHE`. Every dependency permits both; Apache-2.0 adds the express patent grant a cryptographic core should carry.

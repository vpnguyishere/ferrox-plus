# Ferrox prompt library

Twenty-one reusable templates. `ferrox-prompt` fills each one from the live matrix in `README.md` and the pins in `upstream/pins.toml`, so `next` names the concrete row to work on rather than a hand-transcribed idea; `issue <number>` fills the one template that takes a regression issue. If the tool and these files disagree, the files are right — that is why `ferrox-prompt check` is a CI step and `tests/contract.rs` locks the properties below.

## Grammar

One `## P<n> · <title>` section per template, ids `1..=n` with no gaps. Required lines, `check` fails if one is missing:

| line | meaning |
| --- | --- |
| `**When to use:**` | the situation that calls for this slice |
| `**Status:**` | `todo`, `doing`, `done`, `blocked`; a template stays `todo` because it is a standing kind of work |
| `**Leverage:**` | 1-5, the advisor's ranking key |
| `**Effort:**` | `small`, `medium`, `large`; ties break to the smaller one |
| `**Gates:**` | semicolon-separated checks that must pass; wrap a command in backticks so it reads as one |
| `**Targets:**` | `open`, `implemented`, `all`, or `none` — which matrix rows the template draws from |

Optional: `**Depends on:**` (prompt ids), `**Touches:**` (paths; `+` prefix for one created), `**Random weight:**` (0-9, 0 excludes it from `--rotate`), `**Prompt protocol:**` (a rule that layers on top of the shared one). Only `**Status:**` is meant to be edited; the advisor records progress via `set-status`.

A body is the single fenced `text` block in the section — a second fenced block is an error, not a fallback. Seven blanks fill automatically; any other `{name}` the tool refuses to invent and prints the command to supply instead:

| blank | source |
| --- | --- |
| `{method}` | the chosen row's method name |
| `{index}` | its `#` in the matrix |
| `{section}` | the table letter (`A`..`N`) |
| `{state}` | its verdict cell, verbatim |
| `{page}` | its method page, or the page its slug suggests |
| `{target}` | its key — `{section}{index}` |
| `{references}` | the pins relevant to that row: the `always` set plus any whose `name` or `topics` keywords appear in the row's line |

`next` picks the first row of the template's target class the ledger (`.ferrox/slices.log`) has not served to *this* template, records it, and renders the body. Calling `next` again moves on. For `open` templates the candidates are ordered nearness-to-done: a row that already links a method page goes before a `planned` greenfield one, because finishing the missing half of something already on the wire is the cheapest parity win. `implemented` and `all` templates are offered in plain matrix order.

A row can also be named by hand — `--row A13` for its key, `--row 13` for its number, `--row quic` for part of its method name — and `rows` lists the matrix. A template draws only a row of its own class, so an open template refuses a shipped row and names the templates that take it.

A row's verdict is read from its state cell alone: `implemented`, `in tree`, or `both roles` with no `planned`/`not carried`/`not parsed`/`refused` negation beside it. Everything else is open, including a half-role. Neighbouring columns never flip a verdict.

Add-ons are one line each: `**Add-on — <slug>:** <extra instruction>`. Paths under `upstream/<name>/` are pinned reading copies fetched by `scripts/fetch-upstream.sh`; they never appear in `**Touches:**` and are never committed. `{references}` is drawn per row from that pin file — every `always` pin, plus every pin the row's own line names or hits one of its `topics` keywords, so a QUIC row asks for quiche and an unrelated row does not, with the whole list as the fallback when nothing matches — which keeps "compare against the best implementation" reading the pins rather than a hand-kept sentence.

Every handout carries the shared protocol, so a template says only what it adds: `check` refuses a `**Prompt protocol:**`, body or add-on that runs five content words with the protocol, and warns when two templates echo each other for six. Code spans, `{blanks}` and function words are not counted as evidence.

## Shared protocol

```text
You are working on Ferrox, a from-scratch proxy core. Two claims define it and both are checked: output is byte-identical to the implementation it replaces, and it is not slower at any measured length. A change that alters the bytes on the wire to buy a syscall is neither, and it does not land.

Ferrox is a superset: any well-formed config xray-core accepts must run here, including every surface the tree currently refuses. An unimplemented surface is planned work, never a terminal verdict; a refusal is a temporary reason to close the gap, and the slice that reaches it removes it. Only malformed or unsafe input fails closed.

The bar is the best implementation, not a working one. References are the pins in `upstream/pins.toml`: learn how each does the thing, find where it copies, branches, refills, or allocates needlessly, and write the smaller, faster, leaner thing that is bit-identical. Rewrite, do not copy — no upstream line or test enters this tree.

Trust neither this tree nor a reference to have found the floor: hunt the wins, try ideas no template names, keep only what a count proves, and revert a measured regression with its arithmetic on the page. One fewer proven operation is a win worth landing. Faster, safer, leaner, or it does not land; counts prove, durations suggest.

A claim is either checked by something that runs or it is not made — name its checker, or say in the same sentence that no such check exists. A count nobody has measured stays `UNBLESSED`, never quoted as a figure, and a number enters `scripts/expected-ops.txt` only after reading the diff that moved it. A copy or allocation is proved by pointer identity, not by reading the code: the returned slice's base lies inside the caller's buffer, that buffer's pointer does not move, its capacity does not grow. A byte-level test cannot see a copy — the bytes are identical either way.

Before landing a rewrite, ask what the worst input does: the length that is not a multiple of the vector width, the window already full, the cursor this change moves. The arithmetic finds the regression a green suite hides.

Local before every push: `./scripts/check.sh` runs fmt, clippy, doc, the policy checks, exact operation counts, and the workspace tests. Never local: anything connection-dependent — benchmarks, parity, upstream suites, Miri — because every contributor sits behind a VPN and a proxy, so a local dial measures a tunnel, not the reference. Where the counting userspace cannot be provisioned the count stays `UNBLESSED`, never a silently skipped gate, and no slice waits on `ops.yml` for it.

Simpler with less code wins every tie at equal performance: no abstraction with one implementor, no second way of doing something, no debt left for a later slice. Unsafe only for a measured win; if the safe form ties, the safe form ships.

Report tersely: what changed, what was measured with numbers, what is still open. A slice that fails is worth more than one reported done that quietly skipped half its gates. Fixes leave no trace — one line of comment per item at most, no TODO, no changelog.

Do not widen the slice. If it exposes a larger problem, tighten an existing prompt here by a surgical edit of ten words at most; add no new template, add-on, or prompt.
```

## P1 · Land an open method row

**When to use:** The matrix has a row the tree does not implement, and moving it from planned or one-role-only to shipped is the largest single step towards parity with the references; a surface the tree currently refuses is planned work, not a scope boundary.
**Status:** todo
**Leverage:** 5
**Effort:** large
**Targets:** open
**Gates:** `cargo test --workspace --all-features`; CI: `conformance.yml`; CI: `bench.yml`; CI: `parity.yml`
**Random weight:** 8

```text
Implement {method} — matrix row {index} of table {section}, currently "{state}". Finish the whole row, both roles where the method has two. Take the best idea from each of {references}. Prove byte-identity before any speed claim, and where a reference ships a suite with a seam to inject `ferrox-app`, run it unmodified in `conformance.yml`.
```

**Add-on — both-roles:** If the state cell concedes one role only, the missing role is the whole slice.
**Add-on — refused-by-name:** A config naming an unimplemented surface refuses with a reason for now; that refusal is a temporary gate, and this slice removes it. Never treat a refusal as scope or as the end state.
**Add-on — connect-ip-terminate:** When the row is MASQUE CONNECT-IP (matrix row 21) the client and the two-way codec are already shipped — the Foxy `h3` lane dials over HTTP/2 and quiche HTTP/3, and `crates/ferrox-core/src/foxy/connectip.rs` writes and reads every capsule (`address_assign_encode`, `route_advert_encode`), proven inverse to their readers byte-for-byte. The two open roles are each their own slice: (a) a proxy that *terminates* a tunnel — read `upstream/xray-core/transport/internet/masque/connectip/` and `upstream/mqvpn` — whose open work is the address pool and IP/ICMP forwarding to a privileged `tun`, which no share-link row reaches; (b) a standalone `Carrier::Masque` VLESS outbound off the account. Land the client row, then route each of those as a separate `next`; never fold a privileged device write into a codec slice.
**Add-on — pattng-tls-shaping:** When the row is the PattNG `unsafe-*` fingerprint / `cipherSuites` cluster, read `upstream/pattng/V2rayNG/app/src/main/java/com/v2ray/ang/core/TlsSettingsCheck.kt` first: "unsafe" means the stock stdlib ClientHello that honours the user's `cipherSuites` and offers `alpn` as written, not uTLS spoofing, so `ferrox-core`'s existing rustls hello is already the no-spoof half (`reality.rs:978`). Rows 18, 19 and 4 landed the `cipherSuites` parse, `--allow-unsafe-fp` and `--allow-plaintext-public`; the only rung still open is applying the alpn-as-written policy to every TLS outbound (`reality.rs` pins empty alpn). A rustls hello can never be byte-equal to the reference's Go `crypto/tls` one across the whole surface, so this row's byte-identity claim is gated per field: the `cipher_suites` field has a byte checker (`a_crafted_list_reorders_the_dialer_hello_to_the_reference` captures the real hello via `write_tls`), while the fingerprint cluster as a whole is replaced by the `*_selected_fingerprints` rows in the `xray-rust` pin's `conformance.yml` seam, which run the reference client against `ferrox-app` unmodified — name that checker instead of writing a whole-hello byte claim.
**Add-on — pattng-tls12-advertise:** Row 18's TLS 1.2 half has landed on two lanes: `rustls` carries the TLS 1.3 trio plus ring's six TLS 1.2 AEAD ids, and a BoringSSL lane (already linked for ECH) takes the whole handshake when the list names a suite ring has not — ECDHE CBC (`c009`, `c00a`, `c013`, `c014`, `c023`, `c027`), static-RSA (`002f`, `0035`, `009c`, `009d`) and `000a` — so either role negotiates what it named. Named ceilings, not claims: a legacy list that also offers TLS 1.3 puts BoringSSL's trio before the 1.2 ids where `crypto/tls` appends it, so only the 1.2 ids match, while a list with no TLS 1.3 id is capped at 1.2 and matches whole; an ECH config keeps the rustls lane, so a list naming both does not advertise the CBC id; the legacy lane keeps no session cache, so `enableSessionResumption` does not carry there; and RC4 (`0005`, `c007`, `c011`), ECDHE-3DES (`c012`) and `003c` reach neither backend. Do not claim a whole-field match: the capture tests assert the actual fields and the SCSV split.
**Add-on — tun-native-device:** Row 32's consume path landed: `crates/ferrox-app/src/tun.rs` reads whole IP packets off an injected descriptor (`FERROX_TUN_FD`, a pipe a test supplies so it runs on CI without root), the stream demux dials through `serve_connect`, the datagram demux rides `serve_socks_udp` on one association per device, and `scripts/tun-oracle` golden-diffs the (target, payload) dial sets both ways (`the_datagram_dial_set_matches_the_pinned_stream`). What stays open, each its own `next`: the ICMP responder answers only an IPv4 echo request (`an_icmp_echo_request_is_answered_as_a_reply`, `a_non_echo_icmp_message_is_refused`) — ICMPv6 echo, the neighbour/multicast discovery the Windows WFP path serves, and an ICMP error minted *for* a relayed flow are each their own slice — and no datagram over the device MTU or an empty one is in `script.txt`, so those two shapes stay the spec's rather than a golden's. The privileged open (`/dev/net/tun` + `TUNSETIFF`, `utun`, Wintun) is compile-checked only, since no CI runner holds `CAP_NET_ADMIN` — name that no run-check exists rather than claiming the interface works. A device carries no wire byte-stream to diff, so this row's identity claim is never an `UNBLESSED` op count but the (target, payload) dial-set differential. Read `upstream/sing-box/transport/device`, `upstream/xray-core/proxy/tun`, `upstream/zeptun` and `upstream/zeronet/crates/zero-tun` for the technique.
**Add-on — finalmask-refused-types:** Matrix row 34 shipped the one TCP mask this tree could prove byte-for-byte on a socket — `fragment` — and refuses the other three names `tcpmaskLoader` accepts (`upstream/xray-core/infra/conf/transport_finalmask.go:73-76`): `header-custom`, `sudoku`, `xmc`. The refusal is the gate today (`crates/ferrox-app/src/config.rs::tcp_mask`, witnessed by `a_tcp_mask_this_tree_cannot_arm_is_refused`); each mask is its own `next`, and none of them inherits row 34's conformance seam — the pinned `xray-rust` suite has exactly the two `fragment_finalmask_tls_*` rows, so a new TCP mask's checker is a scripted byte differential in the `crates/ferrox-core/src/kcp/oracle.rs` shape against the pinned Go writer, plus `upstream/xray-core/transport/internet/finalmask/tcp_test.go` as the behavioural spec, and the page must say in the same sentence that no pinned interop row covers it. Ordered by size: (a) `sudoku` (`finalmask/sudoku/`) is a fixed-shape fake header, so it lands as a stage in the same `Chain` and needs only the encode/decode differential and one wire test; (b) `header-custom` (`finalmask/header/custom/`) is the general masquerade the old `tcpSettings.header` spelling already reaches for http — the work is the configurable case/append/`connection` form, and it must not fork a second header path (`carrier-httpheader` owns that surface); (c) `xmc` (`finalmask/xmc/`) carries a *profile* with usernames (`xmcUsernamePattern`, 3-16 `[A-Za-z0-9_]`) and per-case shapes, which is a subsystem and a config surface of its own — the largest of the three, and the one to route last. The UDP families upstream also lists (`noise`, `realm`, `udphop`, `xdns`, `xicmp`, and salamander ahead of a TCP stream) are a second row's work: this tree's udp masks are the `mkcp-legacy` chain on KCP (`crates/ferrox-core/src/kcp/mask.rs`) and hysteria's datagram salamander (`carrier-hysteria`), and neither is a general udp mask chain. Do not widen row 34 to cover any of this: the row's own gates are the two pinned rows, and a mask that fails to split the hello on the wire makes those rows red rather than the new one.
**Add-on — hysteria-obfs-masquerade:** Hysteria v2 (matrix rows 20/134) now reaches every auxiliary surface the pinned trees agree on — the UDP lane, salamander and gecko obfs, client port-hopping, and the masquerade site including an `https` origin. What stays out, each a genuine ceiling rather than a gap: a dial naming port-hop and gecko together is refused at `connect` because neither alone carries the other's bytes; the throughput knobs `brutal`/`force-brutal`, `up_mbps`/`down_mbps` and `bbr_profile` change pacing and durations, not a wire byte, and quiche ships no brutal sender to pace as, so they are accepted-and-ignored and named on `docs/function/carrier-hysteria.md`; and the sing-box-only `realm`/`server_url`/STUN discovery (`upstream/sing-box/protocol/hysteria2/realm.go`, `realm_server.go`) is a registration-and-NAT-traversal protocol absent from `upstream/xray-core/transport/internet/hysteria/config.proto` and from zeronet, so with no second implementation to pin its bytes against it is not a minimal-subset wire method — route it as its own slice, never folded into a datagram or obfs slice.

## P2 · Make a shipped method faster and leaner

**When to use:** A row is implemented — the standing hunt for maximum throughput and minimum CPU now applies to it.
**Status:** todo
**Leverage:** 5
**Effort:** medium
**Targets:** implemented
**Gates:** `./scripts/check.sh`; CI: `bench.yml`; CI: §ops.yml; CI: `compare.yml`
**Random weight:** 9

```text
Move {method} — matrix row {index} of table {section}, state "{state}" — towards the best known implementation among {references}. Throughput and leanness at bit-identical output: fewer retired instructions, fewer copies, fewer branches. Think in eliminated work, not added code: factor the math, fuse passes that touch the buffer twice, hoist per-record dispatch, narrow a parse that re-checks what a caller already checked. Re-measure the exact count with `scripts/count-ops.sh`.
```

**Add-on — shared-codec-scope:** When the row's codec lives in a `ferrox-core` module no page owns because a second method calls it too (`early_encode_into` is also `proxy.rs::b64url`'s encoder for a REALITY x25519 key), do not add that module to the page's `paths` or `symbols` to narrow the run: a claim narrows the plan to one carrier and hides the other caller. Leave it shared, take the wide plan, and name the second caller in the page's `CI scope` prose so the next reader knows why the run is wide rather than assuming it is sloppy.
**Add-on — handshake-entropy:** A carrier's per-connection randomness is a syscall the data path never sees: the ws client asks `getrandom` for the 16-byte key on every dial while `fresh_mask` already pulls 512 bytes at a time into a thread-local. Batching the key the same way is real, is that carrier's own row rather than the row whose handshake happens to ride in the same buffer, and is gated on the syscalls per connection over a loopback dial — so route it to that row's next `next` instead of folding it in.
**Add-on — carrier-stage-drop:** A `BufReader` wrapped around a carrier to smooth a codec that asks its frame header and its payload separately is a stage: every downlink byte crosses user space twice, and because a carrier caps a read at the record it is inside, the only widths the socket ever shows are the carrier's own records — so a stage's capacity is invisible at the socket and the counter has to sit between the carrier and the codec to see the ask the codec actually made. The wrap also falsifies the codec's own copies rows whenever its checker drives the codec directly and never enters the wrap — audit the gate before the code, per the rule that the named checker has to observe the thing the row claims.
**Add-on — head-buffer-round:** The kept head reader `proxy::kept_head_rounds` is shared by `ws`, `xhttp`, `httpupgrade` and `httpheader`, so its per-handshake allocations are shared infrastructure, not one carrier row's hunt. It opens at `Vec::with_capacity(HEAD_ROUND=512)` and `reserve`s in fixed 512-byte rounds, so a camouflage head over 512 B (an ordinary GET already carrying `Host`+`User-Agent`+`Accept` crosses it) reallocates and re-copies the bytes it had already read; the capacities double from 512 B — 512, 1024, 2048, 4096, 8192 — so a head at or under one window is one allocation and an 8 KiB head is five (15872 B of requests in all), and that growth is already amortised-optimal for a length the reader cannot know. Two ways to take the extra allocations out, each its own slice with its own gate, never folded into the row that only notices it: (a) pre-size the first round to cover a realistic head (raise `HEAD_ROUND`, or `with_capacity` a single-read head size) so the common head is one allocation while the syscall quantum stays modest — gated on an allocation count held steady over a dial cycle in `ferrox-core`'s counting binary, and argued against the page's own rule that `HEAD_LIMIT=8192` is a limit not a buffer, because pre-sizing the whole window is the 8 KiB-per-handshake over-allocation that rule rejects; or (b) sing-box's pooled-buffer shape (`transport/v2rayhttp`), which needs single-thread ownership the way the pool-owner add-on states — the head `Vec` is handed to `HeadReader`/`UpReader` and lives for the whole connection, so a cross-connection pool only reclaims when one thread serves connections back to back, and the per-`HeadReader` drop-to-`Vec::new()` on final drain that `httpheader` and `httpupgrade` now do is the safe half already landed.

## P3 · Take a shipped method's memory footprint down

**When to use:** A row is implemented and its steady-state allocations, buffers, or per-record copies still scale with traffic rather than with the connection.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Targets:** implemented
**Gates:** `./scripts/check.sh`; CI: `bench.yml`; CI: §ops.yml
**Random weight:** 6

```text
For {method} — matrix row {index} of table {section} — remove work that is generated and thrown away: a per-record buffer that could be reused, a second copy of a payload already in the caller's buffer, a zero-fill before a read that overwrites every byte, a `Vec` that reallocates under steady traffic. Gate the allocation claim on `capacity()` held steady over a push/drain cycle, and name the pass that got worse if there is one.
```

**Add-on — pool-owner:** When one buffer is filled by one thread and drained by another, the pool lives in the object both touch; the parse order respects that single owner.
**Add-on — tls-config-once:** A rustls `ClientConfig` is rebuilt on every TLS dial (`RustlsProvider::connect` → `config()`), where xray's `GetTLSConfig()` and sing-box's transport both build theirs once per outbound and hand the same value to every connection; memoise the built `Arc` by the config's security-relevant bytes (roots, alpn, pins — never `server_name`, which is per-connection) so a repeat dial pays a key clone and an `Arc` bump instead of re-parsing every DER and rebuilding the verifier and cipher Arcs, gate it on the allocation count in `ferrox-core`'s counting test binary, and because it sits in the shared session layer every `*-tls` carrier funnels through, it is its own slice rather than one method row's hunt.
**Add-on — per-datagram-aes-schedule:** Every AES-GCM datagram carries a fresh salt, so `Cipher::from_master_key` runs HKDF-SHA1 and boxes a whole new `Aes128Gcm`/`Aes256Gcm` engine — key schedule and GHASH table — per datagram. A per-thread cipher is impossible (the key *is* the salt) but a rekey in place on the engine already in hand is not, and it would remove the per-datagram `Box` and the schedule build. It is not one UDP method row's hunt: the seam is a rekey surface in `crates/ferrox-core/src/aesgcm`, whose scope covers the record layer, so it lands as its own slice gated on an allocation count in `ferrox-core`'s counting binary held steady over a datagram stream, never on a wall clock.
**Add-on — arena-header-gap:** The KCP send arena keeps an 18-byte header gap before each payload so a segment is contiguous and the payload never crosses a staging buffer; `SendingWindow::push` reserves that gap with `arena.resize(start + DATA_HEADER, 0)`, and `write_data_header` overwrites all 18 bytes at flush before the range is read — the exact zero-fill-before-an-overwriting-read the row-14 template names, and the only generated-and-thrown-away operation left in the method now that every buffer is reused and every copy is proved gone by pointer identity. A safe `Vec` cannot extend its length without initializing what it appends, so taking the fill out is not a safe edit: it needs the arena as `Vec<MaybeUninit<u8>>`, rippling through `emit_slice`'s writer handoff, `trim`/`drain`, and the pointer-identity witness. That removes about 18 stores per segment (roughly 170 k/s at 100 Mbps), an instruction count no checker here can attribute to `push` — `push` is not a `method-ops` symbol, it inlines into its caller at release, and the slice host has no valgrind — and the unsafe has to be shown sound under Miri, which is `safety.yml`-only. Under *unsafe only for a measured win* the fill stays in row 14; the uninit-arena refactor is its own slice, gated on a `SendingWindow::push` retired-instruction count measured on the Linux CI runner plus Miri green, never on a wall clock.

## P4 · Prove a shipped row bit-identical to the references

**When to use:** A row is implemented but its byte-identity is argued from the source rather than swept against the pinned copy — the check that must run before any speed claim on that row.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Targets:** implemented
**Gates:** CI: `parity.yml`; CI: `bench.yml`; `cargo test --workspace --all-features`
**Random weight:** 4

```text
For {method} — matrix row {index} of table {section} — replace the argument with a differential sweep against the pinned reference: every length and every offset the method can see, both sides of every group boundary where a vector rung could overrun. Keep the key or nonce material such that a permuted implementation cannot pass. Name both backends in every row of the report; if one build dispatches to scalar against the reference's vector path, say so.
```

**Add-on — forged-input:** A malformed or wrong-tag input must leave the buffer exactly as it found it; a sweep that only feeds valid input proves the happy path.
**Add-on — query-rewrite-spelling:** When the reference strips a query parameter and re-encodes what remains through Go's `url.Values.Encode()` — which sorts by key and re-escapes — the rewrite's *spelling* is part of the wire, and a rewrite that keeps the original order keeps different bytes. No checker in this tree sees it while every server compares `URL.Path` without the query (`request_path` strips it here too), so the divergence only surfaces behind a proxy that routes on the full URI. Prove it or name it: a differential over unsorted multi-parameter paths against the pinned `url.Values` encode, or an explicit sentence on the page saying which spelling ships and why no reference peer can tell.

## P5 · Rewrite one parser or framer to the best form

**When to use:** The bytes of a method are right but the code that produces or reads them is not the smallest, cheapest thing the references imply.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Targets:** all
**Gates:** `cargo test --workspace --all-features`; `./scripts/check.sh`; CI: `compare.yml`
**Random weight:** 5

```text
Read the parsing and framing for {method} — matrix row {index} of table {section} — against {references}, and rewrite this tree's version cheaper at the same bytes. Prove the validator by the same counts as the parser — checking code is code too, and it runs on every frame.
```

**Add-on — seed-fuzz:** Feed untrusted bytes through every entry point on a seeded corpus and assert no panic.

## P6 · Bring a method page up to the four-number standard

**When to use:** A row's data path is real but its page under `docs/function` is missing, or states counts with no checker named.
**Status:** todo
**Leverage:** 3
**Effort:** small
**Targets:** all
**Gates:** `./scripts/check.sh`; `bash scripts/check-method-docs.sh`; CI: `ci.yml`
**Random weight:** 3

```text
Write or bring up to standard {page} for {method} — matrix row {index} of table {section}, state "{state}". Every connection-method page carries the same four numbers — ops, syscalls, memory copies, time — each with the name of the thing that produces it, a `graph TD` of the data path, and what was removed against {references}. The numbers live in exactly one place, `scripts/method-counts.txt`; the page cites the manifest row and does not keep a second copy. Name what was not removed as openly as the wins. Carry the scope block with the page: `paths` for the files it owns, `symbols` for every item of a shared file that is its own — a rung in `proxy.rs`, a resolver in `config.rs` — because a method whose code lives in the relay is recognised by nothing else, then `scenarios`, `oracle` and `go`, and `engines` only where its own cell already showed a comparator serving it nothing.
```

## P7 · Wire a conformance seam for a shipped row

**When to use:** A method is implemented here and a pinned reference ships a suite for it, but nothing runs that suite against `ferrox-app`.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Targets:** implemented
**Gates:** CI: `conformance.yml`; `cargo test --workspace --all-features`
**Random weight:** 3

```text
Give matrix row {index} of table {section} — the implemented method {method} — a conformance leg: find the suite in {references} that exercises it, add, enable or widen the `[sources.*]` seam in `upstream/pins.toml` that injects `ferrox-app`, and run that suite unmodified in `conformance.yml`. Prove the leg reached this binary — name the seam and the test count. Green here plus red there is not done; if no `seam` in `upstream/pins.toml` reaches this binary, say so plainly.
```

**Add-on — pin-honesty:** Any pins edit carries the real rev from a resolved ref; never fabricate one to satisfy a gate.

**Add-on — seamless-byte-row:** When the row's reference tests are in-package Go with no binary seam — matrix row 35 is that case, since `upstream/xray-core/transport/internet/xdrive/*_test.go` calls unexported constructors and no pinned suite names an xdrive test — the page names the absent seam and the byte-identity gate stays in-tree, recorded request bytes over a loopback fake; and the seam worth building afterwards is the reference's own `local` store over one directory both binaries can see, which needs no network and no token: the xray-baseline job's binary serves an xdrive `local` inbound on a shared folder while `ferrox-app` dials it as an outbound and echoes through, then the roles swap, so the object names, the `%09d` sequence, `.end` and the hole rule are proved against the reference rather than restated. That harness is its own slice with its own job, never folded into the row that first shipped the transport.

## P8 · Find the work the tree does and discards

**When to use:** The standing RAM/CPU hunt on a shipped row — where something is computed, filled, or locked and then thrown away or re-done before the value is ever used.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Targets:** implemented
**Gates:** `./scripts/check.sh`; CI: `bench.yml`; CI: §ops.yml
**Random weight:** 5

```text
Audit the hot path of {method} — matrix row {index} of table {section} — for work done and discarded: a value computed then overwritten before anything reads it, a lock taken twice for one wait, a buffer sized for the worst case on the common small one. For each finding, remove it or prove it load-bearing against the leanest shape in {references}. Before writing a test that reconstructs a quantity, look for the counter already lying around as state.
```

**Add-on — write-all-slices:** A framer's staging Vec that copies the caller's payload so a head and a trailer can share one record is not fixed by moving the copy to a stack buffer; fix `RecordAlignment::write_all_slices` at the provider layer to go through `write_vectored`, override it at every wrapper in the caller's path (the record-layer wrappers and the session types both need an arm that reaches the coalescing impl), and hand the framer's head, body, and trailer over as three slices. The default that iterates `write_all` per part is right on a raw stream and wrong under TLS, where each write_all becomes its own record. Landed since: the raw stream's arm is `proxy::write_all_parts`, one `writev` or one `WSASend` for any list up to sixty-four segments, so a frame's head, envelope and payload no longer split into one `write_all` each off unix and a gathered batch of h2 frames costs one call — `carrier-grpc writes-per-relay-read 1`.

## P9 · Prove a vector rung on the ISA it compiles for

**When to use:** A SIMD or width-generic rung is in the tree and a CI runner whose architecture is named has not yet run the differential on it.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Targets:** implemented
**Gates:** CI: `bench.yml`; CI: `safety.yml`; `cargo test --workspace --all-features`
**Random weight:** 3

```text
For {method} — matrix row {index} of table {section} — confirm each width backend of its vector rung means what it claims on a runner whose architecture the job names: lane count, chunk-to-block layout, the store that writes consecutive output bytes with no transpose. The layout is the part worth reading twice — a backend that produces the right bytes through the wrong layout is right by accident, and the next change makes it wrong. Make the layout a named constant or an assertion, not a comment.
```

**Add-on — miri-boundary:** Miri interprets the safe-Rust ladder but not `core::arch` intrinsics; say which rungs Miri covered and which the differential covers instead.

## P10 · Prove the engine does less at a length nobody measured

**When to use:** A rung's counts are argued rather than blessed, or a length boundary has never been swept — turning an `UNBLESSED` claim into a number a runner reproduces.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Targets:** implemented
**Gates:** CI: §ops.yml; CI: `bench.yml`; `./scripts/check.sh`
**Random weight:** 3

```text
For {method} — matrix row {index} of table {section} — measure the operation count of its hot symbol with `scripts/count-ops.sh` across every length and boundary the method reaches; read `scripts/method-ops.txt` for the CI number before deciding anything. A connection-dependent count belongs to `ops.yml`, not to a laptop run. If the runner cannot provision the counting userspace the count stays `UNBLESSED`: never quote a figure, never wait on `ops.yml` for it.
```

## P11 · Make a test that loses to the runner fail on a defect

**When to use:** A test for a shipped row goes red one run in several and green otherwise — it is asserting a quantity the scheduler or the runner moves, not a property of the code.
**Status:** todo
**Leverage:** 3
**Effort:** small
**Targets:** implemented
**Gates:** `cargo test --workspace --all-features`; `./scripts/check.sh`
**Random weight:** 4

```text
Take the flaky test on {method} — matrix row {index} of table {section} — and make it fail only on a defect. Drive the counted quantity from an in-memory stream that always answers the whole buffer, where the number is exact; over a real socket assert only the bytes. A loopback test cannot gate a syscall count and a scheduler-dependent count is not a gate at all — move the assertion to where it is deterministic and leave the socket test proving the wire.
```

**Add-on — replay:** Seed any corpus-dependent test so a red run prints the case that broke it and replays on any machine.

**Add-on — harness-bound:** Before a bench row is read as an engine's, read the cell's own `harness_ceilings_mib_s`: throughput at a small fraction of it for *every* engine in the cell is the instrument's bound, not the comparators' — that is how every upload cell of `vless-raw-up-1` read 616 MiB/s for three engines at 14% of a 4 294 MiB/s pipe while the same build's download cell read 2.115× better (#166 replaced the sink's per-byte modulo with a run compare). A ceiling row is one generator into one reader and the relay rows are two hops, so it is read as a floor. A cell can also be bound by the runner rather than by any part of the harness: `vless-raw-duplex-8` on `macos-15` (8 connections full-duplex, 512 MiB each way, 3 logical CPUs) failed every engine in every repeat with `No buffer space available (os error 55)` on the upload writes and `Connection reset by peer` on the reads at a 481–671 MiB/s ceiling, and the run-compare sink (#166) left it exactly as broken, so that row is a kernel-buffer fault rather than a comparison and is not priceable on that runner class. `benchmark-matrix.yml`'s `only` input intersects its comma-separated substrings rather than unioning them, so a multi-scenario dispatch silently plans zero cells: dispatch one scenario per run.

**Add-on — cpu-split-tick:** `compare_process::check_split` drops a run whose `cpu_user_millis + cpu_sys_millis` differs from its `cpu_millis` by more than 1 ms, and on Windows the two cannot be made to agree: `ps::win32::sample` rounds the total from the tick pair, `f(U+K)`, and each half on its own, so a sample carries its own rounding error `d = f(U)+f(K) − f(U+K)` and a run's gap is `d₁ − d₀` — up to 2 ms by construction, and a lost run is a lost pair, so a cell under two pairs reports `UNPROVEN` on the platform this tree is behind on. Nightly `39001299614` is the measurement: over its 81 Windows runs and 7 239 samples `d` is +1 ms in 1 124, −1 in 648, 0 in 5 467, and 30 of the 81 runs sit at ±1 — on the tolerance line, one sample pair from a drop, while the drop itself, the two endpoints rounding apart in opposite directions, was 0 of 81 because the tick residue keeps its sign as it drifts. Fix it by rounding each half once and making every sample's total their sum, so `d` is 0 by arithmetic and no run can be dropped for it; gate it with a fixture whose two endpoints round apart in opposite directions.

## P12 · Collapse a duplicated walk, ladder, or dispatch to one copy

**When to use:** The same config walk, header parse, ladder fork, or relay dispatch is written out in more than one file, and a change to one silently diverges from the others.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Targets:** all
**Gates:** `cargo test --workspace --all-features`; `./scripts/check.sh`; CI: `compare.yml`
**Random weight:** 4

```text
Find where the bytes or dispatch of {method} — matrix row {index} of table {section} — are written more than once across the carrier and proxy files, and fold them into one shared helper, not a trait with one implementer. Nothing on the wire or in the count moves; the line count and the divergence risk go down. Where a fork exists only because two paths disagree on one boundary, make them agree and delete the fork.
```

**Add-on — retire-dead:** A knob or code path with no consumer gets a caller in a test or is deleted — do not leave it named-but-unreachable.

## P13 · Bound a loop or handshake the socket currently ignores

**When to use:** A handshake, relay, or server drive can spin or block on a peer that goes silent — the hang is reachable in principle and no deadline stops it.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Targets:** implemented
**Gates:** `cargo test --workspace --all-features`; CI: `safety.yml`
**Random weight:** 5

```text
Give {method} — matrix row {index} of table {section} — every wait a deadline the socket cannot ignore: bound the handshake, the relay read, and the server drive that spins on an idle peer. Test it by parking the peer and asserting the loop stops within the budget, not by sleeping and hoping. A budget a peer can exhaust must refuse cleanly, not truncate or silently drop what is in flight.
```

**Add-on — deep-retry:** A carrier whose own reader loops on timeouts (gRPC, xHTTP, VMess, Shadowsocks handshakes) needs the budget inside that loop, not around it; record it as a row rather than bolting a wrapper on top. The shared primitive is the worst instance: `proxy::read_exact` treats `is_timeout` as retryable, so a caller waiting on bytes that never arrive spins forever instead of failing — which is why a lost frame in a test harness reads as a stall, not a red test — while `read_exact_head` already shows the budgeted shape, so take the wait-bound from there rather than inventing a second one. Outstanding in this shape: a carried reader disarms its own clock once the head is answered, so every protocol that then decodes its opening request through it waits unarmed — `proxy::under_handshake` is the arm, and the gRPC carrier now runs all five of its plaintext decodes through it and carries a `pinned-threads-per-silent-*-request` row per protocol. The same four protocols (`trojan`, `vmess`, `shadowsocks`, `shadowsocks-2022`) still wait unbounded behind the `ws`, `xhttp`, `httpupgrade` and `http-header` carriers, one carrier per slice, each owing a witness that reads its own arm taken away and a row on `carrier-*.md`; the websocket carrier also owes its already-armed `vless` decode a witness of its own.

**Add-on — flow-wait-with-no-bound:** In `poll_relay`, `drive` waits on both directions with no bound and `Worker::push` drops the flow when the queue lock is poisoned, so a worker parked inside `copy_all_memcpy` starves every flow queued behind it and their waits print nothing; bound the flow the way `RELAY_JOIN` bounds a leg, and prove it by parking one worker and asserting the flows behind it still end.

## P14 · Put a layer where the references put it

**When to use:** A method's bytes are right but the security layer, framing, or session lives at a different depth than every pinned reference puts it, so the next row that reuses it cannot.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Targets:** implemented
**Gates:** `cargo test --workspace --all-features`; `./scripts/check.sh`; CI: `parity.yml`
**Random weight:** 3

```text
Compare where {references} place the layer for {method} — matrix row {index} of table {section} — against where this tree places it, and move it to match if the references agree and this tree does not: the security layer outside the carrier, the session above the transport, the framer below the record. Prove the move by the byte-differential still passing and the seam a later row needs now existing; a move that shifts a byte or a count is a method change, not a move.
```

## P15 · Give a non-matrix surface a working seam

**When to use:** Engine-adjacent capability the matrix does not carry a row for — the account plane, an upstream-proxy chain, TUN/VPN modes — that parses or is described but is not reachable from a config or a test.
**Status:** todo
**Leverage:** 3
**Effort:** large
**Targets:** none
**Gates:** `cargo test --workspace --all-features`; CI: `conformance.yml`
**Random weight:** 2

```text
Take one engine-adjacent surface {references} carry that this tree names but cannot drive — the account plane, the upstream-proxy chain, or a TUN/VPN mode — and give it a working seam: wire it to a config path or a test entry point, name the reference it matches, and prove one round-trip in CI. If it genuinely cannot be reached from this tree's shape, say why plainly in the place a reader would expect the capability rather than leaving it silently half-described.
```

**Add-on — server-engine-surface:** The pinned ZeroNet tree carries server surfaces this tree cannot drive — reverse bridge/portal (`zero-runtime/src/reverse.rs`), PROXY-protocol parsing on an accept (`zero-protocol/src/proxy_protocol.rs`), the WireGuard inbound (`wg_server.rs`), transparent `SO_ORIGINAL_DST`/TPROXY dials (`zero-net/src/transparent.rs`). README table N rows 154–162 and `docs/method-superset.md` name each with its reference paths; take them one row per slice, seam first.

## P16 · Deep-optimization hunt: beat every reference, or prove the floor

**When to use:** The open-ended, high-effort pass on a shipped method — not the one clean win, but the hunt for an order-of-magnitude one, assuming the current implementation and every reference still leave the breakthrough undiscovered.
**Status:** todo
**Leverage:** 5
**Effort:** large
**Targets:** implemented
**Gates:** `./scripts/check.sh`; CI: `bench.yml`; CI: §ops.yml; CI: `compare.yml`; CI: `parity.yml`
**Random weight:** 9

```text
Make {method} — matrix row {index} of table {section} — faster, leaner and more functional than {references} put together. This is the open-ended pass: not the one clean win but the order-of-magnitude one, so push each winner to the end instead of stopping at the first.

Think like a math paper, not a patch: change the basis or the order, factor, recast the computation, and prove the new form equivalent before shipping it. Mine every lens — algebraic structure and hot inner loops; bit tricks and SIMD across every width the ladder runs; microarchitecture (cache locality, branch prediction, IPC); I/O (batching, zero-copy, vectored and kernel offloads, ring buffers, lock-free handoffs, segment offloads); outright elimination of ops, copies, allocations, syscalls, locks, atomics, branches, zeroing, checks and dead code nothing reads; and the method-specific tricks — codec tables and DFA walks, one's-complement folding where the modulus allows, varint and padding shapes, multiplexing, and the crypto primitives' hardware paths.

Prove the win or discard it: the exact count from `scripts/count-ops.sh` where the runner can provision it (`UNBLESSED` otherwise), and the benchmark gate in CI. Re-measure the byte-differential before and after — bit-identical means the block, byte, counter and panic-threshold counts are unchanged, not only the output. Where the wire shape is fixed, say so.
```

**Add-on — novel-idea:** An idea none of the lenses above names is welcome; it is proved the same way or discarded.
**Add-on — floor-proof:** If the hunt finds nothing above noise, prove the floor: record the ideas tried, each one's count, and what a reader should try next — an argued floor beats a quiet stop.
**Add-on — many-rounds:** Land one proven win per commit and keep hunting; a single diff that "optimized the method" is the end of one round, not the end of the slice.

**Add-on — httpupgrade-handshake-floor:** Row 17's rounds took the payload's round trip, one write syscall and one TLS record per riding dial, the request buffer's slack and growth, 22 bytes off the status compare, the round trip every Shadowsocks dial paid whatever the config asked for, and the `peek` round the fd handshake paid to prove a head it then re-read (`proxy::read_http_head_kept` now consumes the head and keeps the tail as the caller's prefix, and `UpReader` walks it by cursor instead of `drain`ing it); what is left there is priced, not guessed. Outstanding, in the order the arithmetic favors: (1) closed: `ws`, `xhttp` and `httpheader` each took the kept reader on their own pages, and `read_exact_head` — the record streams, which have no `peek` to lose — is that same loop now, so a head crosses user space once and its tail needs no buffer of its own except in the xHTTP accept loop, where `accept_core` parses the head and hands the tail on and a borrow of a buffer cannot outlive the move of it; `peek_head_rounds` stays for the two callers that must leave the tail in the socket — the `http` front, which hands one buffer to a `CONNECT` writer, and the Shadowsocks rung, which waits in a `peek` for the first byte of the request packet; (2) closed: the dial stages its five pieces into the dialling thread's own buffer and hands the writer a slice of it, so the allocator is entered once per thread rather than once per dial (`the_request_buffer_holds_its_capacity_over_a_dial_cycle` holds `capacity()` and the base pointer steady over twelve dials of four shapes, and `the_early_data_rides_in_one_write_with_the_request` proves the request part's base is that buffer); the five-run gather this note proposed as the way to remove the buffer outright was refused when written — on the record lane rustls' `coalesce` stacked four `IoSlice`s and heap-allocated past that, so five pieces traded the saving for one allocation per write; `carrier-httpheader` has since widened that stack to five for its camouflage gather, so the gather's remaining price is the writer's own segment list; (3) `dial_ss_httpupgrade` passed `0, &[]`, so Shadowsocks and Shadowsocks-2022 over httpUpgrade paid a round trip the carrier could save; the handshake now seals its request packet into a buffer through the `&mut dyn Write` seam it already had and hands it to the carrier as one `first` part. The twin is open: `dial_ss_ws` still passes `0, &[]` to `ws::connect`, and there the payload has to fit the frame header, so the flag rule does not cross that carrier unchanged; (4) the dial side of the carrier still closes over an RST when the peer's tail is unread (`quiet` is served-role only), the same abort `carrier-grpc` and `carrier-xhttp` each record on their own lanes; (5) refused, with its reason: `quiet` parks its thread for a whole `SESSION_POLL` (1 ms) on the ordinary exit where nothing was pipelined, and `at == buf.len()` looks like the bit that lets that teardown skip the drain and its three socket calls — but it proves only that the *last round* over-read nothing, while the dial's `ed=0` path writes its payload as a second write that can still reach the queue before the close, and a close over an unread queue is the RST `a_drained_teardown_ends_the_upgrade_with_a_fin` exists to prevent; the same argument refuses the zero-timeout probe. What is left inside `quiet` is the 4 KiB stack fill ahead of its drain, which needs `MaybeUninit` and an instruction count no checker here can take — `httpupgrade` blesses no symbol and macOS has no valgrind — so *unsafe only for a measured win* keeps the fill; the last buffer the row holds is the per-connection head `Vec`, and pooling it is shared infrastructure, since `read_exact_head` serves `ws`, `grpc`, `xhttp` and `http-header` beside it, so that is its own slice and not row 12's; (6) the dial's request carries `Host`, `Connection` and `Upgrade` only, while the pinned xray dials a random `Sec-WebSocket-Key` and `Sec-WebSocket-Version: 13` and replays every `header` entry from the config (`upstream/xray-core/transport/internet/httpupgrade/dialer.go:95-109`), so a server that validates the websocket handshake before upgrading refuses us. This is not an optimisation slice's work: it moves bytes on the wire, so it needs its own row with a real peer agreeing on it; (7) `proxy::read_vless_response` reads only the two-byte VLESS response head, and `VlessLink::decode_response_header` answers `Ok(2 + len)` only when the buffer it is handed already holds `2 + len` — the call hands it two — so a non-zero addons length is `Err(Response)` and the `consumed > 2` read under it is unreachable: the pinned xray writes the version then `EncodeHeaderAddons`, length byte and protobuf, on every response (`upstream/xray-core/proxy/vless/encoding/encoding.go:135-152`), so a server that answers with response addons is refused here where it is accepted there. That is a functional row, not this hunt's — read the length, carry the addons past the head, and diff the bytes against that encoder. Until it lands, the unreachable `vec![0u8; consumed - 2]` is `retire-dead`'s instance: it gets a caller or it goes, which is that row's first commit and not this slice's.

## P17 · Hunt and fix the concurrency, timing and flakiness bugs

**When to use:** The engine has races, stalls and flaky tests — half-closed races, duplex deadlocks, timeouts that never fire, buffer-ownership races, tests that lose to the scheduler — and each one is a defect to find, prove, and fix one at a time.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Targets:** implemented
**Gates:** `cargo test --workspace --all-features`; CI: `safety.yml`; CI: `conformance.yml`; CI: `bench.yml`
**Random weight:** 8

```text
Find a concurrency, timing or duplex defect in {method} — matrix row {index} of table {section} — and fix one: a half-closed race, a full-duplex stall, a timeout or deadline the socket can miss, a buffer-ownership or pool race, a wakeup lost behind a cursor, or a test that goes red one run in several. One defect per slice.

Reproduce before fixing: land a test that is red on the defect and green after it, and keep the red case in the suite — a bug read off a symptom is a guess until that test exists. Where a timing window is genuinely involved, drive it from an in-memory stream or a controllable clock, never a wall-clock sleep or a real socket. A flaky test is itself the defect's witness: pin what it actually observes.

Prove the fix under the tools that see these bugs: Miri for the memory and aliasing races, the byte-differential for the wire, CI conformance and benches for the connections. Never paper over a race by moving a wire byte or a datagram boundary; fix the ordering or the ownership, and say which.
```

**Add-on — race-hunt:** Audit where one buffer is touched by two actors, where a cursor or counter can lag what a read consumed, and where a window can fill; name the invariant each guard holds.
**Add-on — half-close:** The close edge is the usual bug site — check who shuts which direction, what the peer sees, and whether a pending read can outlive its writer.
**Add-on — shared-close:** Where both directions of one relay tear down through a single shared `close` closure, no per-direction half-close is expressible and whichever thread finishes first aborts the sibling's still-open read; carry two directional closes per site, and where a carrier has no half-close primitive at all, name that limit rather than sweeping `Both` to `Write` blind.
**Add-on — withheld-answer:** A server may hold its handshake answer until it sees client payload — xray flushes its buffered response on the first downstream write, zeronet's `HeaderFirst::hold` waits for it outright — so a client that stops sending to wait deadlocks both ways; pump the upload leg during the answer wait and hand it back before the session relay. Where the answer read shares one session lock with its writer (TLS halves, mux, the UDP uplink) the leg has to yield that lock first, so record those arms as rows instead of bolting a pump onto a locked half.
**Add-on — unread-close-rst:** Where a peer's answer is already on its way and that peer still holds payload it never read, ask what its close sends.
**Add-on — padded-data-credit:** The xHTTP h2 lane now credits a padded `DATA` frame at its wire length — Pad Length octet and Padding counted, RFC 7540 6.9, the reference's take of `f.Length` — and named what this shape left behind: the gRPC lane (`grpc.rs`'s `data`, replenishing `len - first - pad`) and the Foxy lane (`foxy.rs`'s `credit`, handed the already-unpadded payload by `frames::h2_event`, so the lane cannot see the octets it owes without the frame length) still grant only the post-cut length, and a peer that keeps a strict send window loses `1 + pad` octets of credit per padded frame. Each lane is its own slice with its own red-then-green witness reading the `WINDOW_UPDATE` increments, shaped like `xhttp_h2::tests::a_padded_data_credit_counts_the_whole_wire_payload`; the Foxy leg first needs the parser to hand the frame's length beside the trimmed payload, and that seam change is counted as its own method change, not folded into the arithmetic.
**Add-on — parked-leg:** A relay that tears down its *own* direction and then joins its sibling wakes nobody: shutting one half of a socket does not release a `recv` blocked on it, so the pooled leg sleeps until the join budget burns, the give-up prints, and the worker is lost for the life of the process while the next flow spawns another. Audit every join the way the close edge is audited — ask what ends the leg that is *not* on the calling thread, and land the witness as a red-then-green test that the flow whose partner ended returns inside the park, not inside the budget.
**Add-on — transient-ref-loss:** A benchmark runner on a loaded, small-core box can lose the *reference* engine's runs while the candidate measures clean — the harness's own sink hits `ENOBUFS` (macOS os error 55) or `EPIPE` (32) under concurrent bulk flows, the transfer comes up short, and each short run is discarded — so the gated row falls to `fewer than N usable pairs` and the cell reports a regression that never happened. Never report a short transfer as a number; instead give the run loop a bounded retry for a transient sink or startup fault (fresh output per attempt, so the stale-output guard still bites), and drive a red-then-green witness from a controllable stream that drops the reference's first attempts and asserts the recovered cell no longer reads as `WORSE`. Where the fault is genuinely terminal, say which engine went unmeasured rather than blaming the candidate.
**Add-on — own-baseline:** A gated row can compare two of this tree's own paths rather than an engine and a reference, which makes its bar a claim about the *difference between the paths* — and a length can make that difference smaller than any runner's noise. Count the work each shape does at that length before gating it: the fused `fill_exact_with_head` and the unfused `fill_exact`-then-`poly_key` split both generate `ceil(len/64) + 1` blocks, so from the first length where the message fills a pass they issue the same passes plus the same lone tail block and the row measures a function call, while under a pass the headed shape covers the whole seal in one invocation and the split opens a second for block zero — which is where the fused shape's measured 1.44x-1.75x lives. `framing::timed_row` re-measures a sub-`BAR` ratio at four times the iterations, but a confirmation is one process's steady reading: main's nightly at `70fdfd0` aborted `measure trojan-raw-down-8 (macos-15)` on `chacha20-poly1305 seal, 16384B = 0.939x` while `bench.yml` run `39000283851` passed this same gate on the same commit and the same macos runner, and the row cleared `BAR` on the other three classes alike. So read such a row on every runner class before naming either path a regression, then gate the lengths whose ratio a code change can move and print the rest as `framing::gated_seals` does after `muxframe::REPORTED_ONLY` — never move a threshold to make a gate go green, and never blame one class's pass shape until the counts say that shape has work left to remove.

## P18 · Give a decision the engine already implies its owner

**When to use:** The engine classifies failures, negotiates capabilities or probes alternatives somewhere, but no component acts on that knowledge — the recovery ladder, the climb or the probe is implied by the design and unwritten in the code.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Targets:** implemented
**Gates:** `cargo test --workspace --all-features`; `./scripts/check.sh`; CI: `conformance.yml`
**Random weight:** 4

```text
{method} — matrix row {index} of table {section} — already implies a decision the engine does not own: which failure is worth retrying versus terminal, what it climbs or descends when one path stops answering, what it asks the peer before committing to a pooled or multiplexed shape, when a credential or pass latches rather than retries. Read how {references} make the same call, then give this one a named owner and a bounded policy: the taxonomy row that decides, the component that acts on it, the counter or deadline that bounds it.

Prove the decision, not the intent: a test that drives each failure kind and asserts the ladder takes the branch it names, and — where the policy depends on what the peer says — a test that answers differently and asserts the engine follows the answer. A probe that costs a round-trip on every flow is a count change; state what it costs and what it saves.
```

**Add-on — bounded-cost:** Name the worst case of the probe or retry — rounds, bytes, latency — and cap it, so recovery cannot become a stall.
**Add-on — one-owner:** One component decides and one acts; a policy consulted in two places diverges, so fold the second into the first.

## P19 · Make a stall name itself from inside the engine

**When to use:** A hang is only visible from outside — `watch-test.sh` reads procfs wchan on Linux runners and nothing elsewhere, and a thread parked in the engine carries no name of its own — so a stall in the field, on macOS, or on Windows reports a pid, not a wait.
**Status:** doing
**Leverage:** 5
**Effort:** medium
**Targets:** implemented
**Gates:** `./scripts/check.sh`; `cargo test --workspace --all-features`; CI: `safety.yml`; CI: §ops.yml
**Random weight:** 7

```text
{method} — matrix row {index} of table {section} — parks a thread in waits the engine knows about by name but the running process cannot say: every cadence lives in `crates/ferrox-app/src/budgets.rs`, yet nothing at runtime reports which named wait holds which thread on which fd for how long. Give the engine its own wchan: a census next to `budgets.rs` where a wait registers its name, the fd it blocks on and the deadline it armed, deregisters on return, and dumps as per-thread lines on demand — from a test, a signal, or the CI harness.

Gate the census on a build shape with no production traffic, the way `count-ops.sh` gates its binary: the hot relay path must not pay for a map a stall hunt reads once. Prove the census by parking a wait on an in-memory stream that answers nothing and asserting the dump names that wait, its fd and a waited-for duration — a test that only compiles the dump sees the API, not the thing it claims. The engine's waits are the table; a row of that table with no census entry is the finding, and the census earns its keep the first time a P17 or P13 slice is written from a dump line naming the wait rather than from a post-mortem.

Report the per-wait cost the census adds where it is reachable, or state that the gated shape makes it zero and name the gate that proves it.
```

**Add-on — stall-to-name:** Extend `watch-test.sh`: before it kills a stalled test binary it sends the stop and re-reads the log once, and the workspace test harness answers that stop by dumping the census. A stall then prints the engine's wait names beside the procfs lines, on every OS — procfs sees the kernel, only the census sees the engine.

**Add-on — starved-leg:** A dump showing one leg of a relay in `read` and its partner in nothing is a join that outlived its bound; check it against `RELAY_JOIN` and the leg-witness tests before naming it a peer problem.

**Add-on — sys-attribution:** `ferrox-bench`'s kernel tally cannot price a Rust relay's sys time: `/proc/<pid>/io` counts the `read`/`write` paths, and std's socket legs — `send`/`recv` — never appear there, which the `ps` witnesses show against a child that writes a file. Attribute the residual per thread instead: sample `/proc/<pid>/task/*/stat` for who holds the `stime`, then name the asks from the census' waits, and report a `0` per-GiB row as the instrument's gap rather than as a crossing that cost nothing.

**Add-on — rest-of-the-table:** Eight of the ten named budgets still have no census entry — `dial`, `handshake`, `headArrival`, `relayQuantum`, `udpIdle`, `payloadGrace`, `goawayGrace`, `carrierProbe` — nor do the constants that pace a loop. Most arm sites hold the deadline and then do the blocking call in the same scope, so a row there costs one registration around that call rather than one inside the funnel; a leg through the shared relay half first needs its descriptor named, because a `dyn Read` reaches the wait with no fd to report.

## P20 · Scale the parameter surface without growing the app file

**When to use:** A knob a reference ships is either unreachable from this tree's config or is plumbed ad-hoc through the app monolith, so adding the next one costs more of the same accretion rather than a section; the superset rows (README table N 116–124) all land through this shape.
**Status:** todo
**Leverage:** 4
**Effort:** large
**Targets:** implemented
**Gates:** `./scripts/check.sh`; `cargo test --workspace --all-features`; CI: `conformance.yml`
**Random weight:** 6

```text
{method} — matrix row {index} of table {section} — gains its user-settable parameters by carving, not by accretion: move the knob group named in its superset row into the section-owned config type that `crates/ferrox-app/src/config.rs` already shapes per plane, give the app one reader of it, and keep the defaults byte-for-byte what the constants in `budgets.rs` say today, so every blessed count holds across the move and `scripts/count-ops.sh` is the witness that the carve moved no work. A runtime-settable cadence is a count change: the page states the new worst case of a wait the peer can tune, and a knob whose default differs from the constant is refused until the matrix and pages say so.

Prove the surface, not the struct: a config-named test per knob that asserts the engine acts on the value it names — a bound that stops a parked wait, a header that appears on the wire, a byte rate the gauge enforces — beside the parse round-trip. A parsed field no component reads is the defect P18 exists to own; check the knob has its actor before calling the row shipped, and record in the superset matrix the row that moved from planned to implemented only when the actor exists.
```

## P21 · Fix and land a P0/P1 regression issue

**When to use:** A P0 or P1 regression issue is open and must be fixed end to end — reproduced, fixed, proven, landed on `main` and closed — before any feature slice continues.
**Status:** todo
**Leverage:** 5
**Effort:** medium
**Targets:** none
**Gates:** `./scripts/check.sh`; `cargo test --workspace --all-features`; CI: `conformance.yml`; CI: `bench.yml`; CI: §ops.yml
**Random weight:** 0

```text
Phase 1 — Fix and land issue #{issue}, a {priority=P0 or P1} regression. Read the issue and reproduce the failure before editing; work only in a worktree made by `./scripts/new-worktree.sh bugfix-{issue}`. The fix is complete when the defect cannot recur: add a test that is red on the unfixed tree and green after the fix, run it with the gate in `./scripts/check.sh`, then rebase onto `main`, land the fix there, and close the issue with the integration that proves it. Do not leave a smaller defect behind to finish the issue.

Phase 2 — Study upstream. Read the relevant pinned implementations in {references} and find how each handles this path. Name which one is best, and why, with the evidence that decides it.

Phase 3 — Performance passes. First, the focused pass: move the thing the issue touched towards the best upstream form without changing a wire byte: fewer retired instructions, copies, branches, locks and allocations. Re-measure the exact count with `scripts/count-ops.sh` where the runner can provision it; land only the changes that count proves (`UNBLESSED` otherwise), and write down the arithmetic for any regression you revert. Then the open-ended pass: make it faster, leaner and more capable than every reference in {references} together. Carry each winner as far as it goes rather than stopping after one; change the basis or the order, factor, recast and prove equivalence. Mine hot loops and algebraic structure, every SIMD width the ladder runs, cache locality and branch prediction, batched or vectored I/O and lock-free handoffs, and remove ops, copies, allocations, syscalls, atomics, zeroing and checks nothing reads. Sweep the bytes both ways after the change: the block, byte, counter and panic-threshold totals must stay put, not merely agree at one length. Where the wire shape is fixed, say so.

Phase 4 — Before every push, run the shared local gate. Nothing connection-dependent is local evidence; the CI jobs are where a dial, a benchmark and Miri count.
```

# TUN stacks (system, userspace, hybrid)

A `tun` inbound with no `stack` setting, or `stack: "smoltcp"` / `"userspace"`, opens the device through `tun-rs` and terminates TCP in a userspace `smoltcp` interface. On Linux the device is multi-queue when `queues` exceeds one and setup succeeds; non-Linux platforms and `queues: 1` use one queue. Each queue is one reader, one smoltcp server stack and one writer, so flows hash across queues without a lock between them when more than one queue is active. The device negotiates virtio GSO/GRO when the platform offers it. A flow still reaches the proxy machinery through the same per-flow local stream every other front uses.

On Linux, `stack: "system"` hands TCP to the kernel instead. It binds a listener on the TUN address and rewrites an outgoing SYN onto a second address inside the prefix and an allocated port on that listener, updating the IP and TCP checksums incrementally over the changed addresses and ports before writing it back to the device. The kernel completes the handshake, owns the receive window and retransmits, and `accept_loop` relays each accepted stream through the same per-flow proxy seam. UDP and ICMP stay on the userspace stack. `stack: "hybrid"` adds one rule: a TCP packet the NAT loop cannot map (a non-SYN segment with no mapping, an exhausted NAT table) goes to the userspace stack instead of being dropped, and a failed system setup warns once and takes the whole inbound to userspace. A flow handed to the userspace stack stays there until a FIN or RST releases it, so a retransmitted SYN cannot be claimed by the kernel after NAT capacity returns. `system` and `hybrid` open one queue with virtio offload off, and need a prefix with a second address — IPv4 /30 or wider, IPv6 /126 or wider; a narrower prefix is an error for `system` and a userspace fallback for `hybrid`. On non-Linux platforms `system` is refused and `hybrid` warns and uses userspace.

`stack: "loopback"` keeps the native packet handler in `docs/function/front-tun.md` as the fallback for an IPv4 address; an IPv6 address is refused because that handler reads only IPv4. An unknown stack name warns once and takes the userspace path rather than silently changing protocol.

## Data path

```mermaid
graph TD
    A["inbound config: protocol tun, stack smoltcp"] --> B["tun_stack::open<br/>DeviceBuilder offload + multi_queue"]
    B --> C["one queue thread set per device queue"]
    C --> R["recv_loop: recv_multiple with a virtio header<br/>packet_bytes into a reused Vec"]
    R --> S["serve_tun_device<br/>QueueDevice receive"]
    S --> T["smoltcp Interface::poll<br/>TcpSocket per flow"]
    T --> U["QueueDevice transmit<br/>one segment per TxToken"]
    U --> W["send_loop: GROTable + send_multiple<br/>bounded aggregate buffers"]
    W --> K["kernel TUN queues"]
    S --> P["per-flow local stream<br/>proxy relay (splice on Linux)"]
    P --> T
    C --> X["one writer and one reader per queue"]
```

The system path replaces the smoltcp TCP hop for a handled flow:

```mermaid
graph TD
    A["inbound config: protocol tun, stack system"] --> B["tun_stack::build<br/>one queue, offload off"]
    B --> R["recv_loop: batched recv_multiple<br/>packet_bytes into a reused Vec"]
    R --> N["Nat::rewrite<br/>source peer, destination local:listener<br/>incremental IP + TCP checksums"]
    N -->|handled TCP| W["send_plain with a bounded recycle pool<br/>write back to the device"]
    N -->|UDP, ICMP, hybrid fallback| S["serve_tun_device<br/>smoltcp"]
    W --> K["kernel TCP stack"]
    K --> L["accept_loop<br/>serve_device_flow"]
    L --> N
    S --> W
```

## Measured

<!-- counts:begin -->
| key | value | checked by |
| --- | --- | --- |
| ops-retired-instructions | 32598 | scripts/count-ops.sh |
| syscalls-per-tun-packet | UNBLESSED | no syscall checker yet |
| user-space-copies-per-tun-packet | UNBLESSED | no copy checker yet |
| time-tcp-down-1 | ferrox=9.883Gbit/s,zeptun=17.937Gbit/s,ratio=0.55 | tun-bench.yml |
| time-tcp-down-10 | ferrox=14.309Gbit/s,zeptun=23.950Gbit/s,ratio=0.60 | tun-bench.yml |
| time-tcp-up-1 | ferrox=12.860Gbit/s,zeptun=20.331Gbit/s,ratio=0.63 | tun-bench.yml |
| time-tcp-up-10 | ferrox=15.854Gbit/s,zeptun=26.821Gbit/s,ratio=0.59 | tun-bench.yml |
| time-rr | ferrox=6581tps,zeptun=11504tps,ratio=0.57 | tun-bench.yml |
| time-rr-8x1k | ferrox=38261tps,zeptun=64001tps,ratio=0.60 | tun-bench.yml |
| time-udp-100k | ferrox=99920pps,zeptun=99962pps,ratio=1.00 | tun-bench.yml |
| cpu-cores-at-tcp-down-10 | ferrox=2.9cores,zeptun=1.7cores | tun-bench.yml |
| rss-mb-at-ten-flows | ferrox=60-75MB,zeptun=2-8MB | tun-bench.yml |
<!-- counts:end -->

`scripts/count-ops.sh` measures `Nat::rewrite` over the payload lengths in `a_rewrite_keeps_the_checksum_of_every_payload_length`; no pointer-identity or copy-count checker yet covers this path, so the syscall and copy rows stay open. The writer copies each smoltcp segment into an aggregate buffer, and the reader copies each device packet into a stack slot. The `time-*` rows measure the userspace stack; no `system` or `hybrid` row has been measured, so this page makes no speed claim for either.

## Time

The `time-*` rows above are the same-run `tun-bench.yml` cells; a later single-engine run is host-sensitive, so the same-run ratios are the comparable figure. The `cpu-*` and `rss-*` rows name the remaining gap: stack CPU, not the device. No duration outside those rows is claimed.

## What we removed

Against the native handler the userspace path removes the hand-written TCP reassembly and the single-queue limit: `smoltcp` supplies retransmit, receive windows and congestion control, and `tun-rs` supplies multi-queue and GSO/GRO. The writer batches a queue's segments so GRO can coalesce same-flow packets into one aggregate, and the reader asks for a batch instead of one packet per syscall. The `tun` config keeps one stack knob (`smoltcp`, `userspace`, `system`, `hybrid`, `loopback`) instead of growing a second inbound protocol. The system path removes smoltcp's TCP state machine from the handled flow: the kernel owns the handshake and retransmits, and the userspace stack keeps only UDP, ICMP and (under hybrid) the flows the kernel cannot take. That is one packet rewrite and an incremental checksum update over the changed addresses and ports, not a second userspace TCP implementation. The changed words are folded into one delta, so the IPv4 header and TCP checksum each take one `checksum_update` call instead of one per field.

Against the pinned references, xray-core and sing-box open the platform device and hand packets to their configured stack, ZeroNet's zero-tun is its own device wrapper, and this tree's native handler remains the `loopback` fallback. None of those references carries this per-queue smoltcp server, so the comparison is the same-run Time rows rather than a removed pass; this page does not claim their code was removed. What is not removed is the userspace stack's per-byte copying, priced in the rows above.

## What was not removed

- **The userspace stack itself.** `smoltcp` per-socket receive and send buffers still copy every byte: the device read copies into a stack slot, `smoltcp` copies into the socket ring, the pump copies to the local stream, and the writer copies into the aggregate. The reference's custom stack does less of that; this is the measured CPU gap, not a device limitation. `system` and `hybrid` still keep that stack alive for UDP and ICMP, so they do not remove it.
- **The system path's copies.** A handled TCP packet is parsed, rewritten in place and written back to the device, and the payload is still copied there; the accepted flow then copies through the relay pair like every other front. The checksum pass over the segment is gone, but no pointer-identity or copy-count checker covers the remaining copies yet, so it stays out of the Measured table.
- **System-mode offload and multi-queue.** The kernel path opens one queue and leaves virtio GSO/GRO off; `queues > 1` warns once and runs one queue. No benchmark says the single-queue kernel path is faster or slower than the userspace multi-queue path.
- **The native handler.** It remains the path for `stack: "loopback"` with an IPv4 address; an IPv6 address is refused rather than handed to it, and a failed userspace open returns its error instead of falling back. Its page stays the description of that path.
- **Per-flow buffers and relay threads.** A flow still owns a pair of fixed smoltcp socket buffers and the relay's local pair; the RSS row above carries the post-flow cost. Reducing the buffers is a tuning cell, not a proven win yet.
- **The download scale cell.** The larger download cell does not reach the reference; the ratio row above is the claim. The gap is open and is not claimed as done.
- **UDP lane scheduling.** The UDP cell has varied across runners; no lane change is claimed until a focused repeat separates variance from a limit.

## Pins

| what | where |
| --- | --- |
| the device API, multi-queue, GSO and GRO | `tun-rs` 2.8.18 (`platform/linux/device.rs`, `platform/linux/offload.rs`) |
| the TCP state machine and socket buffers | `smoltcp` 0.14 |
| the stack tuning reference | `upstream/zeptun/src/stack/tcp.zig`, `src/engine.zig` |
| the native fallback | `docs/function/front-tun.md`, `crates/ferrox-app/src/tun.rs` |
| the system NAT loop, accepted flow and relay | `crates/ferrox-app/src/tun_system.rs` |
| the kernel-TCP stack shape | `upstream/zeptun/src/stack/system.zig`, `upstream/zeptun/src/flow/nat.zig` |

## CI scope

What a change here owes, read by `scripts/ci-scope.py`; see [`docs/ci-scope.md`](../ci-scope.md).

<!-- scope:begin -->
- paths: crates/ferrox-app/src/tun_stack.rs, crates/ferrox-app/src/tun_system.rs
- symbols: tun_stack, tun_system
<!-- scope:end -->

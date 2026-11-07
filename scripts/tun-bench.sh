#!/bin/sh
# End-to-end TUN benchmark: two network namespaces joined by a veth pair, a
# SOCKS5 server plus TCP/UDP targets on the far side, and every engine fed by
# the same clients. Runs in a throw-away user+net namespace, so no host root and
# no host route is touched. CI only: local numbers measure a VPN, not the code.
set -eu

if [ "${TUN_BENCH_INNER:-}" != "1" ]; then
    export TUN_BENCH_INNER=1
    exec unshare --user --map-root-user --net --fork -- sh "$0" "$@"
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT_DIR=${OUT_DIR:-"$ROOT/tun-bench-results"}
mkdir -p "$OUT_DIR"
OUT_DIR=$(CDPATH= cd -- "$OUT_DIR" && pwd)
RESULTS="$OUT_DIR/results.jsonl"
: > "$RESULTS"

FERROX=${FERROX:-}
BENCH=${BENCH:-}
ZEPTUN=${ZEPTUN:-}
HEV=${HEV:-}
HEV_SERVER=${HEV_SERVER:-}
SINGBOX=${SINGBOX:-}
TUN2SOCKS=${TUN2SOCKS:-}

DURATION=${DURATION:-5}
REPEAT=${REPEAT:-2}
QUEUES=${QUEUES:-4}
MTU=${MTU:-1500}
SETTLE=${SETTLE:-3}
ENGINES=${ENGINES:-"ferrox zeptun-userspace zeptun-hybrid hev tun2socks singbox-system"}
SCENARIOS=${SCENARIOS:-"tcp-up-1 tcp-up-10 tcp-down-1 tcp-down-10 rr rr-8x1k udp-100k"}

VETH_CLIENT=192.168.77.1
VETH_SERVER=192.168.77.2
VETH_MTU=9000
SERVER_ADDR=10.99.0.1
TUN_ADDR=198.18.0.1
TUN_PREFIX=15
SOCKS_PORT=1080

SERVER_PID=""
BG_PIDS=""
ENGINE_PIDS=""

note() { printf '%s\n' "$*" >&2; }
die() { note "tun-bench: $*"; exit 2; }

in_server() {
    nsenter --target "$SERVER_PID" --net -- "$@"
}

bg_server() {
    in_server "$@" > /dev/null 2>&1 &
    BG_PIDS="$BG_PIDS $!"
}

cleanup() {
    for pid in ${ENGINE_PIDS:-}; do kill -9 "$pid" 2> /dev/null || true; done
    for pid in ${BG_PIDS:-}; do kill "$pid" 2> /dev/null || true; done
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2> /dev/null || true
    wait 2> /dev/null || true
}
trap cleanup EXIT INT TERM

wait_server_ns() {
    for _ in $(seq 1 100); do
        if [ "$(readlink "/proc/$SERVER_PID/ns/net" 2> /dev/null)" != "$(readlink /proc/self/ns/net)" ]; then
            return 0
        fi
        sleep 0.05
    done
    return 1
}

wait_port() {
    for _ in $(seq 1 200); do
        if in_server ss -Hltn "sport = :$1" 2> /dev/null | grep -q LISTEN; then return 0; fi
        if in_server ss -Hlun "sport = :$1" 2> /dev/null | grep -q UNCONN; then return 0; fi
        sleep 0.05
    done
    return 1
}

wait_dev() {
    for _ in $(seq 1 200); do
        if ip -o link show "$1" > /dev/null 2>&1; then return 0; fi
        sleep 0.05
    done
    return 1
}

wait_up() {
    for _ in $(seq 1 200); do
        if ip -o link show "$1" 2> /dev/null | grep -q "UP"; then return 0; fi
        sleep 0.05
    done
    return 1
}

install_routes() {
    ip route replace default dev "$1" table 2022
    ip rule add pref 9000 lookup main suppress_prefixlength 0 2> /dev/null || true
    ip rule add pref 9001 lookup 2022 2> /dev/null || true
}

remove_routes() {
    ip rule del pref 9001 lookup 2022 2> /dev/null || true
    ip rule del pref 9000 lookup main suppress_prefixlength 0 2> /dev/null || true
    ip route flush table 2022 2> /dev/null || true
}

ns_setup() {
    unshare --net -- sleep 1000000 &
    SERVER_PID=$!
    wait_server_ns || die "the server namespace did not come up"
    ip link set lo up
    ip link add veth0 mtu "$VETH_MTU" type veth peer name veth1 mtu "$VETH_MTU"
    ip link set veth1 netns "$SERVER_PID"
    ip addr add "$VETH_CLIENT/24" dev veth0
    ip link set veth0 up

    in_server ip link set lo up
    in_server ip addr add "$VETH_SERVER/24" dev veth1
    in_server ip link set veth1 up
    in_server ip addr add "$SERVER_ADDR/32" dev lo
}

services() {
    [ -n "$BENCH" ] || die "BENCH is required"
    bg_server "$BENCH" tcp-server --listen "$SERVER_ADDR:5201"
    bg_server "$BENCH" tcp-server --listen "$SERVER_ADDR:5203"
    bg_server "$BENCH" udp-server --listen "$SERVER_ADDR:5202" --echo
    if [ -n "$HEV_SERVER" ]; then
        printf "main:\n  workers: %s\n  port: %s\n  listen-address: '%s'\n" \
            "$(nproc)" "$SOCKS_PORT" "$VETH_SERVER" > "$OUT_DIR/socks5.yml"
        bg_server "$HEV_SERVER" "$OUT_DIR/socks5.yml"
    else
        bg_server "$BENCH" socks5-server --listen "$VETH_SERVER:$SOCKS_PORT"
    fi
    wait_port 5201 || die "the TCP target never listened"
    wait_port 5203 || die "the RR target never listened"
    wait_port 5202 || die "the UDP target never listened"
    wait_port "$SOCKS_PORT" || die "the SOCKS5 server never listened"
}

start_ferrox() {
    [ -n "$FERROX" ] || return 1
    printf '%s\n' "{\"inbounds\":[{\"tag\":\"tun\",\"protocol\":\"tun\",\"settings\":{\"name\":\"fx0\",\"mtu\":$MTU}}],\"outbounds\":[{\"tag\":\"proxy\",\"protocol\":\"socks\",\"settings\":{\"servers\":[{\"address\":\"$VETH_SERVER\",\"port\":$SOCKS_PORT}]}}]}" \
        > "$OUT_DIR/ferrox.json"
    "$FERROX" run -c "$OUT_DIR/ferrox.json" > "$OUT_DIR/ferrox.log" 2>&1 &
    ENGINE_PIDS=$!
    if ! wait_dev fx0; then
        note "ferrox did not create fx0"; cat "$OUT_DIR/ferrox.log" >&2; return 1
    fi
    ip addr replace "$TUN_ADDR/$TUN_PREFIX" dev fx0
    ip link set fx0 up
    wait_up fx0 || return 1
    install_routes fx0
    TUN_NAME=fx0
}

start_zeptun() {
    mode=$1
    [ -n "$ZEPTUN" ] || return 1
    "$ZEPTUN" run --tun zep0 --mtu "$MTU" --queues "$QUEUES" --stack "$mode" \
        --socks5 "$VETH_SERVER:$SOCKS_PORT" --auto-route --log-level warn \
        > "$OUT_DIR/zeptun-$mode.log" 2>&1 &
    ENGINE_PIDS=$!
    wait_dev zep0 || { note "zeptun-$mode did not create zep0"; cat "$OUT_DIR/zeptun-$mode.log" >&2; return 1; }
    wait_up zep0 || return 1
    install_routes zep0
    TUN_NAME=zep0
}

start_hev() {
    [ -n "$HEV" ] || return 1
    if [ "$QUEUES" -gt 1 ]; then multi=true; else multi=false; fi
    printf "tunnel:\n  name: hev0\n  mtu: %s\n  multi-queue: %s\n  ipv4: %s\nsocks5:\n  port: %s\n  address: %s\n  udp: 'udp'\n  pipeline: true\nmisc:\n  log-level: error\n" \
        "$MTU" "$multi" "$TUN_ADDR" "$SOCKS_PORT" "$VETH_SERVER" > "$OUT_DIR/hev.yml"
    i=0
    while [ "$i" -lt "$QUEUES" ]; do
        "$HEV" "$OUT_DIR/hev.yml" > "$OUT_DIR/hev-$i.log" 2>&1 &
        ENGINE_PIDS="$ENGINE_PIDS $!"
        i=$((i + 1))
        sleep 0.2
    done
    wait_dev hev0 || { note "hev did not create hev0"; cat "$OUT_DIR/hev-0.log" >&2; return 1; }
    wait_up hev0 || return 1
    install_routes hev0
    TUN_NAME=hev0
}

start_singbox() {
    stack=$1
    [ -n "$SINGBOX" ] || return 1
    printf '{"log":{"level":"error"},"inbounds":[{"type":"tun","tag":"tun-in","interface_name":"sb0","address":["%s/%s"],"mtu":%s,"auto_route":false,"stack":"%s"}],"outbounds":[{"type":"socks","tag":"proxy","server":"%s","server_port":%s}],"route":{"final":"proxy"}}' \
        "$TUN_ADDR" "$TUN_PREFIX" "$MTU" "$stack" "$VETH_SERVER" "$SOCKS_PORT" > "$OUT_DIR/singbox-$stack.json"
    "$SINGBOX" run -c "$OUT_DIR/singbox-$stack.json" > "$OUT_DIR/singbox-$stack.log" 2>&1 &
    ENGINE_PIDS=$!
    wait_dev sb0 || { note "singbox-$stack did not create sb0"; cat "$OUT_DIR/singbox-$stack.log" >&2; return 1; }
    wait_up sb0 || return 1
    install_routes sb0
    TUN_NAME=sb0
}

start_tun2socks() {
    [ -n "$TUN2SOCKS" ] || return 1
    "$TUN2SOCKS" -d tun://t2s0 -p "socks5://$VETH_SERVER:$SOCKS_PORT" --mtu "$MTU" --loglevel error \
        > "$OUT_DIR/tun2socks.log" 2>&1 &
    ENGINE_PIDS=$!
    wait_dev t2s0 || { note "tun2socks did not create t2s0"; cat "$OUT_DIR/tun2socks.log" >&2; return 1; }
    ip addr replace "$TUN_ADDR/$TUN_PREFIX" dev t2s0
    ip link set t2s0 up
    wait_up t2s0 || return 1
    install_routes t2s0
    TUN_NAME=t2s0
}

start_engine() {
    engine=$1
    ENGINE_PIDS=""
    remove_routes
    case "$engine" in
        ferrox) start_ferrox ;;
        zeptun-userspace) start_zeptun userspace ;;
        zeptun-hybrid) start_zeptun hybrid ;;
        zeptun-system) start_zeptun system ;;
        hev) start_hev ;;
        singbox-system) start_singbox system ;;
        singbox-gvisor) start_singbox gvisor ;;
        tun2socks) start_tun2socks ;;
        *) note "unknown engine $engine"; return 1 ;;
    esac
}

stop_engine() {
    for pid in ${ENGINE_PIDS:-}; do kill -INT "$pid" 2> /dev/null || true; done
    for pid in ${ENGINE_PIDS:-}; do
        for _ in $(seq 1 100); do kill -0 "$pid" 2> /dev/null || break; sleep 0.1; done
        kill -9 "$pid" 2> /dev/null || true
        wait "$pid" 2> /dev/null || true
    done
    ENGINE_PIDS=""
    remove_routes
    sleep 0.5
}

engine_memory() {
    rss=0
    pss=0
    for pid in ${ENGINE_PIDS:-}; do
        r=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status" 2> /dev/null || true)
        p=$(awk '/^Pss:/ {s += $2} END {printf "%d", s}' "/proc/$pid/smaps_rollup" 2> /dev/null || true)
        rss=$((rss + ${r:-0}))
        pss=$((pss + ${p:-0}))
    done
    printf '%s %s\n' "$rss" "$pss"
}

monitor_engine() {
    tag=$1
    MON_PIDS=""
    for pid in ${ENGINE_PIDS:-}; do
        "$BENCH" monitor --pid "$pid" --seconds "$DURATION" --interval-ms 500 \
            --json "$OUT_DIR/mon-$tag-$pid.json" > /dev/null 2>&1 &
        MON_PIDS="$MON_PIDS $!"
    done
}

summarize_monitor() {
    python3 - "$OUT_DIR" "$1" << 'PY'
import glob, json, sys
out, tag = sys.argv[1], sys.argv[2]
cpu = rss = pss = 0.0
for path in glob.glob(f"{out}/mon-{tag}-*.json"):
    try:
        m = json.load(open(path))
    except Exception:
        continue
    cpu += m.get("avg_cpu_pct", 0.0)
    rss = max(rss, m.get("max_rss_kb", 0))
    pss = max(pss, m.get("max_pss_kb", 0))
print(f"{cpu:.1f} {rss:.0f} {pss:.0f}")
PY
}

run_scenario() {
    engine=$1
    scenario=$2
    rep=$3
    tag="$engine-$scenario-$rep"
    rm -f "$OUT_DIR"/mon-"$tag"-*.json
    monitor_engine "$tag"
    value=""
    unit=""
    case "$scenario" in
        tcp-up-*|tcp-down-*)
            streams=${scenario##*-}
            reverse=""
            case "$scenario" in tcp-down-*) reverse="--reverse" ;; esac
            "$BENCH" tcp-client --connect "$SERVER_ADDR:5201" --seconds "$DURATION" \
                --streams "$streams" $reverse --json "$OUT_DIR/$tag.json" > /dev/null 2>&1 || true
            value=$(python3 -c "import json,sys; print('%.3f' % json.load(open(sys.argv[1]))['gbps'])" "$OUT_DIR/$tag.json" 2> /dev/null || echo 0)
            unit=Gbit/s
            ;;
        rr|rr-8x1k)
            conns=1
            size=64
            [ "$scenario" = rr-8x1k ] && { conns=8; size=1024; }
            "$BENCH" rr-client --connect "$SERVER_ADDR:5203" --seconds "$DURATION" \
                --conns "$conns" --size "$size" --json "$OUT_DIR/$tag.json" > /dev/null 2>&1 || true
            value=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print('%.0f tps p50=%.0fus p99=%.0fus' % (d['tps'], d['p50_us'], d['p99_us']))" "$OUT_DIR/$tag.json" 2> /dev/null || echo 0)
            unit=""
            ;;
        udp|udp-*)
            size=1200
            pps=0
            gso=""
            case "$scenario" in
                udp-gso-*) gso="--gso"; pps=${scenario#udp-gso-} ;;
                udp-*) pps=${scenario#udp-} ;;
            esac
            case "$pps" in *k) pps=$((${pps%k} * 1000)) ;; esac
            "$BENCH" udp-client --connect "$SERVER_ADDR:5202" --seconds "$DURATION" \
                --size "$size" --pps "$pps" --echo $gso --json "$OUT_DIR/$tag.json" > /dev/null 2>&1 || true
            value=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print('%.0f echo pps (%.1f%% of %.0f sent)' % (d['received']/d['seconds'], 100.0*d['received']/max(d['sent'],1), d['sent']/d['seconds']))" "$OUT_DIR/$tag.json" 2> /dev/null || echo 0)
            unit=""
            ;;
        *) note "unknown scenario $scenario"; return 0 ;;
    esac
    for mp in $MON_PIDS; do wait "$mp" 2> /dev/null || true; done
    set -- $(summarize_monitor "$tag")
    cpu_pct=$1
    peak_rss=$2
    peak_pss=$3
    sleep "$SETTLE"
    set -- $(engine_memory)
    printf '{"engine":"%s","scenario":"%s","rep":%s,"value":"%s","unit":"%s","cpu_pct":%s,"rss_kb":%s,"pss_kb":%s,"rss_after_kb":%s,"pss_after_kb":%s,"settle_s":%s,"mtu":%s,"queues":%s}\n' \
        "$engine" "$scenario" "$rep" "$value" "$unit" "$cpu_pct" "$peak_rss" "$peak_pss" "$1" "$2" "$SETTLE" "$MTU" "$QUEUES" >> "$RESULTS"
    printf "  %-18s %-12s rep %s: %s %s cpu %s%% rss %s KB, %s KB after %ss idle\n" \
        "$engine" "$scenario" "$rep" "$value" "$unit" "$cpu_pct" "$peak_rss" "$1" "$SETTLE"
}

runner_spec() {
    {
        printf '| property | value |\n|---|---|\n'
        printf '| runner image | %s %s |\n' "${ImageOS:-unknown}" "${ImageVersion:-}"
        printf '| cpu | %s |\n' "$(awk -F': ' '/model name/ {print $2; exit}' /proc/cpuinfo)"
        printf '| cpu cores | %s |\n' "$(nproc)"
        printf '| memory | %s |\n' "$(awk '/MemTotal/ {printf "%.1f GB", $2/1048576}' /proc/meminfo)"
        printf '| kernel | %s |\n' "$(uname -sr)"
        printf '| mtu | %s |\n' "$MTU"
        printf '| queues | %s |\n' "$QUEUES"
        printf '| duration | %ss x %s rounds |\n' "$DURATION" "$REPEAT"
    } > "$OUT_DIR/runner.md"
    cat "$OUT_DIR/runner.md" >&2
}

ns_setup
services
runner_spec
for knob in "net.ipv4.tcp_tw_reuse=1" "net.ipv4.ip_local_port_range=1024 65000"; do
    sysctl -qw "$knob" 2> /dev/null || true
    in_server sysctl -qw "$knob" 2> /dev/null || true
done

rep=1
while [ "$rep" -le "$REPEAT" ]; do
    for engine in $ENGINES; do
        case "$engine" in
            ferrox) [ -n "$FERROX" ] || continue ;;
            zeptun-*) [ -n "$ZEPTUN" ] || continue ;;
            hev) [ -n "$HEV" ] || continue ;;
            singbox-*) [ -n "$SINGBOX" ] || continue ;;
            tun2socks) [ -n "$TUN2SOCKS" ] || continue ;;
        esac
        printf 'round %s engine %s\n' "$rep" "$engine"
        if ! start_engine "$engine"; then
            printf '  failed to start %s\n' "$engine"
            stop_engine
            continue
        fi
        for scenario in $SCENARIOS; do
            run_scenario "$engine" "$scenario" "$rep"
        done
        stop_engine
    done
    rep=$((rep + 1))
done

python3 - "$RESULTS" "$OUT_DIR/summary.md" << 'PY'
import json, statistics, sys
rows = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
groups = {}
for row in rows:
    groups.setdefault((row["engine"], row["scenario"]), []).append(row)

def first_number(value):
    try:
        return float(str(value).split()[0])
    except ValueError:
        return 0.0

lines = [
    "| engine | scenario | median | cpu % | max rss MB | rss after idle MB |",
    "|---|---|---:|---:|---:|---:|",
]
for (engine, scenario), group in groups.items():
    best = sorted(group, key=lambda row: first_number(row["value"]))[len(group) // 2]
    cpu = statistics.median(row["cpu_pct"] for row in group)
    rss = max(row["rss_kb"] for row in group) / 1024
    after = max(row.get("rss_after_kb", 0) for row in group) / 1024
    lines.append(f"| {engine} | {scenario} | {best['value']} {best['unit']} | {cpu:.0f} | {rss:.1f} | {after:.1f} |")
open(sys.argv[2], "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
PY

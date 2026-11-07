#!/bin/sh
# Raw TUN device benchmark: a forwarder between two TUN devices, with iperf3
# crossing it. This isolates the device layer (open/read/write, offload,
# multi-queue) from any tun2socks stack. Run as root in CI; it creates two
# throw-away namespaces and removes them.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT_DIR=${OUT_DIR:-"$ROOT/tun-raw-results"}
mkdir -p "$OUT_DIR"
OUT_DIR=$(CDPATH= cd -- "$OUT_DIR" && pwd)
RESULTS="$OUT_DIR/results.jsonl"
: > "$RESULTS"

FERROX_RAW=${FERROX_RAW:-"$ROOT/scripts/tun-raw/target/release/ferrox-tun-raw"}
TUN_RS_DIR=${TUN_RS_DIR:-}
DURATION=${DURATION:-5}
CLIENT_TIMEOUT=${CLIENT_TIMEOUT:-$((DURATION + 20))}
REPEAT=${REPEAT:-2}
QUEUES=${QUEUES:-4}
VARIANTS=${VARIANTS:-"ferrox-raw-plain ferrox-raw-gso ferrox-raw-mq ferrox-raw-gso-mq tun-rs-sync-normal tun-rs-sync-gso tun-rs-sync-gso-concurrent"}

SERVER_PID=""
FORWARDER_PID=""
IPERF_PID=""
SAMPLER_PID=""

cleanup() {
    [ -n "$SAMPLER_PID" ] && kill "$SAMPLER_PID" 2> /dev/null || true
    [ -n "$IPERF_PID" ] && kill "$IPERF_PID" 2> /dev/null || true
    [ -n "$FORWARDER_PID" ] && kill -9 "$FORWARDER_PID" 2> /dev/null || true
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2> /dev/null || true
    ip link del tun11 2> /dev/null || true
    ip link del tun22 2> /dev/null || true
    wait 2> /dev/null || true
}
trap cleanup EXIT INT TERM

wait_dev() {
    for _ in $(seq 1 200); do
        if ip -o link show "$1" > /dev/null 2>&1; then return 0; fi
        sleep 0.05
    done
    return 1
}

wait_ns() {
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
        if nsenter --target "$SERVER_PID" --net -- ss -Hltn "sport = :5201" 2> /dev/null | grep -q LISTEN; then
            return 0
        fi
        sleep 0.05
    done
    return 1
}

command_for() {
    case "$1" in
        ferrox-raw-plain) printf '%s --iface1 tun11 --iface2 tun22' "$FERROX_RAW" ;;
        ferrox-raw-gso) printf '%s --iface1 tun11 --iface2 tun22 --gso' "$FERROX_RAW" ;;
        ferrox-raw-mq) printf '%s --iface1 tun11 --iface2 tun22 --queues %s' "$FERROX_RAW" "$QUEUES" ;;
        ferrox-raw-gso-mq) printf '%s --iface1 tun11 --iface2 tun22 --gso --queues %s' "$FERROX_RAW" "$QUEUES" ;;
        tun-rs-sync-normal)
            [ -n "$TUN_RS_DIR" ] || return 1
            printf '%s --iface1 tun11 --ip1 10.0.1.1 --iface2 tun22 --ip2 10.0.2.1' "$TUN_RS_DIR/target/release/tun-rs-sync-normal"
            ;;
        tun-rs-sync-gso)
            [ -n "$TUN_RS_DIR" ] || return 1
            printf '%s --iface1 tun11 --ip1 10.0.1.1 --iface2 tun22 --ip2 10.0.2.1' "$TUN_RS_DIR/target/release/tun-rs-sync-gso"
            ;;
        tun-rs-sync-gso-concurrent)
            [ -n "$TUN_RS_DIR" ] || return 1
            printf '%s --iface1 tun11 --ip1 10.0.1.1 --iface2 tun22 --ip2 10.0.2.1' "$TUN_RS_DIR/target/release/tun-rs-sync-gso-concurrent"
            ;;
        *) return 1 ;;
    esac
}

start_variant() {
    variant=$1
    command=$(command_for "$variant") || return 1
    # shellcheck disable=SC2086
    $command > "$OUT_DIR/$variant.log" 2>&1 &
    FORWARDER_PID=$!
    wait_dev tun11 || { echo "  $variant: tun11 did not appear" >&2; cat "$OUT_DIR/$variant.log" >&2; return 1; }
    wait_dev tun22 || { echo "  $variant: tun22 did not appear" >&2; cat "$OUT_DIR/$variant.log" >&2; return 1; }

    unshare --net -- sleep 1000000 &
    SERVER_PID=$!
    wait_ns || return 1
    ip link set tun22 netns "$SERVER_PID"

    ip addr replace 10.0.1.1/24 dev tun11
    ip link set tun11 up
    ip route replace 10.0.2.1/32 dev tun11

    nsenter --target "$SERVER_PID" --net -- ip link set lo up
    nsenter --target "$SERVER_PID" --net -- ip addr replace 10.0.2.1/24 dev tun22
    nsenter --target "$SERVER_PID" --net -- ip link set tun22 up
    nsenter --target "$SERVER_PID" --net -- ip route replace 10.0.0.0/16 dev tun22

    nsenter --target "$SERVER_PID" --net -- iperf3 -s -B 10.0.2.1 -p 5201 > "$OUT_DIR/$variant-iperf.log" 2>&1 &
    IPERF_PID=$!
    wait_port || { echo "  $variant: iperf3 never listened" >&2; return 1; }
    sleep 0.5

    ip -s link show tun11 > "$OUT_DIR/$variant-links.log" 2>&1 || true
    ip -s link show tun22 >> "$OUT_DIR/$variant-links.log" 2>&1 || true
    ip route get 10.0.2.1 >> "$OUT_DIR/$variant-links.log" 2>&1 || true
    if ! ping -c 3 -i 0.2 -W 1 -q 10.0.2.1 > "$OUT_DIR/$variant-ping-before.log" 2>&1; then
        echo "  $variant: the path probe failed" >&2
        cat "$OUT_DIR/$variant-links.log" >&2
        cat "$OUT_DIR/$variant-ping-before.log" >&2
        cat "$OUT_DIR/$variant.log" >&2
        return 1
    fi
}

stop_variant() {
    [ -n "$SAMPLER_PID" ] && kill "$SAMPLER_PID" 2> /dev/null || true
    [ -n "$IPERF_PID" ] && kill "$IPERF_PID" 2> /dev/null || true
    [ -n "$FORWARDER_PID" ] && kill -9 "$FORWARDER_PID" 2> /dev/null || true
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2> /dev/null || true
    SAMPLER_PID=""
    IPERF_PID=""
    FORWARDER_PID=""
    SERVER_PID=""
    ip link del tun11 2> /dev/null || true
    ip link del tun22 2> /dev/null || true
    sleep 0.5
}

sample_start() {
    file=$1
    : > "$file"
    (
        while [ -n "$FORWARDER_PID" ] && kill -0 "$FORWARDER_PID" 2> /dev/null; do
            ps -p "$FORWARDER_PID" -o %cpu=,rss= --no-headers >> "$file" 2> /dev/null || true
            sleep 0.5
        done
    ) &
    SAMPLER_PID=$!
}

sample_stop() {
    file=$1
    [ -n "$SAMPLER_PID" ] && kill "$SAMPLER_PID" 2> /dev/null || true
    SAMPLER_PID=""
    python3 - "$file" << 'PY'
import sys
cpu = rss = 0.0
count = 0
for line in open(sys.argv[1]):
    parts = line.split()
    if len(parts) != 2:
        continue
    cpu += float(parts[0])
    rss = max(rss, float(parts[1]))
    count += 1
print(f"{cpu / count if count else 0:.1f} {rss:.0f}")
PY
}

emit() {
    variant=$1
    scenario=$2
    value=$3
    unit=$4
    cpu=$5
    rss=$6
    printf '{"engine":"%s","scenario":"%s","value":%s,"unit":"%s","cpu_pct":%s,"rss_kb":%s,"mtu":1500,"queues":%s}\n' \
        "$variant" "$scenario" "$value" "$unit" "$cpu" "$rss" "$QUEUES" >> "$RESULTS"
    printf '  %-28s %-6s %s %s cpu %s%% rss %s KB\n' "$variant" "$scenario" "$value" "$unit" "$cpu" "$rss"
}

run_variant() {
    variant=$1
    rep=$2
    command=$(command_for "$variant") || return 1
    echo "round $rep variant $variant"
    if ! start_variant "$variant"; then
        stop_variant
        return 0
    fi

    sample_start "$OUT_DIR/$variant-$rep.samples"
    timeout "$CLIENT_TIMEOUT" iperf3 -c 10.0.2.1 -p 5201 -t "$DURATION" -J > "$OUT_DIR/$variant-$rep-tcp.json" 2> /dev/null || true
    set -- $(sample_stop "$OUT_DIR/$variant-$rep.samples")
    tcp=$(python3 - "$OUT_DIR/$variant-$rep-tcp.json" << 'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("0"); raise SystemExit
end = d.get("end", {})
received = end.get("sum_received") or end.get("sum") or {}
print("%.3f" % (received.get("bits_per_second", 0) / 1e9))
PY
)
    emit "$variant" "tcp-${rep}" "$tcp" "Gbit/s" "$1" "$2"

    sample_start "$OUT_DIR/$variant-$rep-udp.samples"
    timeout "$CLIENT_TIMEOUT" iperf3 -c 10.0.2.1 -p 5201 -u -b 1G -t "$DURATION" -J > "$OUT_DIR/$variant-$rep-udp.json" 2> /dev/null || true
    set -- $(sample_stop "$OUT_DIR/$variant-$rep-udp.samples")
    udp_cpu=$1
    udp_rss=$2
    udp=$(python3 - "$OUT_DIR/$variant-$rep-udp.json" << 'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("0 0"); raise SystemExit
end = d.get("end", {})
total = end.get("sum") or {}
print("%.3f %.2f" % (total.get("bits_per_second", 0) / 1e9, total.get("lost_percent", 0)))
PY
)
    set -- $udp
    emit "$variant" "udp-${rep}" "$1" "Gbit/s" "$udp_cpu" "$udp_rss"

    timeout 10 ping -c 100 -i 0.01 -W 1 -q 10.0.2.1 > "$OUT_DIR/$variant-$rep-ping.log" 2>&1 || true
    rtt=$(python3 - "$OUT_DIR/$variant-$rep-ping.log" << 'PY'
import re, sys
text = open(sys.argv[1]).read()
m = re.search(r'= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', text)
print("%.3f" % float(m.group(2)) if m else "0")
PY
)
    emit "$variant" "ping-${rep}" "$rtt" "ms" "0" "0"

    stop_variant
}

runner_spec() {
    {
        printf '| property | value |\n|---|---|\n'
        printf '| runner image | %s %s |\n' "${ImageOS:-unknown}" "${ImageVersion:-}"
        printf '| cpu | %s |\n' "$(awk -F': ' '/model name/ {print $2; exit}' /proc/cpuinfo)"
        printf '| cpu cores | %s |\n' "$(nproc)"
        printf '| memory | %s |\n' "$(awk '/MemTotal/ {printf "%.1f GB", $2/1048576}' /proc/meminfo)"
        printf '| kernel | %s |\n' "$(uname -sr)"
        printf '| duration | %ss x %s rounds |\n' "$DURATION" "$REPEAT"
        printf '| queues | %s |\n' "$QUEUES"
    } > "$OUT_DIR/runner.md"
    cat "$OUT_DIR/runner.md" >&2
}

runner_spec
for knob in "net.ipv4.tcp_tw_reuse=1" "net.ipv4.ip_local_port_range=1024 65000"; do
    sysctl -qw "$knob" 2> /dev/null || true
done

rep=1
while [ "$rep" -le "$REPEAT" ]; do
    for variant in $VARIANTS; do
        run_variant "$variant" "$rep"
    done
    rep=$((rep + 1))
done

python3 - "$RESULTS" "$OUT_DIR/summary.md" << 'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
groups = {}
for row in rows:
    groups.setdefault((row["engine"], row["scenario"].rsplit("-", 1)[0]), []).append(row)
def median(values):
    values = sorted(values)
    return values[len(values) // 2] if values else 0
lines = ["| engine | scenario | median | cpu % | max rss MB |", "|---|---|---:|---:|---:|"]
for (engine, scenario), group in groups.items():
    value = median([row["value"] for row in group])
    cpu = median([row["cpu_pct"] for row in group])
    rss = max(row["rss_kb"] for row in group) / 1024
    lines.append(f"| {engine} | {scenario} | {value:.3f} {group[0]['unit']} | {cpu:.0f} | {rss:.1f} |")
open(sys.argv[2], "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
PY

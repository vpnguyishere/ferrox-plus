#!/usr/bin/env bash

UUID="f47ac10b-58cc-4372-a567-0e02b2c3d479"
PASSWORD="matrix-secret"
SS_PASSWORD="matrix-shadowsocks-password"
SS2022_PASSWORD="MDEyMzQ1Njc4OUFCQ0RFRg=="
HYSTERIA_AUTH="matrix-hysteria-auth"
HYSTERIA_V1_OBFS="matrix-hysteria-v1-xplus"
VLESS_ENC_CLIENT="mlkem768x25519plus.native.1rtt.2KpP3KYKjxF9Rew2c-oAq0YdFawg9Lhc6yzMrSWfZcAzN8O2MrVQEHCAKfOVdCyDAvIEI-gcswjOvDCsZcTPiFITitJt1SGrYsjF4pc_7cua3CNgZ5qUBrZEKRGvcQkdpYswh2ozDxApJParJXa8s-h9YeEWRKG8aGhwQhBq5RVIepsFaAa2SDQA7YUn2rBWKFmJc9gngJQfDftticxhWPC0h9BMgBxx5tiU46tNu1ifyjaWOcVoIwtxfFCSv-p2btNHJJeBOAdQ61dC46qdO2CzujO4clRz0TrB2tliQBi0BKVG8mgYtxZFOGoDtre3sTYO6CS5xExmcOp9zUrHBeoFo5quBZFr5nZ84pQ0NrYBigwemDFE0htQM1YHCFESm1eY_sWSfRGkCLC2KqVXh0cClKjIF2Fazgaoy6qACttDccd0YVtVzFgyNAi1tKXKjNMhgZIyx5e_QmhjJcdDCOS0tzE-ecJRggZ31XzLlPVCeeiuliwJ_UzOWXHOJ0wYiwwtiZhQYIwF7GqHBmF6hrqbSLm0Pau5wLKSUdc3OgjGxWMs34okmnoIvTWoA1Am-IKxCISsCdy-iqFghasCdruLb7luKgMT7soJ95NY0LQOn4FSonEZPKIP_rBvmKJJWyOtl6qThFNzfYBQD2pTM4aXZKrOrYB7kbI_CPqM9dE740IM-suSyoEBCSi8NCB6feoMw5PNdTRDhnyuFPjKL3o_61gMjJwsW8Vq3CKMVByMJXq8QqCmQlyRXxhFVTcNdAYOeePA_JczfWIOGzCIc5wuuAHFxzfAfpWMtlEe3BMxYySXEBTG8meB7nYULth9XorFvYyM7giO4_h7YGqZEfe5hDxnAUpN00nLEwaWNfhaq9x4p7KkCEG6xIFzBhN__7OJUTgARjCagHAxBgSWDCY8qqHI4ZYpzxTI8qkPvTRZBylJZkOhGKdI_XCb9ulTy0cpeeAIF2Fw_UF7RKQ7IrnF1Ycza7MFQzd1i6wPE8fDgBFE1Jgfi_Fg8UsZtSS_q_xnV-pqOPAkDcK9MDt7obIejfHPaKTBZfa-_kp-67l_TRaudHCWoDQ4mtaZcTRo8kNX4BZ1ibUqytYU-IucCfnG32iOlVxCSzA_2CiQqvgiApu3KfiqekBM2YoaIoDEFzmwJVlsSvMDufCf3mo43YhkQFdEHxFLkpgS4WcGPCK59PuM8lNzlDXCvkeNY2lwN8yv7sI06YCz31Q38gqNjsmrBPRYTOQ550Ag8UoTE5dZUOUfhMMaomIYOnA2zUpU_tWy-Vq-F8AL8vVyjEtJRunGY-Q1D9qIaCI1YHmiKQLACiOwR6RDu-Ok0SmtCKeI9iNfqYgbnYyXP2VVIGcpw7uIwVeW_bVMnYqZIgzL4_kMQqGwmGImusoHKvNhRVc6wrkzCdhbXpmAK0nIhtSde4Q9JYqrTVmQBGRLLEc9tAK8-4ydcvJJ3PWCablnEASktKvInUh3g0xQ2teRoqC_fXCi--E0VySRQ7CGWmA8RxNJmvA2WakGplG5QhoK8hSNiIgXmXph_MQO6M34HQtfqyHVqeItfyOmgns747xGrPs"
VLESS_ENC_SERVER="mlkem768x25519plus.native.600.7SIPAtLwXE0BAcgnUkP8ERcxxHc0NMa-7GE0fcqjc4b8ckDaZ2WEGg7FvAbJs_0ovWXWLWz4CYwjGoqT9TaiMw"

matrix_srvport() {
  python3 -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()'
}

matrix_udp_srvport() {
  python3 -c 'import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()'
}

matrix_udp_carrier() {
  case "$1" in
    *-kcp-*|*-hysteria-*|*-quic-*|hysteria-*|masque-*|warp-*|wireguard-*) return 0 ;;
    *) return 1 ;;
  esac
}

# A WARP cell needs an external engine that speaks WARP. At this pin only Aether
# qualifies: ZeroNet and xray-core are skipped for WARP cells.
matrix_warp_needs_external_reference() {
  [[ "$1" == warp-* ]]
}

# A filter names a whole rung: the id itself or a `-`-separated child of it, so
# `vless-raw-down-1` never selects `vless-raw-down-16`.
scenario_matches() {
  local id="$1" pattern="$2"
  [[ "$id" == "$pattern" || "$id" == "$pattern"-* ]]
}

# The scenario bases scripts/leg-gaps.txt files: the cells a bug-fix slice re-measures.
filed_gap_bases() {
  python3 "$(dirname "${BASH_SOURCE[0]}")/check-matrix-legs.py" --bases
}

matrix_server_serves() {
  case "$1:$2" in
    xray-core:hysteria-v1-*) return 1 ;;
    sing-box:hysteria-v1-*) return 0 ;;
    sing-box:wireguard-*) return 0 ;;
    xray-core:*-quic-*) return 1 ;;
    sing-box:*-quic-*) return 0 ;;
    sing-box:*) return 1 ;;
  esac
  return 0
}

# A pair can carry a scenario's transport and still not interoperate at its pins. Name that
# here rather than letting the cell fail as a workload fault: the reason reaches the bundle's
# skipped list, so a reader sees which side is behind instead of a zero.
matrix_engine_skip_reason() {
  local engine="$1" id="$2" role="${3:-client}"
  if [[ "$id" == wireguard-kernel-* ]]; then
    if [[ "$(uname -s)" != Linux ]]; then
      printf '%s\n' "the kernel WireGuard device is Linux-only"
      return 0
    fi
    if [[ "$role" == client && "$engine" != ferrox ]]; then
      printf '%s\n' "only ferrox opens the kernel WireGuard device in this matrix"
      return 0
    fi
    if [[ "$role" == client && ! -d /sys/module/wireguard ]]; then
      printf '%s\n' "this runner has no wireguard module"
      return 0
    fi
  fi
  if [[ "$engine" == "aether" ]]; then
    case "$id" in
      masque-* | wireguard-raw-* | warp-*) ;;
      *)
        printf '%s\n' "Aether at this pin only speaks MASQUE, WireGuard and WARP"
        return 0
        ;;
    esac
    if [[ "$role" == server ]]; then
      printf '%s\n' "Aether is a client-only reference"
      return 0
    fi
  fi
  if [[ "$engine" == zeronet && "$role" == server && "$id" == warp-* ]]; then
    printf '%s\n' "ZeroNet at this pin has a WARP client, not a WARP server"
    return 0
  fi
  if [[ "$engine" == zeronet && "$id" == warp-* ]]; then
    printf '%s\n' "ZeroNet at this pin drops ADDRESS_ASSIGN and dials from its configured address, which a shared WARP server has already assigned to another tunnel"
    return 0
  fi
  if [[ "$engine" == "leaf" && "$id" == vless-* && "$id" != *-vision-* ]]; then
    printf '%s\n' "leaf at this pin only sends VLESS with the Vision flow, which this scenario does not configure"
    return 0
  fi
  if [[ "$engine" == sing-box && "$id" == shadowsocks* && "$id" != shadowsocks-raw-* && "$id" != shadowsocks2022-raw-* ]]; then
    printf '%s\n' "sing-box at this pin has no stream layer on a Shadowsocks outbound"
    return 0
  fi
  if [[ "$engine" == ferrox && "$role" == server && "$id" == shadowsocks*reality* ]]; then
    printf '%s\n' "ferrox has no Shadowsocks REALITY server role; this lane dials it and xray-core serves it"
    return 0
  fi
  if [[ "$id" == vless-vision-reality-android-* && "$role" == client ]]; then
    case "$engine" in
      xray-core | xray-core-rust | sing-box | zeronet)
        printf '%s\n' "android's uTLS preset has no TLS 1.3 suites or key share, so REALITY cannot establish"
        return 0
        ;;
    esac
  fi
  case "$engine:$id" in
    sing-box:*-quic-*)
      printf '%s\n' "sing-box at this pin has no QUIC transport" ;;
    sing-box:*-xhttp-*|sing-box:*-kcp-*)
      printf '%s\n' "sing-box at this pin has no xhttp or KCP transport" ;;
    sing-box:*-hysteria-*)
      printf '%s\n' "sing-box at this pin has no VLESS over Hysteria transport" ;;
    sing-box:*-encryption-*)
      printf '%s\n' "sing-box at this pin has no VLESS encryption field" ;;
    xray-core:*-quic-*)
      printf '%s\n' "xray-core at this pin removed the QUIC transport; xhttp stream-one h3 replaces it" ;;
    xray-rust:*-quic-*)
      printf '%s\n' "xray-rust at this pin removed the QUIC transport" ;;
    zeronet:*-quic-*)
      printf '%s\n' "zeronet at this pin has no VLESS over QUIC transport" ;;
    leaf:*-quic-*)
      printf '%s\n' "leaf at this pin has no QUIC transport" ;;
    leaf:*-xhttp-*)
      printf '%s\n' "leaf at this pin has no xhttp transport" ;;
    leaf:*-kcp-*)
      printf '%s\n' "leaf at this pin has no KCP transport" ;;
    leaf:*-hysteria-*|leaf:hysteria-v1-*)
      printf '%s\n' "leaf at this pin has no Hysteria transport" ;;
    leaf:*-encryption-*)
      printf '%s\n' "leaf at this pin has no VLESS encryption" ;;
    leaf:*-grpc-*)
      printf '%s\n' "leaf at this pin has no gRPC transport" ;;
    leaf:*-httpupgrade-*)
      printf '%s\n' "leaf at this pin has no HTTPUpgrade transport" ;;
    leaf:http-*)
      printf '%s\n' "leaf at this pin has no HTTP proxy outbound" ;;
    leaf:shadowsocks2022-*)
      printf '%s\n' "leaf at this pin has no Shadowsocks 2022" ;;
    xray-core-rust:wireguard-*|zeronet:wireguard-*|xray-rust:wireguard-*|leaf:wireguard-*)
      printf '%s\n' "$engine at this pin has no WireGuard handler" ;;
    xray-rust:*-hysteria-*)
      printf '%s\n' "xray-rust at this pin has no VLESS over Hysteria; its Hysteria outbound is the native proxy protocol" ;;
    xray-core-rust:masque-*|zeronet:masque-*|sing-box:masque-*|xray-rust:masque-*|leaf:masque-*)
      printf '%s\n' "$engine at this pin has no MASQUE CONNECT-IP outbound" ;;
    xray-core:warp-*)
      if [[ "$role" == server ]]; then
        printf '%s\n' "xray-core's MASQUE inbound speaks CONNECT-IP, not WARP's profile"
      else
        printf '%s\n' "xray-core at this pin has no WARP carrier"
      fi ;;
    xray-core-rust:warp-*|sing-box:warp-*|xray-rust:warp-*|leaf:warp-*)
      printf '%s\n' "$engine at this pin has no WARP carrier" ;;
    *)
      return 1 ;;
  esac
  return 0
}

server_config() {
  local port="$3" cover="${4:-}"
  local extra=""
  local routes="{\"type\": \"field\", \"inboundTag\": [\"matrix-server\"], \"outboundTag\": \"direct\"}"
  if [[ -n "$cover" ]]; then
    extra=", $cover"
    routes="$routes, {\"type\": \"field\", \"inboundTag\": [\"matrix-cover\"], \"outboundTag\": \"direct\"}"
  fi
  cat <<EOF
{"inbounds": [{"tag": "matrix-server", "listen": "127.0.0.1", "port": $port, $1}$extra],
 "outbounds": [{$2}, {"tag": "direct", "protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}],
 "routing": {"rules": [{"type": "field", "inboundTag": ["harness-socks"], "outboundTag": "proxy"}, $routes]}}
EOF
}

# A routed cell pays for the table it walks: a thousand rules that do not match, then the one that
# sends the sink's own address direct. The bytes on the wire are the raw lane's; the CPU is not.
routed_server_config() {
  server_config "$1" "$2" "$3" "${4:-}" | python3 -c '
import json, sys
d = json.load(sys.stdin)
d.setdefault("routing", {}).setdefault("rules", []).extend(
    {"type": "field", "domain": [f"no-route-{i}.test"], "outboundTag": "direct"}
    for i in range(1000)
)
d["routing"]["rules"].append(
    {"type": "field", "ip": ["127.0.0.1/32"], "outboundTag": "direct"}
)
print(json.dumps(d, separators=(",", ":")))
'
}

# REALITY's server dials `dest` for the certificate it presents, so the fixture gives it a live
# TLS inbound in the same process instead of a public endpoint the runner would have to reach.
cover_inbound() {
  local port="$1" dir
  dir="$(matrix_tls_dir)"
  echo "{\"tag\": \"matrix-cover\", \"listen\": \"127.0.0.1\", \"port\": $port, \"protocol\": \"vless\", \"settings\": {\"clients\": [{\"id\": \"$UUID\"}], \"decryption\": \"none\"}, \"streamSettings\": {\"network\": \"tcp\", \"security\": \"tls\", \"tlsSettings\": {\"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"keyFile\": \"$dir/key.pem\"}]}}}"
}

vless_server() {
  echo "\"protocol\": \"vless\", \"settings\": {\"clients\": [{\"id\": \"$UUID\"}], \"decryption\": \"none\"}$1"
}
vless_client() {
  echo "\"tag\": \"proxy\", \"protocol\": \"vless\", \"settings\": {\"vnext\": [{\"address\": \"127.0.0.1\", \"port\": $2, \"users\": [{\"id\": \"$UUID\", \"encryption\": \"none\"}]}]}$1"
}
vless_server_encryption() {
  echo "\"protocol\": \"vless\", \"settings\": {\"clients\": [{\"id\": \"$UUID\"}], \"decryption\": \"$VLESS_ENC_SERVER\"}$1"
}
vless_client_encryption() {
  echo "\"tag\": \"proxy\", \"protocol\": \"vless\", \"settings\": {\"vnext\": [{\"address\": \"127.0.0.1\", \"port\": $2, \"users\": [{\"id\": \"$UUID\", \"encryption\": \"$VLESS_ENC_CLIENT\"}]}]}$1"
}
# The TLS arm's fixture: a self-signed certificate and its key, minted into the ignored target
# tree by the harness at run time, so no private key is ever in the tree and no CA is needed in
# the runner's store. The path is absolute, because the engines do not read it the same way:
# `xray-core` resolves a relative certificate path against its own executable directory rather
# than the directory it was spawned in, so a relative path finds the file for one engine and
# not for another. On Windows the absolute path is the one Windows spells, because a Git-Bash
# path is not one a native engine can open; the pin is hashed off the minted file, so the two
# cannot drift.
matrix_tls_dir() {
  local dir="target/matrix-tls" root
  case "${OS:-}" in
    Windows_NT) root="$(pwd -W 2>/dev/null || pwd)" ;;
    *) root="$(pwd)" ;;
  esac
  dir="$root/$dir"
  if [[ ! -s "$dir/cert.pem" ]]; then
    "${bench_bin:?no harness binary to mint the fixture}" make-tls "$dir" || return 1
  fi
  echo "$dir"
}

matrix_tls_pin() {
  python3 -c 'import base64, hashlib, sys
pem = open(sys.argv[1]).read()
body = "".join(line for line in pem.splitlines() if line and not line.startswith("-----"))
print(hashlib.sha256(base64.b64decode(body)).hexdigest())' "$1"
}

# WARP pins the edge's SubjectPublicKeyInfo, not the certificate hash.
matrix_tls_spki() {
  python3 scripts/cert_spki.py "$1"
}

matrix_reality_dir() {
  local dir="target/matrix-reality" root
  case "${OS:-}" in
    Windows_NT) root="$(pwd -W 2>/dev/null || pwd)" ;;
    *) root="$(pwd)" ;;
  esac
  dir="$root/$dir"
  mkdir -p "$dir"
  if [[ ! -s "$dir/keys.txt" ]]; then
    "${ferrox_bin:?no ferrox binary to mint the reality keypair}" x25519 >"$dir/keys.txt" || return 1
  fi
  echo "$dir"
}

matrix_reality_private() {
  sed -n 's/^PrivateKey: //p' "$(matrix_reality_dir)/keys.txt"
}

matrix_reality_public() {
  sed -n 's/^Password (PublicKey): //p' "$(matrix_reality_dir)/keys.txt"
}

matrix_wireguard_dir() {
  local dir="target/matrix-wireguard" root
  case "${OS:-}" in
    Windows_NT) root="$(pwd -W 2>/dev/null || pwd)" ;;
    *) root="$(pwd)" ;;
  esac
  dir="$root/$dir"
  mkdir -p "$dir"
  if [[ ! -s "$dir/server.txt" ]]; then
    "${ferrox_bin:?no ferrox binary to mint the WireGuard keypairs}" x25519 >"$dir/server.txt" || return 1
  fi
  echo "$dir"
}

matrix_wireguard_key() {
  local file="$1" field="$2" value
  value="$(sed -n "s/^${field}: //p" "$file")" || return 1
  [[ -n "$value" ]] || return 1
  printf '%s\n' "$value"
}

matrix_wireguard_server_private() {
  matrix_wireguard_key "$(matrix_wireguard_dir)/server.txt" PrivateKey
}

matrix_wireguard_server_public() {
  matrix_wireguard_key "$(matrix_wireguard_dir)/server.txt" 'Password (PublicKey)'
}

# One identity per engine: the peer's replay timestamp belongs to a key, and a shared
# key lets one engine's handshake lock every other engine out of the server for its
# retry interval.
matrix_wireguard_engines() {
  printf '%s\n' ferrox aether xray-core sing-box
}

matrix_wireguard_index() {
  local engine="$1" index=0
  for candidate in $(matrix_wireguard_engines); do
    if [[ "$candidate" == "$engine" ]]; then
      printf '%s\n' "$index"
      return 0
    fi
    index=$((index + 1))
  done
  return 1
}

matrix_wireguard_engine_dir() {
  local dir
  dir="$(matrix_wireguard_dir)/$1"
  mkdir -p "$dir" || return 1
  if [[ ! -s "$dir/client.txt" ]]; then
    "${ferrox_bin:?no ferrox binary to mint the WireGuard keypairs}" x25519 >"$dir/client.txt" || return 1
  fi
  echo "$dir"
}

matrix_wireguard_engine_private() {
  matrix_wireguard_key "$(matrix_wireguard_engine_dir "$1")/client.txt" PrivateKey
}

matrix_wireguard_engine_public() {
  matrix_wireguard_key "$(matrix_wireguard_engine_dir "$1")/client.txt" 'Password (PublicKey)'
}

matrix_wireguard_engine_v4() {
  local index
  index="$(matrix_wireguard_index "$1")" || return 1
  printf '10.0.0.%d/32\n' "$((index + 2))"
}

matrix_wireguard_engine_v6() {
  local index
  index="$(matrix_wireguard_index "$1")" || return 1
  printf 'fd00::%d/128\n' "$((index + 2))"
}

# The server's TLS: the identity the client is asked to trust.
tls_server_settings() {
  local dir
  dir="$(matrix_tls_dir)"
  echo "\"streamSettings\": {\"network\": \"tcp\", \"security\": \"tls\", \"tlsSettings\": {\"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"keyFile\": \"$dir/key.pem\"}]}}"
}

# The client's TLS: the roots this tree reads, the pin the reference reads, and the
# verify certificate the third reference reads. Each takes the one it knows.
tls_client_settings() {
  local dir pin
  dir="$(matrix_tls_dir)"
  pin="$(matrix_tls_pin "$dir/cert.pem")"
  echo "\"streamSettings\": {\"network\": \"tcp\", \"security\": \"tls\", \"tlsSettings\": {\"serverName\": \"carrier.test\", \"caCertFile\": \"$dir/cert.pem\", \"pinnedPeerCertSha256\": \"$pin\", \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"usage\": \"verify\"}]}}"
}

# The TLS arm of a carried lane: the same identity the tcp arm uses, under the carrier's framing.
tls_ws_server_settings() {
  local dir
  dir="$(matrix_tls_dir)"
  echo "\"streamSettings\": {\"network\": \"ws\", \"security\": \"tls\", \"wsSettings\": {\"path\": \"/tunnel\"}, \"tlsSettings\": {\"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"keyFile\": \"$dir/key.pem\"}]}}"
}

tls_ws_client_settings() {
  local dir pin
  dir="$(matrix_tls_dir)"
  pin="$(matrix_tls_pin "$dir/cert.pem")"
  echo "\"streamSettings\": {\"network\": \"ws\", \"security\": \"tls\", \"wsSettings\": {\"path\": \"/tunnel\"}, \"tlsSettings\": {\"serverName\": \"carrier.test\", \"caCertFile\": \"$dir/cert.pem\", \"pinnedPeerCertSha256\": \"$pin\", \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"usage\": \"verify\"}]}}"
}

tls_grpc_server_settings() {
  local dir
  dir="$(matrix_tls_dir)"
  echo "\"streamSettings\": {\"network\": \"grpc\", \"grpcSettings\": {\"serviceName\": \"TunnelService\"}, \"security\": \"tls\", \"tlsSettings\": {\"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"keyFile\": \"$dir/key.pem\"}]}}"
}

tls_grpc_client_settings() {
  local dir pin
  dir="$(matrix_tls_dir)"
  pin="$(matrix_tls_pin "$dir/cert.pem")"
  echo "\"streamSettings\": {\"network\": \"grpc\", \"grpcSettings\": {\"serviceName\": \"TunnelService\"}, \"security\": \"tls\", \"tlsSettings\": {\"serverName\": \"carrier.test\", \"caCertFile\": \"$dir/cert.pem\", \"pinnedPeerCertSha256\": \"$pin\", \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"usage\": \"verify\"}]}}"
}

reality_server_settings() {
  local network="$1" carrier="$2"
  echo "\"streamSettings\": {\"network\": \"$network\"$carrier, \"security\": \"reality\", \"realitySettings\": {\"dest\": \"${MATRIX_REALITY_DEST:-127.0.0.1:9}\", \"serverNames\": [\"carrier.test\"], \"privateKey\": \"$(matrix_reality_private)\", \"shortIds\": [\"0123456789abcdef\"]}}"
}

reality_client_settings() {
  local network="$1" carrier="$2" fingerprint="${3:-chrome}"
  echo "\"streamSettings\": {\"network\": \"$network\"$carrier, \"security\": \"reality\", \"realitySettings\": {\"serverName\": \"carrier.test\", \"fingerprint\": \"$fingerprint\", \"publicKey\": \"$(matrix_reality_public)\", \"shortId\": \"0123456789abcdef\"}}"
}

kcp_settings() {
  echo '"streamSettings": {"network": "kcp", "kcpSettings": {"mtu": 1350, "tti": 50, "uplinkCapacity": 5, "downlinkCapacity": 20, "congestion": false, "readBufferSize": 2, "writeBufferSize": 2, "header": {"type": "none"}, "seed": "matrix"}}'
}

# QUIC is TLS by definition, and the ALPN is the one every pin reads: h3. xray-core-rust
# otherwise defaults its TLS to h2/http1.1, which a h3-only lane refuses.
quic_server_settings() {
  local dir
  dir="$(matrix_tls_dir)"
  echo "\"streamSettings\": {\"network\": \"quic\", \"security\": \"tls\", \"tlsSettings\": {\"alpn\": [\"h3\"], \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"keyFile\": \"$dir/key.pem\"}]}, \"quicSettings\": {}}"
}

quic_client_settings() {
  local dir pin
  dir="$(matrix_tls_dir)"
  pin="$(matrix_tls_pin "$dir/cert.pem")"
  echo "\"streamSettings\": {\"network\": \"quic\", \"security\": \"tls\", \"tlsSettings\": {\"serverName\": \"carrier.test\", \"alpn\": [\"h3\"], \"caCertFile\": \"$dir/cert.pem\", \"pinnedPeerCertSha256\": \"$pin\", \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"usage\": \"verify\"}]}, \"quicSettings\": {}}"
}

# MASQUE CONNECT-IP is TLS by definition; the h3 ALPN names the carrier this cell measures.
masque_server_settings() {
  local dir
  dir="$(matrix_tls_dir)"
  echo "\"protocol\": \"masque\", \"settings\": {\"warp\": true, \"users\": [{\"email\": \"matrix@carrier.test\", \"pass\": \"$PASSWORD\"}], \"address\": [\"10.13.0.1/24\", \"fd13::1/64\"]}, \"streamSettings\": {\"network\": \"masque\", \"security\": \"tls\", \"tlsSettings\": {\"alpn\": [\"h3\"], \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"keyFile\": \"$dir/key.pem\"}]}}"
}

masque_client_settings() {
  local port="$1" dir pin auth
  dir="$(matrix_tls_dir)"
  pin="$(matrix_tls_pin "$dir/cert.pem")"
  auth="$(printf '%s' "matrix@carrier.test:$PASSWORD" | base64)"
  echo "\"tag\": \"proxy\", \"protocol\": \"masque\", \"settings\": {\"address\": \"127.0.0.1\", \"port\": $port, \"largeSegments\": true}, \"streamSettings\": {\"network\": \"masque\", \"security\": \"tls\", \"masqueSettings\": {\"headers\": {\"Authorization\": \"Basic $auth\"}}, \"tlsSettings\": {\"serverName\": \"carrier.test\", \"alpn\": [\"h3\"], \"caCertFile\": \"$dir/cert.pem\", \"pinnedPeerCertSha256\": \"$pin\", \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"usage\": \"verify\"}]}}"
}

# WARP's MASQUE half against this matrix's own server: the outbound is the warp
# dialect with a pinned mode, a WireGuard half the pinned mode never dials, and
# a stream TLS fixture the Aether adapter alone reads for its client identity.
warp_client_settings() {
  local port="$1" key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" pem="MEECAQEwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQg==" dir pin
  dir="$(matrix_tls_dir)" || return 1
  pin="$(matrix_tls_spki "$dir/cert.pem")" || return 1
  echo "\"tag\": \"proxy\", \"protocol\": \"warp\", \"settings\": {\"mode\": \"masque\", \"identity\": {\"deviceId\": \"matrix\", \"token\": \"matrix\", \"wireguard\": {\"privateKey\": \"$key\", \"publicKey\": \"$key\", \"endpoint\": \"192.0.2.1:2408\", \"address\": [\"10.13.0.2/32\", \"fd13::2/128\"], \"reserved\": [0, 0, 0]}, \"masque\": {\"privateKey\": \"$pem\", \"publicKey\": \"$pin\", \"address\": [\"10.13.0.2/32\", \"fd13::2/128\"]}}, \"masque\": {\"address\": \"127.0.0.1\", \"port\": $port, \"serverName\": \"carrier.test\", \"host\": \"carrier.test\", \"path\": \"/\"}}, \"streamSettings\": {\"network\": \"masque\", \"security\": \"tls\", \"tlsSettings\": {\"serverName\": \"carrier.test\", \"alpn\": [\"h3\"], \"caCertFile\": \"$dir/cert.pem\", \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"keyFile\": \"$dir/key.pem\", \"usage\": \"verify\"}]}}"
}

httpupgrade_settings() {
  echo '"streamSettings": {"network": "httpupgrade", "httpupgradeSettings": {"path": "/tunnel", "host": "carrier.test"}}'
}

# Early data is a query parameter on the carrier's path: the client writes the first `ed` bytes
# before the upgrade completes and the server holds them until the session is bound.
ws_ed_settings() {
  echo '"streamSettings": {"network": "ws", "wsSettings": {"path": "/tunnel?ed=2048"}}'
}

tls_ws_ed_server_settings() {
  local dir
  dir="$(matrix_tls_dir)"
  echo "\"streamSettings\": {\"network\": \"ws\", \"wsSettings\": {\"path\": \"/tunnel?ed=2048\"}, \"security\": \"tls\", \"tlsSettings\": {\"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"keyFile\": \"$dir/key.pem\"}]}}"
}

tls_ws_ed_client_settings() {
  local dir pin
  dir="$(matrix_tls_dir)"
  pin="$(matrix_tls_pin "$dir/cert.pem")"
  echo "\"streamSettings\": {\"network\": \"ws\", \"wsSettings\": {\"path\": \"/tunnel?ed=2048\"}, \"security\": \"tls\", \"tlsSettings\": {\"serverName\": \"carrier.test\", \"caCertFile\": \"$dir/cert.pem\", \"pinnedPeerCertSha256\": \"$pin\", \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"usage\": \"verify\"}]}}"
}

httpupgrade_ed_settings() {
  echo '"streamSettings": {"network": "httpupgrade", "httpupgradeSettings": {"path": "/tunnel?ed=2048", "host": "carrier.test"}}'
}

tls_httpupgrade_server_settings() {
  local dir
  dir="$(matrix_tls_dir)"
  echo "\"streamSettings\": {\"network\": \"httpupgrade\", \"httpupgradeSettings\": {\"path\": \"/tunnel\", \"host\": \"carrier.test\"}, \"security\": \"tls\", \"tlsSettings\": {\"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"keyFile\": \"$dir/key.pem\"}]}}"
}

tls_httpupgrade_client_settings() {
  local dir pin
  dir="$(matrix_tls_dir)"
  pin="$(matrix_tls_pin "$dir/cert.pem")"
  echo "\"streamSettings\": {\"network\": \"httpupgrade\", \"httpupgradeSettings\": {\"path\": \"/tunnel\", \"host\": \"carrier.test\"}, \"security\": \"tls\", \"tlsSettings\": {\"serverName\": \"carrier.test\", \"caCertFile\": \"$dir/cert.pem\", \"pinnedPeerCertSha256\": \"$pin\", \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"usage\": \"verify\"}]}}"
}

tls_httpupgrade_ed_server_settings() {
  local dir
  dir="$(matrix_tls_dir)"
  echo "\"streamSettings\": {\"network\": \"httpupgrade\", \"httpupgradeSettings\": {\"path\": \"/tunnel?ed=2048\", \"host\": \"carrier.test\"}, \"security\": \"tls\", \"tlsSettings\": {\"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"keyFile\": \"$dir/key.pem\"}]}}"
}

tls_httpupgrade_ed_client_settings() {
  local dir pin
  dir="$(matrix_tls_dir)"
  pin="$(matrix_tls_pin "$dir/cert.pem")"
  echo "\"streamSettings\": {\"network\": \"httpupgrade\", \"httpupgradeSettings\": {\"path\": \"/tunnel?ed=2048\", \"host\": \"carrier.test\"}, \"security\": \"tls\", \"tlsSettings\": {\"serverName\": \"carrier.test\", \"caCertFile\": \"$dir/cert.pem\", \"pinnedPeerCertSha256\": \"$pin\", \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"usage\": \"verify\"}]}}"
}

grpc_multi_settings() {
  echo '"streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": "TunnelService", "multiMode": true}}'
}

tls_grpc_multi_server_settings() {
  local dir
  dir="$(matrix_tls_dir)"
  echo "\"streamSettings\": {\"network\": \"grpc\", \"grpcSettings\": {\"serviceName\": \"TunnelService\", \"multiMode\": true}, \"security\": \"tls\", \"tlsSettings\": {\"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"keyFile\": \"$dir/key.pem\"}]}}"
}

tls_grpc_multi_client_settings() {
  local dir pin
  dir="$(matrix_tls_dir)"
  pin="$(matrix_tls_pin "$dir/cert.pem")"
  echo "\"streamSettings\": {\"network\": \"grpc\", \"grpcSettings\": {\"serviceName\": \"TunnelService\", \"multiMode\": true}, \"security\": \"tls\", \"tlsSettings\": {\"serverName\": \"carrier.test\", \"caCertFile\": \"$dir/cert.pem\", \"pinnedPeerCertSha256\": \"$pin\", \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"usage\": \"verify\"}]}}"
}

xhttp_h1_settings() {
  local mode="$1"
  echo "\"streamSettings\": {\"network\": \"xhttp\", \"xhttpSettings\": {\"path\": \"/share\", \"mode\": \"$mode\"}}"
}

# xHTTP over TLS: the ALPN is what decides H1 from H2; the carrier's own mode stays independent.
tls_xhttp_server_settings() {
  local mode="$1" alpn="$2" dir
  dir="$(matrix_tls_dir)"
  echo "\"streamSettings\": {\"network\": \"xhttp\", \"xhttpSettings\": {\"path\": \"/share\", \"mode\": \"$mode\"}, \"security\": \"tls\", \"tlsSettings\": {\"alpn\": [\"$alpn\"], \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"keyFile\": \"$dir/key.pem\"}]}}"
}

tls_xhttp_client_settings() {
  local mode="$1" alpn="$2" dir pin
  dir="$(matrix_tls_dir)"
  pin="$(matrix_tls_pin "$dir/cert.pem")"
  echo "\"streamSettings\": {\"network\": \"xhttp\", \"xhttpSettings\": {\"path\": \"/share\", \"mode\": \"$mode\"}, \"security\": \"tls\", \"tlsSettings\": {\"serverName\": \"carrier.test\", \"alpn\": [\"$alpn\"], \"caCertFile\": \"$dir/cert.pem\", \"pinnedPeerCertSha256\": \"$pin\", \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"usage\": \"verify\"}]}}"
}

hysteria_server_settings() {
  local dir
  dir="$(matrix_tls_dir)"
  echo "\"streamSettings\": {\"network\": \"hysteria\", \"hysteriaSettings\": {\"version\": 2, \"auth\": \"$HYSTERIA_AUTH\"}, \"security\": \"tls\", \"tlsSettings\": {\"alpn\": [\"h3\"], \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"keyFile\": \"$dir/key.pem\"}]}}"
}

hysteria_client_settings() {
  local dir pin
  dir="$(matrix_tls_dir)"
  pin="$(matrix_tls_pin "$dir/cert.pem")"
  echo "\"streamSettings\": {\"network\": \"hysteria\", \"hysteriaSettings\": {\"version\": 2, \"auth\": \"$HYSTERIA_AUTH\"}, \"security\": \"tls\", \"tlsSettings\": {\"serverName\": \"carrier.test\", \"alpn\": [\"h3\"], \"caCertFile\": \"$dir/cert.pem\", \"pinnedPeerCertSha256\": \"$pin\", \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"usage\": \"verify\"}]}}"
}

hysteria_v1_server_settings() {
  local dir
  dir="$(matrix_tls_dir)"
  echo "\"protocol\": \"hysteria\", \"settings\": {\"version\": 1, \"users\": [{\"auth\": \"$HYSTERIA_AUTH\"}]}, \"streamSettings\": {\"network\": \"hysteria\", \"security\": \"tls\", \"tlsSettings\": {\"alpn\": [\"hysteria\"], \"obfs\": \"$HYSTERIA_V1_OBFS\", \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"keyFile\": \"$dir/key.pem\"}]}}"
}

hysteria_v1_client_settings() {
  local dir port="$1"
  dir="$(matrix_tls_dir)"
  echo "\"tag\": \"proxy\", \"protocol\": \"hysteria\", \"settings\": {\"version\": 1, \"address\": \"127.0.0.1\", \"port\": $port, \"auth\": \"$HYSTERIA_AUTH\"}, \"streamSettings\": {\"network\": \"hysteria\", \"security\": \"tls\", \"hysteriaSettings\": {\"version\": 1, \"auth\": \"$HYSTERIA_AUTH\"}, \"tlsSettings\": {\"serverName\": \"carrier.test\", \"alpn\": [\"hysteria\"], \"caCertFile\": \"$dir/cert.pem\", \"obfs\": \"$HYSTERIA_V1_OBFS\"}}"
}

wireguard_server() {
  local peers="" engine peer public v4 v6 secret
  secret="$(matrix_wireguard_server_private)" || return 1
  for engine in $(matrix_wireguard_engines); do
    public="$(matrix_wireguard_engine_public "$engine")" || return 1
    v4="$(matrix_wireguard_engine_v4 "$engine")" || return 1
    v6="$(matrix_wireguard_engine_v6 "$engine")" || return 1
    peer="{\"publicKey\": \"$public\", \"allowedIPs\": [\"$v4\", \"$v6\"]}"
    peers+="${peers:+,}$peer"
  done
  echo "\"protocol\": \"wireguard\", \"settings\": {\"secretKey\": \"$secret\", \"address\": [\"10.0.0.1/32\", \"fd00::1/128\"], \"mtu\": 1420, \"peers\": [$peers]}"
}

wireguard_client() {
  local port="$1" engine="${2:-ferrox}" kernel="${3:-true}" secret v4 v6 server
  secret="$(matrix_wireguard_engine_private "$engine")" || return 1
  v4="$(matrix_wireguard_engine_v4 "$engine")" || return 1
  v6="$(matrix_wireguard_engine_v6 "$engine")" || return 1
  server="$(matrix_wireguard_server_public)" || return 1
  echo "\"tag\": \"proxy\", \"protocol\": \"wireguard\", \"settings\": {\"isClient\": true, \"largeSegments\": true, \"noKernelTun\": $kernel, \"secretKey\": \"$secret\", \"address\": [\"$v4\", \"$v6\"], \"mtu\": 1420, \"peers\": [{\"publicKey\": \"$server\", \"endpoint\": \"127.0.0.1:$port\", \"allowedIPs\": [\"0.0.0.0/0\", \"::/0\"]}]}"
}

wireguard_kernel_client() {
  wireguard_client "$1" "${2:-ferrox}" false
}

vless_server_vision() {
  echo "\"protocol\": \"vless\", \"settings\": {\"clients\": [{\"id\": \"$UUID\", \"flow\": \"xtls-rprx-vision\"}], \"decryption\": \"none\"}$1"
}

vless_client_vision() {
  echo "\"tag\": \"proxy\", \"protocol\": \"vless\", \"settings\": {\"vnext\": [{\"address\": \"127.0.0.1\", \"port\": $2, \"users\": [{\"id\": \"$UUID\", \"encryption\": \"none\", \"flow\": \"xtls-rprx-vision\"}]}]}$1"
}

stream_json() {
  case "$1" in
    tcp) echo '"streamSettings": {"network": "tcp"}' ;;
    ws) echo '"streamSettings": {"network": "ws", "wsSettings": {"path": "/tunnel"}}' ;;
    grpc) echo '"streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": "TunnelService"}}' ;;
    xhttp) echo '"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share"}}' ;;
  esac
}

# VMess, Trojan and both Shadowsocks dialects share one carrier surface. The carrier token is
# read from the scenario id, so a protocol adds a carrier with one case arm rather than one per
# protocol, and the scenario list can grow without the config table growing with it.
carrier_of() {
  case "$1" in
    *-tls-httpupgrade-ed-*) echo tls-httpupgrade-ed ;;
    *-tls-httpupgrade-*) echo tls-httpupgrade ;;
    *-httpupgrade-ed-*) echo httpupgrade-ed ;;
    *-httpupgrade-*) echo httpupgrade ;;
    *-tls-ws-ed-*) echo tls-ws-ed ;;
    *-ws-ed-*) echo ws-ed ;;
    *-tls-ws-*) echo tls-ws ;;
    *-ws-*) echo ws ;;
    *-tls-grpc-multi-*) echo tls-grpc-multi ;;
    *-grpc-multi-*) echo grpc-multi ;;
    *-tls-grpc-*) echo tls-grpc ;;
    *-grpc-*) echo grpc ;;
    *-tls-xhttp-h3-*) echo tls-xhttp-h3 ;;
    *-tls-xhttp-h2-*) echo tls-xhttp-h2 ;;
    *-tls-xhttp-h1-*) echo tls-xhttp-h1 ;;
    *-xhttp-streamone-*) echo xhttp-streamone ;;
    *-xhttp-streamup-*) echo xhttp-streamup ;;
    *-xhttp-packets-*) echo xhttp-packets ;;
    *-xhttp-*) echo xhttp ;;
    *-reality-raw-*) echo reality-raw ;;
    *-tls-raw-*) echo tls-raw ;;
    *-kcp-*) echo kcp ;;
    *-quic-*) echo quic ;;
    *-hysteria-*) echo hysteria ;;
    *-raw-*) echo raw ;;
    *) return 1 ;;
  esac
}

carrier_server_stream() {
  carrier_stream "$1" server
}

carrier_stream() {
  local carrier="$1" role="$2"
  case "$carrier" in
    raw) stream_json tcp ;;
    tls-raw) if [[ "$role" == server ]]; then tls_server_settings; else tls_client_settings; fi ;;
    ws) stream_json ws ;;
    tls-ws) if [[ "$role" == server ]]; then tls_ws_server_settings; else tls_ws_client_settings; fi ;;
    ws-ed) ws_ed_settings ;;
    tls-ws-ed) if [[ "$role" == server ]]; then tls_ws_ed_server_settings; else tls_ws_ed_client_settings; fi ;;
    httpupgrade) httpupgrade_settings ;;
    tls-httpupgrade) if [[ "$role" == server ]]; then tls_httpupgrade_server_settings; else tls_httpupgrade_client_settings; fi ;;
    httpupgrade-ed) httpupgrade_ed_settings ;;
    tls-httpupgrade-ed) if [[ "$role" == server ]]; then tls_httpupgrade_ed_server_settings; else tls_httpupgrade_ed_client_settings; fi ;;
    grpc) stream_json grpc ;;
    tls-grpc) if [[ "$role" == server ]]; then tls_grpc_server_settings; else tls_grpc_client_settings; fi ;;
    grpc-multi) grpc_multi_settings ;;
    tls-grpc-multi) if [[ "$role" == server ]]; then tls_grpc_multi_server_settings; else tls_grpc_multi_client_settings; fi ;;
    xhttp) stream_json xhttp ;;
    tls-xhttp-h1) if [[ "$role" == server ]]; then tls_xhttp_server_settings auto http/1.1; else tls_xhttp_client_settings auto http/1.1; fi ;;
    tls-xhttp-h2) if [[ "$role" == server ]]; then tls_xhttp_server_settings auto h2; else tls_xhttp_client_settings auto h2; fi ;;
    tls-xhttp-h3) if [[ "$role" == server ]]; then tls_xhttp_server_settings auto h3; else tls_xhttp_client_settings auto h3; fi ;;
    xhttp-streamone) xhttp_h1_settings stream-one ;;
    xhttp-streamup) xhttp_h1_settings stream-up ;;
    xhttp-packets) xhttp_h1_settings packet-up ;;
    kcp) kcp_settings ;;
    quic) if [[ "$role" == server ]]; then quic_server_settings; else quic_client_settings; fi ;;
    hysteria) if [[ "$role" == server ]]; then hysteria_server_settings; else hysteria_client_settings; fi ;;
    *) echo "::error::unknown carrier $carrier" >&2; return 1 ;;
  esac
}

vmess_server() { echo "\"protocol\": \"vmess\", \"settings\": {\"clients\": [{\"id\": \"$UUID\"}]}"; }
vmess_client() { echo "\"tag\": \"proxy\", \"protocol\": \"vmess\", \"settings\": {\"vnext\": [{\"address\": \"127.0.0.1\", \"port\": $1, \"users\": [{\"id\": \"$UUID\", \"security\": \"auto\"}]}]}" ; }
trojan_server() { echo "\"protocol\": \"trojan\", \"settings\": {\"clients\": [{\"password\": \"$PASSWORD\"}]}"; }
trojan_client() { echo "\"tag\": \"proxy\", \"protocol\": \"trojan\", \"settings\": {\"servers\": [{\"address\": \"127.0.0.1\", \"port\": $1, \"password\": \"$PASSWORD\"}]}"; }
shadowsocks_server() { echo "\"protocol\": \"shadowsocks\", \"settings\": {\"method\": \"aes-256-gcm\", \"password\": \"$SS_PASSWORD\", \"network\": \"tcp\"}"; }
shadowsocks_client() { echo "\"tag\": \"proxy\", \"protocol\": \"shadowsocks\", \"settings\": {\"servers\": [{\"address\": \"127.0.0.1\", \"port\": $1, \"method\": \"aes-256-gcm\", \"password\": \"$SS_PASSWORD\"}]}"; }
shadowsocks2022_server() { echo "\"protocol\": \"shadowsocks\", \"settings\": {\"method\": \"2022-blake3-aes-128-gcm\", \"password\": \"$SS2022_PASSWORD\", \"network\": \"tcp\"}"; }
shadowsocks2022_client() { echo "\"tag\": \"proxy\", \"protocol\": \"shadowsocks\", \"settings\": {\"servers\": [{\"address\": \"127.0.0.1\", \"port\": $1, \"method\": \"2022-blake3-aes-128-gcm\", \"password\": \"$SS2022_PASSWORD\"}]}"; }

# One function per protocol family; the carrier decides the stream layer, so no protocol needs a
# case arm per carrier.
protocol_scenario() {
  local proto="$1" carrier="$2" port="$3" cover="${4:-}" srv cli srv_stream cli_stream cover_json=""
  case "$proto" in
    vmess) srv="$(vmess_server)"; cli="$(vmess_client "$port")" ;;
    trojan) srv="$(trojan_server)"; cli="$(trojan_client "$port")" ;;
    shadowsocks) srv="$(shadowsocks_server)"; cli="$(shadowsocks_client "$port")" ;;
    shadowsocks2022) srv="$(shadowsocks2022_server)"; cli="$(shadowsocks2022_client "$port")" ;;
    *) echo "::error::unknown protocol $proto" >&2; return 1 ;;
  esac
  if [[ "$carrier" == reality-raw ]]; then
    srv_stream="$(reality_server_settings tcp "")"
    cli_stream="$(reality_client_settings tcp "")"
    if [[ -n "$cover" ]]; then cover_json="$(cover_inbound "$cover")"; fi
  else
    srv_stream="$(carrier_server_stream "$carrier")" || return 1
    cli_stream="$(carrier_stream "$carrier" client)" || return 1
  fi
  server_config "$srv, $srv_stream" "$cli, $cli_stream" "$port" "$cover_json"
}

dispatch_protocol() {
  local proto="$1" id="$2" port="$3" cover="${4:-}" carrier
  carrier="$(carrier_of "$id")" || {
    echo "::error::$id names no carrier this matrix knows" >&2
    return 1
  }
  protocol_scenario "$proto" "$carrier" "$port" "$cover"
}

socks_server() { echo "\"protocol\": \"socks\", \"settings\": {\"auth\": \"noauth\", \"udp\": true}"; }
socks_client() { echo "\"tag\": \"proxy\", \"protocol\": \"socks\", \"settings\": {\"servers\": [{\"address\": \"127.0.0.1\", \"port\": $1}]}"; }
http_server() { echo "\"protocol\": \"http\", \"settings\": {}"; }
http_client() { echo "\"tag\": \"proxy\", \"protocol\": \"http\", \"settings\": {\"servers\": [{\"address\": \"127.0.0.1\", \"port\": $1}]}"; }

scenario_config() {
  local port="$2" cover="${3:-}" cover_json=""
  if [[ -n "$cover" ]]; then cover_json="$(cover_inbound "$cover")"; fi
  case "$1" in
    vless-raw-*) server_config "$(vless_server ', "streamSettings": {"network": "tcp"}')" "$(vless_client ', "streamSettings": {"network": "tcp"}' "$port")" "$port" ;;
    vless-encryption-raw-*) server_config "$(vless_server_encryption ', "streamSettings": {"network": "tcp"}')" "$(vless_client_encryption ', "streamSettings": {"network": "tcp"}' "$port")" "$port" ;;
    vless-encryption-tls-raw-*) server_config "$(vless_server_encryption ", $(tls_server_settings)")" "$(vless_client_encryption ", $(tls_client_settings)" "$port")" "$port" ;;
    vless-encryption-reality-raw-*) server_config "$(vless_server_encryption ", $(reality_server_settings tcp "")")" "$(vless_client_encryption ", $(reality_client_settings tcp "")" "$port")" "$port" "$cover_json" ;;
    vless-tls-ws-ed-*) server_config "$(vless_server ", $(tls_ws_ed_server_settings)")" "$(vless_client ", $(tls_ws_ed_client_settings)" "$port")" "$port" ;;
    vless-ws-ed-*) server_config "$(vless_server ", $(ws_ed_settings)")" "$(vless_client ", $(ws_ed_settings)" "$port")" "$port" ;;
    vless-tls-httpupgrade-ed-*) server_config "$(vless_server ", $(tls_httpupgrade_ed_server_settings)")" "$(vless_client ", $(tls_httpupgrade_ed_client_settings)" "$port")" "$port" ;;
    vless-tls-httpupgrade-*) server_config "$(vless_server ", $(tls_httpupgrade_server_settings)")" "$(vless_client ", $(tls_httpupgrade_client_settings)" "$port")" "$port" ;;
    vless-httpupgrade-ed-*) server_config "$(vless_server ", $(httpupgrade_ed_settings)")" "$(vless_client ", $(httpupgrade_ed_settings)" "$port")" "$port" ;;
    vless-tls-grpc-multi-*) server_config "$(vless_server ", $(tls_grpc_multi_server_settings)")" "$(vless_client ", $(tls_grpc_multi_client_settings)" "$port")" "$port" ;;
    vless-grpc-multi-*) server_config "$(vless_server ", $(grpc_multi_settings)")" "$(vless_client ", $(grpc_multi_settings)" "$port")" "$port" ;;
    vless-tls-xhttp-h2-*) server_config "$(vless_server ", $(tls_xhttp_server_settings auto h2)")" "$(vless_client ", $(tls_xhttp_client_settings auto h2)" "$port")" "$port" ;;
    vless-tls-xhttp-h1-*) server_config "$(vless_server ", $(tls_xhttp_server_settings auto http/1.1)")" "$(vless_client ", $(tls_xhttp_client_settings auto http/1.1)" "$port")" "$port" ;;
    vless-xhttp-streamup-*) server_config "$(vless_server ", $(xhttp_h1_settings stream-up)")" "$(vless_client ", $(xhttp_h1_settings stream-up)" "$port")" "$port" ;;
    vless-xhttp-streamone-*) server_config "$(vless_server ", $(xhttp_h1_settings stream-one)")" "$(vless_client ", $(xhttp_h1_settings stream-one)" "$port")" "$port" ;;
    vless-xhttp-packets-*) server_config "$(vless_server ", $(xhttp_h1_settings packet-up)")" "$(vless_client ", $(xhttp_h1_settings packet-up)" "$port")" "$port" ;;
    vless-raw-routed-*) routed_server_config "$(vless_server ', "streamSettings": {"network": "tcp"}')" "$(vless_client ', "streamSettings": {"network": "tcp"}' "$port")" "$port" ;;
    vless-tls-raw-*) server_config "$(vless_server ", $(tls_server_settings)")" "$(vless_client ", $(tls_client_settings)" "$port")" "$port" ;;
    vless-ws-*) server_config "$(vless_server ", $(stream_json ws)")" "$(vless_client ", $(stream_json ws)" "$port")" "$port" ;;
    vless-grpc-*) server_config "$(vless_server ", $(stream_json grpc)")" "$(vless_client ", $(stream_json grpc)" "$port")" "$port" ;;
    vless-xhttp-*) server_config "$(vless_server ", $(stream_json xhttp)")" "$(vless_client ", $(stream_json xhttp)" "$port")" "$port" ;;
    vmess-raw-*) server_config "\"protocol\": \"vmess\", \"settings\": {\"clients\": [{\"id\": \"$UUID\"}]}, \"streamSettings\": {\"network\": \"tcp\"}" "\"tag\": \"proxy\", \"protocol\": \"vmess\", \"settings\": {\"vnext\": [{\"address\": \"127.0.0.1\", \"port\": $port, \"users\": [{\"id\": \"$UUID\", \"security\": \"auto\"}]}]}, \"streamSettings\": {\"network\": \"tcp\"}" "$port" ;;
    vmess-tls-raw-*) server_config "\"protocol\": \"vmess\", \"settings\": {\"clients\": [{\"id\": \"$UUID\"}]}, $(tls_server_settings)" "\"tag\": \"proxy\", \"protocol\": \"vmess\", \"settings\": {\"vnext\": [{\"address\": \"127.0.0.1\", \"port\": $port, \"users\": [{\"id\": \"$UUID\", \"security\": \"auto\"}]}]}, $(tls_client_settings)" "$port" ;;
    trojan-raw-*) server_config "\"protocol\": \"trojan\", \"settings\": {\"clients\": [{\"password\": \"$PASSWORD\"}]}" "\"tag\": \"proxy\", \"protocol\": \"trojan\", \"settings\": {\"servers\": [{\"address\": \"127.0.0.1\", \"port\": $port, \"password\": \"$PASSWORD\"}]}" "$port" ;;
    trojan-tls-raw-*) server_config "\"protocol\": \"trojan\", \"settings\": {\"clients\": [{\"password\": \"$PASSWORD\"}]}, $(tls_server_settings)" "\"tag\": \"proxy\", \"protocol\": \"trojan\", \"settings\": {\"servers\": [{\"address\": \"127.0.0.1\", \"port\": $port, \"password\": \"$PASSWORD\"}]}, $(tls_client_settings)" "$port" ;;
    vless-tls-ws-*) server_config "$(vless_server ", $(tls_ws_server_settings)")" "$(vless_client ", $(tls_ws_client_settings)" "$port")" "$port" ;;
    shadowsocks-raw-*) server_config "\"protocol\": \"shadowsocks\", \"settings\": {\"method\": \"aes-256-gcm\", \"password\": \"$SS_PASSWORD\", \"network\": \"tcp\"}" "\"tag\": \"proxy\", \"protocol\": \"shadowsocks\", \"settings\": {\"servers\": [{\"address\": \"127.0.0.1\", \"port\": $port, \"method\": \"aes-256-gcm\", \"password\": \"$SS_PASSWORD\"}]}" "$port" ;;
    shadowsocks2022-raw-*) server_config "\"protocol\": \"shadowsocks\", \"settings\": {\"method\": \"2022-blake3-aes-128-gcm\", \"password\": \"$SS2022_PASSWORD\", \"network\": \"tcp\"}" "\"tag\": \"proxy\", \"protocol\": \"shadowsocks\", \"settings\": {\"servers\": [{\"address\": \"127.0.0.1\", \"port\": $port, \"method\": \"2022-blake3-aes-128-gcm\", \"password\": \"$SS2022_PASSWORD\"}]}" "$port" ;;
    vless-httpupgrade-*) server_config "$(vless_server ", $(httpupgrade_settings)")" "$(vless_client ", $(httpupgrade_settings)" "$port")" "$port" ;;
    vless-tls-grpc-*) server_config "$(vless_server ", $(tls_grpc_server_settings)")" "$(vless_client ", $(tls_grpc_client_settings)" "$port")" "$port" ;;
    vless-reality-raw-*) server_config "$(vless_server ", $(reality_server_settings tcp "")")" "$(vless_client ", $(reality_client_settings tcp "")" "$port")" "$port" "$cover_json" ;;
    vless-reality-grpc-*) server_config "$(vless_server ", $(reality_server_settings grpc ', "grpcSettings": {"serviceName": "TunnelService"}')")" "$(vless_client ", $(reality_client_settings grpc ', "grpcSettings": {"serviceName": "TunnelService"}')" "$port")" "$port" "$cover_json" ;;
    vless-reality-xhttp-*) server_config "$(vless_server ", $(reality_server_settings xhttp ', "xhttpSettings": {"path": "/share"}')")" "$(vless_client ", $(reality_client_settings xhttp ', "xhttpSettings": {"path": "/share"}')" "$port")" "$port" "$cover_json" ;;
    vless-vision-reality-edge-*) server_config "$(vless_server_vision ", $(reality_server_settings tcp "")")" "$(vless_client_vision ", $(reality_client_settings tcp "" edge)" "$port")" "$port" "$cover_json" ;;
    vless-vision-reality-ios-*) server_config "$(vless_server_vision ", $(reality_server_settings tcp "")")" "$(vless_client_vision ", $(reality_client_settings tcp "" ios)" "$port")" "$port" "$cover_json" ;;
    vless-vision-reality-android-*) server_config "$(vless_server_vision ", $(reality_server_settings tcp "")")" "$(vless_client_vision ", $(reality_client_settings tcp "" android)" "$port")" "$port" "$cover_json" ;;
    vless-vision-reality-random-*) server_config "$(vless_server_vision ", $(reality_server_settings tcp "")")" "$(vless_client_vision ", $(reality_client_settings tcp "" random)" "$port")" "$port" "$cover_json" ;;
    vless-vision-reality-randomized-*) server_config "$(vless_server_vision ", $(reality_server_settings tcp "")")" "$(vless_client_vision ", $(reality_client_settings tcp "" randomized)" "$port")" "$port" "$cover_json" ;;
    vless-vision-reality-firefox-*) server_config "$(vless_server_vision ", $(reality_server_settings tcp "")")" "$(vless_client_vision ", $(reality_client_settings tcp "" firefox)" "$port")" "$port" "$cover_json" ;;
    vless-vision-reality-safari-*) server_config "$(vless_server_vision ", $(reality_server_settings tcp "")")" "$(vless_client_vision ", $(reality_client_settings tcp "" safari)" "$port")" "$port" "$cover_json" ;;
    vless-vision-tls-*) server_config "$(vless_server_vision ", $(tls_server_settings)")" "$(vless_client_vision ", $(tls_client_settings)" "$port")" "$port" ;;
    vless-vision-reality-*) server_config "$(vless_server_vision ", $(reality_server_settings tcp "")")" "$(vless_client_vision ", $(reality_client_settings tcp "")" "$port")" "$port" "$cover_json" ;;
    vless-quic-*) server_config "$(vless_server ", $(quic_server_settings)")" "$(vless_client ", $(quic_client_settings)" "$port")" "$port" ;;
    vless-kcp-*) server_config "$(vless_server ", $(kcp_settings)")" "$(vless_client ", $(kcp_settings)" "$port")" "$port" ;;
    vless-hysteria-*) server_config "$(vless_server ", $(hysteria_server_settings)")" "$(vless_client ", $(hysteria_client_settings)" "$port")" "$port" ;;
    hysteria-v1-*) server_config "$(hysteria_v1_server_settings)" "$(hysteria_v1_client_settings "$port")" "$port" ;;
    wireguard-kernel-raw-*) server_config "$(wireguard_server)" "$(wireguard_kernel_client "$port")" "$port" ;;
    wireguard-raw-*) server_config "$(wireguard_server)" "$(wireguard_client "$port")" "$port" ;;
    vmess-tls-ws-*) server_config "\"protocol\": \"vmess\", \"settings\": {\"clients\": [{\"id\": \"$UUID\"}]}, $(tls_ws_server_settings)" "\"tag\": \"proxy\", \"protocol\": \"vmess\", \"settings\": {\"vnext\": [{\"address\": \"127.0.0.1\", \"port\": $port, \"users\": [{\"id\": \"$UUID\", \"security\": \"auto\"}]}]}, $(tls_ws_client_settings)" "$port" ;;
    trojan-tls-ws-*) server_config "\"protocol\": \"trojan\", \"settings\": {\"clients\": [{\"password\": \"$PASSWORD\"}]}, $(tls_ws_server_settings)" "\"tag\": \"proxy\", \"protocol\": \"trojan\", \"settings\": {\"servers\": [{\"address\": \"127.0.0.1\", \"port\": $port, \"password\": \"$PASSWORD\"}]}, $(tls_ws_client_settings)" "$port" ;;
    masque-*) server_config "$(masque_server_settings)" "$(masque_client_settings "$port")" "$port" ;;
    warp-masque-*) server_config "$(masque_server_settings)" "$(warp_client_settings "$port")" "$port" ;;
    socks-raw-*) server_config "$(socks_server)" "$(socks_client "$port")" "$port" ;;
    http-raw-*) server_config "$(http_server)" "$(http_client "$port")" "$port" ;;
    vmess-*) dispatch_protocol vmess "$1" "$port" "$cover" ;;
    trojan-*) dispatch_protocol trojan "$1" "$port" "$cover" ;;
    shadowsocks2022-*) dispatch_protocol shadowsocks2022 "$1" "$port" "$cover" ;;
    shadowsocks-*) dispatch_protocol shadowsocks "$1" "$port" "$cover" ;;
    *) echo "::error::unknown scenario $1" >&2; return 1 ;;
  esac
}

MIB=1024
KIb=$((1024 * MIB))
GIB=$((1024 * 1024))

# Every carrier a stream-based proxy protocol can ride in this tree. The grid is protocol by
# carrier, so a carrier added here is measured for VMess, Trojan and both Shadowsocks dialects
# without another list. QUIC is absent: xray-core removed the transport at its pin and sing-box
# cannot serve these protocols, so a QUIC row would have no reference; the VLESS QUIC cell keeps
# its sing-box control. `full` dedupes against the older hand-written rows.
matrix_carriers() {
  printf '%s\n' \
    raw tls-raw ws tls-ws ws-ed tls-ws-ed \
    httpupgrade tls-httpupgrade httpupgrade-ed tls-httpupgrade-ed \
    grpc tls-grpc grpc-multi tls-grpc-multi \
    xhttp tls-xhttp-h1 tls-xhttp-h2 tls-xhttp-h3 xhttp-streamone xhttp-streamup xhttp-packets \
    kcp hysteria reality-raw
}

matrix_protocols() {
  printf '%s\n' vmess trojan shadowsocks shadowsocks2022
}

carrier_matrix() {
  local proto carrier
  for proto in $(matrix_protocols); do
    for carrier in $(matrix_carriers); do
      echo "$proto-$carrier-down-8 download 8 256 65536"
    done
  done
  for proto in $(matrix_protocols); do
    for carrier in raw tls-raw ws tls-ws grpc tls-grpc; do
      echo "$proto-$carrier-up-1 upload 1 2048 65536"
      echo "$proto-$carrier-duplex-8 full-duplex 8 128 65536"
    done
    echo "$proto-raw-udp-8 udp 8 64 1200 0"
    echo "$proto-raw-idle-100 held-open 100 1 1 10000"
    echo "$proto-raw-tcp-latency-1 tcp-latency 1 1000 64 0"
  done
}

standard_scenarios() {
  echo "vless-raw-down-1 download 1 2048 65536"
  echo "vless-raw-down-8 download 8 256 65536"
  echo "vless-raw-up-1 upload 1 2048 65536"
  echo "vless-raw-duplex-8 full-duplex 8 128 65536"
  echo "vless-ws-down-8 download 8 256 65536"
  echo "vless-grpc-down-8 download 8 256 65536"
  echo "vless-xhttp-down-8 download 8 256 65536"
  echo "vmess-raw-down-8 download 8 256 65536"
  echo "trojan-raw-down-8 download 8 256 65536"
  echo "shadowsocks-raw-down-8 download 8 256 65536"
  echo "vless-raw-setup-1k download 1 1000 8"
  echo "vless-encryption-raw-down-8 download 8 256 65536"
  echo "vless-tls-raw-down-8 download 8 256 65536"
  echo "vless-encryption-tls-raw-down-8 download 8 256 65536"
  echo "vless-tls-raw-up-1 upload 1 2048 65536"
  echo "vless-tls-raw-duplex-8 full-duplex 8 128 65536"
  echo "vless-tls-ws-down-8 download 8 256 65536"
  echo "trojan-tls-raw-down-8 download 8 256 65536"
  echo "vless-httpupgrade-down-8 download 8 256 65536"
  echo "vless-tls-grpc-down-8 download 8 256 65536"
  echo "vless-reality-raw-down-8 download 8 256 65536"
  echo "vless-encryption-reality-raw-down-8 download 8 256 65536"
  echo "vless-reality-grpc-down-8 download 8 256 65536"
  echo "vless-reality-xhttp-down-8 download 8 256 65536"
  echo "vless-vision-tls-raw-down-8 download 8 256 65536"
  echo "vless-vision-reality-raw-down-8 download 8 256 65536"
  echo "vless-kcp-down-8 download 8 256 65536"
  echo "vless-quic-down-8 download 8 256 65536"
  echo "vless-hysteria-down-8 download 8 256 65536"
  echo "hysteria-v1-down-8 download 8 256 65536"
  echo "wireguard-raw-down-8 download 8 256 65536"
  echo "wireguard-kernel-raw-down-8 download 8 256 65536"
  echo "shadowsocks2022-raw-down-8 download 8 256 65536"
  echo "vmess-tls-ws-down-8 download 8 256 65536"
  echo "trojan-tls-ws-down-8 download 8 256 65536"
  echo "masque-down-8 download 8 256 65536"
  echo "warp-masque-down-8 download 8 256 65536"
  echo "vless-ws-ed-down-8 download 8 256 65536"
  echo "vless-tls-ws-ed-down-8 download 8 256 65536"
  echo "vless-httpupgrade-ed-down-8 download 8 256 65536"
  echo "vless-tls-httpupgrade-down-8 download 8 256 65536"
  echo "vless-tls-httpupgrade-ed-down-8 download 8 256 65536"
  echo "vless-grpc-multi-down-8 download 8 256 65536"
  echo "vless-tls-grpc-multi-down-8 download 8 256 65536"
  echo "vless-tls-xhttp-h1-down-8 download 8 256 65536"
  echo "vless-tls-xhttp-h2-down-8 download 8 256 65536"
  echo "vless-xhttp-streamone-down-8 download 8 256 65536"
  echo "vless-xhttp-streamup-down-8 download 8 256 65536"
  echo "vless-xhttp-packets-down-8 download 8 256 65536"
  echo "vless-grpc-bulk-down-1 download 1 2048 65536"
  echo "vless-vision-reality-bulk-down-1 download 1 2048 65536"
  echo "vless-vision-reality-firefox-down-8 download 8 256 65536"
  echo "vless-vision-reality-safari-down-8 download 8 256 65536"
  echo "vless-vision-reality-edge-down-8 download 8 256 65536"
  echo "vless-vision-reality-ios-down-8 download 8 256 65536"
  echo "vless-vision-reality-android-down-8 download 8 256 65536"
  echo "vless-vision-reality-random-down-8 download 8 256 65536"
  echo "vless-vision-reality-randomized-down-8 download 8 256 65536"
  echo "vless-raw-routed-down-8 download 8 256 65536"
  echo "vless-raw-idle idle 1 1 1 10000"
  echo "vless-raw-idle-100 held-open 100 1 1 10000"
  echo "vless-raw-idle-1000 held-open 1000 1 1 10000"
  echo "vless-raw-reconnect-16 reconnect 16 32 1 0"
  echo "vless-raw-udp-8 udp 8 64 1200 0"
  echo "vless-raw-mixed-8 mixed 8 16 1200 0"
  echo "vless-vision-reality-udp-8 udp 8 64 1200 0"
  echo "vless-raw-tcp-latency-1 tcp-latency 1 1000 64 0"
  echo "vmess-grpc-down-8 download 8 256 65536"
  echo "vmess-tls-grpc-down-8 download 8 256 65536"
  echo "vmess-httpupgrade-down-8 download 8 256 65536"
  echo "vmess-tls-httpupgrade-down-8 download 8 256 65536"
  echo "vmess-xhttp-down-8 download 8 256 65536"
  echo "vmess-tls-xhttp-h2-down-8 download 8 256 65536"
  echo "vmess-reality-raw-down-8 download 8 256 65536"
  echo "trojan-grpc-down-8 download 8 256 65536"
  echo "trojan-tls-grpc-down-8 download 8 256 65536"
  echo "trojan-httpupgrade-down-8 download 8 256 65536"
  echo "trojan-tls-xhttp-h2-down-8 download 8 256 65536"
  echo "trojan-reality-raw-down-8 download 8 256 65536"
  echo "shadowsocks-tls-raw-down-8 download 8 256 65536"
  echo "shadowsocks-ws-down-8 download 8 256 65536"
  echo "shadowsocks-grpc-down-8 download 8 256 65536"
  echo "shadowsocks2022-tls-raw-down-8 download 8 256 65536"
  echo "shadowsocks2022-ws-down-8 download 8 256 65536"
  # Carriers every protocol already serves but the standard tier did not measure: KCP and
  # Hysteria for all four families, QUIC for Trojan, TLS-raw for VMess, and HTTPUpgrade for
  # both Shadowsocks dialects. The plain ws cells flap on the server leg, so they wait.
  echo "vmess-tls-raw-down-8 download 8 256 65536"
  echo "vmess-kcp-down-8 download 8 256 65536"
  echo "trojan-tls-httpupgrade-down-8 download 8 256 65536"
  echo "trojan-kcp-down-8 download 8 256 65536"
  echo "trojan-quic-down-8 download 8 256 65536"
  echo "trojan-hysteria-down-8 download 8 256 65536"
  echo "shadowsocks-httpupgrade-down-8 download 8 256 65536"
  echo "shadowsocks-kcp-down-8 download 8 256 65536"
  echo "shadowsocks2022-httpupgrade-down-8 download 8 256 65536"
  echo "shadowsocks2022-kcp-down-8 download 8 256 65536"
  echo "socks-raw-down-8 download 8 256 65536"
  echo "http-raw-down-8 download 8 256 65536"
}

scenarios() {
  {
  case "${1:-$tier}" in
    smoke) echo "vless-raw-down-1 download 1 2048 65536" ;;
    standard) standard_scenarios ;;
    full)
      standard_scenarios
      echo "vless-raw-down-16 download 16 128 65536"
      echo "vless-ws-down-16 download 16 128 65536"
      echo "vless-raw-duplex-16 full-duplex 16 64 65536"
      echo "vless-tls-raw-duplex-16 full-duplex 16 64 65536"
      echo "vless-raw-down-64 download 64 64 65536"
      echo "vless-tls-raw-down-64 download 64 64 65536"
      echo "vless-raw-duplex-64 full-duplex 64 64 65536"
      echo "vmess-raw-down-64 download 64 64 65536"
      echo "trojan-raw-down-64 download 64 64 65536"
      echo "vmess-raw-up-1 upload 1 2048 65536"
      echo "vmess-raw-duplex-8 full-duplex 8 128 65536"
      echo "trojan-raw-up-1 upload 1 2048 65536"
      echo "trojan-raw-duplex-8 full-duplex 8 128 65536"
      echo "shadowsocks-raw-up-1 upload 1 2048 65536"
      echo "shadowsocks-raw-duplex-8 full-duplex 8 128 65536"
      echo "shadowsocks2022-raw-up-1 upload 1 2048 65536"
      echo "shadowsocks2022-raw-duplex-8 full-duplex 8 128 65536"
      echo "vless-httpupgrade-up-1 upload 1 2048 65536"
      echo "vless-httpupgrade-duplex-8 full-duplex 8 128 65536"
      echo "vless-grpc-up-1 upload 1 2048 65536"
      echo "vless-grpc-duplex-8 full-duplex 8 128 65536"
      echo "vless-xhttp-up-1 upload 1 2048 65536"
      echo "vless-xhttp-duplex-8 full-duplex 8 128 65536"
      echo "vless-kcp-up-1 upload 1 2048 65536"
      echo "vless-kcp-duplex-8 full-duplex 8 128 65536"
      echo "vless-quic-up-1 upload 1 2048 65536"
      echo "vless-quic-duplex-8 full-duplex 8 128 65536"
      echo "vless-hysteria-up-1 upload 1 2048 65536"
      echo "vless-hysteria-duplex-8 full-duplex 8 128 65536"
      echo "hysteria-v1-up-1 upload 1 2048 65536"
      echo "hysteria-v1-duplex-8 full-duplex 8 128 65536"
      echo "wireguard-raw-up-1 upload 1 2048 65536"
      echo "wireguard-raw-duplex-8 full-duplex 8 128 65536"
      echo "warp-masque-up-1 upload 1 2048 65536"
      echo "warp-masque-duplex-8 full-duplex 8 128 65536"
      echo "warp-masque-down-16 download 16 128 65536"
      echo "warp-masque-down-64 download 64 64 65536"
      echo "warp-masque-duplex-64 full-duplex 64 64 65536"
      echo "wireguard-kernel-raw-up-1 upload 1 2048 65536"
      echo "wireguard-kernel-raw-duplex-8 full-duplex 8 128 65536"
      echo "vless-reality-raw-up-1 upload 1 2048 65536"
      echo "vless-reality-raw-duplex-8 full-duplex 8 128 65536"
      echo "vless-vision-tls-raw-up-1 upload 1 2048 65536"
      echo "vless-vision-tls-raw-duplex-8 full-duplex 8 128 65536"
      echo "vless-tls-grpc-up-1 upload 1 2048 65536"
      echo "vless-tls-grpc-duplex-8 full-duplex 8 128 65536"
      echo "vless-tls-ws-up-1 upload 1 2048 65536"
      echo "vless-tls-ws-duplex-8 full-duplex 8 128 65536"
      echo "vmess-tls-ws-up-1 upload 1 2048 65536"
      echo "vmess-tls-ws-duplex-8 full-duplex 8 128 65536"
      echo "vmess-tls-raw-down-8 download 8 256 65536"
      echo "vmess-tls-raw-up-1 upload 1 2048 65536"
      echo "vmess-tls-raw-duplex-8 full-duplex 8 128 65536"
      echo "trojan-tls-raw-up-1 upload 1 2048 65536"
      echo "trojan-tls-raw-duplex-8 full-duplex 8 128 65536"
      echo "trojan-tls-ws-up-1 upload 1 2048 65536"
      echo "trojan-tls-ws-duplex-8 full-duplex 8 128 65536"
      carrier_matrix
      ;;
  esac
  } | awk '!seen[$1]++'
}

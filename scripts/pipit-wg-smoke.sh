#!/usr/bin/env bash
set -euo pipefail

ROLE="client"
CONFIG="pipit.wg.yaml"
PIPIT_BIN="./target/release/pipit"
LOG_DIR="/tmp"
START=0
DOMAIN="example.com"
TCPDUMP_SECONDS=8

usage() {
  cat <<'USAGE'
Usage:
  scripts/pipit-wg-smoke.sh --role server --config pipit.wg.yaml --start
  scripts/pipit-wg-smoke.sh --role client --config pipit.wg.yaml --start

Options:
  --role client|server       Which side to diagnose. Default: client.
  --config PATH              pipit YAML config with client/server mode: wg. Default: pipit.wg.yaml.
  --pipit PATH               pipit binary. Default: ./target/release/pipit.
  --start                    Start the selected pipit WG side in the background.
  --domain NAME              DNS smoke-test domain. Default: example.com.
  --tcpdump-seconds N        Seconds to wait for UDP 51820 packets. Default: 8.

The server and client usually live on different machines. Run this script once on
the server with --role server --start, then run it on the client with
--role client --start.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --role)
      ROLE="${2:?missing --role value}"
      shift 2
      ;;
    --config)
      CONFIG="${2:?missing --config value}"
      shift 2
      ;;
    --pipit)
      PIPIT_BIN="${2:?missing --pipit value}"
      shift 2
      ;;
    --start)
      START=1
      shift
      ;;
    --domain)
      DOMAIN="${2:?missing --domain value}"
      shift 2
      ;;
    --tcpdump-seconds)
      TCPDUMP_SECONDS="${2:?missing --tcpdump-seconds value}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$ROLE" != "client" && "$ROLE" != "server" ]]; then
  echo "--role must be client or server" >&2
  exit 2
fi

if [[ ! -f "$CONFIG" ]]; then
  echo "config not found: $CONFIG" >&2
  exit 2
fi

section_value() {
  local section="$1"
  local key="$2"
  awk -v section="$section" -v key="$key" '
    $0 ~ "^" section ":" { in_section=1; next }
    /^[^[:space:]][^:]*:/ { in_section=0 }
    in_section && $1 == key ":" {
      sub("^[[:space:]]*" key ":[[:space:]]*", "")
      print
      exit
    }
  ' "$CONFIG"
}

nested_section_value() {
  local parent="$1"
  local child="$2"
  local key="$3"
  awk -v parent="$parent" -v child="$child" -v key="$key" '
    $0 ~ "^" parent ":" { in_parent=1; in_child=0; next }
    /^[^[:space:]][^:]*:/ { in_parent=0; in_child=0 }
    in_parent && $0 ~ "^[[:space:]]+" child ":" { in_child=1; next }
    in_parent && in_child && $0 ~ "^  [^[:space:]][^:]*:" {
      if ($1 != key ":") {
        in_child=0
      }
    }
    in_parent && in_child && $1 == key ":" {
      sub("^[[:space:]]*" key ":[[:space:]]*", "")
      print
      exit
    }
  ' "$CONFIG"
}

strip_quotes() {
  local value="$1"
  value="${value%\"}"
  value="${value#\"}"
  value="${value%\'}"
  value="${value#\'}"
  printf '%s' "$value"
}

endpoint_host() {
  local endpoint="$1"
  if [[ "$endpoint" == \[*\]*:* ]]; then
    printf '%s' "$endpoint" | sed -E 's/^\[([^]]+)\]:[0-9]+$/\1/'
  else
    printf '%s' "${endpoint%:*}"
  fi
}

endpoint_port() {
  local endpoint="$1"
  printf '%s' "${endpoint##*:}"
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing command: $1" >&2
    exit 1
  fi
}

run_step() {
  echo
  echo "==> $*"
}

start_pipit() {
  local subcommand="$1"
  local logfile="$2"
  run_step "starting pipit $subcommand"
  "$PIPIT_BIN" --log-file "$logfile" --config "$CONFIG" "$subcommand" >"$logfile.stdout" 2>"$logfile.stderr" &
  PIPIT_PID=$!
  echo "pid: $PIPIT_PID"
  echo "log: $logfile"
  sleep 2
  if ! kill -0 "$PIPIT_PID" >/dev/null 2>&1; then
    echo "pipit $subcommand exited early" >&2
    tail -80 "$logfile" "$logfile.stdout" "$logfile.stderr" 2>/dev/null || true
    exit 1
  fi
}

detect_iface() {
  local host="$1"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    if [[ "$host" == *:* ]]; then
      route -n get -inet6 "$host" 2>/dev/null | awk '/interface:/{print $2; exit}'
    else
      route -n get "$host" 2>/dev/null | awk '/interface:/{print $2; exit}'
    fi
  else
    if [[ "$host" == *:* ]]; then
      ip -6 route get "$host" 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}'
    else
      ip route get "$host" 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}'
    fi
  fi
}

server_smoke() {
  local listen
  listen="$(strip_quotes "$(nested_section_value server wg listen)")"
  local port="${listen##*:}"
  local logfile="$LOG_DIR/pipit-wg-server-smoke.log"

  if [[ "$START" -eq 1 ]]; then
    start_pipit "server" "$logfile"
  fi

  run_step "server process"
  pgrep -fl 'pipit.*server' || true

  if command -v ss >/dev/null 2>&1; then
    run_step "UDP listen check with ss"
    ss -lunp | grep ":$port" || true
  elif command -v netstat >/dev/null 2>&1; then
    run_step "UDP listen check with netstat"
    netstat -an | grep "[.:]$port" || true
  fi

  run_step "server log tail"
  tail -80 "$logfile" 2>/dev/null || true
}

client_smoke() {
  local endpoint peer_tunnel dns host port iface tcpdump_log logfile
  endpoint="$(strip_quotes "$(nested_section_value client wg endpoint)")"
  peer_tunnel="$(strip_quotes "$(nested_section_value client wg peer_tunnel_ip)")"
  dns="$(strip_quotes "$(nested_section_value client wg dns)")"
  host="$(endpoint_host "$endpoint")"
  port="$(endpoint_port "$endpoint")"
  logfile="$LOG_DIR/pipit-wg-client-smoke.log"

  if [[ "$START" -eq 1 ]]; then
    start_pipit "client" "$logfile"
  fi

  run_step "client process"
  pgrep -fl 'pipit.*client' || true

  run_step "route to WG endpoint $host"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    if [[ "$host" == *:* ]]; then
      route -n get -inet6 "$host" || true
    else
      route -n get "$host" || true
    fi
  else
    if [[ "$host" == *:* ]]; then
      ip -6 route get "$host" || true
    else
      ip route get "$host" || true
    fi
  fi

  iface="$(detect_iface "$host")"
  if [[ -n "$iface" && "$(id -u)" -eq 0 && -n "$port" && "$port" =~ ^[0-9]+$ && "$(command -v tcpdump || true)" ]]; then
    tcpdump_log="$LOG_DIR/pipit-wg-tcpdump-smoke.log"
    run_step "tcpdump UDP transport check on $iface host=$host port=$port"
    tcpdump -ni "$iface" -c 4 "host $host and udp port $port" >"$tcpdump_log" 2>&1 &
    TCPDUMP_PID=$!
  else
    TCPDUMP_PID=""
    echo "skipping tcpdump; run as root with tcpdump installed to verify UDP packets"
  fi

  run_step "ping tunnel peer $peer_tunnel"
  if [[ "$peer_tunnel" == *:* ]]; then
    if [[ "$(uname -s)" == "Darwin" ]]; then
      ping6 -c 3 "$peer_tunnel"
    else
      ping -6 -c 3 "$peer_tunnel"
    fi
  else
    ping -c 3 "$peer_tunnel"
  fi

  run_step "public egress IP via ifconfig.me"
  if command -v curl >/dev/null 2>&1; then
    if [[ "$peer_tunnel" == *:* ]]; then
      curl -6 --max-time 10 https://ifconfig.me || true
    else
      curl -4 --max-time 10 https://ifconfig.me || true
    fi
    echo
  else
    echo "curl not found; skipping public egress check"
  fi

  run_step "DNS lookup for $DOMAIN"
  if command -v dig >/dev/null 2>&1; then
    if [[ -n "$dns" ]]; then
      dig @"$dns" +short "$DOMAIN" || true
    fi
    dig +short "$DOMAIN" || true
  elif command -v nslookup >/dev/null 2>&1; then
    nslookup "$DOMAIN" || true
  else
    echo "dig/nslookup not found; skipping DNS check"
  fi

  if [[ -n "${TCPDUMP_PID:-}" ]]; then
    for _ in $(seq 1 "$TCPDUMP_SECONDS"); do
      if ! kill -0 "$TCPDUMP_PID" >/dev/null 2>&1; then
        break
      fi
      sleep 1
    done
    if kill -0 "$TCPDUMP_PID" >/dev/null 2>&1; then
      kill "$TCPDUMP_PID" >/dev/null 2>&1 || true
    fi
    wait "$TCPDUMP_PID" || true
    run_step "tcpdump result"
    cat "$tcpdump_log" || true
    if grep -q " UDP," "$tcpdump_log"; then
      echo "UDP transport verified"
    else
      echo "WARNING: did not capture UDP transport packets; generate more traffic or check iface/filter" >&2
    fi
  fi

  run_step "client log tail"
  tail -80 "$logfile" 2>/dev/null || true
}

need_cmd "$PIPIT_BIN"

case "$ROLE" in
  server) server_smoke ;;
  client) client_smoke ;;
esac

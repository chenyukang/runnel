#!/usr/bin/env bash
set -euo pipefail

ROUTE_SET=(
  "1.0.0.0/8"
  "2.0.0.0/7"
  "4.0.0.0/6"
  "8.0.0.0/5"
  "16.0.0.0/4"
  "32.0.0.0/3"
  "64.0.0.0/2"
  "128.0.0.0/1"
  "198.18.0.0/15"
)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONFIG_PATH="${REPO_ROOT}/pipit.tun.yaml"
ASSUME_YES=0
TAIL_LINES=40
RESET_DRY_RUN=0

usage() {
  cat <<'EOF'
Usage:
  scripts/pipit-tun.sh doctor [--config PATH] [--server HOST[:PORT]] [--tail N]
  scripts/pipit-tun.sh reset  [--config PATH] [--server HOST[:PORT]] [--yes] [--dry-run]

Commands:
  doctor  Print a macOS-oriented diagnosis of the current pipit tun state.
  reset   Stop stale pipit/tun2socks processes, remove pipit split routes, and
          bring down leftover utun interfaces that still hold 198.18.0.1.

Options:
  --config PATH   Read tun defaults from this YAML config. Default: ./pipit.tun.yaml
  --server SPEC   Upstream server host[:port]. Used when removing the pinned host route.
  --tail N        Tail N lines from proxy.log in doctor mode. Default: 40
  --yes, -y       Do not prompt before reset.
  --dry-run       Print reset actions without changing the system.
  -h, --help      Show this help.
EOF
}

log() {
  printf '[pipit-tun] %s\n' "$*"
}

warn() {
  printf '[pipit-tun] WARN: %s\n' "$*" >&2
}

die() {
  printf '[pipit-tun] ERROR: %s\n' "$*" >&2
  exit 1
}

require_macos() {
  [[ "$(uname -s)" == "Darwin" ]] || die "this helper currently only supports macOS"
}

extract_server_host() {
  local spec="$1"
  if [[ -z "${spec}" ]]; then
    return 0
  fi
  if [[ "${spec}" == \[*\]*:* ]]; then
    local without_brackets="${spec#\[}"
    printf '%s\n' "${without_brackets%%]*}"
    return 0
  fi
  if [[ "${spec}" == *:* ]]; then
    printf '%s\n' "${spec%:*}"
    return 0
  fi
  printf '%s\n' "${spec}"
}

infer_server_spec_from_config() {
  local config="$1"
  [[ -f "${config}" ]] || return 0
  awk '
    /^[[:space:]]*client:[[:space:]]*$/ { in_client = 1; next }
    in_client && /^[^[:space:]]/ { in_client = 0 }
    in_client && /^[[:space:]]+server:[[:space:]]*/ {
      sub(/^[[:space:]]+server:[[:space:]]*/, "", $0)
      gsub(/^["'\''"]|["'\''"]$/, "", $0)
      print
      exit
    }
  ' "${config}"
}

infer_server_spec_from_processes() {
  ps -axo command= | awk '
    /pipit/ && / tun( |$)/ {
      for (i = 1; i <= NF; ++i) {
        if ($i == "--server" && (i + 1) <= NF) {
          print $(i + 1)
          exit
        }
      }
    }
  '
}

resolve_server_spec() {
  local explicit="${1:-}"
  if [[ -n "${explicit}" ]]; then
    printf '%s\n' "${explicit}"
    return 0
  fi
  local from_config
  from_config="$(infer_server_spec_from_config "${CONFIG_PATH}" || true)"
  if [[ -n "${from_config}" ]]; then
    printf '%s\n' "${from_config}"
    return 0
  fi
  infer_server_spec_from_processes || true
}

print_section() {
  printf '\n== %s ==\n' "$1"
}

route_summary() {
  local target="$1"
  route -n get "${target}" 2>/dev/null || true
}

list_utun_with_pipit_addr() {
  local iface
  while IFS= read -r iface; do
    if ifconfig "${iface}" 2>/dev/null | grep -q 'inet 198\.18\.0\.1 '; then
      printf '%s\n' "${iface}"
    fi
  done < <(ifconfig -l | tr ' ' '\n' | grep '^utun' || true)
}

print_utun_details() {
  local iface
  while IFS= read -r iface; do
    [[ -n "${iface}" ]] || continue
    echo "--- ${iface}"
    ifconfig "${iface}" | sed -n '1,12p'
  done < <(ifconfig -l | tr ' ' '\n' | grep '^utun' || true)
}

print_split_routes() {
  netstat -rn -f inet | egrep '^(default|1/8|2/7|4/6|8/5|16/4|32/3|64/2|128\.0/1|198\.18/15|198\.18\.0\.1)' || true
}

print_active_processes() {
  ps -axo pid,ppid,user,etime,command | awk '
    /pipit|tun2socks|AmneziaVPN|wireguard-go/ &&
    $0 !~ /scripts\/pipit-tun\.sh/ &&
    $0 !~ /awk/ {
      print
    }
  ' || true
}

print_repo_artifacts() {
  find "${REPO_ROOT}" -maxdepth 1 \
    \( -name 'proxy*.sock' -o -name 'proxy*.pid' -o -name 'proxy*.state.json' \) \
    -print | sort || true
}

run_or_echo() {
  if [[ "${RESET_DRY_RUN}" -eq 1 ]]; then
    printf '+ %s\n' "$*"
  else
    "$@"
  fi
}

run_shell_or_echo() {
  if [[ "${RESET_DRY_RUN}" -eq 1 ]]; then
    printf '+ %s\n' "$*"
  else
    /bin/sh -c "$*"
  fi
}

collect_pipit_tun_pids() {
  ps -axo pid=,command= | awk '
    /pipit/ && / tun( |$)/ && $0 !~ /scripts\/pipit-tun\.sh/ {
      print $1
    }
  ' | sort -u
}

collect_tun2socks_pids_for_ifaces() {
  local iface
  for iface in "$@"; do
    [[ -n "${iface}" ]] || continue
    ps -axo pid=,command= | awk -v iface="${iface}" '
      /tun2socks/ && $0 ~ ("-device " iface "($| )") {
        print $1
      }
    '
  done | sort -u
}

term_then_kill() {
  local label="$1"
  shift
  local pids=("$@")
  local pid
  [[ "${#pids[@]}" -gt 0 ]] || return 0

  log "sending SIGTERM to ${label}: ${pids[*]}"
  for pid in "${pids[@]}"; do
    run_or_echo kill -TERM "${pid}"
  done

  if [[ "${RESET_DRY_RUN}" -eq 0 ]]; then
    sleep 1
    for pid in "${pids[@]}"; do
      if kill -0 "${pid}" 2>/dev/null; then
        warn "${label} pid ${pid} is still alive; sending SIGKILL"
        kill -KILL "${pid}" 2>/dev/null || true
      fi
    done
  fi
}

doctor() {
  local server_spec="$1"
  local server_host
  server_host="$(extract_server_host "${server_spec}")"

  print_section "Summary"
  printf 'repo: %s\n' "${REPO_ROOT}"
  printf 'config: %s\n' "${CONFIG_PATH}"
  printf 'server: %s\n' "${server_spec:-<unknown>}"
  printf 'server_host: %s\n' "${server_host:-<unknown>}"

  print_section "Active Processes"
  print_active_processes

  print_section "Routes"
  route_summary default
  if [[ -n "${server_host}" ]]; then
    echo '---'
    route_summary "${server_host}"
  fi

  print_section "Split Routes"
  print_split_routes

  print_section "utun Interfaces"
  print_utun_details

  print_section "System Proxy"
  scutil --proxy | sed -n '1,120p'

  print_section "Repo Artifacts"
  print_repo_artifacts

  print_section "Quick Read"
  cat <<EOF
- If default route still points to en0 but 1/8..128.0/1 point to utun233/234/235, pipit tun is actively diverting most traffic through TUN.
- If those split routes remain after pipit/tun2socks dies, the Mac may look "offline" even though Wi-Fi itself is fine.
- The pinned host route for ${server_host:-the upstream server} should stay on the original interface so the proxy server itself does not loop back into the tunnel.
EOF
}

reset() {
  require_macos
  if [[ "${EUID}" -ne 0 && "${RESET_DRY_RUN}" -ne 1 ]]; then
    die "reset needs root; run it with sudo"
  fi

  local server_spec="$1"
  local server_host
  server_host="$(extract_server_host "${server_spec}")"
  local ifaces=()
  local iface
  while IFS= read -r iface; do
    [[ -n "${iface}" ]] || continue
    ifaces+=("${iface}")
  done < <(list_utun_with_pipit_addr)

  local pipit_pids=()
  local tun2socks_pids=()
  local pid
  while IFS= read -r pid; do
    [[ -n "${pid}" ]] || continue
    pipit_pids+=("${pid}")
  done < <(collect_pipit_tun_pids)
  while IFS= read -r pid; do
    [[ -n "${pid}" ]] || continue
    tun2socks_pids+=("${pid}")
  done < <(collect_tun2socks_pids_for_ifaces "${ifaces[@]}")

  print_section "Reset Plan"
  printf 'server: %s\n' "${server_spec:-<unknown>}"
  printf 'server_host: %s\n' "${server_host:-<unknown>}"
  printf 'utun interfaces with 198.18.0.1: %s\n' "${ifaces[*]:-<none>}"
  printf 'pipit tun pids: %s\n' "${pipit_pids[*]:-<none>}"
  printf 'tun2socks pids: %s\n' "${tun2socks_pids[*]:-<none>}"
  printf 'reset dry-run: %s\n' "$( [[ "${RESET_DRY_RUN}" -eq 1 ]] && echo yes || echo no )"

  if [[ "${ASSUME_YES}" -ne 1 && "${RESET_DRY_RUN}" -ne 1 ]]; then
    printf 'Continue with reset? [y/N] '
    read -r answer
    [[ "${answer}" == "y" || "${answer}" == "Y" ]] || die "aborted"
  fi

  term_then_kill "pipit tun" "${pipit_pids[@]}"
  term_then_kill "tun2socks" "${tun2socks_pids[@]}"

  local cidr
  for cidr in "${ROUTE_SET[@]}"; do
    run_shell_or_echo "route -q -n delete -net ${cidr} >/dev/null 2>&1 || true"
  done
  if [[ -n "${server_host}" ]]; then
    run_shell_or_echo "route -q -n delete -host ${server_host} >/dev/null 2>&1 || true"
  fi

  for iface in "${ifaces[@]}"; do
    run_shell_or_echo "ifconfig ${iface} down >/dev/null 2>&1 || true"
  done

  run_shell_or_echo "rm -f '${REPO_ROOT}/proxy.tun.sock' '${REPO_ROOT}/proxy.tun.pid' '${REPO_ROOT}/proxy.tun.state.json' >/dev/null 2>&1 || true"

  print_section "Post-Reset Summary"
  route_summary default
  if [[ -n "${server_host}" ]]; then
    echo '---'
    route_summary "${server_host}"
  fi
  echo '---'
  print_split_routes
  echo '---'
  list_utun_with_pipit_addr || true
}

main() {
  require_macos
  local command="${1:-doctor}"
  if [[ $# -gt 0 ]]; then
    shift
  fi

  local server_spec=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config)
        CONFIG_PATH="$2"
        shift 2
        ;;
      --server)
        server_spec="$2"
        shift 2
        ;;
      --tail)
        TAIL_LINES="$2"
        shift 2
        ;;
      --yes|-y)
        ASSUME_YES=1
        shift
        ;;
      --dry-run)
        RESET_DRY_RUN=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown argument: $1"
        ;;
    esac
  done

  server_spec="$(resolve_server_spec "${server_spec}")"

  case "${command}" in
    doctor|status)
      doctor "${server_spec}"
      ;;
    reset|cleanup)
      reset "${server_spec}"
      ;;
    *)
      die "unknown command: ${command}"
      ;;
  esac
}

main "$@"

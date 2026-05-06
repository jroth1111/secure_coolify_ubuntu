parse_cli_args() {
  local arg
  for arg in "$@"; do
    case "${arg}" in
      --json) JSON_MODE="true" ;;
      --health-check) HEALTH_CHECK_MODE="true" ;;
      --gate-c) GATE_C_MODE="true" ;;
      *)
        printf 'Error: unknown option: %s\n' "${arg}" >&2
        exit 1
        ;;
    esac
  done

  if [[ "${JSON_MODE}" == "true" && "${HEALTH_CHECK_MODE}" == "true" ]]; then
    printf 'Error: --json and --health-check are mutually exclusive.\n' >&2
    exit 1
  fi
}

detect_container_runtime() {
  if [[ -f /.dockerenv || "${container:-}" == "docker" ]]; then
    IS_CONTAINER="true"
  fi
}

record() {
  local status="$1"
  local name="$2"
  local detail="${3:-}"

  case "${status}" in
    PASS) ((++PASS_COUNT)) ;;
    FAIL) ((++FAIL_COUNT)) ;;
    INFO) ((++INFO_COUNT)) ;;
  esac

  if [[ "${JSON_MODE}" == "true" ]]; then
    RESULTS+=("$(jq -nc \
      --arg check "${name}" \
      --arg status "${status}" \
      --arg detail "${detail}" \
      '{check:$check,status:$status,detail:$detail}')")
  elif [[ "${HEALTH_CHECK_MODE}" != "true" ]]; then
    printf '%-6s %-45s %s\n' "[${status}]" "${name}" "${detail}"
  else
    :
  fi
}

check() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    record "PASS" "${name}"
  else
    record "FAIL" "${name}" "$*"
  fi
}

unit_available() {
  local unit_name="$1"
  command -v systemctl >/dev/null 2>&1 || return 1
  local load_state
  load_state="$(systemctl show --property=LoadState --value "${unit_name}" 2>/dev/null || true)"
  [[ -n "${load_state}" && "${load_state}" != "not-found" ]]
}

ifupdown_is_authoritative() {
  unit_available "networking.service" || return 1

  local path
  for path in /etc/network/interfaces /etc/network/interfaces.d/*; do
    [[ -f "${path}" ]] || continue
    if awk '
      /^[[:space:]]*#/ { next }
      /^[[:space:]]*iface[[:space:]]+/ {
        if ($2 != "lo") {
          found=1
          exit
        }
      }
      END { exit(found ? 0 : 1) }
    ' "${path}"; then
      return 0
    fi
  done

  return 1
}

load_state_context() {
  local state_snapshot
  [[ -f "${STATE_FILE}" ]] || return 0
  state_snapshot="$(mktemp)"
  if command -v flock >/dev/null 2>&1; then
    if ! flock -s "${STATE_LOCK_FILE}" bash -ceu 'cat "$1" > "$2"' _ "${STATE_FILE}" "${state_snapshot}"; then
      rm -f "${state_snapshot}"
      return 0
    fi
  else
    cat "${STATE_FILE}" > "${state_snapshot}"
  fi

  # shellcheck disable=SC1090
  source "${state_snapshot}"
  rm -f "${state_snapshot}"

  ADMIN_USER="${admin_user:-}"
  DOMAIN="${domain:-}"
  SSH_PORT="${ssh_port:-22}"
  TUNNEL_MODE="${tunnel_mode:-false}"
  WAN_IFACE="${wan_iface:-}"
  swap_size="${swap_size:-2G}"
  BIND_DASHBOARD_TO_TAILSCALE="${bind_dashboard_to_tailscale:-false}"
  TAILSCALE_IP="${tailscale_ip:-}"
  TAILSCALE_CIDR="${tailscale_cidr:-100.64.0.0/10}"
  STRICT_DOCKER_SSH_CIDRS="${strict_docker_ssh_cidrs:-false}"
  DOCKER_SSH_CIDRS="${docker_ssh_cidrs:-10.0.0.0/8,172.16.0.0/12}"
  ALLOWED_PRIVILEGED_CONTAINERS="${allowed_privileged_containers:-}"
  TAILSCALE_DIRECT_WAN="${tailscale_direct_wan:-auto}"
  UPDATE_PROFILE="${update_profile:-}"
  DOCKER_PRESENT="${docker_present:-false}"
  DOCKER_RULES_APPLIED="${docker_rules_applied:-false}"
  CONFIGURED_TIMEZONE="${timezone:-}"
}

is_true() {
  case "${1,,}" in
    1|true|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
}

regex_escape() {
  printf '%s' "$1" | sed -e 's/[][\\/.*^$(){}+?|]/\\&/g'
}

is_tailscale_ipv4() {
  local ip="$1"
  local o1 o2 o3 o4
  IFS='.' read -r o1 o2 o3 o4 <<< "${ip}"
  [[ "${o1:-}" =~ ^[0-9]+$ && "${o2:-}" =~ ^[0-9]+$ && "${o3:-}" =~ ^[0-9]+$ && "${o4:-}" =~ ^[0-9]+$ ]] || return 1
  (( o1 == 100 )) || return 1
  (( o2 >= 64 && o2 <= 127 )) || return 1
  (( o3 >= 0 && o3 <= 255 )) || return 1
  (( o4 >= 0 && o4 <= 255 )) || return 1
}

private_domain_hosts_check() {
  if [[ -z "${DOMAIN}" ]]; then
    record "INFO" "hosts: private domain loopback override" "domain not recorded in state; skipped"
    return
  fi

  if [[ ! -f "${HOSTS_FILE}" ]]; then
    record "FAIL" "hosts: private domain loopback override" "${HOSTS_FILE} not found"
    return
  fi

  local pair host label loopback_hits
  for pair in "${DOMAIN}:dashboard domain" "ws.${DOMAIN}:websocket domain"; do
    host="${pair%%:*}"
    label="${pair##*:}"
    loopback_hits="$(awk -v target="${host}" '
      $0 !~ /^[[:space:]]*#/ && NF > 1 {
        ip = $1
        if (ip ~ /^127\./ || ip == "::1") {
          for (i = 2; i <= NF; i++) {
            if ($i == target) {
              print ip
              break
            }
          }
        }
      }
    ' "${HOSTS_FILE}" | sort -u | tr '\n' ' ' | sed 's/[[:space:]]*$//')"

    if [[ -n "${loopback_hits}" ]]; then
      record "FAIL" "hosts: ${label} not loopback-pinned" \
        "${host} mapped to ${loopback_hits} in ${HOSTS_FILE}"
    else
      record "PASS" "hosts: ${label} not loopback-pinned"
    fi
  done
}

tailscale_runssh_pref_value() {
  local attempts="${1:-5}"
  local delay_seconds="${2:-1}"
  local attempt=1
  local run_ssh_pref="unknown"

  while (( attempt <= attempts )); do
    run_ssh_pref="$(tailscale debug prefs 2>/dev/null | jq -r 'if has("RunSSH") then (.RunSSH|tostring) else "unknown" end' 2>/dev/null || echo "unknown")"
    if [[ "${run_ssh_pref}" == "true" || "${run_ssh_pref}" == "false" ]]; then
      printf '%s\n' "${run_ssh_pref}"
      return 0
    fi
    if (( attempt < attempts )); then
      sleep "${delay_seconds}"
    fi
    attempt=$((attempt + 1))
  done

  printf '%s\n' "${run_ssh_pref:-unknown}"
}

infer_update_profile() {
  local apt_local="$1"
  local updates_origin='origin=Ubuntu,codename=${distro_codename}-updates,label=Ubuntu'
  local docker_origin_archive='origin=Docker,label=Docker CE,archive=${distro_codename},component=stable'
  local docker_origin_suite='origin=Docker,label=Docker CE,suite=${distro_codename},component=stable'

  if grep -qF "${updates_origin}" "${apt_local}" \
    || grep -qF "${docker_origin_archive}" "${apt_local}" \
    || grep -qF "${docker_origin_suite}" "${apt_local}"; then
    printf 'balanced\n'
  else
    printf 'security-only\n'
  fi
}

listening_ports_info() {
  local ports
  ports="$(ss -tlnp 2>/dev/null | tail -n +2 | awk '{print $4}' | sort -u)" || true
  if [[ -n "${ports}" ]]; then
    record "INFO" "listening: TCP ports" "$(echo "${ports}" | tr '\n' ' ')"
  fi
}

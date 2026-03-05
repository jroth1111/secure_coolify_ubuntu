#!/usr/bin/env bash
if [[ -z "${BASH_VERSINFO:-}" || "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  printf 'FATAL: %s requires Bash 4+ (found %s). On macOS: brew install bash, then run with /opt/homebrew/bin/bash %s ...\n' \
    "$(basename "$0")" "${BASH_VERSION:-unknown}" "$(basename "$0")" >&2
  exit 1
fi
set -Eeuo pipefail

# validate_hardening.sh — Standalone health-check companion for bootstrap_hardening.sh
# Re-runnable: prints PASS/FAIL per check, exits 0 if all pass, 1 if any fail.
# Usage: sudo ./validate_hardening.sh [--json|--health-check]

STATE_FILE="/var/lib/bootstrap-hardening/state"
JOURNALD_DROPIN="/etc/systemd/journald.conf.d/90-coolify-persistent.conf"
AUDITD_CONF="/etc/audit/auditd.conf"
JSON_MODE="false"
HEALTH_CHECK_MODE="false"
GATE_C_MODE="false"
IS_CONTAINER="false"

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

PASS_COUNT=0
FAIL_COUNT=0
INFO_COUNT=0
declare -a RESULTS=()

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

# Load state file for context (non-fatal if missing)
ADMIN_USER=""
SSH_PORT="22"
TUNNEL_MODE="false"
WAN_IFACE=""
TAILSCALE_IFACE="tailscale0"
BIND_DASHBOARD_TO_TAILSCALE="false"
TAILSCALE_IP=""
TAILSCALE_CIDR="100.64.0.0/10"
STRICT_DOCKER_SSH_CIDRS="false"
DOCKER_SSH_CIDRS="10.0.0.0/8,172.16.0.0/12"
TAILSCALE_DIRECT_WAN="auto"
UPDATE_PROFILE=""
DOCKER_RULES_APPLIED="false"
CONFIGURED_TIMEZONE=""
COOLIFY_ENV_FILE="/data/coolify/source/.env"
DOCKER_SSH_CIDR_SYNC_SCRIPT="/usr/local/sbin/docker-ssh-cidr-sync.sh"
DOCKER_SSH_CIDR_SYNC_SERVICE="docker-ssh-cidr-sync.service"
DOCKER_SSH_CIDR_SYNC_TIMER="docker-ssh-cidr-sync.timer"

load_state_context() {
  [[ -f "${STATE_FILE}" ]] || return 0
  # shellcheck disable=SC1090
  source "${STATE_FILE}"
  ADMIN_USER="${admin_user:-}"
  SSH_PORT="${ssh_port:-22}"
  TUNNEL_MODE="${tunnel_mode:-false}"
  WAN_IFACE="${wan_iface:-}"
  swap_size="${swap_size:-2G}"
  BIND_DASHBOARD_TO_TAILSCALE="${bind_dashboard_to_tailscale:-false}"
  TAILSCALE_IP="${tailscale_ip:-}"
  TAILSCALE_CIDR="${tailscale_cidr:-100.64.0.0/10}"
  STRICT_DOCKER_SSH_CIDRS="${strict_docker_ssh_cidrs:-false}"
  DOCKER_SSH_CIDRS="${docker_ssh_cidrs:-10.0.0.0/8,172.16.0.0/12}"
  TAILSCALE_DIRECT_WAN="${tailscale_direct_wan:-auto}"
  UPDATE_PROFILE="${update_profile:-}"
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

load_docker_ssh_cidrs() {
  local raw="${DOCKER_SSH_CIDRS:-10.0.0.0/8,172.16.0.0/12}"
  local item
  local -a cidrs=()
  local -A seen=()

  IFS=',' read -r -a cidrs <<< "${raw}"
  for item in "${cidrs[@]}"; do
    item="${item//[[:space:]]/}"
    [[ -n "${item}" ]] || continue
    if [[ -z "${seen[${item}]:-}" ]]; then
      seen["${item}"]=1
      printf '%s\n' "${item}"
    fi
  done

  # In strict mode, also include currently detected Docker bridge CIDRs so
  # post-hardening network drift is surfaced by validation.
  if is_true "${STRICT_DOCKER_SSH_CIDRS}"; then
    while IFS= read -r item; do
      item="${item//[[:space:]]/}"
      [[ -n "${item}" ]] || continue
      if [[ -z "${seen[${item}]:-}" ]]; then
        seen["${item}"]=1
        printf '%s\n' "${item}"
      fi
    done < <(
      docker network ls --format '{{.Name}} {{.Driver}}' 2>/dev/null \
        | awk '$2 == "bridge" && ($1 == "bridge" || $1 == "coolify" || $1 ~ /^br-/) {print $1}' \
        | xargs -r docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}' 2>/dev/null \
        | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' \
        | sort -u
    )
  fi
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

# ── SSH effective config ──

ssh_check() {
  local effective
  effective="$(sshd -T 2>/dev/null)" || { record "FAIL" "ssh: sshd -T" "cannot query"; return; }

  local field val expected
  declare -A ssh_expects=(
    [permitrootlogin]="no"
    [passwordauthentication]="no"
    [pubkeyauthentication]="yes"
    [permitemptypasswords]="no"
    [compression]="no"
  )

  for field in "${!ssh_expects[@]}"; do
    expected="${ssh_expects[${field}]}"
    val="$(grep -m1 "^${field} " <<< "${effective}" | awk '{print $2}')"
    if [[ "${val}" == "${expected}" ]]; then
      record "PASS" "ssh: ${field}=${val}"
    else
      record "FAIL" "ssh: ${field}" "expected ${expected}, got ${val:-<empty>}"
    fi
  done

  if grep -q "chacha20-poly1305@openssh.com" <<< "${effective}"; then
    record "PASS" "ssh: cipher restrictions present"
  else
    record "FAIL" "ssh: cipher restrictions" "chacha20-poly1305 not in ciphers"
  fi

  if grep -q "sntrup761x25519-sha512@openssh.com" <<< "${effective}"; then
    record "PASS" "ssh: post-quantum KEX algorithm present"
  else
    record "FAIL" "ssh: post-quantum KEX algorithm" "sntrup761x25519-sha512@openssh.com not in kexalgorithms"
  fi

  if [[ -n "${ADMIN_USER}" ]]; then
    if grep -qE "^allowusers .*\\b${ADMIN_USER}\\b" <<< "${effective}"; then
      record "PASS" "ssh: AllowUsers includes ${ADMIN_USER}"
    else
      record "FAIL" "ssh: AllowUsers" "${ADMIN_USER} not listed"
    fi
  fi

  # Verify Match Address block: root key-only login from localhost/Docker bridge CIDRs
  local match_local
  match_local="$(sshd -T -C addr=127.0.0.1,user=root,host=localhost,laddr=127.0.0.1 2>/dev/null)" || true
  if [[ -n "${match_local}" ]]; then
    local match_root_val
    match_root_val="$(grep -m1 "^permitrootlogin " <<< "${match_local}" | awk '{print $2}')"
    if grep -qE "^permitrootlogin (prohibit-password|without-password)$" <<< "${match_local}"; then
      record "PASS" "ssh: Match localhost root=prohibit-password"
    else
      record "FAIL" "ssh: Match localhost root" "expected prohibit-password/without-password, got ${match_root_val:-<empty>}"
    fi

    if grep -qE "^allowusers .*\\broot\\b" <<< "${match_local}"; then
      record "PASS" "ssh: Match localhost AllowUsers includes root"
    else
      record "FAIL" "ssh: Match localhost AllowUsers" "root not listed"
    fi
  fi

  local ssh_dropin match_line cidr
  ssh_dropin="/etc/ssh/sshd_config.d/00-coolify-hardening.conf"
  if [[ -f "${ssh_dropin}" ]]; then
    match_line="$(grep -m1 '^Match Address ' "${ssh_dropin}" || true)"
    if [[ -n "${match_line}" ]]; then
      while IFS= read -r cidr; do
        if grep -qE "(^|,|[[:space:]])$(regex_escape "${cidr}")($|,|[[:space:]])" <<< "${match_line}"; then
          record "PASS" "ssh: Match includes Docker CIDR ${cidr}"
        else
          record "FAIL" "ssh: Match Docker CIDR ${cidr}" "missing from sshd Match Address block"
        fi
      done < <(load_docker_ssh_cidrs)
    else
      record "FAIL" "ssh: Match Address block" "missing in ${ssh_dropin}"
    fi

    if grep -q '^Ciphers \^' "${ssh_dropin}"; then
      record "PASS" "ssh: Ciphers policy uses operator mode"
    else
      record "FAIL" "ssh: Ciphers policy mode" "expected '^' operator to preserve OpenSSH defaults"
    fi

    if grep -q '^MACs \^' "${ssh_dropin}"; then
      record "PASS" "ssh: MACs policy uses operator mode"
    else
      record "FAIL" "ssh: MACs policy mode" "expected '^' operator to preserve OpenSSH defaults"
    fi

    if grep -q '^KexAlgorithms \^' "${ssh_dropin}"; then
      record "PASS" "ssh: KexAlgorithms policy uses operator mode"
    else
      record "FAIL" "ssh: KexAlgorithms policy mode" "expected '^' operator to preserve OpenSSH defaults"
    fi

    if grep -q '^HostKeyAlgorithms \^' "${ssh_dropin}"; then
      record "PASS" "ssh: HostKeyAlgorithms policy uses operator mode"
    else
      record "FAIL" "ssh: HostKeyAlgorithms policy mode" "expected '^' operator to preserve OpenSSH defaults"
    fi
  else
    record "FAIL" "ssh: Match Address block" "${ssh_dropin} not found"
  fi

  # Verify external addresses still deny root
  local match_external
  match_external="$(sshd -T -C addr=203.0.113.1,user=root,host=example.com,laddr=0.0.0.0 2>/dev/null)" || true
  if [[ -n "${match_external}" ]]; then
    local ext_root_val
    ext_root_val="$(grep -m1 "^permitrootlogin " <<< "${match_external}" | awk '{print $2}')"
    if [[ "${ext_root_val}" == "no" ]]; then
      record "PASS" "ssh: external root login denied"
    else
      record "FAIL" "ssh: external root login" "expected no, got ${ext_root_val:-<empty>}"
    fi
  fi
}

# ── UFW ──

ufw_check() {
  local ufw_out
  ufw_out="$(ufw status verbose 2>/dev/null)" || { record "FAIL" "ufw: status query" "cannot run ufw"; return; }
  ufw_has_port_on_iface() {
    local port="$1" iface="$2" proto="${3:-tcp}" iface_re
    iface_re="$(regex_escape "${iface}")"
    grep -qE "(^|[[:space:]])${port}/${proto}([[:space:]]|$).*(on[[:space:]]+${iface_re}.*ALLOW IN|ALLOW IN.*on[[:space:]]+${iface_re})([[:space:]]|$)" <<< "${ufw_out}"
  }
  ufw_has_port_anywhere_unscoped() {
    local port="$1" proto="${2:-tcp}"
    grep -qE "(^|[[:space:]])${port}/${proto}([[:space:]]|$)[[:space:]]+ALLOW IN[[:space:]]+Anywhere([[:space:]]+\\(v6\\))?$" <<< "${ufw_out}"
  }

  if grep -q "^Status: active$" <<< "${ufw_out}"; then
    record "PASS" "ufw: active"
  else
    record "FAIL" "ufw: active" "UFW is not active"
    return
  fi

  if ufw_has_port_on_iface "${SSH_PORT}" "${TAILSCALE_IFACE}"; then
    record "PASS" "ufw: SSH on ${TAILSCALE_IFACE}"
  else
    record "FAIL" "ufw: SSH on ${TAILSCALE_IFACE}" "rule missing"
  fi

  # Coolify SSHes from its Docker bridge CIDRs to the host.
  local cidr escaped_cidr
  while IFS= read -r cidr; do
    escaped_cidr="$(regex_escape "${cidr}")"
    if grep -qE "${SSH_PORT}.*ALLOW.*${escaped_cidr}" <<< "${ufw_out}"; then
      record "PASS" "ufw: SSH from Docker bridge (${cidr})"
    else
      record "FAIL" "ufw: SSH from Docker bridge (${cidr})" "${cidr} → port ${SSH_PORT} rule missing — Coolify cannot reach host"
    fi
  done < <(load_docker_ssh_cidrs)

  # Coolify dashboard (8000), Soketi (6001), terminal (6002) on Tailscale only.
  for port_label in "8000:dashboard" "6001:soketi" "6002:terminal"; do
    local port="${port_label%%:*}" label="${port_label##*:}"
    if ufw_has_port_on_iface "${port}" "${TAILSCALE_IFACE}"; then
      record "PASS" "ufw: Coolify ${label} (${port}) on ${TAILSCALE_IFACE}"
    else
      record "FAIL" "ufw: Coolify ${label} (${port})" "port ${port} not allowed on ${TAILSCALE_IFACE}"
    fi
  done

  if [[ -n "${WAN_IFACE}" ]]; then
    # SSH must not be on WAN
    if ufw_has_port_on_iface "${SSH_PORT}" "${WAN_IFACE}" \
      || ufw_has_port_anywhere_unscoped "${SSH_PORT}"; then
      record "FAIL" "ufw: SSH NOT on WAN" "SSH allowed on ${WAN_IFACE}"
    else
      record "PASS" "ufw: SSH NOT on WAN"
    fi

    # Coolify ports must not be on WAN (must only be on tailscale0)
    for port_label in "8000:dashboard" "6001:soketi" "6002:terminal"; do
      local port="${port_label%%:*}" label="${port_label##*:}"
      if ufw_has_port_on_iface "${port}" "${WAN_IFACE}" \
         || ufw_has_port_anywhere_unscoped "${port}"; then
        record "FAIL" "ufw: ${label} (${port}) NOT on WAN" \
          "port ${port} allowed on WAN — must be tailscale0-only"
      else
        record "PASS" "ufw: ${label} (${port}) NOT on WAN"
      fi
    done

    if is_true "${TUNNEL_MODE}"; then
      if ufw_has_port_on_iface "80" "${WAN_IFACE}" \
        || ufw_has_port_anywhere_unscoped "80"; then
        record "FAIL" "ufw: tunnel-mode no port 80" "WAN 80 rule exists"
      else
        record "PASS" "ufw: tunnel-mode no port 80"
      fi
      if ufw_has_port_on_iface "443" "${WAN_IFACE}" \
        || ufw_has_port_anywhere_unscoped "443"; then
        record "FAIL" "ufw: tunnel-mode no port 443" "WAN 443 rule exists"
      else
        record "PASS" "ufw: tunnel-mode no port 443"
      fi
    fi

    case "${TAILSCALE_DIRECT_WAN,,}" in
      true|1|yes|y|on)
        if ufw_has_port_on_iface "41641" "${WAN_IFACE}" "udp" \
          || ufw_has_port_anywhere_unscoped "41641" "udp"; then
          record "PASS" "ufw: tailscale direct UDP 41641 on WAN"
        else
          record "FAIL" "ufw: tailscale direct UDP 41641 on WAN" "TAILSCALE_DIRECT_WAN enabled but rule missing"
        fi
        ;;
      false|0|no|n|off)
        if ufw_has_port_on_iface "41641" "${WAN_IFACE}" "udp" \
          || ufw_has_port_anywhere_unscoped "41641" "udp"; then
          record "FAIL" "ufw: tailscale direct UDP 41641 closed" "TAILSCALE_DIRECT_WAN disabled but WAN rule exists"
        else
          record "PASS" "ufw: tailscale direct UDP 41641 closed"
        fi
        ;;
      *)
        if ufw_has_port_on_iface "41641" "${WAN_IFACE}" "udp" \
          || ufw_has_port_anywhere_unscoped "41641" "udp"; then
          record "INFO" "ufw: tailscale direct UDP 41641" "rule present (legacy state: tailscale_direct_wan unset)"
        else
          record "INFO" "ufw: tailscale direct UDP 41641" "rule absent (legacy state: tailscale_direct_wan unset)"
        fi
        ;;
    esac
  fi
}

# ── DOCKER-USER iptables (IPv4 + IPv6) ──

docker_user_check() {
  if ! command -v iptables >/dev/null 2>&1; then
    record "FAIL" "docker-user: iptables" "iptables not found"
    return
  fi

  # Check if Docker is installed first
  if ! command -v docker >/dev/null 2>&1; then
    record "INFO" "docker-user: Docker" "Docker not installed; skipping DOCKER-USER checks"
    return
  fi

  # Warn if Docker is using nftables backend (experimental in Docker 29+)
  # DOCKER-USER chain behavior differs in nftables mode; iptables rules won't apply.
  # See: https://docs.docker.com/engine/network/firewall-nftables/
  if docker info 2>/dev/null | grep -qiE 'iptables:\s*false|firewall:\s*nftables'; then
    record "FAIL" "docker-user: backend" "Docker using nftables backend — DOCKER-USER iptables rules will NOT work"
    return
  else
    record "PASS" "docker-user: iptables backend"
  fi

  local docker_service_present="false"
  if unit_available "docker.service"; then
    docker_service_present="true"
  fi
  if [[ "${DOCKER_RULES_APPLIED}" != "true" && "${docker_service_present}" != "true" ]]; then
    record "INFO" "docker-user: IPv4" "docker.service unavailable and DOCKER-USER apply deferred"
    return
  fi

  local rules
  rules="$(iptables -t filter -S DOCKER-USER 2>/dev/null)" || { record "FAIL" "docker-user: IPv4" "DOCKER-USER chain absent (Docker may need restart)"; return; }

  if grep -q "coolify-hardening-wan-drop" <<< "${rules}"; then
    record "PASS" "docker-user: IPv4 wan-drop"
  else
    record "FAIL" "docker-user: IPv4 wan-drop" "rule missing"
  fi

  if grep -q "coolify-hardening-bridge-docker0" <<< "${rules}"; then
    record "PASS" "docker-user: IPv4 bridge-docker0"
  else
    record "FAIL" "docker-user: IPv4 bridge-docker0" "rule missing"
  fi

  if is_true "${TUNNEL_MODE}" && grep -q "coolify-hardening-wan-web" <<< "${rules}"; then
    record "FAIL" "docker-user: tunnel-mode no wan-web" "wan-web ACCEPT present"
  elif is_true "${TUNNEL_MODE}"; then
    record "PASS" "docker-user: tunnel-mode no wan-web"
  fi

  if command -v ip6tables >/dev/null 2>&1; then
    local rules6
    rules6="$(ip6tables -t filter -S DOCKER-USER 2>/dev/null)" || { record "INFO" "docker-user: IPv6" "DOCKER-USER chain absent"; return; }

    if grep -q "coolify-hardening-wan-drop6" <<< "${rules6}"; then
      record "PASS" "docker-user: IPv6 wan-drop6"
    else
      record "FAIL" "docker-user: IPv6 wan-drop6" "rule missing"
    fi
  else
    record "INFO" "docker-user: IPv6" "ip6tables not available"
  fi
}

# ── docker-user-hardening service lifecycle ──

docker_user_lifecycle_check() {
  local unit_file="/etc/systemd/system/docker-user-hardening.service"
  if [[ ! -f "${unit_file}" ]]; then
    if command -v docker >/dev/null 2>&1; then
      record "FAIL" "docker-user: unit file" "not found at ${unit_file}"
    else
      record "INFO" "docker-user: unit file" "Docker not installed; skipped"
    fi
    return
  fi

  if grep -q "PartOf=docker.service" "${unit_file}"; then
    record "PASS" "docker-user: PartOf=docker.service"
  else
    record "FAIL" "docker-user: PartOf=docker.service" "missing — rules lost on Docker daemon restart"
  fi

  if grep -q "WantedBy=docker.service" "${unit_file}"; then
    record "PASS" "docker-user: WantedBy=docker.service"
  else
    record "FAIL" "docker-user: WantedBy=docker.service" "missing — rules may not re-apply after Docker start"
  fi

  local docker_service_present="false"
  if unit_available "docker.service"; then
    docker_service_present="true"
  fi
  if [[ "${docker_service_present}" != "true" ]]; then
    record "INFO" "docker-user: enabled state" "docker.service unavailable; enable/start deferred"
    return
  fi

  local enabled_state
  enabled_state="$(systemctl is-enabled docker-user-hardening.service 2>/dev/null || echo "unknown")"
  if [[ "${enabled_state}" == "enabled" || "${enabled_state}" == "enabled-runtime" ]]; then
    record "PASS" "docker-user: enabled"
  else
    record "FAIL" "docker-user: enabled" "state=${enabled_state} — rules may not re-apply on Docker restart"
  fi

  # Functional: service must have run at least once since boot (rules are only in iptables if it did).
  local active_state
  active_state="$(systemctl show docker-user-hardening.service --property=ActiveState --value 2>/dev/null || echo "unknown")"
  if [[ "${active_state}" == "active" || "${active_state}" == "activating" ]]; then
    record "PASS" "docker-user: service has run (${active_state})"
  else
    # For a oneshot service, "inactive" is normal after a successful run.
    local result
    result="$(systemctl show docker-user-hardening.service --property=Result --value 2>/dev/null || echo "unknown")"
    if [[ "${result}" == "success" ]]; then
      record "PASS" "docker-user: service completed successfully"
    else
      record "FAIL" "docker-user: service result" "result=${result} — rules may not have been applied"
    fi
  fi
}

# ── docker-ssh-cidr-sync lifecycle (strict CIDR mode) ──

docker_ssh_cidr_sync_check() {
  if ! is_true "${STRICT_DOCKER_SSH_CIDRS}"; then
    record "INFO" "docker-ssh-cidr-sync: strict mode" "disabled"
    return
  fi

  if [[ ! -f "${DOCKER_SSH_CIDR_SYNC_SCRIPT}" ]]; then
    record "FAIL" "docker-ssh-cidr-sync: script" "missing at ${DOCKER_SSH_CIDR_SYNC_SCRIPT}"
    return
  fi

  # Guard against legacy script versions that inserted host/prefix values
  # (for example 10.0.0.1/24) into sshd Match Address and broke sshd reloads.
  if grep -q 'normalize_cidr()' "${DOCKER_SSH_CIDR_SYNC_SCRIPT}"; then
    record "PASS" "docker-ssh-cidr-sync: CIDR normalization"
  else
    record "FAIL" "docker-ssh-cidr-sync: CIDR normalization" \
      "normalize_cidr() missing; host/prefix CIDRs can break sshd Match Address"
  fi

  if ! command -v systemctl >/dev/null 2>&1; then
    record "INFO" "docker-ssh-cidr-sync: systemd" "systemctl unavailable"
    return
  fi

  if systemctl is-active --quiet "${DOCKER_SSH_CIDR_SYNC_TIMER}" 2>/dev/null; then
    record "PASS" "docker-ssh-cidr-sync: timer active"
  elif systemctl list-unit-files --no-legend "${DOCKER_SSH_CIDR_SYNC_TIMER}" 2>/dev/null | grep -q "${DOCKER_SSH_CIDR_SYNC_TIMER}"; then
    record "FAIL" "docker-ssh-cidr-sync: timer active" "installed but inactive"
  else
    record "FAIL" "docker-ssh-cidr-sync: timer active" "timer not installed"
  fi

  local active_state result
  active_state="$(systemctl show "${DOCKER_SSH_CIDR_SYNC_SERVICE}" --property=ActiveState --value 2>/dev/null || echo "unknown")"
  if [[ "${active_state}" == "active" || "${active_state}" == "activating" ]]; then
    record "PASS" "docker-ssh-cidr-sync: service has run (${active_state})"
    return
  fi

  # Oneshot services are expected to go inactive after successful completion.
  result="$(systemctl show "${DOCKER_SSH_CIDR_SYNC_SERVICE}" --property=Result --value 2>/dev/null || echo "unknown")"
  if [[ "${result}" == "success" ]]; then
    record "PASS" "docker-ssh-cidr-sync: service completed successfully"
  else
    record "FAIL" "docker-ssh-cidr-sync: service result" \
      "result=${result} — inspect: journalctl -u ${DOCKER_SSH_CIDR_SYNC_SERVICE}"
  fi
}

# ── Sysctl ──

sysctl_check() {
  local key expected val
  declare -A sysctl_expects=(
    [net.ipv4.tcp_syncookies]="1"
    [net.ipv4.ip_forward]="1"
    [net.ipv4.conf.all.rp_filter]="2"
    [net.ipv4.tcp_max_syn_backlog]="2048"
    [net.ipv4.tcp_synack_retries]="2"
    [fs.protected_hardlinks]="1"
    [fs.protected_symlinks]="1"
    [fs.suid_dumpable]="0"
    [kernel.unprivileged_bpf_disabled]="2"
    [kernel.kexec_load_disabled]="1"
    [kernel.sysrq]="4"
    [kernel.randomize_va_space]="2"
    [kernel.dmesg_restrict]="1"
    [kernel.perf_event_paranoid]="3"
    [kernel.yama.ptrace_scope]="1"
    [kernel.kptr_restrict]="2"
    [vm.swappiness]="10"
  )

  for key in "${!sysctl_expects[@]}"; do
    expected="${sysctl_expects[${key}]}"
    val="$(sysctl -n "${key}" 2>/dev/null || echo "?")"
    if [[ "${val}" == "${expected}" ]]; then
      record "PASS" "sysctl: ${key}=${val}"
    elif [[ "${val}" == "?" && "${IS_CONTAINER}" == "true" ]]; then
      record "INFO" "sysctl: ${key}" "unavailable in container namespace"
    else
      record "FAIL" "sysctl: ${key}" "expected ${expected}, got ${val}"
    fi
  done

  # BBR congestion control (informational — depends on kernel module availability)
  local bbr_val
  bbr_val="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "?")"
  if [[ "${bbr_val}" == "bbr" ]]; then
    record "PASS" "sysctl: tcp_congestion_control=bbr"
  elif [[ "${bbr_val}" == "?" && "${IS_CONTAINER}" == "true" ]]; then
    record "INFO" "sysctl: tcp_congestion_control" "unavailable in container namespace"
  else
    record "INFO" "sysctl: tcp_congestion_control=${bbr_val}" "BBR not active (kernel module may be unavailable)"
  fi

  local qdisc_val
  qdisc_val="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "?")"
  if [[ "${qdisc_val}" == "fq" ]]; then
    record "PASS" "sysctl: default_qdisc=fq"
  elif [[ "${qdisc_val}" == "?" && "${IS_CONTAINER}" == "true" ]]; then
    record "INFO" "sysctl: default_qdisc" "unavailable in container namespace"
  else
    record "INFO" "sysctl: default_qdisc=${qdisc_val}" "fq not active (BBR may be unavailable)"
  fi
}

# ── fail2ban ──

fail2ban_check() {
  if systemctl is-active --quiet fail2ban 2>/dev/null; then
    record "PASS" "fail2ban: active"
  else
    record "FAIL" "fail2ban: active" "service not running"
    return
  fi

  if fail2ban-client status sshd >/dev/null 2>&1; then
    record "PASS" "fail2ban: sshd jail enabled"
  else
    record "FAIL" "fail2ban: sshd jail" "jail not active"
  fi

  local _jail_file="/etc/fail2ban/jail.d/coolify-hardening.local"
  if [[ -f "${_jail_file}" ]] && grep -Fq "${TAILSCALE_CIDR}" "${_jail_file}"; then
    record "PASS" "fail2ban: ignoreip includes Tailscale CIDR"
  elif [[ ! -f "${_jail_file}" ]]; then
    record "FAIL" "fail2ban: ignoreip" "jail file missing"
  else
    record "FAIL" "fail2ban: ignoreip" "${TAILSCALE_CIDR} not in ignoreip"
  fi

  # Functional check: verify fail2ban's ban backend is operational.
  # When banaction=ufw, fail2ban delegates to UFW instead of creating iptables chains directly.
  # When banaction=iptables-multiport (default), it creates f2b-* chains.
  local banaction
  banaction="$(
    awk -F= '
      /^[[:space:]]*banaction[[:space:]]*=/ {
        value=$2
        sub(/[[:space:]]*#.*$/, "", value)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
        print value
        exit
      }
    ' /etc/fail2ban/jail.d/coolify-hardening.local 2>/dev/null || true
  )"
  banaction="${banaction:-iptables-multiport}"

  if [[ "${banaction}" == "ufw" ]]; then
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "^Status: active"; then
      record "PASS" "fail2ban: banaction=ufw and UFW active"
    else
      record "FAIL" "fail2ban: banaction=ufw" "UFW not active — fail2ban bans will silently fail"
    fi
  else
    if iptables -L f2b-sshd >/dev/null 2>&1; then
      record "PASS" "fail2ban: f2b-sshd iptables chain present"
    else
      record "FAIL" "fail2ban: f2b-sshd iptables chain" "chain missing — fail2ban may not have hooked into iptables"
    fi
  fi
}

# ── auditd ──

auditd_check() {
  if systemctl is-active --quiet auditd 2>/dev/null; then
    record "PASS" "auditd: active"
  elif [[ "${IS_CONTAINER}" == "true" ]]; then
    record "INFO" "auditd: active" "not active in container test environment"
  else
    record "FAIL" "auditd: active" "service not running"
    return
  fi

  local rules
  rules="$(auditctl -l 2>/dev/null)" || { record "FAIL" "auditd: rules" "cannot list"; return; }

  if grep -q "identity" <<< "${rules}"; then
    record "PASS" "auditd: identity rules loaded"
  else
    record "FAIL" "auditd: identity rules" "not loaded"
  fi

  if grep -q "sudoers-change" <<< "${rules}"; then
    record "PASS" "auditd: sudoers rules loaded"
  else
    record "FAIL" "auditd: sudoers rules" "not loaded"
  fi

  if grep -q "kernel-module" <<< "${rules}"; then
    record "PASS" "auditd: kernel-module rules loaded"
  else
    record "FAIL" "auditd: kernel-module rules" "not loaded"
  fi

  if grep -q "user_commands" <<< "${rules}"; then
    record "PASS" "auditd: user_commands execve rules loaded"
  else
    record "FAIL" "auditd: user_commands execve rules" "not loaded"
  fi

  if [[ -f "${AUDITD_CONF}" ]]; then
    if grep -qE '^[[:space:]]*max_log_file_action[[:space:]]*=[[:space:]]*keep_logs' "${AUDITD_CONF}"; then
      record "PASS" "auditd: max_log_file_action=keep_logs"
    else
      record "FAIL" "auditd: max_log_file_action" "expected keep_logs in ${AUDITD_CONF}"
    fi

    if grep -qE '^[[:space:]]*disk_full_action[[:space:]]*=[[:space:]]*suspend' "${AUDITD_CONF}" \
      && grep -qE '^[[:space:]]*disk_error_action[[:space:]]*=[[:space:]]*suspend' "${AUDITD_CONF}"; then
      record "PASS" "auditd: disk failure actions configured"
    else
      record "FAIL" "auditd: disk failure actions" "expected disk_full_action/disk_error_action=suspend"
    fi

    local space_left space_left_action admin_space_left admin_space_left_action
    space_left="$(grep -E '^[[:space:]]*space_left[[:space:]]*=' "${AUDITD_CONF}" | tail -1 | sed 's/.*=[[:space:]]*//')"
    space_left_action="$(grep -E '^[[:space:]]*space_left_action[[:space:]]*=' "${AUDITD_CONF}" | tail -1 | sed 's/.*=[[:space:]]*//')"
    if [[ "${space_left:-0}" =~ ^[0-9]+$ ]] && (( space_left > 0 )) && [[ "${space_left_action}" == "syslog" ]]; then
      record "PASS" "auditd: space_left=${space_left}, space_left_action=syslog"
    else
      record "FAIL" "auditd: space_left thresholds" "expected space_left>0 and space_left_action=syslog"
    fi

    admin_space_left="$(grep -E '^[[:space:]]*admin_space_left[[:space:]]*=' "${AUDITD_CONF}" | tail -1 | sed 's/.*=[[:space:]]*//')"
    admin_space_left_action="$(grep -E '^[[:space:]]*admin_space_left_action[[:space:]]*=' "${AUDITD_CONF}" | tail -1 | sed 's/.*=[[:space:]]*//')"
    if [[ "${admin_space_left:-0}" =~ ^[0-9]+$ ]] && (( admin_space_left > 0 )) && [[ "${admin_space_left_action}" == "suspend" ]]; then
      record "PASS" "auditd: admin_space_left=${admin_space_left}, admin_space_left_action=suspend"
    else
      record "FAIL" "auditd: admin_space_left thresholds" "expected admin_space_left>0 and admin_space_left_action=suspend"
    fi
  else
    record "INFO" "auditd: policy config" "${AUDITD_CONF} not found"
  fi

  local audit_status lost backlog
  audit_status="$(auditctl -s 2>/dev/null || true)"
  if [[ -n "${audit_status}" ]]; then
    lost="$(awk '/^lost[[:space:]]/ {print $2; exit}' <<< "${audit_status}")"
    backlog="$(awk '/^backlog[[:space:]]/ {print $2; exit}' <<< "${audit_status}")"
    if [[ "${lost:-0}" =~ ^[0-9]+$ ]] && [[ "${lost}" == "0" ]]; then
      record "PASS" "auditd: queue loss (lost=0)"
    elif [[ "${lost:-}" =~ ^[0-9]+$ ]] && (( lost > 100 )); then
      record "FAIL" "auditd: queue loss" "lost=${lost} (>100 events dropped)"
    elif [[ "${lost:-}" =~ ^[0-9]+$ ]]; then
      record "INFO" "auditd: queue loss" "lost=${lost} (minor — below threshold)"
    else
      record "INFO" "auditd: queue loss" "unable to parse 'lost' from auditctl -s"
    fi
    [[ -n "${backlog}" ]] && record "INFO" "auditd: backlog" "backlog=${backlog}"
  else
    record "INFO" "auditd: queue status" "auditctl -s unavailable"
  fi
}

# ── journald ──

journald_check() {
  if [[ -f "${JOURNALD_DROPIN}" ]] && grep -q "^Storage=persistent$" "${JOURNALD_DROPIN}"; then
    record "PASS" "journald: persistent storage config"
  else
    record "FAIL" "journald: persistent storage config" "drop-in missing or not persistent"
  fi

  # Verify persistent storage directory exists (journald creates /var/log/journal when Storage=persistent)
  if [[ -d /var/log/journal ]]; then
    record "PASS" "journald: /var/log/journal directory exists"
  else
    record "FAIL" "journald: /var/log/journal" "directory missing — persistent storage not active"
  fi

  if [[ -f "${JOURNALD_DROPIN}" ]] && grep -q "^SystemKeepFree=500M$" "${JOURNALD_DROPIN}"; then
    record "PASS" "journald: keep-free policy"
  else
    record "FAIL" "journald: keep-free policy" "SystemKeepFree=500M missing"
  fi

  local usage
  usage="$(journalctl --disk-usage 2>/dev/null | head -1)" || true
  if [[ -n "${usage}" ]]; then
    record "INFO" "journald: disk usage" "${usage}"
  fi
}

rsyslog_collect_log_targets() {
  local cfg
  local -a cfgs=()

  [[ -f /etc/rsyslog.conf ]] && cfgs+=("/etc/rsyslog.conf")
  for cfg in /etc/rsyslog.d/*.conf; do
    [[ -f "${cfg}" ]] || continue
    cfgs+=("${cfg}")
  done

  ((${#cfgs[@]} > 0)) || return 0

  awk '
    /^[[:space:]]*#/ { next }
    {
      for (i = 1; i <= NF; i++) {
        tok = $i
        if (tok ~ /^-?\/var\/log\//) {
          sub(/^-/, "", tok)
          sub(/[;,]+$/, "", tok)
          print tok
        }
      }
    }
  ' "${cfgs[@]}" | sort -u
}

rsyslog_check() {
  local mode owner group group_digit
  local target q_target
  local target_count=0

  owner="$(stat -c '%U' /var/log 2>/dev/null || true)"
  group="$(stat -c '%G' /var/log 2>/dev/null || true)"
  mode="$(stat -c '%a' /var/log 2>/dev/null || true)"

  if [[ "${owner}" == "root" && "${group}" == "syslog" ]]; then
    record "PASS" "rsyslog: /var/log owner/group"
  else
    record "FAIL" "rsyslog: /var/log owner/group" \
      "expected root:syslog, got ${owner:-unknown}:${group:-unknown}"
  fi

  if [[ "${mode}" =~ ^[0-7]{3,4}$ ]]; then
    group_digit="${mode: -2:1}"
    if (( (10#${group_digit} & 2) != 0 )); then
      record "PASS" "rsyslog: /var/log group-write enabled"
    else
      record "FAIL" "rsyslog: /var/log group-write" \
        "mode ${mode} lacks group write; rsyslog cannot create missing targets"
    fi
  else
    record "FAIL" "rsyslog: /var/log mode" "unreadable (${mode:-unknown})"
  fi

  while IFS= read -r target; do
    [[ -n "${target}" ]] || continue
    ((++target_count))
    if [[ -f "${target}" ]]; then
      record "PASS" "rsyslog: target exists (${target})"
      printf -v q_target '%q' "${target}"
      if su -s /bin/sh -c "test -w ${q_target}" syslog >/dev/null 2>&1; then
        record "PASS" "rsyslog: target writable by syslog (${target})"
      else
        record "FAIL" "rsyslog: target writable by syslog (${target})" "permission denied"
      fi
    else
      record "FAIL" "rsyslog: target exists (${target})" "missing"
    fi
  done < <(rsyslog_collect_log_targets)

  if (( target_count == 0 )); then
    record "INFO" "rsyslog: configured /var/log targets" "none found in rsyslog config"
  fi

  if [[ -f /etc/logrotate.d/rsyslog ]] \
    && grep -Eq '^[[:space:]]*create[[:space:]]+640[[:space:]]+syslog[[:space:]]+(adm|syslog)([[:space:]]|$)' /etc/logrotate.d/rsyslog; then
    record "PASS" "rsyslog: logrotate create directive"
  else
    record "FAIL" "rsyslog: logrotate create directive" \
      "missing in /etc/logrotate.d/rsyslog (expected create 640 syslog <group>)"
  fi

  if [[ -f /etc/logrotate.d/ufw ]] \
    && grep -Eq '^[[:space:]]*create[[:space:]]+640[[:space:]]+syslog[[:space:]]+(adm|syslog)([[:space:]]|$)' /etc/logrotate.d/ufw; then
    record "PASS" "rsyslog: ufw logrotate create directive"
  else
    record "FAIL" "rsyslog: ufw logrotate create directive" \
      "missing in /etc/logrotate.d/ufw (expected create 640 syslog <group>)"
  fi

  if systemctl is-active --quiet rsyslog 2>/dev/null; then
    record "PASS" "rsyslog: service active"
  else
    record "FAIL" "rsyslog: service active" "service not running"
  fi

  local active_since
  active_since="$(systemctl show -p ActiveEnterTimestamp --value rsyslog 2>/dev/null || true)"
  if [[ -n "${active_since}" ]]; then
    if journalctl -u rsyslog --since "${active_since}" --no-pager -o cat 2>/dev/null \
      | grep -Eq 'suspended \(module '\''builtin:omfile'\''\)|Permission denied|open error|e/2007|e/2433'; then
      record "FAIL" "rsyslog: runtime log-write health" \
        "omfile suspend/permission errors present since last restart"
    else
      record "PASS" "rsyslog: runtime log-write health"
    fi
  else
    record "INFO" "rsyslog: runtime log-write health" "unable to determine service activation timestamp"
  fi
}

# ── NTP / Timesync ──

timesync_check() {
  local ntp_val
  ntp_val="$(timedatectl show --property=NTP --value 2>/dev/null || echo "?")"
  if [[ "${ntp_val}" == "yes" ]]; then
    record "PASS" "timesync: NTP active"
  elif [[ "${IS_CONTAINER}" == "true" ]]; then
    record "INFO" "timesync: NTP" "unavailable in container"
  else
    record "FAIL" "timesync: NTP" "not active"
  fi

  local synced_val
  synced_val="$(timedatectl show --property=NTPSynchronized --value 2>/dev/null || echo "?")"
  if [[ "${synced_val}" == "yes" ]]; then
    record "PASS" "timesync: NTPSynchronized"
  elif [[ "${IS_CONTAINER}" == "true" || "${ntp_val}" != "yes" ]]; then
    record "INFO" "timesync: NTPSynchronized" "skipped (NTP not active or container)"
  else
    record "FAIL" "timesync: NTPSynchronized" "not yet synchronized"
  fi
}

timezone_check() {
  local current_tz=""
  if command -v timedatectl >/dev/null 2>&1; then
    current_tz="$(timedatectl show --property=Timezone --value 2>/dev/null || true)"
  fi
  if [[ -z "${current_tz}" || "${current_tz}" == "n/a" ]]; then
    if [[ -f /etc/timezone ]]; then
      current_tz="$(tr -d '[:space:]' < /etc/timezone 2>/dev/null || true)"
    elif [[ -L /etc/localtime ]]; then
      current_tz="$(readlink /etc/localtime 2>/dev/null || true)"
      current_tz="${current_tz#*/zoneinfo/}"
    fi
  fi
  if [[ -z "${current_tz}" || "${current_tz}" == "n/a" ]]; then
    record "INFO" "timezone: current timezone" "unable to determine timezone from timedatectl or system files"
    return
  fi
  record "INFO" "timezone: current" "${current_tz}"

  if [[ -z "${CONFIGURED_TIMEZONE}" ]]; then
    record "INFO" "timezone: configured value" "state missing timezone; cannot verify expected value"
    return
  fi

  if [[ "${current_tz}" == "${CONFIGURED_TIMEZONE}" ]]; then
    record "PASS" "timezone: configured (${CONFIGURED_TIMEZONE})"
  else
    record "FAIL" "timezone: configured (${CONFIGURED_TIMEZONE})" \
      "current timezone is ${current_tz}"
  fi
}

# ── Swap ──

swap_check() {
  local swap_size="${swap_size:-2G}"
  if [[ "${swap_size}" == "0" ]]; then
    record "INFO" "swap: disabled" "swap creation was skipped (--swap-size 0)"
    return
  fi

  if swapon --show --noheadings 2>/dev/null | grep -q .; then
    local swap_total swap_output
    # swapon --show output format: NAME TYPE SIZE USED PRIO
    # SIZE column position varies; use --bytes and sum the SIZE column (3rd field)
    swap_output="$(swapon --show --noheadings --bytes 2>/dev/null)" || true
    if [[ -n "${swap_output}" ]]; then
      swap_total="$(awk '{sum+=$3} END {printf "%.0fM", sum/1048576}' <<< "${swap_output}")"
      record "PASS" "swap: active (${swap_total})"
    else
      record "PASS" "swap: active"
    fi
  elif [[ "${IS_CONTAINER}" == "true" ]]; then
    record "INFO" "swap: status" "unavailable in container"
  else
    record "FAIL" "swap: active" "no swap detected"
  fi

  if [[ -f /swapfile ]]; then
    local perms
    perms="$(stat -c '%a' /swapfile 2>/dev/null || echo "?")"
    if [[ "${perms}" == "600" ]]; then
      record "PASS" "swap: /swapfile permissions 0600"
    else
      record "FAIL" "swap: /swapfile permissions" "expected 600, got ${perms}"
    fi
  fi

  local fstab_count
  # Match any /swapfile fstab entry regardless of options format.
  # Old Ubuntu: "/swapfile none swap sw 0 0"
  # Modern Ubuntu: "/swapfile swap swap defaults 0 0"
  fstab_count="$(grep -cE '^/swapfile[[:space:]]' /etc/fstab 2>/dev/null || true)"
  fstab_count="${fstab_count:-0}"
  if [[ "${fstab_count}" == "1" ]]; then
    record "PASS" "swap: single fstab entry"
  elif [[ "${fstab_count}" == "0" && "${IS_CONTAINER}" == "true" ]]; then
    record "INFO" "swap: fstab" "not applicable in container"
  elif (( fstab_count > 1 )); then
    record "FAIL" "swap: fstab" "duplicate entries (${fstab_count})"
  else
    record "FAIL" "swap: fstab" "entry not found in /etc/fstab — swap will not persist on reboot"
  fi
}

# ── Banner ──

banner_check() {
  if [[ -f /etc/issue.net ]] && grep -q "AUTHORIZED" /etc/issue.net; then
    record "PASS" "banner: /etc/issue.net present"
  else
    record "FAIL" "banner: /etc/issue.net" "missing or no AUTHORIZED text"
  fi
}

# ── Admin sudo access ──

admin_sudo_check() {
  # Skip if no admin user configured
  if [[ -z "${ADMIN_USER}" ]]; then
    record "INFO" "admin: sudo" "no admin user in state file"
    return 0
  fi

  # Check if admin user exists
  if ! id "${ADMIN_USER}" >/dev/null 2>&1; then
    record "FAIL" "admin: user" "${ADMIN_USER} does not exist"
    return 0
  fi

  # Check if admin user is in sudo group
  if id -nG "${ADMIN_USER}" | tr ' ' '\n' | grep -qx "sudo"; then
    record "PASS" "admin: in sudo group"
  else
    record "FAIL" "admin: sudo group" "${ADMIN_USER} not in sudo group"
    return 0
  fi

  # Check if passwordless sudo is configured.
  # Passwordless sudo is required: ssh_admin_sudo in the orchestrator runs non-interactively
  # and will hang waiting for a password prompt if NOPASSWD is absent.
  local sudoers_file="/etc/sudoers.d/${ADMIN_USER}"
  if [[ -f "${sudoers_file}" ]]; then
    if grep -q "NOPASSWD" "${sudoers_file}" 2>/dev/null; then
      record "PASS" "admin: passwordless sudo"
    else
      record "FAIL" "admin: sudo" "sudoers file exists but NOPASSWD not set — ssh_admin_sudo will hang"
    fi
  else
    # Check if sudo -l shows NOPASSWD for this user
    if sudo -l -U "${ADMIN_USER}" 2>/dev/null | grep -q "NOPASSWD"; then
      record "PASS" "admin: passwordless sudo (via other config)"
    else
      record "FAIL" "admin: sudo" "NOPASSWD not configured — ssh_admin_sudo will hang"
    fi
  fi

  # Check admin authorized_keys: file must exist, be non-empty, and each key must be
  # on its own line. The concatenation bug (missing trailing newline on a prior key)
  # would still allow sudo to work while silently breaking SSH login.
  local home_dir auth_file
  home_dir="$(getent passwd "${ADMIN_USER}" | cut -d: -f6 2>/dev/null)" || true
  auth_file="${home_dir}/.ssh/authorized_keys"
  if [[ ! -f "${auth_file}" ]]; then
    record "FAIL" "admin: authorized_keys exists" "${auth_file} not found"
  elif [[ ! -s "${auth_file}" ]]; then
    record "FAIL" "admin: authorized_keys non-empty" "${auth_file} is empty"
  else
    # Allow valid key lines with optional OpenSSH options prefix:
    # from="...",command="...",no-agent-forwarding,... ssh-ed25519 AAAA...
    # Flag only lines that do not contain a recognized key type token.
    local bad_lines
    bad_lines="$(
      awk '
        /^[[:space:]]*($|#)/ { next }
        /(^|[[:space:]])(ssh-[^[:space:]]+|ecdsa-sha2-[^[:space:]]+|sk-[^[:space:]]+)[[:space:]]+/ { next }
        { bad++ }
        END { print bad + 0 }
      ' "${auth_file}" 2>/dev/null
    )" || bad_lines="0"
    if [[ "${bad_lines}" -eq 0 ]]; then
      record "PASS" "admin: authorized_keys format"
    else
      record "FAIL" "admin: authorized_keys format" \
        "${bad_lines} line(s) do not start with a valid key type (possible concatenation bug)"
    fi
  fi
}

# ── Docker daemon.json ──
# Hardening owns: log-driver, log-opts, live-restore, default-ipc-mode,
#   storage-driver, default-ulimits. Coolify may add: default-address-pools.
# Using json-file driver to match Coolify's expectation for compatibility.

docker_daemon_check() {
  local daemon_json="/etc/docker/daemon.json"
  if [[ ! -f "${daemon_json}" ]]; then
    if command -v docker >/dev/null 2>&1; then
      record "FAIL" "docker-daemon: daemon.json" "file missing (no log rotation)"
    else
      record "INFO" "docker-daemon: daemon.json" "Docker not installed; skipped"
    fi
    return
  fi

  # Check log-driver is json-file (matches Coolify's expectation)
  local log_driver
  log_driver="$(jq -r '.["log-driver"] // ""' "${daemon_json}" 2>/dev/null || true)"
  if [[ "${log_driver}" == "json-file" ]]; then
    record "PASS" "docker-daemon: log-driver is json-file"
  elif [[ "${log_driver}" == "" ]]; then
    record "FAIL" "docker-daemon: log-driver" "not set in daemon.json"
  else
    record "FAIL" "docker-daemon: log-driver" "expected 'json-file', got '${log_driver}'"
  fi

  # Check log-opts have rotation configured
  if jq -e '.["log-opts"]["max-size"]' "${daemon_json}" >/dev/null 2>&1; then
    record "PASS" "docker-daemon: log-opts.max-size configured"
  else
    record "FAIL" "docker-daemon: log-opts.max-size" "not set in daemon.json"
  fi

  local live_restore
  live_restore="$(jq -r 'if has("live-restore") then .["live-restore"] else "missing" end | tostring' "${daemon_json}" 2>/dev/null || echo "invalid")"
  case "${live_restore}" in
    true)
      record "PASS" "docker-daemon: live-restore=true"
      ;;
    false)
      record "FAIL" "docker-daemon: live-restore" "expected true, got false"
      ;;
    missing)
      record "FAIL" "docker-daemon: live-restore" "not set in daemon.json"
      ;;
    *)
      record "FAIL" "docker-daemon: live-restore" "invalid value in daemon.json"
      ;;
  esac

  # CIS 5.19: isolate container IPC namespaces
  local ipc_mode
  ipc_mode="$(jq -r '.["default-ipc-mode"] // ""' "${daemon_json}" 2>/dev/null || true)"
  if [[ "${ipc_mode}" == "private" ]]; then
    record "PASS" "docker-daemon: default-ipc-mode is private"
  else
    record "FAIL" "docker-daemon: default-ipc-mode" "expected 'private', got '${ipc_mode:-<unset>}'"
  fi

  # Make overlay2 explicit to prevent regression
  local storage
  storage="$(jq -r '.["storage-driver"] // ""' "${daemon_json}" 2>/dev/null || true)"
  if [[ "${storage}" == "overlay2" ]]; then
    record "PASS" "docker-daemon: storage-driver is overlay2"
  else
    record "FAIL" "docker-daemon: storage-driver" "expected 'overlay2', got '${storage:-<unset>}'"
  fi

  # Prevent fork bombs / fd exhaustion
  if jq -e '.["default-ulimits"]["nofile"]' "${daemon_json}" >/dev/null 2>&1 \
    && jq -e '.["default-ulimits"]["nproc"]' "${daemon_json}" >/dev/null 2>&1; then
    record "PASS" "docker-daemon: default-ulimits (nofile+nproc) configured"
  else
    record "FAIL" "docker-daemon: default-ulimits" "nofile and/or nproc not set in daemon.json"
  fi

  # Verify the RUNNING daemon matches the config file — daemon.json changes only take
  # effect after a restart, so file and live state can diverge silently.
  if docker info >/dev/null 2>&1; then
    local live_driver
    live_driver="$(docker info --format '{{.LoggingDriver}}' 2>/dev/null || true)"
    if [[ "${live_driver}" == "json-file" ]]; then
      record "PASS" "docker-daemon: live log-driver is json-file"
    elif [[ -n "${live_driver}" ]]; then
      record "FAIL" "docker-daemon: live log-driver" \
        "daemon reports '${live_driver}' — restart Docker to apply daemon.json"
    fi
  else
    record "INFO" "docker-daemon: live config" "docker daemon not responding; skipping live check"
  fi
}

# ── Docker daemon trust-boundary checks ──

docker_trust_boundary_check() {
  local docker_sock="/var/run/docker.sock"

  if ! command -v docker >/dev/null 2>&1; then
    record "INFO" "docker-trust: docker" "Docker not installed; skipped"
    return
  fi

  if [[ ! -S "${docker_sock}" ]]; then
    record "INFO" "docker-trust: socket" "${docker_sock} not present; skipped"
    return
  fi

  local mode owner group other
  mode="$(stat -c '%a' "${docker_sock}" 2>/dev/null || echo "")"
  owner="$(stat -c '%U' "${docker_sock}" 2>/dev/null || echo "")"
  group="$(stat -c '%G' "${docker_sock}" 2>/dev/null || echo "")"

  if [[ -n "${mode}" ]]; then
    other="${mode: -1}"
    if [[ "${other}" =~ ^[0-7]$ ]] && (( (10#${other} & 2) != 0 )); then
      record "FAIL" "docker-trust: socket world-writable check" \
        "${docker_sock} mode=${mode} allows world write"
    else
      record "PASS" "docker-trust: socket world-writable check"
    fi
  else
    record "FAIL" "docker-trust: socket mode" "cannot read mode for ${docker_sock}"
  fi

  if [[ "${owner}" == "root" ]]; then
    record "PASS" "docker-trust: socket owner is root"
  else
    record "FAIL" "docker-trust: socket owner" "expected root, got ${owner:-<unknown>}"
  fi

  if [[ "${group}" == "docker" || "${group}" == "root" ]]; then
    record "PASS" "docker-trust: socket group is ${group}"
  else
    record "INFO" "docker-trust: socket group" \
      "group=${group:-<unknown>} (verify intended access model)"
  fi

  if getent group docker >/dev/null 2>&1; then
    local docker_members
    docker_members="$(getent group docker | awk -F: '{print $4}')"

    if [[ -z "${docker_members}" ]]; then
      record "PASS" "docker-trust: docker group has no named members"
    else
      record "INFO" "docker-trust: docker group members" "${docker_members}"
    fi

    if [[ -n "${ADMIN_USER}" ]] && grep -qE "(^|,)$(regex_escape "${ADMIN_USER}")($|,)" <<< "${docker_members}"; then
      record "FAIL" "docker-trust: admin user not in docker group" \
        "${ADMIN_USER} is in docker group (root-equivalent Docker access)"
    else
      record "PASS" "docker-trust: admin user not in docker group"
    fi
  else
    record "INFO" "docker-trust: docker group" "group not present"
  fi

  # Check for privileged containers (INFO — some workloads legitimately need it)
  local priv_containers
  priv_containers="$(docker ps -q 2>/dev/null | xargs -r docker inspect \
    --format '{{if .HostConfig.Privileged}}{{.Name}}{{end}}' 2>/dev/null \
    | sed 's|^/||' | paste -sd, - || true)"
  if [[ -n "${priv_containers}" ]]; then
    record "INFO" "docker-trust: privileged containers" "running: ${priv_containers}"
  else
    record "PASS" "docker-trust: no privileged containers running"
  fi
}

# ── AppArmor ──

apparmor_check() {
  if command -v aa-status >/dev/null 2>&1; then
    if aa-status --enabled 2>/dev/null; then
      record "PASS" "apparmor: enabled"
    elif [[ "${IS_CONTAINER}" == "true" ]]; then
      record "INFO" "apparmor: status" "cannot verify in container"
    else
      record "FAIL" "apparmor: enabled" "AppArmor not enabled"
    fi
  elif [[ "${IS_CONTAINER}" == "true" ]]; then
    record "INFO" "apparmor: status" "cannot check in container"
  else
    record "FAIL" "apparmor: aa-status" "command not found"
  fi
}

# ── Disabled services ──

disabled_services_check() {
  local svc
  for svc in rpcbind avahi-daemon cups; do
    local state="not-found"
    state="$(systemctl is-enabled "${svc}.service" 2>/dev/null || true)"
    state="${state%%$'\n'*}"
    [[ -n "${state}" ]] || state="not-found"

    if [[ "${state}" == masked* || "${state}" == "not-found" ]]; then
      record "PASS" "disabled: ${svc} (${state})"
    else
      record "FAIL" "disabled: ${svc}" "state is ${state}, expected masked"
    fi
  done
}

# ── Tailscale interface ──

tailscale_check() {
  if ip link show "${TAILSCALE_IFACE}" >/dev/null 2>&1; then
    record "PASS" "tailscale: ${TAILSCALE_IFACE} present"
  else
    record "FAIL" "tailscale: ${TAILSCALE_IFACE}" "interface not found"
    return
  fi

  # Check actual connection state via tailscale CLI (not just interface presence).
  # Interface can exist while the daemon is in a broken/logged-out state.
  if command -v tailscale >/dev/null 2>&1; then
    local ts_state
    ts_state="$(tailscale status --json 2>/dev/null \
      | jq -r '.BackendState // "unknown"' \
      2>/dev/null || echo "unknown")"
    if [[ "${ts_state}" == "Running" ]]; then
      record "PASS" "tailscale: BackendState=Running"
    else
      record "FAIL" "tailscale: BackendState" "expected Running, got ${ts_state}"
    fi

    # Check that a Tailscale IPv4 (100.x) has actually been assigned
    local ts_ip
    ts_ip="$(tailscale ip -4 2>/dev/null || true)"
    if [[ -n "${ts_ip}" ]]; then
      record "PASS" "tailscale: IPv4 assigned (${ts_ip})"
    else
      record "FAIL" "tailscale: IPv4 address" "no Tailscale IPv4 — check auth key and login state"
    fi

    local direct_count relay_count
    direct_count="$(tailscale status --json 2>/dev/null | jq -r '[.Peer[]? | select((.CurAddr // "") != "" and ((.Relay // "") == ""))] | length' 2>/dev/null || echo "")"
    relay_count="$(tailscale status --json 2>/dev/null | jq -r '[.Peer[]? | select((.Relay // "") != "")] | length' 2>/dev/null || echo "")"
    if [[ "${direct_count}" =~ ^[0-9]+$ && "${relay_count}" =~ ^[0-9]+$ ]]; then
      record "INFO" "tailscale: peer path summary" "direct=${direct_count}, relay=${relay_count}"
    else
      record "INFO" "tailscale: peer path summary" "unable to parse direct/relay counts"
    fi
  else
    record "INFO" "tailscale: CLI" "tailscale binary not found; skipping state/IP checks"
  fi
}

# ── Coolify split-horizon binding ──

coolify_binding_check() {
  # Skip if binding restriction was not configured
  if ! is_true "${BIND_DASHBOARD_TO_TAILSCALE}"; then
    record "INFO" "coolify: dashboard UFW restriction" "not configured (use --bind-dashboard-to-tailscale)"
    return 0
  fi

  # Dashboard Tailscale restriction is enforced via UFW rules on tailscale0, not by
  # socket binding (APP_PORT=IP:port breaks Coolify's expose: directive). Check UFW rules.

  if ! command -v ufw >/dev/null 2>&1; then
    record "FAIL" "coolify: ufw" "ufw command not found"
    return 0
  fi

  local ufw_out
  ufw_out="$(ufw status 2>/dev/null)" || true

  # Check UFW rule for port 8000 on tailscale0
  if echo "${ufw_out}" | grep -q "8000.*on ${TAILSCALE_IFACE}"; then
    record "PASS" "coolify: UFW rule port 8000 on ${TAILSCALE_IFACE}"
  else
    record "FAIL" "coolify: UFW rule port 8000" "rule for port 8000 on ${TAILSCALE_IFACE} missing"
  fi

  # Check UFW rule for port 6001 on tailscale0
  if echo "${ufw_out}" | grep -q "6001.*on ${TAILSCALE_IFACE}"; then
    record "PASS" "coolify: UFW rule port 6001 on ${TAILSCALE_IFACE}"
  else
    record "INFO" "coolify: UFW rule port 6001" "rule for port 6001 on ${TAILSCALE_IFACE} missing (Soketi may not be in use)"
  fi

  # Check UFW rule for port 6002 on tailscale0
  if echo "${ufw_out}" | grep -q "6002.*on ${TAILSCALE_IFACE}"; then
    record "PASS" "coolify: UFW rule port 6002 on ${TAILSCALE_IFACE}"
  else
    record "INFO" "coolify: UFW rule port 6002" "rule for port 6002 on ${TAILSCALE_IFACE} missing (terminal may not be in use)"
  fi

  # Check port 8000 is listening (any address — UFW restricts which interfaces can reach it)
  local bound_8000
  bound_8000="$(ss -tlnp 2>/dev/null | grep ':8000 ' || true)"
  if [[ -n "${bound_8000}" ]]; then
    record "PASS" "coolify: port 8000 listening"
  else
    record "INFO" "coolify: port 8000" "not yet listening (Coolify may still be starting)"
  fi

  # Note: nc-based self-connect tests cannot validate public exposure — the kernel
  # routes server→own-public-IP locally, bypassing UFW INPUT rules entirely.
  # Public port exposure is validated via UFW rule inspection in ufw_check() instead.
  # External connectivity tests (Gate E/F in deploy.sh) verify from the operator machine.

  # Verify UFW binding-guard timer is active (periodically re-applies UFW rules if removed)
  if systemctl is-active --quiet coolify-binding-guard.timer 2>/dev/null; then
    record "PASS" "coolify: UFW binding-guard timer active"
  else
    record "FAIL" "coolify: UFW binding-guard timer" "not active — UFW rule drift may go undetected"
  fi
}

# ── unattended-upgrades coverage ──

unattended_upgrades_check() {
  local apt_local="/etc/apt/apt.conf.d/52unattended-upgrades-local"
  local security_origin='origin=Ubuntu,codename=${distro_codename}-security,label=Ubuntu'
  local updates_origin='origin=Ubuntu,codename=${distro_codename}-updates,label=Ubuntu'
  local docker_origin_archive='origin=Docker,label=Docker CE,archive=${distro_codename},component=stable'
  local docker_origin_suite='origin=Docker,label=Docker CE,suite=${distro_codename},component=stable'
  local profile="${UPDATE_PROFILE:-}"

  if [[ ! -f "${apt_local}" ]]; then
    record "FAIL" "auto-updates: local config" "not found at ${apt_local}"
    return
  fi

  if [[ -z "${profile}" ]]; then
    profile="$(infer_update_profile "${apt_local}")"
    record "INFO" "auto-updates: profile" "state missing update_profile; inferred ${profile} from local config"
  fi

  case "${profile}" in
    security-only|balanced) ;;
    *)
      record "FAIL" "auto-updates: profile" "unsupported profile '${profile}'"
      return
      ;;
  esac

  if grep -qF "${security_origin}" "${apt_local}"; then
    record "PASS" "auto-updates: Ubuntu security origin covered"
  else
    record "FAIL" "auto-updates: Ubuntu security origin" "not in origins pattern"
  fi

  if [[ "${profile}" == "balanced" ]]; then
    if grep -qF "${updates_origin}" "${apt_local}"; then
      record "PASS" "auto-updates: Ubuntu updates origin covered"
    else
      record "FAIL" "auto-updates: Ubuntu updates origin" "missing for balanced profile"
    fi

    if grep -qF "${docker_origin_archive}" "${apt_local}" || grep -qF "${docker_origin_suite}" "${apt_local}"; then
      record "PASS" "auto-updates: Docker CE origin pinned to stable"
    elif grep -q "origin=Docker,label=Docker CE" "${apt_local}"; then
      record "FAIL" "auto-updates: Docker CE origin" "present but not pinned to archive/suite + component=stable"
    else
      record "FAIL" "auto-updates: Docker CE origin" "missing for balanced profile"
    fi
  else
    if grep -qF "${updates_origin}" "${apt_local}"; then
      record "FAIL" "auto-updates: Ubuntu updates origin" "present but profile is security-only"
    else
      record "PASS" "auto-updates: Ubuntu updates origin excluded (security-only)"
    fi

    if grep -qF "${docker_origin_archive}" "${apt_local}" \
      || grep -qF "${docker_origin_suite}" "${apt_local}" \
      || grep -q "origin=Docker,label=Docker CE" "${apt_local}"; then
      record "FAIL" "auto-updates: Docker CE origin" "present but profile is security-only"
    else
      record "PASS" "auto-updates: Docker CE origin excluded (security-only)"
    fi
  fi

  if grep -q 'Unattended-Upgrade::Automatic-Reboot' "${apt_local}"; then
    record "PASS" "auto-updates: reboot policy configured"
  else
    record "FAIL" "auto-updates: reboot policy" "not configured"
  fi

  # Functional: verify apt timers are actually running (config alone doesn't prove execution).
  for timer in apt-daily.timer apt-daily-upgrade.timer; do
    if systemctl is-active --quiet "${timer}" 2>/dev/null; then
      record "PASS" "auto-updates: ${timer} active"
    else
      record "FAIL" "auto-updates: ${timer}" "timer not active — unattended-upgrades will not run"
    fi
  done

  # Verify apt timers have Persistent=false to prevent boot-time catch-up blocking package ops.
  # See: https://documentation.ubuntu.com/server/how-to/software/automatic-updates/
  for timer in apt-daily.timer apt-daily-upgrade.timer; do
    local override_file="/etc/systemd/system/${timer}.d/override.conf"
    if [[ -f "${override_file}" ]] && grep -q "Persistent=false" "${override_file}"; then
      record "PASS" "auto-updates: ${timer} Persistent=false"
    else
      record "FAIL" "auto-updates: ${timer} Persistent" \
        "override missing — boot-time catch-up may block package operations"
    fi
  done
}

# ── Listening ports (informational) ──

listening_ports_info() {
  local ports
  ports="$(ss -tlnp 2>/dev/null | tail -n +2 | awk '{print $4}' | sort -u)" || true
  if [[ -n "${ports}" ]]; then
    record "INFO" "listening: TCP ports" "$(echo "${ports}" | tr '\n' ' ')"
  fi
}

# ── Coolify SSH access to localhost ──
# Gate-C safe: all checks are skipped if Coolify is not yet installed.

coolify_ssh_check() {
  local ssh_dir="/data/coolify/ssh/keys"
  local coolify_env="/data/coolify/source/.env"

  # Gate-C safe: if Coolify environment is not present yet, treat this as
  # pre-install state and skip SSH key checks.
  if [[ ! -f "${coolify_env}" ]]; then
    return 0
  fi

  # Skip entirely if Coolify hasn't been installed yet (Gate C runs before install)
  if [[ ! -d "${ssh_dir}" ]]; then
    return 0
  fi

  local keyfile
  keyfile="$(ls "${ssh_dir}"/ssh_key@* "${ssh_dir}"/id.root@* 2>/dev/null | head -1 || true)"
  if [[ -z "${keyfile}" ]]; then
    keyfile="$(find "${ssh_dir}" -maxdepth 1 -type f ! -name '*.pub' 2>/dev/null | head -1 || true)"
  fi
  if [[ -z "${keyfile}" ]]; then
    record "FAIL" "coolify: ssh key exists" "no private key file found in ${ssh_dir}"
    return 0
  fi
  record "PASS" "coolify: ssh key exists"

  # Derive the public key from the private key
  local pubkey
  pubkey=$(ssh-keygen -y -f "${keyfile}" 2>/dev/null || true)
  if [[ -z "${pubkey}" ]]; then
    record "FAIL" "coolify: ssh key readable" "ssh-keygen -y failed on ${keyfile}"
    return 0
  fi

  # Check authorized_keys exists and contains the key on its own line.
  # Match on key data (field 2) only — sshd ignores comment field 3+, and ssh-keygen -y
  # may output a different comment than what was written. A bare substring grep would
  # still match a concatenated line, so we compare against per-line field 2 extractions.
  local auth="/root/.ssh/authorized_keys"
  if [[ ! -f "${auth}" ]]; then
    record "FAIL" "coolify: key in root authorized_keys" "${auth} does not exist"
    return 0
  fi

  local key_data
  key_data=$(awk '{print $2}' <<< "${pubkey}")

  if awk '{print $2}' "${auth}" 2>/dev/null | grep -qxF "${key_data}"; then
    record "PASS" "coolify: key in root authorized_keys"
  else
    # Check for concatenation: key data appears but not as a standalone field
    if grep -qF "${key_data}" "${auth}" 2>/dev/null; then
      record "FAIL" "coolify: key in root authorized_keys" \
        "key present but not on its own line (concatenation bug) — rewrite ${auth}"
    else
      record "FAIL" "coolify: key in root authorized_keys" \
        "Coolify public key not found in ${auth}"
    fi
    return 0
  fi

  # Functional test 1: SSH as root to 127.0.0.1 using Coolify's key (host-side).
  # Tests key + sshd Match block from the host loopback perspective.
  if ssh \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 \
      -o BatchMode=yes \
      -o LogLevel=ERROR \
      -i "${keyfile}" \
      root@127.0.0.1 'exit 0' 2>/dev/null; then
    record "PASS" "coolify: root@127.0.0.1 SSH functional"
  else
    record "FAIL" "coolify: root@127.0.0.1 SSH functional" \
      "key auth failed — check sshd Match block and authorized_keys"
  fi

  # Functional test 2: SSH from INSIDE the coolify container to host.docker.internal.
  # This is the exact path Coolify uses for 'This Machine'. Catches:
  #   - host.docker.internal not resolving (host-gateway bug on Linux Docker)
  #   - UFW blocking port 22 from Docker bridge subnets
  #   - sshd Match block not covering the Docker bridge address range
  if command -v docker >/dev/null 2>&1 && docker inspect coolify >/dev/null 2>&1; then
    local container_keyfile
    container_keyfile="/var/www/html/storage/app/ssh/keys/$(basename "${keyfile}")"
    if docker exec coolify \
        sh -c "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
               -o ConnectTimeout=5 -o BatchMode=yes -o LogLevel=ERROR \
               -i '${container_keyfile}' root@host.docker.internal 'exit 0'" \
        2>/dev/null; then
      record "PASS" "coolify: container→host SSH via host.docker.internal"
    else
      record "FAIL" "coolify: container→host SSH via host.docker.internal" \
        "SSH from coolify container failed — check host.docker.internal in /etc/hosts, UFW Docker-bridge SSH rules, and sshd Match block"
    fi
  else
    record "INFO" "coolify: container→host SSH" "coolify container not running; skipped"
  fi
}

# ── cloudflared ──

cloudflared_check() {
  # Not installed at all — that is fine before Coolify deploy
  if ! systemctl list-unit-files --no-legend cloudflared.service 2>/dev/null | grep -q cloudflared \
      && ! command -v cloudflared >/dev/null 2>&1; then
    record "INFO" "cloudflared: not installed"
    return
  fi

  # Installed — now it must be active
  if systemctl is-active --quiet cloudflared 2>/dev/null; then
    record "PASS" "cloudflared: service active"
  else
    local svc_state
    svc_state="$(systemctl is-active cloudflared 2>/dev/null || echo "unknown")"
    record "FAIL" "cloudflared: service active" "state is ${svc_state}"
    return
  fi

  # cloudflared warns at startup when ping_group_range excludes gid 0.
  # Keep a sane range that includes root to avoid noisy ICMP proxy warnings.
  if command -v sysctl >/dev/null 2>&1; then
    local ping_group_range pg_lo pg_hi
    ping_group_range="$(sysctl -n net.ipv4.ping_group_range 2>/dev/null || true)"
    if [[ "${ping_group_range}" =~ ^[[:space:]]*([0-9]+)[[:space:]]+([0-9]+)[[:space:]]*$ ]]; then
      pg_lo="${BASH_REMATCH[1]}"
      pg_hi="${BASH_REMATCH[2]}"
      if (( pg_hi < pg_lo )); then
        record "FAIL" "cloudflared: ping_group_range" \
          "invalid range (${pg_lo} ${pg_hi}); expected ascending values including gid 0"
      elif (( pg_lo > 0 || pg_hi < 0 )); then
        record "FAIL" "cloudflared: ping_group_range" \
          "gid 0 excluded (${pg_lo} ${pg_hi}); cloudflared logs ICMP proxy warnings"
      else
        record "PASS" "cloudflared: ping_group_range includes gid 0 (${pg_lo} ${pg_hi})"
      fi
    else
      record "INFO" "cloudflared: ping_group_range" \
        "unable to parse net.ipv4.ping_group_range (${ping_group_range:-unknown})"
    fi
  else
    record "INFO" "cloudflared: ping_group_range" "sysctl not found; skipped"
  fi

  # Config file checks
  local config_file="/etc/cloudflared/config.yml"
  if [[ ! -f "${config_file}" ]]; then
    record "FAIL" "cloudflared: config file" "${config_file} not found"
    return
  fi

  local tunnel_id
  tunnel_id="$(grep -m1 '^tunnel:' "${config_file}" | awk '{print $2}' || true)"
  if [[ -n "${tunnel_id}" ]]; then
    record "PASS" "cloudflared: tunnel ID configured"
  else
    record "FAIL" "cloudflared: tunnel ID" "not found in ${config_file}"
  fi

  # Wildcard app domains must route to Traefik (coolify-proxy) on port 80.
  if grep -qE 'localhost:80$|localhost:80[^0-9]|127\.0\.0\.1:80$|127\.0\.0\.1:80[^0-9]' "${config_file}"; then
    record "PASS" "cloudflared: ingress routes apps via Traefik (port 80)"
  else
    record "FAIL" "cloudflared: ingress app routing" \
      "no localhost:80 route — app domains will show dashboard instead of apps"
  fi

  # Private-only profile: dashboard/realtime/terminal must not be tunneled publicly.
  if grep -qE 'localhost:8000|127\.0\.0\.1:8000' "${config_file}"; then
    record "FAIL" "cloudflared: dashboard ingress disabled" \
      "found route to localhost:8000 — dashboard must stay Tailscale-only"
  else
    record "PASS" "cloudflared: dashboard ingress disabled"
  fi

  if grep -qE 'localhost:6001|127\.0\.0\.1:6001' "${config_file}"; then
    record "FAIL" "cloudflared: realtime ingress disabled" \
      "found route to localhost:6001 — realtime must stay on Tailscale"
  else
    record "PASS" "cloudflared: realtime ingress disabled"
  fi

  if grep -qE 'localhost:6002|127\.0\.0\.1:6002' "${config_file}"; then
    record "FAIL" "cloudflared: terminal ingress disabled" \
      "found route to localhost:6002 — terminal must stay on Tailscale"
  else
    record "PASS" "cloudflared: terminal ingress disabled"
  fi

  if grep -q '/terminal/ws' "${config_file}"; then
    record "FAIL" "cloudflared: terminal path disabled" \
      "found '/terminal/ws' ingress rule — terminal must not be publicly tunneled"
  else
    record "PASS" "cloudflared: terminal path disabled"
  fi

  local deny_count
  deny_count="$(grep -Ec 'service:\s*http_status:404' "${config_file}" || true)"
  if [[ "${deny_count}" =~ ^[0-9]+$ ]] && (( deny_count >= 2 )); then
    record "PASS" "cloudflared: deny rules present"
  else
    record "FAIL" "cloudflared: deny rules" \
      "expected at least two http_status:404 ingress rules (explicit host blocks + fallback)"
  fi

  if is_true "${TUNNEL_MODE}"; then
    local dashboard_host ws_host
    dashboard_host="$(awk '
      /^[[:space:]]*-[[:space:]]*hostname:[[:space:]]*/ {
        host=$3
        gsub(/"/, "", host)
        if (host !~ /^\*\./ && host !~ /^ws\./) {
          print host
          exit
        }
      }
    ' "${config_file}" 2>/dev/null || true)"
    ws_host="$(awk '
      /^[[:space:]]*-[[:space:]]*hostname:[[:space:]]*ws\./ {
        host=$3
        gsub(/"/, "", host)
        print host
        exit
      }
    ' "${config_file}" 2>/dev/null || true)"

    if [[ -n "${dashboard_host}" && -z "${ws_host}" ]]; then
      ws_host="ws.${dashboard_host}"
    fi

    local private_route_file
    private_route_file="/data/coolify/proxy/dynamic/coolify-private-dashboard.yaml"
    if [[ -f "${private_route_file}" ]]; then
      record "PASS" "cloudflared: private dashboard route file present"
    else
      record "FAIL" "cloudflared: private dashboard route file" \
        "missing ${private_route_file}; private DOMAIN/ws routing may be broken"
    fi

    if [[ -f "${private_route_file}" && -n "${dashboard_host}" ]]; then
      if grep -Fq "Host(\`${dashboard_host}\`)" "${private_route_file}"; then
        record "PASS" "cloudflared: private dashboard host route (${dashboard_host})"
      else
        record "FAIL" "cloudflared: private dashboard host route" \
          "missing Host(\`${dashboard_host}\`) in ${private_route_file}"
      fi
    fi

    if [[ -f "${private_route_file}" && -n "${ws_host}" ]]; then
      if grep -Fq "Host(\`${ws_host}\`)" "${private_route_file}"; then
        record "PASS" "cloudflared: private websocket host route (${ws_host})"
      else
        record "FAIL" "cloudflared: private websocket host route" \
          "missing Host(\`${ws_host}\`) in ${private_route_file}"
      fi
    fi

    if [[ -f "${private_route_file}" ]]; then
      local private_router_name
      local private_router_fail=0
      for private_router_name in \
        coolify-private-dashboard-http \
        coolify-private-dashboard-https \
        coolify-private-realtime-http \
        coolify-private-realtime-https \
        coolify-private-terminal-http \
        coolify-private-terminal-https; do
        if grep -Fq "${private_router_name}:" "${private_route_file}"; then
          record "PASS" "cloudflared: private router present (${private_router_name})"
        else
          record "FAIL" "cloudflared: private router present (${private_router_name})" \
            "missing router ${private_router_name} in ${private_route_file}"
          private_router_fail=1
        fi
      done
      if [[ "${private_router_fail}" -eq 0 ]]; then
        record "PASS" "cloudflared: private http/https router set complete"
      fi
    fi

    if [[ -n "${dashboard_host}" ]]; then
      local coolify_env_file expected_pusher_host actual_pusher_host actual_pusher_port actual_pusher_scheme
      coolify_env_file="/data/coolify/source/.env"
      expected_pusher_host="ws.${dashboard_host}"
      if [[ -f "${coolify_env_file}" ]]; then
        actual_pusher_host="$(awk -F= '/^PUSHER_HOST=/{print $2; exit}' "${coolify_env_file}" | tr -d '"' || true)"
        actual_pusher_port="$(awk -F= '/^PUSHER_PORT=/{print $2; exit}' "${coolify_env_file}" | tr -d '"' || true)"
        actual_pusher_scheme="$(awk -F= '/^PUSHER_SCHEME=/{print $2; exit}' "${coolify_env_file}" | tr -d '"' || true)"

        if [[ "${actual_pusher_host}" == "${expected_pusher_host}" ]]; then
          record "PASS" "coolify: PUSHER_HOST private ws domain"
        else
          record "FAIL" "coolify: PUSHER_HOST private ws domain" \
            "expected ${expected_pusher_host}, found ${actual_pusher_host:-<unset>}"
        fi

        if [[ "${actual_pusher_port}" == "443" ]]; then
          record "PASS" "coolify: PUSHER_PORT private ws TLS"
        else
          record "FAIL" "coolify: PUSHER_PORT private ws TLS" \
            "expected 443, found ${actual_pusher_port:-<unset>}"
        fi

        if [[ "${actual_pusher_scheme}" == "https" ]]; then
          record "PASS" "coolify: PUSHER_SCHEME private ws TLS"
        else
          record "FAIL" "coolify: PUSHER_SCHEME private ws TLS" \
            "expected https, found ${actual_pusher_scheme:-<unset>}"
        fi
      else
        record "FAIL" "coolify: PUSHER env file present" \
          "missing ${coolify_env_file}"
      fi
    fi

    if command -v getent >/dev/null 2>&1; then
      check_private_dns_host() {
        local host="$1"
        local label="$2"
        local resolved_list ip
        local all_tailscale="true"
        local matched_expected="false"

        if command -v dig >/dev/null 2>&1; then
          # Query authoritative DNS directly to avoid local /etc/hosts or resolver overrides.
          resolved_list="$(dig +short @1.1.1.1 "${host}" A 2>/dev/null \
            | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/' \
            | sort -u | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
        else
          resolved_list="$(getent ahostsv4 "${host}" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
        fi
        if [[ -z "${resolved_list}" ]]; then
          record "FAIL" "cloudflared: ${label} DNS resolution" "no IPv4 answer for ${host}"
          return 0
        fi

        for ip in ${resolved_list}; do
          if ! is_tailscale_ipv4 "${ip}"; then
            all_tailscale="false"
          fi
          if [[ -n "${TAILSCALE_IP}" && "${ip}" == "${TAILSCALE_IP}" ]]; then
            matched_expected="true"
          fi
        done

        if [[ "${all_tailscale}" != "true" ]]; then
          record "FAIL" "cloudflared: ${label} DNS resolution" \
            "${host} resolved to non-Tailscale IPv4(s): ${resolved_list}"
          return 0
        fi

        if [[ -n "${TAILSCALE_IP}" && "${matched_expected}" != "true" ]]; then
          record "FAIL" "cloudflared: ${label} DNS resolution" \
            "${host} resolved to ${resolved_list}; expected to include ${TAILSCALE_IP}"
          return 0
        fi

        record "PASS" "cloudflared: ${label} DNS resolves to Tailscale (${resolved_list})"
      }

      if [[ -n "${dashboard_host}" ]]; then
        check_private_dns_host "${dashboard_host}" "dashboard host"
      else
        record "FAIL" "cloudflared: dashboard host in config" \
          "unable to parse dashboard hostname from ${config_file}"
      fi

      if [[ -n "${ws_host}" ]]; then
        check_private_dns_host "${ws_host}" "websocket host"
      else
        record "FAIL" "cloudflared: websocket host in config" \
          "unable to parse websocket hostname from ${config_file}"
      fi
    else
      record "INFO" "cloudflared: DNS resolution checks" "getent not found; skipped private DNS checks"
    fi
  fi

  # Functional connectivity: probe cloudflared's /ready endpoint.
  # The metrics port is not always 2000; newer cloudflared picks an ephemeral port or
  # uses a management socket. Discover the port dynamically from ss/procfs, then probe it.
  local cf_pid cf_port
  cf_pid="$(pgrep -x cloudflared | head -1 || true)"
  if [[ -n "${cf_pid}" ]]; then
    cf_port="$(ss -tlnp 2>/dev/null \
      | awk -v pid="${cf_pid}" 'index($0,"pid="pid",") && /127\.0\.0\.1:/{print $4}' \
      | awk -F: '{print $NF}' | head -1 || true)"
  fi

  if [[ -n "${cf_port:-}" ]] && curl -sf --max-time 3 "http://127.0.0.1:${cf_port}/ready" >/dev/null 2>&1; then
    local ready_json conn_count
    ready_json="$(curl -sf --max-time 3 "http://127.0.0.1:${cf_port}/ready" 2>/dev/null || true)"
    conn_count="$(printf '%s' "${ready_json}" | python3 -c \
      "import sys,json; print(json.load(sys.stdin).get('readyConnections',0))" 2>/dev/null || echo "?")"
    record "PASS" "cloudflared: tunnel /ready OK (${conn_count} connections)"
  elif [[ -n "${cf_port:-}" ]]; then
    record "FAIL" "cloudflared: tunnel /ready" \
      "port ${cf_port} not responding — tunnel may be disconnected"
  else
    record "INFO" "cloudflared: tunnel /ready" \
      "could not determine cloudflared metrics port — manual check needed"
  fi
}

# ── Coolify container health ──
# Gate-C safe: skips entirely if /data/coolify does not exist.

coolify_container_check() {
  if ! command -v docker >/dev/null 2>&1; then
    record "INFO" "coolify-containers: docker" "Docker not installed; skipped"
    return
  fi

  # Gate-C safe: only enforce Coolify container health after Coolify environment
  # has been created. Partial directories from interrupted installs should not
  # fail pre-phase3 validation.
  if [[ ! -d "/data/coolify" || ! -f "${COOLIFY_ENV_FILE}" ]]; then
    return 0
  fi

  local containers=("coolify" "coolify-db" "coolify-redis" "coolify-proxy")
  for ctr in "${containers[@]}"; do
    local state health
    state="$(docker inspect --format '{{.State.Status}}' "${ctr}" 2>/dev/null || echo "not-found")"
    state="$(printf '%s' "${state}" | tr -d '[:space:]')"
    if [[ "${state}" == "not-found" ]]; then
      # proxy may genuinely be absent if no apps deployed yet — info not fail
      if [[ "${ctr}" == "coolify-proxy" ]]; then
        record "INFO" "coolify-containers: ${ctr}" "not found (normal before first app deploy)"
      else
        record "FAIL" "coolify-containers: ${ctr}" "container not found"
      fi
      continue
    fi

    if [[ "${state}" != "running" ]]; then
      record "FAIL" "coolify-containers: ${ctr} running" "state is ${state}"
      continue
    fi

    # Check healthcheck status if configured (some containers have none)
    health="$(docker inspect \
      --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' \
      "${ctr}" 2>/dev/null || echo "unknown")"
    health="$(printf '%s' "${health}" | tr -d '[:space:]')"

    case "${health}" in
      healthy|no-healthcheck)
        record "PASS" "coolify-containers: ${ctr} running (${health})" ;;
      starting)
        record "INFO" "coolify-containers: ${ctr}" "healthcheck still starting — re-run in a minute" ;;
      *)
        record "FAIL" "coolify-containers: ${ctr} health" "${health}" ;;
    esac
  done
}

# ── Hardening validation timer ──

validate_timer_check() {
  if systemctl is-active --quiet hardening-validate.timer 2>/dev/null; then
    record "PASS" "validate-timer: active"
  elif systemctl list-unit-files --no-legend hardening-validate.timer 2>/dev/null | grep -q hardening-validate; then
    record "FAIL" "validate-timer: active" "timer installed but not active"
  else
    record "INFO" "validate-timer: not installed" "run bootstrap to install"
  fi
}

# ── Run all checks ──

main() {
  parse_cli_args "$@"
  detect_container_runtime
  load_state_context

  [[ "$(id -u)" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }

  if [[ "${JSON_MODE}" == "false" && "${HEALTH_CHECK_MODE}" != "true" ]]; then
    printf '%-6s %-45s %s\n' "STATUS" "CHECK" "DETAIL"
    printf '%s\n' "--------------------------------------------------------------"
  fi

  ssh_check
  ufw_check
  docker_user_check
  docker_user_lifecycle_check
  docker_ssh_cidr_sync_check
  docker_daemon_check
  docker_trust_boundary_check
  sysctl_check
  fail2ban_check
  auditd_check
  unattended_upgrades_check
  journald_check
  rsyslog_check
  timesync_check
  timezone_check
  swap_check
  banner_check
  admin_sudo_check
  apparmor_check
  disabled_services_check
  tailscale_check
  coolify_binding_check
  if [[ "${GATE_C_MODE}" == "true" ]]; then
    record "INFO" "gate-c: coolify runtime checks" "skipped in --gate-c mode"
  else
    coolify_ssh_check
    coolify_container_check
  fi
  validate_timer_check
  listening_ports_info
  cloudflared_check

  if [[ "${HEALTH_CHECK_MODE}" == "true" ]]; then
    if ((FAIL_COUNT > 0)); then
      echo "UNHEALTHY"
      exit 1
    fi
    echo "HEALTHY"
    exit 0
  elif [[ "${JSON_MODE}" == "true" ]]; then
    checks_json='[]'
    if ((${#RESULTS[@]} > 0)); then
      checks_json="$(printf '%s\n' "${RESULTS[@]}" | jq -s '.')"
    fi
    jq -nc \
      --argjson pass "${PASS_COUNT}" \
      --argjson fail "${FAIL_COUNT}" \
      --argjson info "${INFO_COUNT}" \
      --argjson checks "${checks_json}" \
      '{pass:$pass,fail:$fail,info:$info,checks:$checks}'
  else
    printf '%s\n' "--------------------------------------------------------------"
    printf 'Summary: %d PASS, %d FAIL, %d INFO\n' "${PASS_COUNT}" "${FAIL_COUNT}" "${INFO_COUNT}"
  fi

  if ((FAIL_COUNT > 0)); then
    exit 1
  fi
  exit 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi

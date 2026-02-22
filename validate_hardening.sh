#!/usr/bin/env bash
set -Eeuo pipefail

# validate_hardening.sh — Standalone health-check companion for bootstrap_hardening.sh
# Re-runnable: prints PASS/FAIL per check, exits 0 if all pass, 1 if any fail.
# Usage: sudo ./validate_hardening.sh [--json]

STATE_FILE="/var/lib/bootstrap-hardening/state"
JOURNALD_DROPIN="/etc/systemd/journald.conf.d/60-persistent.conf"
JSON_MODE="false"
IS_CONTAINER="false"

if [[ "${1:-}" == "--json" ]]; then
  JSON_MODE="true"
fi

if [[ -f /.dockerenv || "${container:-}" == "docker" ]]; then
  IS_CONTAINER="true"
fi

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
    RESULTS+=("{\"check\":\"${name}\",\"status\":\"${status}\",\"detail\":\"${detail}\"}")
  else
    printf '%-6s %-45s %s\n' "[${status}]" "${name}" "${detail}"
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

# Load state file for context (non-fatal if missing)
ADMIN_USER=""
SSH_PORT="22"
TUNNEL_MODE="false"
WAN_IFACE=""
TAILSCALE_IFACE="tailscale0"
BIND_DASHBOARD_TO_TAILSCALE="false"
TAILSCALE_IP=""
COOLIFY_ENV_FILE="/data/coolify/source/.env"

if [[ -f "${STATE_FILE}" ]]; then
  # shellcheck disable=SC1090
  source "${STATE_FILE}"
  ADMIN_USER="${admin_user:-}"
  SSH_PORT="${ssh_port:-22}"
  TUNNEL_MODE="${tunnel_mode:-false}"
  WAN_IFACE="${wan_iface:-}"
  swap_size="${swap_size:-2G}"
  BIND_DASHBOARD_TO_TAILSCALE="${bind_dashboard_to_tailscale:-false}"
  TAILSCALE_IP="${tailscale_ip:-}"
fi

is_true() {
  case "${1,,}" in
    1|true|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
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

  if [[ -n "${ADMIN_USER}" ]]; then
    if grep -qE "^allowusers .*\\b${ADMIN_USER}\\b" <<< "${effective}"; then
      record "PASS" "ssh: AllowUsers includes ${ADMIN_USER}"
    else
      record "FAIL" "ssh: AllowUsers" "${ADMIN_USER} not listed"
    fi
  fi

  # Verify Match Address block: root key-only login from localhost/Docker bridge
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

  if grep -q "^Status: active$" <<< "${ufw_out}"; then
    record "PASS" "ufw: active"
  else
    record "FAIL" "ufw: active" "UFW is not active"
    return
  fi

  if grep -qE "${SSH_PORT}/tcp.*on ${TAILSCALE_IFACE}.*ALLOW IN" <<< "${ufw_out}"; then
    record "PASS" "ufw: SSH on ${TAILSCALE_IFACE}"
  else
    record "FAIL" "ufw: SSH on ${TAILSCALE_IFACE}" "rule missing"
  fi

  if [[ -n "${WAN_IFACE}" ]]; then
    if grep -qE "${SSH_PORT}/tcp.*on ${WAN_IFACE}.*ALLOW IN" <<< "${ufw_out}"; then
      record "FAIL" "ufw: SSH NOT on WAN" "SSH allowed on ${WAN_IFACE}"
    else
      record "PASS" "ufw: SSH NOT on WAN"
    fi

    if is_true "${TUNNEL_MODE}"; then
      if grep -qE "80/tcp.*on ${WAN_IFACE}.*ALLOW IN" <<< "${ufw_out}"; then
        record "FAIL" "ufw: tunnel-mode no port 80" "WAN 80 rule exists"
      else
        record "PASS" "ufw: tunnel-mode no port 80"
      fi
      if grep -qE "443/tcp.*on ${WAN_IFACE}.*ALLOW IN" <<< "${ufw_out}"; then
        record "FAIL" "ufw: tunnel-mode no port 443" "WAN 443 rule exists"
      else
        record "PASS" "ufw: tunnel-mode no port 443"
      fi
    fi
  fi
}

# ── DOCKER-USER iptables (IPv4 + IPv6) ──

docker_user_check() {
  if ! command -v iptables >/dev/null 2>&1; then
    record "FAIL" "docker-user: iptables" "iptables not found"
    return
  fi

  local rules
  rules="$(iptables -t filter -S DOCKER-USER 2>/dev/null)" || { record "INFO" "docker-user: IPv4" "DOCKER-USER chain absent"; return; }

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
    [kernel.unprivileged_bpf_disabled]="1"
    [kernel.kexec_load_disabled]="1"
    [kernel.sysrq]="4"
    [kernel.randomize_va_space]="2"
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
}

# ── journald ──

journald_check() {
  if [[ -f "${JOURNALD_DROPIN}" ]] && grep -q "^Storage=persistent$" "${JOURNALD_DROPIN}"; then
    record "PASS" "journald: persistent storage"
  else
    record "FAIL" "journald: persistent storage" "drop-in missing or not persistent"
  fi

  local usage
  usage="$(journalctl --disk-usage 2>/dev/null | head -1)" || true
  if [[ -n "${usage}" ]]; then
    record "INFO" "journald: disk usage" "${usage}"
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
}

# ── Swap ──

swap_check() {
  local swap_size="${swap_size:-2G}"
  if [[ "${swap_size}" == "0" ]]; then
    record "INFO" "swap: disabled" "swap creation was skipped (--swap-size 0)"
    return
  fi

  if swapon --show --noheadings 2>/dev/null | grep -q .; then
    local swap_total
    swap_total="$(swapon --show --noheadings --bytes 2>/dev/null | awk '{sum+=$3} END {printf "%.0fM", sum/1048576}')"
    record "PASS" "swap: active (${swap_total})"
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
  fstab_count="$(grep -cxF '/swapfile none swap sw 0 0' /etc/fstab 2>/dev/null || true)"
  fstab_count="${fstab_count:-0}"
  if [[ "${fstab_count}" == "1" ]]; then
    record "PASS" "swap: single fstab entry"
  elif [[ "${fstab_count}" == "0" && "${IS_CONTAINER}" == "true" ]]; then
    record "INFO" "swap: fstab" "not applicable in container"
  elif (( fstab_count > 1 )); then
    record "FAIL" "swap: fstab" "duplicate entries (${fstab_count})"
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

# ── Docker daemon.json ──

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

  if grep -q '"log-driver"' "${daemon_json}"; then
    record "PASS" "docker-daemon: log-driver configured"
  else
    record "FAIL" "docker-daemon: log-driver" "not set in daemon.json"
  fi

  if grep -q '"live-restore"' "${daemon_json}"; then
    record "PASS" "docker-daemon: live-restore configured"
  else
    record "FAIL" "docker-daemon: live-restore" "not set in daemon.json"
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
  fi
}

# ── Coolify split-horizon binding ──

coolify_binding_check() {
  # Skip if binding was not configured
  if ! is_true "${BIND_DASHBOARD_TO_TAILSCALE}"; then
    record "INFO" "coolify: split-horizon" "not configured (use --bind-dashboard-to-tailscale)"
    return 0
  fi

  # Check if Coolify is installed
  if [[ ! -f "${COOLIFY_ENV_FILE}" ]]; then
    record "FAIL" "coolify: .env file" "not found at ${COOLIFY_ENV_FILE}"
    return 0
  fi

  # Check if Tailscale IP was detected
  if [[ -z "${TAILSCALE_IP}" ]]; then
    # Try to detect it now
    if command -v tailscale >/dev/null 2>&1; then
      TAILSCALE_IP="$(tailscale ip -4 2>/dev/null)" || true
    fi
    if [[ -z "${TAILSCALE_IP}" ]]; then
      record "FAIL" "coolify: Tailscale IP" "not detected"
      return 0
    fi
  fi

  # Check APP_PORT in .env
  local app_port
  app_port="$(grep "^APP_PORT=" "${COOLIFY_ENV_FILE}" 2>/dev/null | cut -d= -f2)" || true
  if [[ "${app_port}" == "${TAILSCALE_IP}:8000" ]]; then
    record "PASS" "coolify: APP_PORT bound to Tailscale"
  elif [[ -n "${app_port}" ]]; then
    record "FAIL" "coolify: APP_PORT" "expected ${TAILSCALE_IP}:8000, got ${app_port}"
  else
    record "FAIL" "coolify: APP_PORT" "not set in .env"
  fi

  # Check SOKETI_PORT in .env
  local soketi_port
  soketi_port="$(grep "^SOKETI_PORT=" "${COOLIFY_ENV_FILE}" 2>/dev/null | cut -d= -f2)" || true
  if [[ "${soketi_port}" == "${TAILSCALE_IP}:6001" ]]; then
    record "PASS" "coolify: SOKETI_PORT bound to Tailscale"
  elif [[ -n "${soketi_port}" ]]; then
    record "FAIL" "coolify: SOKETI_PORT" "expected ${TAILSCALE_IP}:6001, got ${soketi_port}"
  else
    record "FAIL" "coolify: SOKETI_PORT" "not set in .env"
  fi

  # Check actual listening ports
  local bound_8000 bound_6001
  bound_8000="$(ss -tlnp 2>/dev/null | grep ':8000 ' || true)"
  bound_6001="$(ss -tlnp 2>/dev/null | grep ':6001 ' || true)"

  if echo "${bound_8000}" | grep -q "${TAILSCALE_IP}:8000"; then
    record "PASS" "coolify: port 8000 listening on Tailscale IP"
  else
    record "FAIL" "coolify: port 8000" "not bound to ${TAILSCALE_IP}:8000"
  fi

  if echo "${bound_6001}" | grep -q "${TAILSCALE_IP}:6001"; then
    record "PASS" "coolify: port 6001 listening on Tailscale IP"
  else
    record "INFO" "coolify: port 6001" "not bound to ${TAILSCALE_IP}:6001 (may not be in use)"
  fi

  # Verify public IP is NOT serving the dashboard
  if command -v nc >/dev/null 2>&1; then
    local public_ip
    public_ip="$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')"
    if [[ -n "${public_ip}" && "${public_ip}" != "${TAILSCALE_IP}" ]]; then
      if nc -z -w2 "${public_ip}" 8000 2>/dev/null; then
        record "FAIL" "coolify: public exposure" "port 8000 reachable on public IP ${public_ip}"
      else
        record "PASS" "coolify: not exposed on public IP"
      fi
    fi
  fi
}

# ── Listening ports (informational) ──

listening_ports_info() {
  local ports
  ports="$(ss -tlnp 2>/dev/null | tail -n +2 | awk '{print $4}' | sort -u)" || true
  if [[ -n "${ports}" ]]; then
    record "INFO" "listening: TCP ports" "$(echo "${ports}" | tr '\n' ' ')"
  fi
}

# ── cloudflared (informational) ──

cloudflared_check() {
  if systemctl is-active --quiet cloudflared 2>/dev/null; then
    record "INFO" "cloudflared: active"
  elif systemctl list-unit-files --no-legend cloudflared.service 2>/dev/null | grep -q cloudflared; then
    record "INFO" "cloudflared: installed but not active"
  else
    record "INFO" "cloudflared: not installed"
  fi
}

# ── Run all checks ──

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }

if [[ "${JSON_MODE}" == "false" ]]; then
  printf '%-6s %-45s %s\n' "STATUS" "CHECK" "DETAIL"
  printf '%s\n' "--------------------------------------------------------------"
fi

ssh_check
ufw_check
docker_user_check
docker_daemon_check
sysctl_check
fail2ban_check
auditd_check
journald_check
timesync_check
swap_check
banner_check
apparmor_check
disabled_services_check
tailscale_check
coolify_binding_check
listening_ports_info
cloudflared_check

# ── Summary ──

if [[ "${JSON_MODE}" == "true" ]]; then
  printf '{"pass":%d,"fail":%d,"info":%d,"checks":[' "${PASS_COUNT}" "${FAIL_COUNT}" "${INFO_COUNT}"
  first="true"
  for r in "${RESULTS[@]}"; do
    if [[ "${first}" == "true" ]]; then
      first="false"
    else
      printf ','
    fi
    printf '%s' "${r}"
  done
  printf ']}\n'
else
  printf '%s\n' "--------------------------------------------------------------"
  printf 'Summary: %d PASS, %d FAIL, %d INFO\n' "${PASS_COUNT}" "${FAIL_COUNT}" "${INFO_COUNT}"
fi

if ((FAIL_COUNT > 0)); then
  exit 1
fi
exit 0

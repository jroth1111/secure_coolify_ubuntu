bool_cmd() {
  if "$@" >/dev/null 2>&1; then
    echo "true"
  else
    echo "false"
  fi
}

is_container_runtime() {
  if [[ -f /.dockerenv || "${container:-}" == "docker" ]]; then
    return 0
  fi
  if command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt -cq; then
    return 0
  fi
  return 1
}

assert_rsyslog_posture() {
  local log_dir_owner log_dir_group log_dir_mode log_dir_group_digit
  local target q_target target_owner target_group target_mode
  local expected_dir_group="syslog"
  local expected_target_owner="syslog"
  local expected_target_group="adm"
  local require_dir_group_write="true"

  if ! getent group syslog >/dev/null 2>&1; then
    expected_dir_group="root"
    require_dir_group_write="false"
  fi
  if ! getent passwd syslog >/dev/null 2>&1; then
    expected_target_owner="root"
  fi
  if ! getent group "${expected_target_group}" >/dev/null 2>&1; then
    if getent group syslog >/dev/null 2>&1; then
      expected_target_group="syslog"
    else
      expected_target_group="root"
    fi
  fi

  log_dir_owner="$(stat -c '%U' /var/log 2>/dev/null || true)"
  log_dir_group="$(stat -c '%G' /var/log 2>/dev/null || true)"
  log_dir_mode="$(stat -c '%a' /var/log 2>/dev/null || true)"
  [[ "${log_dir_owner}" == "root" ]] || die "Post-check failed: /var/log owner is ${log_dir_owner:-unknown}, expected root."
  [[ "${log_dir_group}" == "${expected_dir_group}" ]] || die "Post-check failed: /var/log group is ${log_dir_group:-unknown}, expected ${expected_dir_group}."
  [[ "${log_dir_mode}" =~ ^[0-7]{3,4}$ ]] || die "Post-check failed: /var/log mode unreadable (${log_dir_mode:-unknown})."
  if is_true "${require_dir_group_write}"; then
    log_dir_group_digit="${log_dir_mode: -2:1}"
    if (( (10#${log_dir_group_digit} & 2) == 0 )); then
      die "Post-check failed: /var/log mode ${log_dir_mode} lacks group write; rsyslog cannot create missing log targets."
    fi
  fi

  while IFS= read -r target; do
    [[ -n "${target}" ]] || continue
    [[ -f "${target}" ]] || die "Post-check failed: rsyslog target ${target} is missing."
    target_owner="$(stat -c '%U' "${target}" 2>/dev/null || true)"
    target_group="$(stat -c '%G' "${target}" 2>/dev/null || true)"
    target_mode="$(stat -c '%a' "${target}" 2>/dev/null || true)"
    [[ "${target_owner}" == "${expected_target_owner}" ]] || die "Post-check failed: ${target} owner is ${target_owner:-unknown}, expected ${expected_target_owner}."
    [[ "${target_group}" == "${expected_target_group}" ]] || die "Post-check failed: ${target} group is ${target_group:-unknown}, expected ${expected_target_group}."
    [[ "${target_mode}" == "640" ]] || die "Post-check failed: ${target} mode is ${target_mode:-unknown}, expected 640."
    printf -v q_target '%q' "${target}"
    if getent passwd syslog >/dev/null 2>&1; then
      su -s /bin/sh -c "test -w ${q_target}" syslog \
        || die "Post-check failed: rsyslog user cannot write ${target}."
    fi
  done < <(rsyslog_collect_log_targets)

  if [[ -f /etc/logrotate.d/ufw ]]; then
    grep -Eq "^[[:space:]]*create[[:space:]]+640[[:space:]]+${expected_target_owner}[[:space:]]+${expected_target_group}([[:space:]]|$)" /etc/logrotate.d/ufw \
      || die "Post-check failed: /etc/logrotate.d/ufw missing create 640 ${expected_target_owner} ${expected_target_group} directive."
  else
    warn "Post-check: /etc/logrotate.d/ufw not found; skipping create directive assertion."
  fi
  if [[ -f /etc/logrotate.d/rsyslog ]]; then
    grep -Eq "^[[:space:]]*create[[:space:]]+640[[:space:]]+${expected_target_owner}[[:space:]]+${expected_target_group}([[:space:]]|$)" /etc/logrotate.d/rsyslog \
      || die "Post-check failed: /etc/logrotate.d/rsyslog missing create 640 ${expected_target_owner} ${expected_target_group} directive."
  else
    warn "Post-check: /etc/logrotate.d/rsyslog not found; skipping create directive assertion."
  fi
}

run_post_checks() {
  if is_true "${DRY_RUN}"; then
    log "Dry-run complete; post-apply checks skipped."
    return 0
  fi

  local ssh_effective
  ssh_effective="$(sshd -T 2>/dev/null || true)"
  assert_sshd_effective "${ssh_effective}" || die "Post-check failed: sshd effective settings do not match expected hardening."

  local ssh_match_local
  ssh_match_local="$(sshd -T -C addr=127.0.0.1,user=root,host=localhost,laddr=127.0.0.1 2>/dev/null || true)"
  assert_sshd_match_localhost "${ssh_match_local}" || die "Post-check failed: SSH Match block for localhost/Docker root access not effective."

  local ssh_match_external
  ssh_match_external="$(sshd -T -C addr=203.0.113.1,user=root,host=example.com,laddr=0.0.0.0 2>/dev/null || true)"
  if grep -qE "^permitrootlogin (prohibit-password|without-password|yes)$" <<< "${ssh_match_external}"; then
    die "Post-check failed: root login permitted from external address (Match block leak)."
  fi

  ufw status | grep -q "^Status: active$" || die "Post-check failed: UFW is not active."
  ufw status verbose | grep -qE "${SSH_PORT}/tcp.*on ${TAILSCALE_IFACE}.*ALLOW IN" || die "Post-check failed: SSH allow rule on ${TAILSCALE_IFACE} missing."
  if ufw status verbose | grep -qE "${SSH_PORT}/tcp.*on ${WAN_IFACE}.*ALLOW IN"; then
    die "Post-check failed: SSH appears allowed on WAN interface ${WAN_IFACE}."
  fi

  if is_true "${TUNNEL_MODE}"; then
    if ufw status verbose | grep -qE "80/tcp.*on ${WAN_IFACE}.*ALLOW IN"; then
      die "Post-check failed: tunnel-mode is active but WAN port 80 UFW rule exists."
    fi
    if ufw status verbose | grep -qE "443/tcp.*on ${WAN_IFACE}.*ALLOW IN"; then
      die "Post-check failed: tunnel-mode is active but WAN port 443 UFW rule exists."
    fi
  fi

  if is_true "${TAILSCALE_DIRECT_WAN}"; then
    if ! ufw status verbose | grep -qE "41641/udp.*on ${WAN_IFACE}.*ALLOW IN"; then
      die "Post-check failed: TAILSCALE_DIRECT_WAN=true but WAN UDP 41641 UFW rule is missing."
    fi
  else
    if ufw status verbose | grep -qE "41641/udp.*on ${WAN_IFACE}.*ALLOW IN"; then
      die "Post-check failed: TAILSCALE_DIRECT_WAN=false but WAN UDP 41641 UFW rule exists."
    fi
  fi

  if [[ "${DOCKER_PRESENT}" == "true" ]]; then
    local docker_service_present="false"
    if unit_available "docker.service"; then
      docker_service_present="true"
    fi

    if [[ "${DOCKER_RULES_APPLIED}" == "true" ]]; then
      iptables -t filter -S DOCKER-USER | grep -q "coolify-hardening-wan-drop" || die "Post-check failed: DOCKER-USER IPv4 drop rule missing."
      iptables -t filter -S DOCKER-USER | grep -q "coolify-hardening-bridge-docker0" || die "Post-check failed: DOCKER-USER bridge-docker0 rule missing."
      if is_true "${TUNNEL_MODE}"; then
        if iptables -t filter -S DOCKER-USER | grep -q "coolify-hardening-wan-web"; then
          die "Post-check failed: tunnel-mode is active but DOCKER-USER wan-web ACCEPT rule exists."
        fi
      fi
      if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -t filter -S DOCKER-USER 2>/dev/null | grep -q "coolify-hardening-wan-drop6" || die "Post-check failed: DOCKER-USER IPv6 drop rule missing."
      fi
    elif [[ "${docker_service_present}" == "true" ]]; then
      die "Post-check failed: docker.service exists but DOCKER-USER rules were not applied."
    else
      warn "Post-check: Docker CLI is present but docker.service is unavailable; skipping DOCKER-USER chain assertions."
    fi

    if [[ -S /var/run/docker.sock ]]; then
      local docker_sock_mode docker_sock_other docker_sock_owner_group
      docker_sock_mode="$(stat -c '%a' /var/run/docker.sock 2>/dev/null || true)"
      docker_sock_owner_group="$(stat -c '%U:%G' /var/run/docker.sock 2>/dev/null || true)"

      if [[ -n "${docker_sock_mode}" ]]; then
        docker_sock_other="${docker_sock_mode: -1}"
        if [[ "${docker_sock_other}" =~ ^[0-7]$ ]] && (( (10#${docker_sock_other} & 2) != 0 )); then
          die "Post-check failed: /var/run/docker.sock is world-writable (mode ${docker_sock_mode})."
        fi
      fi

      if [[ -n "${docker_sock_owner_group}" && ! "${docker_sock_owner_group}" =~ ^root: ]]; then
        warn "Post-check: /var/run/docker.sock owner/group is ${docker_sock_owner_group}; expected root:*."
      fi
    else
      warn "Post-check: /var/run/docker.sock missing; cannot validate Docker socket permissions."
    fi

    if getent group docker >/dev/null 2>&1; then
      local docker_group_members
      docker_group_members="$(getent group docker | awk -F: '{print $4}')"
      if [[ -n "${docker_group_members}" ]]; then
        warn "Post-check: docker group has named members (${docker_group_members}); Docker access is root-equivalent."
      fi
      if id -nG "${ADMIN_USER}" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
        warn "Post-check: admin user ${ADMIN_USER} is in docker group (root-equivalent Docker access)."
      fi
    fi
  fi

  if [[ "${DOCKER_PRESENT}" == "true" && -f "${DOCKER_DAEMON_JSON}" ]]; then
    grep -q '"log-driver"' "${DOCKER_DAEMON_JSON}" || warn "Post-check: Docker daemon.json exists but log-driver not configured."
    grep -q '"live-restore"' "${DOCKER_DAEMON_JSON}" || warn "Post-check: Docker daemon.json exists but live-restore not configured."
    grep -q '"default-ipc-mode"' "${DOCKER_DAEMON_JSON}" || warn "Post-check: Docker daemon.json exists but default-ipc-mode not configured."
    grep -q '"storage-driver"' "${DOCKER_DAEMON_JSON}" || warn "Post-check: Docker daemon.json exists but storage-driver not configured."
    grep -q '"default-ulimits"' "${DOCKER_DAEMON_JSON}" || warn "Post-check: Docker daemon.json exists but default-ulimits not configured."
  fi

  if is_true "${STRICT_DOCKER_SSH_CIDRS}"; then
    if ! systemctl is-active --quiet docker-ssh-cidr-sync.timer 2>/dev/null; then
      warn "Post-check: docker-ssh-cidr-sync.timer is not active; Docker CIDR drift auto-reconcile is disabled."
    fi
  fi

  grep -q "^Storage=persistent$" "${JOURNALD_DROPIN_FILE}" || die "Post-check failed: journald persistence drop-in missing."

  local audit_rules_blob=""
  local audit_rules_source="live"
  if command -v auditctl >/dev/null 2>&1; then
    audit_rules_blob="$(auditctl -l 2>/dev/null || true)"
  fi
  if [[ -z "${audit_rules_blob}" ]]; then
    audit_rules_blob="$(cat "${AUDIT_RULES_FILE}" 2>/dev/null || true)"
    audit_rules_source="file"
  fi

  if ! systemctl is-active --quiet auditd 2>/dev/null; then
    if is_container_runtime; then
      warn "Post-check: auditd inactive in container; validating persisted audit rules file."
    else
      die "Post-check failed: auditd is not active."
    fi
  elif [[ "${audit_rules_source}" != "live" ]]; then
    die "Post-check failed: could not read live audit rules from auditctl."
  fi

  grep -q "identity" <<< "${audit_rules_blob}" \
    || die "Post-check failed: audit identity rules missing."
  grep -q "sudoers-change" <<< "${audit_rules_blob}" \
    || die "Post-check failed: sudoers audit rules missing."
  grep -q "user_commands" <<< "${audit_rules_blob}" \
    || die "Post-check failed: execve user_commands audit rules missing."
  grep -q 'APT::Periodic::Unattended-Upgrade "1";' "${APT_AUTO_FILE}" || die "Post-check failed: unattended-upgrades periodic config missing."

  local syncookies ip_forward
  syncookies="$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "?")"
  ip_forward="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "?")"
  [[ "${syncookies}" == "1" ]] || die "Post-check failed: tcp_syncookies is ${syncookies}, expected 1."
  [[ "${ip_forward}" == "1" ]] || die "Post-check failed: ip_forward is ${ip_forward}, expected 1."

  local current_timezone
  current_timezone="$(timedatectl show --property=Timezone --value 2>/dev/null || true)"
  [[ "${current_timezone}" == "${TIMEZONE}" ]] \
    || die "Post-check failed: timezone is ${current_timezone:-unknown}, expected ${TIMEZONE}."

  if command -v tailscale >/dev/null 2>&1; then
    if tailscale status --json >/dev/null 2>&1; then
      local run_ssh_pref
      run_ssh_pref="$(tailscale_runssh_pref_value 5 1)"
      [[ "${run_ssh_pref}" == "false" ]] \
        || die "Post-check failed: tailscale RunSSH is ${run_ssh_pref:-unknown}, expected false."
    elif is_true "${INSTALL_TAILSCALE}"; then
      die "Post-check failed: tailscale CLI is present but status is unavailable after INSTALL_TAILSCALE=true."
    else
      warn "Post-check: tailscale CLI present but status unavailable; skipping RunSSH verification because INSTALL_TAILSCALE=false."
    fi
  elif is_true "${INSTALL_TAILSCALE}"; then
    die "Post-check failed: tailscale CLI not found after INSTALL_TAILSCALE=true."
  else
    warn "Post-check: tailscale CLI not found; skipping RunSSH verification because INSTALL_TAILSCALE=false."
  fi

  if [[ -f "${APPORT_DEFAULT_FILE}" ]]; then
    local apport_enabled
    apport_enabled="$(awk -F= '/^[[:space:]]*enabled[[:space:]]*=/{gsub(/[[:space:]]/, "", $2); print $2; exit}' "${APPORT_DEFAULT_FILE}" || true)"
    [[ "${apport_enabled}" == "0" ]] \
      || die "Post-check failed: apport enabled=${apport_enabled:-unknown}, expected 0."
  fi
  if unit_available "apport.service" && systemctl is-active --quiet apport.service 2>/dev/null; then
    die "Post-check failed: apport.service is active."
  fi

  systemctl is-active --quiet fail2ban || die "Post-check failed: fail2ban is not active."
  if unit_available "rsyslog.service"; then
    systemctl is-active --quiet rsyslog || die "Post-check failed: rsyslog is not active."
  else
    warn "Post-check: rsyslog.service not installed; skipping active-state verification."
  fi
  assert_rsyslog_posture

  [[ -f /etc/issue.net ]] || die "Post-check failed: /etc/issue.net missing."

  journalctl --disk-usage || true

  if command -v aa-status >/dev/null 2>&1; then
    if ! aa-status --enabled 2>/dev/null; then
      warn "AppArmor is installed but not enabled. Ubuntu 24.04 should have it active by default."
    fi
  else
    warn "aa-status not found; cannot verify AppArmor status."
  fi

  # Dashboard UFW restriction verification (UFW-based; does not check socket binding)
  if is_true "${BIND_DASHBOARD_TO_TAILSCALE}"; then
    log "Verifying Coolify dashboard UFW rules on ${TAILSCALE_IFACE}..."
    if command -v ufw >/dev/null 2>&1; then
      if ufw status | grep -q "8000.*on ${TAILSCALE_IFACE}"; then
        log "PASS: UFW rule for port 8000 on ${TAILSCALE_IFACE} is present"
      else
        warn "UFW rule for port 8000 on ${TAILSCALE_IFACE} not found. Check: ufw status"
      fi
      if ufw status | grep -q "6001.*on ${TAILSCALE_IFACE}"; then
        log "PASS: UFW rule for port 6001 on ${TAILSCALE_IFACE} is present"
      else
        warn "UFW rule for port 6001 on ${TAILSCALE_IFACE} not found. Check: ufw status"
      fi
      if ufw status | grep -q "6002.*on ${TAILSCALE_IFACE}"; then
        log "PASS: UFW rule for port 6002 on ${TAILSCALE_IFACE} is present"
      else
        warn "UFW rule for port 6002 on ${TAILSCALE_IFACE} not found. Check: ufw status"
      fi
    fi

    log "External dashboard exposure is validated from off-host; skipping host-local public-IP probe."
  fi
}

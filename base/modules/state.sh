warn_on_state_version_mismatch() {
  [[ -f "${STATE_FILE}" ]] || return 0

  local existing_version
  existing_version="$(grep -m1 '^script_version=' "${STATE_FILE}" | cut -d= -f2- || true)"
  if [[ -n "${existing_version}" && "${existing_version}" != "${SCRIPT_VERSION}" ]]; then
    warn "Existing hardening state found (v${existing_version}), re-running v${SCRIPT_VERSION}."
  fi
}

write_state() {
  local cidr_csv=""
  local tmp_state=""
  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: write ${STATE_FILE}"
    return 0
  fi

  cidr_csv="$(IFS=,; echo "${DOCKER_SSH_CIDRS[*]}")"

  install -d -m 0750 "${STATE_DIR}"
  tmp_state="$(mktemp)"
  cat > "${tmp_state}" <<EOF
script_version=${SCRIPT_VERSION}
applied_at=$(date -Iseconds)
admin_user=${ADMIN_USER}
domain=${DOMAIN}
wan_iface=${WAN_IFACE}
ssh_port=${SSH_PORT}
tailscale_cidr=${TAILSCALE_CIDR}
tunnel_mode=${TUNNEL_MODE}
swap_size=${SWAP_SIZE}
journal_retention=${JOURNAL_RETENTION}
update_profile=${UPDATE_PROFILE}
timezone=${TIMEZONE}
docker_present=${DOCKER_PRESENT}
docker_rules_applied=${DOCKER_RULES_APPLIED}
strict_docker_ssh_cidrs=${STRICT_DOCKER_SSH_CIDRS}
docker_ssh_cidrs=${cidr_csv}
docker_nproc_hard=${DOCKER_NPROC_HARD}
docker_nproc_soft=${DOCKER_NPROC_SOFT}
allowed_privileged_containers=${ALLOWED_PRIVILEGED_CONTAINERS}
tailscale_direct_wan=${TAILSCALE_DIRECT_WAN}
bind_dashboard_to_tailscale=${BIND_DASHBOARD_TO_TAILSCALE}
install_tailscale=${INSTALL_TAILSCALE}
EOF

  if is_true "${BIND_DASHBOARD_TO_TAILSCALE}" && [[ -n "${DETECTED_TAILSCALE_IP}" ]]; then
    echo "tailscale_ip=${DETECTED_TAILSCALE_IP}" >> "${tmp_state}"
  fi

  if command -v flock >/dev/null 2>&1; then
    exec 9>"${STATE_LOCK_FILE}"
    flock 9
  fi

  install -m 0640 "${tmp_state}" "${STATE_FILE}"
  rm -f "${tmp_state}"

  if command -v flock >/dev/null 2>&1; then
    flock -u 9 || true
    exec 9>&-
  fi
}

generate_report() {
  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: write ${REPORT_FILE}"
    return 0
  fi

  local tailscale_iface_present
  local ufw_active
  local ssh_root_disabled
  local ssh_password_disabled
  local journald_persistent
  local auditd_enabled
  local audit_rules_loaded
  local docker_drop_rule
  local docker_drop_rule_v6
  local sysctl_syncookies
  local fail2ban_active
  local tailscale_runssh_disabled
  local banner_present
  local docker_ssh_cidrs_csv
  local docker_sock_world_writable="false"
  local admin_in_docker_group="false"

  tailscale_iface_present="$(bool_cmd ip link show "${TAILSCALE_IFACE}")"
  ufw_active="$(ufw status | grep -q "^Status: active$" && echo "true" || echo "false")"
  local ssh_root_local_only
  ssh_root_disabled="$(sshd -T 2>/dev/null | grep -q "^permitrootlogin no$" && echo "true" || echo "false")"
  ssh_root_local_only="$(sshd -T -C addr=127.0.0.1,user=root,host=localhost,laddr=127.0.0.1 2>/dev/null | grep -qE "^permitrootlogin (prohibit-password|without-password)$" && echo "true" || echo "false")"
  ssh_password_disabled="$(sshd -T 2>/dev/null | grep -q "^passwordauthentication no$" && echo "true" || echo "false")"
  journald_persistent="$(grep -q "^Storage=persistent$" "${JOURNALD_DROPIN_FILE}" && echo "true" || echo "false")"
  auditd_enabled="$(systemctl is-enabled auditd >/dev/null 2>&1 && echo "true" || echo "false")"
  audit_rules_loaded="$(auditctl -l | grep -q "identity" && echo "true" || echo "false")"
  docker_drop_rule="$(iptables -t filter -S DOCKER-USER 2>/dev/null | grep -q "coolify-hardening-wan-drop" && echo "true" || echo "false")"
  docker_drop_rule_v6="$(ip6tables -t filter -S DOCKER-USER 2>/dev/null | grep -q "coolify-hardening-wan-drop6" && echo "true" || echo "false")"
  sysctl_syncookies="$([[ "$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)" == "1" ]] && echo "true" || echo "false")"
  local sysctl_bbr
  sysctl_bbr="$([[ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" == "bbr" ]] && echo "true" || echo "false")"
  local timesync_ntp
  timesync_ntp="$([[ "$(timedatectl show --property=NTP --value 2>/dev/null)" == "yes" ]] && echo "true" || echo "false")"
  local swap_active
  swap_active="$(swapon --show --noheadings 2>/dev/null | grep -q . && echo "true" || echo "false")"
  fail2ban_active="$(systemctl is-active --quiet fail2ban && echo "true" || echo "false")"
  tailscale_runssh_disabled="$([[ "$(tailscale_runssh_pref_value 5 1)" == "false" ]] && echo "true" || echo "false")"
  banner_present="$([[ -f /etc/issue.net ]] && echo "true" || echo "false")"
  docker_ssh_cidrs_csv="$(IFS=,; echo "${DOCKER_SSH_CIDRS[*]}")"

  if [[ "${DOCKER_PRESENT}" == "true" ]]; then
    if [[ -S /var/run/docker.sock ]]; then
      local docker_sock_mode docker_sock_other
      docker_sock_mode="$(stat -c '%a' /var/run/docker.sock 2>/dev/null || echo "")"
      if [[ -n "${docker_sock_mode}" ]]; then
        docker_sock_other="${docker_sock_mode: -1}"
        if [[ "${docker_sock_other}" =~ ^[0-7]$ ]] && (( (10#${docker_sock_other} & 2) != 0 )); then
          docker_sock_world_writable="true"
        fi
      fi
    fi
    if getent group docker >/dev/null 2>&1 && id -nG "${ADMIN_USER}" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
      admin_in_docker_group="true"
    fi
  fi

  # Dashboard UFW restriction check (UFW-based; security enforced by UFW not socket binding)
  local coolify_dashboard_bound="false"
  local coolify_dashboard_ip=""
  if is_true "${BIND_DASHBOARD_TO_TAILSCALE}"; then
    coolify_dashboard_ip="${DETECTED_TAILSCALE_IP:-}"
    # Check if UFW rule for port 8000 on tailscale0 is present
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "8000.*on ${TAILSCALE_IFACE}"; then
      coolify_dashboard_bound="true"
    fi
  fi

  jq -n \
    --arg generated_at "$(date -Iseconds)" \
    --arg script_version "${SCRIPT_VERSION}" \
    --arg os_version "${OS_VERSION}" \
    --arg admin_user "${ADMIN_USER}" \
    --arg wan_iface "${WAN_IFACE}" \
    --arg tailscale_iface "${TAILSCALE_IFACE}" \
    --arg tailscale_cidr_hint "${TAILSCALE_CIDR}" \
    --argjson ssh_port "${SSH_PORT}" \
    --argjson tunnel_mode "$(is_true "${TUNNEL_MODE}" && echo true || echo false)" \
    --arg swap_size "${SWAP_SIZE:-2G}" \
    --arg journal_retention "${JOURNAL_RETENTION}" \
    --arg update_profile "${UPDATE_PROFILE}" \
    --arg timezone "${TIMEZONE}" \
    --argjson auto_reboot_requested "$(is_true "${ENABLE_AUTO_REBOOT}" && echo true || echo false)" \
    --arg auto_reboot_time "${AUTO_REBOOT_TIME}" \
    --argjson strict_docker_ssh_cidrs "$(is_true "${STRICT_DOCKER_SSH_CIDRS}" && echo true || echo false)" \
    --arg docker_ssh_cidrs "${docker_ssh_cidrs_csv}" \
    --argjson docker_nproc_hard "${DOCKER_NPROC_HARD}" \
    --argjson docker_nproc_soft "${DOCKER_NPROC_SOFT}" \
    --argjson tailscale_direct_wan "$(is_true "${TAILSCALE_DIRECT_WAN}" && echo true || echo false)" \
    --argjson bind_dashboard_to_tailscale "$(is_true "${BIND_DASHBOARD_TO_TAILSCALE}" && echo true || echo false)" \
    --argjson install_tailscale "$(is_true "${INSTALL_TAILSCALE}" && echo true || echo false)" \
    --arg tailscale_ip "${DETECTED_TAILSCALE_IP:-}" \
    --argjson dry_run "$(is_true "${DRY_RUN}" && echo true || echo false)" \
    --argjson tailscale_iface_present "${tailscale_iface_present}" \
    --argjson ufw_active "${ufw_active}" \
    --argjson ssh_root_login_disabled "${ssh_root_disabled}" \
    --argjson ssh_root_local_only_key_auth "${ssh_root_local_only}" \
    --argjson ssh_password_auth_disabled "${ssh_password_disabled}" \
    --argjson journald_persistent "${journald_persistent}" \
    --argjson auditd_enabled "${auditd_enabled}" \
    --argjson audit_rules_loaded "${audit_rules_loaded}" \
    --argjson docker_user_drop_rule_v4 "${docker_drop_rule}" \
    --argjson docker_user_drop_rule_v6 "${docker_drop_rule_v6}" \
    --argjson docker_sock_world_writable "${docker_sock_world_writable}" \
    --argjson admin_user_in_docker_group "${admin_in_docker_group}" \
    --argjson sysctl_syncookies "${sysctl_syncookies}" \
    --argjson sysctl_bbr "${sysctl_bbr}" \
    --argjson timesync_ntp "${timesync_ntp}" \
    --argjson swap_active "${swap_active}" \
    --argjson fail2ban_active "${fail2ban_active}" \
    --argjson tailscale_runssh_disabled "${tailscale_runssh_disabled}" \
    --argjson banner_present "${banner_present}" \
    --argjson coolify_dashboard_bound_to_tailscale "${coolify_dashboard_bound}" \
    '{
      generated_at: $generated_at,
      script_version: $script_version,
      os_version: $os_version,
      admin_user: $admin_user,
      wan_iface: $wan_iface,
      tailscale_iface: $tailscale_iface,
      tailscale_cidr_hint: $tailscale_cidr_hint,
      ssh_port: $ssh_port,
      tunnel_mode: $tunnel_mode,
      swap_size: $swap_size,
      journal_retention: $journal_retention,
      update_profile: $update_profile,
      timezone: $timezone,
      auto_reboot_requested: $auto_reboot_requested,
      auto_reboot_time: $auto_reboot_time,
      strict_docker_ssh_cidrs: $strict_docker_ssh_cidrs,
      docker_ssh_cidrs: $docker_ssh_cidrs,
      docker_nproc_hard: $docker_nproc_hard,
      docker_nproc_soft: $docker_nproc_soft,
      tailscale_direct_wan: $tailscale_direct_wan,
      bind_dashboard_to_tailscale: $bind_dashboard_to_tailscale,
      install_tailscale: $install_tailscale,
      tailscale_ip: $tailscale_ip,
      dry_run: $dry_run,
      checks: {
        tailscale_iface_present: $tailscale_iface_present,
        ufw_active: $ufw_active,
        ssh_root_login_disabled: $ssh_root_login_disabled,
        ssh_root_local_only_key_auth: $ssh_root_local_only_key_auth,
        ssh_password_auth_disabled: $ssh_password_auth_disabled,
        journald_persistent: $journald_persistent,
        auditd_enabled: $auditd_enabled,
        audit_rules_loaded: $audit_rules_loaded,
        docker_user_drop_rule_v4: $docker_user_drop_rule_v4,
        docker_user_drop_rule_v6: $docker_user_drop_rule_v6,
        docker_sock_world_writable: $docker_sock_world_writable,
        admin_user_in_docker_group: $admin_user_in_docker_group,
        sysctl_syncookies: $sysctl_syncookies,
        sysctl_bbr: $sysctl_bbr,
        timesync_ntp: $timesync_ntp,
        swap_active: $swap_active,
        fail2ban_active: $fail2ban_active,
        tailscale_runssh_disabled: $tailscale_runssh_disabled,
        banner_present: $banner_present,
        coolify_dashboard_bound_to_tailscale: $coolify_dashboard_bound_to_tailscale
      }
    }' > "${REPORT_FILE}"

  chmod 0600 "${REPORT_FILE}"
}

migrate_legacy_state() {
  local legacy="/var/lib/bootstrap-hardening"
  local target="/var/lib/server-hardening"

  [[ -d "${legacy}" ]] || return 0
  [[ -d "${target}" ]] && return 0

  log "Migrating state: ${legacy} → ${target}"
  install -d -m 0750 "$(dirname "${target}")"
  mv "${legacy}" "${target}"
  log "State migration complete."
}

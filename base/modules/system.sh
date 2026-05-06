ensure_packages() {
  local packages
  local missing=()
  local fail2ban_missing="false"
  packages=(
    curl
    jq
    gdisk
    ufw
    auditd
    audispd-plugins
    unattended-upgrades
    apt-listchanges
    openssh-server
    iptables
  )

  for pkg in "${packages[@]}"; do
    if ! dpkg-query -W -f='${Status}' "${pkg}" 2>/dev/null | grep -q "install ok installed"; then
      missing+=("${pkg}")
    fi
  done

  if ! dpkg-query -W -f='${Status}' fail2ban 2>/dev/null | grep -q "install ok installed"; then
    fail2ban_missing="true"
  fi

  if ((${#missing[@]} > 0)); then
    log "Installing required packages: ${missing[*]}"
    retry_apt_update
    run_apt_command env DEBIAN_FRONTEND=noninteractive PYTHONWARNINGS=ignore::SyntaxWarning \
      apt-get install -y --no-install-recommends "${missing[@]}"
  fi

  if [[ "${fail2ban_missing}" == "true" ]]; then
    install_fail2ban_without_autostart
  fi
}

install_fail2ban_without_autostart() {
  local policy_rc_d="/usr/sbin/policy-rc.d"
  local policy_backup=""
  local policy_restore="false"
  local install_rc=0

  log "Installing required package: fail2ban (service autostart suppressed until managed config is written)"
  retry_apt_update

  if is_true "${DRY_RUN}"; then
    run_apt_command env DEBIAN_FRONTEND=noninteractive PYTHONWARNINGS=ignore::SyntaxWarning \
      apt-get install -y --no-install-recommends fail2ban
    return 0
  fi

  if [[ -e "${policy_rc_d}" ]]; then
    policy_backup="$(mktemp "${policy_rc_d}.server-hardening.XXXXXX")"
    cp -a "${policy_rc_d}" "${policy_backup}"
    policy_restore="true"
  fi

  write_file "${policy_rc_d}" "0755" "root" "root" <<'EOF'
#!/usr/bin/env bash
exit 101
EOF

  if ! run_apt_command env DEBIAN_FRONTEND=noninteractive PYTHONWARNINGS=ignore::SyntaxWarning \
    apt-get install -y --no-install-recommends fail2ban; then
    install_rc=$?
  fi

  if [[ "${policy_restore}" == "true" ]]; then
    cp -a "${policy_backup}" "${policy_rc_d}"
    rm -f "${policy_backup}"
  else
    rm -f "${policy_rc_d}"
  fi

  (( install_rc == 0 )) || return "${install_rc}"
}

ensure_system_group() {
  local group_name="$1"
  [[ -n "${group_name}" ]] || die "ensure_system_group requires a non-empty group name."

  if getent group "${group_name}" >/dev/null 2>&1; then
    return 0
  fi

  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would create missing system group '${group_name}'."
    return 0
  fi

  log "Creating missing system group '${group_name}'."
  run groupadd --system "${group_name}"
}

ensure_power_group() {
  ensure_system_group "power"
}

require_commands() {
  local commands=()
  commands+=(ip awk grep sed jq sgdisk)

  if ! is_true "${DRY_RUN}"; then
    commands+=(sshd ufw iptables journalctl systemctl augenrules auditctl fail2ban-client)
  fi

  for cmd in "${commands[@]}"; do
    command -v "${cmd}" >/dev/null 2>&1 || die "Missing command: ${cmd}"
  done
}

retry_apt_update() {
  local attempts=3 delay=5 i
  for (( i = 1; i <= attempts; i++ )); do
    if run_apt_command apt-get update; then
      return 0
    fi
    if (( i < attempts )); then
      log "apt-get update failed (attempt ${i}/${attempts}); retrying in ${delay}s..."
      sleep "${delay}"
    fi
  done
  die "apt-get update failed after ${attempts} attempts."
}

retry_apt_noninteractive() {
  local description="$1"
  shift

  local attempts=3 delay=10 i
  for (( i = 1; i <= attempts; i++ )); do
    if run_apt_command env DEBIAN_FRONTEND=noninteractive PYTHONWARNINGS=ignore::SyntaxWarning \
      apt-get -y \
      -o Dpkg::Options::=--force-confdef \
      -o Dpkg::Options::=--force-confold \
      "$@"; then
      return 0
    fi
    if (( i < attempts )); then
      log "${description} failed (attempt ${i}/${attempts}); retrying in ${delay}s..."
      sleep "${delay}"
    fi
  done
  die "${description} failed after ${attempts} attempts."
}

emit_filtered_package_output() {
  sed -E \
    -e '/SyntaxWarning: invalid escape sequence/d' \
    -e '/dpkg: warning: while removing .* directory .* not empty so not removed/d' \
    -e '/Service restarts being deferred:/d' \
    -e '/No containers need to be restarted\./d' \
    -e '/No user sessions are running outdated binaries\./d' \
    -e '/No VM guests are running outdated hypervisor.*\./d'
}

run_apt_command() {
  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: $*"
    return 0
  fi

  local tmp rc
  tmp="$(mktemp)"
  if "$@" >"${tmp}" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  emit_filtered_package_output < "${tmp}" || true
  rm -f "${tmp}"
  return "${rc}"
}

apply_system_package_updates() {
  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would run apt-get full-upgrade and autoremove for baseline patching."
    return 0
  fi

  retry_apt_update
  log "Applying baseline package patches (apt-get full-upgrade, include phased updates)..."
  retry_apt_noninteractive \
    "apt-get full-upgrade" \
    -o APT::Get::Always-Include-Phased-Updates=true \
    full-upgrade

  log "Removing obsolete packages (apt-get autoremove --purge)..."
  retry_apt_noninteractive "apt-get autoremove --purge" autoremove --purge
  run apt-get -y autoclean

  local upgradable_count
  upgradable_count="$(apt list --upgradable 2>/dev/null | awk 'NR>1{c++} END{print c+0}')"
  if [[ "${upgradable_count}" =~ ^[0-9]+$ && "${upgradable_count}" -eq 0 ]]; then
    log "Baseline patching complete: no upgradable packages remain."
  else
    warn "Baseline patching complete with ${upgradable_count:-unknown} upgradable package(s) still listed."
  fi

  if [[ -f /var/run/reboot-required ]]; then
    warn "System reports reboot required after package updates (/var/run/reboot-required)."
  fi
}

ensure_timesync() {
  if ! is_true "${DRY_RUN}"; then
    local ntp_active
    ntp_active="$(timedatectl show --property=NTP --value 2>/dev/null || echo "n/a")"
    if [[ "${ntp_active}" != "yes" ]]; then
      if run timedatectl set-ntp true; then
        log "NTP synchronization enabled."
      else
        warn "Could not enable NTP (timedatectl set-ntp failed). Verify manually."
      fi
    else
      log "NTP synchronization already active."
    fi
    local i
    for (( i = 1; i <= 6; i++ )); do
      local synced
      synced="$(timedatectl show --property=NTPSynchronized --value 2>/dev/null || echo "n/a")"
      if [[ "${synced}" == "yes" ]]; then
        log "NTP synchronized."
        return 0
      fi
      log "Waiting for NTP synchronization (${i}/6)..."
      sleep 5
    done
    warn "NTP not synchronized after 30s; continuing. Verify with: timedatectl status"
  else
    log "DRY-RUN: would verify NTP synchronization."
  fi
}

configure_timezone() {
  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would configure timezone to ${TIMEZONE}."
    return 0
  fi

  if ! command -v timedatectl >/dev/null 2>&1; then
    warn "timedatectl not found; skipping timezone configuration."
    return 0
  fi

  local current_tz
  current_tz="$(timedatectl show --property=Timezone --value 2>/dev/null || true)"
  if [[ "${current_tz}" == "${TIMEZONE}" ]]; then
    log "Timezone already configured: ${TIMEZONE}."
    return 0
  fi

  run timedatectl set-timezone "${TIMEZONE}"
  current_tz="$(timedatectl show --property=Timezone --value 2>/dev/null || true)"
  [[ "${current_tz}" == "${TIMEZONE}" ]] \
    || die "Failed to set timezone to ${TIMEZONE} (current: ${current_tz:-unknown})."
  log "Timezone configured: ${TIMEZONE}."
}

normalize_private_hosts_file() {
  if [[ -z "${DOMAIN}" ]]; then
    log "DOMAIN not provided; skipping /etc/hosts private-domain normalization."
    return 0
  fi

  if [[ ! -f "${HOSTS_FILE}" ]]; then
    warn "${HOSTS_FILE} not found; skipping private-domain normalization."
    return 0
  fi

  local short_host tmp awk_rc
  short_host="$(hostname -s 2>/dev/null || true)"

  if is_true "${DRY_RUN}"; then
    if awk -v dashboard="${DOMAIN}" -v websocket="ws.${DOMAIN}" '
      $0 !~ /^[[:space:]]*#/ && NF > 1 {
        ip=$1
        if (ip ~ /^127\./ || ip == "::1") {
          for (i=2; i<=NF; i++) {
            if ($i == dashboard || $i == websocket) exit 0
          }
        }
      }
      END { exit 1 }
    ' "${HOSTS_FILE}"; then
      log "DRY-RUN: would remove ${DOMAIN} and ws.${DOMAIN} from loopback entries in ${HOSTS_FILE}"
    else
      log "DRY-RUN: ${HOSTS_FILE} already leaves ${DOMAIN} DNS-driven"
    fi
    return 0
  fi

  tmp="$(mktemp)"
  if awk -v dashboard="${DOMAIN}" -v websocket="ws.${DOMAIN}" -v short="${short_host}" '
    function is_loopback(ip) { return ip ~ /^127\./ || ip == "::1" }
    function has_token(arr, count, value,   idx) {
      for (idx = 1; idx <= count; idx++) {
        if (arr[idx] == value) {
          return 1
        }
      }
      return 0
    }
    {
      if ($0 ~ /^[[:space:]]*#/) {
        print
        next
      }
      if (NF == 0) {
        print ""
        next
      }

      ip = $1
      if (!is_loopback(ip)) {
        print
        next
      }

      if (ip == "127.0.1.1") {
        have_12701 = 1
      }

      keep_count = 0
      delete keep
      for (i = 2; i <= NF; i++) {
        token = $i
        if (token == dashboard || token == websocket) {
          changed = 1
          continue
        }
        keep[++keep_count] = token
      }

      if (ip == "127.0.1.1" && short != "" && short != "localhost" && !has_token(keep, keep_count, short)) {
        keep[++keep_count] = short
        changed = 1
      }

      if (keep_count == 0) {
        changed = 1
        next
      }

      printf "%s", ip
      for (i = 1; i <= keep_count; i++) {
        printf " %s", keep[i]
      }
      printf "\n"
    }
    END {
      if (!have_12701 && short != "" && short != "localhost") {
        print "127.0.1.1 " short
        changed = 1
      }
      exit changed ? 10 : 0
    }
  ' "${HOSTS_FILE}" > "${tmp}"; then
    awk_rc=0
  else
    awk_rc=$?
  fi

  case "${awk_rc}" in
    0)
      rm -f "${tmp}"
      log "${HOSTS_FILE} already keeps ${DOMAIN} and ws.${DOMAIN} DNS-driven."
      return 0
      ;;
    10)
      install -m 0644 -o root -g root "${tmp}" "${HOSTS_FILE}"
      rm -f "${tmp}"
      log "Normalized ${HOSTS_FILE} to keep ${DOMAIN} and ws.${DOMAIN} DNS-driven."
      return 0
      ;;
    *)
      rm -f "${tmp}"
      die "Failed to normalize ${HOSTS_FILE} for ${DOMAIN}."
      ;;
  esac
}

configure_swap() {
  local swap_size="${SWAP_SIZE:-2G}"
  [[ "${swap_size}" == "0" ]] && { log "Swap creation disabled (--swap-size 0)."; return 0; }

  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would configure ${swap_size} swap file at /swapfile."
    return 0
  fi

  if swapon --show --noheadings | grep -q .; then
    log "Swap already active. Skipping."
    return 0
  fi

  local swap_file="/swapfile"
  if [[ -f "${swap_file}" ]]; then
    log "Stale ${swap_file} found (not active in swapon); removing."
    run rm -f "${swap_file}"
  fi
  run fallocate -l "${swap_size}" "${swap_file}"
  run chmod 600 "${swap_file}"
  run mkswap "${swap_file}"
  run swapon "${swap_file}"

  # Accept any existing /swapfile entry to avoid duplicate lines across distro formats.
  if ! grep -qE '^/swapfile[[:space:]]' /etc/fstab; then
    echo "${swap_file} none swap sw 0 0" >> /etc/fstab
  fi

  log "Swap configured: ${swap_size} at ${swap_file}."
}

configure_banner() {
  write_file "/etc/issue.net" "0644" "root" "root" <<'EOF'
***************************************************************************
                   AUTHORIZED ACCESS ONLY
This system is for authorized use only. All activity may be monitored
and reported. Unauthorized access is prohibited and may be subject to
criminal and civil penalties.
***************************************************************************
EOF
}

ensure_admin_access() {
  local home_dir
  local ssh_dir
  local auth_file
  local user_exists="false"

  if id "${ADMIN_USER}" >/dev/null 2>&1; then
    user_exists="true"
    log "Admin user exists: ${ADMIN_USER}"
  else
    run useradd -m -s /bin/bash -G sudo "${ADMIN_USER}"
  fi

  if [[ "${user_exists}" == "true" ]] && ! id -nG "${ADMIN_USER}" | tr ' ' '\n' | grep -qx "sudo"; then
    run usermod -aG sudo "${ADMIN_USER}"
  fi

  # Configure passwordless sudo for admin user
  # This is required because the admin user has no password set,
  # but sudo requires password by default, blocking all admin operations.
  local sudoers_file="/etc/sudoers.d/${ADMIN_USER}"
  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would create ${sudoers_file} with passwordless sudo for ${ADMIN_USER}"
  else
    cat > "${sudoers_file}" <<EOF
Defaults:${ADMIN_USER} timestamp_timeout=0
${ADMIN_USER} ALL=(ALL) NOPASSWD: ALL
EOF
    chmod 440 "${sudoers_file}"
    # Validate sudoers syntax before committing
    if ! visudo -c -f "${sudoers_file}" >/dev/null 2>&1; then
      rm -f "${sudoers_file}"
      die "Failed to create valid sudoers file for ${ADMIN_USER}"
    fi
    log "Configured passwordless sudo for ${ADMIN_USER}"
  fi

  if is_true "${DRY_RUN}" && [[ "${user_exists}" == "false" ]]; then
    log "DRY-RUN: would create /home/${ADMIN_USER}/.ssh/authorized_keys with provided key."
    return 0
  fi

  home_dir="$(getent passwd "${ADMIN_USER}" | cut -d: -f6)"
  [[ -n "${home_dir}" ]] || die "Unable to resolve home directory for ${ADMIN_USER}."
  ssh_dir="${home_dir}/.ssh"
  auth_file="${ssh_dir}/authorized_keys"

  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: ensure ${auth_file} contains provided key."
    return 0
  fi

  install -d -m 0700 -o "${ADMIN_USER}" -g "${ADMIN_USER}" "${ssh_dir}"
  touch "${auth_file}"
  chown "${ADMIN_USER}:${ADMIN_USER}" "${auth_file}"
  chmod 0600 "${auth_file}"

  if ! grep -qxF "${ADMIN_PUBKEY}" "${auth_file}"; then
    printf '%s\n' "${ADMIN_PUBKEY}" >> "${auth_file}"
  fi

  # Lock root password — root login is blocked by sshd config but a set
  # password is still a credential that could be leveraged via console or
  # a misconfigured PAM rule.
  if ! is_true "${DRY_RUN}"; then
    local root_pw_status
    root_pw_status="$(passwd -S root 2>/dev/null | awk '{print $2}')"
    if [[ "${root_pw_status}" == "P" ]]; then
      passwd -l root >/dev/null 2>&1
      log "Root password locked."
    fi
  else
    log "DRY-RUN: would lock root password."
  fi

  # Clear root authorized_keys — provisioning systems often inject keys
  # into /root/.ssh/authorized_keys that are unrelated to the admin user.
  # Root login is already blocked from external addresses, but stale keys
  # are a credential that should not persist.
  if ! is_true "${DRY_RUN}"; then
    local root_auth_keys="/root/.ssh/authorized_keys"
    if [[ -f "${root_auth_keys}" ]] && [[ -s "${root_auth_keys}" ]]; then
      : > "${root_auth_keys}"
      log "Cleared root authorized_keys."
    fi
  else
    log "DRY-RUN: would clear root authorized_keys."
  fi
}

restore_ssh_dropin() {
  local backup="$1"
  if is_true "${DRY_RUN}"; then
    return 0
  fi
  if [[ -n "${backup}" && -f "${backup}" ]]; then
    cp -a "${backup}" "${SSH_DROPIN_FILE}"
  else
    rm -f "${SSH_DROPIN_FILE}"
  fi
}

assert_sshd_effective() {
  local effective="$1"

  grep -qE "^port ${SSH_PORT}$" <<< "${effective}" || return 1
  grep -q "^permitrootlogin no$" <<< "${effective}" || return 1
  grep -q "^passwordauthentication no$" <<< "${effective}" || return 1
  grep -q "^kbdinteractiveauthentication no$" <<< "${effective}" || return 1
  grep -q "^pubkeyauthentication yes$" <<< "${effective}" || return 1
  grep -q "^authenticationmethods publickey$" <<< "${effective}" || return 1
  grep -qE "^allowusers .*\\b${ADMIN_USER}\\b" <<< "${effective}" || return 1
  grep -q "^permitemptypasswords no$" <<< "${effective}" || return 1
  grep -q "^compression no$" <<< "${effective}" || return 1
  grep -q "chacha20-poly1305@openssh.com" <<< "${effective}" || return 1
  grep -q "hmac-sha2-512-etm@openssh.com" <<< "${effective}" || return 1
  grep -q "sntrup761x25519-sha512@openssh.com" <<< "${effective}" || return 1
  grep -q "hostkeyalgorithms .*ssh-ed25519" <<< "${effective}" || return 1
}

assert_sshd_match_localhost() {
  local effective="$1"

  # OpenSSH outputs "prohibit-password" or its legacy synonym "without-password"
  grep -qE "^permitrootlogin (prohibit-password|without-password)$" <<< "${effective}" || return 1
  grep -qE "^allowusers .*\\broot\\b" <<< "${effective}" || return 1
  grep -qE "^allowusers .*\\b${ADMIN_USER}\\b" <<< "${effective}" || return 1
}

reload_ssh_service() {
  local units
  local has_ssh="false"
  local has_sshd="false"

  if ! systemctl list-unit-files --type=service --no-legend >/dev/null 2>&1; then
    return 1
  fi

  units="$(systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}')"
  grep -qx "ssh.service" <<< "${units}" && has_ssh="true" || true
  grep -qx "sshd.service" <<< "${units}" && has_sshd="true" || true

  if [[ "${has_ssh}" == "true" ]]; then
    if ! systemctl is-active --quiet ssh; then
      systemctl start ssh || return 1
    fi
    systemctl reload ssh || systemctl restart ssh || return 1
    return 0
  fi

  if [[ "${has_sshd}" == "true" ]]; then
    if ! systemctl is-active --quiet sshd; then
      systemctl start sshd || return 1
    fi
    systemctl reload sshd || systemctl restart sshd || return 1
    return 0
  fi

  return 1
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

configure_ssh() {
  local backup=""
  local effective=""
  local match_addresses="127.0.0.1,::1"
  local cidr

  for cidr in "${DOCKER_SSH_CIDRS[@]}"; do
    match_addresses+=",${cidr}"
  done

  if ! is_true "${DRY_RUN}" && [[ ! -d /run/sshd ]]; then
    install -d -m 0755 /run/sshd
  fi

  if [[ -f "${SSH_DROPIN_FILE}" ]] && ! is_true "${DRY_RUN}"; then
    backup="${SSH_DROPIN_FILE}.bak.$(date +%s)"
    cp -a "${SSH_DROPIN_FILE}" "${backup}"
  fi

  # Fix base sshd_config to not rely solely on drop-in overrides
  local base_config="/etc/ssh/sshd_config"
  if [[ -f "${base_config}" ]] && ! is_true "${DRY_RUN}"; then
    sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' "${base_config}"
    sed -i 's/^X11Forwarding yes/X11Forwarding no/' "${base_config}"
    log "Hardened base sshd_config (PermitRootLogin no, X11Forwarding no)."
  elif [[ -f "${base_config}" ]]; then
    log "DRY-RUN: would harden base sshd_config (PermitRootLogin no, X11Forwarding no)."
  fi

  # Neutralize cloud-init override that re-enables password auth
  local cloud_init_ssh="/etc/ssh/sshd_config.d/50-cloud-init.conf"
  local cloud_init_cfg="/etc/cloud/cloud.cfg.d/99-disable-ssh-password.cfg"
  if ! is_true "${DRY_RUN}"; then
    if [[ -f "${cloud_init_ssh}" ]]; then
      echo "PasswordAuthentication no" > "${cloud_init_ssh}"
      chmod 0644 "${cloud_init_ssh}"
      log "Neutralized ${cloud_init_ssh} (set PasswordAuthentication no)."
    fi
    mkdir -p "$(dirname "${cloud_init_cfg}")"
    echo "ssh_pwauth: false" > "${cloud_init_cfg}"
    log "Prevented cloud-init from re-enabling SSH password auth."
  else
    log "DRY-RUN: would neutralize cloud-init SSH password auth override."
  fi

  write_file "${SSH_DROPIN_FILE}" "0644" "root" "root" <<EOF
# Managed by ${SCRIPT_NAME}
Port ${SSH_PORT}
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
AllowUsers ${ADMIN_USER}
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
Compression no
MaxAuthTries 3
MaxSessions 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
PerSourceMaxStartups 3
# Modern algorithms only — explicit allowlist, no legacy defaults.
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
Banner /etc/issue.net

# Coolify connects to its own host as root via localhost / Docker bridge.
# Compatibility mode uses broad RFC1918 ranges; strict mode uses discovered
# Docker bridge CIDRs with safe fallback if discovery fails.
Match Address ${match_addresses}
    PermitRootLogin prohibit-password
    AllowUsers ${ADMIN_USER} root
EOF

  if is_true "${DRY_RUN}"; then
    return 0
  fi

  if ! sshd -t; then
    restore_ssh_dropin "${backup}"
    die "sshd -t failed after writing SSH hardening drop-in."
  fi

  effective="$(sshd -T 2>/dev/null || true)"
  if ! assert_sshd_effective "${effective}"; then
    restore_ssh_dropin "${backup}"
    die "sshd -T did not match expected hardened values."
  fi

  local match_effective
  match_effective="$(sshd -T -C addr=127.0.0.1,user=root,host=localhost,laddr=127.0.0.1 2>/dev/null || true)"
  if ! assert_sshd_match_localhost "${match_effective}"; then
    restore_ssh_dropin "${backup}"
    die "sshd -T -C (localhost Match block) did not match expected values."
  fi

  if ! reload_ssh_service; then
    restore_ssh_dropin "${backup}"
    die "Failed to reload SSH service."
  fi

  rm -f "${SSH_DROPIN_FILE}".bak.*

  # Remove weak DSA host key — deprecated in OpenSSH 7.0+, not negotiated
  # by our HostKeyAlgorithms list, but the key file should not exist.
  if [[ -f /etc/ssh/ssh_host_dsa_key ]] && ! is_true "${DRY_RUN}"; then
    rm -f /etc/ssh/ssh_host_dsa_key /etc/ssh/ssh_host_dsa_key.pub
    log "Removed deprecated DSA host key."
  elif [[ -f /etc/ssh/ssh_host_dsa_key ]]; then
    log "DRY-RUN: would remove deprecated DSA host key."
  fi
}

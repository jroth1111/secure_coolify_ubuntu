build_audit_rules() {
  # Modern syscall-form rules — higher performance than legacy -w syntax.
  # File watches use: -a always,exit -F path=... -F perm=wa
  # Dir  watches use: -a always,exit -F dir=...  -F perm=wa
  # Exec watches use: -a always,exit -F path=... -F perm=x
  cat <<'EOF'
# Managed by bootstrap hardening (syscall-form)
# Identity files
-a always,exit -F path=/etc/passwd -F perm=wa -k identity
-a always,exit -F path=/etc/shadow -F perm=wa -k identity
-a always,exit -F path=/etc/group -F perm=wa -k identity
-a always,exit -F path=/etc/gshadow -F perm=wa -k identity
# SSH config
-a always,exit -F path=/etc/ssh/sshd_config -F perm=wa -k sshd-config
-a always,exit -F dir=/etc/ssh/sshd_config.d -F perm=wa -k sshd-config
# Time
-a always,exit -F path=/etc/localtime -F perm=wa -k time-change
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
# Network / locale
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
# Sudoers
-a always,exit -F path=/etc/sudoers -F perm=wa -k sudoers-change
-a always,exit -F dir=/etc/sudoers.d -F perm=wa -k sudoers-change
# Kernel module loading (important for container hosts)
-a always,exit -F path=/etc/modules -F perm=wa -k kernel-module
-a always,exit -F dir=/etc/modprobe.d -F perm=wa -k kernel-module
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k kernel-module
-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k kernel-module
# User command tracking — forensic attribution via auid
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=unset -k user_commands
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=unset -k user_commands
EOF

  local bin
  for bin in /usr/bin/docker /usr/bin/dockerd /usr/bin/containerd; do
    if [[ -e "${bin}" ]]; then
      printf -- "-a always,exit -F path=%s -F perm=x -k container-runtime\n" "${bin}"
    fi
  done

  local path
  for path in /var/run/docker.sock /etc/docker/; do
    if [[ -e "${path}" ]]; then
      if [[ -d "${path}" ]]; then
        printf -- "-a always,exit -F dir=%s -F perm=wa -k docker-config\n" "${path%/}"
      else
        printf -- "-a always,exit -F path=%s -F perm=wa -k docker-config\n" "${path}"
      fi
    fi
  done
}

set_auditd_conf_kv() {
  local key="$1"
  local value="$2"

  [[ -f "${AUDITD_CONF_FILE}" ]] || return 0

  if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "${AUDITD_CONF_FILE}"; then
    run sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "${AUDITD_CONF_FILE}"
  else
    if is_true "${DRY_RUN}"; then
      log "DRY-RUN: append '${key} = ${value}' to ${AUDITD_CONF_FILE}"
    else
      printf '%s = %s\n' "${key}" "${value}" >> "${AUDITD_CONF_FILE}"
    fi
  fi
}

configure_auditd_policy() {
  if [[ ! -f "${AUDITD_CONF_FILE}" ]]; then
    warn "${AUDITD_CONF_FILE} not found; skipping auditd failure-policy tuning."
    return 0
  fi

  # Preserve historical logs and avoid silent overwrite; pair with space thresholds.
  set_auditd_conf_kv "max_log_file_action" "keep_logs"
  set_auditd_conf_kv "space_left" "100"
  set_auditd_conf_kv "space_left_action" "syslog"
  set_auditd_conf_kv "admin_space_left" "50"
  set_auditd_conf_kv "admin_space_left_action" "suspend"
  set_auditd_conf_kv "disk_full_action" "suspend"
  set_auditd_conf_kv "disk_error_action" "suspend"
}

configure_auditd() {
  local tmp
  tmp="$(mktemp)"
  build_audit_rules > "${tmp}"

  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: write ${AUDIT_RULES_FILE}"
    rm -f "${tmp}"
  else
    install -d -m 0755 "$(dirname "${AUDIT_RULES_FILE}")"
    install -m 0640 -o root -g root "${tmp}" "${AUDIT_RULES_FILE}"
    rm -f "${tmp}"
  fi

  run systemctl enable --now auditd || warn "auditd could not be started (container/kernel limitation); rules file written."
  run augenrules --load
  configure_auditd_policy
  run systemctl restart auditd || warn "auditd restart failed after auditd.conf policy update."
}

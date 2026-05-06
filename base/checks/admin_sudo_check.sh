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

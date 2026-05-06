fail2ban_check() {
  if systemctl is-active --quiet fail2ban 2>/dev/null; then
    record "PASS" "fail2ban: active"
  else
    record "FAIL" "fail2ban: active" "service not running"
    return
  fi

  local attempt jail_ready="false"
  for (( attempt=1; attempt<=12; attempt++ )); do
    if fail2ban-client status sshd >/dev/null 2>&1; then
      jail_ready="true"
      break
    fi
    (( attempt < 12 )) || break
    sleep 2
  done

  if [[ "${jail_ready}" == "true" ]]; then
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

  if [[ -f "${FAIL2BAN_LOCAL_FILE}" ]] \
    && grep -Eq '^[[:space:]]*allowipv6[[:space:]]*=[[:space:]]*auto([[:space:]]|$)' "${FAIL2BAN_LOCAL_FILE}"; then
    record "PASS" "fail2ban: allowipv6=auto"
  elif [[ ! -f "${FAIL2BAN_LOCAL_FILE}" ]]; then
    record "FAIL" "fail2ban: allowipv6" "${FAIL2BAN_LOCAL_FILE} missing"
  else
    record "FAIL" "fail2ban: allowipv6" "expected allowipv6 = auto in ${FAIL2BAN_LOCAL_FILE}"
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
    local chain_ready="false"
    for (( attempt=1; attempt<=12; attempt++ )); do
      if iptables -L f2b-sshd >/dev/null 2>&1; then
        chain_ready="true"
        break
      fi
      (( attempt < 12 )) || break
      sleep 2
    done

    if [[ "${chain_ready}" == "true" ]]; then
      record "PASS" "fail2ban: f2b-sshd iptables chain present"
    else
      record "FAIL" "fail2ban: f2b-sshd iptables chain" "chain missing — fail2ban may not have hooked into iptables"
    fi
  fi
}

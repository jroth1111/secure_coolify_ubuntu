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
    if grep -qE "(^|[[:space:]])${SSH_PORT}/tcp([[:space:]]|$).*ALLOW.*${escaped_cidr}" <<< "${ufw_out}"; then
      record "PASS" "ufw: SSH from Docker bridge (${cidr})"
    else
      record "FAIL" "ufw: SSH from Docker bridge (${cidr})" "${cidr} → port ${SSH_PORT}/tcp rule missing — Coolify cannot reach host"
    fi
    # Also check for orphaned non-tcp rules (legacy drift)
    if grep -qE "(^|[[:space:]])${SSH_PORT}([[:space:]]|$).*ALLOW.*${escaped_cidr}" <<< "${ufw_out}" \
      && ! grep -qE "(^|[[:space:]])${SSH_PORT}/tcp([[:space:]]|$).*ALLOW.*${escaped_cidr}" <<< "${ufw_out}"; then
      record "FAIL" "ufw: SSH from Docker bridge (${cidr})" \
        "${cidr} → port ${SSH_PORT} must be tcp-only; broad rule allows non-SSH protocols"
    fi
  done < <(load_docker_ssh_cidrs)

  # Check for orphaned non-tcp SSH rules from Docker bridges (even if tcp rules exist)
  while IFS= read -r cidr; do
    escaped_cidr="$(regex_escape "${cidr}")"
    # Match "22 " (port without /tcp) followed by ALLOW and the CIDR
    if grep -qE "(^|[[:space:]])${SSH_PORT}([[:space:]]+ALLOW[[:space:]]|ALLOW[[:space:]]IN[[:space:]]).*${escaped_cidr}" <<< "${ufw_out}"; then
      record "FAIL" "ufw: orphaned non-tcp SSH rule (${cidr})" \
        "${cidr} → port ${SSH_PORT} rule without 'proto tcp' must be removed"
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

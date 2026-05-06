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

    # Root password should be locked
    local root_pw_status
    root_pw_status="$(passwd -S root 2>/dev/null | awk '{print $2}')" || true
    if [[ "${root_pw_status}" == "L" ]]; then
      record "PASS" "ssh: root password locked"
    elif [[ -n "${root_pw_status}" ]]; then
      record "FAIL" "ssh: root password locked" "expected L (locked), got ${root_pw_status}"
    fi

    # Root authorized_keys should be empty (provisioning keys cleared)
    local root_auth="/root/.ssh/authorized_keys"
    if [[ -f "${root_auth}" ]]; then
      if [[ ! -s "${root_auth}" ]] || grep -qE "^[[:space:]]*$" "${root_auth}" && ! grep -qE "[^[:space:]]" "${root_auth}"; then
        record "PASS" "ssh: root authorized_keys empty"
      else
        record "FAIL" "ssh: root authorized_keys empty" "file contains keys — provisioning artifacts not cleaned"
      fi
    fi

    # DSA host key should not exist (deprecated)
    if [[ ! -f /etc/ssh/ssh_host_dsa_key ]]; then
      record "PASS" "ssh: no deprecated DSA host key"
    else
      record "FAIL" "ssh: DSA host key" "/etc/ssh/ssh_host_dsa_key exists — deprecated and should be removed"
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

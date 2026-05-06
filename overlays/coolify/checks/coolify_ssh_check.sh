coolify_ssh_check() {
  local ssh_dir="/data/coolify/ssh/keys"
  local coolify_env="/data/coolify/source/.env"

  # Gate-C safe: if Coolify environment is not present yet, treat this as
  # pre-install state and skip SSH key checks.
  if [[ ! -f "${coolify_env}" ]]; then
    return 0
  fi

  # Skip entirely if Coolify hasn't been installed yet (Gate C runs before install)
  if [[ ! -d "${ssh_dir}" ]]; then
    return 0
  fi

  local keyfile
  keyfile="$(ls "${ssh_dir}"/ssh_key@* "${ssh_dir}"/id.root@* 2>/dev/null | head -1 || true)"
  if [[ -z "${keyfile}" ]]; then
    keyfile="$(find "${ssh_dir}" -maxdepth 1 -type f ! -name '*.pub' 2>/dev/null | head -1 || true)"
  fi
  if [[ -z "${keyfile}" ]]; then
    record "FAIL" "coolify: ssh key exists" "no private key file found in ${ssh_dir}"
    return 0
  fi
  record "PASS" "coolify: ssh key exists"

  # Derive the public key from the private key
  local pubkey
  pubkey=$(ssh-keygen -y -f "${keyfile}" 2>/dev/null || true)
  if [[ -z "${pubkey}" ]]; then
    record "FAIL" "coolify: ssh key readable" "ssh-keygen -y failed on ${keyfile}"
    return 0
  fi

  # Check authorized_keys exists and contains the key on its own line.
  # Match on key data (field 2) only — sshd ignores comment field 3+, and ssh-keygen -y
  # may output a different comment than what was written. A bare substring grep would
  # still match a concatenated line, so we compare against per-line field 2 extractions.
  local auth="/root/.ssh/authorized_keys"
  if [[ ! -f "${auth}" ]]; then
    record "FAIL" "coolify: key in root authorized_keys" "${auth} does not exist"
    return 0
  fi

  local key_data
  key_data=$(awk '{print $2}' <<< "${pubkey}")

  if awk '{print $2}' "${auth}" 2>/dev/null | grep -qxF "${key_data}"; then
    record "PASS" "coolify: key in root authorized_keys"
  else
    # Check for concatenation: key data appears but not as a standalone field
    if grep -qF "${key_data}" "${auth}" 2>/dev/null; then
      record "FAIL" "coolify: key in root authorized_keys" \
        "key present but not on its own line (concatenation bug) — rewrite ${auth}"
    else
      record "FAIL" "coolify: key in root authorized_keys" \
        "Coolify public key not found in ${auth}"
    fi
    return 0
  fi

  # Functional test 1: SSH as root to 127.0.0.1 using Coolify's key (host-side).
  # Tests key + sshd Match block from the host loopback perspective.
  local host_known_hosts
  host_known_hosts="$(mktemp /tmp/validate-hardening-host-known-hosts.XXXXXX)"
  if ssh \
      -o StrictHostKeyChecking=accept-new \
      -o UserKnownHostsFile="${host_known_hosts}" \
      -o ConnectTimeout=5 \
      -o BatchMode=yes \
      -o LogLevel=ERROR \
      -i "${keyfile}" \
      root@127.0.0.1 'exit 0' 2>/dev/null; then
    record "PASS" "coolify: root@127.0.0.1 SSH functional"
  else
    record "FAIL" "coolify: root@127.0.0.1 SSH functional" \
      "key auth failed — check sshd Match block and authorized_keys"
  fi
  rm -f "${host_known_hosts}"

  # Functional test 2: SSH from INSIDE the coolify container to host.docker.internal.
  # This is the exact path Coolify uses for 'This Machine'. Catches:
  #   - host.docker.internal not resolving (host-gateway bug on Linux Docker)
  #   - UFW blocking port 22 from Docker bridge subnets
  #   - sshd Match block not covering the Docker bridge address range
  if command -v docker >/dev/null 2>&1 && docker inspect coolify >/dev/null 2>&1; then
    local container_keyfile
    local container_known_hosts
    container_keyfile="/var/www/html/storage/app/ssh/keys/$(basename "${keyfile}")"
    container_known_hosts="/tmp/validate-hardening-container-known-hosts"
    if docker exec coolify \
        sh -c "rm -f '${container_known_hosts}' \
               && ssh -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile='${container_known_hosts}' \
               -o ConnectTimeout=5 -o BatchMode=yes -o LogLevel=ERROR \
               -i '${container_keyfile}' root@host.docker.internal 'exit 0' \
               && rm -f '${container_known_hosts}'" \
        2>/dev/null; then
      record "PASS" "coolify: container→host SSH via host.docker.internal"
    else
      record "FAIL" "coolify: container→host SSH via host.docker.internal" \
        "SSH from coolify container failed — check host.docker.internal in /etc/hosts, UFW Docker-bridge SSH rules, and sshd Match block"
      docker exec coolify sh -c "rm -f '${container_known_hosts}'" >/dev/null 2>&1 || true
    fi
  else
    record "INFO" "coolify: container→host SSH" "coolify container not running; skipped"
  fi
}


#!/usr/bin/env bats
# Tier 2 negative matrix for validate_hardening.sh.

load '../helpers'

TEST_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyDataForValidateNegative test@bats"
TEST_USER="validatenegative"
TEST_PORT="2299"
TEST_WAN="eth0"
SSH_DROPIN="/etc/ssh/sshd_config.d/00-coolify-hardening.conf"
JOURNALD_DROPIN="/etc/systemd/journald.conf.d/90-coolify-persistent.conf"
APT_LOCAL_FILE="/etc/apt/apt.conf.d/52unattended-upgrades-local"
STATE_FILE="/var/lib/server-hardening/state"

setup_file() {
  ip link add tailscale0 type dummy 2>/dev/null || true
  ip addr add 100.64.0.1/32 dev tailscale0 2>/dev/null || true
  ip link set tailscale0 up 2>/dev/null || true

  ip link add "${TEST_WAN}" type dummy 2>/dev/null || true
  ip link set "${TEST_WAN}" up 2>/dev/null || true

  local retries=10
  while true; do
    local state
    state="$(systemctl is-system-running 2>/dev/null || true)"
    if [[ "${state}" == "running" || "${state}" == "degraded" ]]; then
      break
    fi
    retries=$((retries - 1))
    if [[ ${retries} -le 0 ]]; then
      echo "WARNING: systemd not fully ready (state=${state}), proceeding anyway" >&2
      break
    fi
    sleep 1
  done

  bash "${SCRIPT}" \
    --admin-user "${TEST_USER}" \
    --admin-pubkey "${TEST_PUBKEY}" \
    --ssh-port "${TEST_PORT}" \
    --wan-iface "${TEST_WAN}" \
    --force
}

teardown_file() {
  ip link del tailscale0 2>/dev/null || true
}

set_state_value() {
  local key="$1"
  local value="$2"
  local src="$3"
  local dst="$4"
  awk -v k="${key}" -v v="${value}" '
    BEGIN { done = 0 }
    $0 ~ "^" k "=" {
      print k "=" v
      done = 1
      next
    }
    { print }
    END {
      if (!done) print k "=" v
    }
  ' "${src}" > "${dst}"
}

json_status_for_check() {
  local check="$1"
  jq -r --arg check "${check}" '.checks[] | select(.check == $check) | .status' <<< "${output}"
}

json_fail_count() {
  jq -r '.fail' <<< "${output}"
}

@test "validate negative: fail2ban stopped triggers failure" {
  systemctl stop fail2ban 2>/dev/null || true
  run bash "${VALIDATE_SCRIPT}" --json
  systemctl start fail2ban 2>/dev/null || true
  assert_failure
  [[ "$(json_status_for_check "fail2ban: active")" == "FAIL" ]]
  [[ "$(json_fail_count)" -ge 1 ]]
}

@test "validate negative: journald volatile setting triggers failure" {
  local backup
  backup="$(mktemp)"
  cp "${JOURNALD_DROPIN}" "${backup}"
  cat > "${JOURNALD_DROPIN}" <<'EOF'
[Journal]
Storage=volatile
EOF

  run bash "${VALIDATE_SCRIPT}" --json

  cp "${backup}" "${JOURNALD_DROPIN}"
  rm -f "${backup}"
  assert_failure
  [[ "$(json_status_for_check "journald: persistent storage config")" == "FAIL" ]]
  [[ "$(json_fail_count)" -ge 1 ]]
}

@test "validate negative: missing banner triggers failure" {
  local backup
  backup="$(mktemp)"
  cp /etc/issue.net "${backup}"
  rm -f /etc/issue.net

  run bash "${VALIDATE_SCRIPT}" --json

  cp "${backup}" /etc/issue.net
  rm -f "${backup}"
  assert_failure
  [[ "$(json_status_for_check "banner: /etc/issue.net")" == "FAIL" ]]
  [[ "$(json_fail_count)" -ge 1 ]]
}

@test "validate negative: disabling ufw triggers failure" {
  ufw --force disable >/dev/null 2>&1 || true
  run bash "${VALIDATE_SCRIPT}" --json
  ufw --force enable >/dev/null 2>&1 || true
  assert_failure
  [[ "$(json_status_for_check "ufw: active")" == "FAIL" ]]
  [[ "$(json_fail_count)" -ge 1 ]]
}

@test "validate negative: docker daemon config drift triggers failure" {
  local daemon_json="/etc/docker/daemon.json"
  local backup
  backup="$(mktemp)"
  cp "${daemon_json}" "${backup}"
  jq '.["log-driver"]="none"' "${backup}" > "${daemon_json}"

  run bash "${VALIDATE_SCRIPT}" --json

  cp "${backup}" "${daemon_json}"
  rm -f "${backup}"
  assert_failure
  [[ "$(json_status_for_check "docker-daemon: log-driver")" == "FAIL" ]]
  [[ "$(json_fail_count)" -ge 1 ]]
}

@test "validate negative: SSH policy drift triggers failure" {
  local backup
  backup="$(mktemp)"
  cp "${SSH_DROPIN}" "${backup}"
  sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' "${SSH_DROPIN}"
  systemctl reload ssh 2>/dev/null || true

  run bash "${VALIDATE_SCRIPT}" --json

  cp "${backup}" "${SSH_DROPIN}"
  systemctl reload ssh 2>/dev/null || true
  rm -f "${backup}"
  assert_failure
  [[ "$(json_status_for_check "ssh: passwordauthentication")" == "FAIL" ]]
  [[ "$(json_fail_count)" -ge 1 ]]
}

@test "validate negative: sysctl drift triggers failure" {
  sysctl -w net.ipv4.tcp_syncookies=0 >/dev/null 2>&1 || true
  run bash "${VALIDATE_SCRIPT}" --json
  sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null 2>&1 || true
  assert_failure
  [[ "$(json_status_for_check "sysctl: net.ipv4.tcp_syncookies")" == "FAIL" ]]
  [[ "$(json_fail_count)" -ge 1 ]]
}

@test "validate negative: unattended upgrades drift triggers failure" {
  local backup
  backup="$(mktemp)"
  cp "${APT_LOCAL_FILE}" "${backup}"
  rm -f "${APT_LOCAL_FILE}"

  run bash "${VALIDATE_SCRIPT}" --json

  cp "${backup}" "${APT_LOCAL_FILE}"
  rm -f "${backup}"
  assert_failure
  [[ "$(json_status_for_check "auto-updates: local config")" == "FAIL" ]]
  [[ "$(json_fail_count)" -ge 1 ]]
}

@test "validate negative: admin state drift to missing user triggers failure" {
  local backup
  local mutated
  backup="$(mktemp)"
  mutated="$(mktemp)"
  cp "${STATE_FILE}" "${backup}"
  set_state_value "admin_user" "doesnotexist" "${backup}" "${mutated}"
  cp "${mutated}" "${STATE_FILE}"

  run bash "${VALIDATE_SCRIPT}" --json

  cp "${backup}" "${STATE_FILE}"
  rm -f "${backup}" "${mutated}"
  assert_failure
  [[ "$(json_status_for_check "admin: user")" == "FAIL" ]]
  [[ "$(json_fail_count)" -ge 1 ]]
}

@test "validate negative: apparmor command failure maps to container-safe INFO outcome" {
  local stubdir
  stubdir="$(mktemp -d)"
  cat > "${stubdir}/aa-status" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
  chmod +x "${stubdir}/aa-status"

  run env PATH="${stubdir}:${PATH}" bash "${VALIDATE_SCRIPT}" --json

  rm -rf "${stubdir}"
  assert_success
  [[ "$(json_status_for_check "apparmor: status")" == "INFO" ]]
}

@test "validate negative: cloudflared installed-but-inactive path triggers failure" {
  local stubdir
  stubdir="$(mktemp -d)"
  cat > "${stubdir}/cloudflared" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${stubdir}/cloudflared"

  run env PATH="${stubdir}:${PATH}" bash "${VALIDATE_SCRIPT}" --json

  rm -rf "${stubdir}"
  assert_failure
  [[ "$(json_status_for_check "cloudflared: service active")" == "FAIL" ]]
  [[ "$(json_fail_count)" -ge 1 ]]
}

@test "validate negative: coolify binding guard timer inactive triggers failure when binding enabled" {
  local state_backup
  local state_mutated
  local stubdir
  local real_systemctl

  state_backup="$(mktemp)"
  state_mutated="$(mktemp)"
  stubdir="$(mktemp -d)"
  real_systemctl="$(command -v systemctl)"

  cp "${STATE_FILE}" "${state_backup}"
  set_state_value "bind_dashboard_to_tailscale" "true" "${state_backup}" "${state_mutated}"
  cp "${state_mutated}" "${STATE_FILE}"

  cat > "${stubdir}/systemctl" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "is-active" && "${2:-}" == "--quiet" && "${3:-}" == "coolify-binding-guard.timer" ]]; then
  exit 1
fi
exec "${REAL_SYSTEMCTL}" "$@"
EOF
  chmod +x "${stubdir}/systemctl"

  run env REAL_SYSTEMCTL="${real_systemctl}" PATH="${stubdir}:${PATH}" bash "${VALIDATE_SCRIPT}" --json

  cp "${state_backup}" "${STATE_FILE}"
  rm -f "${state_backup}" "${state_mutated}"
  rm -rf "${stubdir}"
  assert_failure
  [[ "$(json_status_for_check "coolify: UFW binding-guard timer")" == "FAIL" ]]
  [[ "$(json_fail_count)" -ge 1 ]]
}

@test "validate negative: disabled service drift triggers failure" {
  local unit="/etc/systemd/system/rpcbind.service"
  local had_unit="false"
  local unit_backup=""
  local enabled_link="/etc/systemd/system/multi-user.target.wants/rpcbind.service"
  local had_link="false"
  local enabled_link_target=""

  if [[ -f "${unit}" ]]; then
    had_unit="true"
    unit_backup="$(mktemp)"
    cp "${unit}" "${unit_backup}"
  fi
  if [[ -L "${enabled_link}" ]]; then
    had_link="true"
    enabled_link_target="$(readlink "${enabled_link}" || true)"
  fi

  cat > "${unit}" <<'EOF'
[Unit]
Description=Fake rpcbind for validate negative test

[Service]
Type=oneshot
ExecStart=/bin/true

[Install]
WantedBy=multi-user.target
EOF
  mkdir -p /etc/systemd/system/multi-user.target.wants
  ln -sf "${unit}" "${enabled_link}"
  systemctl daemon-reload 2>/dev/null || true

  run bash "${VALIDATE_SCRIPT}" --json

  if [[ "${had_link}" == "true" ]]; then
    ln -sf "${enabled_link_target}" "${enabled_link}"
  else
    rm -f "${enabled_link}"
  fi
  if [[ "${had_unit}" == "true" ]]; then
    cp "${unit_backup}" "${unit}"
    rm -f "${unit_backup}"
  else
    rm -f "${unit}"
  fi
  systemctl daemon-reload 2>/dev/null || true

  assert_failure
  [[ "$(json_status_for_check "disabled: rpcbind")" == "FAIL" ]]
}

@test "validate negative: docker-user lifecycle unit missing triggers failure" {
  local unit
  local backup
  unit="/etc/systemd/system/docker-user-hardening.service"
  [[ -f "${unit}" ]] || skip "docker-user-hardening.service not present in environment"

  backup="$(mktemp)"
  cp "${unit}" "${backup}"
  rm -f "${unit}"
  systemctl daemon-reload 2>/dev/null || true

  run bash "${VALIDATE_SCRIPT}" --json

  cp "${backup}" "${unit}"
  systemctl daemon-reload 2>/dev/null || true
  rm -f "${backup}"
  assert_failure
  [[ "$(json_status_for_check "docker-user: unit file")" == "FAIL" ]]
}

@test "validate negative: expected swap without active swap maps to container-safe INFO outcome" {
  local state_backup
  local state_mutated
  local stubdir
  state_backup="$(mktemp)"
  state_mutated="$(mktemp)"
  stubdir="/workspace/.tmp-swap-stub-$$-$RANDOM"
  mkdir -p "${stubdir}"
  cp "${STATE_FILE}" "${state_backup}"
  set_state_value "swap_size" "2G" "${state_backup}" "${state_mutated}"
  cp "${state_mutated}" "${STATE_FILE}"

  cat > "${stubdir}/swapon" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
  chmod +x "${stubdir}/swapon"

  run env PATH="${stubdir}:${PATH}" bash "${VALIDATE_SCRIPT}" --json

  cp "${state_backup}" "${STATE_FILE}"
  rm -f "${state_backup}" "${state_mutated}"
  rm -rf "${stubdir}"
  assert_success
  local swap_status
  swap_status="$(jq -r '.checks[]
    | select((.check == "swap: status") or (.check | startswith("swap: active")))
    | .status' <<< "${output}" | head -1)"
  [[ "${swap_status}" == "INFO" || "${swap_status}" == "PASS" ]]
  ! jq -e '.checks[]
    | select((.check | startswith("swap:")) and .status == "FAIL")' <<< "${output}" >/dev/null
}

@test "validate negative: tailscale BackendState drift triggers failure" {
  local stubdir
  stubdir="$(mktemp -d)"
  cat > "${stubdir}/tailscale" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "status" && "${2:-}" == "--json" ]]; then
  cat <<JSON
{"BackendState":"Stopped","Peer":[]}
JSON
  exit 0
fi
if [[ "${1:-}" == "ip" && "${2:-}" == "-4" ]]; then
  exit 1
fi
exit 0
EOF
  chmod +x "${stubdir}/tailscale"

  run env PATH="${stubdir}:${PATH}" bash "${VALIDATE_SCRIPT}" --json

  rm -rf "${stubdir}"
  assert_failure
  [[ "$(json_status_for_check "tailscale: BackendState")" == "FAIL" ]]
  [[ "$(json_fail_count)" -ge 1 ]]
}

@test "validate negative: timesync drift maps to container-safe INFO outcome" {
  local stubdir
  stubdir="$(mktemp -d)"
  cat > "${stubdir}/timedatectl" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "show" && "${2:-}" == "--property=NTP" ]]; then
  echo "no"
  exit 0
fi
if [[ "${1:-}" == "show" && "${2:-}" == "--property=NTPSynchronized" ]]; then
  echo "no"
  exit 0
fi
exit 0
EOF
  chmod +x "${stubdir}/timedatectl"

  run env PATH="${stubdir}:${PATH}" bash "${VALIDATE_SCRIPT}" --json

  rm -rf "${stubdir}"
  assert_success
  [[ "$(json_status_for_check "timesync: NTP")" == "INFO" ]]
  [[ "$(json_status_for_check "timesync: NTPSynchronized")" == "INFO" ]]
}

@test "validate negative: validate timer installed but inactive triggers failure" {
  systemctl list-unit-files --no-legend hardening-validate.timer 2>/dev/null | grep -q hardening-validate \
    || skip "hardening-validate.timer not installed in this environment"
  systemctl stop hardening-validate.timer 2>/dev/null || skip "cannot stop hardening-validate.timer in this environment"
  if systemctl is-active --quiet hardening-validate.timer 2>/dev/null; then
    systemctl start hardening-validate.timer 2>/dev/null || true
    skip "hardening-validate.timer remains active after stop in this environment"
  fi

  run bash "${VALIDATE_SCRIPT}" --json

  systemctl start hardening-validate.timer 2>/dev/null || true
  assert_failure
  [[ "$(json_status_for_check "validate-timer: active")" == "FAIL" ]]
}

@test "validate negative: coolify container health triggers failure when /data/coolify exists without containers" {
  mkdir -p /data/coolify/source 2>/dev/null || skip "cannot create /data/coolify in this environment"
  cat > /data/coolify/source/.env <<'EOF'
APP_ID=test
EOF

  run bash "${VALIDATE_SCRIPT}" --json

  rm -rf /data/coolify
  assert_failure
  jq -e '
    [.checks[]
      | select((.check | startswith("coolify-containers: ")) and .status == "FAIL")
    ] | length >= 1
  ' <<< "${output}" >/dev/null
}

@test "validate negative: coolify ssh key absence triggers failure when ssh key dir exists" {
  mkdir -p /data/coolify/source /data/coolify/ssh/keys 2>/dev/null || skip "cannot create /data/coolify directories in this environment"
  cat > /data/coolify/source/.env <<'EOF'
APP_ID=test
EOF

  run bash "${VALIDATE_SCRIPT}" --json

  rm -rf /data/coolify
  assert_failure
  [[ "$(json_status_for_check "coolify: ssh key exists")" == "FAIL" ]]
}

@test "validate negative: docker trust boundary reports socket-state outcome" {
  run bash "${VALIDATE_SCRIPT}" --json
  assert_success
  jq -e '
    [.checks[] | select((.check == "docker-trust: docker") or (.check | startswith("docker-trust: socket")))] | length >= 1
  ' <<< "${output}" >/dev/null
}

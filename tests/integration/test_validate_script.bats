#!/usr/bin/env bats
# Tier 1/2 validation script tests: verify validate_hardening.sh behavior.

load '../helpers'

TEST_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyDataForValidateTests test@bats"
TEST_USER="validateadmin"
TEST_PORT="2222"
TEST_WAN="eth0"

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

@test "validate: exits 0 after hardening bootstrap" {
  run bash "${VALIDATE_SCRIPT}"
  assert_success
  assert_output --partial "Summary:"
}

@test "validate: JSON output includes expected top-level fields" {
  run bash "${VALIDATE_SCRIPT}" --json
  assert_success
  assert_output --partial '"pass":'
  assert_output --partial '"fail":'
  assert_output --partial '"checks":['
}

@test "validate: JSON output has valid structure with check entries" {
  run bash "${VALIDATE_SCRIPT}" --json
  assert_success
  assert_output --regexp '^\{"pass":[0-9]+,"fail":[0-9]+,"info":[0-9]+'
  assert_output --partial '"check":'
  assert_output --partial '"status":"PASS"'
}

@test "validate: pass count is positive after hardening" {
  run bash "${VALIDATE_SCRIPT}" --json
  assert_success
  local pass_count
  pass_count="$(echo "${output}" | grep -o '"pass":[0-9]*' | cut -d: -f2)"
  [ "${pass_count}" -gt 0 ]
}

@test "validate: state file values are reflected in output" {
  run bash "${VALIDATE_SCRIPT}"
  assert_success
  assert_output --partial "${TEST_USER}"
}

@test "validate: stopping fail2ban causes failure" {
  systemctl stop fail2ban 2>/dev/null || true

  run bash "${VALIDATE_SCRIPT}"

  # Restore before assertions
  systemctl start fail2ban 2>/dev/null || true

  assert_failure
  assert_output --partial "fail2ban"
}

@test "validate: exits non-zero when expected control is missing" {
  local backup
  backup="$(mktemp)"
  cp /etc/issue.net "${backup}"

  rm -f /etc/issue.net

  run bash "${VALIDATE_SCRIPT}"

  # Restore before assertions
  cp "${backup}" /etc/issue.net
  rm -f "${backup}"

  assert_failure
  assert_output --partial "banner: /etc/issue.net"
}

@test "validate: exits non-zero when journald persistence is disabled" {
  local journald_dropin
  local backup
  journald_dropin="/etc/systemd/journald.conf.d/60-persistent.conf"
  backup="$(mktemp)"

  cp "${journald_dropin}" "${backup}"
  cat > "${journald_dropin}" <<'EOF'
[Journal]
Storage=volatile
EOF

  run bash "${VALIDATE_SCRIPT}"

  cp "${backup}" "${journald_dropin}"
  rm -f "${backup}"

  assert_failure
  assert_output --partial "journald: persistent storage"
}

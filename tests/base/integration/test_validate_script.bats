#!/usr/bin/env bats
# Tier 1/2 validation script tests: verify base/validate.sh behavior.

load '../../helpers/helpers'

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
  run bash "${VALIDATE_SCRIPT}" --json
  assert_success
  assert_json_fail_count "${output}" "0"
}

@test "validate: JSON output includes expected top-level fields" {
  run bash "${VALIDATE_SCRIPT}" --json
  assert_success
  run jq -e 'has("pass") and has("fail") and has("info") and has("checks")' <<< "${output}"
  assert_success
}

@test "validate: JSON output has valid structure with check entries" {
  local validate_json

  run bash "${VALIDATE_SCRIPT}" --json
  assert_success
  validate_json="${output}"

  run jq -e '.pass >= 0 and .fail >= 0 and .info >= 0 and (.checks | type == "array") and (.checks | length > 0)' <<< "${validate_json}"
  assert_success
  run jq -e 'all(.checks[]; has("check") and has("status") and has("detail"))' <<< "${validate_json}"
  assert_success
}

@test "validate: pass count is positive after hardening" {
  run bash "${VALIDATE_SCRIPT}" --json
  assert_success
  local pass_count
  pass_count="$(jq -r '.pass' <<< "${output}")"
  [ "${pass_count}" -gt 0 ]
}

@test "validate: state file values are reflected in output" {
  run bash "${VALIDATE_SCRIPT}" --json
  assert_success
  assert_json_check_status "${output}" "ssh: AllowUsers includes ${TEST_USER}" "PASS"
}

@test "validate: stopping fail2ban causes failure" {
  systemctl stop fail2ban 2>/dev/null || true

  run bash "${VALIDATE_SCRIPT}" --json

  # Restore before assertions
  systemctl start fail2ban 2>/dev/null || true

  assert_failure
  assert_json_check_status "${output}" "fail2ban: active" "FAIL"
}

@test "validate: exits non-zero when expected control is missing" {
  local backup
  backup="$(mktemp)"
  cp /etc/issue.net "${backup}"

  rm -f /etc/issue.net

  run bash "${VALIDATE_SCRIPT}" --json

  # Restore before assertions
  cp "${backup}" /etc/issue.net
  rm -f "${backup}"

  assert_failure
  assert_json_check_status "${output}" "banner: /etc/issue.net" "FAIL"
}

@test "validate: exits non-zero when journald persistence is disabled" {
  local journald_dropin
  local backup
  journald_dropin="/etc/systemd/journald.conf.d/90-coolify-persistent.conf"
  backup="$(mktemp)"

  cp "${journald_dropin}" "${backup}"
  cat > "${journald_dropin}" <<'EOF'
[Journal]
Storage=volatile
EOF

  run bash "${VALIDATE_SCRIPT}" --json

  cp "${backup}" "${journald_dropin}"
  rm -f "${backup}"

  assert_failure
  assert_json_check_status "${output}" "journald: persistent storage config" "FAIL"
}

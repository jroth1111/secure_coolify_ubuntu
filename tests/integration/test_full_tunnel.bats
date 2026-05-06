#!/usr/bin/env bats
# Tier 2: Full integration tests (tunnel mode)
# Requires: --privileged Docker container with systemd as PID 1.
# Verifies --tunnel-mode inverse behavior: no WAN 80/443 rules.

load '../helpers'

TEST_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyDataForTunnelTests test@bats"
TEST_USER="tunneladmin"
TEST_PORT="2222"
TEST_WAN="eth0"

setup_file() {
  # Create dummy tailscale0 interface
  ip link add tailscale0 type dummy 2>/dev/null || true
  ip addr add 100.64.0.1/32 dev tailscale0 2>/dev/null || true
  ip link set tailscale0 up 2>/dev/null || true

  # Ensure WAN interface exists
  ip link add "${TEST_WAN}" type dummy 2>/dev/null || true
  ip link set "${TEST_WAN}" up 2>/dev/null || true

  # Wait for systemd to reach a stable state
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

  # Run the script in tunnel mode
  bash "${SCRIPT}" \
    --admin-user "${TEST_USER}" \
    --admin-pubkey "${TEST_PUBKEY}" \
    --ssh-port "${TEST_PORT}" \
    --wan-iface "${TEST_WAN}" \
    --tunnel-mode \
    --force
}

teardown_file() {
  ip link del tailscale0 2>/dev/null || true
}

iptables_usable() {
  command -v iptables >/dev/null 2>&1 || return 1
  iptables -t filter -S DOCKER-USER >/dev/null 2>&1
}

ip6tables_usable() {
  command -v ip6tables >/dev/null 2>&1 || return 1
  ip6tables -t filter -S DOCKER-USER >/dev/null 2>&1
}

@test "tunnel: no WAN port 80 UFW rule" {
  run ufw status verbose
  assert_success
  ! grep -qE "80/tcp.*on ${TEST_WAN}.*ALLOW IN" <<< "${output}"
}

@test "tunnel: no WAN port 443 UFW rule" {
  run ufw status verbose
  assert_success
  ! grep -qE "443/tcp.*on ${TEST_WAN}.*ALLOW IN" <<< "${output}"
}

@test "tunnel: SSH remains allowed on tailscale0" {
  run ufw status verbose
  assert_success
  assert_output --partial "${TEST_PORT}/tcp"
  assert_output --partial "tailscale0"
}

@test "tunnel: state file shows tunnel_mode=true" {
  run grep -q '^tunnel_mode=true$' /var/lib/server-hardening/state
  assert_success
}

@test "tunnel: report JSON shows tunnel_mode=true" {
  run jq -r '.tunnel_mode' /var/log/server-hardening-report.json
  assert_success
  assert_output "true"
}

@test "tunnel: DOCKER-USER chain has no wan-web ACCEPT rule" {
  iptables_usable || skip "iptables backend unavailable in this kernel"
  run iptables -t filter -S DOCKER-USER
  assert_success
  ! grep -q "coolify-hardening-wan-web" <<< "${output}"
}

@test "tunnel: DOCKER-USER IPv6 chain has no wan-web6 ACCEPT rule" {
  ip6tables_usable || skip "ip6tables backend unavailable in this kernel"

  run ip6tables -t filter -S DOCKER-USER
  assert_success
  ! grep -q "coolify-hardening-wan-web6" <<< "${output}"
}

@test "tunnel: tailscale direct UDP 41641 closed on WAN by default" {
  run ufw status verbose
  assert_success
  refute_output --partial "41641/udp"
}

@test "tunnel: validate JSON reports zero failures" {
  run bash "${VALIDATE_SCRIPT}" --json
  assert_success
  assert_json_fail_count "${output}" "0"
}

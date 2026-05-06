#!/usr/bin/env bats
# Tier 2 scenario matrix tests for base/bootstrap.sh (Docker-feasible variants).

load '../../helpers/helpers'

TEST_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyDataForBootstrapMatrix test@bats"
TEST_WAN="eth0"
STATE_FILE="/var/lib/server-hardening/state"
APT_LOCAL_FILE="/etc/apt/apt.conf.d/52unattended-upgrades-local"
DOCKER_DAEMON_JSON="/etc/docker/daemon.json"

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
}

teardown_file() {
  ip link del tailscale0 2>/dev/null || true
}

run_matrix_bootstrap() {
  local user="$1" ssh_port="$2"
  shift 2
  bash "${SCRIPT}" \
    --admin-user "${user}" \
    --admin-pubkey "${TEST_PUBKEY}" \
    --ssh-port "${ssh_port}" \
    --wan-iface "${TEST_WAN}" \
    --force \
    "$@"
}

assert_validate_json_passes() {
  run bash "${VALIDATE_SCRIPT}" --json
  assert_success
  assert_output --partial '"fail":0'
}

@test "bootstrap matrix: standard mode + security profile passes validate" {
  run run_matrix_bootstrap "matrixstd" "2241" --update-profile security-only --no-tailscale-direct-wan
  assert_success
  grep -q '^tunnel_mode=false' "${STATE_FILE}"
  grep -q '^tailscale_direct_wan=false' "${STATE_FILE}"
  assert_validate_json_passes
}

@test "bootstrap matrix: tunnel mode enforces no WAN 80/443 and validate passes" {
  run run_matrix_bootstrap "matrixtunnel" "2242" --tunnel-mode --compat-docker-ssh-cidrs --swap-size 512M
  assert_success
  grep -q '^tunnel_mode=true' "${STATE_FILE}"
  grep -q '^strict_docker_ssh_cidrs=false' "${STATE_FILE}"

  local ufw_output
  ufw_output="$(ufw status verbose)"
  ! grep -qE '(^|[[:space:]])80/tcp' <<< "${ufw_output}"
  ! grep -qE '(^|[[:space:]])443/tcp' <<< "${ufw_output}"
  assert_validate_json_passes
}

@test "bootstrap matrix: tailscale-direct-wan=true opens UDP 41641 on WAN and validate passes" {
  run run_matrix_bootstrap "matrixwan" "2243" --tailscale-direct-wan
  assert_success
  grep -q '^tailscale_direct_wan=true' "${STATE_FILE}"

  run ufw status verbose
  assert_success
  assert_output --partial "41641/udp"
  assert_validate_json_passes
}

@test "bootstrap matrix: custom docker nproc limits are persisted and reconciled" {
  run run_matrix_bootstrap "matrixnproc" "2244" --tailscale-direct-wan --docker-nproc-hard 16384 --docker-nproc-soft 8192
  assert_success
  grep -q '^docker_nproc_hard=16384' "${STATE_FILE}"
  grep -q '^docker_nproc_soft=8192' "${STATE_FILE}"

  if [[ -f "${DOCKER_DAEMON_JSON}" ]]; then
    run jq -r '.["default-ulimits"]["nproc"]["Hard"]' "${DOCKER_DAEMON_JSON}"
    assert_success
    assert_output "16384"
    run jq -r '.["default-ulimits"]["nproc"]["Soft"]' "${DOCKER_DAEMON_JSON}"
    assert_success
    assert_output "8192"
  fi
  assert_validate_json_passes
}

@test "bootstrap matrix: repeated non-default run stays healthy" {
  run run_matrix_bootstrap "matrixrerun" "2246" --tunnel-mode --tailscale-direct-wan
  assert_success
  run run_matrix_bootstrap "matrixrerun" "2246" --tunnel-mode --tailscale-direct-wan
  assert_success
  assert_validate_json_passes
}

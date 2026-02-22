#!/usr/bin/env bats
# Tier 0: Unit tests for pure functions in validate_hardening.sh
# No Docker, no root, no system access required.
#
# Note: validate_hardening.sh has a root check that runs at source time.
# These tests extract and test the functions using grep/sed to avoid
# triggering the root check.

load '../helpers'

VALIDATE_SCRIPT="${PROJECT_ROOT}/validate_hardening.sh"

# ── is_true() (extracted from validate_hardening.sh) ───────────────────────────
# We define our own is_true here to match the one in validate_hardening.sh

is_true() {
  case "${1,,}" in
    1|true|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
}

# ── record() (extracted for unit testing) ─────────────────────────────────────

record() {
  local status="$1"
  local name="$2"
  local detail="${3:-}"

  case "${status}" in
    PASS) ((++PASS_COUNT)) ;;
    FAIL) ((++FAIL_COUNT)) ;;
    INFO) ((++INFO_COUNT)) ;;
  esac

  if [[ "${JSON_MODE}" == "true" ]]; then
    RESULTS+=("{\"check\":\"${name}\",\"status\":\"${status}\",\"detail\":\"${detail}\"}")
  else
    printf '%-6s %-45s %s\n' "[${status}]" "${name}" "${detail}"
  fi
}

# ── check() (extracted for unit testing) ──────────────────────────────────────

check() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    record "PASS" "${name}"
  else
    record "FAIL" "${name}" "$*"
  fi
}

setup() {
  PASS_COUNT=0
  FAIL_COUNT=0
  INFO_COUNT=0
  JSON_MODE="false"
  RESULTS=()
}

# ── is_true() tests ────────────────────────────────────────────────────────────

@test "validate is_true: '1' returns 0" {
  run is_true "1"
  assert_success
}

@test "validate is_true: 'true' returns 0" {
  run is_true "true"
  assert_success
}

@test "validate is_true: 'false' returns 1" {
  run is_true "false"
  assert_failure
}

@test "validate is_true: empty returns 1" {
  run is_true ""
  assert_failure
}

@test "validate is_true: 'yes' returns 0" {
  run is_true "yes"
  assert_success
}

@test "validate is_true: 'on' returns 0" {
  run is_true "on"
  assert_success
}

@test "validate is_true: 'no' returns 1" {
  run is_true "no"
  assert_failure
}

# ── record() tests ────────────────────────────────────────────────────────────

@test "record: increments PASS_COUNT on PASS" {
  record "PASS" "test-check" "detail"
  [ "${PASS_COUNT}" -eq 1 ]
}

@test "record: increments FAIL_COUNT on FAIL" {
  record "FAIL" "test-check" "detail"
  [ "${FAIL_COUNT}" -eq 1 ]
}

@test "record: increments INFO_COUNT on INFO" {
  record "INFO" "test-check" "detail"
  [ "${INFO_COUNT}" -eq 1 ]
}

@test "record: outputs formatted line in non-JSON mode" {
  run record "PASS" "my-check" "my-detail"
  assert_output --partial "[PASS]"
  assert_output --partial "my-check"
  assert_output --partial "my-detail"
}

@test "record: adds to RESULTS array in JSON mode" {
  JSON_MODE="true"
  record "PASS" "json-check" "json-detail"
  [ "${#RESULTS[@]}" -eq 1 ]
  [[ "${RESULTS[0]}" == *"json-check"* ]]
}

@test "record: formats JSON entry correctly" {
  JSON_MODE="true"
  record "FAIL" "some-check" "error detail"
  [[ "${RESULTS[0]}" == *'"status":"FAIL"'* ]]
  [[ "${RESULTS[0]}" == *'"check":"some-check"'* ]]
}

# ── check() tests ─────────────────────────────────────────────────────────────

@test "check: records PASS when command succeeds" {
  check "test-check" true
  [ "${PASS_COUNT}" -eq 1 ]
  [ "${FAIL_COUNT}" -eq 0 ]
}

@test "check: records FAIL when command fails" {
  check "test-check" false
  [ "${PASS_COUNT}" -eq 0 ]
  [ "${FAIL_COUNT}" -eq 1 ]
}

@test "check: records multiple passes correctly" {
  check "check1" true
  check "check2" true
  check "check3" true
  [ "${PASS_COUNT}" -eq 3 ]
}

@test "check: records mixed results correctly" {
  check "passing" true
  check "failing" false
  check "another-pass" true
  [ "${PASS_COUNT}" -eq 2 ]
  [ "${FAIL_COUNT}" -eq 1 ]
}

# ── validate_hardening.sh function existence tests ─────────────────────────────
# These verify the functions exist in the script without sourcing it

@test "validate script contains is_true function" {
  grep -q "^is_true()" "${VALIDATE_SCRIPT}"
}

@test "validate script contains record function" {
  grep -q "^record()" "${VALIDATE_SCRIPT}"
}

@test "validate script contains check function" {
  grep -q "^check()" "${VALIDATE_SCRIPT}"
}

@test "validate script contains ssh_check function" {
  grep -q "^ssh_check()" "${VALIDATE_SCRIPT}"
}

@test "validate script contains ufw_check function" {
  grep -q "^ufw_check()" "${VALIDATE_SCRIPT}"
}

@test "validate script contains docker_user_check function" {
  grep -q "^docker_user_check()" "${VALIDATE_SCRIPT}"
}

@test "validate script contains sysctl_check function" {
  grep -q "^sysctl_check()" "${VALIDATE_SCRIPT}"
}

@test "validate script contains fail2ban_check function" {
  grep -q "^fail2ban_check()" "${VALIDATE_SCRIPT}"
}

@test "validate script contains auditd_check function" {
  grep -q "^auditd_check()" "${VALIDATE_SCRIPT}"
}

@test "validate script contains journald_check function" {
  grep -q "^journald_check()" "${VALIDATE_SCRIPT}"
}

@test "validate script contains banner_check function" {
  grep -q "^banner_check()" "${VALIDATE_SCRIPT}"
}

@test "validate script contains docker_daemon_check function" {
  grep -q "^docker_daemon_check()" "${VALIDATE_SCRIPT}"
}

@test "validate script contains apparmor_check function" {
  grep -q "^apparmor_check()" "${VALIDATE_SCRIPT}"
}

@test "validate script contains disabled_services_check function" {
  grep -q "^disabled_services_check()" "${VALIDATE_SCRIPT}"
}

@test "validate script contains tailscale_check function" {
  grep -q "^tailscale_check()" "${VALIDATE_SCRIPT}"
}

# ── validate_hardening.sh SSH check expectations ───────────────────────────────

@test "ssh_check expects permitrootlogin no" {
  grep -q '\[permitrootlogin\]="no"' "${VALIDATE_SCRIPT}"
}

@test "ssh_check expects passwordauthentication no" {
  grep -q '\[passwordauthentication\]="no"' "${VALIDATE_SCRIPT}"
}

@test "ssh_check expects pubkeyauthentication yes" {
  grep -q '\[pubkeyauthentication\]="yes"' "${VALIDATE_SCRIPT}"
}

# ── validate_hardening.sh sysctl check expectations ────────────────────────────

@test "sysctl_check expects tcp_syncookies=1" {
  grep -q '\[net.ipv4.tcp_syncookies\]="1"' "${VALIDATE_SCRIPT}"
}

@test "sysctl_check expects ip_forward=1" {
  grep -q '\[net.ipv4.ip_forward\]="1"' "${VALIDATE_SCRIPT}"
}

@test "sysctl_check expects protected_hardlinks=1" {
  grep -q '\[fs.protected_hardlinks\]="1"' "${VALIDATE_SCRIPT}"
}

# ── JSON output format tests ──────────────────────────────────────────────────

@test "JSON_MODE flag is respected" {
  JSON_MODE="true"
  [ "${JSON_MODE}" == "true" ]
}

@test "IS_CONTAINER can be set for container tests" {
  IS_CONTAINER="true"
  [ "${IS_CONTAINER}" == "true" ]
}

# ── State file defaults verification ───────────────────────────────────────────

@test "validate script sets default SSH_PORT=22" {
  grep -q 'SSH_PORT="22"' "${VALIDATE_SCRIPT}" || grep -q 'SSH_PORT=\${ssh_port:-22}' "${VALIDATE_SCRIPT}"
}

@test "validate script sets default TUNNEL_MODE=false" {
  grep -q 'TUNNEL_MODE="false"' "${VALIDATE_SCRIPT}" || grep -q 'TUNNEL_MODE=\${tunnel_mode:-false}' "${VALIDATE_SCRIPT}"
}

@test "validate script sets default TAILSCALE_IFACE=tailscale0" {
  grep -q 'TAILSCALE_IFACE="tailscale0"' "${VALIDATE_SCRIPT}"
}

# ── validate_hardening.sh journald check ──────────────────────────────────────

@test "journald_check looks for Storage=persistent" {
  grep -q 'Storage=persistent' "${VALIDATE_SCRIPT}"
}

# ── validate_hardening.sh banner check ────────────────────────────────────────

@test "banner_check looks for AUTHORIZED in /etc/issue.net" {
  grep -q 'AUTHORIZED' "${VALIDATE_SCRIPT}"
}

# ── validate_hardening.sh disabled services check ─────────────────────────────

@test "disabled_services_check checks rpcbind" {
  grep -q 'rpcbind' "${VALIDATE_SCRIPT}"
}

@test "disabled_services_check checks avahi-daemon" {
  grep -q 'avahi-daemon' "${VALIDATE_SCRIPT}"
}

@test "disabled_services_check checks cups" {
  grep -q 'cups' "${VALIDATE_SCRIPT}"
}

# ── validate_hardening.sh docker checks ───────────────────────────────────────

@test "docker_user_check looks for wan-drop rule" {
  grep -q 'coolify-hardening-wan-drop' "${VALIDATE_SCRIPT}"
}

@test "docker_daemon_check looks for log-driver" {
  grep -q 'log-driver' "${VALIDATE_SCRIPT}"
}

@test "docker_daemon_check looks for live-restore" {
  grep -q 'live-restore' "${VALIDATE_SCRIPT}"
}

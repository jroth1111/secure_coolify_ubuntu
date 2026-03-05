#!/usr/bin/env bats
# Runtime-focused unit tests for core validate_hardening.sh helper behavior.

load '../helpers'

setup() {
  source_validate_script
  reset_validate_runtime
}

@test "validate is_true: truthy values return success" {
  run is_true "true"
  assert_success

  run is_true "1"
  assert_success

  run is_true "yes"
  assert_success
}

@test "validate is_true: falsy values return failure" {
  run is_true "false"
  assert_failure

  run is_true "0"
  assert_failure

  run is_true ""
  assert_failure
}

@test "record: PASS status increments pass counter and stores check in JSON payload" {
  record "PASS" "record-pass" "ok"

  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "record-pass" "PASS"
  assert_json_fail_count "${json}" "0"
  [[ "$(jq -r '.pass' <<< "${json}")" == "1" ]]
}

@test "record: FAIL status increments fail counter and stores detail" {
  record "FAIL" "record-fail" "boom"

  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "record-fail" "FAIL"
  assert_json_check_detail_contains "${json}" "record-fail" "boom"
  assert_json_fail_count "${json}" "1"
}

@test "record: INFO status increments info counter" {
  record "INFO" "record-info" "heads-up"

  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "record-info" "INFO"
  [[ "$(jq -r '.info' <<< "${json}")" == "1" ]]
}

@test "check: successful command records PASS" {
  check "check-pass" true

  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "check-pass" "PASS"
  assert_json_fail_count "${json}" "0"
}

@test "check: failing command records FAIL with command detail" {
  check "check-fail" false

  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "check-fail" "FAIL"
  assert_json_check_detail_contains "${json}" "check-fail" "false"
  assert_json_fail_count "${json}" "1"
}

@test "check: mixed outcomes keep accurate aggregate counters" {
  check "a" true
  check "b" false
  check "c" true

  local json
  json="$(emit_validate_results_json)"
  [[ "$(jq -r '.pass' <<< "${json}")" == "2" ]]
  [[ "$(jq -r '.fail' <<< "${json}")" == "1" ]]
  assert_json_check_status "${json}" "b" "FAIL"
}

@test "parse_cli_args: enables JSON mode" {
  JSON_MODE="false"
  HEALTH_CHECK_MODE="false"

  parse_cli_args --json

  [ "${JSON_MODE}" = "true" ]
  [ "${HEALTH_CHECK_MODE}" = "false" ]
}

@test "parse_cli_args: enables health-check mode" {
  JSON_MODE="false"
  HEALTH_CHECK_MODE="false"

  parse_cli_args --health-check

  [ "${HEALTH_CHECK_MODE}" = "true" ]
  [ "${JSON_MODE}" = "false" ]
}

@test "parse_cli_args: rejects mutually exclusive --json and --health-check" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    parse_cli_args --json --health-check
  '
  assert_failure
  assert_output --partial "mutually exclusive"
}

@test "parse_cli_args: rejects unknown flags" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    parse_cli_args --bogus
  '
  assert_failure
  assert_output --partial "unknown option"
}

@test "detect_container_runtime: flags docker runtime via container variable" {
  container="docker"

  detect_container_runtime

  [ "${IS_CONTAINER}" = "true" ]
}

@test "regex_escape: escapes regex metacharacters" {
  run regex_escape 'a.b[c]\\d+$'
  assert_success
  assert_output 'a\.b\[c\]\\d\+\$'
}

@test "load_docker_ssh_cidrs: emits de-duplicated CIDRs in declaration order" {
  DOCKER_SSH_CIDRS='10.0.0.0/8, 172.16.0.0/12,10.0.0.0/8'
  STRICT_DOCKER_SSH_CIDRS='false'

  run load_docker_ssh_cidrs
  assert_success
  assert_line --index 0 '10.0.0.0/8'
  assert_line --index 1 '172.16.0.0/12'
}

@test "infer_update_profile: returns balanced when updates origin is present" {
  local apt_local
  apt_local="$(mktemp)"
  printf '"origin=Ubuntu,codename=${distro_codename}-updates,label=Ubuntu";\n' > "${apt_local}"

  run infer_update_profile "${apt_local}"
  assert_success
  assert_output 'balanced'

  rm -f "${apt_local}"
}

@test "infer_update_profile: returns security-only when only security origin is present" {
  local apt_local
  apt_local="$(mktemp)"
  printf '"origin=Ubuntu,codename=${distro_codename}-security,label=Ubuntu";\n' > "${apt_local}"

  run infer_update_profile "${apt_local}"
  assert_success
  assert_output 'security-only'

  rm -f "${apt_local}"
}

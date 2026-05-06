#!/usr/bin/env bats

load '../../helpers/helpers'

HARNESS_SCRIPT="${PROJECT_ROOT}/scripts/run_token_edge_matrix.sh"

@test "token edge harness: help output is available" {
  run "${HARNESS_SCRIPT}" --help
  assert_success
  assert_output --partial "run_token_edge_matrix.sh"
  assert_output --partial "precondition failures"
}

@test "token edge harness: classifies root failure as precondition" {
  run bash -c '
    source "'"${HARNESS_SCRIPT}"'"
    cls="$(classify_failure_class "FATAL: This script must be run as root (use sudo).")"
    [[ "${cls}" == "precondition" ]]
  '
  assert_success
}

@test "token edge harness: classifies token failure as behavior" {
  run bash -c '
    source "'"${HARNESS_SCRIPT}"'"
    cls="$(classify_failure_class "FATAL: Cloudflare API token verification failed.")"
    [[ "${cls}" == "behavior" ]]
  '
  assert_success
}

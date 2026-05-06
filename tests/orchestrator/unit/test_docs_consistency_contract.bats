#!/usr/bin/env bats
# Tier 0: Contract tests for workflow consistency docs/checker

load '../../helpers/helpers'

CONTRACT_FILE="${PROJECT_ROOT}/docs/workflow_contract.yaml"
CHECKER_SCRIPT="${PROJECT_ROOT}/scripts/check_workflow_consistency.sh"
FUNCTION_COVERAGE_CHECKER="${PROJECT_ROOT}/scripts/check_function_behavior_coverage.sh"
LOGIC_STEP_CONTRACT_FILE="${PROJECT_ROOT}/docs/logic_step_contract.yaml"
LOGIC_STEP_CHECKER="${PROJECT_ROOT}/scripts/check_logic_step_coverage.sh"
BATS_TARGET_COVERAGE_CHECKER="${PROJECT_ROOT}/scripts/check_bats_target_coverage.sh"

@test "docs consistency: workflow contract file exists" {
  [ -f "${CONTRACT_FILE}" ]
}

@test "docs consistency: contract contains bootstrap ids" {
  grep -Fq "HB-01" "${CONTRACT_FILE}"
  grep -Fq "HB-15" "${CONTRACT_FILE}"
}

@test "docs consistency: contract contains deploy and setup ids" {
  grep -Fq "DEP-01" "${CONTRACT_FILE}"
  grep -Fq "DEP-10" "${CONTRACT_FILE}"
  grep -Fq "SET-01" "${CONTRACT_FILE}"
  grep -Fq "SET-09" "${CONTRACT_FILE}"
}

@test "docs consistency: checker script exists" {
  [ -f "${CHECKER_SCRIPT}" ]
}

@test "docs consistency: checker script passes" {
  run bash "${CHECKER_SCRIPT}"
  assert_success
  assert_output --partial "Workflow consistency check passed"
}

@test "docs consistency: function behavior coverage checker exists" {
  [ -f "${FUNCTION_COVERAGE_CHECKER}" ]
}

@test "docs consistency: function behavior coverage checker passes" {
  run bash "${FUNCTION_COVERAGE_CHECKER}"
  assert_success
  assert_output --partial "Function behavior coverage summary:"
}

@test "docs consistency: logic-step contract file exists" {
  [ -f "${LOGIC_STEP_CONTRACT_FILE}" ]
}

@test "docs consistency: logic-step coverage checker exists" {
  [ -f "${LOGIC_STEP_CHECKER}" ]
}

@test "docs consistency: logic-step coverage checker passes" {
  run bash "${LOGIC_STEP_CHECKER}"
  assert_success
  assert_output --partial "Logic-step coverage check passed."
}

@test "docs consistency: bats target coverage checker exists" {
  [ -f "${BATS_TARGET_COVERAGE_CHECKER}" ]
}

@test "docs consistency: bats target coverage checker passes" {
  run bash "${BATS_TARGET_COVERAGE_CHECKER}"
  assert_success
  assert_output --partial "BATS target coverage check passed."
}

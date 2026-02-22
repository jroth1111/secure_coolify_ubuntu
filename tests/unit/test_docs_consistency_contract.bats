#!/usr/bin/env bats
# Tier 0: Contract tests for workflow consistency docs/checker

load '../helpers'

CONTRACT_FILE="${PROJECT_ROOT}/docs/workflow_contract.yaml"
CHECKER_SCRIPT="${PROJECT_ROOT}/scripts/check_workflow_consistency.sh"

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

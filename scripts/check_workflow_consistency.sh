#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONTRACT_FILE="${REPO_ROOT}/docs/workflow_contract.yaml"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

[[ -f "${CONTRACT_FILE}" ]] || die "Contract file not found: ${CONTRACT_FILE}"

section=""
step_count=0
check_count=0
error_count=0
declare -A seen_ids=()
declare -A workflow_counts=()

report_error() {
  printf 'FAIL: %s\n' "$*" >&2
  error_count=$((error_count + 1))
}

assert_file_contains() {
  local rel_path="$1"
  local needle="$2"
  local abs_path="${REPO_ROOT}/${rel_path}"

  if [[ ! -f "${abs_path}" ]]; then
    report_error "missing file '${rel_path}'"
    return
  fi

  if ! grep -Fq -- "${needle}" "${abs_path}"; then
    report_error "expected '${needle}' in '${rel_path}'"
  fi
}

assert_test_exists() {
  local rel_path="$1"
  local test_title="$2"
  local abs_path="${REPO_ROOT}/${rel_path}"
  local signature="@test \"${test_title}\""

  if [[ ! -f "${abs_path}" ]]; then
    report_error "missing test file '${rel_path}'"
    return
  fi

  if ! grep -Fq -- "${signature}" "${abs_path}"; then
    report_error "missing test '${test_title}' in '${rel_path}'"
  fi
}

while IFS= read -r raw_line || [[ -n "${raw_line}" ]]; do
  case "${raw_line}" in
    steps:)
      section="steps"
      continue
      ;;
    consistency_checks:)
      section="checks"
      continue
      ;;
    '  - "'*'"')
      entry="${raw_line#  - \"}"
      entry="${entry%\"}"
      ;;
    *)
      continue
      ;;
  esac

  if [[ "${section}" == "steps" ]]; then
    step_count=$((step_count + 1))
    IFS='|' read -r step_id workflow_id script_path script_anchor doc_path doc_anchor test_refs <<< "${entry}"

    if [[ -z "${step_id}" || -z "${workflow_id}" || -z "${script_path}" || -z "${script_anchor}" || -z "${doc_path}" || -z "${doc_anchor}" || -z "${test_refs}" ]]; then
      report_error "malformed step contract entry: ${entry}"
      continue
    fi

    if [[ -n "${seen_ids[${step_id}]:-}" ]]; then
      report_error "duplicate contract step id '${step_id}'"
    fi
    seen_ids["${step_id}"]=1
    workflow_counts["${workflow_id}"]=$((workflow_counts["${workflow_id}"] + 1))

    assert_file_contains "${script_path}" "${script_anchor}"
    assert_file_contains "${doc_path}" "${doc_anchor}"

    IFS=';' read -r -a refs <<< "${test_refs}"
    if [[ "${#refs[@]}" -eq 0 ]]; then
      report_error "step '${step_id}' has no test refs"
    fi

    for ref in "${refs[@]}"; do
      test_file="${ref%%::*}"
      test_title="${ref#*::}"
      if [[ -z "${test_file}" || -z "${test_title}" || "${test_file}" == "${test_title}" ]]; then
        report_error "malformed test ref '${ref}' in step '${step_id}'"
        continue
      fi
      assert_test_exists "${test_file}" "${test_title}"
    done
  elif [[ "${section}" == "checks" ]]; then
    check_count=$((check_count + 1))
    IFS='|' read -r target_path expected_text <<< "${entry}"
    if [[ -z "${target_path}" || -z "${expected_text}" ]]; then
      report_error "malformed consistency check entry: ${entry}"
      continue
    fi
    assert_file_contains "${target_path}" "${expected_text}"
  fi
done < "${CONTRACT_FILE}"

if [[ ${step_count} -lt 20 ]]; then
  report_error "expected at least 20 contract step entries; found ${step_count}"
fi

if [[ ${check_count} -lt 5 ]]; then
  report_error "expected at least 5 consistency checks; found ${check_count}"
fi

for expected_workflow in bootstrap deploy setup; do
  if [[ "${workflow_counts[${expected_workflow}]:-0}" -eq 0 ]]; then
    report_error "no contract steps found for workflow '${expected_workflow}'"
  fi
done

if [[ ${error_count} -gt 0 ]]; then
  printf '\nWorkflow consistency check failed: %d issue(s)\n' "${error_count}" >&2
  exit 1
fi

printf 'Workflow consistency check passed. steps=%d checks=%d\n' "${step_count}" "${check_count}"

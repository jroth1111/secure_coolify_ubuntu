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

step_count=0
check_count=0
error_count=0
declare -A seen_ids=()
declare -A workflow_counts=()
EXPECTED_STEP_COUNT=34
EXPECTED_CHECK_COUNT=7

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

emit_contract_entries() {
  python3 - "${CONTRACT_FILE}" <<'PY'
import sys
try:
    import yaml
except ModuleNotFoundError:
    print("ERROR: python3 package 'yaml' (PyYAML) is required to parse workflow_contract.yaml", file=sys.stderr)
    sys.exit(2)

path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
except Exception as exc:
    print(f"ERROR: failed to parse YAML: {exc}", file=sys.stderr)
    sys.exit(2)

if not isinstance(data, dict):
    print("ERROR: workflow contract root must be a YAML mapping/object", file=sys.stderr)
    sys.exit(2)

steps = data.get("steps")
checks = data.get("consistency_checks")
if not isinstance(steps, list):
    print("ERROR: 'steps' must be a YAML list", file=sys.stderr)
    sys.exit(2)
if not isinstance(checks, list):
    print("ERROR: 'consistency_checks' must be a YAML list", file=sys.stderr)
    sys.exit(2)

for entry in steps:
    if not isinstance(entry, str):
        print(f"ERROR: non-string entry in steps: {entry!r}", file=sys.stderr)
        sys.exit(2)
    print(f"STEP\t{entry}")

for entry in checks:
    if not isinstance(entry, str):
        print(f"ERROR: non-string entry in consistency_checks: {entry!r}", file=sys.stderr)
        sys.exit(2)
    print(f"CHECK\t{entry}")
PY
}

contract_entries="$(emit_contract_entries)" || die "Failed to parse ${CONTRACT_FILE}"

while IFS=$'\t' read -r entry_type entry || [[ -n "${entry_type}" ]]; do
  if [[ "${entry_type}" == "STEP" ]]; then
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
  elif [[ "${entry_type}" == "CHECK" ]]; then
    check_count=$((check_count + 1))
    IFS='|' read -r target_path expected_text <<< "${entry}"
    if [[ -z "${target_path}" || -z "${expected_text}" ]]; then
      report_error "malformed consistency check entry: ${entry}"
      continue
    fi
    assert_file_contains "${target_path}" "${expected_text}"
  else
    report_error "unexpected parser record type '${entry_type}'"
  fi
done <<< "${contract_entries}"

if [[ ${step_count} -ne ${EXPECTED_STEP_COUNT} ]]; then
  report_error "expected exactly ${EXPECTED_STEP_COUNT} contract step entries; found ${step_count}"
fi

if [[ ${check_count} -ne ${EXPECTED_CHECK_COUNT} ]]; then
  report_error "expected exactly ${EXPECTED_CHECK_COUNT} consistency checks; found ${check_count}"
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

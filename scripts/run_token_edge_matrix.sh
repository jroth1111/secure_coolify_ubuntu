#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DEPLOY_SCRIPT="${REPO_ROOT}/deploy.sh"
SETUP_SCRIPT="${REPO_ROOT}/setup.sh"
DOMAIN=""
SERVER_IP="203.0.113.10"
ADMIN_USER="coolifyadmin"
PUBKEY_FILE="${HOME}/.ssh/id_ed25519.pub"
GOOD_API_TOKEN_FILE=""
GOOD_TUNNEL_TOKEN_FILE=""
BAD_API_TOKEN_FILE=""
BAD_TUNNEL_TOKEN_FILE=""
LOG_FILE=""

PASS_COUNT=0
MISMATCH_COUNT=0
PRECONDITION_COUNT=0

usage() {
  cat <<'EOF'
run_token_edge_matrix.sh — Token edge-case harness for deploy.sh and setup.sh

Runs preflight-only token scenarios and separates:
- behavior failures (true logic mismatches)
- environment precondition failures (root/sudo/missing deps/files)

Usage:
  scripts/run_token_edge_matrix.sh [options]

Required:
  --domain <fqdn>
  --good-api-token-file <path>

Optional:
  --good-tunnel-token-file <path>  Tunnel token file (defaults to API token file)
  --bad-api-token-file <path>      Bad API token file (defaults to generated invalid token)
  --bad-tunnel-token-file <path>   Bad tunnel token file (defaults to generated invalid token)
  --server-ip <ip>                 Synthetic server IP for preflight args (default: 203.0.113.10)
  --admin-user <name>              Admin user for setup preflight (default: coolifyadmin)
  --pubkey-file <path>             Public key used for validation (default: ~/.ssh/id_ed25519.pub)
  --deploy-script <path>           Override deploy.sh path
  --setup-script <path>            Override setup.sh path
  --log-file <path>                Output log path (default: artifacts/live-run/token-edge-matrix-<utc>.log)
  -h, --help                       Show this help

Exit codes:
  0  All behavior expectations matched, no precondition failures
  1  One or more behavior mismatches
  2  No behavior mismatches, but one or more precondition failures
EOF
}

die() {
  printf 'FATAL: %s\n' "$*" >&2
  exit 1
}

require_file() {
  local path="$1" label="$2"
  [[ -f "${path}" ]] || die "${label} not found: ${path}"
}

classify_failure_class() {
  local output="$1"
  if printf '%s' "${output}" | grep -Eiq \
    'must be run as root|use sudo|permission denied|required command not found|public key file not found|private key not found|invalid ssh public key|no such file or directory'; then
    printf 'precondition'
  else
    printf 'behavior'
  fi
}

extract_signal_line() {
  local output="$1"
  local line
  line="$(printf '%s\n' "${output}" | grep -E -m1 'FATAL:|FAIL|PASS' || true)"
  if [[ -z "${line}" ]]; then
    line="$(printf '%s\n' "${output}" | awk 'NF { print; exit }')"
  fi
  line="${line//$'\t'/ }"
  printf '%s' "${line}"
}

run_case() {
  local script="$1" case_id="$2" expect="$3" description="$4"
  shift 4
  [[ "${1:-}" == "--" ]] || die "run_case internal error: missing -- separator"
  shift
  local -a cmd=("$@")

  local output exit_code result class signal
  set +e
  output="$("${cmd[@]}" 2>&1)"
  exit_code=$?
  set -e

  if (( exit_code == 0 )); then
    result="pass"
    class="behavior"
  else
    class="$(classify_failure_class "${output}")"
    if [[ "${class}" == "precondition" ]]; then
      result="precondition_fail"
    else
      result="fail"
    fi
  fi

  signal="$(extract_signal_line "${output}")"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${script}" "${case_id}" "${expect}" "${result}" "${class}" "${exit_code}" "${signal}" >> "${LOG_FILE}"

  if [[ "${class}" == "precondition" ]]; then
    PRECONDITION_COUNT=$((PRECONDITION_COUNT + 1))
    return 0
  fi

  if [[ "${expect}" == "pass" && "${result}" == "pass" ]]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    return 0
  fi
  if [[ "${expect}" == "fail" && "${result}" == "fail" ]]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    return 0
  fi

  MISMATCH_COUNT=$((MISMATCH_COUNT + 1))
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --domain) DOMAIN="${2:?--domain requires a value}"; shift 2 ;;
      --server-ip) SERVER_IP="${2:?--server-ip requires a value}"; shift 2 ;;
      --admin-user) ADMIN_USER="${2:?--admin-user requires a value}"; shift 2 ;;
      --pubkey-file) PUBKEY_FILE="${2:?--pubkey-file requires a value}"; shift 2 ;;
      --good-api-token-file) GOOD_API_TOKEN_FILE="${2:?--good-api-token-file requires a value}"; shift 2 ;;
      --good-tunnel-token-file) GOOD_TUNNEL_TOKEN_FILE="${2:?--good-tunnel-token-file requires a value}"; shift 2 ;;
      --bad-api-token-file) BAD_API_TOKEN_FILE="${2:?--bad-api-token-file requires a value}"; shift 2 ;;
      --bad-tunnel-token-file) BAD_TUNNEL_TOKEN_FILE="${2:?--bad-tunnel-token-file requires a value}"; shift 2 ;;
      --deploy-script) DEPLOY_SCRIPT="${2:?--deploy-script requires a value}"; shift 2 ;;
      --setup-script) SETUP_SCRIPT="${2:?--setup-script requires a value}"; shift 2 ;;
      --log-file) LOG_FILE="${2:?--log-file requires a value}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown option: $1 (use --help)" ;;
    esac
  done
}

main() {
  parse_args "$@"

  [[ -n "${DOMAIN}" ]] || die "--domain is required"
  [[ -n "${GOOD_API_TOKEN_FILE}" ]] || die "--good-api-token-file is required"
  require_file "${DEPLOY_SCRIPT}" "deploy script"
  require_file "${SETUP_SCRIPT}" "setup script"
  require_file "${GOOD_API_TOKEN_FILE}" "good API token file"
  require_file "${PUBKEY_FILE}" "public key file"

  if [[ -z "${GOOD_TUNNEL_TOKEN_FILE}" ]]; then
    GOOD_TUNNEL_TOKEN_FILE="${GOOD_API_TOKEN_FILE}"
  else
    require_file "${GOOD_TUNNEL_TOKEN_FILE}" "good tunnel token file"
  fi

  local tmp_dir
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "'"${tmp_dir}"'"' EXIT

  if [[ -z "${BAD_API_TOKEN_FILE}" ]]; then
    BAD_API_TOKEN_FILE="${tmp_dir}/bad_api.token"
    printf '%s' 'invalid-api-token-value' > "${BAD_API_TOKEN_FILE}"
    chmod 600 "${BAD_API_TOKEN_FILE}"
  else
    require_file "${BAD_API_TOKEN_FILE}" "bad API token file"
  fi
  if [[ -z "${BAD_TUNNEL_TOKEN_FILE}" ]]; then
    BAD_TUNNEL_TOKEN_FILE="${tmp_dir}/bad_tunnel.token"
    printf '%s' 'invalid-tunnel-token-value' > "${BAD_TUNNEL_TOKEN_FILE}"
    chmod 600 "${BAD_TUNNEL_TOKEN_FILE}"
  else
    require_file "${BAD_TUNNEL_TOKEN_FILE}" "bad tunnel token file"
  fi

  if [[ -z "${LOG_FILE}" ]]; then
    local ts
    ts="$(date -u '+%Y%m%d-%H%M%S')"
    LOG_FILE="${REPO_ROOT}/artifacts/live-run/token-edge-matrix-${ts}.log"
  fi
  mkdir -p "$(dirname "${LOG_FILE}")"

  {
    printf '[STEP] log_file=%s\n' "${LOG_FILE}"
    printf '[STEP] cwd=%s\n' "${REPO_ROOT}"
    printf 'script\tcase\texpect\tresult\tclass\texit\tsignal\n'
  } > "${LOG_FILE}"

  local -a deploy_base setup_base
  deploy_base=(
    bash "${DEPLOY_SCRIPT}"
    --server-ip "${SERVER_IP}"
    --admin-user "${ADMIN_USER}"
    --pubkey-file "${PUBKEY_FILE}"
    --domain "${DOMAIN}"
    --preflight-only
    --yes
  )
  setup_base=(
    bash "${SETUP_SCRIPT}"
    --server-ip "${SERVER_IP}"
    --admin-user "${ADMIN_USER}"
    --pubkey-file "${PUBKEY_FILE}"
    --domain "${DOMAIN}"
    --preflight-only
    --yes
  )

  # deploy.sh scenarios
  run_case deploy D1_tunnel_split_both pass "tunnel mode, explicit api+tunnel files" -- \
    "${deploy_base[@]}" --mode tunnel --cf-api-token-file "${GOOD_API_TOKEN_FILE}" --cf-tunnel-api-token-file "${GOOD_TUNNEL_TOKEN_FILE}"
  run_case deploy D2_tunnel_api_fallback pass "tunnel mode, api file only (fallback tunnel token)" -- \
    "${deploy_base[@]}" --mode tunnel --cf-api-token-file "${GOOD_API_TOKEN_FILE}"
  run_case deploy D3_standard_bad_tunnel_ignored pass "standard mode ignores tunnel token" -- \
    "${deploy_base[@]}" --mode standard --cf-api-token-file "${GOOD_API_TOKEN_FILE}" --cf-tunnel-api-token-file "${BAD_TUNNEL_TOKEN_FILE}"
  run_case deploy D4_tunnel_bad_tunnel fail "tunnel mode rejects invalid tunnel token" -- \
    "${deploy_base[@]}" --mode tunnel --cf-api-token-file "${GOOD_API_TOKEN_FILE}" --cf-tunnel-api-token-file "${BAD_TUNNEL_TOKEN_FILE}"
  run_case deploy D5_tunnel_bad_api fail "tunnel mode rejects invalid API token" -- \
    "${deploy_base[@]}" --mode tunnel --cf-api-token-file "${BAD_API_TOKEN_FILE}" --cf-tunnel-api-token-file "${GOOD_TUNNEL_TOKEN_FILE}"
  run_case deploy D6_tunnel_missing_api fail "tunnel mode requires API token input" -- \
    env -u CF_API_TOKEN -u CF_TUNNEL_API_TOKEN "${deploy_base[@]}" --mode tunnel
  run_case deploy D7_tunnel_bad_zone fail "tunnel mode rejects non-existent zone override" -- \
    "${deploy_base[@]}" --mode tunnel --cf-api-token-file "${GOOD_API_TOKEN_FILE}" --cf-zone "nonexistent.invalid"

  # setup.sh scenarios
  run_case setup S1_tunnel_split_both pass "tunnel mode, explicit api+tunnel files" -- \
    "${setup_base[@]}" --mode tunnel --cf-api-token-file "${GOOD_API_TOKEN_FILE}" --cf-tunnel-api-token-file "${GOOD_TUNNEL_TOKEN_FILE}"
  run_case setup S2_tunnel_api_fallback pass "tunnel mode, api file only (fallback tunnel token)" -- \
    "${setup_base[@]}" --mode tunnel --cf-api-token-file "${GOOD_API_TOKEN_FILE}"
  run_case setup S3_standard_bad_tunnel_ignored pass "standard mode ignores tunnel token" -- \
    "${setup_base[@]}" --mode standard --cf-api-token-file "${GOOD_API_TOKEN_FILE}" --cf-tunnel-api-token-file "${BAD_TUNNEL_TOKEN_FILE}"
  run_case setup S4_tunnel_bad_tunnel fail "tunnel mode rejects invalid tunnel token" -- \
    "${setup_base[@]}" --mode tunnel --cf-api-token-file "${GOOD_API_TOKEN_FILE}" --cf-tunnel-api-token-file "${BAD_TUNNEL_TOKEN_FILE}"
  run_case setup S5_tunnel_bad_api fail "tunnel mode rejects invalid API token" -- \
    "${setup_base[@]}" --mode tunnel --cf-api-token-file "${BAD_API_TOKEN_FILE}" --cf-tunnel-api-token-file "${GOOD_TUNNEL_TOKEN_FILE}"
  run_case setup S6_tunnel_missing_api fail "tunnel mode requires API token input" -- \
    env -u CF_API_TOKEN -u CF_TUNNEL_API_TOKEN "${setup_base[@]}" --mode tunnel
  run_case setup S7_tunnel_bad_zone fail "tunnel mode rejects non-existent zone override" -- \
    "${setup_base[@]}" --mode tunnel --cf-api-token-file "${GOOD_API_TOKEN_FILE}" --cf-zone "nonexistent.invalid"

  {
    printf '[SUMMARY] pass=%d mismatch=%d precondition=%d\n' "${PASS_COUNT}" "${MISMATCH_COUNT}" "${PRECONDITION_COUNT}"
  } >> "${LOG_FILE}"

  printf 'Token matrix complete: pass=%d mismatch=%d precondition=%d\n' "${PASS_COUNT}" "${MISMATCH_COUNT}" "${PRECONDITION_COUNT}"
  printf 'Log: %s\n' "${LOG_FILE}"

  if (( MISMATCH_COUNT > 0 )); then
    exit 1
  fi
  if (( PRECONDITION_COUNT > 0 )); then
    exit 2
  fi
  exit 0
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi

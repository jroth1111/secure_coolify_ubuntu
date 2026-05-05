#!/usr/bin/env bash
# lib/common.sh — Generic helpers shared across orchestrators and overlays.
# Source this file; do not execute it directly.
# Requires: set -Eeuo pipefail in the caller.

[[ "${BASH_SOURCE[0]}" != "${0}" ]] \
  || { printf 'Source this file, do not execute it.\n' >&2; exit 1; }
if [[ -z "${BASH_VERSINFO:-}" || "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  printf 'Bash 4+ is required (found %s). On macOS use Homebrew bash and run via its absolute path.\n' "${BASH_VERSION:-unknown}" >&2
  return 1
fi
[[ -z "${_LIB_COMMON_LOADED:-}" ]] || return 0
_LIB_COMMON_LOADED=1

# ── Regex patterns ──────────────────────────────────────────────────────────

IPV4_RE='^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
LINUX_USER_RE='^[a-z_][a-z0-9_-]*$'
FQDN_RE='^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
SWAP_RE='^[0-9]+[GM]$'
CF_ID_RE='^[a-f0-9]{32}$'
TIMEZONE_RE='^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$'

# ── Helpers ─────────────────────────────────────────────────────────────────

utc_now() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
local_tz_offset() {
  local raw
  raw="$(date '+%z')"
  printf '%s:%s' "${raw:0:3}" "${raw:3:2}"
}

# ── Structured run report state (opt-in via run_report_init) ────────────────

RUN_REPORT_ENABLED="${RUN_REPORT_ENABLED:-true}"
RUN_REPORT_ACTIVE="false"
RUN_REPORT_FILE="${RUN_REPORT_FILE:-}"
RUN_REPORT_SCRIPT=""
RUN_REPORT_START_EPOCH=""
RUN_REPORT_START_UTC=""
RUN_REPORT_LOCAL_OFFSET=""
RUN_REPORT_CURRENT_STEP_ID=""
RUN_REPORT_CURRENT_STEP_NAME=""
RUN_REPORT_CURRENT_STEP_START_EPOCH=""
RUN_REPORT_CURRENT_STEP_START_UTC=""
RUN_REPORT_STEPS_JSON=""
RUN_REPORT_GATES_JSON=""
RUN_REPORT_ROOT_CAUSE=""
RUN_REPORT_FINALIZED="false"

run_report_close_current_step() {
  local status="$1" root_cause="${2:-}"
  [[ "${RUN_REPORT_ACTIVE:-false}" == "true" ]] || return 0
  [[ -n "${RUN_REPORT_CURRENT_STEP_ID:-}" ]] || return 0

  local end_epoch end_utc duration step_json
  end_epoch="$(date '+%s')"
  end_utc="$(utc_now)"
  duration="$(( end_epoch - RUN_REPORT_CURRENT_STEP_START_EPOCH ))"

  step_json="$(jq -cn \
    --arg id "${RUN_REPORT_CURRENT_STEP_ID}" \
    --arg name "${RUN_REPORT_CURRENT_STEP_NAME}" \
    --arg status "${status}" \
    --arg started "${RUN_REPORT_CURRENT_STEP_START_UTC}" \
    --arg ended "${end_utc}" \
    --arg root "${root_cause}" \
    --argjson duration "${duration}" \
    '{
      id:$id,
      name:$name,
      status:$status,
      started_at_utc:$started,
      ended_at_utc:$ended,
      duration_seconds:$duration,
      root_cause:(if $root == "" then null else $root end)
    }')"
  RUN_REPORT_STEPS_JSON+="${step_json}"$'\n'

  RUN_REPORT_CURRENT_STEP_ID=""
  RUN_REPORT_CURRENT_STEP_NAME=""
  RUN_REPORT_CURRENT_STEP_START_EPOCH=""
  RUN_REPORT_CURRENT_STEP_START_UTC=""
}

run_report_step_start() {
  local id="$1" name="$2"
  [[ "${RUN_REPORT_ACTIVE:-false}" == "true" ]] || return 0

  run_report_close_current_step "pass" ""
  RUN_REPORT_CURRENT_STEP_ID="${id}"
  RUN_REPORT_CURRENT_STEP_NAME="${name}"
  RUN_REPORT_CURRENT_STEP_START_EPOCH="$(date '+%s')"
  RUN_REPORT_CURRENT_STEP_START_UTC="$(utc_now)"
}

run_report_record_gate() {
  local status="$1" message="$2"
  [[ "${RUN_REPORT_ACTIVE:-false}" == "true" ]] || return 0
  [[ "${message}" == Gate\ *:* ]] || return 0

  local gate_id gate_json
  gate_id="${message%%:*}"
  gate_json="$(jq -cn \
    --arg gate "${gate_id}" \
    --arg status "${status}" \
    --arg detail "${message}" \
    --arg ts "$(utc_now)" \
    '{
      gate:$gate,
      status:$status,
      detail:$detail,
      timestamp_utc:$ts
    }')"
  RUN_REPORT_GATES_JSON+="${gate_json}"$'\n'
}

run_report_init() {
  local script_name="$1"
  [[ "${RUN_REPORT_ENABLED:-true}" == "true" ]] || return 0
  command -v jq >/dev/null 2>&1 || return 0

  local report_file="${RUN_REPORT_FILE:-}"
  if [[ -z "${report_file}" ]]; then
    local report_dir ts
    report_dir="${RUN_REPORT_DIR:-${PWD}/artifacts/live-run}"
    mkdir -p "${report_dir}" 2>/dev/null || true
    if [[ ! -d "${report_dir}" ]]; then
      report_dir="/tmp/secure-coolify-runs"
      mkdir -p "${report_dir}" 2>/dev/null || true
    fi
    [[ -d "${report_dir}" ]] || return 0
    ts="$(date -u '+%Y%m%d-%H%M%S')"
    report_file="${report_dir}/${script_name%.sh}-run-${ts}-$$.json"
  else
    mkdir -p "$(dirname "${report_file}")" 2>/dev/null || true
  fi

  RUN_REPORT_FILE="${report_file}"
  RUN_REPORT_SCRIPT="${script_name}"
  RUN_REPORT_START_EPOCH="$(date '+%s')"
  RUN_REPORT_START_UTC="$(utc_now)"
  RUN_REPORT_LOCAL_OFFSET="$(local_tz_offset)"
  RUN_REPORT_CURRENT_STEP_ID=""
  RUN_REPORT_CURRENT_STEP_NAME=""
  RUN_REPORT_CURRENT_STEP_START_EPOCH=""
  RUN_REPORT_CURRENT_STEP_START_UTC=""
  RUN_REPORT_STEPS_JSON=""
  RUN_REPORT_GATES_JSON=""
  RUN_REPORT_ROOT_CAUSE=""
  RUN_REPORT_FINALIZED="false"
  RUN_REPORT_ACTIVE="true"
  log "Run report file: ${RUN_REPORT_FILE}"
}

run_report_finalize() {
  local exit_code="${1:-0}"
  [[ "${RUN_REPORT_ACTIVE:-false}" == "true" ]] || return 0
  [[ "${RUN_REPORT_FINALIZED:-false}" == "true" ]] && return 0
  RUN_REPORT_FINALIZED="true"

  local status="pass"
  if (( exit_code != 0 )); then
    status="fail"
  fi

  if [[ "${status}" == "fail" && -z "${RUN_REPORT_ROOT_CAUSE:-}" ]]; then
    RUN_REPORT_ROOT_CAUSE="Deployment failed; inspect terminal output for details."
  fi
  run_report_close_current_step "${status}" "${RUN_REPORT_ROOT_CAUSE:-}"

  local end_epoch end_utc duration steps_json gates_json report_json
  end_epoch="$(date '+%s')"
  end_utc="$(utc_now)"
  duration="$(( end_epoch - RUN_REPORT_START_EPOCH ))"

  if [[ -n "${RUN_REPORT_STEPS_JSON}" ]]; then
    steps_json="$(printf '%s' "${RUN_REPORT_STEPS_JSON}" | jq -s '.')"
  else
    steps_json='[]'
  fi
  if [[ -n "${RUN_REPORT_GATES_JSON}" ]]; then
    gates_json="$(printf '%s' "${RUN_REPORT_GATES_JSON}" | jq -s '.')"
  else
    gates_json='[]'
  fi

  report_json="$(jq -cn \
    --arg script "${RUN_REPORT_SCRIPT}" \
    --arg status "${status}" \
    --arg started "${RUN_REPORT_START_UTC}" \
    --arg ended "${end_utc}" \
    --arg local_offset "${RUN_REPORT_LOCAL_OFFSET}" \
    --arg root "${RUN_REPORT_ROOT_CAUSE:-}" \
    --argjson duration "${duration}" \
    --argjson steps "${steps_json}" \
    --argjson gates "${gates_json}" \
    '{
      script:$script,
      status:$status,
      started_at_utc:$started,
      ended_at_utc:$ended,
      duration_seconds:$duration,
      local_tz_offset:$local_offset,
      root_cause:(if $root == "" then null else $root end),
      steps:$steps,
      gates:$gates
    }')"
  printf '%s\n' "${report_json}" > "${RUN_REPORT_FILE}" || true
}

log()  { printf '[%s] %s\n' "$(utc_now)" "$*"; }
warn() { log "WARN: $*"; }
die()  {
  RUN_REPORT_ROOT_CAUSE="$*"
  log "FATAL: $*" >&2
  exit 1
}
HEARTBEAT_INTERVAL_SECONDS="${HEARTBEAT_INTERVAL_SECONDS:-20}"

# run_with_heartbeat <label> <command...>
# Execute a command while emitting periodic progress lines when command output is quiet.
run_with_heartbeat() {
  local label="$1"
  shift
  [[ -n "${label}" ]] || die "run_with_heartbeat: label is required"
  (( $# > 0 )) || die "run_with_heartbeat: command is required"

  local interval="${HEARTBEAT_INTERVAL_SECONDS:-20}"
  if ! [[ "${interval}" =~ ^[0-9]+$ ]] || (( interval < 5 )); then
    interval=20
  fi

  local started elapsed rc hb_pid
  started="$(date '+%s')"
  log "BEGIN: ${label}"

  (
    while :; do
      sleep "${interval}"
      elapsed="$(( $(date '+%s') - started ))"
      log "IN-PROGRESS: ${label} (${elapsed}s elapsed)"
    done
  ) &
  hb_pid=$!

  if "$@"; then
    rc=0
  else
    rc=$?
  fi

  kill "${hb_pid}" >/dev/null 2>&1 || true
  wait "${hb_pid}" 2>/dev/null || true

  elapsed="$(( $(date '+%s') - started ))"
  if (( rc == 0 )); then
    log "END: ${label} (${elapsed}s)"
  else
    warn "FAILED: ${label} (exit=${rc}, elapsed=${elapsed}s)"
  fi
  return "${rc}"
}

# stream_command_output <capture_file> <command...>
# Stream command output to stdout while persisting a copy to capture_file.
stream_command_output() {
  local capture_file="$1"
  shift
  [[ -n "${capture_file}" ]] || die "stream_command_output: capture file is required"
  (( $# > 0 )) || die "stream_command_output: command is required"
  "$@" 2>&1 | tee "${capture_file}"
}
step() {
  printf '\n\033[1;36m[%s] %s\033[0m\n' "$1" "$2"
  run_report_step_start "$1" "$2"
}
pass() {
  local msg="$*"
  printf '  \033[1;32mPASS\033[0m %s\n' "${msg}"
  run_report_record_gate "pass" "${msg}"
}
fail() {
  local msg="$*"
  printf '  \033[1;31mFAIL\033[0m %s\n' "${msg}"
  run_report_record_gate "fail" "${msg}"
}

is_true() {
  case "${1,,}" in
    1|true|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
}

confirm() {
  if is_true "${AUTO_YES}"; then return 0; fi
  local msg="${1:-Continue?}"
  printf '\n%s [y/N] ' "${msg}"
  read -r ans
  case "${ans,,}" in
    y|yes) return 0 ;;
    *) die "Aborted by user." ;;
  esac
}

# ── Input helpers ───────────────────────────────────────────────────────────

prompt_value() {
  local var_name="$1" prompt="$2" default="${3:-}" regex="${4:-}"
  local val
  # When --yes is set and a default exists, accept it without prompting
  if is_true "${AUTO_YES}" && [[ -n "${default}" ]]; then
    # Use declare -g for safer variable assignment (bash 4.2+)
    declare -g "${var_name}=${default}"
    return 0
  fi
  printf '%s' "${prompt}"
  [[ -n "${default}" ]] && printf ' [%s]' "${default}"
  printf ': '
  read -r val
  val="${val:-$default}"
  if [[ -n "${regex}" ]] && ! [[ "${val}" =~ ${regex} ]]; then
    die "Invalid input for ${var_name}: '${val}' does not match ${regex}"
  fi
  declare -g "${var_name}=${val}"
}

prompt_secret() {
  local var_name="$1" prompt="$2"
  local val
  printf '%s: ' "${prompt}"
  read -rs val
  printf '\n'
  [[ -n "${val}" ]] || die "${var_name} cannot be empty."
  declare -g "${var_name}=${val}"
}

prompt_choice() {
  local var_name="$1" prompt="$2" default="$3"
  shift 3
  local options=("$@")
  # When --yes is set, accept the default without prompting
  if is_true "${AUTO_YES}"; then
    declare -g "${var_name}=${default}"
    return 0
  fi
  printf '%s [%s] (%s): ' "${prompt}" "${default}" "$(IFS=/; echo "${options[*]}")"
  read -r val
  val="${val:-$default}"
  local valid=false
  for opt in "${options[@]}"; do
    [[ "${val}" == "${opt}" ]] && valid=true
  done
  ${valid} || die "Invalid choice for ${var_name}: '${val}'. Options: ${options[*]}"
  declare -g "${var_name}=${val}"
}

read_secret_file() {
  local path="$1" label="$2"
  [[ -f "${path}" ]] || die "${label} file not found: ${path}"
  local file_perms
  file_perms="$(stat -c '%a' "${path}" 2>/dev/null || stat -f '%Lp' "${path}" 2>/dev/null || echo "unknown")"
  if [[ "${file_perms}" != "unknown" && "${file_perms}" != "600" && "${file_perms}" != "400" ]]; then
    warn "${label} file ${path} has permissions ${file_perms}; recommend 0600 or stricter."
  fi
  local secret
  secret="$(cat "${path}")"
  secret="${secret%$'\n'}"
  secret="${secret%$'\r'}"
  [[ -n "${secret}" ]] || die "${label} file is empty: ${path}"
  printf '%s' "${secret}"
}

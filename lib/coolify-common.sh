#!/usr/bin/env bash
# lib/coolify-common.sh — Shared utilities for deploy.sh and setup.sh.
# Source this file; do not execute it directly.
# Requires: set -Eeuo pipefail in the caller.

[[ "${BASH_SOURCE[0]}" != "${0}" ]] \
  || { printf 'Source this file, do not execute it.\n' >&2; exit 1; }
if [[ -z "${BASH_VERSINFO:-}" || "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  printf 'Bash 4+ is required (found %s). On macOS use Homebrew bash and run via its absolute path.\n' "${BASH_VERSION:-unknown}" >&2
  return 1
fi
[[ -z "${_COOLIFY_COMMON_LOADED:-}" ]] || return 0
_COOLIFY_COMMON_LOADED=1

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

load_cloudflare_tokens_from_files() {
  if [[ -n "${CF_API_TOKEN_FILE:-}" ]]; then
    CF_API_TOKEN="$(read_secret_file "${CF_API_TOKEN_FILE}" "Cloudflare API token")"
  fi
  if [[ -n "${CF_TUNNEL_API_TOKEN_FILE:-}" ]]; then
    CF_TUNNEL_API_TOKEN="$(read_secret_file "${CF_TUNNEL_API_TOKEN_FILE}" "Cloudflare tunnel API token")"
  fi
}

finalize_cloudflare_tokens() {
  CF_API_TOKEN="${CF_API_TOKEN:-}"
  CF_TUNNEL_API_TOKEN="${CF_TUNNEL_API_TOKEN:-}"
  CF_API_TOKEN="${CF_API_TOKEN%$'\n'}"
  CF_API_TOKEN="${CF_API_TOKEN%$'\r'}"
  CF_TUNNEL_API_TOKEN="${CF_TUNNEL_API_TOKEN%$'\n'}"
  CF_TUNNEL_API_TOKEN="${CF_TUNNEL_API_TOKEN%$'\r'}"

  # Single-token mode: if no dedicated tunnel token is provided, reuse CF_API_TOKEN.
  if [[ -z "${CF_TUNNEL_API_TOKEN:-}" && -n "${CF_API_TOKEN:-}" ]]; then
    CF_TUNNEL_API_TOKEN="${CF_API_TOKEN}"
  fi
}

# ── Cloudflare API ─────────────────────────────────────────────────────────

cf_api_with_token() {
  local method="$1" endpoint="$2" body="${3:-}" token="${4:-}"
  local url="https://api.cloudflare.com/client/v4${endpoint}"
  local args=(-s -X "${method}" -H "Content-Type: application/json")
  [[ -n "${body}" ]] && args+=(-d "${body}")
  [[ -n "${token}" ]] || die "Cloudflare API token is empty for ${method} ${endpoint}"
  # Use a secure temp file instead of pipe to avoid race condition
  # where the token could be read by other processes
  local curl_config
  curl_config="$(mktemp)" || die "Failed to create temp file for curl config"
  printf -- '-H "Authorization: Bearer %s"\n' "${token}" > "${curl_config}"
  chmod 600 "${curl_config}"
  local resp ec
  if ! resp="$(curl --config "${curl_config}" "${args[@]}" "${url}")"; then
    ec=$?
    rm -f "${curl_config}"
    return "${ec}"
  fi
  rm -f "${curl_config}"
  printf '%s' "${resp}"
}

cf_api() {
  cf_api_with_token "$1" "$2" "${3-}" "${CF_API_TOKEN:-}"
}

cf_tunnel_api() {
  local token="${CF_TUNNEL_API_TOKEN:-${CF_API_TOKEN:-}}"
  cf_api_with_token "$1" "$2" "${3-}" "${token}"
}

cf_verify_token() {
  # Use zones endpoint rather than /user/tokens/verify — the latter requires
  # User:User Tokens:Read which is not part of our required token permissions.
  local resp
  resp="$(cf_api GET /zones?per_page=1)"
  local status err code
  status="$(printf '%s' "${resp}" | jq -r '.success // false')"
  if [[ "${status}" != "true" ]]; then
    err="$(printf '%s' "${resp}" | jq -r '.errors[0].message // "unknown"')"
    code="$(printf '%s' "${resp}" | jq -r '.errors[0].code // empty')"
    [[ -n "${code}" ]] && err="${err} (code ${code})"
    die "Cloudflare API token verification failed: ${err}. Ask the user for a token with Zone DNS permissions."
  fi
  log "Cloudflare API token verified."
}

cf_get_zone_id() {
  # Explicit zone ID override (operator already knows the exact zone).
  if [[ -n "${CF_ZONE_ID:-}" ]]; then
    [[ "${CF_ZONE_ID}" =~ ${CF_ID_RE} ]] || die "Invalid --cf-zone-id value: ${CF_ZONE_ID}"
    local zone_resp zone_ok zone_name
    zone_resp="$(cf_api GET "/zones/${CF_ZONE_ID}")"
    zone_ok="$(printf '%s' "${zone_resp}" | jq -r '.success // false')"
    [[ "${zone_ok}" == "true" ]] || die "Cloudflare zone ID lookup failed for '${CF_ZONE_ID}': $(printf '%s' "${zone_resp}" | jq -r '.errors[0].message // "unknown"')"
    zone_name="$(printf '%s' "${zone_resp}" | jq -r '.result.name // empty')"
    [[ -n "${zone_name}" ]] || die "Cloudflare zone name missing for zone ID '${CF_ZONE_ID}'"
    if [[ -n "${CF_ZONE:-}" && "${CF_ZONE}" != "${zone_name}" ]]; then
      die "--cf-zone (${CF_ZONE}) and --cf-zone-id (${CF_ZONE_ID} => ${zone_name}) do not match."
    fi
    CF_ZONE_NAME="${zone_name}"
    CF_ZONE="${zone_name}"
    log "Cloudflare zone ID override: ${CF_ZONE_ID} (${CF_ZONE_NAME})"
    return 0
  fi

  # If --cf-zone was specified, use it directly
  if [[ -n "${CF_ZONE}" ]]; then
    local resp
    resp="$(cf_api GET "/zones?name=${CF_ZONE}&status=active")"
    CF_ZONE_ID="$(printf '%s' "${resp}" | jq -r '.result[0].id // empty')"
    [[ -n "${CF_ZONE_ID}" ]] || die "Cloudflare zone not found for '${CF_ZONE}'. Check --cf-zone value."
    CF_ZONE_NAME="${CF_ZONE}"
    log "Cloudflare zone ID: ${CF_ZONE_ID} (${CF_ZONE_NAME})"
    return 0
  fi

  # Auto-detect zone by trying progressively shorter suffixes of DOMAIN.
  # This correctly handles multi-part TLDs (e.g. .com.au, .co.uk) where
  # stripping only the first label would give a non-existent zone.
  local candidate="${DOMAIN}"
  while [[ "${candidate}" == *.* ]]; do
    local resp
    resp="$(cf_api GET "/zones?name=${candidate}&status=active")"
    CF_ZONE_ID="$(printf '%s' "${resp}" | jq -r '.result[0].id // empty')"
    if [[ -n "${CF_ZONE_ID}" ]]; then
      CF_ZONE_NAME="${candidate}"
      log "Cloudflare zone ID: ${CF_ZONE_ID} (${CF_ZONE_NAME})"
      return 0
    fi
    candidate="${candidate#*.}"  # strip leftmost label and retry
  done
  die "Cloudflare zone not found for any suffix of '${DOMAIN}'. Check domain or use --cf-zone."
}

cf_get_account_id() {
  if [[ -n "${CF_ACCOUNT_ID:-}" ]]; then
    [[ "${CF_ACCOUNT_ID}" =~ ${CF_ID_RE} ]] || die "Invalid --cf-account-id value: ${CF_ACCOUNT_ID}"
    log "Cloudflare account ID override: ${CF_ACCOUNT_ID}"
    return 0
  fi

  local resp
  resp="$(cf_api GET /accounts)"
  CF_ACCOUNT_ID="$(printf '%s' "${resp}" | jq -r '.result[0].id // empty')"
  if [[ -n "${CF_ACCOUNT_ID}" ]]; then
    log "Cloudflare account ID: ${CF_ACCOUNT_ID}"
    return 0
  fi

  # Some scoped API tokens can manage a specific zone/tunnel but return an empty
  # list from /accounts. Fall back to resolving account.id from the selected zone.
  if [[ -n "${CF_ZONE_ID}" ]]; then
    local zone_resp
    zone_resp="$(cf_api GET "/zones/${CF_ZONE_ID}")"
    CF_ACCOUNT_ID="$(printf '%s' "${zone_resp}" | jq -r '.result.account.id // empty')"
    if [[ -n "${CF_ACCOUNT_ID}" ]]; then
      log "Cloudflare account ID (from zone ${CF_ZONE_ID}): ${CF_ACCOUNT_ID}"
      return 0
    fi
  fi

  die "No Cloudflare account found (both /accounts and zone account lookup were empty)."
}

cf_expect_probe_authorized_or_validation_error() {
  local action="$1" resp="$2" expected_codes_csv="$3"
  local success code msg
  success="$(printf '%s' "${resp}" | jq -r '.success // false' 2>/dev/null || echo "false")"
  [[ "${success}" == "true" ]] && return 0
  code="$(printf '%s' "${resp}" | jq -r '.errors[0].code // empty' 2>/dev/null || true)"
  msg="$(printf '%s' "${resp}" | jq -r '.errors[0].message // "unknown"' 2>/dev/null || echo "unknown")"
  if [[ "${code}" == "10000" || "${code}" == "9109" ]]; then
    die "${action} failed: ${msg} (code ${code}). Ask the user for a token with the required permissions."
  fi

  if [[ -z "${expected_codes_csv}" ]]; then
    die "${action} failed unexpectedly: ${msg} (code ${code:-unknown})."
  fi

  local expected
  IFS=',' read -r -a expected <<< "${expected_codes_csv}"
  local allow
  for allow in "${expected[@]}"; do
    [[ "${code}" == "${allow}" ]] && return 0
  done

  die "${action} failed unexpectedly: ${msg} (code ${code:-unknown})."
}

cf_verify_dns_write_token() {
  # Probe DNS write authorization with an intentionally invalid payload.
  # Expected outcome when authorized: validation error (non-auth) and no mutation.
  local resp
  resp="$(cf_api POST "/zones/${CF_ZONE_ID}/dns_records" '{}')"
  cf_expect_probe_authorized_or_validation_error \
    "Cloudflare DNS write permission check" "${resp}" "9000,1004"
  log "Cloudflare DNS write permission verified."
}

cf_verify_tunnel_token() {
  [[ "${DEPLOY_MODE}" == "tunnel" ]] || return 0
  local resp
  resp="$(cf_tunnel_api GET "/accounts/${CF_ACCOUNT_ID}/cfd_tunnel?per_page=1")"
  cf_expect_probe_authorized_or_validation_error \
    "Cloudflare Tunnel read permission check" "${resp}" ""
  local status err
  status="$(printf '%s' "${resp}" | jq -r '.success // false')"
  if [[ "${status}" != "true" ]]; then
    err="$(printf '%s' "${resp}" | jq -r '.errors[0].message // "unknown"')"
    die "Cloudflare tunnel API token verification failed: ${err}. Ask the user for a token with Cloudflare Tunnel permissions."
  fi

  # Probe tunnel create authorization with an intentionally invalid payload.
  # Expected outcome when authorized: validation error (non-auth) and no mutation.
  resp="$(cf_tunnel_api POST "/accounts/${CF_ACCOUNT_ID}/cfd_tunnel" '{}')"
  cf_expect_probe_authorized_or_validation_error \
    "Cloudflare Tunnel write permission check" "${resp}" "1030,1004"
  log "Cloudflare tunnel API token verified (read/write)."
}

cf_expect_success() {
  local action="$1" resp="$2"
  local success
  success="$(printf '%s' "${resp}" | jq -r '.success // false' 2>/dev/null || echo "false")"
  if [[ "${success}" != "true" ]]; then
    local err
    err="$(printf '%s' "${resp}" | jq -r '[.errors[]?.message] | join("; ")' 2>/dev/null || true)"
    [[ -n "${err}" && "${err}" != "null" ]] || err="unknown"
    die "${action} failed: ${err}"
  fi
}

cf_upsert_a_record() {
  local name="$1" ip="$2" proxied="${3:-true}"
  local existing
  existing="$(cf_api GET "/zones/${CF_ZONE_ID}/dns_records?type=A&name=${name}")"
  local record_id record_content record_proxied needs_update="true"
  record_id="$(printf '%s' "${existing}" | jq -r '.result[0].id // empty')"
  record_content="$(printf '%s' "${existing}" | jq -r '.result[0].content // empty')"
  record_proxied="$(printf '%s' "${existing}" | jq -r '.result[0].proxied // false')"
  local body
  body="$(jq -n --arg name "${name}" --arg ip "${ip}" --argjson proxied "${proxied}" \
    '{type:"A",name:$name,content:$ip,proxied:$proxied,ttl:1}')"
  local resp

  if [[ -n "${record_id}" ]]; then
    if [[ "${record_content}" == "${ip}" && "${record_proxied}" == "${proxied}" ]]; then
      needs_update="false"
    else
      resp="$(cf_api PUT "/zones/${CF_ZONE_ID}/dns_records/${record_id}" "${body}")"
      cf_expect_success "Cloudflare A record update (${name})" "${resp}"
    fi
    while IFS= read -r duplicate_id; do
      [[ -n "${duplicate_id}" ]] || continue
      resp="$(cf_api DELETE "/zones/${CF_ZONE_ID}/dns_records/${duplicate_id}")"
      cf_expect_success "Cloudflare duplicate A record delete (${name})" "${resp}"
      log "Deleted duplicate A record: ${name} (${duplicate_id})"
    done < <(printf '%s' "${existing}" | jq -r --arg keep "${record_id}" '.result[]?.id | select(. != $keep)')
    if [[ "${needs_update}" == "true" ]]; then
      log "Updated A record: ${name} → ${ip} (proxied=${proxied})"
    else
      log "A record unchanged: ${name} → ${ip} (proxied=${proxied})"
    fi
  else
    resp="$(cf_api POST "/zones/${CF_ZONE_ID}/dns_records" "${body}")"
    cf_expect_success "Cloudflare A record create (${name})" "${resp}"
    log "Created A record: ${name} → ${ip} (proxied=${proxied})"
  fi
}

coolify_tunnel_name() {
  local domain_lc slug digest
  domain_lc="$(printf '%s' "${DOMAIN}" | tr '[:upper:]' '[:lower:]')"
  slug="$(printf '%s' "${domain_lc}" | tr -cs 'a-z0-9' '-')"
  slug="${slug#-}"
  slug="${slug%-}"
  digest="$(printf '%s' "${domain_lc}" | openssl dgst -sha256 -r | awk '{print substr($1, 1, 12)}')"
  printf 'coolify-%s-%s' "${slug:0:42}" "${digest}"
}

cf_create_tunnel() {
  local stop_fn="${1:-}"   # optional: name of function to call to stop cloudflared
  local fetch_existing_tunnel_fn="${2:-}"  # optional: prints "id<TAB>secret" for server-configured tunnel
  local tunnel_name
  tunnel_name="$(coolify_tunnel_name)"

  # Prefer reusing the currently configured tunnel on reruns. If the same-name tunnel set
  # does not match the server's configured credentials, fall back to delete/recreate.
  # Stop cloudflared first in the delete path so it releases active connections.
  local existing_ids=()
  mapfile -t existing_ids < <(
    cf_tunnel_api GET "/accounts/${CF_ACCOUNT_ID}/cfd_tunnel?name=${tunnel_name}&is_deleted=false" \
      | jq -r '.result[]?.id // empty'
  )
  if (( ${#existing_ids[@]} > 0 )); then
    local reusable_id="" reusable_secret="" reusable_material=""
    if [[ -n "${fetch_existing_tunnel_fn}" ]] && declare -F "${fetch_existing_tunnel_fn}" >/dev/null 2>&1; then
      reusable_material="$("${fetch_existing_tunnel_fn}" 2>/dev/null || true)"
      if [[ -n "${reusable_material}" ]]; then
        IFS=$'\t' read -r reusable_id reusable_secret <<< "${reusable_material}"
      fi
    fi

    if [[ -n "${reusable_id}" && -n "${reusable_secret}" ]]; then
      local existing_id found_reusable="false" delete_resp delete_ok delete_err
      for existing_id in "${existing_ids[@]}"; do
        if [[ "${existing_id}" == "${reusable_id}" ]]; then
          found_reusable="true"
          break
        fi
      done
      if [[ "${found_reusable}" == "true" ]]; then
        TUNNEL_ID="${reusable_id}"
        TUNNEL_SECRET="${reusable_secret}"
        for existing_id in "${existing_ids[@]}"; do
          [[ "${existing_id}" == "${TUNNEL_ID}" ]] && continue
          log "Deleting duplicate stale tunnel ${tunnel_name} (${existing_id}) while reusing ${TUNNEL_ID}..."
          delete_resp="$(cf_tunnel_api DELETE "/accounts/${CF_ACCOUNT_ID}/cfd_tunnel/${existing_id}" 2>/dev/null || true)"
          delete_ok="$(printf '%s' "${delete_resp}" | jq -r '.success // false' 2>/dev/null || echo "false")"
          if [[ "${delete_ok}" == "true" ]]; then
            log "Deleted stale tunnel ${existing_id}"
          else
            delete_err="$(printf '%s' "${delete_resp}" | jq -r '[.errors[]?.message] | join("; ")' 2>/dev/null || true)"
            [[ -n "${delete_err}" && "${delete_err}" != "null" ]] || delete_err="unknown"
            die "Could not delete duplicate stale tunnel ${existing_id} (${delete_err}) while reusing ${TUNNEL_ID}."
          fi
        done
        log "Reusing existing tunnel: ${tunnel_name} (${TUNNEL_ID})"
        return 0
      fi
    fi

    log "Stopping cloudflared on server to release tunnel connections before delete..."
    [[ -n "${stop_fn}" ]] && "${stop_fn}"
    sleep 3  # Allow connections to close
    local existing_id delete_resp delete_ok delete_err
    for existing_id in "${existing_ids[@]}"; do
      log "Deleting stale tunnel ${tunnel_name} (${existing_id}) before recreating..."
      delete_resp="$(cf_tunnel_api DELETE "/accounts/${CF_ACCOUNT_ID}/cfd_tunnel/${existing_id}" 2>/dev/null || true)"
      delete_ok="$(printf '%s' "${delete_resp}" | jq -r '.success // false' 2>/dev/null || echo "false")"
      if [[ "${delete_ok}" == "true" ]]; then
        log "Deleted stale tunnel ${existing_id}"
      else
        delete_err="$(printf '%s' "${delete_resp}" | jq -r '[.errors[]?.message] | join("; ")' 2>/dev/null || true)"
        [[ -n "${delete_err}" && "${delete_err}" != "null" ]] || delete_err="unknown"
        die "Could not delete stale tunnel ${existing_id} (${delete_err}); refusing to reuse reserved tunnel name ${tunnel_name}."
      fi
    done
    sleep 2  # Allow CF to release the name
  fi

  TUNNEL_SECRET="$(openssl rand -base64 32)"
  local body
  body="$(jq -n --arg name "${tunnel_name}" --arg secret "${TUNNEL_SECRET}" \
    '{name:$name,tunnel_secret:$secret,config_src:"local"}')"
  local resp
  resp="$(cf_tunnel_api POST "/accounts/${CF_ACCOUNT_ID}/cfd_tunnel" "${body}")"
  TUNNEL_ID="$(printf '%s' "${resp}" | jq -r '.result.id // empty')"
  [[ -n "${TUNNEL_ID}" ]] || die "Failed to create Cloudflare Tunnel: $(printf '%s' "${resp}" | jq -r '.errors[0].message // "unknown"')"
  log "Created tunnel: ${tunnel_name} (${TUNNEL_ID})"
}

cf_upsert_cname() {
  local name="$1" target="$2"
  local existing
  existing="$(cf_api GET "/zones/${CF_ZONE_ID}/dns_records?type=CNAME&name=${name}")"
  local record_id record_content record_proxied needs_update="true"
  record_id="$(printf '%s' "${existing}" | jq -r '.result[0].id // empty')"
  record_content="$(printf '%s' "${existing}" | jq -r '.result[0].content // empty')"
  record_proxied="$(printf '%s' "${existing}" | jq -r '.result[0].proxied // false')"
  local body
  body="$(jq -n --arg name "${name}" --arg target "${target}" \
    '{type:"CNAME",name:$name,content:$target,proxied:true,ttl:1}')"
  local resp

  if [[ -n "${record_id}" ]]; then
    if [[ "${record_content}" == "${target}" && "${record_proxied}" == "true" ]]; then
      needs_update="false"
    else
      resp="$(cf_api PUT "/zones/${CF_ZONE_ID}/dns_records/${record_id}" "${body}")"
      cf_expect_success "Cloudflare CNAME update (${name})" "${resp}"
    fi
    while IFS= read -r duplicate_id; do
      [[ -n "${duplicate_id}" ]] || continue
      resp="$(cf_api DELETE "/zones/${CF_ZONE_ID}/dns_records/${duplicate_id}")"
      cf_expect_success "Cloudflare duplicate CNAME delete (${name})" "${resp}"
      log "Deleted duplicate CNAME: ${name} (${duplicate_id})"
    done < <(printf '%s' "${existing}" | jq -r --arg keep "${record_id}" '.result[]?.id | select(. != $keep)')
    if [[ "${needs_update}" == "true" ]]; then
      log "Updated CNAME: ${name} → ${target}"
    else
      log "CNAME unchanged: ${name} → ${target}"
    fi
  else
    resp="$(cf_api POST "/zones/${CF_ZONE_ID}/dns_records" "${body}")"
    cf_expect_success "Cloudflare CNAME create (${name})" "${resp}"
    log "Created CNAME: ${name} → ${target}"
  fi
}

cf_delete_conflicting_host_records() {
  local name="$1"
  local type existing record_id resp

  for type in AAAA CNAME; do
    existing="$(cf_api GET "/zones/${CF_ZONE_ID}/dns_records?type=${type}&name=${name}")"
    while IFS= read -r record_id; do
      [[ -n "${record_id}" ]] || continue
      resp="$(cf_api DELETE "/zones/${CF_ZONE_ID}/dns_records/${record_id}")"
      cf_expect_success "Cloudflare ${type} record delete (${name})" "${resp}"
      log "Deleted conflicting ${type} record: ${name} (${record_id})"
    done < <(printf '%s' "${existing}" | jq -r '.result[]?.id // empty')
  done
}

cf_assert_private_tailscale_a_record() {
  local name="$1" expected_ip="$2"
  local resp success matching_count conflicting_count
  resp="$(cf_api GET "/zones/${CF_ZONE_ID}/dns_records?type=A&name=${name}")"
  success="$(printf '%s' "${resp}" | jq -r '.success // false')"
  [[ "${success}" == "true" ]] || die "Cloudflare DNS lookup failed for ${name}: $(printf '%s' "${resp}" | jq -r '.errors[0].message // "unknown"')"

  matching_count="$(printf '%s' "${resp}" \
    | jq -r --arg ip "${expected_ip}" '[.result[]? | select((.content // "") == $ip and (.proxied == false))] | length')"
  conflicting_count="$(printf '%s' "${resp}" \
    | jq -r --arg ip "${expected_ip}" '[.result[]? | select((.content // "") != $ip or (.proxied != false))] | length')"

  [[ "${matching_count}" =~ ^[0-9]+$ ]] || matching_count=0
  [[ "${conflicting_count}" =~ ^[0-9]+$ ]] || conflicting_count=0

  (( matching_count >= 1 )) || die "Expected DNS-only A record ${name} → ${expected_ip}, but none found."
  (( conflicting_count == 0 )) || die "Conflicting A record(s) found for ${name}; expected only DNS-only ${expected_ip}."
  log "Verified DNS-only A record: ${name} → ${expected_ip}"
}

# ── Shared deployment helpers ────────────────────────────────────────────────

# report_validation_result — Parse and report validate_hardening.sh JSON output.
# Caller captures JSON (via SSH or locally) and passes it in as the second argument.
# Usage: report_validation_result "Gate C" "${validate_json}" "Gate C failed. ..."
report_validation_result() {
  local label="$1" validate_json="$2" die_msg="$3"
  local fail_count
  fail_count="$(printf '%s' "${validate_json}" | jq -r '.fail // -1' 2>/dev/null || echo "-1")"
  if [[ "${fail_count}" == "0" ]]; then
    pass "${label}: validate_hardening.sh — 0 failures"
  else
    fail "${label}: validate_hardening.sh reported ${fail_count} failures"
    printf '%s\n' "${validate_json}" | jq '.checks[] | select(.status=="FAIL")' 2>/dev/null || true
    die "${die_msg}"
  fi
}

# coolify_phase3_docker_coolify_shared — Shared phase 3 orchestration used by
# deploy.sh and setup.sh. Transport-specific behavior is injected via callbacks.
# Callback signatures:
#   has_docker_fn()
#   install_docker_fn()
#   start_docker_user_fn()
#   verify_docker_user_fn <gate-label>
#   has_coolify_env_fn()
#   install_coolify_fn()
#   reconcile_docker_daemon_fn()
#   restart_docker_user_fn()
#   add_coolify_root_key_fn()
#   fix_host_docker_internal_fn()
#   sync_docker_ssh_cidrs_fn()
coolify_phase3_docker_coolify_shared() {
  local has_docker_fn="$1"
  local install_docker_fn="$2"
  local start_docker_user_fn="$3"
  local verify_docker_user_fn="$4"
  local has_coolify_env_fn="$5"
  local install_coolify_fn="$6"
  local reconcile_docker_daemon_fn="$7"
  local restart_docker_user_fn="$8"
  local add_coolify_root_key_fn="$9"
  local fix_host_docker_internal_fn="${10}"
  local sync_docker_ssh_cidrs_fn="${11}"

  step "3/5" "Install Docker & Coolify"

  # Install Docker (skip if already present).
  if "${has_docker_fn}"; then
    log "Docker already installed — skipping install."
  else
    log "Installing Docker via official apt repository..."
    run_with_heartbeat "Docker installation" "${install_docker_fn}" \
      || die "Docker installation failed."
    pass "Docker installed"
  fi
  pass "Docker present"

  # Start DOCKER-USER hardening service
  "${start_docker_user_fn}" || die "Failed to start docker-user-hardening.service"

  # Gate D: Verify DOCKER-USER rules
  "${verify_docker_user_fn}" "Gate D"

  # Install Coolify (skip if already installed). Probe with retries because
  # Docker may still be converging right after daemon reconciliation.
  local coolify_present="false"
  local coolify_probe_attempts=4
  local coolify_probe_delay=3
  local coolify_probe
  for (( coolify_probe=1; coolify_probe<=coolify_probe_attempts; coolify_probe++ )); do
    if "${has_coolify_env_fn}"; then
      coolify_present="true"
      break
    fi
    if (( coolify_probe < coolify_probe_attempts )); then
      log "Coolify presence check not ready; retrying in ${coolify_probe_delay}s (${coolify_probe}/${coolify_probe_attempts})..."
      sleep "${coolify_probe_delay}"
    fi
  done

  if [[ "${coolify_present}" == "true" ]]; then
    log "Coolify .env found — skipping install (already installed)."
    pass "Coolify already installed"
  else
    log "Installing Coolify (this may take a few minutes)..."
    run_with_heartbeat "Coolify installation" "${install_coolify_fn}" \
      || die "Coolify installation failed."
    pass "Coolify installed"
  fi

  # Coolify installer manages daemon.json; re-apply hardening settings while preserving its keys.
  "${reconcile_docker_daemon_fn}"

  # Docker restart can flush DOCKER-USER runtime rules; re-apply and verify.
  "${restart_docker_user_fn}" \
    || die "Failed to restart docker-user-hardening.service after Docker daemon reconciliation."
  "${verify_docker_user_fn}" "Gate D (post-Coolify)"

  # Add Coolify's generated SSH public key to root's authorized_keys.
  # Required for the Coolify "This Machine" onboarding: Coolify SSHes to localhost as root
  # using its own key. The hardening Match block allows key-only root login from
  # localhost (127.0.0.1), 172.16.0.0/12, and 10.0.0.0/8 (Docker pool); key must be present.
  log "Adding Coolify SSH key to root authorized_keys..."
  "${add_coolify_root_key_fn}" || die "Failed to reconcile root authorized_keys with Coolify key."
  pass "Coolify SSH key in root authorized_keys"

  # Fix host.docker.internal resolution on Linux Docker.
  # Docker on Linux doesn't resolve host-gateway to a real IP in all versions/configurations.
  # Patch Coolify's docker-compose.yml to use the actual coolify network gateway IP,
  # then recreate the container so the fix takes effect.
  log "Fixing host.docker.internal for Linux Docker..."
  run_with_heartbeat "host.docker.internal reconcile" "${fix_host_docker_internal_fn}" \
    || die "Failed to reconcile host.docker.internal in Coolify compose."
  pass "host.docker.internal patched in Coolify docker-compose"

  # Coolify may create new Docker bridge CIDRs (for example 10.0.0.0/24 and 10.0.1.0/24)
  # after bootstrap. Reconcile SSH/UFW bridge allowlists now so final validation does not
  # depend on waiting for the timer.
  log "Reconciling Docker bridge SSH CIDRs..."
  "${sync_docker_ssh_cidrs_fn}" || die "Failed to reconcile Docker bridge SSH CIDRs."
  pass "Docker bridge SSH CIDRs reconciled"
}

# coolify_phase4_binding_dns_shared — Shared phase 4 orchestration used by
# deploy.sh and setup.sh. Transport-specific behavior is injected via callbacks.
# Callback signatures:
#   coolify_env_exists_fn()
#   configure_binding_fn()
#   mark_binding_state_fn()
#   set_wildcard_domain_fn()
#   reconcile_instance_settings_fn()
#   reconcile_pusher_fn()
#   install_cloudflared_fn()
#   configure_cloudflared_fn()
#   stop_cloudflared_fn()
#   fetch_existing_tunnel_fn()   # optional; prints "id<TAB>secret" or nothing
#   configure_private_routes_fn()
#   configure_private_tls_fn()
#   remove_private_routes_fn()
coolify_phase4_binding_dns_shared() {
  local coolify_env_exists_fn="$1"
  local configure_binding_fn="$2"
  local mark_binding_state_fn="$3"
  local set_wildcard_domain_fn="$4"
  local reconcile_instance_settings_fn="$5"
  local reconcile_pusher_fn="$6"
  local install_cloudflared_fn="$7"
  local configure_cloudflared_fn="$8"
  local stop_cloudflared_fn="$9"
  local fetch_existing_tunnel_fn="${10}"
  local configure_private_routes_fn="${11}"
  local configure_private_tls_fn="${12}"
  local remove_private_routes_fn="${13}"

  step "4/5" "Configure dashboard binding & DNS"

  # Wait for Coolify to write its .env file before binding (installer is async)
  log "Waiting for Coolify to initialize /data/coolify/source/.env..."
  local coolify_wait=0 coolify_max=120
  until "${coolify_env_exists_fn}"; do
    (( coolify_wait += 5 ))
    if (( coolify_wait >= coolify_max )); then
      warn "Coolify .env not found after ${coolify_max}s — binding may fail; continuing."
      break
    fi
    sleep 5
  done

  log "Restricting Coolify dashboard access to Tailscale via UFW..."
  "${configure_binding_fn}" || die "configure_coolify_binding.sh failed. Fix binding errors before continuing."
  "${mark_binding_state_fn}" || die "Failed to persist bind_dashboard_to_tailscale=true in state."
  pass "Dashboard access restrictions configured"

  # Set Coolify wildcard domain directly in the database.
  # configure_coolify_binding.sh already waited up to 60s for port 8000 to bind,
  # which guarantees the s6 startup sequence (migrate→seed→init) has completed and
  # the server_settings row (server_id=0, the hardcoded Localhost server) exists.
  # The API PATCH /servers/{uuid} does not expose wildcard_domain, so we write
  # directly to PostgreSQL via docker exec on the coolify-db container.
  log "Setting Coolify wildcard domain to http://${APP_DOMAIN}..."
  "${set_wildcard_domain_fn}" || die "Failed to update wildcard domain in Coolify database"
  pass "Coolify wildcard domain: http://${APP_DOMAIN}"

  log "Reconciling Coolify instance settings..."
  "${reconcile_instance_settings_fn}" || die "Failed to reconcile Coolify instance settings"
  pass "Coolify instance settings reconciled"

  # Configure PUSHER_* for the selected mode.
  # Tunnel mode keeps realtime traffic on Tailscale; standard mode clears explicit overrides.
  log "Reconciling PUSHER env vars for ${DEPLOY_MODE} mode..."
  run_with_heartbeat "PUSHER env reconcile (${DEPLOY_MODE})" "${reconcile_pusher_fn}" \
    || die "Failed to reconcile PUSHER env vars"
  if [[ "${DEPLOY_MODE}" == "tunnel" ]]; then
    pass "PUSHER env vars configured: ws.${DOMAIN}:443 (https)"
  else
    pass "PUSHER env vars cleared for standard mode"
  fi

  if [[ "${DEPLOY_MODE}" == "standard" ]]; then
    # Standard mode: A records pointing to server public IP (proxied)
    log "Configuring DNS: A record ${DOMAIN} → ${SERVER_IP} (proxied)..."
    cf_upsert_a_record "${DOMAIN}" "${SERVER_IP}" "true"
    pass "DNS A record configured: ${DOMAIN} → ${SERVER_IP}"

    # Wildcard A records — always create both scopes so manually set domains at either level work
    local wildcard_name="*.${APP_DOMAIN}"
    log "Configuring DNS: wildcard A record ${wildcard_name} → ${SERVER_IP} (proxied)..."
    cf_upsert_a_record "${wildcard_name}" "${SERVER_IP}" "true"
    pass "DNS wildcard A record configured: ${wildcard_name} → ${SERVER_IP}"
    if [[ "${APP_DOMAIN}" != "${CF_ZONE_NAME}" ]]; then
      local apex_wildcard="*.${CF_ZONE_NAME}"
      cf_upsert_a_record "${apex_wildcard}" "${SERVER_IP}" "true"
      pass "DNS wildcard A record configured: ${apex_wildcard} → ${SERVER_IP}"
    fi

    # Standard mode must not keep tunnel-private dashboard routes.
    "${remove_private_routes_fn}" || die "Failed to remove private-only dashboard routes."
    pass "Private dashboard routes removed for standard mode"
    return 0
  fi

  # Tunnel mode: create tunnel, install cloudflared, CNAME
  log "Creating Cloudflare Tunnel..."
  cf_create_tunnel "${stop_cloudflared_fn}" "${fetch_existing_tunnel_fn}"
  pass "Tunnel ready: ${TUNNEL_ID}"

  log "Installing cloudflared..."
  run_with_heartbeat "cloudflared install" "${install_cloudflared_fn}" \
    || die "Failed to install cloudflared"
  pass "cloudflared installed"

  run_with_heartbeat "cloudflared tunnel configure" "${configure_cloudflared_fn}" \
    || die "Failed to write cloudflared credentials/config or start service"
  local wc_summary="*.${APP_DOMAIN}"
  [[ "${APP_DOMAIN}" != "${CF_ZONE_NAME}" ]] && wc_summary+=" and *.${CF_ZONE_NAME}"
  pass "Tunnel credentials and config written (wildcards: ${wc_summary})"
  pass "cloudflared service running"

  # Private-only dashboard/realtime routes via Tailscale-only host records.
  "${configure_private_routes_fn}" || die "Failed to configure private-only dashboard routes."
  pass "Private dashboard/realtime routes configured for ${DOMAIN} and ws.${DOMAIN}"

  "${configure_private_tls_fn}" || die "Failed to configure trusted private TLS for dashboard/realtime routes."
  pass "Trusted private TLS configured for ${DOMAIN} and ws.${DOMAIN}"

  # Ensure exact host records converge to DNS-only Tailscale A records without
  # deleting matching A records on every rerun.
  cf_delete_conflicting_host_records "${DOMAIN}"
  cf_delete_conflicting_host_records "ws.${DOMAIN}"
  cf_upsert_a_record "${DOMAIN}" "${TS_IP}" "false"
  pass "DNS host A record configured: ${DOMAIN} → ${TS_IP} (DNS-only)"
  cf_upsert_a_record "ws.${DOMAIN}" "${TS_IP}" "false"
  pass "DNS host A record configured: ws.${DOMAIN} → ${TS_IP} (DNS-only)"

  # Create wildcard CNAME records for app routing through cloudflared/Traefik.
  local tunnel_target="${TUNNEL_ID}.cfargotunnel.com"
  cf_upsert_cname "*.${APP_DOMAIN}" "${tunnel_target}"
  pass "DNS wildcard CNAME configured: *.${APP_DOMAIN} → ${tunnel_target}"
  if [[ "${APP_DOMAIN}" != "${CF_ZONE_NAME}" ]]; then
    cf_upsert_cname "*.${CF_ZONE_NAME}" "${tunnel_target}"
    pass "DNS wildcard CNAME configured: *.${CF_ZONE_NAME} → ${tunnel_target}"
  fi
}

# coolify_phase5_verify_shared — Shared phase 5 verification orchestration used
# by deploy.sh and setup.sh.
# Arguments:
#   1) fetch_validate_json_fn : callback that prints validate_hardening JSON
#   2) public_probe_mode      : external|operator
#   3) operator_confirm_fn    : callback used only when mode=operator
coolify_phase5_fetch_pusher_app_key() {
  local fetch_cmd output
  fetch_cmd="docker inspect coolify --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | sed -n 's/^PUSHER_APP_KEY=//p' | tail -n 1"

  if declare -F ssh_admin_sudo >/dev/null 2>&1; then
    output="$(ssh_admin_sudo "${fetch_cmd}" 2>/dev/null || true)"
  else
    output="$(bash -o pipefail -c "${fetch_cmd}" 2>/dev/null || true)"
  fi

  printf '%s\n' "${output}" | awk 'NF { last=$0 } END { if (last != "") print last }'
}

coolify_phase5_websocket_url() {
  local base_url="${1:?coolify_phase5_websocket_url requires base_url}"
  local pusher_app_key="${2:?coolify_phase5_websocket_url requires pusher_app_key}"

  printf '%s/app/%s?protocol=7&client=js&version=8.4.0&flash=false' "${base_url%/}" "${pusher_app_key}"
}

coolify_phase5_probe_websocket_code() {
  local websocket_url="${1:?coolify_phase5_probe_websocket_code requires websocket_url}"
  local timeout_seconds="${2:-10}"
  local connect_host="${3:-}"

  if ! command -v python3 >/dev/null 2>&1; then
    printf '000\n'
    return 0
  fi

  python3 - "${websocket_url}" "${timeout_seconds}" "${connect_host}" <<'PY'
import base64
import os
import socket
import ssl
import sys
from urllib.parse import urlparse


def emit(code: str) -> None:
    print(code if code else "000")


try:
    raw_url = sys.argv[1]
    timeout = float(sys.argv[2])
    connect_host = sys.argv[3] if len(sys.argv) > 3 else ""
    parsed = urlparse(raw_url)
    if parsed.scheme not in ("ws", "wss") or not parsed.hostname:
        emit("000")
        raise SystemExit(0)

    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "wss" else 80)
    target_host = connect_host or host
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    host_header = parsed.netloc or host
    origin_scheme = "https" if parsed.scheme == "wss" else "http"
    sec_key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"Origin: {origin_scheme}://{host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {sec_key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ).encode("ascii")

    with socket.create_connection((target_host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        if parsed.scheme == "wss":
            context = ssl.create_default_context()
            stream = context.wrap_socket(sock, server_hostname=host)
        else:
            stream = sock

        with stream:
            stream.sendall(request)
            response = b""
            while b"\r\n\r\n" not in response and len(response) < 16384:
                chunk = stream.recv(4096)
                if not chunk:
                    break
                response += chunk

    status_line = response.split(b"\r\n", 1)[0].decode("ascii", "replace")
    parts = status_line.split()
    emit(parts[1] if len(parts) >= 2 else "000")
except Exception:
    emit("000")
PY
}

coolify_phase5_private_tls_diagnostic() {
  local host="${1:?coolify_phase5_private_tls_diagnostic requires host}"
  local connect_host="${2:?coolify_phase5_private_tls_diagnostic requires connect_host}"
  local health_path="${3:-/api/v1/health}"
  local verified_code="000"
  local insecure_code="000"
  local cert_meta cert_subject cert_issuer san_summary

  if command -v curl >/dev/null 2>&1; then
    verified_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
      --resolve "${host}:443:${connect_host}" "https://${host}${health_path}" 2>/dev/null || true)"
    insecure_code="$(curl -k -s -o /dev/null -w '%{http_code}' --max-time 10 \
      --resolve "${host}:443:${connect_host}" "https://${host}${health_path}" 2>/dev/null || true)"
  fi
  verified_code="${verified_code:-000}"
  insecure_code="${insecure_code:-000}"
  verified_code="${verified_code:0:3}"
  insecure_code="${insecure_code:0:3}"

  cert_meta=""
  if command -v openssl >/dev/null 2>&1; then
    cert_meta="$(printf '' | openssl s_client -connect "${connect_host}:443" -servername "${host}" -showcerts 2>/dev/null \
      | openssl x509 -noout -subject -issuer -ext subjectAltName 2>/dev/null || true)"
  fi
  cert_subject="$(awk -F= '/^subject=/{print $2; exit}' <<< "${cert_meta}" | sed 's/^ *//')"
  cert_issuer="$(awk -F= '/^issuer=/{print $2; exit}' <<< "${cert_meta}" | sed 's/^ *//')"
  san_summary="$(awk '
    BEGIN { in_san=0 }
    /^X509v3 Subject Alternative Name:/ { in_san=1; next }
    in_san && /^[[:space:]]*DNS:/ { gsub(/^[[:space:]]+/, "", $0); print; exit }
  ' <<< "${cert_meta}")"

  if [[ -n "${cert_meta}" ]] && grep -Fq "TRAEFIK DEFAULT CERT" <<< "${cert_meta}"; then
    if [[ "${insecure_code}" =~ ^2[0-9][0-9]$ && ! "${verified_code}" =~ ^2[0-9][0-9]$ ]]; then
      log "  Gate F diagnostic (${host}): route responds behind untrusted default cert (verified=${verified_code}, insecure=${insecure_code}, subject=${cert_subject:-unknown}, issuer=${cert_issuer:-unknown})"
    else
      log "  Gate F diagnostic (${host}): Traefik default cert still served (verified=${verified_code}, insecure=${insecure_code}, subject=${cert_subject:-unknown}, issuer=${cert_issuer:-unknown})"
    fi
  else
    log "  Gate F diagnostic (${host}): verified=${verified_code}, insecure=${insecure_code}, subject=${cert_subject:-unknown}, issuer=${cert_issuer:-unknown}, san=${san_summary:-<none>}"
  fi
}

coolify_http_code_is_success_or_redirect() {
  local code="${1:-000}"
  [[ "${code}" =~ ^2[0-9][0-9]$ || "${code}" =~ ^30[12378]$ ]]
}

coolify_dashboard_http_code_is_healthy() {
  local code="${1:-000}"
  coolify_http_code_is_success_or_redirect "${code}"
}

coolify_phase5_verify_shared() {
  local fetch_validate_json_fn="${1:-}"
  local public_probe_mode="${2:-external}"
  local operator_confirm_fn="${3:-}"

  [[ -n "${fetch_validate_json_fn}" ]] || die "coolify_phase5_verify_shared requires fetch_validate_json_fn"
  [[ "${public_probe_mode}" == "external" || "${public_probe_mode}" == "operator" ]] \
    || die "Invalid public probe mode: ${public_probe_mode}"

  step "5/5" "Final verification"

  # Gate E: Dashboard reachable on Tailscale.
  # In external mode, also enforce dashboard/ws blocked on public IP.
  # In operator mode (setup.sh on-server), keep public-IP checks as operator-confirmed
  # because localhost-origin probes to the host's public IP are not authoritative.
  log "Gate E: Checking dashboard accessibility..."
  sleep 5

  local ts_code pub_code
  local attempts=24
  local attempt
  local delay=5
  local gate_e_passed=false
  for (( attempt=1; attempt<=attempts; attempt++ )); do
    ts_code="$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 10 "http://${TS_IP}:8000" 2>/dev/null)" || ts_code=""
    ts_code="${ts_code:-000}"
    ts_code="${ts_code:0:3}"

    if [[ "${public_probe_mode}" == "external" ]]; then
      pub_code="$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 "http://${SERVER_IP}:8000" 2>/dev/null)" || pub_code=""
      pub_code="${pub_code:-000}"
      pub_code="${pub_code:0:3}"
      if coolify_dashboard_http_code_is_healthy "${ts_code}" && [[ "${pub_code}" == "000" ]]; then
        gate_e_passed=true
        break
      fi
      if (( attempt < attempts )); then
        log "  Gate E not ready (tailscale=${ts_code}, public=${pub_code}); retrying in ${delay}s (${attempt}/${attempts})..."
        sleep "${delay}"
      fi
    else
      if coolify_dashboard_http_code_is_healthy "${ts_code}"; then
        gate_e_passed=true
        break
      fi
      if (( attempt < attempts )); then
        log "  Gate E not ready (tailscale=${ts_code}); retrying in ${delay}s (${attempt}/${attempts})..."
        sleep "${delay}"
      fi
    fi
  done

  if [[ "${gate_e_passed}" != "true" ]]; then
    fail "Gate E: dashboard not reachable on ${TS_IP}:8000"
    die "Gate E failed: dashboard not reachable via Tailscale."
  fi

  pass "Gate E: Dashboard reachable on Tailscale IP (HTTP ${ts_code})"
  if [[ "${public_probe_mode}" == "external" ]]; then
    if [[ "${pub_code}" != "000" ]]; then
      fail "Gate E: dashboard reachable on public IP ${SERVER_IP}:8000 (HTTP ${pub_code})"
      die "Gate E failed: dashboard reachable on public IP."
    fi
    pass "Gate E: Dashboard NOT reachable on public IP (good)"
  fi

  # Gate E (realtime): actual websocket handshake must work on the Tailscale
  # IP, and raw port 6001 must stay blocked from the public internet.
  log "Gate E: Checking websocket accessibility..."
  local pusher_app_key ws_ts_url ws_pub_url ws_ts_code ws_pub_code
  pusher_app_key="$(coolify_phase5_fetch_pusher_app_key | tr -d '\r' | tail -n 1)"
  [[ -n "${pusher_app_key}" ]] || die "Gate E failed: unable to determine PUSHER_APP_KEY from Coolify."
  ws_ts_url="$(coolify_phase5_websocket_url "ws://${TS_IP}:6001" "${pusher_app_key}")"
  ws_pub_url="$(coolify_phase5_websocket_url "ws://${SERVER_IP}:6001" "${pusher_app_key}")"
  local gate_e_ws_passed=false
  for (( attempt=1; attempt<=attempts; attempt++ )); do
    ws_ts_code="$(coolify_phase5_probe_websocket_code "${ws_ts_url}" 10)"
    ws_ts_code="${ws_ts_code:-000}"
    ws_ts_code="${ws_ts_code:0:3}"

    if [[ "${public_probe_mode}" == "external" ]]; then
      ws_pub_code="$(coolify_phase5_probe_websocket_code "${ws_pub_url}" 5)"
      ws_pub_code="${ws_pub_code:-000}"
      ws_pub_code="${ws_pub_code:0:3}"
      if [[ "${ws_ts_code}" == "101" && "${ws_pub_code}" == "000" ]]; then
        gate_e_ws_passed=true
        break
      fi
      if (( attempt < attempts )); then
        log "  Gate E websocket not ready (tailscale=${ws_ts_code}, public=${ws_pub_code}); retrying in ${delay}s (${attempt}/${attempts})..."
        sleep "${delay}"
      fi
    else
      if [[ "${ws_ts_code}" == "101" ]]; then
        gate_e_ws_passed=true
        break
      fi
      if (( attempt < attempts )); then
        log "  Gate E websocket not ready (tailscale=${ws_ts_code}); retrying in ${delay}s (${attempt}/${attempts})..."
        sleep "${delay}"
      fi
    fi
  done

  if [[ "${gate_e_ws_passed}" != "true" ]]; then
    fail "Gate E: websocket not reachable on ${TS_IP}:6001"
    die "Gate E failed: websocket not reachable via Tailscale."
  fi

  pass "Gate E: Websocket reachable on Tailscale IP (HTTP ${ws_ts_code})"
  if [[ "${public_probe_mode}" == "external" ]]; then
    if [[ "${ws_pub_code}" != "000" ]]; then
      fail "Gate E: websocket reachable on public IP ${SERVER_IP}:6001 (HTTP ${ws_pub_code})"
      die "Gate E failed: websocket reachable on public IP."
    fi
    pass "Gate E: Websocket NOT reachable on public IP (good)"
  elif [[ -n "${operator_confirm_fn}" ]]; then
    "${operator_confirm_fn}" "From your LAPTOP, verify: curl http://${SERVER_IP}:8000 fails and curl http://${SERVER_IP}:6001 fails" \
      || die "Gate E failed: operator could not confirm public dashboard/websocket blocking."
    pass "Gate E: Operator-confirmed dashboard/websocket blocked on public IP"
  fi

  if [[ "${DEPLOY_MODE}" == "standard" ]]; then
    # Gate F (standard): external HTTPS endpoint must be reachable.
    log "Gate F: Checking external HTTPS endpoint..."
    local https_code
    local gate_f_passed=false
    for (( attempt=1; attempt<=attempts; attempt++ )); do
      https_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -L "https://${DOMAIN}" 2>/dev/null)" || https_code=""
      https_code="${https_code:-000}"
      https_code="${https_code:0:3}"
      if [[ "${https_code}" =~ ^[23][0-9][0-9]$ ]]; then
        gate_f_passed=true
        break
      fi
      if (( attempt < attempts )); then
        log "  Gate F not ready (https_code=${https_code}); retrying in ${delay}s (${attempt}/${attempts})..."
        sleep "${delay}"
      fi
    done

    if [[ "${gate_f_passed}" == "true" ]]; then
      pass "Gate F: https://${DOMAIN} reachable (HTTP ${https_code})"
    else
      fail "Gate F: https://${DOMAIN} not reachable with success response (last HTTP ${https_code})"
      die "Gate F failed: external HTTPS endpoint check did not pass."
    fi
  else
    # Gate F (tunnel/private): private host routes must work on Tailscale-only DNS.
    # Probe the expected Tailscale IP directly so Gate F does not depend on local DNS cache
    # propagation. Keep a longer window for private ACME DNS-01 issuance + Traefik reload.
    attempts=180
    log "Gate F: Checking private host routes and public-origin blocking..."
    local dashboard_private_code ws_private_code dashboard_private_https_code ws_private_wss_code
    local ws_private_url
    ws_private_url="$(coolify_phase5_websocket_url "wss://ws.${DOMAIN}" "${pusher_app_key}")"
    local gate_f_private_routes_passed=false
    for (( attempt=1; attempt<=attempts; attempt++ )); do
      dashboard_private_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 --resolve "${DOMAIN}:80:${TS_IP}" "http://${DOMAIN}" 2>/dev/null)" || dashboard_private_code=""
      ws_private_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 --resolve "ws.${DOMAIN}:80:${TS_IP}" "http://ws.${DOMAIN}" 2>/dev/null)" || ws_private_code=""
      dashboard_private_https_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 --resolve "${DOMAIN}:443:${TS_IP}" "https://${DOMAIN}/api/v1/health" 2>/dev/null)" || dashboard_private_https_code=""
      ws_private_wss_code="$(coolify_phase5_probe_websocket_code "${ws_private_url}" 10 "${TS_IP}")"
      dashboard_private_code="${dashboard_private_code:-000}"
      ws_private_code="${ws_private_code:-000}"
      dashboard_private_https_code="${dashboard_private_https_code:-000}"
      ws_private_wss_code="${ws_private_wss_code:-000}"
      dashboard_private_code="${dashboard_private_code:0:3}"
      ws_private_code="${ws_private_code:0:3}"
      dashboard_private_https_code="${dashboard_private_https_code:0:3}"
      ws_private_wss_code="${ws_private_wss_code:0:3}"

      if [[ "${dashboard_private_code}" =~ ^30[12378]$ && \
            "${ws_private_code}" =~ ^30[12378]$ && \
            "${dashboard_private_https_code}" =~ ^2[0-9][0-9]$ && \
            "${ws_private_wss_code}" == "101" ]]; then
        gate_f_private_routes_passed=true
        break
      fi
      if [[ "${dashboard_private_code}" =~ ^30[12378]$ && \
            "${ws_private_code}" =~ ^30[12378]$ && \
            ( "${dashboard_private_https_code}" == "000" || "${ws_private_wss_code}" == "000" ) && \
            ( ${attempt} == 1 || $(( attempt % 12 )) == 0 ) ]]; then
        coolify_phase5_private_tls_diagnostic "${DOMAIN}" "${TS_IP}" "/api/v1/health"
        coolify_phase5_private_tls_diagnostic "ws.${DOMAIN}" "${TS_IP}" "/"
      fi
      if (( attempt < attempts )); then
        log "  Gate F private routes not ready (dashboard-http=${dashboard_private_code}, ws-http=${ws_private_code}, dashboard-https=${dashboard_private_https_code}, ws-wss=${ws_private_wss_code}); retrying in ${delay}s (${attempt}/${attempts})..."
        sleep "${delay}"
      fi
    done

    if [[ "${gate_f_private_routes_passed}" != "true" ]]; then
      coolify_phase5_private_tls_diagnostic "${DOMAIN}" "${TS_IP}" "/api/v1/health"
      coolify_phase5_private_tls_diagnostic "ws.${DOMAIN}" "${TS_IP}" "/"
      if [[ "${dashboard_private_code}" =~ ^30[12378]$ ]]; then
        pass "Gate F: private dashboard HTTP redirects to HTTPS (http://${DOMAIN} → HTTP ${dashboard_private_code})"
      else
        fail "Gate F: private dashboard HTTP did not redirect to HTTPS (http://${DOMAIN} → HTTP ${dashboard_private_code})"
      fi
      if [[ "${ws_private_code}" =~ ^30[12378]$ ]]; then
        pass "Gate F: private websocket HTTP redirects to HTTPS (http://ws.${DOMAIN} → HTTP ${ws_private_code})"
      else
        fail "Gate F: private websocket HTTP did not redirect to HTTPS (http://ws.${DOMAIN} → HTTP ${ws_private_code})"
      fi
      if [[ "${dashboard_private_https_code}" =~ ^2[0-9][0-9]$ ]]; then
        pass "Gate F: private dashboard HTTPS route works (https://${DOMAIN} → HTTP ${dashboard_private_https_code})"
      else
        fail "Gate F: private dashboard HTTPS route failed (https://${DOMAIN} → HTTP ${dashboard_private_https_code})"
      fi
      if [[ "${ws_private_wss_code}" == "101" ]]; then
        pass "Gate F: private websocket WSS handshake works (wss://ws.${DOMAIN} → HTTP ${ws_private_wss_code})"
      else
        fail "Gate F: private websocket WSS handshake failed (wss://ws.${DOMAIN} → HTTP ${ws_private_wss_code})"
      fi
      die "Gate F failed: private host routes are not functional on Tailscale."
    fi
    pass "Gate F: private dashboard HTTP redirects to HTTPS (http://${DOMAIN} → HTTP ${dashboard_private_code})"
    pass "Gate F: private websocket HTTP redirects to HTTPS (http://ws.${DOMAIN} → HTTP ${ws_private_code})"
    pass "Gate F: private dashboard HTTPS route works (https://${DOMAIN} → HTTP ${dashboard_private_https_code})"
    pass "Gate F: private websocket WSS handshake works (wss://ws.${DOMAIN} → HTTP ${ws_private_wss_code})"

    if [[ "${public_probe_mode}" == "external" ]]; then
      local pub80_code pub443_code
      pub80_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://${SERVER_IP}" 2>/dev/null)" || pub80_code=""
      pub443_code="$(curl -k -s -o /dev/null -w '%{http_code}' --max-time 10 "https://${SERVER_IP}" 2>/dev/null)" || pub443_code=""
      pub80_code="${pub80_code:-000}"
      pub443_code="${pub443_code:-000}"
      pub80_code="${pub80_code:0:3}"
      pub443_code="${pub443_code:0:3}"

      if [[ "${pub80_code}" != "000" || "${pub443_code}" != "000" ]]; then
        fail "Gate F: public origin still reachable (${SERVER_IP}:80=${pub80_code}, :443=${pub443_code})"
        die "Gate F failed: public origin web ports must remain blocked in tunnel mode."
      fi
      pass "Gate F: public origin blocked on ${SERVER_IP}:80 and :443"
    elif [[ -n "${operator_confirm_fn}" ]]; then
      "${operator_confirm_fn}" "From your LAPTOP, verify: curl http://${SERVER_IP} fails and curl -k https://${SERVER_IP} fails" \
        || die "Gate F failed: operator could not confirm public origin blocking."
      pass "Gate F: Operator-confirmed public origin blocked on ${SERVER_IP}:80 and :443"
    fi

    cf_assert_private_tailscale_a_record "${DOMAIN}" "${TS_IP}"
    pass "Gate F: DNS A record verified (${DOMAIN} → ${TS_IP}, DNS-only)"
    cf_assert_private_tailscale_a_record "ws.${DOMAIN}" "${TS_IP}"
    pass "Gate F: DNS A record verified (ws.${DOMAIN} → ${TS_IP}, DNS-only)"
  fi

  # Final validation run
  log "Running final validate_hardening.sh..."
  local final_validate_json
  final_validate_json="$("${fetch_validate_json_fn}" 2>/dev/null)" || true
  report_validation_result "Final validation" "${final_validate_json}" \
    "Final validation failed. Resolve validation failures before considering deployment complete."

  # Print summary
  print_deployment_summary
}

# coolify_install_docker_engine_script — Emit host-side script to install Docker
# via the official apt repository (no convenience curl|sh installer).
coolify_install_docker_engine_script() {
  cat <<'EOF'
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
source /etc/os-release
codename="${VERSION_CODENAME:-}"
[[ -n "${codename}" ]] || { echo "VERSION_CODENAME missing in /etc/os-release" >&2; exit 1; }

apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
cat > /etc/apt/sources.list.d/docker.list <<REPO
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${codename} stable
REPO
apt-get update -qq
apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
EOF
}

# coolify_install_coolify_script — Emit host-side script to install Coolify by
# downloading installer to a local temp file, validating basic format, then executing it.
coolify_install_coolify_script() {
  cat <<'EOF'
set -Eeuo pipefail
installer_url="https://cdn.coollabs.io/coolify/install.sh"
tmp="$(mktemp /tmp/coolify-install.XXXXXX.sh)"
cleanup() { rm -f "${tmp}"; }
trap cleanup EXIT

curl -fsSL "${installer_url}" -o "${tmp}"
[[ -s "${tmp}" ]] || { echo "Downloaded Coolify installer is empty" >&2; exit 1; }
head -1 "${tmp}" | grep -Eq '^#!.*/(ba)?sh$' || { echo "Unexpected Coolify installer header" >&2; exit 1; }
chmod 700 "${tmp}"
if command -v timeout >/dev/null 2>&1; then
  if ! timeout --signal=TERM --kill-after=60 1800 bash "${tmp}"; then
    rc=$?
    if [[ "${rc}" -eq 124 || "${rc}" -eq 137 ]]; then
      echo "Coolify installer timed out after 1800s (likely blocked image pull)." >&2
    fi
    exit "${rc}"
  fi
else
  bash "${tmp}"
fi
EOF
}

# coolify_reconcile_docker_daemon_script — Emit a host-side script that enforces
# daemon.json hardening keys while preserving unrelated settings.
# Caller is responsible for transport/execution (local bash -s vs remote sudo bash -s).
coolify_reconcile_docker_daemon_script() {
  cat <<'EOF'
set -Eeuo pipefail
daemon_json="/etc/docker/daemon.json"
state_file="/var/lib/bootstrap-hardening/state"
nproc_hard="8192"
nproc_soft="4096"
tmp="$(mktemp)" || { echo "Failed to create temp file for daemon.json merge" >&2; exit 1; }

if [[ -f "${state_file}" ]]; then
  nproc_hard="$(grep -m1 '^docker_nproc_hard=' "${state_file}" | cut -d= -f2- || echo "8192")"
  nproc_soft="$(grep -m1 '^docker_nproc_soft=' "${state_file}" | cut -d= -f2- || echo "4096")"
fi
[[ "${nproc_hard}" =~ ^[1-9][0-9]*$ ]] || nproc_hard="8192"
[[ "${nproc_soft}" =~ ^[1-9][0-9]*$ ]] || nproc_soft="4096"
if (( nproc_soft > nproc_hard )); then
  nproc_soft="${nproc_hard}"
fi

if [[ -f "${daemon_json}" ]]; then
  current_driver="$(jq -r '.["log-driver"] // ""' "${daemon_json}" 2>/dev/null || true)"
  if [[ "${current_driver}" != "" && "${current_driver}" != "json-file" ]]; then
    echo "WARNING: Docker log-driver drift detected (was '${current_driver}', expected 'json-file'). Reconciling..." >&2
  fi
  current_live_restore="$(jq -r '.["live-restore"] // ""' "${daemon_json}" 2>/dev/null || true)"
  if [[ "${current_live_restore}" != "" && "${current_live_restore}" != "true" ]]; then
    echo "WARNING: Docker live-restore drift detected (was '${current_live_restore}', expected 'true'). Reconciling..." >&2
  fi
  current_ipc_mode="$(jq -r '.["default-ipc-mode"] // ""' "${daemon_json}" 2>/dev/null || true)"
  if [[ "${current_ipc_mode}" != "" && "${current_ipc_mode}" != "private" ]]; then
    echo "WARNING: Docker default-ipc-mode drift detected (was '${current_ipc_mode}', expected 'private'). Reconciling..." >&2
  fi
  current_storage_driver="$(jq -r '.["storage-driver"] // ""' "${daemon_json}" 2>/dev/null || true)"
  if [[ "${current_storage_driver}" != "" && "${current_storage_driver}" != "overlay2" ]]; then
    echo "WARNING: Docker storage-driver drift detected (was '${current_storage_driver}', expected 'overlay2'). Reconciling..." >&2
  fi
fi

if [[ -f "${daemon_json}" ]]; then
  jq \
    --argjson nproc_hard "${nproc_hard}" \
    --argjson nproc_soft "${nproc_soft}" \
    '. + {
      "log-driver":"json-file",
      "log-opts":((.["log-opts"] // {}) + {"max-size":"10m","max-file":"3"}),
      "live-restore":true,
      "default-ipc-mode":"private",
      "storage-driver":"overlay2",
      "default-ulimits":((.["default-ulimits"] // {}) + {
        "nofile":{"Name":"nofile","Hard":65536,"Soft":65536},
        "nproc":{"Name":"nproc","Hard":$nproc_hard,"Soft":$nproc_soft}
      })
    }' "${daemon_json}" > "${tmp}"
else
  jq -n \
    --argjson nproc_hard "${nproc_hard}" \
    --argjson nproc_soft "${nproc_soft}" \
    '{
      "log-driver":"json-file",
      "log-opts":{"max-size":"10m","max-file":"3"},
      "live-restore":true,
      "default-ipc-mode":"private",
      "storage-driver":"overlay2",
      "default-ulimits":{
        "nofile":{"Name":"nofile","Hard":65536,"Soft":65536},
        "nproc":{"Name":"nproc","Hard":$nproc_hard,"Soft":$nproc_soft}
      }
    }' > "${tmp}"
fi

if [[ -f "${daemon_json}" ]] && cmp -s "${tmp}" "${daemon_json}"; then
  rm -f "${tmp}"
  exit 0
fi

if [[ -f "${daemon_json}" ]]; then
  cp -a "${daemon_json}" "${daemon_json}.bak.$(date +%s)"
fi

cat "${tmp}" > "${daemon_json}"
chmod 0644 "${daemon_json}"
rm -f "${tmp}"
if ! systemctl restart docker; then
  echo "Failed to restart Docker after daemon.json update" >&2
  exit 1
fi
EOF
}

# coolify_mark_bind_dashboard_state_script — Emit host-side script that updates
# bootstrap-hardening state after phase-4 dashboard binding is enforced.
coolify_mark_bind_dashboard_state_script() {
  cat <<'EOF'
set -Eeuo pipefail
state_file="/var/lib/bootstrap-hardening/state"
tmp="$(mktemp)"

if [[ ! -f "${state_file}" ]]; then
  rm -f "${tmp}"
  exit 0
fi

awk '
  BEGIN { seen=0 }
  /^bind_dashboard_to_tailscale=/ {
    print "bind_dashboard_to_tailscale=true"
    seen=1
    next
  }
  { print }
  END {
    if (seen == 0) {
      print "bind_dashboard_to_tailscale=true"
    }
  }
' "${state_file}" > "${tmp}"

install -m 0640 "${tmp}" "${state_file}"
rm -f "${tmp}"
EOF
}

# coolify_install_binding_guard_script — Emit host-side script that installs and
# enables the Coolify UFW binding guard timer after phase-4 binding is configured.
coolify_install_binding_guard_script() {
  cat <<'EOF'
set -Eeuo pipefail
guard_script="/usr/local/sbin/coolify-binding-guard.sh"
guard_service="/etc/systemd/system/coolify-binding-guard.service"
guard_timer="/etc/systemd/system/coolify-binding-guard.timer"

install -d -m 0755 /usr/local/sbin

cat > "${guard_script}" <<'GUARD_EOF'
#!/usr/bin/env bash
set -Euo pipefail

TAILSCALE_IFACE="tailscale0"
LOG_TAG="coolify-binding-guard"

log() { logger -t "${LOG_TAG}" -- "$*"; }

delete_non_tailscale_rule_numbers() {
  local numbered rules=()
  numbered="$(ufw status numbered 2>/dev/null || true)"
  mapfile -t rules < <(
    awk '
      BEGIN { IGNORECASE=1 }
      /\[[[:space:]]*[0-9]+\]/ && /ALLOW IN/ && /(8000|6001|6002)(\/tcp)?/ {
        line=tolower($0)
        if (index(line, "tailscale0") == 0) {
          rule=$1
          gsub(/\[/, "", rule)
          gsub(/\]/, "", rule)
          print rule
        }
      }
    ' <<< "${numbered}" | sort -rn
  )
  printf '%s\n' "${rules[@]}"
}

command -v ufw >/dev/null 2>&1 || { log "ufw not found; skipping."; exit 0; }
ufw_status="$(ufw status 2>/dev/null | head -1)" || true
[[ "${ufw_status}" == "Status: active" ]] || { log "UFW not active; skipping."; exit 0; }

changed=false
while IFS= read -r rule_number; do
  [[ -n "${rule_number}" ]] || continue
  ufw --force delete "${rule_number}" >/dev/null 2>&1 || true
  changed=true
done < <(delete_non_tailscale_rule_numbers)
if ! ufw status | grep -q "8000.*on ${TAILSCALE_IFACE}"; then
  ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 8000 comment "coolify-hardening-dashboard-tailscale" >/dev/null 2>&1 || true
  changed=true
fi
if ! ufw status | grep -q "6001.*on ${TAILSCALE_IFACE}"; then
  ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 6001 comment "coolify-hardening-soketi-tailscale" >/dev/null 2>&1 || true
  changed=true
fi
if ! ufw status | grep -q "6002.*on ${TAILSCALE_IFACE}"; then
  ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 6002 comment "coolify-hardening-terminal-tailscale" >/dev/null 2>&1 || true
  changed=true
fi

if "${changed}"; then
  log "UFW binding rules repaired on ${TAILSCALE_IFACE}."
fi
GUARD_EOF
chmod 0750 "${guard_script}"

cat > "${guard_service}" <<'UNIT_EOF'
[Unit]
Description=Verify Coolify dashboard UFW rules on tailscale0 are present
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/coolify-binding-guard.sh
UNIT_EOF

cat > "${guard_timer}" <<'TIMER_EOF'
[Unit]
Description=Periodically verify Coolify dashboard UFW rules on tailscale0

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
TIMER_EOF

systemctl daemon-reload
systemctl enable --now coolify-binding-guard.timer
systemctl start coolify-binding-guard.service || true
EOF
}

# coolify_set_wildcard_domain_script — Emit host-side script to update Coolify
# wildcard domain directly in PostgreSQL. Requires APP_DOMAIN in environment.
coolify_set_wildcard_domain_script() {
  cat <<'EOF'
set -Eeuo pipefail
: "${APP_DOMAIN:?APP_DOMAIN is required}"
coolify_env="/data/coolify/source/.env"
db_user="$(grep -m1 '^DB_USERNAME=' "${coolify_env}" | cut -d= -f2- || true)"
db_name="$(grep -m1 '^DB_DATABASE=' "${coolify_env}" | cut -d= -f2- || true)"
db_pass="$(grep -m1 '^DB_PASSWORD=' "${coolify_env}" | cut -d= -f2- || true)"
db_user="${db_user:-coolify}"
db_name="${db_name:-coolify}"
[[ -n "${db_pass}" ]] || { echo "DB_PASSWORD missing in ${coolify_env}" >&2; exit 1; }
# Verify coolify-db container is running before attempting docker exec
if ! docker ps --filter "name=coolify-db" --filter "status=running" --format "{{.Names}}" 2>/dev/null | grep -q "coolify-db"; then
  echo "coolify-db container is not running" >&2
  exit 1
fi
sql="$(cat <<SQL
DO \$\$
DECLARE
  targeted_rows integer;
  total_rows integer;
BEGIN
  SELECT COUNT(*) INTO targeted_rows FROM server_settings WHERE server_id = 0;
  IF targeted_rows = 1 THEN
    UPDATE server_settings
       SET wildcard_domain = 'http://${APP_DOMAIN}'
     WHERE server_id = 0;
    RETURN;
  END IF;

  SELECT COUNT(*) INTO total_rows FROM server_settings;
  IF targeted_rows = 0 AND total_rows = 1 THEN
    UPDATE server_settings
       SET wildcard_domain = 'http://${APP_DOMAIN}';
    RETURN;
  END IF;

  RAISE EXCEPTION 'Unable to identify a unique Coolify server_settings row (server_id=0 rows=%, total rows=%).',
    targeted_rows, total_rows;
END
\$\$;
SQL
)"
docker exec -i coolify-db sh -ceu '
  IFS= read -r PGPASSWORD
  export PGPASSWORD
  psql -v ON_ERROR_STOP=1 -U "$1" -d "$2" -c "$3" >/dev/null
' _ "${db_user}" "${db_name}" "${sql}" <<< "${db_pass}"
EOF
}

# coolify_reconcile_instance_settings_script — Emit host-side script to update
# Coolify instance settings directly in PostgreSQL. Requires DOMAIN and
# DEPLOY_MODE. Tunnel mode keeps fqdn empty so Coolify does not regenerate
# conflicting dashboard HTTPS routers; standard mode sets fqdn to the public
# dashboard URL.
coolify_reconcile_instance_settings_script() {
  cat <<'EOF'
set -Eeuo pipefail
: "${DOMAIN:?DOMAIN is required}"
: "${DEPLOY_MODE:?DEPLOY_MODE is required}"
coolify_env="/data/coolify/source/.env"
db_user="$(grep -m1 '^DB_USERNAME=' "${coolify_env}" | cut -d= -f2- || true)"
db_name="$(grep -m1 '^DB_DATABASE=' "${coolify_env}" | cut -d= -f2- || true)"
db_pass="$(grep -m1 '^DB_PASSWORD=' "${coolify_env}" | cut -d= -f2- || true)"
db_user="${db_user:-coolify}"
db_name="${db_name:-coolify}"
[[ -n "${db_pass}" ]] || { echo "DB_PASSWORD missing in ${coolify_env}" >&2; exit 1; }
if ! docker ps --filter "name=coolify-db" --filter "status=running" --format "{{.Names}}" 2>/dev/null | grep -q "coolify-db"; then
  echo "coolify-db container is not running" >&2
  exit 1
fi
sql_fqdn=""
if [[ "${DEPLOY_MODE}" == "tunnel" ]]; then
  sql_fqdn=""
else
  sql_fqdn="https://${DOMAIN}"
fi
sql="$(cat <<SQL
DO \$\$
DECLARE
  total_rows integer;
BEGIN
  SELECT COUNT(*) INTO total_rows FROM instance_settings;
  IF total_rows != 1 THEN
    RAISE EXCEPTION 'Expected exactly one instance_settings row, found %.', total_rows;
  END IF;

  UPDATE instance_settings
     SET is_registration_enabled = false,
         fqdn = '${sql_fqdn}'
   WHERE id = (SELECT id FROM instance_settings ORDER BY id LIMIT 1);
END
\$\$;
SQL
)"
docker exec -i coolify-db sh -ceu '
  IFS= read -r PGPASSWORD
  export PGPASSWORD
  psql -v ON_ERROR_STOP=1 -U "$1" -d "$2" -c "$3" >/dev/null
' _ "${db_user}" "${db_name}" "${sql}" <<< "${db_pass}"
EOF
}

# coolify_reconcile_pusher_env_script — Emit host-side script to reconcile
# PUSHER_* environment variables by deployment mode.
# Tunnel mode requires DEPLOY_MODE=tunnel and DOMAIN.
coolify_reconcile_pusher_env_script() {
  cat <<'EOF'
set -Eeuo pipefail
: "${DEPLOY_MODE:?DEPLOY_MODE is required}"
coolify_env="/data/coolify/source/.env"
mode="${DEPLOY_MODE}"
tmp="$(mktemp)"
sed '/^PUSHER_HOST=/d; /^PUSHER_PORT=/d; /^PUSHER_SCHEME=/d' "${coolify_env}" > "${tmp}"

if [[ "${mode}" == "tunnel" ]]; then
  : "${DOMAIN:?DOMAIN is required for tunnel mode}"
  cat >> "${tmp}" <<INNER
PUSHER_HOST=ws.${DOMAIN}
PUSHER_PORT=443
PUSHER_SCHEME=https
INNER
fi

if cmp -s "${tmp}" "${coolify_env}"; then
  rm -f "${tmp}"
  echo "PUSHER env unchanged for mode=${mode}"
  exit 0
fi

install -m 0600 "${tmp}" "${coolify_env}"
rm -f "${tmp}"
echo "PUSHER env updated for mode=${mode}"
docker compose -f /data/coolify/source/docker-compose.yml \
               -f /data/coolify/source/docker-compose.prod.yml \
               up -d --no-deps coolify >/dev/null
EOF
}

# coolify_configure_private_dashboard_routes_script — Emit host-side script to
# write managed Traefik routes for private dashboard/realtime hostnames.
coolify_configure_private_dashboard_routes_script() {
  cat <<'EOF'
set -Eeuo pipefail
: "${DOMAIN:?DOMAIN is required}"
: "${PRIVATE_TLS_RESOLVER:=privatedns}"

dynamic_dir="/data/coolify/proxy/dynamic"
route_file="${dynamic_dir}/coolify-private-dashboard.yaml"
mkdir -p "${dynamic_dir}"

cat > "${route_file}" <<CFG
# This file is managed by secure_coolify_ubuntu.
http:
  middlewares:
    coolify-private-gzip:
      compress: true
    coolify-private-force-https:
      redirectScheme:
        scheme: https
        permanent: true
  routers:
    coolify-private-dashboard-http:
      entryPoints:
        - http
      rule: "Host(\`${DOMAIN}\`)"
      service: noop@internal
      middlewares:
        - coolify-private-force-https
    coolify-private-dashboard-https:
      entryPoints:
        - https
      rule: "Host(\`${DOMAIN}\`)"
      service: coolify-private-dashboard
      middlewares:
        - coolify-private-gzip
      tls:
        certResolver: ${PRIVATE_TLS_RESOLVER}
        domains:
          - main: ${DOMAIN}
            sans:
              - ws.${DOMAIN}
    coolify-private-realtime-http:
      entryPoints:
        - http
      rule: "Host(\`ws.${DOMAIN}\`)"
      service: noop@internal
      middlewares:
        - coolify-private-force-https
    coolify-private-realtime-https:
      entryPoints:
        - https
      rule: "Host(\`ws.${DOMAIN}\`)"
      service: coolify-private-realtime
      tls: {}
    coolify-private-terminal-http:
      entryPoints:
        - http
      rule: "Host(\`ws.${DOMAIN}\`) && PathPrefix(\`/terminal/ws\`)"
      service: noop@internal
      middlewares:
        - coolify-private-force-https
      priority: 100
    coolify-private-terminal-https:
      entryPoints:
        - https
      rule: "Host(\`ws.${DOMAIN}\`) && PathPrefix(\`/terminal/ws\`)"
      service: coolify-private-terminal
      priority: 100
      tls: {}
  services:
    coolify-private-dashboard:
      loadBalancer:
        servers:
          - url: http://coolify:8080
    coolify-private-realtime:
      loadBalancer:
        servers:
          - url: http://coolify-realtime:6001
    coolify-private-terminal:
      loadBalancer:
        servers:
          - url: http://coolify-realtime:6002
CFG

echo "Private dashboard routes written: ${route_file}"
EOF
}

# coolify_configure_private_tls_dns_script — Emit host-side script to ensure
# Traefik can issue trusted certificates for private dashboard/realtime routes
# via ACME DNS-01 using Cloudflare.
coolify_configure_private_tls_dns_script() {
  cat <<'EOF'
set -Eeuo pipefail
: "${CF_DNS_API_TOKEN:?CF_DNS_API_TOKEN is required}"
: "${CF_ZONE_NAME:?CF_ZONE_NAME is required}"
: "${PRIVATE_TLS_RESOLVER:=privatedns}"

proxy_dir="/data/coolify/proxy"
compose_file="${proxy_dir}/docker-compose.yml"
env_file="${proxy_dir}/.env"
dynamic_dir="${proxy_dir}/dynamic"
default_redirect_file="${dynamic_dir}/default_redirect_503.yaml"
coolify_dynamic_file="${dynamic_dir}/coolify.yaml"

[[ -f "${compose_file}" ]] || { echo "Missing ${compose_file}" >&2; exit 1; }
install -d -m 0700 "${proxy_dir}"
cat > "${env_file}" <<ENV
CLOUDFLARE_DNS_API_TOKEN=${CF_DNS_API_TOKEN}
CF_DNS_API_TOKEN=${CF_DNS_API_TOKEN}
ENV
chmod 0600 "${env_file}"

reconcile_private_tls_compose() {
  python3 - "${compose_file}" "${PRIVATE_TLS_RESOLVER}" "${CF_ZONE_NAME}" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
resolver = sys.argv[2]
zone = sys.argv[3]
env_path = "/data/coolify/proxy/.env"
required_flags = [
    f"--certificatesresolvers.{resolver}.acme.dnschallenge=true",
    f"--certificatesresolvers.{resolver}.acme.dnschallenge.provider=cloudflare",
    f"--certificatesresolvers.{resolver}.acme.dnschallenge.resolvers=1.1.1.1:53,8.8.8.8:53",
    f"--certificatesresolvers.{resolver}.acme.email=coolify-admin@{zone}",
    f"--certificatesresolvers.{resolver}.acme.storage=/traefik/acme.json",
]

text = path.read_text()
lines = text.splitlines(keepends=True)

service_start = next((idx for idx, line in enumerate(lines) if re.match(r"^  traefik:\s*$", line)), None)
if service_start is None:
    raise SystemExit("Traefik service block not found in docker-compose.yml")

service_end = service_start + 1
while service_end < len(lines) and not re.match(r"^  [A-Za-z0-9_-]+:\s*$", lines[service_end]):
    service_end += 1

service_lines = lines[service_start + 1 : service_end]
scrubbed_service_lines = []
resolver_flag_pattern = re.compile(rf"^ {{6}}- '?--certificatesresolvers\.{re.escape(resolver)}\..*'?\s*$")
for line in service_lines:
    if re.match(r"^ {6}- (?:CLOUDFLARE_DNS_API_TOKEN|CF_DNS_API_TOKEN)=.*$", line):
        continue
    if re.match(r"^ {6}- .*certificatesresolvers\.letsencrypt\..*$", line):
        continue
    if resolver_flag_pattern.match(line):
        continue
    scrubbed_service_lines.append(line)
service_lines = scrubbed_service_lines

def find_section(block_lines, key):
    prefix = f"    {key}:"
    for idx, line in enumerate(block_lines):
        if line.startswith(prefix):
            return idx
    return None

def section_end(block_lines, start_idx):
    idx = start_idx + 1
    while idx < len(block_lines):
        if re.match(r"^    [A-Za-z0-9_-]+:\s*$", block_lines[idx]):
            break
        idx += 1
    return idx

env_idx = find_section(service_lines, "env_file")
if env_idx is None:
    insert_idx = 0
    for idx, line in enumerate(service_lines):
        if re.match(r"^    (image|container_name|restart):", line):
            insert_idx = idx + 1
            break
    service_lines[insert_idx:insert_idx] = ["    env_file:\n", f"      - {env_path}\n"]
    env_idx = find_section(service_lines, "env_file")
else:
    env_end = section_end(service_lines, env_idx)
    env_items = service_lines[env_idx + 1 : env_end]
    if f"      - {env_path}\n" not in env_items:
        env_items.append(f"      - {env_path}\n")
        service_lines = service_lines[: env_idx + 1] + env_items + service_lines[env_end:]

command_idx = find_section(service_lines, "command")
if command_idx is None:
    env_idx = find_section(service_lines, "env_file")
    if env_idx is None:
        raise SystemExit("Unable to locate insertion point for Traefik command block")
    insert_idx = section_end(service_lines, env_idx)
    service_lines[insert_idx:insert_idx] = ["    command:\n"]
    command_idx = insert_idx

command_end = section_end(service_lines, command_idx)
command_items = service_lines[command_idx + 1 : command_end]
existing_command_flags = set()
for line in command_items:
    match = re.match(r"^ {6}- '?([^'\n]+)'?\s*$", line)
    if match:
        existing_command_flags.add(match.group(1))

for flag in required_flags:
    if flag not in existing_command_flags:
        command_items.append(f"      - '{flag}'\n")

service_lines = service_lines[: command_idx + 1] + command_items + service_lines[command_end:]
lines = lines[: service_start + 1] + service_lines + lines[service_end:]
path.write_text("".join(lines))
PY
}

reconcile_private_tls_compose

scrub_default_redirect_public_resolver() {
  [[ -f "${default_redirect_file}" ]] || return 0
  python3 - "${default_redirect_file}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
text = text.replace("      tls:\n        certResolver: letsencrypt\n", "")
path.write_text(text)
PY
}

scrub_coolify_public_https_routers() {
  [[ -f "${coolify_dynamic_file}" ]] || return 0
  python3 - "${coolify_dynamic_file}" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text()
for router_name in ("coolify-https", "coolify-realtime-wss", "coolify-terminal-wss"):
    pattern = rf"(?ms)^    {router_name}:\n(?:      .*\n|        .*\n)*"
    text = re.sub(pattern, "", text)
path.write_text(text)
PY
}

# Coolify regenerates this catchall file with a public resolver; remove it in
# tunnel mode so wildcard traffic cannot trigger public ACME flows.
scrub_default_redirect_public_resolver
scrub_coolify_public_https_routers

if docker compose -f "${compose_file}" config >/dev/null 2>&1; then
  docker compose -f "${compose_file}" up -d >/dev/null
else
  echo "Invalid Traefik compose generated at ${compose_file}" >&2
  exit 1
fi

for _ in $(seq 1 30); do
  scrub_default_redirect_public_resolver
  scrub_coolify_public_https_routers
  if ! grep -Eq '^[[:space:]]*certResolver:[[:space:]]*letsencrypt[[:space:]]*$' "${default_redirect_file}" 2>/dev/null \
    && ! grep -Eq '^[[:space:]]*coolify-(https|realtime-wss|terminal-wss):[[:space:]]*$|^[[:space:]]*certresolver:[[:space:]]*letsencrypt[[:space:]]*$' "${coolify_dynamic_file}" 2>/dev/null; then
    break
  fi
  sleep 1
done

if grep -Eq '^[[:space:]]*certResolver:[[:space:]]*letsencrypt[[:space:]]*$' "${default_redirect_file}" 2>/dev/null; then
  echo "Public letsencrypt resolver remained in ${default_redirect_file}" >&2
  exit 1
fi

if grep -Eq '^[[:space:]]*coolify-(https|realtime-wss|terminal-wss):[[:space:]]*$|^[[:space:]]*certresolver:[[:space:]]*letsencrypt[[:space:]]*$' "${coolify_dynamic_file}" 2>/dev/null; then
  echo "Public Coolify HTTPS routers remained in ${coolify_dynamic_file}" >&2
  exit 1
fi

wait_for_private_tls_ready() {
  local host="vps.invalid"
  local ws_host="ws.vps.invalid"
  local attempts=120
  local delay=5
  local attempt dashboard_code dashboard_code_insecure cert_meta cert_subject cert_issuer

  if ! command -v curl >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
    return 0
  fi

  host="${DOMAIN}"
  ws_host="ws.${DOMAIN}"
  for (( attempt=1; attempt<=attempts; attempt++ )); do
    dashboard_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
      --resolve "${host}:443:127.0.0.1" "https://${host}/api/v1/health" 2>/dev/null || true)"
    dashboard_code_insecure="$(curl -k -s -o /dev/null -w '%{http_code}' --max-time 10 \
      --resolve "${host}:443:127.0.0.1" "https://${host}/api/v1/health" 2>/dev/null || true)"
    dashboard_code="${dashboard_code:-000}"
    dashboard_code_insecure="${dashboard_code_insecure:-000}"
    dashboard_code="${dashboard_code:0:3}"
    dashboard_code_insecure="${dashboard_code_insecure:0:3}"

    cert_meta="$(printf '' | openssl s_client -connect 127.0.0.1:443 -servername "${host}" -showcerts 2>/dev/null \
      | openssl x509 -noout -subject -issuer -ext subjectAltName 2>/dev/null || true)"
    cert_subject="$(awk -F= '/^subject=/{print $2; exit}' <<< "${cert_meta}" | sed 's/^ *//')"
    cert_issuer="$(awk -F= '/^issuer=/{print $2; exit}' <<< "${cert_meta}" | sed 's/^ *//')"

    if [[ "${dashboard_code}" =~ ^2[0-9][0-9]$ ]] \
      && ! grep -Fq "TRAEFIK DEFAULT CERT" <<< "${cert_meta}" \
      && grep -Fq "DNS:${host}" <<< "${cert_meta}" \
      && grep -Fq "DNS:${ws_host}" <<< "${cert_meta}"; then
      echo "Private TLS certificate ready for ${host} (HTTP ${dashboard_code})."
      return 0
    fi

    if (( attempt == 1 || attempt % 12 == 0 )); then
      if [[ "${dashboard_code_insecure}" =~ ^2[0-9][0-9]$ && ! "${dashboard_code}" =~ ^2[0-9][0-9]$ ]]; then
        echo "Waiting for trusted private TLS on ${host}: route is up behind untrusted cert (verified=${dashboard_code}, insecure=${dashboard_code_insecure}, subject=${cert_subject:-unknown}, issuer=${cert_issuer:-unknown}, attempt=${attempt}/${attempts})."
      else
        echo "Waiting for trusted private TLS on ${host}: verified=${dashboard_code}, insecure=${dashboard_code_insecure}, subject=${cert_subject:-unknown}, issuer=${cert_issuer:-unknown}, attempt=${attempt}/${attempts}."
      fi
    fi

    if (( attempt < attempts )); then
      sleep "${delay}"
    fi
  done

  echo "Timed out waiting for trusted private TLS on ${host}; verified=${dashboard_code:-000}, insecure=${dashboard_code_insecure:-000}, subject=${cert_subject:-unknown}, issuer=${cert_issuer:-unknown}" >&2
  return 1
}

wait_for_private_tls_ready

echo "Private TLS DNS challenge configured for resolver '${PRIVATE_TLS_RESOLVER}'."
EOF
}

# coolify_remove_private_dashboard_routes_script — Emit host-side script to
# remove managed private dashboard route file when not in tunnel mode.
coolify_remove_private_dashboard_routes_script() {
  cat <<'EOF'
set -Eeuo pipefail
route_file="/data/coolify/proxy/dynamic/coolify-private-dashboard.yaml"
if [[ -f "${route_file}" ]]; then
  rm -f "${route_file}"
  echo "Removed private dashboard routes: ${route_file}"
else
  echo "Private dashboard routes already absent: ${route_file}"
fi
EOF
}

# coolify_add_coolify_root_key_script — Emit host-side script that inserts Coolify's
# generated SSH public key into /root/.ssh/authorized_keys idempotently.
coolify_add_coolify_root_key_script() {
  cat <<'EOF'
set -Eeuo pipefail
key_dir="/data/coolify/ssh/keys"
keyfile="$(ls "${key_dir}"/ssh_key@* "${key_dir}"/id.root@* 2>/dev/null | head -1 || true)"
if [[ -z "${keyfile}" ]]; then
  keyfile="$(find "${key_dir}" -maxdepth 1 -type f ! -name '*.pub' 2>/dev/null | head -1 || true)"
fi
[[ -n "${keyfile}" ]] || { echo "No Coolify SSH key found — skipping"; exit 0; }
pubkey="$(ssh-keygen -y -f "${keyfile}")"
auth="/root/.ssh/authorized_keys"
mkdir -p /root/.ssh && chmod 700 /root/.ssh
touch "${auth}" && chmod 600 "${auth}"
tmp="$(mktemp)"
awk '
  $1 ~ /^(ssh-(rsa|ed25519|dss)|ecdsa-[^[:space:]]+)$/ && NF >= 2 {
    if (!seen[$2]++) {
      print $1 " " $2
    }
  }
' "${auth}" > "${tmp}" 2>/dev/null || true
key_data="$(awk '{print $2}' <<< "${pubkey}")"
if awk '{print $2}' "${tmp}" 2>/dev/null | grep -qxF "${key_data}"; then
  echo "Coolify key already in root authorized_keys"
else
  printf '%s\n' "${pubkey}" >> "${tmp}"
  echo "Coolify key added to root authorized_keys"
fi
install -m 600 "${tmp}" "${auth}"
rm -f "${tmp}"
EOF
}

# coolify_fix_host_docker_internal_script — Emit host-side script that patches
# host.docker.internal in Coolify compose files to the current coolify bridge gateway.
coolify_fix_host_docker_internal_script() {
  cat <<'EOF'
set -Eeuo pipefail
compose_yml="/data/coolify/source/docker-compose.yml"
[[ -f "${compose_yml}" ]] || { echo "docker-compose.yml not found — skipping"; exit 0; }
gateway="$(docker network inspect coolify --format '{{range .IPAM.Config}}{{.Subnet}} {{.Gateway}} {{end}}' 2>/dev/null \
  | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -v '/[0-9]' | head -1 || true)"
if [[ -z "${gateway}" ]]; then
  echo "Cannot determine coolify network gateway — skipping host.docker.internal fix"
  exit 0
fi
current="$(grep -m1 'host\.docker\.internal:' "${compose_yml}" | awk -F: '{print $NF}' | tr -d ' ' || true)"
if [[ "${current}" == "${gateway}" ]]; then
  echo "host.docker.internal already set to ${gateway}"
  exit 0
fi
sed -i "s|host\.docker\.internal:.*|host.docker.internal:${gateway}|g" "${compose_yml}"
echo "Patched host.docker.internal → ${gateway}"
docker compose -f /data/coolify/source/docker-compose.yml \
               -f /data/coolify/source/docker-compose.prod.yml \
               up -d --force-recreate coolify soketi 2>&1 | tail -5
EOF
}

# coolify_install_cloudflared_script — Emit host-side script to install cloudflared
# with apt first, then Cloudflare repo fallback.
coolify_install_cloudflared_script() {
  cat <<'EOF'
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
if bash -c "apt-get update -qq && apt-get install -y -qq cloudflared" 2>/dev/null; then
  exit 0
fi
echo "Trying Cloudflare repository..."
bash -o pipefail -c "curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null"
bash -c "echo \"deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared \$(lsb_release -cs) main\" | tee /etc/apt/sources.list.d/cloudflared.list >/dev/null"
bash -c "apt-get update -qq && apt-get install -y -qq cloudflared"
EOF
}

# coolify_configure_cloudflared_script — Emit host-side script to write tunnel creds/config
# and start cloudflared service. Requires TUNNEL_ID, TUNNEL_SECRET, CF_ACCOUNT_ID, DOMAIN,
# APP_DOMAIN, CF_ZONE_NAME in environment.
coolify_configure_cloudflared_script() {
  cat <<'EOF'
set -Eeuo pipefail
: "${TUNNEL_ID:?TUNNEL_ID is required}"
: "${TUNNEL_SECRET:?TUNNEL_SECRET is required}"
: "${CF_ACCOUNT_ID:?CF_ACCOUNT_ID is required}"
: "${DOMAIN:?DOMAIN is required}"
: "${APP_DOMAIN:?APP_DOMAIN is required}"
: "${CF_ZONE_NAME:?CF_ZONE_NAME is required}"

creds_json="$(jq -n --arg id "${TUNNEL_ID}" --arg secret "${TUNNEL_SECRET}" --arg account "${CF_ACCOUNT_ID}" \
  '{AccountTag:$account,TunnelID:$id,TunnelSecret:$secret}')"
mkdir -p /etc/cloudflared
printf '%s' "${creds_json}" > "/etc/cloudflared/${TUNNEL_ID}.json"
chmod 600 "/etc/cloudflared/${TUNNEL_ID}.json"

extra_apex_ingress=""
if [[ "${APP_DOMAIN}" != "${CF_ZONE_NAME}" ]]; then
  extra_apex_ingress="  - hostname: \"*.${CF_ZONE_NAME}\"
    service: http://localhost:80
"
fi
cat > /etc/cloudflared/config.yml <<CFG
tunnel: ${TUNNEL_ID}
credentials-file: /etc/cloudflared/${TUNNEL_ID}.json

ingress:
  - hostname: ${DOMAIN}
    service: http_status:404
  - hostname: ws.${DOMAIN}
    service: http_status:404
  - hostname: "*.${APP_DOMAIN}"
    service: http://localhost:80
${extra_apex_ingress}  - service: http_status:404
CFG

cloudflared service install 2>/dev/null || true
systemctl enable --now cloudflared
EOF
}

# collect_common_inputs — Prompt for inputs shared by both deploy.sh and setup.sh.
# Each script calls this then adds its own script-specific prompts.
collect_common_inputs() {
  load_cloudflare_tokens_from_files
  [[ -n "${SERVER_IP}" ]]   || prompt_value  SERVER_IP "Server public IP" "" "${IPV4_RE}"
  [[ -n "${ADMIN_USER}" ]]  || prompt_value  ADMIN_USER "Admin username" "coolifyadmin" "${LINUX_USER_RE}"
  [[ -n "${PUBKEY_FILE}" ]] || prompt_value  PUBKEY_FILE "SSH public key file" "${HOME}/.ssh/id_ed25519.pub"
  [[ -n "${TAILSCALE_AUTH_KEY}" ]] || prompt_value TAILSCALE_AUTH_KEY "Tailscale auth key (tskey-auth-...)" ""
  [[ -n "${DEPLOY_MODE}" ]] || prompt_choice DEPLOY_MODE "Deployment mode" "tunnel" "tunnel" "standard"
  [[ -n "${DOMAIN}" ]]      || prompt_value  DOMAIN "Domain name (FQDN)" "" "${FQDN_RE}"
  if [[ -z "${CF_API_TOKEN:-}" ]]; then
    if is_true "${AUTO_YES}"; then
      die "Cloudflare API token is required in non-interactive mode. Set CF_API_TOKEN or use --cf-api-token-file."
    fi
    prompt_secret CF_API_TOKEN "Cloudflare API token"
  fi
  # CF_ZONE intentionally left as-is (derived from domain when empty; --cf-zone overrides)
  [[ -n "${SWAP_SIZE}" ]]   || SWAP_SIZE="2G"
  if [[ -z "${SERVER_TIMEZONE:-}" ]]; then
    if is_true "${AUTO_YES}"; then
      die "Server timezone is required in non-interactive mode. Set SERVER_TIMEZONE or use --server-timezone."
    fi
    prompt_value SERVER_TIMEZONE "Server timezone (IANA, e.g. Australia/Melbourne)" "UTC" "${TIMEZONE_RE}"
  fi
  # App subdomain scope: where Coolify auto-assigns app URLs.
  #   apex → appname.CF_ZONE     e.g. appname.example.com      (default — Free Universal SSL)
  #   vps  → appname.DOMAIN      e.g. appname.vps.example.com  (server-scoped; needs ACM/Enterprise for proxied SSL)
  if [[ -z "${APP_DOMAIN_MODE}" ]]; then
    printf '  App subdomain scope:\n'
    printf '    apex → appname.ZONE_APEX                (default — works with Cloudflare Free SSL)\n'
    printf '    vps  → appname.%s  (scoped to this server; requires paid ACM or Enterprise for proxied SSL)\n' "${DOMAIN:-DOMAIN}"
    prompt_choice APP_DOMAIN_MODE "App subdomain scope" "apex" "apex" "vps"
  fi
}

# resolve_app_domain — Set APP_DOMAIN from APP_DOMAIN_MODE after CF_ZONE_NAME is known.
# Call this after cf_get_zone_id.
resolve_app_domain() {
  if [[ "${APP_DOMAIN_MODE}" == "apex" ]]; then
    APP_DOMAIN="${CF_ZONE_NAME}"
  else
    APP_DOMAIN="${DOMAIN}"
    if [[ "${DOMAIN}" != "${CF_ZONE_NAME}" ]]; then
      warn "vps mode: DOMAIN (${DOMAIN}) is a subdomain of zone ${CF_ZONE_NAME}."
      warn "Apps at appname.${DOMAIN} are two levels deep and NOT covered by Cloudflare Free Universal SSL."
      warn "Use --app-domain-mode apex for free proxied SSL, or provision ACM / CF for SaaS manually."
    fi
  fi
  log "App subdomain scope: ${APP_DOMAIN_MODE} — new apps at appname.${APP_DOMAIN}"
}

# print_deployment_summary — Print completion banner and next-steps block.
# Uses globals: SERVER_IP, TS_IP, ADMIN_USER, DEPLOY_MODE, DOMAIN, CF_ZONE_NAME, APP_DOMAIN, TUNNEL_ID, SERVER_TIMEZONE
summary_box_print_prefixed_text() {
  local first_prefix="$1" continuation_prefix="$2" text="$3"
  local width=59 prefix available chunk
  prefix="${first_prefix}"

  while :; do
    available=$(( width - ${#prefix} ))
    if (( ${#text} <= available )); then
      printf '│ %s%-*s│\n' "${prefix}" "${available}" "${text}"
      return 0
    fi

    chunk="${text:0:available}"
    if [[ "${chunk}" == *" "* && "${text:available:1}" != " " ]]; then
      chunk="${chunk% *}"
    fi
    [[ -n "${chunk}" ]] || chunk="${text:0:available}"

    printf '│ %s%-*s│\n' "${prefix}" "${available}" "${chunk}"
    text="${text:${#chunk}}"
    text="${text## }"
    prefix="${continuation_prefix}"
  done
}

summary_box_print_field() {
  local label="$1" value="$2" prefix
  printf -v prefix '  %-16s: ' "${label}"
  summary_box_print_prefixed_text "${prefix}" "                    " "${value}"
}

summary_box_print_continuation() {
  summary_box_print_prefixed_text "                    " "                    " "$1"
}

print_deployment_summary() {
  local dashboard_url
  if [[ "${DEPLOY_MODE}" == "tunnel" ]]; then
    dashboard_url="https://${DOMAIN}"
  else
    dashboard_url="http://${TS_IP}:8000"
  fi

  printf '\n'
  printf '┌─────────────────────────────────────────────────────────────┐\n'
  printf '│                    DEPLOYMENT COMPLETE                      │\n'
  printf '├─────────────────────────────────────────────────────────────┤\n'
  summary_box_print_field "Server Public IP" "${SERVER_IP}"
  summary_box_print_field "Tailscale IP" "${TS_IP}"
  summary_box_print_field "Admin User" "${ADMIN_USER}"
  summary_box_print_field "Deploy Mode" "${DEPLOY_MODE}"
  summary_box_print_field "Domain" "${DOMAIN}"
  summary_box_print_field "Server Timezone" "${SERVER_TIMEZONE}"
  summary_box_print_field "Dashboard URL" "${dashboard_url}"
  summary_box_print_field "SSH Access" "ssh ${ADMIN_USER}@${TS_IP}"
  printf '├─────────────────────────────────────────────────────────────┤\n'
  if [[ "${DEPLOY_MODE}" == "standard" ]]; then
    summary_box_print_field "DNS" "A ${DOMAIN} -> ${SERVER_IP}"
    summary_box_print_field "Wildcard DNS" "A *.${APP_DOMAIN}"
    [[ "${APP_DOMAIN}" != "${CF_ZONE_NAME}" ]] \
      && summary_box_print_continuation "+ A *.${CF_ZONE_NAME}"
  else
    summary_box_print_field "DNS" "A ${DOMAIN} -> ${TS_IP} (DNS-only)"
    summary_box_print_continuation "+ A ws.${DOMAIN} -> ${TS_IP} (DNS-only)"
    summary_box_print_field "Wildcard DNS" "CNAME *.${APP_DOMAIN}"
    [[ "${APP_DOMAIN}" != "${CF_ZONE_NAME}" ]] \
      && summary_box_print_continuation "+ CNAME *.${CF_ZONE_NAME}"
    summary_box_print_field "Tunnel ID" "${TUNNEL_ID}"
    summary_box_print_field "Public Dashboard" "blocked (Tailscale-only)"
    summary_box_print_field "Public WebSocket" "blocked (Tailscale-only)"
  fi
  printf '└─────────────────────────────────────────────────────────────┘\n'
  printf '\n'
  log "Next steps:"
  if [[ "${DEPLOY_MODE}" == "tunnel" ]]; then
    log "  1. Open https://${DOMAIN} and create your Coolify admin account."
  else
    log "  1. Open http://${TS_IP}:8000 and create your Coolify admin account."
  fi
  log ""
  if [[ "${DEPLOY_MODE}" == "tunnel" ]]; then
    log "  2. Private dashboard/websocket TLS is already configured for https://${DOMAIN} and wss://ws.${DOMAIN}."
  else
    log "  2. Cloudflare SSL mode (one-time):"
    log "       Cloudflare dashboard > your zone > SSL/TLS > Overview > set to 'Full'"
    log "       (use Full Strict only if you manage strict-valid origin certs for all proxied hosts)"
  fi
  log ""
  log "  3. Start the proxy: Coolify UI > Servers > localhost > Proxy > Start Proxy"
  log "       (required for app subdomains to route through Traefik)"
  log ""
  log "  4. Wildcard Domain is already set to http://${APP_DOMAIN} (done automatically)."
  log "       New apps will get http://appname.${APP_DOMAIN}"
  log "       If an app already has a sslip.io URL: App > Settings > Domains > update it."
  log ""
  log "  5. For each app deployment behind the wildcard route:"
  log "       Use http:// for the app's Coolify domain entry; Cloudflare adds TLS at the edge."
  log "       Example: http://myapp.${APP_DOMAIN}"
  log ""
  log "  6. Deploy your first app — it gets a subdomain + Cloudflare SSL automatically."
}

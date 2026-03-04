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
  local record_id
  record_id="$(printf '%s' "${existing}" | jq -r '.result[0].id // empty')"
  local body
  body="$(jq -n --arg name "${name}" --arg ip "${ip}" --argjson proxied "${proxied}" \
    '{type:"A",name:$name,content:$ip,proxied:$proxied,ttl:1}')"
  local resp

  if [[ -n "${record_id}" ]]; then
    resp="$(cf_api PUT "/zones/${CF_ZONE_ID}/dns_records/${record_id}" "${body}")"
    cf_expect_success "Cloudflare A record update (${name})" "${resp}"
    log "Updated A record: ${name} → ${ip} (proxied=${proxied})"
  else
    resp="$(cf_api POST "/zones/${CF_ZONE_ID}/dns_records" "${body}")"
    cf_expect_success "Cloudflare A record create (${name})" "${resp}"
    log "Created A record: ${name} → ${ip} (proxied=${proxied})"
  fi
}

cf_create_tunnel() {
  local stop_fn="${1:-}"   # optional: name of function to call to stop cloudflared
  local tunnel_name="${DOMAIN%%.*}-coolify"

  # Delete any existing tunnel with the same name (idempotent re-run support).
  # Stop cloudflared first so it releases active connections — the CF API rejects DELETE for
  # tunnels with active connections, and the name stays reserved even after a failed delete.
  local existing_id
  existing_id="$(cf_tunnel_api GET "/accounts/${CF_ACCOUNT_ID}/cfd_tunnel?name=${tunnel_name}&is_deleted=false" \
    | jq -r '.result[0].id // empty')"
  if [[ -n "${existing_id}" ]]; then
    log "Stopping cloudflared on server to release tunnel connections before delete..."
    [[ -n "${stop_fn}" ]] && "${stop_fn}"
    sleep 3  # Allow connections to close
    log "Deleting stale tunnel ${tunnel_name} (${existing_id}) before recreating..."
    local delete_resp delete_ok delete_err
    delete_resp="$(cf_tunnel_api DELETE "/accounts/${CF_ACCOUNT_ID}/cfd_tunnel/${existing_id}" 2>/dev/null || true)"
    delete_ok="$(printf '%s' "${delete_resp}" | jq -r '.success // false' 2>/dev/null || echo "false")"
    if [[ "${delete_ok}" == "true" ]]; then
      log "Deleted stale tunnel ${existing_id}"
    else
      delete_err="$(printf '%s' "${delete_resp}" | jq -r '[.errors[]?.message] | join("; ")' 2>/dev/null || true)"
      [[ -n "${delete_err}" && "${delete_err}" != "null" ]] || delete_err="unknown"
      warn "Could not delete stale tunnel ${existing_id} (${delete_err}); proceeding anyway."
    fi
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
  local record_id
  record_id="$(printf '%s' "${existing}" | jq -r '.result[0].id // empty')"
  local body
  body="$(jq -n --arg name "${name}" --arg target "${target}" \
    '{type:"CNAME",name:$name,content:$target,proxied:true,ttl:1}')"
  local resp

  if [[ -n "${record_id}" ]]; then
    resp="$(cf_api PUT "/zones/${CF_ZONE_ID}/dns_records/${record_id}" "${body}")"
    cf_expect_success "Cloudflare CNAME update (${name})" "${resp}"
    log "Updated CNAME: ${name} → ${target}"
  else
    resp="$(cf_api POST "/zones/${CF_ZONE_ID}/dns_records" "${body}")"
    cf_expect_success "Cloudflare CNAME create (${name})" "${resp}"
    log "Created CNAME: ${name} → ${target}"
  fi
}

cf_delete_host_records() {
  local name="$1"
  local type existing record_id resp

  for type in A AAAA CNAME; do
    existing="$(cf_api GET "/zones/${CF_ZONE_ID}/dns_records?type=${type}&name=${name}")"
    while IFS= read -r record_id; do
      [[ -n "${record_id}" ]] || continue
      resp="$(cf_api DELETE "/zones/${CF_ZONE_ID}/dns_records/${record_id}")"
      cf_expect_success "Cloudflare ${type} record delete (${name})" "${resp}"
      log "Deleted ${type} record: ${name} (${record_id})"
    done < <(printf '%s' "${existing}" | jq -r '.result[]?.id // empty')
  done
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

  step "3/5" "Install Docker & Coolify"

  # Install Docker (skip if already present).
  if "${has_docker_fn}"; then
    log "Docker already installed — skipping install."
  else
    log "Installing Docker via official apt repository..."
    "${install_docker_fn}" || die "Docker installation failed."
    pass "Docker installed"
  fi
  pass "Docker present"

  # Start DOCKER-USER hardening service
  "${start_docker_user_fn}" || die "Failed to start docker-user-hardening.service"

  # Gate D: Verify DOCKER-USER rules
  "${verify_docker_user_fn}" "Gate D"

  # Install Coolify (skip if already running)
  if "${has_coolify_env_fn}"; then
    log "Coolify .env found — skipping install (already installed)."
    pass "Coolify already installed"
  else
    log "Installing Coolify (this may take a few minutes)..."
    "${install_coolify_fn}" || die "Coolify installation failed."
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
  "${fix_host_docker_internal_fn}" || die "Failed to reconcile host.docker.internal in Coolify compose."
  pass "host.docker.internal patched in Coolify docker-compose"
}

# coolify_phase4_binding_dns_shared — Shared phase 4 orchestration used by
# deploy.sh and setup.sh. Transport-specific behavior is injected via callbacks.
# Callback signatures:
#   coolify_env_exists_fn()
#   configure_binding_fn()
#   set_wildcard_domain_fn()
#   reconcile_pusher_fn()
#   install_cloudflared_fn()
#   configure_cloudflared_fn()
#   stop_cloudflared_fn()
coolify_phase4_binding_dns_shared() {
  local coolify_env_exists_fn="$1"
  local configure_binding_fn="$2"
  local set_wildcard_domain_fn="$3"
  local reconcile_pusher_fn="$4"
  local install_cloudflared_fn="$5"
  local configure_cloudflared_fn="$6"
  local stop_cloudflared_fn="$7"

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

  log "Binding Coolify dashboard to Tailscale IP..."
  "${configure_binding_fn}" || die "configure_coolify_binding.sh failed. Fix binding errors before continuing."
  pass "Dashboard binding configured"

  # Set Coolify wildcard domain directly in the database.
  # configure_coolify_binding.sh already waited up to 60s for port 8000 to bind,
  # which guarantees the s6 startup sequence (migrate→seed→init) has completed and
  # the server_settings row (server_id=0, the hardcoded Localhost server) exists.
  # The API PATCH /servers/{uuid} does not expose wildcard_domain, so we write
  # directly to PostgreSQL via docker exec on the coolify-db container.
  log "Setting Coolify wildcard domain to http://${APP_DOMAIN}..."
  "${set_wildcard_domain_fn}" || die "Failed to update wildcard domain in Coolify database"
  pass "Coolify wildcard domain: http://${APP_DOMAIN}"

  # Configure PUSHER_* for the selected mode.
  # Tunnel mode keeps realtime traffic on Tailscale; standard mode clears explicit overrides.
  log "Reconciling PUSHER env vars for ${DEPLOY_MODE} mode..."
  "${reconcile_pusher_fn}" || die "Failed to reconcile PUSHER env vars"
  if [[ "${DEPLOY_MODE}" == "tunnel" ]]; then
    pass "PUSHER env vars configured: ${TS_IP}:6001 (http)"
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
    return 0
  fi

  # Tunnel mode: create tunnel, install cloudflared, CNAME
  log "Creating Cloudflare Tunnel..."
  cf_create_tunnel "${stop_cloudflared_fn}"
  pass "Tunnel created: ${TUNNEL_ID}"

  log "Installing cloudflared..."
  "${install_cloudflared_fn}" || die "Failed to install cloudflared"
  pass "cloudflared installed"

  "${configure_cloudflared_fn}" \
    || die "Failed to write cloudflared credentials/config or start service"
  local wc_summary="*.${APP_DOMAIN}"
  [[ "${APP_DOMAIN}" != "${CF_ZONE_NAME}" ]] && wc_summary+=" and *.${CF_ZONE_NAME}"
  pass "Tunnel credentials and config written (wildcards: ${wc_summary})"
  pass "cloudflared service running"

  # Private-only default: remove exact dashboard/realtime records on every run.
  # This guarantees redeploys remove any previous public exposure from older profiles.
  cf_delete_host_records "${DOMAIN}"
  pass "DNS host records removed: ${DOMAIN}"
  cf_delete_host_records "ws.${DOMAIN}"
  pass "DNS host records removed: ws.${DOMAIN}"

  # Create wildcard CNAME records for app routing through Traefik only.
  local tunnel_target="${TUNNEL_ID}.cfargotunnel.com"
  cf_upsert_cname "*.${APP_DOMAIN}" "${tunnel_target}"
  pass "DNS wildcard CNAME configured: *.${APP_DOMAIN} → ${tunnel_target}"
  if [[ "${APP_DOMAIN}" != "${CF_ZONE_NAME}" ]]; then
    cf_upsert_cname "*.${CF_ZONE_NAME}" "${tunnel_target}"
    pass "DNS wildcard CNAME configured: *.${CF_ZONE_NAME} → ${tunnel_target}"
  fi
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
sql="UPDATE server_settings SET wildcard_domain = 'http://${APP_DOMAIN}' WHERE server_id = 0;"
docker exec -i coolify-db sh -ceu '
  IFS= read -r PGPASSWORD
  export PGPASSWORD
  psql -v ON_ERROR_STOP=1 -U "$1" -d "$2" -c "$3" >/dev/null
' _ "${db_user}" "${db_name}" "${sql}" <<< "${db_pass}"
EOF
}

# coolify_reconcile_pusher_env_script — Emit host-side script to reconcile
# PUSHER_* environment variables by deployment mode. Requires DEPLOY_MODE, TS_IP.
coolify_reconcile_pusher_env_script() {
  cat <<'EOF'
set -Eeuo pipefail
: "${DEPLOY_MODE:?DEPLOY_MODE is required}"
: "${TS_IP:?TS_IP is required}"
coolify_env="/data/coolify/source/.env"
mode="${DEPLOY_MODE}"
tmp="$(mktemp)"
sed '/^PUSHER_HOST=/d; /^PUSHER_PORT=/d; /^PUSHER_SCHEME=/d' "${coolify_env}" > "${tmp}"

if [[ "${mode}" == "tunnel" ]]; then
  cat >> "${tmp}" <<INNER
PUSHER_HOST=${TS_IP}
PUSHER_PORT=6001
PUSHER_SCHEME=http
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
               up -d --force-recreate coolify soketi 2>&1 | tail -5
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
print_deployment_summary() {
  printf '\n'
  printf '┌─────────────────────────────────────────────────────────────┐\n'
  printf '│                    DEPLOYMENT COMPLETE                      │\n'
  printf '├─────────────────────────────────────────────────────────────┤\n'
  printf '│  Server Public IP : %-40s│\n' "${SERVER_IP}"
  printf '│  Tailscale IP     : %-40s│\n' "${TS_IP}"
  printf '│  Admin User       : %-40s│\n' "${ADMIN_USER}"
  printf '│  Deploy Mode      : %-40s│\n' "${DEPLOY_MODE}"
  printf '│  Domain           : %-40s│\n' "${DOMAIN}"
  printf '│  Server Timezone  : %-40s│\n' "${SERVER_TIMEZONE}"
  printf '│  Dashboard URL    : %-40s│\n' "http://${TS_IP}:8000"
  printf '│  SSH Access       : ssh %-36s│\n' "${ADMIN_USER}@${TS_IP}"
  printf '├─────────────────────────────────────────────────────────────┤\n'
  if [[ "${DEPLOY_MODE}" == "standard" ]]; then
    printf '│  DNS              : A %-38s│\n' "${DOMAIN} → ${SERVER_IP}"
    printf '│  Wildcard DNS     : A *.%-36s│\n' "${APP_DOMAIN}"
    [[ "${APP_DOMAIN}" != "${CF_ZONE_NAME}" ]] \
      && printf '│                   + A *.%-36s│\n' "${CF_ZONE_NAME}"
  else
    printf '│  DNS              : private-only host records removed %-13s│\n' "${DOMAIN}"
    printf '│  Wildcard DNS     : CNAME *.%-32s│\n' "${APP_DOMAIN}"
    [[ "${APP_DOMAIN}" != "${CF_ZONE_NAME}" ]] \
      && printf '│                   + CNAME *.%-32s│\n' "${CF_ZONE_NAME}"
    printf '│  Tunnel ID        : %-40s│\n' "${TUNNEL_ID}"
    printf '│  Public Dashboard : %-40s│\n' "blocked (Tailscale-only)"
    printf '│  Public WebSocket : %-40s│\n' "blocked (Tailscale-only)"
  fi
  printf '└─────────────────────────────────────────────────────────────┘\n'
  printf '\n'
  log "Next steps:"
  log "  1. Open http://${TS_IP}:8000 and create your Coolify admin account."
  log ""
  log "  2. Cloudflare SSL mode (one-time):"
  log "       Cloudflare dashboard > your zone > SSL/TLS > Overview > set to 'Full'"
  log "       (not Full Strict — Coolify uses self-signed certs internally)"
  log ""
  log "  3. Start the proxy: Coolify UI > Servers > localhost > Proxy > Start Proxy"
  log "       (required for app subdomains to route through Traefik)"
  log ""
  log "  4. Wildcard Domain is already set to http://${APP_DOMAIN} (done automatically)."
  log "       New apps will get  http://appname.${APP_DOMAIN}"
  log "       If an app already has a sslip.io URL: App > Settings > Domains > update it."
  log ""
  log "  5. For each app deployment in Coolify:"
  log "       Use http:// domain (not https://) — Cloudflare proxy adds TLS."
  log "       Example:  http://myapp.${APP_DOMAIN}"
  log ""
  log "  6. Deploy your first app — it gets a subdomain + Cloudflare SSL automatically."
}

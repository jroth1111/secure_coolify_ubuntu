#!/usr/bin/env bash
# overlays/coolify/modules/phase5-verify.sh — Phase 5 probe helpers and verify orchestration.
# Sourced by coolify-common.sh; do not execute directly.

[[ "${BASH_SOURCE[0]}" != "${0}" ]] \
  || { printf 'Source this file, do not execute it.\n' >&2; exit 1; }

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
  log "Running final base/validate.sh..."
  local final_validate_json
  final_validate_json="$("${fetch_validate_json_fn}" 2>/dev/null)" || true
  report_validation_result "Final validation" "${final_validate_json}" \
    "Final validation failed. Resolve validation failures before considering deployment complete."

  # Print summary
  print_deployment_summary
}

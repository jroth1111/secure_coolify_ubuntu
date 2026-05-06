cloudflared_check() {
  # Not installed at all — that is fine before Coolify deploy
  if ! systemctl list-unit-files --no-legend cloudflared.service 2>/dev/null | grep -q cloudflared \
      && ! command -v cloudflared >/dev/null 2>&1; then
    record "INFO" "cloudflared: not installed"
    return
  fi

  # Installed — now it must be active
  if systemctl is-active --quiet cloudflared 2>/dev/null; then
    record "PASS" "cloudflared: service active"
  else
    local svc_state
    svc_state="$(systemctl is-active cloudflared 2>/dev/null || echo "unknown")"
    record "FAIL" "cloudflared: service active" "state is ${svc_state}"
    return
  fi

  # cloudflared warns at startup when ping_group_range excludes gid 0.
  # Keep a sane range that includes root to avoid noisy ICMP proxy warnings.
  if command -v sysctl >/dev/null 2>&1; then
    local ping_group_range pg_lo pg_hi
    ping_group_range="$(sysctl -n net.ipv4.ping_group_range 2>/dev/null || true)"
    if [[ "${ping_group_range}" =~ ^[[:space:]]*([0-9]+)[[:space:]]+([0-9]+)[[:space:]]*$ ]]; then
      pg_lo="${BASH_REMATCH[1]}"
      pg_hi="${BASH_REMATCH[2]}"
      if (( pg_hi < pg_lo )); then
        record "FAIL" "cloudflared: ping_group_range" \
          "invalid range (${pg_lo} ${pg_hi}); expected ascending values including gid 0"
      elif (( pg_lo > 0 || pg_hi < 0 )); then
        record "FAIL" "cloudflared: ping_group_range" \
          "gid 0 excluded (${pg_lo} ${pg_hi}); cloudflared logs ICMP proxy warnings"
      else
        record "PASS" "cloudflared: ping_group_range includes gid 0 (${pg_lo} ${pg_hi})"
      fi
    else
      record "INFO" "cloudflared: ping_group_range" \
        "unable to parse net.ipv4.ping_group_range (${ping_group_range:-unknown})"
    fi
  else
    record "INFO" "cloudflared: ping_group_range" "sysctl not found; skipped"
  fi

  # Config file checks
  local config_file="${CLOUDFLARED_CONFIG_FILE:-/etc/cloudflared/config.yml}"
  if [[ ! -f "${config_file}" ]]; then
    record "FAIL" "cloudflared: config file" "${config_file} not found"
    return
  fi

  local tunnel_id
  tunnel_id="$(grep -m1 '^tunnel:' "${config_file}" | awk '{print $2}' || true)"
  if [[ -n "${tunnel_id}" ]]; then
    record "PASS" "cloudflared: tunnel ID configured"
  else
    record "FAIL" "cloudflared: tunnel ID" "not found in ${config_file}"
  fi

  # Wildcard app domains must route to Traefik (coolify-proxy) on port 80.
  if grep -qE 'localhost:80$|localhost:80[^0-9]|127\.0\.0\.1:80$|127\.0\.0\.1:80[^0-9]' "${config_file}"; then
    record "PASS" "cloudflared: ingress routes apps via Traefik (port 80)"
  else
    record "FAIL" "cloudflared: ingress app routing" \
      "no localhost:80 route — app domains will show dashboard instead of apps"
  fi

  # Private-only profile: dashboard/realtime/terminal must not be tunneled publicly.
  if grep -qE 'localhost:8000|127\.0\.0\.1:8000' "${config_file}"; then
    record "FAIL" "cloudflared: dashboard ingress disabled" \
      "found route to localhost:8000 — dashboard must stay Tailscale-only"
  else
    record "PASS" "cloudflared: dashboard ingress disabled"
  fi

  if grep -qE 'localhost:6001|127\.0\.0\.1:6001' "${config_file}"; then
    record "FAIL" "cloudflared: realtime ingress disabled" \
      "found route to localhost:6001 — realtime must stay on Tailscale"
  else
    record "PASS" "cloudflared: realtime ingress disabled"
  fi

  if grep -qE 'localhost:6002|127\.0\.0\.1:6002' "${config_file}"; then
    record "FAIL" "cloudflared: terminal ingress disabled" \
      "found route to localhost:6002 — terminal must stay on Tailscale"
  else
    record "PASS" "cloudflared: terminal ingress disabled"
  fi

  if grep -q '/terminal/ws' "${config_file}"; then
    record "FAIL" "cloudflared: terminal path disabled" \
      "found '/terminal/ws' ingress rule — terminal must not be publicly tunneled"
  else
    record "PASS" "cloudflared: terminal path disabled"
  fi

  local deny_count
  deny_count="$(grep -Ec 'service:\s*http_status:404' "${config_file}" || true)"
  if [[ "${deny_count}" =~ ^[0-9]+$ ]] && (( deny_count >= 2 )); then
    record "PASS" "cloudflared: deny rules present"
  else
    record "FAIL" "cloudflared: deny rules" \
      "expected at least two http_status:404 ingress rules (explicit host blocks + fallback)"
  fi

  if is_true "${TUNNEL_MODE}"; then
    local dashboard_host ws_host
    dashboard_host="$(awk '
      /^[[:space:]]*-[[:space:]]*hostname:[[:space:]]*/ {
        host=$3
        gsub(/"/, "", host)
        if (host !~ /^\*\./ && host !~ /^ws\./) {
          print host
          exit
        }
      }
    ' "${config_file}" 2>/dev/null || true)"
    ws_host="$(awk '
      /^[[:space:]]*-[[:space:]]*hostname:[[:space:]]*ws\./ {
        host=$3
        gsub(/"/, "", host)
        print host
        exit
      }
    ' "${config_file}" 2>/dev/null || true)"

    if [[ -n "${dashboard_host}" && -z "${ws_host}" ]]; then
      ws_host="ws.${dashboard_host}"
    fi

    local private_route_file
    local proxy_compose_file
    local default_redirect_file
    local coolify_dynamic_file
    local coolify_env_file
    private_route_file="${COOLIFY_PRIVATE_ROUTE_FILE:-/data/coolify/proxy/dynamic/coolify-private-dashboard.yaml}"
    proxy_compose_file="${COOLIFY_PROXY_COMPOSE_FILE:-/data/coolify/proxy/docker-compose.yml}"
    default_redirect_file="${COOLIFY_PROXY_DEFAULT_REDIRECT_FILE:-/data/coolify/proxy/dynamic/default_redirect_503.yaml}"
    coolify_dynamic_file="${COOLIFY_PROXY_DYNAMIC_FILE:-/data/coolify/proxy/dynamic/coolify.yaml}"
    coolify_env_file="${COOLIFY_ENV_FILE:-/data/coolify/source/.env}"
    if [[ -f "${private_route_file}" ]]; then
      record "PASS" "cloudflared: private dashboard route file present"
    else
      record "FAIL" "cloudflared: private dashboard route file" \
        "missing ${private_route_file}; private DOMAIN/ws routing may be broken"
    fi

    if [[ -f "${private_route_file}" && -n "${dashboard_host}" ]]; then
      if grep -Fq "Host(\`${dashboard_host}\`)" "${private_route_file}"; then
        record "PASS" "cloudflared: private dashboard host route (${dashboard_host})"
      else
        record "FAIL" "cloudflared: private dashboard host route" \
          "missing Host(\`${dashboard_host}\`) in ${private_route_file}"
      fi
    fi

    if [[ -f "${private_route_file}" && -n "${ws_host}" ]]; then
      if grep -Fq "Host(\`${ws_host}\`)" "${private_route_file}"; then
        record "PASS" "cloudflared: private websocket host route (${ws_host})"
      else
        record "FAIL" "cloudflared: private websocket host route" \
          "missing Host(\`${ws_host}\`) in ${private_route_file}"
      fi
    fi

    if [[ -f "${private_route_file}" ]]; then
      local private_router_name
      local private_router_fail=0
      for private_router_name in \
        coolify-private-dashboard-http \
        coolify-private-dashboard-https \
        coolify-private-realtime-http \
        coolify-private-realtime-https \
        coolify-private-terminal-http \
        coolify-private-terminal-https; do
        if grep -Fq "${private_router_name}:" "${private_route_file}"; then
          record "PASS" "cloudflared: private router present (${private_router_name})"
        else
          record "FAIL" "cloudflared: private router present (${private_router_name})" \
            "missing router ${private_router_name} in ${private_route_file}"
          private_router_fail=1
        fi
      done
      if [[ "${private_router_fail}" -eq 0 ]]; then
        record "PASS" "cloudflared: private http/https router set complete"
      fi

      if grep -Fq "coolify-private-force-https:" "${private_route_file}" \
        && grep -Fq "redirectScheme:" "${private_route_file}" \
        && grep -Eq '^[[:space:]]*scheme:[[:space:]]*https[[:space:]]*$' "${private_route_file}"; then
        record "PASS" "cloudflared: private HTTP→HTTPS redirect middleware"
      else
        record "FAIL" "cloudflared: private HTTP→HTTPS redirect middleware" \
          "missing coolify-private-force-https redirectScheme in ${private_route_file}"
      fi

      local http_router_name http_router_block
      for http_router_name in \
        coolify-private-dashboard-http \
        coolify-private-realtime-http \
        coolify-private-terminal-http; do
        http_router_block="$(awk -v router="${http_router_name}:" '
          $0 ~ "^    " router "[[:space:]]*$" {in_router=1; next}
          in_router && $0 ~ "^    [a-zA-Z0-9_-]+:[[:space:]]*$" {exit}
          in_router {print}
        ' "${private_route_file}")"
        if grep -Fq "service: noop@internal" <<< "${http_router_block}" \
          && grep -Fq "coolify-private-force-https" <<< "${http_router_block}"; then
          record "PASS" "cloudflared: ${http_router_name} enforces HTTPS redirect"
        else
          record "FAIL" "cloudflared: ${http_router_name} enforces HTTPS redirect" \
            "expected service noop@internal + coolify-private-force-https middleware"
        fi
      done

      local https_router_name https_router_block private_https_router_fail=0
      for https_router_name in \
        coolify-private-dashboard-https \
        coolify-private-realtime-https \
        coolify-private-terminal-https; do
        https_router_block="$(awk -v router="${https_router_name}:" '
          $0 ~ "^    " router "[[:space:]]*$" {in_router=1; next}
          in_router && $0 ~ "^    [a-zA-Z0-9_-]+:[[:space:]]*$" {exit}
          in_router {print}
        ' "${private_route_file}")"
        if grep -Eq '^[[:space:]]*certResolver:[[:space:]]*[^[:space:]]+' <<< "${https_router_block}"; then
          record "PASS" "cloudflared: ${https_router_name} uses certResolver"
        else
          record "FAIL" "cloudflared: ${https_router_name} uses certResolver" \
            "missing certResolver in ${https_router_name} router block"
          private_https_router_fail=1
        fi
      done
      if [[ "${private_https_router_fail}" -eq 0 ]]; then
        record "PASS" "cloudflared: private HTTPS routers use certResolver"
      else
        record "FAIL" "cloudflared: private HTTPS routers use certResolver" \
          "one or more private HTTPS routers in ${private_route_file} are missing certResolver"
      fi
    fi

    if [[ -f "${proxy_compose_file}" ]]; then
      if grep -Eq 'certificatesresolvers\.letsencrypt\.' "${proxy_compose_file}"; then
        record "FAIL" "cloudflared: public letsencrypt resolver removed" \
          "found public letsencrypt resolver flags in ${proxy_compose_file}"
      else
        record "PASS" "cloudflared: public letsencrypt resolver removed"
      fi

      local private_tls_resolver private_tls_ca traefik_command_block private_resolver_flag_fail
      private_tls_resolver="$(awk '
        $0 ~ /^    coolify-private-(dashboard|realtime|terminal)-https:[[:space:]]*$/ { in_router=1; next }
        in_router && /^[[:space:]]*certResolver:[[:space:]]*/ {
          gsub(/^[[:space:]]*certResolver:[[:space:]]*/, "", $0)
          print
          exit
        }
        in_router && /^    [a-zA-Z0-9_-]+:[[:space:]]*$/ { in_router=0 }
      ' "${private_route_file}" 2>/dev/null || true)"
      [[ -n "${private_tls_resolver}" ]] || private_tls_resolver="privatedns"
      private_tls_ca="letsencrypt"

      traefik_command_block="$(awk '
        /^  traefik:[[:space:]]*$/ { in_service=1; next }
        in_service && /^  [a-zA-Z0-9_-]+:[[:space:]]*$/ { exit }
        in_service && /^    command:[[:space:]]*$/ { in_command=1; next }
        in_command && /^    [a-zA-Z0-9_-]+:[[:space:]]*$/ { exit }
        in_command { print }
      ' "${proxy_compose_file}" 2>/dev/null || true)"

      private_resolver_flag_fail=0
      local required_private_resolver_flag
      for required_private_resolver_flag in \
        "--certificatesresolvers.${private_tls_resolver}.acme.dnschallenge=true" \
        "--certificatesresolvers.${private_tls_resolver}.acme.dnschallenge.provider=cloudflare" \
        "--certificatesresolvers.${private_tls_resolver}.acme.dnschallenge.resolvers=1.1.1.1:53,8.8.8.8:53" \
        "--certificatesresolvers.${private_tls_resolver}.acme.email=" \
        "--certificatesresolvers.${private_tls_resolver}.acme.storage=/traefik/acme.json"; do
        if ! grep -Fq -- "${required_private_resolver_flag}" <<< "${traefik_command_block}"; then
          private_resolver_flag_fail=1
          break
        fi
      done

      if [[ "${private_resolver_flag_fail}" -eq 0 ]]; then
        record "PASS" "cloudflared: private TLS resolver present in Traefik command"
      else
        record "FAIL" "cloudflared: private TLS resolver present in Traefik command" \
          "missing ${private_tls_resolver} ACME flags in traefik command block of ${proxy_compose_file}"
      fi

      if grep -Fq -- "--certificatesresolvers.${private_tls_resolver}.acme.caserver=https://acme.zerossl.com/v2/DV90" <<< "${traefik_command_block}"; then
        private_tls_ca="zerossl"
      fi
      if [[ "${private_tls_ca}" == "zerossl" ]]; then
        if grep -Fq -- "--certificatesresolvers.${private_tls_resolver}.acme.eab.kid=" <<< "${traefik_command_block}" \
          && grep -Fq -- "--certificatesresolvers.${private_tls_resolver}.acme.eab.hmacencoded=" <<< "${traefik_command_block}"; then
          record "PASS" "cloudflared: private TLS CA (${private_tls_ca}) flags present"
        else
          record "FAIL" "cloudflared: private TLS CA (${private_tls_ca}) flags present" \
            "missing ZeroSSL caServer/EAB flags in traefik command block of ${proxy_compose_file}"
        fi
      else
        record "PASS" "cloudflared: private TLS CA (${private_tls_ca}) flags present"
      fi
    else
      record "FAIL" "cloudflared: proxy compose file" "missing ${proxy_compose_file}"
    fi

    if [[ -f "${default_redirect_file}" ]]; then
      if grep -Eq '^[[:space:]]*certResolver:[[:space:]]*letsencrypt[[:space:]]*$' "${default_redirect_file}"; then
        record "FAIL" "cloudflared: catchall route avoids public letsencrypt" \
          "found public letsencrypt resolver in ${default_redirect_file}"
      else
        record "PASS" "cloudflared: catchall route avoids public letsencrypt"
      fi
    else
      record "PASS" "cloudflared: catchall route avoids public letsencrypt"
    fi

    if [[ -f "${coolify_dynamic_file}" ]]; then
      if grep -Eq '^[[:space:]]*coolify-(https|realtime-wss|terminal-wss):[[:space:]]*$|^[[:space:]]*certresolver:[[:space:]]*letsencrypt[[:space:]]*$' "${coolify_dynamic_file}"; then
        record "FAIL" "cloudflared: generated Coolify HTTPS routers disabled" \
          "found public dashboard HTTPS routers in ${coolify_dynamic_file}"
      else
        record "PASS" "cloudflared: generated Coolify HTTPS routers disabled"
      fi
    else
      # In tunnel mode with empty FQDN, Coolify intentionally doesn't generate this file.
      # No file = no public HTTPS routers, which is the desired state.
      record "PASS" "cloudflared: generated Coolify HTTPS routers disabled" \
        "(no ${coolify_dynamic_file} — expected when no public FQDN)"
    fi

    if [[ -n "${dashboard_host}" ]]; then
      local expected_pusher_host actual_pusher_host actual_pusher_port actual_pusher_scheme
      expected_pusher_host="ws.${dashboard_host}"
      if [[ -f "${coolify_env_file}" ]]; then
        actual_pusher_host="$(awk -F= '/^PUSHER_HOST=/{print $2; exit}' "${coolify_env_file}" | tr -d '"' || true)"
        actual_pusher_port="$(awk -F= '/^PUSHER_PORT=/{print $2; exit}' "${coolify_env_file}" | tr -d '"' || true)"
        actual_pusher_scheme="$(awk -F= '/^PUSHER_SCHEME=/{print $2; exit}' "${coolify_env_file}" | tr -d '"' || true)"

        if [[ "${actual_pusher_host}" == "${expected_pusher_host}" ]]; then
          record "PASS" "coolify: PUSHER_HOST private ws domain"
        else
          record "FAIL" "coolify: PUSHER_HOST private ws domain" \
            "expected ${expected_pusher_host}, found ${actual_pusher_host:-<unset>}"
        fi

        if [[ "${actual_pusher_port}" == "443" ]]; then
          record "PASS" "coolify: PUSHER_PORT private ws TLS"
        else
          record "FAIL" "coolify: PUSHER_PORT private ws TLS" \
            "expected 443, found ${actual_pusher_port:-<unset>}"
        fi

        if [[ "${actual_pusher_scheme}" == "https" ]]; then
          record "PASS" "coolify: PUSHER_SCHEME private ws TLS"
        else
          record "FAIL" "coolify: PUSHER_SCHEME private ws TLS" \
            "expected https, found ${actual_pusher_scheme:-<unset>}"
        fi
      else
        record "FAIL" "coolify: PUSHER env file present" \
          "missing ${coolify_env_file}"
      fi
    fi

    if command -v getent >/dev/null 2>&1; then
      check_private_dns_host() {
        local host="$1"
        local label="$2"
        local resolved_list ip
        local all_tailscale="true"
        local matched_expected="false"

        if command -v dig >/dev/null 2>&1; then
          # Query authoritative DNS directly to avoid local /etc/hosts or resolver overrides.
          resolved_list="$(dig +short @1.1.1.1 "${host}" A 2>/dev/null \
            | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/' \
            | sort -u | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
        else
          resolved_list="$(getent ahostsv4 "${host}" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
        fi
        if [[ -z "${resolved_list}" ]]; then
          record "FAIL" "cloudflared: ${label} DNS resolution" "no IPv4 answer for ${host}"
          return 0
        fi

        for ip in ${resolved_list}; do
          if ! is_tailscale_ipv4 "${ip}"; then
            all_tailscale="false"
          fi
          if [[ -n "${TAILSCALE_IP}" && "${ip}" == "${TAILSCALE_IP}" ]]; then
            matched_expected="true"
          fi
        done

        if [[ "${all_tailscale}" != "true" ]]; then
          record "FAIL" "cloudflared: ${label} DNS resolution" \
            "${host} resolved to non-Tailscale IPv4(s): ${resolved_list}"
          return 0
        fi

        if [[ -n "${TAILSCALE_IP}" && "${matched_expected}" != "true" ]]; then
          record "FAIL" "cloudflared: ${label} DNS resolution" \
            "${host} resolved to ${resolved_list}; expected to include ${TAILSCALE_IP}"
          return 0
        fi

        record "PASS" "cloudflared: ${label} DNS resolves to Tailscale (${resolved_list})"
      }

      if [[ -n "${dashboard_host}" ]]; then
        check_private_dns_host "${dashboard_host}" "dashboard host"
      else
        record "FAIL" "cloudflared: dashboard host in config" \
          "unable to parse dashboard hostname from ${config_file}"
      fi

      if [[ -n "${ws_host}" ]]; then
        check_private_dns_host "${ws_host}" "websocket host"
      else
        record "FAIL" "cloudflared: websocket host in config" \
          "unable to parse websocket hostname from ${config_file}"
      fi
    else
      record "INFO" "cloudflared: DNS resolution checks" "getent not found; skipped private DNS checks"
    fi

    check_private_tls_cert_served() {
      local host="$1"
      local label="$2"
      local cert_meta
      cert_meta="$(printf '' | openssl s_client -connect 127.0.0.1:443 -servername "${host}" -showcerts 2>/dev/null \
        | openssl x509 -noout -subject -issuer -ext subjectAltName 2>/dev/null || true)"

      if [[ -z "${cert_meta}" ]]; then
        record "FAIL" "cloudflared: ${label} served TLS cert" \
          "could not inspect served certificate for ${host} on 127.0.0.1:443"
        return 0
      fi

      if grep -Fq "TRAEFIK DEFAULT CERT" <<< "${cert_meta}"; then
        record "FAIL" "cloudflared: ${label} served TLS cert" \
          "Traefik default certificate still served for ${host}"
      else
        record "PASS" "cloudflared: ${label} served TLS cert"
      fi

      if grep -Fq "DNS:${host}" <<< "${cert_meta}"; then
        record "PASS" "cloudflared: ${label} certificate SAN (${host})"
      else
        record "FAIL" "cloudflared: ${label} certificate SAN (${host})" \
          "missing DNS:${host} in served certificate"
      fi
    }

    if command -v openssl >/dev/null 2>&1; then
      if [[ -n "${dashboard_host}" ]]; then
        check_private_tls_cert_served "${dashboard_host}" "dashboard host"
      fi
      if [[ -n "${ws_host}" ]]; then
        check_private_tls_cert_served "${ws_host}" "websocket host"
      fi
    else
      record "INFO" "cloudflared: private TLS certificate checks" "openssl not found; skipped served certificate checks"
    fi

    if command -v curl >/dev/null 2>&1; then
      if [[ -n "${dashboard_host}" ]]; then
        local private_dashboard_http_code
        private_dashboard_http_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
          --resolve "${dashboard_host}:80:127.0.0.1" "http://${dashboard_host}" 2>/dev/null || true)"
        private_dashboard_http_code="${private_dashboard_http_code:-000}"
        private_dashboard_http_code="${private_dashboard_http_code:0:3}"

        if [[ "${private_dashboard_http_code}" =~ ^30[12378]$ ]]; then
          record "PASS" "cloudflared: private dashboard HTTP redirect verified"
        else
          record "FAIL" "cloudflared: private dashboard HTTP redirect verified" \
            "expected 30x from http://${dashboard_host} via local Traefik, got ${private_dashboard_http_code}"
        fi

        local private_dashboard_https_code
        private_dashboard_https_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
          --resolve "${dashboard_host}:443:127.0.0.1" "https://${dashboard_host}/api/v1/health" 2>/dev/null || true)"
        private_dashboard_https_code="${private_dashboard_https_code:-000}"
        private_dashboard_https_code="${private_dashboard_https_code:0:3}"

        if [[ "${private_dashboard_https_code}" =~ ^2[0-9][0-9]$ ]]; then
          record "PASS" "cloudflared: private dashboard HTTPS health verified"
        else
          record "FAIL" "cloudflared: private dashboard HTTPS health verified" \
            "expected 2xx from https://${dashboard_host}/api/v1/health via local Traefik, got ${private_dashboard_https_code}"
        fi
      fi

      if [[ -n "${ws_host}" ]]; then
        local private_ws_http_code private_ws_https_code
        private_ws_http_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
          --resolve "${ws_host}:80:127.0.0.1" "http://${ws_host}" 2>/dev/null || true)"
        private_ws_https_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
          --resolve "${ws_host}:443:127.0.0.1" "https://${ws_host}/" 2>/dev/null || true)"
        private_ws_http_code="${private_ws_http_code:-000}"
        private_ws_https_code="${private_ws_https_code:-000}"
        private_ws_http_code="${private_ws_http_code:0:3}"
        private_ws_https_code="${private_ws_https_code:0:3}"

        if [[ "${private_ws_http_code}" =~ ^30[12378]$ ]]; then
          record "PASS" "cloudflared: private websocket HTTP redirect verified"
        else
          record "FAIL" "cloudflared: private websocket HTTP redirect verified" \
            "expected 30x from http://${ws_host} via local Traefik, got ${private_ws_http_code}"
        fi

        if [[ "${private_ws_https_code}" =~ ^[234][0-9][0-9]$ ]]; then
          record "PASS" "cloudflared: private websocket HTTPS route verified"
        else
          record "FAIL" "cloudflared: private websocket HTTPS route verified" \
            "expected 2xx/3xx/4xx from https://${ws_host}/ via local Traefik, got ${private_ws_https_code}"
        fi
      fi
    else
      record "INFO" "cloudflared: private dashboard HTTP redirect verified" "curl not found; skipped redirect check"
      record "INFO" "cloudflared: private dashboard HTTPS health verified" "curl not found; skipped verified HTTPS health check"
      record "INFO" "cloudflared: private websocket HTTP redirect verified" "curl not found; skipped redirect check"
      record "INFO" "cloudflared: private websocket HTTPS route verified" "curl not found; skipped verified HTTPS route check"
    fi
  fi

  # Functional connectivity: probe cloudflared's /ready endpoint.
  # The metrics port is not always 2000; newer cloudflared picks an ephemeral port or
  # uses a management socket. Discover the port dynamically from ss/procfs, then probe it.
  local cf_pid cf_port
  cf_pid="$(pgrep -x cloudflared | head -1 || true)"
  if [[ -n "${cf_pid}" ]]; then
    cf_port="$(ss -tlnp 2>/dev/null \
      | awk -v pid="${cf_pid}" 'index($0,"pid="pid",") && /127\.0\.0\.1:/{print $4}' \
      | awk -F: '{print $NF}' | head -1 || true)"
  fi

  if [[ -n "${cf_port:-}" ]] && curl -sf --max-time 3 "http://127.0.0.1:${cf_port}/ready" >/dev/null 2>&1; then
    local ready_json conn_count
    ready_json="$(curl -sf --max-time 3 "http://127.0.0.1:${cf_port}/ready" 2>/dev/null || true)"
    conn_count="$(printf '%s' "${ready_json}" | python3 -c \
      "import sys,json; print(json.load(sys.stdin).get('readyConnections',0))" 2>/dev/null || echo "?")"
    record "PASS" "cloudflared: tunnel /ready OK (${conn_count} connections)"
  elif [[ -n "${cf_port:-}" ]]; then
    record "FAIL" "cloudflared: tunnel /ready" \
      "port ${cf_port} not responding — tunnel may be disconnected"
  else
    record "INFO" "cloudflared: tunnel /ready" \
      "could not determine cloudflared metrics port — manual check needed"
  fi
}


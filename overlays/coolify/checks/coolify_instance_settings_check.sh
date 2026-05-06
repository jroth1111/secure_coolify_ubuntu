coolify_instance_settings_check() {
  if ! command -v docker >/dev/null 2>&1; then
    record "INFO" "coolify: instance settings" "Docker not installed; skipped"
    return
  fi

  if [[ ! -f "${COOLIFY_ENV_FILE}" ]]; then
    return 0
  fi

  if [[ -z "${DOMAIN}" ]]; then
    record "FAIL" "coolify: instance fqdn" "domain missing from ${STATE_FILE}"
    record "FAIL" "coolify: registration disabled" "domain missing from ${STATE_FILE}"
    return
  fi

  local db_user db_name db_pass settings_row registration_enabled fqdn expected_fqdn
  db_user="$(grep -m1 '^DB_USERNAME=' "${COOLIFY_ENV_FILE}" | cut -d= -f2- || true)"
  db_name="$(grep -m1 '^DB_DATABASE=' "${COOLIFY_ENV_FILE}" | cut -d= -f2- || true)"
  db_pass="$(grep -m1 '^DB_PASSWORD=' "${COOLIFY_ENV_FILE}" | cut -d= -f2- || true)"
  db_user="${db_user:-coolify}"
  db_name="${db_name:-coolify}"
  if is_true "${TUNNEL_MODE}"; then
    expected_fqdn=""
  else
    expected_fqdn="https://${DOMAIN}"
  fi

  if [[ -z "${db_pass}" ]]; then
    record "FAIL" "coolify: instance settings query" "DB_PASSWORD missing in ${COOLIFY_ENV_FILE}"
    return
  fi

  if ! docker ps --filter "name=coolify-db" --filter "status=running" --format "{{.Names}}" 2>/dev/null | grep -qx "coolify-db"; then
    record "FAIL" "coolify: instance settings query" "coolify-db container is not running"
    return
  fi

  local pg_ready="false" attempt
  for (( attempt=1; attempt<=15; attempt++ )); do
    if docker exec -i coolify-db sh -ceu '
      IFS= read -r PGPASSWORD
      export PGPASSWORD
      pg_isready -U "$1" -d "$2" >/dev/null 2>&1
    ' _ "${db_user}" "${db_name}" <<< "${db_pass}" >/dev/null 2>&1; then
      pg_ready="true"
      break
    fi
    (( attempt < 15 )) || break
    sleep 2
  done

  if [[ "${pg_ready}" != "true" ]]; then
    record "FAIL" "coolify: instance settings query" "coolify-db is running but PostgreSQL is not ready"
    return
  fi

  settings_row="$(
    docker exec -i coolify-db env PGPASSWORD="${db_pass}" \
      psql -v ON_ERROR_STOP=1 -U "${db_user}" -d "${db_name}" -At -F '|' \
      -c "SELECT is_registration_enabled, COALESCE(fqdn,'') FROM instance_settings LIMIT 1;" \
      2>/dev/null || true
  )"

  if [[ -z "${settings_row}" ]]; then
    record "FAIL" "coolify: instance settings query" "instance_settings query returned no data"
    return
  fi

  registration_enabled="${settings_row%%|*}"
  fqdn="${settings_row#*|}"

  if [[ "${registration_enabled}" == "f" || "${registration_enabled}" == "false" ]]; then
    record "PASS" "coolify: registration disabled"
  else
    record "FAIL" "coolify: registration disabled" \
      "expected false, found ${registration_enabled:-<empty>}"
  fi

  if [[ "${fqdn}" == "${expected_fqdn}" ]]; then
    record "PASS" "coolify: instance fqdn"
  else
    record "FAIL" "coolify: instance fqdn" \
      "expected ${expected_fqdn:-<empty>}, found ${fqdn:-<empty>}"
  fi
}


coolify_container_check() {
  if ! command -v docker >/dev/null 2>&1; then
    record "INFO" "coolify-containers: docker" "Docker not installed; skipped"
    return
  fi

  # Gate-C safe: only enforce Coolify container health after Coolify environment
  # has been created. Partial directories from interrupted installs should not
  # fail pre-phase3 validation.
  if [[ ! -f "${COOLIFY_ENV_FILE}" ]]; then
    return 0
  fi

  local containers=("coolify" "coolify-db" "coolify-redis" "coolify-proxy")
  for ctr in "${containers[@]}"; do
    local state health
    state="$(docker inspect --format '{{.State.Status}}' "${ctr}" 2>/dev/null || echo "not-found")"
    state="$(printf '%s' "${state}" | tr -d '[:space:]')"
    if [[ "${state}" == "not-found" ]]; then
      # proxy may genuinely be absent if no apps deployed yet — info not fail
      if [[ "${ctr}" == "coolify-proxy" ]]; then
        record "INFO" "coolify-containers: ${ctr}" "not found (normal before first app deploy)"
      else
        record "FAIL" "coolify-containers: ${ctr}" "container not found"
      fi
      continue
    fi

    if [[ "${state}" != "running" ]]; then
      record "FAIL" "coolify-containers: ${ctr} running" "state is ${state}"
      continue
    fi

    # Check healthcheck status if configured (some containers have none)
    health="$(docker inspect \
      --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' \
      "${ctr}" 2>/dev/null || echo "unknown")"
    health="$(printf '%s' "${health}" | tr -d '[:space:]')"

    case "${health}" in
      healthy|no-healthcheck)
        record "PASS" "coolify-containers: ${ctr} running (${health})" ;;
      starting)
        record "INFO" "coolify-containers: ${ctr}" "healthcheck still starting — re-run in a minute" ;;
      *)
        record "FAIL" "coolify-containers: ${ctr} health" "${health}" ;;
    esac
  done
}


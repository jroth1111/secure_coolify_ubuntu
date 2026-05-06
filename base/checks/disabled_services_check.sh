disabled_services_check() {
  local svc
  for svc in rpcbind avahi-daemon cups ModemManager udisks2 fwupd upower; do
    local state="not-found"
    state="$(systemctl is-enabled "${svc}.service" 2>/dev/null || true)"
    state="${state%%$'\n'*}"
    [[ -n "${state}" ]] || state="not-found"

    if [[ "${state}" == masked* || "${state}" == "not-found" ]]; then
      record "PASS" "disabled: ${svc} (${state})"
    else
      record "FAIL" "disabled: ${svc}" "state is ${state}, expected masked"
    fi
  done
}

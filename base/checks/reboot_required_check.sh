reboot_required_check() {
  if [[ -f /run/reboot-required ]]; then
    local pkgs
    pkgs="$(tr '\n' ',' < /run/reboot-required.pkgs 2>/dev/null | sed 's/,$//' || true)"
    if [[ -n "${pkgs}" ]]; then
      record "FAIL" "reboot: pending" "reboot required by updated packages (${pkgs})"
    else
      record "FAIL" "reboot: pending" "reboot required"
    fi
  else
    record "PASS" "reboot: not required"
  fi
}

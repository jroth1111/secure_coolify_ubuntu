configure_password_policy() {
  local pwquality="/etc/security/pwquality.conf"

  if ! is_true "${DRY_RUN}"; then
    cat > "${pwquality}" <<'PWEOF'
# Managed by base/bootstrap.sh
minlen = 12
minclass = 3
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
maxsequence = 4
dictcheck = 1
usercheck = 1
enforcing = 1
retry = 3
PWEOF
    chmod 0644 "${pwquality}"
    log "Applied password quality policy."

    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
    log "Set PASS_MAX_DAYS=90, PASS_MIN_DAYS=1 in login.defs."
  else
    log "DRY-RUN: would apply password quality policy and login.defs."
  fi
}

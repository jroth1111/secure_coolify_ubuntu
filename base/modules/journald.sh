configure_journald() {
  write_file "${JOURNALD_DROPIN_FILE}" "0644" "root" "root" <<EOF
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=${JOURNAL_MAX_USE}
SystemKeepFree=500M
MaxRetentionSec=${JOURNAL_RETENTION}
EOF
  run journalctl --flush
  run systemctl restart systemd-journald

  # Verify persistent storage is active (journald should create /var/log/journal)
  if ! is_true "${DRY_RUN}"; then
    local flush_check=0
    local max_wait=10
    while (( flush_check < max_wait )); do
      if [[ -d /var/log/journal ]]; then
        log "Journald persistent storage verified (/var/log/journal exists)."
        break
      fi
      sleep 1
      ((++flush_check))
    done
    if (( flush_check >= max_wait )) && [[ ! -d /var/log/journal ]]; then
      warn "Journald persistent storage directory /var/log/journal not found after ${max_wait}s. Verify with: journalctl --verify"
    fi
  fi
}

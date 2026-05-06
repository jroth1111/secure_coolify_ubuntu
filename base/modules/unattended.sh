configure_unattended_upgrades() {
  local reboot_bool
  reboot_bool="false"
  if is_true "${ENABLE_AUTO_REBOOT}"; then
    reboot_bool="true"
  fi

  log "Configuring unattended-upgrades profile: ${UPDATE_PROFILE}"

  write_file "${APT_AUTO_FILE}" "0644" "root" "root" <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

  write_file "${APT_LOCAL_FILE}" "0644" "root" "root" <<EOF
Unattended-Upgrade::Origins-Pattern {
$(case "${UPDATE_PROFILE}" in
  security-only)
    cat <<'PROFILEEOF'
    "origin=Ubuntu,codename=${distro_codename}-security,label=Ubuntu";
PROFILEEOF
    ;;
  balanced)
    cat <<'PROFILEEOF'
    "origin=Ubuntu,codename=${distro_codename}-security,label=Ubuntu";
    "origin=Ubuntu,codename=${distro_codename}-updates,label=Ubuntu";
    "origin=Docker,label=Docker CE,archive=${distro_codename},component=stable";
PROFILEEOF
    ;;
esac)
};
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Automatic-Reboot "${reboot_bool}";
Unattended-Upgrade::Automatic-Reboot-Time "${AUTO_REBOOT_TIME}";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
$(if [[ -n "${UPGRADE_MAIL}" ]]; then
  printf 'Unattended-Upgrade::Mail "%s";\n' "${UPGRADE_MAIL}"
  printf 'Unattended-Upgrade::MailReport "only-on-error";\n'
fi)
EOF

  run systemctl enable --now apt-daily.timer apt-daily-upgrade.timer

  # Set Persistent=false to prevent boot-time catch-up blocking other package operations
  # See: https://documentation.ubuntu.com/server/how-to/software/automatic-updates/
  if ! is_true "${DRY_RUN}"; then
    mkdir -p /etc/systemd/system/apt-daily.timer.d
    cat > /etc/systemd/system/apt-daily.timer.d/override.conf <<'EOF'
[Timer]
Persistent=false
EOF
    mkdir -p /etc/systemd/system/apt-daily-upgrade.timer.d
    cat > /etc/systemd/system/apt-daily-upgrade.timer.d/override.conf <<'EOF'
[Timer]
Persistent=false
EOF
    systemctl daemon-reload
    log "Configured apt timers with Persistent=false to prevent boot-time catch-up."
  else
    log "DRY-RUN: would configure apt timers with Persistent=false"
  fi

  if ! is_true "${DRY_RUN}"; then
    unattended-upgrade --dry-run --debug >/tmp/unattended-upgrade-dryrun.log 2>&1 || warn "unattended-upgrade dry-run returned non-zero; see /tmp/unattended-upgrade-dryrun.log"
  fi
}

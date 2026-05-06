timesync_check() {
  local ntp_val
  ntp_val="$(timedatectl show --property=NTP --value 2>/dev/null || echo "?")"
  if [[ "${ntp_val}" == "yes" ]]; then
    record "PASS" "timesync: NTP active"
  elif [[ "${IS_CONTAINER}" == "true" ]]; then
    record "INFO" "timesync: NTP" "unavailable in container"
  else
    record "FAIL" "timesync: NTP" "not active"
  fi

  local synced_val
  synced_val="$(timedatectl show --property=NTPSynchronized --value 2>/dev/null || echo "?")"
  if [[ "${synced_val}" == "yes" ]]; then
    record "PASS" "timesync: NTPSynchronized"
  elif [[ "${IS_CONTAINER}" == "true" || "${ntp_val}" != "yes" ]]; then
    record "INFO" "timesync: NTPSynchronized" "skipped (NTP not active or container)"
  else
    record "FAIL" "timesync: NTPSynchronized" "not yet synchronized"
  fi
}

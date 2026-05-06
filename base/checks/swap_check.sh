swap_check() {
  local swap_size="${swap_size:-2G}"
  if [[ "${swap_size}" == "0" ]]; then
    record "INFO" "swap: disabled" "swap creation was skipped (--swap-size 0)"
    return
  fi

  if swapon --show --noheadings 2>/dev/null | grep -q .; then
    local swap_total swap_output
    # swapon --show output format: NAME TYPE SIZE USED PRIO
    # SIZE column position varies; use --bytes and sum the SIZE column (3rd field)
    swap_output="$(swapon --show --noheadings --bytes 2>/dev/null)" || true
    if [[ -n "${swap_output}" ]]; then
      swap_total="$(awk '{sum+=$3} END {printf "%.0fM", sum/1048576}' <<< "${swap_output}")"
      record "PASS" "swap: active (${swap_total})"
    else
      record "PASS" "swap: active"
    fi
  elif [[ "${IS_CONTAINER}" == "true" ]]; then
    record "INFO" "swap: status" "unavailable in container"
  else
    record "FAIL" "swap: active" "no swap detected"
  fi

  if [[ -f /swapfile ]]; then
    local perms
    perms="$(stat -c '%a' /swapfile 2>/dev/null || echo "?")"
    if [[ "${perms}" == "600" ]]; then
      record "PASS" "swap: /swapfile permissions 0600"
    else
      record "FAIL" "swap: /swapfile permissions" "expected 600, got ${perms}"
    fi
  fi

  local fstab_count
  # Match any /swapfile fstab entry regardless of options format.
  # Old Ubuntu: "/swapfile none swap sw 0 0"
  # Modern Ubuntu: "/swapfile swap swap defaults 0 0"
  fstab_count="$(grep -cE '^/swapfile[[:space:]]' /etc/fstab 2>/dev/null || true)"
  fstab_count="${fstab_count:-0}"
  if [[ "${fstab_count}" == "1" ]]; then
    record "PASS" "swap: single fstab entry"
  elif [[ "${fstab_count}" == "0" && "${IS_CONTAINER}" == "true" ]]; then
    record "INFO" "swap: fstab" "not applicable in container"
  elif (( fstab_count > 1 )); then
    record "FAIL" "swap: fstab" "duplicate entries (${fstab_count})"
  else
    record "FAIL" "swap: fstab" "entry not found in /etc/fstab — swap will not persist on reboot"
  fi
}

resolve_root_disk() {
  local root_src root_pk
  root_src="$(findmnt -n -o SOURCE / 2>/dev/null || true)"
  [[ "${root_src}" =~ ^/dev/ ]] || return 1

  root_pk="$(lsblk -no PKNAME "${root_src}" 2>/dev/null | head -n1 || true)"
  if [[ -z "${root_pk}" ]]; then
    case "${root_src}" in
      /dev/nvme*n[0-9]p[0-9]*) root_pk="${root_src#/dev/}"; root_pk="${root_pk%p*}" ;;
      /dev/*[0-9]) root_pk="${root_src#/dev/}"; root_pk="${root_pk%%[0-9]*}" ;;
      /dev/*) root_pk="${root_src#/dev/}" ;;
    esac
  fi
  [[ -n "${root_pk}" ]] || return 1
  printf '/dev/%s\n' "${root_pk}"
}

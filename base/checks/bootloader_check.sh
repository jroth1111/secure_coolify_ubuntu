bootloader_check() {
  if [[ "${IS_CONTAINER}" == "true" ]]; then
    record "INFO" "bootloader: partition safety" "unavailable in container"
    return
  fi

  if [[ -d /sys/firmware/efi ]]; then
    record "PASS" "bootloader: UEFI mode"
    return
  fi

  local root_disk pttype
  root_disk="$(resolve_root_disk 2>/dev/null || true)"
  if [[ -z "${root_disk}" || ! -b "${root_disk}" ]]; then
    record "INFO" "bootloader: BIOS/GPT safety" "unable to resolve root disk"
    return
  fi

  pttype="$(lsblk -dn -o PTTYPE "${root_disk}" 2>/dev/null | head -n1 | tr -d '[:space:]')"
  if [[ "${pttype}" != "gpt" ]]; then
    record "PASS" "bootloader: BIOS non-GPT mode (${pttype:-unknown})"
    return
  fi

  if ! command -v sgdisk >/dev/null 2>&1; then
    record "FAIL" "bootloader: BIOS/GPT safety" "sgdisk missing; cannot verify EF02 BIOS boot partition"
    return
  fi

  if sgdisk -p "${root_disk}" 2>/dev/null | awk '/^[[:space:]]*[0-9]+[[:space:]]+[0-9]+/{ if ($6=="EF02") found=1 } END{ exit(found?0:1) }'; then
    record "PASS" "bootloader: BIOS/GPT has EF02 partition (${root_disk})"
  else
    record "FAIL" "bootloader: BIOS/GPT missing EF02 partition (${root_disk})" \
      "GRUB BIOS installs may fall back to unreliable blocklists"
  fi
}

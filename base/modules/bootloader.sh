ensure_bootloader_embed_safety() {
  # UEFI does not require a BIOS boot partition.
  if [[ -d /sys/firmware/efi ]]; then
    log "UEFI boot detected; BIOS embedding safety check skipped."
    return 0
  fi

  local root_src root_pk disk pttype
  root_src="$(findmnt -n -o SOURCE / 2>/dev/null || true)"
  [[ "${root_src}" =~ ^/dev/ ]] || {
    warn "Unable to determine root block device from '/'; skipping BIOS/GPT bootloader check."
    return 0
  }

  root_pk="$(lsblk -no PKNAME "${root_src}" 2>/dev/null | head -n1 || true)"
  if [[ -z "${root_pk}" ]]; then
    case "${root_src}" in
      /dev/nvme*n[0-9]p[0-9]*) root_pk="${root_src#/dev/}"; root_pk="${root_pk%p*}" ;;
      /dev/*[0-9]) root_pk="${root_src#/dev/}"; root_pk="${root_pk%%[0-9]*}" ;;
      /dev/*) root_pk="${root_src#/dev/}" ;;
    esac
  fi
  [[ -n "${root_pk}" ]] || die "Failed to determine parent disk for root device '${root_src}'."
  disk="/dev/${root_pk}"
  [[ -b "${disk}" ]] || die "Resolved boot disk '${disk}' is not a block device."

  pttype="$(lsblk -dn -o PTTYPE "${disk}" 2>/dev/null | head -n1 | tr -d '[:space:]')"
  if [[ "${pttype}" != "gpt" ]]; then
    log "Boot disk ${disk} partition table is '${pttype:-unknown}'; BIOS/GPT embedding risk not applicable."
    return 0
  fi

  if sgdisk -p "${disk}" | awk '/^[[:space:]]*[0-9]+[[:space:]]+[0-9]+/{ if ($6=="EF02") found=1 } END{ exit(found?0:1) }'; then
    log "BIOS boot partition already present on ${disk} (EF02)."
    return 0
  fi

  log "Detected BIOS boot on GPT without EF02 partition on ${disk}; attempting auto-remediation."

  local first_start end start part_num
  first_start="$(sgdisk -p "${disk}" | awk '/^[[:space:]]*[0-9]+[[:space:]]+[0-9]+/{ print $2; exit }')"
  [[ "${first_start}" =~ ^[0-9]+$ ]] || die "Failed to determine first partition start sector on ${disk}."

  end="$(( first_start - 1 ))"
  start="$(( end - 2047 ))"
  if (( start < 34 )); then
    die "BIOS/GPT bootloader risk: no room to auto-create a 1MiB EF02 partition before ${disk}p1. Rebuild with a BIOS boot partition."
  fi

  part_num="$(sgdisk -p "${disk}" | awk '
    /^[[:space:]]*[0-9]+[[:space:]]+[0-9]+/ { used[$1]=1 }
    END {
      for (i=1; i<=128; i++) {
        if (!(i in used)) {
          print i
          exit
        }
      }
    }'
  )"
  [[ "${part_num}" =~ ^[0-9]+$ ]] || die "No free GPT partition slots available on ${disk}."

  run sgdisk -n "${part_num}:${start}:${end}" -t "${part_num}:ef02" -c "${part_num}:BIOS boot partition" "${disk}"
  run partprobe "${disk}" || true
  run grub-install "${disk}"
  run update-grub

  if sgdisk -p "${disk}" | awk '/^[[:space:]]*[0-9]+[[:space:]]+[0-9]+/{ if ($6=="EF02") found=1 } END{ exit(found?0:1) }'; then
    log "Bootloader embedding safety fixed: created EF02 BIOS boot partition on ${disk} and reinstalled GRUB."
  else
    die "Failed to verify EF02 BIOS boot partition on ${disk} after remediation."
  fi
}

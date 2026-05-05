# BATS Sequence-Dependency Fixes

## Fix #1: test_dry_run.bats — Use teardown() Function

**Current (BROKEN):**
```bash
@test "dry-run: fails when tailscale0 interface is missing" {
  ip link del tailscale0 2>/dev/null || true
  run run_dry_run
  assert_failure
  ...
  ip link add tailscale0 type dummy 2>/dev/null || true  # AFTER ASSERTIONS
  ip addr add 100.64.0.1/32 dev tailscale0 2>/dev/null || true
  ip link set tailscale0 up 2>/dev/null || true
}
```

**Fixed:**
```bash
teardown() {
  # Ensure tailscale0 is restored after each test
  ip link add tailscale0 type dummy 2>/dev/null || true
  ip addr add 100.64.0.1/32 dev tailscale0 2>/dev/null || true
  ip link set tailscale0 up 2>/dev/null || true
}

@test "dry-run: fails when tailscale0 interface is missing" {
  ip link del tailscale0 2>/dev/null || true
  run run_dry_run
  assert_failure
  ...
  # teardown() automatically restores interface
}
```

---

## Fix #2: test_full_run.bats — Add Cleanup After Test

**Current (BROKEN):**
```bash
@test "docker-daemon: pre-existing daemon.json is not overwritten on re-run" {
  ...
  sed -i 's/}$/,"test-marker": "'"${marker}"'"}/' "${daemon_json}"
  bash "${SCRIPT}" ...
  run cat "${daemon_json}"
  assert_output --partial "${marker}"
}  # NO CLEANUP
```

**Fixed:**
```bash
@test "docker-daemon: pre-existing daemon.json is not overwritten on re-run" {
  command -v docker >/dev/null 2>&1 || skip "Docker not installed"
  local daemon_json="/etc/docker/daemon.json"
  [ -f "${daemon_json}" ] || skip "daemon.json not present"
  
  local marker="__test_preserve_marker__"
  local backup
  backup="$(mktemp)"
  cp "${daemon_json}" "${backup}"
  
  sed -i 's/}$/,"test-marker": "'"${marker}"'"}/' "${daemon_json}"
  bash "${SCRIPT}" ...
  run cat "${daemon_json}"
  assert_output --partial "${marker}"
  
  # RESTORE BEFORE TEST ENDS
  cp "${backup}" "${daemon_json}"
  rm -f "${backup}"
}
```

---

## Fix #3: test_validate_negative_matrix.bats — Add teardown() Function

**Current (BROKEN):**
```bash
@test "validate negative: fail2ban stopped triggers failure" {
  systemctl stop fail2ban 2>/dev/null || true
  run bash "${VALIDATE_SCRIPT}" --json
  systemctl start fail2ban 2>/dev/null || true  # AFTER ASSERTIONS
  assert_failure
}
```

**Fixed:**
```bash
teardown() {
  # Ensure all services are restored
  systemctl start fail2ban 2>/dev/null || true
  systemctl start ssh 2>/dev/null || true
  ufw --force enable >/dev/null 2>&1 || true
}

@test "validate negative: fail2ban stopped triggers failure" {
  systemctl stop fail2ban 2>/dev/null || true
  run bash "${VALIDATE_SCRIPT}" --json
  assert_failure
  # teardown() automatically restores service
}
```

---

## Fix #4: test_validate_negative_matrix.bats — Use Trap for Cleanup

**Current (BROKEN):**
```bash
@test "disabled service drift triggers failure" {
  cat > "${unit}" <<'EOF'
...
EOF
  ...
  run bash "${VALIDATE_SCRIPT}" --json
  
  if [[ "${had_link}" == "true" ]]; then
    ln -sf "${enabled_link_target}" "${enabled_link}"
  else
    rm -f "${enabled_link}"
  fi
  assert_failure
}
```

**Fixed:**
```bash
@test "disabled service drift triggers failure" {
  local unit="/etc/systemd/system/rpcbind.service"
  local backup
  backup="$(mktemp)"
  
  # TRAP: Ensure cleanup even if test fails
  trap "rm -f '${unit}' '${backup}'; systemctl daemon-reload 2>/dev/null || true" RETURN
  
  cat > "${unit}" <<'EOF'
...
EOF
  ...
  run bash "${VALIDATE_SCRIPT}" --json
  assert_failure
  # trap automatically cleans up
}
```

---

## Fix #5: test_validate_negative_matrix.bats — Use Unique Temp Directories

**Current (BROKEN):**
```bash
stubdir="/workspace/.tmp-swap-stub-$$-$RANDOM"
mkdir -p "${stubdir}"
...
rm -rf "${stubdir}"  # AFTER ASSERTIONS
```

**Fixed:**
```bash
stubdir="$(mktemp -d)" || skip "Cannot create temp directory"
trap "rm -rf '${stubdir}'" RETURN

mkdir -p "${stubdir}"
...
# trap automatically cleans up
```

---

## Testing Verification

After applying fixes, verify with:

```bash
# Test in isolation
bats tests/integration/test_dry_run.bats

# Test full suite
bats tests/integration/*.bats

# Test specific file
bats tests/integration/test_validate_negative_matrix.bats
```

All tests should pass in both isolation and suite execution.


# BATS Sequence-Dependency Bugs — Detailed Evidence

## Bug #1: test_dry_run.bats — Tailscale Interface Deletion

**File:** `tests/integration/test_dry_run.bats`  
**Test Name:** `dry-run: fails when tailscale0 interface is missing`  
**Lines:** 165-177

```bash
@test "dry-run: fails when tailscale0 interface is missing" {
  ip link del tailscale0 2>/dev/null || true          # Line 166: DELETE

  run run_dry_run
  assert_failure
  [ ! -f "${STATE_FILE}" ]
  [ ! -f "${REPORT_FILE}" ]
  assert_output --partial "Interface tailscale0 not found"

  ip link add tailscale0 type dummy 2>/dev/null || true    # Line 174: RESTORE
  ip addr add 100.64.0.1/32 dev tailscale0 2>/dev/null || true
  ip link set tailscale0 up 2>/dev/null || true
}
```

**Problem:** Restoration (lines 174-176) is INSIDE test body AFTER assertions. If `assert_failure` or `assert_output` fails, restoration never executes. Next test in suite inherits missing interface.

**Isolation Test:** Running alone: PASS. Running after other tests: FAIL (interface missing).

---

## Bug #2: test_full_run.bats — daemon.json Marker Injection

**File:** `tests/integration/test_full_run.bats`  
**Test Name:** `docker-daemon: pre-existing daemon.json is not overwritten on re-run`  
**Lines:** 591-610

```bash
@test "docker-daemon: pre-existing daemon.json is not overwritten on re-run" {
  command -v docker >/dev/null 2>&1 || skip "Docker not installed"
  local daemon_json="/etc/docker/daemon.json"
  [ -f "${daemon_json}" ] || skip "daemon.json not present"

  local marker="__test_preserve_marker__"
  sed -i 's/}$/,"test-marker": "'"${marker}"'"}/' "${daemon_json}"  # Line 598: MUTATE

  bash "${SCRIPT}" ...
  run cat "${daemon_json}"
  assert_output --partial "${marker}"
}  # Line 610: NO CLEANUP
```

**Problem:** Marker is injected at line 598 but never removed. Subsequent tests see modified daemon.json. No cleanup after test ends.

**Impact:** Tests at lines 321-341 (docker-daemon checks) may fail if they expect pristine config.

---

## Bug #3: test_validate_negative_matrix.bats — Multiple State Mutations

**File:** `tests/integration/test_validate_negative_matrix.bats`

### 3a. fail2ban Service Stop (lines 78-85)
```bash
@test "validate negative: fail2ban stopped triggers failure" {
  systemctl stop fail2ban 2>/dev/null || true        # Line 79: STOP
  run bash "${VALIDATE_SCRIPT}" --json
  systemctl start fail2ban 2>/dev/null || true       # Line 81: START
  assert_failure
  [[ "$(json_status_for_check "fail2ban: active")" == "FAIL" ]]
}
```
**Issue:** If `assert_failure` fails, `systemctl start` never executes.

### 3b. SSH Config Modification (lines 145-160)
```bash
@test "validate negative: SSH policy drift triggers failure" {
  local backup
  backup="$(mktemp)"
  cp "${SSH_DROPIN}" "${backup}"                    # Line 148: BACKUP
  sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' "${SSH_DROPIN}"  # Line 149: MUTATE
  systemctl reload ssh 2>/dev/null || true

  run bash "${VALIDATE_SCRIPT}" --json

  cp "${backup}" "${SSH_DROPIN}"                    # Line 154: RESTORE
  systemctl reload ssh 2>/dev/null || true
  rm -f "${backup}"
  assert_failure
}
```
**Issue:** Restore at line 154 is BEFORE assertions. If assertions fail, state is restored but test still fails. However, if `run` command fails, restore never executes.

### 3c. State File Mutation (lines 186-202)
```bash
@test "validate negative: admin state drift to missing user triggers failure" {
  local backup
  local mutated
  backup="$(mktemp)"
  mutated="$(mktemp)"
  cp "${STATE_FILE}" "${backup}"                    # Line 191: BACKUP
  set_state_value "admin_user" "doesnotexist" "${backup}" "${mutated}"
  cp "${mutated}" "${STATE_FILE}"                   # Line 193: MUTATE

  run bash "${VALIDATE_SCRIPT}" --json

  cp "${backup}" "${STATE_FILE}"                    # Line 197: RESTORE
  rm -f "${backup}" "${mutated}"
  assert_failure
}
```
**Issue:** Same pattern — restore before assertions. If `run` fails, state corrupted.

---

## Bug #4: test_validate_negative_matrix.bats — Systemd Unit Creation

**File:** `tests/integration/test_validate_negative_matrix.bats`  
**Test Name:** `disabled service drift triggers failure`  
**Lines:** 271-321

```bash
@test "validate negative: disabled service drift triggers failure" {
  local unit="/etc/systemd/system/rpcbind.service"
  local had_unit="false"
  ...
  cat > "${unit}" <<'EOF'                           # Line 289: CREATE UNIT
[Unit]
Description=Fake rpcbind for validate negative test
...
EOF
  mkdir -p /etc/systemd/system/multi-user.target.wants
  ln -sf "${unit}" "${enabled_link}"                # Line 301: CREATE LINK
  systemctl daemon-reload 2>/dev/null || true

  run bash "${VALIDATE_SCRIPT}" --json

  if [[ "${had_link}" == "true" ]]; then            # Line 306: CONDITIONAL CLEANUP
    ln -sf "${enabled_link_target}" "${enabled_link}"
  else
    rm -f "${enabled_link}"
  fi
  ...
  assert_failure
}
```

**Issue:** Cleanup is conditional (lines 306-317). If condition logic is wrong or test crashes before cleanup, fake unit remains.

---

## Bug #5: test_validate_negative_matrix.bats — Stub Directory Cleanup

**File:** `tests/integration/test_validate_negative_matrix.bats`  
**Test Name:** `expected swap without active swap maps to container-safe INFO outcome`  
**Lines:** 343-374

```bash
@test "validate negative: expected swap without active swap maps to container-safe INFO outcome" {
  ...
  stubdir="/workspace/.tmp-swap-stub-$$-$RANDOM"    # Line 349: HARDCODED PATH
  mkdir -p "${stubdir}"
  ...
  run env PATH="${stubdir}:${PATH}" bash "${VALIDATE_SCRIPT}" --json

  cp "${state_backup}" "${STATE_FILE}"
  rm -f "${state_backup}" "${state_mutated}"
  rm -rf "${stubdir}"                               # Line 365: CLEANUP
  assert_success
}
```

**Issue:** Hardcoded path with `$$-$RANDOM` may collide. If `mkdir` or `run` fails, `rm -rf` never executes, leaving stub in PATH.

---

## Summary Table

| Bug # | File | Test | Lines | Issue Type | Severity |
|-------|------|------|-------|-----------|----------|
| 1 | test_dry_run.bats | tailscale0 missing | 165-177 | Cleanup after assertions | CRITICAL |
| 2 | test_full_run.bats | daemon.json marker | 591-610 | No cleanup | HIGH |
| 3a | test_validate_negative_matrix.bats | fail2ban stop | 78-85 | Cleanup after assertions | HIGH |
| 3b | test_validate_negative_matrix.bats | SSH drift | 145-160 | Cleanup before assertions | MEDIUM |
| 3c | test_validate_negative_matrix.bats | state drift | 186-202 | Cleanup before assertions | MEDIUM |
| 4 | test_validate_negative_matrix.bats | systemd unit | 271-321 | Conditional cleanup | HIGH |
| 5 | test_validate_negative_matrix.bats | swap stub | 343-374 | Cleanup after assertions | HIGH |


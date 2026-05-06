# BATS Test Suite Sequence-Dependency Audit

## Critical Issues Found

### 1. **test_dry_run.bats: Tailscale Interface Deletion Without Restoration**
**File:** `tests/integration/test_dry_run.bats`  
**Test:** `dry-run: fails when tailscale0 interface is missing` (lines 165-177)  
**Issue:** Test deletes `tailscale0` interface at line 166 but restoration at lines 174-176 is OUTSIDE the test body. If test fails before reaching line 174, subsequent tests in the suite will fail because `setup_file()` already created the interface once.  
**Evidence:** Lines 165-177 show cleanup code after assertions, not in a trap or proper teardown.  
**Impact:** Running this test in isolation succeeds; running full suite causes subsequent tests to fail due to missing interface.

---

### 2. **test_validate_negative_matrix.bats: Unguarded State File Mutations**
**File:** `tests/integration/test_validate_negative_matrix.bats`  
**Tests:** Multiple tests mutate `/var/lib/server-hardening/state` without per-test isolation  
- Line 78-85: `fail2ban stopped triggers failure` — stops fail2ban, restarts after test
- Line 87-103: `journald volatile setting triggers failure` — modifies journald config
- Line 145-160: `SSH policy drift triggers failure` — modifies SSH config with `sed -i`
- Line 186-202: `admin state drift to missing user triggers failure` — mutates state file

**Issue:** Tests use backup/restore pattern but if a test crashes before restore, subsequent tests inherit corrupted state. No per-test `setup()` function to reset state.  
**Evidence:** Lines 79-81, 148-156, 191-198 show mutations with restore only in test body.  
**Impact:** Test order dependency; running tests individually vs. suite produces different results.

---

### 3. **test_full_run.bats: daemon.json Mutation Without Restoration**
**File:** `tests/integration/test_full_run.bats`  
**Test:** `docker-daemon: pre-existing daemon.json is not overwritten on re-run` (lines 591-610)  
**Issue:** Line 598 injects marker into `/etc/docker/daemon.json` with `sed -i` but never removes it. Subsequent tests see modified daemon.json.  
**Evidence:** Line 598 mutates file; no cleanup after line 609.  
**Impact:** Subsequent tests in suite may fail if they expect pristine daemon.json state.

---

### 4. **test_validate_negative_matrix.bats: Systemd Unit Creation Without Cleanup**
**File:** `tests/integration/test_validate_negative_matrix.bats`  
**Test:** `disabled service drift triggers failure` (lines 271-321)  
**Issue:** Creates fake rpcbind unit at lines 289-301, attempts cleanup at lines 306-317 but cleanup is conditional and may fail. If cleanup fails, subsequent tests see the fake unit.  
**Evidence:** Lines 289-301 create unit; lines 306-317 show conditional cleanup that may not execute.  
**Impact:** Subsequent tests may encounter unexpected systemd units.

---

### 5. **test_validate_negative_matrix.bats: Stub Directory Cleanup Race**
**File:** `tests/integration/test_validate_negative_matrix.bats`  
**Tests:** Multiple tests create stub directories in `/workspace/.tmp-*` (line 349)  
- Line 349: `expected swap without active swap` creates stubdir
- Line 378-400: `tailscale BackendState drift` creates stubdir
- Line 403-425: `timesync drift` creates stubdir

**Issue:** Cleanup uses `rm -rf` but if test crashes, stubs remain. Hardcoded path `/workspace/.tmp-swap-stub-$$-$RANDOM` may collide.  
**Evidence:** Lines 349, 365, 378, 394, 403, 419 show stub creation/cleanup.  
**Impact:** Orphaned stub directories; potential PATH pollution affecting subsequent tests.

---

### 6. **test_validate_negative_matrix.bats: Missing Trap for Cleanup**
**File:** `tests/integration/test_validate_negative_matrix.bats`  
**Tests:** All negative matrix tests (lines 78-480)  
**Issue:** No `setup()` or `teardown()` functions; all cleanup is inline. If test assertion fails before cleanup code, state is not restored.  
**Evidence:** Tests use pattern: mutate → run test → restore. If `run` or assertion fails, restore never executes.  
**Impact:** Test failures leave system in dirty state; subsequent tests inherit corrupted state.

---

## Recommendations

1. **Add per-test `teardown()` function** to all integration tests that mutate state
2. **Use `trap` for cleanup** in tests that modify system files
3. **Isolate state mutations** with `setup_file()` + `teardown_file()` or per-test cleanup
4. **Test in isolation** before committing: `bats tests/integration/test_X.bats`
5. **Document test order dependencies** if any are intentional

---

## Test Files Affected

- `tests/integration/test_dry_run.bats` (1 issue)
- `tests/integration/test_full_run.bats` (1 issue)
- `tests/integration/test_validate_negative_matrix.bats` (4 issues)

**Total Issues:** 6 critical sequence-dependent bugs


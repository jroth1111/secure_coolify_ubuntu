# Research-Based Improvements Analysis (Updated)

**Updated:** 2026-03-04  
**Source Research:** `/Users/gwizz/CascadeProjects/coolify-docs/research/`  
**Target Scripts:** `bootstrap_hardening.sh`, `validate_hardening.sh`

## Summary

The previous analysis file was partially stale relative to the current scripts.  
This update reflects the real implementation state and the follow-up fix applied in this repo.

## Suggestion Evaluation

### 1) Docker Origins Pattern (`archive=` vs `suite=`)

**Original suggestion:** Replace `archive=` with `suite=` in unattended-upgrades Docker origin matching.

**Current code status:**
- `bootstrap_hardening.sh` currently writes Docker origin with `archive=...`.
- `validate_hardening.sh` now accepts **either** `archive=` or `suite=` for Docker origin checks.

**Decision:** Keep bootstrap output unchanged for now; accept both forms in validation.  
**Why:** `unattended-upgrades` supports both forms; enforcing only one creates avoidable Gate C false positives.

**Implemented fix:** `validate_hardening.sh` now treats Docker origin as valid when pinned with:
- `origin=Docker,label=Docker CE,archive=${distro_codename},component=stable`
- or `origin=Docker,label=Docker CE,suite=${distro_codename},component=stable`

---

### 2) Audit queue health monitoring

**Original suggestion:** Add `auditctl -s` lost/backlog monitoring.

**Current code status:** Already implemented in `validate_hardening.sh` (`auditd_check`):
- queue loss parsing (`lost`)
- backlog reporting (`backlog`)
- PASS/INFO/FAIL thresholds

**Decision:** No change needed.

---

### 3) Profile-based hardening

**Original suggestion:** Add hardening profiles.

**Current code status:** Implemented for auto-updates:
- `UPDATE_PROFILE` exists (`security-only` default, `balanced` optional)
- `--update-profile` CLI flag
- profile-aware validation in `validate_hardening.sh`

**Decision:** No additional change needed for this cycle.

---

### 4) Tailscale UDP 41641 optionality clarity

**Original suggestion:** Document as optimization, not hard dependency.

**Current code status:** Rule remains enabled by default in UFW (`bootstrap_hardening.sh`).

**Decision:** Valid documentation improvement, low priority.  
No behavior change applied in this cycle.

---

### 5) Docker bridge CIDR strictness

**Original suggestion:** Prefer least-privilege discovered bridge CIDRs over broad RFC1918 ranges.

**Current code status:** Implemented:
- strict CIDR mode is default
- compatibility mode remains explicitly available
- discovery uses bridge network/interface sources with compatibility fallback

**Decision:** No additional change needed.

## Net Assessment

Most high-value research items are already implemented.  
The only actionable script gap found during review was Docker origin field strictness in validation, which is now fixed by accepting both `archive=` and `suite=` forms while still enforcing `component=stable`.

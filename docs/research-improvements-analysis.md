# Research-Based Improvements Analysis (Updated)

**Updated:** 2026-03-04  
**Source Research:** `research/` (local repo directory)  
**Target Scripts:** `base/bootstrap.sh`, `base/validate.sh`

## Summary

The previous analysis file was partially stale relative to the current scripts.  
This update reflects the real implementation state and the follow-up fix applied in this repo.

## Suggestion Evaluation

### 1) Docker Origins Pattern (`archive=` vs `suite=`)

**Original suggestion:** Replace `archive=` with `suite=` in unattended-upgrades Docker origin matching.

**Current code status:**
- `base/bootstrap.sh` currently writes Docker origin with `archive=...`.
- `base/validate.sh` now accepts **either** `archive=` or `suite=` for Docker origin checks.

**Decision:** Keep bootstrap output unchanged for now; accept both forms in validation.  
**Why:** `unattended-upgrades` supports both forms; enforcing only one creates avoidable Gate C false positives.

**Implemented fix:** `base/validate.sh` now treats Docker origin as valid when pinned with:
- `origin=Docker,label=Docker CE,archive=${distro_codename},component=stable`
- or `origin=Docker,label=Docker CE,suite=${distro_codename},component=stable`

---

### 2) Audit queue health monitoring

**Original suggestion:** Add `auditctl -s` lost/backlog monitoring.

**Current code status:** Already implemented in `base/validate.sh` (`auditd_check`):
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
- profile-aware validation in `base/validate.sh`

**Decision:** No additional change needed for this cycle.

---

### 4) Tailscale UDP 41641 optionality clarity

**Original suggestion:** Document as optimization, not hard dependency.

**Current code status:** Implemented as explicit behavior:
- New `TAILSCALE_DIRECT_WAN` setting (default `false`) in `base/bootstrap.sh`
- New CLI flags: `--tailscale-direct-wan` / `--no-tailscale-direct-wan`
- UFW only opens WAN UDP `41641` when explicitly enabled
- State/report now record `tailscale_direct_wan`
- `base/validate.sh` now validates presence/absence of UDP `41641` based on state

**Decision:** Applied as a script-level hardening improvement.  
Default behavior now minimizes WAN exposure while preserving opt-in direct-path performance.

---

### 5) Docker bridge CIDR strictness

**Original suggestion:** Prefer least-privilege discovered bridge CIDRs over broad RFC1918 ranges.

**Current code status:** Implemented:
- strict CIDR mode is default
- compatibility mode remains explicitly available
- discovery uses bridge network/interface sources with compatibility fallback

**Decision:** No additional change needed.

## Net Assessment

Most high-value research items are now implemented in scripts.
- Docker origin validation accepts both `archive=` and `suite=` while enforcing `component=stable`.
- Tailscale direct-path WAN UDP (`41641`) is now optional and state-driven (default closed, explicit opt-in).

# Script fix: Coolify instance settings enforcement

Date: 2026-03-06

Issue:
- Coolify `instance_settings` drift was not managed by deploy/setup phase 4.
- `is_registration_enabled` could remain `true`.
- `fqdn` could remain empty.

Changes:
- Added phase-4 instance settings reconciliation to set `fqdn=https://<domain>` and `is_registration_enabled=false`.
- Added final validator checks for those two instance settings.
- Added unit tests and logic-step coverage mappings.

Verification:
- `bash -n deploy.sh setup.sh lib/coolify-common.sh validate_hardening.sh bootstrap_hardening.sh configure_coolify_binding.sh` -> pass
- `bash scripts/check_function_behavior_coverage.sh` -> `248/248`
- `bash scripts/check_logic_step_coverage.sh` -> `248/248`
- `bats tests/unit` -> `484/484`

Live note:
- Initial VPS-side verification was partially completed before the host became unavailable for unrelated reasons.
- On the reachable host before outage, direct SQL verification showed the intended values can be enforced:
  - before: `t|<null>`
  - after: `f|https://vps.megastyleapartments.com.au`

# Refactor Layout Map

Maps old file paths (before refactor) to new paths (after C1–C10).

| Old path | New path(s) |
|---|---|
| `bootstrap_hardening.sh` | `base/bootstrap.sh` (orchestration) + `base/modules/*.sh` |
| `validate_hardening.sh` | `base/validate.sh` (orchestration) + `base/checks/*.sh` |
| `lib/coolify-common.sh` | `overlays/coolify/coolify-common.sh` (all content) |
| `configure_coolify_binding.sh` | `overlays/coolify/configure_coolify_binding.sh` |
| `tests/helpers.bash` | `tests/helpers/helpers.bash` |
| (inline in bootstrap_hardening.sh) | `lib/common.sh` — log, warn, die, is_true, prompt_*, run_report_* |
| (inline in bootstrap_hardening.sh) | `lib/tailscale.sh` — install_tailscale, get_tailscale_ip, etc. |
| (docker-host functions) | `overlays/docker-host/modules/` — cidrs, daemon, detect, etc. |
| (coolify binding functions) | `overlays/coolify/modules/` — binding, binding_watchdog |
| (coolify check functions) | `overlays/coolify/checks/` — 7 check files |

## Test directory layout

| Old path | New path |
|---|---|
| `tests/unit/*.bats` (base tests) | `tests/base/unit/*.bats` |
| `tests/integration/*.bats` | `tests/base/integration/*.bats` |
| `tests/unit/test_common_additional_behavior.bats` | `tests/overlays/coolify/unit/test_common_additional_behavior.bats` |
| `tests/unit/test_deploy_setup_additional_behavior.bats` | `tests/orchestrator/unit/test_deploy_setup_additional_behavior.bats` |

## State paths

| Old path | New path |
|---|---|
| `/var/lib/bootstrap-hardening/` | `/var/lib/server-hardening/` |
| `/var/log/bootstrap-hardening.log` | `/var/log/server-hardening.log` |
| `/var/log/bootstrap-hardening-report.json` | `/var/log/server-hardening-report.json` |

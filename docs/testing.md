# Testing Guide

This repository uses BATS with Docker-backed test lanes for deterministic execution across local and CI environments.

## Prerequisites

- Docker installed and running
- GNU Make

No host-level BATS install is required. All suites run inside `Dockerfile.test`.

## Quick Start

```bash
make test-ci-max
```

## Target Matrix

| Target | Scope | Privileges |
| --- | --- | --- |
| `make test-lint-docker` | Bash syntax + shellcheck inside Docker | None |
| `make test-unit-docker` | Pure function tests (`tests/unit`) | None |
| `make test-contracts` | Workflow/function/logic-step/target coverage contracts | None |
| `make test-orchestrator-smoke` | `deploy.sh`/`setup.sh` orchestrator behavior smoke lane | None |
| `make test-dry-run` | Dry-run integration (`--dry-run`) | `--cap-add NET_ADMIN` |
| `make test-validate` | `base/validate.sh` pass/fail behavior | Privileged + systemd |
| `make test-full-standard` | Full standard-mode integration | Privileged + systemd |
| `make test-full-tunnel` | Full tunnel-mode integration | Privileged + systemd |
| `make test-idempotency` | Re-run safety / duplicate-prevention checks | Privileged + systemd |
| `make test-bootstrap-matrix` | Bootstrap scenario matrix | Privileged + systemd |
| `make test-validate-negative-matrix` | Validator negative/fault-injection matrix | Privileged + systemd |
| `make test-integration-core` | Core integration lanes | Mixed |
| `make test-integration-matrix` | Scenario matrix lanes | Privileged + systemd |
| `make test-negative-matrix` | Negative/fault lanes | Privileged + systemd |
| `make test-integration` | Core + matrix + negative lanes | Mixed |
| `make test-all` | Lint + unit + contracts + integration | Mixed |
| `make test-ci-max` | Max coverage gate (used for PR/main/nightly) | Mixed |

Logs and JSON snapshots are written to `artifacts/` during execution. These are ephemeral run artifacts and are git-ignored by default.

## Functionality Coverage Matrix

- Hardening workflow matrix: `docs/bootstrap_functionality_test_matrix.md`
- Deploy/setup workflow matrix: `docs/deploy_setup_functionality_test_matrix.md`
- Canonical workflow contract (machine-checked): `docs/workflow_contract.yaml`
- Logic-step contract v2 (machine-checked, function-level): `docs/logic_step_contract.yaml`

`docs/logic_step_contract.yaml` now tracks every discovered function in:

- `base/bootstrap.sh`
- `base/validate.sh`
- `deploy.sh`
- `setup.sh`
- `overlays/coolify/coolify-common.sh`

Each function entry must reference:

- one behavior test (`behavior_test`)
- one or more check tests (`checks`)

Both behavior and check references are validated as executable test evidence by:

- `scripts/check_logic_step_coverage.sh`
- `scripts/check_function_behavior_coverage.sh`

## CI Jobs

Workflow: `.github/workflows/tests.yml`

- `lint-docker`: Docker lint lane (`make test-lint-docker`)
- `unit-contracts`: unit + contract checks (`make test-unit-docker` + `make test-contracts`)
- `integration-core`: core integration (`make test-integration-core`)
- `integration-matrix`: matrix integration (`make test-integration-matrix`)
- `negative-matrix`: negative/fault matrix (`make test-negative-matrix`)
- `workflow_dispatch`: optional lane selection (`all`, `lint`, `unit-contracts`, `integration-core`, `integration-matrix`, `negative-matrix`)

## Fidelity Notes

`Dockerfile.test` includes controlled stubs for container-incompatible subsystems:

- `auditctl` and `augenrules` are stubbed to model rule loading behavior
- `sysctl --system` wrapper filters known container namespace noise
- `docker` CLI is stubbed to exercise managed `DOCKER-USER` path
- Real external dependencies (live VPS/Tailscale/Cloudflare) are intentionally excluded from Docker lanes

These stubs keep the suite deterministic while preserving expected control-flow coverage for hardening logic.

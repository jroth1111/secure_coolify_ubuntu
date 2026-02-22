# Testing Guide

This repository uses BATS with Docker-backed test lanes for deterministic execution across local and CI environments.

## Prerequisites

- Docker installed and running
- GNU Make

No host-level BATS install is required. All suites run inside `Dockerfile.test`.

## Quick Start

```bash
make test-ci-pr
```

## Target Matrix

| Target | Scope | Privileges |
| --- | --- | --- |
| `make test-unit` | Pure function tests (`tests/unit`) | None |
| `make test-dry-run` | Dry-run integration (`--dry-run`) | `--cap-add NET_ADMIN` |
| `make test-validate` | `validate_hardening.sh` pass/fail behavior | Privileged + systemd |
| `make test-full-standard` | Full standard-mode integration | Privileged + systemd |
| `make test-full-tunnel` | Full tunnel-mode integration | Privileged + systemd |
| `make test-idempotency` | Re-run safety / duplicate-prevention checks | Privileged + systemd |
| `make test-integration` | All integration lanes | Mixed |
| `make test-all` | Unit + integration lanes | Mixed |
| `make test-ci-pr` | PR gate: unit + dry-run + validate | Mixed |
| `make test-ci-main` | Mainline gate: full suite | Mixed |

Logs and JSON snapshots are stored in `artifacts/`.

## Functionality Coverage Matrix

The itemized script-to-test mapping lives in `docs/bootstrap_functionality_test_matrix.md`.

## CI Jobs

Workflow: `.github/workflows/tests.yml`

- `lint-shell`: `bash -n` + `shellcheck` (required for PR/push)
- `tests-pr-fast`: `make test-ci-pr` (required for PR/push except `main`)
- `tests-main-full`: `make test-ci-main` (required on `main`)
- `tests-nightly`: scheduled full suite (non-blocking signal lane)
- `tests-manual-full`: workflow-dispatch selectable suite (`full-standard`, `full-tunnel`, `all`)

## Fidelity Notes

`Dockerfile.test` includes controlled stubs for container-incompatible subsystems:

- `auditctl` and `augenrules` are stubbed to model rule loading behavior
- `sysctl --system` wrapper filters known container namespace noise
- `docker` CLI is stubbed to exercise managed `DOCKER-USER` path

These stubs keep the suite deterministic while preserving expected control-flow coverage for hardening logic.

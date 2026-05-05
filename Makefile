SHELL := /bin/bash

.PHONY: \
	docker-build \
	docker-build-tier1 \
	docker-build-tier2 \
	setup-bats \
	test-lint-docker \
	test \
	test-all \
	test-unit \
	test-unit-docker \
	test-unit-local \
	test-orchestrator-smoke \
	test-dry-run \
	test-full-standard \
	test-full-tunnel \
	test-validate \
	test-idempotency \
	test-bootstrap-matrix \
	test-validate-negative-matrix \
	test-workflow-consistency \
	test-function-coverage \
	test-bats-target-coverage \
	test-logic-step-coverage \
	test-contracts \
	test-integration-core \
	test-integration-matrix \
	test-negative-matrix \
	test-integration \
	test-ci-max \
	test-ci-pr \
	test-ci-main \
	aggregate-artifacts \
	clean-artifacts

IMAGE_TIER1 ?= hardening-test-tier1:latest
IMAGE_TIER2 ?= hardening-test:latest
BATS_LIB_DIR ?= tests/lib
ARTIFACTS_DIR ?= artifacts
CONTAINER_PREFIX ?= ht
WORKSPACE ?= /workspace
RUNNER_DOCKER_CMD ?= scripts/run_docker_lane_cmd.sh
RUNNER_BATS_TIER1 ?= scripts/run_bats_tier1_lane.sh
RUNNER_BATS_TIER2 ?= scripts/run_bats_tier2_lane.sh
RUNNER_MATRIX_TIER2 ?= scripts/run_tier2_scenario_matrix.sh

# ==============================================================================
# Docker Build Targets
# ==============================================================================

docker-build-tier1:
	docker build -f Dockerfile.tier1 -t $(IMAGE_TIER1) .

docker-build-tier2:
	docker build -f Dockerfile.test -t $(IMAGE_TIER2) .

# Backwards compatible alias
docker-build: docker-build-tier2

# ==============================================================================
# Local Setup (Tier 0 - no Docker)
# ==============================================================================

setup-bats:
	@command -v bats >/dev/null 2>&1 || { echo "Error: bats not found. Install with: brew install bats-core"; exit 1; }
	@mkdir -p $(BATS_LIB_DIR)
	@if [ ! -d "$(BATS_LIB_DIR)/bats-support" ]; then \
	  git clone --depth 1 https://github.com/bats-core/bats-support.git $(BATS_LIB_DIR)/bats-support; \
	else \
	  echo "bats-support already installed"; \
	fi
	@if [ ! -d "$(BATS_LIB_DIR)/bats-assert" ]; then \
	  git clone --depth 1 https://github.com/bats-core/bats-assert.git $(BATS_LIB_DIR)/bats-assert; \
	else \
	  echo "bats-assert already installed"; \
	fi

# ==============================================================================
# Test Targets
# ==============================================================================

# Tier 1: Lint and syntax checks inside Docker (container-first execution)
test-lint-docker: docker-build-tier1
	$(RUNNER_DOCKER_CMD) \
	  --image $(IMAGE_TIER1) \
	  --lane lint-docker \
	  --workspace $(WORKSPACE) \
	  --artifacts-dir $(ARTIFACTS_DIR) \
	  --cmd 'bash -n base/bootstrap.sh base/validate.sh setup.sh deploy.sh configure_coolify_binding.sh lib/coolify-common.sh lib/common.sh lib/tailscale.sh && shellcheck -S error base/bootstrap.sh base/validate.sh setup.sh deploy.sh configure_coolify_binding.sh lib/coolify-common.sh lib/common.sh lib/tailscale.sh scripts/*.sh'

# Tier 0: Unit tests - local (fastest, no Docker)
test-unit-local: setup-bats
	bats tests/unit/

# Tier 1: Unit tests in Docker (for CI consistency)
test-unit-docker: docker-build-tier1
	$(RUNNER_BATS_TIER1) \
	  --image $(IMAGE_TIER1) \
	  --lane unit \
	  --target /workspace/tests/unit/ \
	  --workspace $(WORKSPACE) \
	  --artifacts-dir $(ARTIFACTS_DIR)

# Backwards-compatible alias
test-unit: test-unit-docker

# Tier 1: Deploy/setup orchestrator smoke tests (mocked behavior)
test-orchestrator-smoke: docker-build-tier1
	$(RUNNER_BATS_TIER1) \
	  --image $(IMAGE_TIER1) \
	  --lane orchestrator-smoke \
	  --target /workspace/tests/integration/test_deploy.bats \
	  --workspace $(WORKSPACE) \
	  --artifacts-dir $(ARTIFACTS_DIR)

# Tier 1: Dry-run integration tests (lightweight container)
test-dry-run: docker-build-tier1
	$(RUNNER_BATS_TIER1) \
	  --image $(IMAGE_TIER1) \
	  --lane dry-run \
	  --target /workspace/tests/integration/test_dry_run.bats \
	  --workspace $(WORKSPACE) \
	  --artifacts-dir $(ARTIFACTS_DIR) \
	  --docker-arg --cap-add \
	  --docker-arg NET_ADMIN

# Tier 2: Full integration tests (privileged systemd container)
test-full-standard: docker-build-tier2
	$(RUNNER_BATS_TIER2) \
	  --image $(IMAGE_TIER2) \
	  --lane full-standard \
	  --target /workspace/tests/integration/test_full_run.bats \
	  --workspace $(WORKSPACE) \
	  --artifacts-dir $(ARTIFACTS_DIR) \
	  --container-prefix $(CONTAINER_PREFIX)

test-full-tunnel: docker-build-tier2
	$(RUNNER_BATS_TIER2) \
	  --image $(IMAGE_TIER2) \
	  --lane full-tunnel \
	  --target /workspace/tests/integration/test_full_tunnel.bats \
	  --workspace $(WORKSPACE) \
	  --artifacts-dir $(ARTIFACTS_DIR) \
	  --container-prefix $(CONTAINER_PREFIX)

test-validate: docker-build-tier2
	$(RUNNER_BATS_TIER2) \
	  --image $(IMAGE_TIER2) \
	  --lane validate \
	  --target /workspace/tests/integration/test_validate_script.bats \
	  --workspace $(WORKSPACE) \
	  --artifacts-dir $(ARTIFACTS_DIR) \
	  --container-prefix $(CONTAINER_PREFIX)

test-idempotency: docker-build-tier2
	$(RUNNER_BATS_TIER2) \
	  --image $(IMAGE_TIER2) \
	  --lane idempotency \
	  --target /workspace/tests/integration/test_idempotency.bats \
	  --workspace $(WORKSPACE) \
	  --artifacts-dir $(ARTIFACTS_DIR) \
	  --container-prefix $(CONTAINER_PREFIX)

# Tier 2: Scenario-matrix integration tests
test-bootstrap-matrix: docker-build-tier2
	$(RUNNER_MATRIX_TIER2) \
	  --image $(IMAGE_TIER2) \
	  --lane bootstrap-matrix \
	  --file /workspace/tests/integration/test_bootstrap_matrix.bats \
	  --workspace $(WORKSPACE) \
	  --artifacts-dir $(ARTIFACTS_DIR) \
	  --container-prefix $(CONTAINER_PREFIX)

test-validate-negative-matrix: docker-build-tier2
	$(RUNNER_MATRIX_TIER2) \
	  --image $(IMAGE_TIER2) \
	  --lane validate-negative-matrix \
	  --file /workspace/tests/integration/test_validate_negative_matrix.bats \
	  --workspace $(WORKSPACE) \
	  --artifacts-dir $(ARTIFACTS_DIR) \
	  --container-prefix $(CONTAINER_PREFIX)

# Workflow contract and documentation consistency checks
test-workflow-consistency:
	bash scripts/check_workflow_consistency.sh

# Function-level behavior coverage check
test-function-coverage:
	bash scripts/check_function_behavior_coverage.sh

test-bats-target-coverage:
	bash scripts/check_bats_target_coverage.sh

test-logic-step-coverage:
	bash scripts/check_logic_step_coverage.sh

test-contracts: docker-build-tier1
	$(RUNNER_DOCKER_CMD) \
	  --image $(IMAGE_TIER1) \
	  --lane contracts \
	  --workspace $(WORKSPACE) \
	  --artifacts-dir $(ARTIFACTS_DIR) \
	  --cmd 'bash scripts/check_workflow_consistency.sh && bash scripts/check_function_behavior_coverage.sh && bash scripts/check_bats_target_coverage.sh && bash scripts/check_logic_step_coverage.sh'

# ==============================================================================
# Combined Targets
# ==============================================================================

test-integration-core: test-dry-run test-full-standard test-full-tunnel test-validate test-idempotency test-orchestrator-smoke

test-integration-matrix: test-bootstrap-matrix

test-negative-matrix: test-validate-negative-matrix

test-integration: test-integration-core test-integration-matrix test-negative-matrix

test-all: test-lint-docker test-unit-docker test-contracts test-integration

aggregate-artifacts:
	bash scripts/aggregate_test_artifacts.sh

# CI targets: max coverage always in Docker
test-ci-max: clean-artifacts test-all aggregate-artifacts

# Backwards-compatible aliases
test-ci-pr: test-ci-max

test-ci-main: test-ci-max

test: test-ci-max

# ==============================================================================
# Cleanup
# ==============================================================================

clean-artifacts:
	rm -rf $(ARTIFACTS_DIR)

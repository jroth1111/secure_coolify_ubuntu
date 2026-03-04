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

# Run BATS in tier1 container (lightweight, no systemd)
define run_bats_tier1
mkdir -p $(ARTIFACTS_DIR); \
docker run --rm $(1) -v "$$(pwd)":$(WORKSPACE) $(IMAGE_TIER1) \
  bats $(2) > $(ARTIFACTS_DIR)/$(3).log 2>&1; \
rc=$$?; \
cat $(ARTIFACTS_DIR)/$(3).log; \
exit $$rc
endef

# Run BATS in tier2 container (privileged systemd)
define run_bats_tier2
name="$(CONTAINER_PREFIX)-$(1)-$$RANDOM"; \
mkdir -p $(ARTIFACTS_DIR); \
docker run -d --name "$$name" --privileged \
  --tmpfs /tmp --tmpfs /run \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  -v "$$(pwd)":$(WORKSPACE) $(IMAGE_TIER2) >/dev/null; \
sleep 3; \
docker exec "$$name" bats $(2) > $(ARTIFACTS_DIR)/$(1).log 2>&1; \
rc=$$?; \
docker exec "$$name" test -f /var/log/bootstrap-hardening-report.json \
  && docker exec "$$name" cat /var/log/bootstrap-hardening-report.json > $(ARTIFACTS_DIR)/$(1)-bootstrap-report.json || true; \
docker exec "$$name" bash -lc '/workspace/validate_hardening.sh --json' \
  > $(ARTIFACTS_DIR)/$(1)-validate.json 2>/dev/null || true; \
docker rm -f "$$name" >/dev/null 2>&1 || true; \
cat $(ARTIFACTS_DIR)/$(1).log; \
exit $$rc
endef

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
	mkdir -p $(ARTIFACTS_DIR); \
	docker run --rm -v "$$(pwd)":$(WORKSPACE) $(IMAGE_TIER1) \
	  bash -lc 'cd $(WORKSPACE) && \
	    bash -n bootstrap_hardening.sh setup.sh deploy.sh validate_hardening.sh configure_coolify_binding.sh lib/coolify-common.sh && \
	    shellcheck -S error bootstrap_hardening.sh setup.sh deploy.sh validate_hardening.sh configure_coolify_binding.sh lib/coolify-common.sh scripts/*.sh' \
	  > $(ARTIFACTS_DIR)/lint-docker.log 2>&1; \
	rc=$$?; \
	cat $(ARTIFACTS_DIR)/lint-docker.log; \
	exit $$rc

# Tier 0: Unit tests - local (fastest, no Docker)
test-unit-local: setup-bats
	bats tests/unit/

# Tier 1: Unit tests in Docker (for CI consistency)
test-unit-docker: docker-build-tier1
	$(call run_bats_tier1,,/workspace/tests/unit/,unit)

# Backwards-compatible alias
test-unit: test-unit-docker

# Tier 1: Deploy/setup orchestrator smoke tests (mocked behavior)
test-orchestrator-smoke: docker-build-tier1
	$(call run_bats_tier1,,/workspace/tests/integration/test_deploy.bats,orchestrator-smoke)

# Tier 1: Dry-run integration tests (lightweight container)
test-dry-run: docker-build-tier1
	$(call run_bats_tier1,--cap-add NET_ADMIN,/workspace/tests/integration/test_dry_run.bats,dry-run)

# Tier 2: Full integration tests (privileged systemd container)
test-full-standard: docker-build-tier2
	$(call run_bats_tier2,full-standard,/workspace/tests/integration/test_full_run.bats)

test-full-tunnel: docker-build-tier2
	$(call run_bats_tier2,full-tunnel,/workspace/tests/integration/test_full_tunnel.bats)

test-validate: docker-build-tier2
	$(call run_bats_tier2,validate,/workspace/tests/integration/test_validate_script.bats)

test-idempotency: docker-build-tier2
	$(call run_bats_tier2,idempotency,/workspace/tests/integration/test_idempotency.bats)

# Tier 2: Scenario-matrix integration tests
test-bootstrap-matrix: docker-build-tier2
	$(call run_bats_tier2,bootstrap-matrix,/workspace/tests/integration/test_bootstrap_matrix.bats)

test-validate-negative-matrix: docker-build-tier2
	$(call run_bats_tier2,validate-negative-matrix,/workspace/tests/integration/test_validate_negative_matrix.bats)

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

test-contracts: test-workflow-consistency test-function-coverage test-bats-target-coverage test-logic-step-coverage

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
test-ci-max: test-all aggregate-artifacts

# Backwards-compatible aliases
test-ci-pr: test-ci-max

test-ci-main: test-ci-max

test: test-ci-max

# ==============================================================================
# Cleanup
# ==============================================================================

clean-artifacts:
	rm -rf $(ARTIFACTS_DIR)

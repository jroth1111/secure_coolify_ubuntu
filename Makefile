SHELL := /bin/bash

.PHONY: \
	docker-build \
	docker-build-tier1 \
	docker-build-tier2 \
	setup-bats \
	test \
	test-all \
	test-unit \
	test-unit-local \
	test-dry-run \
	test-full-standard \
	test-full-tunnel \
	test-validate \
	test-idempotency \
	test-workflow-consistency \
	test-integration \
	test-ci-pr \
	test-ci-main \
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

# Tier 0: Unit tests - local (fastest, no Docker)
test-unit-local: setup-bats
	bats tests/unit/

# Tier 1: Unit tests in Docker (for CI consistency)
test-unit: docker-build-tier1
	$(call run_bats_tier1,,/workspace/tests/unit/,unit)

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

# Workflow contract and documentation consistency checks
test-workflow-consistency:
	bash scripts/check_workflow_consistency.sh

# ==============================================================================
# Combined Targets
# ==============================================================================

test-integration: test-dry-run test-full-standard test-full-tunnel test-validate test-idempotency

test-all: test-unit test-integration

# CI targets: use Docker for consistency
test-ci-pr: test-unit test-dry-run test-validate test-workflow-consistency

test-ci-main: test-all test-workflow-consistency

test: test-all

# ==============================================================================
# Cleanup
# ==============================================================================

clean-artifacts:
	rm -rf $(ARTIFACTS_DIR)

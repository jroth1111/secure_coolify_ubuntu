# Deploy/Setup Workflow Functionality Test Matrix

This matrix maps `deploy.sh` and `setup.sh` workflow steps to explicit automated tests.

| Contract ID | Workflow step | Coverage tests | Sufficiency |
| --- | --- | --- | --- |
| `DEP-01` | Deploy preflight phase exists and is callable | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: preflight phase marker exists` | Sufficient |
| `DEP-02` | Deploy phase 1 upload + hardening orchestration | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: phase1 upload+harden marker exists` | Sufficient |
| `DEP-03` | Deploy hardening invocation includes env-file + Tailscale install path | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: hardening invocation uses env-file and tailscale install` | Sufficient |
| `DEP-04` | Deploy Gate A validates admin SSH over Tailscale | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: gate A checks admin SSH on tailscale` | Sufficient |
| `DEP-05` | Deploy Gate B validates expected admin identity | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: gate B verifies admin identity` | Sufficient |
| `DEP-06` | Deploy Gate C runs `validate_hardening.sh --json` | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: gate C runs validate_hardening.sh json` | Sufficient |
| `DEP-07` | Deploy Gate D requires active `docker-user-hardening.service` and managed rules | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: gate D validates service active and managed rules` | Sufficient |
| `DEP-08` | Deploy phase 4 binding + DNS stage exists | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: phase4 binding+dns marker exists` | Sufficient |
| `DEP-09` | Deploy Gate E enforces dashboard exposure boundary checks | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: gate E fails when exposure checks do not pass` | Sufficient |
| `DEP-10` | Deploy final validation run exists | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: final validation is executed` | Sufficient |
| `SET-01` | Setup preflight phase exists and is callable | `tests/unit/test_setup_workflow_contract.bats`: `setup: preflight phase marker exists` | Sufficient |
| `SET-02` | Setup phase 1 hardening orchestration | `tests/unit/test_setup_workflow_contract.bats`: `setup: phase1 harden marker exists` | Sufficient |
| `SET-03` | Setup Gate A requires operator SSH verification from laptop | `tests/unit/test_setup_workflow_contract.bats`: `setup: gate A requires operator laptop verification` | Sufficient |
| `SET-04` | Setup Gate B validates admin home + `.ssh` state | `tests/unit/test_setup_workflow_contract.bats`: `setup: gate B verifies admin user home and ssh directory` | Sufficient |
| `SET-05` | Setup Gate C runs `validate_hardening.sh --json` | `tests/unit/test_setup_workflow_contract.bats`: `setup: gate C runs validate_hardening.sh json` | Sufficient |
| `SET-06` | Setup Gate D requires active `docker-user-hardening.service` and managed rules | `tests/unit/test_setup_workflow_contract.bats`: `setup: gate D validates service active and managed rules` | Sufficient |
| `SET-07` | Setup phase 4 binding + DNS stage exists | `tests/unit/test_setup_workflow_contract.bats`: `setup: phase4 binding+dns marker exists` | Sufficient |
| `SET-08` | Setup Gate E requires operator dashboard boundary verification from laptop | `tests/unit/test_setup_workflow_contract.bats`: `setup: gate E requires operator laptop verification` | Sufficient |
| `SET-09` | Setup final validation run exists | `tests/unit/test_setup_workflow_contract.bats`: `setup: final validation is executed` | Sufficient |

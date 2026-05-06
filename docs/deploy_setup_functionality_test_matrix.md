# Deploy/Setup Workflow Functionality Test Matrix

This matrix maps `deploy.sh` and `setup.sh` workflow steps to explicit automated tests.

| Contract ID | Workflow step | Coverage tests | Sufficiency |
| --- | --- | --- | --- |
| `DEP-01` | Deploy preflight executes prerequisite checks and root SSH probe path | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: preflight phase marker exists` | Sufficient |
| `DEP-02` | Deploy phase 1 performs hardening flow and captures Tailscale sentinel IP | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: phase1 upload+harden marker exists` | Sufficient |
| `DEP-03` | Deploy phase 1 invokes bootstrap with required hardening flags | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: hardening invocation uses env-file and tailscale install` | Sufficient |
| `DEP-04` | Deploy Gate A retries and succeeds on admin SSH over Tailscale | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: gate A checks admin SSH on tailscale` | Sufficient |
| `DEP-05` | Deploy Gate B fails on admin identity mismatch | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: gate B verifies admin identity` | Sufficient |
| `DEP-06` | Deploy Gate C invokes `base/validate.sh --json` and reports result | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: gate C runs base/validate.sh json` | Sufficient |
| `DEP-07` | Deploy Gate D fails if docker-user hardening service/rules are not valid | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: gate D validates service active and managed rules` | Sufficient |
| `DEP-08` | Deploy phase 4 performs DNS updates for standard mode | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: phase4 binding+dns marker exists` | Sufficient |
| `DEP-09` | Deploy Gate E blocks completion when exposure checks fail | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: gate E fails when exposure checks do not pass` | Sufficient |
| `DEP-10` | Deploy final validation is executed after verification gates | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: final validation is executed` | Sufficient |
| `SET-01` | Setup preflight executes prerequisite checks | `tests/unit/test_setup_workflow_contract.bats`: `setup: preflight phase marker exists` | Sufficient |
| `SET-02` | Setup phase 1 performs hardening flow and captures local Tailscale IP | `tests/unit/test_setup_workflow_contract.bats`: `setup: phase1 harden marker exists` | Sufficient |
| `SET-03` | Setup Gate A enforces operator verification pause | `tests/unit/test_setup_workflow_contract.bats`: `setup: gate A requires operator laptop verification` | Sufficient |
| `SET-04` | Setup Gate B fails when admin home/`.ssh` state is invalid | `tests/unit/test_setup_workflow_contract.bats`: `setup: gate B verifies admin user home and ssh directory` | Sufficient |
| `SET-05` | Setup Gate C invokes `base/validate.sh --json` and reports result | `tests/unit/test_setup_workflow_contract.bats`: `setup: gate C runs base/validate.sh json` | Sufficient |
| `SET-06` | Setup Gate D fails if docker-user hardening service/rules are invalid | `tests/unit/test_setup_workflow_contract.bats`: `setup: gate D validates service active and managed rules` | Sufficient |
| `SET-07` | Setup phase 4 performs DNS updates for standard mode | `tests/unit/test_setup_workflow_contract.bats`: `setup: phase4 binding+dns marker exists` | Sufficient |
| `SET-08` | Setup Gate E enforces operator verification pause | `tests/unit/test_setup_workflow_contract.bats`: `setup: gate E requires operator laptop verification` | Sufficient |
| `SET-09` | Setup final validation is executed after verification gates | `tests/unit/test_setup_workflow_contract.bats`: `setup: final validation is executed` | Sufficient |

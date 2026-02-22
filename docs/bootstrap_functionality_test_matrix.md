# Bootstrap Functionality Test Matrix

This matrix itemizes the hardening script behavior and maps each item to explicit tests.

## Contract Step Map

These IDs are the canonical hardening workflow contract IDs used by `docs/workflow_contract.yaml`.

| Contract ID | Step |
| --- | --- |
| `HB-01` | Preflight + dependency checks |
| `HB-02` | Time sync verification |
| `HB-03` | Swap configuration |
| `HB-04` | Service cleanup |
| `HB-05` | Login banner |
| `HB-06` | Admin account + SSH hardening |
| `HB-07` | Auditd baseline |
| `HB-08` | Sysctl hardening |
| `HB-09` | UFW baseline |
| `HB-10` | Docker daemon defaults |
| `HB-11` | DOCKER-USER hardening |
| `HB-12` | Fail2ban policy |
| `HB-13` | Journald persistence |
| `HB-14` | Unattended-upgrades policy |
| `HB-15` | Post-apply checks + state/report |

| Script behavior item | Coverage tests | Sufficiency |
| --- | --- | --- |
| Show CLI help (`usage`) | `tests/unit/test_functions.bats`: `usage: prints required and optional flag sections`; `usage: outputs help text with required options` | Sufficient |
| Parse truthy flags (`is_true`) | `tests/unit/test_functions.bats`: `is_true: ...` cases | Sufficient |
| Enforce required option values (`require_value`) | `tests/unit/test_functions.bats`: `require_value: ...` cases | Sufficient |
| Parse CLI/env-file flags (`parse_args`) | `tests/unit/test_functions.bats`: `parse_args: ...` suite (admin user, env-file, overrides, unknown flag, swap-size, tunnel/dry-run/force) | Sufficient |
| Validate SSH public key format (`validate_pubkey`) | `tests/unit/test_functions.bats`: `validate_pubkey: ...` cases | Sufficient |
| Validate inputs (admin user/port/reboot/retention/swap) (`validate_inputs`) | `tests/unit/test_functions.bats`: `validate_inputs: ...` suite including swap-size variants | Sufficient |
| Require root privileges (`require_root`) | `tests/integration/test_dry_run.bats`: `dry-run: rejects non-root execution` | Sufficient |
| Dry-run command wrapper (`run`) | `tests/unit/test_functions.bats`: `script_run: dry-run logs command and skips execution`; `script_run: executes command when dry-run is disabled`; `run: ...` | Sufficient |
| Managed file writer (`write_file`) | `tests/unit/test_functions.bats`: `write_file: ...`; `tests/integration/test_dry_run.bats`: no files created; `tests/integration/test_full_run.bats`: managed files exist | Sufficient |
| Logging setup (`setup_logging`) | `tests/unit/test_functions.bats`: `setup_logging: dry-run does not touch log file` | Sufficient |
| OS guard (`detect_os`) | `tests/unit/test_functions.bats`: `detect_os: ...` checks; all integration suites execute on Ubuntu test image | Sufficient |
| WAN interface detection (`detect_wan_iface`) | `tests/unit/test_functions.bats`: explicit-iface + auto-detect failure tests | Sufficient |
| SSH session safety gate (`ssh_session_safety_gate`) | `tests/unit/test_functions.bats`: no-SSH, Tailscale allow, non-Tailscale block, force override | Sufficient |
| Package ensure/install (`ensure_packages`) | `tests/unit/test_functions.bats`: `ensure_packages: skips apt-get when all packages are installed`; `ensure_packages: installs only missing packages via apt-get` | Sufficient |
| Required command presence (`require_commands`) | `tests/unit/test_functions.bats`: dry-run base command set + missing command failure | Sufficient |
| Tailscale interface verification (`verify_tailscale_iface`) | `tests/integration/test_dry_run.bats`: `dry-run: fails when tailscale0 interface is missing`; `tests/unit/test_tailscale.bats` | Sufficient |
| Time synchronization (`ensure_timesync`) | `tests/integration/test_full_run.bats`: `timesync: NTP is active when supported by container runtime` | Sufficient |
| Swap configuration (`configure_swap`) | `tests/integration/test_full_run.bats`: `swap: ...` tests (active, /swapfile perms, fstab entry, swappiness, state) | Sufficient |
| Disable/mask unused services and sockets (`disable_unused_services`) | `tests/integration/test_full_run.bats`: `services: rpcbind ...`; `services: avahi-daemon ...`; `services: avahi-daemon.socket ...`; `services: cups ...` | Sufficient |
| Admin account/key provisioning (`ensure_admin_access`) | `tests/integration/test_full_run.bats`: `admin: ...` tests (user, groups, shell, home, key content/perms); `tests/unit/test_admin.bats` | Sufficient |
| SSH hardening config and effective policy (`configure_ssh`) | `tests/unit/test_functions.bats`: `assert_sshd_effective`, `assert_sshd_match_localhost`, `restore_ssh_dropin`; `tests/integration/test_full_run.bats`: `ssh: ...` suite | Sufficient |
| UFW baseline and tunnel-mode behavior (`configure_ufw`) | `tests/integration/test_full_run.bats`: `ufw: ...`; `tests/integration/test_full_tunnel.bats`: tunnel-specific WAN deny checks | Sufficient |
| Sysctl hardening (`configure_sysctl`) | `tests/integration/test_full_run.bats`: `sysctl: ...` suite (syncookies, ip_forward, syn backlog, retries, BBR/qdisc, drop-in) | Sufficient |
| Fail2ban policy (`configure_fail2ban`) | `tests/integration/test_full_run.bats`: `fail2ban: ...` tests | Sufficient |
| DOCKER-USER assets + service wiring (`install_docker_user_assets`, `configure_docker_user`) | `tests/integration/test_full_run.bats`: iptables managed rule tests + `docker-user: service is enabled`; `tests/integration/test_full_tunnel.bats`: no `wan-web` in tunnel mode | Sufficient |
| Docker daemon defaults (`configure_docker_daemon`) | `tests/integration/test_full_run.bats`: `docker-daemon: ...` tests | Sufficient |
| Journald persistence (`configure_journald`) | `tests/integration/test_full_run.bats`: `journald: drop-in has Storage=persistent` | Sufficient |
| Audit rules generation and load (`build_audit_rules`, `configure_auditd`) | `tests/unit/test_functions.bats`: `build_audit_rules: ...`; `tests/integration/test_full_run.bats`: `audit: ...` tests | Sufficient |
| Unattended-upgrades config (`configure_unattended_upgrades`) | `tests/integration/test_full_run.bats`: default policy checks; `tests/unit/test_functions.bats`: `configure_unattended_upgrades: writes disabled reboot policy when requested` | Sufficient |
| Login banner (`configure_banner`) | `tests/integration/test_full_run.bats`: `banner: /etc/issue.net contains AUTHORIZED` | Sufficient |
| Post-apply verification gate (`run_post_checks`) | Covered by successful completion in `tests/integration/test_full_run.bats`, `tests/integration/test_full_tunnel.bats`, `tests/integration/test_idempotency.bats` | Sufficient |
| Persisted state artifact (`write_state`) | `tests/integration/test_full_run.bats`: `state: ...`; `tests/integration/test_full_tunnel.bats`: `tunnel_mode=true`; `tests/unit/test_dashboard_binding.bats` (dashboard binding fields) | Sufficient |
| JSON report artifact (`generate_report`) | `tests/integration/test_full_run.bats`: `state: JSON report written`; `report: JSON includes new check fields`; `tests/integration/test_full_tunnel.bats`: tunnel flag in JSON | Sufficient |
| Idempotent re-run behavior (`main` rerun safety) | `tests/integration/test_idempotency.bats`: `idempotency: repeated run keeps single managed entries and healthy state` | Sufficient |
| Tailscale install (`install_tailscale`) | `tests/unit/test_tailscale.bats`: skips if already installed; dry-run mode; auth-key flow; interactive timeout | Sufficient |
| Tailscale IP lookup (`get_tailscale_ip`) | `tests/unit/test_tailscale.bats`: returns cached IP; `tests/unit/test_dashboard_binding.bats`: fails cleanly when tailscale absent | Sufficient |
| Docker presence detection (`detect_docker`) | Implicit in `tests/integration/test_full_run.bats`: `docker-daemon: ...` tests and `docker-user: service is enabled` — Docker presence determines whether DOCKER-USER service starts | Sufficient |
| Coolify binding to Tailscale IP (`configure_coolify_binding`) | `tests/unit/test_dashboard_binding.bats`: skip when flag false; dry-run mode; APP_PORT binding; SOKETI_PORT binding; fails without Tailscale IP | Sufficient |
| Coolify binding watchdog timer (`configure_coolify_binding_watchdog`) | `tests/unit/test_validate_functions.bats`: `coolify_binding_check verifies binding-guard timer is active` — validates timer unit written and enabled | Sufficient |
| Validator baseline pass output (`validate_hardening.sh`) | `tests/integration/test_validate_script.bats`: `validate: exits 0 after hardening bootstrap`; `validate: JSON output includes expected top-level fields` | Sufficient |
| Validator failure detection paths (`validate_hardening.sh`) | `tests/integration/test_validate_script.bats`: failure on missing banner + failure on non-persistent journald | Sufficient |
| Docker user service wiring check (`docker_user_lifecycle_check`) | `tests/unit/test_validate_functions.bats`: `PartOf=docker.service`; `WantedBy=docker.service` | Sufficient |
| Unattended-upgrades Docker CE origin check (`unattended_upgrades_check`) | `tests/unit/test_validate_functions.bats`: Docker CE origin present in upgrades config | Sufficient |
| Coolify binding guard timer check (`coolify_binding_check`) | `tests/unit/test_validate_functions.bats`: binding-guard timer active | Sufficient |
| Deploy orchestrator input validation (`deploy.sh` `validate_inputs`, `parse_args`) | `tests/integration/test_deploy.bats`: IP regex validation; username validation; domain validation; swap size validation; Tailscale key format; mode validation; argument parsing | Sufficient |
| Deploy orchestrator Cloudflare API interaction (`deploy.sh` `cf_*` functions) | `tests/integration/test_deploy.bats`: token verification; zone lookup; tunnel creation; record upsert idempotency | Sufficient |
| Deploy orchestrator gate logic (`deploy.sh` gate A-E) | `tests/integration/test_deploy.bats`: verify_docker_user_gate_remote mock tests; phase/gate label consistency | Sufficient |

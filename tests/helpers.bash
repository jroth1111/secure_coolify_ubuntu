# Common BATS helpers — loaded by all test files

# Derive PROJECT_ROOT from this helpers file's own location (tests/helpers.bash → project root)
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SCRIPT="${PROJECT_ROOT}/bootstrap_hardening.sh"
VALIDATE_SCRIPT="${PROJECT_ROOT}/validate_hardening.sh"
DEPLOY_SCRIPT="${PROJECT_ROOT}/deploy.sh"
SETUP_SCRIPT="${PROJECT_ROOT}/setup.sh"

# Load bats-support and bats-assert from the first available location
_helpers_loaded=false

# 1. Local project checkout (tests/lib/ — installed by `make setup-bats`)
if [[ -f "${PROJECT_ROOT}/tests/lib/bats-support/load.bash" ]]; then
  load "${PROJECT_ROOT}/tests/lib/bats-support/load"
  load "${PROJECT_ROOT}/tests/lib/bats-assert/load"
  _helpers_loaded=true
fi

# 2. Docker container path (Dockerfile.test installs here)
if ! $_helpers_loaded && [[ -f "/opt/bats-support/load.bash" ]]; then
  load '/opt/bats-support/load'
  load '/opt/bats-assert/load'
  _helpers_loaded=true
fi

# 3. Linux package-manager path
if ! $_helpers_loaded && [[ -f "/usr/lib/bats-support/load.bash" ]]; then
  load '/usr/lib/bats-support/load'
  load '/usr/lib/bats-assert/load'
  _helpers_loaded=true
fi

# 4. macOS Homebrew path
if ! $_helpers_loaded && [[ -f "/usr/local/lib/bats-support/load.bash" ]]; then
  load '/usr/local/lib/bats-support/load'
  load '/usr/local/lib/bats-assert/load'
  _helpers_loaded=true
fi

# 5. Fallback: rely on BATS_LIB_PATH / npm
if ! $_helpers_loaded; then
  load 'bats-support'
  load 'bats-assert'
fi

unset _helpers_loaded

# Source the script to import functions.
# Guards against:
#   1. set -Eeuo pipefail and ERR trap leaking into the BATS process
#   2. The script's run() function shadowing BATS's run builtin
source_script() {
  # Save BATS's run function before it gets overwritten
  eval "$(declare -f run | sed '1s/^run /bats_run /')" 2>/dev/null || true

  local _old_opts
  _old_opts="$(set +o)"          # capture current shell options as restore commands
  local _old_traps
  _old_traps="$(trap -p ERR)"    # capture current ERR trap (if any)

  source "${SCRIPT}"

  eval "${_old_opts}"            # restore original shell options
  trap - ERR                     # clear any ERR trap set by the script
  if [[ -n "${_old_traps}" ]]; then
    eval "${_old_traps}"         # restore original ERR trap if there was one
  fi

  # Rename the script's run() → script_run(), restore BATS's run
  if declare -f run >/dev/null 2>&1; then
    eval "$(declare -f run | sed '1s/^run /script_run /')"
  fi
  eval "$(declare -f bats_run | sed '1s/^bats_run /run /')"
}

# Source deploy.sh to import functions for unit testing.
# Same guards as source_script() above.
source_deploy_script() {
  # Save BATS's run function before it gets overwritten
  eval "$(declare -f run | sed '1s/^run /bats_run /')" 2>/dev/null || true

  local _old_opts
  _old_opts="$(set +o)"
  local _old_traps
  _old_traps="$(trap -p ERR)"

  source "${DEPLOY_SCRIPT}"

  eval "${_old_opts}"
  trap - ERR
  if [[ -n "${_old_traps}" ]]; then
    eval "${_old_traps}"
  fi

  # Rename the script's run() → deploy_run(), restore BATS's run
  if declare -f run >/dev/null 2>&1; then
    eval "$(declare -f run | sed '1s/^run /deploy_run /')"
  fi
  eval "$(declare -f bats_run | sed '1s/^bats_run /run /')"
}

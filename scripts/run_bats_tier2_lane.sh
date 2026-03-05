#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

wait_for_docker() {
  local retries="${DOCKER_WAIT_RETRIES:-90}"
  local delay="${DOCKER_WAIT_DELAY:-2}"
  local i
  for ((i = 1; i <= retries; i++)); do
    if docker info >/dev/null 2>&1; then
      return 0
    fi
    sleep "${delay}"
  done
  printf 'ERROR: Docker daemon not reachable after %s attempts\n' "${retries}" >&2
  return 1
}

docker_retry() {
  local attempts="${DOCKER_CMD_RETRIES:-5}"
  local delay="${DOCKER_CMD_RETRY_DELAY:-2}"
  local i rc
  for ((i = 1; i <= attempts; i++)); do
    if docker "$@"; then
      return 0
    fi
    rc=$?
    if ((i < attempts)); then
      sleep "${delay}"
    fi
  done
  return "${rc:-1}"
}

usage() {
  cat <<'USAGE'
Usage: run_bats_tier2_lane.sh --image <image> --lane <lane> --target <bats_target> [options]

Options:
  --workspace <path>        Container workspace mount path (default: /workspace)
  --artifacts-dir <path>    Host artifacts dir (default: artifacts)
  --container-prefix <name> Container name prefix (default: ht)
  -h, --help                Show this help
USAGE
}

IMAGE=""
LANE=""
TARGET=""
WORKSPACE="/workspace"
ARTIFACTS_DIR="artifacts"
CONTAINER_PREFIX="ht"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image)
      IMAGE="${2:?--image requires a value}"
      shift 2
      ;;
    --lane)
      LANE="${2:?--lane requires a value}"
      shift 2
      ;;
    --target)
      TARGET="${2:?--target requires a value}"
      shift 2
      ;;
    --workspace)
      WORKSPACE="${2:?--workspace requires a value}"
      shift 2
      ;;
    --artifacts-dir)
      ARTIFACTS_DIR="${2:?--artifacts-dir requires a value}"
      shift 2
      ;;
    --container-prefix)
      CONTAINER_PREFIX="${2:?--container-prefix requires a value}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'ERROR: unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ -n "${IMAGE}" ]] || { printf 'ERROR: --image is required\n' >&2; exit 2; }
[[ -n "${LANE}" ]] || { printf 'ERROR: --lane is required\n' >&2; exit 2; }
[[ -n "${TARGET}" ]] || { printf 'ERROR: --target is required\n' >&2; exit 2; }

cd "${REPO_ROOT}"
LANE_DIR="${ARTIFACTS_DIR}/${LANE}"
LOG_FILE="${LANE_DIR}/default.log"
REPORT_FILE="${LANE_DIR}/default-bootstrap-report.json"
VALIDATE_FILE="${LANE_DIR}/default-validate.json"
META_FILE="${LANE_DIR}/metadata.json"

rm -rf "${LANE_DIR}"
mkdir -p "${LANE_DIR}"

name="${CONTAINER_PREFIX}-${LANE}-${RANDOM}"
start_ts="$(date +%s)"

cleanup() {
  docker_retry rm -f "${name}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for_docker
docker_retry run -d --name "${name}" --privileged \
  --tmpfs /tmp --tmpfs /run \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  -v "${REPO_ROOT}:${WORKSPACE}" "${IMAGE}" >/dev/null
sleep 3

if docker_retry exec "${name}" bats "${TARGET}" >"${LOG_FILE}" 2>&1; then
  rc=0
else
  rc=$?
fi

docker_retry exec "${name}" test -f /var/log/bootstrap-hardening-report.json \
  && docker_retry exec "${name}" cat /var/log/bootstrap-hardening-report.json >"${REPORT_FILE}" || true

docker_retry exec "${name}" bash -lc '/workspace/validate_hardening.sh --json' >"${VALIDATE_FILE}" 2>/dev/null || true

end_ts="$(date +%s)"
tests_passed="$(grep -cE '^ok[[:space:]]+[0-9]+' "${LOG_FILE}" 2>/dev/null || true)"
tests_failed="$(grep -cE '^not ok[[:space:]]+[0-9]+' "${LOG_FILE}" 2>/dev/null || true)"
tests_passed="${tests_passed:-0}"
tests_failed="${tests_failed:-0}"

duration="$(( end_ts - start_ts ))"
status="pass"
if [[ "${rc}" -ne 0 || "${tests_failed}" -gt 0 ]]; then
  status="fail"
fi

python3 - "$META_FILE" "$LANE" "$status" "$duration" "$tests_passed" "$tests_failed" "$LOG_FILE" "$REPORT_FILE" "$VALIDATE_FILE" "$rc" <<'PY'
import json
import sys
from pathlib import Path

meta_file = Path(sys.argv[1])
lane = sys.argv[2]
status = sys.argv[3]
duration = int(sys.argv[4])
passed = int(sys.argv[5])
failed = int(sys.argv[6])
log_file = Path(sys.argv[7])
report_file = Path(sys.argv[8])
validate_file = Path(sys.argv[9])
exit_code = int(sys.argv[10])

artifact_paths = [log_file.as_posix()]
if report_file.is_file():
    artifact_paths.append(report_file.as_posix())
if validate_file.is_file():
    artifact_paths.append(validate_file.as_posix())

payload = {
    "lane": lane,
    "status": status,
    "duration_seconds": duration,
    "tests_passed": passed,
    "tests_failed": failed,
    "exit_code": exit_code,
    "scenario_count": 1,
    "scenarios": [
        {
            "scenario_id": None,
            "status": status,
            "duration_seconds": duration,
            "tests_passed": passed,
            "tests_failed": failed,
            "exit_code": exit_code,
            "artifact_paths": artifact_paths,
        }
    ],
}
meta_file.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

cat "${LOG_FILE}"
exit "${rc}"

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
Usage: run_docker_lane_cmd.sh --image <image> --lane <lane> --cmd <bash_command> [options]

Options:
  --workspace <path>        Container workspace mount path (default: /workspace)
  --artifacts-dir <path>    Host artifacts dir (default: artifacts)
  --docker-arg <arg>        Extra docker run argument (repeatable)
  -h, --help                Show this help
USAGE
}

IMAGE=""
LANE=""
RUN_CMD=""
WORKSPACE="/workspace"
ARTIFACTS_DIR="artifacts"
declare -a DOCKER_ARGS=()

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
    --cmd)
      RUN_CMD="${2:?--cmd requires a value}"
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
    --docker-arg)
      DOCKER_ARGS+=("${2:?--docker-arg requires a value}")
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
[[ -n "${RUN_CMD}" ]] || { printf 'ERROR: --cmd is required\n' >&2; exit 2; }

cd "${REPO_ROOT}"
LANE_DIR="${ARTIFACTS_DIR}/${LANE}"
LOG_FILE="${LANE_DIR}/default.log"
META_FILE="${LANE_DIR}/metadata.json"

rm -rf "${LANE_DIR}"
mkdir -p "${LANE_DIR}"

wait_for_docker
start_ts="$(date +%s)"
if docker_retry run --rm "${DOCKER_ARGS[@]}" -v "${REPO_ROOT}:${WORKSPACE}" "${IMAGE}" \
  bash -lc "cd ${WORKSPACE} && ${RUN_CMD}" >"${LOG_FILE}" 2>&1; then
  rc=0
else
  rc=$?
fi
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

python3 - "$META_FILE" "$LANE" "$status" "$duration" "$tests_passed" "$tests_failed" "$LOG_FILE" "$rc" <<'PY'
import json
import sys
from pathlib import Path

meta_file = Path(sys.argv[1])
lane = sys.argv[2]
status = sys.argv[3]
duration = int(sys.argv[4])
passed = int(sys.argv[5])
failed = int(sys.argv[6])
log_path = Path(sys.argv[7]).as_posix()
exit_code = int(sys.argv[8])

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
            "artifact_paths": [log_path],
        }
    ],
}
meta_file.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

cat "${LOG_FILE}"
exit "${rc}"

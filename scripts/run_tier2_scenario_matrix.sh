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
Usage: run_tier2_scenario_matrix.sh --image <image> --lane <lane> --file <bats_file> [options]

Options:
  --workspace <path>        Container workspace mount path (default: /workspace)
  --artifacts-dir <path>    Host artifacts dir (default: artifacts)
  --container-prefix <name> Container name prefix (default: ht)
  --scenario-regex <regex>  Only run scenario titles matching regex
  -h, --help                Show this help
USAGE
}

IMAGE=""
LANE=""
BATS_FILE=""
WORKSPACE="/workspace"
ARTIFACTS_DIR="artifacts"
CONTAINER_PREFIX="ht"
SCENARIO_REGEX=""

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
    --file)
      BATS_FILE="${2:?--file requires a value}"
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
    --scenario-regex)
      SCENARIO_REGEX="${2:?--scenario-regex requires a value}"
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
[[ -n "${BATS_FILE}" ]] || { printf 'ERROR: --file is required\n' >&2; exit 2; }

cd "${REPO_ROOT}"
LANE_DIR="${ARTIFACTS_DIR}/${LANE}"
META_FILE="${LANE_DIR}/metadata.json"
SCENARIO_TSV="${LANE_DIR}/scenario-results.tsv"

rm -rf "${LANE_DIR}"
mkdir -p "${LANE_DIR}"

SCENARIO_REGEX_ENV="${SCENARIO_REGEX}" python3 - "$REPO_ROOT" "$BATS_FILE" > "${LANE_DIR}/scenarios.tsv" <<'PY'
import os
import re
import sys
from pathlib import Path

repo = Path(sys.argv[1])
file_arg = sys.argv[2]
scenario_regex = os.environ.get("SCENARIO_REGEX_ENV", "")

if file_arg.startswith("/workspace/"):
    rel = file_arg.removeprefix("/workspace/")
    bats_file = repo / rel
else:
    bats_file = repo / file_arg

if not bats_file.is_file():
    print(f"ERROR\tBATS file not found: {bats_file}")
    raise SystemExit(2)

content = bats_file.read_text(encoding="utf-8")
pattern = re.compile(r'@test\s+"([^"]+)"\s*\{')

rows = []
for idx, m in enumerate(pattern.finditer(content), start=1):
    title = m.group(1)
    if scenario_regex and re.search(scenario_regex, title) is None:
        continue

    escaped = re.escape(title)
    filter_pat = f"^{escaped}$"

    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    if not slug:
        slug = f"scenario-{idx}"
    slug = slug[:48]
    scenario_id = f"s{idx:02d}-{slug}"

    rows.append((scenario_id, title, filter_pat))

if not rows:
    print("ERROR\tNo matching scenarios found")
    raise SystemExit(2)

for scenario_id, title, filter_pat in rows:
    print(f"{scenario_id}\t{title}\t{filter_pat}")
PY

if grep -q '^ERROR\t' "${LANE_DIR}/scenarios.tsv"; then
  cat "${LANE_DIR}/scenarios.tsv" >&2
  exit 2
fi

lane_start="$(date +%s)"
any_fail=0
: > "${SCENARIO_TSV}"

while IFS=$'\t' read -r scenario_id scenario_title scenario_filter; do
  [[ -n "${scenario_id}" ]] || continue

  scenario_start="$(date +%s)"
  name="${CONTAINER_PREFIX}-${LANE}-${scenario_id}-${RANDOM}"

  log_file="${LANE_DIR}/${scenario_id}.log"
  report_file="${LANE_DIR}/${scenario_id}-bootstrap-report.json"
  validate_file="${LANE_DIR}/${scenario_id}-validate.json"
  : > "${log_file}"

  cleanup() {
    docker_retry rm -f "${name}" >/dev/null 2>&1 || true
  }

  wait_for_docker
  docker_retry run -d --name "${name}" --privileged \
    --tmpfs /tmp --tmpfs /run \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "${REPO_ROOT}:${WORKSPACE}" "${IMAGE}" >/dev/null
  sleep 3

  if docker_retry exec "${name}" bats --filter "${scenario_filter}" "${BATS_FILE}" >"${log_file}" 2>&1; then
    rc=0
  else
    rc=$?
  fi

  docker_retry exec "${name}" test -f /var/log/server-hardening-report.json \
    && docker_retry exec "${name}" cat /var/log/server-hardening-report.json >"${report_file}" || true

  docker_retry exec "${name}" bash -lc '/workspace/base/validate.sh --json' >"${validate_file}" 2>/dev/null || true

  cleanup

  scenario_end="$(date +%s)"
  duration="$(( scenario_end - scenario_start ))"
  tests_passed="$(grep -cE '^ok[[:space:]]+[0-9]+' "${log_file}" 2>/dev/null || true)"
  tests_failed="$(grep -cE '^not ok[[:space:]]+[0-9]+' "${log_file}" 2>/dev/null || true)"
  tests_passed="${tests_passed:-0}"
  tests_failed="${tests_failed:-0}"

  status="pass"
  if [[ "${rc}" -ne 0 || "${tests_failed}" -gt 0 ]]; then
    status="fail"
    any_fail=1
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${scenario_id}" "${status}" "${duration}" "${tests_passed}" "${tests_failed}" "${rc}" \
    "${log_file}" "${report_file}" "${validate_file}" >> "${SCENARIO_TSV}"

  printf '\n=== %s (%s) ===\n' "${scenario_title}" "${scenario_id}"
  if [[ -f "${log_file}" ]]; then
    cat "${log_file}"
  else
    printf 'WARNING: missing scenario log file: %s\n' "${log_file}" >&2
  fi
done < "${LANE_DIR}/scenarios.tsv"

lane_end="$(date +%s)"
lane_duration="$(( lane_end - lane_start ))"
lane_status="pass"
if [[ "${any_fail}" -ne 0 ]]; then
  lane_status="fail"
fi

python3 - "$META_FILE" "$LANE" "$lane_status" "$lane_duration" "$SCENARIO_TSV" <<'PY'
import json
import sys
from pathlib import Path

meta_file = Path(sys.argv[1])
lane = sys.argv[2]
lane_status = sys.argv[3]
lane_duration = int(sys.argv[4])
results_tsv = Path(sys.argv[5])

rows = []
with results_tsv.open("r", encoding="utf-8") as fh:
    for line in fh:
        line = line.rstrip("\n")
        if not line:
            continue
        scenario_id, status, duration, passed, failed, exit_code, log_path, report_path, validate_path = line.split("\t")
        artifact_paths = [log_path]
        if Path(report_path).is_file():
            artifact_paths.append(report_path)
        if Path(validate_path).is_file():
            artifact_paths.append(validate_path)

        rows.append(
            {
                "scenario_id": scenario_id,
                "status": status,
                "duration_seconds": int(duration),
                "tests_passed": int(passed),
                "tests_failed": int(failed),
                "exit_code": int(exit_code),
                "artifact_paths": artifact_paths,
            }
        )

payload = {
    "lane": lane,
    "status": lane_status,
    "duration_seconds": lane_duration,
    "tests_passed": sum(r["tests_passed"] for r in rows),
    "tests_failed": sum(r["tests_failed"] for r in rows),
    "exit_code": 0 if lane_status == "pass" else 1,
    "scenario_count": len(rows),
    "scenarios": rows,
}
meta_file.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

if [[ "${any_fail}" -ne 0 ]]; then
  exit 1
fi

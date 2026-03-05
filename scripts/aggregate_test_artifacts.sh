#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ARTIFACTS_DIR="${1:-${ARTIFACTS_DIR:-${REPO_ROOT}/artifacts}}"
SUMMARY_FILE="${ARTIFACTS_DIR}/test-summary.json"

mkdir -p "${ARTIFACTS_DIR}"

python3 - "${ARTIFACTS_DIR}" "${SUMMARY_FILE}" <<'PY'
import json
import sys
from collections import defaultdict
from pathlib import Path

artifacts_dir = Path(sys.argv[1])
summary_file = Path(sys.argv[2])

required_meta_keys = {
    "lane",
    "status",
    "duration_seconds",
    "tests_passed",
    "tests_failed",
    "exit_code",
    "scenario_count",
    "scenarios",
}
required_scenario_keys = {
    "scenario_id",
    "status",
    "duration_seconds",
    "tests_passed",
    "tests_failed",
    "exit_code",
    "artifact_paths",
}

rows = []
lane_statuses: dict[str, list[str]] = defaultdict(list)
meta_files = sorted(artifacts_dir.glob("*/metadata.json"))

if not meta_files:
    payload = {
        "lanes": [],
        "total_lanes": 0,
        "total_scenarios": 0,
        "failed_lanes": 1,
        "errors": [f"No lane metadata files found under {artifacts_dir}"],
    }
    summary_file.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote artifact summary: {summary_file}")
    print("  lanes=0 failed=1")
    raise SystemExit(1)

for meta_path in meta_files:
    lane_dir = meta_path.parent
    lane_name = lane_dir.name

    try:
      meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception as exc:
      rows.append(
          {
              "lane": lane_name,
              "scenario_id": None,
              "status": "fail",
              "duration_seconds": None,
              "tests_passed": 0,
              "tests_failed": 0,
              "artifact_paths": [meta_path.as_posix()],
              "error": f"invalid metadata JSON: {exc}",
          }
      )
      lane_statuses[lane_name].append("fail")
      continue

    missing = sorted(required_meta_keys - set(meta.keys()))
    if missing:
      rows.append(
          {
              "lane": lane_name,
              "scenario_id": None,
              "status": "fail",
              "duration_seconds": None,
              "tests_passed": 0,
              "tests_failed": 0,
              "artifact_paths": [meta_path.as_posix()],
              "error": f"metadata missing keys: {', '.join(missing)}",
          }
      )
      lane_statuses[lane_name].append("fail")
      continue

    scenarios = meta.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
      rows.append(
          {
              "lane": lane_name,
              "scenario_id": None,
              "status": "fail",
              "duration_seconds": None,
              "tests_passed": 0,
              "tests_failed": 0,
              "artifact_paths": [meta_path.as_posix()],
              "error": "metadata scenarios must be a non-empty list",
          }
      )
      lane_statuses[lane_name].append("fail")
      continue

    for scenario in scenarios:
      if not isinstance(scenario, dict):
          rows.append(
              {
                  "lane": lane_name,
                  "scenario_id": None,
                  "status": "fail",
                  "duration_seconds": None,
                  "tests_passed": 0,
                  "tests_failed": 0,
                  "artifact_paths": [meta_path.as_posix()],
                  "error": "scenario entry is not an object",
              }
          )
          lane_statuses[lane_name].append("fail")
          continue

      missing_scenario = sorted(required_scenario_keys - set(scenario.keys()))
      if missing_scenario:
          rows.append(
              {
                  "lane": lane_name,
                  "scenario_id": scenario.get("scenario_id"),
                  "status": "fail",
                  "duration_seconds": None,
                  "tests_passed": 0,
                  "tests_failed": 0,
                  "artifact_paths": [meta_path.as_posix()],
                  "error": f"scenario missing keys: {', '.join(missing_scenario)}",
              }
          )
          lane_statuses[lane_name].append("fail")
          continue

      scenario_status = str(scenario.get("status", "fail"))
      lane_statuses[lane_name].append(scenario_status)

      rows.append(
          {
              "lane": lane_name,
              "scenario_id": scenario.get("scenario_id"),
              "status": scenario_status,
              "duration_seconds": scenario.get("duration_seconds"),
              "tests_passed": scenario.get("tests_passed"),
              "tests_failed": scenario.get("tests_failed"),
              "artifact_paths": scenario.get("artifact_paths", []),
          }
      )

failed_lanes = sum(1 for _lane, statuses in lane_statuses.items() if any(status != "pass" for status in statuses))

summary = {
    "lanes": rows,
    "total_lanes": len(lane_statuses),
    "total_scenarios": len(rows),
    "failed_lanes": failed_lanes,
}
summary_file.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"Wrote artifact summary: {summary_file}")
print(f"  lanes={summary['total_lanes']} failed={summary['failed_lanes']}")
PY

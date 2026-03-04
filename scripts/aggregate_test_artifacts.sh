#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ARTIFACTS_DIR="${REPO_ROOT}/artifacts"
SUMMARY_FILE="${ARTIFACTS_DIR}/test-summary.json"

mkdir -p "${ARTIFACTS_DIR}"

python3 - "${ARTIFACTS_DIR}" "${SUMMARY_FILE}" <<'PY'
import json
import re
import sys
from pathlib import Path

artifacts_dir = Path(sys.argv[1])
summary_file = Path(sys.argv[2])

rows = []
for log_path in sorted(artifacts_dir.glob("*.log")):
    text = log_path.read_text(encoding="utf-8", errors="replace")
    passed = len(re.findall(r"^ok\s+\d+", text, flags=re.MULTILINE))
    failed = len(re.findall(r"^not ok\s+\d+", text, flags=re.MULTILINE))

    status = "pass"
    if failed > 0:
        status = "fail"
    elif passed == 0 and re.search(r"(^make: \*\*\*|^ERROR:|Traceback \(most recent call last\):|shellcheck:)", text, flags=re.MULTILINE):
        status = "fail"

    lane = log_path.stem
    row = {
        "lane": lane,
        "status": status,
        "duration_seconds": None,
        "tests_passed": passed,
        "tests_failed": failed,
        "scenario_id": None,
        "artifact_paths": [str(log_path.relative_to(artifacts_dir))],
    }

    for suffix in ("-validate.json", "-bootstrap-report.json"):
        maybe = artifacts_dir / f"{lane}{suffix}"
        if maybe.is_file():
            row["artifact_paths"].append(str(maybe.relative_to(artifacts_dir)))

    rows.append(row)

summary = {
    "lanes": rows,
    "total_lanes": len(rows),
    "failed_lanes": sum(1 for row in rows if row["status"] != "pass"),
}
summary_file.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"Wrote artifact summary: {summary_file}")
print(f"  lanes={summary['total_lanes']} failed={summary['failed_lanes']}")
PY

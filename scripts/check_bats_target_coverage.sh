#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MAKEFILE_PATH="${REPO_ROOT}/Makefile"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

[[ -f "${MAKEFILE_PATH}" ]] || die "Makefile not found at ${MAKEFILE_PATH}"

python3 - "${REPO_ROOT}" "${MAKEFILE_PATH}" <<'PY'
import re
import sys
from pathlib import Path

repo = Path(sys.argv[1])
makefile_path = Path(sys.argv[2])
make_txt = makefile_path.read_text(encoding="utf-8")

errors: list[str] = []

unit_files = sorted((repo / "tests").rglob("*.bats"))
integration_files = sorted((repo / "tests" / "base" / "integration").glob("*.bats"))

# Unit coverage: Makefile should reference test directories.
has_unit_target = any(p in make_txt for p in [
    "/workspace/tests/base/unit/",
    "/workspace/tests/overlays/coolify/unit/",
    "/workspace/tests/orchestrator/unit/",
])
if not has_unit_target:
    errors.append("Makefile does not reference /workspace/tests/*/unit/ (unit suite targets missing)")

integration_refs = set(
    re.findall(r"/workspace/tests/base/integration/([A-Za-z0-9._-]+\.bats)", make_txt)
)

missing_integration = []
for path in integration_files:
    if path.name not in integration_refs:
        missing_integration.append(path.name)

for name in missing_integration:
    errors.append(f"integration test file not covered by any Make target: tests/base/integration/{name}")

missing_files = []
for name in sorted(integration_refs):
    if not (repo / "tests" / "base" / "integration" / name).is_file():
        missing_files.append(name)
for name in missing_files:
    errors.append(f"Makefile references missing integration test file: tests/base/integration/{name}")

if unit_files and not has_unit_target:
    errors.append(f"unit test files present but no unit dir target found ({len(unit_files)} files)")

if errors:
    print("BATS target coverage check failed:")
    for err in errors:
        print(f"  - {err}")
    raise SystemExit(1)

print("BATS target coverage check passed.")
print(f"  total test files: {len(unit_files)}")
print(f"  integration files: {len(integration_files)}")
print(f"  integration references in Makefile: {len(integration_refs)}")
PY

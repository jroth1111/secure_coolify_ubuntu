#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONTRACT_FILE="${REPO_ROOT}/docs/logic_step_contract.yaml"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

[[ -f "${CONTRACT_FILE}" ]] || die "Contract file not found: ${CONTRACT_FILE}"

python3 - "${REPO_ROOT}" "${CONTRACT_FILE}" <<'PY'
import re
import sys
from pathlib import Path

try:
    import yaml
except ModuleNotFoundError:
    print("ERROR: python3 package 'yaml' (PyYAML) is required to parse logic_step_contract.yaml", file=sys.stderr)
    raise SystemExit(2)

repo = Path(sys.argv[1])
contract_path = Path(sys.argv[2])

SCRIPT_TARGETS = (
    "bootstrap_hardening.sh",
    "validate_hardening.sh",
    "deploy.sh",
    "setup.sh",
    "lib/coolify-common.sh",
)

REQUIRED_KEYS = {
    "id",
    "script_path",
    "function",
    "criticality",
    "behavior_test",
    "checks",
}

VALID_CRITICALITY = {"security", "orchestration", "utility"}


def strip_heredocs(text: str) -> str:
    """Remove heredoc bodies so regex function extraction ignores script templates."""
    out: list[str] = []
    lines = text.splitlines(keepends=True)
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.search(r"<<-?\s*(?:[\"']?)([A-Za-z_][A-Za-z0-9_]*)(?:[\"']?)", line)
        if not m:
            out.append(line)
            i += 1
            continue

        delim = m.group(1)
        out.append(line)
        i += 1

        while i < len(lines):
            current = lines[i]
            if re.match(rf"^\t*{re.escape(delim)}\s*\n?$", current):
                out.append(current)
                i += 1
                break
            out.append("\n" if current.endswith("\n") else "")
            i += 1
    return "".join(out)


def extract_functions(script_rel: str) -> list[str]:
    script_abs = repo / script_rel
    raw = script_abs.read_text(encoding="utf-8")
    stripped = strip_heredocs(raw)
    names = sorted(
        set(
            m.group(1)
            for m in re.finditer(r"^([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{", stripped, re.M)
        )
    )
    return names


def parse_bats_tests() -> dict[str, dict[str, str]]:
    tests: dict[str, dict[str, str]] = {}
    for suite in (repo / "tests" / "unit", repo / "tests" / "integration"):
        for path in sorted(suite.glob("*.bats")):
            txt = path.read_text(encoding="utf-8")
            rel = path.relative_to(repo).as_posix()
            tests[rel] = {}

            for m in re.finditer(r'@test\s+"([^\"]+)"\s*\{', txt):
                title = m.group(1)
                start = m.end()
                depth = 1
                i = start
                while i < len(txt) and depth > 0:
                    if txt[i] == "{":
                        depth += 1
                    elif txt[i] == "}":
                        depth -= 1
                    i += 1
                body = txt[start : i - 1]
                tests[rel][title] = body
    return tests


def has_assertion(body: str) -> bool:
    if re.search(r"\bassert_(success|failure|output|line|regex|equal|not_equal)\b", body):
        return True
    if re.search(r"(^|\n)\s*\[\[?\s*[^\n]+\s*\]\]?\s*$", body, re.M):
        return True
    return False


def run_command_token(line: str) -> str | None:
    m = re.match(r"^\s*run\s+([A-Za-z_][A-Za-z0-9_]*)\b", line)
    return m.group(1) if m else None


def calls_function(body: str, fn: str, script_path: str) -> bool:
    # bootstrap_hardening.sh defines run(); tests call it as script_run via helpers.
    if script_path == "bootstrap_hardening.sh" and fn == "run":
        return bool(re.search(r"\bscript_run\b", body))

    for raw in body.splitlines():
        if re.match(r"^\s*#", raw):
            continue

        line = raw.split("#", 1)[0]
        if not line.strip():
            continue

        # Ignore local function definitions/stubs inside tests.
        if re.search(rf"^\s*{re.escape(fn)}\s*\(\)\s*\{{", line):
            continue

        token = run_command_token(line)
        if token == fn:
            return True

        # run bash -c '... fn ...' or run env ... bash -c '... fn ...'
        if token in {"bash", "env"} and len(fn) > 4 and re.search(rf"\b{re.escape(fn)}\b", line):
            return True

        # Direct call in shell body.
        if re.search(rf"^\s*(?:if\s+)?{re.escape(fn)}(?:\s|$)", line):
            return True
        if re.search(rf"[|;]\s*{re.escape(fn)}(?:\s|$)", line):
            return True

        # bash -c embedded direct call (for longer names only to avoid noisy matches).
        if len(fn) > 4 and re.search(rf"\bbash\s+-c\b[^\n]*\b{re.escape(fn)}\b", line):
            return True

    return False


def parse_test_ref(ref: str) -> tuple[str, str]:
    if "::" not in ref:
        raise ValueError(f"test reference must be '<file>::<title>' (got: {ref})")
    file_rel, title = ref.split("::", 1)
    file_rel = file_rel.strip()
    title = title.strip()
    if not file_rel or not title:
        raise ValueError(f"invalid test reference (empty file/title): {ref}")
    return file_rel, title


try:
    data = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"ERROR: failed to parse YAML: {exc}", file=sys.stderr)
    raise SystemExit(2)

if not isinstance(data, dict):
    print("ERROR: contract root must be a mapping/object", file=sys.stderr)
    raise SystemExit(2)

version = data.get("version")
if version != 2:
    print(f"ERROR: expected contract version 2, got: {version!r}", file=sys.stderr)
    raise SystemExit(2)

entries = data.get("entries")
if not isinstance(entries, list):
    print("ERROR: 'entries' must be a list", file=sys.stderr)
    raise SystemExit(2)

inventory: dict[str, set[str]] = {script: set(extract_functions(script)) for script in SCRIPT_TARGETS}
tests = parse_bats_tests()

errors: list[str] = []
seen_ids: set[str] = set()
seen_pairs: set[tuple[str, str]] = set()
mapped: dict[str, set[str]] = {script: set() for script in SCRIPT_TARGETS}

for idx, entry in enumerate(entries, start=1):
    if not isinstance(entry, dict):
        errors.append(f"entry #{idx} must be an object/mapping")
        continue

    missing_keys = sorted(REQUIRED_KEYS - set(entry.keys()))
    if missing_keys:
        errors.append(f"entry #{idx} missing required keys: {', '.join(missing_keys)}")
        continue

    entry_id = str(entry["id"])
    script_path = str(entry["script_path"])
    fn = str(entry["function"])
    criticality = str(entry["criticality"])
    behavior_ref = str(entry["behavior_test"])
    checks = entry["checks"]

    if entry_id in seen_ids:
        errors.append(f"duplicate entry id: {entry_id}")
        continue
    seen_ids.add(entry_id)

    if script_path not in SCRIPT_TARGETS:
        errors.append(f"[{entry_id}] unknown script_path: {script_path}")
        continue

    if criticality not in VALID_CRITICALITY:
        errors.append(
            f"[{entry_id}] criticality must be one of {sorted(VALID_CRITICALITY)} (got: {criticality})"
        )

    if fn not in inventory[script_path]:
        errors.append(f"[{entry_id}] function not found in {script_path}: {fn}")
        continue

    pair = (script_path, fn)
    if pair in seen_pairs:
        errors.append(f"duplicate function mapping: {script_path}:{fn}")
        continue
    seen_pairs.add(pair)
    mapped[script_path].add(fn)

    if not isinstance(checks, list) or not checks:
        errors.append(f"[{entry_id}] checks must be a non-empty list")
        continue

    # Validate behavior test reference and quality.
    try:
        behavior_file, behavior_title = parse_test_ref(behavior_ref)
    except ValueError as exc:
        errors.append(f"[{entry_id}] {exc}")
        continue

    if behavior_file not in tests:
        errors.append(f"[{entry_id}] behavior test file not found: {behavior_file}")
        continue
    if behavior_title not in tests[behavior_file]:
        errors.append(
            f"[{entry_id}] behavior test title not found in {behavior_file}: {behavior_title}"
        )
        continue

    behavior_body = tests[behavior_file][behavior_title]
    if not has_assertion(behavior_body):
        errors.append(
            f"[{entry_id}] behavior test has no outcome assertion: {behavior_file}::{behavior_title}"
        )
    if not calls_function(behavior_body, fn, script_path):
        errors.append(
            f"[{entry_id}] behavior test does not execute {fn}: {behavior_file}::{behavior_title}"
        )

    # Validate check references and quality.
    for check_idx, check_ref in enumerate(checks, start=1):
        if not isinstance(check_ref, str):
            errors.append(f"[{entry_id}] checks[{check_idx}] must be a string reference")
            continue
        try:
            check_file, check_title = parse_test_ref(check_ref)
        except ValueError as exc:
            errors.append(f"[{entry_id}] checks[{check_idx}] {exc}")
            continue

        if check_file not in tests:
            errors.append(f"[{entry_id}] check test file not found: {check_file}")
            continue
        if check_title not in tests[check_file]:
            errors.append(
                f"[{entry_id}] check test title not found in {check_file}: {check_title}"
            )
            continue

        check_body = tests[check_file][check_title]
        if not has_assertion(check_body):
            errors.append(
                f"[{entry_id}] check has no outcome assertion: {check_file}::{check_title}"
            )
        if not calls_function(check_body, fn, script_path):
            errors.append(
                f"[{entry_id}] check does not execute {fn}: {check_file}::{check_title}"
            )

# Inventory completeness.
for script_path in SCRIPT_TARGETS:
    inv = inventory[script_path]
    seen = mapped[script_path]
    missing = sorted(inv - seen)
    extra = sorted(seen - inv)

    if missing:
        errors.append(
            f"{script_path}: missing function mappings ({len(missing)}): {', '.join(missing[:10])}"
            + (" ..." if len(missing) > 10 else "")
        )
    if extra:
        errors.append(
            f"{script_path}: mapped unknown functions ({len(extra)}): {', '.join(extra[:10])}"
            + (" ..." if len(extra) > 10 else "")
        )

if errors:
    print("Logic-step coverage check failed:")
    for err in errors:
        print(f"  - {err}")
    raise SystemExit(1)

entries_count = len(entries)
functions_count = sum(len(v) for v in inventory.values())
print("Logic-step coverage check passed.")
for script_path in SCRIPT_TARGETS:
    print(f"  {script_path}: {len(mapped[script_path])}/{len(inventory[script_path])}")
print(f"  entries={entries_count} functions={functions_count}")
PY

#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

python3 - <<'PY'
import re
from pathlib import Path

SCRIPT_TARGETS = (
    "base/bootstrap.sh",
    "base/validate.sh",
    "deploy.sh",
    "setup.sh",
    "lib/common.sh",
    "lib/tailscale.sh",
    "lib/coolify-common.sh",
)

ALLOWED_TEST_FILES = {
    "base/bootstrap.sh": {
        "tests/unit/test_bootstrap_additional_behavior.bats",
        "tests/unit/test_functions.bats",
        "tests/unit/test_admin.bats",
        "tests/unit/test_tailscale.bats",
        "tests/unit/test_dashboard_binding.bats",
        "tests/integration/test_full_run.bats",
        "tests/integration/test_full_tunnel.bats",
        "tests/integration/test_dry_run.bats",
        "tests/integration/test_validate_script.bats",
        "tests/integration/test_bootstrap_matrix.bats",
    },
    "base/validate.sh": {
        "tests/unit/test_validate_additional_behavior.bats",
        "tests/unit/test_validate_check_outcomes_robust.bats",
        "tests/unit/test_validate_functions.bats",
        "tests/integration/test_validate_script.bats",
        "tests/integration/test_validate_negative_matrix.bats",
        "tests/integration/test_full_run.bats",
    },
    "deploy.sh": {
        "tests/unit/test_deploy_setup_additional_behavior.bats",
        "tests/unit/test_deploy_workflow_contract.bats",
        "tests/integration/test_deploy.bats",
    },
    "setup.sh": {
        "tests/unit/test_setup_workflow_contract.bats",
        "tests/unit/test_deploy_setup_additional_behavior.bats",
    },
    "lib/common.sh": {
        "tests/unit/test_common_additional_behavior.bats",
        "tests/integration/test_deploy.bats",
        "tests/unit/test_deploy_setup_additional_behavior.bats",
        "tests/unit/test_deploy_workflow_contract.bats",
        "tests/unit/test_setup_workflow_contract.bats",
    },
    "lib/tailscale.sh": {
        "tests/unit/test_tailscale.bats",
        "tests/unit/test_bootstrap_additional_behavior.bats",
    },
    "lib/coolify-common.sh": {
        "tests/unit/test_common_additional_behavior.bats",
        "tests/integration/test_deploy.bats",
        "tests/unit/test_deploy_setup_additional_behavior.bats",
        "tests/unit/test_deploy_workflow_contract.bats",
        "tests/unit/test_setup_workflow_contract.bats",
    },
}

SOURCE_PATTERNS = {
    "base/bootstrap.sh": [
        r"\bsource_script\b",
        r"\bsource\b[^\n]*(?:SCRIPT|bootstrap\.sh)",
    ],
    "base/validate.sh": [
        r"\bsource_validate_script\b",
        r"\bsource\b[^\n]*(?:VALIDATE_SCRIPT|validate\.sh)",
    ],
    "deploy.sh": [
        r"\bsource_deploy_script\b",
        r"\bsource\b[^\n]*(?:DEPLOY_SCRIPT|deploy\.sh)",
    ],
    "setup.sh": [
        r"\bsource_setup_script\b",
        r"\bsource\b[^\n]*(?:SETUP_SCRIPT|setup\.sh)",
    ],
    "lib/common.sh": [
        r"\bsource_common_lib\b",
        r"\bsource_deploy_script\b",
        r"\bsource_setup_script\b",
        r"\bsource_script\b",
        r"\bsource\b[^\n]*(?:COMMON_LIB|common\.sh|coolify-common\.sh|DEPLOY_SCRIPT|SETUP_SCRIPT|SCRIPT)",
    ],
    "lib/tailscale.sh": [
        r"\bsource_script\b",
        r"\bsource\b[^\n]*(?:SCRIPT|bootstrap\.sh|tailscale\.sh)",
    ],
    "lib/coolify-common.sh": [
        r"\bsource_common_lib\b",
        r"\bsource_deploy_script\b",
        r"\bsource_setup_script\b",
        r"\bsource_script\b",
        r"\bsource\b[^\n]*(?:COMMON_LIB|coolify-common\.sh|DEPLOY_SCRIPT|SETUP_SCRIPT|SCRIPT)",
    ],
}


def strip_heredocs(text: str) -> str:
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


def extract_functions(path: str) -> list[str]:
    txt = Path(path).read_text(encoding="utf-8")
    txt = strip_heredocs(txt)
    return sorted(
        set(m.group(1) for m in re.finditer(r"^([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{", txt, re.M))
    )


class TestBlock:
    def __init__(self, file: str, title: str, body: str):
        self.file = file
        self.title = title
        self.body = body


def parse_bats_tests() -> tuple[list[TestBlock], dict[str, str]]:
    blocks: list[TestBlock] = []
    file_texts: dict[str, str] = {}
    for suite in (Path("tests/unit"), Path("tests/integration")):
        for path in sorted(suite.glob("*.bats")):
            txt = path.read_text(encoding="utf-8")
            rel = path.as_posix()
            file_texts[rel] = txt

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
                blocks.append(TestBlock(rel, title, body))
    return blocks, file_texts


def file_sources_target(file_text: str, script_path: str) -> bool:
    return any(re.search(pattern, file_text) for pattern in SOURCE_PATTERNS[script_path])


def has_assertion(body: str) -> bool:
    if re.search(r"\bassert_[A-Za-z0-9_]+\b", body):
        return True
    if re.search(r"(^|\n)\s*\[\[?\s*[^\n]+\s*\]\]?\s*$", body, re.M):
        return True
    return False


def run_command_token(line: str) -> str | None:
    m = re.match(r"^\s*run\s+([A-Za-z_][A-Za-z0-9_]*)\b", line)
    return m.group(1) if m else None


def calls_function(body: str, fn: str, script_path: str) -> bool:
    if script_path == "base/bootstrap.sh" and fn == "run":
        return bool(re.search(r"\bscript_run\b", body))

    for raw in body.splitlines():
        if re.match(r"^\s*#", raw):
            continue

        line = raw.split("#", 1)[0]
        if not line.strip():
            continue

        if re.search(rf"^\s*{re.escape(fn)}\s*\(\)\s*\{{", line):
            continue

        token = run_command_token(line)
        if token == fn:
            return True

        if token in {"bash", "env"} and len(fn) > 4 and re.search(rf"\b{re.escape(fn)}\b", line):
            return True

        if re.search(rf"^\s*(?:if\s+)?{re.escape(fn)}(?:\s|$)", line):
            return True
        if re.search(rf"[|;]\s*{re.escape(fn)}(?:\s|$)", line):
            return True

        if len(fn) > 4 and re.search(rf"\bbash\s+-c\b[^\n]*\b{re.escape(fn)}\b", line):
            return True

    return False


all_tests, file_texts = parse_bats_tests()
inventory = {script: extract_functions(script) for script in SCRIPT_TARGETS}

missing: list[tuple[str, str]] = []
covered_total = 0
functions_total = 0

print("Function behavior coverage summary:")
for script in SCRIPT_TARGETS:
    allowed = ALLOWED_TEST_FILES[script]
    functions = inventory[script]
    script_covered = 0

    for fn in functions:
        candidates = [
            t
            for t in all_tests
            if t.file in allowed
            and file_sources_target(file_texts.get(t.file, ""), script)
            and has_assertion(t.body)
            and calls_function(t.body, fn, script)
        ]
        if candidates:
            script_covered += 1
        else:
            missing.append((script, fn))

    covered_total += script_covered
    functions_total += len(functions)
    print(f"  {script}: {script_covered}/{len(functions)}")

print(f"  TOTAL: {covered_total}/{functions_total}")

if missing:
    print("\nMissing behavior coverage for:")
    for script, fn in missing:
        print(f"  {script}:{fn}")
    raise SystemExit(1)
PY

# overlay-loader.sh — resolve overlay depends_on and source overlay files
# Requires: set -Eeuo pipefail in the caller.

overlay_topo_sort() {
  local overlay_id="$1"
  local overlay_dir="${SCRIPT_DIR}/overlays/${overlay_id}"
  local manifest="${overlay_dir}/overlay.yaml"
  [[ -f "${manifest}" ]] || { echo "overlay_topo_sort: ${manifest} not found" >&2; return 1; }

  python3 - "${overlay_dir}" << 'PY'
import sys, os, re

def parse_depends(manifest):
    deps = []
    with open(manifest) as f:
        for line in f:
            m = re.search(r'depends_on:\s*\[([^\]]*)\]', line)
            if m:
                deps = [d.strip().strip('"\'') for d in m.group(1).split(',') if d.strip()]
    return deps

overlay_dir = sys.argv[1]
overlays_root = os.path.dirname(overlay_dir)
overlay_id = os.path.basename(overlay_dir)

visited = set()
order = []

def visit(oid, chain):
    if oid in chain:
        print(f"cycle detected: {' -> '.join(chain)} -> {oid}", file=sys.stderr)
        sys.exit(1)
    if oid in visited:
        return
    visited.add(oid)
    manifest = os.path.join(overlays_root, oid, "overlay.yaml")
    for dep in parse_depends(manifest):
        visit(dep, chain | {oid})
    order.append(oid)

visit(overlay_id, set())
print('\n'.join(order))
PY
}

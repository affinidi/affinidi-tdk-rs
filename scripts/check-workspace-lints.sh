#!/usr/bin/env bash
#
# Fail if a workspace member does not inherit the workspace lints.
#
# WHY THIS EXISTS
#
# The root Cargo.toml sets the lint policy once, in `[workspace.lints]` —
# notably `unsafe_code = "deny"` and the clippy lints CI enforces. A member only
# gets that policy if its own manifest says
#
#   [lints]
#   workspace = true
#
# Without it the member silently opts out: a new `unsafe` block or a lint the
# rest of the workspace rejects goes through unnoticed. Before #1064, 22 of 47
# members (the messaging SDK, the credential crates, the whole OID4VC family)
# had opted out this way by omission.
#
# WHAT IT CHECKS
#
# Every package in `cargo metadata`'s workspace_members has `lints.workspace =
# true` in its manifest (any TOML spelling of it).

set -euo pipefail

echo "=== Workspace lints guard ==="
echo

# NOTE: `python3 -c` (not `python3 -`), so stdin stays free for the pipe.
read -r -d '' CHECK <<'PY' || true
import json, re, sys

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    tomllib = None


def inherits(path):
    text = open(path, encoding="utf-8").read()
    if tomllib is not None:
        lints = tomllib.loads(text).get("lints")
        return isinstance(lints, dict) and lints.get("workspace") is True
    # Fallback for older Pythons: accept the three TOML spellings.
    if re.search(r"^\s*lints\.workspace\s*=\s*true\b", text, re.M):
        return True
    if re.search(r"^\s*lints\s*=\s*\{[^}]*\bworkspace\s*=\s*true\b", text, re.M):
        return True
    m = re.search(r"^\s*\[lints\]\s*$(.*?)(?=^\s*\[|\Z)", text, re.M | re.S)
    return bool(m and re.search(r"^\s*workspace\s*=\s*true\b", m.group(1), re.M))


meta = json.load(sys.stdin)
members = [p for p in meta["packages"] if p["id"] in meta["workspace_members"]]
bad = 0
for pkg in sorted(members, key=lambda p: p["name"]):
    if not inherits(pkg["manifest_path"]):
        print(f"  MISSING {pkg['name']}  ({pkg['manifest_path']})")
        bad += 1
if bad:
    sys.exit(1)
print(f"  ok     all {len(members)} workspace members inherit [workspace.lints]")
PY

if ! cargo metadata --format-version 1 --no-deps | python3 -c "$CHECK"; then
    cat <<'EOF'

Some workspace members do not inherit the workspace lint policy.

Fix: add to each listed Cargo.toml

  [lints]
  workspace = true

If a crate genuinely needs `unsafe`, keep the workspace policy and put a scoped
`#[allow(unsafe_code)]` on the specific item, next to its SAFETY comment.
EOF
    exit 1
fi

#!/usr/bin/env bash
#
# Fail if a workspace member is ALSO resolved from crates.io.
#
# WHY THIS EXISTS
#
# A workspace member that another crate depends on *by version* (rather than by
# path) is only redirected to local source if it is listed in the root
# `[patch.crates-io]`. Miss the entry and cargo silently resolves the published
# copy **alongside** the local one. Two things then go wrong, both quietly:
#
#   1. Local changes to that crate do not take effect in workspace builds. You
#      edit source, rebuild, and nothing happens.
#   2. Two copies of the same types exist, so a value produced by one cannot be
#      passed to the other:
#
#        error[E0308]: expected `affinidi_did_common::Document`,
#                      found a different `affinidi_did_common::Document`
#
#      or, more confusingly, an unsatisfied trait bound naming a type that
#      obviously does implement the trait — because the trait came from the
#      other copy.
#
# External consumers make this worse: a crates.io crate that depends on our
# crates (e.g. `vta-sdk`) drags the registry copies in even when every internal
# reference uses a path.
#
# This has bitten repeatedly, and the symptom never points at the cause:
#   * `did-example`                (PR #629)
#   * `affinidi-messaging-core`    (PR #630) — spent a long time written off as
#                                   an unrelated, unfixable `vta-sdk` failure
#   * `affinidi-vc`, `affinidi-sd-jwt`, `affinidi-oid4vc-core`,
#     `affinidi-openid4vci`, `affinidi-openid4vp`,
#     `affinidi-messaging-delivery` (all found by this script's first run)
#
# WHAT IT CHECKS
#
# The *symptom*, not the cause: any package whose name is a workspace member and
# which also appears in the resolved graph with a registry source. That catches
# both a missing `[patch.crates-io]` entry and a patch entry whose version no
# longer satisfies an external consumer's requirement — the two ways a redirect
# falls through — with no false positives from members nothing depends on.
#
# ALLOWLIST
#
# `scripts/workspace-duplicates-allow.txt` lists duplicates that are known and
# cannot be fixed from this repository, one crate name per line. Keep it short
# and keep the reason in the file; an entry is a debt marker, not a resolution.

set -euo pipefail

ALLOW_FILE="$(dirname "$0")/workspace-duplicates-allow.txt"

echo "=== Workspace duplicate guard ==="
echo

allowed=""
if [[ -f "$ALLOW_FILE" ]]; then
    allowed="$(grep -vE '^\s*(#|$)' "$ALLOW_FILE" || true)"
fi

# cargo metadata resolves the full graph; a workspace member has a null source,
# so a non-null source for a member's name means a second, registry-sourced copy.
# NOTE: `python3 -c` (not `python3 -`), so stdin stays free for the pipe.
read -r -d '' EXTRACT <<'PY' || true
import json, sys

meta = json.load(sys.stdin)
members = {p["name"] for p in meta["packages"] if p["id"] in meta["workspace_members"]}
for pkg in sorted(meta["packages"], key=lambda p: (p["name"], p["version"])):
    if pkg["name"] in members and pkg.get("source"):
        print(pkg["name"], pkg["version"], sep="\t")
PY

duplicates="$(cargo metadata --format-version 1 | python3 -c "$EXTRACT")"

status=0
unexpected=""

while IFS=$'\t' read -r name version; do
    [[ -z "$name" ]] && continue
    if grep -qxF "$name" <<<"$allowed" 2>/dev/null; then
        echo "  allow  $name $version (known, see $(basename "$ALLOW_FILE"))"
    else
        echo "  DUP    $name $version is resolved from crates.io as well as locally"
        unexpected="${unexpected}${name}"$'\n'
        status=1
    fi
done <<<"$duplicates"

if [[ -z "$duplicates" ]]; then
    echo "  ok     no workspace member is shadowed by a crates.io copy"
fi

echo
if [[ $status -ne 0 ]]; then
    cat <<EOF
Some workspace members are ALSO being pulled from crates.io.

Local edits to these crates will not take effect in workspace builds, and having
two copies of their types in the graph produces mismatched-type or unsatisfied-
trait errors that point anywhere but here.

Fix: add each to '[patch.crates-io]' in the root Cargo.toml, e.g.

  <crate-name> = { path = "crates/<group>/<crate-name>" }

Then confirm with:

  cargo tree --workspace -i "registry+https://github.com/rust-lang/crates.io-index#<crate>@<version>"

If a duplicate genuinely cannot be resolved from this repository — an external
consumer pinning an incompatible version range, say — add it to
$ALLOW_FILE with a note explaining why and what would clear it.
EOF
else
    echo "All workspace members resolve to local source."
fi

exit $status

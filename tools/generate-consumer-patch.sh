#!/usr/bin/env bash
# Emit a `[patch.crates-io]` block that downstream consumers can drop
# into their own Cargo.toml when depending on affinidi-* crates via
# a git rev pin instead of crates.io.
#
# Usage:
#     tools/generate-consumer-patch.sh [<git-rev>]
#
# `<git-rev>` defaults to the current HEAD commit. Pass a tag, branch,
# or full SHA to lock to a specific point in history.
#
# The list of crates to emit is read from this workspace's own
# [patch.crates-io] table — keeping the two in sync. If you add a new
# affinidi-* crate to the workspace patch table, this script picks it
# up automatically.

set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

rev="${1:-$(git rev-parse HEAD)}"
url="https://github.com/affinidi/affinidi-tdk-rs"

# Extract the bare crate names from the workspace's [patch.crates-io]
# block so we don't drift from the canonical list. Uses awk so the
# script runs on macOS's default bash 3.x (no `mapfile`).
crates=$(
    awk '
        /^\[patch\.crates-io\]/ { in_block = 1; next }
        /^\[/                   { in_block = 0 }
        in_block && /^[a-zA-Z0-9_-]+[[:space:]]*=/ { print $1 }
    ' Cargo.toml
)

if [[ -z "$crates" ]]; then
    echo "error: no [patch.crates-io] entries found in Cargo.toml" >&2
    exit 1
fi

cat <<EOF
# Mirror of affinidi-tdk-rs's [patch.crates-io] table at rev ${rev}.
# Keep this rev in sync with whichever affinidi-* version constraints
# your own [dependencies] resolves to — when you bump one, bump the
# rev to match.
[patch.crates-io]
EOF
while IFS= read -r crate; do
    [[ -z "$crate" ]] && continue
    printf '%s = { git = "%s", rev = "%s" }\n' "$crate" "$url" "$rev"
done <<< "$crates"

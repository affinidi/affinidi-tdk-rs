#!/usr/bin/env bash
# PR guard: `cargo publish --dry-run` every PUBLISHABLE workspace crate whose
# source changed in this PR.
#
# Why this exists (the normal PR build can't catch what `cargo publish` does):
# `cargo publish` builds each crate's packaged tarball IN ISOLATION, with the
# crate's DEFAULT features, under `-D warnings`, resolving dependencies from
# crates.io — it ignores the workspace `[patch.crates-io]`. The everyday
# workspace build never reproduces that combination: feature unification across
# members silently turns optional features ON, and the `[patch]` path deps mask
# registry-version drift. So a crate can be green on every check yet fail to
# publish at release time, blocking the whole release pipeline on main.
#
# This has bitten the release twice:
#   * 2026-06-13  generic-array 0.14.9 deprecated `from_slice`; the registry-
#     resolved verify build failed under `-D warnings`. (The version-bump guard
#     now covers the stale-source half of that story.)
#   * 2026-06-29  affinidi-messaging-didcomm-service: `Listener::tsp_handler` is
#     only read by `process_next_frame`, which is `#[cfg(feature = "tsp")]`. The
#     default-feature publish-verify build hit `field ... is never read` ->
#     `dead_code` -> `-D warnings` error and blocked every release on main.
#     Workspace CI was green because another member enabled the `tsp` feature.
#
# Running the real `cargo publish --dry-run` at PR time surfaces both classes
# before merge instead of at release time.
#
# Scope: only crates whose SOURCE changed (same source/test/doc split as
# check-version-bumps.sh) so the job stays cheap. KNOWN LIMITATION: if a PR adds
# a new upstream API AND consumes it from a downstream crate in the SAME PR, the
# downstream dry-run resolves the upstream's already-published (older) version
# from the registry and may fail to compile. That mirrors the ordering the
# release pipeline must do anyway — split such changes so the upstream publishes
# first.
#
# Relies on RUSTFLAGS from the environment (the workflow sets `-D warnings ...`
# to match release.yaml) so dead-code and other lints are hard errors here too.
#
# Usage: scripts/check-publish-dry-run.sh [BASE_REF]   (default: origin/main)
# Portable to macOS bash 3.2 / BSD userland.
set -euo pipefail

BASE="${1:-origin/main}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ -t 1 ]; then
  RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; CYAN=$'\033[0;36m'; NC=$'\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
fi

if ! git rev-parse --verify --quiet "$BASE" >/dev/null; then
  echo "${RED}error:${NC} base ref '$BASE' not found. Pass a reachable ref, e.g. origin/main." >&2
  exit 2
fi

# Files changed between the merge-base of BASE and HEAD (three-dot = PR diff).
changed=$(git diff --name-only "$BASE"...HEAD)
if [ -z "$changed" ]; then
  echo "${GREEN}No changes vs $BASE — nothing to dry-run.${NC}"
  exit 0
fi

# Publishable crates as  name<TAB>relative-crate-dir  lines, longest dir first
# so the most specific crate wins for nested manifests (e.g. affinidi-tdk vs
# affinidi-tdk/common).
crates=$(cargo metadata --format-version 1 --no-deps 2>/dev/null \
  | jq -r '.packages[]
      | select(.publish == null or .publish == ["crates.io"])
      | "\(.name)\t\(.manifest_path)"' \
  | sed "s|\t$ROOT/|\t|; s|/Cargo.toml\$||" \
  | awk -F'\t' '{ print length($2)"\t"$0 }' \
  | sort -rn \
  | cut -f2-)

# classify a path (relative to a crate dir) as source-or-not — must match
# check-version-bumps.sh so the two guards agree on what "source" means.
is_source() {
  case "$1" in
    tests/*|*/tests/*) return 1 ;;
    benches/*|*/benches/*) return 1 ;;
    examples/*|*/examples/*) return 1 ;;
    *.md) return 1 ;;
    CHANGELOG*|*/CHANGELOG*) return 1 ;;
    *) return 0 ;;
  esac
}

# attribute a changed file to its most-specific publishable crate dir
crate_of() { # $1 = changed path -> prints "name<TAB>dir" or nothing
  local path="$1" name dir
  while IFS=$'\t' read -r name dir; do
    [ -z "$dir" ] && continue
    case "$path" in
      "$dir"/*) printf '%s\t%s\n' "$name" "$dir"; return 0 ;;
    esac
  done <<EOF
$crates
EOF
}

# collect publishable crates with a real source change (newline-separated "name\tdir")
touched=""
while IFS= read -r f; do
  [ -z "$f" ] && continue
  hit=$(crate_of "$f") || true
  [ -z "$hit" ] && continue
  name=$(printf '%s' "$hit" | cut -f1)
  dir=$(printf '%s' "$hit" | cut -f2)
  rel=${f#"$dir"/}
  is_source "$rel" || continue
  case "
$touched" in
    *"
$name	$dir"*) : ;;            # already recorded
    *) touched="$touched
$name	$dir" ;;
  esac
done <<EOF
$changed
EOF

touched=$(printf '%s\n' "$touched" | sed '/^$/d')

if [ -z "$touched" ]; then
  echo "${GREEN}No publishable-crate source changed vs $BASE — nothing to dry-run.${NC}"
  exit 0
fi

echo "${CYAN}=== Publish dry-run for changed publishable crates (base: $BASE) ===${NC}"
echo "RUSTFLAGS=${RUSTFLAGS:-<unset>}"
echo ""

fail=0
failed=""
while IFS=$'\t' read -r name dir; do
  [ -z "$name" ] && continue
  echo "${CYAN}--- cargo publish -p $name --dry-run ---${NC}"
  if cargo publish -p "$name" --dry-run; then
    echo "  ${GREEN}ok${NC}   $name"
  else
    echo "  ${RED}FAIL${NC} $name"
    fail=1
    failed="$failed $name"
  fi
  echo ""
done <<EOF
$touched
EOF

if [ "$fail" -eq 0 ]; then
  echo "${GREEN}All changed publishable crates pass cargo publish --dry-run.${NC}"
else
  echo "${RED}Publish dry-run failed for:${NC}${failed}"
  echo "These crates would fail to publish at release time. Fix the packaged-tarball"
  echo "build (default features, -D warnings, registry-resolved deps) before merging."
  echo "Reproduce locally with: RUSTFLAGS=\"-D warnings --cfg tracing_unstable\" \\"
  echo "  cargo publish -p <crate> --dry-run"
  exit 1
fi

#!/usr/bin/env bash
# Guard against the "edited a published crate's source but forgot to bump its
# version" trap that broke the release pipeline on 2026-06-13.
#
# What happened: W9 (#448) edited affinidi-meeting-place's source to add a
# wildcard match arm for the newly `#[non_exhaustive]` `Endpoint`, but left its
# version at 0.4.2. crates.io therefore kept the *pre-seal* 0.4.2 source. Later,
# when did-common 0.3.6 published, `cargo publish`'s registry-resolved verify
# build (which ignores `[patch.crates-io]`) compiled the stale 0.4.2 source
# against the new did-common and hit `error[E0004]: non-exhaustive patterns`,
# blocking the whole release. The local `[patch.crates-io]` workspace build was
# green the whole time, so nothing caught it pre-merge.
#
# This guard runs on PRs: for every PUBLISHABLE workspace crate whose *source*
# changed between the base ref and HEAD, it requires the crate's Cargo.toml
# `version` to differ from the base ref's version. Forcing a bump alongside any
# source edit means main never accumulates an unpublished source delta against a
# stale crates.io version — the release pipeline then publishes the new source
# at a fresh version and the registry never goes incompatible.
#
# "Source" = anything under the crate dir EXCEPT tests/, benches/, examples/,
# *.md and CHANGELOG* (test-/doc-only changes get no bump, per repo convention).
# `publish = false` crates are skipped — they never reach crates.io, so a stale
# registry source is impossible for them.
#
# Usage: scripts/check-version-bumps.sh [BASE_REF]   (default: origin/main)
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
  echo "${GREEN}No changes vs $BASE — nothing to check.${NC}"
  exit 0
fi

# ALL crates as  pub<TAB>name<TAB>relative-crate-dir  lines, longest dir first
# so the most specific crate wins for nested manifests (e.g. affinidi-tdk vs
# affinidi-tdk/common). `pub` is 1 for publishable, 0 otherwise.
#
# We include non-publishable crates here (not just publishable ones) so a file
# under a nested `publish = false` package (e.g. the mediator-setup tool nested
# in the publishable affinidi-messaging-mediator dir) is attributed to that
# nested package and skipped — rather than bubbling up to the publishable parent
# and demanding a spurious bump for source that never reaches crates.io.
crates=$(cargo metadata --format-version 1 --no-deps 2>/dev/null \
  | jq -r '.packages[]
      | (if (.publish == null or .publish == ["crates.io"]) then "1" else "0" end) as $pub
      | "\($pub)\t\(.name)\t\(.manifest_path)"' \
  | sed "s|\t$ROOT/|\t|; s|/Cargo.toml\$||" \
  | awk -F'\t' '{ print length($3)"\t"$0 }' \
  | sort -rn \
  | cut -f2-)

# classify a path (relative to a crate dir) as source-or-not
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

# attribute a changed file to its most-specific crate dir (publishable or not)
crate_of() { # $1 = changed path -> prints "pub<TAB>name<TAB>dir" or nothing
  local path="$1" pub name dir
  while IFS=$'\t' read -r pub name dir; do
    [ -z "$dir" ] && continue
    case "$path" in
      "$dir"/*) printf '%s\t%s\t%s\n' "$pub" "$name" "$dir"; return 0 ;;
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
  pub=$(printf '%s' "$hit" | cut -f1)
  name=$(printf '%s' "$hit" | cut -f2)
  dir=$(printf '%s' "$hit" | cut -f3)
  # A file whose most-specific owner is a non-publishable crate never reaches
  # crates.io (even when nested under a publishable parent dir) — skip it.
  [ "$pub" = "1" ] || continue
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
  echo "${GREEN}No publishable-crate source changed vs $BASE — nothing to check.${NC}"
  exit 0
fi

echo "${CYAN}=== Version-bump guard (base: $BASE) ===${NC}"
echo ""

fail=0
while IFS=$'\t' read -r name dir; do
  [ -z "$name" ] && continue
  manifest="$dir/Cargo.toml"
  cur=$(grep -E '^[[:space:]]*version[[:space:]]*=' "$manifest" | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
  base=$(git show "$BASE:$manifest" 2>/dev/null | grep -E '^[[:space:]]*version[[:space:]]*=' | head -1 | sed -E 's/.*"([^"]+)".*/\1/' || true)
  if [ -z "$base" ]; then
    echo "  ${GREEN}ok${NC}   $name: new crate (no version at $BASE) -> $cur"
  elif [ "$cur" != "$base" ]; then
    echo "  ${GREEN}ok${NC}   $name: $base -> $cur"
  else
    echo "  ${RED}MISS${NC} $name: source changed but version still $cur (unchanged from $BASE)"
    fail=1
  fi
done <<EOF
$touched
EOF

echo ""
if [ "$fail" -eq 0 ]; then
  echo "${GREEN}All changed publishable crates were version-bumped.${NC}"
else
  echo "${RED}Some changed publishable crates were NOT version-bumped.${NC}"
  echo "Bump the crate's Cargo.toml version (and CHANGELOG) so the source change actually"
  echo "publishes. If the change is genuinely test-/doc-only, move it out of the crate's"
  echo "source paths or adjust this guard's exclusions."
  exit 1
fi

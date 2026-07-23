#!/usr/bin/env bash
# Guard: a published version with no changelog entry.
#
# Sibling to check-version-bumps.sh, which enforces the other half of the same
# convention. That script already tells you to "bump the crate's Cargo.toml
# version (and CHANGELOG)" — but only the version half was ever enforced, so the
# changelog half depended on the author remembering. It stopped being
# remembered: between them, affinidi-messaging-mediator 0.17.7/0.17.8/0.17.9,
# affinidi-messaging-sdk 0.18.62/0.18.63/0.18.64 and
# affinidi-messaging-test-mediator 0.2.40/0.2.41/0.2.42 all shipped to crates.io
# with nothing written down.
#
# That matters beyond tidiness. CLAUDE.md (R3.6) makes the changelog part of the
# downstream contract: services pin these crates loosely, so a behavioural change
# to send/ack/reconnect semantics is breaking for a consumer even when no
# signature changes, and the changelog is where they are supposed to find out.
# An undocumented release is a silent breaking change waiting to happen.
#
# The rule: if a publishable crate's VERSION changed in this PR, that crate's
# CHANGELOG.md must MENTION THE NEW VERSION.
#
# Deliberately not the weaker "the changelog file was touched". A PR that edits
# a changelog for one reason and bumps a version for another would satisfy that
# and still ship an undocumented release — which is exactly how the first draft
# of this guard passed a version bump it should have caught.
#
# Not circular with check-version-bumps.sh — that script explicitly excludes
# CHANGELOG* from "source changes", so a changelog-only PR needs no bump, and a
# bump needs a changelog. The two guards meet in the middle.
#
# Usage: scripts/check-changelogs.sh [base-ref]
# Portable to macOS bash 3.2 / BSD userland.
set -euo pipefail

BASE="${1:-origin/main}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ -t 1 ]; then
  RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; CYAN=$'\033[0;36m'; NC=$'\033[0m'
else
  RED=''; GREEN=''; CYAN=''; NC=''
fi

if ! git rev-parse --verify --quiet "$BASE" >/dev/null; then
  echo "${RED}error:${NC} base ref '$BASE' not found. Pass a reachable ref, e.g. origin/main." >&2
  exit 2
fi

echo "=== Changelog guard (base: $BASE) ==="
echo

changed=$(git diff --name-only "$BASE"...HEAD)
if [ -z "$changed" ]; then
  echo "${GREEN}No changes vs $BASE — nothing to check.${NC}"
  exit 0
fi

# Publishable crates as  name<TAB>relative-crate-dir. Non-publishable crates are
# irrelevant here: nothing reaches a consumer, so there is no contract to record.
crates=$(cargo metadata --format-version 1 --no-deps 2>/dev/null \
  | jq -r '.packages[]
      | select(.publish == null or .publish == ["crates.io"])
      | "\(.name)\t\(.manifest_path)"' \
  | sed "s|\t$ROOT/|\t|; s|/Cargo.toml\$||")

fail=0
found=0

while IFS="$(printf '\t')" read -r name dir; do
  [ -n "$name" ] || continue
  manifest="$dir/Cargo.toml"

  # Did this PR change the crate's version?
  old_version=$(git show "$BASE:$manifest" 2>/dev/null \
    | awk '/^\[/{ in_pkg = ($0 == "[package]") } in_pkg && /^version = / { gsub(/^version = "|"$/, ""); print; exit }')
  new_version=$(awk '/^\[/{ in_pkg = ($0 == "[package]") } in_pkg && /^version = / { gsub(/^version = "|"$/, ""); print; exit }' "$manifest" 2>/dev/null)

  # A crate that is new in this PR has no old version; it still needs an entry.
  [ -n "$new_version" ] || continue
  [ "$old_version" != "$new_version" ] || continue

  found=1
  changelog="$dir/CHANGELOG.md"
  if [ ! -f "$changelog" ]; then
    echo "  ${RED}MISSING${NC} $name: ${old_version:-<new>} -> $new_version but $changelog does not exist"
    fail=1
  # Match the version as a whole token: a plain substring search would let
  # `0.1.30`'s entry satisfy a bump to `0.1.3`.
  elif grep -qE "(^|[^0-9.])$(printf '%s' "$new_version" | sed 's/\./\\./g')([^0-9.]|\$)" "$changelog"; then
    echo "  ${GREEN}ok${NC}   $name: ${old_version:-<new>} -> $new_version (documented)"
  else
    echo "  ${RED}MISSING${NC} $name: ${old_version:-<new>} -> $new_version, but $new_version does not appear in $changelog"
    fail=1
  fi
done <<EOF
$crates
EOF

echo
if [ "$found" -eq 0 ]; then
  echo "${GREEN}No publishable crate versions changed — nothing to check.${NC}"
  exit 0
fi

if [ "$fail" -ne 0 ]; then
  echo "${RED}A crate is being published with no record of what changed.${NC}"
  echo "Consumers pin these crates loosely, so a behavioural change is breaking for"
  echo "them even when no signature changes — the changelog is where they find out."
  echo "Add an entry naming the new version to the crate's ${CYAN}CHANGELOG.md${NC}."
  exit 1
fi

echo "${GREEN}Every version bump in this PR has a changelog entry.${NC}"

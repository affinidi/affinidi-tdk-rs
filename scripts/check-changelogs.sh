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
# CHANGELOG.md must carry a heading for the new version in exactly this form:
#
#     ## [x.y.z] - YYYY-MM-DD
#
# One grammar, so a reader (or a tool extracting "the notes for x.y.z") can
# find a release and see when it shipped. Five heading shapes used to coexist,
# and 32 changelogs headed versions that had already been published
# `## Unreleased (x.y.z)` — merging to main publishes, so nothing in this repo
# is "unreleased" once merged (#1065). `## Unreleased (x.y.z)` and
# `## [x.y.z] - Unreleased` are therefore refused outright for the new version.
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

# shellcheck source=scripts/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
guard_require_base "$BASE"

echo "=== Changelog guard (base: $BASE) ==="
echo

changed=$(git diff --name-only "$BASE"...HEAD)
if [ -z "$changed" ]; then
  echo "${GREEN}No changes vs $BASE — nothing to check.${NC}"
  exit 0
fi

# Publishable crates as  name<TAB>relative-crate-dir. Non-publishable crates are
# irrelevant here: nothing reaches a consumer, so there is no contract to record.
# guard_load_crates (lib.sh) refuses to continue if the ROOT strip failed.
guard_load_crates
crates=$(publishable_crates)

fail=0
found=0

while IFS="$(printf '\t')" read -r name dir; do
  [ -n "$name" ] || continue
  manifest="$dir/Cargo.toml"

  # Did this PR change the crate's version?
  #
  # The trailing `|| true` is load-bearing. For a crate added by this PR the
  # manifest does not exist at $BASE, so `git show` exits non-zero — and under
  # `set -o pipefail` that fails the whole command substitution, which `set -e`
  # then turns into an abort. The script would exit 128 partway through the
  # crate list, printing a few `ok` lines and no verdict: a *silent pass* for
  # every crate after the new one. Sibling check-version-bumps.sh already
  # guards its equivalent line this way; this one did not, and the gap went
  # unnoticed because no PR had added a crate since the guard landed.
  old_version=$(git show "$BASE:$manifest" 2>/dev/null \
    | awk '/^\[/{ in_pkg = ($0 == "[package]") } in_pkg && /^version = / { gsub(/^version = "|"$/, ""); print; exit }' || true)
  new_version=$(awk '/^\[/{ in_pkg = ($0 == "[package]") } in_pkg && /^version = / { gsub(/^version = "|"$/, ""); print; exit }' "$manifest" 2>/dev/null)

  # A crate that is new in this PR has no old version; it still needs an entry.
  [ -n "$new_version" ] || continue
  [ "$old_version" != "$new_version" ] || continue

  found=1
  changelog="$dir/CHANGELOG.md"
  ver_re=$(printf '%s' "$new_version" | sed 's/\./\\./g')
  if [ ! -f "$changelog" ]; then
    echo "  ${RED}MISSING${NC} $name: ${old_version:-<new>} -> $new_version but $changelog does not exist"
    fail=1
  # The version is escaped and the heading anchored at both ends, so
  # `0.1.30`'s entry cannot satisfy a bump to `0.1.3`.
  elif grep -qE "^##[[:space:]]+Unreleased[[:space:]]*\($ver_re\)|^##[[:space:]]+\[$ver_re\][[:space:]]+-[[:space:]]+Unreleased" "$changelog"; then
    echo "  ${RED}UNRELEASED${NC} $name: ${old_version:-<new>} -> $new_version is headed \"Unreleased\" in $changelog"
    echo "         merging publishes it; head it  ## [$new_version] - $(date -u +%Y-%m-%d)"
    fail=1
  elif grep -qE "^## \[$ver_re\] - [0-9]{4}-[0-9]{2}-[0-9]{2}\$" "$changelog"; then
    echo "  ${GREEN}ok${NC}   $name: ${old_version:-<new>} -> $new_version (documented)"
  elif grep -qE "(^|[^0-9.])$ver_re([^0-9.]|\$)" "$changelog"; then
    echo "  ${RED}HEADING${NC} $name: ${old_version:-<new>} -> $new_version is mentioned in $changelog but has no"
    echo "         \"## [$new_version] - YYYY-MM-DD\" heading"
    fail=1
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
  echo "Add an entry headed ${CYAN}## [x.y.z] - YYYY-MM-DD${NC} for the new version to the"
  echo "crate's CHANGELOG.md, newest first, with a one-line summary as its first line."
  exit 1
fi

echo "${GREEN}Every version bump in this PR has a changelog entry.${NC}"

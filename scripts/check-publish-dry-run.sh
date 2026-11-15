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
# ONE FAILURE IS NOT A FAILURE: "waiting on a sibling this release publishes".
# The split above is impossible when the upstream and downstream share a PUBLIC
# type from a third crate — bumping it in one crate and not the others puts two
# semver-incompatible copies in the workspace graph, and the everyday build
# fails with E0308 before publish is ever reached. Such a bump has to be atomic
# across the workspace, so the downstream necessarily requires a sibling version
# that is not on crates.io yet, and its dry-run cannot resolve.
#
# The release pipeline already handles exactly this: it publishes per crate with
# bounded retries "to resolve dependency ordering", so the sibling goes up on an
# earlier pass and the dependent succeeds on a later one. Failing the PR here
# would block a change the release can perform, so that one shape is reported as
# `wait` rather than `FAIL`.
#
# It is recognised narrowly: the unmet requirement must name a publishable crate
# in THIS workspace whose LOCAL version is exactly the version required. A
# requirement on a version nobody is publishing — real registry drift, which is
# what this guard exists to catch — still fails.
#
# Relies on RUSTFLAGS from the environment (the workflow sets `-D warnings ...`
# to match release.yaml) so dead-code and other lints are hard errors here too.
#
# Usage: scripts/check-publish-dry-run.sh [BASE_REF]   (default: origin/main)
# Portable to macOS bash 3.2 / BSD userland.
set -euo pipefail

BASE="${1:-origin/main}"

# shellcheck source=scripts/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
guard_require_base "$BASE"

# Files changed between the merge-base of BASE and HEAD (three-dot = PR diff).
changed=$(git diff --name-only "$BASE"...HEAD)
if [ -z "$changed" ]; then
  echo "${GREEN}No changes vs $BASE — nothing to dry-run.${NC}"
  exit 0
fi

# Every workspace crate, longest dir first, with the ROOT-strip sanity check;
# is_source and crate_of are shared with check-version-bumps.sh (lib.sh) so the
# two guards agree on what "source" means and which crate owns a file. A file
# whose most-specific owner is a `publish = false` crate is skipped below.
guard_load_crates

# collect publishable crates with a real source change (newline-separated "name\tdir")
touched=""
while IFS= read -r f; do
  [ -z "$f" ] && continue
  hit=$(crate_of "$f") || true
  [ -z "$hit" ] && continue
  [ "$(printf '%s' "$hit" | cut -f1)" = "1" ] || continue
  name=$(printf '%s' "$hit" | cut -f2)
  dir=$(printf '%s' "$hit" | cut -f3)
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

# name<TAB>version for every publishable workspace crate, so a dry-run failure
# can be checked against what THIS release publishes.
crate_versions=$(cargo metadata --format-version 1 --no-deps 2>/dev/null \
  | jq -r '.packages[]
      | select(.publish == null or .publish == ["crates.io"])
      | "\(.name)\t\(.version)"')

# Does the local version satisfy the requirement the dry-run could not resolve?
#
# String equality is wrong here, and wrong in the direction that makes the
# `wait` path unreachable for the only shape it exists to recognise. Internal
# requirements in this workspace are written `major.minor` by convention
# (`affinidi-tdk = { version = "0.11", path = ... }`), while a crate version is
# always `major.minor.patch` — so `req_ver` is `0.11` and `local_ver` is
# `0.11.0`, and `[ "0.11.0" = "0.11" ]` is false. Every coordinated breaking
# release therefore reported FAIL, which is precisely what the header's "ONE
# FAILURE IS NOT A FAILURE" note says must not happen.
#
# Prefix-with-boundary rather than a semver library: the requirement is either
# the local version exactly, or a `major.minor` prefix of it. The `.` in the
# second pattern is load-bearing — without it `0.3` would also match a local
# `0.30.0`, which is a different, incompatible release.
version_satisfies() { # $1 = local version, $2 = required version
  case "$1" in
    "$2" | "$2".*) return 0 ;;
    *) return 1 ;;
  esac
}

# Is this failure solely "requires a sibling version this release publishes"?
# See the header note. Returns 0 only when at least one unmet requirement was
# found AND every one of them names a workspace crate whose local version
# satisfies what was required.
awaits_sibling_release() { # $1 = captured dry-run output
  local out="$1" line req_name req_ver local_ver found=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    req_name=$(printf '%s' "$line" | sed -n 's/.*failed to select a version for the requirement `\([^ ]*\) = "\^\{0,1\}\([^"]*\)".*/\1/p')
    req_ver=$(printf '%s' "$line" | sed -n 's/.*failed to select a version for the requirement `\([^ ]*\) = "\^\{0,1\}\([^"]*\)".*/\2/p')
    [ -z "$req_name" ] && continue
    found=1
    local_ver=$(printf '%s\n' "$crate_versions" | awk -F'\t' -v n="$req_name" '$1 == n { print $2 }')
    # Not ours, or not a version this release is about to publish -> real failure.
    [ -n "$local_ver" ] && version_satisfies "$local_ver" "$req_ver" || return 1
  done <<AWAIT_EOF
$(printf '%s\n' "$out" | grep 'failed to select a version for the requirement' || true)
AWAIT_EOF
  [ "$found" -eq 1 ]
}

echo "${CYAN}=== Publish dry-run for changed publishable crates (base: $BASE) ===${NC}"
echo "RUSTFLAGS=${RUSTFLAGS:-<unset>}"
echo ""

fail=0
failed=""
waiting=""
while IFS=$'\t' read -r name dir; do
  [ -z "$name" ] && continue
  echo "${CYAN}--- cargo publish -p $name --dry-run ---${NC}"
  out=$(cargo publish -p "$name" --dry-run 2>&1) && rc=0 || rc=$?
  printf '%s\n' "$out"
  if [ "$rc" -eq 0 ]; then
    echo "  ${GREEN}ok${NC}   $name"
  elif awaits_sibling_release "$out"; then
    echo "  ${YELLOW}wait${NC} $name — unresolvable only until a sibling in this release publishes first"
    waiting="$waiting $name"
  else
    echo "  ${RED}FAIL${NC} $name"
    fail=1
    failed="$failed $name"
  fi
  echo ""
done <<EOF
$touched
EOF

# Never silent: an ordered publish is a claim about the release, so it is stated
# even when the job goes green.
if [ -n "$waiting" ]; then
  echo "${YELLOW}Waiting on in-release siblings:${NC}${waiting}"
  echo "Each of these requires a workspace crate at a version this same release"
  echo "publishes. The per-crate release path retries in passes to resolve that"
  echo "ordering, so they are not treated as failures. If the release is ever"
  echo "split so the sibling does NOT go out with them, they will fail for real."
  echo ""
fi

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

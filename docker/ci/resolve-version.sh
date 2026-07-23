#!/usr/bin/env bash
# Resolve the mediator image version tag for the publish workflow.
#
# Inputs (environment):
#   REF_NAME       - github.ref_name (branch or tag the workflow runs on)
#   INPUT_VERSION  - workflow_dispatch 'version' input (optional). Accepts a
#                    full release tag (affinidi-messaging-mediator-vX.Y.Z), a
#                    bare vX.Y.Z, or X.Y.Z.
#   CRATE_MANIFEST - mediator Cargo.toml for the crate-version fallback
#                    (default: crates/messaging/affinidi-messaging-mediator/Cargo.toml)
#
# Output: appends `version=` and `is_latest=` to $GITHUB_OUTPUT (or stdout when
# unset, so the script is runnable locally). Diagnostics go to stderr.
#
# Whatever the source, the result is normalised to a single `vX.Y.Z`: the
# `affinidi-messaging-mediator-` tag prefix is stripped and a lone `v` ensured.
set -euo pipefail

: "${REF_NAME:=}"
: "${INPUT_VERSION:=}"
: "${CRATE_MANIFEST:=crates/messaging/affinidi-messaging-mediator/Cargo.toml}"

if [ -n "$INPUT_VERSION" ]; then
  # Explicit dispatch input wins.
  version="$INPUT_VERSION"
else
  case "$REF_NAME" in
    affinidi-messaging-mediator-v* | v[0-9]*)
      # Running on a release tag (push or dispatch-on-tag).
      version="$REF_NAME" ;;
    *)
      # Default to the crate version on the checked-out ref. awk (not GNU-only
      # `sed '0,/re/'`) grabs the first `version = "..."`, i.e. the [package] one.
      version="$(awk -F'"' '/^version[[:space:]]*=[[:space:]]*"/{print $2; exit}' "$CRATE_MANIFEST")"
      if [ -z "$version" ]; then
        echo "::error::could not read crate version from $CRATE_MANIFEST" >&2
        exit 1
      fi ;;
  esac
fi

# Normalise: accept a full release tag, a bare vX.Y.Z, or X.Y.Z from any source.
version="${version#affinidi-messaging-mediator-}"
case "$version" in
  v*) ;;
  *) version="v${version}" ;;
esac

# Only advance :latest when this version is at least as new as every released
# one, so re-publishing an older version never moves :latest backwards.
#
# Pre-releases are excluded from the comparison AND never take :latest: `sort -V`
# orders `v1.0.0-rc1` AFTER `v1.0.0`, so leaving them in would let an rc claim
# :latest and would then stop the stable release from claiming it back.
highest="$(git tag --list 'affinidi-messaging-mediator-v*' \
  | sed 's/^affinidi-messaging-mediator-//' \
  | grep -v -- '-' \
  | sort -V | tail -1)"

case "$version" in
  *-*)
    # Pre-release (e.g. v1.0.0-rc1).
    is_latest=false
    ;;
  *)
    # Rank, don't compare for equality: a tag push of the newest release ranks
    # equal to `highest`, while a workflow_dispatch of a version that has not
    # been tagged yet ranks above it. Both should take :latest; only a genuinely
    # older version must not.
    top="$(printf '%s\n%s\n' "$version" "$highest" | sort -V | tail -1)"
    if [ "$version" = "$top" ]; then
      is_latest=true
    else
      is_latest=false
    fi
    ;;
esac

out="${GITHUB_OUTPUT:-/dev/stdout}"
{
  echo "version=${version}"
  echo "is_latest=${is_latest}"
} >> "$out"
echo "Resolved version: ${version} (is_latest=${is_latest}, highest=${highest:-none})" >&2

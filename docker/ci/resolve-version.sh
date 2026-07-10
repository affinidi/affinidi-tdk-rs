#!/usr/bin/env bash
# Resolve the mediator image version tag for the publish workflow.
#
# Inputs (environment):
#   EVENT_NAME     - github.event_name (push | workflow_dispatch | pull_request)
#   REF_NAME       - github.ref_name (the tag name on a push)
#   INPUT_VERSION  - workflow_dispatch 'version' input (optional)
#   CRATE_MANIFEST - mediator Cargo.toml for the crate-version fallback
#                    (default: crates/messaging/affinidi-messaging-mediator/Cargo.toml)
#
# Output: appends `version=` and `is_latest=` to $GITHUB_OUTPUT (or stdout when
# unset, so the script is runnable locally). Diagnostics go to stderr.
set -euo pipefail

: "${EVENT_NAME:=}"
: "${REF_NAME:=}"
: "${INPUT_VERSION:=}"
: "${CRATE_MANIFEST:=crates/messaging/affinidi-messaging-mediator/Cargo.toml}"

if [ "$EVENT_NAME" = "push" ]; then
  version="${REF_NAME#affinidi-messaging-mediator-}"
elif [ -n "$INPUT_VERSION" ]; then
  version="$INPUT_VERSION"
else
  # Default to the crate version on the checked-out ref. awk (not GNU-only
  # `sed '0,/re/'`) grabs the first `version = "..."`, i.e. the [package] one.
  version="$(awk -F'"' '/^version[[:space:]]*=[[:space:]]*"/{print $2; exit}' "$CRATE_MANIFEST")"
  if [ -z "$version" ]; then
    echo "::error::could not read crate version from $CRATE_MANIFEST" >&2
    exit 1
  fi
fi

case "$version" in
  v*) ;;
  *) version="v${version}" ;;
esac

# Only advance :latest when this is the highest mediator release tag, so
# re-publishing an older version never moves :latest backwards.
highest="$(git tag --list 'affinidi-messaging-mediator-v*' \
  | sed 's/^affinidi-messaging-mediator-//' | sort -V | tail -1)"
if [ "$version" = "$highest" ] || [ -z "$highest" ]; then
  is_latest=true
else
  is_latest=false
fi

out="${GITHUB_OUTPUT:-/dev/stdout}"
{
  echo "version=${version}"
  echo "is_latest=${is_latest}"
} >> "$out"
echo "Resolved version: ${version} (is_latest=${is_latest}, highest=${highest:-none})" >&2

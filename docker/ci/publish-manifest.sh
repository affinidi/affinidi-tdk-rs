#!/usr/bin/env bash
# Create + push the multi-arch GHCR manifest list from the per-arch digests.
#
# Expects the per-arch digest files in the current directory (one empty file
# named after each `sha256:<digest>` sans prefix; produced by the build jobs).
#
# Inputs (environment):
#   IMAGE     - target repo, e.g. ghcr.io/<owner>/messaging-mediator
#   VERSION   - version tag to publish, e.g. v0.16.44
#   IS_LATEST - "true" to also tag :latest (highest release only; see version job)
# Output: appends `digest=` to $GITHUB_OUTPUT (or stdout when unset).
set -euo pipefail

: "${IMAGE:?IMAGE must be set}"
: "${VERSION:?VERSION must be set}"
: "${IS_LATEST:=false}"

tags=(--tag "${IMAGE}:${VERSION}")
if [ "$IS_LATEST" = "true" ]; then
  tags+=(--tag "${IMAGE}:latest")
fi

# shellcheck disable=SC2046  # intentional: each digest must be a separate arg
docker buildx imagetools create \
  "${tags[@]}" \
  $(printf "${IMAGE}@sha256:%s " *)

digest=$(docker buildx imagetools inspect "${IMAGE}:${VERSION}" --format '{{json .Manifest.Digest}}' | tr -d '"')

out="${GITHUB_OUTPUT:-/dev/stdout}"
echo "digest=${digest}" >> "$out"
echo "Published ${IMAGE}:${VERSION} (latest=${IS_LATEST}) (${digest})" >&2

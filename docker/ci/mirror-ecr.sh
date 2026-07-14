#!/usr/bin/env bash
# Mirror the published manifest from GHCR to ECR Public, preserving the digest.
#
# Assumes AWS credentials are already configured in the environment (OIDC) and
# the runner is logged in to the GHCR source. Logs in to ECR Public here, then
# copies the manifest list by tag (imagetools copies the same digest).
#
# Inputs (environment):
#   ECR_PUBLIC_REGION - region for the ecr-public login token, e.g. us-east-1
#   SRC               - source repo, e.g. ghcr.io/<owner>/messaging-mediator
#   DST               - destination repo, e.g. public.ecr.aws/<ns>/messaging-mediator
#   VERSION           - version tag to mirror, e.g. v0.16.44
#   IS_LATEST         - "true" to mirror the :latest tag as well, so the two
#                       registries don't disagree about what :latest is
#
# NOTE: ECR Public does not create repositories on push — `<DST>` must already
# exist (Terraform/console) or `imagetools create` fails with a 404.
set -euo pipefail

: "${ECR_PUBLIC_REGION:?ECR_PUBLIC_REGION must be set}"
: "${SRC:?SRC must be set}"
: "${DST:?DST must be set}"
: "${VERSION:?VERSION must be set}"
: "${IS_LATEST:=false}"

aws ecr-public get-login-password --region "${ECR_PUBLIC_REGION}" \
  | docker login --username AWS --password-stdin public.ecr.aws

tags=(--tag "${DST}:${VERSION}")
if [ "$IS_LATEST" = "true" ]; then
  tags+=(--tag "${DST}:latest")
fi

docker buildx imagetools create "${tags[@]}" "${SRC}:${VERSION}"
docker buildx imagetools inspect "${DST}:${VERSION}"

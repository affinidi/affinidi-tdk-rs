#!/usr/bin/env bash
# Boot-probe the production mediator image.
#
# No AWS creds are present, so the run is expected to exit while probing the
# secrets backend. We assert HOW it fails: the AWS feature must be compiled
# (SDK initialises, the backend probe is attempted), and it must NOT die on a
# missing feature, unreadable config, or a panic.
#
# Inputs (environment):
#   IMAGE - image reference to run (e.g. messaging-mediator:verify)
set -euo pipefail

: "${IMAGE:?IMAGE must be set}"

log="$(mktemp)"
set +e
timeout 40 docker run --rm \
  -e MEDIATOR_SECRETS_BACKEND=aws_secrets://us-east-1/ci-probe \
  -e MEDIATOR_DID=aws_parameter_store://mediator/ci/did \
  -e LISTEN_ADDRESS=0.0.0.0:7037 -e API_PREFIX=/ \
  -e MEDIATOR_ACL_MODE=explicit_deny \
  -e AWS_REGION=us-east-1 -e AWS_EC2_METADATA_DISABLED=true \
  -e RUST_LOG=info \
  "$IMAGE" >"$log" 2>&1
set -e

echo "----- mediator output -----"; cat "$log"; echo "---------------------------"
if grep -qiE "feature .*not enabled|compiled without|could not open secret backend '(keyring|file)|failed to parse|panicked" "$log"; then
  echo "::error::production image failed on a feature/config/panic error — not a clean AWS-reach failure" >&2
  exit 1
fi
if ! grep -qiE "initializing AWS SDK" "$log"; then
  echo "::error::image never initialised the AWS SDK — secrets-aws likely not compiled" >&2
  exit 1
fi
echo "Boot probe OK: config parsed, secrets-aws active, reached backend probe."

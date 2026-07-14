#!/usr/bin/env bash
# Boot-probe the production mediator image.
#
# Two runs, because the image has two failure modes worth pinning down:
#
#   1. DEFAULT CONFIG — `docker run <image>` with no env, exactly as an operator
#      first tries it. The image ships docker/conf/mediator.toml with no identity,
#      so it MUST fail — but it must fail on the *missing identity*, not on a
#      backend the binary was never compiled with. This is the regression guard
#      for the image shipping a config it cannot honour (e.g. `keyring://` against
#      a build without `secrets-keyring`).
#
#   2. CLOUD CONFIG — the AWS scheme the deployment actually uses. No AWS creds
#      are present, so the run is expected to exit while probing the secrets
#      backend. We assert HOW it fails: the AWS feature must be compiled (SDK
#      initialises, the backend probe is attempted), and it must NOT die on a
#      missing feature, unreadable config, or a panic.
#
# Inputs (environment):
#   IMAGE - image reference to run (e.g. messaging-mediator:verify)
set -euo pipefail

: "${IMAGE:?IMAGE must be set}"

# Errors that mean the IMAGE is broken, regardless of which config it was run
# with: a feature named in config but not compiled in, a config that doesn't
# parse, or a crash.
BROKEN_IMAGE_RE="feature .*not enabled|compiled without|failed to parse|panicked"

# Run the image, capture combined output and exit status. Never fails the script
# itself — each probe below decides what a given exit means.
run_image() {
  local log=$1; shift
  local status=0
  timeout 40 docker run --rm "$@" "$IMAGE" >"$log" 2>&1 || status=$?
  echo "$status"
}

# ── Probe 1: the shipped default config, no environment ─────────────────────
log1="$(mktemp)"
status1="$(run_image "$log1" -e RUST_LOG=info)"
echo "----- default-config run (exit ${status1}) -----"; cat "$log1"; echo "-----------------------------------------------"

if [ "$status1" -eq 0 ]; then
  echo "::error::image booted with no identity configured — it must refuse to start" >&2
  exit 1
fi
if [ "$status1" -eq 124 ]; then
  echo "::error::image hung on the default config instead of failing fast" >&2
  exit 1
fi
if grep -qiE "$BROKEN_IMAGE_RE" "$log1"; then
  echo "::error::default config names something the binary can't honour (feature/parse/panic) — the shipped conf/mediator.toml does not match the image's feature set" >&2
  exit 1
fi
if grep -qi "could not open secret backend" "$log1"; then
  echo "::error::the shipped default secret backend does not open — see docker/conf/mediator.toml" >&2
  exit 1
fi
if ! grep -qi "mediator_did" "$log1"; then
  echo "::error::expected the default run to fail on the missing mediator_did; it failed on something else" >&2
  exit 1
fi
echo "Default-config probe OK: shipped config parses, secret backend opens, refuses to boot without an identity."

# ── Probe 2: the cloud (AWS) config the deployment actually uses ────────────
log2="$(mktemp)"
status2="$(run_image "$log2" \
  -e MEDIATOR_SECRETS_BACKEND=aws_secrets://us-east-1/ci-probe \
  -e MEDIATOR_DID=aws_parameter_store://mediator/ci/did \
  -e ADMIN_DID=aws_parameter_store://mediator/ci/admin-did \
  -e LISTEN_ADDRESS=0.0.0.0:7037 -e API_PREFIX=/ \
  -e MEDIATOR_ACL_MODE=explicit_deny \
  -e AWS_REGION=us-east-1 -e AWS_EC2_METADATA_DISABLED=true \
  -e RUST_LOG=info)"
echo "----- aws-config run (exit ${status2}) -----"; cat "$log2"; echo "-------------------------------------------"

if grep -qiE "$BROKEN_IMAGE_RE" "$log2"; then
  echo "::error::production image failed on a feature/config/panic error — not a clean AWS-reach failure" >&2
  exit 1
fi
if grep -qiE "could not open secret backend '(keyring|file)" "$log2"; then
  echo "::error::MEDIATOR_SECRETS_BACKEND was ignored — the run fell back to the shipped backend" >&2
  exit 1
fi
# `initializing AWS SDK` is logged by config::TryFrom when an AWS scheme is seen
# (crates/messaging/affinidi-messaging-mediator/src/common/config/mod.rs). If that
# line is reworded, update it here too.
if ! grep -qiE "initializing AWS SDK" "$log2"; then
  echo "::error::image never initialised the AWS SDK — secrets-aws likely not compiled" >&2
  exit 1
fi
echo "AWS-config probe OK: secrets-aws active, reached the backend probe."

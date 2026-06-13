#!/usr/bin/env bash
# TI4b guard: the advanceable `TestClock` must never compile into the mediator
# binary.
#
# `TestClock` lives behind mediator-common's NON-DEFAULT `test-clock` feature so
# it can be injected by test fixtures (e.g. affinidi-messaging-test-mediator)
# but never reaches production. Cargo feature unification means that if a crate
# in the *mediator binary's* dependency graph ever turned `test-clock` on, it
# would silently ship. This check fails the build if that ever happens.
#
# Pure `cargo tree` (no compile). Resolves features as if building only the
# mediator binary — test fixtures are not in that graph, so `test-clock` must
# be absent.
set -euo pipefail

echo "Checking that 'test-clock' is not enabled for the mediator binary..."

graph=$(cargo tree -p affinidi-messaging-mediator -f '{p} {f}' 2>/dev/null)

# Lines for mediator-common carry its activated feature list as the last field.
offenders=$(echo "$graph" | grep 'affinidi-messaging-mediator-common' | grep 'test-clock' || true)

if [ -n "$offenders" ]; then
  echo "ERROR: the 'test-clock' feature is enabled in the mediator binary's graph:" >&2
  echo "$offenders" >&2
  echo "TestClock must stay test-only — do not enable 'test-clock' for the mediator." >&2
  exit 1
fi

echo "OK: 'test-clock' is not enabled for the mediator binary."

#!/usr/bin/env bash
# TI3 — smoke test for the docker-compose.test.yml stack.
#
# Brings the stack up (unless ALREADY_UP=1), waits for the mediator + did:web to
# be reachable, checks the did:web document resolves, then runs the SDK
# round-trip (authenticate + trust-ping) via the docker_smoke example. Tears the
# stack down at the end unless KEEP_UP=1.
#
# Usage: docker/smoke/smoke.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

COMPOSE="docker compose -f docker-compose.test.yml"
MEDIATOR_LIVEZ="http://localhost:7037/mediator/v1/livez"
MEDIATOR_READYZ="http://localhost:7037/mediator/v1/readyz"
DIDWEB_URL="http://localhost:8080/.well-known/did.json"

cleanup() {
  if [ "${KEEP_UP:-0}" != "1" ]; then
    echo "==> tearing down"
    $COMPOSE down -v >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [ "${ALREADY_UP:-0}" != "1" ]; then
  echo "==> bringing up the stack (build if needed)"
  $COMPOSE up -d --build
fi

echo "==> waiting for the mediator liveness probe"
for i in $(seq 1 60); do
  if curl -fsS "$MEDIATOR_LIVEZ" >/dev/null 2>&1; then
    echo "    mediator live after ${i} attempt(s)"
    break
  fi
  if [ "$i" -eq 60 ]; then
    echo "ERROR: mediator did not become live in time" >&2
    $COMPOSE logs mediator | tail -40 >&2 || true
    exit 1
  fi
  sleep 2
done

echo "==> /readyz reports component health"
curl -fsS "$MEDIATOR_READYZ" >/dev/null 2>&1 || echo "    (readyz non-200 — acceptable; body carries component health)"

echo "==> did:web document resolves"
did_id=$(curl -fsS "$DIDWEB_URL" | sed -n 's/.*"id"[: ]*"\([^"]*\)".*/\1/p' | head -1)
if [ "$did_id" != "did:web:localhost%3A8080" ]; then
  echo "ERROR: did:web doc id mismatch (got '$did_id')" >&2
  exit 1
fi
echo "    resolved $did_id"

echo "==> SDK round-trip (authenticate + trust-ping) via docker_smoke"
cargo run --quiet -p affinidi-messaging-helpers --example docker_smoke

echo "==> SMOKE PASSED"

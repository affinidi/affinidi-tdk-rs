# Composed test stack (`docker-compose.test.yml`)

A self-contained, language-agnostic environment for exercising the Affinidi
Messaging mediator: **mediator + Redis + a static `did:web` host**, with fixed,
committed **TEST-ONLY** identities so any client (any language) can point at a
known-good target.

> ⚠️ **TEST-ONLY.** Every key and DID below is committed to the repository for
> reproducible testing. **Never reuse them anywhere real.**

## Run it

```bash
# from the repo root
docker compose -f docker-compose.test.yml up --build
```

| Service  | Reachable at                                      | Notes |
|----------|---------------------------------------------------|-------|
| mediator | `http://localhost:7037/mediator/v1/`              | DIDComm v2; liveness `…/livez`, readiness `…/readyz` |
| did:web  | `http://localhost:8080/.well-known/did.json`      | resolves `did:web:localhost%3A8080` |
| redis    | internal only (not published)                     | backing store for the mediator |

Tear down with `docker compose -f docker-compose.test.yml down -v`.

## Fixed identities (TEST-ONLY)

- **Mediator** — `did:peer:2.Vz6Mksfa1ijceFf8yFmTSdRha6Ha2Lzzfuc68UyRAdpsC5pr6.Ez6LShyV6x81XmxvpyDpgwaXo27783iBBJPTeUtDgcvyKLDXP.Sey…`
  (full value in `docker/test/conf/mediator.toml`; DIDComm service endpoint
  `http://localhost:7037/mediator/v1`). Its private keys live in
  `docker/test/conf/secrets.json` (file `://` secrets backend).
- **Admin** — `did:key:z6MkhnJYiMpUGjvedv1eXZziYsFoi6WYRiidWx6EEwvxy3Ed`
  (private key in `secrets.json` / `docker/test/conf/admin-monitor.json`).
- **`did:web`** — `did:web:localhost%3A8080`, served from
  `docker/did-web/.well-known/did.json` (an Ed25519 verification key; resolution
  target only — no private key is published).

The identity is regenerable from the committed recipe:

```bash
cd docker/test
mediator-setup --from mediator-build.toml --non-interactive   # overwrites conf/
```

## Smoke test

`docker/smoke/smoke.sh` brings the stack up, waits for the mediator liveness
probe, checks the `did:web` document resolves, then runs a full DIDComm
round-trip (the `docker_smoke` example generates a fresh user, authenticates,
and trust-pings the mediator):

```bash
docker/smoke/smoke.sh            # up → checks → round-trip → down
KEEP_UP=1 docker/smoke/smoke.sh  # leave the stack running afterwards
```

CI runs this on demand and nightly (not per-PR — the image build is heavy) via
the `compose-smoke` workflow.

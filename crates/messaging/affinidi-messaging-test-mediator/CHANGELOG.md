# Changelog

## Unreleased (0.7.0) — `trust-tasks-rs` 0.20

- Bumps `trust-tasks-rs` 0.19 → 0.20. **No source change** — only manifests.
  0.20 is additive for everything this crate uses: its one breaking change is a
  `process-attestation` schema tightening (digest floor 16 → 43 base64url
  characters, a category correction, a dropped duplicate member), and no crate
  in this workspace references that spec.
- **Moves because it is the path, not because its own code changed.** This crate
  re-exports `affinidi-messaging-sdk`, so a consumer reaching a generated type
  through the facade sees the same API change. Leaving it unbumped would publish
  a move that never arrives — and the version guard cannot see it, because only
  its manifest changed.

## Unreleased (0.5.2) — `forwarding_ws_threshold` so the relay socket can be tested

`TestMediatorBuilder::forwarding_ws_threshold(msgs_per_10s)` sets the rate at
or above which the forwarding processor relays over a WebSocket instead of
REST. Pass `0` to force the socket on the first relayed message.

Without it the WebSocket relay path had no end-to-end coverage and could not
get any. The production default reads as 1 msg/10s, but the rate is measured
over a 300-second window — `total / window * 10` — so a single relayed message
scores 0.03 and every short test silently relays over REST. A test could
therefore assert cross-mediator delivery, pass, and never once exercise the
transport it looked like it was covering.

New `tests/ws_relay_admission.rs` uses it for the two-mediator case, alongside
three raw-socket tests of the receiving side: the anonymous upgrade is admitted
and echoes `relay-ack`, an accepted frame is acked *and* really delivered, a
refused frame comes back nacked with the mediator's error code, and a
non-relay mediator refuses the upgrade outright.

## Unreleased (0.5.1) — no longer depends on `jsonwebtoken`

Support for mediator 0.22.0 (issue #770). The fixture used to build
`EncodingKey`/`DecodingKey` itself and assign them into `SecurityConfig`; it now
generates the Ed25519 PKCS#8 document and hands the bytes to
`SecurityConfig::set_jwt_keys_from_pkcs8`.

The `jsonwebtoken` dependency is **gone from this crate entirely**, which is the
practical proof that it is now private to the mediator: there is no second copy
left to mismatch. `install_default_crypto_provider` delegates to the mediator's
`install_jwt_crypto_provider()` for the same reason — that provider is registered
per `jsonwebtoken` instance, and it is the mediator's copy that verifies tokens.

## Unreleased (0.5.0) — `trust-tasks-rs` 0.18

- Follows `affinidi-messaging-sdk` 0.22.0 and `affinidi-messaging-mediator`
  0.21.0 to `trust-tasks-rs` 0.18. No source change.

## Unreleased (0.4.5) — support for the TSP relay peer allowlist

Support for mediator 0.20.10 (issue #758). No API change; the fixture already
exposed `relay_trusted_mediators` on `TestMediatorBuilder` and `configure_each`
on `TestTopologyBuilder`, which is what the new `tsp_relay_peer_trust` suite
drives.

## Unreleased (0.4.4) — a fixture that can permit direct delivery

Support for mediator 0.20.9, which makes TSP direct delivery honour
`security.local_direct_delivery_allowed` (issue #757). The fixture defaults that
flag **off** — matching the code default for an unset setting rather than the
shipped `conf/mediator.toml`, which sets `"true"` — so 23 TSP tests that had been
written against a path which ignored it now need it on.

- **`TestEnvironment::spawn_with_direct_delivery()`** — the default mediator with
  `local_direct_delivery_allowed = true`. Use it whenever the subject of a test
  is what happens *after* a message is accepted (pickup, streaming, capability
  discovery); without it such a test fails on the policy gate before reaching
  what it is actually asserting.
- **`spawn_with_tsp_auth` and `spawn_with_tsp_policy` now enable direct delivery
  themselves.** Both exist to round-trip a TSP Direct message — pure-TSP
  authentication and `send_to` protocol selection are only observable once a
  message is accepted — so every caller needed it and none of them was testing
  the policy.

`TestEnvironment::spawn()` is unchanged and still defaults the flag off, which is
what lets a test pin the refusal.

## Unreleased (0.4.3) — a test user that is mediated the way production is

- Requires `affinidi-tdk` 0.11 (was 0.10), which re-exports `affinidi-mdoc`
  0.3 / `coset` 0.4. Declaration-only; no source change here.
- New `TestEnvironment::add_tsp_mediated_user` / `TestTopology::add_tsp_mediated_user`:
  a user whose DID advertises a `TSPTransport` service **naming its mediator by
  DID**, which is what a real persona/agent document publishes. `add_user` is
  unchanged and still advertises no TSP service.
- New `tests/tsp_mediated_recipient.rs`: a TSP message crosses two mediators
  where the route names only the recipient, so the sending mediator has to
  discover the transport URL through the recipient's mediator's document. This is
  the gap `tsp_federation.rs` left — that test names the peer mediator's DID *in
  the route*, so the mediator reads a URL straight out of the mediator's own
  document and the indirection is never exercised. Reverting the mediator fix
  reproduces the production `builder error for url (did:…/inbound)` verbatim.
- The mediated user advertises **only** the TSP service: a `did:peer:2` inlines
  each service into the identifier and the mediator's own DID is itself a
  `did:peer:2` carrying three services, so embedding it twice pushes the user's
  DID past the resolver's 1000-byte ceiling — an artefact of `did:peer` that a
  real `did:webvh` persona never approaches.

## Unreleased (0.4.1) — `forwarding_retry_policy` builder knob

- `TestMediatorBuilder::forwarding_retry_policy(max_retries, initial_backoff,
  max_backoff)` overrides the forwarding processor's retry budget. The
  production defaults (5 retries doubling from 1s) put ~31s of real
  `tokio::time::sleep` — inside the processor task, so a paused test clock
  cannot skip it — in front of the abandonment, which is the event an
  abandonment test is waiting for.
- Used by the new `tests/forwarding_abandonment_report.rs`: two real mediators,
  the second taken down before the forward is sent, asserting that the sender
  can `unpack` the resulting problem report under the **default** receive
  policy. A test that only asserted a report was stored would have passed on
  the bug.

## Unreleased (0.4.0) — `trust-tasks-rs` 0.17

- Bumps `trust-tasks-rs` 0.12 → 0.17.
- **Breaking for consumers** for the same reason as `affinidi-messaging-sdk`
  0.21.0: the harness hands back generated types that are now
  `#[non_exhaustive]`, and two `trust-tasks-rs` versions in one graph fail to
  compile.
- The five `QueueLimits` / `MediatorAcl` constructions in
  `tests/trust_tasks.rs` moved to the generated builders. All 14 integration
  tests pass unchanged against the migrated mediator.

## Unreleased (0.3.0) — `trust-tasks-rs` 0.12

- Bumps `trust-tasks-rs` 0.11 → 0.12, and `affinidi-messaging-sdk` to 0.20.
- Minor rather than patch for the same reason as the rest of the family: a
  harness a downstream workspace builds against must resolve one
  `trust-tasks-rs`, so consumers move in lockstep.
- Carries the mediator's new `ping` freshness bounds — a test that mints a
  document with a badly skewed `issuedAt`, or an `expiresAt` at or before it,
  will now see `malformedRequest`.
## Unreleased (0.2.53) — dependency refresh

- Bumps `base64` 0.22 → 0.23.
- Bumps `tokio-tungstenite` 0.29 → 0.30.
- No source or API change; the bumps are declaration-only and the crate
  compiles unmodified against them. Bumped workspace-wide in the same
  change so no two versions of these crates are compiled side by side.

## [0.2.52] - 2026-08-19

### Changed

- **Track `trust-tasks-rs` 0.11.0**, up from 0.9.0. Both releases in between are
  additive — new task families, no change to any type this crate uses — so
  nothing here had to move but the requirement:

  - **0.10.0** added the `vta/contexts/*` and `vta/webvh/*` families (the
    did:webvh lifecycle: DIDs, hosting servers, agent names) and the eight
    `vta/services/*` families that supersede a VTA's `/services/*` REST routes.
  - **0.11.0** corrected two of those `vta/services/*` schemas after writing the
    handlers found them unable to express the operation: rollback can
    legitimately publish no log entry, and disable takes a drain window the
    agent may refuse to honour.

  The reason to take it here is that a VTA cannot: `vta-sdk` must speak the same
  `trust-tasks-rs` these crates do, because `acl_setup` builds a `MediatorAcl`
  and hands it to `TrustTasks::account_update`. Two semver-incompatible copies
  make that a type error, so the VTA stays on 0.9 until this workspace moves.



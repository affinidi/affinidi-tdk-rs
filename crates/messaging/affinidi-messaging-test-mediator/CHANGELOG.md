# Changelog

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



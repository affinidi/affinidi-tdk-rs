# Changelog

## [0.36.0] - 2026-11-15

TSP-multiplexed live path: ack after the handler, TSP frames in the in-flight record

Behaviour changes for consumers (R3.6) are marked **Behaviour**; read them
before upgrading. Requires `affinidi-messaging-sdk` 0.49.2.

- **Behaviour (#1150, R1.6):** a listener with TSP enabled (`tsp` feature,
  `Protocols::TSP_ONLY` or `BOTH`) now pulls live frames without acking them
  and acks each one only after its handler returns, as the DIDComm-only live
  path already did. Before, `live_stream_next_frame(.., auto_delete)` acked
  every frame on receipt, so a teardown between receipt and the handler lost
  it. A frame whose handler is still running when the connection is torn down
  (past `shutdown_drain_timeout`) is now redelivered rather than lost. Handlers
  must already tolerate redelivery (at-least-once).
- **Behaviour (#1150, R1.7):** live TSP frames are claimed in the record of
  mediator ids the live stream and the offline drain share, keyed by
  `InboundFrame::ack_id()` (sha256 of the stored frame, the same id the
  offline drain's delivery attachment carries). A TSP frame the live stream is
  handling, or acked a moment ago, is no longer dispatched a second time by the
  offline drain.
- **Behaviour:** on the multiplexed live path a frame no handler here will take
  — a DIDComm frame on a TSP-only listener, a TSP frame with no `TspHandler`,
  a TSP frame that does not decode, or an unknown frame kind — is acked at once
  regardless of `auto_delete`, as the offline drain already did. Before, with
  `auto_delete = false`, only the first of these was acked. A handled frame is
  still acked only with `auto_delete`.

## [0.35.1] - 2026-11-15

Workspace lint and dependency housekeeping. No API or behaviour change.

- Dependency versions now come from the root `[workspace.dependencies]`
  for the external crates shared by five or more workspace members
  (#1070). The published manifest still names concrete requirements; the
  resolved dependency graph and every feature selection are unchanged.
- Now inherits the workspace lints (`[lints] workspace = true`, #1064):
  `unsafe_code` is denied and the workspace clippy lints apply.
- Minimum dependency requirements raised to versions already in use across the
  workspace (no new major/minor, Cargo.lock unchanged): `affinidi-did-common`
  0.4.4 -> 0.4.8, `affinidi-messaging-didcomm` 0.15.9 -> 0.15.15,
  `affinidi-messaging-sdk` 0.49 -> 0.49.0, `affinidi-secrets-resolver` 0.5 ->
  0.5.19, `affinidi-tdk-common` 0.7 -> 0.7.2.
- `echo_server` example: format arguments inlined.

## [0.35.0] - 2026-11-15

observable connection state, one owner per message, bounded handlers, enforced config

Behaviour changes for consumers (R3.6) are marked **Behaviour**; read them
before upgrading.

- **Behaviour (#1029, R6.2):** the listener now follows the SDK's
  `ATMProfile::connection_state()` for the life of each connection. When the
  websocket drops, it emits `ListenerEvent::Disconnected { error: Some(..) }`,
  withdraws its connection handle, and emits `Connected` and republishes the
  handle when the SDK reconnects. Before, both were set once at connect and
  never changed. During a reconnect window `send_message`/`send_tsp*` now
  return `NotConnected` and `wait_connected`/`send_message_with_retry` wait.
  Expect more `Disconnected`/`Connected` events than before. If the transport
  task itself ends, the listener ends that connection and its restart policy
  takes over.
- **Behaviour (#1030):** a queued message is dispatched once. The live stream
  and the offline drain share a record of the mediator ids (`sha256_hash`)
  being handled and recently acked, and each skips what the other owns.
  Previously a message whose live handler was still running was dispatched a
  second time by the 30-second offline sync.
- **Behaviour (#1030):** the offline drain honours `auto_delete = false`: it
  no longer acks the messages it handled (frames it drops as undeliverable are
  still acked). Such messages stay queued until the application deletes them
  and are dispatched again on a later sync.
- **Behaviour (#1030):** the offline drain runs its batch's DIDComm handlers
  concurrently and fetches the next batch straight away while full batches
  come back and some were acked, up to 50 per tick. Before, it took one batch
  of 100 per 30 s and ran its handlers one at a time. TSP frames in a batch
  are still handled one at a time, in order.
- **Added (#1030):** `ListenerConfig::max_concurrent_handlers` (default
  `DEFAULT_MAX_CONCURRENT_HANDLERS` = 64; 0 is refused). It bounds the
  handlers running at once across both paths. When all are busy the listener
  stops pulling and the mediator keeps the rest queued. Before, every inbound
  message got its own task with no cap.
- **Added (#1030):** `ListenerConfig::shutdown_drain_timeout` (default
  `DEFAULT_SHUTDOWN_DRAIN_TIMEOUT` = 10 s). On shutdown, `remove_listener` or
  a lost transport, running handlers get this long and are then aborted.
  Their messages were not acked, so the mediator redelivers them.
  `remove_listener` is now bounded too (drain timeout + 5 s). `shutdown()`
  joins listeners concurrently with the same bound, and aborts a listener
  task that outlives it rather than leaving it running detached (it used a
  flat 5 s).
- **Behaviour (#1034):** `RestartPolicy::default()`, and so
  `ListenerConfig::new`/`Default`, is now `OnFailure { max_retries: None,
  backoff: RetryConfig::default() }` (was `Never`). A mediator that is
  briefly unreachable at boot no longer ends the listener for good. Set
  `RestartPolicy::Never` explicitly to keep the old behaviour.
- **Changed (breaking, #1034):** `ListenerState` is `#[non_exhaustive]` and
  gains `Connecting`. `list_listeners` derives it from the live connection
  and the restart loop's exit reason: `Running` only while connected,
  `Connecting` during the first connect, a websocket reconnect or a restart
  backoff, `Stopped` after shutdown/removal, and `Failed` (now actually
  reported) when the restart policy gave up after a failure.
- **Changed (breaking, #1034):** `Protocols`' fields are private. Use the
  constants, `Protocols::new`, and the new `didcomm()`/`tsp()` accessors.
  The empty set can no longer be built.
- **Behaviour (#1034):** `protocols.didcomm` is enforced. A `TSP_ONLY`
  listener drops (and acks) DIDComm frames, live and in the offline drain,
  instead of passing them to the `DIDCommHandler`. A listener with `tsp`
  off likewise drops TSP frames found by the offline drain.
- **Changed (breaking, #1034):** `start`/`start_with_tsp`/`add_listener`
  validate each listener (`ListenerConfig::validate`, new) and fail with
  `DIDCommServiceError::Config` (new variant). A listener that enables TSP in
  a build without the `tsp` feature gets `ConfigError::TspFeatureDisabled`
  (new) instead of being accepted and silently ignored. 0 handler concurrency
  gets `ConfigError::ZeroHandlerConcurrency` (new). `start_with_tsp` in such
  a build logs a warning that its TSP handler will never be called.
- **Deprecated (#1033):** `DIDCommResponse::to`, `to_many` and `from`. A
  response always goes to the authenticated sender, encrypted from the
  listener's DID. These setters only ever rewrote headers, so a receiver
  checking addressing rejected the reply. **Behaviour:** their values are now
  ignored, with a warning when they differ, so the headers match who the
  reply is really for and from. Use `AffinidiMessageService::send_message` to
  reach anyone else.
- **Fixed (#1028), regression test only:** a request without a `thid` that
  arrives through the offline drain is answered with `thid` = its own id. The
  fix shipped in 0.34.0 with SDK 0.49 (#1149), which stopped overwriting the
  message id with the mediator's. A test now covers the handler context and
  the reply.
- New dependency: `affinidi-messaging-core` 0.1.13, for `ConnState`.


## [0.34.0] - 2026-11-15

affinidi-messaging-sdk 0.49; offline sync acks by the mediator's id

- **Changed (breaking):** requires `affinidi-messaging-sdk` 0.49, whose types
  it re-exports. See that crate's changelog for the send/receive behaviour
  changes (R3.6): auto-delete failures no longer fail a receive, websocket
  writes are bounded, enabling a websocket returns the real connect error, an
  unresolvable mediator DID fails profile construction.
- **Fixed (non-`tsp` builds):** the offline sync acknowledged the drained
  batch by each message's `id`. SDK 0.49 no longer overwrites that with the
  mediator's id, so the ack now uses `UnpackMetadata::sha256_hash`, the
  mediator's id for each message. Dispatched messages keep their sender's
  `id`, so a reply threads to the sender. The `tsp` build already acked by
  the attachment id.

## [0.33.0] - 2026-11-15

affinidi-messaging-sdk 0.48 and affinidi-tsp 0.4

- **Changed (breaking):** requires `affinidi-messaging-sdk` 0.48 and
  `affinidi-tsp` 0.4, whose types it re-exports. No source change.


## [0.32.0] - 2026-11-14

affinidi-messaging-sdk 0.47

- **Changed (breaking):** requires `affinidi-messaging-sdk` 0.47
  (`trust-tasks-rs` 0.39, `affinidi-crypto` 0.3), whose types it re-exports.
  No source change.

## [0.31.0] - 2026-11-13

affinidi-messaging-sdk 0.46

- **Changed (breaking):** requires `affinidi-messaging-sdk` 0.46
  (`trust-tasks-rs` 0.38), whose types it re-exports. No source change.

## [0.30.2] - 2026-11-12

no reply to problem reports; error text kept local

Follows 0.30.1 (#1083); merge that first.

- **Behaviour (R3.6):** with no matching route and no fallback, `Router`
  no longer answers a problem report (any `report-problem` version) or a
  message pickup `status`; it logs the type at debug and sends nothing.
  Other unmatched types still get `e.p.msg.bad-request`, now with the fixed
  comment `UNSUPPORTED_TYPE_COMMENT` instead of one that repeats the type.
- **Behaviour (R3.6):** the listener never sends a problem report in reply
  to a problem report, whatever the handler returned, so two services cannot
  keep a pair of reports going.
- **Behaviour (R3.6):** `DefaultErrorHandler` sends `e.p.msg.internal-error`
  with the fixed comment `INTERNAL_ERROR_COMMENT`; the error text is only in
  the warning it logs. Problem report codes are unchanged; a peer that read
  the comment gets the fixed text.
- `PROBLEM_REPORT_TYPE`, `is_problem_report_type` and
  `UNSUPPORTED_TYPE_COMMENT` are re-exported from the crate root.
  `build_problem_report` / `send_problem_report` document that they are not
  for answering a problem report; they are called directly by handlers and
  are not checked (`HandlerContext` does not carry the inbound type).
- `examples/echo_server.rs`'s fallback follows the same rules as `Router`.

## [0.30.1] - 2026-11-12

log names a repeated TSP invite

The debug line for an inbound TSP control message that was not recorded now
also names a copy of an invite already acted on, which
`affinidi-messaging-sdk` 0.45.8 refuses. Log text only.

## [0.30.0] - 2026-11-04

SDK 0.45

Moves to `affinidi-messaging-sdk` 0.45 (`trust-tasks-rs` 0.37). The SDK is a public dependency here, so this crate moves a minor. No source change.

## [0.29.0] - 2026-10-28

SDK 0.44

Moves to `affinidi-messaging-sdk` 0.44 (`trust-tasks-rs` 0.36). The SDK is a public dependency here, so this crate moves a minor. No source change.

## [0.28.0] - 2026-10-27

SDK 0.43

Moves to `affinidi-messaging-sdk` 0.43, whose account types for `account/update` are now the 0.2 ones. The SDK is a public dependency here, so this crate moves a minor.

## [0.27.0] - 2026-10-27

SDK 0.42

Moves to `affinidi-messaging-sdk` 0.42, and takes the Trust Task types from `affinidi_messaging_sdk::tasks` instead of `trust-tasks-rs`, which is no longer a dependency. The SDK is a public dependency here, so this crate moves a minor.

## [0.26.0] - 2026-10-27

SDK 0.41, trust-tasks 0.35

Moves to `affinidi-messaging-sdk` 0.41 and `trust-tasks-rs` 0.35. The SDK is a public dependency here, so this crate moves a minor. No source change.

## [0.25.0] - 2026-10-24

SDK 0.40, trust-tasks 0.34

Moves to `affinidi-messaging-sdk` 0.40 and `trust-tasks-rs` 0.34. The SDK is a public dependency here, so this crate moves a minor. No source change.

## [0.24.0] - 2026-10-22

SDK 0.39, TSP 1.0

Moves to `affinidi-messaging-sdk` 0.39 and `affinidi-tsp` 0.3. With the `tsp`
feature this speaks TSP 1.0 (`YTSP-BAA`) and cannot exchange TSP messages with
a service still on 0.23.x (Rev 3) in either direction — upgrade both ends
together. See `affinidi-tsp`'s changelog. The SDK is a public dependency, so
this crate moves a minor. No source change.

## [0.23.1] - 2026-10-21

did:scid profiles

- **Behaviour:** a `message.from` that differs from the profile DID only by a
  did:scid `src` locator no longer logs a mismatch warning.
- `affinidi-did-common` moves from a dev-dependency to a dependency.

## [0.23.0] - 2026-10-21

SDK 0.38, trust-tasks 0.33

Moves to `affinidi-messaging-sdk` 0.38 and `trust-tasks-rs` 0.33. The SDK is a public dependency here, so this crate moves a minor. No source change.

## [0.22.0] - 2026-10-18

SDK 0.37, trust-tasks 0.32

Moves to `affinidi-messaging-sdk` 0.37 and `trust-tasks-rs` 0.32. The SDK is a public dependency here, so this crate moves a minor. No source change.

## [0.21.1] - 2026-10-14

end-to-end tests moved to affinidi-messaging-mediator

The tests that ran this crate against the embedded test mediator
(`soft_restart_websocket`, `tsp_live_stream`, `tsp_transport_adapter`,
`tsp_invite_then_payload`) moved with the mediator to
[affinidi-messaging-mediator](https://github.com/affinidi/affinidi-messaging-mediator).
The `affinidi-messaging-test-mediator`, `affinidi-tdk`,
`affinidi-messaging-core` and `futures-util` dev-dependencies went with them.
Tests only; nothing a consumer builds changes.

## [0.21.0] - 2026-10-13

SDK 0.36, trust-tasks 0.31

Moves to `affinidi-messaging-sdk` 0.36, `affinidi-tdk` 0.26 and `trust-tasks-rs` 0.31. The SDK is a public dependency here, so this crate moves a minor. No source change.

## [0.20.0] - 2026-10-11

SDK 0.35, trust-tasks 0.30

Moves to `affinidi-messaging-sdk` 0.35, `affinidi-tdk` 0.25 and `trust-tasks-rs` 0.30. The SDK is a public dependency here, so this crate moves a minor. No source change.

## [0.19.0] - 2026-10-11

SDK 0.34, trust-tasks 0.28

Moves to `affinidi-messaging-sdk` 0.34, `affinidi-tdk` 0.24 and `trust-tasks-rs` 0.28. The SDK is a public dependency here, so this crate moves a minor. No source change.

## [0.18.1] - 2026-10-10

test-mediator 0.19 (dev-dependency

The `affinidi-messaging-test-mediator` dev-dependency moves to 0.19. Tests
only; nothing a consumer builds changes.

## [0.18.0] - 2026-10-03

SDK 0.33, trust-tasks 0.27

Moves to `affinidi-messaging-sdk` 0.33, `affinidi-tdk` 0.23 and `trust-tasks-rs` 0.27. The SDK is a public dependency here, so this crate moves a minor. No source change.

## [0.17.1] - 2026-10-02

test-mediator 0.17 (dev-dependency

The `affinidi-messaging-test-mediator` dev-dependency moves to 0.17. Tests
only; nothing a consumer builds changes.

## [0.17.0] - 2026-10-01

SDK 0.32, trust-tasks 0.26

Moves to `affinidi-messaging-sdk` 0.32, `affinidi-tdk-common` 0.7 and `trust-tasks-*` 0.26 (on data-integrity 0.8). Their types (`ATMError`, `TDKProfile`) are in this crate's public API, so it moves a minor. No source change.

## [0.16.0] - 2026-09-30

trust-tasks-rs 0.25

Moves to `trust-tasks-rs` 0.25, with the rest of the `trust-tasks-*` family at 0.25. That release conforms the Trust Task vetting, member and endorsement specs to the DTG Credentials v1 statement and authority credentials (trustoverip/dtgwg-trust-tasks-tf#691). A public dependency moving a minor is breaking, so this crate moves a minor. No source change.

## [0.15.2] - 2026-09-29

a payload sent right behind an invite is delivered

### Fixed

- A TSP payload a peer sends immediately after its relationship invite is no
  longer dropped. The listener handed each inbound frame to its own task with
  nothing ordering them, so the payload could be unpacked before the invite
  was recorded, and the relationship gate (§7.2.2) then discarded it. Only a
  peer's first exchange was exposed. Frames from one sender are now unpacked
  in arrival order: each waits for the previous frame from the same sender to
  be unpacked and, for a control message, recorded. Handlers still run
  concurrently, and frames from different peers never wait on each other.
- A TSP frame that cannot be unpacked, including an application message the
  relationship gate discards, is logged at warn as a dropped frame with the
  reason.

## [0.15.1] - 2026-09-28

test-mediator 0.14 in dev-dependencies

The `affinidi-messaging-test-mediator` dev-dependency moves 0.13 -> 0.14, which
embeds mediator 0.33. Tests only; no source or public API change.

## [0.15.0] - 2026-09-27

trust-tasks-rs 0.24

trust-tasks-rs and trust-tasks-proof 0.23 -> 0.24. A minor rather than a patch, as for 0.21, 0.22 and 0.23: the public API carries generated Trust Task types, so a consumer must move in the same change. 0.24 changes how a `oneOf` branch that uses a compound `not` is generated (trust-tasks-rs #665: `auth/passkey/enroll/invite/update/0.1` and `auth/revoke-session/0.2` become structs with optional members instead of uninhabited enums); this crate uses neither, and trust-tasks-proof is unchanged. Takes SDK 0.30. No source change.

## [0.14.0] - 2026-09-27

SDK 0.29

Carries the messaging crates' removal of the legacy mediator admin surface: a pin on a bumped 0.x crate does not admit its new line, so this crate moves a minor with it. No source change.

## [0.13.0] - 2026-09-26

trust-tasks-rs 0.23

trust-tasks-rs and trust-tasks-proof 0.22 -> 0.23. A minor rather than a patch, as for 0.21 and 0.22: the public API carries generated Trust Task types, so a consumer must move in the same change. 0.23 also resolves a proof's key only when the issuer lists it under the relationship the proof declares (proofPurpose, VTI-KEY-022), so a Trust Task signed with a key its DID document does not list for that purpose is now refused.

## [0.12.1] - 2026-09-25

`sender_did` is the authenticated sender

### Security

- `HandlerContext::sender_did` is now the DID of the message's verified signer,
  else its authcrypt sender (`None` when those differ or nothing authenticated
  the message). It was the plaintext `from`, which the sender chooses. The field
  and its type are unchanged.
- `MessagePolicy::require_sender_did` (and `allow_anonymous_sender(false)`)
  now require such an authenticated sender; a `from` alone no longer
  satisfies them.

### Added

- `handler::authenticated_sender_did(&UnpackMetadata)`.

Built on `affinidi-messaging-sdk` 0.27.2.

## [0.12.0] - 2026-09-23

TSP relationship persistence + ensure

Lets a facade consumer form and persist TSP relationships, which the framework
otherwise could not reach because it builds the ATM internally (design note
`tsp-relationship-recovery.md` in the VTI repo). Both use only the 0.26.5 SDK
already depended on:

- **`ListenerConfig::with_relationship_store(Arc<dyn RelationshipStore>)`** (and
  a `relationship_store` field) — injected into that listener's ATM at build, so
  relationships survive a restart instead of being dropped from an ephemeral
  in-memory store (after which §7.2.2 discards a peer's traffic until it
  re-handshakes). A consumer supplies a `PersistentRelationshipStore` over its
  own `RelationshipKv` backend.
- **`DIDCommService::tsp_ensure_relationship(listener_id, peer_did)`** — forms a
  relationship if absent, **idempotent by state read** (skips when one already
  admits application messages, so it is safe to call at every reconnect and does
  not raise an invalid `SendInvite` once a durable store makes reconnect start
  non-`None`). The invite is routed (§7.2.4). Both are `#[cfg(feature = "tsp")]`.

**trust-tasks-rs 0.22.** A dependency bump with no code change: 0.22 renamed
part of the `persona/*` family, nothing here uses those tasks, and the
messaging specifications these crates do use are unchanged.

It carries a minor rather than a patch because `trust_tasks_rs` types cross
this crate's API — `MediatorAcl` among them — so a consumer combining it with
another `trust-tasks-rs` user has to move in step. A graph holding both
versions does not merely carry a duplicate; it fails to compile on those types.

## [0.10.0] - 2026-09-16

`trust-tasks-rs` 0.21

Dependency move only; no source change. Minor because the handler traits carry
`trust_tasks_rs` types.

## [0.9.0] - 2026-09-15

TSP Rev 3 control messages

- **Handles TSP control messages.** The service had no relationship lifecycle at
  all: invites, accepts and cancels arrived and were discarded as
  non-application traffic. Under Rev 3's §7.2.2 gating that is fatal rather than
  merely lossy — no relationship can ever form, so every application message is
  then refused, and the service goes from lossy to inert. Gating was turned off
  while this was outstanding and is **on again** now that `handle_control` exists
  to complete a handshake.
- Requires `affinidi-tsp` 0.2 / `affinidi-messaging-sdk` 0.22 when built with
  `--features tsp`.

## [0.5.0] - 2026-08-27

`trust-tasks-rs` 0.17

## [0.8.0] - 2026-09-10

`trust-tasks-rs` 0.20

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

## [0.6.0] - 2026-09-06

`trust-tasks-rs` 0.18

- Follows `affinidi-messaging-sdk` 0.22.0 to `trust-tasks-rs` 0.18. No source
  change.

## [0.5.1] - 2026-09-01

`trust-tasks-rs` 0.17

- Requires `affinidi-tdk` 0.11 (was 0.10), which re-exports `affinidi-mdoc`
  0.3 / `coset` 0.4. Declaration-only; no source change here.
- Bumps `trust-tasks-rs` 0.12 → 0.17.
- The one `MediatorAcl` construction in `service/mediator.rs` moved to the
  generated builder — `#[non_exhaustive]` in 0.17, so the
  `..Default::default()` literal no longer compiles.
- **Breaking for consumers** only in that this crate now requires
  `trust-tasks-rs` 0.17; no API or behaviour change here.

## [0.4.0] - 2026-08-26

`trust-tasks-rs` 0.12

- Bumps `trust-tasks-rs` 0.11 → 0.12. No source change; the crate compiles
  unmodified against it.
- Released as a minor bump rather than a patch because `trust-tasks-rs` types
  reach this crate's API surface, so a consumer must move in lockstep — two
  versions in one graph fail to compile rather than warn.
## [0.3.27] - 2026-08-19

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


## [0.3.26] - 2026-08-17

### Changed

- **Track `trust-tasks-rs` 0.9.0** and `affinidi-messaging-sdk` 0.19.8, up from
  0.6.1 / 0.19.7. Version requirements only — the single use here is
  `specs::messaging::account`, whose `v0_1` types are shape-identical across the
  move. See the SDK's 0.19.8 entry for what the three intervening breaking
  releases changed and why this ships as a patch.

## [0.3.25] - 2026-08-14

### Changed

- **Track `trust-tasks-rs` 0.6.1** (from 0.4.0), and move the
  `affinidi-messaging-sdk` requirement to 0.19.7 alongside it. The pairing is
  the invariant 0.3.24 established: a crate declaring both must name the SDK
  version whose public `trust_tasks()` types match its own `trust-tasks-rs`, or
  a resolver can satisfy the manifest with a pair the compiler rejects.

  The two breaking releases in between — an optional `ceremony` member on the
  `TrustTask<P>` envelope (0.5.0) and `DigestMultibase` narrowing to the `z` and
  `u` multibase headers (0.6.0) — reach nothing here: this crate hands
  `trust_tasks_rs::specs::messaging::account` types to `atm.trust_tasks()` and
  builds no envelopes by struct literal. No source changed.

## [0.3.24] - 2026-08-09

### Fixed

- **Require `affinidi-messaging-sdk` 0.19.3, not "0.19".** 0.3.23 shipped asking
  for `^0.19` while itself requiring `trust-tasks-rs` `^0.4.0`. Those two are
  mutually satisfiable by a resolver and mutually incompatible at compile time:
  `trust-tasks-rs` is a public dependency of the SDK's `trust_tasks()` surface,
  and 0.19.2 exposes it as 0.2.x. This crate hands
  `trust_tasks_rs::specs::messaging::account` types to `atm.trust_tasks()`, so
  the pair 0.19.2 + 0.4.0 fails with `E0308`.

  A fresh resolve picks 0.19.3 and compiles — which is why publishing 0.3.23
  succeeded — but a consumer with an existing lockfile pinning 0.19.2, or one
  passing `--precise 0.19.2`, gets the mismatch. The packaged manifest now names
  the minimum SDK carrying the matching `trust-tasks-rs`, so a stale one is
  rejected at resolve time instead of at compile time.

  Same failure mode as `affinidi-messaging-didcomm-v1` 0.1.0's
  `affinidi-messaging-core` requirement (#688).

## [0.3.23] - 2026-08-09

### Changed

- Track `trust-tasks-rs` 0.4.0 (was 0.2.46) and `affinidi-messaging-sdk` 0.19.3.
  This crate uses `trust_tasks_rs::specs::messaging::account` to register with a
  mediator; those types are unchanged across the bump, so no code changed.

  `trust-tasks-rs` is a public dependency of the SDK's `trust_tasks()` surface
  and therefore of this crate's, so a consumer still on `trust-tasks-rs` 0.2.x
  must move to `0.4` in the same change that takes this version. See the
  `affinidi-messaging-sdk` 0.19.3 entry for why this is a patch rather than a
  minor.

## [0.3.22] - 2026-07-30

### Changed

- Track `affinidi-messaging-sdk` 0.19.0 (secure-by-default `unpack`: the
  configured `UnpackPolicy` is enforced, rejecting non-authenticated wrappings).
  Dependency bump only; no behavioural change in this crate.

## [0.3.21] - 2026-07-29

### Changed

- Startup ACL-mode configuration now sends `messaging/account/update` (the
  `acl` member) instead of the retired `messaging/acl/set`, following the
  `messaging/*` trust-task rationalization (affinidi/affinidi-tdk-rs#667;
  affinidi-messaging-sdk 0.18.65). Same partial-update semantics — only
  `accessListMode` is set, everything else is left unchanged.

## [0.3.20] - 2026-07-19

### Changed

- Bumped the `affinidi-did-common` requirement from `"0.3"` to `"0.4"`.
  No functional change to this crate: `Document` gained a typed
  `also_known_as` field, which is additive.

## [0.3.19] - 2026-07-16

- Ack (delete) live inbound messages only AFTER the handler has processed them,
  not on receipt (D1-F5, R1.6/R1.7). `process_next_message` used
  `live_stream_next(auto_delete = true)`, which deleted the mediator's copy the
  instant the frame arrived — then dispatched the message to the handler in a
  *spawned* task. A teardown (or crash) between the delete and the handler
  running lost the message permanently, since the mediator had already dropped
  it. The live path now pulls with `auto_delete = false` and acks via
  `delete_message_background` inside `dispatch_message`, once the handler has had
  the message; a teardown before that leaves the message queued for redelivery
  on the next pickup instead. The operator's `auto_delete = false` opt-out is
  honoured (no ack at all). Behaviour is otherwise unchanged: the offline-sync
  drain already batch-acked after dispatch, and the TSP-multiplexed live path is
  unchanged (its ack-after-handoff lands with TSP conformance). Failed acks are
  non-fatal — the message is redelivered and de-duplicated by the receiver.

## [0.3.18] - 2026-07-16

- Keep the caller-seeded DID resolver across listener restarts (D1-F4).
  `Listener::connect()` runs on every iteration of the restart loop
  (`restart::run_with_restart`), but it consumed the pre-seeded `TDKConfig`
  with `Option::take()` — leaving the field `None`, so every retry after the
  first fell back to a cold `TDKConfig::headless()` and lost the caller's
  DID resolver and its warm cache. It now `clone()`s the config instead; both
  `TDKConfig` and its `DIDCacheClient` are `Arc`-cheap clones that share the
  same underlying resolver state, so every reconnect keeps the warm resolver.
  Behaviour-preserving for the first connect; fixes the degraded-resolution +
  extra cold-resolver cost on every subsequent reconnect.

## [0.3.16] - 2026-07-03

- Fix a TSP poison-loop in the offline-sync poller. `AffinidiMessageService` runs a periodic
  offline/backlog drain (`run_periodic_offline_sync`, every 30s) alongside the TSP-aware live
  loop, but that drain was DIDComm-only: it blindly `atm.unpack()`d every queued message, so
  a queued **TSP** frame failed to unpack ("Cannot parse message as JSON") and — never being
  acked/deleted — was redelivered every 30s forever. The drain is now TSP-aware: it fetches
  the backlog via the new `send_delivery_request_frames`, routes TSP frames to the same
  `TspHandler` the live loop uses, dispatches DIDComm frames as before, and acks **all**
  fetched frames (including undeliverable ones) so nothing loops. `tsp`-feature only; the
  DIDComm-only path is unchanged.

## [0.3.15] - 2026-07-02

- Fix inbound TSP: `dispatch_tsp` handed the **qb64** pickup string (`base64url(qb2)`, `-E…`
  text) straight to `atm.tsp().unpack_bytes`, which expects **decoded qb2** — so every
  multiplexed inbound TSP frame failed with `couldn't parse TSP envelope: missing -E
  envelope wrapper` and was dropped. Use `atm.tsp().unpack` (decodes base64url first),
  matching the mediator round-trip tests. The raw-TSP `connect_websocket` path already
  yields decoded qb2 and is unaffected. This is what made a TSP Trust-Ping to a VTA fail
  end-to-end even with the listener correctly in `Protocols::BOTH`.

## [0.3.14] - 2026-07-02

Symmetric TSP replies (ADR 0005 stage 6). `TspHandler::handle` now returns
`Result<Option<TspResponse>, DIDCommServiceError>` instead of `Result<(), _>`, mirroring
`DIDCommHandler`: return `Ok(Some(TspResponse::new(bytes)))` and the service seals the reply
to the authenticated `sender_vid` and routes it back over the *same* shared mediator socket
(no second connection, no consumer-side outbound plumbing). Routing rule: `send_routed(
[profile_mediator_did, sender_vid])` when the listener profile has a mediator, else a TSP
Direct `send` fallback. `Ok(None)` keeps the previous one-way (fire-and-forget) behaviour;
cross-mediator replies remain a consumer concern via `AffinidiMessageService::send_tsp_routed`.

**Breaking**: existing `TspHandler` implementors must change their return type (`Ok(())`
→ `Ok(None)`, or return `Ok(Some(..))` to reply). `IgnoreTspHandler` now returns `Ok(None)`.
`tsp`-feature only; default builds are source-compatible. New `TspResponse` type re-exported
from the crate root.

## [0.3.12] - 2026-06-30

Fixes the publish-verify failure that has blocked the release pipeline since the listener
multiplex landed. The `Listener::tsp_handler` field is only read by `process_next_frame`,
which is `#[cfg(feature = "tsp")]`; `cargo publish` verifies the packaged tarball with
**default features** under `-D warnings`, where the field is set but never read, so the
`dead_code` lint became a hard error (`field tsp_handler is never read`). Gated the lint
with `#[cfg_attr(not(feature = "tsp"), allow(dead_code))]`. No behaviour change; the `tsp`
build is unaffected.

## [0.3.8] - 2026-06-24

Migrated `set_acl_mode` off the deprecated `atm.mediator()` methods onto
`atm.trust_tasks().acl_set` (a non-admin self-service ACL change, now supported by the
mediator). The Trust Tasks partial-update model replaces the previous read-modify-write
(no `account_get` / `MediatorACLSet` decode needed). Dropped the `#![allow(deprecated)]`.

## [0.3.7] - 2026-06-24

Allows the now-`#[deprecated]` legacy `atm.mediator()` methods it still calls
(`#![allow(deprecated)]` in `service/mediator.rs`) so the build stays clean under
`-D warnings`. No behaviour change; migration to `atm.trust_tasks()` is a follow-up.

## [0.3.6] - 2026-06-14

### Changed

- `TransportError`, `StartupError`, and `DIDCommServiceError` are now
  `#[non_exhaustive]` (ADR-0003) so new variants land additively. Patch bump
  keeps the `0.3` pin valid; match them with a `_` wildcard arm. No behaviour
  change. (W7 sweep)

## [0.3.5] - 2026-06-10

### Fixed

- Listener now tears down its websocket transport (`stop_websocket`) on
  terminal exit — shutdown, `RestartPolicy::Never`, or exhausted
  `OnFailure` retries — not only on the reconnect path. The SDK websocket
  runs as an independent, self-reconnecting spawned task with no `Drop`
  hook, so dropping the listener's `ATM`/profile previously left it alive.
  In an in-process service teardown (e.g. a host's *soft restart*, where
  the process keeps running) the orphaned socket kept reconnecting to the
  mediator while the newly-started service opened a second channel for the
  same DID, producing an endless `w.websocket.duplicate-channel` flood.

## [0.3.3] - 2026-06-01

### Changed

- Offline sync no longer logs a misleading `Offline sync failed ... No
  response from API` warning when a websocket reconnect (e.g. the mediator
  closing the socket on access-token expiry) aborts an in-flight poll. The
  reconnect race is now recognised via `ATMError::Disconnected` and logged
  at `debug` ("Offline sync skipped: websocket reconnecting"); it self-heals
  on the next 30s cycle. Genuine failures still warn. Bumps
  `affinidi-messaging-sdk` to 0.18.5.

## [0.3.2] - 2026-05-31

### Changed

- Bump `affinidi-messaging-didcomm` to 0.14 (DIDComm v2.1 interop fixes:
  ECDH-1PU authcrypt KDF #322, JWS unprotected `kid` #323,
  sign-then-encrypt unpack #324). No service API change.

## [0.3.0] - 2026-05-02

### Breaking

- Migrated to `affinidi-tdk-common` 0.6 and `affinidi-messaging-sdk` 0.17.
  Both upstream bumps are SemVer-breaking, so this crate's public API is
  re-exported through the new types.
- The `connect()` retry path no longer falls back to
  `TDKSharedState::default().await` (removed upstream). It now requires a
  `TDKConfig` (either supplied via `ListenerConfig.tdk_config` or built
  internally with `with_load_environment(false) / with_use_atm(false)`).
  Initialisation failures now surface as `TDKError` instead of silently
  panicking.
- `ListenerConfig` literals using `TDKProfile { ... }` must switch to
  `TDKProfile::new(...)` — the `secrets` field is `pub(crate)` in
  tdk-common 0.6.

## [0.2.3] - 2026-04-25

### Fixed

- `Listener::run_with_restart` now races the cancellation token against `connect()` and the inter-attempt backoff sleep. Previously a listener whose mediator was unreachable could take a full backoff window (up to `max_delay_secs`, default 60s) to honour shutdown.
- `DIDCommService::wait_connected` now races the service's internal shutdown token in addition to its timeout. A `Ctrl-C` arriving during a startup wait returns `NotConnected` immediately rather than parking the caller through the full timeout.
- `DIDCommService::shutdown` now actually awaits each listener task's `JoinHandle` (with a 5-second per-task outer timeout) instead of `await`ing already-cancelled child tokens that resolved instantly. Listener tasks are guaranteed to have returned (or the timeout to have fired) when `shutdown()` returns.

### Added

- `DIDCommService::wait_connected_with_cancel(listener_id, timeout, cancel)` — overload that races against a caller-supplied `CancellationToken` for callers that own their own shutdown signal.

## [0.2.1] - 2026-04-15

### Fixed

- Reject duplicate DID listeners: `add_listener()` and `start()` now return `DuplicateDid` error when attempting to register a listener with a DID that is already in use by another listener, preventing mediator connection conflicts.

## [0.2.0] - 2026-04-13

### Added

- `DIDCommService` now implements `Clone` — eliminates the need for `Arc<DIDCommService>` wrappers since the struct is already cheaply cloneable (all fields are `Arc`-wrapped internally).
- `DIDCommService::wait_connected(listener_id, timeout)` blocks until a listener has established its mediator connection, eliminating the race between `start()` and first `send_message()`.
- `DIDCommService::send_message_with_retry(listener_id, message, recipient_did, max_retries, initial_backoff)` retries on `NotConnected` errors with exponential backoff, using `wait_connected` between attempts.
- `DIDCommService::listener_did(listener_id)` returns the DID associated with a listener for self-contained outbound message building.
- `DIDCommService::subscribe()` returns a `broadcast::Receiver<ListenerEvent>` for listener lifecycle notifications.
- `ListenerEvent` enum with `Connected`, `Disconnected { error }`, and `Restarting { attempt, delay }` variants, emitted as listeners connect, fail, or restart.
- `ListenerConfig::new(id, profile)` constructor — takes the two required fields and defaults the rest.
- `HandlerContext::listener_id` field — handlers can now identify which listener received the message.
- `Debug` derive on `DIDCommResponse`, `DIDCommServiceConfig`, `ListenerConfig`, `RestartPolicy`, `RetryConfig`.
- `PartialEq` derive on `ListenerEvent`, `ListenerState`, `ListenerStatus`.
- `MiddlewareResult` type alias is now publicly exported.
- Specific error variants `MessageAlreadyExtracted`, `MetadataAlreadyExtracted`, `ExtensionNotFound`, `InvalidRoutePattern` — replacing generic `Internal(String)` for known error conditions.
- Documentation on `DIDCommResponse` explaining auto-fill behavior for `from`, `to`, `thid`, `pthid`.

### Changed

- **Breaking:** `DIDCommService::shutdown()` now takes `&self` instead of consuming `self`, making it compatible with shared ownership patterns (`Arc`, cloned instances).
- **Breaking:** `ErrorHandler::on_error()` is now `async` and returns `Option<DIDCommResponse>`. The default error handler now sends a problem report back to the sender instead of silently dropping the error.
- **Breaking:** `HandlerContext` has a new `listener_id: String` field.

## [0.1.5] - 2026-04-13

### Added

- `DIDCommService::send_message()` for sending proactive (unsolicited) DIDComm messages through an existing listener's mediator connection, avoiding duplicate websocket sessions.
- `NotConnected` error variant returned when attempting to send through a listener that hasn't established its mediator connection yet.
- Warning log when `message.from` doesn't match the profile DID, which would cause recipients to reject the message.
- Unit tests for `send_message` error paths (`ListenerNotFound`, `NotConnected`) and connection handle lifecycle.

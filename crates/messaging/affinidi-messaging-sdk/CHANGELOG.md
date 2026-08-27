# Changelog

## Unreleased (0.21.0) — `trust-tasks-rs` 0.17

- Bumps `trust-tasks-rs` 0.12 → 0.17.
- **Breaking for consumers.** 0.17 marks the generated payload, response and
  component types `#[non_exhaustive]`. This crate's public API carries them —
  `TrustTasks::account_update` takes an `account::update::v0_1::MediatorAcl` —
  so a consumer that builds one with a struct literal, with or without
  `..Default::default()`, no longer compiles and must use the generated
  builder. A consumer must also move to 0.17 in the same change: two
  `trust-tasks-rs` versions in one graph do not merely warn, they fail with
  `expected MediatorAcl, found a different MediatorAcl`.
- The twelve payload constructions in `protocols/trust_tasks.rs` moved to
  builders behind one `payload()` helper. No wire change and no behaviour
  change: the same members are set, and the only new failure mode is a
  builder left missing a required member, which every call site sets.

## Unreleased (0.20.0) — `trust-tasks-rs` 0.12

- Bumps `trust-tasks-rs` 0.11 → 0.12.
- **Breaking for consumers, despite no source change here.** This crate's
  public API carries `trust-tasks-rs` types — `TrustTasks::account_update`
  takes an `account::update::v0_1::MediatorAcl` — so a consumer must move to
  0.12 in the same change. Two `trust-tasks-rs` versions in one graph do not
  merely warn; they fail to compile with `expected MediatorAcl, found a
  different MediatorAcl`.
- No behaviour change in this crate.
## Unreleased (0.19.12) — dependency refresh

- Bumps `base64` 0.22 → 0.23.
- Bumps `tokio-tungstenite` 0.29 → 0.30.
- No source or API change; the bumps are declaration-only and the crate
  compiles unmodified against them. Bumped workspace-wide in the same
  change so no two versions of these crates are compiled side by side.

## Unreleased (0.19.11) — drop the unmaintained `rustls-pemfile`

- SSL certificate loading in `config.rs` now parses PEM with
  `CertificateDer::pem_reader_iter` from `rustls-pki-types`, which `rustls`
  already re-exports as `rustls::pki_types`. The `rustls-pemfile` dependency is
  removed; it is archived and unmaintained (RUSTSEC-2025-0134), and its final
  release is a thin wrapper over exactly this code.
- No new dependency and no behaviour change: the same certificates parse into
  the same `CertificateDer` values.

## [0.19.10] - 2026-08-22

### Fixed

- **The websocket close frame is no longer discarded.** It was matched as
  `Message::Close(_)` and answered with
  `debug!("WebSocket connection closed by server")`, so the mediator's only
  chance to say *why* it closed a socket was dropped on the floor.

  That is the client half of the mediator's 0.18.21 fix, and without it that fix
  would be inert: a deliberately refused connection was indistinguishable from a
  dropped one, so the reconnect loop simply ran again. Two app instances sharing
  a DID duelled indefinitely and the user was shown a network error.

  The close code and reason are now logged at **WARN**. A server that closed us
  on purpose is the one disconnect an operator needs to see, and the text is the
  difference between "check your network" and "you have this open twice".

  Reconnect behaviour is unchanged.

## [0.19.9] - 2026-08-19

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


## [0.19.8] - 2026-08-17

### Changed

- **Track `trust-tasks-rs` 0.9.0**, up from 0.6.1. Three breaking releases sit
  in between, none of which reaches this crate's source:

  - **0.7.0** made `StandardCode` `#[non_exhaustive]`. Nothing here matches on
    it, so no arm had to be added — and this is the last time a new framework
    error code will break a downstream `match`.
  - **0.8.0** added `StandardCode::Cancelled` and the `trust-task-control/0.1`
    payloads, and moved emitted error documents to `trust-task-error/0.5`.
    Additive on the Rust side because of the attribute above.
  - **0.9.0** gave `consume_inbound` a required `PayloadPolicy` argument
    (SPEC.md §7.2 item 2) and replaced `ValidatedPayload::SCHEMA_JSON` with
    `Payload::PAYLOAD_SCHEMA`. This crate calls neither: it builds documents
    through `TrustTask::for_payload` / `respond_with` and decodes replies
    directly, so only the version requirement moved.

  The `v0_1` payload types the `trust_tasks()` surface returns — `ping`,
  `account`, `acl`, `access_list`, `audit`, `config` — are shape-identical
  across the move. What changes is which crate version provides them.

  It ships as a patch rather than a minor, for the reason 0.19.2 and 0.19.7
  both give: consumers require `affinidi-messaging-sdk` `^0.19` and resolve it
  from the registry, so a 0.20 would pull a second registry copy of this crate
  into their graphs — the exact defect this bump exists to remove, relocated one
  crate over. The cost is unchanged and still worth stating: `trust-tasks-rs` is
  a public dependency of the `trust_tasks()` surface, so this is
  **source-breaking for a consumer still on `trust-tasks-rs` 0.6.x** despite the
  patch version. Move that pin in the same change.

## [0.19.7] - 2026-08-14

### Changed

- **Track `trust-tasks-rs` 0.6.1**, up from 0.4.0. Two breaking releases sit in
  between. 0.5.0 added an optional `ceremony` member to the `TrustTask<P>`
  envelope, which breaks struct-literal construction and exhaustive
  destructuring but nothing else. 0.6.0 narrowed `DigestMultibase` to the two
  multibase headers W3C Controlled Identifiers 1.0 §2.4 normatively requires —
  `z` (base58btc) and `u` (base64url-no-pad) — and enforces each alphabet
  rather than assuming it, so values previously accepted (base32, base16,
  base64pad, and strings that were never valid base58) now fail to parse.

  Neither reaches this crate: documents are built through
  `TrustTask::for_payload` / `respond_with` rather than by struct literal, and
  no source changed beyond the version requirement.

  It ships as a patch rather than a minor, for the reason 0.19.2 gives: consumers
  require `affinidi-messaging-sdk` `^0.19` and resolve it from the registry, and
  a 0.20 would pull a second registry copy of this crate into their graphs. The
  cost is that `trust-tasks-rs` is a public dependency of the `trust_tasks()`
  surface, so this is **source-breaking for a consumer still on `trust-tasks-rs`
  0.4.x or 0.5.x** despite the patch version.

## [0.19.6] - 2026-08-14

### Fixed

- **A torn-down profile no longer spins the inbound stream forever.** The
  inbound poll loop treated every error as transient, backed off 500ms and
  retried — for the life of the process. That is right for a socket
  reconnecting, but `ATMError::ProfileError` means the profile has no mediator,
  or its `ws_channel_tx` slot is empty, and that slot is only ever emptied by an
  explicit teardown (`stop_websocket` / `cleanup_failed_websocket`). A reconnect
  happens *inside* the transport task and keeps the same command sender, so
  nothing short of a fresh `profile_enable_websocket` can refill it — and that
  installs a new transport with a new stream anyway.

  The result was a 2Hz poll against a transport that would never come back, each
  attempt logging `WebSocket channel not set for profile <did>`: roughly 172,000
  warnings a day, per leaked profile, drowning every other line in the log.
  Observed in the trust registry, whose startup fetches its identity from a VTA
  over an ephemeral `did:key` session; the session is shut down when the fetch
  completes, and its inbound stream outlived it.

  A terminal error now ends the stream. The delivery layer's forwarder task
  (`while let Some(item) = stream.next()`) retires cleanly when it does, so the
  dead transport stops pumping while every other transport is unaffected.

- **An inbound TSP frame that cannot be unpacked is now deleted instead of being
  redelivered forever.** This stream polls with `auto_delete = false`, so the
  mediator holds its copy until the consumer acks after a durable handoff. But a
  frame that fails to unpack never becomes an `Inbound`, so it never reaches the
  delivery layer that would ack it — and the ack handle was computed and then
  dropped on the floor. Every reconnect and every restart redelivered it, so one
  sender whose DID no longer resolves became a permanent boot-time error on the
  receiving node, indefinitely.

  Unpack failures are now classified the way the trust registry classifies the
  same failure, so both ends of a TSP hop agree on what "transient" means: a
  resolution or network fault is retried in-process (3 attempts, 200ms doubling
  to 800ms) rather than costing a frame we still hold, while bytes that can
  never decrypt or parse are not retried at all. A frame that exhausts the
  budget — or that was poison to begin with — is deleted from the mediator and
  logged at error level with the frame id.

  The retry budget is deliberately tight because the inbound stream is
  sequential: every retry stalls all other inbound traffic for that profile. The
  tradeoff is stated plainly at the call site — a resolver outage lasting longer
  than the budget will discard a frame that would have been valid, which is why
  the delete is an auditable error line rather than a silent drop.

## [0.19.5] - 2026-08-11

### Fixed

- **A TSP frame now names itself in a build without the `tsp` feature, instead
  of surfacing as a JSON parse error.** Recognising a TSP frame and processing
  one are different jobs, but classification lived behind the `tsp` feature
  alongside the machinery. A build without it therefore did not merely fail to
  *handle* a TSP frame — it failed to *recognise* one, handed the CESR bytes to
  the DIDComm unpacker, and reported

  ```text
  Error unpacking message: DidcommError("Cannot parse message as JSON",
  "invalid number at line 1 column 2")
  ```

  CESR qb64 opens with `-`, which `serde_json` reads as the start of a number,
  hence the column-2 failure. Nothing in that message names TSP, names the
  missing feature, or suggests the frame was well-formed and simply unreadable
  by this build.

  This was found downstream: a VTC advertising `#tsp` in its DID document, built
  without the feature, accepted every community join and recorded none. Senders
  saw success — the frames were delivered, just never decoded.

  Two `#[cfg(not(feature = "tsp"))]` warnings written for exactly this case could
  never fire, because both sit *downstream* of classification —
  `transport_adapter::tsp_to_inbound`'s fallback is reached only after a frame
  has been tagged TSP, which was the gated step. Its doc comment read "a
  DIDComm-only build never advertises TSP, so this is unreachable in practice";
  a build does not control what its operator's DID document advertises.

  Classification now lives in the new `tsp_wire` module and is compiled into
  **every** build — it inspects one leading byte and needs no TSP machinery.
  Unpacking still requires the feature; the difference is that a build lacking
  it now says so by name. Three paths improve:

  - the live websocket transport tags the frame as packed rather than feeding it
    to the DIDComm unpacker;
  - `transport_adapter::tsp_to_inbound`'s non-`tsp` arm is now reachable and
    logs at ERROR, naming the transport, why this build cannot read it, and both
    remedies (rebuild with `--features tsp`, or stop advertising `TSPTransport`);
  - the DIDComm-only pickup path (`_handle_delivery`) identifies a TSP
    attachment and purges it as undeliverable-by-name, rather than as a failed
    DIDComm unpack.

  No behaviour change for a build **with** `tsp`: classification is byte-for-byte
  the same test, and `TspOps::is_tsp` now delegates to the shared implementation
  so the gated and ungated answers cannot disagree. `tsp_wire::TSP_MAGIC_BYTE`
  is pinned to `affinidi_tsp::TSP_MAGIC_BYTE` by a test that compiles under the
  feature, and a second test asserts the two classifiers agree on real frames, so
  the copy cannot drift.

  The regression guard is
  `transports::websockets::websocket::tests::a_tsp_frame_is_delivered_packed_in_every_build`,
  which compiles in **every** feature configuration. Re-introducing a
  `#[cfg(feature = "tsp")]` around the classification fails the default build —
  verified by mutation. Notably, that same mutation still *passes* with `tsp`
  enabled, which is exactly how the original defect survived: every TSP-focused
  test run has the feature on, so no existing test could have caught it.

### Added

- `tsp_wire::{looks_like_tsp, TSP_MAGIC_BYTE}`, re-exported at the crate root.
  Lets any consumer — including one built without `tsp` — tell a TSP frame from
  a DIDComm one without pulling in the TSP stack.

## [0.19.4] - 2026-08-10

### Fixed

- **A poll in flight no longer blocks `stop_websocket`, so shutdown is prompt.**
  The four `live_stream_next*` entry points in `message_pickup` took a **read**
  guard on `Mediator::ws_channel_tx` to get the command sender and then held it
  across the wait for a frame. `stop_websocket` takes the **write** guard on that
  same lock, so any teardown with a poll parked had to wait the poll out.

  For the delivery layer that is `INBOUND_POLL_WAIT`, 10 seconds — its inbound
  pump issues a read-ahead after every frame, so a consumer whose work finished
  mid-window paid the remainder on exit. A CLI felt this as a fixed pause after
  every command: the result printed, then up to 10s of nothing before the process
  left. For a `wait: None` caller it was worse — that sleep is `Duration::MAX`,
  so the read guard was held until a frame arrived, and a shutdown could block
  indefinitely.

  The sender is now cloned out and the guard dropped before the wait. `mpsc::Sender`
  is `Clone`, so this costs nothing and the poll behaves identically; only the
  lock is released earlier. No API change.

  Covered by `profiles::tests::a_poll_in_flight_does_not_block_stop_websocket`,
  which parks a 120s poll and asserts `stop_websocket` still returns within 2s.

## [0.19.3] - 2026-08-09

### Changed

- **Tracks `trust-tasks-rs` 0.4.0 (was 0.2.46). Source-breaking for a consumer
  that also depends on `trust-tasks-rs` 0.2.x, despite the patch version.**
  `atm.trust_tasks()` returns `trust_tasks_rs` types — `TrustTask<R>`,
  `account::update::v0_1::MediatorAcl`, `audit::list::v0_1::Response` and the
  rest — so `trust-tasks-rs` is a *public* dependency of this crate's API.
  Crossing its leading version component changes those types' identity: a caller
  still on 0.2.x gets `E0308` at the call site, not a deprecation warning.

  It ships as a patch because it cannot ship as a minor. `vta-sdk` requires
  `affinidi-messaging-sdk = "0.19"` and resolves it from the registry (it
  deliberately keeps no `[patch.crates-io]`), and this workspace's own mediator
  depends on `vta-sdk`. A 0.20 would therefore pull a *second*, registry copy of
  this crate into the mediator's graph alongside the workspace one — the ADR
  0003 trap. Update in lockstep instead: a consumer moves its own
  `trust-tasks-rs` requirement to `0.4` in the same change that takes this
  version.

- Nothing in this crate is affected by the framework's own breaking changes.
  `TrustTask` gained `parentThreadId` and `ErrorPayload` gained `inResponseTo`,
  both of which only break struct-literal construction — this crate builds
  documents through `TrustTask::for_payload` / `respond_with`. The digest-carrying
  members that became the `DigestMultibase` newtype (`audit`, `chat`, `consent`,
  `policy`, `task-consent`) are not constructed here. `decode_body` deserialises
  whatever the mediator returns without asserting a Type URI, so an older peer's
  documents still parse.

- No wire-format change from this crate. `parentThreadId` is optional and
  omitted when unset, so a request this SDK sends is byte-identical to 0.19.2's
  unless the caller populates it.

## [0.19.2] - 2026-08-08

Dependency-pin bump only; no API or behaviour change.

- Track `affinidi-messaging-core` 0.1.6, which adds `Protocol::DIDCommV1` for
  the new `affinidi-messaging-didcomm-v1` crate and makes `Protocol`
  `#[non_exhaustive]`. This crate's exact-patch pin has to move in lockstep.
  Nothing here matches on `Protocol`, so no code changed.

## [0.19.1] - 2026-08-07

Follow-ups to the AgenticSec review of #671. No API change.

### Security

- **Unsupported signer curves are no longer retried forever (DoS / liveness).**
  `resolve_verify_key` returned a bare `Option`, collapsing two failures with
  opposite retry semantics: *the DID did not resolve* (transient — the network
  or registry may recover) and *the DID resolved but carries no key this build
  can verify with* (deterministic — e.g. a P-384 or P-521 signer, which fails
  identically forever). Both surfaced as the retryable `ATMError::DidcommError`,
  so the message-pickup drain re-queued the deterministic case on **every**
  pickup cycle — the same poison-loop the `VerificationFailed` split fixed for
  bad signatures, still present on this path. The two arms are now distinct: an
  unusable key yields `ATMError::VerificationFailed` (purged), an unresolvable
  DID stays `ATMError::DidcommError` (retried).

- **The authoritative signature is resolved first (resolution-amplification
  reduction).** Under the default policy a signed message is accepted only if a
  *verified* signer matches the inner `from`, so if that signature fails the
  message is rejected regardless of the others — and every resolution spent on
  the others was attacker-directed outbound work for nothing. Signatures whose
  `kid` matches `from` are now visited first, so a message stuffed with
  signatures costs **one** DID resolution instead of `max_signatures` before
  rejection. This reorders *resolution*, not semantics: every signature within
  the cap is still visited and the same signers are recorded.

  This **reduces** the amplification ceiling, it does not remove it. A single
  frame can still drive resolutions across its crypto layers and forward hops
  (`MAX_CRYPTO_LAYERS + MAX_FORWARD_DEPTH`); those are legitimate for a real
  multi-hop message and cannot be cut without changing routing behaviour. Making
  the budget operator-configurable would require adding a field to the public
  `UnpackPolicy`, which is breaking — deliberately deferred rather than bundled
  into a security patch.

- **Tolerated signatures are no longer silent.** With
  `allow_invalid_signatures` enabled, a co-signature that cannot be verified was
  recorded in `UnpackMetadata::unverified_signers` and nothing else — an
  application that keys authorization off co-signature validity had no signal
  its check had been skipped. Every tolerated path now emits a `warn!` naming
  the `kid` and the reason, and says explicitly that the signature must not be
  treated as valid. The authoritative (`from`-matching) signature must still
  verify under `validate_addressing_consistency`, so this remains a *visibility*
  fix, not a policy change.

## [0.19.0] - 2026-07-29

> **BREAKING CHANGE.** `atm.unpack` now rejects non-authenticated envelopes by
> default — it accepts only the authenticated-encryption wrappings
> `authcrypt(plaintext)`, `authcrypt(sign(plaintext))` and
> `anoncrypt(authcrypt(plaintext))`. Because the default
> behaviour changes for every caller, this is a breaking release: the version
> bumps `0.18 → 0.19` (a SemVer minor bump is the breaking increment for a `0.x`
> crate). Restore the previous "accept anything" behaviour explicitly with
> `ATMConfigBuilder::with_unpack_policy(UnpackPolicy { .. })` — see below.
>
> **Also breaking:** `UnpackMetadata` gains two public fields (`wrapping`,
> `signers`), which breaks any struct-literal construction of it downstream. It
> is now sealed with `#[non_exhaustive]`, so future field additions will *not*
> be breaking — external code should read its (public) fields rather than
> construct it, and use `UnpackMetadata::default()` + field assignment if it
> ever needs to build one.

### Rollout across the VTI ecosystem (R3.6)

Publishing `0.19.0` does **not** by itself deliver this fix to the services that
depend on it — a `^0.18` requirement will not resolve to `0.19`. Each consuming
repo has to move its pin deliberately. Pins as observed at the time of writing:

| Repo / crate | How it depends | Picks up `0.19` automatically? |
| --- | --- | --- |
| `verifiable-trust-infrastructure` → `vta-sdk` | `affinidi-messaging-sdk = "0.18"` (direct, optional) | **No** — needs an explicit bump |
| `affinidi-trust-registry-rs` | `affinidi-messaging-sdk = "0.18"` (workspace) | **No** — needs an explicit bump |
| `verifiable-trust-infrastructure` (workspace) | `affinidi-tdk = "0.8"` | ⚠️ **Yes, silently** — via `affinidi-tdk` 0.8.5, a *patch* |
| `affinidi-webvh-service` | `affinidi-tdk = "0.8"` | ⚠️ **Yes, silently** — same |
| `vti-push-gateway` | `affinidi-tdk = "0.7"` | **No** — two minors behind the facade |
| `cierge` | `vta-sdk = "0.20.25"` (transitive) | Only once `vta-sdk` bumps |
| `vti-message-bridge` | `vta-sdk = "0.18"` (transitive) | Only once `vta-sdk` bumps |

**⚠️ The facade delivers this break as a *patch*.** `affinidi-tdk` re-exports
this crate wholesale (`pub use affinidi_messaging_sdk as messaging;`, default-on
feature), so the new acceptance policy and the sealed `UnpackMetadata` reach
every facade consumer — and `affinidi-tdk` can only ship as **0.8.5**, not
`0.9.0`. `vta-sdk` (external, on crates.io, depended on here via the mediator)
pins `affinidi-tdk = "0.8"`, so a minor bump breaks our own
`[patch.crates-io]` redirect and drags duplicate registry copies of
`affinidi-tdk` *and* this crate into the graph. See ADR 0003 point 3 and the
`affinidi-tdk` 0.8.5 changelog.

The practical consequence for rollout: `verifiable-trust-infrastructure` and
`affinidi-webvh-service` will pick up the new `unpack` acceptance policy on a
routine `cargo update`, with **no version signal that anything breaking
happened**. Do not rely on the version number to gate this — schedule those
upgrades deliberately, and pin `affinidi-tdk = "=0.8.4"` in any repo that is not
ready. Unblocking a real `affinidi-tdk` 0.9.0 means releasing a `vta-sdk` that
depends on `affinidi-tdk` 0.9 first.

**Sequencing matters, not just the bumps.** Once `affinidi-tdk` pulls
`affinidi-messaging-sdk` 0.19 while a `^0.18` direct pin resolves to 0.18.x, any
graph holding both (e.g. `verifiable-trust-infrastructure`, which depends on
`affinidi-tdk` *and* on `vta-sdk`) links **two copies of the SDK** and the
`ATMConfig` / `UnpackMetadata` types stop unifying. Move `vta-sdk` and
`affinidi-trust-registry-rs` in the same cascade as the facade, and re-resolve
lockfiles afterwards — publishing an upgrade is not the same as consuming it.

**Do senders pack authcrypt today?** Verified for the main path: `vta-sdk`'s
session transport packs with `pack_encrypted(&msg, vta_did, Some(client_did), …)`
(authcrypt), and the VTA has *required* authcrypt on `/auth/` and `/auth/refresh`
since VTI #771, rejecting anoncrypt outright — so those senders already produce a
wrapping the new default accepts. One caveat to confirm per deployment:
`vta-sdk::didcomm_light` is an **anoncrypt** packer whose output is unpacked by
`ATM::unpack`. It has no remaining in-tree caller (auth moved to `auth_di`), but
the module is still `pub`, so any external caller still packing through it will
start seeing `ATMError::UnexpectedEnvelope` after this upgrade. Such callers
should move to authcrypt, or opt in explicitly with
`with_unpack_policy(UnpackPolicy { expected: vec![MessageWrappingType::AnoncryptPlaintext, ..], .. })`.

**Upgrade tip.** Pair the first deployment with
`with_purge_policy_rejected_messages(false)` and
`with_unprocessable_message_channel(..)` for a bounded window, so anything the
stricter policy rejects is observable and recoverable rather than deleted from
the mediator queue.

### Changed

- **`atm.unpack` is now secure by default (behavioural change).** Unpacking now
  enforces an [`UnpackPolicy`](src/config.rs) whose default accepts only
  authenticated encryption — `authcrypt(plaintext)`, `authcrypt(sign(plaintext))`
  and `anoncrypt(authcrypt(plaintext))` (which additionally hides the sender key
  id from intermediaries) — and enforces message-layer addressing
  consistency: the inner `from` must equal the authcrypt sender key (`skid`)
  DID (and a verified signer's DID when signed). This closes a forged-sender
  authentication-bypass class where a message authcrypted by one key claims
  another party's `from`. Apps that previously reconciled
  `from`/`encrypted_from_kid` themselves can now trust `msg.from` on a returned
  `Ok` and drop that logic.

  Configure via `ATMConfigBuilder::with_unpack_policy(...)`. The policy is an
  explicit allow-list of `MessageWrappingType` values (no `secure`/`permissive`
  presets), so protocols expecting an unauthenticated wrapping (anoncrypt
  receipts or signed-only notifications) list exactly what they accept. The
  same policy governs the message-pickup delivery drain, so messages pulled via
  pickup get the identical secure-by-default guarantees as a direct `unpack`.

### Added

- **Layered (double) envelope unpacking.** `unpack` now iteratively removes
  nested cryptographic layers, so the DIDComm-defined two-layer wrappings —
  `anoncrypt(authcrypt(plaintext))`, `authcrypt(sign(plaintext))` and
  `anoncrypt(sign(plaintext))` — decrypt/verify end-to-end (previously only a
  single encryption layer plus an optional inner signature was handled).
- **Multi-signature verification.** All JWS signatures are now verified (not
  just the first), across Ed25519 / P-256 / secp256k1 signers. Addressing
  consistency requires a verified signer whose DID matches the inner `from`, and
  — for an `authcrypt(sign(plaintext))` message — the authcrypt `skid` must
  match it too, binding `from == signer == authcrypt sender`.
- **Tolerate non-authoritative signatures (opt-in).** By default every
  signature must verify, so a single co-signature you don't control (a missing
  `kid`, an unresolvable signer DID, a curve this build can't handle — e.g.
  P-384, or an invalid signature) makes the whole message undeliverable.
  `ATMConfigBuilder::with_allow_invalid_signatures(true)` keeps unpacking such a
  message and records the offending signers in the new
  `UnpackMetadata::unverified_signers` list instead — the authoritative
  (`from`-matching) signature must still verify under addressing consistency, so
  only *supplementary* co-signatures are relaxed.
- **`UnpackMetadata` additive fields + sealing.** New public fields —
  `wrapping: MessageWrappingType` (the classified envelope combination),
  `signers: Vec<String>` (every *verified* signer `kid`), and
  `unverified_signers: Vec<String>` (signers tolerated by
  `allow_invalid_signatures`; empty in the default strict mode). The struct is
  now `#[non_exhaustive]`: it is a value the SDK *returns* (downstream reads it),
  so sealing it makes future field additions non-breaking. Downstream code that
  built it by struct literal must switch to reading it (or, if it must produce
  one, `UnpackMetadata::default()` + field assignment).
- **Opt-in unprocessable-message channel.**
  `ATMConfigBuilder::with_unprocessable_message_channel(capacity)` enables a
  broadcast channel (subscribe via `ATM::get_unprocessable_message_channel`)
  that receives an `UnprocessableMessage { attachment_id, raw, reason }` for
  every inbound message the SDK can't process. Concretely, a message is sent to
  this channel when it fails to unpack for any reason — an unexpected/rejected
  wrapping (`UnexpectedEnvelope`), an invalid signature (`VerificationFailed`),
  an addressing mismatch (`AddressingMismatch`), too many signatures/recipients,
  or malformed base64/UTF-8 — carrying the attachment id, the raw payload, and
  the failure reason. All three inbound paths — the batch drain, the TSP-aware
  `send_delivery_request_frames` drain, and live WebSocket delivery — report on
  it *before* the message is deleted/dropped, so a consumer can observe or
  quarantine it instead of losing it to a log line. Off by default (unchanged
  behaviour when not configured).
- **Configurable deletion of policy-rejected pickup messages
  (`with_purge_policy_rejected_messages`).** The pickup drain decides deletion
  by *recoverability*. Non-recoverable input — malformed base64/UTF-8, an
  unsupported attachment type, or a cryptographically invalid signature
  (`VerificationFailed`) — is **always** deleted so it can't be redelivered every
  pickup and fill the queue. A message the *policy* rejected — a disallowed
  wrapping (`UnexpectedEnvelope`) or an addressing mismatch
  (`AddressingMismatch`) — is also **deleted by default**, because the mediator's
  per-recipient queue is bounded (a fixed message limit) and a retained reject is
  redelivered every pickup, so it would accumulate and eventually fill the queue,
  blocking new inbound messages. Set
  `ATMConfigBuilder::with_purge_policy_rejected_messages(false)` to *retain*
  policy-rejected messages instead — e.g. for a bounded window during an
  `unpack_policy` tightening/upgrade, so a message rejected only by the stricter
  policy can be recovered by relaxing the policy (accepting that retained rejects
  count against the queue limit). Pair with the channel above to observe what is
  affected. (Review note: an opt-in *purge* was suggested, but the mediator's
  bounded per-recipient queue makes delete-by-default the safe choice — so the
  deletion stays the default and an opt-in *retain* is provided instead.)

### Security

- **Message pickup is now secure by default (no more `accept_all`).** The
  delivery drain unpacks every pulled attachment under the *configured*
  `UnpackPolicy` — the same authenticated-encryption default as `atm.unpack` —
  instead of a permissive "accept every wrapping" policy. An unauthenticated or
  forged-`from` message sitting in the mediator queue is no longer surfaced to
  the application; it is rejected (and purged) exactly as a direct `unpack`
  would reject it. This closes an authentication-bypass gap where the pickup
  transport did not honour the app's secure policy.
- **Unprocessable-message resistance on message pickup.** The delivery drain
  removes messages it can never process so a crafted "poison" message can't be
  redelivered every pickup cycle, fill the bounded queue, and stall it (or, under
  backpressure, the mediator connection). Deletion is split by *recoverability*:
  non-recoverable input — malformed base64/utf8, an unsupported attachment type,
  or a cryptographically invalid signature (`VerificationFailed`) — is **always**
  deleted; a *policy*-rejected message (a disallowed wrapping, too many
  signatures/recipients, an addressing mismatch, a non-conformant envelope) is
  also **deleted by default** — the mediator's per-recipient queue is bounded, so
  a retained reject redelivered every pickup would accumulate and fill it — but
  can be **retained** with `with_purge_policy_rejected_messages(false)` (see
  *Added*) for a bounded window during an `unpack_policy` upgrade, so a message
  rejected only by the stricter policy can be recovered by relaxing the policy.
  Failures that might be *transient* (e.g. a temporarily unresolvable signer DID)
  are always left queued for retry. All three inbound paths —
  `send_delivery_request`, the TSP-aware `send_delivery_request_frames`, and live
  WebSocket delivery — apply this policy and report to the opt-in
  unprocessable-message channel before deleting/dropping.
- **`UnpackPolicy::max_signatures` (default `5`) — bounded signature
  verification.** The policy's signature cap is enforced *before* any signer
  DID is resolved, so a crafted message stuffed with signature entries cannot
  amplify (potentially networked) DID-resolution work: a JWS carrying more than
  `max_signatures` entries is rejected with `ATMError::UnexpectedEnvelope`
  without resolving a single key. The default accepts up to **5** signers; raise
  it to any value your protocol expects (there is no absolute ceiling above your
  policy) or lower it (e.g. `max_signatures: 1`) for single-signer only. Every
  signature within the cap is fully verified.
- **SSRF: an unprotected signer `kid` can no longer steer DID resolution.** The
  signer `kid` selects which DID `unpack` resolves — an outbound HTTPS fetch for
  `did:web` — and is read *before* the signature is verified. When that `kid`
  comes from the per-signature **unprotected** header (`parse_jws`'s interop
  fallback), it sits outside the signing input, so **any intermediary** — a
  mediator, a relay — could rewrite it in transit without invalidating the
  signature and redirect the fetch to a host of its choosing. That is an SSRF
  primitive available to a party who cannot forge a signature at all, and the
  per-message resolution budget bounded only the *count* of such fetches, not
  their *targets*.

  An unprotected `kid` is now resolved only when its DID matches the signed
  payload's `from` — which *is* inside the signing input, so the binding cannot
  be forged in transit. A rewritten `kid` now yields
  `ATMError::UnexpectedEnvelope` **before any outbound request is made** (the
  check runs ahead of the resolution-budget charge, so a refused `kid` costs zero
  fetches). A payload with no readable `from` offers nothing to bind against, so
  an unprotected `kid` is refused there too. A `kid` in the protected header is
  unaffected: it is the original sender's own, integrity-protected choice, and
  resolving a claimed sender's DID is inherent to DID messaging (authcrypt
  resolves the `skid` identically).

  This does not make `unpack` an SSRF sandbox — a sender naming its own
  `did:web` still causes one fetch — so resolver-side host allow-listing remains
  worthwhile as defence in depth.
- **Per-message DID-resolution budget (DoS guard).** The wrapping allow-list is
  necessarily enforced *after* layers are decrypted and signatures verified, and
  each signer/sender key is a DID resolution (an outbound HTTPS fetch for
  `did:web`). A single shared budget now spans every cryptographic layer **and**
  every forward hop of one `unpack` (it is *not* reset per hop), so a frame that
  is ultimately rejected can no longer drive
  `MAX_CRYPTO_LAYERS × MAX_FORWARD_DEPTH × max_signatures` attacker-chosen
  resolutions. The budget scales with `max_signatures` plus headroom for a
  sender key per layer and one resolution per forward hop (default ceiling
  `5 + 2 + 10 = 17` per frame); exceeding it fails with
  `ATMError::UnexpectedEnvelope`.
- **Bounded JWE recipients (DoS guard) + `UnpackPolicy::max_recipients`.** A JWE
  layer addressing more than `max_recipients` (default `100`) recipients is
  rejected before the recipient-matching loop — the same policy-driven bound as
  `max_signatures`, with no separate absolute ceiling above your policy. The
  default is deliberately permissive because a receiver is legitimately one of
  many recipients; decryption runs the key agreement once (for the matched
  recipient), so this bounds parse/allocation cost, not asymmetric-crypto work.
  Lower it (e.g. `max_recipients: 1`) for stricter one-to-one deployments.
- **Anonymous (`anoncrypt`) messages must not claim a `from`.** With addressing
  consistency enabled (the default), a pure `anoncrypt(plaintext)` that declares
  an inner `from` is rejected (`ATMError::AddressingMismatch`): anonymous
  encryption carries no authenticated sender, so a `from` there is an unbacked,
  spoofable claim. `anoncrypt(sign(plaintext))` is unaffected — the signature
  authenticates the `from`, which is preserved under the anoncrypt wrapping.
- **Removed the non-conformant `anoncrypt(authcrypt(sign(plaintext)))` wrapping.**
  The DIDComm v2 spec (§IANA Media Types) explicitly states this combination
  MUST NOT be used (`anoncrypt(sign(plaintext))` covers the same need). The
  `MessageWrappingType::AnoncryptAuthcryptSignPlaintext` variant is removed, and
  `unpack` now rejects the triple layering as `ATMError::UnexpectedEnvelope`.
- **Cryptographic nesting capped at 2 layers.** No DIDComm-defined wrapping
  nests more than two crypto layers, so `unpack` now rejects a third (or deeper)
  JWE/JWS layer *before* removing it (`ATMError::UnexpectedEnvelope`), replacing
  the previous depth-6 guard. This enforces the taxonomy structurally and bounds
  decrypt/verify work against a nested-envelope DoS.
- **Scope note — this hardens the SDK `unpack`, not the mediator's own unpack
  path (follow-up).** The mediator authenticates callers through its separate
  `didcomm_compat` unpack, which this release does not change, so it does *not*
  yet enforce the new layer-ordering `UnpackPolicy` (e.g. rejecting
  sign-outside-encrypt or repeated encryption layers). This is not a mediator
  admin-auth bypass: mediator identity is anchored on the authcrypt sender key
  (`skid`) proven by ECDH-1PU decryption and bound to the authenticated session
  DID (`force_session_did_match`), with the `explicit_allow` gate rejecting
  unknown DIDs — the plaintext `from` is only ever checked *against* that
  cryptographic identity, never trusted on its own. Converging the mediator's
  `didcomm_compat` path onto the same `UnpackPolicy` is a tracked follow-up so
  both unpack paths enforce identical crypto-layer policy.

## [0.18.65] - 2026-07-29

### Changed

- **BREAKING (`trust_tasks()` surface): the `messaging/*` Trust Task family is
  rationalized 19 → 9 tasks** (affinidi/affinidi-tdk-rs#667, trust-tasks-rs
  0.2.46), matching the mediator's clean cutover in 0.17.13 — the retired URIs
  are no longer accepted server-side, so the superseded senders are removed
  rather than deprecated:
  - `account_update(profile, did_hash, account_type, acl, queue_limits)`
    replaces `account_change_type`, `account_change_queue_limits`, `acl_set`,
    `admin_add`, and `admin_strip` (one `account/update` per DID for the old
    batched admin grant/strip).
  - `access_list_update(profile, did_hash, clear, add, remove)` replaces
    `access_list_add`, `access_list_remove`, and `access_list_clear`.
  - `account_list` gains an `account_type: Option<AccountType>` role-filter
    parameter, replacing `admin_list`.
  - `access_list_list` gains an `entries: Option<Vec<String>>` membership-filter
    parameter, replacing `access_list_get` (returned `entries` = the old
    `present`; the remainder of the supplied set = the old `absent`).
  - `audit_list(profile, cursor, page_size)` (generic `audit/list`) replaces
    `admin_audit_log`; `config_show(profile, keys)` (generic `config/show`)
    replaces `admin_config` (the mediator version is the `mediator.version`
    key).

## [0.18.64] - 2026-07-23

### Fixed

- **A slow consumer silently lost packed (TSP) frames.** The packed-frame queue
  added in 0.18.62 sat outside the socket-read backpressure guard, so the only
  way to honour its bound was to discard the oldest frame — and a discarded
  packed frame is unrecoverable, because under delete-on-send the mediator drops
  its copy the moment it writes it. A consumer that stopped polling long enough
  lost messages outright, with a `warn!` as the only trace. Measured: 130 frames
  sent while the consumer idled lost exactly 30 (the amount over the 100-frame
  default limit), oldest first.

  Both inbound caches now share one policy — **back-pressure, never discard**.
  When either queue is full the select loop stops reading the socket; a consumer
  that has stopped consuming stalls its own connection, a visible failure,
  rather than silently losing messages. The packed queue is bounded by the same
  count *and* byte limits as the DIDComm cache. (#655)

## [0.18.63] - 2026-07-23

### Added

- **`connect_websocket_acked` — opt-in delete-to-ack for raw-TSP** (`tsp-ack`
  subprotocol). The mediator sends and keeps; `TspWebSocket::ack` releases its
  copy once you actually hold the frame. Anything un-acked when the connection
  dies is redelivered on reconnect, so consumers **must be idempotent**. The
  message id is derived, not transmitted — `sha256` of the stored body, which is
  the base64url of exactly the bytes on the wire — so no protocol change was
  needed. `is_acked()` reports what was really negotiated: a mediator predating
  the mode echoes the client's subprotocol list unchanged, so a downgrade is
  detected and warned about rather than silently leaving you at-most-once.
  Plain `connect_websocket` is unchanged. (#651)

### Changed

- **`TspWebSocket::recv` surfaces the close reason.** A close frame is now an
  `Err` carrying the mediator's RFC 6455 code and reason ("replaced by a newer
  connection", "authentication token expired", "streaming task unavailable"),
  instead of collapsing every one of them — and a socket that merely went quiet
  — into a bare `Ok(None)`. A stream that ends with no close frame still returns
  `Ok(None)`. (#651)

## [0.18.62] - 2026-07-23

### Fixed

- **Packed (TSP) frames arriving between polls were dropped.** A TSP frame is
  handed back packed and was delivered only if a `Next` request happened to be
  outstanding at that instant or a direct channel was attached; otherwise it fell
  off the end of the function. The DIDComm branch caches an unmatched message,
  but the packed branch had nowhere to put one — `inbound_cache` is keyed by
  unpacked DIDComm message id. A polling consumer always leaves a gap between one
  poll returning and the next being registered, so this was a race it could only
  lose. Packed frames now go to a queue that the next `Next` drains, and every
  arm hands the frame onward rather than dropping it. (#646)

## [0.18.61] - 2026-07-22

### Fixed

- **Reconnect backoff no longer resets on a connection that doesn't survive.**
  `connect_delay` was zeroed the moment a socket connected and the
  live-delivery frame was written; it only escalated on connect *failures*. A
  socket that connects and is then closed by the mediator therefore never
  backed off past the first step. Two clients authenticated as the same DID
  duelling over the mediator's one-socket-per-DID slot each saw
  "connect → success → evicted", pinning both at a ~1s reconnect loop
  indefinitely (observed: ~40 connects/sec sustained against a production
  mediator). A connection must now stay up for 30s — longer than the 20s
  watchdog, so at least one ping/pong completed — before its loss earns an
  immediate retry; anything shorter escalates 1→2→4→…→60s as a connect failure
  always did.

  **Behavioural change:** a client evicted by a duplicate session for its DID
  now reconnects on the backoff ladder rather than instantly. Deployments
  running a single session per DID are unaffected.

- **`graceful_shutdown` now stops websockets first, and cannot hang.** The
  Deletion Handler was stopped first, followed by an *unbounded* wait for its
  `Exit`; the profiles' websocket transports were stopped only afterwards. A
  handler that had already died sent no `Exit`, so shutdown could stall with
  the websocket transports still running — and those auto-reconnect on their
  own timer and hold the mediator's slot for the profile's DID. Callers that
  open a session per refresh cycle accumulated orphaned, reconnecting sockets
  this way. Websockets are now torn down first and the handler drain is bounded
  at 5s.

- **`ATMProfile::stop_websocket` clears the profile's channel slot.** It left
  the stale `Sender` in place, so `profile_enable_websocket` saw a populated
  slot, reported "already connected" and returned `Ok` — leaving a stopped
  profile permanently unable to reconnect. Now idempotent, and a stopped
  profile can be re-enabled.

## [0.18.60] - 2026-07-19

### Changed

- Bumped the `affinidi-did-common` requirement from `"0.3"` to `"0.4"`.
  No functional change to this crate: `Document` gained a typed
  `also_known_as` field, which is additive.

## [0.18.59] - 2026-07-18

- **Fix: `DidCommTransport` dropped every inbound TSP frame** (regression in
  0.18.58's TSP surfacing). The multiplexed pickup socket
  (`live_stream_next_frame`) hands a TSP frame to `tsp_to_inbound` as the
  **qb64** stored string (base64url of qb2 — `-E…` *text*), but the adapter called
  `unpack_bytes(packed.as_bytes())`, which expects raw qb2 and so pushed the ASCII
  `'-','E',…` bytes straight into the CESR parser — failing with `missing -E
  envelope wrapper` and skipping the frame. Every inbound TSP message (e.g. a
  trust-ping) was silently dropped and never answered. Now calls
  `atm.tsp().unpack(profile, packed)`, which base64url-decodes first — matching the
  framework listener's `dispatch_tsp`. TSP-only; the DIDComm path was unaffected.

## [0.18.58] - 2026-07-17

- **`DidCommTransport` now surfaces inbound TSP frames as well as DIDComm.**
  `inbound()` polled `live_stream_next` (DIDComm-only), so a mediator that
  multiplexes DIDComm **and** TSP to one DID (e.g. the VTA) had its inbound TSP
  silently dropped once it moved to the delivery layer. It now polls
  `live_stream_next_frame` and maps each `InboundFrame`: a DIDComm frame as
  before, and a TSP frame (unpacked via `atm.tsp().unpack_bytes`, which
  authenticates the sender VID) into a neutral `Inbound` with
  `protocol = Protocol::TSP`, `sender` = the authenticated VID, `verified =
  true`. The consumer routes by `message.protocol`. TSP unpacking is behind the
  `tsp` feature (a DIDComm-only build skips a stray TSP frame rather than
  dropping the stream). Additive; the DIDComm path and `SendReceipt`/ack
  contract are unchanged. Unblocks the multi-protocol VTA cut-over.

## [0.18.57] - 2026-07-17

- **Fix `DidCommTransport::send` to actually deliver.** It called
  `ATM::send_message`, which only pushes the packed bytes to our own mediator
  without wrapping a DIDComm routing/2.0 `forward` envelope — so a standard
  mediator never routes the message to the recipient and it is silently
  undelivered. (A same-DID self-send happened to round-trip, which is why the
  0.18.53 live check missed it.) `send` now uses `forward_and_send_message`,
  forwarding the packed frame to `dest` (the recipient the delivery layer
  passes) through the profile's mediator. The `SendReceipt`/`hop_id` contract is
  unchanged, but the outbox-drain (§5a) correlation must be re-validated for a
  forwarded frame before a `Guaranteed` flow relies on it. `dest` is no longer
  ignored. Behavioural fix; no signature change.

## [0.18.56] - 2026-07-17

- **`DidCommTransport` now yields a cryptographically-authenticated sender.**
  `to_inbound` set `ReceivedMessage.sender` from the **plaintext `from` header**
  (sender-controlled) and `verified` from `meta.authenticated` alone — so a
  message authcrypted with an attacker's own key but claiming a victim's `from`
  surfaced as `sender = victim, verified = true`. Now `sender` is the DID of the
  key that **actually** authcrypted the envelope (`encrypted_from_kid`), returned
  only when the plaintext `from` matches it; anonymous / unauthenticated / spoofed
  messages yield `sender = None, verified = false`. Consumers can trust
  `sender` + `verified` for authorization without re-deriving the check.
  **Behavioural change** (R3.6): a consumer that read `sender` off a spoofed or
  anonymous message will now see `None`. Additive at the type level; 2 new tests
  (spoof, anonymous) + the mapping test tightened.

## [0.18.55] - 2026-07-17

- **Fix a connect-path deadlock introduced by the truthful-send change in
  0.18.52** (#611). The websocket transport's connection setup enables live
  delivery *from the transport task itself*; since 0.18.52 that call — routed
  through `ATM::send_message` — enqueued a `SendMessage` command into the
  transport's **own** command channel and awaited the write-outcome reply that
  only the (busy) transport task could produce. Every websocket connect
  attempt therefore hung until the caller's timeout, deterministically:
  `profile_add(_, true)` timed out at 10s, and the didcomm-service
  `soft_restart_websocket` CI test failed on every run after 0.18.52 (it was
  mis-filed as a flake). The live-delivery-change frame is now packed via the
  new internal `MessagePickup::packed_live_delivery_change` and written
  directly to the socket the setup code already holds — same message, same
  packing, no round-trip through the command channel. `toggle_live_delivery`
  is unchanged for external callers and still sends through the normal
  (truthful) transport path.

## [0.18.54] - 2026-07-16

- `DidCommTransport` gains outbox-drain delivery evidence (D1 Phase 2, §5a):
  `send` now returns the mediator queue-id — `sha256(packed)` — as
  `SendReceipt::hop_id`, and `outbox_message_ids()` lists the sender's
  `Folder::Outbox` message ids. Together they let the delivery layer confirm a
  message `Delivered` once its hop-id **drains** from the outbox (the recipient
  took pickup). The `hop_id = sha256(packed) = outbox msg_id` correlation and the
  drain-on-pickup behaviour were verified live against a real mediator. Additive.

## [0.18.53] - 2026-07-16

- Add `DidCommTransport`, a `MessageTransport` (from `affinidi-messaging-core`)
  implementation over the DIDComm ATM wire — the first step of the messaging
  delivery layer (D1 Phase 2). It binds the now-conformant SDK to the
  transport-agnostic contract:
  - `send` maps to the truthful `ATM::send_message` (an untransmitted frame is
    an `Err`, never a false `Ok`); the receipt is hop-acceptance, not
    end-to-end delivery.
  - `connection_state` hands out the profile's live `watch<ConnState>` (captured
    at construction; tracks socket reconnects for the transport task's life).
  - `inbound` yields undeleted messages (`live_stream_next(auto_delete = false)`)
    as neutral `Inbound { message, thread_id, ack }`; `ack` deletes the message
    from the mediator only after the caller's durable handoff.
  Construct with `DidCommTransport::new(atm, profile).await` (errors if the
  profile has no websocket transport). `async-trait` is now a normal dependency
  (was `tsp`-feature-gated) so the trait can be implemented unconditionally.
  Additive; no existing API changed.

### Behaviour change (see note on versioning)

- **Truthful websocket send (D1 conformance, R1.1).** On the websocket
  transport, `ATM::send_message` previously returned `Ok(EmptyResponse)` for a
  fire-and-forget send **the moment the command was enqueued to the transport
  task** — before any byte reached the socket. During a reconnect the socket is
  `None`, so the frame was silently discarded yet the caller saw success; a
  failed socket write was likewise swallowed into a log line. Every downstream
  "delivered" record was built on that false `Ok`.

  `WebSocketCommands::SendMessage` now carries a `oneshot` reply; the transport
  reports the **actual** write outcome, and `send_message` awaits it:
  - socket write succeeds → `Ok` (as before);
  - socket disconnected (reconnect window) or write fails → `Err`
    (`ATMError::TransportError`) — **never** a false `Ok` for an untransmitted
    frame.

  This is a **behavioural break**: a caller that sent while the socket was down
  now receives `Err` where it used to receive `Ok(EmptyResponse)`. The public
  signature of `send_message` is unchanged; `WebSocketCommands` is `pub(crate)`.
  Delivery-critical callers should treat the `Err` as "not sent" and retry /
  queue (the delivery-layer outbox, landing separately, will absorb this for
  `Guaranteed` sends). The REST path was already truthful and is unchanged.

  **Versioning note:** the repo convention signals breaking changes with a minor
  bump, but a minor bump here forces every in-workspace `affinidi-messaging-sdk
  = "0.18"` consumer to update its pin in the same PR, which trips the
  `publish-dry-run` guard (consumers would reference an unpublished 0.19). This
  change therefore ships as a **patch with this explicit break note**; if the
  maintainers prefer a coordinated `0.19.0` + consumer-pin cascade, that is a
  mechanical follow-up.

## [0.18.51] - 2026-07-16

- Publish a re-falsifiable websocket connection-state signal (D1 conformance,
  R6.2). The reconnect loop lives entirely inside the SDK's `WebSocketTransport`
  task and previously emitted nothing on drop/reconnect, so every consumer's
  connectivity view (`ListenerEvent`, health flags) was a boot-time latch. The
  transport now owns a `tokio::sync::watch::<ConnState>` (from the new
  `affinidi-messaging-core::ConnState`): it publishes `Connected` at the single
  reconnect-success site and `Disconnected` from `fail_pending_requests` (the
  one choke point every drop funnels through). Exposed additively via
  `ATMProfile::connection_state() -> Option<watch::Receiver<ConnState>>`
  (`None` for a REST-only profile). No existing API changed; the internal
  `WebSocketTransport::start`/`start_with_options` now also return the receiver.

- Footgun guard: `TspOps::connect_websocket` now warns when the profile already
  has a live-stream pickup websocket. The mediator permits one websocket per DID,
  so opening a second (raw-TSP) socket on the same DID makes it evict a duplicate
  channel and the two flap. Combined DIDComm+TSP receivers should multiplex on the
  single pickup socket via `MessagePickup::live_stream_next_frame` (or the
  `affinidi-messaging-didcomm-service` crate) instead.

## [0.18.49] - 2026-07-04

- Route the DIDComm pack and unpack paths through the shared
  `affinidi_crypto::KeyType::key_agreement_curve()` helper (single source of
  truth for the `KeyType` → key-agreement `Curve` mapping) instead of two
  local copies of the match.
- Fix: the JWE unpack path previously handled only X25519/P-256/secp256k1
  recipient keys and silently skipped P-384/P-521 (they fell through to
  `_ => continue`), so a message encrypted to a local P-384/P-521 key failed
  to decrypt with "no matching recipient". Consolidating onto the shared
  helper restores P-384/P-521 recipient decryption, matching the pack path
  and the mediator. Patch bump — see ADR 0003.

## [0.18.47] - 2026-07-03

- Add `MessagePickup::send_delivery_request_frames` (+ `MessagePickupOps` delegate), the
  offline/backlog counterpart of `live_stream_next_frame`: it returns each queued message as
  an `InboundFrame` (DIDComm or TSP) paired with its ack id, so an offline-sync consumer can
  route TSP frames to a TSP handler instead of DIDComm-unpacking (and poison-looping on)
  them. Undeliverable attachments (bad encoding, or a non-TSP frame that fails DIDComm
  unpack) yield `(None, id)` so the caller still acks them. `tsp`-feature only; additive.

## [0.18.45] - 2026-07-02

- TSP capability learning (SDD phase 2): the per-peer TSP capability cache is now
  populated automatically, so `atm.send_to` upgrades a peer from DIDComm to TSP once
  we know their agent speaks it. A peer is marked `Supported` when a relationship
  completes (`accept_relationship` / `record_incoming_control` reaching `Bidirectional`)
  or when an authenticated inbound TSP message is observed (`unpack` / `unpack_bytes` /
  `unpack_control`). Learning is a no-op under the default `TspPolicy::Off` (no extra
  store writes) and skips redundant writes when a fresh `Supported` record already exists.

## [0.18.44] - 2026-07-02

- Fix a poison-message loop: `MessagePickup::live_stream_next` / `live_stream_get` errored
  (without deleting) when a **packed** frame (e.g. a TSP/CESR message) arrived on a
  DIDComm-only stream, so the mediator redelivered it every pickup cycle forever. They now
  delete the undeliverable packed frame (when `auto_delete`) and skip it (`Ok(None)`) with a
  warning, keeping the stream live. A consumer that wants packed frames should use
  `live_stream_next_frame` (multiplexed) or `live_stream_next_packed`. Behaviour change:
  these paths return `Ok(None)` instead of `Err(MsgReceiveError)` on an unexpected packed
  frame.

## [0.18.43] - 2026-07-02

- TSP-preferred protocol selection (SDD phase 1). New `ATM::send_to(profile, message, to,
  from, sign_by)` façade automatically picks TSP or DIDComm and returns the `SendProtocol`
  used. Selection is governed by a new `TspPolicy` (`Off` default / `Preferred` / `Required`)
  set via `ATMConfigBuilder::with_tsp_policy`; with the default `Off` nothing changes.
- Per-peer TSP capability cache folded into `RelationshipStore` (new `get_capability` /
  `set_capability` trait methods with default no-op impls, so existing stores keep
  compiling; `InMemoryRelationshipStore` persists it). New `TspOps::select_protocol`,
  `peer_capability`, `set_peer_capability`; `PeerCapability` / `TspSupport` /
  `CapabilitySource` types; a configurable capability TTL via
  `ATMConfigBuilder::with_tsp_capability_ttl` measured against the injected clock.
- Selection precedence: a fresh cached capability, else a `Bidirectional` relationship
  (→ TSP, cached), else a DID-doc `TSPTransport` service (→ TSP, tentative), else DIDComm
  (or an error under `Required`). Additive/patch — no breaking changes.

## [0.18.41] - 2026-06-29

- TSP relationship methods follow affinidi-tsp 0.1.10's spec-compliant Control encoding:
  `accept_relationship` / `cancel_relationship` now take the invite's thread digest (the
  SHA-256 of the invite's payload frame) for cross-impl correlation, and a new
  `TspOps::unpack_control` returns `(ControlMessage, sender, thread_digest)`.

## [0.18.40] - 2026-06-29

- Doc/comment updates for affinidi-tsp 0.1.8's new `-E` CESR wire framing. No functional
  change — the SDK's TSP path already routes by envelope addressing and unpacks for the
  message kind, so it is agnostic to the framing magic byte.

## [0.18.39] - 2026-06-27

SDK consumer for the mediator's raw-TSP WebSocket mode.

- New `atm.tsp().connect_websocket(profile)` → `TspWebSocket`: opens a WebSocket to the
  mediator offering the `tsp` subprotocol (alongside the bearer token), so the socket runs
  in raw-TSP mode (flush-on-connect + delete-on-successful-send, server-side). `TspWebSocket`
  has `recv()` (next raw qb2 TSP message, `None` on close — skips ping/pong), `send(&[u8])`
  (send a raw TSP message inbound), and `close()`.
- New `atm.tsp().unpack_bytes(profile, qb2)` — unpack a raw qb2 TSP message (what `recv`
  returns) without the base64 round-trip; `unpack(stored)` now decodes then delegates to it
  (its signature + behaviour are unchanged).
- Re-exports `TspWebSocket`. Additive; no existing API changed.

## [0.18.38] - 2026-06-26

Formatting only (`cargo fmt --all`); no functional or API change. Patch bump
required by the release guard because the crate source changed. Reconciles the
version after the pure-TSP-auth `0.18.37` release landed on `main`.

## [0.18.37] - 2026-06-26

Pure-TSP client authentication: `TspAuthHandler` lets a TSP-only client (no DIDComm)
authenticate to the mediator's `POST /tsp/authenticate` and obtain the same JWT session.

- New `TspAuthHandler` (impl `affinidi_did_authentication::CustomAuthHandler`): resolves the
  mediator's `#auth` service, `POST {base}/challenge`, signs the challenge with the profile's
  Ed25519 VID key, then `POST {base}/tsp/authenticate {vid, session_id, signature}` and returns
  the access/refresh `AuthorizationTokens`. Register it via
  `CustomAuthHandlers::default().with_auth_handler(Arc::new(TspAuthHandler::new(secrets)))` when
  building the TDK; the existing `atm.tsp()` / cache / `send_raw` path then authenticates over
  TSP transparently.
- Adds `affinidi-did-resolver-cache-sdk` + `reqwest` as optional deps behind the `tsp` feature
  (named directly by the `CustomAuthHandler` trait signature). Additive; no existing API changed.

## [0.18.36] - 2026-06-25

TSP **relationship management** — drive the TSP relationship lifecycle (RFI/RFA: invite /
accept / cancel) through `atm.tsp()`, backed by a pluggable store.

- New `atm.tsp()` methods: `form_relationship`, `accept_relationship`,
  `cancel_relationship`, `relationship_state`, and `record_incoming_control` (advance the
  FSM for a received control message). Each drives the pure
  `affinidi_tsp::relationship::RelationshipState` state machine
  (None → Pending / InviteReceived → Bidirectional) and sends via the existing
  `send_control`; outbound state is persisted only **after** the control message is sent.
- New `RelationshipStore` trait — pluggable persistence (consumers implement it against
  durable storage) — plus an ephemeral `InMemoryRelationshipStore` default. Select one via
  `ATMConfigBuilder::with_relationship_store`; defaults to in-memory (wiped on restart).
- Adds `async-trait` behind the `tsp` feature. Additive; no existing API changed.

## [0.18.35] - 2026-06-25

The `tsp` feature is no longer marked **experimental** — `atm.tsp()` (pack / send /
send_routed / send_nested / send_control / unpack) is supported. Documentation/labelling
only; no behaviour change. Caveat: pure-TSP client auth (`/tsp/authenticate`) is still
pending, so `atm.tsp()` reuses the profile's DIDComm-authenticated session for now.

## [0.18.34] - 2026-06-24

New `atm.tsp().send_control(profile, to_did, control)`: send a TSP **`Control`** message
— a relationship-management message (invite / accept / cancel) to a peer. Build `control`
with `affinidi_tsp::message::control::ControlMessage`'s `invite` / `accept` / `cancel`; it
is sealed to `to_did` and carried with message type `Control`, which the mediator relays
to the recipient like a Direct message. Additive; no existing API changed.

## [0.18.33] - 2026-06-24

New `atm.tsp().send_nested(profile, intermediary, to_did, payload)` and
`send_nested_opaque(profile, intermediary, inner)`: send a TSP message wrapped in a
**`Nested`** metadata-privacy envelope. The payload is sealed end-to-end to `to_did`,
then wrapped in an outer `Nested` message sealed to `intermediary` (typically the
recipient's mediator), which unwraps the outer layer and forwards the inner — so only
the intermediary learns `to_did`. The `_opaque` form takes a pre-built inner (which may
be a DIDComm message — the TSP↔DIDComm bridge). Additive; no existing API changed.

## [0.18.32] - 2026-06-24

`atm.trust_tasks().acl_set` is no longer admin-only — a non-admin may set its own ACL
(the self-manageable capabilities); docs updated. (Server-side change in the mediator;
the SDK call is unchanged.)

## [0.18.31] - 2026-06-24

The legacy `atm.mediator()` management methods are now `#[deprecated]` in favour of the
`atm.trust_tasks()` core: `account_get`/`account_add`/`account_remove`/`accounts_list`/
`account_change_type`/`account_change_queue_limits`, `acls_get`/`acls_set`,
`access_list_{list,add,remove,clear,get}`, and `get_config`/`add_admins`/`strip_admins`/
`list_admins`/`list_audit_log` — each points to its `atm.trust_tasks().*` replacement.
The methods still work (legacy DIDComm wire); they will be removed in a future major
release (the breaking change). **Additive — patch bump, `0.18` pin stays valid.** (The
deliberately-louder minor/major bump is reserved for the removal, per the workspace's
patch-not-minor convention.)

## [0.18.30] - 2026-06-24

`atm.trust_tasks()` gains the admin family: `admin_add` / `admin_strip` / `admin_list` /
`admin_audit_log` / `admin_config` (all admin only). Completes the messaging Trust Tasks
client surface. Additive.

## [0.18.29] - 2026-06-24

`atm.trust_tasks()` gains the access-list family: `access_list_add` / `access_list_remove`
/ `access_list_clear` / `access_list_get` / `access_list_list` (self-or-admin; `None` =
own list). Completes the messaging Trust Tasks client surface. Additive.

## [0.18.28] - 2026-06-24

`atm.trust_tasks().account_add(profile, did_hash, account_type, acl)` — create an
account and return its realized view. Completes the account-family client surface.
Additive.

## [0.18.27] - 2026-06-24

`atm.trust_tasks()` gains `acl_get(profile, did_hashes)` (self-or-admin; batched ACL
read → entries + unknown) and `acl_set(profile, did_hash, acl)` (admin only; partial
ACL update → realized ACL). Additive.

## [0.18.26] - 2026-06-24

`atm.trust_tasks().account_change_type(profile, did_hash, account_type)` (admin only) —
change an account's role and return its realized view. Only a root admin may assign the
root-admin role or modify a root-admin account. Additive.

## [0.18.25] - 2026-06-24

`atm.trust_tasks().account_remove(profile, did_hash)` — remove an account (self-or-admin;
`None` = self) and return whether a record was removed. The mediator's own and the
root-admin accounts can't be removed. Additive.

## [0.18.24] - 2026-06-24

`atm.trust_tasks().account_change_queue_limits(profile, did_hash, send, receive)` —
change an account's queued-message limits and return the updated view. `None` target
= self; each limit is `Some(-1)` (unlimited) / `Some(n)` / `None` (unchanged). Additive.

## [0.18.23] - 2026-06-24

`atm.trust_tasks().account_list(profile, cursor, limit)` (admin only) — returns one
page of accounts plus an opaque `next_cursor` (present only when more remain); pass
it back to continue. Additive.

## [0.18.22] - 2026-06-24

`atm.trust_tasks().account_get(profile, did_hash)` — fetch the mediator's view of an
account as a typed `account/get` response. `None` requests the caller's own account
(self; no admin rights needed). Shares the binding-envelope send path with `ping`
(refactored into an internal `exchange` helper). Additive.

## [0.18.21] - 2026-06-23

New `atm.trust_tasks()` accessor with `.ping(profile, nonce)` — sends a
`messaging/ping` Trust Task to the mediator (over the DIDComm binding envelope) and
returns the typed `ping` response (server time, status, supported protocols, echoed
nonce). Additive — the first of the messaging Trust Tasks client surface; account /
acl / access-list follow, and the legacy `atm.mediator()` / `atm.trust_ping()`
methods will route through this core (the breaking change that lands then is
signalled by a minor bump).

## [0.18.20] - 2026-06-23

`MessageType` gains a `TrustTaskEnvelope` variant (the Trust Tasks DIDComm binding
envelope `type`), so the mediator can route Trust Task documents. Additive
scaffolding for the messaging Trust Tasks migration; no API change. The deliberate
minor bump that signals the migration's breaking client changes lands with
`atm.trust_tasks()` (next).

## [0.18.19] - 2026-06-23

WebSocket live-stream is now TSP-safe. An inbound frame is sniffed (the frame is
self-describing CESR qb64); a TSP message is delivered **packed** — so the
consumer unpacks it via `atm.tsp()` — instead of being routed into the DIDComm
`unpack`, where it previously failed and was silently dropped. DIDComm frames are
unchanged, and the sniff is gated on the `tsp` feature (no-op without it).

## [0.18.18] - 2026-06-23

Re-exports `MessageProtocol` (from `affinidi-messaging-mediator-common`).
Fetched messages now carry a `protocol` field (`Some(MessageProtocol::DidComm |
Tsp | …)`), tagged server-side, so a client can route each message natively
without inspecting it. Additive; patch bump.

## [0.18.17] - 2026-06-23

`atm.tsp().send_routed_opaque(profile, route, inner)` — route an **already-packed**
inner message through TSP relay hops. The inner may be a **DIDComm** message (the
TSP↔DIDComm bridge): pack it with `atm.pack_encrypted`, then route it over TSP to a
recipient who unpacks it natively. `send_routed` now builds on this. Additive;
patch bump.

## [0.18.16] - 2026-06-23

`atm.tsp()` gains routed send:
- `send_routed(profile, route, payload)` — send a TSP message through one or more
  relay hops. The payload is sealed end-to-end to the final recipient
  (`route.last()`), wrapped in a routing layer sealed to the first hop
  (`route[0]`, a TSP-routing mediator); each hop unwraps and forwards onward.
- `send_raw(profile, bytes)` — POST an already-packed TSP message to `/inbound`
  (the shared transport `send()` now builds on this).

Verified end to end against a live mediator relay in
`affinidi-messaging-test-mediator`. Additive; patch bump.

## [0.18.15] - 2026-06-22

Picks up the `affinidi-did-common` 0.3.8 fix for
`DocumentExt::find_authentication`, which **fixes DIDComm signed-message
verification when the signer's `kid` is a bare DID** (no fragment): the unpack
path looked up the first authentication key via that method and previously got a
keyAgreement (X25519) key, so verification failed. Fragment-qualified kids were
unaffected. Also drops the local workaround in `atm.tsp()` (now that
`find_authentication` is correct). No API change; patch bump.

## [0.18.14] - 2026-06-22

TSP send/receive — `atm.tsp()` can now pack, send, and unpack TSP **Direct**
messages end to end:

- `pack(profile, to_did, payload)` builds a TSP Direct message — extracting the
  profile's Ed25519 signing key (from its `authentication`) and X25519 encryption
  key (from its `keyAgreement`) via the secrets resolver, and resolving the
  recipient's keys from its DID document.
- `send(profile, to_did, payload)` packs and POSTs to the mediator `/inbound`,
  reusing the profile's existing (DIDComm) authenticated session for the bearer
  token; the mediator sniffs the TSP magic byte and stores it for pickup.
- `unpack(profile, stored)` decodes a fetched message, resolves the sender, and
  decrypts + verifies with the profile's key, returning `(payload, sender_vid)`.

Verified end to end against a live mediator in
`affinidi-messaging-test-mediator` (alice packs → mediator stores → bob unpacks).
Additive (no `tsp` feature = no change); patch bump keeps the `0.18` pin valid.

NB: works around a copy-paste bug in `affinidi-did-common`'s
`DocumentExt::find_authentication(None)` (it returns `keyAgreement` ids) by
reading `doc.authentication` directly.

## [0.18.13] - 2026-06-22

TSP client support — foundation. New optional `tsp` feature and an `atm.tsp()`
ops accessor (the TSP sibling of `atm.routing()` etc.). This first slice adds the
**storage-format codec** a client needs on pickup: a mediator stores a TSP message
`base64url(qb2)` (its CESR qb64 text form, `1AAF…`), so `atm.tsp().is_tsp()`
distinguishes it from a DIDComm JSON envelope and `decode()`/`encode()` convert
to/from the raw qb2 bytes. Purely additive (no `tsp` feature = no change); patch
bump keeps the `0.18` pin valid. The pack/send and fetch/unpack paths land next.

## [0.18.12] - 2026-06-14

`ATMError` is now `#[non_exhaustive]` (ADR-0003) so new variants land additively.
Patch bump keeps the `0.18` pin valid; match it with a `_` wildcard arm. No
behaviour change. (W7 sweep)

## [0.18.11] - 2026-06-14

Injectable clock for the SDK's expiry/TTL reads (TI4b-2).

### Added

- `ATMConfigBuilder::with_clock(Arc<dyn Clock>)` injects the clock the SDK uses
  for its time reads (defaults to the real `SystemClock`). The `Clock` trait
  comes from `affinidi-messaging-mediator-common` (shared with the mediator,
  TI4b-1), so a test can drive both with one `TestClock`.

### Changed

- The SDK's expiry/TTL **decisions** now read the injected clock instead of the
  wall clock directly: forwarded-message expiry (`extract_forward_payload`) and
  the WebSocket token-refresh TTL (`refresh_deadline`). Additive — existing
  callers are unaffected. The refresh deadline is still *scheduled* on tokio's
  monotonic timer; only the TTL computation moved to the injected clock.
- Outbound protocol-message `created_time`/`expires_time` stamps still read the
  wall clock (a documented follow-up); the mediator's own injected clock governs
  enforcement, so this does not affect expiry tests.

## [0.18.10] - 2026-06-13

WS resilience (W16, part 2 of 2).

### Added

- **Proactive WebSocket token refresh.** The mediator force-closes a WebSocket
  at access-token expiry (it only checks the JWT at upgrade, and has no in-band
  refresh). The transport now records the token's expiry and, at ~80% of its
  lifetime, refreshes the token via the refresh-token flow
  (`AuthenticationCache::refresh`, which has the mediator re-verify the DID is
  still allowed to connect) and reconnects with the fresh token — *before* the
  forced close — rather than waiting to be kicked and reconnecting reactively.

### Changed

- **The background deletion handler is now supervised** via the shared
  `affinidi-task-utils` `TaskSupervisor`: a panic or error is detected and the
  task restarted with capped backoff (it previously died silently, leaving
  background deletions unprocessed for the life of the process). Shutdown now
  flows through a `CancellationToken`. Public method signatures are unchanged.

## [0.18.9] - 2026-06-13

SDK request-path hardening (W16, part 1 of 2).

### Added

- **Configurable request timeout.** `ATMConfig::with_request_timeout(Duration)`
  (default 15s) overrides the per-request timeout for mediator REST calls. The
  previously hardcoded `MEDIATOR_REQUEST_TIMEOUT` constants (duplicated in
  `delete.rs`/`list.rs`) are removed in favour of the config value.

### Fixed

- **No panic on a malformed mediator response.** `delete_messages_direct`,
  `list_messages`, and `get_messages` parsed the response body with
  `.ok().unwrap()`, panicking the caller (or the deletion-handler task) on any
  non-JSON 2xx body. They now return `ATMError::TransportError` instead.
- **`get_messages` had no request timeout** and could hang indefinitely on a
  network stall; it is now bounded by the configured request timeout like the
  other REST calls.

### Changed

- **WebSocket reconnect backoff is now jittered (±15%).** The exponential
  backoff (1→2→4…→60s) previously reconnected in lock-step across clients;
  jitter spreads reconnections so a recovering mediator isn't stampeded.
  (`rand` promoted from dev- to normal dependency for non-cryptographic jitter.)

## [0.18.8] - 2026-06-13

### Added

- **`Mediator::list_audit_log` (and `MediatorOps::list_audit_log`)** — admin
  client method to page the mediator's privileged-change audit log (newest-first,
  cursor-paginated), sending the new `audit_log_list` administration request.
  Re-exports `AuditLogEntry`, `AuditAction`, and `MediatorAuditLogList` from
  `affinidi-messaging-mediator-common`. Pairs with mediator 0.15.44 / simplification T25b.

## [0.18.7] - 2026-06-06

### Changed

- **Robust key-agreement negotiation in `pack_encrypted` (#357).** The
  authcrypt path now enumerates *all* of the sender's usable key-agreement
  keys and negotiates the best shared curve with the recipient by a
  documented preference order (`X25519 > P-256 > secp256k1`), rather than
  deriving the curve from the sender's *first* key only — so a sender whose
  first KA curve has no recipient match but whose second does now packs
  successfully, and a no-common-curve failure names the curve set each side
  offered. The anoncrypt path now selects the recipient's most-preferred
  usable key-agreement curve using the **same** ordering as authcrypt
  (skipping undecodable/unsupported entries) instead of blindly taking
  `first()`, so the two paths never disagree on curve choice. The duplicated
  negotiation/resolution helpers were removed in favour of
  `affinidi-did-common`'s shared `key_negotiation` module (its new
  `key-agreement` feature).
- **P-384/P-521 key agreement + configurable curve preference (#357).**
  `pack_encrypted` now supports the P-384 and P-521 key-agreement curves
  (sender key-type → curve mapping), and `ATMConfigBuilder` gains
  `with_curve_preference(Vec<Curve>)` to override the default curve ordering
  (`X25519 > P-256 > P-384 > P-521 > secp256k1`) at runtime — e.g. P-256
  first for a FIPS deployment. The override applies to both authcrypt and
  anoncrypt.

## [0.18.6] - 2026-06-01

### Fixed

- Fix `cargo test` compilation in the `ws_cache` unit tests: a `oneshot`
  send was `.unwrap()`-ed, which requires `WebSocketResponses: Debug` (not
  derived). Assert on `.is_ok()` instead. Test-only; no runtime change.

## [0.18.5] - 2026-06-01

### Changed

- **In-flight websocket requests now fail fast on disconnect.** When the
  connection to the mediator drops (server `Close`, reset, missed pong, or
  any socket error), every pending `live_stream_get` / `live_stream_next`
  waiter is notified immediately instead of blocking until its own timeout
  elapses. Previously a request that was in flight when the socket dropped
  (e.g. the mediator closing the socket on access-token expiry) sat idle for
  up to the full wait window and then surfaced as a misleading
  `MsgSendError("No response from API")`.
  - New `WebSocketResponses::Disconnected` variant carries the signal to
    waiters. `live_stream_next` / `live_stream_next_packed` map it to
    `Ok(None)` (streaming callers quietly retry on reconnect);
    `live_stream_get` maps it to the new `ATMError::Disconnected` so
    request/response callers can distinguish a reconnect race from a genuine
    no-response.

## [0.18.4] - 2026-05-31

### Security

- **`unpack()` now verifies JWS signatures.** Previously a signed
  (JWS) message was parsed *without* checking the signature and returned
  with `non_repudiation: true` — i.e. a forged signature was accepted and
  labelled non-repudiable. `unpack()` now resolves the signer's Ed25519
  key from its `kid` (via the DID resolver) and verifies the signature;
  an unresolvable signer or an invalid signature is an **error**. The
  signer is attributed in `UnpackMetadata.sign_from`, read from the
  protected header and falling back to the unprotected header (#323).
  Behaviour change: flows that relied on the previous lax parsing of
  unverified JWS will now receive an error instead of a message.

### Added

- **Sign-then-encrypt support (#324).** When a decrypted JWE wraps a JWS
  (DIDComm v2.1 non-repudiation), `unpack()` verifies the inner signature
  and reports `non_repudiation` + `sign_from` alongside the encryption
  metadata, instead of failing to parse.

### Changed

- Bump `affinidi-messaging-didcomm` to 0.14 (corrected ECDH-1PU authcrypt
  KDF + dual-KEK fallback, #322). The decrypt path picks these up
  transparently.
- Verification-material parsing now delegates to
  `affinidi-did-common`'s `VerificationMethod::decode_public_key`,
  removing the SDK's bespoke JWK/multibase branch (shared with the
  DID-authentication layer).

## [0.18.3] - 2026-05-24

### Security

- `OOBDiscovery::retrieve_invite` no longer panics on malformed
  responses from the invitation endpoint. The four `.unwrap()` /
  `.expect()` sites on the response envelope, base64url payload,
  UTF-8 decode and inner `Message` parse now return
  `ATMError::TransportError`. Previously a misbehaving or hostile
  mediator could crash the SDK client.
- `AuthorizationResponse` no longer derives `Debug`; a manual impl
  redacts `access_token` and `refresh_token` while leaving the
  `*_expires_at` fields visible. The derived impl printed both
  tokens verbatim, so any `debug!`/`warn!("{:?}", resp)` or panic
  dump leaked credentials granting a full authenticated session.
  Matches the redaction already applied to the equivalent structs
  in `affinidi-did-authentication`.

## [0.18.1] - 2026-05-05

### Changed

- `From<ACLError> for ATMError` now includes a wildcard arm because
  `mediator-common 0.15.0` marked `ACLError` as `#[non_exhaustive]`.
  Future ACL variants surface as `ATMError::ACLConfigError` until
  the SDK adds a more specific mapping. No behavior change for
  existing `Config` and `Denied` variants.
- Bumped `mediator-common` caret pin to `"0.15"` to pick up the
  feature-gating rework. The SDK already takes
  `default-features = false`, so this build no longer pulls
  `axum`, `redis`, or `aes-gcm`/`argon2` via mediator-common.

## [0.18.0] - 2026-05-05

### Breaking

- `MediatorACLSet::*` fallible methods now return `Result<_, ACLError>`
  instead of `Result<_, ATMError>`. `ACLError` is a lightweight enum
  (`Config(String)` / `Denied(String)`) that lives in
  `affinidi-messaging-mediator-common::types::acls` so the mediator's
  storage trait can describe its API without depending on this crate.
  Callers using `?` against `ATMError` are unaffected — a
  `From<ACLError> for ATMError` is provided. Callers that
  match-arm on `ATMError::ACLDenied(_)` / `ATMError::ACLConfigError(_)`
  need to convert via `.map_err(ATMError::from)` (or update to match on
  `ACLError` directly).

### Changed

- The mediator protocol vocabulary moved out of this crate and into
  `affinidi-messaging-mediator-common::types::*`. Affected types:
  `MediatorACLSet`, `AccessListModeType`, `Account`, `AccountType`,
  `MediatorAccountList`, `AdminAccount`, `MediatorAdminList`,
  `Folder`, `MessageList`, `MessageListElement`, `GetMessagesResponse`,
  `FetchDeletePolicy`, `FetchOptions`, `ProblemReport`, plus the
  ACL-handler / admin request and response shapes. Each type is
  re-exported from its original `affinidi_messaging_sdk::*` path so
  existing imports keep working unchanged.
- This crate now depends on `affinidi-messaging-mediator-common`
  (was the other way around). Removes a circular-feeling layering
  where the storage trait imported from the client SDK.

## [0.17.0] - 2026-05-02

### Breaking

- Migrated to `affinidi-tdk-common` 0.6. The change is mechanical only —
  `TDKSharedState` field accesses (`tdk_common.client`, `.did_resolver`,
  `.secrets_resolver`, `.authentication`, `.environment`) replaced with
  the corresponding accessor methods on every code path. No behavioural
  changes within the SDK itself.
- `ATMProfile::to_tdk_profile` now constructs the `TDKProfile` via
  `TDKProfile::new(...)` instead of a struct literal — the `secrets`
  field is `pub(crate)` in tdk-common 0.6 and only constructible through
  the public API.

### Tests

- `unpack` test helpers (`create_atm_with_secrets`, `create_atm`,
  `create_atm_no_unpack_forwards`) updated to build a `TDKSharedState`
  via `TDKConfig::builder().with_load_environment(false)
  .with_use_atm(false).build()?` + `TDKSharedState::new`, replacing the
  removed `TDKSharedState::default().await`.

## [0.16.5] - 2026-04-25

### Fixed

- `ATM::list_messages` and `ATM::delete_messages_direct` now apply a 15-second per-request HTTP timeout. Previously the calls were unbounded and would block for the OS-level TCP RTO (~30–60s on macOS) when the mediator was unreachable, contributing to slow shutdowns in downstream consumers that wrap them in their own connect path.

## [0.16.3] - 2026-04-15

### Fixed

- Add exponential backoff (1s-60s cap) on WebSocket reconnection after server-initiated disconnects. Previously, server-initiated Close frames (including mediator `duplicate-channel` rejections), protocol resets, and connection errors triggered immediate reconnection with zero delay, causing an infinite reconnect loop between two profiles sharing the same DID.
- Missed pong timeout now immediately drops the WebSocket and applies backoff, instead of leaving a half-closed connection.

## [0.16.2] - 2026-03-28

### Fixed

- Handle inbound WebSocket Ping frames from the mediator by responding with a Pong, instead of logging them as unknown message types.

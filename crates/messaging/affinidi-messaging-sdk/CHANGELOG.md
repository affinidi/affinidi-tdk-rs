# Changelog

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

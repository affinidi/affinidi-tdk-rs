# Changelog

## Unreleased (0.20.5) — pack the forwarding-abandonment problem report

**Bug fix (host side of mediator-common 0.15.37): the mediator now packs the
problem report it sends when it gives up on a forward.**

The report went out as bare DIDComm plaintext, which every SDK client on the
default (authcrypt-only) receive policy discards — the mediator logged
`FORWARD_PROBLEM_REPORT: stored problem report … for sender …` while the sender
logged `UnexpectedEnvelope("envelope wrapping Plaintext is not in the accepted
set …")`. Every forwarding abandonment was silent to the sender.

- New `tasks::system_packer::MediatorSystemPacker` implements
  `mediator-common`'s `SystemMessagePacker` over the same
  `didcomm_compat::pack_encrypted` every protocol reply already goes through.
  Only compiled with the `didcomm` feature; a TSP-only build has no DIDComm
  packer to offer and the processor logs the abandonment instead.
- The forwarding processor is now spawned *after* the DID resolver is built and
  the mediator's own document preloaded — authcrypt resolves both ends, and a
  `did:web`/`did:webvh` mediator may not reach its own document over the
  network from inside its deployment. No other ordering depends on it.

## Unreleased (0.20.4) — blind cross-mediator relay is no longer refused as a session mismatch

**Bug fix: with the default `RelayMode::Blind`, a mediator refused every
message relayed to it by a peer mediator.**

Observed in production: mediator M2 relays to M1, and M1 answers
`HTTP 400 / errorCode 52` —
`e.p.authorization.did.session_mismatch`, "Sender DID (…) doesn't match
session DID", on session `ANON-INBOUND`. No cross-mediator DIDComm delivery
completed.

`inbound.rs` enforces `security.force_session_did_match` in two places, and
only one of them was guarded. The **forward** branch (the message is addressed
to the mediator) already skipped the check for an unauthenticated session,
because an inter-mediator relay hop arrives anonymously and has no session DID
to match against. The **direct-delivery** branch (the message is addressed to
a local account) did not, so it compared the claimed sender against the
anonymous session's empty DID and could only ever fail.

Which branch a relayed message lands on is decided by the relay mode.
`RelayMode::Blind` — the default — relays the peer's inner envelope
byte-for-byte, and that envelope is addressed to the *recipient*, not to the
receiving mediator: a direct delivery. So the unguarded branch is exactly the
one every blind relay hop takes. `RelayMode::Rewrap` re-wraps the envelope as
a forward addressed to the next mediator and therefore took the already-guarded
branch, which is why rewrap deployments were unaffected.

The direct-delivery check now carries the same `session.authenticated` guard as
its sibling.

**The security tradeoff, stated plainly.** A directly-delivered envelope cannot
be decrypted by the mediator, so its sender is only a *claim* (the JWE `skid`),
and that claim is what feeds `from_hash` in the recipient's access-list
verdict. Exempting the anonymous relay session means a blind-relayed message's
sender is not verified against anything: a relaying peer can present any sender
DID. This is inherent to blind relay rather than introduced here — by
construction the receiving mediator cannot see which peer relayed — and the
alternative is the bug being fixed, refusing the hop outright.
`RelayMode::Rewrap` together with
`processors.forwarding.relay_trusted_mediators` exists precisely so a
deployment can authenticate and allowlist the relaying peer; deployments that
need the peer authenticated should run it.

Unchanged: an **authenticated** session's direct delivery is still bound to its
session DID, so a client cannot claim someone else's sender DID.

## Unreleased (0.20.3) — say which origin CORS refused, and whether CORS is on

**Observability fix: a CORS refusal was invisible from both ends.**

The browser gets an opaque `TypeError: Failed to fetch` with the reason
confined to its devtools console, and the mediator logs a clean `200` — the
`CorsLayer` does not reject anything, it simply omits the header. Operator and
user are left with no shared evidence. `curl` cannot reproduce the fault
either, because a terminal sends no `Origin` header, so the endpoint answers
perfectly and the refusal looks like it never happened.

- The `List` predicate now logs a refused origin at `warn`, naming it and
  pointing at `security.cors_allow_origin`. Logged **once per distinct
  origin** and capped at 32: the origin is attacker-controlled, so an
  unbounded record of it is a log-flooding and memory-growth primitive for
  anyone who can reach the port. A misconfigured deployment has one or two
  distinct origins to report, so the cap loses nothing real.
- The effective policy is now stated at boot. This is the half that matters
  most: `CorsOriginPolicy::None` (the default) installs **no predicate** — it
  never emits the header at all — so there is no per-request hook to log from,
  and a mediator refusing every browser client otherwise says so nowhere.
- The WebSocket path already logged its equivalent refusal and returns a
  readable `403`; only the REST path was silent, which is the one a browser
  client reaches first.

No behaviour change: the layer, the matchers and the policy are untouched, and
refusals are still refusals.

## Unreleased (0.20.2) — `rotate-admin` works against a VTA with no REST URL

**Bug fix: `mediator rotate-admin` could not authenticate to a VTA that
exposes no REST endpoint.**

The command pinned `TransportPreference::PreferRest`, which vta-sdk maps to
`TransportPlan::RestOnly` with **no DIDComm fallback**. Against a DIDComm-only
VTA there is no REST endpoint to resolve, so rotation failed before it began.
Newly reachable: until 0.20.1 an admin credential naming a VTA with no URL
could not be stored at all, so the command had no way to load one.

- The transport preference is now chosen from whether the credential carries a
  usable REST URL. With a URL, `PreferRest` is kept — it is known-good, and it
  avoids dialling DIDComm in the self-mediated topology, where the VTA's
  DIDComm mediator is the very process the operator is running the CLI against.
  Without one, `Auto` lets the SDK resolve the VTA's mediator from its DID
  document and try DIDComm with a REST fallback; a VTA advertising no
  `DIDCommMessaging` service degrades to `RestOnly`, exactly as before.
- The original rationale for pinning REST — that `get_acl` / `create_acl`
  needed the synchronous REST API — no longer holds. Both go through
  `rpc_tt` -> `dispatch_trust_task`, which is identical across the REST,
  DIDComm and TSP transports; the operation is a Trust Task on every transport
  and REST's bespoke per-operation routes were removed upstream.
- No behaviour change for any deployment whose admin credential has a REST URL.

**Known gap: TSP-only VTAs still cannot be rotated against.** `Auto` cannot
select TSP — `decide_transport` has no TSP arm, and `Transport::Tsp` is only
reachable through the explicit `VtaClient::connect_tsp`. Closing that belongs
in vta-sdk's preference matrix, not here.

## Unreleased (0.20.1) — `vta-sdk` 0.32.1

- Bumps `vta-sdk` 0.25 → 0.32.1. No source changes were required across the
  seven intervening minor releases, and `ContextProvisionBundle` is unchanged.
- Realigns this crate with the VTI workspace copy. Per the `vta` feature's
  comment, VTI's `[patch.crates-io] vta-sdk = { path = "vta-sdk" }` only
  deletes the registry node while our requirement admits their workspace
  version; holding at 0.25 while they shipped 0.32 is what re-opens the
  cross-repo dependency cycle.
- **`vta-sdk` is a public dependency of this crate's API** — `tasks::VtaRefresher`
  exposes a `VtaServiceConfig` field — so this is source-breaking for a consumer
  that builds with `--features vta` against `vta-sdk` 0.25. Shipped as a patch
  deliberately: `affinidi-messaging-test-mediator` pins `"0.20"`, and a minor
  would drop out of that range and duplicate this crate in the graph. Consumers
  that do not enable `vta` (including `test-mediator`, which builds
  `default-features = false`) never compile `vta-sdk` and are unaffected.

## Unreleased (0.20.0) — `trust-tasks-rs` 0.17

- Bumps `trust-tasks-rs` 0.12 → 0.17; sixteen response and component
  constructions moved to the generated builders behind one `build()` helper.
- **Behaviour change: three refusals that did not exist before.** 0.17 marks
  the generated *enums* `#[non_exhaustive]`, so a match on one needs a wildcard
  — and a wire enum can now carry a variant added to the registry after this
  binary was built. What the mediator does with one is a decision per site:
  - `account/list`'s role **filter** treats an unknown role as
    `AccountType::Unknown`, which selects nothing. Widening it to `Standard`
    would answer the request with a confident list of the wrong accounts.
  - `account/update` and `account/add` **refuse** an unknown role
    (`message.trust_task.rejected`, 400). They write it, and storing a
    privilege level this mediator cannot reason about — while telling the
    caller it set the role they asked for — is worse than a refusal.
  - `merge_wire_acl` **refuses** an unknown `accessListMode`. That member
    decides whether the access list allows or denies; guessing it inverts the
    ACL.
- No wire change for any known variant.

## Unreleased (0.19.0) — `trust-tasks-rs` 0.12, and `ping` gains freshness bounds

- Bumps `trust-tasks-rs` 0.11 → 0.12, and adapts the one `consume_inbound`
  call site: 0.12 requires a `ConsumeChecks` argument and `ConsumeOutcome`
  gains a `Duplicate` variant.
- **Behaviour change.** `ping` now refuses two document shapes it previously
  accepted, both as `malformedRequest`: an `issuedAt` beyond the 60s clock-skew
  tolerance, and an `expiresAt` at or before its own `issuedAt`. Before 0.12
  the only temporal check was `expiresAt` and `issuedAt` was parsed and never
  looked at, so a document stamped a year ahead was accepted — and accepted
  again for the whole of that year. A peer with a badly skewed clock will start
  seeing refusals.
- `ping` is declared `ConsumeChecks::not_consequential()`. Answering it grants
  no access, moves no value, discloses nothing beyond a nonce echo and the
  protocol list, and executing it twice leaves the mediator exactly as
  executing it once did — so SPEC §7.2 item 11 is knowingly disapplied and no
  duplicate-execution record is kept. On the hottest path in this module, a
  per-document record would be pure cost.
- The `Duplicate` arm is matched rather than `unreachable!()`, so that making
  this call consequential later is a compile-time prompt to decide what to
  return, not a panic on the first retried ping.
- `PayloadPolicy::AcceptUnvalidated` is unchanged, for the reason already
  recorded at that call site: moving it to `Validate` can start refusing
  documents a peer sends today, and belongs in its own change with its own
  rollout.
## Unreleased (0.18.22) — dependency refresh

- Bumps `base64` 0.22 → 0.23.
- Bumps `tokio-tungstenite` 0.29 → 0.30.
- Bumps `tower-http` 0.6 → 0.7.
- No source or API change; the bumps are declaration-only and the crate
  compiles unmodified against them. Bumped workspace-wide in the same
  change so no two versions of these crates are compiled side by side.

## [0.18.21] - 2026-08-22

### Fixed

- **A websocket close now states why**, so a refused duplicate connection stops
  reading as a network fault.

  `WebSocketCommands::Close` carried no reason, so the handler answered all three
  of its senders identically — the `duplicate-channel` problem report and the
  close reason `"replaced by a newer connection"`:

  - the incumbent, displaced by a newer connection — true;
  - a newcomer **refused** by the duel damper, whose own connection was never
    displaced and whose peer kept the slot — the inverse of true;
  - a session that reached registration with no authenticated DID — not a
    duplicate at all.

  A refused client was told it had been replaced, so the most it could honestly
  render was "the connection dropped". Two app instances presenting one DID
  therefore looked like a transport problem.

  `Close` now carries a `CloseReason`, and each maps to its own problem-report
  code and close reason:

  | Reason | Problem-report code | Close reason |
  |---|---|---|
  | `Replaced` | `w.websocket.duplicate-channel` | `replaced by a newer connection` |
  | `Refused` | `w.websocket.duplicate-channel-refused` | `this DID already has a live connection` |
  | `Unauthenticated` | `w.websocket.unauthenticated-session` | `session has no authenticated DID` |

  **`duplicate-channel` is preserved verbatim** for `Replaced`: it is the code
  existing clients already match on, and that socket is the one whose meaning
  never changed. Clients keying on it need no change.

  The eviction *policy* is deliberately untouched — newest-wins on an isolated
  duplicate still lets a client reclaim a half-open slot, the duel damper still
  holds the slot for a live incumbent, and displacement still triggers the
  stored-mail re-cover. The defect was never the policy; it was that the
  policy's outcome was unsayable.

## [0.18.20] - 2026-08-19

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

  A second `trust-tasks-rs` 0.9 remains in the lockfile via this crate's
  `vta-sdk` dependency, and both coexist cleanly — no `trust-tasks-rs` type
  crosses that boundary. It clears when VTI ships a `vta-sdk` built on 0.11.



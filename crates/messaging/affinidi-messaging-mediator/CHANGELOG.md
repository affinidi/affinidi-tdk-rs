# Changelog

## Unreleased (0.24.0) — `trust-tasks-rs` 0.20

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

## Unreleased (0.22.3) — answer management Trust Tasks over TSP

A TSP-only deployment could not manage its own accounts. The dispatcher that
turns a `TrustTaskEnvelope` into `account/update`, `acl/get`,
`access-list/update` and the rest — `MessageType::process` — is wholly
`#[cfg(feature = "didcomm")]` and takes a DIDComm `Message`, so a TSP
`Direct`/`Control` message addressed to the mediator never reached it. It went
to `deliver_tsp_local` → `deliver_opaque`, which files it for pickup. There was
no packet a TSP-only client could send to set its own account ACL.

That bites where it is least visible. An account is created at authentication
with `global_acl_default`, so a permissive default hides the gap entirely; a
restrictive one leaves the client unable to fix its own ACL over any transport.
TSP delivery is not exempt from ACLs — `deliver_opaque` applies existence,
`RECEIVE_MESSAGES` and the access-list verdict through `delivery_decision`.

The handlers were already transport-agnostic: each takes the document, the
authenticated sender, `state` and `session`, and nothing about them is DIDComm.
So the dispatch splits into a core plus a wrapper per transport.

- `consume` runs the dispatch and returns the response document. It requires the
  caller to have established the sender cryptographically — the handlers
  authorise against that sender, so a caller passing an unverified claim would
  hand over the admin surface.
- The DIDComm wrapper is unchanged in behaviour: sender from `UnpackMetadata`,
  document from the message body, reply packed as a DIDComm message.
- The TSP wrapper unpacks a `Direct`/`Control` message addressed to this
  mediator, dispatches, then seals the reply to the sender and delivers it
  through the ordinary local path — so it arrives on the client's existing
  pickup socket. No second socket, and no new delivery mechanism.

The TSP sender carries the same standing as the DIDComm one: `direct::unpack`
verifies Ed25519 over envelope‖ciphertext against the key resolved from the
VID's DID document *and* opens with HPKE-Auth, binding the sender's static key.
Two independent proofs, which is what lets the handlers authorise on it
unchanged.

Requests are recognised by payload rather than a binding type URI, because the
client packs the bare task document and there is no envelope tag to switch on. A
document that parses *and* names a served type is claimed; everything else falls
through to delivery unchanged, so ordinary traffic addressed to the mediator is
unaffected.

**Behavioural note for operators.** A message that previously landed in the
mediator's own inbox is now answered if it is a served management task. Nothing
else changes, and no client is required to move — the DIDComm path is
untouched.

## Unreleased (0.22.2) — admit an inter-mediator relay over WebSocket

The WebSocket route now admits an anonymous inter-mediator relay hop, on the
same terms `/inbound` has always used: only when the operator has opted in via
`security.enable_inter_mediator_relay` (or the legacy implicit
`SEND_FORWARDED` in `global_acl_default`), and only for a socket that
identifies itself by offering the `relay-ack` subprotocol. The admission
decision itself now lives in one place — `jwt_auth::anonymous_relay_session` —
so the two routes cannot drift on *who* is let in.

What such a socket may do is deliberately narrow, and structurally so rather
than by enumeration:

- **It is never registered with the streaming task.** A relay session has no
  DID, so registering would claim the empty `did_hash`'s stream for an
  anonymous peer. Skipping it is what makes "a relay can only send" a property
  of the code rather than of which message types we happen to handle: the
  socket's inbound channel can never yield.
- **It is gated on `SEND_MESSAGES`, not `LOCAL`** — the same capability
  `message_inbound_handler` requires of the REST relay session. `LOCAL` gates
  access to an inbox this session does not have.
- **It gets a `RelayAck` per frame instead of a problem report.** A problem
  report is packed *to* `session.did`, which a relay session does not have,
  and the peer is a mediator waiting on a transport answer rather than a client
  reading its inbox. The ack carries the mediator error code and reason on
  refusal, so the rejection reaches the relaying peer's logs and — once retries
  are exhausted — the original sender.
- **Raw-TSP mode is forced off, and a binary frame closes the socket.** Neither
  can arise from a correct peer; both are enforced rather than assumed, because
  the cost of being wrong is an anonymous socket registered as a live streaming
  client.
- **`relay-ack` is echoed if and only if the socket will actually be acked.**
  An authenticated client that offers it is not a relay — a relay hop presents
  no credential — so the entry is dropped from the echo rather than reflected
  back. Same honesty requirement as `tsp-ack`, and here it is load-bearing: the
  relaying peer relays over the socket *because* of that echo.
- **The socket has a bounded lifetime** (one hour). There is no token expiry to
  inherit, and re-admission re-runs the relay-enabled check against current
  configuration — so turning relay off takes effect without a restart.

`docs/multi-mediator.md` §7 is updated, and its §11 "known gaps" is now empty:
this was the gap.

The `affinidi-messaging-mediator-common` requirement moves from `0.15.37` to
`0.15.44`, the version that introduces `relay_ack`. The old floor allowed a
consumer resolving from the registry to pick a `0.15.x` without the module and
fail to build this crate — normally masked by cargo picking the newest patch,
but not under a lockfile pinning an older one. (`publish dry-run` is expected
to be red on this PR: it resolves each crate against the registry in isolation
and cannot see an unpublished sibling from the same PR. mediator-common 0.15.44
verifies and publishes cleanly on its own, so the release job's dependency
ordering resolves it.)

## Unreleased (0.22.1) — a multi-mediator guide, and the gaps writing it exposed

`docs/multi-mediator.md` documents federating two or more independent
mediators. The material existed only as scattered fragments — a section of
`docs/acls.md`, a section of the test-mediator README, `TestTopology`'s
rustdoc, and the config file's per-key comments — with nothing tying them
together.

What it covers, and the parts that were not written down anywhere before:

- **The two hop shapes land on different code paths at the receiving
  mediator.** A double forward arrives as a forward and needs
  `RECEIVE_FORWARDED`; a single forward (`ATM::send_to`'s DIDComm shape)
  arrives as a *direct delivery* and needs `local_direct_delivery_allowed`.
- **The four accounts one cross-mediator delivery consults**, with the error
  code each produces — including the non-obvious one: the *peer mediator's*
  DID needs an account with `RECEIVE_FORWARDED` on the relaying mediator, and
  nothing but `global_acl_default` creates it. The shipped default grants
  neither forwarded bit, so it is not a federation configuration.
- **Endpoint classification** — DID vs URL, one hop of indirection, and the
  three "Storing locally — it will not be delivered" warnings that follow a
  `200` to the sender.
- Blind vs rewrap, relay admission, delivery mechanics, the TSP differences, a
  `TestTopology` recipe, and a symptom-to-cause table.

Every claim is sourced from the code path named in its section and from the
cross-mediator e2e suites, which the document lists as its executable form.

**`ERRORS.md`:** the table stopped at 89 while the code reaches 94. Adds 90
(`me.res.forwarding.enqueue`), 91, 92, 94 (`protocol.forwarding.loop_detected`)
and the second variants of 58 (`message.tsp.no_endpoint`) and 60
(`authorization.relay.untrusted_peer`) — the last two both on relay paths this
document sends readers to. Corrects the access-list batch limit row, which was
still filed under 82 after the code moved it to 93.

**`conf/mediator.toml`:** documents `max_hops` (previously defaulted at 10 with
no mention in the file) and names `LOCAL_ENDPOINTS`. The `Env:` lines for
`PROCESSOR_FORWARDING_RELAY_MODE` and
`PROCESSOR_FORWARDING_RELAY_TRUSTED_MEDIATORS` were describing overrides that
did not exist; they do now — see mediator-config 0.2.2.

Also picks up mediator-common 0.15.43, which stops the forwarding processor
re-attempting a WebSocket upgrade that an anonymous relay hop can never pass.

Documentation, configuration comments and a dependency bump — no behaviour
change in this crate.

## Unreleased (0.22.0) — `jsonwebtoken` is now a private dependency, and moves to 11

Closes [#770]. **Breaking:** `SecurityConfig::jwt_encoding_key` and
`jwt_decoding_key` are no longer public fields. Set them with the new
[`SecurityConfig::set_jwt_keys_from_pkcs8`], which takes the Ed25519 PKCS#8
document — the same bytes the production path already reads from the
`JWT_SECRET` well-known entry — and derives both keys from it.

**Why this was worth a breaking change.** Those fields are `jsonwebtoken` types,
so while they were public, `jsonwebtoken` was a *public dependency* of this
crate: anyone constructing a `SecurityConfig` had to name `EncodingKey` /
`DecodingKey` and therefore had to compile against the same `jsonwebtoken`
major we did. Every bump of it was then source-breaking for consumers rather
than routine currency.

That is not theoretical. It was caught in #767, where bumping to 11 as ordinary
dependency currency made `affinidi-messaging-test-mediator` fail to build
against the published mediator with `expected jsonwebtoken::decoding::DecodingKey,
found DecodingKey`. It would have gone green at release time, because crates
publish in dependency order — so a breaking change would have shipped as a patch
bump, and any consumer mixing versions would have got a type error pointing at
neither crate.

**`jsonwebtoken` 10 → 11** now lands as part of this, and from here on such
bumps are internal.

Two smaller consequences worth naming:

- The key derivation lived in two places (the config loader and the test
  fixture), each doing `Ed25519KeyPair::from_pkcs8` then `DecodingKey::from_ed_der`.
  It now lives only in `set_jwt_keys_from_pkcs8`, so the signing and verification
  keys cannot drift apart.
- New `install_jwt_crypto_provider()` at the crate root. `jsonwebtoken`'s
  `aws_lc_rs` provider is registered per *instance* of that crate, so a consumer
  installing it against its own copy installs nothing for the copy this mediator
  verifies with. While the key fields were public that mismatch was at least a
  compile error; with the dependency private it would have become a silent
  runtime failure, so the installation has to be callable from here.

[#770]: https://github.com/affinidi/affinidi-tdk-rs/issues/770

## Unreleased (0.21.0) — `trust-tasks-rs` 0.18

**`trust-tasks-rs` 0.17 → 0.18.** Follows `affinidi-messaging-sdk` 0.22.0. No
source change; the generated types this crate uses are unaffected by 0.18's
only change. Minor rather than patch because the SDK's move is breaking for
consumers — `trust-tasks-rs` is a public dependency of its API — and this
crate's requirement moves with it.

## 0.20.11 — dependency currency

Published. No behaviour change. Two major-version dependency bumps, verified
against the full suite (242 unit tests, 30 e2e suites) rather than a compile:

- **`itertools` 0.14 → 0.15.**
- **`tikv-jemallocator` 0.6 → 0.7** — the allocator behind the `jemalloc`
  feature. The memory work in 0.17.0 measured against jemalloc, so this is worth
  re-measuring if RSS is ever in question again.

`jsonwebtoken` 10 → 11 was attempted here and pulled back out: `SecurityConfig`
exposes `pub jwt_encoding_key: EncodingKey` and `pub jwt_decoding_key:
DecodingKey`, so jsonwebtoken is a **public dependency** of this crate's API and
bumping it is semver-breaking rather than routine currency. Tracked separately.

## Unreleased (0.20.10) — TSP relay honours the peer-mediator allowlist

Closes [#758], raised by the AgenticSec review on #756 (alert 67) and by the
correction it prompted: `relay_peer_trusted` was DIDComm-only, so a TSP
deployment that needed its relaying peer authenticated had no lever at all.

`processors.forwarding.relay_trusted_mediators` now applies to TSP relay hops,
and TSP gets a stronger form of it than DIDComm. A routed or nested hop is
sealed to this mediator, so `handle_inbound_tsp` unpacks it — verifying an
Ed25519 signature over envelope‖ciphertext against the key in the sender's DID
document, *and* opening the payload with HPKE **Auth**, which binds the sender's
static key. Two independent proofs, so the peer identity the allowlist is
checked against is cryptographically established rather than claimed.

**No `RelayMode` distinction is needed.** DIDComm can only identify its peer in
`RelayMode::Rewrap`, where a layer addressed to this mediator can be
authcrypt-opened; in `Blind` the peer is invisible and the allowlist is ignored.
TSP routed relay is re-wrap-like *by construction* — every hop is sealed to the
next and authenticated as the previous — so there is no mode to select and no
blind variant to except.

Two scoping rules, both load-bearing:

- **Anonymous sessions only.** This is the part that differs from DIDComm and is
  easy to get wrong. Only a peer mediator ever produces a DIDComm re-wrap layer,
  so peeling one is inter-mediator by construction; a TSP *routed* message is
  not — an ordinary client sends one through its own mediator for metadata
  privacy (TSP §5.5). Gating those on a list of peer *mediators* would refuse
  every routed client the moment an operator populated it. An inter-mediator hop
  arrives with no `Authorization` header, on the anonymous session, which is
  exactly the traffic this list exists to admit or refuse.
- **Relay arms only.** `Direct` and `Control` addressed to this mediator are
  messages *to* it — Trust Tasks over TSP arrive that way — not relays through
  it.

What this does **not** cover, stated plainly: TSP opaque pass-through (a message
addressed to a local recipient rather than to this mediator) has nothing
addressed to us to open, so there is no peer to identify and no allowlist can
apply. That is the true analogue of DIDComm blind relay. `security.enable_inter_mediator_relay`,
which gates anonymous inbound at all, and `security.local_direct_delivery_allowed`
are the levers there. The comment added in 0.20.7 saying TSP had no equivalent
hardening has been corrected to say precisely which hops are now covered.

Not a behaviour change for any deployment leaving `relay_trusted_mediators`
empty, which is the default and means "accept any peer".

[#758]: https://github.com/affinidi/affinidi-tdk-rs/issues/758

## Unreleased (0.20.9) — TSP direct delivery honours `local_direct_delivery_allowed`

Closes [#757], the gap deliberately left open by 0.20.7 and independently
confirmed by the security review on that PR.

`security.local_direct_delivery_allowed` exists so an operator can refuse
unwrapped direct delivery and force everything through a routing envelope, where
the relay layer can audit it, scrub metadata, or inspect it. The DIDComm path
enforced it; `handle_inbound_tsp` did not, so any TSP-capable sender walked
straight past that control and the operator got no such enforcement for TSP
traffic.

- The `receiver != mediator` branch of `handle_inbound_tsp` — the genuine
  direct-delivery case — now returns the same `direct_delivery.denied` (code 71)
  report the DIDComm branch does when the switch is off.
- **No TSP analogue of `local_direct_delivery_allow_anon`, deliberately.** That
  hatch exists because a DIDComm envelope can be anon-packed with no sender at
  all; a TSP envelope always names its sender in the clear, so there is no
  anonymous TSP case to admit. `docs/acls.md` now records this as the single
  remaining asymmetry between the two protocols, in place of the deviation note
  0.20.7 added.
- Relay and nested submissions are unaffected: they are addressed to the
  mediator, not to a local account, so they never reach this branch.

**Behaviour change.** A deployment running with direct delivery disabled — the
code default when the setting is absent, though the shipped `conf/mediator.toml`
sets `"true"` — will now refuse direct TSP delivery that it previously accepted.
That is the point of the fix, but it is a break for anyone who had (knowingly or
not) been relying on TSP bypassing the switch (R3.6).

**Test-harness change (`affinidi-messaging-test-mediator` 0.4.4).** The fixture
defaults the flag off, and 23 TSP tests across nine files were written against a
path that ignored it. Rather than 23 hand-rolled builders, the harness gained
`TestEnvironment::spawn_with_direct_delivery()`, and the two TSP-specific spawns
(`spawn_with_tsp_auth`, `spawn_with_tsp_policy`) now enable direct delivery
themselves — every caller of those needs it, since protocol selection and pure-TSP
auth are only observable once a message is accepted. Tests whose subject *is* the
policy state it at the call site instead.

[#757]: https://github.com/affinidi/affinidi-tdk-rs/issues/757

## Unreleased (0.20.8) — state the v2 addressing contract: DID-addressed, no keylist

Answers [#755]. A downstream transport binding measured that delivery to a
`did:key` client works purely on the authenticated session DID, with no keylist
update, and asked whether that is a contract or an accident.

It is structural, and now it is written down.

- **New `docs/mediation-and-routing.md`.** DIDComm v2 routing is DID-addressed:
  a `routing/2.0` forward names its next hop as a DID, which hashes straight
  into the recipient's account lookup. There is no verkey indirection for a
  keylist to populate, so a v2 client registers nothing. The mediator maintains
  the account itself — `resolve_next_account` creates one on first forward, and
  authentication registers the DID too.
- **The keylist that exists is v1-only, and the document says why.** A DIDComm
  v1 (Aries RFC 0019) envelope carries no DID, so the recipient is identified by
  verkey and the mediator must hold the verkey→account mapping; the keylist is
  how a wallet populates it. It exists to manufacture a stable identifier for a
  client that has none — which a v2 `did:key` client already has.
- **The advertised protocol set is now a named constant**,
  `messages::protocols::discover_features::ADVERTISED_PROTOCOLS`, which
  `server.rs` builds its `DiscoverFeatures` state from. The list was previously
  inline in a long startup function and could not be asserted on.
- **`coordinate_mediation_is_not_advertised`** pins the absence, so implementing
  v2 mediation becomes a deliberate act — amending a contract other people have
  built on — rather than an incidental change that silently invalidates it.
  `did_addressed_delivery_protocols_are_advertised` is its control: without it
  the first test would pass just as happily against an empty list.

The document is also explicit that "no keylist" is not "no requirements", since
that is the part most likely to bite a client author. `mediator_acl_mode =
"explicit_allow"`, the `LOCAL` / `RECEIVE_MESSAGES` / `RECEIVE_FORWARDED`
capabilities, the recipient's access list and `local_direct_delivery_allowed`
all gate reachability without any keylist being involved — and direct delivery
to a DID that has never authenticated is refused (`direct_delivery.recipient.unknown`)
where a forward to the same DID would auto-create the account.

No behaviour change: documentation, one extracted constant, and three tests.

[#755]: https://github.com/affinidi/affinidi-tdk-rs/issues/755

## Unreleased (0.20.7) — bind a TSP envelope's sender to the authenticated session

**Security fix: the TSP ingress trusted the envelope's claimed sender.**
Reported as [#754], measured against a public deployment: a TSP frame sent on a
socket authenticated as DID A, carrying envelope sender DID E (never
authenticated), was forwarded normally.

A TSP envelope names its sender in the clear and the mediator does not decrypt
it, so `meta.sender` is a claim. `handle_inbound_tsp` never consulted the
session at all — it passed that claim straight to `deliver_opaque`, which hashes
it into the recipient's `delivery_decision` access-list lookup. An authenticated
client could therefore borrow any allow-listed VID and be admitted to an inbox
that does not admit it.

This is the TSP twin of the DIDComm direct-delivery bypass fixed in 0.15.5. The
TSP path was written after that fix and did not carry it. `docs/acls.md` §6 has
documented the flow as "Direct delivery (DIDComm and TSP)" — including the
session-DID match — the whole time, so the contract was already stated; only the
implementation was missing.

- The cleartext envelope sender is now bound to the session DID under the same
  `security.force_session_did_match` switch the DIDComm paths use, reusing the
  same `check_direct_delivery_session_match` predicate and returning the same
  `authorization.did.session_mismatch` problem report.
- Checked on the **outer** envelope, before the receiver branch, so it covers
  relayed and nested submissions too: a client must have authored the layer it
  hands over. Inner layers are exempt by construction — they are sealed to
  someone else.
- **Anonymous sessions are exempt**, exactly as on the DIDComm side since 0.20.4:
  an inter-mediator relay hop is POSTed to `/inbound` with no `Authorization`
  header and lands on the anonymous `ANON-INBOUND` session, whose DID is empty.
  Without the exemption cross-mediator TSP delivery would stop entirely. The
  residual cost is the one already named for blind relay: on an anonymous hop the
  claimed sender stays unverified, which is inherent to relaying. Note the
  asymmetry: DIDComm deployments that need the relaying peer authenticated can run
  `RelayMode::Rewrap` with `processors.forwarding.relay_trusted_mediators`, and
  **TSP has no equivalent yet** — `relay_peer_trusted` is DIDComm-only. Anonymous
  inbound is itself opt-in (`security.enable_inter_mediator_relay`, or the legacy
  implicit `SEND_FORWARDED` in `global_acl_default`), which bounds the exposure to
  relay-enabled deployments.
- Direct TSP delivery now also checks the sender's own `SEND_MESSAGES`, mirroring
  the DIDComm direct-delivery branch. This is load-bearing on the **WebSocket**
  ingress in particular, which gates only on `LOCAL` at upgrade: a DID whose
  `SEND_MESSAGES` had been revoked could still post TSP frames over a socket.

**Behaviour change.** A client that deliberately sends under a VID other than the
one it authenticated as will now be refused with
`e.p.authorization.did.session_mismatch` unless the deployment sets
`security.force_session_did_match = "false"`. Deployments relying on the split
between connection identity and egress identity should move to TSP **routed**
mode, where the outer sender is the connection identity and the egress identity
travels inside the sealed layer — that shape satisfies the binding by
construction (R3.6: coordinate with consuming repos).

**Still outstanding, tracked separately:** TSP direct delivery does not honour
`security.local_direct_delivery_allowed`, so a deployment that has turned direct
delivery off to force everything through a routing envelope still accepts direct
TSP. That is a policy change with far wider blast radius than this fix — it
changes the default fixture's behaviour for ~20 existing tests — and is being
handled on its own rather than folded in here.

[#754]: https://github.com/affinidi/affinidi-tdk-rs/issues/754

## Unreleased (0.20.6) — TSP forwarding follows a next hop that names its mediator by DID

**Bug fix: TSP remote forwarding could not deliver to a mediated peer.** Observed
on a live mediator:

```text
WARN forwarding::processor: FORWARD_FAILED
  endpoint=did:webvh:Qmb…:dids.firstperson.dev:firstperson-mediator
  error=Connection error to did:webvh:…/inbound:
        builder error for url (did:webvh:…/inbound)
  retry_count=5  → FORWARD_ABANDONED
```

The `endpoint` is a DID, not a URL. Two documents are involved, and the mediator
was only reading the first:

```text
persona     #tsp  TSPTransport  serviceEndpoint: did:webvh:…firstperson-mediator
that mediator #tsp TSPTransport  serviceEndpoint: https://mediator.firstperson.dev/mediator/v1
```

- `forward_tsp_remote` no longer takes `endpoints.first()` as a URL. A new
  `classify_tsp_relay` decides — without I/O — between a direct transport URL, a
  mediator DID to follow, a hop that comes back to us, and nothing usable. A
  mediator DID is resolved **one hop**, and that document's own `TSPTransport`
  URL is what the forward is enqueued against.
- **One hop only**, mirroring `protocols::routing::service_endpoint_for_remote`
  on the DIDComm side (added in #705 for exactly this shape): a mediator's own
  document is expected to publish a URL, and chasing further would let a chain of
  documents steer this mediator's relay.
- The loop guard is extended, not weakened: a transport URL on one of our own
  authorities still fails as a loop, and so does a next hop that names *this*
  mediator as its mediator while holding no account here.
- Failure now names the next hop and distinguishes its causes —
  `message.tsp.no_endpoint`, `message.tsp.mediator.unresolvable` (the named
  mediator did not resolve) and `protocol.forwarding.loop_detected` — at the
  point the forward is accepted, rather than five retries later inside an HTTP
  client that has no idea whose message it is.
- `tsp_endpoint_is_self` is gone; the TSP path now shares
  `server::uri_points_at_self` with the DIDComm relay. That also fixes an IPv6
  mismatch in the TSP copy, which compared `Url::host_str()` (`"[::1]"`)
  against the bare form the authority set stores (`"::1"`) and so never matched.

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



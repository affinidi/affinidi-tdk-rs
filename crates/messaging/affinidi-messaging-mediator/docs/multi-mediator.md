# Multi-mediator: federation, relay and cross-mediator delivery

Two different things get called "multi-mediator", and only one of them is
this document:

- **A cluster** — several mediator *processes* sharing one Redis, one DID and
  one account store. That is horizontal scale of a single mediator; see the
  storage backend notes in [`../README.md`](../README.md) and
  [`memory-tuning.md`](./memory-tuning.md). Fjall cannot do it (no
  cross-process pub/sub).
- **A federation** — several *independent* mediators, each with its own DID,
  its own accounts and its own operator, relaying messages to each other so a
  user homed on mediator A can reach a user homed on mediator B. **That is
  this document.**

Everything below is sourced from the code paths named in each section and
from the end-to-end tests listed in §9; those tests are the executable form of
this document.

---

## 1. What a hop actually looks like

Alice is homed on mediator **A**, Bob on mediator **B**. There are two
client-side constructions, and they land on *different* code paths at B. This
is the single most common source of confusion, so it is first.

### 1a. The double forward (explicit next hop)

```text
Alice ──▶ A                                   B ──▶ Bob
          │                                   ▲
   outer forward                        inner forward
   to=A, next=B                         to=B, next=Bob
   attachment = inner forward           attachment = authcrypt(Alice→Bob)
          └────── POST /inbound (anonymous) ──┘
```

Alice builds it inside-out: authcrypt for Bob, an **inner** `forward`
addressed to B with `next = Bob`, an **outer** `forward` addressed to A with
`next = B`. A peels the outer, sees `next = B` is remote, and relays the inner
forward to B's `/inbound`. B peels it, sees `next = Bob` is local, and stores
it for pickup.

At B the message arrives as a *forward*, so B's forward gate applies: Bob's
account needs `RECEIVE_FORWARDED`.

The SDK builds each layer with
`atm.routing().forward_message(profile, anonymous, message, target_did,
next_did, ...)` — called twice. `TestTopology::forward` is exactly this
(`affinidi-messaging-test-mediator/src/topology.rs`).

### 1b. The single forward (mediator discovers the next hop)

```text
Alice ──▶ A ─── POST /inbound ───▶ B ──▶ Bob
   forward to=A, next=Bob      authcrypt(Alice→Bob), verbatim
```

Alice sends *one* `forward` to A with `next = Bob`. A resolves Bob's DID
document, finds it mediated by B (§2), and relays the **inner authcrypt
itself** — there is no forward envelope left by the time it reaches B.

At B that envelope is addressed to a local account, which is a **direct
delivery**, not a forward. So B needs `local_direct_delivery_allowed = true`,
and Bob needs `RECEIVE_MESSAGES` rather than `RECEIVE_FORWARDED`. A mediator
that terminates single-forward relays with direct delivery switched off drops
them. (Regression test: `blind_relay_direct_delivery_reaches_recipient`.)

This is the shape `ATM::send_to` produces on the DIDComm path, so it is what
you get by default when the sender knows only the recipient's DID.

---

## 2. How the sending mediator decides local vs remote

`service_endpoint_for_remote` (`src/messages/protocols/routing.rs`) resolves
the next hop's DID document and classifies every `DIDCommMessaging` service
endpoint URI it publishes:

| Endpoint URI shape | Classification | Result |
|---|---|---|
| This mediator's own DID | `Local` | store locally |
| `http(s)://` / `ws(s)://` whose `(host, port)` is one of ours | `Local` | store locally |
| `http(s)://` / `ws(s)://` anywhere else | `Remote(url)` | enqueue on `FORWARD_Q` |
| Another `did:...` | `Indirect(did)` | resolve **one** hop, classify that document's endpoints the same way |
| Anything else | — | treated as local, with a warning |

Rules that matter in production:

- **Publish the mediator's DID, not its URL**, in a user's DIDComm service
  entry. The `Indirect` arm is the shape the VTI stack publishes and it is
  followed correctly; a URL works too but couples the user's document to the
  mediator's hostname.
- **Only one hop of indirection is followed.** A mediator's own document is
  expected to publish a transport URL. A chain of documents cannot steer a
  relay.
- **`(host, port)` self-matching is how loops are avoided.** The bind address
  is compared case-insensitively, with IPv6 normalisation and scheme-default
  ports. With the default wildcard `listen_address` (`0.0.0.0`) a public
  hostname never literally matches, so a hostname-fronted deployment (load
  balancer, public DNS, ingress) **must** declare `server.local_endpoints`, or
  a message addressed to one of its own users is relayed to itself.
- **The "storing locally" warnings are delivery failures.** Three log lines
  say a message was accepted and will never arrive:

  ```text
  Next hop (…) publishes a DIDCommMessaging service this mediator can't turn into an endpoint (…). Storing locally — it will not be delivered.
  Next hop (…) is mediated by (…), which couldn't be resolved: …. Storing locally — it will not be delivered.
  Next hop (…) is mediated by (…), whose document publishes no DIDComm endpoint URL. Storing locally — it will not be delivered.
  ```

  Alert on them. The sender got a `200`.

Setting `processors.forwarding.external_forwarding = "false"` skips this
classification entirely and makes every forward local — useful for isolating
the forward handler in tests, never for a federated deployment.

---

## 3. Relay modes: blind vs rewrap

`processors.forwarding.relay_mode` decides what goes on the A→B wire.

| | `blind` (default) | `rewrap` |
|---|---|---|
| What is relayed | the inner envelope, verbatim | a fresh `forward`, authcrypted **from A to B**, carrying the inner envelope as its attachment |
| Original sender's key id on the wire | visible (authcrypt carries it in the clear in the JWE header) | hidden |
| Can B identify the relaying peer? | no — nothing is addressed to B | yes — authcrypt names A |
| Peer allowlist usable? | no | yes |
| Both sides must agree? | — | **yes**, both mediators must run `rewrap` |

In rewrap mode A calls `rewrap_for_relay`, and B peels the layer in
`peel_relay_rewrap_layers` (`src/messages/inbound.rs`) before processing:
unpack, confirm `next == B`, check the peer allowlist, decode the attachment,
repeat. The peel loop is bounded by `max_hops`; exceeding it is error 94,
`protocol.forwarding.loop_detected`.

`hop_count` is carried across the re-wrap rather than reset, so loop detection
survives the mode.

`processors.forwarding.relay_trusted_mediators` is the receiver-side allowlist
of peer mediator DIDs. Empty accepts any peer (still ACL-gated); non-empty
admits only its members and rejects anonymous peers outright. An unlisted peer
is refused with error 60, `authorization.relay.untrusted_peer`. Where it does
and does not apply is tabulated in [`acls.md` §6, "Inter-mediator relay
admission"](./acls.md) — read that table before populating the list, because
it does **not** apply to blind relay or to TSP opaque pass-through, and must
not apply to an ordinary client's routed message.

---

## 4. Admission on the receiving mediator

An inter-mediator hop is POSTed to `/inbound` **with no Authorization
header**. It lands on the anonymous session `ANON-INBOUND`, whose ACL set is
synthesised as exactly `DENY_ALL,SEND_MESSAGES,SEND_FORWARDED`
(`relay_anonymous_acls`, `src/common/jwt_auth.rs`) — never the mediator's
global default.

That session is created only when the mediator is configured as a relay:

- `security.enable_inter_mediator_relay = "true"` — the explicit flag; or
- `security.global_acl_default` grants `SEND_FORWARDED` — the legacy implicit
  behaviour, which logs a deprecation warning at boot and will stop working in
  a future release.

Otherwise the anonymous request is rejected like any other unauthenticated
one, and the cross-mediator forward never reaches the recipient. (Test:
`non_relay_mediator_rejects_cross_mediator_forward`.)

Two adjacent gates that are *not* the relay gate, and are easy to confuse
with it:

- `security.block_anonymous_outer_envelope` — the envelope must carry an
  authcrypt sender or a JWS. A relayed envelope normally does.
- `security.force_session_did_match` — the envelope sender must match the
  session DID. It is deliberately skipped for unauthenticated sessions (the
  anonymous relay session has no DID and would fail every comparison), and
  still enforced for authenticated clients. (Test:
  `authenticated_direct_delivery_still_enforces_session_match`.)

---

## 5. Configuration, side by side

A is the sending/relaying mediator, B the receiving one. In a bidirectional
federation both roles apply to both mediators.

| Setting | A (relays out) | B (accepts in) | Notes |
|---|---|---|---|
| `processors.forwarding.enabled` | `true` | `true` | the queue consumer |
| `processors.forwarding.external_forwarding` | `true` | — | `false` collapses every forward to local delivery |
| `processors.forwarding.relay_mode` | `blind` \| `rewrap` | must match A | `PROCESSOR_FORWARDING_RELAY_MODE` |
| `processors.forwarding.relay_trusted_mediators` | — | peer DIDs, or empty | rewrap and TSP routed hops only; `PROCESSOR_FORWARDING_RELAY_TRUSTED_MEDIATORS`, comma-separated |
| `processors.forwarding.max_hops` | applies | applies | default 10; `PROCESSOR_FORWARDING_MAX_HOPS` |
| `processors.forwarding.blocked_forwarding_dids` | JSON array string | — | own DID + every service URI in its document are added automatically |
| `security.enable_inter_mediator_relay` | — | `true` | admits the anonymous `/inbound` hop |
| `security.global_acl_default` | must grant `RECEIVE_FORWARDED` (§6) | must grant `SEND_FORWARDED` (§6) | a relay deployment typically runs `ALLOW_ALL`; see [`acls.md` §7](./acls.md) |
| `security.local_direct_delivery_allowed` | — | `true` for single-forward relays (§1b) | not needed for the double forward |
| `server.local_endpoints` | required behind a hostname/LB | required behind a hostname/LB | otherwise the mediator relays to itself; `LOCAL_ENDPOINTS`, comma-separated |
| storage backend | any | any | Redis only if you also scale each mediator across processes |

---

## 6. The ACLs that have to line up

Four different accounts are consulted for one cross-mediator delivery. Getting
any of them wrong produces a `403` in a place that looks unrelated.

**On A (sender's mediator):**

| Account | Capability | Enforced by | Error |
|---|---|---|---|
| Alice | `SEND_FORWARDED` | `resolve_forward_sender` | 60 `authorization.send_forwarded` |
| the next hop — **B's DID** for a double forward, **Bob's DID** for a single forward | `RECEIVE_FORWARDED` | forward gate | 58 `authorization.receive_forwarded` |

The next-hop account is auto-created on first contact with A's
`global_acl_default` (`resolve_next_account`). **This is why a relay mediator
needs a default that grants `RECEIVE_FORWARDED`**: the peer mediator's DID has
to hold an account on A, and nothing else creates it.

**On B (recipient's mediator):**

| Account | Capability | Enforced by | Error |
|---|---|---|---|
| Alice (no account on B) | `SEND_FORWARDED` | `resolve_forward_sender` | 60 `authorization.send_forwarded` |
| Bob | `RECEIVE_FORWARDED` (double forward) or `RECEIVE_MESSAGES` (single forward) | forward gate / direct delivery | 58 `authorization.receive_forwarded` / 74 `authorization.receive` |
| Bob's access list | must admit Alice | `check_access_list` | 73 `authorization.access_list.denied` |
| — (mediator policy, single forward only) | `local_direct_delivery_allowed` | direct-delivery gate | 71 `direct_delivery.denied` |
| Bob, if the inner envelope is anon-packed | `ANON_RECEIVE` | `deliver_forward` | 69 `authorization.receive_anon` |

Alice is an account-less forward sender on B, so B auto-registers her via
`relay_sender_acls` — which seeds `SEND_FORWARDED` **only if B's
`global_acl_default` grants it**, and nothing else (no `LOCAL`, no
`RECEIVE_*`, no invites, no self-management). A DID that has only ever relayed
a forward through B does not gain an inbox there.

Consequence worth stating plainly: **the shipped default
`global_acl_default = "DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES"` is not
a federation configuration.** It grants neither forwarded bit. A mediator that
should relay needs at minimum the "Relay only" or an allow-all recipe from
[`acls.md` §7](./acls.md).

---

## 7. Delivery mechanics

Once A classifies a next hop as remote, the forward is enqueued on `FORWARD_Q`
(`forward_queue_enqueue`, bounded by `limits.forward_task_queue`, default
50 000) and the forwarding processor delivers it.

- **Transport.** Per-endpoint rate is tracked over `rate_window_seconds`; at
  or above `ws_threshold_msgs_per_10s` (default 1 msg/10s) the processor
  prefers a pooled WebSocket, otherwise REST. **Between two mediators running
  this implementation the WebSocket never opens, and every hop lands on
  REST**: `deliver_via_websocket` connects with no `Authorization` header —
  the relaying mediator holds no session on its peer — while the peer's
  upgrade handler requires a valid bearer token *and* the `LOCAL` capability.
  The first failed attempt suppresses WebSocket for that endpoint for five
  minutes (`WS_SUPPRESSION_WINDOW`) so the cost is one failed connect per
  window rather than one per message; the window then re-probes, so a peer
  that does accept anonymous upgrades is still picked up. Watch for
  `Falling back to REST and suppressing WebSocket` in the logs.
- **REST shape.** `POST {endpoint}/inbound`, `Content-Type:
  application/didcomm-encrypted+json` for DIDComm, `application/tsp` (raw qb2)
  for TSP. TSP always goes over REST regardless of rate.
- **Retry.** `max_retries` (5) with exponential backoff from
  `initial_backoff_ms` to `max_backoff_ms`, in batches of `batch_size`.
- **Abandonment.** On exhaustion the entry is ACKed and dropped, logged as
  `FORWARD_ABANDONED`, and — when `report_errors` is set — a problem report is
  packed by the mediator and stored in the *sender's* inbox
  (`FORWARD_PROBLEM_REPORT`). Test:
  `forwarding_abandonment_report.rs`.
- **Durability.** The queue survives restart on Redis and Fjall; the in-memory
  backend loses it.
- **Loop protection.** `hop_count` increments per relay and is rejected at
  `max_hops` (error 94). Independently, `blocked_forwarding` — the mediator's
  own DID plus every service endpoint URI in its document, loaded at boot by
  `load_forwarding_protection_blocks` — prevents packing a forward that loops
  back to itself.
- **Observability.** `FORWARD_ENQUEUED` (with `endpoint=`),
  `MESSAGES_FORWARDED_TOTAL`, `FORWARD_LOOP_DETECTED_TOTAL`.

---

## 8. TSP across mediators

TSP federates over the same loopback: A unwraps its routing layer, sees the
next hop is B, resolves B's advertised **`TSPTransport`** endpoint, re-seals
the onward route to B, and the forwarding processor POSTs it to B's
`/inbound`.

Differences from DIDComm that matter:

- **There is no relay mode to choose.** A TSP routed hop is sealed to the next
  mediator and signed by the previous one, so it is rewrap-like by
  construction: `unpack` verifies an Ed25519 signature over
  envelope‖ciphertext *and* opens the payload with HPKE-Auth. Two independent
  proofs, so `relay_trusted_mediators` is always applicable to a routed or
  nested hop on an anonymous session.
- **It must not gate clients.** An ordinary client sends a routed message
  through its own mediator for metadata privacy (TSP §5.5) on an
  *authenticated* session. The allowlist check is scoped to anonymous sessions
  precisely so populating it does not break those. Test:
  `client_routed_message_is_unaffected_by_the_peer_allowlist`.
- **Opaque pass-through is the blind analogue.** When the cleartext receiver
  is not this mediator there is nothing addressed to us to open and no peer to
  identify; `local_direct_delivery_allowed` and `enable_inter_mediator_relay`
  are the only levers.
- **Advertise `TSPTransport` or nothing routes to you.** `did:web` gets it
  automatically at startup (mirroring the DIDComm endpoint — they share
  `/inbound`); `did:peer` and `did:webvh` are bound to their document, so the
  service must be added **when the DID is generated**. The mediator logs a
  startup warning if `tsp` is enabled and no `TSPTransport` is advertised.
- **Client-side routing.** `ATM::send_to` routes cross-mediator automatically
  when the peer's mediator is known and differs from the sender's — learned
  from a routed relationship invite via `record_incoming_control`, or set
  explicitly with `TspOps::set_peer_mediator` (the service-less `did:key`
  case). Otherwise it sends Direct via its own mediator.

See [`../../../../docs/tsp/cookbook.md`](../../../../docs/tsp/cookbook.md) for
the client-side TSP API.

---

## 9. Reproducing a federation locally

`TestTopology` (`affinidi-messaging-test-mediator`) spawns N in-process
mediators, each relay-enabled and wired to its own SDK environment, with no
Redis and no external network. Every identity is `did:peer:2.*`, so all DIDs
resolve locally and the mesh is fully connected; the only real socket traffic
is the loopback A→B `/inbound` POST.

```rust,ignore
let topology = TestTopology::builder().mediators(2).spawn().await?;
let alice = topology.add_user(0, "Alice").await?;   // homed on mediator 0
let bob   = topology.add_user(1, "Bob").await?;     // homed on mediator 1

let got = topology
    .forward(0, &alice, 1, &bob, "Hello Bob", Duration::from_secs(15))
    .await?;
assert_eq!(got.as_deref(), Some("Hello Bob"));
topology.shutdown().await?;
```

`.rewrap()` switches every node to `RelayMode::Rewrap`; `.configure_each(|b|
…)` reaches the underlying `TestMediatorBuilder` for per-node tuning. The
topology deliberately spawns every node with an allow-all default ACL and an
**empty** trusted-peer allowlist — that is what makes the mesh connect without
knowing each peer's DID before spawn. Tests that need a populated allowlist,
or a deliberately non-relay mediator, drop to `TestMediator::builder()`
directly.

The tests below are the verified reference for every claim in this document:

| Scenario | Test |
|---|---|
| Two-hop double forward | `test-mediator/tests/topology.rs`, `tests/cross_mediator_forwarding.rs` |
| Non-relay mediator refuses the hop | `cross_mediator_forwarding.rs::non_relay_mediator_rejects_cross_mediator_forward` |
| Rewrap round-trip, trusted and untrusted peer | `cross_mediator_forwarding.rs::rewrap_relay_*` |
| Rewrap crypto on the wire | `mediator/tests/relay_rewrap.rs` |
| Single forward → direct delivery at B | `cross_mediator_forwarding.rs::blind_relay_direct_delivery_reaches_recipient` |
| TSP federation over `TSPTransport` | `test-mediator/tests/tsp_federation.rs` |
| TSP routed/nested + peer discovery | `test-mediator/tests/tsp_cross_mediator.rs` |
| TSP peer allowlist scoping | `test-mediator/tests/tsp_relay_peer_trust.rs` |
| Abandonment problem report | `test-mediator/tests/forwarding_abandonment_report.rs` |

A runnable two-mediator demo against real deployments lives in
`affinidi-messaging-helpers/examples/cross_mediator_forwarding.rs` (pass
mediator **DIDs**, not URLs).

---

## 10. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Sender gets `200`, recipient never receives, no relay in A's logs | A classified the next hop as local | check A's logs for a "Storing locally — it will not be delivered" warning (§2); publish the mediator's DID in the user's service entry |
| Message loops back to A | A's public hostname doesn't match its bind address | set `server.local_endpoints` to every public URL in A's DID document |
| B returns `401` on `/inbound` | B isn't configured as a relay | `security.enable_inter_mediator_relay = "true"` on B |
| Error 60 `authorization.send_forwarded` at B | B's `global_acl_default` doesn't grant `SEND_FORWARDED`, so the auto-registered sender got nothing | widen B's default (§6) |
| Error 58 `authorization.receive_forwarded` at A | the peer mediator's auto-created account on A lacks the bit | A's `global_acl_default` must grant `RECEIVE_FORWARDED` |
| Error 60 `authorization.relay.untrusted_peer` | B's `relay_trusted_mediators` doesn't name A | add A's DID, or empty the list; confirm both sides run `rewrap` |
| Error 71 `direct_delivery.denied` at B | a single-forward relay landed as a direct delivery | `local_direct_delivery_allowed = "true"` on B, or send the double forward |
| Error 94 `loop_detected` | genuine loop, or `max_hops` too low for the topology | inspect the route before raising `max_hops` |
| `FORWARD_ABANDONED` in A's logs | B unreachable through `max_retries` | check B's endpoint and TLS; the sender receives a problem report |
| TSP messages never leave A | B advertises no `TSPTransport` service | add it (§8); `did:peer`/`did:webvh` need it at DID-generation time |

---

## 11. Known gaps

Accurate as of this document's commit; verify before relying on it.

- **Inter-mediator WebSocket delivery cannot authenticate.** A relay hop is
  anonymous by design, and the WebSocket route is not; the transport therefore
  degrades to REST between two mediators running this implementation (§7).
  Restoring it needs a relay-scoped WebSocket admission path on the receiving
  side — the same decision `security.enable_inter_mediator_relay` already
  makes for `/inbound` — not a change in the forwarding processor.

---

## Cross-references

- [`acls.md`](./acls.md) — the permission model; §6 has the relay-admission
  table
- [`mediation-and-routing.md`](./mediation-and-routing.md) — the addressing
  contract a recipient is reachable under
- [`../README.md`](../README.md) — features, deployment, TSP endpoint
  advertisement
- [`memory-tuning.md`](./memory-tuning.md) — queue and storage sizing for a
  relay-heavy mediator
- [`../../affinidi-messaging-test-mediator/README.md`](../../affinidi-messaging-test-mediator/README.md)
  — the fixture, including the local-vs-remote routing footgun

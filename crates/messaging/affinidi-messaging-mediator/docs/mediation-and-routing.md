# Mediation and routing: how a recipient becomes reachable

This document states the mediator's addressing contract, so client and
transport-binding authors can build on it rather than infer it from
observation.

The short version: **DIDComm v2 is DID-addressed and has no keylist.** A v2
client registers nothing before it can receive. DIDComm v1 does have a keylist,
because a v1 envelope has no DID to address.

---

## 1. DIDComm v2 — DID-addressed, no keylist

A `routing/2.0` forward names its next hop as a DID. The mediator hashes that
DID and looks the recipient up by the hash; delivery decisions are made against
the account it finds. There is no verkey, no routing key and no indirection of
any kind between the DID on the envelope and the account that receives — so
there is nothing a keylist could populate.

This is why the advertised protocol set
(`messages::protocols::discover_features::ADVERTISED_PROTOCOLS`) contains no
`coordinate-mediation` entry:

```
https://didcomm.org/discover-features/2.0
https://didcomm.org/routing/2.0
https://didcomm.org/trust-ping/2.0
https://didcomm.org/out-of-band/2.0
https://didcomm.org/messagepickup/3.0
https://affinidi.com/atm/1.0/authenticate
https://didcomm.org/mediator/1.0/admin-management
https://didcomm.org/mediator/1.0/account-management
https://didcomm.org/mediator/1.0/acl-management
https://didcomm.org/report-problem/2.0
```

The mediator maintains the account itself. `resolve_next_account` creates one on
first forward to an unknown DID, using `global_acl_default`; authenticating also
registers the DID. A client never has to ask.

`did:key` clients are the common case and are not special: a `did:key` has no
service endpoint, so it cannot be routed to from outside and instead collects
mail from the mediator it authenticated with, over `messagepickup/3.0` or the
WebSocket. That works on the authenticated session DID alone.

### How to depend on this

Assert on discover-features. If `https://didcomm.org/coordinate-mediation/*`
ever appears in the advertised set, the assumption has changed and your check
should fail loudly. On our side the same assertion runs as
`coordinate_mediation_is_not_advertised`, so adding v2 mediation cannot happen
by accident — it means amending this document too.

---

## 2. DIDComm v1 — keylist-addressed, because there is no DID

A v1 (Aries RFC 0019) envelope carries no DID. The recipient is identified by
**verkey**, so the mediator has to hold the verkey→account mapping itself, and
`coordinate-mediation/1.0` keylist-update is how a wallet populates it. The
account is keyed by the `did:key` derived from the client's authenticated
verkey (`messages::v1_mediation`).

So the keylist exists to *manufacture* a stable identifier for a client that
does not have one. A v2 `did:key` client already holds what the keylist would
have produced — which is the underlying reason it needs no keylist, and why
that is unlikely to change.

v1 support is compile-gated (`--features didcomm-v1`) and additive.

---

## 3. What *does* gate reachability

"No keylist" is not "no requirements". None of the following involves a keylist,
and all of them can make a v2 recipient unreachable:

| Gate | Effect |
|------|--------|
| `mediator_acl_mode = "explicit_allow"` | Unknown DIDs are refused at the authentication challenge, and v1 mediation is denied. Such a deployment registers DIDs out of band, via admin `account_add`. |
| Account existence, on **direct delivery** | A directly-delivered message to a DID with no account is refused: `direct_delivery.recipient.unknown` (error 72). Forwarding differs — it auto-creates the account. |
| `LOCAL` | Required to complete the WebSocket upgrade and to use inbox fetch/list/delete. |
| `RECEIVE_MESSAGES` | Required to accept direct delivery. |
| `RECEIVE_FORWARDED` | Required to accept a forwarded message. |
| Recipient's access list | Evaluated against the sender; see [`acls.md`](acls.md). |
| `local_direct_delivery_allowed` | When false, direct delivery is refused and senders must use a routing envelope. |

The asymmetry in row two is the one most likely to surprise: a recipient that
has authenticated at least once is reachable both ways, but a recipient that
never has can be reached by a *forward* and not by *direct delivery*.

---

## 4. Summary for binding authors

- v2: DID-addressed. No keylist, no registration call. Reachability is governed
  by ACLs and by deployment ACL mode, not by anything the client registers.
- v1: keylist-addressed, and the keylist is load-bearing.
- The falsifiable check is the discover-features advertisement, not this
  document.

Related: [`acls.md`](acls.md) for the capability and access-list model.

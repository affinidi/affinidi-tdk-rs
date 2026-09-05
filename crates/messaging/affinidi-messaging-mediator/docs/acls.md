# Mediator Access Control Guide

How the Affinidi mediator decides whether a DID may connect, send, receive,
forward, or administer. This is the reference for operators configuring a
deployment and for developers adding a permission check.

**The one thing to take away:** `mediator_acl_mode` decides whether the
mediator is open (`explicit_deny` — any DID may authenticate) or closed
(`explicit_allow` — only pre-registered DIDs may authenticate). On an open
mediator, `global_acl_default` is the setting that controls what an
arbitrary DID may then do.

---

## 1. The four layers

Access control is four independent mechanisms. They are often confused
because two of them use the same `ExplicitAllow` / `ExplicitDeny` enum while
meaning entirely different things.

| # | Layer | Scope | Set by | What it decides |
|---|-------|-------|--------|-----------------|
| 1 | `mediator_acl_mode` | mediator-wide | `mediator.toml` | Whether **unknown DIDs may authenticate**, and who may pre-register other DIDs via `account_add`. |
| 2 | `global_acl_default` | mediator-wide | `mediator.toml` | The ACL set handed to every new or unknown DID. |
| 3 | `MediatorACLSet` | per DID | admin, or the DID itself where delegated | What that DID may do (19 permission bits). |
| 4 | Access list | per DID | the DID (if delegated) or an admin | Which **senders** that DID accepts messages from. |

Layers 1 and 4 both use `AccessListModeType`. They are unrelated:

- **Layer 1** (`mediator_acl_mode`): `ExplicitAllow` = closed mediator —
  only pre-registered DIDs may authenticate, only admins may add accounts.
  `ExplicitDeny` = open mediator — any DID may authenticate and any
  authenticated DID may add accounts.
- **Layer 4** (a DID's own `access_list_mode` bit): `ExplicitAllow` = the
  access list is an **allowlist** (empty list ⇒ nobody may send to me).
  `ExplicitDeny` = it is a **denylist** (empty list ⇒ anybody may).

In both layers `ExplicitAllow` is the *closed*, secure posture; for layer 4
it is also `MediatorACLSet::default()`.

---

## 2. `mediator_acl_mode` — open or closed

```toml
[security]
mediator_acl_mode = "explicit_deny"   # or "explicit_allow"
```

It has two effects: who may authenticate, and who may add accounts.

| Mode | Authentication | `messaging/account/add` (DIDComm admin protocol and Trust Tasks) |
|------|----------------|------------------------------------------------------------------|
| `explicit_allow` | **Closed.** Only DIDs that already hold an account record may authenticate. An unknown DID is rejected at `/authenticate/challenge` with `403 authentication.blocked` and no account is created for it. | Only `Admin` / `RootAdmin` accounts may add accounts. |
| `explicit_deny` | **Open.** Any DID may authenticate; an unknown DID is auto-registered with `global_acl_default` when it requests a challenge. | Any authenticated DID may add accounts. |

In `explicit_allow`, the unknown-DID rejection is deliberately identical to
the blocked-DID rejection (same status, error code, and problem report):
`/authenticate/challenge` is unauthenticated, and a distinguishable error
would let anyone probe which DIDs hold accounts. The response step applies
the same policy — an account deleted between the challenge and the response
is treated as a revocation, not re-registered.

**It does not affect message delivery.** No send, receive, forward, or
pickup decision reads it.

**It does not let a non-admin grant privileges.** A non-admin using
`account_add` in `explicit_deny` mode always creates the account with
`global_acl_default`; any ACLs it supplies are ignored. Only admins may
specify custom ACLs. So in `explicit_deny` the worst a non-admin can do is
create account records that would have been created anyway on first
authentication.

> **Historical note.** Before mediator 0.18.0, `explicit_allow` did **not**
> gate authentication — any DID completing the challenge was auto-registered
> in either mode, and the only closed-ish posture was a denying
> `global_acl_default` (unknown DIDs authenticated but could do nothing).
> 0.18.0 made the mode enforce what its name always promised. If you run
> `explicit_allow` and *relied* on unknown DIDs being able to
> self-register, switch to `explicit_deny` with a restrictive
> `global_acl_default` (§3).

---

## 3. `global_acl_default` — the open-mediator control

```toml
[security]
global_acl_default = "DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES"
```

This is the ACL set applied to every DID the mediator has not seen before,
and the fallback whenever a permission check runs against a DID with no
stored record. On an open mediator (`explicit_deny`) it therefore decides
what an arbitrary DID off the internet can do; on a closed mediator
(`explicit_allow`) unknown DIDs never authenticate, and this setting only
matters as the account_add default and the no-record fallback.

It is consumed in four places:

1. **Registration.** Written verbatim as the new account's ACL set on every
   auto-registration path (§4).
2. **Fallback.** Any check on a DID with no account record uses it
   (`authz::effective_acls`).
3. **Seeding the inbox mode.** Its `access_list_mode` bit becomes each new
   DID's own allowlist/denylist mode (layer 4).
4. **Implicit relay.** If it grants `SEND_FORWARDED`, the mediator accepts
   anonymous inter-mediator relay on `/inbound` even without
   `enable_inter_mediator_relay = "true"`. This is deprecated and warns at
   boot; a future release will require the explicit flag.

### Ruleset syntax

A comma-separated string. `ALLOW_ALL` or `DENY_ALL` must come **first** if
present; later flags layer on top.

| Keyword | Effect |
|---------|--------|
| `ALLOW_ALL` | Every capability, every self-change bit, every `self_manage_*`, and `access_list_mode = ExplicitDeny` (open inbox). |
| `DENY_ALL` | No capability, no self-change, no self-management, and `access_list_mode = ExplicitAllow` (closed inbox). |
| `ALLOW_ALL_SELF_CHANGE` / `DENY_ALL_SELF_CHANGE` | Set/clear every self-change bit, leaving the capability values alone. |
| `MODE_EXPLICIT_ALLOW` / `MODE_EXPLICIT_DENY` | This DID's own access-list mode (layer 4). |
| `MODE_SELF_CHANGE` | Let the DID change its own access-list mode. |
| `LOCAL` | Grant an inbox (message storage). No `_CHANGE` variant — admin-only. |
| `SEND_MESSAGES`, `RECEIVE_MESSAGES`, `SEND_FORWARDED`, `RECEIVE_FORWARDED`, `CREATE_INVITES`, `ANON_RECEIVE` | Grant that capability. Each has a `_CHANGE` variant granting the DID the right to flip it itself. |
| `SELF_MANAGE_LIST` | Let the DID edit its own access list. Admin-only to set. |
| `SELF_MANAGE_SEND_QUEUE_LIMIT`, `SELF_MANAGE_RECEIVE_QUEUE_LIMIT` | Let the DID set its own queue limits. Admin-only to set. |
| `BLOCKED` | Marks the DID blocked. **Never put this in `global_acl_default`** — it blocks every new DID from authenticating. |

Watch the mode inversion: `ALLOW_ALL` gives every new DID an *open* inbox
(denylist), while `DENY_ALL` gives a *closed* one (allowlist). Boot-time
validation warns when `mediator_acl_mode = explicit_deny` is combined with
`global_acl_default = ALLOW_ALL`, since that combination accepts everything
from everyone.

---

## 4. How a DID gets an account

Five paths, and they do **not** all grant the same ACLs:

| Path | Trigger | ACLs granted |
|------|---------|--------------|
| Authentication challenge | Any DID requesting `/authenticate/challenge` — `explicit_deny` mode only (`explicit_allow` rejects unknown DIDs instead) | `global_acl_default` |
| Authentication response | Backstop if the record vanished mid-flow — `explicit_deny` mode only (`explicit_allow` rejects instead) | `global_acl_default` |
| `account_add` by an admin | Admin protocol or Trust Task | Admin's choice, else `global_acl_default` |
| `account_add` by a non-admin | Only in `explicit_deny` mode | Always `global_acl_default` |
| Forward routing | An unseen DID relays a forward through the mediator | **Least privilege**: `DENY_ALL` + `SEND_FORWARDED`, and only if `global_acl_default` grants `SEND_FORWARDED`. A DID that has only ever relayed a forward does not get `LOCAL`, `RECEIVE_*`, invites, or self-management. |

The first path is the one that surprises people: in `explicit_deny` mode,
**registration is automatic and unconditional** — there is no approval
step. `explicit_allow` is the mode that turns it off.

---

## 5. The permission bits

A DID's `MediatorACLSet` is a packed `u64`. Most permissions occupy a
*pair* of bits — the capability, and a self-change bit saying whether the
DID may flip it without an admin.

| Bit | Flag | Enforced at |
|-----|------|-------------|
| 0 | `access_list_mode` | Access-list evaluation on every delivery (§6) |
| 1 | `access_list_mode_change` | Self-service gate for bit 0 |
| 2 | `did_blocked` | Authentication (both steps), session load, token refresh |
| 3 | `did_local` | Inbox fetch, message list, message delete, outbound, WebSocket upgrade |
| 4 / 5 | `send_messages` (+change) | Inbound handler (session), direct-delivery sender check |
| 6 / 7 | `receive_messages` (+change) | Direct-delivery recipient check (DIDComm and TSP) |
| 8 / 9 | `send_forwarded` (+change) | Forward gate (sender); anonymous inter-mediator relay |
| 10 / 11 | `receive_forwarded` (+change) | Forward gate (next hop) |
| 12 / 13 | `create_invites` (+change) | OOB invite handler |
| 14 / 15 | `anon_receive` (+change) | Anonymous senders in access-list evaluation; anonymous forward next hop |
| 16 | `self_manage_list` | Access-list add / remove / clear |
| 17 | `self_manage_send_queue_limit` | Setting one's own send queue limit |
| 18 | `self_manage_receive_queue_limit` | Setting one's own receive queue limit |

Bits 19–63 are unassigned and must stay zero.

`did_blocked` is the only *bit* checked at authentication (plus the
mediator-wide `explicit_allow` known-DID gate, which is not a bit).
Everything else is checked at the point of use, which means **a registered
DID with `DENY_ALL` still authenticates successfully** — it just cannot do
anything afterwards. That is by design, but it does mean "the DID connected
fine" tells you nothing about its permissions.

### Two classes of bit

- **Self-changeable** (bits 0, 4, 6, 8, 10, 12, 14): the DID may flip the
  value when the paired `_change` bit is set. It may **never** flip the
  `_change` bit itself.
- **Admin-only** (bits 2, 3, 16, 17, 18): no self-change bit exists.
  `blocked` and `local` are the mediator's own gates; the `self_manage_*`
  bits are what delegate self-service in the first place, so a DID that
  could set them would be granting itself the authority you withheld.

A DID can therefore only ever *exercise* delegated authority, never widen
it.

---

## 6. Decision walkthroughs

### Authentication

```
/authenticate/challenge
  ├─ DID is `did:`-shaped?                      else 400
  ├─ resolve ACLs: stored, else global_acl_default
  ├─ blocked?                                   else 403 authentication.blocked
  ├─ unknown?
  │    ├─ explicit_allow → reject               403 authentication.blocked
  │    └─ explicit_deny  → register with global_acl_default
  └─ issue challenge
```

No capability bit other than `blocked` is consulted. The two 403s are
deliberately identical (§2).

### Direct delivery (DIDComm and TSP)

```
├─ local_direct_delivery_allowed?               else 403 direct_delivery.denied
├─ recipient has an account?                    else 403 direct_delivery.recipient.unknown
├─ force_session_did_match: envelope sender == session DID?
├─ sender has SEND_MESSAGES?                    else 403 authorization.send
│    (anonymous sender: local_direct_delivery_allow_anon?)
├─ recipient has RECEIVE_MESSAGES?              else 403 authorization.receive
└─ recipient's access list admits the sender?   else 403 authorization.access_list.denied
```

The claimed sender is unverified in both protocols — the mediator holds no key
for an envelope it is only carrying, so it reads the JWE `skid` (DIDComm) or the
cleartext CESR sender field (TSP). `force_session_did_match` is what makes it
trustworthy enough to feed the access-list lookup, by pinning it to the DID that
authenticated. It is skipped for unauthenticated sessions, because an
inter-mediator relay hop arrives anonymously and has no session DID to match
against; on such a hop the claimed sender stays unverified.

Every step above applies to both protocols. The one asymmetry is
`local_direct_delivery_allow_anon`, which has no TSP analogue: it exists because
a DIDComm envelope can be anon-packed with no sender at all, whereas a TSP
envelope always names its sender in the clear, so there is no anonymous TSP case
to admit or refuse.

### Forwarding

```
├─ sender has SEND_FORWARDED?                   else 403
├─ next hop has RECEIVE_FORWARDED?              else 403
├─ anonymous envelope → next hop has ANON_RECEIVE? else 403
└─ access list check
```

### Access-list evaluation

The single decision, applied on every delivery:

| Sender | Recipient's mode | Verdict |
|--------|------------------|---------|
| Anonymous | (irrelevant) | Allowed iff `anon_receive` |
| Known | `ExplicitAllow` (allowlist) | Allowed iff on the list |
| Known | `ExplicitDeny` (denylist) | Allowed iff **not** on the list |

### Pickup and streaming

Inbox fetch, message list, message delete, outbound, and the WebSocket
upgrade all require `LOCAL` and nothing else. Clearing `LOCAL` is the
blunt instrument for cutting a DID off from its inbox.

---

## 7. Recipes

| Goal | Configuration |
|------|---------------|
| **Open public mediator** | `mediator_acl_mode = "explicit_deny"`, `global_acl_default = "ALLOW_ALL"`. Anyone may do anything; deny per-DID afterwards. Boot warns — this accepts everything from everyone. |
| **Open, consent-based** | `global_acl_default = "ALLOW_ALL,MODE_EXPLICIT_ALLOW"`. Anyone may register and send, but each DID's inbox is an allowlist, so nobody receives until they add senders. Add `SELF_MANAGE_LIST` so users can curate it themselves. |
| **Direct messaging only, no relay** | `global_acl_default = "DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES"` (the shipped default). No forwarding, no invites, no self-management. |
| **Relay only** | `global_acl_default = "DENY_ALL,SEND_FORWARDED,RECEIVE_FORWARDED"` plus `enable_inter_mediator_relay = "true"`. No inboxes: nothing is stored, nothing is picked up. |
| **Closed / allowlist** | `mediator_acl_mode = "explicit_allow"`. Unknown DIDs cannot authenticate; an admin pre-registers each DID via `account_add` (with the ACLs it should have, else `global_acl_default`). Keep a restrictive `global_acl_default` anyway — it remains the no-record fallback for permission checks. |
| **Let users manage their own privacy** | Add `MODE_SELF_CHANGE,SELF_MANAGE_LIST` and the `_CHANGE` variants of whichever capabilities you want users to control. |

---

## 8. Administration

### Account types

`Standard`, `Admin`, `RootAdmin`, `Mediator`. Admin and RootAdmin may
operate on any DID; a Standard account may only target its own DID hash.
Creating an Admin requires admin rights; creating a RootAdmin requires
RootAdmin.

### Admin message hardening

- `block_remote_admin_msgs = "true"` (default) requires admin messages to
  be signed by a key belonging to the session DID, so admin operations
  cannot be relayed in from elsewhere.
- `admin_messages_expiry` bounds replay of captured admin messages. It is
  enforced for every admin account regardless of the setting above, and
  rejects future-dated `created_time` as well as stale ones.

### Changing ACLs

Two equivalent surfaces, with identical rules:

- DIDComm admin protocol: `messaging/acls/set`
- Trust Task: `messaging/account/acl-set`

An admin may set anything. A non-admin may only target its own DID, may
only change capabilities whose self-change bit is set, may never change a
self-change bit, and may never change an admin-only flag (§5).

### Limits

`access_list_limit` and `local_max_acl` cap per-DID list growth;
`queued_send_messages_*` / `queued_receive_messages_*` cap queue depth,
overridable per DID only when the matching `self_manage_*_queue_limit` bit
is set.

---

## 9. Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| DID authenticates fine but every operation is 403 | `global_acl_default` is `DENY_ALL`, or too narrow. Authentication only checks `blocked` and (in `explicit_allow`) that the DID is registered. |
| `authorization.local` on fetch/list/WebSocket | The DID lacks `LOCAL`. |
| `authorization.receive` on delivery | The **recipient** lacks `RECEIVE_MESSAGES`. |
| `authorization.send` on delivery | The **sender** lacks `SEND_MESSAGES`. |
| `authorization.access_list.denied` | Recipient's access list rejects the sender. Check the recipient's `access_list_mode`: in `ExplicitAllow` an *empty* list denies everyone. |
| Messages silently not received, no error | Recipient's inbox mode is `ExplicitAllow` with an empty list, or `anon_receive` is unset for an anonymous sender. |
| Setting `explicit_allow` did not stop unknown DIDs connecting | You are running mediator < 0.18.0 — the mode only gates authentication from 0.18.0 on (§2). |
| DID gets `403 authentication.blocked` but was never blocked | `mediator_acl_mode = explicit_allow` and the DID has no account. The rejection deliberately reuses the blocked problem report (§2); pre-register the DID via `account_add`. |
| `acl/set` rejected with "admin-only" | You tried to change `blocked`, `local`, or a `self_manage_*` flag as a non-admin. |
| Every new DID is blocked | `BLOCKED` was included in `global_acl_default`. |

---

## 10. Implementation notes

Every permission decision resolves through `src/common/authz.rs`:

- `require_capability` / `grants` — the capability gate
- `check_access_list` — the sender↔recipient verdict
- `effective_acls` — stored ACLs, else `global_acl_default`
- `authentication_check` — the pre-auth blocked gate (the `explicit_allow`
  known-DID gate consumes its `known` result in the challenge handler)
- `acl_change_ok` — non-admin self-service rules

The `Capability` enum deliberately carries no `#[allow(dead_code)]`: an
unused variant means a permission bit the mediator advertises but never
enforces, and the dead-code warning is the tripwire for that.

The backend-agnostic parts of the access-list decision live in
`affinidi-messaging-mediator-common/src/store/ops.rs` so the Fjall and
memory backends cannot drift; the Redis backend implements the equivalent
logic in Lua and is kept aligned by the store conformance suite.

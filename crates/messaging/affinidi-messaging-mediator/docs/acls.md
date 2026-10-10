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

| Mode | Authentication | `messaging/account/add` |
|------|----------------|-------------------------|
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

> **Historical note.** Before mediator 0.18.0, `explicit_allow` did not gate
> authentication (see the CHANGELOG). If you relied on unknown DIDs
> self-registering, switch to `explicit_deny` with a restrictive
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

A comma-separated, case-insensitive string. Entries apply left to right.
`ALLOW_ALL` and `DENY_ALL` reset every flag, so put them first and layer the
other flags after them.

| Keyword | Effect |
|---------|--------|
| `ALLOW_ALL` | Every capability, every self-change bit, every `self_manage_*`, and `access_list_mode = ExplicitDeny` (open inbox). |
| `DENY_ALL` | No capability, no self-change, no self-management, and `access_list_mode = ExplicitAllow` (closed inbox). |
| `ALLOW_ALL_SELF_CHANGE` / `DENY_ALL_SELF_CHANGE` | Set/clear every self-change bit and every `self_manage_*` bit, leaving the capability values alone. |
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

Six paths, and they do **not** all grant the same ACLs:

| Path | Trigger | ACLs granted |
|------|---------|--------------|
| Authentication challenge | Any DID requesting `/authenticate/challenge` — `explicit_deny` mode only (`explicit_allow` rejects unknown DIDs instead) | `global_acl_default` |
| Authentication response | Backstop if the record vanished mid-flow — `explicit_deny` mode only (`explicit_allow` rejects instead) | `global_acl_default` |
| `messaging/account/add` by an admin | Trust Task | The admin's ACL applied onto `global_acl_default`, else `global_acl_default` |
| `messaging/account/add` by a non-admin | Trust Task, `explicit_deny` mode only | Always `global_acl_default` |
| Forward next hop | An unseen DID is named as a forward's `next` (`resolve_next_account`) | `global_acl_default` — in either mode |
| Forward sender | An unseen DID relays a forward through the mediator (`relay_sender_acls`) | **Least privilege**: `DENY_ALL` + `SEND_FORWARDED`, and only if `global_acl_default` grants `SEND_FORWARDED`. No `LOCAL`, `RECEIVE_*`, invites, or self-management. |

The first path is the one that surprises people: in `explicit_deny` mode,
**registration is automatic and unconditional** — there is no approval
step. `explicit_allow` turns off registration at authentication. It does not
turn off the forward paths: a forward naming an unseen `next` DID still
creates an account for it with `global_acl_default`.

---

## 5. The permission bits

A DID's `MediatorACLSet` is a packed `u64`. Most permissions occupy a
*pair* of bits — the capability, and a self-change bit saying whether the
DID may flip it without an admin.

| Bit | Flag | Enforced at |
|-----|------|-------------|
| 0 | `access_list_mode` | Access-list evaluation on every delivery (§6) |
| 1 | `access_list_mode_self_change` | Self-service gate for bit 0 |
| 2 | `did_blocked` | Authentication (both steps), session load, token refresh |
| 3 | `did_local` | Inbox fetch, message list, message delete, outbound, WebSocket upgrade |
| 4 / 5 | `send_messages` (+`_self_change`) | Inbound handler (session), direct-delivery sender check |
| 6 / 7 | `receive_messages` (+`_self_change`) | Direct-delivery recipient check (DIDComm and TSP) |
| 8 / 9 | `send_forwarded` (+`_self_change`) | Forward gate (sender); anonymous inter-mediator relay |
| 10 / 11 | `receive_forwarded` (+`_self_change`) | Forward gate (next hop) |
| 12 / 13 | `create_invites` (+`_self_change`) | OOB invite handler |
| 14 / 15 | `anon_receive` (+`_self_change`) | Anonymous senders in access-list evaluation; anonymous forward next hop |
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
  value when the paired `_self_change` bit is set. It may **never** flip the
  `_self_change` bit itself.
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
├─ recipient has an account?                    else 403 delivery.refused
├─ force_session_did_match: envelope sender == session DID?
│                                               else 400 authorization.did.session_mismatch
├─ sender has SEND_MESSAGES?                    else 403 authorization.send
│    (anonymous sender: local_direct_delivery_allow_anon?  else 403 message.anonymous)
├─ recipient has RECEIVE_MESSAGES?              else 403 delivery.refused
└─ recipient's access list admits the sender?   else 403 delivery.refused
```

Every refusal that is a fact about the **recipient** (no account, no
`RECEIVE_*`, no `ANON_RECEIVE`, access list) returns the same
`delivery.refused` (error 73). A distinguishable answer would let a sender
enumerate which DIDs the mediator serves and probe their access lists. The
specific reason is logged against the session on the mediator.

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
├─ sender has SEND_FORWARDED?                   else 403 authorization.send_forwarded
├─ next hop has RECEIVE_FORWARDED?              else 403 delivery.refused
├─ anonymous envelope → next hop has ANON_RECEIVE? else 403 delivery.refused
└─ next hop's access list admits the sender?    else 403 delivery.refused
```

### Inter-mediator relay admission

`processors.forwarding.relay_trusted_mediators` allowlists the peer mediators
whose relays this mediator accepts. Empty means any peer (still ACL-gated).

It applies wherever the relaying peer can actually be identified:

| Protocol | Applies | Why |
|----------|---------|-----|
| DIDComm, `RelayMode::Rewrap` | yes | the re-wrap layer is addressed to this mediator, so authcrypt names its sender |
| DIDComm, `RelayMode::Blind` | no | nothing is addressed to us; the peer is invisible |
| TSP, routed/nested hop | yes | the hop is sealed to this mediator; unpacking verifies an Ed25519 signature *and* HPKE-Auth |
| TSP, opaque pass-through | no | addressed to a local recipient, not to us — no peer to identify |

TSP needs no `RelayMode` choice: a routed hop is re-wrap-like by construction.

Two scoping rules matter. The check runs only on **anonymous** sessions, because
that is how an inter-mediator hop arrives — an ordinary client's routed message
(metadata privacy, TSP §5.5) is authenticated and must not be gated by a list of
peer *mediators*. And it runs only on relay arms: `Direct` and `Control`
addressed to this mediator are messages *to* it — Trust Tasks over TSP arrive
that way — not relays through it.

Where no peer can be identified, `security.enable_inter_mediator_relay` (which
gates anonymous inbound at all) and `security.local_direct_delivery_allowed` are
the levers.

The end-to-end picture these gates sit inside — how a relay hop is built,
routed and admitted across two mediators — is in
[`multi-mediator.md`](./multi-mediator.md).

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

Administration is done only through Trust Tasks; the list is in
[`didcomm-protocols.md` §4](./didcomm-protocols.md#4-administration-trust-tasks).

### Admin message hardening

- `block_remote_admin_msgs = "true"` (default) requires an admin's Trust
  Task to be signed or authcrypted by a key of the session DID, so admin
  operations cannot be relayed in from elsewhere.
- `trust_task_verification` checks each Trust Task's `proof`, `issuedAt`
  (bounding replay) and issuer. The default `"warn"` logs failures and still
  runs the task; `"enforce"` refuses them.

### Changing ACLs

Through the `messaging/account/update` Trust Task, with an `acl` member.

An admin may set anything. A non-admin may only target its own DID, may
only change capabilities whose self-change bit is set, may never change a
self-change bit, and may never change an admin-only flag (§5). A refused
change returns `authorization.acl.not_self_manageable`, naming the flag.

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
| `authorization.send` on delivery | The **sender** lacks `SEND_MESSAGES`. |
| `authorization.send_forwarded` on a forward | The **sender** lacks `SEND_FORWARDED`. |
| `delivery.refused` (73) | A recipient-side check failed: no account, no `RECEIVE_MESSAGES` / `RECEIVE_FORWARDED`, no `ANON_RECEIVE` for an anonymous sender, or the access list rejects the sender. The mediator log names the reason. In `ExplicitAllow` mode an *empty* access list denies everyone. |
| Setting `explicit_allow` did not stop unknown DIDs connecting | Mediator older than 0.18.0 (§2). |
| DID gets `403 authentication.blocked` but was never blocked | `mediator_acl_mode = explicit_allow` and the DID has no account. The rejection deliberately reuses the blocked problem report (§2); pre-register the DID via `account_add`. |
| `authorization.acl.not_self_manageable` on `account/update` | A non-admin tried to change `blocked`, `local`, a `self_manage_*` flag, or a capability whose self-change bit is unset. |
| Every new DID is blocked | `BLOCKED` was included in `global_acl_default`. |

---

## 10. Implementation notes

Permission decisions resolve through `src/common/authz.rs`:

- `require_capability` / `grants` — the capability gate
- `check_access_list` — the sender↔recipient verdict
- `effective_acls` — stored ACLs, else `global_acl_default`
- `authentication_check` — the pre-auth blocked gate (the `explicit_allow`
  known-DID gate consumes its `known` result in the challenge handler)
- `check_permissions` — admin, or own DID only, plus the admin-signature check

The non-admin self-service rules for `account/update` are
`ensure_self_manageable` in `src/messages/protocols/trust_tasks.rs`.

The `Capability` enum deliberately carries no `#[allow(dead_code)]`: an
unused variant means a permission bit the mediator advertises but never
enforces, and the dead-code warning is the tripwire for that.

The backend-agnostic parts of the access-list decision live in
`affinidi-messaging-mediator-common/src/store/ops.rs` so the Fjall and
memory backends cannot drift; the Redis backend implements the equivalent
logic in Lua and is kept aligned by the store conformance suite.

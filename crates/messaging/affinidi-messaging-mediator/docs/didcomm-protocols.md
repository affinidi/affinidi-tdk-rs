# Affinidi Messaging Mediator - DIDComm Protocol Messages

The DIDComm v2 messages the mediator handles, with their request and response
formats. The advertised set is `ADVERTISED_PROTOCOLS` in
`src/messages/protocols/discover_features.rs`. DIDComm v1 mediation (built with
`--features didcomm-v1`) is covered in
[`mediation-and-routing.md`](./mediation-and-routing.md).

Messages are packed (encrypted) before transmission. Common headers are `id`,
`type`, `from`, `to`, `created_time` and `expires_time`. A message whose
`expires_time` has passed is refused with `message.expired`. Error codes are
listed in [`ERRORS.md`](../ERRORS.md).

Authentication (`https://affinidi.com/atm/1.0/authenticate`) and out-of-band
invitations run over the REST endpoints, not as DIDComm messages to the
mediator.

---

## 1. Trust Ping 2.0

Simple protocol to verify connectivity and that the mediator is responsive.

### Ping Request

| Field         | Value                                     |
| ------------- | ----------------------------------------- |
| **Type URI**  | `https://didcomm.org/trust-ping/2.0/ping` |
| **Direction** | Client -> Mediator                        |

**Body:**

```json
{
  "response_requested": true
}
```

| Field                | Type   | Required | Description                                                                                                |
| -------------------- | ------ | -------- | ---------------------------------------------------------------------------------------------------------- |
| `response_requested` | `bool` | No       | If `true` (default), the mediator sends a ping response back. If `false`, the mediator processes silently. A ping asking for a response must carry a `from` header, else `message.anonymous`. |

### Ping Response

| Field         | Value                                     |
| ------------- | ----------------------------------------- |
| **Type URI**  | `https://didcomm.org/trust-ping/2.0/ping` |
| **Direction** | Mediator -> Client                        |

Only sent when `response_requested` is `true`.

**Headers:**

- `thid` is set to the original ping message `id`
- `from` and `to` are swapped from the original message

**Body:**

```json
{}
```

---

## 2. Routing / Forward 2.0

Routes an encrypted DIDComm message to a recipient through the mediator.

### Forward Request

| Field         | Value                                     |
| ------------- | ----------------------------------------- |
| **Type URI**  | `https://didcomm.org/routing/2.0/forward` |
| **Direction** | Client -> Mediator                        |

**Body:**

```json
{
  "next": "did:example:recipient123"
}
```

| Field  | Type     | Required | Description                            |
| ------ | -------- | -------- | -------------------------------------- |
| `next` | `string` | Yes      | DID of the next hop / final recipient. Missing → `protocol.forwarding.next.missing`. |

**Extra Headers (optional):**

| Header        | Type   | Description |
| ------------- | ------ | ----------- |
| `ephemeral`   | `bool` | If `true`, the message is never stored or relayed. It is pushed only to a recipient that is live-connected right now, and dropped otherwise. |
| `delay_milli` | `i64`  | Delay in milliseconds before the forwarding processor relays the message to a **remote** next hop. Values ≤ 0 mean no delay; local delivery is immediate. A magnitude above `processors.forwarding.future_time_limit` seconds is refused (`protocol.forwarding.delay_milli`). |

**Attachments:**

The packed message to forward is the first attachment, as `base64` or inline
`json`. JWS-signed JSON and linked attachments are refused.

### Response

No DIDComm response message is generated. The mediator stores the message
locally or queues it for a remote mediator. The ACL checks it applies are in
[`acls.md` §6](./acls.md#forwarding); relay between mediators is in
[`multi-mediator.md`](./multi-mediator.md).

---

## 3. Message Pickup 3.0

Protocol for clients to retrieve queued messages from the mediator.

Every Message Pickup 3.0 request must:

- be addressed (`to`) to the mediator's DID;
- carry a `from` header (anonymous requests get `message.anonymous`);
- include the extra header `"return_route": "all"` (else `protocol.pickup.return_route`).

A request acts only on the authenticated session's own inbox. A
`recipient_did` that differs from the session DID is refused.

Message IDs in this protocol are the mediator's stored message IDs (SHA-256
hashes), as returned in the delivery attachment IDs — not the `id` header of
the original message.

### 3.1 Status Request

Request the current mailbox status for a DID.

| Field         | Value                                                  |
| ------------- | ------------------------------------------------------ |
| **Type URI**  | `https://didcomm.org/messagepickup/3.0/status-request` |
| **Direction** | Client -> Mediator                                     |

**Body:**

```json
{
  "recipient_did": "did:example:alice"
}
```

| Field           | Type     | Required | Description                                                            |
| --------------- | -------- | -------- | ---------------------------------------------------------------------- |
| `recipient_did` | `string` | No       | Must equal the session DID if present. Defaults to the session DID. |

### 3.2 Status Response

| Field         | Value                                          |
| ------------- | ---------------------------------------------- |
| **Type URI**  | `https://didcomm.org/messagepickup/3.0/status` |
| **Direction** | Mediator -> Client                             |

**Body:**

```json
{
  "recipient_did": "did:example:alice",
  "message_count": 5,
  "longest_waited_seconds": 3600,
  "newest_received_time": 1700000000,
  "oldest_received_time": 1699996400,
  "total_bytes": 10240,
  "live_delivery": false
}
```

| Field                    | Type     | Required | Description                                                         |
| ------------------------ | -------- | -------- | ------------------------------------------------------------------- |
| `recipient_did`          | `string` | Yes      | The DID this status applies to.                                     |
| `message_count`          | `u32`    | Yes      | Number of messages waiting.                                         |
| `longest_waited_seconds` | `u64`    | No       | Seconds the oldest message has been queued. Omitted if no messages. |
| `newest_received_time`   | `u64`    | No       | Unix timestamp of the newest message. Omitted if no messages.       |
| `oldest_received_time`   | `u64`    | No       | Unix timestamp of the oldest message. Omitted if no messages.       |
| `total_bytes`            | `u64`    | Yes      | Total size of all queued messages in bytes.                         |
| `live_delivery`          | `bool`   | Yes      | Whether live delivery (WebSocket streaming) is currently enabled.   |

### 3.3 Live Delivery Change

Toggle real-time message delivery via WebSocket.

| Field         | Value                                                        |
| ------------- | ------------------------------------------------------------ |
| **Type URI**  | `https://didcomm.org/messagepickup/3.0/live-delivery-change` |
| **Direction** | Client -> Mediator                                           |

**Body:**

```json
{
  "live_delivery": true
}
```

| Field           | Type   | Required | Description                                         |
| --------------- | ------ | -------- | --------------------------------------------------- |
| `live_delivery` | `bool` | Yes      | `true` to enable live delivery, `false` to disable. |

**Response:** Returns a **Status Response** message (type `status`) with the updated `live_delivery` value.

### 3.4 Delivery Request

Request retrieval of queued messages.

| Field         | Value                                                    |
| ------------- | -------------------------------------------------------- |
| **Type URI**  | `https://didcomm.org/messagepickup/3.0/delivery-request` |
| **Direction** | Client -> Mediator                                       |

**Body:**

```json
{
  "recipient_did": "did:example:alice",
  "limit": 10
}
```

| Field           | Type     | Required | Description                                                          |
| --------------- | -------- | -------- | -------------------------------------------------------------------- |
| `recipient_did` | `string` | Yes      | Must equal the session DID.                                          |
| `limit`         | `usize`  | Yes      | Number of messages to retrieve. Must be between 1 and 100 inclusive. |

### 3.5 Delivery Response

| Field         | Value                                            |
| ------------- | ------------------------------------------------ |
| **Type URI**  | `https://didcomm.org/messagepickup/3.0/delivery` |
| **Direction** | Mediator -> Client                               |

If messages exist, each one is an attachment: the stored packed message,
base64url-encoded without padding, with the attachment `id` set to its message
ID.

If no messages are available, a **Status Response** is returned instead.

**Body:**

```json
{
  "recipient_did": "did:example:alice"
}
```

### 3.6 Messages Received (Acknowledgement/Delete)

Acknowledge receipt and delete messages from the mediator.

| Field         | Value                                                     |
| ------------- | --------------------------------------------------------- |
| **Type URI**  | `https://didcomm.org/messagepickup/3.0/messages-received` |
| **Direction** | Client -> Mediator                                        |

**Body:**

```json
{
  "message_id_list": ["abc123sha256hash...", "def456sha256hash..."]
}
```

| Field             | Type       | Required | Description                                             |
| ----------------- | ---------- | -------- | ------------------------------------------------------- |
| `message_id_list` | `string[]` | Yes      | Message IDs to delete. IDs not found in the caller's inbox are skipped. |

**Response:** Returns a **Status Response** message reflecting the updated queue state.

---

## 4. Administration: Trust Tasks

The mediator is administered, and an account manages itself, through the
`messaging/*`, `audit/*` and `config/*` [Trust Tasks](https://trusttasks.org),
not through bespoke DIDComm protocols. Over DIDComm a Trust Task document rides
the Trust Tasks binding envelope; the same documents are carried over TSP.

| Field         | Value                                                  |
| ------------- | ------------------------------------------------------ |
| **Type URI**  | `https://trusttasks.org/binding/didcomm/0.1/envelope`  |
| **Direction** | Client <-> Mediator                                    |
| **Body**      | The complete Trust Task document (request or response) |

The SDK sends every one of them through `atm.trust_tasks()`.

| Area         | Trust Tasks                                                                                                        |
| ------------ | ------------------------------------------------------------------------------------------------------------------ |
| Accounts     | `messaging/account/{get,list,add,update,remove}` (`update` changes the role, the ACL and the queue limits)          |
| ACLs         | `messaging/acl/get`, `messaging/access-list/{list,update}`                                                         |
| Queues       | `messaging/queue/{status,list,purge}`, `messaging/message/{list,get,status,delete}`                                |
| Operations   | `messaging/ping`, `messaging/stats/show`, `messaging/monitor/{subscribe,unsubscribe}`                              |
| Mediator     | `audit/list`, `config/{show,patch,reload}`                                                                          |

The former `https://didcomm.org/mediator/1.0/*` admin, account and ACL
protocols are not served; a message of those types is refused as unknown.

---

## 5. Discover Features 2.0

| Field         | Value                                               |
| ------------- | --------------------------------------------------- |
| **Type URI**  | `https://didcomm.org/discover-features/2.0/queries` |
| **Direction** | Client -> Mediator                                  |

The mediator answers with a `https://didcomm.org/discover-features/2.0/disclose`
message drawn from `ADVERTISED_PROTOCOLS`. The query must carry a `from`
header. The mediator does not accept incoming `disclose` messages.

---

## 6. Problem Report 2.0

Error reporting protocol. The mediator generates problem reports for errors but does **not** accept incoming problem reports.

| Field         | Value                                                   |
| ------------- | ------------------------------------------------------- |
| **Type URI**  | `https://didcomm.org/report-problem/2.0/problem-report` |
| **Direction** | Mediator -> Client (outbound only)                      |

**Body:**

```json
{
  "code": "e.p.message.expired",
  "comment": "Message {1} has expired after {2} seconds",
  "args": ["msg-abc123", "300"],
  "escalate_to": "mailto:admin@example.com"
}
```

| Field         | Type       | Required | Description                                                                |
| ------------- | ---------- | -------- | -------------------------------------------------------------------------- |
| `code`        | `string`   | Yes      | Error code in format `{sorter}.{scope}.{descriptor}`.                      |
| `comment`     | `string`   | Yes      | Human-readable message. Use `{1}`, `{2}`, etc. as placeholders for `args`. |
| `args`        | `string[]` | No       | Substitution arguments for placeholders in `comment`. Omitted if empty.    |
| `escalate_to` | `string`   | No       | URI for escalation (e.g., `mailto:` or support URL). Omitted if not set.   |

### Code Format: `{sorter}.{scope}.{descriptor}`

**Sorter values:**

| Sorter  | Code | Description                           |
| ------- | ---- | ------------------------------------- |
| Error   | `e`  | Clear failure to achieve goal.        |
| Warning | `w`  | May be a problem -- receiver decides. |

**Scope values:**

| Scope    | Code       | Description           |
| -------- | ---------- | --------------------- |
| Protocol | `p`        | Protocol-level issue. |
| Message  | `m`        | Message-level issue.  |
| Other    | `{custom}` | Custom scope string.  |

---

## Appendix A: ACL reference

The ACL bit layout and the ruleset strings used in `global_acl_default` are
documented once, in [`acls.md` §5](./acls.md#5-the-permission-bits) and
[`acls.md` §3](./acls.md#ruleset-syntax).

---

## Appendix B: Message Type URI Summary

| Protocol              | Message Type URI                                             | Direction          |
| --------------------- | ------------------------------------------------------------ | ------------------ |
| Trust Ping 2.0        | `https://didcomm.org/trust-ping/2.0/ping`                    | Request & Response |
| Routing 2.0           | `https://didcomm.org/routing/2.0/forward`                    | Request only       |
| Message Pickup 3.0    | `https://didcomm.org/messagepickup/3.0/status-request`       | Request            |
| Message Pickup 3.0    | `https://didcomm.org/messagepickup/3.0/status`               | Response           |
| Message Pickup 3.0    | `https://didcomm.org/messagepickup/3.0/live-delivery-change` | Request            |
| Message Pickup 3.0    | `https://didcomm.org/messagepickup/3.0/delivery-request`     | Request            |
| Message Pickup 3.0    | `https://didcomm.org/messagepickup/3.0/delivery`             | Response           |
| Message Pickup 3.0    | `https://didcomm.org/messagepickup/3.0/messages-received`    | Request            |
| Discover Features 2.0 | `https://didcomm.org/discover-features/2.0/queries`          | Request            |
| Discover Features 2.0 | `https://didcomm.org/discover-features/2.0/disclose`         | Response           |
| Trust Tasks 0.1       | `https://trusttasks.org/binding/didcomm/0.1/envelope`        | Request & Response |
| Problem Report 2.0    | `https://didcomm.org/report-problem/2.0/problem-report`      | Outbound only      |

# Affinidi Messaging Mediator - DIDComm Protocol Messages

This document describes all DIDComm protocol messages supported by the mediator, including request/response formats and options.

All DIDComm messages follow the standard envelope structure and are packed/encrypted before transmission. Common headers include `id`, `type`, `from`, `to`, `created_time`, and `expires_time`.

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
| `response_requested` | `bool` | No       | If `true` (default), the mediator sends a ping response back. If `false`, the mediator processes silently. |

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
| `next` | `string` | No       | DID of the next hop / final recipient. |

**Extra Headers (optional):**

| Header        | Type   | Description                                                                         |
| ------------- | ------ | ----------------------------------------------------------------------------------- |
| `ephemeral`   | `bool` | If `true`, the message is not stored -- only live-streamed to connected recipients. |
| `delay_milli` | `i64`  | Delay in milliseconds before delivering. A negative value selects a random delay.   |

**Attachments:**

The forwarded packed DIDComm message is carried as an attachment (Base64-encoded or JSON).

### Response

No DIDComm response message is generated. The mediator silently stores or forwards the message.

---

## 3. Message Pickup 3.0

Protocol for clients to retrieve queued messages from the mediator.

> **Required Header:** All Message Pickup 3.0 messages **must** include `"return_route": "all"` as an extra header.

> **Note:** All Message IDs referenced in this protocol are SHA256 hashes of the message content. Do not pass raw message IDs to the mediator.

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
| `recipient_did` | `string` | No       | DID to query status for. Defaults to the authenticated DID if omitted. |

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
| `recipient_did` | `string` | Yes      | DID to retrieve messages for.                                        |
| `limit`         | `usize`  | Yes      | Number of messages to retrieve. Must be between 1 and 100 inclusive. |

### 3.5 Delivery Response

| Field         | Value                                            |
| ------------- | ------------------------------------------------ |
| **Type URI**  | `https://didcomm.org/messagepickup/3.0/delivery` |
| **Direction** | Mediator -> Client                               |

If messages exist, the response contains Base64-encoded packed DIDComm messages as **attachments**. Each attachment ID is the SHA256 hash of the message.

If no messages are available, a **Status Response** message is returned instead.

**Body:**

```json
{}
```

**Attachments:** Array of Base64-encoded packed DIDComm messages.

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
| `message_id_list` | `string[]` | Yes      | List of SHA256 message hashes to delete from the queue. |

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

The DIDComm protocols `https://didcomm.org/mediator/1.0/admin-management`,
`…/account-management` and `…/acl-management` are no longer served or
advertised; a message of those types is not recognised.

---

## 5. Problem Report 2.0

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

## Appendix A: ACL Bitmask Reference

The ACL is stored as a Little Endian `u64` integer. Each bit controls a specific permission:

| Bit | Field                             | Values                                              |
| --- | --------------------------------- | --------------------------------------------------- |
| 0   | `access_list_mode`                | `0` = ExplicitAllow, `1` = ExplicitDeny             |
| 1   | `access_list_mode_self_change`    | `0` = admin only, `1` = self-changeable             |
| 2   | `did_blocked`                     | `0` = allowed, `1` = blocked                        |
| 3   | `did_local`                       | `0` = not local, `1` = local (can store messages)   |
| 4   | `send_messages`                   | `0` = cannot send, `1` = can send                   |
| 5   | `send_messages_self_change`       | `0` = admin only, `1` = self-changeable             |
| 6   | `receive_messages`                | `0` = cannot receive, `1` = can receive             |
| 7   | `receive_messages_self_change`    | `0` = admin only, `1` = self-changeable             |
| 8   | `send_forwarded`                  | `0` = cannot forward, `1` = can forward             |
| 9   | `send_forwarded_self_change`      | `0` = admin only, `1` = self-changeable             |
| 10  | `receive_forwarded`               | `0` = cannot receive forwarded, `1` = can receive   |
| 11  | `receive_forwarded_self_change`   | `0` = admin only, `1` = self-changeable             |
| 12  | `create_invites`                  | `0` = cannot create OOB invites, `1` = can create   |
| 13  | `create_invites_self_change`      | `0` = admin only, `1` = self-changeable             |
| 14  | `anon_receive`                    | `0` = cannot receive anonymous, `1` = can receive   |
| 15  | `anon_receive_self_change`        | `0` = admin only, `1` = self-changeable             |
| 16  | `self_manage_list`                | `0` = admin only, `1` = can self-manage access list |
| 17  | `self_manage_send_queue_limit`    | `0` = admin only, `1` = can self-manage             |
| 18  | `self_manage_receive_queue_limit` | `0` = admin only, `1` = can self-manage             |

### Convenience Rule Strings

ACLs can also be configured using comma-separated rule strings:

| Rule                    | Description                                     |
| ----------------------- | ----------------------------------------------- |
| `allow_all`             | Enable all permissions with ExplicitDeny mode   |
| `deny_all`              | Disable all permissions with ExplicitAllow mode |
| `allow_all_self_change` | Allow self-change on all permissions            |
| `deny_all_self_change`  | Deny self-change on all permissions             |
| `mode_explicit_allow`   | Set access list mode to ExplicitAllow           |
| `mode_explicit_deny`    | Set access list mode to ExplicitDeny            |
| `local`                 | Set DID as local                                |
| `blocked`               | Block the DID                                   |
| `send_messages`         | Allow sending messages                          |
| `receive_messages`      | Allow receiving messages                        |
| `send_forwarded`        | Allow sending forwarded messages                |
| `receive_forwarded`     | Allow receiving forwarded messages              |
| `create_invites`        | Allow creating OOB invitations                  |
| `anon_receive`          | Allow receiving anonymous messages              |
| `self_manage_list`      | Allow self-management of access list            |

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
| Trust Tasks 0.1       | `https://trusttasks.org/binding/didcomm/0.1/envelope`        | Request & Response |
| Problem Report 2.0    | `https://didcomm.org/report-problem/2.0/problem-report`      | Outbound only      |

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

## 4. Mediator Administration 1.0

Manage mediator admin accounts and retrieve configuration. Requires admin-level access.

| Field         | Value                                               |
| ------------- | --------------------------------------------------- |
| **Type URI**  | `https://didcomm.org/mediator/1.0/admin-management` |
| **Direction** | Client <-> Mediator                                 |

> **Note:** Admin messages must include a valid `created_time` header.

The request body is a **tagged enum** -- exactly one variant is sent per message.

### 4.1 Admin Add

Promote DIDs to admin status.

**Request Body:**

```json
{
  "admin_add": ["sha256_did_hash_1", "sha256_did_hash_2"]
}
```

| Field       | Type       | Description                                                                                   |
| ----------- | ---------- | --------------------------------------------------------------------------------------------- |
| `admin_add` | `string[]` | SHA256 hashes of DIDs to promote. Max 100 per request. Accepts raw DIDs or pre-hashed values. |

**Response Body:**

```json
3
```

Returns `i32` -- the number of admins successfully added.

### 4.2 Admin Strip

Remove admin rights from DIDs.

**Request Body:**

```json
{
  "admin_strip": ["sha256_did_hash_1", "sha256_did_hash_2"]
}
```

| Field         | Type       | Description                                           |
| ------------- | ---------- | ----------------------------------------------------- |
| `admin_strip` | `string[]` | SHA256 hashes of DIDs to demote. Max 100 per request. |

**Response Body:**

```json
2
```

Returns `i32` -- the number of admins successfully stripped.

### 4.3 Admin List

Retrieve a paginated list of admin accounts.

**Request Body:**

```json
{
  "admin_list": {
    "cursor": 0,
    "limit": 100
  }
}
```

| Field    | Type  | Description                                        |
| -------- | ----- | -------------------------------------------------- |
| `cursor` | `u32` | Pagination offset. Start at 0.                     |
| `limit`  | `u32` | Maximum number of results to return. Default: 100. |

**Response Body:**

```json
{
  "accounts": [
    {
      "did_hash": "abc123...",
      "type": "Admin"
    },
    {
      "did_hash": "def456...",
      "type": "RootAdmin"
    }
  ],
  "cursor": 2
}
```

| Field                 | Type             | Description                                                            |
| --------------------- | ---------------- | ---------------------------------------------------------------------- |
| `accounts`            | `AdminAccount[]` | Array of admin accounts.                                               |
| `accounts[].did_hash` | `string`         | SHA256 hash of the admin DID.                                          |
| `accounts[].type`     | `AccountType`    | Account type: `"Standard"`, `"Admin"`, `"RootAdmin"`, or `"Mediator"`. |
| `cursor`              | `u32`            | Cursor for the next page of results.                                   |

### 4.4 Configuration

Retrieve the mediator's current configuration.

**Request Body:**

```json
{
  "Configuration": {}
}
```

**Response Body:**

```json
{
  "version": "0.7.0",
  "config": { ... }
}
```

| Field     | Type     | Description                         |
| --------- | -------- | ----------------------------------- |
| `version` | `string` | Mediator software version.          |
| `config`  | `object` | Full mediator configuration object. |

---

## 5. Mediator Account Management 1.0

Manage DID accounts on the mediator. Admin-level access required for most operations.

| Field         | Value                                                 |
| ------------- | ----------------------------------------------------- |
| **Type URI**  | `https://didcomm.org/mediator/1.0/account-management` |
| **Direction** | Client <-> Mediator                                   |

The request body is a **tagged enum** -- exactly one variant is sent per message.

### 5.1 Account Get

Retrieve account information for a DID.

**Request Body:**

```json
{
  "account_get": "sha256_did_hash"
}
```

**Response Body:**

```json
{
  "did_hash": "abc123...",
  "acls": 505,
  "type": "Standard",
  "access_list_count": 3,
  "queue_send_limit": 1000,
  "queue_receive_limit": 1000,
  "send_queue_count": 12,
  "send_queue_bytes": 4096,
  "receive_queue_count": 5,
  "receive_queue_bytes": 2048
}
```

| Field                 | Type          | Description                                                           |
| --------------------- | ------------- | --------------------------------------------------------------------- |
| `did_hash`            | `string`      | SHA256 hash of the DID.                                               |
| `acls`                | `u64`         | ACL bitmask value (see ACL Bitmask Reference).                        |
| `type`                | `AccountType` | `"Standard"`, `"Admin"`, `"RootAdmin"`, `"Mediator"`, or `"Unknown"`. |
| `access_list_count`   | `u32`         | Number of entries in this account's access list.                      |
| `queue_send_limit`    | `i32?`        | Send queue limit. `null` = default, `-1` = unlimited.                 |
| `queue_receive_limit` | `i32?`        | Receive queue limit. `null` = default, `-1` = unlimited.              |
| `send_queue_count`    | `u32`         | Current number of messages in the send queue.                         |
| `send_queue_bytes`    | `u64`         | Total bytes in the send queue.                                        |
| `receive_queue_count` | `u32`         | Current number of messages in the receive queue.                      |
| `receive_queue_bytes` | `u64`         | Total bytes in the receive queue.                                     |

### 5.2 Account List

Retrieve a paginated list of all accounts.

**Request Body:**

```json
{
  "account_list": {
    "cursor": 0,
    "limit": 100
  }
}
```

| Field    | Type  | Description                              |
| -------- | ----- | ---------------------------------------- |
| `cursor` | `u32` | Pagination offset.                       |
| `limit`  | `u32` | Maximum number of results. Default: 100. |

**Response Body:**

```json
{
  "accounts": [ ... ],
  "cursor": 100
}
```

Returns an array of `Account` objects (same structure as Account Get response) and a cursor for pagination.

### 5.3 Account Add

Create a new account on the mediator.

**Request Body:**

```json
{
  "account_add": {
    "did_hash": "sha256_did_hash",
    "acls": 505
  }
}
```

| Field      | Type     | Required | Description                                                                         |
| ---------- | -------- | -------- | ----------------------------------------------------------------------------------- |
| `did_hash` | `string` | Yes      | SHA256 hash of the DID to register.                                                 |
| `acls`     | `u64`    | No       | ACL bitmask value. If omitted or not admin, defaults to the mediator's default ACL. |

**Response Body:** Returns the created `Account` object, or the existing account if the DID is already registered.

### 5.4 Account Remove

Remove an account from the mediator.

**Request Body:**

```json
{
  "account_remove": "sha256_did_hash"
}
```

**Response Body:**

```json
true
```

Returns `bool` -- whether the account was successfully removed.

### 5.5 Account Change Type

Change the account type/role for a DID. Admin-only.

**Request Body:**

```json
{
  "account_change_type": {
    "did_hash": "sha256_did_hash",
    "type": "Admin"
  }
}
```

| Field      | Type          | Description                                                             |
| ---------- | ------------- | ----------------------------------------------------------------------- |
| `did_hash` | `string`      | SHA256 hash of the DID.                                                 |
| `type`     | `AccountType` | New account type: `"Standard"`, `"Admin"`, `"RootAdmin"`, `"Mediator"`. |

**AccountType Numeric Mappings:**

| Type      | Value  |
| --------- | ------ |
| Standard  | `"0"`  |
| Admin     | `"1"`  |
| RootAdmin | `"2"`  |
| Mediator  | `"3"`  |
| Unknown   | `"-1"` |

**Response Body:**

```json
true
```

Returns `bool` -- whether the type was successfully changed.

### 5.6 Account Change Queue Limits

Modify the message queue limits for a DID.

**Request Body:**

```json
{
  "account_change_queue_limits": {
    "did_hash": "sha256_did_hash",
    "send_queue_limit": 500,
    "receive_queue_limit": -1
  }
}
```

| Field                 | Type     | Required | Description                                                                                |
| --------------------- | -------- | -------- | ------------------------------------------------------------------------------------------ |
| `did_hash`            | `string` | Yes      | SHA256 hash of the DID.                                                                    |
| `send_queue_limit`    | `i32?`   | No       | `null` = no change, `-1` = unlimited, `-2` = reset to soft limit, positive = set to value. |
| `receive_queue_limit` | `i32?`   | No       | Same semantics as `send_queue_limit`.                                                      |

**Response Body:**

```json
{
  "send_queue_limit": 500,
  "receive_queue_limit": null
}
```

| Field                 | Type   | Description                        |
| --------------------- | ------ | ---------------------------------- |
| `send_queue_limit`    | `i32?` | The resulting send queue limit.    |
| `receive_queue_limit` | `i32?` | The resulting receive queue limit. |

---

## 6. Mediator ACL Management 1.0

Manage per-DID access control lists and permission bitmasks.

| Field                 | Value                                                  |
| --------------------- | ------------------------------------------------------ |
| **Request Type URI**  | `https://didcomm.org/mediator/1.0/acl-management`      |
| **Response Type URI** | `https://affinidi.com/messaging/global-acl-management` |
| **Direction**         | Client <-> Mediator                                    |

The request body is a **tagged enum** -- exactly one variant is sent per message.

### 6.1 ACL Get

Retrieve ACL settings for one or more DIDs.

**Request Body:**

```json
{
  "acl_get": ["sha256_did_hash_1", "sha256_did_hash_2"]
}
```

**Response Body:**

```json
{
  "acl_response": [
    {
      "did_hash": "sha256_did_hash_1",
      "acl_value": "00000000000001f9",
      "acls": {
        "access_list_mode": "ExplicitAllow",
        "access_list_mode_self_change": false,
        "did_blocked": false,
        "did_local": true,
        "send_messages": true,
        "send_messages_self_change": true,
        "receive_messages": true,
        "receive_messages_self_change": true,
        "send_forwarded": true,
        "send_forwarded_self_change": false,
        "receive_forwarded": false,
        "receive_forwarded_self_change": false,
        "create_invites": false,
        "create_invites_self_change": false,
        "anon_receive": false,
        "anon_receive_self_change": false,
        "self_manage_list": false,
        "self_manage_send_queue_limit": false,
        "self_manage_receive_queue_limit": false
      }
    }
  ],
  "mediator_acl_mode": "ExplicitAllow"
}
```

| Field                      | Type                    | Description                                                      |
| -------------------------- | ----------------------- | ---------------------------------------------------------------- |
| `acl_response`             | `MediatorACLExpanded[]` | Array of ACL results per DID.                                    |
| `acl_response[].did_hash`  | `string`                | SHA256 hash of the DID.                                          |
| `acl_response[].acl_value` | `string`                | Hex representation of the ACL bitmask.                           |
| `acl_response[].acls`      | `MediatorACLSet`        | Expanded ACL fields (see ACL Bitmask Reference below).           |
| `mediator_acl_mode`        | `string`                | Global mediator ACL mode: `"ExplicitAllow"` or `"ExplicitDeny"`. |

### 6.2 ACL Set

Set the ACL bitmask for a DID.

**Request Body:**

```json
{
  "acl_set": {
    "did_hash": "sha256_did_hash",
    "acls": 505
  }
}
```

| Field      | Type     | Description                            |
| ---------- | -------- | -------------------------------------- |
| `did_hash` | `string` | SHA256 hash of the DID to modify.      |
| `acls`     | `u64`    | New ACL bitmask value (Little Endian). |

**Response Body:**

```json
{
  "acls": { ... }
}
```

Returns the resulting `MediatorACLSet` object with all expanded fields.

### 6.3 Access List - List

List the DIDs in an account's access control list.

**Request Body:**

```json
{
  "access_list_list": {
    "did_hash": "sha256_did_hash",
    "cursor": null
  }
}
```

| Field      | Type     | Required | Description                                          |
| ---------- | -------- | -------- | ---------------------------------------------------- |
| `did_hash` | `string` | Yes      | SHA256 hash of the DID whose access list to query.   |
| `cursor`   | `u64?`   | No       | Pagination cursor. `null` starts from the beginning. |

**Response Body:**

```json
{
  "did_hashes": ["hash1", "hash2", "hash3"],
  "cursor": 12345
}
```

| Field        | Type       | Description                                          |
| ------------ | ---------- | ---------------------------------------------------- |
| `did_hashes` | `string[]` | DID hashes in the access list.                       |
| `cursor`     | `u64?`     | Cursor for the next page. `null` if no more results. |

### 6.4 Access List - Get

Check if specific DIDs exist in an access control list.

**Request Body:**

```json
{
  "access_list_get": {
    "did_hash": "sha256_did_hash",
    "hashes": ["hash_to_search_1", "hash_to_search_2"]
  }
}
```

| Field      | Type       | Description                                         |
| ---------- | ---------- | --------------------------------------------------- |
| `did_hash` | `string`   | SHA256 hash of the DID whose access list to search. |
| `hashes`   | `string[]` | SHA256 hashes to search for. Max 100.               |

**Response Body:**

```json
{
  "did_hashes": ["hash_to_search_1"]
}
```

Returns only the hashes that were found in the access list.

### 6.5 Access List - Add

Add DIDs to an account's access control list.

**Request Body:**

```json
{
  "access_list_add": {
    "did_hash": "sha256_did_hash",
    "hashes": ["hash_to_add_1", "hash_to_add_2"]
  }
}
```

| Field      | Type       | Description                                         |
| ---------- | ---------- | --------------------------------------------------- |
| `did_hash` | `string`   | SHA256 hash of the DID whose access list to modify. |
| `hashes`   | `string[]` | SHA256 hashes of DIDs to add. Max 100 per request.  |

**Response Body:**

```json
{
  "did_hashes": ["hash_to_add_1", "hash_to_add_2"],
  "truncated": false
}
```

| Field        | Type       | Description                                                                  |
| ------------ | ---------- | ---------------------------------------------------------------------------- |
| `did_hashes` | `string[]` | Hashes that were successfully added.                                         |
| `truncated`  | `bool`     | `true` if the access list hit its capacity limit and entries were truncated. |

### 6.6 Access List - Remove

Remove DIDs from an account's access control list.

**Request Body:**

```json
{
  "access_list_remove": {
    "did_hash": "sha256_did_hash",
    "hashes": ["hash_to_remove_1"]
  }
}
```

| Field      | Type       | Description                                           |
| ---------- | ---------- | ----------------------------------------------------- |
| `did_hash` | `string`   | SHA256 hash of the DID whose access list to modify.   |
| `hashes`   | `string[]` | SHA256 hashes of DIDs to remove. Max 100 per request. |

**Response Body:**

```json
2
```

Returns `usize` -- the number of entries successfully removed.

### 6.7 Access List - Clear

Remove all entries from an account's access control list.

**Request Body:**

```json
{
  "access_list_clear": {
    "did_hash": "sha256_did_hash"
  }
}
```

**Response Body:** Empty (unit type). Success is indicated by absence of a problem report.

---

## 7. Problem Report 2.0

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
| Mediator Admin 1.0    | `https://didcomm.org/mediator/1.0/admin-management`          | Request & Response |
| Mediator Accounts 1.0 | `https://didcomm.org/mediator/1.0/account-management`        | Request & Response |
| Mediator ACL 1.0      | `https://didcomm.org/mediator/1.0/acl-management`            | Request            |
| Mediator ACL 1.0      | `https://affinidi.com/messaging/global-acl-management`       | Response           |
| Problem Report 2.0    | `https://didcomm.org/report-problem/2.0/problem-report`      | Outbound only      |

# Affinidi Messaging - Mediator Service

A mediator & relay service based on DIDComm v2 specification for handling connections, permissions, and messages sent over the network.

## Table of Contents

  - [Prerequisites](#prerequisites)
  - [Running Mediator Service](#running-mediator-service)
  - [Supported Access Control Lists (ACLs)](#supported-access-control-lists-acls)
      - [Mediator-level ACLs](#mediator-level-acls)
      - [DID-level ACLs](#did-level-acls)
  - [Common Mediator Operating Modes](#common-mediator-operating-modes)
      - [Private Mediator - Closed Network](#public-mediator--closed-network)
      - [Private Mediator - Open Network](#private-mediator--open-network)
      - [Public Mediator - Closed Network](#public-mediator--closed-network)
      - [Public Mediator - Open Network](#public-mediator--open-network)
      - [Public Mediator - Mixed Mode](#public-mediator--mixed-mode)
  - [Examples](#examples)

## Prerequisites

To build and run this project, you need to set up the following:

1. Install Rust (1.85.0 2024 Edition) on your machine if you haven't installed it yet using [this guide](https://www.rust-lang.org/tools/install).

2. Install Docker on your machine if you haven't installed it yet using [this guide](https://docs.docker.com/desktop/). We will need this to run Redis instance for the mediator.

## Running Mediator Service

1. Run the Redis docker container using the command below:

   ```bash
   docker run --name=redis-local --publish=6379:6379 --hostname=redis --restart=on-failure --detach redis:latest
   ```

   The latest supported version of Redis is version 8.0.

2. Run `setup_environment` and `setup_local_mediator` to configure the mediator with all the required information to run locally.

   You must run the following from the top-level directory of `affinidi-messaging`.

   ```bash
   cargo run --bin setup_environment  # Wizard based to configure various parameters
   cargo run --bin setup_local_mediator  # creates and updates secrets
   ````
   >_**Note**_- Be sure to delete the `affinidi-messaging-mediator/conf/secrets.json` before running `setup_local_mediator` more than once.

   This will generate:

   - Mediator DID and secrets.
   - Administration DID and secrets.
   - SSL Certificates for local development/testing.
   - Optionally, different users with their DIDs for testing.

3. Start `affinidi-messaging-mediator` service via:

   ```bash
   cd affinidi-messaging-mediator
   export REDIS_URL=redis://@localhost:6379
   cargo run
   ```

   >_**Note**_- Please destroy and re-create a new redis container incase you re-configure using `setup_environment` or `setup_local_mediator`.

## Supported Access Control Lists (ACLs)

The mediator service provides a granular set of access control lists to allow administrators to have greater control over who can send and receive messages within the network.

### Mediator-level ACLs

| ACL Flag        | Description        |
|----------       |------------        |
| explicit_deny   | Mediator will allow any DID to connect and forward/deliver messages unless explicitly denied. |
| explicit_deny   | Mediator will deny all DIDs except for what has been explicitly allowed. |
| local_direct_delivery_allowed   | If set to `true`, you can either message the mediator or to a local DID directly. If false, the DIDComm message must be addressed to the mediator, and the mediator will handle the delivery. |

### DID-level ACLs

DID-level ACLs are permissions attached to a specific DID present in the mediator. These ACLs provide access control to whether a DID can store, send, or receive messages in the mediator.

The ACLs configured in the mediator's configuration apply by default to any DID added to the mediator.

#### Send and Receive Messages

The following ACL flags provide granular access control to users whether their DID can send or receive messages.

| ACL Flag        | Description        |
|----------       |------------        |
| ALLOW_ALL       | **`Default ACL`** Allow all operations (sets ACL mode to explicit_deny per DID, DID can self manage their own ACLs). |
| DENY_ALL        | Deny all operations (sets ACL mode to explicit_allow per DID) |
| MODE_EXPLICIT_ALLOW | Per DID Access Control List (ACL) will only allow what is explicitly allowed. |
| MODE_EXPLICIT_DENY | Per DID Access Control List (ACL) will only allow everyone except for those explicitly denied. |
| LOCAL | Will store messages for a DID on the mediator. |
| SEND_MESSAGES | DID Can receive messages from others. | 
| RECEIVE_MESSAGES | DID Can receive messages from others. |
| SEND_FORWARDED |  DID can send forwarded messages. |
| RECEIVE_FORWARDED |  DID can receive forwarded messages. |
| ANON_RECEIVE |  DID can receive anonymous messages. |
| CREATE_INVITES |  DID can create OOB invites. |

#### Self-change Flags

Self-change flags allow the users to update the Access Control List (ACLs) of their own DID instead of the mediator's administrator to have sole control of the ACLs.

This flag is useful if you want to provide a level of control for the user to update their ACL when needed - for example, in the [Public Mediator - Open Network](#public-mediator--open-network) operating mode.

| ACL Flag        | Description        |
|----------       |------------        |
| MODE_SELF_CHANGE | Allows the DID owner to change the ACL Mode for their own DID Access Control List. |
| ALLOW_ALL_SELF_CHANGE | Allows all *_SELF_CHANGE flags (explicitly set when ALLOW_ALL is set). |
| DENY_ALL_SELF_CHANGE | Denies all *_SELF_CHANGE flags (explicitly set when DENY_ALL is set). |
| SEND_MESSAGES_CHANGE | Allows the DID owner to change the send_messages ACL for their own DID. |
| RECEIVE_MESSAGES_CHANGE | Allows the DID owner to change the receive_messages ACL for their own DID. |
| SEND_FORWARDED_CHANGE |  Allows the DID owner to change the send_forwarded ACL for their own DID. |
| RECEIVE_FORWARDED_CHANGE |  Allows the DID owner to change the receive_forwarded ACL for their own DID. |
| CREATE_INVITES_CHANGE |  Allows the DID owner to change the create_invites ACL for their own DID. |
| ANON_RECEIVE_CHANGE |  Allows the DID owner to change the anon_receive ACL for their own DID. |
| SELF_MANAGE_LIST |  DID can self manage their own ACL list (add/remove). |
| SELF_MANAGE_SEND_QUEUE_LIMIT |  DID can set their send queue limits (between the queued_messages_soft and queued_messages_hard). |
| SELF_MANAGE_RECEIVE_QUEUE_LIMIT |  DID can set their receive queue limits (between the queued_messages_soft and queued_messages_hard). |

## Common Mediator Operating Modes

Using the Access Control Lists (ACLs) available, as an administrator, you can configure the mediator to a different operating mode depending on how they want the mediator to handle the access and messages sent over the network.

Refer to the different mediator configurations that you can configure in the `mediator.toml` file for various operating modes.

### Private Mediator – Closed Network

The strictest and most controlled mediator configuration.

A private messaging network that only allows users to communicate with specific users they are authorised with by the administrator using the ACLs. The administrator needs to add the user's DID to the mediator to establish each user's relationship and permission.

For example, a business may want to run a private messaging network only for select staff working on a merger deal that is private within the organisation - staff named Alice and Bob can only communicate with their manager. Still, Alice and Bob can't communicate with each other.

```yaml
### Mediator ACL
mediator_acl_mode = ${GLOBAL_DEFAULT_ACL:explicit_allow}
```
```yaml
### Global Default DID ACL
global_acl_default = ${GLOBAL_DEFAULT_ACL:DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES}
```
```yaml
### Message Delivery ACL
local_direct_delivery_allowed = "${LOCAL_DIRECT_DELIVERY_ALLOWED:true}"
```

### Private Mediator – Open Network

An internal messaging network where users can openly communicate with each other within the company's private network, and the user's DID must be explicitly allowed by the administrator in the mediator.

```yaml
### Mediator ACL
mediator_acl_mode = ${GLOBAL_DEFAULT_ACL:explicit_allow}
```
```yaml
### Global Default DID ACL
global_acl_default = ${GLOBAL_DEFAULT_ACL:ALLOW_ALL}
```
```yaml
### Message Delivery ACL
local_direct_delivery_allowed = "${LOCAL_DIRECT_DELIVERY_ALLOWED:true}"
```

### Public Mediator – Closed Network

A recommended operating mode for most mediators is one in which any user can connect to the mediator unless the administrator explicitly denies them. However, for users to be able to send messages to another user, the recipient must explicitly allow the sender's DID for the messages to be delivered — e.g., you must have permission or consent from the recipient to receive your messages.

This mode protects the users against unknown senders spamming and/or sending unsolicited messages.

It requires the forwarding mechanism for all message delivery, which provides a level of abstraction to the routing and destination of the messages sent over the network.

```yaml
### Mediator ACL
mediator_acl_mode = ${GLOBAL_DEFAULT_ACL:explicit_deny}
```
```yaml
### Global Default DID ACL
global_acl_default = ${GLOBAL_DEFAULT_ACL:ALLOW_ALL,MODE_EXPLICIT_ALLOW}
```
```yaml
### Message Delivery ACL
local_direct_delivery_allowed = "${LOCAL_DIRECT_DELIVERY_ALLOWED:false}"
```

### Public Mediator – Open Network

The most open mediator configuration.

It allows any user to connect, send, and receive messages, whether local or remote. This mediator configuration doesn't have any restrictions unless the user updates their own ACLs if permitted by the administrator *(self-change flags)*.

In this mode, the message handling for spam and unsolicited messages must be handled by the client app or DIDComm agent since the mediator simply relays messages.

```yaml
### Mediator ACL
mediator_acl_mode = ${GLOBAL_DEFAULT_ACL:explicit_deny}
```
```yaml
### Global Default DID ACL
global_acl_default = ${GLOBAL_DEFAULT_ACL:ALLOW_ALL}
```
```yaml
### Message Delivery ACL
local_direct_delivery_allowed = "${LOCAL_DIRECT_DELIVERY_ALLOWED:false}"
```

### Public Mediator – Mixed Mode

The mixed mode allows the mediator to operate on open and closed networks. 

It allows the mediator to accept unknown messages to enable discovery and initiate connections between users using an ephemeral DID. Once the connection is established, users switch to private DIDs to start communicating with each other. The private DIDs are added to the Access Control Lists (ACLs), which will allow message delivery between users.

```yaml
### Mediator ACL
mediator_acl_mode = ${GLOBAL_DEFAULT_ACL:explicit_deny}
```
```yaml
### Global Default DID ACL
global_acl_default = ${GLOBAL_DEFAULT_ACL:ALLOW_ALL,MODE_EXPLICIT_ALLOW}
```
```yaml
### Message Delivery ACL
local_direct_delivery_allowed = "${LOCAL_DIRECT_DELIVERY_ALLOWED:false}"
```

In the case of Out-Of-Band (OOB) discovery, it uses two different DIDs to facilitate discovery:

1. An ephemeral DID that is published in the OOB Invitation. It must be open to the world.

2. A private channel DID that is closed to the world, except for the DID discovered through the OOB discovery protocol.

The ephemeral DID would change its ACL flags to the following:

   - acl_flags: ALLOW_ALL (which also forces MODE_EXPLICIT_DENY)
   
The private channel DID follow the existing `global_acl_default`.

## Examples

_**NOTE |**_ _Ensure Mediator is configured and running before using the following examples._

### Mediator Specific Examples

1. Mediator Administration

You can add/remove/list administration accounts easily using the mediator_administration example

```bash
cargo run --bin mediator_administration
```

### Affinidi Messaging Examples

Refer to the [affinidi-messaging-helpers](../affinidi-messaging-helpers#examples) examples.
# Affinidi Messaging SDK

a Software Development Kit (SDK) to simplify the implementation of Affinidi Messaging into your application.

## Debug logging

To enable logging at DEBUG level just for atm_sdk crate,

```bash
export RUST_LOG=none,affinidi_messaging_sdk=debug
```

## Examples

Use `<MEDIATOR_DID>` from [affinidi-messaging-mediator - Running affinidi-messaging-mediator service](../affinidi-messaging-mediator#running-affinidi-messaging-mediator-service).

```bash
# enable logging for examples,
export RUST_LOG=none,affinidi_messaging_sdk=debug,ping=debug,demo=debug,send_message_to_me=debug,send_message_to_bob=debug,fetch_message_as_bob=debug,message_pickup=debug

# no "did://" prefix for examples
export MEDIATOR_DID=<MEDIATOR_DID>
# default, local mediator endpoint
export MEDIATOR_ENDPOINT=https://localhost:7037/mediator/v1
# relative path to local mediator cert file
export MEDIATOR_TLS_CERTIFICATES="../affinidi-messaging-mediator/conf/keys/client.chain"

# send a trust ping
cargo run --example ping -- \
  --network-address $MEDIATOR_ENDPOINT \
  --ssl-certificates $MEDIATOR_TLS_CERTIFICATES \


cargo run --example message_pickup -- \
  --network-address $MEDIATOR_ENDPOINT \
  --ssl-certificates $MEDIATOR_TLS_CERTIFICATES

# send a message to the same recipient as sender
cargo run --example send_message_to_me -- \
  --network-address $MEDIATOR_ENDPOINT \
  --ssl-certificates $MEDIATOR_TLS_CERTIFICATES

# send a message to another recipient Bob
cargo run --example send_message_to_bob -- \
  --network-address $MEDIATOR_ENDPOINT \
  --ssl-certificates $MEDIATOR_TLS_CERTIFICATES

# pickup a message from another sender Alice
cargo run --example fetch_message_as_bob -- \
  --network-address $MEDIATOR_ENDPOINT \
  --ssl-certificates $MEDIATOR_TLS_CERTIFICATES
```

## WebSocket and HTTPS support

By default, the ATM SDK will use both a WebSocket and HTTPS REST based API calls. Authentication in particular is handled via REST so that JWT access
tokens can be retrieved, these are then used when upgrading to a WebSocket Connection.

WebSocket is used for the following:

1. Sending DIDComm messages, a response containing the message_id is sent via the same websocket.
2. Receiving a stream of inbound messages to the DID used in this SDK

To start using WebSockets, no action is required. A WebSocket is created when `ATM::new()` is called.

You can disable WebSocket through the `ConfigBuilder::with_websocket_disabled()` function.

A custom Websocket URL can be provided via `ConfigBuilder::with_atm_websocket_api(<url>)`

**_NOTE:_** Default action is to take the `ConfigBuilder::with_atm_api()` and convert to a valid WebSocket address

    E.g. `https://localhost:7037/mediator/v1` would become `wss://localhost:7037/mediator/v1/ws`

While you can disable the WebSocket, you can also start and close the WebSocket manually via:

```rust

let my_did = "did:example:alice";
let bob_did = "did:example:bob";
let atm_did = "did:example:atm";

let config = Config::builder()
        .with_ssl_certificates(&mut vec![
            "../affinidi-messaging-mediator/conf/keys/client.chain".into()
        ])
        .with_my_did(my_did)
        .with_atm_did(atm_did)
        .with_websocket_disabled()
        .build()?
let mut atm = ATM::new(config, vec![Box::new(DIDPeer)]).await?;

// Send a ping via REST
atm.send_ping(bob_did, true, true).await?;

// Start the Websocket
atm.start_websocket().await?;

// Send a ping via WebSocket
atm.send_ping(bob_did, true, true).await?;

// Close the websocket (optional)
atm.close_websocket().await?;

```

## WebSocket API Calls

### Send DIDComm Message via WebSocket

- Sends a DIDComm packed message to ATM
- Creating the DIDComm message is not handled by this call

```rust
async fn ws_send_didcomm_message<T>(msg: &str) -> Result<SuccessResponse<T>, ATMError>
// Sends a DIDComm packed message to ATM
// Can specify the return type via <T>

// Example:

let msg = atm.pack_encrypted(&msg, to, from, sign_by);
ws_send_didcomm_message(&msg).await?;
```

Response from `ws_send_didcomm_message()` is:

- Success : Result->Ok `SendMessageResponse` struct
- Error : Result->Err with ATMError object describing the error

## REST API Calls

### DIDComm Trust-Ping

- It can be useful to send a Trust-Ping to a target to test connectivity and routing.
- If you have control of the target, then a response may not be needed. Otherwise you can request a response.

**_NOTE:_** If you a sending an anonymous message, then there is no ability to get a response.

```rust
async fn send_ping(to_did: &str, signed: bool, response:bool) -> Result<(), ATMError>
// Sends a ping to an address via ATM
// - to_did   : DID to ping
// - signed   : if true, then message is signed with your DID, if false then sent anonymous
// - response : Request a PONG response from the target? If signed == false, then this will also be reset to false

// Example: Send a signed trust-ping requesting a response from the target
send_ping("did:example:target#123", true, true).await?;
```

Response from `send_ping()` is:

- Success : Result->Ok with `SendMessageResponse` struct
- Error : Result->Err with ATMError object describing the error

### List Messages

- ATM supports two message folders:
  - Inbox (incoming messages sent to you)
  - Outbox (outbound messages you have sent that have not been delivered to the next node)
- `enum Folder` holds the folder types

```rust
async fn list_messages(did: &str, folder: Folder) -> Result<MessageList, ATMError>
// Retrieves a list of messages for the specified DID (you must own this DID)
// - did    : DID that we want to retrieve messages from (must have authenticated as this DID)
// - folder : Folder enum of either Inbox or Outbox

// Example:
list_messages("did:example:target#123", Folder::Inbox).await?;
```

Response from `list_messages()` is:

- Success : Result->Ok `MessageList` struct containing a list of messages including Metadata
- Error : Result->Err with ATMError object describing the error

### Delete Messages

- Deletes one or more messages from ATM, you need to know the message_ids first!
- Receiver can delete any message that is waiting to be delivered to them
- Sender can delete any message that is waiting still to be delivered for them

```rust
async fn delete_messages(messages: &DeleteMessageRequest) -> Result<DeleteMessageResponse, ATMError>
// Deletes a set of messages contained in an array
// - messages : Vec<String> of message hash ID's

// Example:
delete_messages(&vec!["message_hash1", "message_hash2", ...]).await?;
```

Response from `delete_messages()` is:

- Success : Result->Ok `DeleteMessageResponse` struct
- Error : Result->Err with ATMError object describing the error

Working with `DeleteMessageResponse`:

- success `Vec<String>` : List of message_id's that were successfully deleted
- errors `Vec<(String, String)>` : List of message_id's and error information

### Send DIDComm Message

- Sends a DIDComm packed message to ATM
- Creating the DIDComm message is not handled by this call

```rust
async fn send_didcomm_message<T>(msg: &str) -> Result<SuccessResponse<T>, ATMError>
// Sends a DIDComm packed message to ATM
// Can specify the return type via <T>

// Example:

let msg = atm.pack_encrypted(&msg, to, from, sign_by);
send_didcomm_message(&msg).await?;
```

Response from `send_didcomm_message()` is:

- Success : Result->Ok `SendMessageResponse` struct
- Error : Result->Err with ATMError object describing the error

### Get DIDComm Message

- Retrieves one or more messages from ATM
- You must know the message_id(s) in advance. See `list_messages()`
- You can specify if you want to delete along with the get_message() request
- Call `unpack(&message)` next to unpack the message you have received

```rust
async fn get_messages(messages: &GetMessagesRequest) -> Result<GetMessagesResponse, ATMError>
// Gets one or more messages from ATM

// Example: Get one message, and don't delete it
get_messages(&vec!["message_id".into()], false).await?;
```

Response from `get_messages()` is:

- Success : Result->Ok `GetMessagesResponse` struct
- Error : Result->Err with ATMError object describing the error

Working with `GetMessageResponse`:

- success `Vec<String>` : List of message_id's that were successfully deleted
- get_errors `Vec<(String, String)>` : List of failed gets on message_ids + error message
- delete_errors `vec<(String, String)>` : List of failed deletes on message_ids + error message

### Pack a DIDComm message

- There are three methods to pack (create) a DIDComm message
  - pack_encrypted(message, from, sign_by)
    - encrypts message, if `from` is None, then anonymous encrypt, if `sign_by` is specified then will cryptographically sign the message
  - pack_signed(message, sign_by)
    - signs a plaintext message using the `sign_by` key
  - pack_plaintext(message)
    - creates an unencrypted, no-signature plaintext DIDComm message

```rust
// Example: Send an encrypted and signed message
let message = Message::build()...;
let (message, meta_data) = atm.pack_encrypted(&message, Some(from_did), Some(from_did)).await?;
```

Response from `pack_encrypted()` is:

- Success : Result->Ok (`PackEncryptedMetadata | PackSignedMetadata | String`)
- Error : Result->Err with ATMError object describing the error

### Unpack a DIDComm message

- A wrapper for DIDComm Message::unpack() that simplifies the setup of resolvers etc already done for ATM
- Takes a plain `String` and returns a DIDComm `Message` and `UnpackMetadata` objects

```rust
async fn unpack(message: &str) -> Result<(Message, UnpackMetadata), ATMError>
// Unpacks any DIDComm message into a Message and UnpackMetadata response

// Example:
let didcomm_message = atm.get_messages(&vec!["msg_id".to_string()], true).await?;
let (message, meta_data) = atm.unpack(&didcomm_message).await?;

println!("Message body = {}", message.body);
```

Response from `unpack()` is:

- Success : Result->Ok (`Message`, `UnpackMetadata`)
- Error : Result->Err with ATMError object describing the error

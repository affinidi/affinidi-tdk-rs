# Affinidi Trust Network - Affinidi Trusted Messaging

## Changelog history

Why are there skipped version numbers? Sometimes when deploying via CI/CD Pipeline we find little issues that only affect deployment.
Missing versions on the changelog simply reflect minor deployment changes on our tooling.

## xx April 2025 (0.10.4)

### Mediator (0.10.4)

* FIX: Ephemeral DIDComm messages had send/receive limits applied. Should be ignored for ephemeral.
* Error Handling enhanced to make it easier for developers to figure out what is happening during error conditions
  * See [Error Documentation](affinidi-messaging-mediator/ERRORS.md) for more information

## 1st April 2025 (0.10.3)

* SECURITY_FIX: WARNING: There is an edge case of being able to send bad messages on behalf of another DID if you can steal the authorization tokens. This is due to the security checks being applied to session information only.
  * Mitigation is to add additional checks to check the digital signing of messages in addition to the session info
  * Admin commands will have additional security checks applied
    * Stricter expiry times
    * Can not send Admin commands anonymously (must be signed)

### Mediator (0.10.3)

* FIX: check_permissions() on acls was incorrectly comparing DID to DID_Hash. Should have been DID_Hash to DID_hash comparison
  * There is no security impact from this, prior to this fix, all non-admin requests would have failed.
* SECURITY: See Security Fix notice for 0.10.3
* SECURITY: Constant-time evaluations used for hash comparisons (protection against side-channel attacks)
* FEATURE: Two new mediator configuration options added:
  * `block_anonymous_outer_envelope` Ensures that all messages delivered to the mediator MUST be signed.
  * `block_remote_admin_msgs` Ensures that all admin messages must be delivered from the admin DID itself, can not be forwarded by another party.
  * `admin_messages_expiry` Puts a tight tolerance on admin messages to limit replay attacks
* CHANGE: OOB Invites are now represented as a HASH and not as a SET
  * Only the owner of the OOB Invite or an ADMIN level account can delete OOB Invites
* SECURITY: Inner envelope on forwarded messages is now checked and matched against ACL's
* FEATURE: Better error handling and responses to clients
  * Will now try and respond with a DIDComm Problem Report via both REST and WebSocket API where-ever possible

### SDK (0.10.3)

* CLEANUP: Removed authentication code from the ATM SDK
  * Now uses the affinidi-secrets-resolver crate
* FEATURE: Routing protocol now allows you to configure whether the forward should be anonymous or signed

## 27th March 2025 (0.10.2)

### Mediator (0.10.2)

* FIX: Sending a messages to a DID unknown to the mediator, first message would succeed and then other messages would fail
  * Due to the DID account not being setup correctly. When a DID is unknown, the mediator will correctly setup the DID account
* FEATURE: Improved logging on session errors. Includes DID Hash so you can determine originating DID

### SDK (0.10.2)

* Trust-Ping protocol added the following methods
  * generate_ping_message(): - Creates a DIDComm Plaintext message only
  * generate_pong_message(): - Creates a pong response Plaintext message only

## 24th March 2025 (0.10.1)

### Mediator (0.10.1)

* Ability to specify custom logging attributes to the statistics logs, useful for log aggregation.
  * NOTE: This uses an unstable feature of tracing.

### Examples (0.10.1)

* Fixed loading of secrets into TDK

## 20th March 2025 (0.10.0)

### All (0.10.0)

* Rust 2024 Edition is now enabled for all crates
  * affinidi-did-resolver-cache updated to 0.3.x
* Major refactoring of crate namespace and linking into the Affinidi Trust Development Kit (TDK) Libraries
  * Secrets Resolver now part of TDK Crate
  * DID Authentication added to TDK, stripped from Messaging SDK
  
### SDK (0.10.0)

* FIX/CHANGE: Tungstenite WebSocket replaced with Web-Socket crate
  * Lower-level implementation of WebSocket allows for more graceful handling of error conditions.
  * Addresses the problem of a device going to sleep and missing Close()
* DIDComm Access Lists enabled
  * access_list_list() - Lists DIDs that are allowed/denied for a given DID
  * access_list_add() - Add one or more DIDs to the access list for a given DID
  * access_list_remove() - Remove one or more DIDs from the access list for a given DID
  * access_list_get() - Searches for one or more DIDs from the access list for a given DID
  * access_list_clear() - Resets the Access List to empty for a given DID
* ACL Flag added SELF_MANAGE_QUEUE_LIMIT flag so a DID can change their queue limits

### Mediator (0.10.0)

* FEATURE: Binary WebSocket messages are now converted and handled.
  * Text and Binary Messages supported
* AccessList functions (List, Add, Remove, Get, Clear) added (matches SDK)
  * Database routines added
  * Protocol handling implemented
* Database upgrades will now automatically trigger when a new version of the mediator is started
  * queue_limit ACL Flag will auto add if part of the default ACL set
* JSON fields changed from UpperCamelCase to snake_case
  * Mediator Administration Protocol
  * Mediator Account Management
* Queue limits can now be set per DID between a soft and hard limit, and separate for send/receive queues
  * Admin accounts can override and go above the hard limit as needed
  * New ACL Flag enabled for can change queue_limit (SELF_MANAGE_(SEND|RECEIVE)_QUEUE_LIMIT)
* Ability to set an ephemeral header on messages that will not store the message
  * Instead, if the client is live-streaming it will send only via the live stream

### DIDComm Library (0.10.0)

* Verification Method Type added
  * EcdsaSecp256k1VerificationKey2019

### Helpers (0.10.0)

* mediator_administration
  * access list management added
  * Pagination for Account List and Access List improved
  * Queue Statistics shown in Account Info
  * Can modify queue limits

## 13th February 2025 (0.9.7)

### All (0.9.7)

* MAINTENANCE: Crate dependencies updated to latest
  * Major: Redis 0.27 -> 0.28, Deadpool-redis 0.18 -> 0.19
* MAINTENANCE: Workspace updated for Rust Edition 2024
* FEATURE: affinidi-messaging-processor crate renamed to affinidi-messaging-processors
  * Multiple binaries configured for processors

### Mediator (0.9.7)

* FEATURE: Config: oob_invite_ttl added allowing for customisable time to live (TTL) for OOB Invites
* FEATURE: Message Expiry handling refactored and placed into Expiry Processor
* CHANGE: Config: message_expiry_minutes changed to message_expiry_seconds
* CHANGE: Workspace layout modified
  * Processors moved under the Mediator Workspace
  * Mediator-common created for shared code between Mediator and Processors

### SDK (0.9.7)

* FIX: SDK MPSC Channel when full causes a deadlock
* FEATURE: WebSocket Activated/Disconnected state changes sent through to SDK
  * NOTE: If the channels fill up, the SDK will throw these status updates away as the SDK is not clearing it's channel.

### Helpers (0.9.7)

* FEATURE: read_raw_didcomm example added to help with troubleshooting of DIDComm message errors

## 3rd February 2025 (0.9.6)

### All (0.9.6)

* Cleaning up comments and documentation

### DIDComm Library (0.9.6)

* pack_encrypted will return the forwarded routing_keys from a Service Record
  * Useful for when detecting if message has already been wrapped in a forward/routing wrapper

### Mediator (0.9.6)

* Mediator can now handle JSON Object Attachments

### SDK (0.9.6)

* ATM Struct derives Clone trait, allowing for a simpler clone of the inner representation
* Message Pickup Protocol
  * FEATURE: live_stream_next() wraps Duration in an Option to be more clear that this is an optional setting
  * FIX: live_stream_next() properly waits now for next message vs. only fetching from cache
* Added the ability for a Profile to direct-stream received messages via a channel
  * Allows for mix and match combo when messages are being sent to the SDK
  * Application may want direct-receive capability (all messages from all profiles come on a single channel)
    * Use the WsHandler::DirectMode config option on ATM Configuration
  * Some Profiles may want cache mode where you can call next() against the cache. across all profiles
    * Default mode
  * You may have some tasks that want to stream via a dedicated channel on a per-profile basis
    * use profile.enable_direct_channel() and profile.disable_direct_channel()

### Text-Client (0.9.6)

* When sending a message, will detect if message is already wrapped in a forward envelope
* Chat Messages properly wrap in the text window making it easier to read.

## 30th January 2025 (0.9.4)

### All (0.9.4)

* Rand crate updated from 0.8.x to 0.9.x

### DIDComm Library (0.9.4)

* Cleaned up unneeded lifetime parameters
* Changed how DID Document Verification Methods are discovered, more robust algorithm used
* Tested multi-key recipient sending/receiving - some changes required to pack/unpack
* Removed getrandom crate which is no longer used.

### Mediator (0.9.4)

* Removing Accounts implemented with full cleanup of associated data
  * If admin account, correctly removes from the ADMIN list
  * Can not remove the Mediator DID or Root-Admin DID
* Database Schema version is now recorded, allows for upgrade paths when schema changes
* Mediator Account Type added, allows for treating the Mediator DID separately
* FIX: Trying to strip admin rights from an empty list will now correctly create a ProblemReport that explains the issue
* FIX: Mediator Administration generates a client side error when no Admin DID is selected when removing Admin Accounts
* FIX: Double hashing of DID's on admin_add, refactored so now only uses SHA256 hashed DID's
* FEATURE: Added AccountChangeType to the mediator account-management protocol
* FIX/FEATURE: Mediator will detect when forwarding a message to itself.
  * When a forward to itself is detected, it will block the forward and deliver locally
  * Added configurtion for other local mediator DID's that you want to block forwarding towards

### SDK (0.9.4)

* FIX: If ProblemReport had no args, deserializing would fail as no args field. Now defaults to empty array correctly
* TEST: Added ProblemReport tests to check for empty args and serialization/deserialization
* FEATURE: Added AccountChangeType to the mediator account-management protocol

### Text-Client (0.9.4)

* Added ability to manually add a remote DID for direct establishment

---

## 18th January 2025 (0.9.2)

### Mediator (0.9.2)

* WebSocket connections will now close when the auth session token expires.
* Logging can be configured to use JSON or not (log_json)
* JWT_EXPIRY_TOKEN has a minimum of 10 seconds enforced to stop an issue where clients can get stuck in an
endless refresh loop

### SDK (0.9.2)

* authentication logic will trigger a token refresh if <5 seconds remain on the expiry token (was 10 seconds)
* Fix: refresh retry logic where there was a lock related bug on authentication refresh tokens

## 17th January 2025 (0.8.10)

* Fix Axum Path routes for new version. Internal only.

## 16th January 2025 (0.8.9)

### All (0.8.9)

* Added Global-ACL Support

### Mediator (0.8.9)

* Added Global ACL Support
* Added default_acl to `security` block in configuration
  * Allows to set the default ACL to apply
* New error type ACLDenied added
* Local Direct Delivery added
  * Allows for known recipient DIDs to receive messages directly sent to the
  mediator without wrapping them in a forward envelope

### SDK (0.8.9)

* Authentication will now fail due to ACL Errors and not retry.
* Deleting Messages has been split between direct and background
  * Direct: immediate deletion and the main thread will block
  * Background: requests are handled via a background task

### Affinidi Text Client (0.8.9)

* Updated ratatui-image from 3.x to 4.x

### Affinidi DIDComm (0.8.9)

* MetaEnvelope::new() no longer checks for recipient keys.
  * This has been shifted to the unpack() function
  * This allows for easier handling of any DIDComm message even if recipient is not known by it's secrets

## 16th December 2024 (0.8.1)

### All (0.8.1)

* Updating of required crates.
* Added affinidi-text-client to README

### Affinidi Text Client

* Fixed bug where the OOB invitation process would fail due to incorrect forward_and_send next address
* Fixed bug when displaying chat details, but the chat has been deleted
* Fixed bug when selecting next/previous chat when there are no chats

## 16th December 2024 (0.8.0)

### All

* Crates updated to latest versions
* Shifted crate dependency into top-level Cargo.toml

### Affinidi Mediator

* ACL support added
* DIDComm routing protocol (forwarding) implemented
* Mediator ADMIN accounts added
  * Allows for managing ACL's
* Mediator configuration modified to break config into clearer blocks
  * Breaking change. i.e. config items have changed names and blocks
* send_error_response() method added so that DIDComm error messages can be generated
  * Helps with sending error responses to WebSocket requests
* send_empty_ack_response() method added so that you can ack messages that have no response
* Ability to run the `forwarding` processor locally or remotely
* Redis updated from 0.26 to 0.27 and deadpool-redis from 0.17 to 0.18
* JWT Expiry configuration added
  * access tokens
  * refresh tokens
* Authentication refresh added
  * /authentication/refresh
* OOB Discovery Protocol Added
  * /oob
* Redis Database changes
  * Version check added
  * Redis 7.4 minimum version required
  * LUA scripts shifted
* FIX: deleting a message was returning the incorrect error response when the message_id didn't exist

### Affinidi Processors

* Created forwarding processor
  * Can run as a task within the mediator
  * Optionally, can run as a separate process independently of the mediator

### Affinidi Messaging SDK

* Added forwarding/routing support
* Added routing example
* Added add_secrets() method to add more than one secret at a time
* Added ability to support multiple DID Profiles per SDK ATM Instance
  * Ensures that each DID is authenticated separately, and has their own WebSocket connection
  * Can turn on live-delivery on a per DID basis, or all together
* Added different WebSocket operating modes
  1. Cached Mode: SDK Caches inbound messages and handles a lot of the heavy lifting for you
  2. DirectMode: No caching, you can request a broadcast channel and receive messages directly and handle the logic on the client side.

# Changelog

## [0.2.1] - 2026-04-15

### Fixed

- Reject duplicate DID listeners: `add_listener()` and `start()` now return `DuplicateDid` error when attempting to register a listener with a DID that is already in use by another listener, preventing mediator connection conflicts.

## [0.2.0] - 2026-04-13

### Added

- `DIDCommService` now implements `Clone` — eliminates the need for `Arc<DIDCommService>` wrappers since the struct is already cheaply cloneable (all fields are `Arc`-wrapped internally).
- `DIDCommService::wait_connected(listener_id, timeout)` blocks until a listener has established its mediator connection, eliminating the race between `start()` and first `send_message()`.
- `DIDCommService::send_message_with_retry(listener_id, message, recipient_did, max_retries, initial_backoff)` retries on `NotConnected` errors with exponential backoff, using `wait_connected` between attempts.
- `DIDCommService::listener_did(listener_id)` returns the DID associated with a listener for self-contained outbound message building.
- `DIDCommService::subscribe()` returns a `broadcast::Receiver<ListenerEvent>` for listener lifecycle notifications.
- `ListenerEvent` enum with `Connected`, `Disconnected { error }`, and `Restarting { attempt, delay }` variants, emitted as listeners connect, fail, or restart.
- `ListenerConfig::new(id, profile)` constructor — takes the two required fields and defaults the rest.
- `HandlerContext::listener_id` field — handlers can now identify which listener received the message.
- `Debug` derive on `DIDCommResponse`, `DIDCommServiceConfig`, `ListenerConfig`, `RestartPolicy`, `RetryConfig`.
- `PartialEq` derive on `ListenerEvent`, `ListenerState`, `ListenerStatus`.
- `MiddlewareResult` type alias is now publicly exported.
- Specific error variants `MessageAlreadyExtracted`, `MetadataAlreadyExtracted`, `ExtensionNotFound`, `InvalidRoutePattern` — replacing generic `Internal(String)` for known error conditions.
- Documentation on `DIDCommResponse` explaining auto-fill behavior for `from`, `to`, `thid`, `pthid`.

### Changed

- **Breaking:** `DIDCommService::shutdown()` now takes `&self` instead of consuming `self`, making it compatible with shared ownership patterns (`Arc`, cloned instances).
- **Breaking:** `ErrorHandler::on_error()` is now `async` and returns `Option<DIDCommResponse>`. The default error handler now sends a problem report back to the sender instead of silently dropping the error.
- **Breaking:** `HandlerContext` has a new `listener_id: String` field.

## [0.1.5] - 2026-04-13

### Added

- `DIDCommService::send_message()` for sending proactive (unsolicited) DIDComm messages through an existing listener's mediator connection, avoiding duplicate websocket sessions.
- `NotConnected` error variant returned when attempting to send through a listener that hasn't established its mediator connection yet.
- Warning log when `message.from` doesn't match the profile DID, which would cause recipients to reject the message.
- Unit tests for `send_message` error paths (`ListenerNotFound`, `NotConnected`) and connection handle lifecycle.

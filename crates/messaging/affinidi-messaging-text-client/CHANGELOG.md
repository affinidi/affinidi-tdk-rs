# Changelog

## Unreleased (0.12.8) — inbound messages handled without panicking

- Inbound messages with missing or unreadable fields are logged and skipped
  instead of panicking: a `chat-message` with no `text`, a `chat-effect` with
  no `effect`, a vCard attachment that is not base64 or not JSON (the chat is
  named `UNKNOWN …`, as an unparsable vCard already was), a connection setup
  with no `from`, `to`, `thid` or `pthid`, and failures creating, adding,
  packing or forwarding during the connection setup.
- **Behaviour:** a `chat-message` or `chat-effect` is shown only when it was
  authenticated (authcrypt sender, else verified signer) as the chat's
  remote DID; anything else is logged and dropped.
- **Behaviour:** a problem report is shown in a chat only when it was
  authenticated as the chat's remote DID or the configured mediator DID.
- The terminal is restored (raw mode off, alternate screen left, cursor
  shown) before a panic message is printed, and the client then exits.
- The state file is written whenever the state changes, not only on exit,
  so keys and chats created during a session are on disk if the client stops
  unexpectedly. Each write goes to a new owner-only file in the same
  directory, is synced, and is renamed over `config.json`, so an interrupted
  write leaves the previous file whole; an existing file with wider
  permissions is replaced by a `0600` one.
- **Behaviour:** a `config.json` that exists but cannot be read or parsed is
  no longer replaced by an empty state; the client reports it and exits
  without writing. Only a missing file starts from the default state.
## Unreleased (0.12.7) — dependency currency

No behaviour change: `ratatui-image` 10 → 11.

## [0.12.6] - 2026-08-17

### Changed

- Track `trust-tasks-rs` 0.9.0 (was 0.6.1) and `affinidi-messaging-sdk` 0.19.8.
  The `account` and ACL types this client reads are unchanged across the bump;
  no code changed.

## [0.12.5] - 2026-08-09

### Changed

- Track `trust-tasks-rs` 0.4.0 (was 0.2.46) and `affinidi-messaging-sdk` 0.19.3.
  The `MediatorAclAccessListMode` and `account` types this client reads are
  unchanged across the bump; no code changed.

## [0.12.4] - 2026-06-01

### Changed

- Handle the new `WebSocketResponses::Disconnected` variant on the inbound
  stream (no-op). Bumps `affinidi-messaging-sdk` to 0.18.5.

## [0.12.3] - 2026-05-31

### Changed

- Bump `affinidi-messaging-didcomm` to 0.14 (DIDComm v2.1 interop fixes:
  ECDH-1PU authcrypt KDF #322, JWS unprotected `kid` #323,
  sign-then-encrypt unpack #324). No text-client API change.

## [0.12.2] - 2026-05-24

### Security

- `State::save_to_file` now creates the state file with mode `0o600`
  on Unix. The file serialises `secrets: Vec<Secret>` (DID private
  keys), but was previously opened via `File::create()`, which honours
  the process umask — typically leaving the file world-readable
  (`0644`). On a multi-user host any local account could read the
  keys. No behavior change on non-Unix platforms.
- `send_invitation_accept` no longer panics on a non-UTF-8 OOB invite
  payload. `String::from_utf8(invite).unwrap()` on the base64-decoded
  bytes is replaced with the same warn-and-return pattern the
  surrounding parse steps already use. A malicious invite endpoint
  that returned valid JSON wrapping base64 of non-UTF-8 bytes
  previously crashed the TUI.

## [0.12.1] - 2026-03-28

### Changed

- Added explicit `major.minor` version specifiers for
  `affinidi-messaging-sdk` and `affinidi-messaging-didcomm` path
  dependencies.

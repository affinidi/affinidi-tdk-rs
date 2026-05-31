# Changelog

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

# Affinidi Messaging Mediator

## Changelog history

## 15th April 2026

- **DOC:** Added README section on running without a secure credential store
  (`string://` usage for dev/CI without keyring or AWS Secrets Manager)

## 1st April 2026

### 0.13.0 — VTA Integration

- **FEAT:** Integrate VTA SDK for centralized key management
  - Mediator DID and secrets can now be managed through a Verifiable Trust
    Agent using `vta://` scheme for `mediator_did` and `mediator_secrets`
  - Two-tier authentication: lightweight REST (did:key VTAs) with session-based
    challenge-response fallback (did:web/did:webvh VTAs)
  - Circular dependency detection via VTA health probe — warns when VTA routes
    DIDComm through this mediator
  - REST-first bootstrap prevents deadlock when VTA depends on this mediator
- **FEAT:** Unified VTA startup with local secret caching
  - On startup, fetches fresh secrets from VTA via `integration::startup()`
  - Caches secrets locally (keyring, AWS Secrets Manager, or string backend)
  - Falls back to cached secrets when VTA is unreachable
  - Uses shared `vta-sdk` integration module (same pattern as webvh-service)
- **FEAT:** Interactive setup wizard (`mediator-setup-vta`)
  - Accepts Context Provision Bundle or plain Credential Bundle
  - Credential storage backends: `string://`, `aws_secrets://`, `keyring://`
  - Context selection, DID creation (did:webvh), and existing DID import
  - Multibase-multicodec private key validation during import
  - `--rest` flag resolves VTA DID document for `VTARest` service endpoint
    discovery, bypassing DIDComm transport
  - Saves VTA configuration to mediator.toml
- **FEAT:** VTA credential storage feature gates
  - `vta-aws-secrets` — AWS Secrets Manager credential backend
  - `vta-keyring` — OS keyring credential backend
  - `setup` — interactive setup wizard binary
- **FIX:** Log session ID and DID on duplicate websocket connections
  - Upgraded from debug to WARN with structured fields: `did`, `old_session`,
    `new_session` for easier troubleshooting
  - `StreamingUpdateState::Register` now carries session_id and DID
- **REFACTOR:** Use `fetch_did_secrets_bundle()` for VTA secret loading
  - Replaces manual `fetch_context_secrets` + `list_keys` + zip/remap pattern
  - SDK now maps key labels to verification method IDs automatically
  - Proper pagination (page size 100) instead of single 1000-key page
- **FIX:** Various VTA key management fixes
  - Multicodec prefix handling for Ed25519, X25519, and P256 keys
  - DID verification method ID used as key label for secret lookup
  - AWS SDK region auto-detection from instance metadata
  - Full error details in debug format for AWS SDK errors
- **FIX:** Empty secrets bundle from VTA is now a hard error
  - Prevents starting with zero signing keys due to misconfiguration
- **FIX:** VTA startup timeout (default 30s) prevents hangs when VTA is
  partially reachable
- **FIX:** Dead WebSocket channels cleaned up on send failure
  - Previously, disconnected channels accumulated in the streaming HashMap
- **CHORE:** Replace all `println!`/`eprintln!` with tracing macros
  - Log output now respects log level configuration and JSON formatting
- **CHORE:** Extract `parse_scheme()` helper for `scheme://path` config parsing
- **CHORE:** Switch `vta-sdk` dependency from git nightly to crates.io `0.3.0`

## 28th March 2026

### 0.12.5

- **FIX:** Accept authcrypt (ECDH-1PU) as sender authentication
  - The anonymous message check (`block_anonymous_outer_envelope`) previously
    only recognized JWS signatures (`sign_from`), rejecting authcrypt-only
    messages as "anonymous" even though they are sender-authenticated
  - Now accepts EITHER authcrypt (`metadata.authenticated`) OR JWS
    (`metadata.sign_from`) as proof of sender identity
  - Session DID matching and admin permission checks updated to use
    `sign_from.or(encrypted_from_kid)` as the sender key ID
  - Fixes SDK protocol messages (live-delivery-change, message-pickup, etc.)
    being rejected when `block_anonymous_outer_envelope: true`
- **FIX:** Replaced `deadpool-redis` connection pool with direct `redis` crate
  `ConnectionManager` (auto-reconnecting multiplexed connection)
  - Fixes XREADGROUP BLOCK timeout errors caused by redis 1.x's 500ms default
    response timeout
- **CHORE:** Cleaned up log messages for readability
  - Removed per-second idle DEBUG spam from message expiry cleanup
  - Simplified DID resolver cache, ACL, and auth handler log messages
  - Demoted noisy per-request JWT auth messages from INFO to DEBUG
- **TEST:** Added 19 unit tests for sender authentication handling
  - `check_session_sender_match`: JWS, authcrypt, anonymous, fragment, multi-key
  - `check_admin_signature`: JWS, authcrypt, mismatch, anonymous, malformed
  - `check_permissions`: admin signing with authcrypt kid, anonymous rejection
  - Anonymous detection: authcrypt-only, JWS-only, both, anoncrypt-only

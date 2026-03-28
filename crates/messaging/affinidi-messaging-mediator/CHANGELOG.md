# Affinidi Messaging Mediator

## Changelog history

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

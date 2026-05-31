# Affinidi DID Authentication

## 31st May 2026 (0.3.4)

- Bump `affinidi-messaging-didcomm` to 0.14. This crate authcrypts the
  DID-authentication challenge/response (ECDH-1PU), so it directly picks
  up the corrected authcrypt KDF (#322) and is now interoperable with
  spec-compliant peers; the 0.14 dual-KEK fallback preserves
  compatibility with not-yet-upgraded peers during rollout. No API
  change in this crate.
- Internal: the key-agreement key extractor now delegates to
  `affinidi-did-common`'s `VerificationMethod::decode_public_key`, so the
  JWK/multibase parsing is shared with the messaging SDK rather than
  duplicated here.

## 28th May 2026 (0.3.3)

- **SECURITY (HIGH):** Redact bearer / refresh tokens in `Debug` output for
  three sibling structs. Each derived `Debug` while holding `access_token`
  and the long-lived (or rotated one-time) `refresh_token`. Any
  `debug!`/`warn!("{:?}", x)` on either side of the wire — client session
  state, threaded SDK profiles, mediator refresh handlers — would leak full
  session credentials to logs.
  - `AuthorizationTokens` — primary client-side session credential.
  - `MPAuthorizationTokens` — Meeting Place auth flow.
  - `AuthRefreshResponse` — server-side response wrapping the rotated
    refresh + new access token.
  Manual `Debug` impls now keep the `*_expires_at` timestamps visible and
  render the token values as `[REDACTED]`. `Serialize`/`Deserialize`
  unchanged — wire format and persistence are unaffected.

## 28th March 2026 (0.3.1)

- **FIX:** Republish with `affinidi-messaging-didcomm` 0.13 dependency
  (published 0.3.0 still referenced 0.12 on crates.io)

## 10th March 2026 (0.2.4)

- **MIGRATION:** Migrated to new `affinidi-messaging-didcomm` 0.13.0
  - Pack/unpack functions updated to use bridge helpers
  - Import paths changed from `affinidi_didcomm` to `affinidi_messaging_didcomm`

## 15th December 2025 (0.2.3)

- **FEATURE:** Added support for custom authentication handlers via `CustomAuthHandlers`
  `CustomAuthHandler` trait allows custom authentication logic
  `CustomRefreshHandler` trait allows custom token refresh logic
- **FEATURE:** `DIDAuthentication::with_custom_handlers()` method added
  Authentication and refresh methods now check for custom handlers before
  using default logic

## 3rd November 2025 (0.2.2)

- **MAINTENANCE:** Dependency updates

## 30th May 2025 (0.2.0)

- **BREAKING:** Removed SSI crate dependency

## 29th May 2025 (0.1.10)

- **MAINTENANCE:** Updated crate dependencies (SSI Crate 0.10 --> 0.11)

## 3rd May 2025 (0.1.9)

- **FIX:** building the refresh HTTP request was incorrectly using the DID and
  not the REST API URL
- **FIX:** Refresh was using wrong DIDComm message type
- **FIX:** Debug log message could cause a panic in the authentication task due
  to a negative `u64` value

## 2nd May 2025 (0.1.8)

- **FEATURE:** Adding improved debug messaging for troubleshooting of refreshing
  auth credentials
- **FEATURE:** Splitting refresh logic to be more granular so that `tdk-common`
  authentication task
  has improved handling of refresh logic
- **FEATURE:** Added unit tests for token expiry

## 22nd April 2025 (0.1.7)

- Improved logging of error when no auth service is found

## 24th March 2025 Release 0.1.6

- Implemented caching expiry for AuthenticationRecords

## Release 0.1.0

- Initial release of crate

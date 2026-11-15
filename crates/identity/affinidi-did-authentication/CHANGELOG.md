# Affinidi DID Authentication

## [0.3.21] - 2026-11-15

`authenticate` retries are bounded in time (AgenticSec #529)

### Changed — BEHAVIOUR (R3.6)

- **`retry_limit = -1` is now bounded by a maximum elapsed time, default 15
  minutes** (`DEFAULT_MAX_RETRY_ELAPSED`). `-1` still means "no attempt
  limit", but a service that keeps failing retryably (`408`/`5xx`/timeouts) no
  longer holds the call open forever: once the next backoff would end past
  the bound, `authenticate` returns `DIDAuthError::RetriesExhausted` wrapping
  the last attempt's error. The bound applies in every mode; a finite
  `retry_limit` reached first ends the loop as before. A single attempt in
  progress is bounded by the HTTP client's own timeouts, not cut short.
  Rate-limit waits (`429`) stay capped by `MAX_RATE_LIMIT_WAIT`.
- The `warn` logged on the first retry under `-1` now names the bound instead
  of telling the caller to add its own timeout.

### Added

- `DIDAuthentication::authenticate_with_max_elapsed` — `authenticate` with a
  caller-chosen bound in place of `DEFAULT_MAX_RETRY_ELAPSED`.
- `DEFAULT_MAX_RETRY_ELAPSED` (15 minutes).

## [0.3.20] - 2026-11-15

`retry_limit = -1` is documented and logged as unbounded (AgenticSec #529)

- `DIDAuthentication::authenticate` documents what `retry_limit = -1` means:
  an explicit opt-in to retry for as long as the service fails retryably.
  Rate-limit waits (`429`) stay bounded by `MAX_RATE_LIMIT_WAIT` in every mode
  (now covered by a test with `-1`), but `408`/`5xx`/timeouts are retried
  indefinitely, so a caller choosing `-1` must bound the call itself (the TDK
  authentication task already does, with its own timeout).
- The first retry under `-1` logs a `warn` saying the attempts are unbounded.
  The retry semantics are unchanged.

## [0.3.19] - 2026-11-15

protocol failures are not retried

### Changed — BEHAVIOUR (R3.6)

- An authentication service answer that arrives but cannot be used is now
  `DIDAuthError::InvalidResponse` (was `Authentication`) and is not retried
  (#1145): a body that does not deserialize, and token expiries that are not
  RFC 3339 timestamps or are before the Unix epoch. Before, they were retried
  like a transport failure, and with `retry_limit = -1` forever; now
  `authenticate` returns the first one at once. Display is
  `Invalid authentication response: …` (was `Authentication failed: …`).
- A refresh with no tokens, or whose refresh token has expired too, is now
  `DIDAuthError::NoTokens` (was `Authentication`), which is not retryable: a
  full `authenticate` is needed. `refresh_tokens` returns it; `authenticate`
  still falls back to a full handshake as before. Display is
  `Authentication tokens unavailable: …`.
- `DIDAuthError::Authentication` now means a transport failure only (the
  request could not be made or its body read), and stays retryable.

### Added

- `DIDAuthError::InvalidResponse(String)` and `DIDAuthError::NoTokens(String)`;
  the enum is `#[non_exhaustive]`, so these are additive.

## [0.3.18] - 2026-11-15

Workspace lint and dependency housekeeping. No API or behaviour change.

- Dependency versions now come from the root `[workspace.dependencies]`
  for the external crates shared by five or more workspace members
  (#1070). The published manifest still names concrete requirements; the
  resolved dependency graph and every feature selection are unchanged.
- Now inherits the workspace lints (`[lints] workspace = true`, #1064):
  `unsafe_code` is denied and the workspace clippy lints apply.
- Minimum dependency requirements raised to versions already in use across the
  workspace (no new major/minor, Cargo.lock unchanged): `affinidi-crypto` 0.3
  -> 0.3.2, `affinidi-did-common` 0.4.7 -> 0.4.8,
  `affinidi-did-resolver-cache-sdk` 0.8.53 -> 0.8.55, `affinidi-encoding` 0.1
  -> 0.1.7, `affinidi-messaging-core` 0.1.7 -> 0.1.13,
  `affinidi-messaging-didcomm` 0.15.14 -> 0.15.15, `affinidi-secrets-resolver`
  0.5.18 -> 0.5.19.

## [0.3.17] - 2026-11-15

only retryable errors are retried

### Changed — BEHAVIOUR (R3.6)

- `DIDAuthentication::authenticate` retries only errors that can pass (#1052):
  transport failures (`Authentication`, `DIDResolver`), timeouts, and HTTP
  408, 429 and 5xx. Every other error is returned at once from the attempt
  that hit it — an abort (e.g. a target DID with no `#auth` service), an ACL
  denial, a DIDComm or secrets problem (e.g. "sender has no usable key
  agreement key"), a DID that cannot be resolved, and any other 4xx. Before,
  only `ACLDenied` was; the rest slept and retried, forever with
  `retry_limit = -1`, and otherwise surfaced as `RetriesExhausted` or a bare
  timeout. Callers that relied on retries masking misconfiguration see the
  failure sooner, and not wrapped in `RetriesExhausted`.
- A resolver error for a malformed DID or an unsupported method is now
  `DIDAuthError::UnresolvableDID` (was `DIDResolver`). Display is unchanged.

### Added

- `DIDAuthError::is_retryable()`.
- `DIDAuthError::UnresolvableDID(String)`, `Timeout(String)` (the caller's
  time ran out) and `TaskUnavailable(String)` (the authentication task is not
  running); the enum is `#[non_exhaustive]`, so these are additive.
- `DIDAuthError` is `Clone`, so one result can be handed to several waiters.

## [0.3.16] - 2026-11-13

affinidi-crypto 0.3

- **Changed:** requires `affinidi-crypto` 0.3. No code change and no
  `affinidi-crypto` type in this crate's API.
## [0.3.15] - 2026-11-13

challenge request body built with `serde_json`

The `/challenge` request body was assembled with `format!`, so the DID was not
JSON-escaped. It is now built with `serde_json::json!`. For any valid DID the
bytes on the wire are the same apart from whitespace. No API change.

## [0.3.14] - 2026-11-12

`refresh_check` handles small expiry values

### Fixed

- `refresh_check` computed `access_expires_at - 5` in `u64`. For an expiry
  below 5 (including the `0` of `AuthorizationTokens::default()`) that panicked
  in builds with overflow checks, and in release builds wrapped to a value near
  `u64::MAX`, so the token read as valid and was never refreshed. The margin is
  now added to the clock with saturating arithmetic: such a token is due for a
  refresh (or `Expired` if its refresh token has also run out). The debug log's
  deltas are computed in `i128`, so they cannot overflow either.
- MeetingPlace expiry timestamps before 1970 are an
  `DIDAuthError::Authentication` error instead of wrapping to a far-future
  `u64`. The parse errors for both expiries name the field and no longer
  include the received value (the `refresh_expires_at` one quoted the
  `access_expires_at` value).
- A system clock before 1970 reads as `0` instead of panicking.

### Changed

- **BEHAVIOUR:** a token whose `access_expires_at` is below 5 now reports
  `Refresh`/`Expired` rather than panicking (debug) or `Ok` (release). No API
  change.

## [0.3.13] - 2026-09-16

an authentication `429` is typed, and survives the retry loop

A non-success response from the authentication service (`/challenge`, the
authenticate POST, `/refresh`) became `DIDAuthError::Authentication(String)`
with only the status in the text; and when `authenticate`'s retry loop ran out it
replaced whatever had happened with `AuthenticationAbort("Maximum number of
authentication retries reached")`. A `429` — which service refused, and when to
come back — was lost twice, and the loop retried straight back into the limiter.

### Added

- `DIDAuthError::HttpStatus(Box<HttpStatusError>)` for a non-success status
  other than `401` (still `ACLDenied`). `HttpStatusError` is
  `affinidi_messaging_core::HttpStatusError`, re-exported as
  `affinidi_did_authentication::errors::HttpStatusError` — the same type the
  messaging SDK and `MessagingError` carry.
- `DIDAuthError::RetriesExhausted { attempts, last: Box<DIDAuthError> }`: the
  retry loop gave up, with the last attempt's error kept (also its `source()`).
- `DIDAuthError::http_status()` / `is_rate_limited()`, which look through
  `RetriesExhausted` to the last attempt.
- `MAX_RATE_LIMIT_WAIT` (5 s).

Both variants are additive: `DIDAuthError` is `#[non_exhaustive]`.

### Changed

- **BEHAVIOUR:** a non-success, non-`401` HTTP status is
  `DIDAuthError::HttpStatus`, not `DIDAuthError::Authentication(String)`.
  Display still begins `Authentication failed: `.
- **BEHAVIOUR:** when `DIDAuthentication::authenticate` runs out of retries it
  returns `DIDAuthError::RetriesExhausted`, not `AuthenticationAbort`. Display
  still begins `Authentication Aborted: Maximum number of authentication
  retries reached`, followed by the attempt count and the last error.
- **BEHAVIOUR:** after a `429` the loop waits at least `Retry-After` (never less
  than its own backoff) before the next attempt. Rate-limit waits are budgeted
  at `MAX_RATE_LIMIT_WAIT` across the call: a `Retry-After` that would exceed
  it ends the loop immediately with `RetriesExhausted` carrying the `429`,
  rather than being waited out — the TDK's authentication task allows the
  whole call 10 s, and a longer wait would turn the `429` into a bare timeout.
- New dependency: `affinidi-messaging-core` 0.1.7.

## [0.3.12] - 2026-08-23

dependency refresh

- Bumps `base64` 0.22 → 0.23.
- No source or API change; the bumps are declaration-only and the crate
  compiles unmodified against them. Bumped workspace-wide in the same
  change so no two versions of these crates are compiled side by side.

## [0.3.11] - 2026-08-18

### Fixed

- **A forced refresh of a still-valid access token now actually refreshes.**
  `_refresh_authentication` re-derived the decision from `refresh_check`, which
  only reports `Refresh` inside the last five seconds of the token's life — so a
  caller that had explicitly asked for a refresh was answered with "still valid,
  nothing to do" and got its old token back. The intent was accepted at the
  task boundary (`Refresh needed` was even logged) and then discarded here,
  because there was no way to express it beyond that point.

  Downstream this produced a reconnect storm. `affinidi-messaging-sdk`'s
  websocket transport refreshes proactively at 80% of the token's life and
  rebuilds the socket to carry the new token; because the refresh did nothing,
  each rebuild re-armed the deadline at 80% of what *remained*. For a 900 s
  token that is teardowns at T-180 s, T-36 s, T-7 s and finally T+expired —
  where the refresh at last ran for real — so **four reconnects per token per
  profile instead of one**, the last two close enough together to look like
  flapping.

### Added

- `DIDAuthentication::refresh_tokens`, which mints a new access token while the
  current one is still valid. Purely additive — `authenticate` is unchanged, so
  an ordinary call on a healthy token still costs nothing. Force promotes only
  "still valid": an expired *refresh* token still falls through to a full
  handshake, because there is nothing left to refresh with.

## [0.3.10] - 2026-07-19

### Changed

- Bumped the `affinidi-did-common` requirement from `"0.3"` to `"0.4"`.
  No functional change to this crate: `Document` gained a typed
  `also_known_as` field, which is additive.

## [0.3.9] - 2026-07-04

Internal refactor: the local `_key_type_to_curve` helper is replaced by
`affinidi_crypto::KeyType::key_agreement_curve()`, the shared single source of
truth for the `KeyType` → key-agreement `Curve` mapping. No public API or
behaviour change; patch bump — see ADR 0003.

## [0.3.8] - 2026-06-13

Semver wave (W7 — release W11). `DIDAuthError` is now `#[non_exhaustive]` (match
with a wildcard arm). Patch bump — see ADR 0003 and the migration guide.

## [0.3.7] - 2026-06-13

Auth hygiene (W6):

- Removed the `.expect("negotiated curve came from sender_curves")` in the
  authcrypt packing path; a missing sender key now returns a `DIDComm` error
  instead of panicking.
- Sensitive authentication artifacts — the challenge, the signed challenge
  response, the packed auth message, the received tokens, and the raw HTTP
  request/response bodies — now log at `TRACE` via a `trace_sensitive` helper
  rather than `DEBUG`. `DEBUG` keeps only non-sensitive breadcrumbs
  ("Challenge received", "Tokens received", request URL + status). A capture
  test asserts no sensitive value appears at `DEBUG`.

## [0.3.6] - 2026-06-06

- Robust sender/recipient key-agreement negotiation (#357). The authcrypt
  pack path now enumerates *all* of the sender's usable key-agreement keys
  and negotiates the best shared curve with the recipient by a documented
  preference order (`X25519 > P-256 > secp256k1`), instead of deriving the
  curve from the sender's *first* key only. A sender whose first KA curve
  has no recipient match but whose second does now packs successfully, and a
  no-common-curve failure names the curve set each side offered. The
  negotiation + key-resolution logic moved into `affinidi-did-common`'s new
  `key_negotiation` module (enabled via its `key-agreement` feature),
  removing the helpers that were duplicated between this crate and the
  messaging SDK. The sender key-type → curve mapping now also covers the
  newly-supported P-384 and P-521 key-agreement curves (#357).

## [0.3.5] - 2026-06-01

- Release on `affinidi-messaging-didcomm` 0.15 (#327). The authcrypt
  challenge/response now uses the key-agreement types from
  `affinidi-crypto`'s `jose` module (the `didcomm::crypto` module was
  removed); added a direct `affinidi-crypto` dependency. No behaviour
  change — the ECDH-1PU authcrypt path is byte-identical.

## [0.3.4] - 2026-05-31

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

## [0.3.3] - 2026-05-28

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

## [0.3.1] - 2026-03-28

- **FIX:** Republish with `affinidi-messaging-didcomm` 0.13 dependency
  (published 0.3.0 still referenced 0.12 on crates.io)

## [0.2.4] - 2026-03-10

- **MIGRATION:** Migrated to new `affinidi-messaging-didcomm` 0.13.0
  - Pack/unpack functions updated to use bridge helpers
  - Import paths changed from `affinidi_didcomm` to `affinidi_messaging_didcomm`

## [0.2.3] - 2025-12-15

- **FEATURE:** Added support for custom authentication handlers via `CustomAuthHandlers`
  `CustomAuthHandler` trait allows custom authentication logic
  `CustomRefreshHandler` trait allows custom token refresh logic
- **FEATURE:** `DIDAuthentication::with_custom_handlers()` method added
  Authentication and refresh methods now check for custom handlers before
  using default logic

## [0.2.2] - 2025-11-03

- **MAINTENANCE:** Dependency updates

## [0.2.0] - 2025-05-30

- **BREAKING:** Removed SSI crate dependency

## [0.1.10] - 2025-05-29

- **MAINTENANCE:** Updated crate dependencies (SSI Crate 0.10 --> 0.11)

## [0.1.9] - 2025-05-03

- **FIX:** building the refresh HTTP request was incorrectly using the DID and
  not the REST API URL
- **FIX:** Refresh was using wrong DIDComm message type
- **FIX:** Debug log message could cause a panic in the authentication task due
  to a negative `u64` value

## [0.1.8] - 2025-05-02

- **FEATURE:** Adding improved debug messaging for troubleshooting of refreshing
  auth credentials
- **FEATURE:** Splitting refresh logic to be more granular so that `tdk-common`
  authentication task
  has improved handling of refresh logic
- **FEATURE:** Added unit tests for token expiry

## [0.1.7] - 2025-04-22

- Improved logging of error when no auth service is found

## [0.1.6] - 2025-03-24

- Implemented caching expiry for AuthenticationRecords

## [0.1.0] - 2025-03-11

- Initial release of crate

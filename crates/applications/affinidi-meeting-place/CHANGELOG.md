# Meeting Place Changelog

## [0.6.0] - 2026-11-17

**Breaking (R3.6): moves to the new generation of its affinidi dependencies.** affinidi-tdk-common's `TDKSharedState` / `TDKProfile` appear in this crate's public API, so it moves a minor even where its own code is unchanged. Part of the coordinated breaking release of #1143 and #1166: affinidi-crypto 0.4, affinidi-encoding 0.2, affinidi-secrets-resolver 0.6, affinidi-did-common 0.5, affinidi-did-resolver-traits 0.2, affinidi-did-web 0.2, affinidi-did-resolver-cache-sdk 0.9 and affinidi-data-integrity 0.9 move together; a crate that mixes two generations does not compile.

## [0.5.2] - 2026-11-15

Workspace lint and dependency housekeeping. No API or behaviour change.

- Dependency versions now come from the root `[workspace.dependencies]`
  for the external crates shared by five or more workspace members
  (#1070). The published manifest still names concrete requirements; the
  resolved dependency graph and every feature selection are unchanged.
- Now inherits the workspace lints (`[lints] workspace = true`, #1064):
  `unsafe_code` is denied and the workspace clippy lints apply.
- Minimum dependency requirements raised to versions already in use across the
  workspace (no new major/minor, Cargo.lock unchanged):
  `affinidi-did-authentication` 0.3 -> 0.3.17, `affinidi-did-common` 0.4 ->
  0.4.8, `affinidi-did-resolver-cache-sdk` 0.8 -> 0.8.55,
  `affinidi-messaging-didcomm` 0.15 -> 0.15.15, `affinidi-secrets-resolver`
  0.5 -> 0.5.19, `affinidi-tdk-common` 0.7.1 -> 0.7.2.

## [0.5.1] - 2026-11-13

the `api` endpoint is checked before tokens are sent to it

`MeetingPlace::new` passes the `api` service endpoint from the Meeting Place
DID document to `TDKSharedState::check_service_endpoint` and returns
`MeetingPlaceError::Configuration` if it is refused. Every request to that
endpoint carries the profile's access token, so it must be `https://`, or
`http://` to a loopback host, unless the TDK config sets
`with_allow_insecure_http_endpoints(true)`. Needs `affinidi-tdk-common` 0.7.1.

Behaviour change (R3.6): a Meeting Place DID whose `api` endpoint is plain
`http://` on another host is refused at construction. Requests also inherit
the shared client's new connect and request timeouts. No API change.

## [0.5.0] - 2026-10-01

tdk-common 0.7

Moves to `affinidi-tdk-common` 0.7 (`affinidi-data-integrity` 0.8). `TDKSharedState` and `TDKProfile` are in this crate's public API, so it moves a minor. No source change.

## [0.4.5] - 2026-08-23

dependency refresh

- Bumps `base64` 0.22 → 0.23.
- No source or API change; the bumps are declaration-only and the crate
  compiles unmodified against them. Bumped workspace-wide in the same
  change so no two versions of these crates are compiled side by side.

## [0.4.4] - 2026-07-19

- Bumped the `affinidi-did-common` requirement from `"0.3"` to `"0.4"`.
  No functional change to this crate: `Document` gained a typed
  `also_known_as` field, which is additive.

## [0.4.3] - 2026-06-13

- **Publish fix.** The W9 semver wave (#448) added a wildcard match arm here
  for `affinidi-did-common`'s now-`#[non_exhaustive]` `Endpoint` enum, but the
  crate version was not bumped, so the fix never reached crates.io. The
  published `0.4.2` therefore fails to compile against `affinidi-did-common`
  `0.3.6` (`error[E0004]: non-exhaustive patterns`), which broke the release
  pipeline's publish-verify for downstream crates that pull Meeting Place
  transitively. This bump publishes the already-fixed source. No API or
  behaviour change beyond the W9 match arm.

## [0.4.2] - 2026-06-01

- Release on `affinidi-messaging-didcomm` 0.15 (#327). Dependency-only;
  no Meeting Place API or behaviour change.

## [0.4.1] - 2026-05-31

- Bump `affinidi-messaging-didcomm` to 0.14 (DIDComm v2.1 interop fixes:
  ECDH-1PU authcrypt KDF #322, JWS unprotected `kid` #323,
  sign-then-encrypt unpack #324). No Meeting Place API change.

## [0.4.0] - 2026-05-02

- **BREAKING:** Migrated to `affinidi-tdk-common` 0.6 — field accesses on
  `TDKSharedState` (`.client`, `.did_resolver`, `.authentication`) now go
  through accessor methods.
- **BREAKING:** `MeetingPlaceError` is `#[non_exhaustive]`. The catch-all
  `Error` variant is removed; use `Configuration` (for runtime
  misconfiguration) or `Other` (for everything else). Match arms must
  include a wildcard.
- **BREAKING:** `MeetingPlace::new` no longer falls back to a hardcoded dev
  URL when the service DID lacks an `api` service endpoint — returns
  `MeetingPlaceError::Configuration` instead.
- **BREAKING:** `PlatformType` variants renamed to conventional Rust casing
  (`Apns`, `ApnsSandbox`, `Fcm`, `None`); JSON wire format unchanged via
  `#[serde(rename_all = "SCREAMING_SNAKE_CASE")]`. `FromStr` now rejects
  unknown values instead of silently mapping to `None`.
- **BREAKING:** `MeetingPlace::check_offer_phrase` takes `&TDKProfile`
  instead of consuming it by value (only `.did` was ever used).
- **BREAKING:** `Vcard` inner-field renamed `r#type` → `kind` (the JSON
  field name `type` is preserved via `#[serde(rename = "type")]`).
- **BREAKING:** `RegisterOfferBuilder::build` now consumes `self`.
- **SECURITY:** HTTP request bodies are no longer logged. Offer phrases and
  mnemonics in `register-offer` / `query-offer` / `deregister-offer`
  payloads were previously visible in `debug!` traces.
- **SECURITY:** `valid_until` overflow check tightened — `dur.as_secs() as
  i64` previously wrapped silently for durations exceeding `i64::MAX`,
  letting the wire field carry a negative offset. Now returns
  `Configuration` with a meaningful message.
- **SECURITY:** HTTP 401 _and_ 403 both surface as
  `MeetingPlaceError::Authentication` (was 401-only).
- **CHANGE:** Added `MeetingPlace::did()` and `MeetingPlace::api_url()`
  accessors.
- **CHANGE:** `Vcard` derives `Default`.
- **CHANGE:** Internal HTTP plumbing uses `reqwest::json()` and
  `bearer_auth()` instead of a manually-stringified body.
- **TESTS:** Added 20 unit tests covering vcard serialisation,
  `PlatformType` parsing, `ContactAttributeType` round-trip, valid_until
  encoding (zero / nonzero / overflow), mediator-endpoint splitting,
  OOB-message base64 round-trip, and URI extraction edge cases.
- **DOCS:** Added `#![forbid(unsafe_code)]` at the crate root.

## [0.3.2] - 2026-03-28

- **FIX:** Republish with `affinidi-messaging-didcomm` 0.13 dependency
  (published 0.3.1 still referenced 0.12 on crates.io)

## [0.2.3] - 2026-03-10

- **CHORE:** Updated to new `affinidi-messaging-didcomm` 0.13.0
  - Import paths changed from `affinidi_didcomm` to `affinidi_messaging_didcomm`

## [0.2.2] - 2025-12-18

- **CHORE:** Updating dependencies

## [0.2.1] - 2025-11-03

- **CHORE:** Updating dependencies

## [0.2.0] - 2025-09-30

- **BREAKING:** Removed SSI Library dependencies

## [0.1.10] - 2025-05-29

- **MAINTENANCE:** Updating dependencies (mainly SSI crate)
- **UPDATE:** Meeting Place API changed, requiring mediator DID to be specified

## [0.1.9] - 2025-05-03

- **MAINTENANCE:** Updating dependencies, especially due to changes with DID
  authentication

## [0.1.8] - 2025-04-16

- Removed hardcoded API endpoint for MPX
  - Will derive the API endpoint from the DID (#api), otherwise will fail back to
    the default MPX API

## [0.1.7] - 2025-03-29

- **FEATURE:** MeetingPlace API's added
  - query-offer
  - check-offer
  - register-offer
  - deregister-offer

## [0.1.0] - 2025-03-03

- Initial release of crate

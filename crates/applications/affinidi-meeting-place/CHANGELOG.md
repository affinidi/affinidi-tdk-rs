# Meeting Place Changelog

## 2nd May 2026 (0.4.0)

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

## 28th March 2026 (0.3.2)

- **FIX:** Republish with `affinidi-messaging-didcomm` 0.13 dependency
  (published 0.3.1 still referenced 0.12 on crates.io)

## 10th March 2026 (0.2.3)

- **CHORE:** Updated to new `affinidi-messaging-didcomm` 0.13.0
  - Import paths changed from `affinidi_didcomm` to `affinidi_messaging_didcomm`

## 18th December 2025 (0.2.2)

- **CHORE:** Updating dependencies

## 3rd November 2025 (0.2.1)

- **CHORE:** Updating dependencies

## 30th September 2025 (0.2.0)

- **BREAKING:** Removed SSI Library dependencies

## 29th May 2025 (0.1.10)

- **MAINTENANCE:** Updating dependencies (mainly SSI crate)
- **UPDATE:** Meeting Place API changed, requiring mediator DID to be specified

## 3rd May 2025 (0.1.9)

- **MAINTENANCE:** Updating dependencies, especially due to changes with DID
  authentication

## 16th April 2025 (0.1.8)

- Removed hardcoded API endpoint for MPX
  - Will derive the API endpoint from the DID (#api), otherwise will fail back to
    the default MPX API

## 29th March 2025 (0.1.7)

- **FEATURE:** MeetingPlace API's added
  - query-offer
  - check-offer
  - register-offer
  - deregister-offer

## Release 0.1.0

- Initial release of crate

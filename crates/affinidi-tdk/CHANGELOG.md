# Affinidi TDK Changelog

## 15th December 2025 (Release 0.2.10)

- **FEATURE:** `TDKConfig` now supports custom authentication handlers via
  `custom_auth_handlers` field. Custom auth handlers are passed to the AuthenticationCache during TDK
  initialization
- **FEATURE:** `TDKConfigBuilder::with_custom_auth_handlers()` added to configure custom
  authentication logic

## 8th December 2025 (Release 0.2.9)

- **MAINTENANCE:** Updated to support `affinidi-messaging-sdk` 0.13.x changes

## 4th December 2025 (Release 0.2.8)

- **FEATURE:** TDK now provides a convenience method to verify DataIntegrityProofs
  where a DID lookup is required.
  - This has been added at the TDK level to stop a cyclic dependency between
    `affinidi-data-integrity` crate and `didwebvh-rs` crate

## 9th November 2025 (Release 0.2.7)

- **FEATURE:** Added X25519 key support to `generate_did_key()`
  - `KeyType` also now feature X25519 alongside Ed25519
- **FEATURE:** Added ability to generate did:peer DIDs directly from TDK using
  pre-created secrets
  - This is useful where you already have key material and want to create a did:peer

## 3rd November 2025 (Release 0.2.6)

- **CHORE:** `affinidi-secrets-resolver` updated to 0.4.x
  - `Secret::from_multibase()` API changed

## 31st October 2025 (Release 0.2.5)

- **MAINTENANCE:** Updated dependencies
  - `affinidi-tdk-common` updated to 0.2.2
- **IMPROVEMENT:** Documentation on core TDK instantiation improved

## 11th October 2025 (Release 0.2.4)

- **FEATURE:** [Affinidi DID Common crate](https://crates.io/crates/affinidi-did-common)
  is now re-exported from TDK for ease of use

## 9th October 2025 (Release 0.2.2, 0.2.3)

- **FIX:** Crypto handling improved for Elliptic Curves
  - Key algo names incorrectly capitalized
  - Ed25519 swapped from `ED25519` to `Ed25519`

## 30th September 2025 (Release 0.2.0)

- **IMPROVEMENT:** Removed SSI crate dependencies

## 10th September 2025 (Release 0.1.14)

- **MAINTENANCE:** As part of removing the SSI library from `affinidi-secrets-resolver`,
  added JWK conversion between SSI and Affinidi JWK Structs
- **MAINTENANCE:** Crate dependencies updated

## 29th May 2025 (Release 0.1.12)

- **MAINTENANCE:** Crate dependencies updated
  - SSI crate 0.10 to 0.11
- **FEATURE:** W3C data integrity library added

## 10th May 2025 (Release 0.1.11)

- **FEATURE:** Added `secrets` storage and retrieval to TDK

## 3rd May 2025 (Release 0.1.9 and 0.1.10)

- **FIX:** Addressing DID Authentication retries and refresh errors

## 24th April 2025 (Release 0.1.8)

- MAINTENANCE: Updating dependencies
- UPDATE: DID create supports more complex did:peer service definitions

## 24th March 2025 (Release 0.1.7)

- Ensure that AuthenticationCache starts

## 24th March 2025 (release 0.1.6)

- Added add_profile() to TDK and TDK-Common. Allows for loading of secrets

## Release 0.1.0

- Initial release of crate

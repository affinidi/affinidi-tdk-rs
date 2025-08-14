# Affinidi Trust Network - Affinidi DID Resolver

## Changelog history

### August 2025

Crate donated to [Decentralized Identity Foundation](https://identity.foundation/)

### July 2025

## DID webvh method (0.1.7)

* **BREAKING CHANGE:** WebVH v1.0 spec changes parameters definition
  * empty arrays and objects replaces null values
  * Existing LogEntries using the old format of nulls will still work for reading
* **TESTS:** Additional tests added for complete testing of Parameters Differentials
* **FEATURE:** DID Query parameters added
  * `?versionId=` will resolve a specific versionId LogEntry for the DID
  * `?versionTime=` will resolve to what LogEntry was active at that time
* **FEATURE:** Network based WebVH DID resolution is now enabled
  * call the `resolove()` method to resolve a WebVH DID
* **FEATURE:** LogEntries and Parameters now support versioned schemas
  * V1.0 and pre-V1.0 specification is implemented
  * You can mix and match LogEntry WebVH versions in the same DID

### 14th July 2025

## DID example method (0.5.4)

* **MAINTENANCE:** Updating crate dependencies
* **MAINTENANCE:** Fixing rust lint warnings

## DID peer method (0.6.3)

* **MAINTENANCE:** Updating crate dependencies
* **MAINTENANCE:** Fixing rust lint warnings

### 11th July 2025

## DID webvh method (0.1.6)

* **MAINTENANCE:** Addressing Rust clippy warnings due to new linting rules
* **MAINTENANCE:** Adding Documentation
* **FIX:** Minor tweaks to witness proof handling to properly use `did:key`
* **FIX:** SCID creation was incorrectly using base58 multiencode
* **FIX:** `active_witness` was leaking out from Parameters
* **FIX:** `proof` attribute on LogEntry was not an array, now is an array
* **FEATURE:** `generate_history` example added to create and validate larger DID
  * Default simulates 10 years of change every month
  * Including swapping a witness and a watcher node  every 12 months
* **FEATURE:** webvh portability added to `wizard`

### 26th June 2025

## DID webvh method (0.1.5)

* **CHANGE:** `DIDWebVHState` is now the entry point to working with webvh
LogEntries and WitnessProofs
* **FEATURE:** Witness Proofs are now optimized based on webvh 1.0 spec
  * Prior witness entries will be removed, only keeping the latest witness proof
  for each witness
* **FEATURE:** Witness proof validation enabled
  * Correct handling of optimised Witness Proofs is managed by `WitnessProofCollection`
* **FEATURE:** Future witness proofs will be ignored based on highest versionId
from LogEntry

### 19th June 2025

## DID webvh method (0.1.4)

* **FEATURE:** Conversion of `LogEntry` to `GenericDocument` for signing is now
3.4x faster
  * No need to convert to JSON Value and then transform again, now can use try_from()
* **FIX:** Serialization was not converting camelCase correctly for certain fields
  * `LogEntry` and `Parameters` now correctly use camelCase for serialization
* **OPTIMISATION:** Internal conversion for DataIntegrity now 340% faster
* **FEATURE:** Witnessing of changes enabled.

### 16th June 2025

## DID webvh method (0.1.3)

* **CHANGE:** `create` example moved to `wizard`
* **FEATURE:** `wizard` supports updating the DID and creating new LogEntry records
* **FEATURE:** `wizard` will now store authorization keys in  secrets.json
  * **SECURITY:** This is an example wizard, production use should have more
  robust handling of your secret key material!!!
* **FEATURE:** Updating LogEntries works, can now edit parameters and DID Document
* **FEATURE:** Revoking a DID works

### 6th June 2025

## DID webvh method (0.1.1)

* **FEATURE:** Validation of LogEntry in place
  * Checks Parameters across LogEntries
* **TESTS:** 26 Unit tests added for webvh method
  * Tests cover all aspects of the webvh method, including validation and resolution

### 29th May 2025

## DID Resolver Cache (release 0.5.4)

* **MAINTENANCE:** Bumping crate dependencies
  * SSI crate updated to 0.12
* **FEATURE:** Added `did:webvh` method

## DID webvh method (release 0.1.0)

* Initial release of the `did:webvh` method
  * This is a new method for resolving DIDs using the WebVH protocol
  * The WebVH method is designed to be used with the Affinidi DID Resolver Cache
  
## DID peer method (release 0.6.2)

* **MAINTENANCE:** Bumping crate dependencies
  * SSI crate updated to 0.12

## DID example method (release 0.5.3)

* **MAINTENANCE:** Bumping crate dependencies
  * SSI crate updated to 0.12

### 24th April 2025 (release 0.5.3)

* **MAINTENANCE:** Updating crate dependencies and including updated `did-peer` crate.

### 22nd April 2025 did-peer (release 0.6.1)

* **FEATURE:** Array of `serviceEndpoint` supported in service definitions

### 22nd April 2025 did-peer (release 0.6.0)

* **FEATURE:** Service definitions didn't support specific id's, added defined id's
to Services
  * This is useful where you need to have a named service id, for example DID
  Authentication service
* **FEATURE:** ServiceEndpoint definition can now support a simple URI instead of
just JSON Object
  * Allows for simpler URI's for services that do not need complex definitions
* Crate dependencies updated to latest versions

### 19th March 2025 (release 0.5.1)

* FIX: did_example feature resulted in a build error

### 19th March 2025 (release 0.5.0)

* **MAINTENANCE:** Crates updated
* **CHANGE:** Hashing functions streamlined and changed from blake3 to highway
  * Includes HashMap usage (using aHash)
* ***BREAKING Changes:***
  * Config option with_max_did_size_in_kb --> with_max_did_size_in_bytes
  * Hash key used changed from String to u128

**NOTE:**
Network Performance has increased by approx 82% in this release

### 4th March 2025 (release 0.4.1)

* Fixing release issues to crates.io

### 4th March 2025 (release 0.4.0)

* **MAINTENANCE:** Crates updated
* Added Minimum Supported Rust Version 1.85
* ***Breaking Change:*** ClientConfig and ClientConfigBuilder renamed
  * ClientConfig --> DIDCacheConfig
  * ClientConfigBuilder --> DIDCacheConfigBuilder
  
### 22nd February 2025 (release 0.3.0)

* **MAINTENANCE:** Rust 2024 Edition enabled by default (2021 --> 2024)
* **MAINTENANCE:** Crates updated
* **UPDATE:** affinidi-did-resolver-cache-sdk
  * tokio-tungstenite removed and replaced via web-socket crate
  * Enables better low level error handling of the WebSocket. Especially when a
  device sleeps and detecting the WebSocket Channel has been closed.

### 12th February 2025 (release 0.2.9)

* **FIX:** SDK Network loop would not exit when the MPSC Channel was closed.
* **MAINTENANCE:** Crates updated

### 30th January 2025 (release 0.2.8)

* **FEATURE:** add_did_document() added to manually load DID Documents into the cache.
  * Can be used when you want to pre-load a DID Document or for testing purposes
  load non-public documents
* **MAINTENANCE:** Crates updated (rand 0.8 --> 0.9)

### 23rd January 2025 (release 0.2.5)

* Updating crates
* **Added** did:example method to help with local development/testing

### 7th January 2025 (release 0.2.4)

* Updating crates
  * Updated Axum framework from 0.7.x to 0.8.x

### 13th November 2024 (release 0.2.1)

* Updating crates
* Changed how keys are resolved in did:peer from multicodec to JsonWebTokens

### 5th November 2024 (release 0.2.0)

* Updating dependency crate versions
* Code cleanup on warnings
* Implement local and network features on SDK
* Added to did:key the ability to populate keyAgreement
* Added WASM support
* Added HTTP GET resolution
  * GET /did/v1/resolve/`did`
* Configuration option to enable HTTP or WebSocket routes

### 24nd September 2024 (release 0.1.12)

* Removing all logs of remote_address

### 22nd September 2024 (release 0.1.11)

* Updating crates (SSI, Tower)
* bumping minor crate versions

### 18th September 2024 (release 0.1.10)

* **fix:** example did-peer `generate` added a trailing `/` on the
serviceEndpoint URI
* removed `did-peer` LICENCE and CHANGELOG files, all contained in the parent
crate `affinidi-did-resolver`
* Bumping crate versions

### 15th September 2024 (release 0.1.9)

* **clarity:** Added a note regarding serviceEndpoint Id's being a URI vs a IRI (SSI
Crate limitation)
  * This changes serviceEndpoint.id from `#service` to `did:peer:#service` so
  that it passes Uri checks
* **fix:** If more than a single service was specified, then this would crash due
to `#service-n` not being a valid URI
  * Changed so that all serviceEndpoint Id's are `did:peer:#service` as the
  starting string
* **update:** `tokio-tungstenite` crate updated from 0.23 to 0.24

### 9th September 2024 (release 0.1.5)

* Renaming crate names
* Setting publish to true for crates.io
* Bumping crate versions

### 5th September 2024 (release 0.1.4)

* Updated crates
* did-peer added missing types and support for peer implementation type 0
(supports 0 and 2).

### 3rd September 2024 (release 0.1.3)

* Added Debug trait to ClientConfig so we can print the config elsewhere

### 2nd September 2024 (release: 0.1.2)

* tokio crate updated
* release version changed to 0.1.2
* benchmark example - warnings removed

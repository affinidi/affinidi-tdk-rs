# Affinidi Trust Network - Affinidi DID Resolver

## Changelog history

### 19th March 2025 (release 0.5.1)

* FIX: did_example feature resulted in a build error

### 19th March 2025 (release 0.5.0)

* MAINTENANCE: Crates updated
* CHANGE: Hashing functions streamlined and changed from blake3 to highway
  * Includes HashMap usage (using aHash)
* BREAKING Changes:
  * Config option with_max_did_size_in_kb --> with_max_did_size_in_bytes
  * Hash key used changed from String to u128

NOTE:
Network Performance has increased by approx 82% in this release

### 4th March 2025 (release 0.4.1)

* Fixing release issues to crates.io

### 4th March 2025 (release 0.4.0)

* MAINTENANCE: Crates updated
* Added Minimum Supported Rust Version 1.85
* Breaking Change: ClientConfig and ClientConfigBuilder renamed
  * ClientConfig --> DIDCacheConfig
  * ClientConfigBuilder --> DIDCacheConfigBuilder
  
### 22nd February 2025 (release 0.3.0)

* MAINTENANCE: Rust 2024 Edition enabled by default (2021 --> 2024)
* MAINTENANCE: Crates updated
* UPDATE: affinidi-did-resolver-cache-sdk
  * tokio-tungstenite removed and replaced via web-socket crate
  * Enables better low level error handling of the WebSocket. Especially when a device sleeps and detecting the WebSocket Channel has been closed.

### 12th February 2025 (release 0.2.9)

* FIX: SDK Network loop would not exit when the MPSC Channel was closed.
* MAINTENANCE: Crates updated

### 30th January 2025 (release 0.2.8)

* FEATURE: add_did_document() added to manually load DID Documents into the cache.
  * Can be used when you want to pre-load a DID Document or for testing purposes load non-public documents
* MAINTENANCE: Crates updated (rand 0.8 --> 0.9)

### 23rd January 2025 (release 0.2.5)

* Updating crates
* Added did:example method to help with local development/testing

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

* fix: example did-peer `generate` added a trailing `/` on the serviceEndpoint URI
* removed `did-peer` LICENCE and CHANGELOG files, all contained in the parent crate `affinidi-did-resolver`
* Bumping crate versions

### 15th September 2024 (release 0.1.9)

* clarity: Added a note regarding serviceEndpoint Id's being a URI vs a IRI (SSI Crate limitation)
  * This changes serviceEndpoint.id from `#service` to `did:peer:#service` so that it passes Uri checks
* fix: If more than a single service was specified, then this would crash due to `#service-n` not being a valid URI
  * Changed so that all serviceEndpoint Id's are `did:peer:#service` as the starting string
* update: `tokio-tungstenite` crate updated from 0.23 to 0.24

### 9th September 2024 (release 0.1.5)

* Renaming crate names
* Setting publich to true for crates.io
* Bumping crate versions

### 5th September 2024 (release 0.1.4)

* Updated crates
* did-peer added missing types and support for peer implementation type 0 (supports 0 and 2).

### 3rd September 2024 (release 0.1.3)

* Added Debug trait to ClientConfig so we can print the config elsewhere

### 2nd September 2024 (release: 0.1.2)

* tokio crate updated
* release version changed to 0.1.2
* benchmark example - warnings removed

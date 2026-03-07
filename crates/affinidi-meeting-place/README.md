# affinidi-meeting-place

[![Crates.io](https://img.shields.io/crates/v/affinidi-meeting-place.svg)](https://crates.io/crates/affinidi-meeting-place)
[![Documentation](https://docs.rs/affinidi-meeting-place/badge.svg)](https://docs.rs/affinidi-meeting-place)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-meeting-place)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

SDK for [Affinidi Meeting Place](https://meetingplace.world) — discover and
connect with others in a secure and private way using
[Decentralised Identifiers (DIDs)](https://www.w3.org/TR/did-1.0/) and the
[DIDComm](https://identity.foundation/didcomm-messaging/spec/) protocol.

## How It Works

```mermaid
sequenceDiagram
    participant Alice
    participant MeetingPlace
    participant Bob

    Alice->>MeetingPlace: Publish discoverable profile (DID)
    Bob->>MeetingPlace: Search for Alice
    MeetingPlace->>Bob: Return Alice's DID
    Bob->>Alice: Initiate DIDComm connection
    Alice->>Bob: Establish private channel
```

## Installation

```toml
[dependencies]
affinidi-meeting-place = "0.3"
```

## Related Crates

- [`affinidi-did-authentication`](../affinidi-tdk/common/affinidi-did-authentication/) — DID authentication (dependency)
- [`affinidi-tdk-common`](../affinidi-tdk/common/affinidi-tdk-common/) — Shared utilities (dependency)
- [`affinidi-messaging`](../affinidi-messaging/) — DIDComm messaging framework
- [`affinidi-did-resolver`](../affinidi-did-resolver/) — DID resolution

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

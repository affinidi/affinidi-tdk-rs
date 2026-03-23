# affinidi-siopv2

[![Crates.io](https://img.shields.io/crates/v/affinidi-siopv2.svg)](https://crates.io/crates/affinidi-siopv2)
[![Documentation](https://docs.rs/affinidi-siopv2/badge.svg)](https://docs.rs/affinidi-siopv2)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

Self-Issued OpenID Provider v2 (SIOPv2) implementation per
[OpenID Connect Self-Issued OP v2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html).

Enables decentralized authentication where the End-User IS the OpenID Provider.

## Features

- **Self-Issued ID Token**: Create and validate self-signed ID Tokens
- **JWK Thumbprint subjects**: Subject identifiers via RFC 7638
- **DID-based subjects**: Subject identifiers via DID methods
- **Authorization request/response**: Full SIOPv2 protocol messages
- **Provider and RP roles**: Both wallet-side and verifier-side APIs
- **Cross-device flow**: `direct_post` response mode for QR code flows
- **7-step validation**: Complete ID Token validation per spec

## eIDAS 2.0

Provides wallet-to-RP authentication for the EUDI Wallet ecosystem,
complementing OpenID4VP for credential presentation.

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

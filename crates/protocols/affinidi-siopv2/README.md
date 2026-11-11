# affinidi-siopv2

[![Crates.io](https://img.shields.io/crates/v/affinidi-siopv2.svg)](https://crates.io/crates/affinidi-siopv2)
[![Documentation](https://docs.rs/affinidi-siopv2/badge.svg)](https://docs.rs/affinidi-siopv2)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

Self-Issued OpenID Provider v2 (SIOPv2) implementation per
[OpenID Connect Self-Issued OP v2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html).

Enables decentralized authentication where the End-User IS the OpenID Provider.

## Features

- **Self-Issued ID Token**: build the claims, sign them as a compact JWS
  (`SelfIssuedIdToken::sign`), and verify a received token
  (`verify_id_token`): algorithm allowlist, signature, `iss == sub`, `aud`,
  `nonce`, `exp` / `iat` with leeway, and the JWK Thumbprint
- **JWK Thumbprint subjects**: Subject identifiers via RFC 7638; the token is
  verified with the key in `sub_jwk` (`ES256` or `EdDSA`)
- **DID-based subjects**: Subject identifiers via DID methods; the header
  `kid` must be a DID URL under `sub`, and the caller supplies a
  `DidKeyResolver` (this crate does not resolve DIDs)
- **Authorization request/response**: SIOPv2 protocol messages
- **Cross-device flow**: `direct_post` response mode for QR code flows

`SelfIssuedIdToken::validate_claims` checks claims only and verifies no
signature; do not use it on its own for a token received from a wallet.

## Example

```rust,ignore
use affinidi_siopv2::*;

// Wallet
let jwt = IdTokenBuilder::new(client_id, nonce)
    .with_jwk_thumbprint(signer.public_key_jwk())?
    .build()?
    .sign(&signer)?;

// Relying party
let expected = IdTokenExpectations::new(&["ES256", "EdDSA"], client_id, nonce);
let token = verify_id_token(&jwt, &expected, None)?;
```

## eIDAS 2.0

Provides wallet-to-RP authentication for the EUDI Wallet ecosystem,
complementing OpenID4VP for credential presentation.

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

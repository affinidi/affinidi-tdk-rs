# affinidi-openid4vp

[![Crates.io](https://img.shields.io/crates/v/affinidi-openid4vp.svg)](https://crates.io/crates/affinidi-openid4vp)
[![Documentation](https://docs.rs/affinidi-openid4vp/badge.svg)](https://docs.rs/affinidi-openid4vp)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/protocols/affinidi-openid4vp)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

OpenID for Verifiable Presentations (OpenID4VP) verifier building blocks per
[OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).

## Installation

```toml
[dependencies]
affinidi-openid4vp = "0.1"
```

## Features

- **Client identifiers**: `ClientId` builds and parses prefixed client
  identifiers (`decentralized_identifier:`, `x509_hash:`, `x509_san_dns:`, …)
- **Signed request objects**: `RequestObject` with the 1.0 members,
  `RequestObject::validate`, `RequestObject::sign` (a JAR,
  `typ: oauth-authz-req+jwt`) and `RequestObject::wallet_invocation_uri`
- **DCQL**: `DcqlQuery` parsing and validation, `match_credentials` (which
  stored credentials answer a query) and `evaluate_presentation` (whether
  verified presentations satisfy it)
- **`direct_post.jwt` responses** (feature `direct-post-jwt`):
  `response::receive_direct_post_jwt` reads and decrypts what a wallet posts
  to `response_uri`, or returns the wallet's error response

## What this crate does not do

- **It does not verify presentations.** Check each presentation with its
  credential format's crate (issuer signature, key-binding proof over the
  request's `nonce` and the verifier's `client_id`), then pass what verified
  to `DcqlQuery::evaluate_presentation`.
- **There is no wallet side for 1.0.** Nothing here verifies a signed request
  object as a wallet would.
- **Presentation Exchange v2 and the pre-1.0 request/response are types
  only**, kept for existing callers. `verifier::validate_authorization_response`
  checks the `state`, the submission's `definition_id` and a non-empty
  `descriptor_map`; it does not match the submission against the input
  descriptors or look at the VP token. The `wallet` helpers only build the
  structures.

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

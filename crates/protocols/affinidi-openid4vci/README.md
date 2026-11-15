# affinidi-openid4vci

[![Crates.io](https://img.shields.io/crates/v/affinidi-openid4vci.svg)](https://crates.io/crates/affinidi-openid4vci)
[![Documentation](https://docs.rs/affinidi-openid4vci/badge.svg)](https://docs.rs/affinidi-openid4vci)
[![Rust](https://img.shields.io/badge/rust-1.95.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/protocols/affinidi-openid4vci)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

OpenID for Verifiable Credential Issuance (OpenID4VCI) message types and
issuer/wallet helpers modelled on
[OpenID4VCI **draft 13**](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html).

> **Not OpenID4VCI 1.0 Final.** The wire types are the draft-13 shapes
> (`format` + `proof` in the credential request, a single `credential` plus
> `c_nonce` in the response, `batch_credential_endpoint` in issuer metadata,
> `vc+sd-jwt` as the SD-JWT VC format identifier). A 1.0 Final wallet or issuer
> (`credential_configuration_id`, `proofs`, `credentials[]`, `nonce_endpoint`,
> `dc+sd-jwt`) cannot exchange these messages with this crate. 1.0 Final
> support is tracked separately.

## Installation

```toml
[dependencies]
affinidi-openid4vci = "0.2"
```

## Features

- **Issuer metadata**: `CredentialIssuerMetadata` for `/.well-known/openid-credential-issuer` (draft-13 shape)
- **Credential offer**: offer payloads (QR code / deep link) carrying the
  `authorization_code` or `pre-authorized_code` grant
- **Credential request/response**: draft-13 credential endpoint types, plus a
  structural request check (`issuer::validate_credential_request`) and a
  deferred-issuance response helper
- **Proof of possession**: JWT key proof (`openid4vci-proof+jwt`) build and
  verify — version-independent

### Not implemented

- No OAuth token endpoint types (token request/response), no PKCE, and no
  `tx_code` verification: the authorization-code and pre-authorized-code
  exchanges are left to the caller's OAuth stack. The offer types only *carry*
  the grant.
- No batch credential request/response types (the metadata field exists only
  because draft 13 defines it).

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

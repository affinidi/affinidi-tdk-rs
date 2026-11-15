# affinidi-openid4vci

[![Crates.io](https://img.shields.io/crates/v/affinidi-openid4vci.svg)](https://crates.io/crates/affinidi-openid4vci)
[![Documentation](https://docs.rs/affinidi-openid4vci/badge.svg)](https://docs.rs/affinidi-openid4vci)
[![Rust](https://img.shields.io/badge/rust-1.95.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/protocols/affinidi-openid4vci)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

OpenID for Verifiable Credential Issuance (OpenID4VCI) message types and
issuer/wallet helpers for two protocol versions:

| Version | Module |
|---|---|
| [OpenID4VCI **1.0 Final**](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) | `affinidi_openid4vci::v1` |
| [OpenID4VCI **draft 13**](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html) | crate root (`types`, `issuer`, `wallet`) |

The two message sets are not wire compatible. Draft 13 uses `format` + `proof`
in the credential request, a single `credential` plus `c_nonce` in the
response, `batch_credential_endpoint` in issuer metadata and `vc+sd-jwt`.
1.0 Final uses `credential_configuration_id` / `credential_identifier` +
`proofs`, a `credentials` array, a Nonce Endpoint, `notification_endpoint` /
`batch_credential_issuance` metadata and `dc+sd-jwt`. Use the module that
matches your peer; new integrations should use `v1`.

## Installation

```toml
[dependencies]
affinidi-openid4vci = "0.2"
```

## Features

### OpenID4VCI 1.0 Final (`v1`)

- **Wire types** for every endpoint, each citing its spec section: issuer
  metadata (incl. `nonce_endpoint`, `notification_endpoint`,
  `batch_credential_issuance`, request/response encryption metadata,
  `credential_metadata`), credential offer (`authorization_code` with
  `issuer_state`, `pre-authorized_code` with the `tx_code` object),
  authorization details, Token Request (form-encoded) / Response, Nonce
  Response, Credential Request (`credential_identifier` |
  `credential_configuration_id`, `proofs`, `credential_response_encryption`),
  Credential Response (`credentials`, `transaction_id` + `interval`,
  `notification_id`), Deferred Credential Request/Response, Notification
  Request, and the error responses with their spec error codes
- **Issuer helpers**: offer construction and offer URIs (by value / by
  reference), the pre-authorized code + `tx_code` Token Request check,
  Credential Request validation against issuer metadata (identification,
  proof type, batch size, response encryption), and `jwt` key proof
  verification for the whole `proofs` array (`invalid_proof` vs
  `invalid_nonce`)
- **Wallet helpers**: offer URI parsing, the metadata URL (well-known segment
  inserted before the issuer path), issuer metadata checks, the pre-authorized
  Token Request, credential / deferred / notification request builders, and
  credential response checks
- Serde round-trip tests against the spec's own JSON examples

Not modelled in `v1`: JWE encryption of requests/responses (only the
parameter types), signed issuer metadata verification, the Authorization
Endpoint / PAR / PKCE, wallet and key attestation evaluation, and `di_vp` /
`attestation` proof verification (structural checks only).

### OpenID4VCI draft 13 (crate root)

- **Issuer metadata**: `CredentialIssuerMetadata` for `/.well-known/openid-credential-issuer` (draft-13 shape)
- **Credential offer**: offer payloads (QR code / deep link) carrying the
  `authorization_code` or `pre-authorized_code` grant
- **Credential request/response**: draft-13 credential endpoint types, plus a
  structural request check (`issuer::validate_credential_request`) and a
  deferred-issuance response helper
- No OAuth token endpoint types, PKCE or `tx_code` verification, and no batch
  credential request/response types (the metadata field exists only because
  draft 13 defines it)

### Shared

- **Proof of possession**: JWT key proof (`openid4vci-proof+jwt`) build and
  verify, version-independent

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

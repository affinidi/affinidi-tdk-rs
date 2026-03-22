# affinidi-oid4vc-core

Shared types for the OpenID for Verifiable Credentials (OID4VC) protocol family:
- [SIOPv2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)
- [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)

## Shared Types

- `ResponseType` — id_token, vp_token, code
- `ResponseMode` — fragment, direct_post, direct_post.jwt
- `SubjectSyntaxType` — JWK Thumbprint, DID methods
- `ClientMetadata` — RP metadata fields
- `DisplayProperties` — UI rendering metadata
- JWK Thumbprint computation (RFC 7638)

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

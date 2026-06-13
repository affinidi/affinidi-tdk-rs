# Migration guide — public-API sealing wave (June 2026)

This release adds `#[non_exhaustive]` to a set of public error enums,
data-model enums, and structs across the workspace, and adds constructors to the
sealed structs. The policy is recorded in
[ADR 0003](../adr/0003-public-api-semver-policy.md).

The changes are **future-proofing**: they let new variants/fields be added later
without a breaking release. For most consumers there is **no migration** — only
code that exhaustively matched these enums *without* a wildcard, or constructed
the sealed structs via struct literals, needs a small edit.

## Affected crates / versions

| Crate | Version | Sealed |
|-------|---------|--------|
| `affinidi-crypto` | 0.2.2 | `CryptoError`; `Params`; `JWK`, `ECParams`, `OctectParams`, `KeyPair` (+ `new`) |
| `affinidi-messaging-didcomm` | 0.15.2 | `DIDCommError` |
| `affinidi-did-common` | 0.3.6 | `DocumentError`; `Endpoint`, `VerificationRelationship`, `OneOrMany`; `Document`, `Service`, `VerificationMethod` |
| `affinidi-secrets-resolver` | 0.5.8 | `SecretsResolverError` |
| `affinidi-did-authentication` | 0.3.8 | `DIDAuthError` |
| `affinidi-vc` | 0.1.2 | `VcError`; `VerifiableCredential`, `CredentialStatus` |
| `affinidi-sd-jwt` | 0.1.4 | `SdJwtError`; `SdJwt` (+ `new`) |
| `affinidi-data-integrity` | 0.7.6 | `DataIntegrityProof` (+ `new`) |

> These are **patch bumps**. They stay within each crate's current minor so the
> `[patch.crates-io]` redirects for external consumers (`didwebvh-rs`,
> `vta-sdk`) keep resolving — see ADR 0003 for why.

## 1. Matching a now-`#[non_exhaustive]` enum → add a wildcard arm

```rust
// Before — exhaustive match, breaks when a variant is added:
match err {
    CryptoError::KeyError(m) => ...,
    CryptoError::Signing(m)  => ...,
}

// After — wildcard arm absorbs future variants:
match err {
    CryptoError::KeyError(m) => ...,
    CryptoError::Signing(m)  => ...,
    _ => ...,
}
```

Applies to: `CryptoError`, `DIDCommError`, `VcError`, `SdJwtError`,
`DIDAuthError`, `DocumentError`, `SecretsResolverError`, `Params`, `Endpoint`,
`VerificationRelationship`, `OneOrMany`.

## 2. Constructing a now-sealed struct → use the constructor/builder

```rust
// Before — struct literal, no longer allowed from another crate:
let jwk = JWK { key_id: None, params };

// After — use the constructor:
let jwk = JWK::new(None, params);
```

Constructors added this release:

- `JWK::new(key_id, params)`
- `ECParams::new(curve, x, y, d)` · `OctectParams::new(curve, x, d)`
- `KeyPair::new(key_type, private_bytes, public_bytes, jwk)`
- `SdJwt::new(jws, disclosures, kb_jwt)`
- `DataIntegrityProof::new(cryptosuite, verification_method, proof_purpose, proof_value, created, context)`

`Document` / `Service` / `VerificationMethod` use the existing
`DocumentBuilder` / `ServiceBuilder` / `VerificationMethodBuilder` (and
`Document::new`). `VerifiableCredential` / `CredentialStatus` are obtained via
deserialization or issuance.

Fields remain **public for reading and mutation** — only literal *construction*
and `..spread` updates are sealed:

```rust
// `..proof_config` struct-update is no longer allowed cross-crate; instead:
let mut proof = proof_config.clone();
proof.proof_value = Some(sig);
```

## 3. Deserialization is unaffected

`serde` deserialization of these types is unchanged — the `Deserialize` impls
are generated in the defining crate, which is allowed to construct its own
non-exhaustive types.

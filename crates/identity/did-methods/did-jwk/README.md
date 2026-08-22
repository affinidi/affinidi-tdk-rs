# affinidi-did-jwk

Minimal `did:jwk` DID method resolver for the Affinidi TDK.

Resolves `did:jwk:{base64url-nopad(utf8(jwk))}` into a DID Document. There is
no network step and no state — the whole document is derived from the
identifier.

## The `use` member

Per the specification, a key restricts which verification relationships it
appears in:

| `use` | Relationships |
| --- | --- |
| `"sig"` | all except `keyAgreement` |
| `"enc"` | `keyAgreement` only |
| absent | all five |

## Private key material is refused

A DID is a public identifier. An identifier encoding a JWK with `d`, `p`, `q`,
`dp`, `dq`, `qi` or `k` is rejected rather than stripped — silently discarding
the private half would publish a document while leaving the holder believing
the secret was never there.

## Deviation from the crate it replaced

The `did-jwk` crate this replaced emitted `Multikey` verification methods with
`publicKeyMultibase`, and applied every verification relationship regardless of
the key's `use`. Both diverge from the specification, which mandates
`JsonWebKey2020` with `publicKeyJwk` and honours `use`. This crate follows the
specification.

No production caller consumed the old shape — the `did-jwk` feature was not
enabled by any crate in the workspace — though the resolver SDK's own
`local_resolve_jwk` test asserted it, and was updated alongside this change.

## Why this crate exists

Upstream `did-jwk` reaches the rest of the `ssi-*` stack, which pulls
`derivative` (RUSTSEC-2024-0388, unmaintained) along with the `im` /
`sized-chunks` / `bitmaps` / `smallstr` cluster shared with `did:ethr` and
`did:pkh`. See `affinidi-did-ethr` for the full rationale.

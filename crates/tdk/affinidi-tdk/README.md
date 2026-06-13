# affinidi-tdk

[![Crates.io](https://img.shields.io/crates/v/affinidi-tdk.svg)](https://crates.io/crates/affinidi-tdk)
[![Documentation](https://docs.rs/affinidi-tdk/badge.svg)](https://docs.rs/affinidi-tdk)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-tdk/affinidi-tdk)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

The unified entry point for the Affinidi Trust Development Kit. Depend on this
single crate and enable feature flags to pull in only the libraries you need.

> **Disclaimer:** This project is provided "as is" without warranties or
> guarantees. Users assume all risks associated with its deployment and use.

## Installation

```toml
[dependencies]
affinidi-tdk = "0.8"
```

## Feature Flags

Every published capability crate is reachable through a facade feature. Group
features (e.g. `credentials`, `protocols`) enable a whole layer; the individual
features let you pull in just one crate. The `*` re-export column is the module
name the crate is re-exported as (e.g. `affinidi_tdk::vc`).

| Feature | Default | Enables | Re-export | Description |
|---|---|---|---|---|
| `messaging` | Yes | `affinidi-messaging-sdk` | `messaging` | Affinidi Messaging SDK |
| `meeting-place` | Yes | `affinidi-meeting-place` | `meeting_place` | Affinidi Meeting Place SDK |
| `did-peer` | Yes | — (code-gate) | — | did:peer helpers in `dids` |
| `data-integrity` | Yes | `affinidi-data-integrity` | `data_integrity` | W3C Data Integrity proofs |
| **`credentials`** | No | group ↓ | — | All credential formats + status + proofs |
| `vc` | No | `affinidi-vc` | `vc` | W3C Verifiable Credentials |
| `sd-jwt` | No | `affinidi-sd-jwt` | `sd_jwt` | SD-JWT |
| `sd-jwt-vc` | No | `affinidi-sd-jwt-vc` | `sd_jwt_vc` | SD-JWT VC |
| `mdoc` | No | `affinidi-mdoc` | `mdoc` | ISO mdoc / mDL |
| `status-list` | No | `affinidi-status-list` | `status_list` | Bitstring status lists |
| **`protocols`** | No | group ↓ | — | OID4VC protocol family |
| `oid4vc-core` | No | `affinidi-oid4vc-core` | `oid4vc_core` | OID4VC core |
| `siopv2` | No | `affinidi-siopv2` | `siopv2` | SIOPv2 |
| `openid4vci` | No | `affinidi-openid4vci` | `openid4vci` | OpenID4VCI |
| `openid4vp` | No | `affinidi-openid4vp` | `openid4vp` | OpenID4VP |
| **`did-methods`** | No | group ↓ | — | Standalone DID method crates |
| `did-web` | No | `affinidi-did-web` | `did_web` | did:web |
| `did-ebsi` | No | `did-ebsi` | `did_ebsi` | did:ebsi |
| `did-scid` | No | `did-scid` | `did_scid` | did:scid |
| `trust` | No | `affinidi-trust-lists` | `trust_lists` | Trust lists |
| `tsp` | No | `affinidi-tsp` | `tsp` | Trust Spanning Protocol |

> **Use the facade _or_ direct sub-crate deps, not both.** Mixing
> `affinidi-tdk` with a direct dependency on a crate it re-exports can resolve
> two copies of that crate. Foundation crates (`affinidi-crypto`,
> `affinidi-tdk-common`) are pinned at `major.minor` (caret), so any compatible
> patch resolves to a single version within the facade's tree.

Disable defaults with `default-features = false` in your `Cargo.toml` or
`--no-default-features` on the command line, then enable only what you need:

```toml
[dependencies]
affinidi-tdk = { version = "0.8", default-features = false, features = ["credentials", "protocols"] }
```

## Re-exported Crates

This crate re-exports the following libraries:

- [`affinidi-did-resolver-cache-sdk`](../../../affinidi-did-resolver/affinidi-did-resolver-cache-sdk/) — DID resolution and caching
- [`affinidi-did-common`](../../../affinidi-did-resolver/affinidi-did-common/) — DID Document types
- [`affinidi-messaging-didcomm`](../../../affinidi-messaging/affinidi-messaging-didcomm/) — DIDComm protocol
- [`affinidi-messaging-sdk`](../../../affinidi-messaging/affinidi-messaging-sdk/) — Messaging SDK *(feature: `messaging`)*
- [`affinidi-meeting-place`](../../../affinidi-meeting-place/) — Meeting Place SDK *(feature: `meeting-place`)*
- [`affinidi-data-integrity`](../common/affinidi-data-integrity/) — Data Integrity proofs *(feature: `data-integrity`)*
- [`affinidi-did-authentication`](../common/affinidi-did-authentication/) — DID authentication
- [`affinidi-tdk-common`](../common/affinidi-tdk-common/) — Shared utilities
- [`affinidi-secrets-resolver`](../common/affinidi-secrets-resolver/) — Secret management
- [`affinidi-crypto`](../common/affinidi-crypto/) — Cryptographic primitives

## Examples

Runnable examples live in [`examples/`](examples/) and import **only** through
`affinidi_tdk::*` — they are the canonical onboarding pattern (never depend on a
sub-crate directly):

- `did_auth` — authenticate a DID against a service endpoint.
- `resolve_did` — resolve a DID and print its document.

```sh
cargo run -p affinidi-tdk --example resolve_did -- did:key:z6Mk…
```

## Contributing: new capability crate ⇒ new facade feature

When a new published capability crate is added to the workspace, it **must** be
made reachable through this facade in the same change:

1. Add it as an `optional = true` dependency (path + `major.minor` version).
2. Add a `dep:`-gated feature for it (and fold it into the relevant group
   feature — `credentials` / `protocols` / `did-methods`).
3. Re-export it under a `#[cfg(feature = "…")]` in `src/lib.rs`.
4. Add a row to the Feature Flags table above.
5. Extend the facade feature-matrix CI job.

## Related Crates

- [`affinidi-messaging`](../../../affinidi-messaging/) — Full messaging framework
- [`affinidi-did-resolver`](../../../affinidi-did-resolver/) — DID resolution

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

# did-scid

[![Crates.io](https://img.shields.io/crates/v/did-scid.svg)](https://crates.io/crates/did-scid)
[![Documentation](https://docs.rs/did-scid/badge.svg)](https://docs.rs/did-scid)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/identity/did-methods/did-scid)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

Rust implementation of the `did:scid` (Self-Certifying Identifier) DID method.

A Self-Certifying Identifier (SCID) is a subclass of verifiable identifier that
is cryptographically verifiable without relying on any third party, because the
identifier is cryptographically bound to the keys from which it was generated.

## Installation

```toml
[dependencies]
did-scid = "0.4"
```

## Feature Flags

| Feature | Default | Description |
|---|---|---|
| `did-webs` | No | KERI AIDs via did:webs (`did:scid:ke:1`) |
| `did-webvh` | Yes | Inert since 0.4.9: did:webvh support is always built |
| `did-cheqd` | No | Inert: did:cheqd resolution was retired in 0.2.6 |

## Capabilities

- `did:scid:vh:1` — Verifiable History via did:webvh
- `did:scid:ke:1` — a KERI AID via did:webs (requires the `did-webs` feature)
- Peer-level `did:scid` implementations (the source supplied out of band)

Both formats resolve to the DID's own document: its `id` is the bare
`did:scid:<format>:1:<scid>` DID, and `alsoKnownAs` lists the source's
location as a did:scid DID URL and the source DID (`did:webvh:…` or
`did:webs:…`). `resolve_with_options` applies its timeout and host policy to
both formats.

> ⚠️ The did:scid method type registry (Appendix A of the specification) is
> still marked TODO, and `ke` is listed there as a **proposed** entry rather
> than a registered one. It is implemented because did:webs is named explicitly
> as a supported verification metadata format, but the code could change before
> the registry is settled.

### The SCID sits in a different place per format

`did:webvh` puts the SCID **first**; `did:webs` puts the AID **last**, because
the AID is the final path element of the URL its artifacts are served from:

```text
did:scid:vh:1:<scid>?src=example.com/dids  ->  did:webvh:<scid>:example.com:dids
did:scid:ke:1:<aid>?src=example.com/dids   ->  did:webs:example.com:dids:<aid>
```

## Specification

[DID SCID Method Specification](https://lf-toip.atlassian.net/wiki/spaces/HOME/pages/88572360/DID+SCID+Method+Specification)

## Related Crates

- [`affinidi-did-common`](../../affinidi-did-common/) — DID Document types (dependency)
- [`affinidi-did-resolver-cache-sdk`](../../affinidi-did-resolver-cache-sdk/) — Resolver SDK (uses this via feature flag)

## Contributing

Head over to our
[CONTRIBUTING](https://github.com/affinidi/affinidi-tdk-rs/blob/main/CONTRIBUTING.md)
guidelines.

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

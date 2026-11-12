# affinidi-rdf-encoding

[![Crates.io](https://img.shields.io/crates/v/affinidi-rdf-encoding.svg)](https://crates.io/crates/affinidi-rdf-encoding)
[![Documentation](https://docs.rs/affinidi-rdf-encoding/badge.svg)](https://docs.rs/affinidi-rdf-encoding)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-tdk/common/affinidi-rdf-encoding)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

RDF Dataset Canonicalization
([RDFC-1.0](https://www.w3.org/TR/rdf-canon/)) and JSON-LD expansion for W3C
Verifiable Credentials. A minimal-dependency implementation.

## Features

- **RDF data model** — `NamedNode`, `BlankNode`, `Literal`, `Quad`, `Dataset`
- **N-Quads parser/serializer** — W3C spec-compliant with proper escaping
- **RDFC-1.0 canonicalization** — Full W3C RDF Dataset Canonicalization algorithm
  (passes all 63 cases of the official `w3c/rdf-canon` `rdfc10` test suite)
- **JSON-LD expansion + to-RDF** — Focused on VC/DID contexts with bundled W3C context documents

## Installation

```toml
[dependencies]
affinidi-rdf-encoding = "0.1"
```

## Usage

```rust
use affinidi_rdf_encoding::{jsonld, rdfc1};

// JSON-LD -> RDF -> Canonical N-Quads
let document: serde_json::Value = serde_json::from_str(r#"{ ... }"#)?;
let dataset = jsonld::expand_and_to_rdf(&document)?;
let canonical_nquads = rdfc1::canonicalize(&dataset)?;

// Or use the convenience function for the full pipeline + SHA-256 hash:
let hash = affinidi_rdf_encoding::expand_canonicalize_and_hash(&document)?;
```

## Safe mode and the supported JSON-LD subset

`jsonld::expand_and_to_rdf_safe` is the expansion to use for anything that is
signed or verified. It returns an error rather than dropping content or
producing a dataset that differs from a conforming JSON-LD 1.1 processor. It
supports the subset Verifiable Credentials use:

- keys that are terms, compact IRIs or absolute IRIs, plus `@context`, `@id`,
  `@type` and their `id` / `type` aliases;
- `@id` values that are absolute IRIs or blank node identifiers;
- value objects with `@value` and at most one of `@type` or `@language`;
- term definitions with `@id`, `@type`, `@context`, `@protected` and an
  `@container` of `@set`; contexts with `@vocab`, `@version` and `@protected`;
- type-scoped contexts (not carried into nested nodes) and property-scoped
  contexts; protected terms are enforced.

Anything else, including `@graph`, `@list`, `@reverse`, `@included`, `@nest`,
`@index`, `@graph` and `@list` containers, map containers, `@base` and a
default `@language`, is refused. The lenient `expand_and_to_rdf` keeps its
historical behaviour of ignoring what it does not support.

## Canonicalization limits

RDFC-1.0 needs factorial work on graphs with many blank nodes that cannot be
told apart. Canonicalization fails once the Hash N-Degree Quads work for the
whole dataset passes a limit (100,000 steps by default, far above what the
W3C test suite needs). `rdfc1::canonicalize_with_options` takes a
`CanonicalizeOptions` to change it.

## Bundled Contexts

The following W3C JSON-LD contexts are embedded (no network requests needed):

- `https://www.w3.org/ns/credentials/v2`
- `https://www.w3.org/ns/credentials/examples/v2`
- `https://w3id.org/security/data-integrity/v2`
- `https://www.w3.org/2018/credentials/v1`
- `https://w3id.org/vdl/v1`
- `https://w3id.org/vdl/aamva/v1`

## Related Crates

- [`affinidi-data-integrity`](../affinidi-data-integrity/) — W3C Data Integrity proofs (uses this crate)

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

# affinidi-rdf-encoding

[![Crates.io](https://img.shields.io/crates/v/affinidi-rdf-encoding.svg)](https://crates.io/crates/affinidi-rdf-encoding)
[![Documentation](https://docs.rs/affinidi-rdf-encoding/badge.svg)](https://docs.rs/affinidi-rdf-encoding)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-tdk/common/affinidi-rdf-encoding)
RDF Dataset Canonicalization (RDFC-1.0) and JSON-LD expansion for W3C Verifiable Credentials.

A minimal-dependency implementation providing:

- **RDF data model** — `NamedNode`, `BlankNode`, `Literal`, `Quad`, `Dataset`
- **N-Quads parser/serializer** — W3C spec-compliant with proper escaping
- **RDFC-1.0 canonicalization** — Full W3C RDF Dataset Canonicalization algorithm
- **JSON-LD expansion + to-RDF** — Focused on VC/DID contexts with bundled W3C context documents

## Usage

```rust
use affinidi_rdf_encoding::{jsonld, rdfc1};

// JSON-LD → RDF → Canonical N-Quads
let document: serde_json::Value = serde_json::from_str(r#"{ ... }"#)?;
let dataset = jsonld::expand_and_to_rdf(&document)?;
let canonical_nquads = rdfc1::canonicalize(&dataset)?;

// Or use the convenience function for the full pipeline + SHA-256 hash:
let hash = affinidi_rdf_encoding::expand_canonicalize_and_hash(&document)?;
```

## Bundled Contexts

The following W3C JSON-LD contexts are embedded (no network requests needed):

- `https://www.w3.org/ns/credentials/v2`
- `https://www.w3.org/ns/credentials/examples/v2`
- `https://w3id.org/security/data-integrity/v2`

## License

Apache-2.0

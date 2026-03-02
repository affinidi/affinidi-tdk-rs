# Affinidi RDF Encoding Changelog

## 2nd March 2026 Release 0.1.1

- **PERFORMANCE:** ~40% faster RDFC canonicalization pipeline
  - Lookup-table hex encoding instead of per-byte `format!()` allocations
  - Inline blank-node substitution during serialization, avoiding intermediate
    `Quad` clones in first-degree hashing
  - O(1) reverse index for blank-node hash lookups, replacing O(n) linear scans
  - `Rc`-wrapped JSON-LD `Context.terms` to avoid deep-cloning the term map on
    every object expansion
  - Return borrowed `&str` from `quad_blank_node_ids` instead of cloned `String`s

## 2nd March 2026 Release 0.1.0

- **FEATURE:** Added new `affinidi-rdf-encoding` crate to the workspace
  - Provides RDF Dataset Canonicalization (RDFC-1.0) and JSON-LD expansion
  - Enables future support for `eddsa-rdfc-2022` cryptosuite
  - Minimal-dependency implementation with bundled W3C context documents
  - Includes N-Quads parser/serializer, RDFC-1.0 canonicalization, and JSON-LD
    to-RDF conversion

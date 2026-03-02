# Affinidi RDF Encoding Changelog

## 2nd March 2026 Release 0.1.0

- **FEATURE:** Added new `affinidi-rdf-encoding` crate to the workspace
  - Provides RDF Dataset Canonicalization (RDFC-1.0) and JSON-LD expansion
  - Enables future support for `eddsa-rdfc-2022` cryptosuite
  - Minimal-dependency implementation with bundled W3C context documents
  - Includes N-Quads parser/serializer, RDFC-1.0 canonicalization, and JSON-LD
    to-RDF conversion

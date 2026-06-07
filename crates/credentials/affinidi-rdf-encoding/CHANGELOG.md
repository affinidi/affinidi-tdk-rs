# Affinidi RDF Encoding Changelog

## 7th June 2026 Release 0.1.3

JSON-LD 1.1 expansion conformance for the W3C VC Data Model 1.0
(`credentials/v1`) credential family (needed by the vc-di-bbs pseudonym AAMVA
driver's-license test credential).

### Added

- Bundled contexts: `https://www.w3.org/2018/credentials/v1`,
  `https://w3id.org/vdl/v1`, `https://w3id.org/vdl/aamva/v1`.

### Fixed

- **Type-scoped contexts**: term definitions with compact-IRI `@id`s
  (`"issuer": {"@id": "cred:issuer"}`) now resolve against a prefix defined in
  the same context (two-pass term processing) — so `credentials/v1`'s
  `issuer`/`credentialSubject`/`expirationDate` (defined under the
  `VerifiableCredential` type scope) expand correctly.
- **`@json` literals**: kept verbatim and serialized with the JSON
  Canonicalization Scheme (sorted keys, no whitespace) typed `rdf:JSON`.
- **Numeric type coercion**: numbers honour their term's `@type` (e.g.
  `xsd:unsignedInt`) instead of always defaulting to `xsd:integer`.

## 6th June 2026 Release 0.1.2

W3C-conformance fixes for RDFC-1.0 and JSON-LD, locked with the official
`w3c/rdf-canon` test suite (59/63 cases; the 4 skipped are documented
poison/automorphism graphs) and the vc-di-bbs canonicalization vector.

### Fixed

- **JSON-LD number conversion** (root cause): integral doubles (`7.0`) now map
  to `xsd:integer`; non-integers use the canonical `xsd:double` lexical form
  (`5.5` → `"5.5E0"`). This was a latent bug affecting every rdfc-based suite
  on credentials containing numbers.
- **RDFC-1.0 N-degree** no longer recurses forever on cyclic blank-node graphs
  (issue the temporary id before recursing).
- `hash_related` appends the first-degree hash raw (the spurious `_:` prefix had
  flipped the canonical ordering of symmetric blank nodes).
- RDF dataset deduplication (set semantics); N-Quads `\b`/`\f`/DEL escaping;
  N-Quads IRI multi-byte advance + UCHAR (`\uXXXX`) unescaping.

### Added

- `rdfc1::canonicalize_with_label_map` and `IdentifierIssuer::issued_map()` —
  expose the input→`c14n` label map needed by selective-disclosure schemes.

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

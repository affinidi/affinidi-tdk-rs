# Affinidi RDF Encoding Changelog

## 0.1.8 — safe mode refuses what it cannot convert; RDFC-1.0 work limit per canonicalization; fresh blank node labels

**Safe-mode expansion** (`expand_document_safe`, `expand_and_to_rdf_safe`)
used to skip several inputs without an error, so the JSON and the RDF dataset
built from it could differ. It now refuses:

- keywords used as keys, and terms aliased to keywords, other than `@context`,
  `@id` and `@type` (`@graph`, `@list`, `@set`, `@reverse`, `@included`,
  `@nest`, `@index`, …). These were skipped with everything under them;
- an `@id` that is not a string, a relative IRI, a compact IRI, or `_:` with
  no label; a relative IRI under `@type: @id` coercion;
- a nested object that expands to nothing (for example `{}`), which dropped
  the statement linking it to its parent;
- value objects with members other than `@value`, `@type` and `@language`,
  with both `@type` and `@language`, with a non-string `@type` or
  `@language`, or with a `@value` that is not a string, number or boolean
  (other than under `@json`);
- terms with an `@list` or `@graph` container, which were expanded as plain
  values. The VC v2 `verifiableCredential` term is a `@graph` container, so a
  presentation that embeds credentials is refused in safe mode;
- context features expansion does not implement: `@base`, `@language`,
  `@direction`, `@import`, `@propagate`, map containers (`@language`,
  `@index`, `@id`, `@type`), and `@reverse`, `@nest`, `@index`, `@prefix` in
  term definitions;
- a redefinition of a protected term, or a `null` context over protected
  terms, except in a property-scoped context, as JSON-LD 1.1 requires.

Safe mode also now follows JSON-LD 1.1 for type-scoped contexts: they apply to
the node that carries the type, not to nodes nested inside it, and node types
are expanded with the context from before the type-scoped contexts. Type-scoped
contexts are applied in lexicographic order of the types, and a datatype
coercion applies to booleans as it does to numbers and strings. The README
lists the supported subset. Lenient expansion is unchanged.

**RDFC-1.0.** The Hash N-Degree Quads limit was a count of permutations kept
per call, so nested calls each had their own allowance and the total was
unbounded. The limit now covers the whole canonicalization: every call and
every permutation examined counts against one budget, 100,000 steps by
default. The W3C `rdfc10` suite needs about 3,000. `CanonicalizeOptions` and
`rdfc1::canonicalize_with_options` set a different limit. The public
`hash_ndegree::hash_ndegree_quads` keeps its signature and applies the
default limit to its own call.

**Blank node labels.** `to_rdf` used `_:x` labels from the document as they
were and named nodes without an `@id` `b0`, `b1`, …, so a document node
labelled `_:b0` and an anonymous node became one node. Both now come from one
issuer: every document label is relabelled to a fresh `bN`, and a label used
twice in the document still refers to one node.

Behaviour change (R3.6):

- Safe mode refuses the inputs above, which it used to accept. Documents that
  use only bundled VC contexts and VC terms are unaffected; the W3C
  vc-di-eddsa B.1 and vc-di-bbs vectors now also run through safe mode and
  give the same canonical N-Quads.
- In safe mode, a nested node that used a term defined only by the type of an
  enclosing node now expands as a conforming processor expands it (to
  `@vocab`, or an error if there is none). Its canonical form, and so any
  signature over it, changes.
- A dataset whose canonicalization needs more than 100,000 Hash N-Degree
  Quads steps returns `RdfError::CanonicalizationError`.
- A document that uses an explicit `_:` label that collides with a generated
  one now gives two nodes instead of one, so its canonical form changes.
  Other documents canonicalize as before; the labels in the non-canonical
  `to_rdf` output change.

API: `rdfc1::CanonicalizeOptions`, `rdfc1::canonicalize_with_options` and
`rdfc1::hash_ndegree::DEFAULT_MAX_NDEGREE_WORK` are added. Nothing is
removed or changed in signature. No new dependencies.

## Unreleased (0.1.7) — `sha2` 0.11

No behaviour change and no public API change: these are private dependencies
here, which is what lets each crate move on its own schedule. Verified by
`cargo tree`/grep that no RustCrypto type appears in a public signature anywhere
in the workspace.

Version bump only; no source change. 63 tests green.

## 14th June 2026 Release 0.1.6

- `RdfError` is now `#[non_exhaustive]` (ADR-0003) so new variants land
  additively. Patch bump keeps the `0.1` pin valid; consumers that `match` it
  must add a `_` wildcard arm. No behaviour change. (W7 sweep)

## 8th June 2026 Release 0.1.5

### Added

- **JSON-LD safe-mode expansion** — `expand_document_safe` and
  `expand_and_to_rdf_safe`. These behave like the existing lenient functions
  except that anything lenient expansion would silently drop now raises an error
  naming the offending input. Safe mode covers all three drop sites:
  - a **property key** not defined by the active `@context`;
  - a node **`@type`** that does not resolve to an absolute IRI (no term
    definition and no `@vocab`) — rejected rather than passed through as a
    relative IRI; non-string `@type` entries are likewise rejected;
  - a free-standing **scalar** where a node is expected (document root or a
    node array).

  Required by the W3C Verifiable Credential Data Integrity algorithms so that
  canonicalization cannot discard unmapped data. The default `expand_document` /
  `expand_and_to_rdf` behaviour is **unchanged** (still lenient), so this
  release is backward-compatible. Supports the soundness fix in
  `affinidi-data-integrity` 0.7.5 (issue #381).

## 7th June 2026 Release 0.1.4

Full **63/63** W3C `rdf-canon` (RDFC-1.0) conformance — the last 4 skipped
cases now pass byte-for-byte, so the suite has no quarantined cases.

### Fixed

- **RDFC-1.0 Hash N-Degree Quads — missing `_:` path delimiter** (root cause):
  steps 5.4.4.1, 5.4.4.2.2, and 5.4.5.2 require each identifier to be appended
  to the hash path in blank-node form (`_:` prefix). The `_:` is not cosmetic —
  it delimits consecutive identifiers, so the lexicographic "smallest path"
  tie-break matches the reference. Omitting it ran ids together
  (`c14n1`+`c14n2` → `c14n1c14n2`) and selected a *valid-but-non-canonical*
  labeling on highly-symmetric graphs. This unblocks the previously skipped
  `test044`–`046` ("poison – evil" automorphism graphs) and `test054`
  (deep `t-graph`). Real Verifiable Credentials were unaffected (their graphs
  are not symmetric), and all vc-di-bbs / data-integrity KAT vectors are
  unchanged.

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

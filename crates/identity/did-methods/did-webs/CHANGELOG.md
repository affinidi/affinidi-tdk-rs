# did:webs

All notable changes to this crate are documented here.

## [0.2.0] - 2026-08-23

### Added

- **Designated aliases** — `alsoKnownAs` is now derived from a verified
  attestation rather than omitted. A DID document does not get to assert its own
  aliases: the AID must have issued a credential saying so, in a registry it
  incepted, with both the registry inception and the issuance anchored in its own
  key event log, the attestation signed by its key state, and no revocation. A
  break anywhere in that chain yields no aliases rather than a partially-trusted
  list.
- `designated_aliases` and `DesignatedAliases`, which reports *why* an
  attestation was not used. An attestation that fails to verify does not fail the
  resolution — the key material is still sound, and refusing to resolve would
  make a broken attestation a denial of service on the identifier.
- `Kels::anchors_seal`, `Kels::message_by_said` and the ilk iterators.

### Changed

- **Breaking:** `document_from_keys` takes the verified aliases as a third
  argument.
- Requires `affinidi-keri-core` 0.3.2, which fixes a parser defect this work
  uncovered: a message could take its declared length from a *different*
  message in the stream, so an ACDC followed by any later key event mis-parsed.
  A revocation event after a credential is exactly that shape.

## [0.1.0] - 2026-08-23

Initial release.

- `DidWebs` identifier parsing and artifact URL derivation. The AID is always
  the last path element, so unlike `did:web` a pathless `did:webs` never
  resolves to `/.well-known/`. `%3A` is decoded in either case, because
  published artifacts write the port separator lowercase while the
  specification writes it uppercase.
- `Kels`: verification of the key event logs in a `keri.cesr` stream, including
  delegation — a delegated event is accepted only if the delegator's own
  verified KEL anchors a seal naming it. Chains are bounded and cycle-checked.
- Document generation from verified key state, with `JsonWebKey` verification
  methods keyed by the CESR key.
- `resolve_from_artifacts` for offline verification, and `WebsResolver` /
  `resolve` for fetching over HTTPS with a size cap on each artifact.
- Conformance tests against the published artifacts for
  `did:webs:did-webs-service%3a7676:ENro7uf0…`, reproduced from
  `hyperledger-labs/did-webs-resolver`.

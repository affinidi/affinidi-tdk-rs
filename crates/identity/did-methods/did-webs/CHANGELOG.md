# did:webs

All notable changes to this crate are documented here.

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

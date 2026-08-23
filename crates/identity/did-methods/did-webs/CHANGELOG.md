# did:webs

All notable changes to this crate are documented here.

## [0.5.0] - 2026-08-23

### Added

- **Plain HTTP for loopback hosts**, and `WebsResolver::allow_http` to permit it
  anywhere. Artifacts are still fetched over HTTPS by default.

  The reference implementation fetches over plain HTTP — `resolving.py` builds
  `http://{domain}{port}{path}/{aid}` with no HTTPS path at all — so a
  strict-HTTPS resolver cannot read the artifacts the ecosystem's own tooling
  serves. Loopback is safe by construction; anything else is opt-in and
  documented as such, because a plain-HTTP fetch lets an attacker serve a
  *stale* key event log and hide a rotation that has already happened.

- `DidWebs::is_loopback` and `DidWebs::artifact_url_with_scheme`.

- **Network tests.** `WebsResolver::resolve` was previously never executed: the
  conformance tests verify artifacts already in hand, and the one HTTP test
  fetched with `reqwest` directly and verified offline. `fetch.rs` had no tests
  at all. Seven tests now drive the real entry point against a live server —
  the URLs requested, a missing `did.json` (not fatal), a missing `keri.cesr`
  (fatal), a 5xx, the size cap, a `did.json` that disagrees, and that the
  loopback accommodation does not leak into ordinary hosts.

## [0.4.0] - 2026-08-23

### Added

- **Service endpoints**, derived from signed KERI endpoint authorisations.
  A `did:webs` document does not get to list whatever endpoints it likes, any
  more than it gets to assert its own aliases. An endpoint is published only
  when two signed `rpy` messages agree: `/end/role/add` from this AID
  authorising an identifier in a role, and `/loc/scheme` from **that**
  identifier saying where it is reachable.

  Both halves are required. The first without the second is an authorisation
  pointing nowhere; the second without the first is a stranger volunteering to
  act on someone's behalf. `/end/role/cut` withdraws an authorisation, and
  where the same subject is addressed more than once the latest `dt` wins — so
  a stale `cut` replayed after an `add` does not take effect.

  Signatures are checked both ways KERI identifiers come: a transferable
  identifier signs with an indexed signature group verified against the key
  state its own KEL establishes, while a non-transferable one — a witness,
  typically — has its public key as its prefix, so a receipt couple is checked
  directly.

  Roles are not enumerated. KERI does not fix the set, and rejecting an unknown
  role would drop endpoints we simply have not heard of.

### Changed

- **Breaking:** `document_from_keys` takes the derived services as a fourth
  argument.

## [0.3.0] - 2026-08-23

### Security

- **Witness receipts are now required when a key event log declares them.** An
  event naming backers and a threshold was accepted on controller signatures
  alone, which discards exactly what witnessing exists to provide: a controller
  that later equivocates cannot be caught if nobody had to witness the original.
  `affinidi-keri-core` has verified receipts all along and direct mode used it —
  this resolver simply never called it.

  Receipts are collected both from the event's own attachments and from separate
  `rct` messages naming it, since witnesses commonly receipt out of band. A KEL
  with `bt: 0`, which is the common `did:webs` case, is unaffected.

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

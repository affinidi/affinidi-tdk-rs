# did:webs

All notable changes to this crate are documented here.

## [0.8.2] - 2026-11-09

### Security

- **Resolution refuses hosts that are not public.** A `did:webs` DID names
  the host its `keri.cesr` and `did.json` are fetched from, so a DID anyone
  supplies could aim the resolver at loopback, a private network or the cloud
  metadata address (SSRF). `WebsResolver` checked no host and followed
  redirects. It now takes a `HostPolicy`, default `PublicOnly`, enforced as
  `affinidi-did-web` enforces it, through `affinidi-net-guard`: the host the
  DID names is checked before any request, a hostname is checked against what
  it resolves to at connect time, and the client it builds follows no
  redirect or proxy (not even one named by `HTTPS_PROXY`, since a proxy
  resolves the hostname itself and the DNS check would never see it). A
  refusal is `DidWebsError::BlockedHost`.
- **A caller's client can no longer carry less than the guard.**
  `WebsResolver::with_client_builder` takes a `reqwest::ClientBuilder` and
  applies the guard settings after the caller's, so a caller's redirect,
  proxy or resolver setting cannot undo them. `WebsResolver::with_client`,
  which takes a built client that cannot be inspected, is deprecated: under
  it only the host the DID names is checked.
- **Building the client fails closed.** A client that could not be built fell
  back to `reqwest`'s default, which has none of the guard. It now panics, as
  `reqwest::Client::new` does, and `with_client_builder` returns the error.
- **`HostPolicy::AllowPrivate` is logged.** Building a resolver under it
  emits a warning, so a deployment running without SSRF protection says so.

### Changed

- **A loopback DID resolves only under `HostPolicy::AllowPrivate`.**
  `WebsResolver::new()` fetched a loopback host over plain HTTP. It now
  refuses it; `WebsResolver::with_policy(HostPolicy::AllowPrivate)` restores
  that, for a local stack or the reference implementation.

### Added

- `HostPolicy`, `WebsResolver::with_policy`,
  `WebsResolver::with_client_builder`, `DidWebsError::BlockedHost`.

### Deprecated

- `WebsResolver::with_client`: use `WebsResolver::with_client_builder`.

## [0.8.1] - 2026-11-08

### Added

- **Key agreement and services of any type, by designation.** Two ACDC schemas
  of this crate's (`schemas/`), issued by the AID to itself and anchored in its
  KEL, verified like designated aliases: a key agreement designation (X25519,
  P-256 or secp256k1 keys, published as `JsonWebKey` methods in
  `keyAgreement`) and a service designation (DID document service entries such
  as `DIDCommMessaging` or `TSPTransport`). `CreateConfig::key_agreement`,
  `CreateConfig::designated_service`, `Change::KeyAgreement` and
  `Change::DesignatedServices` designate and replace them without rotating the
  identifier. A key of the current key state is refused as a key agreement key,
  and a designated service cannot take an id KERI's own endpoint data uses.

## [0.8.0] - 2026-11-08

Brought into line with the `did:webs` specification (KSWG, August 2026), and
checked against the reference implementation's artifacts.

### Security

- **Signatures are held to the signing threshold.** A reply or
  designated-aliases attestation was accepted on one valid signature whatever
  the key state's threshold, so one key of a multi-key identifier could
  redirect its services or designate aliases. Signature groups are now counted
  against the threshold of the key state at the establishment event they name,
  and a group naming an interaction event is refused. Creation signs with every
  current key.
- **Replies are ordered as BADA orders them.** Supersedence compared `dt`
  strings alone, so a rotated-out key could sign a reply dated far in the
  future and win every later comparison. Replies are now ordered by the
  establishment event that signed them, then by `dt` parsed as RFC 3339; a reply
  whose `dt` is not a timestamp is ignored.
- **One key of a multi-key identifier no longer authenticates alone.** With
  `kt` > 1 or weighted, every key was listed in `authentication` and
  `assertionMethod`. Only the `ConditionalProof2022` method is now (§
  Thresholds); a weighted threshold with more than one clause, which one
  condition cannot express, fails resolution rather than being weakened.

### Changed (breaking)

- **A DID its AID has not designated does not resolve** (§ Read, step 4):
  `DidWebsError::NotDesignated`. `create` therefore always designates the DID,
  its `did:web` twin and `did:keri:<AID>`.
- **`alsoKnownAs` is only what was designated.** The `did:web` twin is no longer
  added unconditionally. Aliases are the union of every verified, unrevoked
  attestation, and a revocation counts once anchored in the KEL.
- **`Change::AlsoKnownAs` replaces the designation**, revoking the attestations
  in force. An empty list is accepted and leaves the three required entries.
- **`did.json` is the `did:web` form** (§ Transformation to `did:web` DID
  document), with relative verification method ids, a `controller`, no
  `@context`, and no `"d": null` in its JWKs. `alsoKnownAs` always includes
  `did:keri:<AID>` (§ Also Known As). It is compared with the
  derivation as a whole — methods, services, aliases, relationships — rather
  than by `id` and keys alone.
- **`WebsResolver` fails when `did.json` cannot be fetched** (§ Read).
- **`DidWebs::did()` is the DID without query or fragment**, and the `did:web`
  twin keeps the percent-encoding the DID was written with.
- `document::document_from_keys` is replaced by `document::derive_document`,
  which returns the specification's JSON form; `document::into_document` turns
  it into a `Document`.
- `CreateConfig` is `#[non_exhaustive]`: build it with `CreateConfig::builder`.
- `chrono` is a non-optional dependency (without its clock, which `create`
  enables).

### Added

- `resolve_with_metadata` and `WebsResolver::resolve_with_metadata`, returning
  `versionId`, `nextVersionId`, `equivalentId` and `deactivated`; the
  `versionId` DID parameter (`DidWebs::version_id`) resolves as of a key event.
- Witness services from the key state's witness list (§ Witness Service
  Endpoint); an `/end/role/add` in role `witness` no longer makes one.
- `DelegatorOOBI` services for delegated identifiers (§ Delegator Service
  Endpoint), as `delegator_service`.
- `Kels::verify_signature_group`, `Kels::sequence_numbers`, `Kels::as_of`,
  `Kels::is_deactivated`, `DidWebs::did_keri`.

## [0.7.0] - 2026-08-23

### Added

- **Designating `alsoKnownAs`.** `create` takes `also_known_as`, and `update`
  takes `Change::AlsoKnownAs`.

  An alias is not something a document may assert about itself, so this issues
  the credential the resolver already required: a registry (`vcp`), an issuance
  (`iss`), and the attestation itself — each anchored in the identifier's own key
  event log by an interaction event, and the credential signed under the key
  state at a named establishment event. The resolver verifies every link before
  carrying an alias back, so every link is built.

  The attribute and rules blocks carry their own SAIDs, computed before the
  credential's, because they are part of the bytes the outer SAID covers. The
  rules block is reproduced verbatim from the designated-aliases schema so the
  credential this issues is the one the rest of the ecosystem reads.

- **`also_known_as_scid`**, designating this identifier's own `did:scid:ke:1`
  form. It is a switch rather than an entry in `also_known_as` because the AID
  does not exist until the inception event does. ⚠️ The `ke` format code is
  *proposed* in the did:scid registry rather than registered.

  There is still no `also_known_as_web`: the `did:web` twin shares this
  identifier's location and document and the resolver adds it unconditionally, so
  the switch could only ever be on.

## [0.6.0] - 2026-08-23

### Added

- **Creating identifiers**, behind an optional `create` feature: `create` for
  inception, `update` for rotation, interaction and service designation. Both
  return artifact **bytes** plus a custody record and publish nothing.

  The prior state is passed in rather than held, mirroring `didwebvh-rs`'s
  `update_did` — and here that state is the published artifacts themselves,
  since the key event log *is* `keri.cesr`. No database is involved: creation
  uses `affinidi-keri` 0.4's store-free event constructors.

  What has to survive between events is split by sensitivity: the **salt**,
  from which every key is derived, belongs wherever the application keeps
  secrets and is never stored by this crate; the **custody record** is not
  secret and can sit with the artifacts. `update` refuses a custody record whose
  sequence number does not match the published log, because signing from a point
  the log has passed produces an event nothing accepts.

  `did.json` is generated by the same code path the resolver uses, so the two
  cannot disagree. Service endpoints are emitted as signed `rpy` messages rather
  than written into the document, so a resolver verifies them instead of taking
  the document's word for it.

  There are deliberately no `also_known_as_web` / `also_known_as_scid` switches:
  `didwebvh-rs` has them because webvh *writes* `alsoKnownAs` into its log, while
  `did:webs` derives it. The `did:web` twin is added unconditionally by the
  resolver so it cannot be turned off, and a `did:scid:ke` entry is not derivable
  from the log so it cannot be turned on. Offering either would mean publishing a
  document this crate's own resolver does not reproduce.

### Fixed

- **A key rotation silently withdrew everything the identifier had signed.**
  Service authorisations and designated-aliases attestations were verified
  against the identifier's *current* key state. Both are signed under the key
  state at the establishment event their signature group names — so after any
  rotation the signature stopped verifying and the service or alias quietly
  vanished from the resolved document, with no error.

  `Kels::key_state_at` replays the log to a named establishment event, and both
  checks now use it. Found by the creation round-trip test: a service designated
  before a rotation disappeared after it.

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

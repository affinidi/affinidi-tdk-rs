# did:webs

All notable changes to this crate are documented here.

## [0.13.3] - 2026-11-12

### Changed

- **A deactivated identifier no longer resolves to its last keys.** Its last
  rotation committed to no next keys (§ Deactivate), but every entry point that
  returns a document alone — `WebsResolver::resolve`, `resolve` and
  `resolve_from_artifacts` — returned the final key state's keys as current
  ones and dropped the metadata that said otherwise.
  - Deactivation is read from the whole stream: it is a property of the DID,
    not of a version. The document-only entry points fail with the new
    `DidWebsError::Deactivated` for a deactivated DID, with or without a
    `versionId`. `Resolution::into_document` does the same.
  - `resolve_with_metadata` (both forms) still resolves and reports
    `deactivated: true` for every version. The deactivating version's
    document keeps only `@context`, `id` and `alsoKnownAs`: no verification
    method, verification relationship, key role or service. An earlier
    `versionId` returns that version's document, keys included, for a caller
    checking a signature made while they were current.
  - `update` publishes the deactivating version's `did.json` without keys
    too, so a `did:web` reader of the twin does not take them for current
    ones. For that version a published `did.json` may be either that form or
    the full derivation published before, so existing artifacts still
    resolve.
  - `Kels::key_state`, `designated_key_agreement` and `designated_key_roles`
    say nothing of a deactivation; their documentation now says to check
    `Kels::is_deactivated`.
- **Less verification work per stream.** The key state at every establishment
  event is recorded while the log is verified, so a reply's signature group
  is checked against that record instead of a replay of the log from
  inception; each identifier's log over the whole stream, which the
  designation readers share, is replayed and built once and shared; witness
  receipts and SAIDs are indexed when the stream is parsed; an endpoint's
  location replies are read once per resolution, however many roles name it;
  and a `versionId` resolution narrows the stream already parsed instead of
  parsing it again. `Kels::key_state_at` returns the full key state as
  before; the recorded states share one witness list between consecutive
  establishment events that leave it unchanged, so a rotation that does not
  touch its witnesses costs a pointer, not a copy. Some work
  still grows with the product of two counts the bounds below limit:
  receipts against witness lists, and, in `affinidi-keri-core`'s registry
  reader, seals against messages.
- **Bounds on a stream.** `Kels::parse` refuses a stream of more than
  `kel::MAX_STREAM_MESSAGES` (10,000) messages, `kel::MAX_STREAM_SIGNATURES`
  (16,384) signatures (controller and witness signatures, receipt couples and
  signature groups), `kel::MAX_STREAM_BACKERS` (1,024) witness entries (`b`
  and `ba` of key events) or `kel::MAX_STREAM_SEALS` (16,384) seals (`a` of
  key events). They are checked once the stream is parsed, before anything is
  verified; `WebsResolver` caps the stream's size while reading it. Resolution
  fails when credentials marked `critical`, in registries whose inception the
  identifier's verified log anchors, name more than 16 schemas this resolver
  does not implement; credentials outside such a registry cannot stand and are
  not counted.
- **`WebsResolver` verifies off the async executor.** The fetched stream is
  verified on tokio's blocking thread pool, with no more verifications running
  at once across the process than there are CPUs available. A verification
  holds its place until it ends, even when its caller stops waiting. `tokio`
  (already in the dependency tree through `reqwest`) becomes a direct
  dependency with the `rt` and `sync` features.

### Compatibility

Behaviour change, no signature change (R3.6): a deactivated identifier that
resolved `Ok` through a document-only entry point now fails with
`DidWebsError::Deactivated` (the enum is `#[non_exhaustive]`), at every
version; `resolve_with_metadata` reports `deactivated` at every version and
returns the deactivating version without keys; `update` publishes that
version's `did.json` without keys. A stream past the bounds above fails with
`DidWebsError::Stream`.

## [0.13.2] - Unreleased

### Changed (behaviour, R3.6)

- **The host label must decode to a host.** `DidWebs::parse` percent-decodes
  the host label in full and refuses it unless it is a host (a hostname, or
  an IP literal, which this resolver also accepts: IPv4, or IPv6 in
  brackets) and an optional numeric port: a host
  label that decodes to user information (`@`), a path (`/`, `\`), a query
  (`?`), a fragment (`#`), a further `%`, whitespace or a control character
  is refused, as is a malformed escape or one that is not UTF-8. Before, the
  label was put into the artifact URL as written (only `%3A` decoded), so a
  label such as `a.example@b.example` was fetched from `b.example`.
- **Path labels must decode to one path segment.** A path label that is `.`
  or `..`, or that decodes to `/`, `\`, `?`, `#`, `@`, `%` or a control
  character, is refused. Path labels are still written into the URL as they
  appear in the DID.
- **Artifact size is enforced while reading.** `MAX_ARTIFACT_BYTES` was
  checked against `Content-Length` and then only after the whole body had
  been read, so a body without a `Content-Length` was read in full (until the
  request timeout) before being refused. The body is now counted chunk by
  chunk and reading stops as soon as it passes the cap. No API change.

### Fixed

- `DidWebs::is_loopback` recognises a bracketed IPv6 loopback host with a
  port (`[::1]:7676`); it split on the first `:` and never matched one. It
  now compares the host as the URL parser normalises it, so `LOCALHOST`,
  `0x7f.1` and `[0:0:0:0:0:0:0:1]` are recognised as well.
- `DidWebs::host()` returns the host label percent-decoded in full, not only
  its `%3A` port separator.
- Comparing DIDs with non-ASCII characters no longer garbles them while
  normalising percent-encoding case.
## [0.13.1] - 2026-11-11

### Changed

- **`create` no longer compiles LMDB.** It takes `affinidi-keri` 0.8.1 without
  its `store` feature: a `did:webs` controller keeps its key event log in
  `keri.cesr` and never used the LMDB store (`heed`), which every build with
  `create` compiled in, a VTA's among them.

## [0.13.0] - 2026-11-11

On affinidi-keri 0.8. Still alpha.

### Added

- **Native CESR bodies resolve (P8).** A `keri.cesr` from a keripy host with
  default settings, whose messages have native bodies, now resolves; before,
  it failed as unsupported.

### Changed

- **keripy's delegated rotations verify.** A `drt` names no delegator (no
  `di`); the delegator is the one the `dip` named. A delegated identifier
  that had rotated failed to resolve before.
- **`EO` and `DND` are enforced.** An establishment-only identifier's
  interaction events are refused, and a delegated identifier whose delegator
  has `DND` does not resolve, though the delegator anchors it. `Kels` answers
  the delegator's traits only from a KEL it has verified.

## [0.12.0] - 2026-11-10

On affinidi-keri 0.7 and affinidi-cesr 0.1.4. Still alpha.

### Added

- **Superseding recovery (P7).** A rotation after the last establishment event
  may supersede the interaction events there, as keripy accepts it, and takes
  what they anchored with it: a designation, a revocation or a delegation
  anchored only in a superseded event is not the identifier's. The resolver's
  `Kels` records which events a recovery superseded; they leave the issuer log
  the registry reader takes, and neither `anchors_seal` nor the delegator
  lookup answers from them.

### Changed

- **Rotations verify as keripy verifies them** (affinidi-keri 0.7): the prior
  next threshold is met by the committed positions the signatures expose, so a
  rotation that reorders, partly reveals or adds to its committed keys
  resolves; before, it failed. Big indexed signatures (`2A…`) parse.
- Signatures are written as before (`A`, both lists at the same position);
  affinidi-keri 0.7 renames that `sign_indexed(.., false)`.

## [0.11.0] - 2026-11-10

did:webs on KERI 2.0. This integration is **alpha**: expect breaking changes as
the did:webs and KERI 2.0 specifications settle. The positions taken are in
`docs/05-design-notes/did-webs-keri-v2.md` (OpenVTC/verifiable-trust-infrastructure).

### Changed

- **An identifier is written in the KERI version of its log, and so are its
  designations and replies.** `create_controlled` no longer forces KERI 1: an
  `Inception` is 2.0 unless it says otherwise, and the log, designations and
  endpoint replies follow it. A salted identifier (`create`) follows its
  `InceptionConfig`'s version (1.0 by default, as `affinidi-keri`'s `Hab`).
- **2.x designations** are ACDC 2.x credentials (`acm`) in `rip`/`bup`
  registries, one registry per designation, each update salted with a fresh
  random UUID and published with its disclosed state. Every designation has a
  v2 schema: designated aliases `EF9Iy-vw…`, key agreement `EIW1ONwn…`, service
  `EJVZ789s…`, key role `EBMCaUhH…` (which adds `critical` and
  `keyAssurance`). Replacing one revokes it with a further update in its own
  registry, continued from the published stream.
- **2.0 replies** name their sender in `i`, and are endorsed with a `-X` group
  whose sequence number is a 2.x `Number`.
- **Designations are read by `affinidi-keri-core`'s registry reader**, for both
  versions. **Every registry event the identifier's KEL anchors must be in
  `keri.cesr`**, and every registry event in it must be anchored; otherwise
  resolution fails (`DidWebsError::Registry`). Before, an unanchored event was
  skipped, and a stream that left out an anchored revocation read as issued.
- **Under `versionId`**, a designation anchored after the version asked for has
  not happened yet. Before, it was treated as rejected, which also withheld the
  key agreement key the key state converts to.
- Requires affinidi-keri 0.6.2.

### Added

- **Critical designations** (`unsupportedDesignation`): a standing designation
  marked `"critical": true` whose schema this resolver does not implement fails
  resolution (`DidWebsError::UnsupportedDesignation`). A 2.x key role
  designation must be marked critical, and is written so.
- `tests/fixtures/ours-v2`: an identifier's whole lifecycle on KERI 2.0, which
  keripy 2.1.0-dev1 accepts in full (`verify_ours.py`): KEL, endpoint replies,
  and every designation's SAIDs, framing, BLIDs and status.

### Fixed

- **Endorsements name their establishment event's own sequence number.** Replies
  and 1.x credentials were endorsed with the log's latest sequence number beside
  the establishment event's SAID. keripy looks the event up by the number, so
  once an identifier had an interaction event, keripy refused its replies. The
  resolver now refuses such a group too, as keripy does.

## [0.10.0] - 2026-11-10

### Changed

- **affinidi-keri 0.6** (`affinidi-keri`, `-core`, `-crypto`). This is breaking,
  because `create_controlled` takes `affinidi_keri::controller::Inception` and
  `KeySigner`, which are now 0.6's types. 0.6 reads KERI version 2 and is checked
  against keripy 2.x in both directions.
- **`create_controlled` writes its key event log in KERI version 1**, whatever
  version the `Inception` carries. affinidi-keri 0.6's controller defaults to
  v2, but this crate's designations are still v1 ACDCs in v1 registries, and a
  v2 log anchoring them is a combination no resolver is tested against yet.
  Version 2 designations, and a v2 log with them, come next.

### Fixed

- **Rotations now verify in keripy.** The rotations `update` and
  `complete_rotation` produced carried a `c` field, which a KERI v1 rotation
  doesn't have and keripy refuses. affinidi-keri 0.6 no longer writes it, and
  this crate's resolver now refuses it, as keripy does.
- **Thresholds of 10 or more are hex**, as KERI writes them (via
  affinidi-keri 0.6).

## [0.9.3] - 2026-11-09

### Added

- **Identifiers whose keys the caller holds.** `create` and `update` derive
  every key from a salt. A custodian whose keys live in an HSM, an enclave or a
  key service — and one sharing control with a recovery custodian — now has a
  path of its own, built on `affinidi_keri::controller` (affinidi-keri 0.5.1):
  - `CreateConfigBuilder::controlled(Inception)` and `create_controlled(config,
    signers)`: the current keys, the successors as digests or public keys, and
    the thresholds; `signers` are `KeySigner`s for the current keys.
  - `update_controlled(ControlledUpdate, signers)`: every `Change` but a
    rotation, signed by the current keys under their threshold.
  - `prepare_rotation` → `PendingEvent` → `complete_rotation`: a rotation's
    signatures can come from elsewhere, later — a recovery custodian's
    included — and are checked against its `kt` and the prior `nt`.
  - `ControlledResult` carries the artifacts and the non-secret
    `ControllerState` to continue from.

  With `n = [H(R′), H(K)]` and `nt = [["1/2", "1"]]` (the arrangement the VTI
  did:webs method profile states) the custodian's `K` is committed by digest
  alone, `R′` cannot rotate without it, and after rotating `R′` signs routine
  changes alone. The salt-based path is unchanged.

## [0.9.2] - 2026-11-09

### Added

- **Key agreement for identifiers that designate none.** An AID that has never
  issued a key agreement or key role designation, and is not deactivated, now
  resolves with the X25519 key converted from each Ed25519 key of its current
  key state in `keyAgreement` — the keys KERI practice, and the reference
  implementation's DIDComm support, encrypt to. Before, such an identifier
  (any keripy- or KERIA-made one) had no key agreement key, so nothing could
  encrypt to it over DIDComm or TSP. The keys are rendered after the published
  `did.json` is checked: a `did.json` without them agrees, as does one listing
  exactly them. They are never published by `create` or `update`, and an AID
  that has designated keys — even if since revoked — gets none.
- `key_agreement::converted_key_agreement`; `DesignatedKeys::issued`.

## [0.9.1] - 2026-11-09

### Added

- **Key role designations — a proposed extension to `did:webs`, as a proof of
  concept** (`key_roles`, [docs/key-role-designation.md](docs/key-role-designation.md)).
  An AID binds other keys to roles — `attestation` (`assertionMethod`),
  `operational` (`authentication`), `messaging` (`keyAgreement`) — by an ACDC
  it issues to itself and anchors in its KEL (schema
  `EPulJFl5SEb8qb3ca5teXHRGiWmTsTkylGTrS2vB4ZQx`). Once it has, its document
  lists the role keys, each in its role's relationship only, a top-level
  `keyRoles`, and no key of the key state: the KEL alone is the update
  authority. Keys revoked for compromise stay listed with `revoked`, in no
  relationship, for the life of the identifier; the resolver reads them from
  every designation ever issued, so a later one cannot drop a revocation.
  A designation that does not verify as a whole binds nothing, and the
  document never falls back to the key state's keys.
- `KeyRoles`, `KeyRole`, `VerificationKey`, `RevokedKey`,
  `designated_key_roles`, `document::derive_key_role_document`;
  `CreateConfigBuilder::key_roles`; `Change::KeyRoles` and
  `Change::RevokeRoleKey`.

Identifiers that issue no key role designation resolve exactly as before. A
resolver that does not implement the extension refuses the `did.json` of one
that does — the interoperability gap adopting it in the specification would
close.

## [0.9.0] - 2026-11-09

### Changed (breaking)

- **No more global `preserve_order`.** This crate turned on `serde_json`'s
  `preserve_order` feature, and cargo unifies features, so depending on it
  changed how every crate in the build serialized JSON: maps became
  insertion-ordered and every `Value` grew. KERI and ACDC field order is now
  kept by `affinidi_keri_core::SadValue`, whatever features `serde_json` was
  built with. Requires `affinidi-keri-core` 0.5.
- `Change::Interact` carries `affinidi_keri_core::SadValue` seals, not
  `serde_json::Value`: a seal's `i`, `s`, `d` order is part of the event its
  SAID covers. Build one with `affinidi_keri_core::sad!`.
- A designated service's entry is written `id`, `type`, `serviceEndpoint`,
  then its other members, in that order, whatever `serde_json` was built
  with. `DesignatedService::to_service` still returns a `serde_json::Value`.

### Fixed

- **A service entry is checked wherever it is designated.** The check that an
  entry is a service a DID document can carry ran in the one caller; it now
  runs when the entry is built for a designation, so no caller can skip it.

### Added

- A test that every message this crate builds — `icp`, `rot`, `ixn`, `rpy`,
  `vcp`, `iss`, `rev` and the ACDC, with its attributes and a designated
  service entry — is written in KERI and ACDC field order, so a reordered
  literal fails CI rather than shipping events keripy refuses.

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

- **Requires `affinidi-keri-core` 0.4.1**, which refuses a rotation that
  does not meet the signing threshold the previous event committed to. Under
  0.4.0, someone holding one of several pre-committed next keys could rotate
  the identifier alone.

### Fixed

- **A `did:webs` identifier can be deactivated.** Rotating to no next keys
  (`nt: "0"`, an empty `n`) was refused by `affinidi-keri-core` 0.4.0; under
  0.4.1 it resolves, with `deactivated: true` in the document metadata.

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

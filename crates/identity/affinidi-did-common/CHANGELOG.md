# Changelog

## [0.4.9] - 2026-11-15

Workspace lint and dependency housekeeping. No API or behaviour change.

- Dependency versions now come from the root `[workspace.dependencies]`
  for the external crates shared by five or more workspace members
  (#1070). The published manifest still names concrete requirements; the
  resolved dependency graph and every feature selection are unchanged.
- Workspace lints now include `unsafe_code = "deny"` (#1064).
- Minimum dependency requirements raised to versions already in use across the
  workspace (no new major/minor, Cargo.lock unchanged): `affinidi-crypto` 0.3
  -> 0.3.2, `url` 2 -> 2.5, `zeroize` 1 -> 1.8.

## [0.4.8] - 2026-11-15

did:peer:0 documents under the peer DID, SEC1 EC keys from JWKs, validated `DID`s, relative ids

Released as a patch, per ADR 0003 (`didwebvh-rs` and `trust-tasks-proof` pin
this crate at `0.4`). Several items change behaviour; see Compatibility.

- **Fixed (#1039):** a `did:peer:0…` DID resolves to a document whose `id`,
  verification method ids and controllers, and every verification
  relationship reference are the `did:peer:0…` DID. Before, the wrapped
  did:key's document came back unchanged, all `did:key:…`. Each method's
  fragment is still its multikey, as for did:key (`did:peer:0z6Mk…#z6Mk…`).
  A DID URL (`did:key:…#frag`, `did:peer:2…#key-1`) resolves to the document
  of its bare DID; before, the URL's fragment or path leaked into the
  document's `id` and, for did:peer:2, into its key ids.
- **Fixed (#1040):** `KeyMaterial::from_jwk` / `from_jwk_value`, and so
  deserializing a `KeyMaterial`, store an EC public key in the SEC1
  uncompressed form a generated key carries (`0x04 || x || y`, 65 bytes for
  P-256 and secp256k1, 97 for P-384), and refuse a JWK whose `x` or `y` is not
  the curve's coordinate length. Before, they stored `x || y` without the
  prefix, so `public_multibase()` failed with "Invalid public key length" and
  `public_bytes()` differed from the generated key's: a serialize/deserialize
  round trip of a generated EC key broke both.
- **Changed (#1044):** `DID::new` validates the `DIDMethod` it is given: the
  method name and identifier are parsed as a DID string's are, and a method
  whose other fields (a did:key's codec and key bytes, a did:web's domain,
  ...) disagree with its identifier is refused with
  `DIDError::InvalidMethodSpecificId`. Deserializing a `DID` runs the same
  validation and refuses fields that disagree with each other (including
  `url`). The serde form is unchanged: still the struct's fields, not the DID
  string.
- **Changed (#1044):** the keys of a `did:peer:2` DID must be public keys of
  their codec's length, as did:key and did:peer:0 keys already had to be
  (`decode_multikey_checked`). A did:peer:2 naming a private-key codec, or an
  EC key not in compressed form, no longer parses.
- **Added (#1044):** borrowing accessors on `DID`: `method_ref`,
  `method_specific_id_ref`, `path_ref`, `query_ref`, `fragment_ref` and
  `as_url`. The owned accessors stay, documented as allocating; did:key
  resolution uses the codec the `DID` already holds instead of decoding the
  identifier again.
- **Added (#1042):** `Document::from_json`, `from_json_with_base` and
  `from_json_slice` parse a DID document whose verification method and
  service ids, controllers or relationship references are relative DID URLs
  (`"#key-1"`), resolving them against the document's `id` (or a given base).
  `document::absolutize_reference` and `document::absolutize_references` do
  the rewriting, and `document::VERIFICATION_RELATIONSHIPS` names the
  relationships. Deserializing into `Document` directly is unchanged.
- **Added (#1043):** `NetworkError` (`network` module): a failed fetch with
  its URL, HTTP status and `Retry-After`, the shape the DID method crates now
  report. `affinidi-did-resolver-traits` 0.1.5 converts it into its
  `NetworkFetchError`.
- Docs (#1044, #1045): `Document::default()` documents its placeholder `id`
  (`did:example:123456789abcdefghi`), which `..Default::default()` carries
  into a document that sets no `id` of its own; the `DID` docs no longer
  claim more than construction checks.
- Requires `affinidi-encoding` 0.1.7.
- **Compatibility (R3.6):** no signature change. Behaviour that changes for a
  caller: a did:peer:0 document's ids are `did:peer:0…`, not `did:key:…` (a
  lookup by the did:key id no longer matches); a JWK-built EC `KeyMaterial`'s
  `public_bytes()` is 1 byte longer, with the `0x04` prefix; a JWK with
  mis-sized EC coordinates, a did:peer:2 with a private or mis-sized key, a
  `DID::new` of an inconsistent `DIDMethod`, and a serialized `DID` whose
  fields disagree are now errors. Checked with `cargo check --workspace
  --all-targets --all-features`; nothing in this workspace relied on any of
  them.

## [0.4.7] - 2026-11-13

affinidi-crypto 0.3

- **Changed:** requires `affinidi-crypto` 0.3. `KeyMaterial::generate_ed25519`,
  `generate_x25519`, `generate_p256`, `generate_p384` and
  `generate_secp256k1` take the key out of the generated key pair with
  `into_parts()`, so the private key moves into the `KeyMaterial` without a
  copy.
- **Compatibility (R3.6):** no signature change in this crate. `KeyType` and
  the `KeyError::Crypto` source now refer to `affinidi-crypto` 0.3; a caller
  that also uses `affinidi-crypto` directly needs 0.3 for the types to match.
  Released as a patch, per ADR 0003, because `didwebvh-rs` and
  `trust-tasks-proof` pin this crate at `0.4`.

## [0.4.6] - 2026-11-12

`Debug` leaves private keys out; created did:peer keys zeroize

- **Changed:** `Debug` for `KeyMaterial` printed `private_bytes` in full, and
  for `KeyMaterialFormat` the `Multibase` and `Base58` private keys, although
  the JWK inside already printed its `d` as `<redacted>`. They now print
  `<redacted>` in their place; every other field prints as before.
- **Changed:** `PeerCreatedKey`, which `DID::generate_peer` returns with each
  generated private key in `d`, prints `d` as `<redacted>` and derives
  `Zeroize` and `ZeroizeOnDrop`, so the key is cleared when the value is
  dropped. `Clone`, `Serialize` and `Deserialize` stay: callers persist the
  generated keys through them.
- **Changed:** `DID::generate_peer` returns
  `DIDError::InvalidMethodSpecificId` if a generated key carries no private
  key, instead of recording an empty `d`. Generated keys always carry one, so
  nothing changes in practice.
- **Compatibility (R3.6):** no signature change. `ZeroizeOnDrop` gives
  `PeerCreatedKey` a `Drop` impl, so code that moves a field out of it by
  destructuring (`let PeerCreatedKey { d, .. } = key;`) or by `let d = key.d;`
  no longer compiles; borrow or clone the field instead. No such use was found
  in this workspace (checked with `cargo check --workspace --all-targets
  --all-features`) or in verifiable-trust-infrastructure, cierge, openvtc,
  affinidi-trust-registry-rs, affinidi-messaging-mediator, vti-message-bridge
  or affinidi-webvh-service. Code that matches on the `Debug` text of these
  types sees `<redacted>`.

## [0.4.5] - 2026-10-26

builds with its default features off

`affinidi-did-common` with `default-features = false` failed to compile:
`KeyMaterial::generate` named every curve's generator, but each is behind its
own feature (`ed25519`, `p256`, `p384`, `k256`). A crate that took did-common
for its identifier helpers alone, and was built on its own (`cargo test -p`),
could not build. `generate` now returns `UnsupportedKeyType` for a curve whose
feature is off. With the default features nothing changes.

## [0.4.4] - 2026-10-21

did:scid references match by DID

- **Added:** the `scid` module: `strip_scid_src`, `scid_src`, `with_scid_src`
  and `same_reference`. A `did:scid` identity is the DID; its `src` query is a
  locator, so `did:scid:vh:1:Qm?src=example.com#key-1` and
  `did:scid:vh:1:Qm#key-1` name the same key. Only a `did:scid` DID URL whose
  sole query parameter is `src` is affected.
- **Behaviour:** `DocumentExt` lookups by id (`contains_*`, `find_*`,
  `get_verification_method`) match a did:scid reference that carries `src`
  against the bare ids its document lists. Every other id still matches
  exactly.

## [0.4.3] - 2026-09-22

a service endpoint's URI is a URI

`Endpoint::get_uri` and `get_uris` return the `uri` member's **value** for the
map and array forms of `serviceEndpoint`, as they already did for the plain
URL form. Before, those forms returned its JSON encoding, quotes included
(`"\"did:example:mediator\""`). A caller that checked the result (a
`starts_with("did:")` to tell a mediator DID from a URL, say) silently found
nothing. A non-string `uri` is now skipped rather than returned as JSON text.

The fix was merged in #785 but never released: that change left the version
at 0.4.2, which was already published, so crates.io kept serving the old
code. Callers that stripped the quotes themselves are unaffected, because
trimming an unquoted string changes nothing.

## [0.4.2] - 2026-08-23

dependency refresh

- Bumps `base64` 0.22 → 0.23.
- No source or API change; the bumps are declaration-only and the crate
  compiles unmodified against them. Bumped workspace-wide in the same
  change so no two versions of these crates are compiled side by side.

## [0.4.1] - 2026-07-31

Moves to **curve25519-dalek 5** (`ed25519-dalek` 2 -> 3, `x25519-dalek` 2 -> 3),
which brings rand_core 0.10 and signature 3 with it. rand 0.10 renamed `OsRng`
to `SysRng` *and* made it fallible (`TryRng<Error = SysError>`), so it no longer
satisfies dalek's `CryptoRng` bound; key generation moves to `rand::rng()`.

Patch bump, per [ADR 0003](../../../docs/adr/0003-public-api-semver-policy.md) point 3: `vta-sdk` pins this crate through
`[patch.crates-io]`, and a minor bump would break the redirect and pull a second
copy from crates.io.

All notable changes to `affinidi-did-common` are documented here. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-07-19

### Added

- `Document::also_known_as` (`alsoKnownAs`) is now a **typed field** (`Vec<String>`)
  rather than an untyped entry in the flattened `parameters_set` map, plus
  `DocumentBuilder::also_known_as` / `also_known_as_many` to set it.

  The DID specification defines `alsoKnownAs` as a set, so it always *serializes*
  as a JSON array and is omitted entirely when empty. Deserialization is
  deliberately lenient and also accepts a **bare string**, because documents in
  the wild emit that form; a bare string normalizes to a single-element array on
  the next serialization.

  This is groundwork for agent-name (DID shortcut) resolution, where the
  mandatory anti-spoofing check is that a resolved DID Document's `alsoKnownAs`
  contains the agent name that was used to reach it.

  The change itself is additive: `Document` is `#[non_exhaustive]`, so consumers
  already construct it via `Document::new` / `DocumentBuilder` / deserialization
  rather than struct literals, and no consumer code needs to change.

  Note for anyone who previously read the value out of the untyped map:
  `parameters_set["alsoKnownAs"]` is now absent — read `doc.also_known_as`.

### Changed

- **Minor version bump to `0.4.0`.** Although the API change above is additive,
  this is released as a minor rather than a patch, which means every consumer
  must move its requirement from `"0.3"` to `"0.4"`. Per ADR 0003 §3 a minor bump
  of this crate breaks any `[patch.crates-io]` redirect held by an external
  crates.io consumer still pinning `"0.3"`, so those consumers must be released
  first. The one such consumer, `didwebvh-rs`, is updated in lockstep
  (`0.5.8`, requiring `affinidi-did-common "0.4"`); it needed only the dependency
  bump, no code changes.

## [0.3.9] - 2026-06-23

### Fixed

- `did:peer` resolution dropped **non-DIDComm service types**:
  `PeerService::to_did_service` hardcoded the resolved service type to
  `DIDCommMessaging` regardless of the encoded `t` value, so a `did:peer` that
  published e.g. a TSP transport endpoint resolved to a `DIDCommMessaging` service
  and the original type was lost. The service type is now expanded properly: `dm`
  → `DIDCommMessaging`, `tsp` → `TSPTransport`, and any other type is preserved
  verbatim. Existing `dm` services are unchanged.

## [0.3.8] - 2026-06-22

### Fixed

- `DocumentExt::find_authentication(None)` returned the document's **`keyAgreement`**
  ids instead of its **`authentication`** ids (a copy-paste of `find_key_agreement`).
  Callers asking for the default authentication keys got key-agreement (X25519)
  keys. Fixed to return `authentication`, and the regression test now asserts the
  returned ids rather than only their count (the old count-only assertion passed
  coincidentally because the test document had equal numbers of each). This also
  fixes `affinidi-messaging-sdk`'s DIDComm signed-message verification for the
  bare-DID `kid` case, which depends on this method.

## [0.3.7] - 2026-06-14

### Changed

- `DIDError`, `KeyError`, `KeyNegotiationError`, and `PeerError` are now
  `#[non_exhaustive]` (ADR-0003) so future variants are additive. Patch bump to
  keep the `0.3` pin — including the `didwebvh-rs` `[patch.crates-io]` redirect —
  valid; consumers that `match` these must add a `_` arm. No behaviour change.

## [0.3.6] - 2026-06-13

### Changed

- Sealed the public API for future-proofing (semver wave W9, released W11):
  `DocumentError`, `Endpoint`, `VerificationRelationship`, and `OneOrMany` are
  now `#[non_exhaustive]` (match with a wildcard arm); `Document`, `Service`, and
  `VerificationMethod` are `#[non_exhaustive]` (construct via the existing
  builders / `Document::new`; fields stay public for reads). Patch bump preserves
  the `didwebvh-rs` `[patch.crates-io]` coupling — see ADR 0003 and
  `docs/migration/2026-06-semver-wave.md`.

## [0.3.5] - 2026-06-06

### Added

- `key_negotiation` module (behind the new opt-in `key-agreement` feature)
  — the single home for sender/recipient key-agreement curve negotiation,
  shared by the messaging SDK and the DID-authentication layer (#357). It
  exposes `negotiate_authcrypt` (bidirectional best-curve match over the
  cross-product of sender×recipient keys, by a documented preference order
  `X25519 > P-256 > secp256k1`), `select_anoncrypt_key` (first recipient KA
  key that resolves to a supported curve, skipping undecodable codecs),
  `resolve_public_key_agreement`, the `DEFAULT_CURVE_PREFERENCE` constant,
  and a neutral `KeyNegotiationError` (whose `NoCommonCurve` names the curve
  set each side offered). The curve-preference policy is overridable at
  runtime: both `negotiate_authcrypt` and `select_anoncrypt_key` take a
  `preference: &[Curve]` argument (pass `DEFAULT_CURVE_PREFERENCE` for the
  standard policy, or a custom order to force e.g. P-256 first). The default
  policy and key resolution now span all five key-agreement curves —
  `X25519 > P-256 > P-384 > P-521 > secp256k1` (#357) — including JWK
  decoding of `crv: "P-521"`. Anoncrypt
  uses the **same** preference-ordered selection as authcrypt — it picks the
  recipient's most-preferred usable curve rather than the document-first
  key — so signed and anonymous encryption never diverge. The feature gates
  an `affinidi-crypto/jose` dependency, so the default build of this crate is
  unchanged. This replaces the byte-for-byte-duplicated negotiation helpers
  that previously lived in both call-site crates.

## [0.3.4] - 2026-05-31

### Added

- `VerificationMethod::decode_public_key() -> (multicodec, bytes)` —
  a single decoder for verification material that handles both
  `publicKeyMultibase` (Multikey) and `publicKeyJwk` (via
  `affinidi-crypto`), returning the multicodec + raw key bytes (32 octets
  for Ed25519/X25519, uncompressed SEC1 for the EC curves). This is the
  shared source of truth used by the messaging SDK and the
  DID-authentication layer, replacing their previously-duplicated
  JWK/multibase parsing (which had drifted — see the ECDH-1PU interop
  work in `affinidi-messaging-didcomm` 0.14).

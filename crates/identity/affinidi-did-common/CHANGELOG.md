# Changelog

All notable changes to `affinidi-did-common` are documented here. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

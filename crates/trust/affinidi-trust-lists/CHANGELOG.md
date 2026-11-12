# Affinidi Trust Lists Changelog

## Unreleased (0.2.0) — chain signatures verified; list dates and identities parsed

Breaking (R3.6). No in-workspace caller outside `affinidi-tdk`'s re-export
(`affinidi-tdk` 0.38.0).

- **Chain validation verifies signatures.** `validate_chain` / `validate_x5chain`
  used to set `valid: true` from name matching, validity periods and anchor
  membership alone. They now verify each certificate's signature under its
  issuer's key, require `basicConstraints.cA` (and `keyCertSign` when
  `keyUsage` is present) on every issuer, honour `pathLenConstraint`, refuse
  SHA-1 signatures, and refuse critical name-constraint, policy or unrecognised
  extensions they do not enforce. Chains that previously reported valid
  without a verifiable signature now report `valid: false`.
- An x5chain carrying only the leaf (the usual mdoc case) now validates
  against an anchor certificate in the registry that issued it.
- **Anchor service types:** `validate_chain` / `validate_x5chain` (and the new
  `_at` variants, which take the validation time) take `anchor_types`; only
  registry entries of those service types can anchor a chain, and an empty
  slice accepts none. `ChainValidationResult` is `#[non_exhaustive]`.
- **Anchors at the validation time:** an anchor must be active at the
  validation time according to its status history (new
  `ServiceInformation::status_at`), and its trust list must not be past
  `NextUpdate` (new `TrustAnchorEntry::list_next_update` /
  `TrustAnchorEntry::usable_at`). `lookup_by_*` apply the same rule at the
  system clock's time, and `lookup_by_identity_at` at a given time. The
  `find_*` / `*_providers` listings still use the current status and do not
  check freshness.
- Signature algorithms are those of `x509-parser`'s verifier: RSA, ECDSA on
  P-256 / P-384, and Ed25519. P-521 and brainpool certificates do not validate.
- **Fingerprints are separated by identity kind:** `ServiceDigitalIdentity::fingerprint`
  hashes the kind ahead of the value, so a subject name is no longer found by
  `lookup_by_did` with the same string, nor an SKI by `lookup_by_public_key`.
  Fingerprints computed by 0.1 differ.
- `active_certificate_anchors` is `certificate_anchors` and yields every
  certificate identity; filtering is the caller's.
- **XML parsing:** `parse_trust_list_xml` returns `UnverifiedTrustList`; the
  list's XAdES signature is **not** verified by this crate, and the caller
  releases the list with `assume_authenticated()` after authenticating it.
  `ListIssueDateTime` (required) and `NextUpdate` are parsed instead of
  defaulting to now / none. An unparseable date or undecodable certificate or
  SKI is an error instead of being replaced or skipped. `ServiceHistory` is
  parsed into `ServiceInformation::history` and no longer leaks its name or
  certificate into the next service; the `Signature` element's certificates
  are ignored.
- `ServiceInformation::digital_identity` is now `digital_identities: Vec<_>`;
  every `X509Certificate`, `X509SKI` and `X509SubjectName` of a service is kept
  and indexed. A service with no identity is no longer indexed under an empty
  public key.
- `TrustListRegistry::load_trust_list(&tl, now)` returns `Result` and refuses a
  list that is not current (`TrustServiceStatusList::is_current_at`), including
  a closed list. New `TrustListError::NotCurrent`.
- `x509-parser` now uses its `verify-aws` feature (`aws-lc-rs`, already in the
  workspace lockfile). `rcgen` (already in the workspace) is a dev-dependency.

## Unreleased (0.1.6) — `sha2` 0.11

No behaviour change; the crate's only use is `Sha256::digest`, which is
unchanged across the bump. Moves onto the same `sha2` line as the rest of the
workspace's crypto crates.

## Unreleased (0.1.5) — quick-xml 0.42, x509-parser 0.18

- **`quick-xml` 0.41 → 0.42**, which required a source migration. 0.42 makes
  names and text `&str` throughout where they were byte slices, so
  `BytesText::decode()` and `BytesRef::decode()` are gone (the content is already
  decoded) and `QName::as_ref()` yields `&str`. `local_name_owned` now takes
  `&str` and the intermediate `Vec<u8>` per tag is gone with it.

  Entity handling is unchanged: references still arrive as their own `GeneralRef`
  events and are still resolved and appended, so a value containing `&amp;`
  reassembles exactly as before. `xml10_content()` exists in 0.42 but only
  normalises EOLs, which this parser does not need — every consumer trims.
- **`x509-parser` 0.16 → 0.18**, no source change.

37 tests green, including the entity-reference cases.

## Unreleased (0.1.4) — dependency refresh

- Bumps `base64` 0.22 → 0.23.
- No source or API change; the bumps are declaration-only and the crate
  compiles unmodified against them. Bumped workspace-wide in the same
  change so no two versions of these crates are compiled side by side.

## 14th June 2026

### 0.1.2 — non_exhaustive TrustListError (W7 sweep)

- `TrustListError` is now `#[non_exhaustive]` (ADR-0003) so new variants land
  additively. Patch bump keeps the `0.1` pin valid; consumers that `match` it
  must add a `_` wildcard arm. No behaviour change.

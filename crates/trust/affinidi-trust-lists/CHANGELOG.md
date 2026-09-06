# Affinidi Trust Lists Changelog

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

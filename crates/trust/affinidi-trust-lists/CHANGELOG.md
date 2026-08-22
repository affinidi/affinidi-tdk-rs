# Affinidi Trust Lists Changelog

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

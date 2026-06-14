# Affinidi TSP Changelog

## 14th June 2026

### 0.1.3 — non_exhaustive TspError (W7 sweep)

- `TspError` is now `#[non_exhaustive]` (ADR-0003) so new variants land
  additively. Patch bump keeps the `0.1` pin valid; consumers that `match` it
  must add a `_` wildcard arm. No behaviour change.

### 0.1.2 — build fix: drop deprecated `GenericArray::from_slice`

- The HPKE module (`crypto/hpke.rs`) no longer calls the now-deprecated
  `GenericArray::from_slice` for the AES-128-GCM key/nonce — the key is built via
  `KeyInit::new_from_slice` and the nonce via `GenericArray::from([u8; 12])`.
  Keeps the crate compiling under `-D warnings` against `generic-array` 0.14.9+,
  which deprecated `from_slice`. Behaviour-identical (seal/open round-trip tests
  unchanged).

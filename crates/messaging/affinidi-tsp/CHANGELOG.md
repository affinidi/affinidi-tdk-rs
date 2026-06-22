# Affinidi TSP Changelog

## 22nd June 2026

### 0.1.4 — DID-document VID resolver

- New `DidVidResolver` (behind the existing `did-resolver` feature): resolves a
  DID (`did:web` / `did:webvh` / `did:peer` / `did:key`) to a `ResolvedVid` via
  `DIDCacheClient`, reading the Ed25519 signing key from `authentication`, the
  X25519 encryption key from `keyAgreement`, and TSP transport endpoint(s) from a
  `TSPTransport` service entry. DID resolution is async (`resolve_did`) and cached;
  the synchronous `VidResolver` trait serves from that cache.
- New `TspError::DidResolution` variant (additive — `TspError` is already
  `#[non_exhaustive]`) and a new optional `affinidi-encoding` dependency pulled in
  only by the `did-resolver` feature.
- Purely additive; patch bump keeps the `0.1` pin valid. No behaviour change to
  existing APIs.

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

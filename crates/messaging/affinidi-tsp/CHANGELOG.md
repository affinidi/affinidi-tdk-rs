# Affinidi TSP Changelog

## 29th June 2026 (docs)

### 0.1.11 — README: reflect full reference interop

- README now states that `affinidi-tsp` wire-interoperates with the ToIP reference
  (`tsp-sdk`) for all message types (replacing the stale "does not interoperate" note).
  Docs-only; no code change.

## 29th June 2026 (control)

### 0.1.10 — spec-compliant relationship Control (full tsp_sdk wire parity)

- **Relationship Control (invite / accept / cancel) now matches the ToIP reference and
  interoperates both directions** — completing full TSP wire parity (Direct/Routed/Nested/
  Control all interop with `tsp_sdk`). Control payloads are now CESR-coded per the spec:
  invite → `XRFI` + hop list + 32-byte `TSP_NONCE` + empty VID; accept → `XRFA` + 32-byte
  SHA-256 `reply`; cancel → `XRFD` + 32-byte SHA-256 `reply`. Replaces the previous
  serde-serialized `ACT` marker and 16-byte nonce.
- **Correlation digest = `SHA256(plaintext payload frame)`** (`thread_digest`), computed at
  `pack` (before sealing) and `unpack` (after decrypt), byte-identical to the reference's
  `thread_id`. The accept/cancel `reply` references the invite's `thread_digest`. (BLAKE2s
  `message_digest` is retained only as an opaque message id.)
- `ControlMessage` is now `{ control_type, nonce: Option<[u8;32]>, reply: Option<[u8;32]>,
  route }`; `PackedMessage`/`UnpackedMessage` expose `thread_digest`. The relationship FSM
  records the invite digest per `(our, their)` and verifies an accept's `reply` against the
  invite it sent. States/transitions unchanged.
- Wire-breaking for Control (Direct/Routed/Nested unchanged); accept/cancel APIs now take the
  thread digest.

## 29th June 2026 (later)

### 0.1.9 — spec-compliant Routed/Nested payloads + reference-aligned size cap

- **Routed and Nested payloads now match the ToIP reference (`tsp_sdk`) and interoperate
  both directions.** The payload frame inside `-Z` is now kind-encoded per the spec:
  Direct=`XSCS`+`B(body)`, Nested=`XHOP`+empty-hop-list+`B(body)`, Routed=`XHOP`+hop-list+
  `B(body)` (hops as `-J<count>` + a `B` field per VID). Replaces the previous
  affinidi-private `ANS`/`ART` markers and the bespoke `encode_route` (the route is now the
  CESR hop list, not baked into the plaintext). `UnpackedMessage` gains `hops`. New
  `direct::pack_with_hops`; `routed::next_hop(&UnpackedMessage)` (was `next_hop(&[u8])`).
  Control stays on its `ACT` marker (relationship interop is a separate follow-up).
- **Size cap aligned with the reference:** `MAX_FIELD_SIZE` is now `3 * (1 << 24)` (~48 MiB,
  the reference's `DATA_LIMIT`) instead of 1 MiB, so affinidi accepts any field the reference
  can validly send; `MAX_MESSAGE_SIZE` (the ciphertext guard) tracks it. `decode_hops` is
  bounded by `MAX_HOPS` so the larger cap can't let a hostile hop count over-allocate.
  Verified by a 2 MiB Direct round-trip in the interop harness (exercises the large CESR
  variable-data code).
- Wire-breaking for Routed/Nested (Direct unchanged/byte-exact); API: `next_hop` signature
  changed, `pack_with_hops` added, `pack_routed`/`pack_nested` public signatures unchanged.

## 29th June 2026

### 0.1.8 — spec conformance (2/2): CESR wire framing + RFC-9180 HPKE (tsp-sdk interop)

- Rewrote the Direct-message wire format to the TSP spec's CESR framing (the `-E` envelope
  frame, `YTSP` version, var-data VID codes, `G` ciphertext code, `-Z`/`XSCS` payload frame,
  `-C`/`-K` signature framing). The magic byte is now `0xF8` (the `-E` count code), was
  `0xD4`. The message kind (Direct/Routed/Nested/Control) now travels in the *encrypted*
  payload, not the cleartext envelope (`MetaEnvelope` reports a Direct placeholder).
- Corrected four RFC 9180 deviations in the hand-rolled HPKE — DHKEM KEM context order
  (`enc‖pkR‖pkS`), `LabeledExtract` returning the real PRK, and the DHKEM `eae_prk` /
  `shared_secret` labels. These were latent correctness bugs (the prior output was
  non-standard, only self-consistent).
- With both, a Direct message now round-trips **both directions** against the ToIP reference
  `tsp_sdk` 0.9.0-alpha2 (verified by the `interop/` harness). Routed/Nested/Control build on
  the same framing.
- Wire-breaking but API-stable (`pack`/`unpack`/`pack_routed`/`pack_nested` signatures
  unchanged), so consumers need no code changes beyond rebuilding.

## 28th June 2026

### 0.1.7 — spec conformance (1/2): ChaCha20Poly1305 HPKE AEAD + empty HPKE info

- The HPKE AEAD is now **ChaCha20Poly1305** (was AES-128-GCM) and the HPKE `info` is
  now empty/`NULL` (was `"TSP-v1-direct"`), matching the TSP spec (v1.0 Implementor's
  Draft Rev 2), which mandates ChaCha20Poly1305 and `info = NULL`. The HPKE suite ID's
  AEAD code is updated `0x0001 → 0x0003` accordingly.
- **Wire-breaking:** the ciphertext format changed; messages packed by 0.1.6 (or any
  AES-GCM build) will not decrypt under 0.1.7. TSP is pre-adoption / experimental, so
  no migration is provided. The public API is unchanged (`seal`/`open`/`pack`/`unpack`
  signatures identical), so consumers need no code changes.
- This is the first of two spec-conformance steps. The CESR envelope / payload /
  signature **framing** is still being brought to spec (a follow-up); full interop with
  the reference (`tsp-sdk`) lands once both are done. See
  [`docs/tsp/interop.md`](../../../docs/tsp/interop.md).

## 22nd June 2026

### 0.1.6 — ingress sniff + keys-free envelope metadata

- New `message::meta` module for relays/mediators that must route a message
  without holding keys: `is_tsp` (cheap first-byte classifier — every TSP
  message starts with the CESR `1AAF` magic byte `0xD4`, vs DIDComm's `{`/`ey`),
  the `TSP_MAGIC_BYTE` constant, and `MetaEnvelope::parse` which reads the
  cleartext sender/receiver VIDs + message type and computes the SHA-256 message
  id without decrypting the payload.
- Re-exported at the crate root (`is_tsp`, `MetaEnvelope`, `TSP_MAGIC_BYTE`).
- Purely additive; patch bump 0.1.5 → 0.1.6.

### 0.1.5 — routed & nested message modes (§5.3 / §5.5)

- New `message::routed` module implementing TSP routed mode (multi-hop relay
  through intermediaries, with the remaining route carried inside each
  HPKE-sealed routing layer and re-sealed/re-authenticated at every hop) and the
  nested metadata-privacy wrapper. The inner message stays opaque to every
  intermediary. Replaces the previous `MessageType::Nested`/`Routed`
  recognized-but-unimplemented stubs.
- Public primitives `pack_routed`, `pack_nested`, `next_hop`, and the `RouteStep`
  / `MAX_HOPS` exports.
- New high-level `TspAgent` methods `send_routed`, `send_nested`, and
  `forward_routed` (returning `ForwardOutcome::{Relay, Deliver}`), which resolve
  each hop's keys via the agent resolver.
- `TspAdapter::wrap_for_relay` (messaging-core) now implemented (was
  `NotSupported`): relays an opaque packed message to the next hop toward the
  final recipient, as the adapter's default VID.
- Purely additive; patch bump 0.1.4 → 0.1.5. 84 tests incl. a full multi-hop
  crypto round-trip and a two-intermediary agent-level relay.

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

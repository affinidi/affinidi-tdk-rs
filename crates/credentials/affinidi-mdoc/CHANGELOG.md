# Affinidi mdoc Changelog

## 2nd August 2026 (0.2.5)

Moves this crate to the **elliptic-curve 0.14** family (`p256` / `k256` /
`p384` / `p521` 0.13 -> 0.14), which brings rand_core 0.10, digest 0.11 and
signature 3 with it.

API changes handled: the sec1 traits were renamed (`ToEncodedPoint` ->
`ToSec1Point`, `FromEncodedPoint` -> `FromSec1Point`), `EncodedPoint` became a
generic alias for `Sec1Point<C>` so it needs a per-module binding, and the
deprecated `SigningKey::random(rng)` is now `Generate::generate()` (system
CSPRNG, panics on failure).

Patch bump, per [ADR 0003](../../../docs/adr/0003-public-api-semver-policy.md) point 3: `vta-sdk` and `didwebvh-rs` redirect
this crate through `[patch.crates-io]`, and a minor bump breaks the redirect.

Crypto behaviour is unchanged — the golden/KAT vectors (`p256_sign_verify_roundtrip`,
`secp256k1_es256k_golden` RFC 6979, `ecdh_1pu_x25519_kek_golden`,
`concat_kdf_es_golden`, `a256cbc_hs512_golden`) all still pass.

## 31st July 2026 (0.2.4)

Moves to **curve25519-dalek 5** (`ed25519-dalek` 2 -> 3, `x25519-dalek` 2 -> 3),
which brings rand_core 0.10 and signature 3 with it. rand 0.10 renamed `OsRng`
to `SysRng` *and* made it fallible (`TryRng<Error = SysError>`), so it no longer
satisfies dalek's `CryptoRng` bound; key generation moves to `rand::rng()`.

Patch bump, per [ADR 0003](../../../docs/adr/0003-public-api-semver-policy.md) point 3: `vta-sdk` pins this crate through
`[patch.crates-io]`, and a minor bump would break the redirect and pull a second
copy from crates.io.

## 14th June 2026 Release 0.2.3

- **Fix (build):** `session.rs` no longer calls the now-deprecated
  `GenericArray::from_slice` for the AES-256-GCM key/nonce — the key is built via
  `KeyInit::new_from_slice` and the nonce via `Nonce::from([u8; 12])`. This keeps
  the crate compiling under `-D warnings` against `generic-array` 0.14.9+, which
  deprecated `from_slice`. Behaviour-identical (round-trip tests unchanged).
  Supersedes 0.2.2, which carried the same `MdocError` sealing below but failed
  to publish on the deprecation.

## 14th June 2026 Release 0.2.2

- `MdocError` is now `#[non_exhaustive]` (ADR-0003) so new variants land
  additively. Patch bump keeps the `0.2` pin valid; consumers that `match` it
  must add a `_` wildcard arm. No behaviour change. (W7 sweep)

## 1st June 2026 Release 0.2.1

### Security

- **Drops the unmaintained `serde_cbor` dependency (RUSTSEC-2021-0127).**
  `serde_cbor` was declared in `[dependencies]` but referenced nowhere
  in the crate — all CBOR encoding/decoding already goes through
  `ciborium`. Removing the unused dependency clears the advisory with
  no code or behaviour change.

## 28th May 2026 Release 0.2.0

### Security

- **HIGH — MSO `ValidityInfo` was parsed but never enforced.**
  `verify_issuer_auth()` and `verify_digests()` accepted an mdoc whose
  `validUntil` was years in the past. ISO/IEC 18013-5 §9.3.1 requires
  the reader to reject documents outside their validity window, and
  `MdocError::Expired` already existed (unused) for exactly this. New
  `ValidityInfo::check(now)` and `ValidityInfo::check_now()` methods
  parse the RFC 3339 timestamps and return `Expired` when `now` falls
  outside `[validFrom, validUntil]`. Verifiers MUST call this on the
  MSO returned from `IssuerSigned::verify_issuer_auth` — signature and
  digest checks alone do not establish current validity.

### Breaking

- **`MdocError::Expired` is now `Expired(String)`** (was a unit variant).
  The variant existed but was unused, so no in-workspace consumer is
  affected; out-of-workspace callers pattern-matching on the unit form
  must update to the tuple form, e.g.
  `Err(MdocError::Expired) => …` becomes
  `Err(MdocError::Expired(_)) => …`. The carried string describes which
  bound was crossed (not-yet-valid vs. expired) and the offending
  timestamp.

### Dependencies

- Adds `time = "0.3"` (with `parsing` feature) — already in the workspace
  via `affinidi-messaging-sdk`.

### Tests

- `validity_info_check_within_window` — in-window passes.
- `validity_info_check_expired` — `now > validUntil` returns `Expired`.
- `validity_info_check_not_yet_valid` — `now < validFrom` returns `Expired`.
- `validity_info_check_malformed` — non-RFC-3339 timestamps return
  `InvalidMso`.

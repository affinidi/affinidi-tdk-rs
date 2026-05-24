# Affinidi Crypto Changelog

## 24th May 2026 (0.1.6)

- **FIX:** Build against stable `ml-dsa 0.1.0`. The `KeyGen` trait was
  removed from `ml-dsa`'s root module between `0.1.0-rc.8` and the
  `0.1.0` stable release; switched the six callsites to
  `SigningKey::<P>::from_seed()` and pinned the dependency to
  `0.1.0`. No public-API change — `generate_ml_dsa_{44,65,87}`,
  `sign_ml_dsa_{44,65,87}`, `verify_ml_dsa_{44,65,87}`, and
  `MlDsaExpandedKey::from_seed` keep the same signatures and produce
  the same bytes (NIST ACVP keygen KATs unchanged).
- **HARDENING:** Locked `slh-dsa` to exactly `=0.2.0-rc.5`. The crate
  is still pre-release upstream; an exact pin prevents the same kind
  of rc-to-rc API drift that just bit `ml-dsa`. To be relaxed when
  `slh-dsa 0.2.0` ships stable.

## 20th April 2026 (0.1.5)

- **FEATURE:** `did_key` module (behind the `ed25519` feature) adds a
  raw-bytes API for apps doing HPKE, sealed transfer, or other non-
  DIDComm key agreement:
  - `ed25519_pub_to_did_key(&[u8; 32]) -> String` encodes an Ed25519
    public key as a `did:key:z6Mk…` identifier.
  - `did_key_to_ed25519_pub(&str) -> Result<[u8; 32], CryptoError>`
    decodes a `did:key:z6Mk…` string, validating the `did:key:`
    prefix, multibase `z`, Ed25519-pub multicodec, and 32-byte length.
  - `ed25519_pub_to_x25519_bytes(&[u8; 32]) -> Result<[u8; 32],
    CryptoError>` derives the X25519 public key from an Ed25519 public
    key without round-tripping through a multikey string.
  The existing multikey-string helpers in `ed25519.rs` are retained
  for multikey-native callers such as `affinidi-secrets-resolver`.
- **TESTS:** Backfilled `ed25519_public_to_x25519` coverage — parity
  check vs. the new `did_key::ed25519_pub_to_x25519_bytes`, plus the
  three error paths (missing `z` multibase prefix, wrong multicodec,
  wrong payload length).
- **DOCS:** Crate-level docs and README now advertise the post-quantum
  features (ML-DSA / SLH-DSA) and the new `did:key` raw-bytes helpers.
- **HYGIENE:** Dropped the unused direct `rand_core` 0.10 dep —
  transitively pulled in via `ml-dsa` / `slh-dsa`'s own `rand_core`
  feature, never imported here.

## 18th April 2026 (0.1.4)

- **FEATURE:** `post-quantum` Cargo feature (off by default) with
  `ml-dsa` and `slh-dsa` sub-flags. Adds:
  - `ml_dsa` module (FIPS 204): `generate_ml_dsa_{44,65,87}`,
    `sign_ml_dsa_{44,65,87}`, `verify_ml_dsa_{44,65,87}`. Private-key
    representation is the 32-byte seed `xi`.
  - `slh_dsa` module (FIPS 205 SHA2-128s):
    `generate_slh_dsa_sha2_128s`, `sign_slh_dsa_sha2_128s`,
    `verify_slh_dsa_sha2_128s`.
  - `MlDsaExpandedKey` enum exposes the pre-expanded primitive for
    caching (amortises the ~80–100 µs expansion cost over many signs).
- **FEATURE:** `KeyType` gains `MlDsa44`, `MlDsa65`, `MlDsa87`, and
  `SlhDsaSha2_128s` variants under the respective features. Enum is
  `#[non_exhaustive]`.
- **TESTS:** NIST ACVP known-answer vectors pinned for ML-DSA-44/65/87
  keygen via SHA-256 of the full expected public key, plus a full KAT
  for SLH-DSA-SHA2-128s keygen (`slh_keygen_internal` validated
  against the FIPS 205 reference).
- **SECURITY:** ml-dsa and slh-dsa built with their upstream `zeroize`
  features; internal ExpandedSigningKey wipes matrix on drop.
  Intermediate B32 seed buffers wrapped in `zeroize::Zeroizing`.

## 0.1.2 — prior releases

(No CHANGELOG recorded for earlier 0.1.x releases.)

# Affinidi Crypto Changelog

## 1st June 2026 (0.1.10)

- **FEATURE (#327, `jose`):** Added
  `jose::ecdh::derive_sender_key_1pu_legacy`, the sender-side counterpart
  to `derive_key_1pu_recipient_legacy`. Interop/testing only — reproduces
  the pre-#322 unprefixed-tag KEK so a node can synthesise legacy JWEs to
  exercise its decrypt fallback. Completes the surface didcomm needs to
  drop its bespoke crypto (PR 5d).

## 1st June 2026 (0.1.9)

- **FEATURE — `jose` key agreement + ECDH derivation (#327, off by
  default).** Builds on 0.1.8, completing the curve-bearing half of the
  JOSE port from `affinidi-messaging-didcomm`.
  - `jose::key_agreement` — `Curve` (X25519 / P-256 / secp256k1) plus
    `PublicKeyAgreement` / `PrivateKeyAgreement` / `EphemeralKeyPair`,
    with `from_raw_bytes`, `public_key`, `diffie_hellman`, and JWK
    `to_jwk` / `from_jwk`. Curves are runtime-dispatched (a message picks
    its curve at runtime); adding one is a localized change here — all
    derivation/KDF/wrap/AEAD code stays curve-agnostic over the raw
    shared secret.
  - `jose::ecdh` — `derive_key_es` / `derive_key_1pu` (+ recipient and
    `_legacy` variants and the `derive_sender_key*` helpers) combining
    key agreement with the Concat KDF from 0.1.8.
  - KATs now include the ECDH-1PU KEK over X25519, asserting the **same**
    golden as the didcomm harness (PR #336) — proving key agreement +
    Concat-KDF-1PU port byte-identically end to end — plus ECDH-ES and
    JWK round-trips across all three curves.
  - New `CryptoError::KeyAgreement` variant. The `jose` feature now also
    enables the `p256` / `k256` features, and those crates gain the
    `ecdh` cargo feature. Still **off by default**.

## 1st June 2026 (0.1.8)

- **FEATURE — `jose` module (#327, off by default).** Adds the JOSE
  crypto primitives previously hand-rolled in
  `affinidi-messaging-didcomm`, as the first code-bearing step of the
  centralization in `docs/adr/0001`. This release lands the **stateless**
  primitives plus an extensible trait layer; ECDH key agreement / curve
  types follow in a later PR.
  - `jose::aes_kw` — AES-256 Key Wrap (RFC 3394).
  - `jose::content_encryption` — A256CBC-HS512.
  - `jose::concat_kdf` — JOSE Concat KDF for ECDH-ES and ECDH-1PU
    (including the #322-correct length-prefixed `cc_tag`, plus a
    `_legacy` variant for the decrypt-fallback migration path).
  - `jose::signing` — Ed25519 (EdDSA).
  - `jose::traits` — one trait per JOSE role (`KeyWrap`,
    `ContentEncryption`, `KeyDerivation`, `JwsSigner`/`JwsVerifier`) with
    concrete impls (`A256Kw`, `A256CbcHs512`, `ConcatKdf`, `Ed25519`)
    carrying their JOSE `alg`/`enc` identifiers — the open-for-extension
    seam for new curves/AEADs/sig-algs and future PQC.
  - Known-answer tests assert the **same** vectors as the didcomm harness
    (PR #336) plus the RFC 3394 §4.6 spec vector, proving the port is
    byte-identical.
  - New `CryptoError` variants: `KeyDerivation`, `KeyWrap`,
    `ContentEncryption`, `Signing`, `Verification`.
  - Gated behind the new `jose` feature (pulls `aes` / `cbc` / `hmac` /
    `subtle` and enables `ed25519`); **off by default**, so existing
    dependents are unaffected.

## 28th May 2026 (0.1.7)

- **SECURITY (HIGH):** Redact the private `d` scalar in `Debug` output for
  `ECParams` (P-256 / P-384 / secp256k1) and `OctectParams` (Ed25519 /
  X25519). Both structs derived `Debug`, so any `{:?}` format of a JWK
  that carried a private key would print the base64url private scalar
  verbatim — `ZeroizeOnDrop` covered heap lifetime but not the print-side
  leak. Manual `Debug` impls now print the public coordinates and render
  `d` as `<redacted>` when present. Regression test asserts the private
  scalar never appears in formatted output.

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

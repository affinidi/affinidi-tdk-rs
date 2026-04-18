# Affinidi Encoding Changelog

## 18th April 2026 (0.1.2)

- **FEATURE:** Added post-quantum multicodec constants aligned with the
  official multicodec registry (all currently `draft`):
  - `ML_DSA_44_PUB` (`0x1210`), `ML_DSA_65_PUB` (`0x1211`),
    `ML_DSA_87_PUB` (`0x1212`)
  - `ML_DSA_44_PRIV_SEED` (`0x131a`), `ML_DSA_65_PRIV_SEED` (`0x131b`),
    `ML_DSA_87_PRIV_SEED` (`0x131c`) — 32-byte seed representation
  - `SLH_DSA_SHA2_128S_PUB` (`0x1220`)

  SLH-DSA has no registered private-key multicodec, so we do not ship
  one. The matching `Codec` enum variants are gated on `ml-dsa` /
  `slh-dsa` feature availability in consumer crates.
- **SAFETY:** `MultiEncoded` is now `#[repr(transparent)]`. Unsafe
  transmutes in `MultiEncoded::new` and `MultiEncodedBuf::as_multi_encoded`
  carry `// SAFETY:` comments documenting the layout guarantee and
  varint-prefix validation invariant.
- **TESTS:** Existing round-trip test now covers all new codecs via
  byte-level varint-prefix assertions (in downstream
  `affinidi-secrets-resolver` tests).

## 0.1.1 — prior releases

(No CHANGELOG recorded for earlier 0.1.x releases.)

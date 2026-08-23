# did:scid

## 0.2.2

### Changed

- `did-webs` feature now requires `affinidi-did-webs` 0.5.

## 0.2.1

### Changed

- `did-webs` feature now requires `affinidi-did-webs` 0.4, which derives service
  endpoints from signed KERI endpoint authorisations.

## 0.2.0

### Added

- **`did:scid:ke:1` — KERI AIDs via `did:webs`**, behind a new `did-webs`
  feature so the KERI stack stays out of builds that never resolve it.

  ⚠️ The method type registry (Appendix A of the specification) is still marked
  TODO and lists `ke` as a **proposed** entry, not a registered one. It is
  implemented because did:webs is named explicitly as a supported verification
  metadata format, but the code could change before the registry settles.

  Note the SCID's position differs by format: `did:webvh` puts it first,
  `did:webs` puts the AID **last**, because the AID is the final path element of
  the URL its artifacts are served from. Reusing the webvh formatting would
  produce a well-formed DID pointing at the wrong location, so the two are
  derived separately and a test pins both.

- `DIDSCIDError::UnknownFormat` and `DIDSCIDError::UnsupportedVersion`.

### Changed

- **Breaking:** the DID pattern now captures the format and version instead of
  hard-coding `vh:1`, so a well-formed `did:scid` naming an unresolvable format
  reports `UnknownFormat("...")` by name. It previously returned
  `UnsupportedFormat`, indistinguishable from a string that is not a `did:scid`
  at all.
- **Breaking:** `ScidMethod` gains a `Webs` variant and is now
  `#[non_exhaustive]`, since the registry is still open.
- A peer source for one format is no longer accepted for another. They place the
  SCID differently, so crossing them resolved to the wrong location.

## 2nd August 2026 (0.1.13)

`ssi-dids-core` becomes an optional dependency, enabled by `did-cheqd` —
the only feature whose code actually uses it. No behavioural change; the
dependency was previously unconditional but only ever referenced under
that gate.

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

## Changelog history

## 19th July 2026

#

## 0.1.12 — didwebvh-rs 0.6

- Bumped the `didwebvh-rs` requirement from `"0.5"` to `"0.6"`.

  0.6.0 requires `affinidi-did-common "0.4"`. Until now `didwebvh-rs 0.5.7`
  still required `"0.3"`, so the workspace carried **two** copies of
  `affinidi-did-common` (0.3.9 and 0.4.0); it compiled only because no types
  cross the `didwebvh-rs` boundary — `WebvhResolver` builds its own `Document`
  via `serde_json::from_value`. This collapses the graph back to a single
  `affinidi-did-common 0.4.0`.

  0.6.0 is a breaking release (`DIDWebVHError`, `URLType` and
  `LogEntryValidationStatus` became `#[non_exhaustive]`), but no code change was
  needed here: the only use is a `#[from] DIDWebVHError` conversion in
  `did-scid`'s error type, not an exhaustive `match`.

## 19th July 2026

### 0.1.11 — affinidi-did-common 0.4

- Bumped the `affinidi-did-common` requirement from `"0.3"` to `"0.4"`.
  No functional change to this crate: `Document` gained a typed
  `also_known_as` field, which is additive.

## 17th June 2026

### 0.1.10 — drop `did-cheqd` from default features (no forced `ring` TLS)

- **`did-cheqd` is no longer a default feature.** It pulled `did-resolver-cheqd`,
  whose `tonic 0.12` dependency hardcodes the rustls `ring` backend on
  `tokio-rustls`/`rustls 0.23`. That clashed with downstream binaries selecting
  `aws_lc_rs` (the ecosystem default via `kube`/`reqwest`/`jsonwebtoken`),
  compiling both backends and panicking with "no process-level CryptoProvider
  available" at the first TLS call. `default` is now `["did-webvh"]`.
- **Opt back in** with `features = ["did-cheqd"]` when you need `did:scid`
  anchored on `did:cheqd`; doing so re-enables the `ring` backend, so install a
  `CryptoProvider` in your binary's `main`.
- Patch bump keeps the `0.1` pin valid. No API or behaviour change beyond the
  default feature set.

## 14th June 2026

### 0.1.9 — non_exhaustive DIDSCIDError (W7 sweep)

- `DIDSCIDError` is now `#[non_exhaustive]` (ADR-0003) so new variants land
  additively. Patch bump keeps the `0.1` pin valid; consumers that `match` it
  must add a `_` wildcard arm. No behaviour change.

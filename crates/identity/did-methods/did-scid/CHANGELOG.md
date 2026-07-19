# did:scid

## Changelog history

## 19th July 2026

### 0.1.12 — didwebvh-rs 0.6

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

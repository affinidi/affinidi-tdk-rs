# Affinidi DID Resolver Cache SDK

## Changelog history

## 18th April 2026

### DID Resolver Cache SDK (0.8.6)

- **CHANGED:** Bumped `didwebvh-rs` dependency from `0.4` to `0.5`. Public
  resolver API unchanged; enables the `data-integrity 0.5.4` migration
  downstream.

## 17th April 2026

### DID Resolver Cache SDK (0.8.5)

- **SECURITY:** Swapped the upstream `did-web` crate for the new
  [`affinidi-did-web`](../did-methods/did-web/) crate, which sits on
  `reqwest 0.13` + `rustls 0.23` + patched `rustls-webpki 0.103.x`.
  The previous `did-web 0.3.4` chain pulled `rustls-webpki 0.101.7`, which
  is flagged by
  [GHSA-xgp8-3hg3-c2mh](https://github.com/advisories/GHSA-xgp8-3hg3-c2mh)
  and [GHSA-965h-392x-2mh5](https://github.com/advisories/GHSA-965h-392x-2mh5).
  Closes [#288](https://github.com/affinidi/affinidi-tdk-rs/issues/288).
- **CHANGED:** `WebResolver` now wraps a reusable `affinidi_did_web::DIDWeb`
  (and therefore its `reqwest::Client`) instead of constructing a fresh
  resolver per request. Public API (`AsyncResolver` implementation) is
  unchanged.
- **CHANGED:** MSRV bumped `1.90.0 → 1.94.0` via the workspace
  `rust-version`, required by the workspace-wide dep refresh.

## 27th March 2026

### DID Resolver Cache SDK (0.8.4)

- **FIX:** Updated `didwebvh-rs` 0.4.0 API call — `resolve()` now takes a
  `ResolveOptions` struct instead of positional `(Option, bool)` arguments,
  matching the upstream API change

# Affinidi DID Web

## Changelog history

## 17th April 2026

### Affinidi DID Web (0.1.0) — initial release

- **NEW:** Minimal in-workspace `did:web` resolver per the
  [W3C did:web method specification](https://w3c-ccg.github.io/did-method-web/).
- **WHY:** Upstream `did-web` (spruceid/ssi) still pins
  `reqwest = "0.11"` in its 0.5.x line, which transitively pulls
  `rustls 0.21` / `rustls-webpki 0.101.x`
  ([GHSA-xgp8-3hg3-c2mh](https://github.com/advisories/GHSA-xgp8-3hg3-c2mh),
  [GHSA-965h-392x-2mh5](https://github.com/advisories/GHSA-965h-392x-2mh5)).
  This crate sits on `reqwest 0.13` / `rustls 0.23` / patched
  `rustls-webpki 0.103.x` and mirrors the shape of our other in-workspace
  DID method crates (`did-ebsi`, `did-scid`, `didwebvh-rs`).
- **API:**
  - `DIDWeb::new()` — default HTTP client (rustls TLS, native roots,
    20 s timeout).
  - `DIDWeb::with_client(reqwest::Client)` — caller-supplied client for
    custom timeouts / proxies / shared connection pools.
  - `DIDWeb::resolve(did)` — returns `affinidi_did_common::Document`.
  - `affinidi_did_web::resolve(did)` — one-shot convenience wrapper.
  - `build_url(domain, path_segments)` — exposed for callers that want to
    compute the document URL without performing the HTTP request.
  - `DidWebError` — structured error type via `thiserror`.

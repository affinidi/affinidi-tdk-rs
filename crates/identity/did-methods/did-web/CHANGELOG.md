# Affinidi DID Web

## Changelog history

## 14th June 2026

### Affinidi DID Web (0.1.2)

- `DidWebError` is now `#[non_exhaustive]` (ADR-0003) so new variants land
  additively. Patch bump keeps the `0.1` pin valid; consumers that `match` it
  must add a `_` arm. No behaviour change.

## 28th May 2026

### Affinidi DID Web (0.1.1)

- **SECURITY (HIGH — SSRF):** The default reqwest client follows up to
  10 redirects. A hostile `did:web` origin could 302 the resolver to
  `169.254.169.254`, `127.0.0.1`, or any internal address — an SSRF
  pivot that bypasses whatever host-level filtering a deployer puts in
  front of the DID string. The default client now sets
  `redirect::Policy::none()`; callers passing their own
  `reqwest::Client` via `DIDWeb::with_client` are responsible for their
  own redirect policy.
- **SECURITY (HIGH — path traversal):** `build_url()` percent-decoded
  each colon-separated segment and appended it verbatim, so e.g.
  `did:web:example.com:%2E%2E:admin` produced
  `https://example.com/../admin/did.json` and
  `did:web:example.com:a%2Fb` produced `https://example.com/a/b/did.json`
  — a crafted DID could escape the expected `/{segments}/did.json`
  shape. `build_url` now rejects decoded segments that are empty, `.`,
  `..`, or contain `/` or `\`. New regression test
  `url_rejects_path_traversal_segments`.

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

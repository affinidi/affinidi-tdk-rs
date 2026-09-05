# Affinidi DID Web

## Changelog history

## 3rd September 2026

### 0.1.4 — SSRF hardening

- **SECURITY (SSRF):** a `did:web` value names the host the resolver fetches
  from, so an attacker-supplied DID could steer the resolver at an internal or
  cloud-metadata endpoint. Two checks now close that:
  - the DID's host is refused when it *is* a non-routable address —
    loopback, RFC 1918 / unique-local, carrier-grade NAT (`100.64.0.0/10`,
    which holds the Alibaba/Oracle metadata address and many Kubernetes node
    CIDRs), link-local (`169.254.169.254`), `0.0.0.0/8`, broadcast, the
    IPv4-mapped/-compatible and NAT64 spellings of any of those, or the names
    `localhost`, `*.localhost` and `*.local` (with or without a trailing root
    dot);
  - the DID's host is refused when it *resolves to* one. A name is not a
    defence: nothing stops an attacker pointing `evil.example.com` at
    `169.254.169.254`. The default client filters at DNS-resolution time, which
    also closes the rebinding window — the connection is made to the addresses
    the guard vetted, with no second unchecked lookup.
- The resolver response body is now capped at `MAX_DOCUMENT_BYTES` (1 MiB) and
  read incrementally, so a hostile server cannot stream an unbounded body into
  memory.
- **BEHAVIOUR CHANGE (breaking in effect, shipped as a patch per ADR-0003).**
  A deployment whose did:web hosts legitimately live on RFC-1918 space,
  `.local`, or loopback — an internal mediator resolving peers on `10.x`, or a
  local stack using `did:web:localhost%3A8080` — now gets
  `DidWebError::BlockedHost` where 0.1.3 resolved. Opt back in explicitly:

  ```rust
  use affinidi_did_web::{DIDWeb, HostPolicy};
  let resolver = DIDWeb::with_policy(HostPolicy::AllowPrivate);
  ```

- New public API (all additive): `HostPolicy`, `DIDWeb::with_policy`,
  `DIDWeb::with_client_and_policy`, and `guarded_dns_resolver()` — install the
  latter on a client you pass to `DIDWeb::with_client`, which otherwise gets
  only the literal-address half of the guard.

## 19th July 2026

### 0.1.3 — affinidi-did-common 0.4

- Bumped the `affinidi-did-common` requirement from `"0.3"` to `"0.4"`.
  No functional change to this crate: `Document` gained a typed
  `also_known_as` field, which is additive.

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

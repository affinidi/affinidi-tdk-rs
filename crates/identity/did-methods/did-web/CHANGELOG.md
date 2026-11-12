# Affinidi DID Web

## 0.1.8 — the decoded domain must be a host, each path segment one segment

Behaviour change (R3.6): some DIDs that resolved before are refused with
`DidWebError::InvalidDid`. No signature change.

- **The domain must decode to a host.** `build_url` (and so resolution)
  refuses a percent-decoded domain unless it is a host (a hostname, or an IP
  literal, which this resolver also accepts: IPv4, or IPv6 in brackets) and
  an optional numeric port. A domain that decodes to user information (`@`),
  a path (`/`, `\`), a query (`?`), a fragment (`#`), a further `%`,
  whitespace or a control character is refused. Before, the decoded domain
  went into the URL as it was, so `did:web:a.example%40b.example` was fetched
  from `b.example`.
- **Each path segment must decode to one segment.** A segment that decodes
  to `?`, `#`, `@`, `%` or a control character is refused, as `.`, `..`, `/`
  and `\` already were, so the fixed `/did.json` suffix cannot be pushed into
  a query or fragment.

## 0.1.7 — the guard holds behind a proxy and for a caller's client

- **No proxy under `HostPolicy::PublicOnly`.** The default client honoured
  `HTTPS_PROXY` and the other proxy variables. A proxy resolves the hostname
  itself, so the connect-time check never saw the address a request went to,
  and a hostname pointing at a private or cloud-metadata address got through.
  The client now uses no proxy under `PublicOnly`.
- **`DIDWeb::with_client_builder`** takes a `reqwest::ClientBuilder` and
  applies the guard settings (no redirects, the guarded resolver, no proxy,
  no `Referer`) after the caller's, so nothing the caller sets can undo them.
- **Deprecated:** `DIDWeb::with_client` and `DIDWeb::with_client_and_policy`.
  A built client cannot be inspected, so under them only the host the DID
  names is checked. Use `with_client_builder`.
- Building a resolver under `HostPolicy::AllowPrivate` logs a warning.

## 0.1.6 — the fetched document must name the requested DID

- Resolution now refuses a fetched DID document whose `id` is not the DID
  that was requested (new `DocumentIdMismatch` error). Previously a server
  answering for one DID could return a document for another and have its
  verification methods trusted.

## Changelog history

## 11th September 2026

### 0.1.5 — the SSRF guard moves to `affinidi-net-guard`

- Address classification and the connect-time DNS resolver now come from the
  new shared `affinidi-net-guard` 0.1.0 crate instead of private code here.
  The public API is unchanged: `HostPolicy`, `DIDWeb::with_policy`,
  `DIDWeb::with_client_and_policy` and `guarded_dns_resolver()` behave as in
  0.1.4, and `BlockedHost` messages keep their wording.
- **Names are unchanged.** did-web still refuses only `localhost`,
  `*.localhost` and `*.local`. `affinidi-net-guard`'s default also refuses
  `*.internal`, `*.home.arpa` and single-label names; since those can resolve
  to real internal hosts, adopting that set is a behaviour change and is left
  for a minor release.
- **Addresses the shared classifier also refuses.** These were accepted by
  0.1.4 and are now `BlockedHost`. None can host a working public HTTPS
  endpoint, so no working deployment is affected, but a test that expected a
  connect error for one of them now sees `BlockedHost` instead:
  - IPv4 documentation (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`),
    multicast (`224.0.0.0/4`) and reserved (`240.0.0.0/4`) space;
  - IPv6 multicast (`ff00::/8`), documentation (`2001:db8::/32`, `3fff::/20`),
    discard-only `100::/64`, SRv6 `5f00::/16`, and the non-global parts of
    `2001::/23`;
  - the IPv4-mapped, IPv4-compatible and NAT64 forms of those IPv4 ranges;
  - 6to4 (`2002::/16`) and Teredo (`2001::/32`) addresses whose embedded IPv4
    address is not globally routable, and local-use NAT64 (`64:ff9b:1::/48`)
    addresses that embed a non-routable IPv4 address (such as
    `64:ff9b:1::a9fe:a9fe`, which a local NAT64 gateway would translate to the
    metadata address) or are not in the `/96` form.
- The direct `tokio` dependency is dropped; the lookup happens in
  `affinidi-net-guard`.

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

# affinidi-did-web

Minimal `did:web` resolver for the Affinidi TDK.

Implements [W3C did:web](https://w3c-ccg.github.io/did-method-web/) by issuing
a single HTTPS GET against the well-known location for each DID:

- `did:web:example.com` → `https://example.com/.well-known/did.json`
- `did:web:example.com:user:alice` → `https://example.com/user/alice/did.json`
- `did:web:example.com%3A8443` → `https://example.com:8443/.well-known/did.json`

## Why a separate crate?

The upstream [`did-web`](https://crates.io/crates/did-web) crate (spruceid/ssi)
still pins `reqwest = "0.11"` in its 0.5.x line, which transitively pulls
`rustls 0.21` and the vulnerable `rustls-webpki 0.101.x`
([GHSA-xgp8-3hg3-c2mh](https://github.com/advisories/GHSA-xgp8-3hg3-c2mh),
[GHSA-965h-392x-2mh5](https://github.com/advisories/GHSA-965h-392x-2mh5)).
This crate sits on `reqwest 0.13` / `rustls 0.23` and stays consistent with
the other in-workspace DID method crates (`did-ebsi`, `did-scid`,
`didwebvh-rs`).

## Usage

```rust
// One-off lookup
let document = affinidi_did_web::resolve("did:web:example.com").await?;

// Reuse a client across many lookups
let resolver = affinidi_did_web::DIDWeb::new();
let document = resolver.resolve("did:web:example.com:user:alice").await?;

// Configure the client (headers, TLS, connection pool, …). The SSRF guard is
// applied on top of the builder, so nothing set on it can turn the guard off.
// The request timeout is `DEFAULT_TIMEOUT` (20 s) whatever the builder sets.
let builder = reqwest::Client::builder().pool_max_idle_per_host(8);
let resolver = affinidi_did_web::DIDWeb::with_client_builder(
    builder,
    affinidi_did_web::HostPolicy::PublicOnly,
)?;
```

`DIDWeb::with_client`, which takes an already built client, is deprecated: a
built client cannot be given the connect-time guard.

`build_url(domain, path_segments)` is also exposed for callers that need to
compute the document URL without performing the HTTP request.

A document may identify its keys and services, and refer to them, by relative
DID URLs (`"#key-1"`); they are resolved against the document's `id`.

## SSRF and `HostPolicy`

A `did:web` value names the host the resolver fetches from, so a DID supplied
by an attacker can aim it at an internal address. Under the default
`HostPolicy::PublicOnly` the resolver refuses loopback, private, link-local
(including the cloud-metadata address), carrier-grade NAT, `localhost` and
`*.local` hosts, both when the DID names one literally and when a hostname
resolves to one (checked at connect time), and it never follows a redirect or
uses a proxy. `HostPolicy::AllowPrivate` turns that off for deployments whose
did:web hosts really are internal, or for a local test stack
(`did:web:localhost%3A8080`); use it only where the DIDs resolved are trusted.

## License

Apache-2.0

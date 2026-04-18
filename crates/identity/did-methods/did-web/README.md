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

// Bring your own reqwest client (custom timeouts, proxies, headers, …)
let client = reqwest::Client::builder().build()?;
let resolver = affinidi_did_web::DIDWeb::with_client(client);
```

`build_url(domain, path_segments)` is also exposed for callers that need to
compute the document URL without performing the HTTP request.

## License

Apache-2.0

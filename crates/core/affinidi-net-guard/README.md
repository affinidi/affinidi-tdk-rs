# affinidi-net-guard

An egress guard for URLs an attacker can influence, such as a `did:web` host, a
DID document's service endpoint or a redirect `Location`. It stops such a URL
from steering a server-side request at loopback, a private network or a
cloud-metadata address (SSRF).

It is a leaf crate (`reqwest`, `tokio`, `url`, `thiserror`, `tracing`; no
`affinidi-*` dependency), so DID-method crates and external clients can use it
without a dependency cycle.

## Both halves are required

1. **Vet the URL** (`EgressPolicy::vet`): scheme, userinfo, port, allow-list,
   special-use names and IP literals. `reqwest` never consults a DNS resolver
   for an IP-literal host, so this is the only check a literal ever meets.
2. **Vet what a name resolves to** (`GuardedResolver`): every answer is
   checked, one blocked answer fails the name, and the connection is made to
   the checked addresses only, so there is nothing left to rebind.

A proxy resolves names itself and bypasses the second half, so
`GuardedClientBuilder` disables proxies (including `HTTP(S)_PROXY`).

```rust
use affinidi_net_guard::{EgressPolicy, GuardedClientBuilder};

let policy = EgressPolicy::public_internet();
let client = GuardedClientBuilder::new(policy.clone()).build()?;
let url = policy.vet("https://example.com/.well-known/did.json")?;
let response = client.get(&url)?.send().await?;
let body = client.read_body_capped(response).await?;
```

## API

| Item | Purpose |
|---|---|
| `classify`, `is_globally_routable`, `IpClass`, `Embedding` | Pure address classification, including IPv4-mapped/-compatible, NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`), 6to4 and Teredo |
| `EgressPolicy` | `public_internet()`; narrowing `with_allow_list` / `with_schemes` / `with_ports`; `allow_cidrs` for explicit internal ranges; `with_dev_loopback` |
| `DevLoopback` | Token for loopback access, constructible only with the `dev-loopback` feature |
| `VettedUrl` | A URL that passed `vet`; `host()` for operator display, `join_same_origin` |
| `GuardedResolver`, `guarded_dns_resolver` | `reqwest` DNS resolver that vets every answer and pins the connection |
| `RedirectMode`, `redirect_policy` | `None` (default), `SameOrigin`, `ReVet` (hop cap, no https-to-http downgrade) |
| `GuardedClientBuilder`, `GuardedClient` | Both halves on one client: no proxy, finite timeouts, `https_only` unless dev loopback, `read_body_capped` |
| `EgressError`, `blocked_in_chain` | Errors, and recovering a refusal from a `reqwest::Error` |

## Conformance vectors

`conformance/egress-vectors.v1.json` is the vector file shared by the Rust,
TypeScript and Swift guards. The crate's test suite runs every section it has
the capabilities for and skips the rest with a declared reason.

See [ADR 0006](../../../docs/adr/0006-egress-guard-for-attacker-influenceable-urls.md).

## License

Apache-2.0

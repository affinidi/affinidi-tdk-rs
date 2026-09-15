#![forbid(unsafe_code)]
#![warn(missing_docs)]
/*!
# affinidi-net-guard

An egress guard for URLs an attacker can influence: a `did:web` host, a DID
document's service endpoint, a push-subscription endpoint, a redirect
`Location`. Any of them can aim a server-side request at loopback, a private
network or a cloud-metadata address (SSRF).

This crate is deliberately a leaf: it depends on `reqwest`, `tokio`, `url`,
`thiserror` and `tracing`, and on no `affinidi-*` crate, so DID-method crates
and other clients can use it without creating a dependency cycle.

# Both halves are required

A URL is only safe to fetch when **both** checks run.

1. **Vet the URL** with [`EgressPolicy::vet`]. It checks the scheme, userinfo,
   port, operator allow-list, special-use names (`localhost`, `*.local`,
   single-label names, ...) and **IP literals**. Nothing else ever sees a
   literal: `reqwest` (through `hyper-util`) skips any custom DNS resolver when
   the host is already an IP address, so `https://169.254.169.254/` never
   reaches the resolver.
2. **Vet what a name resolves to** with [`GuardedResolver`]. It catches
   `evil.example` with an A record of `169.254.169.254`, fails the whole name
   if *any* answer is blocked, and hands the connector only the addresses it
   checked, so there is no second lookup to rebind.

[`GuardedClient`] runs both. Its request methods take a [`VettedUrl`] and
re-vet it under the client's own policy, and its resolver is a
[`GuardedResolver`].

# Proxies bypass the DNS half

Through an HTTP(S) proxy, the *proxy* resolves the target name, so the
resolver never sees it and only the literal half still applies. `reqwest`
honours `HTTP_PROXY`/`HTTPS_PROXY` by default. [`GuardedClientBuilder`] turns
that off and offers no way to set a proxy. A deployment that must egress
through a proxy needs the proxy itself to enforce the policy.

# Quick start

```no_run
use affinidi_net_guard::{EgressPolicy, GuardedClientBuilder};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let policy = EgressPolicy::public_internet();
let client = GuardedClientBuilder::new(policy.clone()).build()?;

let url = policy.vet("https://example.com/.well-known/did.json")?;
let response = client.get(&url)?.send().await?;
let body = client.read_body_capped(response).await?;
# let _ = body;
# Ok(()) }
```

# What `public_internet()` refuses

* Every address that [`classify`] does not report as globally routable:
  loopback, RFC 1918, link-local (cloud metadata), CGNAT, `0.0.0.0/8`,
  broadcast, multicast, documentation, benchmarking, protocol assignments,
  reserved, unique-local and site-local; and the IPv4-mapped,
  IPv4-compatible, NAT64, 6to4 and Teredo spellings of any of those.
* Special-use names: `localhost`, `*.localhost`, `*.local`, `*.internal`,
  `*.home.arpa` and single-label names, with or without a trailing dot.
* Schemes other than `https` and `wss`, and URLs with userinfo.
* Redirects: a [`GuardedClient`] defaults to [`RedirectMode::None`].

# Narrowing, and the two ways to widen

[`EgressPolicy::with_allow_list`], [`EgressPolicy::with_schemes`] and
[`EgressPolicy::with_ports`] only narrow. Two things widen a policy:

* [`EgressPolicy::allow_cidrs`] re-admits explicit private ranges for internal
  deployments. It never re-admits loopback, link-local, unspecified,
  multicast or broadcast addresses.
* [`EgressPolicy::with_dev_loopback`] admits loopback hosts, and plain
  `http`/`ws` to them. It takes a [`DevLoopback`] token that can only be
  constructed with the `dev-loopback` feature, so a release build without the
  feature cannot opt in.

# Platforms

On `wasm32` only classification and URL vetting are available; the resolver,
redirect policy and client need a native `reqwest`.

# Conformance

`conformance/egress-vectors.v1.json` in this crate is the shared vector file
the Rust, TypeScript and Swift guards all run. This crate's own runner executes
every section it has the capabilities for.
*/

mod cidr;
mod classify;
mod error;
mod policy;

#[cfg(not(target_arch = "wasm32"))]
mod client;
#[cfg(not(target_arch = "wasm32"))]
mod redirect;
#[cfg(not(target_arch = "wasm32"))]
mod resolver;

#[cfg(test)]
mod tests;

pub use cidr::Cidr;
pub use classify::{Embedding, IpClass, classify, is_globally_routable};
pub use error::{EgressError, blocked_in_chain};
pub use policy::{AllowList, DevLoopback, EgressPolicy, HostRule, PortPolicy, Scheme, VettedUrl};

#[cfg(not(target_arch = "wasm32"))]
pub use client::{
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_MAX_BODY, DEFAULT_TIMEOUT, GuardedClient, GuardedClientBuilder,
};
#[cfg(not(target_arch = "wasm32"))]
pub use redirect::{RedirectMode, redirect_policy};
#[cfg(not(target_arch = "wasm32"))]
pub use resolver::{GuardedResolver, guarded_dns_resolver};

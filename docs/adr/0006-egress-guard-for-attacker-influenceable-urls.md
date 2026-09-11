# ADR 0006 — Egress guard for attacker-influenceable URLs

- **Status:** Proposed
- **Date:** 2026-09-11
- **Relates to:** the SSRF guard in `affinidi-did-web` 0.1.4 (`HostPolicy`,
  `guarded_dns_resolver`); [ADR 0003](0003-public-api-semver-policy.md) (semver
  and the external `[patch.crates-io]` coupling); SEC-4045.

## Context

Much of what this workspace fetches is named by data someone else controls. A
`did:web` or `did:webvh` value names the host its document is fetched from; a
DID document names its service endpoints; an HTTP server names its redirect
target. If nothing refuses internal targets, each of these lets whoever controls
the data aim our process at loopback services, a private network, or a
cloud-metadata endpoint (`169.254.169.254`, `fd00:ec2::254`,
`100.100.100.200`): server-side request forgery.

`affinidi-did-web` 0.1.4 closed this for `did:web`, and its guard is the most
complete one in the stack. It checks the host as written, and it also installs a
DNS resolver that refuses any name with a non-routable answer and pins the
connection to the addresses it checked, which closes DNS rebinding. But its
classifier is private to a DID-method crate. Other resolvers and clients, in
this workspace and outside it, either re-implement a weaker check (IP literals
only, IPv4-mapped IPv6 not unwrapped, carrier-grade NAT missing, no name check)
or have none.

Three facts about the HTTP stack shape any fix:

1. **`reqwest` never calls a custom resolver for an IP-literal host.**
   `hyper-util`'s connector parses the host and connects directly if it is an
   address. A resolver-only guard therefore misses `https://169.254.169.254/`.
2. **A proxy resolves the target itself.** With `HTTP(S)_PROXY` set (which
   `reqwest` honours by default), the resolver never sees the name, and only
   the literal check still applies.
3. **Redirects re-open everything** unless each hop is checked again.

The guard also has to be consumable by crates this workspace depends on, such as
`didwebvh-rs`, so it cannot depend on any `affinidi-*` crate.

## Decision

1. **A new leaf crate, `affinidi-net-guard`, in `crates/core/`.** Its
   dependencies are `reqwest` (rustls, no default features), `tokio` (`net`),
   `url`, `thiserror` and `tracing`. No `affinidi-*` dependency.

2. **Two halves, both mandatory, one client that runs both.**
   `EgressPolicy::vet` checks scheme, userinfo, port, allow-list, special-use
   names and literal addresses, and is the only thing that produces a
   `VettedUrl`. `GuardedResolver` checks every resolved address, fails the whole
   name on any blocked answer, and returns only the vetted addresses.
   `GuardedClient` request methods take a `VettedUrl` and re-vet it under the
   client's own policy; the client uses `GuardedResolver`, disables proxies,
   has finite timeouts, does not follow redirects by default, and caps body
   reads.

3. **Deny by default, narrow freely, widen only explicitly.**
   `EgressPolicy::public_internet()` admits `https`/`wss` to globally routable
   addresses only and refuses the special-use names `localhost`, `*.localhost`,
   `*.local`, `*.internal`, `*.home.arpa` and single-label names. The
   allow-list, scheme and port settings only narrow. Internal deployments name
   explicit CIDRs with `allow_cidrs`, which never re-admits loopback,
   link-local, unspecified, multicast or broadcast addresses, and name internal
   hosts with an allow-list entry, whose resolved addresses are still checked.

4. **Loopback for development is compile-gated.** It needs a `DevLoopback`
   token that can only be constructed with the `dev-loopback` Cargo feature. It
   admits only loopback hosts (the literals `127.0.0.0/8` and `::1`, the names
   `localhost` and `*.localhost`) and plain `http`/`ws` to them; a different
   name resolving to loopback stays blocked. It logs a warning once per
   process. No environment variable enables it.

5. **Redirects** are `None` by default. `ReVet { max }` re-vets every hop and
   refuses a secure-to-plaintext downgrade; `SameOrigin { max }` also requires
   the original origin. The DNS half re-applies to each hop automatically,
   because the next host goes through the same resolver.

6. **One conformance vector file**,
   `crates/core/affinidi-net-guard/conformance/egress-vectors.v1.json`, is the
   contract for every implementation of the guard (Rust, TypeScript, Swift).
   Each runner must pass every vector or skip it for a declared missing
   capability; an unknown section or capability fails the run.

7. **Existing guards delegate without changing behaviour in a patch.**
   `affinidi-did-web` keeps its API and its narrower name set, and takes its
   address classification and resolver from the new crate. The classifier
   refuses some additional non-routable ranges; these cannot host a working
   endpoint, and the did-web changelog lists them. Adopting the full special-use
   name set in did-web is a behaviour change, left for its next minor release
   per ADR 0003.

## Consequences

- One classifier and one resolver to review and test, instead of one per
  resolver or client. New egress points should use `GuardedClient`, or
  `affinidi_tdk_common::create_guarded_http_client` to keep the platform TLS
  verifier. Consumer repositories can enforce this with a clippy
  `disallowed-methods` entry for `reqwest::Client::new` and `reqwest::get`.
- A deployment that must egress through a proxy loses the DNS half, and the
  proxy must enforce the policy itself. The crate does not offer a proxy
  setting in 0.1.
- `wasm32` targets get classification and URL vetting only; a browser has no
  resolver hook.
- Not yet provided, and additive when needed: a pinned `connect_tcp` for
  non-`reqwest` transports (WebSocket, TSP), and an explicit proxy mode.
- Follow-ups outside this change: `didwebvh-rs` resolution (client injection
  and the default client's resolver), `WebvhResolver::with_policy` in the
  resolver cache SDK, migrating the agent-names redirect resolver, auditing the
  messaging SDK's DID-document endpoint dials, and the did-web minor release
  that adopts the full name set and replaces `HostPolicy::AllowPrivate` with
  `allow_cidrs`.

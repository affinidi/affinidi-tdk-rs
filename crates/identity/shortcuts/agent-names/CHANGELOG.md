# Changelog

All notable changes to `agent-names` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.3] - 2026-07-23

### Added

- Support for the **community name** — an agent name with an empty local part,
  `example.com/@`, which the agent name FAQ defines as the name of the
  verifiable trust community (VTC) owning the domain and which resolves to that
  community's VTA. It was previously rejected as an "empty local name", so no
  conforming implementation built on this crate could parse, resolve or verify
  one.

- `AgentName::is_community()` — true for `example.com/@`. Preferred over
  testing `local_name()` for emptiness: consumers that key per-agent storage by
  local name generally need to route the community case to the domain's own
  identity instead of writing an empty key.

### Changed

- `example.com/@/path` is still rejected, now with the reason "the community
  name '/@' must not be followed by a path" rather than "empty local name after
  '@'". The FAQ admits the community form "without adding any path except the @
  sign", so a trailing path is malformed rather than a context-qualified
  community name.

The community name is an ordinary agent name otherwise: it canonicalises by the
same rules, and Layer-1 `alsoKnownAs` verification applies unchanged. It is
**not** a prefix of the names beneath it — a document claiming `example.com/@`
does not answer for `example.com/@alice`, nor the reverse.

## [0.1.2] - 2026-07-19

### Added

- `CacheServerResolver` — an `AgentNameResolver` backend that asks an
  `affinidi-did-resolver-cache-server` to map a name to a DID, instead of
  following the redirect locally. Centralising the fetch means it happens once
  for many clients, and the SSRF exposure of fetching caller-supplied URLs sits
  on one hardened host rather than on every client.

  It returns **only a DID**. The mandatory Layer-1 `alsoKnownAs` check is still
  performed by the client against a document the client resolved itself — the
  server is a cache, never a trust anchor. This mirrors how the SDK re-verifies
  `did:webvh` logs locally rather than believing the server's document.

- `AgentNameError::CacheServer { name, status, message }`.

### Fixed

- The cache-server backend now reads the response body as text and parses it
  deliberately, rather than deserializing before checking the status. A server
  without the endpoint (an older build, or `enable_agent_names = false`) answers
  404, and an intermediary may answer with HTML; parsing first turned all of
  those into an opaque deserialization error instead of surfacing the status.

## [0.1.1] - 2026-07-19

### Security

- `HttpRedirectResolver` now refuses names that resolve to **non-public
  addresses** — loopback, RFC1918 private, link-local (including the cloud
  metadata address `169.254.169.254`), carrier-grade NAT, benchmarking,
  documentation and reserved ranges, plus their IPv6 equivalents and
  IPv4-mapped forms such as `::ffff:127.0.0.1`. Controlled by
  `allow_private_addresses(bool)`, **off by default**; the check runs on
  **every** redirect hop, since a public host can redirect inward.

  This matters most when the resolver runs **server-side**: an agent name is
  attacker-supplied, so without this a caller could make the DID cache server
  issue requests from inside your network. It is a prerequisite for exposing
  agent name resolution on the cache server.

  **Limitation, stated plainly:** the check resolves the host and inspects the
  addresses it gets *now*; the subsequent request resolves again. A hostile DNS
  server can answer differently for the two lookups (**DNS rebinding**) and
  reach an internal address anyway. Closing that requires pinning the checked IP
  into the connection, which `reqwest` does not expose. This raises the cost of
  SSRF; it does not eliminate it. Do not rely on it as the only control at an
  untrusted network boundary.

- New `AgentNameError::BlockedAddress { name, address }`.

### Known gaps

- The *mid-chain* address check (a public host redirecting inward) is not
  integration-tested, for the same reason as the mid-chain HTTPS check:
  `wiremock` binds `127.0.0.1`, so the entry point is itself private and the
  test would pass for the wrong reason. The per-hop logic is covered by
  `is_public` unit tests.

## [0.1.0] - 2026-07-19

Initial release. Agent names — human-memorable shortcuts of the form
`example.com/@alice` that resolve to DIDs.

### Added

- `AgentName`: parsing, validation and canonicalisation. Canonicalises a missing
  scheme to `https`, the host to lowercase, a default port away, and a trailing
  slash away; deliberately preserves the case of the local name so `@Alice` and
  `@alice` stay distinct identities.
- `AgentName::looks_like_agent_name`: cheap `/@` marker test with no network
  access, for deciding whether an identifier is a DID or a shortcut. Does not
  match a bare `@handle` (agent names are always rooted in a domain) or an email
  address (which has `@` but not `/@`).
- `verify_also_known_as` / `also_known_as_contains`: the **mandatory** Layer-1
  anti-spoofing check. Both sides are canonicalised before comparison; matching
  is exact afterwards, with no prefix or wildcard matching.
- `extract_agent_names`: the authoritative DID → name direction, reading a
  resolved document's `alsoKnownAs`.
- `AgentNameResolver` trait: the pluggable backend seam. Returns
  `Option<Result<..>>` mirroring `affinidi-did-resolver-traits`' `Resolution`, so
  a chain of name backends reads like a chain of DID method resolvers.
- `HttpRedirectResolver`: the default backend, following the web redirect a name
  serves. Redirects are not auto-followed — each hop is inspected explicitly, so
  the hop cap and per-hop HTTPS check are enforceable (mirroring
  `affinidi-did-web`'s SSRF hardening). Plain HTTP is refused unless
  `allow_insecure_http(true)`.
- `AgentNameError`, `#[non_exhaustive]`.

### Notes on what is deliberately absent

- **Layer 2 (the agent name credential)** is not implemented. Layer 1 stops an
  unrelated party pointing a name they control at a DID they do not; it does not
  survive DNS poisoning or a breach of the name's own web server. The
  `AgentNameResolver` trait is where Layer 2 would attach.
- **No DID → candidate-name construction.** The name→DID link is a web redirect
  and is not derivable from DID structure, even for domain-based methods like
  `did:web`, so such a helper would manufacture unverified guesses behind an
  authoritative-looking API.

### Known gaps

- **The redirect contract is unverified against a live implementation.** The
  agent name FAQ does not specify the status code, the form the DID arrives in,
  or any content negotiation, and there is no reference implementation to test
  against (`firstperson.network` is live, but its example names return 404).
  `HttpRedirectResolver` is therefore permissive, and all of that guesswork is
  confined to it.
- **The specification defines no canonical form**, so the canonicalisation rules
  here are this implementation's choice. Two implementations that normalise
  differently will disagree about whether a name verifies.
- The mid-chain HTTPS-downgrade check is not integration-tested: doing so needs
  a TLS-capable mock server, and `wiremock` serves plain HTTP only.

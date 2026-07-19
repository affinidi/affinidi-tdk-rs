# Changelog

All notable changes to `agent-names` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

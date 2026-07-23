# agent-names

Human-memorable shortcuts that resolve to DIDs.

A DID is unmemorable. An **agent name** is a URL whose path begins with `/@` and
which resolves to one:

```text
example.com/@alice
connect.me/@bob
names.somewhere.info/@john-smith
firstperson.network/@drummond/h2hsummit   # trailing path adds context
example.com/@                             # the domain's own community
```

A name with an empty local part is the **community name**: it belongs to the
verifiable trust community (VTC) owning the domain and resolves to that
community's VTA. It takes no path — `example.com/@/anything` is malformed — and
`AgentName::is_community()` identifies it. It is otherwise an ordinary agent
name, and is **not** a prefix of the names beneath it: claiming `example.com/@`
does not let a document answer for `example.com/@alice`.

An agent name is **not** a DID method. It is a shortcut layer in front of DID
resolution, and the specification anticipates other shortcut kinds later — hence
`crates/identity/shortcuts/`.

## Resolution is two-stage, and the second stage is the point

1. The agent name URL redirects to a DID.
2. The DID resolves to a DID Document as usual.
3. **The document must claim the name back via `alsoKnownAs`.**

Step 3 is mandatory. Step 1 is served by the name's own web server, so by itself
it proves nothing — anyone can publish a redirect pointing at somebody else's
DID. Only the DID's controller can add an `alsoKnownAs` entry, so requiring both
directions is what makes the binding real.

```rust
use agent_names::{AgentName, AgentNameResolver, HttpRedirectResolver, verify_also_known_as};

let name: AgentName = "example.com/@alice".parse()?;

// Stage 1
let resolver = HttpRedirectResolver::new();
let did = resolver.resolve(&name).await.unwrap()?;

// Stage 2: resolve `did` with your DID resolver, then stage 3:
verify_also_known_as(&document, &name)?;
```

Most callers should not drive these stages by hand — `DIDCacheClient::resolve_any()`
wires them together with the resolution cache and performs step 3 for you. This
crate is the standalone, dependency-light half, usable without the resolver.

### What Layer 1 does and does not buy you

It stops an unrelated party from pointing a name they control at a DID they do
not. It does **not** survive DNS poisoning or a breach of the name's own web
server: an attacker with either can serve a redirect to a DID they control whose
document legitimately claims the name.

Defending against that is Layer 2 — the *agent name credential*, a verifiable
presentation with a nonce requested from the DID's `whois` endpoint or its VTA
service endpoint. This crate does not implement Layer 2; the `AgentNameResolver`
trait is the seam where it would attach.

## Canonicalisation

Layer-1 verification compares the name a caller typed against a string in
somebody else's DID Document, so the two must normalise identically or the check
fails for cosmetic reasons. `AgentName` normalises:

| Input | Canonical |
|---|---|
| `example.com/@alice` | `https://example.com/@alice` |
| `EXAMPLE.COM/@alice` | `https://example.com/@alice` |
| `https://example.com:443/@alice` | `https://example.com/@alice` |
| `https://example.com/@alice/` | `https://example.com/@alice` |

The local name keeps its case: `@Alice` and `@alice` are **different** names, and
folding them could merge two distinct identities.

Verification also accepts the scheme-less spelling (`example.com/@alice`) in
`alsoKnownAs`, since that is how names are written in prose. Matching is exact
after canonicalisation — there is deliberately no prefix or wildcard matching, so
`@alice` is never satisfied by `@alicia`, and a path-qualified name is never
satisfied by its bare parent.

**The specification does not define a canonical form.** These rules are this
implementation's choice, and they are the single highest-value thing for the spec
to pin down — without them, two implementations disagree about whether a name
verifies.

## Status: the redirect contract is not pinned down

The agent name FAQ says resolution "typically works through a simple web
redirect" without specifying the status code, the form the DID arrives in, or any
content negotiation — and there is no reference implementation to check against
(`firstperson.network` is live, but its example names return 404).

`HttpRedirectResolver` is therefore deliberately permissive:

- any 3xx carrying a `Location` header (301/302/303/307/308);
- the DID accepted as a bare `did:…`, a `did=` query parameter, or a
  percent-encoded final path segment;
- up to 5 hops, so an apex→`www` redirect on the way does not break resolution.

All of that guesswork is confined to this one type. Parsing, canonicalisation and
verification do not depend on how the DID was obtained, so pinning the contract
down later should not disturb them.

## Security

- Redirects are **not** followed automatically; each hop is inspected explicitly,
  which is what makes the hop cap and the per-hop HTTPS check enforceable. This
  mirrors `affinidi-did-web`'s SSRF hardening.
- Plain HTTP is refused unless `allow_insecure_http(true)` is set. That switch is
  for local development and tests only.
- Names resolving to **non-public addresses** (loopback, private, link-local
  including `169.254.169.254`, and their IPv6/IPv4-mapped forms) are refused
  unless `allow_private_addresses(true)`. Checked on every hop, since a public
  host can redirect inward. This matters most server-side, where the name is
  attacker-supplied and the request originates inside your network.

  It is **not** complete SSRF protection: the check and the request resolve DNS
  separately, so DNS rebinding can still reach an internal address. It raises
  the cost; it does not close the hole.

## DID → name

`extract_agent_names(&document)` returns the names a document claims. That is the
only supported direction.

There is deliberately **no** helper that builds a likely agent name from a
`did:web` / `did:webvh` domain. The name→DID link is a web redirect and is not
derivable from DID structure, so such a helper would manufacture unverified
guesses behind an authoritative-looking API — exactly the spoofing Layer 1 exists
to prevent.

## License

Apache-2.0

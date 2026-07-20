# Affinidi DID Resolver Cache Server

## Changelog history

## 20th July 2026

### 0.9.7 — per-IP rate limiting

The server previously had **no rate limiting of any kind**. It now applies a
per-IP token bucket, via the shared `affinidi-rate-limit` crate extracted from
the mediator.

#### ⚠ On by default — check this before upgrading

`rate_limit_per_ip` defaults to **100 req/s per IP, burst 50**, matching the
mediator. That is generous for a resolver cache, whose whole purpose is that most
lookups are served from memory.

**But raise or disable it behind a load balancer or NAT.** The limiter keys on
the peer address, so if you terminate TLS or route through a CDN, the only
address this server sees is the proxy's — every client shares one bucket and
legitimate traffic gets 429s. Set `rate_limit_per_ip = "0"` to disable.

An unparseable value falls back to the default rather than to 0, so a config typo
cannot silently remove limiting. An explicit `"0"` still disables.

#### Behaviour

- Over-quota requests get `429` with an accurate `Retry-After`, taken from
  `governor`'s estimate of when the next token arrives, floored at 1 second.
- A request whose client IP cannot be determined is **refused with 403**, not
  exempted — failing open would make per-IP limiting trivially bypassable. The
  server already binds with `into_make_service_with_connect_info`, so this only
  bites if that is ever removed.
- The layer sits outermost, so a throttled client costs nothing beyond the
  token-bucket check. It wraps the healthcheck route too, deliberately: an
  unlimited healthcheck is itself a cheap way to hold connections open.
- The keyed bucket store is swept periodically. Without that it grows once per
  source IP for the process lifetime — see the `affinidi-rate-limit` README.

This complements, rather than replaces, `agent_name_concurrency` (0.9.6). Rate
limiting bounds what any one client can ask for; the concurrency cap bounds total
outbound fan-out however many clients ask.
## 20th July 2026

### 0.9.6 — bound the agent name endpoint's outbound fetches

Adds `agent_name_concurrency` (default **16**): a ceiling on how many agent name
lookups may be fetching upstream at once.

Agent name resolution turns one cheap inbound request into one outbound HTTP
request to a host the *caller* chose. Without a ceiling that is an amplification
primitive — a shared cache server can be driven to fan out arbitrary traffic at
third parties, or used to scan them, at a cost to the attacker of one request
each.

The cap bounds that fan-out **however many source addresses the load arrives
from**, which is the property per-IP rate limiting cannot give you. Requests over
the ceiling are shed with `503` rather than queued: queueing would convert a
fetch ceiling into an unbounded backlog of pending outbound requests, which is
the thing being defended against.

A zero or unparseable value falls back to the default rather than meaning "no
limit", so a config typo cannot silently remove the ceiling.

Note this is **not** general rate limiting — the server still has none, and that
remains worth adding. This bounds the *outbound* amplification specifically,
which is the harm this endpoint can do to third parties rather than to itself.
## 19th July 2026

### 0.9.5 — agent name lookup endpoint

Adds `GET /did/v1/resolve-name/{*name}`, mapping an agent name
(`example.com/@alice`) to a DID.

**Off by default.** Set `enable_agent_names = "true"` to enable it.

#### Scope: it returns a DID, not a document

Following the redirect is the network-facing, cacheable half of agent name
resolution and is worth centralising; turning the resulting DID into a document
is already served by `/resolve/{did}`.

More importantly it keeps the trust model honest. The mandatory Layer-1 check —
that the resolved document's `alsoKnownAs` claims the name — must be performed
by the **client**, against a document the client resolved itself. A server
answering "here is the name, the DID, and the document, and I promise they
agree" would be asking to be trusted as an authority. It is a cache, never a
trust anchor, matching how clients re-verify `did:webvh` logs rather than
believing the server.

#### Why it is off by default

The name is entirely caller-supplied, so this endpoint makes the server issue an
HTTP request to a host of the caller's choosing. Mitigations:

- the flag itself, defaulting to off (and to off on a parse failure, so an
  unreadable config value cannot silently enable a network-facing fetch);
- the resolver refuses non-public addresses — loopback, private, link-local,
  cloud metadata — on **every** redirect hop.

Neither is complete: the address check and the request resolve DNS separately,
so DNS rebinding remains possible. Note also that this server still has **no
rate limiting**, so an enabled endpoint is an unmetered outbound fetch primitive.
Enable it only if you accept that.

#### Also

- Statistics gain `agent_name_success` / `agent_name_error`, reported in the
  periodic log line.
- Response shape: `200 {"name": "<canonical>", "did": "<did>"}`. The canonical
  name is echoed so callers can see what normalisation did. Errors are `400`
  (malformed / oversize), `404` (no backend resolved it), `502` (upstream
  failure, including a blocked address) and `504` (timeout).
- The route uses a wildcard capture because an agent name contains slashes,
  which a single path segment cannot match. `/resolve/{did}` is untouched.
## 19th July 2026

### 0.9.4 — didwebvh-rs 0.6

- Bumped the `didwebvh-rs` requirement from `"0.5"` to `"0.6"`.

  0.6.0 requires `affinidi-did-common "0.4"`. Until now `didwebvh-rs 0.5.7`
  still required `"0.3"`, so the workspace carried **two** copies of
  `affinidi-did-common` (0.3.9 and 0.4.0); it compiled only because no types
  cross the `didwebvh-rs` boundary — `WebvhResolver` builds its own `Document`
  via `serde_json::from_value`. This collapses the graph back to a single
  `affinidi-did-common 0.4.0`.

  0.6.0 is a breaking release (`DIDWebVHError`, `URLType` and
  `LogEntryValidationStatus` became `#[non_exhaustive]`), but no code change was
  needed here: the only use is a `#[from] DIDWebVHError` conversion in
  `did-scid`'s error type, not an exhaustive `match`.

## 19th July 2026

### 0.9.3 — affinidi-did-common 0.4

- Bumped the `affinidi-did-common` requirement from `"0.3"` to `"0.4"`.
  No functional change to this crate: `Document` gained a typed
  `also_known_as` field, which is additive.

## 14th June 2026

### 0.9.2 — non_exhaustive error enums (W7 sweep)

- `CacheError` and `SessionError` are now `#[non_exhaustive]` (ADR-0003) so new
  variants land additively. Patch bump keeps the `0.9` pin valid; consumers that
  `match` them must add a `_` arm. No behaviour change.

## 13th June 2026

### 0.9.1 — statistics task on the shared supervisor (W15)

- The statistics task is now supervised by the shared `affinidi-task-utils`
  `TaskSupervisor` instead of a bare `tokio::spawn`. A panic or error restarts
  it with capped exponential backoff and is logged with its restart history;
  its lifecycle is tracked in the supervisor's health registry. The task is
  non-load-bearing — a wedged stats loop never takes the resolver down. The W2
  manual cancel/join wiring is replaced; behaviour on shutdown is unchanged.

### 0.9.0 — request limits, CORS tightening, task supervision, client reuse (W2)

- **DID size limit.** New `max_did_size` setting (default 1024 bytes,
  `MAX_DID_SIZE`). Oversized DIDs are rejected before resolution — HTTP `400`
  on `/resolve/{did}`, a WebSocket error response on `/ws` — and the WebSocket
  upgrade caps frame/message size to the DID limit plus envelope overhead.
- **CORS tightened to GET.** The server only exposes GET endpoints, so the CORS
  layer no longer advertises POST/PUT/DELETE/PATCH (origin stays `Any` — DID
  documents are public).
- **Statistics task supervised.** The stats loop is now cancellation-aware and
  exits cleanly on shutdown; the server installs a Ctrl-C handler that cancels
  background tasks and gracefully drains in-flight requests
  (`axum_server` graceful shutdown), then joins the stats task so a panic is
  logged rather than swallowed.
- **Shared WebVH HTTP client.** `fetch_webvh_log` now takes a single
  `reqwest::Client` built once at startup (pooled connections) instead of
  constructing a fresh client per request.
- New `pub` fields `SharedData.max_did_size` / `SharedData.webvh_client`
  (minor-version bump).

### 0.8.0 — remove request/startup panics, bound upstream resolution (W1)

- **No more panics on the request path.** The four
  `serde_json::to_string(..).unwrap()` calls in the WebSocket handler — a
  serialization failure used to panic the per-connection task — now serialize
  safely and close the connection gracefully on failure. The duplicated
  text/binary resolve-and-respond blocks are consolidated into shared
  `resolve_and_respond` / `send_response` helpers.
- **Bounded upstream resolution.** Both the HTTP (`/resolve/{did}`) and
  WebSocket handlers wrap `resolver.resolve()` in a timeout, so a hung upstream
  returns a clean error to the client instead of blocking the request/socket.
  Configurable via the new `resolve_timeout` setting (default 30s,
  `RESOLVE_TIMEOUT` env var).
- **No more startup panics.** Config-init failure, an invalid `listen_address`,
  and a server bind/serve error now propagate as `DIDCacheError` instead of
  `unwrap()`/`expect()`. The statistics task logs its error instead of
  `expect()`-panicking (full supervision lands in W2).
- `errors.rs`: the `StatusCode::from_u16(..).unwrap()` in `IntoResponse`
  defaults to `500` instead of panicking.
- New `pub` field `SharedData.resolve_timeout` (minor-version bump).

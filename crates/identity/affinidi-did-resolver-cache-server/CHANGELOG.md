# Affinidi DID Resolver Cache Server

## [0.11.2] - 2026-11-15

Server-side error detail stays in the logs (AgenticSec #530)

- A `5xx` response (`500`, `502`, `504`) from `/did/v1/resolve/{did}` and
  `/did/v1/resolve-name/{*name}` used to carry the internal error text
  (upstream URLs, transport errors, resolver internals). It now carries a
  generic message and a `reference` correlation id
  (`{"error": "...", "reference": "<id>"}`); the detail is logged at `warn`
  under the same reference. WebSocket error responses follow the same rule,
  with the reference in the error text. `4xx` errors keep their detail: it
  describes the caller's own request.
- **Behaviour note (R3.6):** the body of a server-side error changes. Clients
  that parsed the error text of a `5xx` (or of a WebSocket error for a
  server-side failure) see the generic message instead; statuses are
  unchanged. `affinidi-did-resolver-cache-sdk` clients in network mode receive
  that text as `DIDCacheError::TransportError`.

## [0.11.1] - 2026-11-15

Workspace lint and dependency housekeeping. No API or behaviour change.

- Dependency versions now come from the root `[workspace.dependencies]`
  for the external crates shared by five or more workspace members
  (#1070). The published manifest still names concrete requirements; the
  resolved dependency graph and every feature selection are unchanged.
- Workspace lints now include `unsafe_code = "deny"` (#1064).
- Minimum dependency requirements raised to versions already in use across the
  workspace (no new major/minor, Cargo.lock unchanged): `affinidi-did-common`
  0.4 -> 0.4.8, `affinidi-did-resolver-cache-sdk` 0.8.47 -> 0.8.55,
  `affinidi-secrets-resolver` 0.5 -> 0.5.19, `agent-names` 0.1.2 -> 0.1.4,
  `didwebvh-rs` 0.8 -> 0.8.1.

## [0.11.0] - 2026-11-15

concurrent WebSocket requests; strict config values; HTTP statuses

Breaking: unused public modules removed, response codes and config parsing
changed (R3.6).

- **Changed — WebSocket requests on one connection are resolved concurrently**
  (#1048). Each runs in its own task and its response is sent as soon as it is
  ready, through one writer per connection, so a slow or blackholed DID host no
  longer holds up every request behind it. Responses can now arrive out of
  order (the SDK has always matched them by hash). New config key
  `ws_max_inflight_per_connection` (default 32): past it, the server stops
  reading the connection until a request finishes. `WsLimits` gains the
  `max_inflight_per_connection` field and `with_max_inflight_per_connection`;
  `Config` gains `ws_max_inflight_per_connection`.
- **Behaviour (stricter) — a config value that does not parse fails startup**
  with an error naming the key and the value (#1051). Before, every value fell
  back to a default silently: `enable_http_endpoint = "False"` or `"no"`
  *enabled* the endpoint, and a typo in a timeout, cache size or rate limit
  went unnoticed. Booleans accept `true`/`false`/`yes`/`no`/`on`/`off`/`1`/`0`
  in any case; `log_level` must be one of trace/debug/info/warn/error. `0`
  still keeps the default for the ceilings (`ws_max_connections`,
  `ws_max_connections_per_ip`, `ws_idle_timeout`, `ws_send_timeout`,
  `agent_name_concurrency`) and still disables rate limiting. A deployment
  that relied on a typo being ignored now fails to start.
- **Fixed:** a read or UTF-8 error in the config file fails the load (naming
  the line) instead of silently truncating the file; two `${VAR:default}`
  references on one line expand separately (the default no longer runs to the
  last `}` on the line).
- **Changed — `GET /did/v1/resolve/{did}` answers with a status that says whose
  fault a failure is** (#1053): `400` for a malformed DID or unsupported
  method, `404` when the DID's host answered 404/410, `502` for any other
  upstream failure, `504` for a resolution timeout, `500` only for this
  server's own faults. Every failure was `500`, logged at `error`; client
  errors now log at `debug`, server-side ones at `warn`.
- **Removed (breaking):** the unused `session` module (`Session`,
  `SessionError`), and from `errors`: `AppError`, `ErrorResponse`,
  `SuccessResponse` and the `CacheError::{ErrorHandlingError, ParseError,
  DIDError}` variants; `common::GenericDataStruct`. None was used by any
  handler. `SharedData`'s extractor rejection is now `Infallible`.
- Docs: `conf/cache-conf.toml` says what each endpoint key enables (the WS
  route is `/did/v1/ws`), the `statistics_interval` default matches the
  shipped value, and the comments say an unparseable value fails startup.
  README documents the HTTP statuses and the WebSocket concurrency.

## [0.10.0] - 2026-11-12

config keys read where written; WebSocket limits

Breaking (R3.6): the config file is checked strictly, and `SharedData` and
`Config` have new public fields.

- **Fixed:** the shipped `conf/cache-conf.toml` set `rate_limit_per_ip` and
  `rate_limit_burst` after the `[cache]` header, which in TOML makes them
  `cache.rate_limit_per_ip` / `cache.rate_limit_burst`. The loader reads them
  at the top level, so both were dropped and the built-in defaults (100 / 50)
  applied whatever the file or `RATE_LIMIT_PER_IP` / `RATE_LIMIT_BURST` said.
  They are now above `[cache]` and take effect.
- **Behaviour (stricter):** an unknown key at the top level or in `[cache]`
  fails startup with an error naming the key, instead of being ignored. A
  config file copied from an earlier release that still has the two keys under
  `[cache]` fails to start until they are moved above it.
- **Changed:** WebSocket request messages are charged to the client's
  rate-limit bucket, the same one its HTTP requests use (before, only the
  upgrade request was charged). A message over the limit gets a
  `WSResponseError` for that request ("Too many requests; retry after Ns") and
  the connection stays open.
- **Added:** WebSocket connection limits, each a config key:
  - `ws_max_connections` (default 4096): over it, a new connection is refused
    with 503 before the upgrade.
  - `ws_max_connections_per_ip` (default 64): per client address; over it,
    429 before the upgrade.
  - `ws_idle_timeout` (default 120 s): a connection that receives no frame
    (pings included) for this long is closed with code 1001. The resolver SDK
    pings every 20 s and reconnects on close.
  - `ws_send_timeout` (default 10 s): a response send that does not finish in
    time closes the connection.
  - `ws_max_message_size` (default `0`: `2 * max_did_size + 1024`, 3072 bytes
    with the default `max_did_size`; it was `max_did_size + 1024`): the largest
    message and frame accepted.
  For the four limits, `0` or an unparseable value keeps the default.
- **Added:** `trusted_proxies` (comma-separated CIDRs; default empty) and
  `client_ipv6_prefix` (default 64). Behind listed proxies the client is read
  from `X-Forwarded-For`, for the HTTP rate limit, the WebSocket message charge
  and the per-address connection cap alike. IPv6 clients are now charged and
  counted by their /64 instead of by address. An invalid value, or a `/0`
  range, fails startup.
- **Changed:** an error reading from a WebSocket (an oversized message among
  them) closes the connection instead of being logged and skipped.
- **Changed (API):** `SharedData` gains `rate_limiter`, `client_ip_extractor`
  and `ws_limits`; `Config` gains the settings above and
  `Config::client_ip_extractor()`. New `limits` module (`WsLimits`,
  `ConnectionSlot`, `ConnectionRefused`) and `config::parse_config_str`.

## [0.9.16] - 2026-11-09

did:webs

Resolves `did:webs`: the SDK's `did-webs` feature is on, and the SDK floor is
0.8.47. A did:webs resolves only when its KERI key event log verifies and the
published `did.json` matches the verified key state. Like did:web, did:webvh
and did:scid, it fetches only from public hosts under the default
`HostPolicy::PublicOnly`, follows no redirect and uses no proxy.

## [0.9.15] - 2026-10-01

didwebvh-rs 0.8

Moves to `didwebvh-rs` 0.8 (on `affinidi-data-integrity` 0.8), and picks up
`affinidi-did-resolver-cache-sdk` 0.8.41. No behaviour change.

## [0.9.14] - 2026-09-16

raw did:webvh log cache

- Adds an optional TTL cache for the raw `did:webvh` logs (`did.jsonl` and
  `did-witness.json`) that this server attaches to every WebVH resolution.
  Those side-files are otherwise re-fetched from the DID's own host on *every*
  resolution — document-cache hits included, because the DID *document* cache
  does not cover them — so a hot did:webvh DID generates continuous upstream
  traffic and can be rate-limited by its host. With the cache enabled a
  document cache hit costs zero upstream requests.
- New config `cache.webvh_log_expire` (env `WEBVH_LOG_EXPIRE`), TTL in seconds.
  **Default `0` disables the cache**, preserving the previous
  fetch-on-every-resolution behaviour; set it to `0` when tests must observe a
  newly-published log entry immediately.
- Only successful fetches are cached: a failed or rate-limited upstream
  response is never cached, so a transient blip cannot be pinned for the whole
  TTL. The cache is keyed by DID and bounded by entry count
  (`cache.capacity_count`), not by bytes; each log is capped at 1 MiB on fetch.
- The cached log tracks the document: a cached log is served only alongside a
  DID *document* that was itself a cache hit. On a document cache miss the
  server has just resolved a fresh `did:webvh` document (a freshly-replayed
  log), so it refetches the raw log and refreshes the cache rather than serving
  a possibly-stale entry — otherwise the returned document and its attached
  `_did_log` could disagree and a verifying client would reject the pair.
- The upstream log fetch is single-flighted (moka `try_get_with`): N concurrent
  resolutions of the same cold DID — for a brand-new hot DID, all document
  cache misses — collapse into one request against the DID's host instead of a
  stampede.
- `webvh_log_expire` is clamped to `cache.expire` (the document TTL). A cached
  log is only served with a still-cached document, and a document refresh
  already refreshes the log, so a larger value buys nothing; keep it
  `<= cache.expire`.

## [0.9.13] - 2026-09-12

did:webvh host policy

- Bumps `didwebvh-rs` 0.6 → 0.7 and requires `affinidi-did-resolver-cache-sdk`
  0.8.37. did:webvh resolution through this server now refuses non-public
  hosts, as did:web resolution already did (see the SDK's 0.8.37 entry).
- The client that fetches `did.jsonl` and `did-witness.json` for `_did_log` /
  `_did_witness_log` now matches the one `didwebvh-rs` builds:
  - it ignores system proxy settings;
  - it resolves names through `didwebvh_rs::resolve::guarded_dns_resolver()`,
    which refuses a name when any resolved address is non-public;
  - it still refuses redirects.

  The fetch URLs come from `WebVHURL::get_fetch_url` under
  `HostPolicy::PublicOnly`, instead of from `get_http_url`.
- **Behaviour:** a deployment that can reach did:webvh hosts only through
  `HTTP(S)_PROXY` can no longer resolve did:webvh DIDs or attach their logs.

## [0.9.12] - 2026-08-23

dependency refresh

- Bumps `tower-http` 0.6 → 0.7.
- No source or API change; the bumps are declaration-only and the crate
  compiles unmodified against them. Bumped workspace-wide in the same
  change so no two versions of these crates are compiled side by side.

## [0.9.11] - 2026-08-22

`did:jwk` is actually served

- **Enables the SDK's `did-jwk` feature.** The README has listed `did:jwk`
  among the methods this server resolves, and the dependency comment claimed
  full method coverage, but SDK 0.8.22 moved the method behind a feature and
  only `did-ethr` and `did-pkh` were opted back in — so `did:jwk` has not been
  compiled into the server since. It now is.

- Picks up SDK 0.8.23, in which `did:ethr`, `did:pkh` and `did:jwk` resolve via
  in-tree crates rather than the `ssi-*` stack. `did:ethr` and `did:pkh`
  documents are byte-for-byte unchanged; `did:jwk` now follows the method
  specification (`JsonWebKey2020` / `publicKeyJwk`) instead of the `Multikey` /
  `publicKeyMultibase` shape the replaced crate emitted. Malformed `did:ethr`
  and `did:pkh` identifiers are now rejected rather than resolved into a
  document naming an account that cannot exist.

## [0.9.10] - 2026-08-02

Opts back in to `did:ethr` and `did:pkh`, which became optional in
`affinidi-did-resolver-cache-sdk` 0.8.22.

Those methods pull the `ssi-*` stack (and with it a second generation of the
elliptic-curve crates), which most libraries embedding the SDK do not want — so
the SDK now gates them off by default. This is a general-purpose resolver
*service*, not an embedded library, so it keeps full method coverage and accepts
that cost. **No change in what this server resolves.**

## Changelog history

## [0.9.9] - 2026-07-20

agent name resolution over WebSocket

A `WSRequest` carrying `agent_name` is now resolved name → DID → document in one
exchange, matching `GET /did/v1/resolve-name/{*name}` but on the connection the
client already holds.

Gated by the same `enable_agent_names` flag and subject to the same
`agent_name_concurrency` ceiling as the HTTP endpoint, including shedding rather
than queueing when saturated.

### The correlation rule

The response's `hash` is the hash of the **name as sent**, not of the resolved
DID. Clients register their waiter under the hash of what they sent and
`ws_recv` drops frames it cannot correlate — so hashing the resolved DID instead
would leave every caller waiting out its full timeout with no error. `did`
carries the resolved DID and `agent_name` echoes the name.

### Still a cache, not a trust anchor

No `alsoKnownAs` verification is performed or claimed here. The client re-verifies
against the document it received, exactly as it re-verifies `did:webvh` logs.
## [0.9.8] - 2026-07-20

build WebSocket responses via constructors

Follows `affinidi-did-resolver-cache-sdk 0.8.18`, which sealed the WebSocket wire
types. `build_response` and the two error paths now use `WSResponse::new` /
`with_logs` and `WSResponseError::new` instead of struct literals.

No behaviour change; the emitted frames are byte-identical.
## [0.9.7] - 2026-07-20

per-IP rate limiting

The server previously had **no rate limiting of any kind**. It now applies a
per-IP token bucket, via the shared `affinidi-rate-limit` crate extracted from
the mediator.

### ⚠ On by default — check this before upgrading

`rate_limit_per_ip` defaults to **100 req/s per IP, burst 50**, matching the
mediator. That is generous for a resolver cache, whose whole purpose is that most
lookups are served from memory.

**But raise or disable it behind a load balancer or NAT.** The limiter keys on
the peer address, so if you terminate TLS or route through a CDN, the only
address this server sees is the proxy's — every client shares one bucket and
legitimate traffic gets 429s. Set `rate_limit_per_ip = "0"` to disable.

An unparseable value falls back to the default rather than to 0, so a config typo
cannot silently remove limiting. An explicit `"0"` still disables.

### Behaviour

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
## [0.9.6] - 2026-07-20

bound the agent name endpoint's outbound fetches

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
## [0.9.5] - 2026-07-19

agent name lookup endpoint

Adds `GET /did/v1/resolve-name/{*name}`, mapping an agent name
(`example.com/@alice`) to a DID.

**Off by default.** Set `enable_agent_names = "true"` to enable it.

### Scope: it returns a DID, not a document

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

### Why it is off by default

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

### Also

- Statistics gain `agent_name_success` / `agent_name_error`, reported in the
  periodic log line.
- Response shape: `200 {"name": "<canonical>", "did": "<did>"}`. The canonical
  name is echoed so callers can see what normalisation did. Errors are `400`
  (malformed / oversize), `404` (no backend resolved it), `502` (upstream
  failure, including a blocked address) and `504` (timeout).
- The route uses a wildcard capture because an agent name contains slashes,
  which a single path segment cannot match. `/resolve/{did}` is untouched.
## [0.9.4] - 2026-07-19

didwebvh-rs 0.6

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

## [0.9.3] - 2026-07-19

affinidi-did-common 0.4

- Bumped the `affinidi-did-common` requirement from `"0.3"` to `"0.4"`.
  No functional change to this crate: `Document` gained a typed
  `also_known_as` field, which is additive.

## [0.9.2] - 2026-06-14

non_exhaustive error enums (W7 sweep)

- `CacheError` and `SessionError` are now `#[non_exhaustive]` (ADR-0003) so new
  variants land additively. Patch bump keeps the `0.9` pin valid; consumers that
  `match` them must add a `_` arm. No behaviour change.

## [0.9.1] - 2026-06-13

statistics task on the shared supervisor (W15)

- The statistics task is now supervised by the shared `affinidi-task-utils`
  `TaskSupervisor` instead of a bare `tokio::spawn`. A panic or error restarts
  it with capped exponential backoff and is logged with its restart history;
  its lifecycle is tracked in the supervisor's health registry. The task is
  non-load-bearing — a wedged stats loop never takes the resolver down. The W2
  manual cancel/join wiring is replaced; behaviour on shutdown is unchanged.

## [0.9.0] - 2026-06-13

request limits, CORS tightening, task supervision, client reuse (W2)

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

## [0.8.0] - 2026-06-13

remove request/startup panics, bound upstream resolution (W1)

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

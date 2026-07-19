# Affinidi DID Resolver Cache Server

## Changelog history

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

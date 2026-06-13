# Affinidi DID Resolver Cache Server

## Changelog history

## 13th June 2026

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

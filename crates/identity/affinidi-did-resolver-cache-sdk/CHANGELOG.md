# Affinidi DID Resolver Cache SDK

## Changelog history

## 13th June 2026

### 0.8.8 — client resilience: no-panic init, local fallback, stampede dedup (W3)

- **Construction never panics or hangs.** The startup wait for the network task
  to connect replaces `rx.recv().await.unwrap()` with a bounded wait
  (`network_timeout`): on `Connected` it's ready; on timeout (server
  unreachable) it continues in **degraded mode** while the task keeps
  reconnecting with backoff; if the task dies before signalling, `new()` returns
  an `Err` instead of panicking the caller.
- **Local fallback in network mode.** When the cache server is unreachable, a
  network resolution failure for the deterministic methods **did:key / did:peer**
  falls back to local resolution instead of failing — the client can compute
  those documents itself. Other (mutable) methods still surface the error.
- **Single-flight resolution.** Concurrent cache misses for the same DID now
  share one underlying resolution (in-flight `watch`-based dedup map); N
  simultaneous callers produce exactly one upstream request, then all read the
  cached result. Prevents cache-stampede load on the resolver/server.
- Note: full restart-supervision of the background network task is deferred to
  W15 (shared supervision utility); this is the interim hardening.

## 6th June 2026

### 0.8.7 — affinidi-crypto 0.2

- Bump `affinidi-crypto` to `0.2` (P-384/P-521 key agreement +
  `#[non_exhaustive]` key-agreement enums, #357). No API change in this
  crate.

## 18th April 2026

### DID Resolver Cache SDK (0.8.6)

- **CHANGED:** Bumped `didwebvh-rs` dependency from `0.4` to `0.5`. Public
  resolver API unchanged; enables the `data-integrity 0.5.4` migration
  downstream.

## 17th April 2026

### DID Resolver Cache SDK (0.8.5)

- **SECURITY:** Swapped the upstream `did-web` crate for the new
  [`affinidi-did-web`](../did-methods/did-web/) crate, which sits on
  `reqwest 0.13` + `rustls 0.23` + patched `rustls-webpki 0.103.x`.
  The previous `did-web 0.3.4` chain pulled `rustls-webpki 0.101.7`, which
  is flagged by
  [GHSA-xgp8-3hg3-c2mh](https://github.com/advisories/GHSA-xgp8-3hg3-c2mh)
  and [GHSA-965h-392x-2mh5](https://github.com/advisories/GHSA-965h-392x-2mh5).
  Closes [#288](https://github.com/affinidi/affinidi-tdk-rs/issues/288).
- **CHANGED:** `WebResolver` now wraps a reusable `affinidi_did_web::DIDWeb`
  (and therefore its `reqwest::Client`) instead of constructing a fresh
  resolver per request. Public API (`AsyncResolver` implementation) is
  unchanged.
- **CHANGED:** MSRV bumped `1.90.0 → 1.94.0` via the workspace
  `rust-version`, required by the workspace-wide dep refresh.

## 27th March 2026

### DID Resolver Cache SDK (0.8.4)

- **FIX:** Updated `didwebvh-rs` 0.4.0 API call — `resolve()` now takes a
  `ResolveOptions` struct instead of positional `(Option, bool)` arguments,
  matching the upstream API change

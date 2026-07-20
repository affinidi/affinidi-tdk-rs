# Affinidi DID Resolver Cache SDK

## Changelog history

## 20th July 2026

### 0.8.17 — single-flight for concurrent agent name lookups

Concurrent first-time lookups of the *same* agent name now collapse into one
backend call, mirroring the single-flight the document cache has always had.

Previously N concurrent callers made N outbound HTTP requests. That matters more
here than for DIDs: a name lookup is an uncached fetch against somebody else's
web server, so fanning out duplicate requests is precisely what a shared resolver
exists to avoid. A verified regression test asserts one call where there were
eight.

The map is deliberately **separate** from the DID `inflight` map rather than
shared. The two key spaces are different — a hashed agent name versus a hashed
DID — and keeping them apart means a hash collision between the two can never
make one wait on the other.

The leader releases leadership and wakes its followers **regardless of outcome**.
A leader that returned early on error would strand every waiter until its
timeout; there is a test for that path specifically, since it is the failure mode
that would only appear under concurrent load in production.

Deferred from 0.8.15, where it was called out as an inefficiency rather than a
correctness problem. It remains an optimisation — no behaviour changes for a
single caller.
## 20th July 2026

### 0.8.16 — seal `ResolveResponse`

`ResolveResponse` is now `#[non_exhaustive]`, with `ResolveResponse::new(..)` as
the construction path. Fields remain `pub` for reads (ADR 0003 Option B).

This is a *returned* type — callers read it, they do not normally build one — so
sealing costs nothing in practice and removes the barrier to reporting more about
a resolution later. That barrier was real: `resolve_any()` in 0.8.15 wanted to
report which agent name a response was resolved under, and the field was dropped
precisely because adding it to an unsealed struct would have been breaking for
marginal value. Sealed, such a field becomes additive whenever there is a genuine
need for it.

Released as a patch bump per ADR 0003 §3: adding `#[non_exhaustive]` is
technically breaking, but shipping it as a minor would invalidate the
`[patch.crates-io]` redirects held by externally-pinned consumers. Nothing in
this workspace constructs a `ResolveResponse` outside this crate — the cache
server only reads its fields, which sealing still permits — so nothing needed
changing.

Not done here: the WebSocket wire types (`WSRequest`, `WSResponse`,
`WSResponseType`, `WSResponseError`) are also unsealed, and sealing them would be
a prerequisite for evolving the protocol additively. They are *constructed* by
the cache server, so sealing needs constructors designed alongside whatever
protocol change actually needs them, rather than speculatively.
## 19th July 2026

### 0.8.15 — agent names (`resolve_any`)

New optional `agent-names` feature. Off by default; nothing changes for existing
callers when it is not enabled.

- `DIDCacheClient::resolve_any(&str)` accepts **either** a DID or an agent name
  (`example.com/@alice`) and returns the same `ResolveResponse`. A DID is passed
  straight through to `resolve()` with identical behaviour, so switching costs
  existing callers nothing. `resolve()` keeps its strict DID-only contract.
- `Identifier` enum + `FromStr`, classifying an input on the `/@` marker with no
  network access.
- A **second** cache, `agent name -> DID`, in front of the document cache.
  Keeping the mapping separate is deliberate:
  - a name and its DID **share one document entry**, so neither form pays twice
    and the two can never hold divergent copies;
  - the mapping always carries a TTL. `DIDExpiry` derives expiry from the
    *resolved document's* `id`, not the cache key, so a name pointing at an
    immutable method (`did:key`) would otherwise inherit "never expires" and pin
    a web redirect that can change at any moment. There is a regression test for
    exactly this.
- Layer-1 verification is enforced on every resolution: the resolved document
  must claim the name via `alsoKnownAs`, or the call fails **and the mapping is
  evicted** so a poisoned entry is not re-failed from cache until its TTL lapses.
- `set_agent_name_resolvers` / `prepend_` / `append_` / `agent_name_resolver_names`
  for the backend chain, and `remove_agent_name` to drop a cached mapping.
  `agent_names::HttpRedirectResolver` is registered by default. As with the DID
  resolver chain, registration must happen **before the client is cloned**.
- Config: `with_agent_name_ttl` (default 300s) and
  `with_agent_name_cache_capacity` (default 1000).
- `DIDCacheError::AgentNameError`.

`ResolveResponse` is deliberately **unchanged**. The plan had it gain a field
naming the originating agent name, but the struct is not `#[non_exhaustive]`, so
adding one is a breaking change — for marginal value, since a caller passing a
name already knows it, and `did` reports the resolved DID either way.

Not implemented: single-flight de-duplication of concurrent lookups of the *same
name*. The expensive half (document resolution) is already de-duplicated by the
existing `inflight` map; concurrent duplicate name lookups cost an extra backend
call, which is an inefficiency rather than a correctness problem.

## 19th July 2026

### 0.8.14 — didwebvh-rs 0.6

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

### 0.8.13 — affinidi-did-common 0.4

- Bumped the `affinidi-did-common` requirement from `"0.3"` to `"0.4"`.
  No functional change to this crate: `Document` gained a typed
  `also_known_as` field, which is additive.

## 17th June 2026

### 0.8.11 — `did-cheqd` is now opt-in (no forced rustls `ring` backend)

- **`did-cheqd` removed from the default `did-methods` set.** It pulled
  `did-resolver-cheqd`, whose `tonic 0.12` dependency hardcodes the rustls
  `ring` backend on `tokio-rustls`/`rustls 0.23`. Combined with `network`
  (which uses `aws_lc_rs`) — or any downstream binary that selects `aws_lc_rs`
  via `kube`/`reqwest`/`jsonwebtoken` — both rustls backends were compiled and
  `rustls` could no longer auto-select one, panicking with "no process-level
  CryptoProvider available" at the first TLS call (e.g. `ClientConfig::builder()`).
  `did-methods` is now `["did-webvh", "did-scid"]`; a default + `network` build
  compiles `aws_lc_rs` only.
- **The `did-scid` dependency now uses `default-features = false` + `did-webvh`**
  so it no longer drags `did-resolver-cheqd` (and the `ring` stack) in
  transitively.
- **The fix is purely about not forcing a backend.** No runtime
  `install_default()` was added here — installing a process-global rustls
  `CryptoProvider` remains the application's decision and belongs in the
  downstream binary's `main`.
- **Opt back in** with `features = ["did-cheqd"]` (or `did-cheqd` +
  `network`) when you need `did:cheqd` resolution; that re-enables the `ring`
  backend, so install a `CryptoProvider` in your binary's `main`. See the
  README's "did-cheqd and the rustls ring backend" section.
- Root cause is the external `did-resolver-cheqd 1.0.1` + `tonic 0.12.3`, which
  cannot be fixed from this workspace (1.0.1 is the latest published version and
  `tonic 0.12` hardcodes `ring`); making cheqd opt-in is the durable in-workspace
  mitigation. Patch bump keeps the `0.8` pin valid.
- **`rustls-platform-verifier` bumped `0.6` → `0.7`** to match the rest of the
  workspace (`affinidi-tdk-common` is already on `0.7`), consolidating the lock
  to a single version. The SDK only calls `ClientConfig::with_platform_verifier()`
  (available on all backends, incl. Android) and does not use
  `Verifier::new_with_extra_roots`, so the Android cross-compile gap from #483/#484
  does not apply here. No source change required.

## 14th June 2026

### 0.8.10 — non_exhaustive DIDCacheError (W7 sweep)

- `DIDCacheError` is now `#[non_exhaustive]` (ADR-0003) so new variants land
  additively. Patch bump keeps the `0.8` pin valid; consumers that `match` it
  must add a `_` arm. No behaviour change.

## 13th June 2026

### 0.8.9 — supervise the network task (W15)

- **Network task supervised.** In network mode the background task is now
  spawned through the shared `affinidi-task-utils` `TaskSupervisor` (the same
  "restart-and-degrade, never fail-fast" policy as the mediator). A panic or
  fatal error in the task — which would previously leave the SDK silently
  unable to resolve over the network — is caught and restarted with capped
  exponential backoff, and its lifecycle is recorded in a health registry.
  This completes the restart-supervision deferred from W3.
- **Observable health.** New `DIDCacheClient::network_health()` returns the
  supervised task's current state (running / restarting / stopped, restart
  count, last error), or `None` in local mode.
- **`stop()` is now async-safe.** It cancels the supervisor's shutdown token
  (the supervisor aborts the task) instead of `blocking_send`, which could
  panic when called from within a tokio runtime. The internal `WSCommands::Exit`
  message — now redundant — was removed.
- No public API removed; the network feature additionally pulls in
  `affinidi-task-utils`. Local (default) builds are unaffected.

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

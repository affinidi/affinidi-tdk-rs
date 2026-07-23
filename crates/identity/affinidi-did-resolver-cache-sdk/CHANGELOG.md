# Affinidi DID Resolver Cache SDK

## Changelog history

## 23rd July 2026

### 0.8.20 — a display name for a resolved DID

`ResolveResponse::display_name()` returns the verified human name for a DID
when one is known, and the DID itself otherwise. It is the call display code
should make:

```rust
let resolved = client.resolve(did).await?;
println!("{}", resolved.display_name()); // "example.com/@alice", or the DID
```

Every consumer that shows a DID to a person previously had to re-derive this:
resolve the DID, read `alsoKnownAs`, resolve each claimed name, check it points
back. The resolver already holds every piece.

#### It cannot show an unverified name

`ResolveResponse::shortcut` is only ever populated after verification, so a UI
that routes every DID through `display_name()` degrades to the full DID rather
than to a spoofable one. Displaying a name straight from `alsoKnownAs` is a
phishing surface — anyone may claim `bigbank.com/@support` in their own
document.

#### Extensible by design

The value is a `DidShortcut`, a `#[non_exhaustive]` enum rather than a bare
`Option<String>`, so further shortcut schemes can be added without a breaking
release. Agent names are the only kind today. A caller that only wants
something printable uses `display_name()` and never matches at all.

`ResolveResponse` gains a field rather than changing `new` — additive on a
sealed struct, per ADR 0003.

#### Two directions, one of them opt-in

From a name (`resolve_any` / `resolve_agent_name`) the shortcut is free:
verification has just run, and the name was previously discarded from the
response.

From a DID, `resolve` establishes one only when `with_resolve_shortcuts(true)`
is set. **Off by default**: it costs a network round-trip to the naming host,
which a caller that only wants a document should not pay unasked. Behaviour and
latency for existing consumers are unchanged.

#### Verification is the same three stages

Entered from the DID end, `derive_shortcut` requires that the candidate come
from this document's `alsoKnownAs`, that the document be the one just resolved,
and that the candidate's forward resolution land back on this DID.

Candidates resolve through the name backends directly rather than through
`resolve_any` — that is what keeps it non-recursive, since `resolve_any` would
resolve the DID again and re-enter derivation without bound. Candidates are
capped, as a hostile document may claim hundreds. A name a document claims but
which resolves elsewhere is logged and skipped, never displayed.

## 20th July 2026

### 0.8.19 — resolve agent names over the WebSocket connection

Opt in with `with_agent_names_over_websocket(true)`. **Off by default**, and
requires `affinidi-did-resolver-cache-server` 0.9.9 or newer.

A name lookup in network mode previously cost **two round trips over two
transports**: HTTP to the cache server for name → DID, then WebSocket for
DID → document. The server now does both in one exchange on the connection the
client already holds.

#### How it stays compatible

The name travels in `WSRequest::did` *and* in a new optional `agent_name`. A
server that predates this ignores the unknown field, tries to parse the name as a
DID, fails, and answers with a `WSResponseError` carrying the hash of what the
client sent — which is what the client registered its waiter under. The caller
sees a **clean error rather than a hang**, which is the failure mode that
mattered: `ws_recv` drops frames it cannot correlate, so a mismatched hash costs
a full `network_timeout` with nothing to report.

`WSResponse` gains an optional `agent_name` echo. No new `WSResponseType`
variant — see the note on that type for why.

#### Not auto-detected, deliberately

An older server's response to a name request is a generic "failed to parse DID",
indistinguishable from a real failure without matching on error strings. Enabling
this against an old server is therefore safe but useless — you get an error, not
a hang. Capability discovery is the proper answer and is not attempted here.

#### Verification is unchanged

`alsoKnownAs` is still checked client-side, against the document this client
received. The server resolves and caches; it is not trusted to have verified
anything. `WSCommands::ResponseReceived` now carries the whole `WSResponse`
rather than picked-apart fields, so the resolved DID and echoed name are
available without further protocol changes.
## 20th July 2026

### 0.8.18 — seal the WebSocket wire types

`WSRequest`, `WSResponse`, `WSResponseError` and `WSResponseType` are now
`#[non_exhaustive]`, with `WSRequest::new`, `WSResponse::new` / `with_logs` and
`WSResponseError::new` as the construction paths.

Groundwork for carrying agent names over the WebSocket transport: today a name
lookup in network mode costs **two round trips over two transports** — HTTP to
the cache server for name→DID, then WebSocket for DID→document. Collapsing that
onto the connection the client already holds means growing these types, and
growing them should not require a breaking release each time.

#### The wire rule these types now document

Sealing records a Rust-level constraint. The wire-level one is stricter and
matters more, so it is written on `WSResponseType`:

> **Do not add variants.** The enum is externally tagged, so a new variant
> serializes as an unrecognised key. An older client fails to deserialize it and
> `ws_recv` *drops the frame* — leaving the caller to wait out its full
> `network_timeout` with no error to report.

A silent hang is a far worse failure than a clean error. Protocol growth
therefore belongs in additive optional fields (as `did_log` already does), never
in a new variant.

Eight tests pin the wire format itself: the request shape, that a minimal
payload from an older peer still deserializes, that unknown fields are ignored
rather than rejected, that absent logs are omitted, and that the enum really is
externally tagged.

No behaviour change — this is types and construction paths only.
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

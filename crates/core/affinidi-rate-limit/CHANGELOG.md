# Changelog

All notable changes to `affinidi-rate-limit` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.4] - 2026-11-03

What a service needs to run all its limiters on this crate, not only the
layer: limits inside handlers, other keys, window-shaped limits, and named
limits. Existing callers compile unchanged.

### Added

- `KeyedRateLimiterState<K>`: the limiter over any `Hash + Eq + Clone` key
  (a sender string, or `()` for one shared budget), with the same distinct-key
  cap and GC. `RateLimiterState` is now its `IpAddr` alias, so
  `RateLimiterState::new(..)` resolves as before. Its `Debug` output now names
  `KeyedRateLimiterState`.
- `per_window(max_per_window, window)`: a burst of up to `max_per_window`,
  refilled evenly across `window`. `0` or a zero window disables limiting.
  A window over 100 years is held there.
- `per_period(period, burst)`: one request every `period` after a burst of
  `burst`, for limits slower than one a second. A zero period disables
  limiting. A full refill over 100 years is held there, rather than
  overflowing `governor`'s nanosecond clock.
- `with_limiter_name(name)` and `limiter_name()`: a refusal body's `limiter`
  names the limit that fired, while `x-rate-limit-source` still names the
  service. Unset, the body is unchanged.
- `charge(key)`, returning `TooManyRequests { retry_after_secs }`: the
  handler-side check, refusing only for the rate. `check(key)` is unchanged
  and now delegates to it.
- `with_max_tracked_keys(n)`: holds a limiter to `n` distinct keys rather than
  250,000, refusing new keys once full of live ones. The refusal log is
  bounded the same way.
- `refuse(&refusal)`: the response the layer sends for a refusal, for handler
  code whose refusals should look the same.
- `first_refusal_in_window(key)`: records a refusal and says whether it is the
  key's first in its window, so handler code can log once per window.
- `ClientIpExtractor` is public. `direct_peer()`, `trusted_proxies(cidrs)`,
  `with_trusted_proxies(cidrs)` and `ipv6_prefix(len)` configure it; `client_key(peer, headers)` gives the key
  the layer charges, and `client_ip(peer, headers)` the unmasked client
  address. `RateLimitLayer::client_ip_extractor` hands one to the layer.
- `RateLimitLayer::ipv6_prefix(len)` charges an IPv6 client to its `/len`
  network, so rotating addresses inside a `/64` does not escape the limit.
  `InvalidIpv6Prefix` refuses 0 and lengths above 128.
- `InvalidForwardedFor`, the error `client_ip` and `client_key` return for a
  chain they cannot attribute, and `MAX_FORWARDED_ENTRIES` (64), now public.

### Changed

- The layer logs a client's first refusal in each window (the time its bucket
  takes to refill) rather than every refused request. `on_refused` still runs
  for every refusal.
- An invalid `X-Forwarded-For` from a trusted proxy is logged once a minute
  per proxy address by the `ClientIpExtractor` that met it, rather than on
  every request, so handler code calling `client_ip` logs it too. Every such
  request is still refused with `400`.
- The `400` for an invalid chain is documented as deliberate. A service moving
  here from a resolver that falls back to the proxy's address, such as the
  DID hosting service's or `vti-common`'s, starts answering those requests
  with `400` rather than charging them to the proxy's bucket.

### Fixed

- `Retry-After` is rounded up to whole seconds rather than down, so a client
  retrying when told no longer arrives just before its next token.

## [0.1.3] - 2026-10-29

Opt-in trusted-proxy attribution, so clients behind a load balancer stop
sharing one bucket.

### Added

- `RateLimitLayer::trusted_proxies(Vec<IpNet>)` to opt into trusted-proxy
  `X-Forwarded-For` attribution with right-to-left parsing and first-untrusted
  selection. `IpNet` is `ipnet::IpNet`, re-exported from this crate. It returns
  `Result<Self, InvalidTrustedProxy>`: a catch-all range (`0.0.0.0/0`, `::/0`)
  would trust every peer and is refused. The chain is walked without
  allocating.
- `Refusal::InvalidForwardedFor` (`Refusal` is `#[non_exhaustive]`).

### Changed

- A named limiter's `400` (`Refusal::InvalidForwardedFor`) carries
  `x-rate-limit-source` and a JSON body
  `{"error":"invalid_forwarded_for","limiter":…,"message":…}`
  (`INVALID_FORWARDED_FOR_ERROR`), and its `403` (no client IP) now carries
  `x-rate-limit-source` too, so every refusal says who refused. Unnamed
  limiters keep plain-text bodies and no header.
- The socket peer is now canonicalised with `IpAddr::to_canonical()` in every
  mode, including the default one without `trusted_proxies`. Previously the
  peer was used exactly as accepted. An IPv4-mapped IPv6 peer
  (`::ffff:a.b.c.d`, as a dual-stack listener reports IPv4 clients) is now
  keyed as its IPv4 address, so it shares one bucket with the same client
  connecting over IPv4. Other addresses, including `::1`, are unchanged. This
  is the one behaviour change that applies without opting in.

### Fixed

- `RateLimitService::call` now calls the inner service that `poll_ready`
  readied and keeps a fresh clone for the next poll. It used to call an
  unpolled clone, which breaks tower's readiness contract for an inner service
  with real backpressure (`ConcurrencyLimit`, `Buffer`).

### Security

- In trusted-proxy mode, a malformed `X-Forwarded-For` entry from the client
  entry rightwards is rejected with `400 Bad Request`
  (`Refusal::InvalidForwardedFor`) instead of being attributed to a fallback
  IP. Entries left of the client entry are client-supplied and never parsed
  as addresses; they still count towards the 64-entry cap.

## [0.1.2] - 2026-09-16

Bound the number of distinct source IPs the limiter tracks, closing an
unbounded-memory path (CWE-770).

### Security

- The keyed state store is keyed on unauthenticated, client-chosen IPs and
  `governor` never caps the *number* of keys — only the periodic GC reclaims
  fully-replenished buckets. Between sweeps a client rotating addresses (an
  IPv6 /64, say) could grow the map without bound, before any authentication.
  A hard cap (`MAX_TRACKED_IPS`, 250_000) now bounds it: when the store is full
  and a *new* IP arrives, the limiter first attempts a throttled reclaim of
  replenished buckets and, if still full, fails that new IP closed with the
  usual `429` contract rather than growing the map. An IP already tracked is
  never refused for capacity or evicted mid-window by this path, and disabled
  mode (`per_second == 0`) is unaffected. The inline reclaim is throttled to at
  most one pass per 100ms so the admission check itself can't be turned into a
  CPU-exhaustion lever. No public API change.

## [0.1.1] - 2026-09-16

A `429` now says which service refused it, when the service names itself.

### Added

- `RateLimiterState::with_source(name)` and `RateLimiterState::source()`. A
  named limiter's refusal carries the ecosystem's attribution contract:
  - `x-rate-limit-source: <name>` (`SOURCE_HEADER`);
  - `Retry-After: <seconds>`, as before;
  - a JSON body `{"error":"rate_limited","limiter":"<name>","message":"…",
    "retryAfterSecs":N}` with `Content-Type: application/json`.

  The names clients match on are `mediator`, `vta`, `vtc` and `did-host`.
- `SOURCE_HEADER` and `RATE_LIMITED_ERROR` constants.

### Unchanged

- An unnamed limiter sends exactly the plain-text `429` it always did, with no
  source header. Additive: a patch.

## [0.1.0] - 2026-07-20

Initial release. Extracted from `affinidi-messaging-mediator`, where it had lived
as `common/rate_limiter.rs`, so that more than one service can use it without the
two copies drifting.

### Added

- `RateLimiterState` — per-IP token bucket over `governor`. `new(per_second,
  burst)`, `disabled()`, `is_enabled()`, `tracked_keys()`.
- `RateLimiterState::check(ip)` — the rate-limit decision, exposed separately
  from the middleware so it can be tested directly. The mediator's copy had no
  tests at all, largely because the logic was only reachable through a live
  server; this release ships 12.
- `RateLimiterState::spawn_gc(shutdown)` — periodic `retain_recent` sweep of the
  keyed store.
- `RateLimitLayer` / `RateLimitService` — the `tower` layer.
- `Refusal` (`#[non_exhaustive]`) — `RateLimited { retry_after_secs }` or
  `NoClientIp`.
- `RateLimiterState::on_refused(callback)` — observe refusals without this crate
  depending on any metrics library. The mediator's `RATE_LIMITED_TOTAL` metric,
  previously emitted inside the limiter, now rides on this.

### Behaviour carried over deliberately

- **The GC sweep.** `governor` never reclaims keys, so an unswept store grows
  once per source IP for the process lifetime, keyed on unauthenticated
  client-chosen input. That was a real bug in the mediator before it was fixed;
  keeping the fix in one shared place is the main reason this crate exists.
- **No client IP means refusal, not exemption.** Failing open would be a trivial
  bypass of per-IP limiting.
- **`Retry-After` has a floor of 1 second.** Zero would invite an immediate retry
  that is guaranteed to fail.

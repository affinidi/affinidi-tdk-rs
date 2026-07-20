# Changelog

All notable changes to `affinidi-rate-limit` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

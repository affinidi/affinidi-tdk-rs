# affinidi-rate-limit

Per-IP request rate limiting for `axum` services — a token bucket keyed by
client IP, applied as a `tower` layer.

```rust
use affinidi_rate_limit::{RateLimitLayer, RateLimiterState};

// 20 requests/second sustained per IP, bursts up to 50.
let limiter = RateLimiterState::new(20, 50);
limiter.spawn_gc(shutdown_token);

let app = Router::new().layer(RateLimitLayer::new(limiter));
```

`per_second = 0` disables limiting and the layer becomes a pass-through.

## Two things that are easy to get wrong

**The keyed state store must be swept.** `governor` never reclaims keys on its
own, so without `spawn_gc` every source IP the service has ever seen keeps an
entry for the process lifetime. The store is keyed on unauthenticated,
client-chosen input — a client rotating through an IPv6 /64 inserts an entry per
request — which makes it an unbounded growth path reachable before any
authentication.

That bug shipped once already, in the mediator. This crate exists in part so the
fix lives in one place rather than being re-derived by every service that needs a
limiter.

`retain_recent` only drops keys whose bucket has fully replenished. Such a key is
indistinguishable from one that was never present, so sweeping cannot let a
client exceed its quota.

**A request with no client IP is refused, not exempted.** Per-IP limiting is
meaningless without an IP, and failing open would be a trivial bypass. Serve with
`into_make_service_with_connect_info::<SocketAddr>()` so `ConnectInfo` is
attached.

## Observing refusals

`on_refused` takes a callback rather than this crate depending on a metrics
library:

```rust
let limiter = RateLimiterState::new(20, 50)
    .on_refused(|refusal| {
        if matches!(refusal, Refusal::RateLimited { .. }) {
            metrics::counter!("rate_limited_total").increment(1);
        }
    });
```

`Retry-After` is set from `governor`'s own estimate of when the next token
arrives, rounded up to whole seconds with a floor of 1 — a `Retry-After: 0`
would invite an immediate retry guaranteed to fail.

## License

Apache-2.0

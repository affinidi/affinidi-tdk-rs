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

To trust `X-Forwarded-For` only from known reverse proxies:

```rust
let app = Router::new().layer(
    RateLimitLayer::new(limiter).trusted_proxies(vec![
        "10.0.0.0/8".parse().unwrap(),
        "2001:db8::/32".parse().unwrap(),
    ]),
);
```

The CIDRs are [`ipnet::IpNet`](https://docs.rs/ipnet), re-exported as
`affinidi_rate_limit::IpNet`.

When `trusted_proxies` is set, a malformed entry from the client entry
rightwards (the part trusted proxies wrote) is rejected with
`400 Bad Request`, as is a chain of more than 64 entries or a header value that
is not visible ASCII. Entries left of the client entry are never parsed as
addresses, so client-supplied junk there is ignored.

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

**Trusted-proxy mode assumes controlled ingress.** Configure only proxies that
append the address of the peer they received the connection from to
`X-Forwarded-For` (an ALB appends the client IP), and do not expose the service
directly except through those proxies.

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

## Saying who refused

A `429` can come from any hop between a client and the service it called, and
each hop is tuned somewhere else. Name the service and its refusals say so:

```rust
let limiter = RateLimiterState::new(20, 50).with_source("mediator");
```

A refusal then carries `x-rate-limit-source: mediator`, `Retry-After: <seconds>`
and a JSON body:

```json
{"error":"rate_limited","limiter":"mediator","message":"Rate limit exceeded. Please try again later.","retryAfterSecs":4}
```

Use the names clients match on: `mediator`, `vta`, `vtc`, `did-host`. An unnamed
limiter sends a plain-text `429` with no source header.

`Retry-After` is set from `governor`'s own estimate of when the next token
arrives, rounded up to whole seconds with a floor of 1 — a `Retry-After: 0`
would invite an immediate retry guaranteed to fail.

## License

Apache-2.0

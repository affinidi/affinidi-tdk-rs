# affinidi-did-resolver-cache-server

[![Crates.io](https://img.shields.io/crates/v/affinidi-did-resolver-cache-server.svg)](https://crates.io/crates/affinidi-did-resolver-cache-server)
[![Documentation](https://docs.rs/affinidi-did-resolver-cache-server/badge.svg)](https://docs.rs/affinidi-did-resolver-cache-server)
[![Rust](https://img.shields.io/badge/rust-1.94.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/identity/affinidi-did-resolver-cache-server)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

A standalone network service for resolving and caching DID Documents at scale.
Exposes both a WebSocket endpoint (multiplexed, out-of-order responses) and an
HTTP endpoint (request–response), backed by a process-wide cache and a pool of
parallel resolvers.

## Architecture

```mermaid
graph LR
    C1["Client 1"] -->|WebSocket| S["Cache Server"]
    C2["Client 2"] -->|WebSocket| S
    C3["Client N"] -->|HTTP| S
    S -->|cache miss| R["Resolver Pool"]
    R --> M1["did:web"]
    R --> M2["did:ethr"]
    R --> M3["did:key"]
    R --> M4["..."]
```

WebSocket clients multiplex multiple in-flight requests on one connection and
may receive responses out of order. The
[`affinidi-did-resolver-cache-sdk`](../affinidi-did-resolver-cache-sdk/) handles
the matching on the client side.

## Running

```bash
# Run with the config file at the default path (./conf/cache-conf.toml)
cargo run --release

# Run with a custom config path (useful when the binary and config live in
# different directories, e.g. /usr/local/bin + /etc/affinidi/)
cargo run --release -- --config /etc/affinidi/cache-conf.toml
# or, short form:
cargo run --release -- -c /etc/affinidi/cache-conf.toml

# Installed binary
affinidi-did-resolver-cache-server -c /etc/affinidi/cache-conf.toml
```

Any configuration value can also be overridden via environment variables
referenced from `cache-conf.toml` (see the default config for the full list).

Every setting except `capacity_count`, `expire` and `webvh_log_expire` is a
top-level key and must appear **above** the `[cache]` header: TOML puts every
key after a table header into that table. An unknown key, at the top level or
under `[cache]`, fails startup with an error naming it.

## Client limits

| Key (env var) | Default | Effect |
|---|---|---|
| `rate_limit_per_ip` (`RATE_LIMIT_PER_IP`) | `100` | Sustained requests per second per client. Charged for each HTTP request and for each request message on a WebSocket, from one bucket. `0` disables. |
| `rate_limit_burst` (`RATE_LIMIT_BURST`) | `50` | Burst above the sustained rate. Over it: HTTP 429, or a `WSResponseError` for that WebSocket request. |
| `trusted_proxies` (`TRUSTED_PROXIES`) | empty | Comma-separated CIDRs of proxies whose `X-Forwarded-For` names the client. Empty: the connecting peer is the client. |
| `client_ipv6_prefix` (`CLIENT_IPV6_PREFIX`) | `64` | IPv6 clients are charged and counted by this prefix. |
| `ws_max_connections` (`WS_MAX_CONNECTIONS`) | `4096` | Open WebSocket connections in all; a new one over it gets 503. |
| `ws_max_connections_per_ip` (`WS_MAX_CONNECTIONS_PER_IP`) | `64` | Open WebSocket connections per client; a new one over it gets 429. |
| `ws_idle_timeout` (`WS_IDLE_TIMEOUT`) | `120` s | A WebSocket that receives nothing (pings included) for this long is closed. |
| `ws_send_timeout` (`WS_SEND_TIMEOUT`) | `10` s | A response send that takes longer closes the connection. |
| `ws_max_message_size` (`WS_MAX_MESSAGE_SIZE`) | `0` | Largest WebSocket message in bytes; `0` means `2 * max_did_size + 1024`. |

Behind a load balancer, list it in `trusted_proxies`; otherwise every client
is charged and counted as the load balancer's address.

## Feature flags

| Feature | Default | Effect |
|---|:---:|---|
| `network` | ✅ | Registers the `/did/v1/ws` WebSocket endpoint that the client SDK's `network` mode connects to. Forwards to `affinidi-did-resolver-cache-sdk/network`, which pulls rustls + WebSocket wiring. |

The HTTP resolver endpoint (`/did/v1/resolve/{did}`) and the health endpoints
are always compiled in — they do not depend on the `network` feature.

```bash
# Full build (WebSocket + HTTP + health)
cargo build -p affinidi-did-resolver-cache-server

# Equivalent: explicitly enable `network`
cargo build -p affinidi-did-resolver-cache-server --features network

# HTTP-only build (no /ws, no WebSocket dependencies)
# If `enable_websocket_endpoint` is still true in cache-conf.toml the server
# logs a notice at startup and skips /ws instead of failing to start.
cargo build -p affinidi-did-resolver-cache-server --no-default-features
```

The DID methods the server resolves (did:web, did:webvh, did:webs, did:cheqd, did:scid,
did:ethr, did:pkh, did:jwk, did:ebsi, did:key, did:peer) are configured via
the `affinidi-did-resolver-cache-sdk` dependency's own feature flags. If you
need a different method mix, edit the SDK's default feature set at
`affinidi-did-resolver-cache-sdk/Cargo.toml`.

## Related Crates

- [`affinidi-did-resolver-cache-sdk`](../affinidi-did-resolver-cache-sdk/) — client SDK (enable the `network` feature to connect over WebSocket)
- [`affinidi-did-common`](../affinidi-did-common/) — DID / DID Document types

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

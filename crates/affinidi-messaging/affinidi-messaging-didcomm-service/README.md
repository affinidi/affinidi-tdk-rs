# affinidi-messaging-didcomm-service

Framework for building always-online DIDComm services. Manages mediator connections, message lifecycle, and handler dispatch so you can focus on protocol logic.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
affinidi-messaging-didcomm-service = { path = "../affinidi-messaging-didcomm-service" }
```

## Features

- **Axum-style routing** -- match handlers by message type using exact strings or regex patterns, with a fallback handler for unmatched types. Route registration is validated at build time (invalid regex returns an error)
- **Function handlers with extractors** -- handlers are plain async functions; shared state is injected via `Extension<T>` extractors (no manual downcasting). `HandlerContext.sender_did` is `Option<String>` — `None` for anonymous (anoncrypt'd) messages
- **Middleware pipeline** -- composable middleware via `.layer()` with access to message, metadata, context, and the `Next` chain
- **N-listener support** -- run multiple listeners (profile + mediator pairs) concurrently within a single service instance
- **Runtime listener management** -- add/remove listeners on the fly via `add_listener` / `remove_listener`; inspect state via `list_listeners`
- **Per-listener restart policies** -- `Never`, `OnFailure` (with max retries), `Always` -- each with configurable exponential backoff
- **Mediator ACL management** -- set `ExplicitAllow` / `ExplicitDeny` mode per listener on the mediator
- **Offline message sync** -- periodic polling for queued messages missed during downtime
- **Pluggable crypto** -- `MessageCryptoProvider` trait for custom pack/unpack (e.g. delegating to external KMS); built-in `DefaultCryptoProvider` uses ATM with local secrets
- **Graceful shutdown** -- in-flight message handlers are tracked via `JoinSet` and drained on shutdown; panicked tasks are detected and logged
- **Transport utilities** -- `build_response`, `send_response`, `build_problem_report`, `send_problem_report`
- **Problem report protocol** -- `ProblemReport` struct with standard DIDComm error codes
- **Message utilities** -- `get_thread_id`, `get_parent_thread_id`, `new_message_id`

### Built-in middleware

| Middleware | Purpose |
|---|---|
| `RequestLogging` | One `info!` log per message with type, sender, status, and latency (target: `didcomm_server::request`) |
| `MessagePolicy` | Enforce encryption, authentication, non-repudiation, and sender DID requirements. Contradictory settings (e.g. `allow_anonymous_sender(false)` + `require_sender_did(false)`) are automatically reconciled |

## Quick start

```rust
use affinidi_messaging_didcomm_service::{
    DIDCommHandler, DIDCommService, DIDCommServiceConfig, DIDCommServiceError,
    HandlerContext, ListenerConfig, RequestLogging, RestartPolicy, RetryConfig,
    Router, handler_fn, DIDCommResponse,
};
use affinidi_messaging_didcomm::Message;
use affinidi_tdk_common::profiles::TDKProfile;
use tokio_util::sync::CancellationToken;
use serde_json::json;

async fn hello(
    ctx: HandlerContext,
    message: Message,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    Ok(Some(DIDCommResponse::new(
        "https://example.com/hello/response",
        json!({ "status": "ok" }),
    )))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let profile = TDKProfile::new(
        "my-service",
        "did:peer:2.Ez...",
        Some("did:web:mediator.example.com"),
        vec![/* secrets */],
    );

    let config = DIDCommServiceConfig {
        listeners: vec![ListenerConfig {
            id: "main".into(),
            profile,
            restart_policy: RestartPolicy::Always {
                backoff: RetryConfig::default(),
            },
            ..Default::default()
        }],
    };

    let router = Router::new()
        .route("https://example.com/hello", handler_fn(hello))?
        .layer(RequestLogging);

    let shutdown = CancellationToken::new();
    let _service = DIDCommService::start(config, router, shutdown).await?;

    tokio::signal::ctrl_c().await.ok();
    Ok(())
}
```

## Restart policies

| Policy | Behavior |
|---|---|
| `Never` | Listener stops on error or clean exit |
| `OnFailure { max_retries, backoff }` | Restarts only on error, up to `max_retries` times (unlimited if `None`) |
| `Always { backoff }` | Restarts on any termination, suitable for listeners that must stay up indefinitely |

## Logging

All internal library logs use `debug!` level. To see them:

```
RUST_LOG=affinidi_messaging_didcomm_service=debug
```

The `RequestLogging` middleware emits one `info!` per message under `didcomm_server::request`:

```
RUST_LOG=didcomm_server::request=info
```

## Example

See [`examples/echo_server.rs`](examples/echo_server.rs) for a complete working example with:
- Axum-style router with regex routes
- Function handlers with `Extension<T>` extractors for shared state
- Custom middleware via `middleware_fn`
- `MessagePolicy` for message validation
- `RequestLogging` for per-request logging
- Restart policy configuration
- Graceful shutdown via `CancellationToken`

## Out of scope

- DID document building and hosting
- Config/profile loaders (env vars, AWS secrets, etc.)
- DID document availability checking

## Related Crates

- [`affinidi-messaging-sdk`](../affinidi-messaging-sdk/) -- Client SDK for Affinidi Messaging (dependency)
- [`affinidi-messaging-didcomm`](../affinidi-messaging-didcomm/) -- DIDComm protocol layer (dependency)
- [`affinidi-tdk-common`](../../affinidi-tdk/common/affinidi-tdk-common/) -- Shared types including `TDKProfile` (dependency)
- [`affinidi-messaging-mediator`](../affinidi-messaging-mediator/) -- Mediator server implementation

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

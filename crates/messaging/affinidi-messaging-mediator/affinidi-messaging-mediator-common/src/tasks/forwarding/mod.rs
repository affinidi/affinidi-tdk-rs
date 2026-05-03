//! Forwarding processor — reads queued messages off `FORWARD_Q` and
//! delivers them to remote mediators via REST POST or WebSocket.
//!
//! Consumed by both the in-process mediator (which spawns the
//! processor as a tokio task) and the standalone
//! `forwarding_processor` binary in `mediator-processors` (for
//! horizontal scaling on dedicated hosts). Both consumers construct
//! the same [`ForwardingProcessor`] over `Arc<dyn MediatorStore>`.

pub mod config;
pub use config::ForwardingConfig;

// `ForwardingProcessor` runs only against the Redis backend (it uses
// XREADGROUP / XACK / XAUTOCLAIM consumer-group semantics for
// multi-process coordination). Gate it on `redis-backend` so memory-
// and fjall-only mediator builds don't drag in `reqwest` /
// `tokio-tungstenite` for code they can't run.
#[cfg(feature = "redis-backend")]
pub mod processor;
#[cfg(feature = "redis-backend")]
pub use processor::ForwardingProcessor;

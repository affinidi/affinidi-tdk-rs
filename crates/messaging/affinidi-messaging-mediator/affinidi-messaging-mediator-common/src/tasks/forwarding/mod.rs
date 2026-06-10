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

// `ForwardingProcessor` is backend-agnostic: it consumes the
// `forward_queue_*` methods on `Arc<dyn MediatorStore>`, which every
// backend implements (Redis via Streams consumer groups; Fjall and
// Memory via an in-process pending-claim emulation of the same
// semantics). Its HTTP/WS delivery deps (`reqwest`,
// `tokio-tungstenite`) ride on the `server` umbrella feature, which
// also gates the parent `tasks` module — so no extra cfg is needed.
// Multi-process scaling (the standalone `forwarding_processor`
// binary) still requires the Redis backend; Fjall and Memory queues
// are single-process.
pub mod processor;
pub use processor::ForwardingProcessor;

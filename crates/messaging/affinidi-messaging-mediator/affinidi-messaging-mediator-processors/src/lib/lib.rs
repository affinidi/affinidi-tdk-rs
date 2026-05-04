//! Standalone background processors for the Affinidi Messaging Mediator.
//!
//! These processors run as separate processes from the mediator binary,
//! intended for horizontal scaling: drop more processor instances onto
//! additional hosts and they coordinate through Redis to share work.
//!
//! ## Redis-only by design
//!
//! Multi-process coordination relies on Redis primitives:
//! - **Forwarding processor**: Redis Streams consumer groups
//!   (`XREADGROUP` / `XACK` / `XAUTOCLAIM`) for at-least-once delivery
//!   across competing consumers.
//! - **Message expiry cleanup**: atomic `SPOP` on expiry-timeslot sets
//!   so multiple processors can drain the same timeslot without
//!   duplicating work.
//!
//! Memory and Fjall backends are single-process by definition and have
//! no equivalent multi-host coordination, so the standalone binaries
//! are not portable to those backends. The mediator's in-process tasks
//! cover the same workloads on every backend via the
//! `MediatorStore` trait — operators only need this crate when they want
//! to scale a Redis deployment horizontally.
//!
//! ## Implementation
//!
//! Both binaries reuse the trait-based code path lifted into
//! `mediator-common`:
//!
//! - `forwarding_processor` constructs an `Arc<dyn MediatorStore>`
//!   over a `RedisStore` and feeds it to
//!   `mediator_common::tasks::forwarding::ForwardingProcessor`. Same
//!   processor type the mediator binary spawns in-process.
//! - `message_expiry_cleanup` opens the same `RedisStore` and calls
//!   `MediatorStore::sweep_expired_messages` on a one-second tick,
//!   matching the mediator's in-process expiry sweep.
//!
//! No duplicated implementation lives in this crate — both binaries
//! are thin shells that wire config to mediator-common.

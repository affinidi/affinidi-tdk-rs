//! Background tasks shared between the mediator binary and the
//! standalone processor binaries in
//! `affinidi-messaging-mediator-processors`.
//!
//! `forwarding::ForwardingConfig` is unconditional (it's a config
//! struct used by the wizard regardless of which backend the operator
//! picked); `forwarding::ForwardingProcessor` itself depends on the
//! Redis-only multi-process coordination primitives and is gated
//! accordingly. Memory and Fjall backends call the trait methods
//! directly without a processor wrapper.

pub mod forwarding;

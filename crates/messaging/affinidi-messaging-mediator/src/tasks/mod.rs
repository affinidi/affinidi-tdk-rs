/// Any parallel task (thread) that needs to be spawned should be defined here.
///
/// `ForwardingProcessor` lives in
/// [`affinidi_messaging_mediator_common::tasks::forwarding`] so the
/// standalone binary in `mediator-processors` can reuse the same
/// implementation; re-exported here for backward compatibility.
pub use affinidi_messaging_mediator_common::tasks::forwarding as forwarding_processor;
pub mod statistics;
pub mod websocket_streaming;

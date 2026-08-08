//! v1 protocol message types.
//!
//! Only the carrier protocol a Trust Tasks binding needs is modelled here.
//! Anything else — connections, trust ping, discover-features — can be built on
//! [`crate::MessageV1`] directly, since a v1 message is just `@id`, `@type`, and
//! top-level members.

pub mod basic_message;
pub mod forward;

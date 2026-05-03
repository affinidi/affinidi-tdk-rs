//! Re-exports of the safe time helpers from
//! [`affinidi_messaging_mediator_common::time`]. Kept here for the
//! many existing call sites under `crate::common::time::*`.

pub use affinidi_messaging_mediator_common::time::{unix_timestamp_millis, unix_timestamp_secs};

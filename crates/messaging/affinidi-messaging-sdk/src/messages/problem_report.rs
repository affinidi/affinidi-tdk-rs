//! DIDComm Problem Report handling — re-exported from
//! [`affinidi-messaging-mediator-common`](https://docs.rs/affinidi-messaging-mediator-common)
//! so the storage trait crate owns the protocol vocabulary while
//! existing call-sites keep the original `affinidi_messaging_sdk::messages::problem_report::*`
//! paths.

pub use affinidi_messaging_mediator_common::types::problem_report::{
    ProblemReport, ProblemReportScope, ProblemReportSorter,
};

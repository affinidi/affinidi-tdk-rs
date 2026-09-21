//! Operate an Affinidi messaging mediator — the engine behind the mediator
//! console, usable headless or embedded in another application.
//!
//! Connect as an [`Identity`] from any [`IdentitySource`] and get a
//! [`MediatorConsole`]. What it can do follows from the mediator's own record
//! of the account ([`Mode`], [`Capabilities`]):
//!
//! - an **administrator** sees the whole mediator — statistics, every account's
//!   queues ranked, any account's messages and settings, the audit log, the
//!   configuration, and live traffic for everyone;
//! - **any other account** manages itself — its own queues and messages, the
//!   settings it may self-manage, and its own live traffic.
//!
//! Every operation is a signed Trust Task, so the mediator authorises each one
//! independently; the console's capability checks only spare a round trip.
//! Destructive work is two-step ([`MediatorConsole::purge_preview`] then
//! [`MediatorConsole::purge`]), and the live [`MonitorFeed`] reports lost
//! batches and dead taps rather than going quiet.

mod console;
mod error;
mod identity;
mod live;
mod purge;

pub use console::{Capabilities, InspectedMessage, MediatorConsole, Mode, Target};
pub use error::{ConsoleError, Result};
pub use identity::{Identity, IdentityChoice, IdentitySource, ProfileFileSource, StaticIdentities};
pub use live::{MonitorEvent, MonitorFeed, MonitorFilter, MonitorUpdate};
pub use purge::{PurgePlan, PurgeRequest};

/// The generated Trust Task types the console's calls take and return.
pub use trust_tasks_rs::specs::messaging as specs;

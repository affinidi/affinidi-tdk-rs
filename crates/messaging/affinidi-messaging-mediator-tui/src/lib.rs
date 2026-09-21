//! A terminal console for an Affinidi messaging mediator.
//!
//! [`App`] is an embeddable ratatui component over a connected
//! [`MediatorConsole`](affinidi_messaging_mediator_admin::MediatorConsole):
//! mediator statistics, every account's queues with gradient quota bars, an
//! account's messages (inspect, delete, preview-then-confirm purges) and a live
//! traffic monitor in a split pane. What it offers follows the session's mode —
//! an administrator sees the whole mediator; any other account, itself.
//!
//! The host owns the terminal: feed keys to [`App::handle_key`], background
//! results to [`App::apply`], and draw with [`App::render`] — or hand a
//! terminal to [`App::run`]. [`quota::QuotaBar`] is usable on its own.

pub mod app;
pub mod quota;

pub use app::{App, Control, Tab, Update};
pub use quota::{ColorDepth, QuotaBar, quota_line};

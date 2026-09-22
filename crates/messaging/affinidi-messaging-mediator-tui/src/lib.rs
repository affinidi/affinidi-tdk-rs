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

pub mod account_edit;
pub mod app;
pub mod quota;
pub mod tally;

pub use app::{App, Control, Tab, Update};
pub use quota::{ColorDepth, QuotaBar, quota_line};

/// Where the console keeps its address book unless told otherwise:
/// `$XDG_CONFIG_HOME/mediator-console/address-book.json`, falling back to
/// `~/.config/mediator-console/address-book.json`. Shared by every console
/// front end (`mediator-console`, `pnm messaging console`), so a name given in
/// one shows in the other. `None` when neither variable is set.
pub fn default_address_book_path() -> Option<std::path::PathBuf> {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config"))
        })?;
    Some(config.join("mediator-console").join("address-book.json"))
}

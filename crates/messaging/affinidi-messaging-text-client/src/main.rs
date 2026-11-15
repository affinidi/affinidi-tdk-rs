use affinidi_tdk::common::TDKSharedState;
use log::LevelFilter;
use paths::Paths;
use state_store::StateStore;
use std::sync::Arc;
use termination::{Interrupted, create_termination};
use tracing::Level;
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, filter, fmt};
use tui_logger::TuiTracingSubscriberLayer;

use crate::ui_management::ui_manager::{UiManager, install_panic_hook};

mod paths;
mod state_store;
mod termination;
mod ui_management;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let paths = Paths::resolve()?;
    let log_file = paths::open_log(&paths.log_file)?;
    tracing_subscriber::registry()
        .with(TuiTracingSubscriberLayer)
        .with(
            fmt::layer()
                .with_ansi(true)
                .with_writer(log_file)
                .with_filter(filter::LevelFilter::from_level(Level::DEBUG)),
        )
        .init();

    tui_logger::init_logger(LevelFilter::Info).unwrap();
    install_panic_hook();

    // Setup the initial state

    let (terminator, interrupt_rx) = create_termination();
    let (state_store, state_rx) = StateStore::new();
    let (ui_manager, action_rx) = UiManager::new();

    if paths.legacy_state_file {
        tracing::info!(
            "Using ./config.json from the current directory (legacy location); new installs use {}",
            paths.log_file.with_file_name("config.json").display()
        );
    }

    let tdk =
        Arc::new(TDKSharedState::new(affinidi_tdk::common::config::TDKConfig::headless()?).await?);
    // `join!`, not `try_join!`: both loops must finish so the UI restores the
    // terminal before anything is printed, and the state store's reason for
    // stopping is not lost behind the UI's error.
    let (store_result, ui_result) = tokio::join!(
        state_store.main_loop(
            terminator,
            action_rx,
            interrupt_rx.resubscribe(),
            tdk,
            paths.state_file.clone(),
        ),
        ui_manager.main_loop(state_rx, interrupt_rx.resubscribe()),
    );

    // The terminal has been restored by now.
    let reason = match (store_result, ui_result) {
        (Err(e), _) => {
            eprintln!("error: {e:#}");
            std::process::exit(1);
        }
        (Ok(Interrupted::SystemError(msg)), _) => {
            eprintln!("error: {msg}");
            eprintln!("(log: {})", paths.log_file.display());
            std::process::exit(1);
        }
        (Ok(_), Err(e)) => {
            eprintln!("error: {e:#}");
            std::process::exit(1);
        }
        (Ok(reason), Ok(_)) => reason,
    };

    match reason {
        Interrupted::UserInt => println!("exited per user request"),
        Interrupted::OsSigInt => println!("exited because of an os sig int"),
        Interrupted::SystemError(msg) => println!("exited because of a system error: {msg}"),
    }

    Ok(())
}

#[derive(Clone, PartialEq)]
pub enum InputType {
    None,
    MediatorDID,
    AvatarPath,
    OurName,
    ChatMessage,
    AcceptInvite,
    ManualConnectRemoteDID,
    ManualConnectAlias,
}

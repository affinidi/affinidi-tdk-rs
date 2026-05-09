mod auth;
mod status;
mod ui;

use std::{
    io::{self, Stdout},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use clap::Parser;
use crossterm::event::EventStream;
use ratatui::{
    crossterm::{
        event::{DisableMouseCapture, Event, KeyCode, KeyEventKind},
        execute,
        terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
    },
    prelude::*,
};
use tokio_stream::StreamExt;

use auth::AdminAuth;
use status::StatusPoller;

#[derive(Parser)]
#[command(
    name = "mediator-monitor",
    about = "Real-time monitoring dashboard for Affinidi Messaging Mediator"
)]
struct Args {
    /// Mediator base URL (e.g., http://localhost:7037/mediator/v1/)
    #[arg(
        long,
        short = 'u',
        default_value = "http://localhost:7037/mediator/v1/"
    )]
    url: String,

    /// Poll interval in seconds
    #[arg(long, short = 'i', default_value_t = 2)]
    interval: u64,

    /// Path to a JSON file describing the admin profile to authenticate as.
    ///
    /// File shape mirrors `affinidi_tdk_common::profiles::TDKProfile`:
    /// `{ "alias": "...", "did": "...", "mediator": "...", "secrets": [...] }`.
    /// The `mediator` field must be the mediator's DID (the JWT audience),
    /// not its URL — the URL comes from `--url`.
    ///
    /// Required because the mediator's `/admin/status` endpoint is gated on
    /// an admin-tier JWT.
    #[arg(long, short = 'a', value_name = "PATH")]
    admin_profile: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let url = args.url.trim_end_matches('/').to_string();
    let poll_interval = Duration::from_secs(args.interval);

    // Build the auth session before opening the TUI: a bad admin profile
    // path or unparseable JSON should fail fast on the terminal the user
    // launched from, not buried inside the alternate screen.
    let auth = Arc::new(
        AdminAuth::from_profile_path(&args.admin_profile)
            .await
            .context("loading admin profile")?,
    );

    let mut poller = StatusPoller::new(&url, auth.clone());

    let mut terminal = setup_terminal()?;

    let result = run_event_loop(&mut terminal, &mut poller, poll_interval).await;

    restore_terminal(&mut terminal)?;

    // Best-effort SDK shutdown — tears down deletion handler and any
    // websocket tasks (we use none, but the deletion handler runs
    // unconditionally on `ATM::new`).
    auth.shutdown().await;

    result
}

async fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    poller: &mut StatusPoller,
    poll_interval: Duration,
) -> anyhow::Result<()> {
    let mut ticker = tokio::time::interval(poll_interval);
    let mut crossterm_events = EventStream::new();

    // Initial poll
    poller.poll().await;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                poller.poll().await;
            },
            maybe_event = crossterm_events.next() => match maybe_event {
                Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Char('r') => { poller.poll().await; },
                        _ => {}
                    }
                },
                None => break,
                _ => (),
            },
        }

        terminal
            .draw(|frame| ui::render(frame, poller))
            .context("could not render to the terminal")?;
    }

    Ok(())
}

fn setup_terminal() -> anyhow::Result<Terminal<CrosstermBackend<Stdout>>> {
    let mut stdout = io::stdout();
    enable_raw_mode()?;
    execute!(stdout, EnterAlternateScreen, DisableMouseCapture)?;
    Ok(Terminal::new(CrosstermBackend::new(stdout))?)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> anyhow::Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    Ok(terminal.show_cursor()?)
}

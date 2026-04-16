mod status;
mod ui;

use std::{
    io::{self, Stdout},
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let url = args.url.trim_end_matches('/').to_string();
    let poll_interval = Duration::from_secs(args.interval);

    let mut poller = StatusPoller::new(&url);

    let mut terminal = setup_terminal()?;

    let result = run_event_loop(&mut terminal, &mut poller, poll_interval).await;

    restore_terminal(&mut terminal)?;

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

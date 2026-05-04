//! TUI rendering for the mediator monitor dashboard.
//!
//! Layout inspired by btop:
//! ┌─ Affinidi Mediator Monitor ──────────────────────────────────────┐
//! │ ┌─ Overview ─────────────────┐  ┌─ Messages ──────────────────┐ │
//! │ │ Version: 0.14.0            │  │ Received:  12,345 (1.2K/s)  │ │
//! │ │ Uptime:  2d 5h 30m         │  │ Sent:      10,200           │ │
//! │ │ Status:  ● Connected       │  │ Deleted:   2,145            │ │
//! │ │ Circuit: closed            │  │ Queued:    10,000           │ │
//! │ └────────────────────────────┘  │ Inbound:   523 bytes/s      │ │
//! │ ┌─ Connections ──────────────┐  └─────────────────────────────┘ │
//! │ │ WebSocket: 42 / 10,000     │  ┌─ Forwarding ────────────────┐ │
//! │ │ Database:  redis://...     │  │ Queue: ██████░░░  120/50K   │ │
//! │ │ Timeout:   2s              │  │ Status: processing          │ │
//! │ └────────────────────────────┘  └─────────────────────────────┘ │
//! │  q Quit  r Refresh                                              │
//! └──────────────────────────────────────────────────────────────────┘

use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Gauge, Padding, Paragraph},
};

use crate::status::StatusPoller;

const PRIMARY: Color = Color::Rgb(100, 149, 237);
const ACCENT: Color = Color::Rgb(72, 209, 204);
const SUCCESS: Color = Color::Green;
const WARNING: Color = Color::Yellow;
const ERROR: Color = Color::Red;
const MUTED: Color = Color::DarkGray;
const TEXT: Color = Color::White;
const BORDER: Color = Color::Rgb(80, 80, 100);

pub fn render(frame: &mut Frame, poller: &StatusPoller) {
    let size = frame.area();

    // Outer border
    let outer = Block::default()
        .title(" Affinidi Mediator Monitor ")
        .title_style(Style::default().fg(PRIMARY).add_modifier(Modifier::BOLD))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER));

    let inner = outer.inner(size);
    frame.render_widget(outer, size);

    // Help bar at bottom
    let help_height = 1u16;
    let main_area = Rect {
        x: inner.x,
        y: inner.y,
        width: inner.width,
        height: inner.height.saturating_sub(help_height),
    };
    let help_area = Rect {
        x: inner.x,
        y: inner.y + main_area.height,
        width: inner.width,
        height: help_height,
    };

    let help = Paragraph::new(Line::from(vec![
        Span::styled(
            "  q",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Quit  ", Style::default().fg(MUTED)),
        Span::styled(
            "r",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Refresh  ", Style::default().fg(MUTED)),
        Span::styled(&poller.current.timestamp, Style::default().fg(MUTED)),
    ]));
    frame.render_widget(help, help_area);

    // Two-column layout
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(main_area);

    // Left column: Overview + Connections
    let left_panels = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(6)])
        .split(columns[0]);

    render_overview(frame, left_panels[0], poller);
    render_connections(frame, left_panels[1], poller);

    // Right column: Messages + Forwarding
    let right_panels = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(5)])
        .split(columns[1]);

    render_messages(frame, right_panels[0], poller);
    render_forwarding(frame, right_panels[1], poller);
}

fn render_overview(frame: &mut Frame, area: Rect, poller: &StatusPoller) {
    let block = Block::default()
        .title(" Overview ")
        .title_style(Style::default().fg(PRIMARY))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .padding(Padding::new(1, 1, 0, 0));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let (status_label, status_style) = if poller.connected {
        ("\u{25CF} Connected", Style::default().fg(SUCCESS))
    } else {
        ("\u{25CF} Disconnected", Style::default().fg(ERROR))
    };

    let cb_style = match poller.current.circuit_breaker.as_str() {
        "closed" => Style::default().fg(SUCCESS),
        "half_open" => Style::default().fg(WARNING),
        _ => Style::default().fg(ERROR),
    };

    let mut lines = vec![
        Line::from(vec![
            Span::styled("  Version:  ", Style::default().fg(MUTED)),
            Span::styled(&poller.current.version, Style::default().fg(TEXT)),
        ]),
        Line::from(vec![
            Span::styled("  Uptime:   ", Style::default().fg(MUTED)),
            Span::styled(poller.uptime_display(), Style::default().fg(TEXT)),
        ]),
        Line::from(vec![
            Span::styled("  Status:   ", Style::default().fg(MUTED)),
            Span::styled(status_label, status_style),
        ]),
        Line::from(vec![
            Span::styled("  Circuit:  ", Style::default().fg(MUTED)),
            Span::styled(&poller.current.circuit_breaker, cb_style),
        ]),
    ];

    if let Some(ref err) = poller.error {
        lines.push(Line::from(Span::styled(
            format!("  Error: {err}"),
            Style::default().fg(ERROR),
        )));
    }

    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_connections(frame: &mut Frame, area: Rect, poller: &StatusPoller) {
    let block = Block::default()
        .title(" Connections ")
        .title_style(Style::default().fg(PRIMARY))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .padding(Padding::new(1, 1, 0, 0));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let ws = &poller.current.connections;
    let db = &poller.current.database;

    let lines = vec![
        Line::from(vec![
            Span::styled("  WebSocket: ", Style::default().fg(MUTED)),
            Span::styled(
                format!("{} / {}", ws.websocket_active, ws.websocket_max),
                Style::default().fg(TEXT),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Database:  ", Style::default().fg(MUTED)),
            Span::styled(&db.url, Style::default().fg(TEXT)),
        ]),
        Line::from(vec![
            Span::styled("  Timeout:   ", Style::default().fg(MUTED)),
            Span::styled(format!("{}s", db.timeout), Style::default().fg(TEXT)),
        ]),
    ];

    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_messages(frame: &mut Frame, area: Rect, poller: &StatusPoller) {
    let block = Block::default()
        .title(" Messages ")
        .title_style(Style::default().fg(PRIMARY))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .padding(Padding::new(1, 1, 0, 0));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let msg = &poller.current.messages;
    let queued = msg.received_count - msg.deleted_count - msg.sent_count;

    let lines = vec![
        Line::from(vec![
            Span::styled("  Received:  ", Style::default().fg(MUTED)),
            Span::styled(
                format_number(msg.received_count),
                Style::default().fg(ACCENT),
            ),
            Span::styled(
                format!("  ({:.1} msg/s)", poller.msg_per_sec),
                Style::default().fg(MUTED),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Sent:      ", Style::default().fg(MUTED)),
            Span::styled(format_number(msg.sent_count), Style::default().fg(TEXT)),
        ]),
        Line::from(vec![
            Span::styled("  Deleted:   ", Style::default().fg(MUTED)),
            Span::styled(format_number(msg.deleted_count), Style::default().fg(TEXT)),
        ]),
        Line::from(vec![
            Span::styled("  Queued:    ", Style::default().fg(MUTED)),
            Span::styled(
                format_number(queued.max(0)),
                Style::default().fg(if queued > 1000 { WARNING } else { TEXT }),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Inbound:   ", Style::default().fg(MUTED)),
            Span::styled(
                format_bytes(poller.bytes_per_sec),
                Style::default().fg(TEXT),
            ),
        ]),
    ];

    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_forwarding(frame: &mut Frame, area: Rect, poller: &StatusPoller) {
    let fwd = &poller.current.forwarding;
    let ratio = if fwd.queue_limit > 0 {
        (fwd.queue_length as f64 / fwd.queue_limit as f64).min(1.0)
    } else {
        0.0
    };

    let color = if ratio > 0.8 {
        ERROR
    } else if ratio > 0.5 {
        WARNING
    } else {
        SUCCESS
    };

    let gauge = Gauge::default()
        .block(
            Block::default()
                .title(" Forwarding Queue ")
                .title_style(Style::default().fg(PRIMARY))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER)),
        )
        .gauge_style(Style::default().fg(color))
        .ratio(ratio)
        .label(format!(
            "{} / {}",
            format_number(fwd.queue_length as i64),
            format_number(fwd.queue_limit as i64)
        ));

    frame.render_widget(gauge, area);
}

fn format_number(n: i64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

fn format_bytes(bytes_per_sec: f64) -> String {
    if bytes_per_sec >= 1_048_576.0 {
        format!("{:.1} MB/s", bytes_per_sec / 1_048_576.0)
    } else if bytes_per_sec >= 1_024.0 {
        format!("{:.1} KB/s", bytes_per_sec / 1_024.0)
    } else {
        format!("{bytes_per_sec:.0} B/s")
    }
}

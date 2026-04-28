//! Renderer for the Testing / Connected phases of the online-VTA sub-flow.
//!
//! Shows a live checklist: per-check icon, label, and detail text. Below the
//! list, surfaces an actionable hint on failure, a success banner on connect,
//! or a spinner while the runner is still in flight.

use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Wrap},
};

use crate::ui::selection::SelectionOption;
use crate::ui::theme;
use crate::vta::{ConnectPhase, DiagEntry, DiagStatus, VtaConnectState};

pub fn render_diagnostics(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    description: &str,
    state: &VtaConnectState,
    options: &[SelectionOption],
    selection_index: usize,
    focused: bool,
) {
    // Layout mirrors `render_instructions`: action box on top, diagnostic
    // checklist below. Keeping the two phases visually consistent means the
    // operator always knows where to look for "next step".
    let status_lines = build_status_lines(state);
    let action_lines: u16 = options.len() as u16 * 2 + status_lines.len() as u16;
    // 2 chrome (border) + content; minimum 4 to still render a visible box
    // during the "runner in flight" state where there are no options yet.
    let action_height = (action_lines + 2).max(4);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(action_height),
            Constraint::Min(4),
        ])
        .split(area);

    let header = Paragraph::new(vec![
        Line::from(Span::styled(title, theme::title_style())),
        Line::from(Span::styled(description, theme::muted_style())),
    ]);
    frame.render_widget(header, chunks[0]);

    crate::ui::instructions::render_action_box(
        frame,
        chunks[1],
        options,
        selection_index,
        focused,
        status_lines,
    );

    let lines = diag_lines(state);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border_style())
        .title(Span::styled(
            " Connection diagnostics ",
            theme::title_style(),
        ));
    let para = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    frame.render_widget(para, chunks[2]);
}

/// Status lines rendered inside the action box: success banner (plus the
/// rotated admin DID on success), runner spinner, or error detail.
fn build_status_lines(state: &VtaConnectState) -> Vec<Line<'_>> {
    match state.phase {
        ConnectPhase::Connected => {
            let Some(conn) = state.connection.as_ref() else {
                return Vec::new();
            };
            // Two reply variants surface different facts. FullSetup
            // reports both the rolled-over admin DID and the
            // VTA-minted integration DID; AdminOnly only has the
            // admin DID (integration DID came from the earlier Did
            // step, not the VTA). The online runner only ever
            // produces these two variants — the offline-only
            // `ContextExport` reply lands directly on `VtaSession`
            // without flowing through `state.connection`.
            use vta_sdk::provision_client::VtaReply;
            let mut rows = match &conn.reply {
                VtaReply::Full(provision) => vec![
                    Line::from(Span::styled(
                        format!("  Connected via {}.", conn.protocol.label()),
                        theme::success_style(),
                    )),
                    Line::from(Span::styled(
                        format!(
                            "  Admin DID: {}{}",
                            provision.admin_did(),
                            if provision.summary.admin_rolled_over {
                                " (rolled over by VTA)"
                            } else {
                                ""
                            }
                        ),
                        theme::info_style(),
                    )),
                    Line::from(Span::styled(
                        format!("  Mediator DID: {}", provision.integration_did()),
                        theme::info_style(),
                    )),
                ],
                VtaReply::AdminOnly(admin) => vec![
                    Line::from(Span::styled(
                        format!("  Connected via {}.", conn.protocol.label()),
                        theme::success_style(),
                    )),
                    Line::from(Span::styled(
                        format!("  Admin DID: {} (enrolled, no rotation)", admin.admin_did),
                        theme::info_style(),
                    )),
                ],
            };
            // Hotkey hint: which letters copy what. `[m]` is hidden
            // for AdminOnly because there's no VTA-minted mediator
            // DID to copy.
            let has_mediator_did = matches!(&conn.reply, VtaReply::Full(_));
            let hint = if has_mediator_did {
                "  [v] copy VTA DID  [m] copy mediator DID  [a] copy admin DID"
            } else {
                "  [v] copy VTA DID  [a] copy admin DID"
            };
            rows.push(Line::from(Span::styled(hint, theme::muted_style())));
            // Surface the most-recent clipboard result so the
            // operator can see whether the last copy actually
            // attempted (and via which path).
            if let Some(status) = state.clipboard_status.as_deref() {
                rows.push(Line::from(Span::styled(
                    format!("  {status}"),
                    theme::muted_style(),
                )));
            }
            rows
        }
        ConnectPhase::Testing => {
            if state.event_rx.is_some() {
                vec![Line::from(Span::styled("  Running…", theme::muted_style()))]
            } else if let Some(err) = state.last_error.as_ref() {
                vec![Line::from(Span::styled(
                    format!("  {err}"),
                    Style::default().fg(Color::Red),
                ))]
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    }
}

fn diag_lines(state: &VtaConnectState) -> Vec<Line<'_>> {
    if state.diagnostics.is_empty() {
        return vec![Line::from(Span::styled(
            "  Waiting for diagnostics…",
            theme::muted_style(),
        ))];
    }
    state
        .diagnostics
        .iter()
        .map(|e| diag_line(e))
        .collect::<Vec<_>>()
}

fn diag_line(entry: &DiagEntry) -> Line<'_> {
    let (icon, icon_style, detail_style, detail) = match &entry.status {
        DiagStatus::Pending => (
            "\u{25CB}",
            theme::muted_style(),
            theme::muted_style(),
            String::new(),
        ),
        DiagStatus::Running => (
            "\u{2022}",
            theme::info_style(),
            theme::muted_style(),
            "running…".into(),
        ),
        DiagStatus::Ok(d) => (
            "\u{2714}",
            theme::success_style(),
            theme::muted_style(),
            d.clone(),
        ),
        DiagStatus::Skipped(d) => (
            "\u{2015}",
            theme::muted_style(),
            theme::muted_style(),
            d.clone(),
        ),
        DiagStatus::Failed(d) => (
            "\u{2718}",
            Style::default().fg(Color::Red),
            Style::default().fg(Color::Red),
            d.clone(),
        ),
    };

    Line::from(vec![
        Span::styled(format!("  {icon}  "), icon_style),
        Span::styled(entry.check.label().to_string(), theme::normal_style()),
        Span::raw("  "),
        Span::styled(detail, detail_style),
    ])
}

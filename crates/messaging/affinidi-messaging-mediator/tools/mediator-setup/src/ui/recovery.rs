//! Renderer for [`ConnectPhase::RecoveryPrompt`].
//!
//! Layout mirrors `render_diagnostics`: title/description header,
//! an action box with the retry / offline / back options, and a
//! bordered "Last attempt" panel beneath that lists each
//! transport's failure reason in dim red.
//!
//! Option building lives in `app::current_options()`; the renderer
//! is purely presentational. Disabled options come from the
//! `app` layer via `SelectionOption::disabled()` — the action box
//! dims them and the keyboard handler skips them.

use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Wrap},
};

use crate::ui::selection::SelectionOption;
use crate::ui::theme;
use crate::vta::{AttemptResult, AttemptResultKind, VtaConnectState};

pub fn render_recovery_prompt(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    description: &str,
    state: &VtaConnectState,
    options: &[SelectionOption],
    selection_index: usize,
    focused: bool,
) {
    // Action box first, attempt-history panel below — same shape
    // as the diagnostics phase so the operator's eye doesn't have
    // to relocate.
    let action_lines: u16 = options.len() as u16 * 2;
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
        Vec::new(),
    );

    let attempt_lines = build_attempt_lines(state);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border_style())
        .title(Span::styled(" Last attempt ", theme::title_style()));
    let para = Paragraph::new(attempt_lines)
        .block(block)
        .wrap(Wrap { trim: false });
    frame.render_widget(para, chunks[2]);
}

/// Render the per-transport failure reasons. Each transport gets
/// at most one line — its most recent attempt outcome. Connected
/// outcomes are skipped (they wouldn't be in the recovery prompt
/// in normal flow). Empty state means the recovery prompt fired
/// before any attempt landed (`Neither` advertised).
fn build_attempt_lines(state: &VtaConnectState) -> Vec<Line<'_>> {
    let mut lines = Vec::new();

    if let Some(result) = state.attempted.didcomm.as_ref()
        && let Some(line) = format_attempt_line("DIDComm", result)
    {
        lines.push(line);
    }
    if let Some(result) = state.attempted.rest.as_ref()
        && let Some(line) = format_attempt_line("REST", result)
    {
        lines.push(line);
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No transport advertised by the VTA — switch to offline sealed-handoff.",
            theme::muted_style(),
        )));
    }

    lines
}

fn format_attempt_line(label: &str, result: &AttemptResult) -> Option<Line<'static>> {
    let (kind, reason) = match &result.outcome {
        AttemptResultKind::Connected => return None,
        AttemptResultKind::PreAuthFailure(reason) => ("pre-auth", reason.clone()),
        AttemptResultKind::PostAuthFailure(reason) => ("post-auth", reason.clone()),
    };
    Some(Line::from(vec![
        Span::styled(
            format!("  {label} ({kind}): "),
            Style::default().fg(Color::Red),
        ),
        Span::styled(reason, theme::muted_style()),
    ]))
}

//! Renderer for [`ConnectPhase::RecoveryPrompt`].
//!
//! Layout mirrors `render_diagnostics`: title/description header,
//! an action box with the retry / offline / back options, and a
//! bordered "Why it failed" panel beneath. That panel surfaces the
//! failure detail that previously only flashed past on the Testing
//! screen before the transition to recovery: the overall error, the
//! per-check diagnostics checklist (reused from `ui::diagnostics`),
//! and the per-transport attempt summary (see [`recovery_detail_lines`]).
//!
//! Option building lives in `app::current_options()`; the renderer
//! is purely presentational. Disabled options come from the
//! `app` layer via `SelectionOption::disabled()` — the action box
//! dims them and the keyboard handler skips them.

use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Wrap},
};

use crate::ui::diagnostics::diag_lines;
use crate::ui::selection::SelectionOption;
use crate::ui::theme;
use crate::vta::{AttemptResult, AttemptResultKind, VtaConnectState};

// 8 params: same shape as `render_diagnostics` /
// `render_instructions`. See `ui/diagnostics.rs` for the grouping
// discussion.
#[allow(clippy::too_many_arguments)]
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

    let detail_lines = recovery_detail_lines(state);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border_style())
        .title(Span::styled(" Why it failed ", theme::title_style()));
    let para = Paragraph::new(detail_lines)
        .block(block)
        .wrap(Wrap { trim: false });
    frame.render_widget(para, chunks[2]);
}

/// Compose the recovery screen's failure panel so the operator can actually
/// *read* what went wrong instead of catching it as it flashes past on the
/// Testing screen. Three sections, each shown only when it has content:
///   1. the overall error (`last_error`),
///   2. the per-check diagnostics checklist — the same lines the Testing screen
///      rendered, now persisted (see [`diag_lines`]),
///   3. the per-transport attempt summary.
pub(crate) fn recovery_detail_lines(state: &VtaConnectState) -> Vec<Line<'_>> {
    let mut lines: Vec<Line<'_>> = Vec::new();

    if let Some(err) = state.last_error.as_ref() {
        lines.push(Line::from(Span::styled(
            format!("  Error: {err}"),
            Style::default().fg(Color::Red),
        )));
    }

    if !state.diagnostics.is_empty() {
        if !lines.is_empty() {
            lines.push(Line::from(""));
        }
        lines.extend(diag_lines(state));
    }

    let attempts = transport_attempt_lines(state);
    if !attempts.is_empty() {
        if !lines.is_empty() {
            lines.push(Line::from(""));
        }
        lines.extend(attempts);
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No transport advertised by the VTA — switch to offline sealed-handoff.",
            theme::muted_style(),
        )));
    }

    lines
}

/// Render the per-transport failure reasons. Each transport gets
/// at most one line — its most recent attempt outcome. Connected
/// outcomes are skipped (they wouldn't be in the recovery prompt
/// in normal flow). Empty state means the recovery prompt fired
/// before any attempt landed (`Neither` advertised).
fn transport_attempt_lines(state: &VtaConnectState) -> Vec<Line<'_>> {
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

#[cfg(test)]
mod tests {
    use super::recovery_detail_lines;
    use crate::vta::{AttemptResult, AttemptResultKind, VtaConnectState, VtaIntent};
    use ratatui::prelude::Line;
    use std::time::Instant;

    /// Flatten rendered lines back to plain text for assertions.
    fn text(lines: &[Line<'_>]) -> String {
        lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn surfaces_the_overall_error() {
        let mut st = VtaConnectState::new(VtaIntent::FullSetup);
        st.last_error = Some("VTA DID resolution failed: not found".into());
        let rendered = text(&recovery_detail_lines(&st));
        assert!(
            rendered.contains("VTA DID resolution failed: not found"),
            "recovery panel must show the captured error, got: {rendered}"
        );
    }

    #[test]
    fn surfaces_per_transport_attempt_reason() {
        let mut st = VtaConnectState::new(VtaIntent::FullSetup);
        st.attempted.rest = Some(AttemptResult {
            outcome: AttemptResultKind::PreAuthFailure("REST 401 Unauthorized".into()),
            at: Instant::now(),
        });
        let rendered = text(&recovery_detail_lines(&st));
        assert!(rendered.contains("REST (pre-auth)"), "got: {rendered}");
        assert!(
            rendered.contains("REST 401 Unauthorized"),
            "got: {rendered}"
        );
    }

    #[test]
    fn falls_back_when_nothing_was_captured() {
        // No error, no diagnostics, no attempts: still render an actionable line
        // rather than an empty box.
        let st = VtaConnectState::new(VtaIntent::FullSetup);
        let rendered = text(&recovery_detail_lines(&st));
        assert!(
            rendered.contains("No transport advertised"),
            "got: {rendered}"
        );
    }
}

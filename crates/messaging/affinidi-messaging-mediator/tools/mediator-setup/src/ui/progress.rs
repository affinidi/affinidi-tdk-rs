use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Padding, Paragraph},
};

use crate::{
    app::{FocusPanel, WizardStep},
    ui::theme,
};

/// Renders the left-side progress panel showing all wizard steps.
/// When focused (via Left arrow), shows a highlight cursor for step selection.
pub fn render_progress(
    frame: &mut Frame,
    area: Rect,
    current_step: WizardStep,
    completed: &[WizardStep],
    focus: FocusPanel,
    progress_index: usize,
) {
    let focused = focus == FocusPanel::Progress;
    let block = Block::default()
        .title(if focused {
            " Progress (select step) "
        } else {
            " Progress "
        })
        .title_style(if focused {
            theme::selected_style()
        } else {
            theme::title_style()
        })
        .borders(Borders::ALL)
        .border_style(if focused {
            theme::selected_style()
        } else {
            theme::border_style()
        })
        .padding(Padding::new(1, 1, 1, 0));

    let steps = WizardStep::all();
    let mut lines: Vec<Line> = Vec::new();

    for (i, step) in steps.iter().enumerate() {
        let (indicator, mut style) = if completed.contains(step) {
            (" \u{2713} ", theme::success_style()) // checkmark
        } else if *step == current_step {
            (" \u{25B6} ", theme::selected_style()) // arrow
        } else {
            (" \u{25CB} ", theme::muted_style()) // circle
        };

        // When progress panel is focused, highlight the cursor position
        if focused && i == progress_index {
            style = style.bg(theme::HIGHLIGHT_BG).add_modifier(Modifier::BOLD);
        }

        lines.push(Line::from(vec![
            Span::styled(indicator, style),
            Span::styled(step.label(), style),
        ]));
        lines.push(Line::from("")); // spacing
    }

    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);
}

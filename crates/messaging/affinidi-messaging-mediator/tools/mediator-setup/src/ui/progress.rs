use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Padding, Paragraph},
};

use crate::{app::WizardStep, ui::theme};

/// Renders the left-side progress panel showing all wizard steps.
pub fn render_progress(
    frame: &mut Frame,
    area: Rect,
    current_step: WizardStep,
    completed: &[WizardStep],
) {
    let block = Block::default()
        .title(" Progress ")
        .title_style(theme::title_style())
        .borders(Borders::ALL)
        .border_style(theme::border_style())
        .padding(Padding::new(1, 1, 1, 0));

    let steps = WizardStep::all();
    let mut lines: Vec<Line> = Vec::new();

    for step in &steps {
        let (indicator, style) = if completed.contains(step) {
            (" \u{2713} ", theme::success_style()) // checkmark
        } else if *step == current_step {
            (" \u{25B6} ", theme::selected_style()) // arrow
        } else {
            (" \u{25CB} ", theme::muted_style()) // circle
        };

        lines.push(Line::from(vec![
            Span::styled(indicator, style),
            Span::styled(step.label(), style),
        ]));
        lines.push(Line::from("")); // spacing
    }

    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);
}

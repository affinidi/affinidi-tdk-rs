use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Padding, Paragraph, Wrap},
};

use crate::ui::theme;

/// Renders a context-sensitive info box with help text.
pub fn render_info_box(frame: &mut Frame, area: Rect, title: &str, text: &str) {
    let block = Block::default()
        .title(format!(" {title} "))
        .title_style(theme::info_style())
        .borders(Borders::ALL)
        .border_style(theme::border_style())
        .padding(Padding::new(1, 1, 0, 0));

    let paragraph = Paragraph::new(text)
        .style(theme::dim_style())
        .block(block)
        .wrap(Wrap { trim: true });

    frame.render_widget(paragraph, area);
}

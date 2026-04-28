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

    // `[Key]` tokens (e.g. `[Space]`, `[Enter]`) render in the accent
    // colour to match the hotkey-cue convention used elsewhere in the
    // wizard. Surrounding text keeps the dim info-box style.
    let paragraph = Paragraph::new(theme::key_styled_line(text, theme::dim_style()))
        .block(block)
        .wrap(Wrap { trim: true });

    frame.render_widget(paragraph, area);
}

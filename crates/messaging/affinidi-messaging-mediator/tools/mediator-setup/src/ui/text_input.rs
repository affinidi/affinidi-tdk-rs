use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Padding, Paragraph},
};
use tui_input::Input;

use crate::ui::theme;

/// Renders a text input field with label and current value.
pub fn render_text_input(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    label: &str,
    input: &Input,
    active: bool,
) {
    let block = Block::default()
        .title(format!(" {title} "))
        .title_style(theme::title_style())
        .borders(Borders::ALL)
        .border_style(if active {
            theme::selected_style()
        } else {
            theme::border_style()
        })
        .padding(Padding::new(1, 1, 1, 0));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Label
    let label_area = Rect {
        x: inner.x,
        y: inner.y,
        width: inner.width,
        height: 1,
    };
    let label_widget = Paragraph::new(label).style(theme::dim_style());
    frame.render_widget(label_widget, label_area);

    // Input value
    let input_area = Rect {
        x: inner.x,
        y: inner.y + 2,
        width: inner.width,
        height: 1,
    };

    let input_style = if active {
        theme::normal_style()
    } else {
        theme::dim_style()
    };

    let value = input.value();
    let display = if value.is_empty() && !active {
        Paragraph::new("(empty)").style(theme::muted_style())
    } else {
        Paragraph::new(value).style(input_style)
    };
    frame.render_widget(display, input_area);

    // Cursor
    if active {
        let cursor_x = input_area.x + input.visual_cursor() as u16;
        frame.set_cursor_position(Position::new(cursor_x, input_area.y));
    }
}

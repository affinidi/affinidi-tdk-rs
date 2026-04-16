use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Padding, Paragraph},
};

use crate::ui::theme;

/// A single option in a selection list.
pub struct SelectionOption {
    pub label: String,
    #[allow(dead_code)] // stored per-option, info text rendered via current_info_text()
    pub info: String,
}

impl SelectionOption {
    pub fn new(label: impl Into<String>, info: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            info: info.into(),
        }
    }
}

/// Renders a selection list with arrow indicator on the selected item.
pub fn render_selection(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    description: &str,
    options: &[SelectionOption],
    selected: usize,
    focused: bool,
) {
    let block = Block::default()
        .title(format!(" {title} "))
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

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Description text
    let desc_height = 2u16;
    let desc_area = Rect {
        x: inner.x,
        y: inner.y,
        width: inner.width,
        height: desc_height,
    };
    let desc = Paragraph::new(description).style(theme::dim_style());
    frame.render_widget(desc, desc_area);

    // Options list
    let list_y = inner.y + desc_height + 1;
    let available_height = inner.height.saturating_sub(desc_height + 1);

    for (i, option) in options.iter().enumerate() {
        if i as u16 >= available_height {
            break;
        }

        let (prefix, style) = if i == selected {
            ("\u{203A} ", theme::selected_style()) // arrow
        } else {
            ("  ", theme::normal_style())
        };

        let line = Line::from(vec![
            Span::styled(prefix, style),
            Span::styled(&option.label, style),
        ]);

        let item_area = Rect {
            x: inner.x,
            y: list_y + i as u16,
            width: inner.width,
            height: 1,
        };
        frame.render_widget(Paragraph::new(line), item_area);
    }
}

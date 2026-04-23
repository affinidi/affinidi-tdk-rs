//! Compact single-field prompt used by the online-VTA sub-flow.
//!
//! The generic `text_input` renderer boxes the field inside a full-area
//! border that feels heavy for a "just type one line" interaction. This
//! prompt keeps the same data in a tighter visual: title + description at
//! the top, a single `❯ <value>` line with an inlined placeholder, a hint
//! below, and built-in keybinding cues.
//!
//! A terminal cursor is positioned via `frame.set_cursor_position` so the
//! native blink on the operator's terminal signals that input is expected —
//! no custom animation needed.

use ratatui::{
    prelude::*,
    widgets::{Paragraph, Wrap},
};
use tui_input::Input;

use crate::ui::theme;

/// Render a single-line prompt with cursor and optional placeholder.
///
/// - `title`: short bold header (e.g. "VTA DID").
/// - `description`: one-liner describing what to type.
/// - `tip`: optional accented line that calls out a specific command or
///   action the operator can use to find the expected input (e.g. "run
///   `pnm config get` to find the VTA DID"). Rendered between the
///   description and the prompt; omitted when `None`.
/// - `placeholder`: ghost text shown in dim grey while the field is empty;
///   disappears as soon as the operator types.
/// - `hint`: small help text rendered below the input line.
pub fn render_prompt(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    description: &str,
    tip: Option<&str>,
    input: &Input,
    placeholder: &str,
    hint: &str,
) {
    // Vertical layout: title, description, optional tip, blank, prompt,
    // blank, hint (grows for multi-line hints), then flex. The global
    // bottom help bar already shows `Enter Confirm / Esc Cancel`, so we
    // don't duplicate those keys here. The hint region is `Min(2)` so a
    // single-line hint renders one row + one row of breathing space, and
    // a multi-line hint (split on `\n`) flows into as many rows as the
    // remaining area allows.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // 0: title
            Constraint::Length(1), // 1: description
            Constraint::Length(1), // 2: tip (or blank)
            Constraint::Length(1), // 3: blank
            Constraint::Length(1), // 4: prompt
            Constraint::Length(1), // 5: blank
            Constraint::Min(2),    // 6: hint (grows for multi-line / wrap)
            Constraint::Min(0),
        ])
        .split(area);

    frame.render_widget(
        Paragraph::new(Span::styled(title, theme::title_style())),
        chunks[0],
    );
    frame.render_widget(
        Paragraph::new(Span::styled(description, theme::muted_style())).wrap(Wrap { trim: true }),
        chunks[1],
    );
    if let Some(t) = tip {
        frame.render_widget(
            Paragraph::new(Span::styled(format!("  {t}"), theme::info_style()))
                .wrap(Wrap { trim: true }),
            chunks[2],
        );
    }

    // Prompt line: two-space indent + `❯` glyph + value (or placeholder).
    let indent = "  ";
    let glyph = "\u{276F}";
    let value = input.value();
    let after_glyph_x = chunks[4].x + indent.len() as u16 + glyph.chars().count() as u16 + 1;

    let prompt_line: Line = if value.is_empty() {
        Line::from(vec![
            Span::raw(indent),
            Span::styled(glyph, theme::selected_style()),
            Span::raw(" "),
            Span::styled(placeholder.to_string(), theme::muted_style()),
        ])
    } else {
        Line::from(vec![
            Span::raw(indent),
            Span::styled(glyph, theme::selected_style()),
            Span::raw(" "),
            Span::styled(value.to_string(), theme::normal_style()),
        ])
    };
    frame.render_widget(Paragraph::new(prompt_line), chunks[4]);

    // Place the terminal cursor right where new characters would appear.
    let cursor_x = after_glyph_x + input.visual_cursor() as u16;
    frame.set_cursor_position(Position::new(cursor_x, chunks[4].y));

    // Hint text below the input. Split the hint string on `\n` so
    // callers can use `\n` (or `\n\n`) as an explicit line break —
    // `Span` treats newlines as literal characters by default, which
    // is why the multi-paragraph hint on AwaitingBundle previously
    // rendered as one clipped line. Each segment becomes its own
    // `Line` with the same dim style and `  ` indent; long lines
    // wrap within the hint's row budget via `Wrap { trim: true }`.
    if !hint.is_empty() {
        let style = theme::dim_style();
        let lines: Vec<Line> = hint
            .split('\n')
            .map(|segment| {
                if segment.is_empty() {
                    Line::from("")
                } else {
                    Line::from(Span::styled(format!("  {segment}"), style))
                }
            })
            .collect();
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), chunks[6]);
    }
}

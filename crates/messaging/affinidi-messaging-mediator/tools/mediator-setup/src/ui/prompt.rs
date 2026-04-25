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
    // don't duplicate those keys here.
    //
    // The hint region is `Min(5)` — enough to fit our widest hint today
    // (the DigestVerify screen: "Computed digest…" + "<digest>" + blank
    // + "If the producer…" wrapping to 2 rows on narrow terminals = 5
    // rows). When a hint is only one line, the extra rows are wasted
    // visual space but would have gone to the trailing flex anyway, so
    // there's no cost to short-hint screens. When two Min constraints
    // compete for leftover rows, ratatui divides them evenly, which on
    // narrow terminals can leave the hint at its minimum — hence a
    // floor generous enough to contain the longest hint rather than
    // depending on terminal height.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // 0: title
            Constraint::Length(1), // 1: description
            Constraint::Length(1), // 2: tip (or blank)
            Constraint::Length(1), // 3: blank
            Constraint::Length(1), // 4: prompt
            Constraint::Length(1), // 5: blank
            Constraint::Min(5),    // 6: hint (multi-line + wrap safety)
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
    //
    // Inside each segment, function-key tokens (`[F5]`, `[F10]`, …)
    // are styled with the accent colour so a hint that calls out a
    // hotkey reads the same as the cheatsheets in `instructions.rs`
    // (which use the bracketed `[c]` convention with the same
    // accent). The match is intentionally narrow — `[F<digits>]`
    // only — so other bracketed tokens like the `host[:port]` cue
    // on the Vault endpoint hint don't get mis-styled.
    if !hint.is_empty() {
        let lines: Vec<Line> = hint.split('\n').map(render_hint_segment).collect();
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), chunks[6]);
    }
}

/// Render one hint line: dim text with `[F\d+]` tokens swapped out
/// for accent-styled spans. `  ` indent matches the prompt line above.
fn render_hint_segment(segment: &str) -> Line<'static> {
    let indent = "  ";
    let dim = theme::dim_style();
    let key = ratatui::style::Style::default().fg(theme::ACCENT);
    if segment.is_empty() {
        return Line::from("");
    }
    let mut spans: Vec<Span<'static>> = vec![Span::raw(indent.to_string())];
    let bytes = segment.as_bytes();
    let mut cursor = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'[' && i + 2 < bytes.len() && bytes[i + 1] == b'F' {
            // Walk the digit run after `F`. A function-key token must
            // have at least one digit and end with `]`.
            let mut k = i + 2;
            while k < bytes.len() && bytes[k].is_ascii_digit() {
                k += 1;
            }
            if k > i + 2 && k < bytes.len() && bytes[k] == b']' {
                if i > cursor {
                    spans.push(Span::styled(segment[cursor..i].to_string(), dim));
                }
                spans.push(Span::styled(segment[i..=k].to_string(), key));
                cursor = k + 1;
                i = k + 1;
                continue;
            }
        }
        i += 1;
    }
    if cursor < segment.len() {
        spans.push(Span::styled(segment[cursor..].to_string(), dim));
    }
    Line::from(spans)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assert that a `[F<digits>]` token is split into its own accent-
    /// styled span and the surrounding text keeps the dim hint style.
    #[test]
    fn hint_segment_styles_function_key_tokens() {
        let line = render_hint_segment("press [F5] to discover existing prefixes.");
        // 4 spans: indent, dim prefix ("press "), accent ("[F5]"),
        // dim suffix (" to discover existing prefixes.").
        assert_eq!(line.spans.len(), 4);
        assert_eq!(line.spans[0].content, "  ");
        assert_eq!(line.spans[1].content, "press ");
        assert_eq!(line.spans[2].content, "[F5]");
        assert_eq!(line.spans[2].style.fg, Some(theme::ACCENT));
        assert_eq!(line.spans[3].content, " to discover existing prefixes.");
    }

    /// Brackets that aren't function-key tokens (e.g. the `[:port]`
    /// cue on the Vault endpoint hint) must stay in the dim hint
    /// style so we don't accidentally highlight non-keys.
    #[test]
    fn hint_segment_leaves_non_function_brackets_alone() {
        let line = render_hint_segment("server `host[:port]` defaults to https://.");
        // No accent span — the whole hint is rendered as indent + dim.
        assert_eq!(line.spans.len(), 2);
        assert_eq!(line.spans[0].content, "  ");
        assert!(
            !line.spans.iter().any(|s| s.style.fg == Some(theme::ACCENT)),
            "expected no accent-styled spans in {:?}",
            line.spans,
        );
    }

    /// Multi-digit function keys (`[F10]`) must match too — the
    /// global F10 quit shortcut would benefit if a future hint
    /// surfaces it inline.
    #[test]
    fn hint_segment_matches_multi_digit_function_keys() {
        let line = render_hint_segment("press [F10] to quit at any time.");
        assert!(
            line.spans
                .iter()
                .any(|s| s.content == "[F10]" && s.style.fg == Some(theme::ACCENT)),
            "[F10] should be accent-styled, got {:?}",
            line.spans,
        );
    }

    /// An empty segment renders an empty line — preserves the
    /// behaviour callers depend on when they want a blank-line gap
    /// between paragraphs (`\n\n`). `Line::from("")` carries no
    /// spans (ratatui treats the empty `&str` as zero content), so
    /// the assertion checks the rendered string is empty rather
    /// than asserting a span count.
    #[test]
    fn hint_segment_empty_segment_renders_blank() {
        let line = render_hint_segment("");
        let rendered: String = line
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect::<Vec<&str>>()
            .concat();
        assert!(rendered.is_empty(), "expected blank line, got {rendered:?}");
    }
}

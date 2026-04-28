use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

// Affinidi brand-inspired color scheme
pub const PRIMARY: Color = Color::Rgb(100, 149, 237); // Cornflower blue
pub const ACCENT: Color = Color::Rgb(72, 209, 204); // Medium turquoise
pub const SUCCESS: Color = Color::Green;
pub const MUTED: Color = Color::DarkGray;
pub const TEXT: Color = Color::White;
pub const DIM_TEXT: Color = Color::Gray;
pub const HIGHLIGHT_BG: Color = Color::Rgb(40, 40, 60);
pub const BORDER: Color = Color::Rgb(80, 80, 100);
pub const TITLE: Color = Color::Rgb(100, 149, 237);

// Gradient endpoints: purple → blue
const GRADIENT_START: (u8, u8, u8) = (160, 100, 220); // Purple
const GRADIENT_END: (u8, u8, u8) = (50, 120, 220); // Blue

/// Interpolate a gradient color for a given row within total height.
pub fn gradient_color(row: u16, total_height: u16) -> Color {
    if total_height <= 1 {
        return Color::Rgb(GRADIENT_START.0, GRADIENT_START.1, GRADIENT_START.2);
    }
    let t = row as f32 / (total_height - 1) as f32;
    let r = (GRADIENT_START.0 as f32 + (GRADIENT_END.0 as f32 - GRADIENT_START.0 as f32) * t) as u8;
    let g = (GRADIENT_START.1 as f32 + (GRADIENT_END.1 as f32 - GRADIENT_START.1 as f32) * t) as u8;
    let b = (GRADIENT_START.2 as f32 + (GRADIENT_END.2 as f32 - GRADIENT_START.2 as f32) * t) as u8;
    Color::Rgb(r, g, b)
}

pub fn title_style() -> Style {
    Style::default().fg(TITLE).add_modifier(Modifier::BOLD)
}

pub fn selected_style() -> Style {
    Style::default()
        .fg(ACCENT)
        .add_modifier(Modifier::BOLD)
        .bg(HIGHLIGHT_BG)
}

pub fn normal_style() -> Style {
    Style::default().fg(TEXT)
}

pub fn muted_style() -> Style {
    Style::default().fg(MUTED)
}

pub fn dim_style() -> Style {
    Style::default().fg(DIM_TEXT)
}

pub fn success_style() -> Style {
    Style::default().fg(SUCCESS)
}

pub fn info_style() -> Style {
    Style::default().fg(PRIMARY)
}

pub fn border_style() -> Style {
    Style::default().fg(BORDER)
}

/// Render `text` as a `Line` where bracketed alphanumeric tokens
/// (e.g. `[Space]`, `[Enter]`, `[Esc]`, `[F5]`) are styled with the
/// accent colour while the surrounding text uses `base_style`. Matches
/// the keyboard-cue convention used elsewhere in the wizard
/// (`instructions.rs::Hotkey:  [c]`, `prompt.rs` hint segments).
pub fn key_styled_line(text: &str, base_style: Style) -> Line<'static> {
    let key_style = Style::default().fg(ACCENT);
    let bytes = text.as_bytes();
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut cursor = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'[' {
            let mut k = i + 1;
            while k < bytes.len() && bytes[k].is_ascii_alphanumeric() {
                k += 1;
            }
            if k > i + 1 && k < bytes.len() && bytes[k] == b']' {
                if i > cursor {
                    spans.push(Span::styled(text[cursor..i].to_string(), base_style));
                }
                spans.push(Span::styled(text[i..=k].to_string(), key_style));
                cursor = k + 1;
                i = k + 1;
                continue;
            }
        }
        i += 1;
    }
    if cursor < text.len() {
        spans.push(Span::styled(text[cursor..].to_string(), base_style));
    }
    if spans.is_empty() {
        spans.push(Span::styled(String::new(), base_style));
    }
    Line::from(spans)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_styled_line_highlights_bracketed_tokens() {
        let line = key_styled_line("Press [Space] to toggle, [Enter] to continue.", dim_style());
        // 5 spans: "Press ", "[Space]", " to toggle, ", "[Enter]", " to continue."
        assert_eq!(line.spans.len(), 5);
        assert_eq!(line.spans[0].content, "Press ");
        assert_eq!(line.spans[0].style.fg, Some(DIM_TEXT));
        assert_eq!(line.spans[1].content, "[Space]");
        assert_eq!(line.spans[1].style.fg, Some(ACCENT));
        assert_eq!(line.spans[2].content, " to toggle, ");
        assert_eq!(line.spans[3].content, "[Enter]");
        assert_eq!(line.spans[3].style.fg, Some(ACCENT));
        assert_eq!(line.spans[4].content, " to continue.");
    }

    #[test]
    fn key_styled_line_leaves_non_alphanumeric_brackets_alone() {
        // `[:port]` contains a colon — not a key cue. Whole text should
        // render with the base style, no accent spans.
        let line = key_styled_line("server host[:port] defaults", dim_style());
        assert!(
            !line.spans.iter().any(|s| s.style.fg == Some(ACCENT)),
            "expected no accent spans, got {:?}",
            line.spans,
        );
    }

    #[test]
    fn key_styled_line_handles_text_without_brackets() {
        let line = key_styled_line("plain description", dim_style());
        assert_eq!(line.spans.len(), 1);
        assert_eq!(line.spans[0].content, "plain description");
        assert_eq!(line.spans[0].style.fg, Some(DIM_TEXT));
    }
}

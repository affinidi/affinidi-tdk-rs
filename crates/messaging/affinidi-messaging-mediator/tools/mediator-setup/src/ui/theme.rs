use ratatui::style::{Color, Modifier, Style};

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

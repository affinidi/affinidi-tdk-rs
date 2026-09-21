//! The quota bar: how full a queue is, as a smooth green → amber → red
//! gradient.
//!
//! The gradient runs along the whole bar, not with the fill level: the cells
//! of a nearly empty queue are green, and a queue near its limit shows the
//! whole ramp up into red at its leading edge. Colours are interpolated in
//! OKLab, where equal steps look equal — interpolating sRGB directly muddies
//! the green→red midpoint into brown. The leading edge is drawn to an eighth of
//! a cell, and the unfilled track is dim.
//!
//! Terminals get what they can show: 24-bit colour where `COLORTERM` says so,
//! the xterm 256-colour cube otherwise, and three plain colours (or none, with
//! `NO_COLOR`) as the last resort.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::Widget;

/// How many colours the terminal can show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColorDepth {
    TrueColor,
    Indexed256,
    Basic,
    Monochrome,
}

impl ColorDepth {
    /// Detect from the environment: `NO_COLOR`, `COLORTERM`, `TERM`.
    pub fn detect() -> Self {
        if std::env::var_os("NO_COLOR").is_some() {
            return ColorDepth::Monochrome;
        }
        let colorterm = std::env::var("COLORTERM")
            .unwrap_or_default()
            .to_lowercase();
        if colorterm.contains("truecolor") || colorterm.contains("24bit") {
            return ColorDepth::TrueColor;
        }
        let term = std::env::var("TERM").unwrap_or_default();
        if term.contains("256color") {
            ColorDepth::Indexed256
        } else {
            ColorDepth::Basic
        }
    }
}

/// The ramp's stops, in sRGB: a healthy green, amber, and an alarm red.
const GREEN: (u8, u8, u8) = (0x22, 0xc5, 0x5e);
const AMBER: (u8, u8, u8) = (0xf5, 0x9e, 0x0b);
const RED: (u8, u8, u8) = (0xef, 0x44, 0x44);
/// The unfilled track.
const TRACK: (u8, u8, u8) = (0x3a, 0x3a, 0x3a);

/// The gradient colour at `t` in `[0, 1]`: green at 0, amber at 0.5, red at 1.
pub fn gradient(t: f64, depth: ColorDepth) -> Color {
    let t = t.clamp(0.0, 1.0);
    match depth {
        ColorDepth::Monochrome => Color::Reset,
        ColorDepth::Basic => {
            if t < 0.5 {
                Color::Green
            } else if t < 0.85 {
                Color::Yellow
            } else {
                Color::Red
            }
        }
        ColorDepth::TrueColor | ColorDepth::Indexed256 => {
            let (a, b, u) = if t < 0.5 {
                (GREEN, AMBER, t * 2.0)
            } else {
                (AMBER, RED, (t - 0.5) * 2.0)
            };
            let (r, g, bl) = oklab_mix(a, b, u);
            if depth == ColorDepth::TrueColor {
                Color::Rgb(r, g, bl)
            } else {
                Color::Indexed(xterm_256(r, g, bl))
            }
        }
    }
}

/// A queue's fill as a gradient bar.
pub struct QuotaBar {
    /// used ÷ limit. `None` for an unlimited queue, drawn as an empty track.
    ratio: Option<f64>,
    depth: ColorDepth,
}

impl QuotaBar {
    pub fn new(ratio: Option<f64>, depth: ColorDepth) -> Self {
        Self { ratio, depth }
    }
}

/// Eighth blocks for the partially filled leading cell.
const EIGHTHS: [&str; 8] = [" ", "▏", "▎", "▍", "▌", "▋", "▊", "▉"];

impl Widget for QuotaBar {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width == 0 || area.height == 0 {
            return;
        }
        let width = area.width as usize;
        let filled_eighths = self.ratio.map_or(0, |r| {
            (r.clamp(0.0, 1.0) * (width * 8) as f64).round() as usize
        });
        let full_cells = filled_eighths / 8;
        let partial = filled_eighths % 8;
        let track = match self.depth {
            ColorDepth::TrueColor => Color::Rgb(TRACK.0, TRACK.1, TRACK.2),
            ColorDepth::Indexed256 => Color::Indexed(237),
            _ => Color::DarkGray,
        };

        for y in area.top()..area.bottom() {
            for i in 0..width {
                let x = area.left() + i as u16;
                let t = if width > 1 {
                    i as f64 / (width - 1) as f64
                } else {
                    1.0
                };
                let color = gradient(t, self.depth);
                let cell = &mut buf[(x, y)];
                if i < full_cells {
                    if self.depth == ColorDepth::Monochrome {
                        cell.set_symbol("█").set_style(Style::default());
                    } else {
                        cell.set_symbol("█").set_style(Style::default().fg(color));
                    }
                } else if i == full_cells && partial > 0 {
                    // Leading edge: the eighth block in the ramp colour over
                    // the track.
                    let style = if self.depth == ColorDepth::Monochrome {
                        Style::default()
                    } else {
                        Style::default().fg(color).bg(track)
                    };
                    cell.set_symbol(EIGHTHS[partial]).set_style(style);
                } else if self.depth == ColorDepth::Monochrome {
                    cell.set_symbol("░")
                        .set_style(Style::default().add_modifier(Modifier::DIM));
                } else {
                    cell.set_symbol(" ").set_style(Style::default().bg(track));
                }
            }
        }
    }
}

/// The same bar as a [`Line`] of styled spans, for places a widget cannot go
/// — a table cell, a line of text.
pub fn quota_line(
    ratio: Option<f64>,
    width: u16,
    depth: ColorDepth,
) -> ratatui::text::Line<'static> {
    let area = Rect::new(0, 0, width, 1);
    let mut buf = Buffer::empty(area);
    QuotaBar::new(ratio, depth).render(area, &mut buf);
    ratatui::text::Line::from(
        (0..width)
            .map(|x| {
                let cell = &buf[(x, 0)];
                ratatui::text::Span::styled(cell.symbol().to_string(), cell.style())
            })
            .collect::<Vec<_>>(),
    )
}

// ─── OKLab ───────────────────────────────────────────────────────────────

fn srgb_to_linear(c: u8) -> f64 {
    let c = c as f64 / 255.0;
    if c <= 0.04045 {
        c / 12.92
    } else {
        ((c + 0.055) / 1.055).powf(2.4)
    }
}

fn linear_to_srgb(c: f64) -> u8 {
    let c = c.clamp(0.0, 1.0);
    let s = if c <= 0.003_130_8 {
        c * 12.92
    } else {
        1.055 * c.powf(1.0 / 2.4) - 0.055
    };
    (s * 255.0).round().clamp(0.0, 255.0) as u8
}

fn to_oklab((r, g, b): (u8, u8, u8)) -> [f64; 3] {
    let (r, g, b) = (srgb_to_linear(r), srgb_to_linear(g), srgb_to_linear(b));
    let l = (0.412_221_470_8 * r + 0.536_332_536_3 * g + 0.051_445_992_9 * b).cbrt();
    let m = (0.211_903_498_2 * r + 0.680_699_545_1 * g + 0.107_396_956_6 * b).cbrt();
    let s = (0.088_302_461_9 * r + 0.281_718_837_6 * g + 0.629_978_700_5 * b).cbrt();
    [
        0.210_454_255_3 * l + 0.793_617_785 * m - 0.004_072_046_8 * s,
        1.977_998_495_1 * l - 2.428_592_205 * m + 0.450_593_709_9 * s,
        0.025_904_037_1 * l + 0.782_771_766_2 * m - 0.808_675_766 * s,
    ]
}

fn from_oklab([l, a, b]: [f64; 3]) -> (u8, u8, u8) {
    let l_ = (l + 0.396_337_777_4 * a + 0.215_803_757_3 * b).powi(3);
    let m_ = (l - 0.105_561_345_8 * a - 0.063_854_172_8 * b).powi(3);
    let s_ = (l - 0.089_484_177_5 * a - 1.291_485_548 * b).powi(3);
    (
        linear_to_srgb(4.076_741_662_1 * l_ - 3.307_711_591_3 * m_ + 0.230_969_929_2 * s_),
        linear_to_srgb(-1.268_438_004_6 * l_ + 2.609_757_401_1 * m_ - 0.341_319_396_5 * s_),
        linear_to_srgb(-0.004_196_086_3 * l_ - 0.703_418_614_7 * m_ + 1.707_614_701 * s_),
    )
}

/// Mix two sRGB colours `u` of the way from `a` to `b`, in OKLab.
fn oklab_mix(a: (u8, u8, u8), b: (u8, u8, u8), u: f64) -> (u8, u8, u8) {
    // The stops themselves come back exactly, not via a rounding round trip.
    if u <= 0.0 {
        return a;
    }
    if u >= 1.0 {
        return b;
    }
    let (x, y) = (to_oklab(a), to_oklab(b));
    from_oklab([
        x[0] + (y[0] - x[0]) * u,
        x[1] + (y[1] - x[1]) * u,
        x[2] + (y[2] - x[2]) * u,
    ])
}

/// The nearest colour in the xterm 256-colour 6×6×6 cube.
fn xterm_256(r: u8, g: u8, b: u8) -> u8 {
    const LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];
    let nearest = |c: u8| {
        LEVELS
            .iter()
            .enumerate()
            .min_by_key(|(_, l)| (i16::from(**l) - i16::from(c)).abs())
            .map(|(i, _)| i as u8)
            .unwrap_or(0)
    };
    16 + 36 * nearest(r) + 6 * nearest(g) + nearest(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ramp_starts_green_passes_amber_and_ends_red() {
        assert_eq!(
            gradient(0.0, ColorDepth::TrueColor),
            Color::Rgb(GREEN.0, GREEN.1, GREEN.2)
        );
        assert_eq!(
            gradient(0.5, ColorDepth::TrueColor),
            Color::Rgb(AMBER.0, AMBER.1, AMBER.2)
        );
        assert_eq!(
            gradient(1.0, ColorDepth::TrueColor),
            Color::Rgb(RED.0, RED.1, RED.2)
        );
    }

    #[test]
    fn the_midpoint_between_green_and_amber_is_not_muddy() {
        // Naive sRGB averaging dips in lightness; OKLab keeps it bright.
        let Color::Rgb(r, g, b) = gradient(0.25, ColorDepth::TrueColor) else {
            panic!("truecolor")
        };
        let luma = 0.2126 * f64::from(r) + 0.7152 * f64::from(g) + 0.0722 * f64::from(b);
        assert!(luma > 140.0, "midpoint too dark: {r},{g},{b} (luma {luma})");
    }

    #[test]
    fn oklab_round_trips() {
        for c in [GREEN, AMBER, RED, TRACK, (0, 0, 0), (255, 255, 255)] {
            let back = from_oklab(to_oklab(c));
            let close = |x: u8, y: u8| (i16::from(x) - i16::from(y)).abs() <= 1;
            assert!(
                close(back.0, c.0) && close(back.1, c.1) && close(back.2, c.2),
                "{c:?} → {back:?}"
            );
        }
    }

    #[test]
    fn fallbacks_cover_every_terminal() {
        assert!(matches!(
            gradient(0.3, ColorDepth::Indexed256),
            Color::Indexed(16..=231)
        ));
        assert_eq!(gradient(0.1, ColorDepth::Basic), Color::Green);
        assert_eq!(gradient(0.95, ColorDepth::Basic), Color::Red);
        assert_eq!(gradient(0.5, ColorDepth::Monochrome), Color::Reset);
    }

    #[test]
    fn a_half_full_bar_fills_half_its_cells_with_the_ramp() {
        let area = Rect::new(0, 0, 10, 1);
        let mut buf = Buffer::empty(area);
        QuotaBar::new(Some(0.55), ColorDepth::TrueColor).render(area, &mut buf);
        let filled = (0..10).filter(|x| buf[(*x, 0)].symbol() == "█").count();
        assert_eq!(filled, 5);
        assert_eq!(
            buf[(5, 0)].symbol(),
            "▌",
            "the leading edge is drawn to an eighth"
        );
        assert_eq!(buf[(9, 0)].symbol(), " ", "the rest is track");
    }

    #[test]
    fn an_unlimited_queue_is_an_empty_track() {
        let area = Rect::new(0, 0, 6, 1);
        let mut buf = Buffer::empty(area);
        QuotaBar::new(None, ColorDepth::TrueColor).render(area, &mut buf);
        assert!((0..6).all(|x| buf[(x, 0)].symbol() == " "));
    }
}

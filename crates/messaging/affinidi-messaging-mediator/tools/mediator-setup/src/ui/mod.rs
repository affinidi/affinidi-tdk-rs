pub mod info_box;
pub mod progress;
pub mod selection;
pub mod summary;
pub mod text_input;
pub mod theme;

use ratatui::{prelude::*, widgets::Paragraph};

use crate::app::{InputMode, WizardApp};

/// Draw a gradient border around a rect, with colors fading from purple to blue.
/// Returns the inner area (1 cell inset on each side).
fn render_gradient_border(frame: &mut Frame, area: Rect, title: &str) -> Rect {
    let buf = frame.buffer_mut();
    let h = area.height;

    // Rounded border characters
    const TL: &str = "╭";
    const TR: &str = "╮";
    const BL: &str = "╰";
    const BR: &str = "╯";
    const HZ: &str = "─";
    const VT: &str = "│";

    for row in 0..h {
        let y = area.y + row;
        let color = theme::gradient_color(row, h);
        let style = Style::default().fg(color);

        if row == 0 {
            // Top border: ╭───── title ─────╮
            buf[(area.x, y)].set_symbol(TL).set_style(style);
            buf[(area.x + area.width - 1, y)]
                .set_symbol(TR)
                .set_style(style);
            for x in (area.x + 1)..(area.x + area.width - 1) {
                buf[(x, y)].set_symbol(HZ).set_style(style);
            }
            // Title overlay
            let title_start = area.x + 2;
            let padded = format!(" {title} ");
            for (i, ch) in padded.chars().enumerate() {
                let x = title_start + i as u16;
                if x < area.x + area.width - 2 {
                    buf[(x, y)].set_char(ch).set_style(theme::title_style());
                }
            }
        } else if row == h - 1 {
            // Bottom border
            buf[(area.x, y)].set_symbol(BL).set_style(style);
            buf[(area.x + area.width - 1, y)]
                .set_symbol(BR)
                .set_style(style);
            for x in (area.x + 1)..(area.x + area.width - 1) {
                buf[(x, y)].set_symbol(HZ).set_style(style);
            }
        } else {
            // Side borders
            buf[(area.x, y)].set_symbol(VT).set_style(style);
            buf[(area.x + area.width - 1, y)]
                .set_symbol(VT)
                .set_style(style);
        }
    }

    // Return inner rect
    Rect {
        x: area.x + 1,
        y: area.y + 1,
        width: area.width.saturating_sub(2),
        height: area.height.saturating_sub(2),
    }
}

/// Render the full wizard layout.
pub fn render(frame: &mut Frame, app: &WizardApp) {
    let size = frame.area();

    // Outer gradient border
    let inner = render_gradient_border(frame, size, "Affinidi Mediator Setup");

    // Bottom help bar (2 lines: 1 blank + 1 help)
    let help_height = 2u16;
    let main_area = Rect {
        x: inner.x,
        y: inner.y,
        width: inner.width,
        height: inner.height.saturating_sub(help_height),
    };
    let help_area = Rect {
        x: inner.x,
        y: inner.y + main_area.height,
        width: inner.width,
        height: help_height,
    };

    // Render help bar
    let help_text = match app.mode {
        InputMode::TextInput => "\u{2191}\u{2193} Navigate  Enter Confirm  Esc Cancel  F10 Quit",
        InputMode::Confirming => "Enter Confirm  Esc Back  F10 Quit",
        _ => match app.focus {
            crate::app::FocusPanel::Content => {
                "\u{2191}\u{2193} Navigate  Enter Select  \u{2190} Steps  Esc Back  F10 Quit"
            }
            crate::app::FocusPanel::Progress => {
                "\u{2191}\u{2193} Navigate  Enter Jump  \u{2192} Options  Esc Back  F10 Quit"
            }
        },
    };
    let help = Paragraph::new(Line::from(Span::styled(
        format!("  {help_text}"),
        theme::muted_style(),
    )));
    frame.render_widget(help, help_area);

    // Summary step gets full width
    if app.current_step == crate::app::WizardStep::Summary {
        summary::render_summary(
            frame,
            main_area,
            &app.config,
            app.mode == InputMode::Confirming,
        );
        return;
    }

    // Split main area: left progress (30%) + right content (70%)
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(main_area);

    // Left: progress panel
    progress::render_progress(
        frame,
        chunks[0],
        app.current_step,
        &app.completed_steps(),
        app.focus,
        app.progress_index,
    );

    // Right: current step content
    render_step_content(frame, chunks[1], app);
}

/// Render the current step's content in the right panel.
fn render_step_content(frame: &mut Frame, area: Rect, app: &WizardApp) {
    let step = app.current_step;
    let step_data = step.step_data();
    let content_focused = app.focus == crate::app::FocusPanel::Content;

    // Split right panel: options area + info box
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(6)])
        .split(area);

    // Render selection or text input based on step type
    match app.mode {
        InputMode::TextInput => {
            text_input::render_text_input(
                frame,
                chunks[0],
                &step_data.title,
                &step_data.description,
                &app.text_input,
                true,
            );
        }
        _ => {
            let options = app.current_options();
            selection::render_selection(
                frame,
                chunks[0],
                &step_data.title,
                &step_data.description,
                &options,
                app.selection_index,
                content_focused,
            );
        }
    }

    // Info box
    let info_text = app.current_info_text();
    info_box::render_info_box(frame, chunks[1], "Info", &info_text);
}

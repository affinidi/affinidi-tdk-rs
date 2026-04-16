pub mod info_box;
pub mod progress;
pub mod selection;
pub mod summary;
pub mod text_input;
pub mod theme;

use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph},
};

use crate::app::{InputMode, WizardApp};

/// Render the full wizard layout.
pub fn render(frame: &mut Frame, app: &WizardApp) {
    let size = frame.area();

    // Outer border with title
    let outer_block = Block::default()
        .title(" Affinidi Mediator Setup ")
        .title_style(theme::title_style())
        .borders(Borders::ALL)
        .border_style(theme::border_style());

    let inner = outer_block.inner(size);
    frame.render_widget(outer_block, size);

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
        InputMode::TextInput => {
            "\u{2191}\u{2193} Navigate  Enter Confirm  Esc Cancel  Tab Next field"
        }
        InputMode::Confirming => "Enter Confirm  Esc Cancel",
        _ => "\u{2191}\u{2193} Navigate  Enter Select  Esc Back  q Quit",
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
    progress::render_progress(frame, chunks[0], app.current_step, &app.completed_steps());

    // Right: current step content
    render_step_content(frame, chunks[1], app);
}

/// Render the current step's content in the right panel.
fn render_step_content(frame: &mut Frame, area: Rect, app: &WizardApp) {
    let step = app.current_step;
    let step_data = step.step_data();

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
            );
        }
    }

    // Info box
    let info_text = app.current_info_text();
    info_box::render_info_box(frame, chunks[1], "Info", &info_text);
}

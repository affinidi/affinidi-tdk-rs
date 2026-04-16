use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Padding, Paragraph, Wrap},
};

use crate::{app::WizardConfig, ui::theme};

/// Renders the summary view showing all configuration choices.
pub fn render_summary(
    frame: &mut Frame,
    area: Rect,
    config: &WizardConfig,
    confirm_selected: bool,
) {
    let block = Block::default()
        .title(" Summary — Review Configuration ")
        .title_style(theme::title_style())
        .borders(Borders::ALL)
        .border_style(theme::border_style())
        .padding(Padding::new(2, 2, 1, 0));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::from(Span::styled(
        "Review your configuration before writing:",
        theme::dim_style(),
    )));
    lines.push(Line::from(""));

    // Deployment
    add_field(&mut lines, "Deployment", &config.deployment_type);

    // Protocol
    add_field(&mut lines, "Protocol", &config.protocol);

    // DID
    add_field(&mut lines, "DID Method", &config.did_method);
    if !config.public_url.is_empty() {
        add_field(&mut lines, "Public URL", &config.public_url);
    }

    // Key Storage
    add_field(&mut lines, "Key Storage", &config.secret_storage);

    // SSL
    add_field(&mut lines, "SSL/TLS", &config.ssl_mode);

    // Database
    add_field(&mut lines, "Database", &config.database_url);

    // Admin
    add_field(&mut lines, "Admin DID", &config.admin_did_mode);

    // Output files
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("Output:", theme::info_style())));
    add_field(&mut lines, "Config file", &config.config_path);

    // Confirm button
    lines.push(Line::from(""));
    lines.push(Line::from(""));

    let confirm_style = if confirm_selected {
        theme::selected_style()
    } else {
        theme::normal_style()
    };
    lines.push(Line::from(Span::styled(
        "  [ Write Configuration ]  ",
        confirm_style,
    )));

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Press Enter to write, Esc to go back",
        theme::muted_style(),
    )));

    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: true });
    frame.render_widget(paragraph, inner);
}

fn add_field(lines: &mut Vec<Line<'_>>, label: &str, value: &str) {
    lines.push(Line::from(vec![
        Span::styled(format!("  {label}: "), theme::dim_style()),
        Span::styled(value.to_string(), theme::normal_style()),
    ]));
}

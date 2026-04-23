use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Padding, Paragraph, Wrap},
};

use crate::{
    app::WizardConfig,
    config_writer::build_backend_url,
    ui::theme,
    vta_connect::{VtaReply, VtaSession},
};

/// Renders the summary view showing all configuration choices.
pub fn render_summary(
    frame: &mut Frame,
    area: Rect,
    config: &WizardConfig,
    vta_session: Option<&VtaSession>,
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

    let label_style = Style::default()
        .fg(theme::PRIMARY)
        .add_modifier(Modifier::BOLD);
    let value_style = Style::default().fg(theme::TEXT);
    let section_style = Style::default()
        .fg(theme::ACCENT)
        .add_modifier(Modifier::BOLD);

    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::from(Span::styled(
        "Review your configuration before writing:",
        theme::dim_style(),
    )));
    lines.push(Line::from(""));

    // ── Deployment ──
    add_section_header(&mut lines, "Deployment", section_style);
    add_field(
        &mut lines,
        "  Type",
        &config.deployment_type,
        label_style,
        value_style,
    );
    add_field(
        &mut lines,
        "  Protocol",
        &config.protocol_display(),
        label_style,
        value_style,
    );
    lines.push(Line::from(""));

    // ── Identity ──
    add_section_header(&mut lines, "Identity", section_style);
    // VTA summary reflects both the transport (`vta_mode`) and the
    // intent (FullSetup vs AdminOnly). Intent comes from the session's
    // reply variant — `Full` means the VTA minted the integration DID,
    // `AdminOnly` means the VTA only issued an admin credential.
    let vta_display = if config.use_vta {
        let intent_label = match vta_session.map(|s| &s.reply) {
            Some(VtaReply::Full(_)) => "full setup",
            Some(VtaReply::AdminOnly(_)) => "admin credential only",
            Some(VtaReply::ContextExport(_)) => "offline export of pre-provisioned state",
            None => "pending", // Vta step not completed yet (shouldn't show on Summary in practice)
        };
        format!("Enabled — {} ({})", intent_label, config.vta_mode)
    } else {
        "Disabled".into()
    };
    add_field(&mut lines, "  VTA", &vta_display, label_style, value_style);
    // Webvh hosting row — only meaningful on a completed FullSetup.
    // The `provision.summary.webvh_server_id` comes straight from
    // the VTA (see the SDK's `ProvisionSummary.webvh_server_id`),
    // so we render whatever the VTA actually resolved rather than
    // echoing the operator's pick — useful if the VTA renamed or
    // re-routed under the covers.
    if let Some(VtaReply::Full(provision)) = vta_session.map(|s| &s.reply) {
        let webvh_display = match provision.summary.webvh_server_id.as_deref() {
            Some(id) => format!("{id} (VTA-pinned)"),
            None => "serverless (self-host at Public URL)".into(),
        };
        add_field(
            &mut lines,
            "  Webvh hosting",
            &webvh_display,
            label_style,
            value_style,
        );
    }
    add_field(
        &mut lines,
        "  DID Method",
        &config.did_method,
        label_style,
        value_style,
    );
    if !config.public_url.is_empty() {
        add_field(
            &mut lines,
            "  Public URL",
            &config.public_url,
            label_style,
            value_style,
        );
    }
    let key_storage_display = build_backend_url(config);
    add_field(
        &mut lines,
        "  Key Storage",
        &key_storage_display,
        label_style,
        value_style,
    );
    lines.push(Line::from(""));

    // ── Security ──
    add_section_header(&mut lines, "Security", section_style);
    add_field(
        &mut lines,
        "  SSL/TLS",
        &config.ssl_mode,
        label_style,
        value_style,
    );
    add_field(
        &mut lines,
        "  Admin DID",
        &config.admin_did_mode,
        label_style,
        value_style,
    );
    lines.push(Line::from(""));

    // ── Infrastructure ──
    add_section_header(&mut lines, "Infrastructure", section_style);
    add_field(
        &mut lines,
        "  Database",
        &config.database_url,
        label_style,
        value_style,
    );
    add_field(
        &mut lines,
        "  Config file",
        &config.config_path,
        label_style,
        value_style,
    );

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

fn add_section_header<'a>(lines: &mut Vec<Line<'a>>, title: &'a str, style: Style) {
    lines.push(Line::from(vec![
        Span::styled("── ", Style::default().fg(theme::BORDER)),
        Span::styled(title, style),
        Span::styled(" ──", Style::default().fg(theme::BORDER)),
    ]));
}

fn add_field<'a>(
    lines: &mut Vec<Line<'a>>,
    label: &'a str,
    value: &str,
    label_style: Style,
    value_style: Style,
) {
    // Right-align labels to a fixed width for clean columns
    let padded_label = format!("{label:>14}");
    lines.push(Line::from(vec![
        Span::styled(padded_label, label_style),
        Span::styled("  ", Style::default()),
        Span::styled(value.to_string(), value_style),
    ]));
}

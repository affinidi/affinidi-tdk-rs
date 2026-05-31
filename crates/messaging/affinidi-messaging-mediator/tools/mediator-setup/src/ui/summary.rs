use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Padding, Paragraph, Wrap},
};

use crate::{
    app::WizardConfig,
    config_writer::build_backend_url,
    consts::{
        CORS_MODE_ANY, CORS_MODE_LIST, CORS_MODE_NONE, JWT_MODE_GENERATE, NETWORK_MODE_CLOSED,
        NETWORK_MODE_OPEN, SSL_EXISTING, SSL_SELF_SIGNED, STORAGE_BACKEND_FJALL,
    },
    ui::theme,
    vta::{VtaReply, VtaSession},
};

/// Renders the summary view showing all configuration choices.
pub fn render_summary(
    frame: &mut Frame,
    area: Rect,
    config: &WizardConfig,
    vta_session: Option<&VtaSession>,
    confirm_selected: bool,
    clipboard_status: Option<&str>,
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
    // Webvh path / mnemonic — only meaningful when the operator picked
    // a hosted webvh server and chose a path. Hidden when blank.
    if let Some(ref path) = config.vta_webvh_path
        && !path.is_empty()
    {
        add_field(&mut lines, "  Webvh path", path, label_style, value_style);
    }
    if !config.public_url.is_empty() {
        add_field(
            &mut lines,
            "  Public URL",
            &config.public_url,
            label_style,
            value_style,
        );
    }
    // Self-host DID indicator — mirrors the same rule
    // `config_writer::generate_toml` uses to decide whether
    // `did_web_self_hosted` is activated. Surfaces the choice on the
    // review screen so the operator knows whether the mediator will
    // serve `/.well-known/did.jsonl` itself.
    if let Some(decision) = self_host_did_decision(config) {
        add_field(
            &mut lines,
            "  Self-host DID",
            decision,
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
    // SSL line: when the operator brought their own certs, surface the
    // paths so the review reflects the configured files rather than
    // just "Existing certificates".
    let ssl_display = if config.ssl_mode == SSL_EXISTING
        && (!config.ssl_cert_path.is_empty() || !config.ssl_key_path.is_empty())
    {
        format!(
            "{} ({} / {})",
            config.ssl_mode,
            empty_or(&config.ssl_cert_path, "—"),
            empty_or(&config.ssl_key_path, "—"),
        )
    } else if config.ssl_mode == SSL_SELF_SIGNED {
        format!("{} (generated into conf/keys/)", config.ssl_mode)
    } else {
        config.ssl_mode.clone()
    };
    add_field(
        &mut lines,
        "  SSL/TLS",
        &ssl_display,
        label_style,
        value_style,
    );
    add_field(
        &mut lines,
        "  Network mode",
        &network_mode_display(&config.network_mode),
        label_style,
        value_style,
    );
    add_field(
        &mut lines,
        "  JWT signing",
        &jwt_mode_display(&config.jwt_mode),
        label_style,
        value_style,
    );
    add_field(
        &mut lines,
        "  CORS policy",
        &cors_policy_display(config),
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
    // Storage backend — branch on the operator's actual choice. Showing
    // the Redis URL when they picked Fjall (or vice versa) was the
    // bug that motivated this Summary audit.
    if config.storage_backend == STORAGE_BACKEND_FJALL {
        add_field(
            &mut lines,
            "  Storage",
            "Fjall (embedded LSM)",
            label_style,
            value_style,
        );
        add_field(
            &mut lines,
            "  Data dir",
            &config.fjall_data_dir,
            label_style,
            value_style,
        );
    } else {
        add_field(&mut lines, "  Storage", "Redis", label_style, value_style);
        add_field(
            &mut lines,
            "  Redis URL",
            &config.database_url,
            label_style,
            value_style,
        );
    }
    add_field(
        &mut lines,
        "  Listen on",
        &config.listen_address,
        label_style,
        value_style,
    );
    add_field(
        &mut lines,
        "  API prefix",
        &config.api_prefix,
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
    lines.push(Line::from(Span::styled(
        "  [c] copy config path  [b] copy backend URL",
        theme::muted_style(),
    )));
    if let Some(status) = clipboard_status {
        lines.push(Line::from(Span::styled(
            format!("  {status}"),
            theme::muted_style(),
        )));
    }

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
    // Right-align labels to a fixed width for clean columns. Width
    // grew from 14 to 18 chars so the longest labels added in the
    // audit ("Webvh hosting", "Self-host DID", "Network mode") stay
    // aligned with the older shorter ones ("VTA", "Database").
    let padded_label = format!("{label:>18}");
    lines.push(Line::from(vec![
        Span::styled(padded_label, label_style),
        Span::styled("  ", Style::default()),
        Span::styled(value.to_string(), value_style),
    ]));
}

/// Friendly label for `WizardConfig::network_mode`. Falls through to
/// the raw string for unknown values so a typo in a recipe stays
/// visible on the review screen rather than being silently relabelled.
fn network_mode_display(mode: &str) -> String {
    match mode {
        NETWORK_MODE_OPEN => "Open (ALLOW_ALL by default)".into(),
        NETWORK_MODE_CLOSED => "Closed (DENY_ALL by default)".into(),
        other => other.to_string(),
    }
}

/// Friendly label for `WizardConfig::jwt_mode`. Same fall-through rule
/// as `network_mode_display`.
fn jwt_mode_display(mode: &str) -> String {
    match mode {
        JWT_MODE_GENERATE => "Wizard generates a new key".into(),
        // Empty value covers the default — the JwtMode sub-phase
        // hasn't run yet (e.g. truncated wizard state in tests).
        "" => "—".into(),
        "provide" => "Operator provides at boot (env / file)".into(),
        other => other.to_string(),
    }
}

/// Friendly label for `WizardConfig::cors_mode`. For the allowlist mode
/// the chosen domains are appended so the operator can audit them on the
/// review screen. Same fall-through rule as `network_mode_display`.
fn cors_policy_display(config: &WizardConfig) -> String {
    match config.cors_mode.as_str() {
        CORS_MODE_NONE | "" => "Deny all cross-origin (default)".into(),
        CORS_MODE_ANY => "Allow any origin (*)".into(),
        CORS_MODE_LIST => format!("Allowlist: {}", config.cors_domains),
        other => other.to_string(),
    }
}

/// Mirror of the rule `config_writer::generate_toml` applies when
/// deciding whether to activate `did_web_self_hosted`:
///   - did:webvh self-host generator → Yes (DID is built from public URL)
///   - VTA-managed webvh DID with matching domain → Yes
///   - Other VTA paths → No (VTA / different webvh server hosts)
///   - did:peer / did:key → field is irrelevant — return None
fn self_host_did_decision(config: &WizardConfig) -> Option<&'static str> {
    use crate::consts::{DID_PEER, DID_VTA, DID_WEBVH};
    if config.did_method == DID_PEER {
        return None;
    }
    if config.did_method == DID_WEBVH {
        // The self-host generator runs whenever did:webvh is picked
        // (no explicit "self-host vs hosted" sub-step), so the wizard
        // always activates the line. Show that intent on the review.
        return Some("Yes — mediator serves /.well-known/did.jsonl");
    }
    if config.did_method == DID_VTA {
        // Without the minted DID we can't pre-compute the host match —
        // the actual decision lands in `config_writer::generate_toml`
        // after `mint_artefacts`. Communicate the heuristic instead.
        return Some(
            "Decided after VTA mints DID — activated only when DID host matches Public URL",
        );
    }
    None
}

/// Replace an empty string with a placeholder for review display.
/// `empty_or("", "—")` → `"—"`; otherwise echoes the input.
fn empty_or<'a>(value: &'a str, placeholder: &'a str) -> &'a str {
    if value.is_empty() { placeholder } else { value }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::{
        ADMIN_GENERATE, DEFAULT_FJALL_DATA_DIR, DEFAULT_LISTEN_ADDR, DEFAULT_REDIS_URL, DID_PEER,
        DID_VTA, DID_WEBVH, JWT_MODE_PROVIDE, SSL_NONE, STORAGE_BACKEND_REDIS,
    };

    fn base_config() -> WizardConfig {
        WizardConfig {
            deployment_type: "Local development".into(),
            did_method: DID_PEER.into(),
            ssl_mode: SSL_NONE.into(),
            network_mode: NETWORK_MODE_OPEN.into(),
            jwt_mode: JWT_MODE_GENERATE.into(),
            admin_did_mode: ADMIN_GENERATE.into(),
            listen_address: DEFAULT_LISTEN_ADDR.into(),
            api_prefix: "/mediator/v1/".into(),
            storage_backend: STORAGE_BACKEND_REDIS.into(),
            database_url: DEFAULT_REDIS_URL.into(),
            fjall_data_dir: DEFAULT_FJALL_DATA_DIR.into(),
            config_path: "conf/mediator.toml".into(),
            ..WizardConfig::default()
        }
    }

    #[test]
    fn network_mode_display_known_modes() {
        assert!(network_mode_display(NETWORK_MODE_OPEN).starts_with("Open"));
        assert!(network_mode_display(NETWORK_MODE_CLOSED).starts_with("Closed"));
    }

    #[test]
    fn network_mode_display_unknown_mode_passes_through() {
        // Defensive: a typo'd recipe value stays visible verbatim on
        // the review screen rather than being silently relabelled.
        assert_eq!(
            network_mode_display("totally-not-a-mode"),
            "totally-not-a-mode"
        );
    }

    #[test]
    fn jwt_mode_display_handles_generate_provide_and_unknown() {
        assert!(jwt_mode_display(JWT_MODE_GENERATE).starts_with("Wizard"));
        assert!(jwt_mode_display(JWT_MODE_PROVIDE).starts_with("Operator"));
        assert_eq!(jwt_mode_display(""), "—");
        assert_eq!(jwt_mode_display("custom"), "custom");
    }

    #[test]
    fn self_host_did_decision_did_peer_is_none() {
        // did:peer needs no /.well-known route — the row is hidden.
        let cfg = WizardConfig {
            did_method: DID_PEER.into(),
            ..base_config()
        };
        assert!(self_host_did_decision(&cfg).is_none());
    }

    #[test]
    fn self_host_did_decision_did_webvh_is_yes() {
        let cfg = WizardConfig {
            did_method: DID_WEBVH.into(),
            ..base_config()
        };
        assert!(matches!(self_host_did_decision(&cfg), Some(s) if s.starts_with("Yes")));
    }

    #[test]
    fn self_host_did_decision_did_vta_communicates_heuristic() {
        // Operator can't see the actual decision until after the VTA
        // mints the DID. The Summary should explain why, not lie.
        let cfg = WizardConfig {
            did_method: DID_VTA.into(),
            ..base_config()
        };
        let s = self_host_did_decision(&cfg).expect("VTA path should produce a row");
        assert!(s.contains("Decided after VTA"));
    }

    #[test]
    fn empty_or_falls_back_only_on_empty() {
        assert_eq!(empty_or("", "—"), "—");
        assert_eq!(empty_or("value", "—"), "value");
    }
}

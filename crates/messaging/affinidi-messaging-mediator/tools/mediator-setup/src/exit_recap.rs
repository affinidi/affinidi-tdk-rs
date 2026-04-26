//! Print-on-exit recap for interactive wizard runs.
//!
//! The TUI runs inside an alternate screen, so once the wizard
//! exits there's no scrollback for the operator to mouse-select
//! DIDs / paths / commands out of. This module drops a structured
//! plain-text recap to normal stdout *after* the alt-screen has
//! been left, giving the operator something they can scroll back
//! to and copy from with their normal terminal mouse selection.
//!
//! Sections render only when their data is present:
//!   - Header with ISO-8601 timestamp
//!   - VTA Integration (when a `VtaSession` was captured)
//!   - Mediator config (paths / URLs)
//!   - Next steps (operator-facing one-liners)
//!   - Fenced TOML block with the salient subset of `mediator.toml`
//!
//! Suppressed in `--non-interactive` / `--from <recipe>` runs —
//! those have structured stdout already that CI scripts parse, and
//! a recap would corrupt the format.

use std::fmt::Write as _;

use crate::app::WizardConfig;
use crate::vta_connect::{VtaReply, VtaSession};

/// Print the operator-facing recap to stdout. Called from `main.rs`
/// after the TUI has restored the terminal (alt-screen left, raw
/// mode disabled), and only on the interactive success path.
pub fn print_exit_recap(config: &WizardConfig, session: Option<&VtaSession>) {
    let now = chrono::Utc::now().to_rfc3339();
    print!("{}", build_recap(config, session, &now));
}

/// Build the recap string. Pure — separated from the IO so tests
/// can pin a known timestamp and inspect the exact output.
fn build_recap(config: &WizardConfig, session: Option<&VtaSession>, timestamp: &str) -> String {
    let mut out = String::new();
    push_header(&mut out, timestamp);
    push_vta_section(&mut out, session);
    push_mediator_section(&mut out, config);
    push_next_steps(&mut out, config, session);
    push_toml_block(&mut out, config);
    push_selection_hint(&mut out);
    out
}

fn push_header(out: &mut String, timestamp: &str) {
    let _ = writeln!(out, "✓ Mediator setup complete — {timestamp}");
    let _ = writeln!(out);
}

fn push_vta_section(out: &mut String, session: Option<&VtaSession>) {
    let Some(session) = session else { return };
    let _ = writeln!(out, "## VTA Integration");
    let intent = match &session.reply {
        VtaReply::Full(_) => "FullSetup (VTA-minted mediator DID)",
        VtaReply::AdminOnly(_) => "AdminOnly (operator brought their own mediator DID)",
        VtaReply::ContextExport(_) => "OfflineExport (sealed-handoff context bundle)",
    };
    let _ = writeln!(out, "  Intent:        {intent}");
    if !session.vta_did.is_empty() {
        let _ = writeln!(out, "  VTA DID:       {}", session.vta_did);
    }
    if !session.context_id.is_empty() {
        let _ = writeln!(out, "  Context:       {}", session.context_id);
    }
    let admin_did = match &session.reply {
        VtaReply::Full(p) => p.admin_did(),
        VtaReply::AdminOnly(a) => &a.admin_did,
        VtaReply::ContextExport(b) => &b.admin_did,
    };
    let _ = writeln!(out, "  Admin DID:     {admin_did}");
    let mediator_did: Option<&str> = match &session.reply {
        VtaReply::Full(p) => Some(p.integration_did()),
        VtaReply::AdminOnly(_) => None,
        VtaReply::ContextExport(b) => b.did.as_ref().map(|d| d.id.as_str()),
    };
    if let Some(did) = mediator_did {
        let _ = writeln!(out, "  Mediator DID:  {did}");
    }
    if let Some(rest_url) = session.rest_url.as_deref() {
        let _ = writeln!(out, "  REST URL:      {rest_url}");
    }
    let _ = writeln!(out);
}

fn push_mediator_section(out: &mut String, config: &WizardConfig) {
    let _ = writeln!(out, "## Mediator config");
    let _ = writeln!(out, "  Config file:   {}", config.config_path);
    if !config.public_url.is_empty() {
        let _ = writeln!(out, "  Public URL:    {}", config.public_url);
    }
    if !config.listen_address.is_empty() {
        let _ = writeln!(out, "  Listen:        {}", config.listen_address);
    }
    let backend_url = crate::config_writer::build_backend_url(config);
    let _ = writeln!(out, "  Secret backend: {backend_url}");
    let _ = writeln!(out);
}

fn push_next_steps(out: &mut String, config: &WizardConfig, session: Option<&VtaSession>) {
    let _ = writeln!(out, "## Next steps");
    let _ = writeln!(
        out,
        "  1. Start the mediator:  affinidi-messaging-mediator --config {}",
        config.config_path
    );
    if session.is_some() {
        let _ = writeln!(
            out,
            "  2. Confirm the admin DID is registered on the VTA before \
             promoting traffic. The wizard verified the auth handshake — \
             the long-term ACL row is still operator-managed."
        );
    }
    let _ = writeln!(
        out,
        "  3. Re-run with --uninstall <config> to roll back this setup."
    );
    let _ = writeln!(out);
}

fn push_toml_block(out: &mut String, config: &WizardConfig) {
    let _ = writeln!(out, "## Snippet for sharing");
    let _ = writeln!(out, "```toml");
    if !config.public_url.is_empty() {
        let _ = writeln!(out, "[mediator]");
        let _ = writeln!(out, "public_url = \"{}\"", config.public_url);
        if !config.listen_address.is_empty() {
            let _ = writeln!(out, "listen_address = \"{}\"", config.listen_address);
        }
        let _ = writeln!(out);
    }
    let backend_url = crate::config_writer::build_backend_url(config);
    let _ = writeln!(out, "[secrets]");
    let _ = writeln!(out, "backend = \"{backend_url}\"");
    let _ = writeln!(out, "```");
    let _ = writeln!(out);
}

/// Tip paragraph helping operators select multi-pane content when
/// they re-run the wizard. The wizard's TUI panes break linear
/// mouse selection; most terminals support a block / rectangle
/// selection mode that respects pane boundaries.
fn push_selection_hint(out: &mut String) {
    let _ = writeln!(out, "## Tip — selecting text in the TUI");
    let _ = writeln!(
        out,
        "  The wizard's TUI uses multiple panes side by side, so a normal click-drag"
    );
    let _ = writeln!(
        out,
        "  can grab content from neighbouring panes. Most terminals support a block /"
    );
    let _ = writeln!(
        out,
        "  rectangle selection mode that respects pane boundaries:"
    );
    let _ = writeln!(out, "    iTerm2:               Cmd+Opt+drag");
    let _ = writeln!(out, "    Apple Terminal.app:   Opt+drag");
    let _ = writeln!(
        out,
        "    Windows Terminal / kitty / alacritty / wezterm:  Alt+drag"
    );
    let _ = writeln!(out, "    gnome-terminal / xterm:  Ctrl+drag");
    let _ = writeln!(
        out,
        "  Or use the `[c]` / `[v]` / `[m]` / `[a]` / `[F2]` hotkeys to copy via"
    );
    let _ = writeln!(
        out,
        "  the operator's clipboard (OSC 52 over SSH, system clipboard locally)."
    );
    let _ = writeln!(out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::WizardConfig;
    use crate::vta_connect::VtaSession;

    const TS: &str = "2026-04-26T12:00:00+00:00";

    fn config_minimal() -> WizardConfig {
        WizardConfig {
            config_path: "/etc/mediator/mediator.toml".into(),
            public_url: "https://mediator.example.com".into(),
            listen_address: "0.0.0.0:7037".into(),
            ..WizardConfig::default()
        }
    }

    fn admin_only_session() -> VtaSession {
        VtaSession::admin_only(
            "mediator".into(),
            "did:webvh:vta.example.com".into(),
            None,
            None,
            "did:key:z6MkAdminOnly".into(),
            "zPrivateAdmin".into(),
        )
    }

    fn full_setup_session() -> VtaSession {
        VtaSession::full(
            "mediator".into(),
            "did:webvh:vta.example.com".into(),
            Some("https://vta.example.com".into()),
            Some("did:webvh:mediator.vta.example.com".into()),
            crate::vta_connect::provision::test_sample_result(true),
        )
    }

    #[test]
    fn full_setup_recap_renders_all_sections() {
        let r = build_recap(&config_minimal(), Some(&full_setup_session()), TS);
        assert!(r.starts_with("✓ Mediator setup complete — 2026-04-26"));
        assert!(r.contains("## VTA Integration"));
        assert!(r.contains("Intent:        FullSetup"));
        assert!(r.contains("VTA DID:       did:webvh:vta.example.com"));
        assert!(r.contains("Admin DID:     did:key:z6MkAdmin"));
        assert!(r.contains("Mediator DID:  did:webvh:mediator.example.com"));
        assert!(r.contains("REST URL:      https://vta.example.com"));
        assert!(r.contains("## Mediator config"));
        assert!(r.contains("Config file:   /etc/mediator/mediator.toml"));
        assert!(r.contains("## Next steps"));
        assert!(r.contains("affinidi-messaging-mediator --config"));
        assert!(r.contains("Confirm the admin DID is registered"));
        assert!(r.contains("```toml"));
    }

    #[test]
    fn admin_only_recap_omits_mediator_did_line() {
        let r = build_recap(&config_minimal(), Some(&admin_only_session()), TS);
        assert!(r.contains("Intent:        AdminOnly"));
        assert!(r.contains("Admin DID:     did:key:z6MkAdminOnly"));
        // No mediator DID — operator brought their own.
        assert!(
            !r.contains("Mediator DID:"),
            "AdminOnly has no VTA-minted mediator DID line; got:\n{r}"
        );
    }

    #[test]
    fn no_session_recap_skips_vta_section() {
        let r = build_recap(&config_minimal(), None, TS);
        assert!(!r.contains("## VTA Integration"));
        assert!(r.contains("## Mediator config"));
        // The "confirm admin DID" hint is VTA-specific; should be absent.
        assert!(!r.contains("Confirm the admin DID"));
    }

    #[test]
    fn toml_block_parses_round_trip() {
        let r = build_recap(&config_minimal(), Some(&full_setup_session()), TS);
        // Extract the fenced TOML block.
        let start = r.find("```toml\n").expect("toml fence start present");
        let after_fence = &r[start + "```toml\n".len()..];
        let end = after_fence.find("```").expect("toml fence end present");
        let toml_text = &after_fence[..end];
        let parsed: toml::Value = toml::from_str(toml_text)
            .unwrap_or_else(|e| panic!("TOML block did not parse: {e}\n--- TOML ---\n{toml_text}"));
        // Spot-check the round-trip values
        let mediator = parsed.get("mediator").expect("[mediator] section");
        assert_eq!(
            mediator.get("public_url").and_then(|v| v.as_str()).unwrap(),
            "https://mediator.example.com"
        );
        let secrets = parsed.get("secrets").expect("[secrets] section");
        assert!(
            secrets
                .get("backend")
                .and_then(|v| v.as_str())
                .unwrap()
                .starts_with("file://")
                || secrets
                    .get("backend")
                    .and_then(|v| v.as_str())
                    .unwrap()
                    .contains("://"),
            "backend URL should be a URL"
        );
    }
}

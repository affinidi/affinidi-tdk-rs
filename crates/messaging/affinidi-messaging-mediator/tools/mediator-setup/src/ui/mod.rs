pub mod diagnostics;
pub mod info_box;
pub mod instructions;
pub mod progress;
pub mod prompt;
pub mod selection;
pub mod summary;
pub mod text_input;
pub mod theme;

use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Padding, Paragraph, Wrap},
};

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
                if app.current_step.is_multi_select() {
                    "\u{2191}\u{2193} Navigate  Space Toggle  Enter Continue  \u{2190} Steps  Esc Back  F10 Quit"
                } else {
                    "\u{2191}\u{2193} Navigate  Enter Select  \u{2190} Steps  Esc Back  F10 Quit"
                }
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
            app.vta_session.as_ref(),
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
    let step_data = app.current_step_data();
    let content_focused = app.focus == crate::app::FocusPanel::Content;

    // The sealed-handoff RequestGenerated screen renders a single
    // full-height pane (JSON + commands together) — the usual
    // top/bottom split would squeeze the producer commands into six
    // lines and clip them. Branch before the split so we keep a
    // single Rect to work with.
    if let Some(state) = app.sealed_handoff.as_ref() {
        if state.phase == crate::sealed_handoff::SealedPhase::RequestGenerated {
            render_sealed_request(frame, area, state);
            return;
        }
    }

    // Split right panel: options area + info box
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(6)])
        .split(area);

    // Online-VTA sub-flow overrides the generic selection/text renderers
    // for phases that need bespoke UI: the compact prompt for DID/context,
    // instructions block (AwaitingAcl), and the live diagnostics checklist
    // (Testing / Connected).
    // Sealed-handoff sub-flow takes precedence over the regular Vta
    // selection list — the operator is mid-cryptography and shouldn't
    // see the scheme picker behind a backdrop.
    if let Some(state) = app.sealed_handoff.as_ref() {
        use crate::sealed_handoff::SealedPhase;
        match state.phase {
            SealedPhase::CollectContext => {
                let hint = state.last_error.clone().unwrap_or_else(|| {
                    "The VTA context this mediator will live in. The VTA admin uses \
                     this slug with `pnm contexts bootstrap --id <ctx>`. Default is \
                     `mediator` — override if you run multiple mediators against \
                     the same VTA."
                        .into()
                });
                prompt::render_prompt(
                    frame,
                    chunks[0],
                    "Sealed handoff — context slug",
                    "Which VTA context should the admin credential live in?",
                    None,
                    &app.text_input,
                    "mediator",
                    &hint,
                );
                info_box::render_info_box(
                    frame,
                    chunks[1],
                    "Info",
                    "The slug is the VTA's context id, not a human-readable name. It \
                     must match an existing context on the VTA or one the admin will \
                     create with `pnm contexts create` before running bootstrap.",
                );
                return;
            }
            SealedPhase::CollectAdminLabel => {
                let hint = state.last_error.clone().unwrap_or_else(|| {
                    "Optional — a human-readable label recorded alongside the admin \
                     ACL row on the VTA. Leave blank to skip the `--admin-label` \
                     flag entirely."
                        .into()
                });
                prompt::render_prompt(
                    frame,
                    chunks[0],
                    "Sealed handoff — admin label",
                    "Label for the admin ACL row the VTA will create (optional).",
                    None,
                    &app.text_input,
                    "mediator-admin",
                    &hint,
                );
                info_box::render_info_box(
                    frame,
                    chunks[1],
                    "Info",
                    "Labels help when auditing the VTA's ACL table later — pick \
                     something that distinguishes this mediator's admin row from \
                     others. The bootstrap request is generated on Enter.",
                );
                return;
            }
            SealedPhase::CollectMediatorUrl => {
                let hint = state.last_error.clone().unwrap_or_else(|| {
                    "The public URL this mediator will serve on. Fed to the VTA's \
                     `didcomm-mediator` template as the required `URL` variable, \
                     which the rendered mediator DID's service endpoints point to."
                        .into()
                });
                prompt::render_prompt(
                    frame,
                    chunks[0],
                    "Sealed handoff — mediator URL",
                    "Public URL this mediator will serve at.",
                    None,
                    &app.text_input,
                    "https://mediator.example.com",
                    &hint,
                );
                info_box::render_info_box(
                    frame,
                    chunks[1],
                    "Info",
                    "The VTA renders the mediator's DID with this URL baked into \
                     the service endpoints. Changing it later means re-provisioning.",
                );
                return;
            }
            SealedPhase::CollectWebvhServer => {
                let hint = state.last_error.clone().unwrap_or_else(|| {
                    "Optional — webvh server id to pin for hosting the minted \
                     mediator DID's did.jsonl log. Leave blank to let the VTA \
                     pick its default. Ask your VTA admin which servers are \
                     registered."
                        .into()
                });
                prompt::render_prompt(
                    frame,
                    chunks[0],
                    "Sealed handoff — webvh server (optional)",
                    "Pin a webvh server for this DID's log (optional).",
                    None,
                    &app.text_input,
                    "webvh-prod-1",
                    &hint,
                );
                info_box::render_info_box(
                    frame,
                    chunks[1],
                    "Info",
                    "Online mode can discover webvh servers from the VTA — offline \
                     can't. If your VTA runs multiple webvh hosts, type the id; \
                     otherwise leave blank. The bootstrap request is generated on \
                     Enter.",
                );
                return;
            }
            SealedPhase::RequestGenerated => {
                // Handled above before the two-panel split so the
                // JSON + producer commands get the full content
                // width. Unreachable here, but kept as an arm so
                // the `match` stays exhaustive if `SealedPhase`
                // gains new variants.
                return;
            }
            SealedPhase::AwaitingBundle => {
                let hint = state.last_error.clone().unwrap_or_else(|| {
                    "Paste the entire `-----BEGIN VTA SEALED BUNDLE-----` block, then press \
                     Enter. Bracketed paste is supported. Esc cancels."
                        .into()
                });
                prompt::render_prompt(
                    frame,
                    chunks[0],
                    "Sealed handoff — paste armored bundle",
                    "Paste the HPKE-armored bundle returned by your VTA admin.",
                    None,
                    &app.text_input,
                    "-----BEGIN VTA SEALED BUNDLE-----",
                    &hint,
                );
                info_box::render_info_box(
                    frame,
                    chunks[1],
                    "Info",
                    "Bundle is parsed locally — no network call. The wizard verifies its \
                     internal AEAD on every chunk and refuses on any tamper.",
                );
                return;
            }
            SealedPhase::DigestVerify => {
                let computed = state.computed_digest.as_deref().unwrap_or("(missing)");
                let title = "Sealed handoff — verify digest";
                let desc = "Type the SHA-256 digest your VTA admin showed you. Leave blank to \
                            skip the OOB check.";
                let placeholder = "sha256 hex (or blank to skip)";
                let hint_default = format!(
                    "Computed digest of the parsed bundle:\n  {computed}\n\nIf the producer \
                     told you a different digest, do NOT continue — abort and re-request the \
                     bundle."
                );
                let hint = state.last_error.clone().unwrap_or(hint_default);
                prompt::render_prompt(
                    frame,
                    chunks[0],
                    title,
                    desc,
                    None,
                    &app.text_input,
                    placeholder,
                    &hint,
                );
                info_box::render_info_box(
                    frame,
                    chunks[1],
                    "Info",
                    "Skipping the digest is acceptable for low-stakes dev work — the bundle's \
                     internal AEAD still binds the payload — but for production rollouts, \
                     paste the digest the VTA admin shared on a separate channel.",
                );
                return;
            }
            SealedPhase::Complete => {
                let session = state
                    .session
                    .as_ref()
                    .expect("Complete phase always has a session");
                let body = format!(
                    "Bundle opened successfully.\n\nAdmin DID: {}\nVTA DID:   {}\n\n\
                     Press Enter to provision the unified secret backend with this credential.",
                    session.admin_did(),
                    session.vta_did
                );
                info_box::render_info_box(frame, chunks[0], "Sealed handoff — complete", &body);
                info_box::render_info_box(
                    frame,
                    chunks[1],
                    "Info",
                    "The wizard will continue to the Protocol step. The captured admin \
                     credential will be written to your chosen secret backend at the end \
                     of the wizard.",
                );
                return;
            }
        }
    }

    if let (Some(state), Some(phase)) = (app.vta_connect.as_ref(), app.vta_phase()) {
        use crate::vta_connect::ConnectPhase;
        match phase {
            ConnectPhase::EnterDid => {
                prompt::render_prompt(
                    frame,
                    chunks[0],
                    "VTA DID",
                    "The DID of the VTA you want to connect to.",
                    Some("Tip: run `pnm config get` on your PNM to find the VTA DID."),
                    &app.text_input,
                    "did:webvh:vta.example.com",
                    "The wizard resolves the DID to discover the VTA's REST and \
                     DIDComm service endpoints — you don't need to supply URLs.",
                );
                return;
            }
            ConnectPhase::EnterContext => {
                prompt::render_prompt(
                    frame,
                    chunks[0],
                    "VTA context",
                    "Name of the VTA context this mediator will live in.",
                    None,
                    &app.text_input,
                    "mediator  (press Enter to accept default)",
                    "Override if you use a different naming convention or run \
                     multiple mediators against the same VTA.",
                );
                return;
            }
            ConnectPhase::EnterMediatorUrl => {
                prompt::render_prompt(
                    frame,
                    chunks[0],
                    "Mediator public URL",
                    "URL this mediator will serve at — the VTA bakes it into \
                     the minted DID's service endpoints.",
                    None,
                    &app.text_input,
                    "https://mediator.example.com",
                    "Passed to the VTA's didcomm-mediator template as the \
                     `URL` variable. The wizard reuses this value for the \
                     mediator's own config — you won't be asked again later.",
                );
                return;
            }
            ConnectPhase::AwaitingAcl => {
                let options = app.current_options();
                instructions::render_instructions(
                    frame,
                    chunks[0],
                    &step_data.title,
                    &step_data.description,
                    state,
                    &options,
                    app.selection_index,
                    content_focused,
                );
                let info_text = app.current_info_text();
                info_box::render_info_box(frame, chunks[1], "Info", &info_text);
                return;
            }
            ConnectPhase::Testing | ConnectPhase::Connected => {
                let options = app.current_options();
                diagnostics::render_diagnostics(
                    frame,
                    chunks[0],
                    &step_data.title,
                    &step_data.description,
                    state,
                    &options,
                    app.selection_index,
                    content_focused,
                );
                let info_text = app.current_info_text();
                info_box::render_info_box(frame, chunks[1], "Info", &info_text);
                return;
            }
        }
    }

    // Render selection or text input based on step type
    match app.mode {
        InputMode::TextInput => {
            // KeyStorage sub-phases collect per-backend config via the
            // compact prompt widget. `key_storage_phase` tells us which
            // field we're on.
            if let Some(phase) = app.key_storage_phase {
                use crate::app::KeyStoragePhase;
                // FileEncryptChoice rides the selection list rather
                // than the text-input prompt, so it's never reached
                // here in TextInput mode. The match below handles it
                // with `unreachable!()` to keep the patterns
                // exhaustive without duplicating the prompt struct.
                let (title, desc, placeholder, hint) = match phase {
                    KeyStoragePhase::FileEncryptChoice => {
                        unreachable!("FileEncryptChoice runs in selection mode, not TextInput")
                    }
                    KeyStoragePhase::FileGate => (
                        "file:// is dev-only — type \"I understand\" to confirm",
                        "Plaintext secrets on disk are unsafe for production. \
                         The mediator will load private keys from a JSON file \
                         readable by anyone with filesystem access. If you \
                         meant to deploy to production, press Esc and pick a \
                         real backend (keyring, AWS Secrets Manager, …).",
                        "I understand",
                        "Type the phrase exactly to continue. Anything else \
                         aborts the file:// choice and returns you to the \
                         backend list.",
                    ),
                    KeyStoragePhase::FilePath => (
                        "Storage file path",
                        "Path where the mediator writes secrets.json.",
                        crate::consts::DEFAULT_SECRET_FILE_PATH,
                        "Relative paths are resolved from the config directory. \
                         Not secure for production — prefer keyring or a cloud \
                         secret manager.",
                    ),
                    KeyStoragePhase::FilePassphrase => (
                        "File-backend passphrase",
                        "Used to derive an AES-256-GCM key (Argon2id, mem=64MiB, t=3, p=4). \
                         Type carefully — there is no recovery if you lose it. The mediator \
                         will need the same passphrase at boot via MEDIATOR_FILE_BACKEND_PASSPHRASE \
                         or MEDIATOR_FILE_BACKEND_PASSPHRASE_FILE.",
                        "(passphrase — input is hidden)",
                        "Empty input is rejected. Pick something long and high-entropy: a \
                         passphrase manager entry or a 6+ word diceware string. The wizard \
                         exports this passphrase to its own process env so it can write \
                         the initial entries; you must arrange for the mediator to see the \
                         same value at boot.",
                    ),
                    KeyStoragePhase::KeyringService => (
                        "Keyring service name",
                        "Label for the mediator's entries in the OS keyring.",
                        crate::consts::DEFAULT_KEYRING_SERVICE,
                        "Appears in Keychain Access (macOS) / seahorse (GNOME) / \
                         credential manager (Windows). Keep it distinct per \
                         deployment so you can clean up easily.",
                    ),
                    KeyStoragePhase::AwsRegion => (
                        "AWS region",
                        "Region the AWS Secrets Manager client should target.",
                        crate::consts::DEFAULT_AWS_REGION,
                        "Uses your ambient AWS credentials (env vars, profile, \
                         or instance role) — make sure they're configured for \
                         the chosen region.",
                    ),
                    KeyStoragePhase::AwsPrefix => (
                        "Secret name prefix",
                        "Key namespace for this mediator's entries.",
                        crate::consts::DEFAULT_AWS_SECRET_PREFIX,
                        "Every secret written goes under this prefix — makes \
                         it easy to grant IAM access or clean up if you \
                         tear the mediator down.",
                    ),
                };
                prompt::render_prompt(
                    frame,
                    chunks[0],
                    title,
                    desc,
                    None,
                    &app.text_input,
                    placeholder,
                    hint,
                );
                return;
            }
            // The Did step collects the mediator URL when the operator
            // picks did:webvh — or did:vta (VTA-managed DID) which needs
            // the same URL so the VTA can publish correct service
            // endpoints. Route both through the compact prompt widget.
            if app.current_step == crate::app::WizardStep::Did
                && app.did_phase.is_none()
                && (app.config.did_method == crate::consts::DID_WEBVH
                    || app.config.did_method == crate::consts::DID_VTA)
            {
                prompt::render_prompt(
                    frame,
                    chunks[0],
                    "Mediator URL",
                    "Public URL where the mediator will be reachable.",
                    Some(
                        "Used to publish did:webvh service endpoints \
                         (DIDComm over HTTPS + WSS, Authentication).",
                    ),
                    &app.text_input,
                    "https://mediator.example.com/mediator/v1",
                    "Include the full path — the wizard derives DIDCommMessaging, \
                     WebSocket (`/ws`), and Authentication (`/authenticate`) \
                     endpoints from this URL.",
                );
                return;
            }
            // DidPhase::EnterCustomUrl / EnterMnemonic render as their
            // own compact prompts. SelectWebvhHost is a Selecting-mode
            // phase, not TextInput — handled by the selection branch
            // further below.
            if let Some(phase) = app.did_phase {
                use crate::app::DidPhase;
                let (title, desc, placeholder, hint) = match phase {
                    DidPhase::EnterCustomUrl => (
                        "Self-host base URL",
                        "Where the VTA should publish the DID document.",
                        "https://did.example.com",
                        "Path is stripped automatically — webvh resolves to \
                         `<url>/.well-known/did.jsonl`, so only scheme+host \
                         (plus optional port) matter.",
                    ),
                    DidPhase::EnterMnemonic => (
                        "Mnemonic",
                        "URL path segment for this DID on the chosen webvh server.",
                        "(blank — VTA auto-assigns)",
                        "Optional. Leave blank to let the VTA generate a \
                         unique path; type a value for a memorable / stable \
                         URL like `/mediator`.",
                    ),
                    DidPhase::SelectWebvhHost => {
                        unreachable!("SelectWebvhHost runs in Selecting mode, not TextInput")
                    }
                };
                prompt::render_prompt(
                    frame,
                    chunks[0],
                    title,
                    desc,
                    None,
                    &app.text_input,
                    placeholder,
                    hint,
                );
                return;
            }
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

/// Full-height render for the sealed-handoff "request" screen.
///
/// The default two-panel split (top content + bottom 6-line info
/// box) squeezes the producer commands into an area that clips the
/// multi-line `vta bootstrap seal` invocation. Here we take the
/// whole right-panel `area`, hand-build colored `Line`s, and render
/// once inside a single bordered `Paragraph`. No ANSI escape string
/// processing — ratatui renders `Style`d spans directly, so we get
/// real bold / color instead of literal `\x1b[1m` bleeding through.
fn render_sealed_request(
    frame: &mut Frame,
    area: Rect,
    state: &crate::sealed_handoff::SealedHandoffState,
) {
    let label = theme::title_style();
    let value = Style::default().fg(theme::TEXT);
    let hint = theme::muted_style();
    let key_style = Style::default().fg(theme::ACCENT);
    let str_style = theme::success_style();
    let punct_style = theme::muted_style();
    let num_style = Style::default().fg(theme::PRIMARY);
    let header_style = theme::title_style();
    let good = theme::success_style();
    let warn = Style::default().fg(Color::Yellow);
    let cmd = Style::default().fg(theme::ACCENT);

    let mut lines: Vec<Line<'static>> = Vec::new();

    lines.push(Line::from(Span::styled(
        "Ship this bootstrap request to your VTA admin out-of-band.",
        value,
    )));
    lines.push(Line::from(""));

    // ── header strip: file path + hotkey + clipboard status ──
    let file_display = state
        .request_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(not written — copy from the JSON below)".into());
    lines.push(Line::from(vec![
        Span::styled("File:     ", label),
        Span::styled(file_display, value),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Hotkeys:  ", label),
        Span::styled("[c]", cmd),
        Span::styled(" copy JSON   ", value),
        Span::styled("[v]", cmd),
        Span::styled(" copy vta cmd   ", value),
        Span::styled("[p]", cmd),
        Span::styled(" copy pnm-cli cmd", value),
    ]));
    lines.push(Line::from(Span::styled(
        "          (mouse selection inside the TUI wraps across panels)",
        hint,
    )));
    if let Some(status) = state.clipboard_status.as_deref() {
        let style = if status.starts_with("Copied") {
            good
        } else {
            warn
        };
        lines.push(Line::from(vec![
            Span::styled("Status:   ", label),
            Span::styled(status.to_string(), style),
        ]));
    }
    lines.push(Line::from(""));

    // ── JSON block (tiny hand-rolled highlighter) ──
    for raw in state.request_json.lines() {
        lines.push(highlight_json_line(
            raw,
            key_style,
            str_style,
            num_style,
            punct_style,
        ));
    }
    lines.push(Line::from(""));

    // ── producer commands ──
    lines.push(Line::from(Span::styled(
        "── Producer commands ─────────────────────────────────────",
        header_style,
    )));
    let (primary_header, primary_hotkey, fallback_header) = match state.intent {
        crate::vta_connect::VtaIntent::AdminOnly => (
            "Recommended — VTA admin runs on any host with an authenticated pnm session:",
            "  [p] ",
            Some(
                "Fallback — only if `pnm` isn't available. Requires a hand-authored \
                 AdminCredential JSON payload at <ADMIN_CREDENTIAL_JSON>:",
            ),
        ),
        crate::vta_connect::VtaIntent::FullSetup => (
            "VTA admin runs this on the VTA host (has local super-admin access to the \
             keyspace — no `pnm acl create` required):",
            "  [v] ",
            None,
        ),
    };
    lines.push(Line::from(Span::styled(primary_header, value)));
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(primary_hotkey, cmd),
        Span::styled(state.primary_command(), cmd),
    ]));
    if let (Some(header), Some(fb)) = (fallback_header, state.fallback_command()) {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(header, value)));
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("  [f] ", cmd),
            Span::styled(fb, cmd),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Returns bundle.armor + a printed digest. Paste the bundle on the next screen.",
        value,
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Press ", hint),
        Span::styled("Enter", cmd),
        Span::styled(" once you have the bundle. ", hint),
        Span::styled("Esc", cmd),
        Span::styled(" cancels.", hint),
    ]));

    let block = Block::default()
        .title(Span::styled(
            " Sealed handoff — request ",
            theme::info_style(),
        ))
        .borders(Borders::ALL)
        .border_style(theme::border_style())
        .padding(Padding::new(2, 2, 1, 0));

    let para = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}

/// Tiny hand-rolled JSON-line highlighter. Handles the shape
/// `BootstrapRequest` produces (four `"key": value,` lines plus
/// outer `{` / `}`). Anything unexpected falls back to muted
/// text — no panics.
fn highlight_json_line(
    raw: &str,
    key_style: Style,
    str_style: Style,
    num_style: Style,
    punct_style: Style,
) -> Line<'static> {
    let trimmed = raw.trim_start();
    let indent = &raw[..raw.len() - trimmed.len()];

    // Bare structural characters (outer `{` / `}`).
    if matches!(trimmed, "{" | "}" | "},") {
        return Line::from(vec![
            Span::styled(indent.to_string(), punct_style),
            Span::styled(trimmed.to_string(), punct_style),
        ]);
    }

    // `"key": <value>,?` — split at the first `:` after the
    // closing quote of the key.
    if let Some(colon_at) = trimmed.find("\":") {
        let key_end = colon_at + 1; // include closing `"`
        let key = &trimmed[..key_end];
        let rest = trimmed[key_end + 1..].trim_start(); // after `:`

        // `rest` is either `"string",`, a number + optional `,`, etc.
        let (value_body, trailing) = if let Some(stripped) = rest.strip_suffix(',') {
            (stripped.trim_end(), ",")
        } else {
            (rest, "")
        };

        let value_style = if value_body.starts_with('"') {
            str_style
        } else if value_body
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit())
        {
            num_style
        } else {
            punct_style
        };

        return Line::from(vec![
            Span::styled(indent.to_string(), punct_style),
            Span::styled(key.to_string(), key_style),
            Span::styled(": ".to_string(), punct_style),
            Span::styled(value_body.to_string(), value_style),
            Span::styled(trailing.to_string(), punct_style),
        ]);
    }

    // Fallback — unknown shape, render dim.
    Line::from(Span::styled(raw.to_string(), punct_style))
}

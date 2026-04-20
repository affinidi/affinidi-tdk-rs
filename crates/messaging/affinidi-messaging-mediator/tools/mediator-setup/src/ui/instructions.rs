//! Renderer for the AwaitingAcl instructions screen.
//!
//! Shows the copy-paste `pnm contexts create` + `pnm acl create` commands
//! (with the ephemeral setup DID already inlined) alongside the standalone
//! setup DID for any out-of-band use. A one-option selection row below the
//! block offers "Test VTA connection".

use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Wrap},
};

use crate::ui::selection::SelectionOption;
use crate::ui::theme;
use crate::vta_connect::VtaConnectState;

/// Render the instructions + single-option selection. `area` is the full
/// right-panel content area (the caller reserves space for the info box
/// below).
pub fn render_instructions(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    description: &str,
    state: &VtaConnectState,
    options: &[SelectionOption],
    selection_index: usize,
    focused: bool,
) {
    // Layout:
    //   [ title + description          ]
    //   [ action box (bordered accent) ]  ← primary call-to-action up top
    //   [ instructions block           ]  ← supporting content below
    //
    // Actions live above the body so the operator's eye lands on "what do I
    // do next" before the supporting text.
    let action_lines: u16 = 2 + options.len() as u16 * 2;
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(action_lines.max(4)),
            Constraint::Min(4),
        ])
        .split(area);

    // Header — title + description, mirrors selection::render_selection.
    let header = Paragraph::new(vec![
        Line::from(Span::styled(title, theme::title_style())),
        Line::from(Span::styled(description, theme::muted_style())),
    ]);
    frame.render_widget(header, chunks[0]);

    // Action box at the top — accented border, short label.
    render_action_box(
        frame,
        chunks[1],
        options,
        selection_index,
        focused,
        Vec::new(),
    );

    // Instructions block.
    let acl = state
        .acl_command()
        .unwrap_or_else(|| "(setup key not generated)".to_string());
    let setup_did = state
        .setup_key
        .as_ref()
        .map(|k| k.did.as_str())
        .unwrap_or("(not generated)");

    let cmd_style = Style::default().fg(theme::PRIMARY);
    let did_style = Style::default().fg(theme::ACCENT);

    let lines = vec![
        Line::from(Span::styled(
            "Using your Personal Network Manager (PNM) connected to this VTA,",
            theme::muted_style(),
        )),
        Line::from(Span::styled(
            "create the mediator context and grant admin access to the setup DID:",
            theme::muted_style(),
        )),
        Line::from(""),
        Line::from(Span::styled(format!("  {acl}"), cmd_style)),
        Line::from(""),
        Line::from(Span::styled(
            "--name is a human-readable label — change \"Mediator\" to anything",
            theme::muted_style(),
        )),
        Line::from(Span::styled(
            "that fits your naming conventions.",
            theme::muted_style(),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "--admin-expires defaults to 1h. Use 24h, 7d, etc. for longer",
            theme::muted_style(),
        )),
        Line::from(Span::styled(
            "roll-outs; the entry is promoted to permanent on first auth.",
            theme::muted_style(),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "On first successful authentication the wizard will auto-rotate",
            theme::muted_style(),
        )),
        Line::from(Span::styled(
            "this setup DID to a fresh did:key — that rotated DID becomes",
            theme::muted_style(),
        )),
        Line::from(Span::styled(
            "the mediator's long-term admin identity.",
            theme::muted_style(),
        )),
        Line::from(""),
        Line::from(Span::styled("Setup DID (ephemeral):", theme::muted_style())),
        Line::from(Span::styled(format!("  {setup_did}"), did_style)),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border_style())
        .title(Span::styled(" Instructions ", theme::title_style()));
    let para = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    frame.render_widget(para, chunks[2]);

    // Failure messages from previous runner attempts show below the
    // instructions block so the operator can diagnose without losing the
    // pasteable command.
    if let Some(err) = state.last_error.as_ref() {
        let err_area = Rect {
            x: chunks[2].x,
            y: chunks[2].y + chunks[2].height.saturating_sub(1),
            width: chunks[2].width,
            height: 1,
        };
        frame.render_widget(
            Paragraph::new(Span::styled(
                format!("  Error: {err}"),
                Style::default().fg(Color::Red),
            )),
            err_area,
        );
    }
}

/// Render the primary-action selector inside a bordered accent box.
///
/// Shared by `render_instructions` (AwaitingAcl) and `render_diagnostics`
/// (Testing / Connected) so the "next step" affordance looks the same
/// wherever it appears. `status_lines` are rendered above the options —
/// typical uses are a "Running…" spinner, a failure hint, or a success
/// banner + rotated admin DID.
pub(crate) fn render_action_box(
    frame: &mut Frame,
    area: Rect,
    options: &[SelectionOption],
    selection_index: usize,
    focused: bool,
    status_lines: Vec<Line<'_>>,
) {
    let border_style = if focused {
        Style::default().fg(theme::ACCENT)
    } else {
        theme::border_style()
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(Span::styled(" Next step ", theme::title_style()));

    let mut lines: Vec<Line> = status_lines;
    if options.is_empty() && lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (waiting)",
            theme::muted_style(),
        )));
    }
    for (i, opt) in options.iter().enumerate() {
        let selected = i == selection_index && focused;
        let marker = if selected { "\u{203A} " } else { "  " };
        let label_style = if selected {
            theme::selected_style()
        } else {
            theme::normal_style()
        };
        lines.push(Line::from(vec![
            Span::styled(marker, label_style),
            Span::styled(opt.label.clone(), label_style),
        ]));
        lines.push(Line::from(Span::styled(
            format!("    {}", opt.info),
            theme::muted_style(),
        )));
    }

    let para = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}

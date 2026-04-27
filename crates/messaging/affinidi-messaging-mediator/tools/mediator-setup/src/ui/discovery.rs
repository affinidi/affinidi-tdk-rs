//! Renderer for the F5-triggered cloud-backend discovery overlay.
//!
//! Drawn on top of the normal step content via [`render_overlay`] —
//! called from `ui::render` when [`crate::app::WizardApp::discovery`]
//! is `Some`. Three sub-states:
//!
//! - **Loading** — single-line spinner row centred in the overlay.
//! - **Loaded** — scrollable list of discovered secret names.
//! - **Failed** — error message with a dismiss hint.
//!
//! The overlay is informational. Esc and Enter both dismiss it; the
//! operator types the namespace into the prompt themselves.
//!
//! The overlay borrows the `Clear` widget pattern from ratatui examples
//! to blank the underlying panels before drawing — without it the
//! progress / prompt content underneath would bleed through the empty
//! regions of the overlay block.

use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Padding, Paragraph, Wrap},
};

use crate::discovery::DiscoveryState;
use crate::ui::theme;

/// Render the discovery overlay over `area`. Caller is responsible for
/// only invoking this when `state` is non-`None`; the function itself
/// just renders unconditionally.
pub fn render_overlay(frame: &mut Frame, area: Rect, state: &DiscoveryState) {
    // Centre the overlay in the supplied area: 80% wide, 60% tall, with
    // sensible mins so a small terminal still gets a usable panel.
    let overlay = centred_rect(area, 80, 60);

    // `Clear` blanks the cells under the overlay so the underlying
    // prompt / list doesn't ghost through.
    frame.render_widget(Clear, overlay);

    match state {
        DiscoveryState::Loading => render_loading(frame, overlay),
        DiscoveryState::Failed { message } => render_failed(frame, overlay, message),
        DiscoveryState::Loaded {
            items,
            cursor,
            scroll,
        } => render_loaded(frame, overlay, items, *cursor, *scroll),
    }
}

fn centred_rect(area: Rect, percent_x: u16, percent_y: u16) -> Rect {
    let width = (area.width * percent_x / 100).max(40).min(area.width);
    let height = (area.height * percent_y / 100).max(8).min(area.height);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    Rect {
        x,
        y,
        width,
        height,
    }
}

fn render_loading(frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .title(" Discovering secrets — F5 ")
        .title_style(theme::info_style())
        .borders(Borders::ALL)
        .border_style(theme::border_style())
        .padding(Padding::new(2, 2, 1, 1));

    let lines = vec![
        Line::from(Span::styled(
            "Listing secrets in the configured backend…",
            theme::normal_style(),
        )),
        Line::from(""),
        Line::from(Span::styled("Press Esc to cancel.", theme::muted_style())),
    ];
    let p = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
    frame.render_widget(p, area);
}

fn render_failed(frame: &mut Frame, area: Rect, message: &str) {
    let block = Block::default()
        .title(" Discovery failed ")
        .title_style(theme::info_style())
        .borders(Borders::ALL)
        .border_style(theme::border_style())
        .padding(Padding::new(2, 2, 1, 1));

    let lines = vec![
        Line::from(Span::styled(message, theme::dim_style())),
        Line::from(""),
        Line::from(Span::styled(
            "Common causes: missing credentials in the environment, the \
             configured project / region / vault doesn't exist, or the IAM \
             role lacks list permission.",
            theme::muted_style(),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Press any key to dismiss and return to the prompt.",
            theme::muted_style(),
        )),
    ];
    let p = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
    frame.render_widget(p, area);
}

fn render_loaded(frame: &mut Frame, area: Rect, items: &[String], cursor: usize, scroll: usize) {
    let block = Block::default()
        .title(" Discovered secrets — Esc to dismiss ")
        .title_style(theme::info_style())
        .borders(Borders::ALL)
        .border_style(theme::border_style());

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if items.is_empty() {
        let empty = vec![
            Line::from(Span::styled(
                "Backend reachable, but it returned no entries.",
                theme::normal_style(),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "That's fine for a fresh deployment — type your namespace \
                 in the prompt and press Enter.",
                theme::muted_style(),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "Press Esc or Enter to dismiss.",
                theme::muted_style(),
            )),
        ];
        frame.render_widget(Paragraph::new(empty).wrap(Wrap { trim: true }), inner);
        return;
    }

    // Split inner into a list area + 2-row footer with the count.
    let footer_height = 2u16;
    let (list_area, footer_area) = if inner.height > footer_height + 1 {
        let split = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(footer_height)])
            .split(inner);
        (split[0], split[1])
    } else {
        // Tiny terminal — drop the footer rather than overlap.
        (inner, Rect::default())
    };

    let list_items: Vec<ListItem> = items
        .iter()
        .map(|s| ListItem::new(Line::from(Span::styled(s.clone(), theme::normal_style()))))
        .collect();

    let mut list_state = ListState::default();
    list_state.select(Some(cursor));
    // The renderer is read-only on `app` (UI rendering can't mutate
    // app state), so we can't update `scroll` here. The cursor's
    // own position is what `ListState` uses to drive scrolling — it
    // will keep the selection visible automatically. The `scroll`
    // field on `Loaded` exists for future fine-grained control but
    // isn't read here yet.
    let _ = scroll;

    let list = List::new(list_items)
        .highlight_style(theme::selected_style())
        .highlight_symbol("\u{2192} ");
    frame.render_stateful_widget(list, list_area, &mut list_state);

    if footer_area.height > 0 {
        let footer_text = format!(
            "  {n} secret{plural} — \u{2191}\u{2193}/PgUp/PgDn scroll  Esc dismiss",
            n = items.len(),
            plural = if items.len() == 1 { "" } else { "s" },
        );
        let footer = Paragraph::new(Line::from(Span::styled(footer_text, theme::muted_style())));
        frame.render_widget(footer, footer_area);
    }
}

use crate::{
    state_store::{State, actions::Action},
    ui_management::components::component::{Component, ComponentRender},
};
use ratatui::{
    Frame,
    crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind},
    layout::{Alignment, Constraint, Flex, Layout, Position},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Widget, Wrap},
};
use tokio::sync::mpsc::UnboundedSender;
use tui_input::{Input, backend::crossterm::EventHandler};

pub struct Props {
    pub show: bool,
    pub invite_link: String,
    pub messages: Vec<Line<'static>>,
    pub invite_error: Option<String>,
}

impl From<&State> for Props {
    fn from(state: &State) -> Self {
        Props {
            show: state.accept_invite_popup.show,
            invite_link: state.accept_invite_popup.invite_link.clone(),
            messages: state.accept_invite_popup.messages.clone(),
            invite_error: state.accept_invite_popup.invite_error.clone(),
        }
    }
}

pub struct AcceptInvitePopup {
    pub action_tx: UnboundedSender<Action>,
    // Mapped Props from State
    pub props: Props,
    // Child Components
    pub invite_link: Input,
}

impl AcceptInvitePopup {
    fn _reset_inputs(&mut self) {
        self.invite_link = Input::new(self.props.invite_link.clone());
    }
}

impl Component for AcceptInvitePopup {
    fn new(state: &State, action_tx: UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        AcceptInvitePopup {
            action_tx: action_tx.clone(),
            props: Props::from(state),
            invite_link: Input::from(state.accept_invite_popup.invite_link.clone()),
        }
        .move_with_state(state)
    }

    fn move_with_state(self, state: &State) -> Self
    where
        Self: Sized,
    {
        AcceptInvitePopup {
            props: Props::from(state),
            ..self
        }
    }

    fn name(&self) -> &str {
        "Accept Invite"
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        fn _convert_input(input: &str) -> String {
            if input.is_empty() {
                String::new()
            } else {
                input.to_string()
            }
        }

        if key.kind != KeyEventKind::Press {
            return;
        }

        match key.code {
            KeyCode::Enter => {
                let _ = self.action_tx.send(Action::AcceptInvite {
                    invite_link: _convert_input(self.invite_link.value()),
                });
            }
            KeyCode::Esc => {
                self._reset_inputs();
                let _ = self.action_tx.send(Action::AcceptInvitePopupStop);
            }
            _ => {
                self.invite_link.handle_event(&Event::Key(key));
            }
        }
    }
}

impl ComponentRender<()> for AcceptInvitePopup {
    fn render(&self, frame: &mut Frame, _props: ()) {
        let outer_block = Block::bordered()
            .title(vec![
                Span::styled("Accept Invitation", Style::default().bold()),
                //Span::styled(&chat.name, Style::default().fg(Color::Blue)),
            ])
            .style(Style::default().bg(Color::White).fg(Color::Black).bold());
        let vertical = Layout::vertical([Constraint::Percentage(30)]).flex(Flex::Center);
        let horizontal = Layout::horizontal([Constraint::Percentage(80)]).flex(Flex::Center);
        let [outer_area] = vertical.areas(frame.area());
        let [outer_area] = horizontal.areas(outer_area);
        let inner_area = outer_block.inner(outer_area);

        // Clear the popup area first
        frame.render_widget(Clear, outer_area);

        // render the outer block
        outer_block.render(outer_area, frame.buffer_mut());

        let vertical = Layout::vertical([
            Constraint::Length(3), // Invite Link
            Constraint::Length(1), // Invite Error message?
            Constraint::Min(1),    // Messages
            Constraint::Length(1), // Help text
        ])
        .split(inner_area);

        // Invitation Link
        let width = vertical[0].width.max(3) - 3;
        let invite_link_scroll = self.invite_link.visual_scroll(width as usize);

        // Mediator DID
        let input = Paragraph::new(self.invite_link.value())
            .style(Style::default().fg(Color::Cyan))
            .scroll((0, invite_link_scroll as u16))
            .block(Block::bordered().title("Invitation Link?"));
        input.render(vertical[0], frame.buffer_mut());

        // set the cursor position
        let cursor: Position = (
            // Put cursor past the end of the input text
            vertical[0].x
                + ((self.invite_link.visual_cursor()).max(invite_link_scroll) - invite_link_scroll)
                    as u16
                + 1,
            // Move one line down, from the border to the input line
            vertical[0].y + 1,
        )
            .into();

        let mut lines = vec![Line::default()];
        for m in self.props.messages.iter() {
            lines.push(m.to_owned());
        }

        if let Some(err) = &self.props.invite_error {
            lines.push(Line::styled(err, Style::default().bold().fg(Color::Red)));
        }
        Paragraph::new(lines)
            .alignment(Alignment::Left)
            .wrap(Wrap { trim: true })
            .render(vertical[2], frame.buffer_mut());

        // Help text
        let help_line = Line::from(vec![
            Span::styled("<ENTER> ", Style::default().fg(Color::LightRed).bold()),
            Span::styled("to save, ", Style::default()),
            Span::styled("<ESCAPE> ", Style::default().fg(Color::LightRed).bold()),
            Span::styled("to quit, ", Style::default()),
        ]);
        let help = Paragraph::new(help_line).centered();
        help.render(vertical[3], frame.buffer_mut());

        frame.set_cursor_position(cursor);
    }
}

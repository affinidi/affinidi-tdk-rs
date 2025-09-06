/*!
 * Popup that allows you to enter a remote DID to directly connect to
 * This will create a local DID
 *
 * There is no disovery occurring here - it is a point-to-point connection
 */
use crate::{
    InputType,
    state_store::{State, actions::Action},
    ui_management::components::component::{Component, ComponentRender},
};
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::{
    Frame,
    layout::{Constraint, Flex, Layout, Position},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Widget},
};
use tokio::sync::mpsc::UnboundedSender;
use tui_input::{Input, backend::crossterm::EventHandler};

pub struct Props {
    pub show: bool,
    pub remote_did: String,
    pub alias: String,
    pub error_msg: Option<String>,
}

impl From<&State> for Props {
    fn from(state: &State) -> Self {
        Props {
            show: state.manual_connect_popup.show,
            remote_did: state.manual_connect_popup.remote_did.clone(),
            alias: state.manual_connect_popup.alias.clone(),
            error_msg: state.manual_connect_popup.error_msg.clone(),
        }
    }
}

pub struct ManualConnectPopup {
    pub action_tx: UnboundedSender<Action>,
    // Mapped Props from State
    pub props: Props,
    // Child Components
    pub alias: Input,
    pub remote_did: Input,
    pub active_field: InputType,
}

impl ManualConnectPopup {
    fn _reset_inputs(&mut self) {
        self.remote_did = Input::new(self.props.remote_did.clone());
        self.alias = Input::new(self.props.alias.clone());
        self.active_field = InputType::ManualConnectAlias;
    }
}

impl Component for ManualConnectPopup {
    fn new(state: &State, action_tx: UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        ManualConnectPopup {
            active_field: InputType::ManualConnectAlias,
            action_tx: action_tx.clone(),
            props: Props::from(state),
            remote_did: Input::from(state.manual_connect_popup.remote_did.clone()),
            alias: Input::from(state.manual_connect_popup.alias.clone()),
        }
        .move_with_state(state)
    }

    fn move_with_state(self, state: &State) -> Self
    where
        Self: Sized,
    {
        ManualConnectPopup {
            props: Props::from(state),
            ..self
        }
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
                let _ = self.action_tx.send(Action::ManualConnect {
                    alias: _convert_input(self.alias.value()),
                    remote_did: _convert_input(self.remote_did.value()),
                });
            }
            KeyCode::Esc => {
                self._reset_inputs();
                let _ = self.action_tx.send(Action::ManualConnectPopupStop);
            }
            KeyCode::Up => {
                // Switch to the next input field
                match self.active_field {
                    InputType::ManualConnectAlias => {
                        self.active_field = InputType::ManualConnectRemoteDID;
                    }
                    InputType::ManualConnectRemoteDID => {
                        self.active_field = InputType::ManualConnectAlias;
                    }
                    _ => {}
                }
            }
            KeyCode::Down => {
                // Switch to the next input field
                match self.active_field {
                    InputType::ManualConnectAlias => {
                        self.active_field = InputType::ManualConnectRemoteDID;
                    }
                    InputType::ManualConnectRemoteDID => {
                        self.active_field = InputType::ManualConnectAlias;
                    }
                    _ => {}
                }
            }
            KeyCode::Tab => {
                // Switch to the next input field
                match self.active_field {
                    InputType::ManualConnectAlias => {
                        self.active_field = InputType::ManualConnectRemoteDID;
                    }
                    InputType::ManualConnectRemoteDID => {
                        self.active_field = InputType::ManualConnectAlias;
                    }
                    _ => {}
                }
            }
            _ => match self.active_field {
                InputType::ManualConnectAlias => {
                    self.alias.handle_event(&Event::Key(key));
                }
                InputType::ManualConnectRemoteDID => {
                    self.remote_did.handle_event(&Event::Key(key));
                }
                _ => {}
            },
        }
    }
}

impl ComponentRender<()> for ManualConnectPopup {
    fn render(&self, frame: &mut Frame, _props: ()) {
        let outer_block = Block::bordered()
            .title(vec![Span::styled(
                "Manual Connection Setup",
                Style::default().bold(),
            )])
            .style(Style::default().bg(Color::White).fg(Color::Black).bold());
        let vertical = Layout::vertical([Constraint::Percentage(30)]).flex(Flex::Center);
        let horizontal = Layout::horizontal([Constraint::Percentage(80)]).flex(Flex::Center);
        let [outer_area] = vertical.areas(frame.area());
        let [outer_area] = horizontal.areas(outer_area);
        let inner_area = outer_block.inner(outer_area);

        // Clear the popup area first
        frame.render_widget(Clear, outer_area);

        // <Alias>
        // Gap
        // <Remote DID>
        // Gap
        // Error Message
        // Gap
        // Help Text
        let vertical = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(inner_area);

        outer_block.render(outer_area, frame.buffer_mut());

        // Inputs
        let width = vertical[0].width.max(3) - 3;
        let input_area = match self.active_field {
            InputType::ManualConnectAlias => vertical[0],
            InputType::ManualConnectRemoteDID => vertical[2],
            _ => vertical[0],
        };
        let alias_scroll = self.alias.visual_scroll(width as usize);
        let remote_did_scroll = self.remote_did.visual_scroll(width as usize);

        // Alias Name
        let input = Paragraph::new(self.alias.value())
            .style(Style::default().fg(Color::Cyan))
            .scroll((0, alias_scroll as u16))
            .block(Block::bordered().title("Chat Alias?"));
        input.render(vertical[0], frame.buffer_mut());

        // Remote DID
        let input = Paragraph::new(self.remote_did.value())
            .style(Style::default().fg(Color::Cyan))
            .scroll((0, remote_did_scroll as u16))
            .block(Block::bordered().title("Remote Did?"));
        input.render(vertical[2], frame.buffer_mut());

        // Display any error messages
        if let Some(error_msg) = &self.props.error_msg {
            let error_msg = Line::styled(error_msg, Style::default().fg(Color::Red));
            error_msg.render(vertical[4], frame.buffer_mut());
        }

        // set the cursor position
        let cursor: Position = (
            // Put cursor past the end of the input text
            if self.active_field == InputType::ManualConnectAlias {
                input_area.x
                    + ((self.alias.visual_cursor()).max(alias_scroll) - alias_scroll) as u16
                    + 1
            } else {
                input_area.x
                    + ((self.remote_did.visual_cursor()).max(remote_did_scroll) - remote_did_scroll)
                        as u16
                    + 1
            },
            // Move one line down, from the border to the input line
            input_area.y + 1,
        )
            .into();

        // Help text
        let help_line = Line::from(vec![
            Span::styled("<ENTER> ", Style::default().fg(Color::LightRed).bold()),
            Span::styled("to save, ", Style::default()),
            Span::styled("<ESCAPE> ", Style::default().fg(Color::LightRed).bold()),
            Span::styled("to quit, ", Style::default()),
        ]);
        let help = Paragraph::new(help_line).centered();
        help.render(vertical[6], frame.buffer_mut());

        frame.set_cursor_position(cursor);
    }
}

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::{
    Frame,
    layout::{Constraint, Flex, Layout, Position},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Widget},
};
use tokio::sync::mpsc::UnboundedSender;
use tui_input::{Input, backend::crossterm::EventHandler};

use crate::{
    InputType,
    state_store::{CommonSettings, State, actions::Action},
    ui_management::components::component::{Component, ComponentRender},
};

pub struct Props {
    mediator_did: String,
    avatar_path: String,
    mediator_did_error: Option<String>,
    avatar_path_error: Option<String>,
    our_name: Option<String>,
    pub show_settings_popup: bool,
}

impl From<&State> for Props {
    fn from(state: &State) -> Self {
        Props {
            mediator_did: state.settings.mediator_did.clone().unwrap_or_default(),
            avatar_path: state.settings.avatar_path.clone().unwrap_or_default(),
            avatar_path_error: state.settings.avatar_path_error.clone(),
            mediator_did_error: state.settings.mediator_did_error.clone(),
            show_settings_popup: state.settings.show_settings_popup,
            our_name: state.settings.our_name.clone(),
        }
    }
}

pub struct SettingsPopup {
    pub action_tx: UnboundedSender<Action>,
    // Mapped Props from State
    pub props: Props,

    // Child Components
    pub active_field: InputType,
    pub mediator_did: Input,
    pub avatar_path: Input,
    pub our_name: Input,
}

impl SettingsPopup {
    fn _reset_inputs(&mut self) {
        self.mediator_did = Input::new(self.props.mediator_did.clone());
        self.avatar_path = Input::new(self.props.avatar_path.clone());
        self.our_name = Input::new(self.props.our_name.clone().unwrap_or_default());
        self.active_field = InputType::MediatorDID;
    }
}

impl Component for SettingsPopup {
    fn new(state: &State, action_tx: UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        SettingsPopup {
            action_tx: action_tx.clone(),
            props: Props::from(state),
            active_field: InputType::MediatorDID,
            mediator_did: Input::from(state.settings.mediator_did.clone().unwrap_or_default()),
            avatar_path: Input::from(state.settings.avatar_path.clone().unwrap_or_default()),
            our_name: Input::from(state.settings.our_name.clone().unwrap_or_default()),
        }
        .move_with_state(state)
    }

    fn move_with_state(self, state: &State) -> Self
    where
        Self: Sized,
    {
        SettingsPopup {
            props: Props::from(state),
            ..self
        }
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        fn _convert_input(input: &str) -> Option<String> {
            if input.is_empty() {
                None
            } else {
                Some(input.to_string())
            }
        }

        if key.kind != KeyEventKind::Press {
            return;
        }

        match key.code {
            KeyCode::F(1) => {
                // switch back to the previous focus
                self._reset_inputs();
                let _ = self.action_tx.send(Action::SettingsPopupToggle);
            }
            KeyCode::Enter => {
                let _ = self.action_tx.send(Action::SettingsUpdate {
                    settings: CommonSettings {
                        mediator_did: _convert_input(self.mediator_did.value()),
                        avatar_path: _convert_input(self.avatar_path.value()),
                        mediator_did_error: None,
                        avatar_path_error: None,
                        show_settings_popup: self.props.show_settings_popup,
                        our_name: _convert_input(self.our_name.value()),
                    },
                });
            }
            KeyCode::Up => {
                let _ = self.action_tx.send(Action::SettingsCheck {
                    settings: CommonSettings {
                        mediator_did: _convert_input(self.mediator_did.value()),
                        avatar_path: _convert_input(self.avatar_path.value()),
                        mediator_did_error: None,
                        avatar_path_error: None,
                        show_settings_popup: self.props.show_settings_popup,
                        our_name: self.props.our_name.clone(),
                    },
                });
                // Switch to the next input field
                match self.active_field {
                    InputType::MediatorDID => {
                        self.active_field = InputType::OurName;
                    }
                    InputType::AvatarPath => {
                        self.active_field = InputType::MediatorDID;
                    }
                    InputType::OurName => {
                        self.active_field = InputType::AvatarPath;
                    }
                    _ => {}
                }
            }
            KeyCode::Down => {
                let _ = self.action_tx.send(Action::SettingsCheck {
                    settings: CommonSettings {
                        mediator_did: _convert_input(self.mediator_did.value()),
                        avatar_path: _convert_input(self.avatar_path.value()),
                        mediator_did_error: None,
                        avatar_path_error: None,
                        show_settings_popup: self.props.show_settings_popup,
                        our_name: self.props.our_name.clone(),
                    },
                });
                // Switch to the next input field
                match self.active_field {
                    InputType::MediatorDID => {
                        self.active_field = InputType::AvatarPath;
                    }
                    InputType::AvatarPath => {
                        self.active_field = InputType::OurName;
                    }
                    InputType::OurName => {
                        self.active_field = InputType::MediatorDID;
                    }
                    _ => {}
                }
            }
            KeyCode::Tab => {
                let _ = self.action_tx.send(Action::SettingsCheck {
                    settings: CommonSettings {
                        mediator_did: _convert_input(self.mediator_did.value()),
                        avatar_path: _convert_input(self.avatar_path.value()),
                        mediator_did_error: None,
                        avatar_path_error: None,
                        show_settings_popup: self.props.show_settings_popup,
                        our_name: self.props.our_name.clone(),
                    },
                });
                // Switch to the next input field
                match self.active_field {
                    InputType::MediatorDID => {
                        self.active_field = InputType::AvatarPath;
                    }
                    InputType::AvatarPath => {
                        self.active_field = InputType::OurName;
                    }
                    InputType::OurName => {
                        self.active_field = InputType::MediatorDID;
                    }
                    _ => {}
                }
            }
            KeyCode::Esc => {
                self._reset_inputs();
                let _ = self.action_tx.send(Action::SettingsPopupToggle);
            }
            _ => match self.active_field {
                InputType::MediatorDID => {
                    self.mediator_did.handle_event(&Event::Key(key));
                }
                InputType::AvatarPath => {
                    self.avatar_path.handle_event(&Event::Key(key));
                }
                InputType::OurName => {
                    self.our_name.handle_event(&Event::Key(key));
                }
                _ => {}
            },
        }
    }
}

impl ComponentRender<()> for SettingsPopup {
    fn render(&self, frame: &mut Frame, _props: ()) {
        let outer_block = Block::bordered()
            .title("Settings")
            .style(Style::default().bg(Color::White).fg(Color::Black).bold());
        let vertical = Layout::vertical([Constraint::Percentage(25)]).flex(Flex::Center);
        let horizontal = Layout::horizontal([Constraint::Percentage(50)]).flex(Flex::Center);
        let [outer_area] = vertical.areas(frame.area());
        let [outer_area] = horizontal.areas(outer_area);
        // Clear the popup area first
        frame.render_widget(Clear, outer_area);

        let inner_area = outer_block.inner(outer_area);

        // <Mediator Input>
        // Mediator error message?
        // <Avatar  Input>
        // Avatar error message?
        // <Our Name Input>
        // Help Text
        let vertical = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(inner_area);

        outer_block.render(outer_area, frame.buffer_mut());

        // Mediator DID Input
        let width = vertical[0].width.max(3) - 3;
        let input_area = match self.active_field {
            InputType::MediatorDID => vertical[0],
            InputType::AvatarPath => vertical[2],
            InputType::OurName => vertical[4],
            _ => vertical[0],
        };
        let mediator_scroll = self.mediator_did.visual_scroll(width as usize);
        let avatar_scroll = self.avatar_path.visual_scroll(width as usize);
        let our_name_scroll = self.our_name.visual_scroll(width as usize);

        // Mediator DID
        let input = Paragraph::new(self.mediator_did.value())
            .style(if self.active_field == InputType::MediatorDID {
                Style::default().fg(Color::Cyan)
            } else {
                Style::default().fg(Color::Black)
            })
            .scroll((0, mediator_scroll as u16))
            .block(Block::bordered().title("Mediator DID"));
        input.render(vertical[0], frame.buffer_mut());

        // Mediator DID error?
        if let Some(error) = &self.props.mediator_did_error {
            let error = Line::styled(error, Style::default().fg(Color::Red));
            error.render(vertical[1], frame.buffer_mut());
        }

        // Avatar Image URL
        let avatar = Paragraph::new(self.avatar_path.value())
            .style(if self.active_field == InputType::AvatarPath {
                Style::default().fg(Color::Cyan)
            } else {
                Style::default().fg(Color::Black)
            })
            .scroll((0, avatar_scroll as u16))
            .block(Block::bordered().title("Avatar Image Path"));
        avatar.render(vertical[2], frame.buffer_mut());

        // Avatar path error?
        if let Some(error) = &self.props.avatar_path_error {
            let error = Line::styled(error, Style::default().fg(Color::Red));
            error.render(vertical[3], frame.buffer_mut());
        }

        // Our Name Input
        let our_name = Paragraph::new(self.our_name.value())
            .style(if self.active_field == InputType::OurName {
                Style::default().fg(Color::Cyan)
            } else {
                Style::default().fg(Color::Black)
            })
            .scroll((0, our_name_scroll as u16))
            .block(Block::bordered().title("Our Name?"));
        our_name.render(vertical[4], frame.buffer_mut());

        // Help text
        let help_line = Line::from(vec![
            Span::styled("<TAB> ", Style::default().fg(Color::LightRed).bold()),
            Span::styled("to change input, ", Style::default()),
            Span::styled("<ENTER> ", Style::default().fg(Color::LightRed).bold()),
            Span::styled("to save, ", Style::default()),
            Span::styled("<ESCAPE> ", Style::default().fg(Color::LightRed).bold()),
            Span::styled("to quit, ", Style::default()),
        ]);
        let help = Paragraph::new(help_line).centered();
        help.render(vertical[5], frame.buffer_mut());

        // set the cursor position
        let cursor: Position = (
            // Put cursor past the end of the input text
            if self.active_field == InputType::MediatorDID {
                input_area.x
                    + ((self.mediator_did.visual_cursor()).max(mediator_scroll) - mediator_scroll)
                        as u16
                    + 1
            } else if self.active_field == InputType::AvatarPath {
                input_area.x
                    + ((self.avatar_path.visual_cursor()).max(avatar_scroll) - avatar_scroll) as u16
                    + 1
            } else {
                input_area.x
                    + ((self.our_name.visual_cursor()).max(our_name_scroll) - our_name_scroll)
                        as u16
                    + 1
            },
            // Move one line down, from the border to the input line
            input_area.y + 1,
        )
            .into();

        frame.set_cursor_position(cursor);
    }
}

use crate::{
    state_store::{
        ChatDetailsPopupState, State,
        actions::{
            Action,
            chat_list::{Chat, ChatStatus},
        },
    },
    ui_management::components::{Component, ComponentRender},
};
use circular_queue::CircularQueue;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use ratatui::{
    Frame,
    layout::{Constraint, Flex, Layout},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Widget},
};
use tokio::sync::mpsc::UnboundedSender;
use tracing::error;

pub struct Props {
    pub chat: Option<Chat>,
    pub chat_details_popup_state: ChatDetailsPopupState,
}

impl From<&State> for Props {
    fn from(state: &State) -> Self {
        Props {
            chat: state.chat_details_popup.chat_name.as_ref().map(|c| {
                if let Some(chat) = state.chat_list.chats.get(c) {
                    chat.to_owned()
                } else {
                    Chat {
                        name: "No longer exists".into(),
                        description: "Chat no longer exists".to_owned(),
                        status: ChatStatus::DoesntExist,
                        our_profile: Default::default(),
                        remote_did: None,
                        invitation_link: None,
                        has_unread: false,
                        hidden: None,
                        initialization: false,
                        messages: CircularQueue::with_capacity(1),
                    }
                }
            }),
            chat_details_popup_state: state.chat_details_popup.clone(),
        }
    }
}

pub struct ChatDetailsPopup {
    pub action_tx: UnboundedSender<Action>,
    // Mapped Props from State
    pub props: Props,
    // Child Components
}

impl Component for ChatDetailsPopup {
    fn new(state: &State, action_tx: UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        ChatDetailsPopup {
            action_tx: action_tx.clone(),
            props: Props::from(state),
        }
        .move_with_state(state)
    }

    fn move_with_state(self, state: &State) -> Self
    where
        Self: Sized,
    {
        ChatDetailsPopup {
            props: Props::from(state),
            ..self
        }
    }

    fn name(&self) -> &str {
        "Chat Details"
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        if key.code == KeyCode::Esc {
            let _ = self.action_tx.send(Action::CloseChatDetails);
        }
    }
}

impl ComponentRender<()> for ChatDetailsPopup {
    fn render(&self, frame: &mut Frame, _props: ()) {
        let Some(chat) = &self.props.chat else {
            error!("ChatDetailsPopup: Chat is None");
            let _ = self.action_tx.send(Action::CloseChatDetails);
            return;
        };

        let outer_block = Block::bordered()
            .title(vec![
                Span::styled("Chat Details: ", Style::default().bold()),
                Span::styled(&chat.name, Style::default().fg(Color::Blue)),
            ])
            .style(Style::default().bg(Color::White).fg(Color::Black).bold());
        let vertical = Layout::vertical([Constraint::Percentage(25)]).flex(Flex::Center);
        let horizontal = Layout::horizontal([Constraint::Percentage(70)]).flex(Flex::Center);
        let [outer_area] = vertical.areas(frame.area());
        let [outer_area] = horizontal.areas(outer_area);
        let inner_area = outer_block.inner(outer_area);

        // Clear the popup area first
        frame.render_widget(Clear, outer_area);

        // render the outer block
        outer_block.render(outer_area, frame.buffer_mut());

        let vertical =
            Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).split(inner_area);

        let mut lines = vec![
            Line::default(),
            Line::from(vec![
                Span::styled(
                    "    Description: ",
                    Style::default().bold().fg(Color::Black),
                ),
                Span::styled(&chat.description, Style::default().fg(Color::Blue)),
            ]),
            Line::from(vec![
                Span::styled(
                    "         Status: ",
                    Style::default().bold().fg(Color::Black),
                ),
                Span::styled(chat.status.to_string(), Style::default().fg(Color::Blue)),
            ]),
            Line::from(vec![
                Span::styled(
                    "    Our Profile: ",
                    Style::default().bold().fg(Color::Black),
                ),
                Span::styled(
                    format!(
                        "alias({}), did({})",
                        &chat.our_profile.alias, &chat.our_profile.did
                    ),
                    Style::default().fg(Color::Blue),
                ),
            ]),
            Line::from(vec![
                Span::styled(
                    "    Has Unread?: ",
                    Style::default().bold().fg(Color::Black),
                ),
                Span::styled(
                    chat.has_unread.to_string(),
                    Style::default().fg(Color::Blue),
                ),
            ]),
        ];

        if let Some(did) = &chat.remote_did {
            lines.push(Line::from(vec![
                Span::styled(
                    "     Remote DID: ",
                    Style::default().bold().fg(Color::Black),
                ),
                Span::styled(did, Style::default().fg(Color::Blue)),
            ]));
        }
        if let Some(invite) = &chat.invitation_link {
            lines.push(Line::from(vec![
                Span::styled(
                    "Invitation Link: ",
                    Style::default().bold().fg(Color::Black),
                ),
                Span::styled(invite, Style::default().fg(Color::Blue)),
            ]));
        }

        Paragraph::new(lines)
            .left_aligned()
            .render(vertical[0], frame.buffer_mut());

        Paragraph::new(Line::from(vec![
            Span::styled("<ESCAPE> ", Style::default().fg(Color::LightRed).bold()),
            Span::styled("to close, ", Style::default()),
        ]))
        .centered()
        .render(vertical[1], frame.buffer_mut());
    }
}

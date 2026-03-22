use crate::{
    state_store::{
        State,
        actions::{
            Action,
            chat_list::{Chat, ChatList},
        },
    },
    ui_management::{
        components::component::{Component, ComponentRender},
        pages::main_page::section::{
            SectionActivation,
            usage::{HasUsageInfo, UsageInfo},
        },
    },
};
use crossterm::event::KeyEvent;
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState},
};
use tokio::sync::mpsc::UnboundedSender;

pub struct Props {
    /// List of chats and current state of those chats
    pub chat_list: ChatList,
    /// Current active chat
    chats: Vec<Chat>,
}

impl From<&State> for Props {
    fn from(state: &State) -> Self {
        let mut chats = state
            .chat_list
            .chats
            .iter()
            .map(|(name, chat_data)| Chat {
                name: name.clone(),
                messages: chat_data.messages.clone(),
                description: chat_data.description.clone(),
                our_profile: chat_data.our_profile.clone(),
                remote_did: chat_data.remote_did.clone(),
                has_unread: chat_data.has_unread,
                invitation_link: chat_data.invitation_link.clone(),
                status: chat_data.status.clone(),
                initialization: chat_data.initialization,
                hidden: None,
            })
            .collect::<Vec<Chat>>();

        chats.sort_by(|chat_a, chat_b| chat_a.name.cmp(&chat_b.name));

        Self {
            chat_list: state.chat_list.clone(),
            chats,
        }
    }
}

pub struct ChatListComponent {
    pub props: Props,
    pub list_state: ListState,
}

impl ChatListComponent {
    pub fn next(&mut self) {
        if !self.props.chat_list.chats.is_empty() {
            let i = match self.list_state.selected() {
                Some(i) => {
                    if i >= self.props.chat_list.chats.len() - 1 {
                        0
                    } else {
                        i + 1
                    }
                }
                None => 0,
            };
            self.list_state.select(Some(i));
        }
    }

    pub fn previous(&mut self) {
        if !self.props.chat_list.chats.is_empty() {
            let i = match self.list_state.selected() {
                Some(i) => {
                    if i == 0 {
                        self.props.chat_list.chats.len() - 1
                    } else {
                        i - 1
                    }
                }
                None => 0,
            };

            self.list_state.select(Some(i));
        }
    }

    pub fn chats(&self) -> &Vec<Chat> {
        &self.props.chats
    }

    fn get_chat_idx(&self, name: &str) -> Option<usize> {
        self.props
            .chats
            .iter()
            .enumerate()
            .find_map(|(idx, chat_state)| {
                if chat_state.name == name {
                    Some(idx)
                } else {
                    None
                }
            })
    }
}

impl Component for ChatListComponent {
    fn new(state: &State, _action_tx: UnboundedSender<Action>) -> Self {
        Self {
            props: Props::from(state),
            list_state: ListState::default(),
        }
    }

    fn move_with_state(self, state: &State) -> Self
    where
        Self: Sized,
    {
        Self {
            props: Props::from(state),
            ..self
        }
    }

    fn handle_key_event(&mut self, _key: KeyEvent) {}
    /*fn handle_key_event(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        match key.code {
            KeyCode::Up => {
                self.previous();

                if let Some(selected_idx) = self.list_state.selected() {
                    if let Some(chat) = self.chats().get(selected_idx) {
                        let _ = self.action_tx.send(Action::SetCurrentChat {
                            chat: chat.name.clone(),
                        });
                    }
                }
            }
            KeyCode::Down => {
                self.next();

                if let Some(selected_idx) = self.list_state.selected() {
                    if let Some(chat) = self.chats().get(selected_idx) {
                        let _ = self.action_tx.send(Action::SetCurrentChat {
                            chat: chat.name.clone(),
                        });
                    }
                }
            }
            KeyCode::Delete | KeyCode::Backspace if self.list_state.selected().is_some() => {
                let selected_idx = self.list_state.selected().unwrap();

                let chats = self.chats();
                let chat_state = if let Some(chat) = chats.get(selected_idx) {
                    chat
                } else {
                    return;
                };

                let _ = self.action_tx.send(Action::DeleteChat {
                    chat: chat_state.name.clone(),
                });
            }
            KeyCode::Enter if self.list_state.selected().is_some() => {
                let selected_idx = self.list_state.selected().unwrap();

                let chat_state = if let Some(chat) = self.chats().get(selected_idx) {
                    chat
                } else {
                    return;
                };

                let _ = self.action_tx.send(Action::ShowChatDetails {
                    chat: chat_state.name.clone(),
                });
            }
            _ => (),
        }
    }*/
}

impl SectionActivation for ChatListComponent {
    fn activate(&mut self) {
        let idx: usize = self
            .props
            .chat_list
            .active_chat
            .as_ref()
            .and_then(|chat_name| self.get_chat_idx(chat_name.as_str()))
            .unwrap_or(0);

        *self.list_state.offset_mut() = 0;
        self.list_state.select(Some(idx));
    }

    fn deactivate(&mut self) {
        *self.list_state.offset_mut() = 0;
        self.list_state.select(None);
    }
}

pub struct RenderProps {
    pub border_color: Color,
    pub area: Rect,
}

impl ComponentRender<RenderProps> for ChatListComponent {
    fn render(&self, frame: &mut Frame, props: RenderProps) {
        let active_chat = self.props.chat_list.active_chat.clone();
        let chat_list: Vec<ListItem> = self
            .chats()
            .iter()
            .map(|room_state| {
                let room_tag = format!(
                    "{}{}",
                    room_state.name,
                    if room_state.has_unread { "*" } else { "" }
                );
                let content = Line::from(Span::raw(room_tag));

                let style = if self.list_state.selected().is_none()
                    && active_chat.is_some()
                    && active_chat.as_ref().unwrap().eq(&room_state.name)
                {
                    Style::default().add_modifier(Modifier::BOLD)
                } else if room_state.has_unread {
                    Style::default().add_modifier(Modifier::SLOW_BLINK | Modifier::ITALIC)
                } else {
                    Style::default()
                };

                ListItem::new(content).style(style.bg(Color::Reset))
            })
            .collect();

        let chat_list = List::new(chat_list)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::new().fg(props.border_color))
                    .title("Chats"),
            )
            .highlight_style(
                Style::default()
                    // yellow that would work for both dark / light modes
                    .bg(Color::Rgb(255, 223, 102))
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">");

        let mut app_chat_list_state = self.list_state.clone();
        frame.render_stateful_widget(chat_list, props.area, &mut app_chat_list_state);
    }
}

impl HasUsageInfo for ChatListComponent {
    fn usage_info(&self) -> UsageInfo {
        UsageInfo {
            description: None,
            lines: vec![],
        }
    }
}

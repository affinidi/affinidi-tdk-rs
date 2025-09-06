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
        pages::{
            accept_invite_popup::accept_invite_popup::AcceptInvitePopup,
            chat_details_popup::chat_details_popup::ChatDetailsPopup,
            invite_popup::invite_popup::InvitePopup,
            manual_connect_popup::manual_connect_popup::ManualConnectPopup,
            settings_popup::settings_popup::SettingsPopup,
        },
    },
};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::Constraint::{Length, Min, Percentage},
    prelude::*,
    widgets::*,
};
use tokio::sync::mpsc::UnboundedSender;

use super::{
    components::{
        bottom_menu::{self, BottomMenu},
        chat_list::{self, ChatListComponent},
        chat_logs::{self, ChatLogs},
        date_time::{self, DateTime},
        message_input_box::{self, MessageInputBox},
    },
    section::{
        SectionActivation,
        usage::{HasUsageInfo, UsageInfo, UsageInfoLine, widget_usage_to_text},
    },
};

#[derive(Debug, Clone, PartialEq)]
pub enum Section {
    ChatList,
    ChatInput,
}

impl Section {
    pub const COUNT: usize = 2;

    fn to_usize(&self) -> usize {
        match self {
            Section::ChatList => 0,
            Section::ChatInput => 1,
        }
    }
}

impl TryFrom<usize> for Section {
    type Error = ();

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Section::ChatList),
            1 => Ok(Section::ChatInput),
            _ => Err(()),
        }
    }
}

struct Props {
    /// The chat data map
    chat_list: ChatList,
    our_name: Option<String>,
    initialization: bool,
}

impl From<&State> for Props {
    fn from(state: &State) -> Self {
        Props {
            chat_list: state.chat_list.clone(),
            our_name: state.settings.our_name.clone(),
            initialization: state.initialization,
        }
    }
}

const DEFAULT_HOVERED_SECTION: Section = Section::ChatList;

/// MainPage handles the UI and the state of the chat page
pub struct MainPage {
    /// Action sender
    pub action_tx: UnboundedSender<Action>,
    /// State Mapped MainPage Props
    props: Props,
    // Internal State
    /// Currently active section, handling input
    pub active_section: Option<Section>,
    /// Section that is currently hovered
    pub last_hovered_section: Section,
    // Child Components
    bottom_menu: BottomMenu,
    date_time: DateTime,
    chat_list: ChatListComponent,
    chat_logs: ChatLogs,
    message_input_box: MessageInputBox,
    pub settings_popup: SettingsPopup,
    pub invite_popup: InvitePopup,
    pub manual_connect_popup: ManualConnectPopup,
    pub chat_details_popup: ChatDetailsPopup,
    pub accept_invite_popup: AcceptInvitePopup,
}

impl MainPage {
    fn get_chat_data(&self, name: &str) -> Option<&Chat> {
        self.props.chat_list.chats.get(name)
    }

    fn get_component_for_section_mut<'a>(&'a mut self, section: &Section) -> &'a mut dyn Component {
        match section {
            Section::ChatList => &mut self.chat_list,
            Section::ChatInput => &mut self.message_input_box,
        }
    }

    fn get_section_activation_for_section<'a>(
        &'a mut self,
        section: &Section,
    ) -> &'a mut dyn SectionActivation {
        match section {
            Section::ChatList => &mut self.chat_list,
            Section::ChatInput => &mut self.message_input_box,
        }
    }

    fn hover_next(&mut self) {
        let idx: usize = self.last_hovered_section.to_usize();
        let next_idx = (idx + 1) % Section::COUNT;
        self.last_hovered_section = Section::try_from(next_idx).unwrap();
    }

    fn hover_previous(&mut self) {
        let idx: usize = self.last_hovered_section.to_usize();
        let previous_idx = if idx == 0 {
            Section::COUNT - 1
        } else {
            idx - 1
        };
        self.last_hovered_section = Section::try_from(previous_idx).unwrap();
    }

    fn calculate_border_color(&self, section: Section) -> Color {
        match (self.active_section.as_ref(), &self.last_hovered_section) {
            (Some(active_section), _) if active_section.eq(&section) => Color::Yellow,
            (_, last_hovered_section) if last_hovered_section.eq(&section) => Color::Blue,
            _ => Color::Reset,
        }
    }

    fn disable_section(&mut self, section: &Section) {
        self.get_section_activation_for_section(section)
            .deactivate();

        self.active_section = None;
    }
}

impl Component for MainPage {
    fn new(state: &State, action_tx: UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        MainPage {
            action_tx: action_tx.clone(),
            // set the props
            props: Props::from(state),
            // internal component state
            active_section: Option::None,
            last_hovered_section: DEFAULT_HOVERED_SECTION,
            // child components
            bottom_menu: BottomMenu,
            date_time: DateTime,
            chat_list: ChatListComponent::new(state, action_tx.clone()),
            chat_logs: ChatLogs,
            message_input_box: MessageInputBox::new(state, action_tx.clone()),
            settings_popup: SettingsPopup::new(state, action_tx.clone()),
            invite_popup: InvitePopup::new(state, action_tx.clone()),
            chat_details_popup: ChatDetailsPopup::new(state, action_tx.clone()),
            accept_invite_popup: AcceptInvitePopup::new(state, action_tx.clone()),
            manual_connect_popup: ManualConnectPopup::new(state, action_tx),
        }
        .move_with_state(state)
    }

    fn move_with_state(self, state: &State) -> Self
    where
        Self: Sized,
    {
        MainPage {
            props: Props::from(state),
            // propagate the update to the child components
            chat_list: self.chat_list.move_with_state(state),
            settings_popup: self.settings_popup.move_with_state(state),
            invite_popup: self.invite_popup.move_with_state(state),
            chat_details_popup: self.chat_details_popup.move_with_state(state),
            message_input_box: self.message_input_box.move_with_state(state),
            accept_invite_popup: self.accept_invite_popup.move_with_state(state),
            manual_connect_popup: self.manual_connect_popup.move_with_state(state),
            ..self
        }
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        if self.settings_popup.props.show_settings_popup {
            self.settings_popup.handle_key_event(key);
        } else if self.invite_popup.props.invite_state.show_invite_popup {
            self.invite_popup.handle_key_event(key);
        } else if self.chat_details_popup.props.chat_details_popup_state.show {
            self.chat_details_popup.handle_key_event(key);
        } else if self.accept_invite_popup.props.show {
            self.accept_invite_popup.handle_key_event(key);
        } else if self.manual_connect_popup.props.show {
            self.manual_connect_popup.handle_key_event(key);
        } else {
            let active_section = self.active_section.clone();

            match active_section {
                None => match key.code {
                    KeyCode::Enter => {
                        if self.last_hovered_section == Section::ChatList {
                            if self.chat_list.list_state.selected().is_none() {
                                if self.chat_list.props.chat_list.active_chat.is_some() {
                                    self.chat_list.list_state.select(Some(0));
                                } else {
                                    return;
                                }
                            }
                            let selected_idx = self.chat_list.list_state.selected().unwrap();

                            let chat_state =
                                if let Some(chat) = self.chat_list.chats().get(selected_idx) {
                                    chat
                                } else {
                                    return;
                                };

                            let _ = self.action_tx.send(Action::ShowChatDetails {
                                chat: chat_state.name.clone(),
                            });
                        } else {
                            let last_hovered_section = self.last_hovered_section.clone();

                            self.active_section = Some(last_hovered_section.clone());
                            self.get_section_activation_for_section(&last_hovered_section)
                                .activate();
                        }
                    }
                    KeyCode::Up => {
                        self.chat_list.previous();

                        if let Some(selected_idx) = self.chat_list.list_state.selected()
                            && let Some(chat) = self.chat_list.chats().get(selected_idx)
                        {
                            let _ = self.action_tx.send(Action::SetCurrentChat {
                                chat: chat.name.clone(),
                            });
                        }
                    }
                    KeyCode::Down => {
                        self.chat_list.next();

                        if let Some(selected_idx) = self.chat_list.list_state.selected()
                            && let Some(chat) = self.chat_list.chats().get(selected_idx)
                        {
                            let _ = self.action_tx.send(Action::SetCurrentChat {
                                chat: chat.name.clone(),
                            });
                        }
                    }
                    KeyCode::Left => self.hover_previous(),
                    KeyCode::Right => self.hover_next(),
                    KeyCode::Delete | KeyCode::Backspace
                        if self.chat_list.list_state.selected().is_some() =>
                    {
                        let selected_idx = self.chat_list.list_state.selected().unwrap();

                        let chats = self.chat_list.chats();
                        let chat_state = if let Some(chat) = chats.get(selected_idx) {
                            chat
                        } else {
                            return;
                        };

                        let _ = self.action_tx.send(Action::DeleteChat {
                            chat: chat_state.name.clone(),
                        });
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        let _ = self.action_tx.send(Action::Exit);
                    }
                    KeyCode::F(1) => {
                        // Display the Settings Popup
                        let _ = self.action_tx.send(Action::SettingsPopupToggle);
                    }
                    KeyCode::F(2) => {
                        // Display the Invitation Popup
                        let _ = self.action_tx.send(Action::InvitePopupStart);
                    }
                    KeyCode::F(3) => {
                        // Display the Accept Invite Popup
                        let _ = self.action_tx.send(Action::AcceptInvitePopupStart);
                    }
                    KeyCode::F(4) => {
                        // Display the Manual Connect Popup
                        let _ = self.action_tx.send(Action::ManualConnectPopupStart);
                    }
                    KeyCode::F(10) => {
                        let _ = self.action_tx.send(Action::Exit);
                    }
                    _ => {}
                },
                Some(section) => {
                    self.get_component_for_section_mut(&section)
                        .handle_key_event(key);

                    // disable the section according to the action taken
                    // the section is disabled when escape is pressed
                    // or when enter is pressed on the chat list
                    match section {
                        Section::ChatList if key.code == KeyCode::Enter => {
                            self.disable_section(&section)
                        }
                        _ if key.code == KeyCode::Esc => self.disable_section(&section),
                        _ => (),
                    }
                }
            }
        }
    }
}

const NO_CHAT_SELECTED_MESSAGE: &str = "Select a Chat to start chatting!";

fn calculate_list_offset(height: u16, items_len: usize) -> usize {
    // go back by (container height + 2 for borders) to get the offset
    items_len.saturating_sub(height as usize - 2)
}

impl ComponentRender<()> for MainPage {
    fn render(&self, frame: &mut Frame, _props: ()) {
        // Split the screen into a single line bottom and the rest for the main content on top
        let [main_top, main_bottom] = *Layout::vertical([Min(0), Length(1)]).split(frame.area())
        else {
            panic!("Invalid layout for main page")
        };
        // Split the bottom into main menu items name, and date/time
        let [bottom_menu, status, name, date_time] =
            *Layout::horizontal([Min(0), Length(30), Length(20), Length(20)]).split(main_bottom)
        else {
            panic!("Invalid layout for main_bottom")
        };
        // Split the top section into two colums, first being ~30% of the screen
        let [main_left, main_right] = *Layout::horizontal([Percentage(30), Min(0)]).split(main_top)
        else {
            panic!("Invalid layout for main_top")
        };
        // Split the main_left column into chats and usage
        let [main_chat_list, main_usage] = *Layout::vertical([Min(0), Length(10)]).split(main_left)
        else {
            panic!("Invalid layout for main_left")
        };
        // Split the main_right into chate title, chat message, message input and log messages
        let [chat_title, chat_messages, chat_input, log_message] =
            *Layout::vertical([Length(3), Min(0), Length(3), Length(10)]).split(main_right)
        else {
            panic!("Invalid layout for main_right")
        };

        // Layout for the main page is completed. Render the components
        self.bottom_menu
            .render(frame, bottom_menu::RenderProps { area: bottom_menu });
        self.date_time
            .render(frame, date_time::RenderProps { area: date_time });

        if self.props.initialization {
            Paragraph::new(Span::styled(
                " Initializing... ",
                Style::default()
                    .bg(Color::Red)
                    .fg(Color::White)
                    .slow_blink()
                    .bold(),
            ))
            .alignment(Alignment::Center)
            .render(status, frame.buffer_mut());
        } else {
            Paragraph::new(Span::styled(
                " READY ",
                Style::default().bg(Color::Green).fg(Color::White).bold(),
            ))
            .alignment(Alignment::Center)
            .render(status, frame.buffer_mut());
        }
        if let Some(our_name) = &self.props.our_name {
            Paragraph::new(Span::styled(
                format!(" {} ", our_name),
                Style::default().bg(Color::Green).fg(Color::Black).bold(),
            ))
            .alignment(Alignment::Right)
            .render(name, frame.buffer_mut());
        }

        // Chat List
        self.chat_list.render(
            frame,
            chat_list::RenderProps {
                border_color: self.calculate_border_color(Section::ChatList),
                area: main_chat_list,
            },
        );

        //info!("Active Chat: {:?}", self.props.active_chat);
        // Active Chat Rendering
        // Chat Title
        let chat_description = if let Some(chat_data) = self
            .props
            .chat_list
            .active_chat
            .as_ref()
            .and_then(|active_chat| self.get_chat_data(active_chat))
        {
            Line::from(vec![
                "Chat:  (".into(),
                Span::from(&chat_data.name).bold(),
                "} Remote DID: (".into(),
                Span::from(chat_data.remote_did.clone().unwrap_or("NONE".to_string())).italic(),
                ")".into(),
            ])
        } else {
            Line::from(NO_CHAT_SELECTED_MESSAGE)
        };
        let text = Text::from(chat_description);

        let chat_description = Paragraph::new(text).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Active Chat Information"),
        );
        frame.render_widget(chat_description, chat_title);

        let messages = if let Some(active_chat) = self.props.chat_list.active_chat.as_ref() {
            self.get_chat_data(active_chat)
                .map(|chat_data| {
                    // let message_offset =
                    //   calculate_list_offset(chat_messages.height, chat_data.messages.len());

                    chat_data
                        .messages
                        .asc_iter()
                        // .skip(message_offset)
                        .flat_map(|mbi| mbi.render(chat_messages.width as usize - 2))
                        .collect::<Vec<Line>>()
                })
                .unwrap_or_default()
        } else {
            vec![Line::from(NO_CHAT_SELECTED_MESSAGE)]
        };
        let message_offset = calculate_list_offset(chat_messages.height, messages.len());

        let chat_message_window = Paragraph::new(messages)
            .block(Block::default().borders(Borders::ALL).title("Messages"))
            .wrap(Wrap { trim: false })
            .scroll((message_offset as u16, 0));

        frame.render_widget(chat_message_window, chat_messages);

        // Chat Message Input
        self.message_input_box.render(
            frame,
            message_input_box::RenderProps {
                border_color: self.calculate_border_color(Section::ChatInput),
                area: chat_input,
                show_cursor: self
                    .active_section
                    .as_ref()
                    .map(|active_section| active_section.eq(&Section::ChatInput))
                    .unwrap_or(false),
            },
        );

        // Log Window
        self.chat_logs
            .render(frame, chat_logs::RenderProps { area: log_message });

        // Usage instructions
        let mut usage_text: Text = widget_usage_to_text(self.usage_info());
        usage_text = usage_text.patch_style(Style::default());
        let usage = Paragraph::new(usage_text)
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::ALL).title("Usage"));
        frame.render_widget(usage, main_usage);

        if self.settings_popup.props.show_settings_popup {
            self.settings_popup.render(frame, ());
        }

        if self.invite_popup.props.invite_state.show_invite_popup {
            self.invite_popup.render(frame, ());
        }

        if self.chat_details_popup.props.chat_details_popup_state.show {
            self.chat_details_popup.render(frame, ());
        }
        if self.accept_invite_popup.props.show {
            self.accept_invite_popup.render(frame, ());
        }
        if self.manual_connect_popup.props.show {
            self.manual_connect_popup.render(frame, ());
        }
    }
}

impl HasUsageInfo for MainPage {
    fn usage_info(&self) -> UsageInfo {
        if let Some(section) = self.active_section.as_ref() {
            let handler: &dyn HasUsageInfo = match section {
                Section::ChatList => &self.chat_list,
                Section::ChatInput => &self.message_input_box,
            };

            handler.usage_info()
        } else {
            let mut usage = UsageInfo {
                description: Some("Select a widget".into()),
                lines: vec![
                    UsageInfoLine {
                        keys: vec!["↑".into(), "↓".into()],
                        description: "to select chat".into(),
                    },
                    UsageInfoLine {
                        keys: vec!["←".into(), "→".into()],
                        description: "to hover widgets".into(),
                    },
                ],
            };

            if self.last_hovered_section == Section::ChatList {
                usage.lines.push(UsageInfoLine {
                    keys: vec!["Enter/Return".into()],
                    description: "to show chat information".into(),
                });
                usage.lines.push(UsageInfoLine {
                    keys: vec!["Delete".into()],
                    description: "to delete Chat".into(),
                });
            } else {
                usage.lines.push(UsageInfoLine {
                    keys: vec!["Enter/Return".into()],
                    description: "to start typing a message".into(),
                });
            }
            usage
        }
    }
}

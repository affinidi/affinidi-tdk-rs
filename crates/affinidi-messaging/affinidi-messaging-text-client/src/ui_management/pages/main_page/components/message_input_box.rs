use super::super::section::usage::{HasUsageInfo, UsageInfo, UsageInfoLine};
use crate::ui_management::components::{
    Component, ComponentRender,
    input_box::{self, InputBox},
};
use crate::{
    state_store::{State, actions::Action},
    ui_management::pages::main_page::section::SectionActivation,
};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use ratatui::{Frame, prelude::Rect, style::Color};
use tokio::sync::mpsc::UnboundedSender;

struct Props {
    /// Active chat that the user is chatting in
    active_chat: Option<String>,
}

impl From<&State> for Props {
    fn from(state: &State) -> Self {
        Self {
            active_chat: state.chat_list.active_chat.clone(),
        }
    }
}

pub struct MessageInputBox {
    action_tx: UnboundedSender<Action>,
    /// State Mapped MessageInputBox Props
    props: Props,
    // Internal State for the Component
    pub input_box: InputBox,
}

impl MessageInputBox {
    fn submit_message(&mut self) {
        if self.input_box.is_empty() {
            return;
        }

        // TODO: handle the error scenario
        let _ = self.action_tx.send(Action::SendMessage {
            chat_msg: String::from(self.input_box.text()),
        });

        self.input_box.reset();
    }
}

impl Component for MessageInputBox {
    fn new(state: &State, action_tx: UnboundedSender<Action>) -> Self {
        Self {
            action_tx: action_tx.clone(),
            props: Props::from(state),
            //
            input_box: InputBox::new(state, action_tx),
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

    fn name(&self) -> &str {
        "Message Input"
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        if self.props.active_chat.is_some() {
            self.input_box.handle_key_event(key);

            if key.code == KeyCode::Enter {
                self.submit_message();
            }
        }
    }
}

impl SectionActivation for MessageInputBox {
    fn activate(&mut self) {}

    fn deactivate(&mut self) {
        self.input_box.reset();
    }
}

pub struct RenderProps {
    pub area: Rect,
    pub border_color: Color,
    pub show_cursor: bool,
}

impl ComponentRender<RenderProps> for MessageInputBox {
    fn render(&self, frame: &mut Frame, props: RenderProps) {
        self.input_box.render(
            frame,
            input_box::RenderProps {
                title: "Message Input".into(),
                area: props.area,
                border_color: props.border_color,
                show_cursor: props.show_cursor,
            },
        )
    }
}

impl HasUsageInfo for MessageInputBox {
    fn usage_info(&self) -> UsageInfo {
        if self.props.active_chat.is_none() {
            UsageInfo {
                description: Some("You can not send a message until you select a chat.".into()),
                lines: vec![UsageInfoLine {
                    keys: vec!["Esc".into()],
                    description: "to cancel".into(),
                }],
            }
        } else {
            UsageInfo {
                description: Some("Type your message to send a message to the active chat".into()),
                lines: vec![
                    UsageInfoLine {
                        keys: vec!["Esc".into()],
                        description: "to cancel".into(),
                    },
                    UsageInfoLine {
                        keys: vec!["Enter".into()],
                        description: "to send your message".into(),
                    },
                ],
            }
        }
    }
}

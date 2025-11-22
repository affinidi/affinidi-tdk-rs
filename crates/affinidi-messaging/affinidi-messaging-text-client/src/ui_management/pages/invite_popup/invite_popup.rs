use std::sync::Mutex;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use image::{DynamicImage, ImageBuffer, ImageReader, Luma};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Flex, Layout},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, StatefulWidget, Widget, Wrap},
};
use ratatui_image::{StatefulImage, picker::Picker, protocol::StatefulProtocol};
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    state_store::{
        State,
        actions::{Action, invitation::InvitePopupState},
    },
    ui_management::components::component::{Component, ComponentRender},
};

pub struct Props {
    pub invite_state: InvitePopupState,
    pub mediator_did: Option<String>,
    pub qr_code: Option<ImageBuffer<Luma<u8>, Vec<u8>>>,
}

impl From<&State> for Props {
    fn from(state: &State) -> Self {
        let qr_code = match &state.invite_popup.invite {
            Some(invite) => invite.qr_code.clone(),
            _ => None,
        };

        Props {
            invite_state: state.invite_popup.clone(),
            mediator_did: state.settings.mediator_did.clone(),
            qr_code,
        }
    }
}

pub struct InvitePopup {
    pub action_tx: UnboundedSender<Action>,
    // Mapped Props from State
    pub props: Props,
    // Child Components
    image: Mutex<StatefulProtocol>,
    picker: Mutex<Picker>,
}

impl Component for InvitePopup {
    fn new(state: &State, action_tx: UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        let picker = Picker::from_query_stdio().unwrap();
        let dyn_img = ImageReader::open("./affinidi_logo.jpg")
            .expect("Couldn't open image")
            .decode()
            .expect("Couldn't decode image");

        InvitePopup {
            action_tx: action_tx.clone(),
            props: Props::from(state),
            image: Mutex::new(picker.new_resize_protocol(dyn_img)),
            picker: Mutex::new(picker),
        }
        .move_with_state(state)
    }

    fn move_with_state(self, state: &State) -> Self
    where
        Self: Sized,
    {
        InvitePopup {
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
            KeyCode::F(2) => {
                // switch back to the previous focus
                let _ = self.action_tx.send(Action::InvitePopupStop);
            }
            KeyCode::Esc => {
                // switch back to the previous focus
                let _ = self.action_tx.send(Action::InvitePopupStop);
            }
            _ => {}
        }
    }
}

impl ComponentRender<()> for InvitePopup {
    fn render(&self, frame: &mut Frame, _props: ()) {
        let outer_block = Block::bordered()
            .title("OOB Invitation")
            .style(Style::default().bg(Color::White).fg(Color::Black).bold());
        let vertical = Layout::vertical([Constraint::Percentage(30)]).flex(Flex::Center);
        let horizontal = Layout::horizontal([Constraint::Percentage(70)]).flex(Flex::Center);
        let [outer_area] = vertical.areas(frame.area());
        let [outer_area] = horizontal.areas(outer_area);
        // Clear the popup area first
        frame.render_widget(Clear, outer_area);

        let inner_area = outer_block.inner(outer_area);
        let [invite_top, invite_url] =
            *Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).split(inner_area)
        else {
            panic!("Failed to split invite inner area");
        };
        let [qr_code_area, text_area] = *Layout::horizontal([
            Constraint::Max((inner_area.height * 2) + 2),
            Constraint::Fill(1),
        ])
        .split(invite_top) else {
            panic!("Failed to split inner area");
        };

        outer_block.render(outer_area, frame.buffer_mut());

        if let Some(invite) = &self.props.invite_state.invite {
            Line::from(vec![
                Span::styled("OOB Invite URL: ", Style::default().fg(Color::Black)),
                Span::styled(
                    invite.invite_url.clone(),
                    Style::default()
                        .add_modifier(Modifier::BOLD)
                        .fg(Color::LightMagenta),
                ),
            ])
            .render(invite_url, frame.buffer_mut());
        }

        match &self.props.mediator_did {
            Some(mediator_did) => {
                let mut lines = vec![
                    Line::default(),
                    Line::styled(
                        "Generating new OOB invitation from the mediator...",
                        Style::default().bold(),
                    ),
                    Line::styled(
                        format!("Using Mediator: {mediator_did}"),
                        Style::default().bold().fg(Color::LightBlue),
                    ),
                    Line::default(),
                ];
                for m in self.props.invite_state.messages.iter() {
                    lines.push(m.to_owned());
                }

                if let Some(err) = &self.props.invite_state.invite_error {
                    lines.push(Line::styled(err, Style::default().bold().fg(Color::Red)));
                }
                Paragraph::new(lines)
                    .alignment(Alignment::Left)
                    .wrap(Wrap { trim: true })
                    .render(text_area, frame.buffer_mut());
            }
            _ => {
                Paragraph::new(vec![
                    Line::default(),
                    Line::styled(
                        "You must specify a mediator DID to generate an invitation.",
                        Style::default().bold().fg(Color::LightRed),
                    ),
                    Line::styled(
                        "You can do this in Setup",
                        Style::default().bold().fg(Color::LightRed),
                    ),
                ])
                .alignment(Alignment::Left)
                .wrap(Wrap { trim: true })
                .render(text_area, frame.buffer_mut());
            }
        }

        match &self.props.qr_code {
            Some(qr_code) => {
                // Render QR Code
                //let image =
                //  StatefulImage::new(Some(image::Rgb([255, 255, 255]))).resize(Resize::Fit(None));
                let image = StatefulImage::default();
                //println!("Inner Block {}", inner_blocks[0]);
                let picker = self.picker.lock().unwrap();
                let mut a = picker.new_resize_protocol(DynamicImage::ImageLuma8(qr_code.clone()));
                StatefulWidget::render(image, qr_code_area, frame.buffer_mut(), &mut a);
            }
            _ => {
                // Render Affinidi Logo
                //let image =
                //  StatefulImage::new(Some(image::Rgb([255, 255, 255]))).resize(Resize::Fit(None));
                let image = StatefulImage::default();
                //println!("Inner Block {}", inner_blocks[0]);
                let mut image2 = self.image.lock().unwrap();
                StatefulWidget::render(image, qr_code_area, frame.buffer_mut(), &mut *image2);
            }
        }
    }
}

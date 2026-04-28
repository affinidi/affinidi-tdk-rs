use chrono::Local;
use ratatui::{
    style::{Color, Style},
    text::Line,
};
use serde::{Deserialize, Serialize};
use textwrap::Options;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum ChatEffect {
    Ballons,
    Confetti,
    #[default]
    System,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum ChatMessageType {
    Inbound,
    Outbound,
    #[default]
    Error,
    Effect {
        effect: ChatEffect,
    },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ChatMessage {
    pub _type: ChatMessageType,
    pub message: String,
    pub timestamp: chrono::DateTime<Local>,
}

impl ChatMessage {
    pub fn new(_type: ChatMessageType, message: String) -> Self {
        Self {
            _type,
            message,
            timestamp: Local::now(),
        }
    }
    // (2025-02-01 20:17:27: << )
    pub fn render(&'_ self, width: usize) -> Vec<Line<'_>> {
        let mut lines: Vec<Line> = Vec::new();
        match &self._type {
            ChatMessageType::Inbound => {
                let initial_indent = format!("{}: >> ", self.timestamp.format("%Y-%m-%d %H:%M:%S"));
                let options = Options::new(width - 24)
                    .initial_indent(&initial_indent)
                    .subsequent_indent("                        ");

                let l = textwrap::wrap(&self.message, options);
                for line in l {
                    if line.trim().is_empty() {
                        continue;
                    }

                    lines.push(Line::styled(
                        line.trim_end().to_string(),
                        Style::default().fg(Color::Blue).bold(),
                    ));
                }
            }
            ChatMessageType::Outbound => lines.push(Line::styled(
                format!(
                    "{}: << {}",
                    self.timestamp.format("%Y-%m-%d %H:%M:%S"),
                    self.message
                ),
                Style::default().italic().fg(Color::LightBlue),
            )),
            ChatMessageType::Error => lines.push(Line::styled(
                format!(
                    "{}: ERROR: {}",
                    self.timestamp.format("%Y-%m-%d %H:%M:%S"),
                    self.message
                ),
                Style::default().red(),
            )),
            ChatMessageType::Effect { effect } => match effect {
                ChatEffect::Ballons => lines.push(Line::styled(
                    format!(
                        "{}: << EFFECT:  You received some balloons!!! ",
                        self.timestamp.format("%Y-%m-%d %H:%M:%S")
                    ),
                    Style::default().fg(Color::LightGreen),
                )),
                ChatEffect::Confetti => lines.push(Line::styled(
                    format!(
                        "{}: << EFFECT:  You received some confetti!!! ",
                        self.timestamp.format("%Y-%m-%d %H:%M:%S")
                    ),
                    Style::default().fg(Color::LightGreen),
                )),
                ChatEffect::System => lines.push(Line::styled(
                    format!(
                        "{}: System Message: {}",
                        self.timestamp.format("%Y-%m-%d %H:%M:%S"),
                        self.message
                    ),
                    Style::default().fg(Color::Yellow),
                )),
            },
        }

        lines
    }
}

use crate::ui_management::components::component::ComponentRender;
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    widgets::Block,
};
use tui_logger::{TuiLoggerLevelOutput, TuiLoggerWidget};

pub struct ChatLogs;

pub struct RenderProps {
    pub area: Rect,
}

impl ComponentRender<RenderProps> for ChatLogs {
    fn render(&self, frame: &mut Frame, props: RenderProps) {
        let logs = TuiLoggerWidget::default()
            .block(Block::bordered().title("Log Window"))
            .style_error(Style::default().fg(Color::Red))
            .style_debug(Style::default().fg(Color::Green))
            .style_warn(Style::default().fg(Color::Yellow))
            .style_trace(Style::default().fg(Color::Magenta))
            .style_info(Style::default().fg(Color::Cyan))
            .output_level(Some(TuiLoggerLevelOutput::Abbreviated));

        frame.render_widget(logs, props.area);
    }
}

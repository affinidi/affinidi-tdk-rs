use chrono::Local;
use ratatui::{Frame, layout::Rect, style::Stylize, widgets::Paragraph};

use crate::ui_management::components::ComponentRender;

pub struct DateTime;

pub struct RenderProps {
    pub area: Rect,
}

impl ComponentRender<RenderProps> for DateTime {
    fn render(&self, frame: &mut Frame, props: RenderProps) {
        let datetime = Paragraph::new(Local::now().format("%H:%M:%S %Y-%m-%d").to_string())
            .light_blue()
            .bold()
            .right_aligned();

        frame.render_widget(datetime, props.area);
    }
}

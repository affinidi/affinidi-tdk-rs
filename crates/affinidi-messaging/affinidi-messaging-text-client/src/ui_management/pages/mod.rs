use crate::{
    state_store::{State, actions::Action},
    ui_management::components::component::{Component, ComponentRender},
};
use crossterm::event::KeyEvent;
use invite_popup::invite_popup::InvitePopup;
use main_page::MainPage;
use ratatui::Frame;
use settings_popup::settings_popup::SettingsPopup;
use tokio::sync::mpsc::UnboundedSender;

mod accept_invite_popup;
mod chat_details_popup;
mod invite_popup;
mod main_page;
mod manual_connect_popup;
mod settings_popup;

enum ActivePage {
    MainPage,
}

struct Props {
    active_page: ActivePage,
}

impl From<&State> for Props {
    fn from(_: &State) -> Self {
        Props {
            active_page: ActivePage::MainPage,
        }
    }
}

pub struct AppRouter {
    props: Props,
    //
    main_page: MainPage,
    settings_popup: SettingsPopup,
    invite_popup: InvitePopup,
}

impl AppRouter {
    fn get_active_page_component_mut(&mut self) -> &mut dyn Component {
        match self.props.active_page {
            ActivePage::MainPage => &mut self.main_page,
        }
    }

    //TIMTAM
    /*
    pub fn get_active_page_component(&self) -> &dyn Component {
        match self.props.active_page {
            ActivePage::MainPage => &self.main_page,
        }
    }
    */
}

impl Component for AppRouter {
    fn new(state: &State, action_tx: UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        AppRouter {
            props: Props::from(state),
            //
            main_page: MainPage::new(state, action_tx.clone()),
            settings_popup: SettingsPopup::new(state, action_tx.clone()),
            invite_popup: InvitePopup::new(state, action_tx.clone()),
        }
        .move_with_state(state)
    }

    fn move_with_state(self, state: &State) -> Self
    where
        Self: Sized,
    {
        AppRouter {
            props: Props::from(state),
            //
            main_page: self.main_page.move_with_state(state),
            settings_popup: self.settings_popup.move_with_state(state),
            invite_popup: self.invite_popup.move_with_state(state),
        }
    }

    // route all functions to the active page
    fn name(&self) -> &str {
        todo!()
        //self.get_active_page_component().name()
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        self.get_active_page_component_mut().handle_key_event(key)
    }
}

impl ComponentRender<()> for AppRouter {
    fn render(&self, frame: &mut Frame, props: ()) {
        match self.props.active_page {
            ActivePage::MainPage => self.main_page.render(frame, props),
        }
    }
}

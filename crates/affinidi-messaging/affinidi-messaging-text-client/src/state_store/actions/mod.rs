use super::CommonSettings;

pub mod chat_list;
pub mod invitation;
pub mod manual_connect;

#[derive(Debug, Clone)]
pub enum Action {
    // Settings Related
    SettingsPopupToggle,
    SettingsCheck { settings: CommonSettings },
    SettingsUpdate { settings: CommonSettings },
    // OOB Invitation Create
    InvitePopupStart,
    InvitePopupStop,
    // OOB Accept
    AcceptInvitePopupStart,
    AcceptInvitePopupStop,
    AcceptInvite { invite_link: String },
    // Manual Connect
    ManualConnectPopupStart,
    ManualConnectPopupStop,
    ManualConnect { alias: String, remote_did: String },
    // Chat information
    ShowChatDetails { chat: String },
    CloseChatDetails,
    DeleteChat { chat: String },
    SetCurrentChat { chat: String },
    // other
    SendMessage { chat_msg: String },
    Exit,
}

use super::actions::{
    chat_list::{Chat, ChatList},
    invitation::InvitePopupState,
};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_sdk::{ATM, protocols::oob_discovery::OOBDiscovery};
use affinidi_tdk::secrets_resolver::secrets::Secret;
use ratatui::text::Line;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

/*
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageBoxItem {
    Message { user_id: String, content: String },
    Notification(String),
}
*/

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ChatDetailsPopupState {
    pub chat_name: Option<String>,
    pub show: bool,
}

/// Common configuration across all chats
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct CommonSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mediator_did: Option<String>,
    #[serde(skip)]
    pub mediator_did_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_path: Option<String>,
    #[serde(skip)]
    pub avatar_path_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub our_name: Option<String>,
    #[serde(skip)]
    pub show_settings_popup: bool,
}

impl CommonSettings {
    async fn _check_mediator_did(
        &self,
        did_resolver: &DIDCacheClient,
    ) -> Result<(), std::io::Error> {
        if let Some(mediator_did) = self.mediator_did.as_ref() {
            match did_resolver.resolve(mediator_did).await {
                Err(e) => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Mediator DID is invalid: {e}"),
                )),
                _ => Ok(()),
            }
        } else {
            Ok(()) // Empty is fine
        }
    }

    /// Checks if the avatar path is correct
    fn _check_avatar_path(&self) -> Result<(), std::io::Error> {
        if let Some(avatar_path) = self.avatar_path.as_ref() {
            let metadata = std::fs::metadata(avatar_path)?;
            if metadata.is_file() {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Avatar path is not a file",
                ))
            }
        } else {
            Ok(())
        }
    }

    /// Checks if the settings are valid
    pub(crate) async fn check(&self, state: &mut State, did_resolver: &DIDCacheClient) -> bool {
        let mut ok_flag = true;
        if let Err(e) = self._check_avatar_path() {
            state.settings.avatar_path_error = Some(e.to_string());
            ok_flag = false;
        } else {
            state.settings.avatar_path_error = None;
        }
        match self._check_mediator_did(did_resolver).await {
            Err(e) => {
                state.settings.mediator_did_error = Some(e.to_string());
                ok_flag = false;
            }
            _ => {
                state.settings.mediator_did_error = None;
            }
        }

        ok_flag
    }

    /// Updates state with the new settings
    pub(crate) async fn update(&self, state: &mut State, did_resolver: &DIDCacheClient) -> bool {
        if self.check(state, did_resolver).await {
            state.settings.mediator_did = self.mediator_did.clone();
            state.settings.avatar_path = self.avatar_path.clone();
            state.settings.our_name = self.our_name.clone();
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct AcceptInvitePopupState {
    pub show: bool,
    pub invite_link: String,
    pub invite_error: Option<String>,
    pub messages: Vec<Line<'static>>,
}

#[derive(Debug, Default, Clone)]
pub struct ManualConnectPopupState {
    pub show: bool,
    pub remote_did: String,
    pub alias: String,
    pub error_msg: Option<String>,
}

/// State holds the state of the application
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub settings: CommonSettings,
    /// Storage of chat data
    pub chat_list: ChatList,
    #[serde(skip)]
    pub invite_popup: InvitePopupState,
    #[serde(skip)]
    pub chat_details_popup: ChatDetailsPopupState,
    #[serde(skip)]
    pub accept_invite_popup: AcceptInvitePopupState,
    #[serde(skip)]
    pub manual_connect_popup: ManualConnectPopupState,
    #[serde(skip)]
    pub initialization: bool,
    pub(crate) secrets: Vec<Secret>,
}

impl State {
    pub fn add_secret(&mut self, secret: Secret) {
        self.secrets.push(secret);
    }

    pub fn add_secrets(&mut self, secrets: &mut Vec<Secret>) {
        self.secrets.append(secrets);
    }

    /// Writes the state to `file_path` if what would be written differs from
    /// `last_saved`, and records what was written. Keys and chats created
    /// since the last write are then on disk without waiting for exit.
    pub fn save_if_changed(
        &self,
        file_path: &str,
        last_saved: &mut Option<Vec<u8>>,
    ) -> Result<(), std::io::Error> {
        let contents = serde_json::to_vec_pretty(self)?;
        if last_saved.as_deref() == Some(contents.as_slice()) {
            return Ok(());
        }
        write_private(file_path, &contents)?;
        *last_saved = Some(contents);
        Ok(())
    }

    pub fn save_to_file(&self, file_path: &str) -> Result<(), std::io::Error> {
        write_private(file_path, &serde_json::to_vec_pretty(self)?)
    }

    pub fn read_from_file(file_path: &str) -> Result<Self, std::io::Error> {
        let file = std::fs::File::open(file_path)?;
        let state: Self = serde_json::from_reader(file)?;

        Ok(state)
    }

    /// Shutdowns and removes a chat.
    pub async fn remove_chat(&mut self, chat: &Chat, atm: &ATM) {
        // Find our current ATM Profile
        let current_profile = {
            let Some(current_profile) = atm
                .get_profiles()
                .read()
                .await
                .find_by_did(&chat.our_profile.did)
            else {
                error!("Profile not found for DID({})", chat.our_profile.did);
                return;
            };
            current_profile
        };

        // Delete the invitation link from the mediator if it exists
        if let Some(invite_link) = &chat.invitation_link {
            if let Some((_, oobid)) = invite_link.split_once("=") {
                // Delete the invite link
                let _ = OOBDiscovery::default()
                    .delete_invite(atm, &current_profile, oobid)
                    .await;
            } else {
                error!("Invalid invite link: {}", invite_link);
            }
        }

        // Shutdown the profile on ATM
        let _ = atm.profile_remove(&current_profile.inner.alias).await;

        // Remove the chat from the list
        self.chat_list.chats.remove(&chat.name);

        // Is the active chat the one we are removing?
        if self
            .chat_list
            .active_chat
            .as_ref()
            .map(|c| c == &chat.name)
            .unwrap_or(false)
        {
            self.chat_list.active_chat = None;
        }
        info!("Chat removed: {}", chat.name);
    }
}

/// Writes `contents` to `file_path`, owner-only on Unix: the state holds
/// private keys, and `File::create` would use the process umask (typically
/// 0644).
fn write_private(file_path: &str, contents: &[u8]) -> Result<(), std::io::Error> {
    use std::io::Write;

    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(file_path)?
    };
    #[cfg(not(unix))]
    let mut file = std::fs::File::create(file_path)?;

    file.write_all(contents)?;
    file.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_if_changed_writes_new_state_and_skips_unchanged_state() {
        let path =
            std::env::temp_dir().join(format!("text-client-state-{}.json", uuid::Uuid::new_v4()));
        let path = path.to_str().unwrap();
        let mut last_saved = None;
        let mut state = State::default();

        state.save_if_changed(path, &mut last_saved).unwrap();
        assert!(last_saved.is_some());

        std::fs::remove_file(path).unwrap();
        state.save_if_changed(path, &mut last_saved).unwrap();
        assert!(
            std::fs::metadata(path).is_err(),
            "unchanged state is not written again"
        );

        state.settings.our_name = Some("Alice".into());
        state.save_if_changed(path, &mut last_saved).unwrap();
        let saved = State::read_from_file(path).unwrap();
        assert_eq!(saved.settings.our_name.as_deref(), Some("Alice"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_file(path).unwrap();
    }
}

use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::protocols::mediator::{accounts::AccountType, acls::MediatorACLSet};
use ahash::AHashMap as HashMap;
use serde::{Deserialize, Serialize};
use sha256::digest;
use std::fmt::{self, Display, Formatter};
use tracing::{debug, warn};

use super::Database;

/// JWT claims embedded in session tokens issued after authentication.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    /// Audience (the mediator identifier).
    pub aud: String,
    /// Subject (the authenticated DID).
    pub sub: String,
    /// Unique session identifier.
    pub session_id: String,
    /// Expiration time as a Unix timestamp.
    pub exp: u64,
}

/// Lifecycle state of an authentication session.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub enum SessionState {
    /// Initial state before any interaction.
    #[default]
    Unknown,
    /// A challenge has been sent to the client, awaiting response.
    ChallengeSent,
    /// The client has successfully authenticated.
    Authenticated,
    /// The session has been blocked (e.g., due to policy violation).
    Blocked,
}

impl TryFrom<&String> for SessionState {
    type Error = MediatorError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "ChallengeSent" => Ok(Self::ChallengeSent),
            "Authenticated" => Ok(Self::Authenticated),
            _ => {
                warn!("Unknown SessionState: ({})", value);
                Err(MediatorError::SessionError(
                    20,
                    "NA".into(),
                    format!("Unknown session state: ({value})"),
                ))
            }
        }
    }
}

impl Display for SessionState {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// An authentication session tracked in Redis, linking a DID to its auth state and permissions.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Session {
    /// Unique session identifier (not serialized; set from the Redis key).
    #[serde(skip)]
    pub session_id: String,
    /// Random challenge string sent to the client for DID-based authentication.
    pub challenge: String,
    /// Current lifecycle state of this session.
    pub state: SessionState,
    /// The DID associated with this session.
    pub did: String,
    /// SHA-256 hash of the DID, used as a Redis key component.
    pub did_hash: String,
    /// Whether the session has been fully authenticated.
    pub authenticated: bool,
    /// Access control permissions granted to this session.
    pub acls: MediatorACLSet,
    /// Account role type (e.g., standard user, admin).
    pub account_type: AccountType,
    /// Unix timestamp when this session expires.
    pub expires_at: u64,
}

impl TryFrom<(&str, HashMap<String, String>)> for Session {
    type Error = MediatorError;

    fn try_from(value: (&str, HashMap<String, String>)) -> Result<Self, Self::Error> {
        let mut session: Session = Session::default();
        let (sid, hash) = value;
        session.session_id = sid.into();

        if let Some(challenge) = hash.get("challenge") {
            session.challenge.clone_from(challenge);
        } else {
            warn!("Session ({}): No challenge found", sid);
            return Err(MediatorError::SessionError(
                20,
                sid.into(),
                "No challenge found when retrieving session".into(),
            ));
        }

        if let Some(state) = hash.get("state") {
            session.state = state.try_into()?;
        } else {
            warn!("Session ({}): No state found", sid);
            return Err(MediatorError::SessionError(
                20,
                sid.into(),
                "No state found when retrieving session".into(),
            ));
        }

        if let Some(did) = hash.get("did") {
            session.did = did.into();
            session.did_hash = digest(did);
        } else {
            warn!("Session ({}): No DID found", sid);
            return Err(MediatorError::SessionError(
                20,
                sid.into(),
                "No DID found when retrieving session".into(),
            ));
        }

        if let Some(acls) = hash.get("acls") {
            session.acls = match u64::from_str_radix(acls, 16) {
                Ok(acl) => MediatorACLSet::from_u64(acl),
                Err(err) => {
                    warn!("{}: Error parsing acls({})! Error: {}", sid, acls, err);
                    return Err(MediatorError::SessionError(
                        26,
                        sid.into(),
                        "No ACL found when retrieving session".into(),
                    ));
                }
            }
        } else {
            warn!("{}: Error parsing acls!", sid);
            return Err(MediatorError::SessionError(
                20,
                sid.into(),
                "No ACL found when retrieving session".into(),
            ));
        }

        Ok(session)
    }
}

impl Database {
    /// Creates a new session in the database
    /// Typically called when sending the initial challenge to the client
    pub async fn create_session(&self, session: &Session) -> Result<(), MediatorError> {
        let mut con = self.get_connection().await?;

        let sid = format!("SESSION:{}", session.session_id);

        redis::pipe()
            .atomic()
            .cmd("HSET")
            .arg(&sid)
            .arg("challenge")
            .arg(&session.challenge)
            .arg("state")
            .arg(session.state.to_string())
            .arg("did")
            .arg(&session.did)
            // .arg("acls")
            // .arg(session.acls.to_hex_string())
            .cmd("HINCRBY")
            .arg("GLOBAL")
            .arg("SESSIONS_CREATED")
            .arg(1)
            .expire(&sid, 900)
            .exec_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::SessionError(
                    14,
                    sid.clone(),
                    format!("Failed to create session ({sid}). Reason: {err}"),
                )
            })?;

        debug!("Session created: session_id={}", session.session_id);

        Ok(())
    }

    /// Retrieves a session and associated other info from the database
    ///
    pub async fn get_session(&self, session_id: &str, did: &str) -> Result<Session, MediatorError> {
        let mut con = self.get_connection().await?;

        let (session_db, did_db): (HashMap<String, String>, Vec<Option<String>>) =
            redis::pipe()
                .atomic()
                .cmd("HGETALL")
                .arg(format!("SESSION:{session_id}"))
                .cmd("HMGET")
                .arg(["DID:", &digest(did)].concat())
                .arg("ROLE_TYPE")
                .arg("ACLS")
                .query_async(&mut con)
                .await
                .map_err(|err| {
                    MediatorError::SessionError(
                        14,
                        session_id.into(),
                        format!("Failed to retrieve session ({session_id}). Reason: {err}"),
                    )
                })?;

        let mut session: Session = Session {
            session_id: session_id.into(),
            ..Default::default()
        };

        // Process Session info from database
        if let Some(challenge) = session_db.get("challenge") {
            session.challenge.clone_from(challenge);
        } else {
            warn!(
                "Session ({}): No challenge found, did_hash={}",
                session_id,
                digest(did)
            );
            return Err(MediatorError::SessionError(
                20,
                session_id.into(),
                "No challenge found when retrieving session".into(),
            ));
        }

        if let Some(state) = session_db.get("state") {
            session.state = state.try_into()?;
        } else {
            warn!("Session ({}): No state found", session_id);
            return Err(MediatorError::SessionError(
                20,
                session_id.into(),
                "No state found when retrieving session".into(),
            ));
        }

        if let Some(did) = session_db.get("did") {
            session.did = did.into();
            session.did_hash = digest(did);
        } else {
            warn!("Session ({}): No DID found", session_id);
            return Err(MediatorError::SessionError(
                20,
                session_id.into(),
                "No DID found when retrieving session".into(),
            ));
        }

        // Process DID info from database
        if let Some(Some(role_type)) = did_db.first() {
            session.account_type = AccountType::from(role_type.as_str());
        } else {
            warn!("{}: Error parsing role_type!", session_id);
            return Err(MediatorError::SessionError(
                20,
                session_id.into(),
                "No role_type found when retrieving session!".into(),
            ));
        }
        if let Some(acls) = did_db.get(1) {
            if let Some(acls) = acls {
                session.acls = match u64::from_str_radix(acls, 16) {
                    Ok(acl) => MediatorACLSet::from_u64(acl),
                    Err(err) => {
                        warn!(
                            "{}: Error parsing acls({})! Error: {}",
                            session_id, acls, err
                        );
                        return Err(MediatorError::SessionError(
                            14,
                            session_id.into(),
                            "Failed to parse ACLs for session".into(),
                        ));
                    }
                }
            } else {
                warn!("{}: Error parsing acls!", session_id);
                return Err(MediatorError::SessionError(
                    20,
                    session_id.into(),
                    "No ACL found when retrieving session".into(),
                ));
            }
        } else {
            warn!("{}: Error parsing acls!", session_id);
            return Err(MediatorError::SessionError(
                20,
                session_id.into(),
                "No ACL found when retrieving session".into(),
            ));
        }

        Ok(session)
    }

    /// Updates a session in the database to become authenticated
    /// Updates the state, and the expiry time
    /// Also ensures that the DID is recorded in the KNOWN_DIDS Set
    /// Stores the refresh token hash for one-time-use validation
    pub async fn update_session_authenticated(
        &self,
        old_session_id: &str,
        new_session_id: &str,
        did_hash: &str,
        refresh_token_hash: &str,
    ) -> Result<(), MediatorError> {
        let mut con = self.get_connection().await?;

        let old_sid = format!("SESSION:{old_session_id}");
        let new_sid = format!("SESSION:{new_session_id}");

        redis::pipe()
            .atomic()
            .cmd("RENAME")
            .arg(&old_sid)
            .arg(&new_sid)
            .cmd("HSET")
            .arg(&new_sid)
            .arg("state")
            .arg(SessionState::Authenticated.to_string())
            .arg("refresh_token_hash")
            .arg(refresh_token_hash)
            .cmd("HINCRBY")
            .arg("GLOBAL")
            .arg("SESSIONS_SUCCESS")
            .arg(1)
            .cmd("SADD")
            .arg("KNOWN_DIDS")
            .arg(did_hash)
            .expire(&new_sid, 86400)
            .exec_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::SessionError(
                    14,
                    old_session_id.into(),
                    format!("Failed to retrieve session ({old_session_id}). Reason: {err}"),
                )
            })?;

        Ok(())
    }

    /// Updates the stored refresh token hash for an existing authenticated session.
    /// Called during token refresh to rotate the one-time-use refresh token.
    pub async fn update_refresh_token_hash(
        &self,
        session_id: &str,
        refresh_token_hash: &str,
    ) -> Result<(), MediatorError> {
        let mut con = self.get_connection().await?;

        let sid = format!("SESSION:{session_id}");

        redis::Cmd::hset(&sid, "refresh_token_hash", refresh_token_hash)
            .exec_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::SessionError(
                    14,
                    session_id.into(),
                    format!("Failed to update refresh token hash for session ({session_id}). Reason: {err}"),
                )
            })?;

        Ok(())
    }

    /// Retrieves the stored refresh token hash for a session.
    pub async fn get_refresh_token_hash(
        &self,
        session_id: &str,
    ) -> Result<Option<String>, MediatorError> {
        let mut con = self.get_connection().await?;

        let sid = format!("SESSION:{session_id}");

        let hash: Option<String> = redis::Cmd::hget(&sid, "refresh_token_hash")
            .query_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::SessionError(
                    14,
                    session_id.into(),
                    format!(
                        "Failed to get refresh token hash for session ({session_id}). Reason: {err}"
                    ),
                )
            })?;

        Ok(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ahash::AHashMap as HashMap;

    // ── SessionState Display ──────────────────────────────────────────

    #[test]
    fn session_state_display_formatting() {
        assert_eq!(SessionState::Unknown.to_string(), "Unknown");
        assert_eq!(SessionState::ChallengeSent.to_string(), "ChallengeSent");
        assert_eq!(SessionState::Authenticated.to_string(), "Authenticated");
        assert_eq!(SessionState::Blocked.to_string(), "Blocked");
    }

    // ── SessionState TryFrom ──────────────────────────────────────────

    #[test]
    fn session_state_try_from_challenge_sent() {
        let val = "ChallengeSent".to_string();
        let state = SessionState::try_from(&val).expect("should parse ChallengeSent");
        assert_eq!(state, SessionState::ChallengeSent);
    }

    #[test]
    fn session_state_try_from_authenticated() {
        let val = "Authenticated".to_string();
        let state = SessionState::try_from(&val).expect("should parse Authenticated");
        assert_eq!(state, SessionState::Authenticated);
    }

    #[test]
    fn session_state_try_from_invalid_returns_error() {
        let val = "InvalidState".to_string();
        let result = SessionState::try_from(&val);
        assert!(result.is_err(), "invalid state string should return Err");
    }

    // ── Session TryFrom ───────────────────────────────────────────────

    fn valid_session_map() -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("challenge".to_string(), "test-challenge".to_string());
        map.insert("state".to_string(), "ChallengeSent".to_string());
        map.insert("did".to_string(), "did:example:123".to_string());
        map.insert("acls".to_string(), "ff".to_string());
        map
    }

    #[test]
    fn session_try_from_valid_hashmap() {
        let map = valid_session_map();
        let session =
            Session::try_from(("test-session-id", map)).expect("should create Session from map");

        assert_eq!(session.session_id, "test-session-id");
        assert_eq!(session.challenge, "test-challenge");
        assert_eq!(session.state, SessionState::ChallengeSent);
        assert_eq!(session.did, "did:example:123");
        assert_eq!(session.did_hash, digest("did:example:123"));
    }

    #[test]
    fn session_try_from_missing_challenge_returns_error() {
        let mut map = valid_session_map();
        map.remove("challenge");

        let result = Session::try_from(("sid", map));
        assert!(result.is_err(), "missing challenge should return Err");
    }

    #[test]
    fn session_try_from_missing_state_returns_error() {
        let mut map = valid_session_map();
        map.remove("state");

        let result = Session::try_from(("sid", map));
        assert!(result.is_err(), "missing state should return Err");
    }

    #[test]
    fn session_try_from_missing_did_returns_error() {
        let mut map = valid_session_map();
        map.remove("did");

        let result = Session::try_from(("sid", map));
        assert!(result.is_err(), "missing DID should return Err");
    }

    #[test]
    fn session_try_from_invalid_acl_returns_error() {
        let mut map = valid_session_map();
        map.insert("acls".to_string(), "not-hex".to_string());

        let result = Session::try_from(("sid", map));
        assert!(result.is_err(), "invalid ACL hex should return Err");
    }

    #[test]
    fn session_try_from_missing_acl_returns_error() {
        let mut map = valid_session_map();
        map.remove("acls");

        let result = Session::try_from(("sid", map));
        assert!(result.is_err(), "missing ACL should return Err");
    }
}

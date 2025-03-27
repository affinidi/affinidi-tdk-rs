use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::protocols::mediator::{accounts::AccountType, acls::MediatorACLSet};
use ahash::AHashMap as HashMap;
use serde::{Deserialize, Serialize};
use sha256::digest;
use std::fmt::{self, Display, Formatter};
use tracing::{debug, warn};

use super::Database;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    pub aud: String, //audience (atm)
    pub sub: String, // subject (DID)
    pub session_id: String,
    pub exp: u64,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub enum SessionState {
    #[default]
    Unknown,
    ChallengeSent,
    Authenticated,
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
                    "NA".into(),
                    format!("Unknown SessionState: ({})", value),
                ))
            }
        }
    }
}

impl Display for SessionState {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Session {
    #[serde(skip)]
    pub session_id: String,
    pub challenge: String,
    pub state: SessionState,
    pub did: String,
    pub did_hash: String,
    pub authenticated: bool,
    pub acls: MediatorACLSet,
    pub account_type: AccountType,
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
            warn!(
                "{}: No challenge found when retrieving session({})!",
                sid, sid
            );
            return Err(MediatorError::SessionError(
                sid.into(),
                "No challenge found when retrieving session!".into(),
            ));
        }

        if let Some(state) = hash.get("state") {
            session.state = state.try_into()?;
        } else {
            warn!("{}: No state found when retrieving session({})!", sid, sid);
            return Err(MediatorError::SessionError(
                sid.into(),
                "No state found when retrieving session!".into(),
            ));
        }

        if let Some(did) = hash.get("did") {
            session.did = did.into();
            session.did_hash = digest(did);
        } else {
            warn!("{}: No DID found when retrieving session({})!", sid, sid);
            return Err(MediatorError::SessionError(
                sid.into(),
                "No DID found when retrieving session!".into(),
            ));
        }

        if let Some(acls) = hash.get("acls") {
            session.acls = match u64::from_str_radix(acls, 16) {
                Ok(acl) => MediatorACLSet::from_u64(acl),
                Err(err) => {
                    warn!("{}: Error parsing acls({})! Error: {}", sid, acls, err);
                    return Err(MediatorError::SessionError(
                        sid.into(),
                        "No ACL found when retrieving session!".into(),
                    ));
                }
            }
        } else {
            warn!("{}: Error parsing acls!", sid);
            return Err(MediatorError::SessionError(
                sid.into(),
                "No ACL found when retrieving session!".into(),
            ));
        }

        Ok(session)
    }
}

impl Database {
    /// Creates a new session in the database
    /// Typically called when sending the initial challenge to the client
    pub async fn create_session(&self, session: &Session) -> Result<(), MediatorError> {
        let mut con = self.0.get_async_connection().await?;

        let sid = format!("SESSION:{}", session.session_id);

        deadpool_redis::redis::pipe()
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
                    sid.clone(),
                    format!("tried to create new session ({})! Error: {}", sid, err),
                )
            })?;

        debug!("Session created: {:?}", session);

        Ok(())
    }

    /// Retrieves a session and associated other info from the database
    ///
    pub async fn get_session(&self, session_id: &str, did: &str) -> Result<Session, MediatorError> {
        let mut con = self.0.get_async_connection().await?;

        let (session_db, did_db): (HashMap<String, String>, Vec<Option<String>>) =
            deadpool_redis::redis::pipe()
                .atomic()
                .cmd("HGETALL")
                .arg(format!("SESSION:{}", session_id))
                .cmd("HMGET")
                .arg(["DID:", &digest(did)].concat())
                .arg("ROLE_TYPE")
                .arg("ACLS")
                .query_async(&mut con)
                .await
                .map_err(|err| {
                    MediatorError::SessionError(
                        session_id.into(),
                        format!("tried to retrieve session({}). Error: {}", session_id, err),
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
                "{}: No challenge found when retrieving session({}) did_hash({})!",
                session_id,
                session_id,
                digest(did)
            );
            return Err(MediatorError::SessionError(
                session_id.into(),
                "No challenge found when retrieving session!".into(),
            ));
        }

        if let Some(state) = session_db.get("state") {
            session.state = state.try_into()?;
        } else {
            warn!(
                "{}: No state found when retrieving session({})!",
                session_id, session_id
            );
            return Err(MediatorError::SessionError(
                session_id.into(),
                "No state found when retrieving session!".into(),
            ));
        }

        if let Some(did) = session_db.get("did") {
            session.did = did.into();
            session.did_hash = digest(did);
        } else {
            warn!(
                "{}: No DID found when retrieving session({})!",
                session_id, session_id
            );
            return Err(MediatorError::SessionError(
                session_id.into(),
                "No DID found when retrieving session!".into(),
            ));
        }

        // Process DID info from database
        if let Some(Some(role_type)) = did_db.first() {
            session.account_type = AccountType::from(role_type.as_str());
        } else {
            warn!("{}: Error parsing role_type!", session_id);
            return Err(MediatorError::SessionError(
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
                            session_id.into(),
                            "No ACL found when retrieving session!".into(),
                        ));
                    }
                }
            } else {
                warn!("{}: Error parsing acls!", session_id);
                return Err(MediatorError::SessionError(
                    session_id.into(),
                    "No ACL found when retrieving session!".into(),
                ));
            }
        } else {
            warn!("{}: Error parsing acls!", session_id);
            return Err(MediatorError::SessionError(
                session_id.into(),
                "No ACL found when retrieving session!".into(),
            ));
        }

        Ok(session)
    }

    /// Updates a session in the database to become authenticated
    /// Updates the state, and the expiry time
    /// Also ensures that the DID is recorded in the KNOWN_DIDS Set
    pub async fn update_session_authenticated(
        &self,
        old_session_id: &str,
        new_session_id: &str,
        did_hash: &str,
    ) -> Result<(), MediatorError> {
        let mut con = self.0.get_async_connection().await?;

        let old_sid = format!("SESSION:{}", old_session_id);
        let new_sid = format!("SESSION:{}", new_session_id);

        deadpool_redis::redis::pipe()
            .atomic()
            .cmd("RENAME")
            .arg(&old_sid)
            .arg(&new_sid)
            .cmd("HSET")
            .arg(&new_sid)
            .arg("state")
            .arg(SessionState::Authenticated.to_string())
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
                    old_session_id.into(),
                    format!(
                        "tried to retrieve session({}). Error: {}",
                        old_session_id, err
                    ),
                )
            })?;

        Ok(())
    }
}

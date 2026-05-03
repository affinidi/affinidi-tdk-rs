//! Session storage on the Redis backend.
//!
//! Session type definitions live in [`crate::common::session`] —
//! they're backend-agnostic (used by the JWT middleware regardless of
//! storage). This file only carries the Redis-specific persistence
//! methods on `Database`.

use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_mediator_common::store::types::{Session, SessionState};
use affinidi_messaging_sdk::protocols::mediator::{accounts::AccountType, acls::MediatorACLSet};
use ahash::AHashMap as HashMap;
use sha256::digest;
use tracing::{debug, warn};

use super::Database;

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
    pub async fn get_session(&self, session_id: &str, did: &str) -> Result<Session, MediatorError> {
        let mut con = self.get_connection().await?;

        let (session_db, did_db): (HashMap<String, String>, Vec<Option<String>>) = redis::pipe()
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

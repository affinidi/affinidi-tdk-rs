/*!
 * This module contains functions to check various ACLs for a given DID.
 * At all times it works on a SHA256 hash of the DID.
 *
 */

use crate::{SharedData, database::session::Session};
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::protocols::mediator::acls::MediatorACLSet;
use tracing::debug;

pub(crate) trait ACLCheck {
    async fn authentication_check(
        shared: &SharedData,
        did_hash: &str,
        session: Option<&Session>,
    ) -> Result<bool, MediatorError>;
}

impl ACLCheck for MediatorACLSet {
    /// Pre-authenticated ACL check to see if DID is blocked from connecting to the mediator
    /// - `shared`: Mediator Shared State
    /// - `did_hash`: SHA256 hash of the DID we are looking up
    /// - `session`: Optional: If provided uses ACL's in Session, otherwise looks up from database
    ///
    /// Returns true if the DID is allowed to connect, false otherwise
    async fn authentication_check(
        shared: &SharedData,
        did_hash: &str,
        session: Option<&Session>,
    ) -> Result<bool, MediatorError> {
        // Do we know about this DID?
        let acls = if let Some(session) = session {
            session.acls.clone()
        } else {
            debug!("Fetching acls from database did_hash({})", did_hash);
            let acls = shared
                .database
                .get_did_acls(
                    &[did_hash.to_string()],
                    shared.config.security.mediator_acl_mode.clone(),
                )
                .await?;
            if let Some(acl) = acls.acl_response.first() {
                debug!(
                    "Fetched acl({}) from database for did_hash({})",
                    acl.acls.to_hex_string(),
                    did_hash
                );
                acl.acls.clone()
            } else {
                debug!(
                    "No acl set for did_hash({})! Using default_acl...",
                    did_hash
                );
                shared.config.security.global_acl_default.clone()
            }
        };

        Ok(!acls.get_blocked())
    }
}

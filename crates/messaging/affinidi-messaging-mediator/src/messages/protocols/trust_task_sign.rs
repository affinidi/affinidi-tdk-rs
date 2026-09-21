//! Signing the mediator's Trust Task responses.
//!
//! Every success response leaves with a Data Integrity proof (`eddsa-jcs-2022`)
//! made with the mediator DID's Ed25519 key, so a client can hold the answer as
//! evidence independent of the transport it came over. `messaging/message/get`
//! requires it outright — that response can carry another account's stored
//! envelope — and the `messaging/*` specs recommend it for the rest.
//!
//! A mediator whose DID has no Ed25519 signing key answers unsigned and says so
//! once in the log; a signing failure with a key in hand is an error, never a
//! silent downgrade to unsigned.

use std::sync::Once;

use affinidi_did_common::DocumentExt;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_secrets_resolver::SecretsResolver;
use affinidi_secrets_resolver::secrets::{KeyType, Secret};
use chrono::{SecondsFormat, Utc};
use serde_json::Value;
use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};

use crate::SharedData;

/// Sign a response document (a serialised `TrustTask<R>`) as the mediator.
///
/// `issuer` is set to the mediator DID when the request named no recipient
/// (so `respond_with` left it empty) — the proof binds to the issuer, and the
/// mediator is the one answering. `issuedAt` is stamped if absent.
pub(crate) async fn sign_response(
    mut response: Value,
    state: &SharedData,
) -> Result<Value, MediatorError> {
    let mediator_did = &state.config.mediator_did;
    if let Some(obj) = response.as_object_mut() {
        obj.entry("issuer")
            .or_insert_with(|| Value::String(mediator_did.clone()));
        obj.entry("issuedAt").or_insert_with(|| {
            Value::String(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true))
        });
    }

    let Some(secret) = signing_secret(state).await else {
        static WARNED: Once = Once::new();
        WARNED.call_once(|| {
            tracing::warn!(
                mediator_did = %mediator_did,
                "the mediator DID has no Ed25519 authentication/assertionMethod key \
                 among its secrets; Trust Task responses are sent unsigned, and \
                 messaging/message/get (which requires a signed response) cannot be \
                 answered conformantly"
            );
        });
        return Ok(response);
    };

    sign_trust_task(&response, &secret, SignOptions::new())
        .await
        .map_err(|e| {
            MediatorError::InternalError(
                14,
                "NA".into(),
                format!("couldn't sign the Trust Task response: {e}"),
            )
        })
}

/// The mediator's Ed25519 secret to sign with: an `assertionMethod` key if its
/// DID declares one, else an `authentication` key.
async fn signing_secret(state: &SharedData) -> Option<Secret> {
    let did = &state.config.mediator_did;
    let doc = match state.did_resolver.resolve(did).await {
        Ok(resolved) => resolved.doc,
        Err(e) => {
            tracing::warn!(did = %did, error = %e, "couldn't resolve the mediator DID to pick a response-signing key");
            return None;
        }
    };
    let secrets = &state.config.security.mediator_secrets;
    let assertion = doc.find_assertion_method(None);
    let authentication = doc.find_authentication(None);
    for kid in assertion.into_iter().chain(authentication) {
        if let Some(secret) = secrets.get_secret(kid).await
            && secret.get_key_type() == KeyType::Ed25519
        {
            return Some(secret);
        }
    }
    None
}

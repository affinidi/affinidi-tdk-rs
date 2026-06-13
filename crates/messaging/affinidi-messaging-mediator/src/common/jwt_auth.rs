use crate::{
    SharedData,
    common::authz::{self, Capability},
    common::session::{Session, SessionClaims},
};
use affinidi_messaging_mediator_common::errors::ErrorResponse;
use affinidi_messaging_sdk::protocols::mediator::acls::MediatorACLSet;
use axum::{
    Json, RequestPartsExt,
    extract::{FromRef, FromRequestParts},
    response::{IntoResponse, Response},
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use http::{StatusCode, request::Parts};
use jsonwebtoken::{TokenData, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha256::digest;
use std::{
    fmt::{Debug, Display},
    net::SocketAddr,
};
use tracing::{Level, debug, error, event, info, warn};

// Payload contents of the JWT
// All times are in seconds since UNIX EPOCH
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPayload {
    pub aud: Vec<String>, // Intended Audience
    pub client_id: String,
    pub exp: u64,    // What does this JWT Expire
    pub iat: u64,    // Issued at this time
    pub iss: String, // Who issued this JWT?
    pub jti: String, // JWT ID
    pub nbf: u64,    // JWT is not valid before this time
    /// OAuth2 scopes (reserved for future use)
    pub scp: Vec<String>,
    pub sub: String, // subject - who this JWT refers to
}

#[derive(Debug)]
pub enum AuthError {
    WrongCredentials,
    MissingCredentials,
    InvalidToken,
    ExpiredToken,
    InternalServerError(String),
    Blocked,
}

impl Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::WrongCredentials => write!(f, "Wrong credentials"),
            AuthError::MissingCredentials => write!(f, "Missing credentials"),
            AuthError::InvalidToken => write!(f, "Invalid token"),
            AuthError::ExpiredToken => write!(f, "Expired token"),
            AuthError::InternalServerError(message) => {
                write!(f, "Internal Server Error: {message}")
            }
            AuthError::Blocked => write!(f, "ACL Blocked"),
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = match self {
            AuthError::WrongCredentials => StatusCode::UNAUTHORIZED,
            AuthError::MissingCredentials => StatusCode::UNAUTHORIZED,
            AuthError::InvalidToken => StatusCode::UNAUTHORIZED,
            AuthError::ExpiredToken => StatusCode::UNAUTHORIZED,
            AuthError::InternalServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::Blocked => StatusCode::UNAUTHORIZED,
        };
        let body = Json(json!(ErrorResponse {
            session_id: "UNAUTHORIZED".into(),
            request_id: None::<String>,
            http_code: status.as_u16(),
            error_code: status.as_u16(),
            error_code_str: status.to_string(),
            message: self.to_string(),
        }));
        (status, body).into_response()
    }
}

/// `jsonwebtoken`'s default expiry leeway (seconds). We move the `exp` time
/// comparison off `jsonwebtoken` — which reads the real wall clock and so
/// ignores an injected [`Clock`](affinidi_messaging_mediator_common::types::clock::Clock)
/// — and onto the mediator's clock, but preserve this exact leeway so the
/// accept/reject boundary is unchanged from the previous behaviour.
pub(crate) const JWT_EXP_LEEWAY_SECS: u64 = 60;

/// A [`Validation`] with `exp` *required* but its time check disabled, so expiry
/// is judged against the injected clock (via [`jwt_exp_is_expired`]) rather than
/// `jsonwebtoken`'s internal `SystemTime::now()`. Signature, audience, and the
/// required-claims set are validated exactly as before.
pub(crate) fn clock_aware_validation() -> Validation {
    let mut validation = Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.set_audience(&["ATM"]);
    validation.set_required_spec_claims(&["exp", "sub", "aud", "session_id"]);
    // Defer the expiry check to the injected clock; `exp` stays a required claim.
    validation.validate_exp = false;
    validation
}

/// Whether a token with the given `exp` is expired at `now`, using the same
/// leeway `jsonwebtoken` applied by default (`exp < now - leeway`). Written as
/// `exp + leeway < now` to avoid underflow.
pub(crate) fn jwt_exp_is_expired(exp: u64, now: u64) -> bool {
    exp + JWT_EXP_LEEWAY_SECS < now
}

/// Validate a raw JWT bearer token and resolve it to an authenticated
/// [`Session`].
///
/// This is the single source of truth for token validation. It is
/// shared by two callers so both apply *identical* signature, claim,
/// expiry, DID-match and ACL checks:
/// - [`Session::from_request_parts`] — the `Authorization: Bearer`
///   header path used by all REST endpoints and by native WebSocket
///   clients (which can set request headers on the upgrade).
/// - [`crate::handlers::websocket::websocket_handler`] — the
///   `Sec-WebSocket-Protocol` subprotocol path used by browsers, which
///   cannot set an `Authorization` header on `new WebSocket(...)`.
///
/// The token's origin (header vs. subprotocol) is irrelevant here: the
/// same JWT yields the same `Session`.
pub(crate) async fn authenticate_token(
    state: &SharedData,
    token: &str,
) -> Result<Session, AuthError> {
    let token_data: TokenData<SessionClaims> = match jsonwebtoken::decode::<SessionClaims>(
        token,
        &state.config.security.jwt_decoding_key,
        &clock_aware_validation(),
    ) {
        Ok(token_data) => token_data,
        Err(err) => {
            event!(Level::WARN, "Decoding JWT failed {:?}", err);
            return Err(AuthError::InvalidToken);
        }
    };

    // Expiry is checked here (not by jsonwebtoken) so it honours the injected
    // clock. Same leeway/boundary as before — see `clock_aware_validation`.
    if jwt_exp_is_expired(token_data.claims.exp, state.clock.unix_secs()) {
        event!(Level::WARN, "JWT access token expired");
        return Err(AuthError::ExpiredToken);
    }

    let session_id = token_data.claims.session_id.clone();
    let did = token_data.claims.sub.clone();
    let did_hash = digest(&did);

    // Everything has passed token wise - expensive database operations happen here
    let mut saved_session: Session = state
        .database
        .get_session(&session_id, &did)
        .await
        .map_err(|e| {
            error!(
                "{}: Couldn't get session from database! Reason: {}",
                session_id, e
            );
            AuthError::InternalServerError(format!(
                "Couldn't get session from database! Reason: {e}"
            ))
        })?
        .into();

    // Defence in depth: the session record's DID must match the
    // JWT's `sub`. If they diverge, the session was either created
    // with a different DID (storage corruption, replay across
    // tenants) or get_session returned a partially populated
    // record (legacy data, schema drift). Either way the handler
    // would silently see the wrong DID — surface as InvalidToken
    // here so the failure is loud and the client re-authenticates.
    if saved_session.did != did {
        warn!(
            session_id = %session_id,
            jwt_did = %did,
            session_did = %saved_session.did,
            "JWT sub does not match session DID — rejecting"
        );
        return Err(AuthError::InvalidToken);
    }

    // Check if ACL is satisfied
    if authz::require_capability(&saved_session.acls, Capability::NotBlocked).is_err() {
        info!("DID({}) is blocked from connecting", did);
        return Err(AuthError::Blocked);
    }

    // Update the expires at time
    saved_session.expires_at = token_data.claims.exp;

    debug!(session_id, did_hash, "JWT auth accepted");

    Ok(saved_session)
}

impl<S> FromRequestParts<S> for Session
where
    SharedData: FromRef<S>,
    S: Send + Sync + Debug,
{
    type Rejection = AuthError;
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let state = parts
            .extract_with_state::<SharedData, _>(_state)
            .await
            .map_err(|e| {
                error!("Couldn't get SharedData state! Reason: {}", e);
                AuthError::InternalServerError(format!(
                    "Couldn't get SharedData state! Reason: {e}"
                ))
            })?;

        match parts
            .extensions
            .get::<axum::extract::ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0)
        {
            Some(address) => address.to_string(),
            _ => {
                warn!("No remote address in request!");
                return Err(AuthError::MissingCredentials);
            }
        };

        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| {
                warn!("No Authorization Bearer header in request!");
                AuthError::MissingCredentials
            })?;

        authenticate_token(&state, bearer.token()).await
    }
}

/// Whether an unauthenticated (no-Bearer) inbound request may be accepted as an
/// anonymous session.
///
/// Anonymous inbound exists solely for inter-mediator relay: a remote
/// `ForwardingProcessor` POSTs a forward whose inner authcrypt *is* the
/// authentication. We only honour that when the operator has opted into acting
/// as a relay, signalled by the global default ACL granting `SEND_FORWARDED`
/// (the capability the relay path consumes, gated again per-message in
/// `routing.rs`). On a mediator with the shipped secure default this returns
/// `false`, so anonymous requests are rejected exactly like before.
fn anonymous_inbound_allowed(global_acl_default: &MediatorACLSet) -> bool {
    authz::grants(global_acl_default, Capability::SendForwarded)
}

/// The minimal ACL set granted to an anonymous inter-mediator relay session.
///
/// Anonymous `/inbound` exists only to relay forwards between mediators, so the
/// synthesised session is given the *least privilege* required to traverse the
/// inbound path rather than the full `global_acl_default` (which is `ALLOW_ALL`
/// in practice and would also grant `LOCAL`, `RECEIVE_MESSAGES`, invite
/// creation, and the `self_manage_*` capabilities to an unauthenticated caller).
///
/// Two capabilities are required and sufficient:
/// - `SEND_MESSAGES` — the handler-level gate in `message_inbound_handler`
///   rejects any session without it before the message is processed.
/// - `SEND_FORWARDED` — consumed by the anonymous-forward branch in
///   `routing.rs` when the inner forward carries no `from` field.
///
/// Per-message authorisation downstream (the forward's `from_account` ACL and
/// the recipient's `receive_forwarded` ACL) is unaffected — it is keyed off the
/// envelope/account identities, not this session.
fn relay_anonymous_acls() -> MediatorACLSet {
    // `from_string_ruleset` cannot fail for this static, audited input; fall
    // back to the all-deny default rather than panicking if it ever does.
    MediatorACLSet::from_string_ruleset("DENY_ALL,SEND_MESSAGES,SEND_FORWARDED").unwrap_or_default()
}

/// Decide whether an authentication failure should be downgraded to an anonymous
/// relay session, and if so build that session.
///
/// Only a genuinely *absent* credential ([`AuthError::MissingCredentials`]) is
/// eligible — and only when the mediator is configured as a relay. Every other
/// failure (`InvalidToken`, `ExpiredToken`, `Blocked`, `InternalServerError`,
/// `WrongCredentials`) is propagated unchanged: a caller that *presents* a bad,
/// expired, or blocked token must be rejected, never silently demoted to
/// anonymous, and a backend error must surface as `500` rather than proceed as
/// an unauthenticated relay.
///
/// Relay is enabled when the explicit `enable_inter_mediator_relay` flag is set
/// OR, for backward compatibility, when `global_acl_default` grants
/// `SEND_FORWARDED` (the legacy implicit-relay behaviour, which boot-time
/// validation now warns about). A future release will require the explicit flag.
fn anonymous_session_for(
    err: &AuthError,
    enable_relay_flag: bool,
    global_acl_default: &MediatorACLSet,
) -> Option<Session> {
    let relay_enabled = enable_relay_flag || anonymous_inbound_allowed(global_acl_default);
    if matches!(err, AuthError::MissingCredentials) && relay_enabled {
        Some(Session {
            session_id: "ANON-INBOUND".to_string(),
            acls: relay_anonymous_acls(),
            ..Default::default()
        })
    } else {
        None
    }
}

/// Extractor that wraps `Session`, optionally allowing anonymous relay requests.
///
/// When a valid `Authorization: Bearer` token is present the inner `Session`
/// is fully populated (i.e. `session.authenticated == true`). When the header
/// is *absent* the request is accepted — as an anonymous session carrying a
/// minimal relay-scoped ACL (see [`relay_anonymous_acls`]) — only if the
/// mediator is configured as an inter-mediator relay (see
/// [`anonymous_session_for`]). A *present but invalid/expired/blocked* token,
/// or a backend error, is propagated unchanged, so a mediator with the shipped
/// secure default keeps rejecting unauthenticated `/inbound` requests.
pub struct MaybeSession(pub Session);

impl<S> FromRequestParts<S> for MaybeSession
where
    SharedData: FromRef<S>,
    S: Send + Sync + Debug,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Session::from_request_parts(parts, state).await {
            Ok(session) => Ok(MaybeSession(session)),
            Err(e) => {
                let shared = SharedData::from_ref(state);
                let security = &shared.config.security;
                match anonymous_session_for(
                    &e,
                    security.enable_inter_mediator_relay,
                    &security.global_acl_default,
                ) {
                    Some(session) => Ok(MaybeSession(session)),
                    None => Err(e),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_exp_uses_the_same_leeway_as_jsonwebtoken() {
        // Boundary equivalent to jsonwebtoken's default (`exp < now - leeway`,
        // i.e. expired iff `exp + leeway < now`), with leeway = 60.
        let exp = 1_000_u64;
        // Well within validity.
        assert!(!jwt_exp_is_expired(exp, exp));
        // Exactly at the leeway edge — still accepted.
        assert!(!jwt_exp_is_expired(exp, exp + JWT_EXP_LEEWAY_SECS));
        // One second past the leeway — now expired.
        assert!(jwt_exp_is_expired(exp, exp + JWT_EXP_LEEWAY_SECS + 1));
        // A token issued "in the future" is certainly not expired (no underflow).
        assert!(!jwt_exp_is_expired(exp, 0));
    }

    #[test]
    fn clock_aware_validation_defers_expiry_but_keeps_exp_required() {
        let validation = clock_aware_validation();
        // jsonwebtoken must NOT check expiry (the injected clock does).
        assert!(!validation.validate_exp);
        // ...but `exp` is still a required claim, so a token without it is
        // rejected at decode time exactly as before.
        assert!(validation.required_spec_claims.contains("exp"));
    }

    #[test]
    fn anon_inbound_allowed_when_global_default_grants_send_forwarded() {
        let acls = MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap();
        assert!(anonymous_inbound_allowed(&acls));
    }

    #[test]
    fn anon_inbound_denied_for_shipped_secure_default() {
        // The shipped default global_acl_default: fine for direct messaging but
        // NOT a relay (no SEND_FORWARDED), so anonymous inbound must be refused.
        let acls =
            MediatorACLSet::from_string_ruleset("DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES")
                .unwrap();
        assert!(!anonymous_inbound_allowed(&acls));
    }

    #[test]
    fn relay_anonymous_acls_grant_only_send_and_forward() {
        // The synthesised relay session must carry exactly the two capabilities
        // the inbound path needs — and none of the ALLOW_ALL extras that would
        // hand an unauthenticated caller broad mediator access.
        let acls = relay_anonymous_acls();
        assert!(
            acls.get_send_messages().0,
            "needs SEND_MESSAGES for the handler gate"
        );
        assert!(
            acls.get_send_forwarded().0,
            "needs SEND_FORWARDED for the relay branch"
        );

        // Everything else must remain denied.
        assert!(!acls.get_local());
        assert!(!acls.get_receive_messages().0);
        assert!(!acls.get_receive_forwarded().0);
        assert!(!acls.get_create_invites().0);
        assert!(!acls.get_anon_receive().0);
        assert!(!acls.get_self_manage_list());
        assert!(!acls.get_self_manage_send_queue_limit());
        assert!(!acls.get_self_manage_receive_queue_limit());
        assert!(!acls.get_blocked());
    }

    #[test]
    fn missing_credentials_downgrades_to_relay_session_only_when_relay_enabled() {
        let relay = MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap();
        // Legacy implicit relay: ACL grants SEND_FORWARDED, flag off.
        let session = anonymous_session_for(&AuthError::MissingCredentials, false, &relay)
            .expect("relay-enabled mediator accepts anonymous inbound");
        // Not authenticated, no DID, and scoped to the minimal relay ACL — never
        // the full global default.
        assert!(!session.authenticated);
        assert!(session.did.is_empty());
        assert!(session.acls.get_send_forwarded().0);
        assert!(!session.acls.get_local());

        // Same request on a non-relay mediator is rejected, not downgraded.
        let secure =
            MediatorACLSet::from_string_ruleset("DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES")
                .unwrap();
        assert!(anonymous_session_for(&AuthError::MissingCredentials, false, &secure).is_none());
    }

    #[test]
    fn explicit_relay_flag_enables_anonymous_inbound_without_the_acl_bit() {
        // The explicit flag enables anonymous relay even when the global default
        // ACL does NOT grant SEND_FORWARDED (the forward-compatible path).
        let secure =
            MediatorACLSet::from_string_ruleset("DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES")
                .unwrap();
        assert!(
            anonymous_session_for(&AuthError::MissingCredentials, true, &secure).is_some(),
            "explicit enable_inter_mediator_relay must accept anonymous inbound"
        );
        // ...and with neither the flag nor the ACL bit, it stays rejected.
        assert!(anonymous_session_for(&AuthError::MissingCredentials, false, &secure).is_none());
    }

    #[test]
    fn presented_but_invalid_credentials_are_never_downgraded() {
        // Even on a relay-enabled mediator, a caller that *presents* a bad,
        // expired, or blocked token — or trips a backend error — must be
        // rejected outright, never silently demoted to an anonymous session.
        let relay = MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap();
        for err in [
            AuthError::InvalidToken,
            AuthError::ExpiredToken,
            AuthError::Blocked,
            AuthError::WrongCredentials,
            AuthError::InternalServerError("backend down".into()),
        ] {
            assert!(
                anonymous_session_for(&err, false, &relay).is_none(),
                "{err:?} must not be downgraded to an anonymous session"
            );
        }
    }
}

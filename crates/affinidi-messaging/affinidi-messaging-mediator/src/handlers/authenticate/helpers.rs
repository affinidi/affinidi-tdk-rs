use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::messages::problem_report::{ProblemReportScope, ProblemReportSorter};
use crate::database::session::SessionClaims;
use http::StatusCode;
use jsonwebtoken::{EncodingKey, Header, encode};
use rand::{RngExt, distr::Alphanumeric};
use sha256::digest;
use crate::common::time::unix_timestamp_secs;

/// creates a random string of up to length characters
pub fn create_random_string(length: usize) -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

pub(super) fn _create_access_token(
    did: &str,
    session_id: &str,
    expiry: u64,
    encoding_key: &EncodingKey,
) -> Result<(String, u64), MediatorError> {
    // Passed all the checks, now create the JWT tokens
    let access_claims = SessionClaims {
        aud: "ATM".to_string(),
        sub: did.to_owned(),
        session_id: session_id.to_owned(),
        exp: (unix_timestamp_secs() + expiry),
    };

    let access_token = encode(
        &Header::new(jsonwebtoken::Algorithm::EdDSA),
        &access_claims,
        encoding_key,
    )
    .map_err(|err| {
        MediatorError::problem_with_log(
            35,
            session_id.to_string(),
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "authentication.session.access_token",
            "Couldn't create JWT Access token. Reason: {1}",
            vec![err.to_string()],
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Couldn't create JWT Access token. Reason: {err}"),
        )
    })?;

    Ok((access_token, access_claims.exp))
}

/// Creates a JWT refresh token and returns the token string, expiry timestamp, and SHA-256 hash.
/// The hash is stored in Redis to enforce one-time use.
pub(super) fn _create_refresh_token(
    did: &str,
    session_id: &str,
    expiry: u64,
    encoding_key: &EncodingKey,
) -> Result<(String, u64, String), MediatorError> {
    let refresh_claims = SessionClaims {
        aud: "ATM".to_string(),
        sub: did.to_owned(),
        session_id: session_id.to_owned(),
        exp: (unix_timestamp_secs() + expiry),
    };

    let refresh_token = encode(
        &Header::new(jsonwebtoken::Algorithm::EdDSA),
        &refresh_claims,
        encoding_key,
    )
    .map_err(|err| {
        MediatorError::problem_with_log(
            36,
            session_id.to_string(),
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "authentication.session.refresh_token",
            "Couldn't create JWT Refresh token. Reason: {1}",
            vec![err.to_string()],
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Couldn't create JWT Refresh token. Reason: {err}"),
        )
    })?;

    let token_hash = digest(&refresh_token);

    Ok((refresh_token, refresh_claims.exp, token_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::session::SessionClaims;
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    /// Helper: generate an Ed25519 key pair and return (encoding_key, decoding_key).
    fn test_ed25519_keys() -> (EncodingKey, DecodingKey) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse pkcs8");

        let encoding_key = EncodingKey::from_ed_der(pkcs8.as_ref());
        let decoding_key = DecodingKey::from_ed_der(pair.public_key().as_ref());
        (encoding_key, decoding_key)
    }

    #[test]
    fn create_random_string_has_expected_length() {
        let s = create_random_string(32);
        assert_eq!(s.len(), 32);

        let s = create_random_string(64);
        assert_eq!(s.len(), 64);

        let s = create_random_string(0);
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn create_random_string_produces_unique_values() {
        let a = create_random_string(32);
        let b = create_random_string(32);
        assert_ne!(a, b, "two random strings of length 32 should differ");
    }

    #[test]
    fn create_access_token_produces_valid_jwt() {
        let (encoding_key, decoding_key) = test_ed25519_keys();

        let (token, _exp) =
            _create_access_token("did:example:123", "session-1", 3600, &encoding_key)
                .expect("should create access token");

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&["ATM"]);
        validation.sub = Some("did:example:123".to_string());

        let token_data =
            decode::<SessionClaims>(&token, &decoding_key, &validation).expect("should decode JWT");

        assert_eq!(token_data.claims.aud, "ATM");
        assert_eq!(token_data.claims.sub, "did:example:123");
        assert_eq!(token_data.claims.session_id, "session-1");
    }

    #[test]
    fn create_access_token_sets_correct_expiry() {
        let (encoding_key, decoding_key) = test_ed25519_keys();
        let expiry_delta = 7200_u64;

        let before = unix_timestamp_secs();
        let (_token, exp) =
            _create_access_token("did:example:456", "session-2", expiry_delta, &encoding_key)
                .expect("should create access token");
        let after = unix_timestamp_secs();

        // The expiry should be roughly now + expiry_delta (within the before/after window).
        assert!(exp >= before + expiry_delta);
        assert!(exp <= after + expiry_delta);

        // Also verify through the JWT claims
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&["ATM"]);
        validation.sub = Some("did:example:456".to_string());

        let token_data = decode::<SessionClaims>(&_token, &decoding_key, &validation)
            .expect("should decode JWT");
        assert_eq!(token_data.claims.exp, exp);
    }

    #[test]
    fn create_refresh_token_returns_token_expiry_and_hash() {
        let (encoding_key, _decoding_key) = test_ed25519_keys();

        let (token, exp, hash) =
            _create_refresh_token("did:example:789", "session-3", 3600, &encoding_key)
                .expect("should create refresh token");

        assert!(!token.is_empty(), "token should not be empty");
        assert!(exp > 0, "expiry should be positive");
        assert!(!hash.is_empty(), "hash should not be empty");
    }

    #[test]
    fn create_refresh_token_hash_matches_sha256_of_token() {
        let (encoding_key, _decoding_key) = test_ed25519_keys();

        let (token, _exp, hash) =
            _create_refresh_token("did:example:abc", "session-4", 3600, &encoding_key)
                .expect("should create refresh token");

        let expected_hash = digest(&token);
        assert_eq!(hash, expected_hash, "hash should be SHA-256 of the token");
    }
}

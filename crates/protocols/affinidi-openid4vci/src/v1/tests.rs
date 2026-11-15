//! Serde round trips against the spec's own examples, plus issuer/wallet
//! helper behaviour.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::issuer::*;
use super::spec_examples::*;
use super::types::*;
use super::wallet::*;

/// Deserialize a spec example into `T`, serialize it back, and require the
/// JSON to be unchanged.
fn round_trip<T: DeserializeOwned + serde::Serialize>(example: &str) -> T {
    let original: Value = serde_json::from_str(example).expect("spec example is JSON");
    let typed: T = serde_json::from_value(original.clone()).expect("deserializes");
    let back = serde_json::to_value(&typed).expect("serializes");
    assert_eq!(back, original, "round trip changed the JSON");
    typed
}

/// The `credential_configurations_supported` fragments of §12.2.4 / App. A.
#[derive(Deserialize, serde::Serialize)]
struct ConfigsOnly {
    credential_configurations_supported: BTreeMap<String, CredentialConfiguration>,
}

// ── Spec examples ───────────────────────────────────────────────────────────

#[test]
fn offers_round_trip() {
    let offer: CredentialOffer = round_trip(OFFER_PRE_AUTH);
    let pre = offer.grants.unwrap().pre_authorized_code.unwrap();
    assert_eq!(pre.pre_authorized_code, "oaKazRN8I0IbtZ0C7JuMn5");
    let tx = pre.tx_code.unwrap();
    assert_eq!(tx.length, Some(4));
    assert_eq!(tx.input_mode, Some(TxCodeInputMode::Numeric));

    let offer: CredentialOffer = round_trip(OFFER_AUTH_CODE);
    let auth = offer.grants.unwrap().authorization_code.unwrap();
    assert_eq!(
        auth.issuer_state.as_deref(),
        Some("eyJhbGciOiJSU0Et...FYUaBy")
    );

    // `"tx_code": {}` means a code is required and must survive the trip.
    let offer: CredentialOffer = round_trip(OFFER_PRE_AUTH_EMPTY_TX_CODE);
    let tx = offer.grants.unwrap().pre_authorized_code.unwrap().tx_code;
    assert_eq!(tx, Some(TxCode::default()));
}

#[test]
fn authorization_details_round_trip() {
    for ex in [
        AUTH_DETAILS,
        AUTH_DETAILS_LOCATIONS,
        AUTH_DETAILS_TWO,
        AUTH_DETAILS_JWT_VC_CLAIMS,
        AUTH_DETAILS_MDOC_CLAIMS,
        AUTH_DETAILS_SD_JWT_CLAIMS,
    ] {
        let details: Vec<AuthorizationDetail> = round_trip(ex);
        assert!(
            details
                .iter()
                .all(|d| d.detail_type == AUTHORIZATION_DETAILS_TYPE_OPENID_CREDENTIAL)
        );
    }
}

#[test]
fn token_messages_round_trip() {
    let resp: TokenResponse = round_trip(TOKEN_RESPONSE);
    assert_eq!(
        credential_identifiers(&resp, "UniversityDegreeCredential"),
        [
            "CivilEngineeringDegree-2023",
            "ElectricalEngineeringDegree-2023"
        ]
    );
    assert!(credential_identifiers(&resp, "other").is_empty());
    assert!(!format!("{resp:?}").contains("eyJhbGci"));

    let err: TokenErrorResponse = round_trip(TOKEN_ERROR);
    assert_eq!(err.error, TokenErrorCode::InvalidRequest);
}

#[test]
fn token_request_form_matches_spec_example() {
    // §6.1.1, line breaks in the authorization_details value removed.
    let body = "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code\
        &pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA\
        &tx_code=493536\
        &authorization_details=%5B%7B%22type%22%3A%20%22openid_credential%22%2C%20%22\
credential_configuration_id%22%3A%20%22UniversityDegreeCredential%22%7D%5D";
    let req = TokenRequest::from_form_urlencoded(body).unwrap();
    assert_eq!(req.grant_type, GRANT_TYPE_PRE_AUTHORIZED_CODE);
    assert_eq!(
        req.pre_authorized_code.as_deref(),
        Some("SplxlOBeZQQYbYS6WxSbIA")
    );
    assert_eq!(req.tx_code.as_deref(), Some("493536"));
    let details = req.authorization_details.as_ref().unwrap();
    assert_eq!(
        details[0].credential_configuration_id,
        "UniversityDegreeCredential"
    );
    // Secrets are redacted from Debug.
    let dbg = format!("{req:?}");
    assert!(!dbg.contains("SplxlOBeZQQYbYS6WxSbIA") && !dbg.contains("493536"));

    // Encode → decode is lossless.
    let again = TokenRequest::from_form_urlencoded(&req.to_form_urlencoded()).unwrap();
    assert_eq!(again, req);
}

#[test]
fn token_request_form_rejects_repeats_and_missing_grant_type() {
    let e = TokenRequest::from_form_urlencoded("grant_type=a&grant_type=b").unwrap_err();
    assert_eq!(e.error, TokenErrorCode::InvalidRequest);
    let e = TokenRequest::from_form_urlencoded("code=x").unwrap_err();
    assert_eq!(e.error, TokenErrorCode::InvalidRequest);
}

#[test]
fn nonce_response_round_trip() {
    let n: NonceResponse = round_trip(NONCE_RESPONSE);
    assert_eq!(n.c_nonce, "wKI4LT17ac15ES9bw8ac4");
}

#[test]
fn credential_requests_round_trip() {
    let req: CredentialRequest = round_trip(CREDENTIAL_REQUEST_MDOC);
    assert_eq!(
        req.credential_configuration_id.as_deref(),
        Some("org.iso.18013.5.1.mDL")
    );
    assert_eq!(req.proofs.unwrap().single(), Some((PROOF_TYPE_JWT, 1)));

    let req: CredentialRequest = round_trip(CREDENTIAL_REQUEST_SD_JWT);
    assert_eq!(
        req.credential_identifier.as_deref(),
        Some("CivilEngineeringDegree-2023")
    );
    assert_eq!(req.proofs.unwrap().single(), Some((PROOF_TYPE_JWT, 2)));

    let req: CredentialRequest = round_trip(CREDENTIAL_REQUEST_DI_VP);
    assert_eq!(req.proofs.unwrap().single(), Some((PROOF_TYPE_DI_VP, 1)));
}

#[test]
fn proofs_round_trip() {
    let p: Proofs = round_trip(PROOFS_JWT);
    assert_eq!(p.single(), Some((PROOF_TYPE_JWT, 1)));
    let p: Proofs = round_trip(PROOFS_DI_VP);
    assert_eq!(p.single(), Some((PROOF_TYPE_DI_VP, 1)));
    let p: Proofs = round_trip(PROOFS_ATTESTATION);
    assert_eq!(p.single(), Some((PROOF_TYPE_ATTESTATION, 1)));

    // Unknown proof types are kept; two proof types are not "single".
    let p: Proofs = round_trip(r#"{"jwt": ["a"], "custom": [{"x": 1}]}"#);
    assert_eq!(p.single(), None);
}

#[test]
fn credential_responses_round_trip() {
    for ex in [
        CREDENTIAL_RESPONSE_ONE,
        CREDENTIAL_RESPONSE_MULTI,
        CREDENTIAL_RESPONSE_JWT_VC_JSON,
        CREDENTIAL_RESPONSE_LDP_VC,
        CREDENTIAL_RESPONSE_MSO_MDOC,
        CREDENTIAL_RESPONSE_DC_SD_JWT,
        DEFERRED_RESPONSE,
    ] {
        let r: CredentialResponse = round_trip(ex);
        assert!(r.check().is_ok() && !r.is_deferred());
    }
    let r: CredentialResponse = round_trip(CREDENTIAL_RESPONSE_MULTI);
    assert_eq!(r.notification_id.as_deref(), Some("3fwe98js"));
    assert!(check_credential_response(&r, 2).is_ok());
    assert!(check_credential_response(&r, 1).is_err());

    // ldp_vc credentials are objects, not strings (Appendix A.1.2.4).
    let r: CredentialResponse = round_trip(CREDENTIAL_RESPONSE_LDP_VC);
    assert!(r.credentials.unwrap()[0].credential.is_object());

    for ex in [CREDENTIAL_RESPONSE_DEFERRED, DEFERRED_RESPONSE_PENDING] {
        let r: DeferredCredentialResponse = round_trip(ex);
        assert!(r.check().is_ok() && r.is_deferred());
        assert_eq!(r.transaction_id.as_deref(), Some("8xLOxBtZp8"));
    }
}

#[test]
fn credential_response_member_rules() {
    assert!(
        CredentialResponse::issued(vec![json!("c")], None)
            .check()
            .is_ok()
    );
    assert!(CredentialResponse::deferred("t", 5).check().is_ok());
    assert!(CredentialResponse::deferred("t", 0).check().is_err());
    assert!(CredentialResponse::default().check().is_err());
    let mut both = CredentialResponse::issued(vec![json!("c")], None);
    both.transaction_id = Some("t".into());
    assert!(both.check().is_err());
    let mut notif = CredentialResponse::deferred("t", 5);
    notif.notification_id = Some("n".into());
    assert!(notif.check().is_err());
    assert!(CredentialResponse::issued(vec![], None).check().is_err());
}

#[test]
fn deferred_and_error_messages_round_trip() {
    let d: DeferredCredentialRequest = round_trip(DEFERRED_REQUEST);
    assert_eq!(d, build_deferred_credential_request("8xLOxBtZp8"));

    let e: CredentialErrorResponse = round_trip(CREDENTIAL_ERROR);
    assert_eq!(e.error, CredentialErrorCode::UnknownCredentialConfiguration);
    let e: CredentialErrorResponse = round_trip(DEFERRED_ERROR);
    assert_eq!(e.error, CredentialErrorCode::InvalidTransactionId);

    // Unknown codes are kept verbatim.
    let e: CredentialErrorResponse = round_trip(r#"{"error": "something_new"}"#);
    assert_eq!(e.error, CredentialErrorCode::Other("something_new".into()));
}

#[test]
fn notification_messages_round_trip() {
    let n: NotificationRequest = round_trip(NOTIFICATION_ACCEPTED);
    assert_eq!(n.event, NotificationEvent::CredentialAccepted);
    assert_eq!(
        n,
        build_notification_request("3fwe98js", NotificationEvent::CredentialAccepted, None)
    );
    let n: NotificationRequest = round_trip(NOTIFICATION_FAILURE);
    assert_eq!(n.event, NotificationEvent::CredentialFailure);

    let e: NotificationErrorResponse = round_trip(NOTIFICATION_ERROR);
    assert_eq!(e.error, NotificationErrorCode::InvalidNotificationId);
}

#[test]
fn configuration_examples_round_trip() {
    let c: ConfigsOnly = round_trip(CONFIGS_SD_JWT);
    let sd = &c.credential_configurations_supported["SD_JWT_VC_example_in_OpenID4VCI"];
    assert_eq!(sd.format, FORMAT_DC_SD_JWT);
    assert_eq!(sd.vct.as_deref(), Some("SD_JWT_VC_example_in_OpenID4VCI"));
    let jwt = &sd.proof_types_supported.as_ref().unwrap()[PROOF_TYPE_JWT];
    assert!(jwt.key_attestations_required.is_some());

    let c: ConfigsOnly = round_trip(CONFIGS_JWT_VC_JSON);
    let def = c.credential_configurations_supported["UniversityDegreeCredential"]
        .credential_definition
        .as_ref()
        .unwrap();
    assert_eq!(
        def.types,
        ["VerifiableCredential", "UniversityDegreeCredential"]
    );

    let c: ConfigsOnly = round_trip(CONFIGS_LDP_VC);
    assert!(
        c.credential_configurations_supported["UniversityDegree_LDP_VC"]
            .credential_definition
            .as_ref()
            .unwrap()
            .context
            .is_some()
    );

    // mdoc signing algorithms are numeric COSE identifiers (Appendix A.2.2).
    let c: ConfigsOnly = round_trip(CONFIGS_MSO_MDOC);
    let mdl = &c.credential_configurations_supported["org.iso.18013.5.1.mDL"];
    assert_eq!(
        mdl.credential_signing_alg_values_supported.as_deref(),
        Some(&[AlgorithmIdentifier::Cose(-7), AlgorithmIdentifier::Cose(-9)][..])
    );
    let claims = mdl
        .credential_metadata
        .as_ref()
        .unwrap()
        .claims
        .as_ref()
        .unwrap();
    assert_eq!(
        claims[0].path,
        [
            ClaimPathElement::Name("org.iso.18013.5.1".into()),
            ClaimPathElement::Name("given_name".into())
        ]
    );

    let _: ConfigsOnly = round_trip(CONFIGS_DC_SD_JWT);
}

#[test]
fn full_issuer_metadata_round_trips_and_checks() {
    let m: CredentialIssuerMetadata = round_trip(ISSUER_METADATA);
    assert_eq!(
        m.nonce_endpoint.as_deref(),
        Some("https://credential-issuer.example.com/nonce")
    );
    assert_eq!(m.batch_credential_issuance.unwrap().batch_size, 10);
    assert_eq!(
        m.credential_request_encryption
            .as_ref()
            .unwrap()
            .jwks
            .keys()
            .len(),
        1
    );
    assert!(check_issuer_metadata(&m, "https://credential-issuer.example.com").is_ok());
    // §12.2.4: simple string comparison, no normalization.
    assert!(check_issuer_metadata(&m, "https://credential-issuer.example.com/").is_err());
}

#[test]
fn signed_issuer_metadata_payload_parses() {
    let (header, payload) =
        affinidi_oid4vc_core::jwt::decode_compact_jws_unverified(SIGNED_ISSUER_METADATA).unwrap();
    assert_eq!(header["typ"], ISSUER_METADATA_JWT_TYP);
    let m: CredentialIssuerMetadata = serde_json::from_value(payload.clone()).unwrap();
    assert_eq!(m.credential_issuer, "https://credential-issuer.example.com");
    // `sub` / `iat` land in `additional` and survive the round trip.
    assert!(m.additional.contains_key("sub"));
    assert_eq!(serde_json::to_value(&m).unwrap(), payload);
}

#[test]
fn jwk_set_object_form_is_accepted() {
    let meta: CredentialRequestEncryptionMetadata = round_trip(
        r#"{"jwks": {"keys": [{"kty": "EC", "kid": "k"}]}, "enc_values_supported": ["A128GCM"], "encryption_required": false}"#,
    );
    assert_eq!(meta.jwks.keys().len(), 1);
}

#[test]
fn claim_path_null_and_index() {
    let c: ClaimsDescription = round_trip(r#"{"path": ["degrees", null, 0, "type"]}"#);
    assert_eq!(c.path[1], ClaimPathElement::All);
    assert_eq!(c.path[2], ClaimPathElement::Index(0));
}

// ── Offers ──────────────────────────────────────────────────────────────────

#[test]
fn build_and_parse_offer_uris() {
    let offer = create_pre_authorized_offer(
        "https://credential-issuer.example.com",
        vec!["org.iso.18013.5.1.mDL".into()],
        "oaKazRN8I0IbtZ0C7JuMn5".into(),
        Some(TxCode::default()),
    )
    .unwrap();
    let uri = credential_offer_by_value_uri(&offer).unwrap();
    assert!(uri.starts_with("openid-credential-offer://?credential_offer="));
    assert_eq!(
        parse_credential_offer_uri(&uri).unwrap(),
        CredentialOfferSource::ByValue(offer)
    );

    // §4.1.2 example (native app), line breaks removed.
    let spec_uri = "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22:%22https://credential-issuer.example.com%22,%22credential_configuration_ids%22:%5B%22org.iso.18013.5.1.mDL%22%5D,%22grants%22:%7B%22urn:ietf:params:oauth:grant-type:pre-authorized_code%22:%7B%22pre-authorized_code%22:%22oaKazRN8I0IbtZ0C7JuMn5%22,%22tx_code%22:%7B%22input_mode%22:%22text%22,%22description%22:%22Please%20enter%20the%20serial%20number%20of%20your%20physical%20drivers%20license%22%7D%7D%7D%7D";
    let CredentialOfferSource::ByValue(o) = parse_credential_offer_uri(spec_uri).unwrap() else {
        panic!("expected by value");
    };
    let tx = o
        .grants
        .unwrap()
        .pre_authorized_code
        .unwrap()
        .tx_code
        .unwrap();
    assert_eq!(tx.input_mode, Some(TxCodeInputMode::Text));

    // §4.1.3 example (by reference).
    let spec_ref = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fserver%2Eexample%2Ecom%2Fcredential-offer%2FGkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM";
    let CredentialOfferSource::ByReference(u) = parse_credential_offer_uri(spec_ref).unwrap()
    else {
        panic!("expected by reference");
    };
    assert_eq!(
        u.as_str(),
        "https://server.example.com/credential-offer/GkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM"
    );
    assert_eq!(
        credential_offer_by_reference_uri(u.as_str()),
        "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fserver.example.com%2Fcredential-offer%2FGkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM"
    );
}

#[test]
fn offer_uri_rejects_both_neither_and_http_reference() {
    let both =
        "openid-credential-offer://?credential_offer=%7B%7D&credential_offer_uri=https%3A%2F%2Fa";
    assert!(parse_credential_offer_uri(both).is_err());
    assert!(parse_credential_offer_uri("openid-credential-offer://?x=1").is_err());
    let http = "openid-credential-offer://?credential_offer_uri=http%3A%2F%2Fa.example";
    assert!(parse_credential_offer_uri(http).is_err());
}

#[test]
fn offer_checks() {
    let ok = create_authorization_code_offer(
        "https://issuer.example.com",
        vec!["A".into()],
        Some("state".into()),
    );
    assert!(ok.is_ok());
    assert!(create_authorization_code_offer("https://issuer.example.com", vec![], None).is_err());
    assert!(
        create_authorization_code_offer(
            "https://issuer.example.com",
            vec!["A".into(), "A".into()],
            None
        )
        .is_err()
    );
    assert!(
        create_authorization_code_offer("http://issuer.example.com", vec!["A".into()], None)
            .is_err()
    );
    let long = TxCode {
        description: Some("x".repeat(301)),
        ..TxCode::default()
    };
    assert!(
        create_pre_authorized_offer(
            "https://issuer.example.com",
            vec!["A".into()],
            "code".into(),
            Some(long)
        )
        .is_err()
    );
    // The pre-authorized code is redacted from Debug.
    let offer = create_pre_authorized_offer(
        "https://issuer.example.com",
        vec!["A".into()],
        "secret-code".into(),
        None,
    )
    .unwrap();
    assert!(!format!("{offer:?}").contains("secret-code"));
}

// ── Metadata URL ────────────────────────────────────────────────────────────

#[test]
fn metadata_url_inserts_well_known_before_path() {
    // Both §12.2.2 examples.
    assert_eq!(
        metadata_url("https://issuer.example.com/tenant").unwrap(),
        "https://issuer.example.com/.well-known/openid-credential-issuer/tenant"
    );
    assert_eq!(
        metadata_url("https://tenant.issuer.example.com").unwrap(),
        "https://tenant.issuer.example.com/.well-known/openid-credential-issuer"
    );
    assert!(metadata_url("https://issuer.example.com/?q=1").is_err());
    assert!(metadata_url("http://issuer.example.com").is_err());
}

// ── Token Endpoint ──────────────────────────────────────────────────────────

fn grant(tx: Option<TxCode>) -> PreAuthorizedCodeGrant {
    PreAuthorizedCodeGrant {
        pre_authorized_code: "SplxlOBeZQQYbYS6WxSbIA".into(),
        tx_code: tx,
        authorization_server: None,
    }
}

fn issued(tx: Option<&str>) -> IssuedPreAuthorizedCode {
    IssuedPreAuthorizedCode {
        pre_authorized_code: "SplxlOBeZQQYbYS6WxSbIA".into(),
        tx_code: tx.map(str::to_string),
        expires_at: Some(1_000),
    }
}

#[test]
fn pre_authorized_token_flow_with_tx_code() {
    let tx = TxCode {
        length: Some(6),
        ..TxCode::default()
    };
    let req = build_pre_authorized_token_request(&grant(Some(tx.clone())), Some("493536".into()))
        .unwrap();
    assert!(check_pre_authorized_token_request(&req, &issued(Some("493536")), 500).is_ok());

    // Wallet-side checks of the tx_code shape.
    assert!(build_pre_authorized_token_request(&grant(Some(tx.clone())), None).is_err());
    assert!(
        build_pre_authorized_token_request(&grant(Some(tx.clone())), Some("12345".into())).is_err()
    );
    assert!(build_pre_authorized_token_request(&grant(Some(tx)), Some("49353a".into())).is_err());
    assert!(build_pre_authorized_token_request(&grant(None), Some("1".into())).is_err());
    let text = TxCode {
        input_mode: Some(TxCodeInputMode::Text),
        ..TxCode::default()
    };
    assert!(build_pre_authorized_token_request(&grant(Some(text)), Some("ab-12".into())).is_ok());
}

#[test]
fn pre_authorized_token_errors_follow_section_6_3() {
    let code = |req: &TokenRequest, iss: &IssuedPreAuthorizedCode, now| {
        check_pre_authorized_token_request(req, iss, now)
            .unwrap_err()
            .error
    };
    let good =
        build_pre_authorized_token_request(&grant(Some(TxCode::default())), Some("1234".into()))
            .unwrap();

    // Wrong tx_code → invalid_grant; missing / unexpected → invalid_request.
    assert_eq!(
        code(&good, &issued(Some("9999")), 0),
        TokenErrorCode::InvalidGrant
    );
    let mut missing = good.clone();
    missing.tx_code = None;
    assert_eq!(
        code(&missing, &issued(Some("1234")), 0),
        TokenErrorCode::InvalidRequest
    );
    assert_eq!(
        code(&good, &issued(None), 0),
        TokenErrorCode::InvalidRequest
    );

    // Wrong / expired code → invalid_grant.
    let mut wrong = good.clone();
    wrong.pre_authorized_code = Some("other".into());
    assert_eq!(
        code(&wrong, &issued(Some("1234")), 0),
        TokenErrorCode::InvalidGrant
    );
    assert_eq!(
        code(&good, &issued(Some("1234")), 1_000),
        TokenErrorCode::InvalidGrant
    );

    // Other grant types.
    let mut auth = good.clone();
    auth.grant_type = GRANT_TYPE_AUTHORIZATION_CODE.into();
    assert_eq!(
        code(&auth, &issued(Some("1234")), 0),
        TokenErrorCode::UnsupportedGrantType
    );
    let mut no_code = good;
    no_code.pre_authorized_code = None;
    assert_eq!(
        code(&no_code, &issued(Some("1234")), 0),
        TokenErrorCode::InvalidRequest
    );

    assert!(!format!("{:?}", issued(Some("1234"))).contains("1234"));
}

// ── Credential Endpoint ─────────────────────────────────────────────────────

fn metadata() -> CredentialIssuerMetadata {
    serde_json::from_str(ISSUER_METADATA).unwrap()
}

const SD: &str = "SD_JWT_VC_example_in_OpenID4VCI";

fn enc(alg: &str, enc: &str) -> CredentialResponseEncryption {
    CredentialResponseEncryption {
        jwk: json!({"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "alg": alg}),
        enc: enc.into(),
        zip: None,
    }
}

#[test]
fn validate_request_identification() {
    let m = metadata();
    let mut req =
        build_credential_request_for_configuration(SD, Some(Proofs::jwt(vec!["j".into()])));
    req.credential_response_encryption = Some(enc("ECDH-ES", "A128GCM"));
    let v = validate_credential_request(&req, &m, |_| None).unwrap();
    assert_eq!(v.credential_configuration_id, SD);
    assert_eq!(v.proofs, Some((PROOF_TYPE_JWT.to_string(), 1)));

    let code = |r: &CredentialRequest| {
        validate_credential_request(r, &m, |id| (id == "ds-1").then(|| SD.to_string()))
            .unwrap_err()
            .error
    };

    let mut by_id = req.clone();
    by_id.credential_configuration_id = None;
    by_id.credential_identifier = Some("ds-1".into());
    assert!(
        validate_credential_request(&by_id, &m, |id| (id == "ds-1").then(|| SD.to_string()))
            .is_ok()
    );
    by_id.credential_identifier = Some("ds-2".into());
    assert_eq!(
        code(&by_id),
        CredentialErrorCode::UnknownCredentialIdentifier
    );

    let mut both = req.clone();
    both.credential_identifier = Some("ds-1".into());
    assert_eq!(code(&both), CredentialErrorCode::InvalidCredentialRequest);

    let mut neither = req.clone();
    neither.credential_configuration_id = None;
    assert_eq!(
        code(&neither),
        CredentialErrorCode::InvalidCredentialRequest
    );

    let mut unknown = req;
    unknown.credential_configuration_id = Some("nope".into());
    assert_eq!(
        code(&unknown),
        CredentialErrorCode::UnknownCredentialConfiguration
    );
}

#[test]
fn validate_request_proofs() {
    let m = metadata();
    let code = |proofs: Option<Proofs>| {
        let mut r = build_credential_request_for_configuration(SD, proofs);
        r.credential_response_encryption = Some(enc("ECDH-ES", "A128GCM"));
        validate_credential_request(&r, &m, |_| None).map_err(|e| e.error)
    };
    // Missing while proof_types_supported is present.
    assert_eq!(code(None).unwrap_err(), CredentialErrorCode::InvalidProof);
    // Empty array, unsupported type, two types.
    assert_eq!(
        code(Some(Proofs::jwt(vec![]))).unwrap_err(),
        CredentialErrorCode::InvalidProof
    );
    assert_eq!(
        code(Some(Proofs::attestation("a".into()))).unwrap_err(),
        CredentialErrorCode::InvalidProof
    );
    let mut two = Proofs::jwt(vec!["a".into()]);
    two.di_vp = Some(vec![json!({})]);
    assert_eq!(
        code(Some(two)).unwrap_err(),
        CredentialErrorCode::InvalidProof
    );
    // Batch size 10 in the example metadata.
    assert!(code(Some(Proofs::jwt(vec!["a".into(); 10]))).is_ok());
    assert_eq!(
        code(Some(Proofs::jwt(vec!["a".into(); 11]))).unwrap_err(),
        CredentialErrorCode::InvalidProof
    );

    // Without batch_credential_issuance only one proof is allowed.
    let mut no_batch = metadata();
    no_batch.batch_credential_issuance = None;
    let mut r =
        build_credential_request_for_configuration(SD, Some(Proofs::jwt(vec!["a".into(); 2])));
    r.credential_response_encryption = Some(enc("ECDH-ES", "A128GCM"));
    assert_eq!(
        validate_credential_request(&r, &no_batch, |_| None)
            .unwrap_err()
            .error,
        CredentialErrorCode::InvalidProof
    );
}

#[test]
fn validate_request_encryption() {
    let m = metadata(); // encryption_required: true
    let code = |e: Option<CredentialResponseEncryption>| {
        let mut r =
            build_credential_request_for_configuration(SD, Some(Proofs::jwt(vec!["a".into()])));
        r.credential_response_encryption = e;
        validate_credential_request(&r, &m, |_| None).map_err(|e| e.error)
    };
    let bad = Err(CredentialErrorCode::InvalidEncryptionParameters);
    assert_eq!(code(None).map(|_| ()), bad);
    assert_eq!(code(Some(enc("RSA-OAEP", "A128GCM"))).map(|_| ()), bad);
    assert_eq!(code(Some(enc("ECDH-ES", "A256GCM"))).map(|_| ()), bad);
    let mut zip = enc("ECDH-ES", "A128GCM");
    zip.zip = Some("DEF".into());
    assert!(code(Some(zip.clone())).is_ok());
    zip.zip = Some("XYZ".into());
    assert_eq!(code(Some(zip)).map(|_| ()), bad);
    let mut private = enc("ECDH-ES", "A128GCM");
    private.jwk["d"] = json!("secret");
    assert_eq!(code(Some(private)).map(|_| ()), bad);
}

// ── Key proofs ──────────────────────────────────────────────────────────────

mod key_proofs {
    use super::*;
    use crate::proof::{DEFAULT_PROOF_ALGS, ProofPolicy, build_key_proof_jwt};
    use affinidi_oid4vc_core::eddsa::{EdDsaSigner, EdDsaVerifier};
    use affinidi_oid4vc_core::jwt::JwtVerifier;

    const ISSUER: &str = "https://credential-issuer.example.com";
    const NOW: i64 = 1_700_000_000;

    fn eddsa_config() -> CredentialConfiguration {
        let mut c = metadata().credential_configurations_supported[SD].clone();
        c.proof_types_supported.as_mut().unwrap().insert(
            PROOF_TYPE_JWT.into(),
            ProofTypeMetadata {
                proof_signing_alg_values_supported: vec!["EdDSA".into()],
                key_attestations_required: None,
                additional: Default::default(),
            },
        );
        c
    }

    fn setup(nonce: Option<&str>) -> (CredentialRequest, Vec<u8>) {
        let signer = EdDsaSigner::generate().with_kid("did:example:holder#key-1");
        let verifier = signer.public_key_bytes();
        let jwt = build_key_proof_jwt(&signer, ISSUER, nonce, NOW).unwrap();
        (
            build_credential_request_for_configuration(SD, Some(Proofs::jwt(vec![jwt]))),
            verifier,
        )
    }

    fn policy(nonce: Option<&str>) -> ProofPolicy<'_> {
        ProofPolicy {
            audience: ISSUER,
            nonce,
            now: NOW,
            max_age_secs: 300,
        }
    }

    /// Resolve every proof to the Ed25519 public key `pk`.
    fn resolver(
        pk: &[u8],
    ) -> impl FnMut(&crate::proof::KeyProof) -> Option<Box<dyn JwtVerifier>> + '_ {
        move |_| {
            EdDsaVerifier::from_bytes(pk)
                .ok()
                .map(|v| Box::new(v) as Box<dyn JwtVerifier>)
        }
    }

    #[test]
    fn verifies_and_maps_nonce_errors() {
        let (req, v) = setup(Some("n-1"));
        let proven = verify_jwt_proofs(
            &req,
            &eddsa_config(),
            resolver(&v),
            DEFAULT_PROOF_ALGS,
            &policy(Some("n-1")),
        )
        .unwrap();
        assert_eq!(proven.len(), 1);
        assert_eq!(proven[0].kid(), Some("did:example:holder#key-1"));

        // A stale/different c_nonce → invalid_nonce (fetch a new one).
        let e = verify_jwt_proofs(
            &req,
            &eddsa_config(),
            resolver(&v),
            DEFAULT_PROOF_ALGS,
            &policy(Some("n-2")),
        )
        .unwrap_err();
        assert_eq!(e.error, CredentialErrorCode::InvalidNonce);

        // No nonce in the proof while one was issued → invalid_proof.
        let (req, v) = setup(None);
        let e = verify_jwt_proofs(
            &req,
            &eddsa_config(),
            resolver(&v),
            DEFAULT_PROOF_ALGS,
            &policy(Some("n-1")),
        )
        .unwrap_err();
        assert_eq!(e.error, CredentialErrorCode::InvalidProof);
    }

    #[test]
    fn alg_must_be_advertised_by_the_configuration() {
        // The example configuration only allows ES256; an EdDSA proof fails.
        let (req, v) = setup(None);
        let config = metadata().credential_configurations_supported[SD].clone();
        let e = verify_jwt_proofs(
            &req,
            &config,
            resolver(&v),
            DEFAULT_PROOF_ALGS,
            &policy(None),
        )
        .unwrap_err();
        assert_eq!(e.error, CredentialErrorCode::InvalidProof);
    }

    #[test]
    fn unresolvable_key_and_wrong_signer_fail() {
        let (req, _) = setup(None);
        let e = verify_jwt_proofs(
            &req,
            &eddsa_config(),
            |_| None,
            DEFAULT_PROOF_ALGS,
            &policy(None),
        )
        .unwrap_err();
        assert_eq!(e.error, CredentialErrorCode::InvalidProof);

        let other = EdDsaSigner::generate().public_key_bytes();
        let e = verify_jwt_proofs(
            &req,
            &eddsa_config(),
            resolver(&other),
            DEFAULT_PROOF_ALGS,
            &policy(None),
        )
        .unwrap_err();
        assert_eq!(e.error, CredentialErrorCode::InvalidProof);
    }
}

// ── Notification / nonce / misc ─────────────────────────────────────────────

#[test]
fn notification_checks() {
    let req = build_notification_request("3fwe98js", NotificationEvent::CredentialDeleted, None);
    assert!(check_notification_request(&req, |id| id == "3fwe98js").is_ok());
    assert_eq!(
        check_notification_request(&req, |_| false)
            .unwrap_err()
            .error,
        NotificationErrorCode::InvalidNotificationId
    );
    let odd: NotificationRequest =
        serde_json::from_str(r#"{"notification_id": "3fwe98js", "event": "credential_lost"}"#)
            .unwrap();
    assert_eq!(
        check_notification_request(&odd, |_| true)
            .unwrap_err()
            .error,
        NotificationErrorCode::InvalidNotificationRequest
    );
}

#[test]
fn nonce_response_builder() {
    assert_eq!(
        serde_json::to_value(create_nonce_response("abc")).unwrap(),
        json!({"c_nonce": "abc"})
    );
}

#[test]
fn error_description_is_sanitized() {
    let e = CredentialErrorResponse::new(CredentialErrorCode::InvalidProof)
        .with_description("bad \"quote\" and \\ and é");
    assert_eq!(
        e.error_description.as_deref(),
        Some("bad ?quote? and ? and ?")
    );
    assert_eq!(e.to_string(), "invalid_proof: bad ?quote? and ? and ?");
}

#[test]
fn find_configuration_by_format() {
    let m = metadata();
    assert_eq!(
        find_credential_configuration(&m, FORMAT_DC_SD_JWT).map(|(k, _)| k.as_str()),
        Some(SD)
    );
    assert!(find_credential_configuration(&m, FORMAT_MSO_MDOC).is_none());
}

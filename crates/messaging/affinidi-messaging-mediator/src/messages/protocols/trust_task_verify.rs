//! The Trust Task acceptance checks that run before any handler.
//!
//! Every served task arrives type-erased (`TrustTask<Value>`) and is routed by
//! URI in [`super::trust_tasks::consume`], so the framework's typed
//! `consume_inbound` pipeline cannot be applied per handler. This module runs
//! the same §7.2 checks, in the same order, against the erased document:
//!
//! 1. **freshness** — `issuedAt` inside the acceptance window; a task whose spec
//!    requires a proof or `issuedAt` gets the consequential (5-minute) bound;
//! 2. **identity** — an in-band `issuer` must be the transport-authenticated
//!    sender, never someone else;
//! 3. **proof** — a present `proof` must verify against the issuer's DID
//!    document, with a key the issuer lists for `authentication` or
//!    `assertionMethod`;
//! 4. **spec policy** — the per-type presence rules (`proofRequired`,
//!    `issuedAtRequired`, `recipientRequired`) from the generated registry.
//!
//! Duplicate-execution (replay) protection is a separate, store-backed step.
//!
//! Whether a failed check refuses the task or only logs it is
//! [`TrustTaskVerification`]: `warn` during the transition while clients start
//! signing, `enforce` once they do.

use affinidi_data_integrity::crypto_suites::CryptoSuite;
use affinidi_data_integrity::{
    DataIntegrityError, ResolvedKey, VerificationMethodResolver, VerifyOptions,
};
use affinidi_did_common::DocumentExt;
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_encoding::ED25519_PUB;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_mediator_common::store::TrustTaskClaim;
use affinidi_secrets_resolver::secrets::KeyType;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use http::StatusCode;
use serde_json::Value;
use trust_tasks_proof::affinidi::parse_data_integrity_proof;
use trust_tasks_rs::{DEFAULT_MAX_AGE, FreshnessPolicy, SpecPolicy, TrustTask, document_digest};

use crate::SharedData;
use crate::common::config::TrustTaskVerification;
use crate::common::session::Session;
use crate::messages::protocols::trust_tasks::tt_problem;

/// Why a Trust Task failed acceptance. Each variant maps to one stable
/// problem-report code, so a client can tell a clock problem from a signing
/// problem without parsing prose (R3.7).
#[derive(Debug)]
pub(crate) enum Rejection {
    /// `issuedAt` missing where required, or outside the acceptance window.
    Stale(String),
    /// The in-band `issuer` is not the authenticated sender.
    IdentityMismatch { issuer: String, sender: String },
    /// The spec requires a proof and the document carries none.
    ProofRequired,
    /// A proof is present and does not verify.
    ProofInvalid(String),
    /// Any other per-spec presence rule (e.g. `issuedAt`, `recipient`).
    PolicyViolation(String),
    /// This exact document was already executed.
    Duplicate,
    /// A different document already executed under this `id`.
    IdConflict,
    /// The duplicate-execution record could not be consulted.
    RecordUnavailable(String),
}

impl Rejection {
    /// Stable problem-report code for this rejection.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Rejection::Stale(_) => "message.trust_task.stale",
            Rejection::IdentityMismatch { .. } => "message.trust_task.identity_mismatch",
            Rejection::ProofRequired => "message.trust_task.proof_required",
            Rejection::ProofInvalid(_) => "message.trust_task.proof_invalid",
            Rejection::PolicyViolation(_) => "message.trust_task.rejected",
            Rejection::Duplicate => "message.trust_task.duplicate",
            Rejection::IdConflict => "message.trust_task.id_conflict",
            Rejection::RecordUnavailable(_) => "message.trust_task.unavailable",
        }
    }

    /// HTTP-equivalent status for the problem report: a record that could not
    /// be consulted is retryable (503); everything else is a refusal (403).
    fn status(&self) -> StatusCode {
        match self {
            Rejection::RecordUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::FORBIDDEN,
        }
    }

    fn metric_reason(&self) -> &'static str {
        match self {
            Rejection::Stale(_) => "stale",
            Rejection::IdentityMismatch { .. } => "identity_mismatch",
            Rejection::ProofRequired => "proof_required",
            Rejection::ProofInvalid(_) => "proof_invalid",
            Rejection::PolicyViolation(_) => "policy",
            Rejection::Duplicate => "duplicate",
            Rejection::IdConflict => "id_conflict",
            Rejection::RecordUnavailable(_) => "record_unavailable",
        }
    }

    fn detail(&self) -> String {
        match self {
            Rejection::Stale(d) => format!("Trust Task is outside its acceptance window: {d}"),
            Rejection::IdentityMismatch { issuer, sender } => {
                format!("Trust Task issuer {issuer} is not the authenticated sender {sender}")
            }
            Rejection::ProofRequired => "this Trust Task type requires a proof".to_string(),
            Rejection::ProofInvalid(d) => format!("Trust Task proof did not verify: {d}"),
            Rejection::PolicyViolation(d) => format!("Trust Task violates its spec policy: {d}"),
            Rejection::Duplicate => "this Trust Task was already executed".to_string(),
            Rejection::IdConflict => {
                "a different Trust Task was already executed under this id".to_string()
            }
            Rejection::RecordUnavailable(d) => {
                format!("the duplicate-execution record is unavailable: {d}")
            }
        }
    }
}

/// Run the acceptance checks and apply the configured [`TrustTaskVerification`]
/// mode: `Enforce` turns a failure into a problem report; `Warn` logs it,
/// counts it, and lets the task through.
///
/// `sender_did` MUST be the transport-authenticated sender (DIDComm
/// authcrypt/JWS or TSP), exactly as for [`super::trust_tasks::consume`].
pub(crate) async fn accept(
    doc: &TrustTask<Value>,
    raw: &Value,
    policy: SpecPolicy,
    sender_did: &str,
    now: DateTime<Utc>,
    state: &SharedData,
    session: &Session,
) -> Result<(), MediatorError> {
    let mode = state.config.security.trust_task_verification;
    let resolver = SigningKeyResolver::new(state.did_resolver.clone());
    // The duplicate-execution claim runs last, and only once every other
    // check has passed: claiming first would burn the id of a document that
    // was then refused, so its corrected resend could never run.
    let outcome = match check(doc, raw, policy, sender_did, now, &resolver).await {
        Ok(()) => claim(doc, policy, sender_did, now, state).await,
        Err(rejection) => Err(rejection),
    };
    let Err(rejection) = outcome else {
        return Ok(());
    };

    let mode_label = match mode {
        TrustTaskVerification::Warn => "warn",
        TrustTaskVerification::Enforce => "enforce",
    };
    metrics::counter!(
        "trust_task_acceptance_failures_total",
        "reason" => rejection.metric_reason(),
        "mode" => mode_label,
    )
    .increment(1);

    match mode {
        TrustTaskVerification::Enforce => Err(tt_problem(
            session,
            rejection.code(),
            rejection.detail(),
            rejection.status(),
        )),
        TrustTaskVerification::Warn => {
            tracing::warn!(
                type_uri = %doc.type_uri,
                sender = sender_did,
                code = rejection.code(),
                "{} — accepted anyway (security.trust_task_verification = \"warn\"); \
                 this will be refused once it is \"enforce\"",
                rejection.detail()
            );
            Ok(())
        }
    }
}

/// The checks themselves, in §7.2 order. First failure wins.
///
/// `doc` is the parsed document; `raw` is the JSON exactly as received, which
/// is what the proof is verified over (see [`verify_proof`]).
pub(crate) async fn check(
    doc: &TrustTask<Value>,
    raw: &Value,
    policy: SpecPolicy,
    sender_did: &str,
    now: DateTime<Utc>,
    resolver: &SigningKeyResolver,
) -> Result<(), Rejection> {
    // 1. Freshness. A type whose spec requires a proof or `issuedAt` is
    //    consequential: it gets the bounded window and must carry `issuedAt`.
    let freshness = freshness_for(policy);
    doc.validate_freshness(now, &freshness)
        .map_err(|reason| Rejection::Stale(format!("{reason:?}")))?;

    // 2. Identity. The in-band issuer, when present, must be the sender the
    //    transport authenticated; an absent issuer is filled from the transport.
    if let Some(issuer) = doc.issuer.as_deref()
        && issuer != sender_did
    {
        return Err(Rejection::IdentityMismatch {
            issuer: issuer.to_string(),
            sender: sender_did.to_string(),
        });
    }

    // 3. Proof, when present. The verifier binds the proof's verification
    //    method to the in-band issuer; the resolver binds it to a signing role.
    if doc.proof.is_some() {
        verify_proof(raw, resolver)
            .await
            .map_err(Rejection::ProofInvalid)?;
    }

    // 4. Spec policy: presence rules. Runs after verification so a present but
    //    forged proof reports `proof_invalid`, not a presence problem.
    policy.enforce(doc).map_err(|reason| {
        if policy.is_proof_required && doc.proof.is_none() {
            Rejection::ProofRequired
        } else {
            Rejection::PolicyViolation(format!("{reason:?}"))
        }
    })?;

    Ok(())
}

/// A task is consequential when its spec requires a proof or `issuedAt`.
fn is_consequential(policy: SpecPolicy) -> bool {
    policy.is_proof_required || policy.is_issued_at_required
}

/// The acceptance window: bounded (5 minutes, `issuedAt` required) for a
/// consequential task, the framework default otherwise.
fn freshness_for(policy: SpecPolicy) -> FreshnessPolicy {
    if is_consequential(policy) {
        FreshnessPolicy::consequential()
    } else {
        FreshnessPolicy::default()
    }
}

/// Record a consequential task in the store's duplicate-execution record
/// (Trust Tasks §7.2 item 11). Reads are not recorded: running one twice
/// changes nothing.
///
/// The key is the **authenticated sender** plus the document `id`, hashed — a
/// party can only ever burn its own ids. The record is kept until the end of
/// the acceptance window: `issuedAt` + max age + skew, or `expiresAt` if that
/// is sooner. A later `expiresAt` buys nothing, because the freshness check
/// already refuses the document once the window closes — so a producer cannot
/// make the mediator hold a record for longer than that.
async fn claim(
    doc: &TrustTask<Value>,
    policy: SpecPolicy,
    sender_did: &str,
    now: DateTime<Utc>,
    state: &SharedData,
) -> Result<(), Rejection> {
    if !is_consequential(policy) {
        return Ok(());
    }
    let retain_until = retention_end(doc, policy, now);

    let digest = document_digest(doc)
        .map_err(|e| Rejection::PolicyViolation(format!("document digest: {e}")))?;
    let key = sha256::digest(format!("{sender_did}\n{}", doc.id));
    let verdict = state
        .database
        .trust_task_claim(
            &key,
            digest.as_str(),
            retain_until.timestamp().max(0) as u64,
            now.timestamp().max(0) as u64,
        )
        .await
        .map_err(|e| Rejection::RecordUnavailable(e.to_string()))?;
    match verdict {
        TrustTaskClaim::Fresh => Ok(()),
        TrustTaskClaim::Duplicate => Err(Rejection::Duplicate),
        TrustTaskClaim::Conflict => Err(Rejection::IdConflict),
    }
}

/// Until when the duplicate-execution record for `doc` must be kept: the end
/// of its acceptance window, or its `expiresAt` if that comes first.
fn retention_end(doc: &TrustTask<Value>, policy: SpecPolicy, now: DateTime<Utc>) -> DateTime<Utc> {
    let freshness = freshness_for(policy);
    let window_end = doc.issued_at.unwrap_or(now)
        + freshness.max_age.unwrap_or(DEFAULT_MAX_AGE)
        + freshness.skew;
    freshness
        .record_expiry(doc, now)
        .map_or(window_end, |expiry| expiry.min(window_end))
}

/// Verify a document's Data Integrity proof over the document **as received**.
///
/// `trust_tasks_proof::affinidi::Verifier` re-serialises the parsed
/// `TrustTask` and verifies over that, so anything the round trip normalises —
/// `issuedAt` written as `+00:00` rather than `Z`, a different number of
/// fractional-second digits, a member the struct does not keep — changes the
/// bytes under the signature and a genuine proof fails. Verifying the received
/// JSON (minus `proof`) is what the signer actually signed.
///
/// The proof's verification method must belong to the in-band `issuer` (the
/// §4.7/§4.8 binding), and only the `eddsa` suites are accepted.
async fn verify_proof(raw: &Value, resolver: &SigningKeyResolver) -> Result<(), String> {
    let obj = raw
        .as_object()
        .ok_or("Trust Task document is not a JSON object")?;
    let proof = parse_data_integrity_proof(obj.get("proof").ok_or("no proof member")?)
        .map_err(|e| e.to_string())?;

    let issuer = obj
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or("document carries a proof but no in-band issuer to bind it to")?;
    let vm_did = proof
        .verification_method
        .split('#')
        .next()
        .unwrap_or(&proof.verification_method);
    if vm_did != issuer {
        return Err(format!(
            "verificationMethod is controlled by {vm_did}, not the document issuer {issuer}"
        ));
    }

    let mut unsigned = obj.clone();
    unsigned.remove("proof");
    let options = VerifyOptions::new()
        .with_allowed_suites(vec![CryptoSuite::EddsaJcs2022, CryptoSuite::EddsaRdfc2022]);
    proof
        .verify(&Value::Object(unsigned), resolver, options)
        .await
        .map_err(|e| e.to_string())
}

impl SigningKeyResolver {
    /// A resolver over the mediator's DID cache.
    pub(crate) fn new(resolver: DIDCacheClient) -> Self {
        Self { resolver }
    }
}

/// Resolves a proof's verification method to an Ed25519 public key — but only
/// one its DID document lists under `authentication` or `assertionMethod`.
///
/// The stock `CachedDidResolver` accepts any verification method in the
/// document, including one listed only under `keyAgreement`, and reads only
/// Multikey `publicKeyMultibase`. A `did:web` admin that publishes JWK keys
/// could not be verified at all, and a key never meant for signing could sign.
/// `did:peer:2` profiles usually list their Ed25519 key under
/// `authentication` alone, so that relationship is accepted as well.
pub(crate) struct SigningKeyResolver {
    resolver: DIDCacheClient,
}

#[async_trait]
impl VerificationMethodResolver for SigningKeyResolver {
    async fn resolve_vm(&self, vm: &str) -> Result<ResolvedKey, DataIntegrityError> {
        let did = vm.split('#').next().unwrap_or(vm);
        let doc = self
            .resolver
            .resolve(did)
            .await
            .map_err(|e| DataIntegrityError::Resolver(format!("resolve {did}: {e}")))?
            .doc;

        // A relationship may reference the method by absolute or relative id.
        let fragment = vm.find('#').map(|i| &vm[i..]);
        let listed =
            |id: &str| doc.contains_authentication(id) || doc.contains_assertion_method(id);
        if !(listed(vm) || fragment.is_some_and(listed)) {
            return Err(DataIntegrityError::Resolver(format!(
                "{vm} is not an authentication or assertionMethod key of {did}"
            )));
        }

        let method = doc
            .get_verification_method(vm)
            .or_else(|| fragment.and_then(|f| doc.get_verification_method(f)))
            .ok_or_else(|| {
                DataIntegrityError::Resolver(format!("{vm} is not in the DID document of {did}"))
            })?;
        let (codec, bytes) = method
            .decode_public_key()
            .map_err(|e| DataIntegrityError::Resolver(format!("{vm}: {e}")))?;
        if codec != ED25519_PUB {
            return Err(DataIntegrityError::Resolver(format!(
                "{vm} is not an Ed25519 key (multicodec 0x{codec:x})"
            )));
        }
        Ok(ResolvedKey::new(KeyType::Ed25519, bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
    use affinidi_secrets_resolver::secrets::Secret;
    use chrono::TimeDelta;
    use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};

    const ACCOUNT_UPDATE: &str = "https://trusttasks.org/spec/messaging/account/update/0.1";
    const ACCOUNT_GET: &str = "https://trusttasks.org/spec/messaging/account/get/0.1";
    const MEDIATOR: &str = "did:web:mediator.example";

    /// An Ed25519 `did:key` and its secret, keyed by the DID's own
    /// verification method (listed under both authentication and
    /// assertionMethod in a did:key document).
    fn did_key() -> (String, Secret) {
        let seed = [9u8; 32];
        let mb = Secret::generate_ed25519(None, Some(&seed))
            .get_public_keymultibase()
            .unwrap();
        let did = format!("did:key:{mb}");
        let secret = Secret::generate_ed25519(Some(&format!("{did}#{mb}")), Some(&seed));
        (did, secret)
    }

    fn doc_json(type_uri: &str, issuer: &str, issued_at: Option<DateTime<Utc>>) -> Value {
        let mut doc = serde_json::json!({
            "id": "urn:uuid:5b1e0a1e-0000-4000-8000-000000000001",
            "type": type_uri,
            "issuer": issuer,
            "recipient": MEDIATOR,
            "payload": { "did": "abc", "accountType": "admin" },
        });
        if let Some(at) = issued_at {
            doc["issuedAt"] = Value::String(at.to_rfc3339());
        }
        doc
    }

    async fn signed(doc: Value, secret: &Secret) -> Value {
        sign_trust_task(&doc, secret, SignOptions::new())
            .await
            .unwrap()
    }

    fn policy_of(doc: &Value) -> SpecPolicy {
        use trust_tasks_rs::specs::messaging::account;
        match doc["type"].as_str().unwrap() {
            ACCOUNT_UPDATE => SpecPolicy::of::<account::update::v0_1::Payload>(),
            ACCOUNT_GET => SpecPolicy::of::<account::get::v0_1::Payload>(),
            other => panic!("no test policy for {other}"),
        }
    }

    async fn run(doc: Value, sender: &str) -> Result<(), Rejection> {
        let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();
        let parsed: TrustTask<Value> = serde_json::from_value(doc.clone()).unwrap();
        check(
            &parsed,
            &doc,
            policy_of(&doc),
            sender,
            Utc::now(),
            &SigningKeyResolver::new(resolver),
        )
        .await
    }

    fn account_update_policy() -> SpecPolicy {
        SpecPolicy::of::<trust_tasks_rs::specs::messaging::account::update::v0_1::Payload>()
    }

    #[test]
    fn a_far_expires_at_cannot_stretch_the_replay_record() {
        // A producer's `expiresAt` a year out must not make the mediator keep
        // the record a year: freshness refuses the document after the window.
        let (did, _) = did_key();
        let now = Utc::now();
        let mut doc = doc_json(ACCOUNT_UPDATE, &did, Some(now));
        doc["expiresAt"] = Value::String((now + TimeDelta::days(365)).to_rfc3339());
        let doc: TrustTask<Value> = serde_json::from_value(doc).unwrap();
        let end = retention_end(&doc, account_update_policy(), now);
        assert!(end <= now + TimeDelta::minutes(10), "retained until {end}");
        assert!(
            end >= now + TimeDelta::minutes(5),
            "window must be covered: {end}"
        );
    }

    #[test]
    fn a_near_expires_at_shortens_the_replay_record() {
        let (did, _) = did_key();
        let now = Utc::now();
        let mut doc = doc_json(ACCOUNT_UPDATE, &did, Some(now));
        let soon = now + TimeDelta::seconds(30);
        doc["expiresAt"] = Value::String(soon.to_rfc3339());
        let doc: TrustTask<Value> = serde_json::from_value(doc).unwrap();
        let end = retention_end(&doc, account_update_policy(), now);
        assert_eq!(end.timestamp(), soon.timestamp());
    }

    #[tokio::test]
    async fn a_signed_fresh_task_from_its_issuer_is_accepted() {
        let (did, secret) = did_key();
        let doc = signed(doc_json(ACCOUNT_UPDATE, &did, Some(Utc::now())), &secret).await;
        let result = run(doc, &did).await;
        assert!(result.is_ok(), "{result:?}");
    }

    #[tokio::test]
    async fn a_proof_verifies_over_the_bytes_as_sent_not_as_reparsed() {
        // `issuedAt` in `+00:00` form re-serialises as `Z`. A verifier that
        // checks the re-serialised document would fail this genuine proof.
        let (did, secret) = did_key();
        let mut doc = doc_json(ACCOUNT_UPDATE, &did, None);
        doc["issuedAt"] =
            Value::String(Utc::now().format("%Y-%m-%dT%H:%M:%S%.3f+00:00").to_string());
        let doc = signed(doc, &secret).await;
        let result = run(doc, &did).await;
        assert!(result.is_ok(), "{result:?}");
    }

    #[tokio::test]
    async fn an_unsigned_proof_required_task_is_proof_required() {
        let (did, _) = did_key();
        let doc = doc_json(ACCOUNT_UPDATE, &did, Some(Utc::now()));
        assert!(matches!(
            run(doc, &did).await,
            Err(Rejection::ProofRequired)
        ));
    }

    #[tokio::test]
    async fn a_task_that_does_not_require_a_proof_passes_unsigned() {
        // account/get requires a recipient but no proof.
        let (did, _) = did_key();
        let doc = doc_json(ACCOUNT_GET, &did, None);
        assert!(run(doc, &did).await.is_ok());
    }

    #[tokio::test]
    async fn a_consequential_task_without_issued_at_is_stale() {
        let (did, secret) = did_key();
        let doc = signed(doc_json(ACCOUNT_UPDATE, &did, None), &secret).await;
        assert!(matches!(run(doc, &did).await, Err(Rejection::Stale(_))));
    }

    #[tokio::test]
    async fn an_old_consequential_task_is_stale() {
        let (did, secret) = did_key();
        let an_hour_ago = Utc::now() - TimeDelta::hours(1);
        let doc = signed(doc_json(ACCOUNT_UPDATE, &did, Some(an_hour_ago)), &secret).await;
        assert!(matches!(run(doc, &did).await, Err(Rejection::Stale(_))));
    }

    #[tokio::test]
    async fn an_issuer_that_is_not_the_sender_is_refused() {
        // A validly signed document relayed by someone else is still refused:
        // authority is the sender's, not whoever's proof is attached.
        let (did, secret) = did_key();
        let doc = signed(doc_json(ACCOUNT_UPDATE, &did, Some(Utc::now())), &secret).await;
        assert!(matches!(
            run(doc, "did:web:someone-else.example").await,
            Err(Rejection::IdentityMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn a_tampered_payload_is_proof_invalid() {
        let (did, secret) = did_key();
        let mut doc = signed(doc_json(ACCOUNT_UPDATE, &did, Some(Utc::now())), &secret).await;
        doc["payload"]["accountType"] = Value::String("rootAdmin".into());
        assert!(matches!(
            run(doc, &did).await,
            Err(Rejection::ProofInvalid(_))
        ));
    }

    #[tokio::test]
    async fn a_key_agreement_key_cannot_sign() {
        // The did:key document's X25519 key is listed only under keyAgreement.
        // Point the proof at it: the resolver must refuse before any signature
        // check, because that key is not a signing key of the issuer.
        let (did, secret) = did_key();
        let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();
        let ka = resolver.resolve(&did).await.unwrap().doc;
        let ka_kid = ka.find_key_agreement(None)[0].to_string();
        let err = SigningKeyResolver { resolver }
            .resolve_vm(&ka_kid)
            .await
            .expect_err("a keyAgreement key must not resolve as a signing key");
        assert!(
            err.to_string()
                .contains("not an authentication or assertionMethod key")
        );
        // …and the ordinary signing key still resolves.
        let _ = secret;
        let _ = did;
    }
}

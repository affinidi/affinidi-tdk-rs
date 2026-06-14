/*!
 * Credential scenario fixture (TI5).
 *
 * [`CredentialScenario`] stands up an **issuer**, a **holder**, and a
 * **verifier** — each a deterministic `did:key` Ed25519 identity — plus an
 * in-memory revocation [`BitstringStatusList`] and a [`StaticResolver`]
 * pre-populated with the three parties' DID documents. It gives the SD-JWT VC
 * flow a home as an end-to-end test (`issue → present → verify`) rather than
 * isolated crypto calls, and is the landing spot for the W4/W5 negatives:
 * status-list revocation, holder-binding failure, and a disallowed `alg`.
 *
 * The workspace SD-JWT crate ships only an HMAC test signer, so this module
 * provides [`Ed25519Signer`] / [`Ed25519Verifier`] — real asymmetric JWS
 * sign/verify keyed on each party's `did:key`. The verifier enforces an
 * **algorithm allowlist** before checking the signature (the W5 principle
 * applied in the credential context), which is what makes the disallowed-`alg`
 * negative expressible.
 *
 * ```
 * use affinidi_tdk_test_support::credential_scenario::CredentialScenario;
 * use serde_json::json;
 *
 * let scenario = CredentialScenario::new();
 * let vc = scenario
 *     .issue_sd_jwt_vc(
 *         "https://example.com/IdentityCredential",
 *         &json!({ "given_name": "Alice", "email": "alice@example.com" }),
 *         &json!({ "_sd": ["given_name", "email"] }),
 *     )
 *     .unwrap();
 *
 * let presentation = scenario
 *     .present(&vc, &["given_name"], scenario.verifier.did(), "nonce-1")
 *     .unwrap();
 * let result = scenario
 *     .verify(&presentation, scenario.verifier.did(), "nonce-1")
 *     .unwrap();
 * assert!(result.is_verified());
 * ```
 */

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{Value, json};

use affinidi_crypto::did_key::ed25519_pub_to_did_key;
use affinidi_did_common::DID;
use affinidi_mdoc::{
    cose::CoseSigner,
    cose_key::CoseKey,
    eddsa_cose::{EdDsaCoseSigner, EdDsaCoseVerifier},
    error::Result as MdocResult,
};
use affinidi_sd_jwt::{
    SdJwt, SdJwtError,
    hasher::Sha256Hasher,
    holder::{self, KbJwtInput, select_disclosures},
    signer::{JwtSigner, JwtVerifier},
    verifier::{self, VerificationOptions, VerificationResult},
};
use affinidi_status_list::bitstring::{BitstringStatusList, StatusPurpose};
use affinidi_vc::sd_jwt_vc::{self, SdJwtVc};
use coset::iana::Algorithm as CoseAlgorithm;

use crate::resolver::StaticResolver;

/// Errors from the credential scenario fixture.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ScenarioError {
    /// An sd-jwt-vc issuance call failed.
    #[error("sd-jwt-vc: {0}")]
    SdJwtVc(String),

    /// An sd-jwt present/verify call failed.
    #[error("sd-jwt: {0}")]
    SdJwt(String),

    /// A status-list operation failed.
    #[error("status list: {0}")]
    Status(String),

    /// An mdoc issue/present/verify call failed.
    #[error("mdoc: {0}")]
    Mdoc(String),

    /// An OID4VP envelope (request/response) operation failed.
    #[error("oid4vp: {0}")]
    Oid4vp(String),

    /// A `did:key` failed to parse or resolve while building the resolver.
    #[error("did: {0}")]
    Did(String),
}

/// EdDSA (Ed25519) implementation of sd-jwt's [`JwtSigner`].
///
/// The emitted header `alg` is configurable ([`with_alg`](Self::with_alg)) so a
/// test can forge a mismatched algorithm and confirm an allowlisting verifier
/// rejects it before checking the signature.
pub struct Ed25519Signer {
    key: SigningKey,
    alg: String,
    kid: Option<String>,
}

impl Ed25519Signer {
    /// A signer emitting `alg: EdDSA`.
    pub fn new(key: SigningKey, kid: Option<String>) -> Self {
        Self {
            key,
            alg: "EdDSA".to_string(),
            kid,
        }
    }

    /// Override the header `alg` (the signature is still Ed25519). Use this to
    /// build a credential whose declared algorithm a verifier should reject.
    pub fn with_alg(mut self, alg: impl Into<String>) -> Self {
        self.alg = alg.into();
        self
    }
}

impl JwtSigner for Ed25519Signer {
    fn algorithm(&self) -> &str {
        &self.alg
    }

    fn key_id(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    fn sign_jwt(&self, header: &Value, payload: &Value) -> Result<String, SdJwtError> {
        // Own the alg/kid header fields so the emitted JWS always matches this
        // signer (the caller's header is otherwise respected).
        let mut header = header.clone();
        if let Some(obj) = header.as_object_mut() {
            obj.insert("alg".to_string(), Value::String(self.alg.clone()));
            if let Some(kid) = &self.kid {
                obj.insert("kid".to_string(), Value::String(kid.clone()));
            }
        }
        let h = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&header)
                .map_err(|e| SdJwtError::Verification(format!("header encode: {e}")))?,
        );
        let p = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(payload)
                .map_err(|e| SdJwtError::Verification(format!("payload encode: {e}")))?,
        );
        let signing_input = format!("{h}.{p}");
        let signature: Signature = self.key.sign(signing_input.as_bytes());
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }
}

/// EdDSA (Ed25519) implementation of sd-jwt's [`JwtVerifier`], with an
/// **algorithm allowlist**: the header `alg` must be in the allowed set or the
/// JWS is rejected *before* the signature is checked.
pub struct Ed25519Verifier {
    key: VerifyingKey,
    allowed_algs: Vec<String>,
}

impl Ed25519Verifier {
    /// A verifier for `key` that accepts only the listed `alg` values.
    pub fn new(key: VerifyingKey, allowed_algs: &[&str]) -> Self {
        Self {
            key,
            allowed_algs: allowed_algs.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl JwtVerifier for Ed25519Verifier {
    fn verify_jwt(&self, jws: &str) -> Result<Value, SdJwtError> {
        let decode = |part: &str, what: &str| {
            URL_SAFE_NO_PAD
                .decode(part)
                .map_err(|e| SdJwtError::Verification(format!("{what} base64: {e}")))
        };

        let parts: Vec<&str> = jws.splitn(3, '.').collect();
        if parts.len() != 3 {
            return Err(SdJwtError::Verification(
                "JWS must have 3 dot-separated parts".to_string(),
            ));
        }

        let header: Value = serde_json::from_slice(&decode(parts[0], "header")?)
            .map_err(|e| SdJwtError::Verification(format!("header json: {e}")))?;
        let alg = header
            .get("alg")
            .and_then(Value::as_str)
            .ok_or_else(|| SdJwtError::Verification("missing alg in JWS header".to_string()))?;
        if !self.allowed_algs.iter().any(|a| a == alg) {
            return Err(SdJwtError::Verification(format!(
                "JWS alg {alg:?} is not in the allowed set {:?}",
                self.allowed_algs
            )));
        }

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = decode(parts[2], "signature")?;
        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|e| SdJwtError::Verification(format!("signature bytes: {e}")))?;
        self.key
            .verify_strict(signing_input.as_bytes(), &signature)
            .map_err(|_| SdJwtError::Verification("signature verification failed".to_string()))?;

        serde_json::from_slice(&decode(parts[1], "payload")?)
            .map_err(|e| SdJwtError::Verification(format!("payload json: {e}")))
    }
}

/// A COSE signer that signs with an Ed25519 key but declares a caller-chosen
/// algorithm in the protected header. The mdoc analogue of
/// [`Ed25519Signer::with_alg`]: it lets a test forge an `issuerAuth` whose
/// declared `alg` an allowlisting verifier should reject before checking the
/// (otherwise valid) signature.
pub struct ForgedAlgCoseSigner {
    key: SigningKey,
    alg: CoseAlgorithm,
}

impl CoseSigner for ForgedAlgCoseSigner {
    fn algorithm(&self) -> CoseAlgorithm {
        self.alg
    }

    fn sign(&self, data: &[u8]) -> MdocResult<Vec<u8>> {
        Ok(self.key.sign(data).to_bytes().to_vec())
    }
}

/// One party in a [`CredentialScenario`] — a deterministic Ed25519 `did:key`.
pub struct Party {
    did: String,
    key: SigningKey,
}

impl Party {
    fn from_seed(seed: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&seed);
        let did = ed25519_pub_to_did_key(&key.verifying_key().to_bytes());
        Self { did, key }
    }

    /// This party's `did:key`.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// This party's public key as an OKP/Ed25519 JWK value (for the SD-JWT VC
    /// `cnf` holder-binding claim).
    pub fn public_jwk(&self) -> Value {
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(self.key.verifying_key().to_bytes()),
        })
    }

    /// An `EdDSA` signer for this party, with `kid` = its DID.
    pub fn signer(&self) -> Ed25519Signer {
        Ed25519Signer::new(self.key.clone(), Some(self.did.clone()))
    }

    /// A verifier for this party's key, accepting only `allowed_algs`.
    pub fn verifier(&self, allowed_algs: &[&str]) -> Ed25519Verifier {
        Ed25519Verifier::new(self.key.verifying_key(), allowed_algs)
    }

    /// An `EdDSA` COSE signer for this party (the mdoc issuer / device signer),
    /// with `kid` = its DID.
    pub fn cose_signer(&self) -> EdDsaCoseSigner {
        EdDsaCoseSigner::from_bytes(&self.key.to_bytes())
            .expect("32-byte Ed25519 key is valid")
            .with_kid(self.did.clone().into_bytes())
    }

    /// An `EdDSA` COSE verifier for this party's key.
    pub fn cose_verifier(&self) -> EdDsaCoseVerifier {
        EdDsaCoseVerifier::from_bytes(&self.key.verifying_key().to_bytes())
            .expect("32-byte Ed25519 public key is valid")
    }

    /// A COSE signer that signs with this party's key but declares `alg` in the
    /// protected header — for the disallowed-`alg` mdoc negative.
    pub fn cose_signer_with_alg(&self, alg: CoseAlgorithm) -> ForgedAlgCoseSigner {
        ForgedAlgCoseSigner {
            key: self.key.clone(),
            alg,
        }
    }

    /// This party's public key as an mdoc device `COSE_Key` (OKP/Ed25519), for
    /// the MSO `deviceKeyInfo` holder-binding slot.
    pub fn device_cose_key(&self) -> ciborium::Value {
        CoseKey::new_ed25519(self.key.verifying_key().to_bytes().to_vec())
            .expect("32-byte Ed25519 public key is a valid COSE_Key")
            .to_cbor_value()
    }
}

/// Issuer / holder / verifier identities, an in-memory revocation status list,
/// and a [`StaticResolver`] that resolves all three DIDs — the home for SD-JWT
/// VC end-to-end tests and their negatives.
pub struct CredentialScenario {
    /// Issues credentials (signs the SD-JWT).
    pub issuer: Party,
    /// Holds credentials and signs the KB-JWT at presentation.
    pub holder: Party,
    /// Receives presentations; its DID is the KB-JWT audience.
    pub verifier: Party,
    status_list: BitstringStatusList,
    resolver: StaticResolver,
    hasher: Sha256Hasher,
}

impl Default for CredentialScenario {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialScenario {
    /// Build a scenario with deterministic default identities.
    pub fn new() -> Self {
        Self::with_seed(0xA5)
    }

    /// Build a scenario whose three identities derive deterministically from
    /// `seed` (distinct per party) — same seed, same DIDs and keys across runs.
    pub fn with_seed(seed: u8) -> Self {
        let issuer = Party::from_seed(party_seed(seed, 1));
        let holder = Party::from_seed(party_seed(seed, 2));
        let verifier = Party::from_seed(party_seed(seed, 3));
        let resolver = build_resolver(&[&issuer, &holder, &verifier])
            .expect("did:key identities resolve locally");
        Self {
            issuer,
            holder,
            verifier,
            status_list: BitstringStatusList::with_default_size(StatusPurpose::Revocation),
            resolver,
            hasher: Sha256Hasher,
        }
    }

    /// The resolver pre-populated with the issuer/holder/verifier DID documents.
    pub fn resolver(&self) -> &StaticResolver {
        &self.resolver
    }

    /// Reserve a status-list index for a credential.
    pub fn allocate_status(&mut self) -> usize {
        self.status_list
            .allocate_index()
            .expect("status list has capacity")
    }

    /// Mark the credential at `index` revoked.
    pub fn revoke(&mut self, index: usize) -> Result<(), ScenarioError> {
        self.status_list
            .set(index, true)
            .map_err(|e| ScenarioError::Status(e.to_string()))
    }

    /// Whether the credential at `index` is revoked.
    pub fn is_revoked(&self, index: usize) -> Result<bool, ScenarioError> {
        self.status_list
            .get(index)
            .map_err(|e| ScenarioError::Status(e.to_string()))
    }

    /// Issue an SD-JWT VC signed by the issuer and bound to the holder's key
    /// (`cnf`). `disclosure_frame` selects which claims are selectively
    /// disclosable (e.g. `{"_sd": ["given_name", "email"]}`).
    pub fn issue_sd_jwt_vc(
        &self,
        vct: &str,
        claims: &Value,
        disclosure_frame: &Value,
    ) -> Result<SdJwtVc, ScenarioError> {
        self.issue_sd_jwt_vc_with_signer(&self.issuer.signer(), vct, claims, disclosure_frame)
    }

    /// Issue with a caller-supplied issuer signer — e.g. a forged-`alg` signer
    /// (`self.issuer.signer().with_alg("ES256")`) for the disallowed-`alg`
    /// negative.
    pub fn issue_sd_jwt_vc_with_signer(
        &self,
        signer: &dyn JwtSigner,
        vct: &str,
        claims: &Value,
        disclosure_frame: &Value,
    ) -> Result<SdJwtVc, ScenarioError> {
        let holder_jwk = self.holder.public_jwk();
        sd_jwt_vc::issue(
            vct,
            self.issuer.did(),
            Some(self.holder.did()),
            claims,
            disclosure_frame,
            signer,
            &self.hasher,
            Some(&holder_jwk),
            now(),
            None,
        )
        .map_err(|e| ScenarioError::SdJwtVc(e.to_string()))
    }

    /// Holder presents `vc`, revealing only the `reveal` claims and signing a
    /// KB-JWT bound to `(audience, nonce)`.
    pub fn present(
        &self,
        vc: &SdJwtVc,
        reveal: &[&str],
        audience: &str,
        nonce: &str,
    ) -> Result<SdJwt, ScenarioError> {
        let revealed = select_disclosures(&vc.sd_jwt, reveal);
        let holder_signer = self.holder.signer();
        let kb = KbJwtInput {
            audience,
            nonce,
            signer: &holder_signer,
            iat: now(),
        };
        holder::present(&vc.sd_jwt, &revealed, Some(&kb), &self.hasher)
            .map_err(|e| ScenarioError::SdJwt(e.to_string()))
    }

    /// Verify a presentation with the default issuer/holder verifiers (both
    /// accepting only `EdDSA`) and KB-JWT binding to `(audience, nonce)`.
    pub fn verify(
        &self,
        presentation: &SdJwt,
        audience: &str,
        nonce: &str,
    ) -> Result<VerificationResult, ScenarioError> {
        self.verify_with(
            presentation,
            &self.issuer.verifier(&["EdDSA"]),
            &self.holder.verifier(&["EdDSA"]),
            audience,
            nonce,
        )
    }

    /// Verify with caller-supplied verifiers — for negatives such as a holder
    /// verifier built from the wrong key, or an issuer verifier with a
    /// restricted `alg` allowlist.
    pub fn verify_with(
        &self,
        presentation: &SdJwt,
        issuer_verifier: &dyn JwtVerifier,
        holder_verifier: &dyn JwtVerifier,
        audience: &str,
        nonce: &str,
    ) -> Result<VerificationResult, ScenarioError> {
        let options = VerificationOptions {
            verify_kb: true,
            expected_audience: Some(audience),
            expected_nonce: Some(nonce),
        };
        verifier::verify(
            presentation,
            issuer_verifier,
            &self.hasher,
            &options,
            Some(holder_verifier),
        )
        .map_err(|e| ScenarioError::SdJwt(e.to_string()))
    }
}

/// Distinct deterministic 32-byte seed per party (`which` = 1/2/3).
fn party_seed(seed: u8, which: u8) -> [u8; 32] {
    let mut bytes = [seed; 32];
    bytes[0] = which;
    bytes
}

/// Resolve each party's `did:key` to a real DID document and register it.
fn build_resolver(parties: &[&Party]) -> Result<StaticResolver, ScenarioError> {
    let mut resolver = StaticResolver::new().with_name("CredentialScenario");
    for party in parties {
        let did: DID = party
            .did()
            .parse()
            .map_err(|e| ScenarioError::Did(format!("{e:?}")))?;
        let document = did
            .resolve()
            .map_err(|e| ScenarioError::Did(format!("{e:?}")))?;
        resolver = resolver.resolves(party.did().to_string(), document);
    }
    Ok(resolver)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/*!
W3C Data Integrity — sign and verify [Data Integrity Proofs] for
Verifiable Credentials, DID documents, and arbitrary JSON documents.

# Quickstart — sign and verify

```no_run
use affinidi_data_integrity::{DataIntegrityProof, SignOptions, VerifyOptions};
use affinidi_secrets_resolver::secrets::Secret;
use serde_json::json;

# async fn demo() -> Result<(), affinidi_data_integrity::DataIntegrityError> {
let secret = Secret::generate_ed25519(Some("did:key:z6Mk...#key-0"), None);
let doc = json!({ "name": "Alice" });

// Sign — the library picks `eddsa-jcs-2022` automatically via
// Signer::cryptosuite() because `secret` is an Ed25519 key.
let proof = DataIntegrityProof::sign(&doc, &secret, SignOptions::new()).await?;

// Verify — pass the raw public-key bytes.
proof.verify_with_public_key(&doc, secret.get_public_bytes(), VerifyOptions::new())?;
# Ok(()) }
```

# Post-quantum cryptography

Enable the `post-quantum` feature (off by default) to sign with
ML-DSA-44 or SLH-DSA-SHA2-128s:

```ignore
[dependencies]
affinidi-data-integrity = { version = "0.5", features = ["post-quantum"] }
```

Then generate a PQC key — the library selects `mldsa44-jcs-2024` or
`slhdsa128-jcs-2024` automatically from the key type.

# Cryptosuites

See [`crypto_suites::CryptoSuite`] for the full list. Each suite has a
canonicalization (JCS or RDFC), a signing algorithm, and a
[`compatible_key_types`] list. Callers rarely need to pick a suite
directly — [`Signer::cryptosuite`] provides a sensible default per key
type, and `SignOptions::with_cryptosuite` is the escape hatch for
explicit selection (e.g. forcing RDFC).

# Forward compatibility

All public enums (`KeyType`, [`CryptoSuite`], [`DataIntegrityError`])
are `#[non_exhaustive]`. Future algorithms and error variants arrive in
minor releases without breaking callers that include a `_ =>` arm.

# Out of scope

This crate implements W3C Data Integrity only. JOSE / JWS / COSE
post-quantum profiles are being standardised separately by IETF and
will live in sibling crates (`affinidi-data-integrity-jose`,
`-cose`) when those drafts stabilise.

[Data Integrity Proofs]: https://www.w3.org/TR/vc-data-integrity/
[`compatible_key_types`]: crate::crypto_suites::CryptoSuite::compatible_key_types
[`CryptoSuite`]: crate::crypto_suites::CryptoSuite
[`Signer::cryptosuite`]: crate::signer::Signer::cryptosuite
*/

use chrono::{DateTime, Utc};
use crypto_suites::CryptoSuite;
use multibase::Base;
use serde::{Deserialize, Serialize};
use serde_json_canonicalizer::to_string;
use sha2::{Digest, Sha256};
use signer::Signer;
use tracing::debug;

pub mod caching_signer;
pub mod conformance;
pub mod crypto_suites;
mod date_time;
pub mod did_vm;
pub mod error;
pub mod multi;
pub mod options;
pub mod signer;
pub mod suite_ops;
pub mod verification_proof;

pub use caching_signer::{CachingSigner, GetPrivateBytes};
pub use conformance::{verify_conformance, verify_conformance_with_skew};
pub use did_vm::{DidKeyResolver, ResolvedKey, VerificationMethodResolver};
pub use multi::{MultiVerifyResult, VerifyPolicy, verify_multi};

/// **Deprecated** — the legacy affinidi-internal `bbs-2023` encoding (not
/// interoperable with other vc-di-bbs implementations). Use
/// [`bbs_2023_transform`] instead. Enabled via the `bbs-2023` feature flag.
#[cfg(feature = "bbs-2023")]
pub mod bbs_2023;

/// W3C vc-di-bbs `bbs-2023` cryptosuite (RDF-canonical, standards-interoperable)
/// — **the** `bbs-2023` implementation. Pinned byte-for-byte to the official
/// `w3c/vc-di-bbs` vectors: issuer ([`bbs_2023_transform::sign_base_document`]),
/// holder ([`bbs_2023_transform::create_derived_proof`]), verifier
/// ([`bbs_2023_transform::verify_derived_proof`]), plus per-verifier pseudonym /
/// holder binding. Supersedes the legacy [`bbs_2023`] module.
#[cfg(feature = "bbs-2023")]
pub mod bbs_2023_transform;

pub use error::{DataIntegrityError, SignatureFailure};
pub use options::{DEFAULT_CLOCK_SKEW, SignOptions, VerifyOptions};

/// Serialized Data Integrity proof.
///
/// `#[non_exhaustive]`: produce via [`DataIntegrityProof::sign`] or
/// [`DataIntegrityProof::new`] rather than a struct literal. Fields stay public
/// for reads.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct DataIntegrityProof {
    /// Must be 'DataIntegrityProof'
    #[serde(rename = "type")]
    pub type_: String,

    pub cryptosuite: CryptoSuite,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    pub verification_method: String,

    pub proof_purpose: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_value: Option<String>,

    /// The proof's `nonce` (VC Data Integrity §2.1), an optional value the
    /// proof creator supplies to reduce linkability between signatures.
    ///
    /// It carries no verification semantics of its own, but it is part of the
    /// proof configuration, and every cryptosuite hashes the proof
    /// configuration. Without this field serde dropped a producer's `nonce` on
    /// deserialize, so [`verify`](Self::verify) re-hashed a configuration the
    /// producer never signed and rejected a valid proof as
    /// `signature invalid`. Producers that set one — `affinidi-ssi-dart` does on
    /// every proof — could not be verified here at all.
    ///
    /// Set it with [`SignOptions::with_nonce`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// The proof's `id` (VC Data Integrity §2.1), a URL naming this proof so
    /// another proof in a chain can refer to it through `previousProof`.
    ///
    /// Like every member below, it is part of the hashed proof configuration,
    /// so it is carried through parse and canonicalization unchanged. Set it
    /// with [`SignOptions::with_id`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// The proof's `expires` (VC Data Integrity §2.1): an `xsd:dateTimeStamp`
    /// after which the proof is no longer valid.
    ///
    /// Verification refuses a proof whose `expires` has passed with
    /// [`DataIntegrityError::ProofExpired`], allowing the same clock skew as
    /// `created`, and refuses a value that is not a well-formed
    /// `dateTimeStamp` with [`DataIntegrityError::MalformedProof`]. Set it with
    /// [`SignOptions::with_expires`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,

    /// The proof's `domain` (VC Data Integrity §2.1): the security domain or
    /// domains the proof is restricted to. Checked against
    /// [`VerifyOptions::with_expected_domain`] when the verifier sets one. Set
    /// it with [`SignOptions::with_domain`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<StringOrList>,

    /// The proof's `challenge` (VC Data Integrity §2.1), supplied by the
    /// verifier to bind the proof to one exchange. Checked against
    /// [`VerifyOptions::with_expected_challenge`] when the verifier sets one.
    /// Set it with [`SignOptions::with_challenge`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,

    /// The proof's `previousProof` (VC Data Integrity §2.1): the `id` of the
    /// proof, or proofs, this one chains from. Set it with
    /// [`SignOptions::with_previous_proof`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_proof: Option<StringOrList>,

    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Vec<String>>,
}

/// A proof member that VC Data Integrity allows as either one string or a
/// list of strings (`domain`, `previousProof`). Serializes in the shape it
/// was given, so a proof configuration hashes the same bytes its producer
/// signed.
///
/// `#[non_exhaustive]` so another shape can be added without a breaking
/// release; match with a `_ =>` arm, or use [`StringOrList::contains`] /
/// [`StringOrList::iter`].
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum StringOrList {
    One(String),
    List(Vec<String>),
}

impl StringOrList {
    /// Whether `value` is the single string or one of the listed strings.
    pub fn contains(&self, value: &str) -> bool {
        match self {
            Self::One(one) => one == value,
            Self::List(list) => list.iter().any(|item| item == value),
        }
    }

    /// The string, or each listed string.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        let items: &[String] = match self {
            Self::One(one) => std::slice::from_ref(one),
            Self::List(list) => list,
        };
        items.iter().map(String::as_str)
    }
}

impl From<String> for StringOrList {
    fn from(value: String) -> Self {
        Self::One(value)
    }
}

impl From<&str> for StringOrList {
    fn from(value: &str) -> Self {
        Self::One(value.to_string())
    }
}

impl From<Vec<String>> for StringOrList {
    fn from(value: Vec<String>) -> Self {
        Self::List(value)
    }
}

impl DataIntegrityProof {
    /// Assemble a Data Integrity proof from its parts. `type_` is fixed to
    /// `"DataIntegrityProof"`. Most callers should use [`DataIntegrityProof::sign`];
    /// this is for reconstructing a proof from known components (e.g. tests or
    /// custom flows).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cryptosuite: CryptoSuite,
        verification_method: String,
        proof_purpose: String,
        proof_value: Option<String>,
        created: Option<String>,
        context: Option<Vec<String>>,
    ) -> Self {
        Self {
            type_: "DataIntegrityProof".to_string(),
            cryptosuite,
            created,
            verification_method,
            proof_purpose,
            proof_value,
            context,
            nonce: None,
            id: None,
            expires: None,
            domain: None,
            challenge: None,
            previous_proof: None,
        }
    }

    /// Produces a Data Integrity proof over `data_doc`.
    ///
    /// The cryptosuite is picked from [`SignOptions::cryptosuite`] if
    /// set, otherwise from [`Signer::cryptosuite`]. Canonicalization
    /// (JCS or RDFC) is derived from the suite.
    ///
    pub async fn sign<S>(
        data_doc: &S,
        signer: &dyn Signer,
        options: SignOptions,
    ) -> Result<DataIntegrityProof, DataIntegrityError>
    where
        S: Serialize,
    {
        let caller_chose_the_suite = options.cryptosuite.is_some();
        let crypto_suite = options.cryptosuite.unwrap_or_else(|| signer.cryptosuite());
        crypto_suite
            .validate_key_type(signer.key_type())
            .map_err(|_| {
                // Two different failures reach here, and reporting them the
                // same way sends the caller after the wrong thing.
                //
                // `Signer::cryptosuite()`'s default is
                // `default_for_key_type(..).unwrap_or(EddsaJcs2022)`, so a key
                // type with no suite compiled in arrives carrying an Ed25519
                // suite the caller never asked for. Reporting that as
                // `KeyTypeMismatch { expected: Ed25519, .. }` blames them for
                // the library's own invention, and names an algorithm that
                // appears nowhere in their configuration.
                //
                // The honest message for that case is that no cryptosuite
                // exists for the key — which for ML-DSA-65/87 is a fact about
                // W3C Quantum-Resistant Cryptosuites v1.0, which defines only
                // the ML-DSA-44 variants, not a defect to be worked around. It
                // is reachable: a VTA can mint an ML-DSA-65 key.
                if !caller_chose_the_suite
                    && CryptoSuite::default_for_key_type(signer.key_type()).is_none()
                {
                    return DataIntegrityError::UnsupportedCryptoSuite {
                        name: format!(
                            "no Data Integrity cryptosuite is available for {:?}; W3C \
                             Quantum-Resistant Cryptosuites v1.0 defines suites for ML-DSA-44 \
                             only, so a credential proof needs an ML-DSA-44 key (the key is \
                             usable for other signing, just not for a Data Integrity proof)",
                            signer.key_type(),
                        ),
                    };
                }
                // A genuine mismatch: the caller named a suite and handed it a
                // key it cannot use.
                DataIntegrityError::KeyTypeMismatch {
                    expected: crypto_suite
                        .compatible_key_types()
                        .first()
                        .copied()
                        .unwrap_or(affinidi_secrets_resolver::secrets::KeyType::Unknown),
                    actual: signer.key_type(),
                    suite: crypto_suite,
                }
            })?;

        let created_str = options
            .created
            .map(format_created)
            .unwrap_or_else(|| format_created(Utc::now()));

        let proof_purpose = options
            .proof_purpose
            .unwrap_or_else(|| "assertionMethod".to_string());

        let proof_options = DataIntegrityProof {
            type_: "DataIntegrityProof".to_string(),
            cryptosuite: crypto_suite,
            created: Some(created_str),
            verification_method: signer.verification_method().to_string(),
            proof_purpose,
            proof_value: None,
            nonce: options.nonce,
            id: options.id,
            expires: options.expires.map(format_created),
            domain: options.domain,
            challenge: options.challenge,
            previous_proof: options.previous_proof,
            context: options.context,
        };
        check_proof_ids(&proof_options)?;
        if let (Some(created), Some(expires)) = (&proof_options.created, &proof_options.expires) {
            check_expires_not_before_created(
                parse_proof_time("created", created)?,
                parse_proof_time("expires", expires)?,
            )?;
        }

        if crypto_suite.is_rdfc() {
            sign_rdfc(data_doc, proof_options, signer).await
        } else {
            sign_jcs(data_doc, proof_options, signer).await
        }
    }

    /// Verifies a proof against `data_doc` using caller-provided public
    /// key bytes.
    ///
    /// Sync because this is pure CPU — callers who already have the key
    /// should not be forced into an async runtime. See [`verify`] for
    /// the resolver-based async variant.
    ///
    /// [`verify`]: Self::verify
    #[must_use = "ignoring a verification result is a security bug"]
    pub fn verify_with_public_key<S>(
        &self,
        data_doc: &S,
        public_key_bytes: &[u8],
        options: VerifyOptions,
    ) -> Result<(), DataIntegrityError>
    where
        S: Serialize,
    {
        verify_proof_internal(self, data_doc, public_key_bytes, &options)
    }

    /// Verifies a proof by resolving the public key from its
    /// `verificationMethod` via a [`VerificationMethodResolver`].
    ///
    /// Use [`did_vm::DidKeyResolver`] for `did:key:` URIs (no I/O); plug
    /// in a custom resolver for `did:web`, `did:webvh`, or any other
    /// method. The library also checks that the resolved key's
    /// [`KeyType`] matches the proof's cryptosuite — a cheap guard
    /// against "right proof, wrong key" class bugs.
    ///
    /// Async because typical resolvers perform I/O (HTTP, cache lookups,
    /// HSM introspection).
    ///
    /// [`KeyType`]: affinidi_secrets_resolver::secrets::KeyType
    #[must_use = "ignoring a verification result is a security bug"]
    pub async fn verify<S, R>(
        &self,
        data_doc: &S,
        resolver: &R,
        options: VerifyOptions,
    ) -> Result<(), DataIntegrityError>
    where
        S: Serialize + Sync,
        R: VerificationMethodResolver + ?Sized,
    {
        let resolved = resolver.resolve_vm(&self.verification_method).await?;
        self.verify_with_resolved_key(data_doc, &resolved, &options)
    }

    /// Verifies against a key already resolved from this proof's
    /// `verificationMethod`, including the key-type check. Shared by
    /// [`verify`](Self::verify) and [`multi::verify_multi`], which needs
    /// the resolved key afterwards to count distinct signers.
    pub(crate) fn verify_with_resolved_key<S>(
        &self,
        data_doc: &S,
        resolved: &ResolvedKey,
        options: &VerifyOptions,
    ) -> Result<(), DataIntegrityError>
    where
        S: Serialize,
    {
        // Belt-and-braces key-type check. The CryptoSuiteOps verify will
        // fail on a mismatched key anyway, but a typed error here is
        // clearer to callers and saves the canonicalization work.
        let compatible = self.cryptosuite.compatible_key_types();
        if !compatible.is_empty() && !compatible.contains(&resolved.key_type) {
            return Err(DataIntegrityError::KeyTypeMismatch {
                expected: compatible
                    .first()
                    .copied()
                    .unwrap_or(affinidi_secrets_resolver::secrets::KeyType::Unknown),
                actual: resolved.key_type,
                suite: self.cryptosuite,
            });
        }

        verify_proof_internal(self, data_doc, &resolved.public_key_bytes, options)
    }
}

// -----------------------------------------------------------------------
// Internal signing helpers
// -----------------------------------------------------------------------

/// Signs `proof_options` (every member set except `proofValue`) over
/// `data_doc` with a JCS suite.
async fn sign_jcs<S>(
    data_doc: &S,
    mut proof_options: DataIntegrityProof,
    signer: &dyn Signer,
) -> Result<DataIntegrityProof, DataIntegrityError>
where
    S: Serialize,
{
    let jcs = to_string(data_doc)
        .map_err(|e| DataIntegrityError::Canonicalization(format!("document: {e}")))?;
    debug!("Document (JCS): {}", jcs);

    let proof_jcs = to_string(&proof_options)
        .map_err(|e| DataIntegrityError::Canonicalization(format!("proof config: {e}")))?;
    debug!("Proof options (JCS): {}", proof_jcs);

    let hash_data = hashing_jcs(&jcs, &proof_jcs);
    let signed = signer.sign(&hash_data).await?;
    proof_options.proof_value = Some(multibase::encode(Base::Base58Btc, &signed));

    Ok(proof_options)
}

/// Signs `proof_options` (every member set except `proofValue`) over
/// `data_doc` with an RDFC suite. A proof `@context` left unset is taken
/// from the document.
async fn sign_rdfc<S>(
    data_doc: &S,
    mut proof_options: DataIntegrityProof,
    signer: &dyn Signer,
) -> Result<DataIntegrityProof, DataIntegrityError>
where
    S: Serialize,
{
    let doc_value = serde_json::to_value(data_doc)
        .map_err(|e| DataIntegrityError::Canonicalization(format!("document serialize: {e}")))?;

    // Proof context: caller override, else pulled from document @context.
    let proof_context = if let Some(ctx) = proof_options.context.take() {
        Some(ctx)
    } else {
        match doc_value.get("@context") {
            Some(serde_json::Value::Array(arr)) => Some(
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect(),
            ),
            Some(serde_json::Value::String(s)) => Some(vec![s.clone()]),
            Some(_) => {
                return Err(DataIntegrityError::MalformedProof(
                    "Invalid @context format in document".to_string(),
                ));
            }
            None => {
                return Err(DataIntegrityError::MalformedProof(
                    "Document must contain @context for RDFC signing".to_string(),
                ));
            }
        }
    };

    proof_options.context = proof_context;

    let proof_value = serde_json::to_value(&proof_options).map_err(|e| {
        DataIntegrityError::Canonicalization(format!("proof config serialize: {e}"))
    })?;

    let hash_data = hashing_rdfc(&doc_value, &proof_value)?;
    let signed = signer.sign(&hash_data).await?;
    proof_options.proof_value = Some(multibase::encode(Base::Base58Btc, &signed));

    Ok(proof_options)
}

fn verify_proof_internal<S>(
    proof: &DataIntegrityProof,
    signed_doc: &S,
    public_key_bytes: &[u8],
    options: &VerifyOptions,
) -> Result<(), DataIntegrityError>
where
    S: Serialize,
{
    // Cryptosuite allowlist.
    if !options.allowed_suites.is_empty() && !options.allowed_suites.contains(&proof.cryptosuite) {
        return Err(DataIntegrityError::Conformance(format!(
            "cryptosuite {} is not in the caller's allowed suites",
            String::try_from(proof.cryptosuite).unwrap_or_default()
        )));
    }

    // Context match (only when caller explicitly supplied one).
    if let Some(expected) = &options.expected_context
        && proof.context.as_ref() != Some(expected)
    {
        return Err(DataIntegrityError::Conformance(
            "Document context does not match proof context".to_string(),
        ));
    }

    // Decode proofValue.
    let Some(proof_value) = &proof.proof_value else {
        return Err(DataIntegrityError::MalformedProof(
            "proofValue is missing in the proof".to_string(),
        ));
    };
    let proof_value = multibase::decode(proof_value)
        .map_err(|e| DataIntegrityError::MalformedProof(format!("Invalid proof value: {e}")))?
        .1;

    // Strip the proof_value from the proof config for re-hashing.
    let proof_config = DataIntegrityProof {
        proof_value: None,
        ..proof.clone()
    };

    if proof_config.type_ != "DataIntegrityProof" {
        return Err(DataIntegrityError::Conformance(
            "Invalid proof type, expected 'DataIntegrityProof'".to_string(),
        ));
    }

    check_proof_ids(&proof_config)?;
    check_proof_times(
        proof_config.created.as_deref(),
        proof_config.expires.as_deref(),
        &ProofClock {
            now: options.verification_time.unwrap_or_else(Utc::now),
            created_skew: options.clock_skew,
            expiry_skew: options.expiry_clock_skew,
        },
    )?;

    if let Some(expected) = &options.expected_domain
        && !proof_config
            .domain
            .as_ref()
            .is_some_and(|domain| domain.contains(expected))
    {
        return Err(DataIntegrityError::Conformance(
            "proof domain does not match the expected domain".to_string(),
        ));
    }

    if let Some(expected) = &options.expected_challenge
        && proof_config.challenge.as_ref() != Some(expected)
    {
        return Err(DataIntegrityError::Conformance(
            "proof challenge does not match the expected challenge".to_string(),
        ));
    }

    // Canonicalize & hash (JCS or RDFC depending on suite).
    let hash_data = if proof_config.cryptosuite.is_rdfc() {
        let doc_value = serde_json::to_value(signed_doc).map_err(|e| {
            DataIntegrityError::Canonicalization(format!("document serialize: {e}"))
        })?;
        let proof_value_json = serde_json::to_value(&proof_config).map_err(|e| {
            DataIntegrityError::Canonicalization(format!("proof config serialize: {e}"))
        })?;
        hashing_rdfc(&doc_value, &proof_value_json)?
    } else {
        #[cfg(feature = "bbs-2023")]
        if matches!(proof_config.cryptosuite, CryptoSuite::Bbs2023) {
            return Err(DataIntegrityError::UnsupportedCryptoSuite {
                name: "bbs-2023 derived proofs are verified via \
                       bbs_2023_transform::verify_derived_proof (or \
                       verify_pseudonym_derived_proof), not the generic verify path"
                    .to_string(),
            });
        }
        let jcs_doc = to_string(&signed_doc)
            .map_err(|e| DataIntegrityError::Canonicalization(format!("document: {e}")))?;
        let jcs_proof_config = to_string(&proof_config)
            .map_err(|e| DataIntegrityError::Canonicalization(format!("proof config: {e}")))?;
        hashing_jcs(&jcs_doc, &jcs_proof_config)
    };

    proof_config
        .cryptosuite
        .verify(public_key_bytes, &hash_data, &proof_value)
}

// -----------------------------------------------------------------------
// Hashing pipelines (shared by all cryptosuites in this family)
// -----------------------------------------------------------------------

/// Hashing Algorithm for EDDSA JCS
fn hashing_jcs(transformed_document: &str, canonical_proof_config: &str) -> Vec<u8> {
    [
        Sha256::digest(canonical_proof_config),
        Sha256::digest(transformed_document),
    ]
    .concat()
}

/// Hashing Algorithm for EDDSA RDFC.
/// Runs both document and proof config through the RDFC pipeline
/// (JSON-LD expansion → RDF Dataset → RDFC-1.0 canonicalization → SHA-256)
/// and concatenates the two 32-byte hashes.
///
/// Expansion runs in safe mode for both inputs. VC Data Integrity 1.0 §2.4.3
/// (Securing Data Losslessly) requires implementations that use JSON-LD
/// processing to "throw an error ... when data is dropped by a JSON-LD
/// processor, such as when an undefined term is detected in an input
/// document". Lenient expansion would drop such a term from the hashed
/// dataset while it stays in the JSON, unsigned. Signing and verifying use the
/// same pipeline, so a document this crate signs is one it can verify.
fn hashing_rdfc(
    document: &serde_json::Value,
    proof_config: &serde_json::Value,
) -> Result<Vec<u8>, DataIntegrityError> {
    let doc_hash = rdfc_hash_safe(document)
        .map_err(|e| DataIntegrityError::Canonicalization(format!("RDFC document hash: {e}")))?;

    let proof_hash = rdfc_hash_safe(proof_config).map_err(|e| {
        DataIntegrityError::Canonicalization(format!("RDFC proof config hash: {e}"))
    })?;

    Ok([proof_hash.as_slice(), doc_hash.as_slice()].concat())
}

/// Safe-mode JSON-LD expansion, RDFC-1.0 canonicalization, SHA-256.
fn rdfc_hash_safe(document: &serde_json::Value) -> affinidi_rdf_encoding::Result<[u8; 32]> {
    let dataset = affinidi_rdf_encoding::jsonld::expand_and_to_rdf_safe(document)?;
    affinidi_rdf_encoding::rdfc1::canonicalize_and_hash(&dataset)
}

// -----------------------------------------------------------------------
// Remote-signer helper: returns the exact bytes a signer is expected to
// sign over, so remote-signing protocols can compute the input ahead of
// time without recomputing the canonicalization/hash pipeline.
// -----------------------------------------------------------------------

/// Returns the byte string a [`Signer`] is expected to sign over, given
/// a document, a partial proof config, and the target cryptosuite.
///
/// Remote signers (KMS, HSM) typically want this so they can submit a
/// well-formed "sign these bytes" request to their backend without
/// re-implementing canonicalization. The returned bytes are exactly
/// what [`DataIntegrityProof::sign`] passes to `signer.sign(data)`.
///
/// `proof_config` should be the proof JSON value with `proofValue`
/// absent but all other fields set (cryptosuite, verificationMethod,
/// proofPurpose, created, optional @context).
pub fn prepare_sign_input<S>(
    data_doc: &S,
    proof_config: &DataIntegrityProof,
    cryptosuite: CryptoSuite,
) -> Result<Vec<u8>, DataIntegrityError>
where
    S: Serialize,
{
    if cryptosuite.is_rdfc() {
        let doc_value = serde_json::to_value(data_doc).map_err(|e| {
            DataIntegrityError::Canonicalization(format!("document serialize: {e}"))
        })?;
        let proof_value = serde_json::to_value(proof_config).map_err(|e| {
            DataIntegrityError::Canonicalization(format!("proof config serialize: {e}"))
        })?;
        hashing_rdfc(&doc_value, &proof_value)
    } else {
        let jcs_doc = to_string(data_doc)
            .map_err(|e| DataIntegrityError::Canonicalization(format!("document: {e}")))?;
        let jcs_proof = to_string(proof_config)
            .map_err(|e| DataIntegrityError::Canonicalization(format!("proof config: {e}")))?;
        Ok(hashing_jcs(&jcs_doc, &jcs_proof))
    }
}

// -----------------------------------------------------------------------
// Internal date helpers
// -----------------------------------------------------------------------

fn format_created(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// The instant and tolerances a proof's `created` and `expires` are checked
/// against. Negative skews are treated as zero.
pub(crate) struct ProofClock {
    pub(crate) now: DateTime<Utc>,
    /// How far into the future `created` may be.
    pub(crate) created_skew: chrono::TimeDelta,
    /// How far past `expires` the proof is still accepted.
    pub(crate) expiry_skew: chrono::TimeDelta,
}

/// Parses a proof timestamp strictly as an `xsd:dateTimeStamp`.
pub(crate) fn parse_proof_time(
    member: &str,
    value: &str,
) -> Result<DateTime<Utc>, DataIntegrityError> {
    date_time::parse_date_time_stamp(value).map_err(|reason| {
        DataIntegrityError::MalformedProof(format!(
            "{member} is not a valid dateTimeStamp ({reason}): {value}"
        ))
    })
}

fn check_expires_not_before_created(
    created: DateTime<Utc>,
    expires: DateTime<Utc>,
) -> Result<(), DataIntegrityError> {
    if expires < created {
        return Err(DataIntegrityError::MalformedProof(
            "expires is earlier than created".to_string(),
        ));
    }
    Ok(())
}

/// Checks a proof's `created` and `expires`:
///
/// - both, when present, must be well-formed `xsd:dateTimeStamp`s
///   ([`DataIntegrityError::MalformedProof`] otherwise);
/// - `created` may be at most `created_skew` in the future
///   ([`DataIntegrityError::Conformance`]);
/// - `expires` may not be earlier than `created`
///   ([`DataIntegrityError::MalformedProof`]);
/// - the proof is expired once `now >= expires + expiry_skew`
///   ([`DataIntegrityError::ProofExpired`]). The bound is inclusive: at the
///   `expires` instant itself the proof is already expired.
pub(crate) fn check_proof_times(
    created: Option<&str>,
    expires: Option<&str>,
    clock: &ProofClock,
) -> Result<(), DataIntegrityError> {
    let zero = chrono::TimeDelta::zero();
    let created_at = created
        .map(|created| parse_proof_time("created", created))
        .transpose()?;
    let expires_at = expires
        .map(|expires| parse_proof_time("expires", expires))
        .transpose()?;

    // `created` is stamped by the signer's clock and checked against ours,
    // so a strict comparison makes acceptance a race between clock skew and
    // delivery latency. `checked_add_signed` so an absurd caller-supplied
    // skew saturates instead of panicking on overflow.
    if let Some(created_at) = created_at {
        let skew = clock.created_skew.max(zero);
        let horizon = clock
            .now
            .checked_add_signed(skew)
            .unwrap_or(DateTime::<Utc>::MAX_UTC);
        if created_at > horizon {
            return Err(DataIntegrityError::Conformance(format!(
                "Created date is in the future (beyond the {}s clock-skew allowance)",
                skew.num_seconds()
            )));
        }
    }

    if let Some(expires_at) = expires_at {
        if let Some(created_at) = created_at {
            check_expires_not_before_created(created_at, expires_at)?;
        }
        let deadline = expires_at
            .checked_add_signed(clock.expiry_skew.max(zero))
            .unwrap_or(DateTime::<Utc>::MAX_UTC);
        if clock.now >= deadline {
            return Err(DataIntegrityError::ProofExpired {
                expires: expires.unwrap_or_default().to_string(),
            });
        }
    }
    Ok(())
}

/// Refuses an `id` or `previousProof` that is not an absolute IRI.
///
/// JSON-LD processors disagree about relative IRIs in these positions: the
/// JSON-LD to-RDF algorithm drops them, and some processors refuse them, while
/// `affinidi-rdf-encoding` keeps them. An RDFC hash over one would then
/// differ between implementations without any error, so neither is accepted.
pub(crate) fn check_proof_ids(proof: &DataIntegrityProof) -> Result<(), DataIntegrityError> {
    check_proof_id_values(proof.id.as_deref(), proof.previous_proof.as_ref())
}

pub(crate) fn check_proof_id_values(
    id: Option<&str>,
    previous_proof: Option<&StringOrList>,
) -> Result<(), DataIntegrityError> {
    let ids = id.into_iter().map(|id| ("id", id)).chain(
        previous_proof
            .into_iter()
            .flat_map(StringOrList::iter)
            .map(|previous| ("previousProof", previous)),
    );
    for (member, value) in ids {
        if !is_absolute_iri(value) {
            return Err(DataIntegrityError::MalformedProof(format!(
                "{member} must be an absolute IRI: {value:?}"
            )));
        }
    }
    Ok(())
}

/// RFC 3987 absolute IRI shape: a scheme (`ALPHA *( ALPHA / DIGIT / "+" /
/// "-" / "." )`), a `:`, and no whitespace or control characters.
fn is_absolute_iri(value: &str) -> bool {
    let Some((scheme, _)) = value.split_once(':') else {
        return false;
    };
    let mut scheme_chars = scheme.chars();
    scheme_chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && scheme_chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        && !value
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | '"'))
}

#[cfg(test)]
mod tests {
    use affinidi_secrets_resolver::secrets::Secret;
    use chrono::Utc;
    use serde_json::json;

    use crate::{DataIntegrityError, DataIntegrityProof, SignOptions, VerifyOptions, hashing_jcs};

    #[test]
    fn hashing_working() {
        let hash = hashing_jcs("test1", "test2");
        let mut output = String::new();
        for x in hash {
            output.push_str(&format!("{x:02x}"));
        }

        assert_eq!(
            output.as_str(),
            "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c7521b4f0e9851971998e732078544c96b36c3d01cedf7caa332359d6f1d83567014",
        );
    }

    #[tokio::test]
    async fn sign_and_verify_via_did_key_resolver_ed25519() {
        use crate::{DidKeyResolver, VerifyOptions};

        let secret = Secret::generate_ed25519(None, Some(&[11u8; 32]));
        let pk_mb = secret.get_public_keymultibase().unwrap();
        // Use the library-built VM URI so the resolver can find the key.
        let mut signer_secret = secret.clone();
        signer_secret.id = format!("did:key:{pk_mb}#{pk_mb}");

        let doc = json!({ "hello": "did:key" });
        let proof = DataIntegrityProof::sign(&doc, &signer_secret, SignOptions::new())
            .await
            .expect("sign");

        proof
            .verify(&doc, &DidKeyResolver, VerifyOptions::new())
            .await
            .expect("verify via resolver");
    }

    /// The end-to-end property that matters: a P-256 key signs a document and
    /// the proof verifies through the ordinary `did:key` resolver path, with no
    /// suite named by hand at either end.
    #[tokio::test]
    async fn sign_and_verify_via_did_key_resolver_p256() {
        use crate::{DidKeyResolver, VerifyOptions};

        let secret = Secret::generate_p256(None, None).expect("generate P-256");
        let pk_mb = secret.get_public_keymultibase().unwrap();
        let mut signer_secret = secret.clone();
        signer_secret.id = format!("did:key:{pk_mb}#{pk_mb}");

        let doc = json!({ "ecdsa": "did:key" });
        let proof = DataIntegrityProof::sign(&doc, &signer_secret, SignOptions::new())
            .await
            .expect("sign");
        assert_eq!(
            proof.cryptosuite,
            crate::crypto_suites::CryptoSuite::EcdsaJcs2019,
            "a P-256 signer must default to ecdsa-jcs-2019 without being told"
        );

        proof
            .verify(&doc, &DidKeyResolver, VerifyOptions::new())
            .await
            .expect("verify via resolver");
    }

    /// A proof must not survive its document changing — ECDSA is randomised, so
    /// a round-trip test alone would still pass against a verify that ignored
    /// the payload.
    #[tokio::test]
    async fn a_p256_proof_does_not_verify_against_a_tampered_document() {
        use crate::{DidKeyResolver, VerifyOptions};

        let secret = Secret::generate_p256(None, None).expect("generate P-256");
        let pk_mb = secret.get_public_keymultibase().unwrap();
        let mut signer_secret = secret.clone();
        signer_secret.id = format!("did:key:{pk_mb}#{pk_mb}");

        let doc = json!({ "amount": 10 });
        let proof = DataIntegrityProof::sign(&doc, &signer_secret, SignOptions::new())
            .await
            .expect("sign");

        let tampered = json!({ "amount": 1000 });
        assert!(
            proof
                .verify(&tampered, &DidKeyResolver, VerifyOptions::new())
                .await
                .is_err(),
            "a P-256 proof must not verify against a document it did not sign"
        );
    }

    #[cfg(feature = "ml-dsa")]
    #[tokio::test]
    async fn sign_and_verify_via_did_key_resolver_ml_dsa() {
        use crate::{DidKeyResolver, VerifyOptions};

        let secret = Secret::generate_ml_dsa_44(None, Some(&[21u8; 32]));
        let pk_mb = secret.get_public_keymultibase().unwrap();
        let mut signer_secret = secret.clone();
        signer_secret.id = format!("did:key:{pk_mb}#{pk_mb}");

        let doc = json!({ "pqc": "did:key" });
        let proof = DataIntegrityProof::sign(&doc, &signer_secret, SignOptions::new())
            .await
            .expect("sign");

        proof
            .verify(&doc, &DidKeyResolver, VerifyOptions::new())
            .await
            .expect("verify via resolver");
    }

    #[tokio::test]
    async fn unified_sign_verify_ed25519_jcs() {
        let secret = Secret::generate_ed25519(Some("did:key:k#k"), Some(&[4u8; 32]));
        let doc = json!({"hello": "world"});
        let proof = DataIntegrityProof::sign(&doc, &secret, SignOptions::new())
            .await
            .expect("sign");
        proof
            .verify_with_public_key(&doc, secret.get_public_bytes(), VerifyOptions::new())
            .expect("verify");
    }

    #[cfg(feature = "ml-dsa")]
    #[tokio::test]
    async fn unified_sign_verify_ml_dsa_44_jcs() {
        let secret = Secret::generate_ml_dsa_44(Some("did:key:k#k"), Some(&[8u8; 32]));
        let doc = json!({"pqc": true});
        let proof = DataIntegrityProof::sign(&doc, &secret, SignOptions::new())
            .await
            .expect("sign");
        // Signer defaulted to mldsa44-jcs-2024 via Signer::cryptosuite().
        assert_eq!(
            proof.cryptosuite,
            crate::crypto_suites::CryptoSuite::MlDsa44Jcs2024
        );
        proof
            .verify_with_public_key(&doc, secret.get_public_bytes(), VerifyOptions::new())
            .expect("verify");
    }

    #[cfg(feature = "ml-dsa")]
    #[tokio::test]
    async fn override_suite_via_sign_options() {
        // An Ed25519 signer asked to produce mldsa44 must fail with
        // KeyTypeMismatch — the caller overrode the default.
        let secret = Secret::generate_ed25519(Some("did:key:k#k"), Some(&[1u8; 32]));
        let doc = json!({"x": 1});
        let err = DataIntegrityProof::sign(
            &doc,
            &secret,
            SignOptions::new().with_cryptosuite(crate::crypto_suites::CryptoSuite::MlDsa44Jcs2024),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            crate::DataIntegrityError::KeyTypeMismatch { .. }
        ));
    }

    /// A signer whose clock runs slightly ahead of the verifier's stamps
    /// `created` in the verifier's future. With zero tolerance this made
    /// acceptance a race between clock skew and delivery latency — the
    /// same proof verified or not depending on how fast it arrived. The
    /// default allowance must absorb it.
    #[tokio::test]
    async fn verify_tolerates_default_clock_skew_on_created() {
        let secret = Secret::generate_ed25519(Some("did:key:k#k"), Some(&[3u8; 32]));
        let doc = json!({"skewed": true});
        let proof = DataIntegrityProof::sign(
            &doc,
            &secret,
            SignOptions::new().with_created(Utc::now() + chrono::TimeDelta::seconds(5)),
        )
        .await
        .expect("sign");

        proof
            .verify_with_public_key(&doc, secret.get_public_bytes(), VerifyOptions::new())
            .expect("a 5s-ahead signer is inside the default 60s allowance");
    }

    /// The allowance is bounded: a `created` beyond it is still rejected,
    /// and the error names the allowance so the cause is diagnosable from
    /// the wire message alone.
    #[tokio::test]
    async fn verify_rejects_created_beyond_the_allowance() {
        let secret = Secret::generate_ed25519(Some("did:key:k#k"), Some(&[4u8; 32]));
        let doc = json!({"skewed": "far"});
        let proof = DataIntegrityProof::sign(
            &doc,
            &secret,
            SignOptions::new().with_created(Utc::now() + chrono::TimeDelta::hours(1)),
        )
        .await
        .expect("sign");

        let err = proof
            .verify_with_public_key(&doc, secret.get_public_bytes(), VerifyOptions::new())
            .expect_err("an hour ahead is well beyond 60s");
        let msg = format!("{err}");
        assert!(msg.contains("future"), "unexpected message: {msg}");
        assert!(
            msg.contains("60s"),
            "message should name the allowance: {msg}"
        );
    }

    /// Zero skew restores the strict pre-allowance behaviour for callers
    /// that want it.
    #[tokio::test]
    async fn verify_zero_skew_rejects_any_future_created() {
        let secret = Secret::generate_ed25519(Some("did:key:k#k"), Some(&[5u8; 32]));
        let doc = json!({"strict": true});
        let proof = DataIntegrityProof::sign(
            &doc,
            &secret,
            SignOptions::new().with_created(Utc::now() + chrono::TimeDelta::seconds(5)),
        )
        .await
        .expect("sign");

        let err = proof
            .verify_with_public_key(
                &doc,
                secret.get_public_bytes(),
                VerifyOptions::new().with_clock_skew(chrono::TimeDelta::zero()),
            )
            .expect_err("zero tolerance must reject a future created");
        assert!(matches!(err, DataIntegrityError::Conformance(_)));
    }

    /// An attacker rewrites the `cryptosuite` field on a proof they
    /// otherwise can't forge — e.g. swaps `eddsa-jcs-2022` to
    /// `eddsa-rdfc-2022`. Verification must fail because the
    /// canonicalization axis changes the hashed bytes.
    #[tokio::test]
    async fn verify_rejects_cryptosuite_tampering() {
        use crate::crypto_suites::CryptoSuite;

        let secret = Secret::generate_ed25519(Some("did:key:k#k"), Some(&[77u8; 32]));
        let doc = json!({"tamper": "target"});
        let mut proof = DataIntegrityProof::sign(&doc, &secret, SignOptions::new())
            .await
            .expect("sign");
        assert_eq!(proof.cryptosuite, CryptoSuite::EddsaJcs2022);

        // Attacker flips the suite.
        proof.cryptosuite = CryptoSuite::EddsaRdfc2022;

        let err = proof
            .verify_with_public_key(&doc, secret.get_public_bytes(), VerifyOptions::new())
            .unwrap_err();
        // The document has no `@context`, so the RDFC path now stops at
        // canonicalization (its terms are undefined) before the signature.
        assert!(
            matches!(
                err,
                crate::DataIntegrityError::InvalidSignature { .. }
                    | crate::DataIntegrityError::Canonicalization(_)
            ),
            "expected rejection after cryptosuite tampering, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn deterministic_signing_same_input_same_output() {
        let secret = Secret::generate_ed25519(Some("did:key:k#k"), Some(&[2u8; 32]));
        let doc = json!({"deterministic": "yes"});
        let created = chrono::Utc::now();
        let opts = || SignOptions::new().with_created(created);
        let a = DataIntegrityProof::sign(&doc, &secret, opts())
            .await
            .unwrap();
        let b = DataIntegrityProof::sign(&doc, &secret, opts())
            .await
            .unwrap();
        assert_eq!(
            a.proof_value, b.proof_value,
            "Ed25519 must be deterministic"
        );
    }

    #[cfg(feature = "ml-dsa")]
    #[tokio::test]
    async fn deterministic_signing_ml_dsa() {
        let secret = Secret::generate_ml_dsa_44(Some("did:key:k#k"), Some(&[5u8; 32]));
        let doc = json!({"deterministic": "pqc"});
        let created = chrono::Utc::now();
        let opts = || SignOptions::new().with_created(created);
        let a = DataIntegrityProof::sign(&doc, &secret, opts())
            .await
            .unwrap();
        let b = DataIntegrityProof::sign(&doc, &secret, opts())
            .await
            .unwrap();
        assert_eq!(a.proof_value, b.proof_value, "ML-DSA must be deterministic");
    }

    /// This key used to be the crate's "bad key" fixture, on the strength of
    /// signing failing for it. It is a **P-256** key, and the failure was only
    /// ever "no suite compiled in for this key type" — so `ecdsa-jcs-2019`
    /// turns it into a supported key, and the old assertion asserted the
    /// absence of a feature rather than any property of the key.
    #[tokio::test]
    async fn test_sign_p256_key_now_produces_an_ecdsa_jcs_2019_proof() {
        let generic_doc = json!({"test": "test_data"});
        let pub_key = "zruqgFba156mDWfMUjJUSAKUvgCgF5NfgSYwSuEZuXpixts8tw3ot5BasjeyM65f8dzk5k6zgXf7pkbaaBnPrjCUmcJ";
        let pri_key = "z42tmXtqqQBLmEEwn8tfi1bA2ghBx9cBo6wo8a44kVJEiqyA";
        let secret = Secret::from_multibase(pri_key, Some(&format!("did:key:{pub_key}#{pub_key}")))
            .expect("Couldn't create test key data");
        assert_eq!(
            secret.get_key_type(),
            affinidi_secrets_resolver::secrets::KeyType::P256
        );

        let proof = DataIntegrityProof::sign(&generic_doc, &secret, SignOptions::new())
            .await
            .expect("a P-256 key signs under ecdsa-jcs-2019");
        assert_eq!(
            proof.cryptosuite,
            crate::crypto_suites::CryptoSuite::EcdsaJcs2019
        );
    }

    /// The genuine "unsupported key type" case the previous test was standing
    /// in for. secp256k1 has no Data Integrity suite here, so it must still
    /// fail — otherwise a key type nothing can verify would sign silently.
    #[tokio::test]
    async fn test_sign_rejects_a_key_type_with_no_suite() {
        let generic_doc = json!({"test": "test_data"});
        let secret =
            Secret::generate_secp256k1(Some("did:key:k#k"), None).expect("generate secp256k1");
        assert!(
            DataIntegrityProof::sign(&generic_doc, &secret, SignOptions::new())
                .await
                .is_err(),
            "a key type with no compiled-in suite must not sign"
        );
    }

    #[tokio::test]
    async fn test_sign_good() {
        let generic_doc = json!({"test": "test_data"});
        let pub_key = "z6MktDNePDZTvVcF5t6u362SsonU7HkuVFSMVCjSspQLDaBm";
        let pri_key = "z3u2UQyiY96d7VQaua8yiaSyQxq5Z5W5Qkpz7o2H2pc9BkEa";
        let secret = Secret::from_multibase(pri_key, Some(&format!("did:key:{pub_key}#{pub_key}")))
            .expect("Couldn't create test key data");
        let context = vec![
            "context1".to_string(),
            "context2".to_string(),
            "context3".to_string(),
        ];
        assert!(
            DataIntegrityProof::sign(
                &generic_doc,
                &secret,
                SignOptions::new().with_context(context)
            )
            .await
            .is_ok(),
            "Signing failed"
        );
    }

    #[cfg(feature = "ml-dsa")]
    #[tokio::test]
    async fn sign_verify_jcs_ml_dsa_44() {
        use crate::crypto_suites::CryptoSuite;

        let secret = Secret::generate_ml_dsa_44(Some("k-did#k-did"), Some(&[5u8; 32]));
        let doc = json!({"hello": "pqc"});

        let proof = DataIntegrityProof::sign(
            &doc,
            &secret,
            SignOptions::new().with_cryptosuite(CryptoSuite::MlDsa44Jcs2024),
        )
        .await
        .expect("sign ml-dsa");

        assert_eq!(proof.cryptosuite, CryptoSuite::MlDsa44Jcs2024);

        proof
            .verify_with_public_key(&doc, secret.get_public_bytes(), VerifyOptions::new())
            .expect("verify ml-dsa");
    }

    #[cfg(feature = "ml-dsa")]
    #[tokio::test]
    async fn sign_wrong_suite_for_key_fails() {
        use crate::crypto_suites::CryptoSuite;

        let secret = Secret::generate_ml_dsa_44(Some("k"), Some(&[1u8; 32]));
        let doc = json!({"x": 1});
        let err = DataIntegrityProof::sign(
            &doc,
            &secret,
            SignOptions::new().with_cryptosuite(CryptoSuite::EddsaJcs2022),
        )
        .await;
        assert!(err.is_err());
    }

    #[cfg(feature = "slh-dsa")]
    #[tokio::test]
    async fn sign_verify_jcs_slh_dsa_128s() {
        use crate::crypto_suites::CryptoSuite;

        let secret = Secret::generate_slh_dsa_sha2_128s(Some("k#k"));
        let doc = json!({"hello": "slh"});

        let proof = DataIntegrityProof::sign(
            &doc,
            &secret,
            SignOptions::new().with_cryptosuite(CryptoSuite::SlhDsa128Jcs2024),
        )
        .await
        .expect("sign slh-dsa");

        proof
            .verify_with_public_key(&doc, secret.get_public_bytes(), VerifyOptions::new())
            .expect("verify slh-dsa");
    }
}

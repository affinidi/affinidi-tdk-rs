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
affinidi-data-integrity = { version = "0.6", features = ["post-quantum"] }
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

// TODO(pqc-refactor): remove this once all internal call-sites have been
// migrated to the structured DataIntegrityError variants. The legacy
// string-payload variants are kept `#[deprecated]` for one minor version
// to give downstream consumers time to migrate.
#![allow(deprecated)]

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
pub mod did_vm;
pub mod error;
pub mod multi;
pub mod options;
pub mod signer;
pub mod suite_ops;
pub mod verification_proof;

pub use caching_signer::{CachingSigner, GetPrivateBytes};
pub use conformance::verify_conformance;
pub use did_vm::{DidKeyResolver, ResolvedKey, VerificationMethodResolver};
pub use multi::{MultiVerifyResult, VerifyPolicy, verify_multi};

/// BBS-2023 Data Integrity Cryptosuite for zero-knowledge selective disclosure.
///
/// Enabled via the `bbs-2023` feature flag.
#[cfg(feature = "bbs-2023")]
pub mod bbs_2023;

pub use error::{DataIntegrityError, SignatureFailure};
pub use options::{SignOptions, VerifyOptions};

/// Serialized Data Integrity proof.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
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

    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Vec<String>>,
}

impl DataIntegrityProof {
    /// Produces a Data Integrity proof over `data_doc`.
    ///
    /// The cryptosuite is picked from [`SignOptions::cryptosuite`] if
    /// set, otherwise from [`Signer::cryptosuite`]. Canonicalization
    /// (JCS or RDFC) is derived from the suite.
    ///
    /// This is the unified entry point — it replaces the four-way
    /// `sign_jcs_data` / `sign_jcs_data_with_suite` / `sign_rdfc_data` /
    /// `sign_rdfc_data_with_suite` matrix.
    pub async fn sign<S>(
        data_doc: &S,
        signer: &dyn Signer,
        options: SignOptions,
    ) -> Result<DataIntegrityProof, DataIntegrityError>
    where
        S: Serialize,
    {
        let crypto_suite = options.cryptosuite.unwrap_or_else(|| signer.cryptosuite());
        crypto_suite
            .validate_key_type(signer.key_type())
            .map_err(|_| DataIntegrityError::KeyTypeMismatch {
                expected: crypto_suite
                    .compatible_key_types()
                    .first()
                    .copied()
                    .unwrap_or_default(),
                actual: signer.key_type(),
                suite: crypto_suite,
            })?;

        let created_str = options
            .created
            .map(format_created)
            .unwrap_or_else(|| format_created(Utc::now()));

        let proof_purpose = options
            .proof_purpose
            .unwrap_or_else(|| "assertionMethod".to_string());

        if crypto_suite.is_rdfc() {
            sign_rdfc(
                data_doc,
                crypto_suite,
                options.context,
                signer,
                created_str,
                proof_purpose,
            )
            .await
        } else {
            sign_jcs(
                data_doc,
                crypto_suite,
                options.context,
                signer,
                created_str,
                proof_purpose,
            )
            .await
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

        // Belt-and-braces key-type check. The CryptoSuiteOps verify will
        // fail on a mismatched key anyway, but a typed error here is
        // clearer to callers and saves the canonicalization work.
        let compatible = self.cryptosuite.compatible_key_types();
        if !compatible.is_empty() && !compatible.contains(&resolved.key_type) {
            return Err(DataIntegrityError::KeyTypeMismatch {
                expected: compatible.first().copied().unwrap_or_default(),
                actual: resolved.key_type,
                suite: self.cryptosuite,
            });
        }

        verify_proof_internal(self, data_doc, &resolved.public_key_bytes, &options)
    }

    // ---- Deprecated legacy entry points ----
    // These remain for one minor release to give downstream consumers
    // time to migrate to the unified `sign` / `verify_with_public_key`
    // API. Remove in the next breaking release.

    /// Creates a JCS (JSON Canonicalization Scheme) signature for the given data.
    ///
    /// **Deprecated** — prefer [`DataIntegrityProof::sign`] with
    /// [`SignOptions`]. Example:
    /// ```ignore
    /// let proof = DataIntegrityProof::sign(
    ///     &doc,
    ///     &signer,
    ///     SignOptions::new().with_context(ctx),
    /// ).await?;
    /// ```
    #[deprecated(
        since = "0.6.0",
        note = "use DataIntegrityProof::sign with SignOptions"
    )]
    pub async fn sign_jcs_data<S>(
        data_doc: &S,
        context: Option<Vec<String>>,
        signer: &dyn Signer,
        created: Option<String>,
    ) -> Result<DataIntegrityProof, DataIntegrityError>
    where
        S: Serialize,
    {
        DataIntegrityProof::sign_jcs_data_with_suite(
            CryptoSuite::EddsaJcs2022,
            data_doc,
            context,
            signer,
            created,
        )
        .await
    }

    /// Creates a JCS signature with an explicit cryptosuite.
    ///
    /// **Deprecated** — prefer [`DataIntegrityProof::sign`] with
    /// `SignOptions::new().with_cryptosuite(...)`.
    #[deprecated(
        since = "0.6.0",
        note = "use DataIntegrityProof::sign with SignOptions"
    )]
    pub async fn sign_jcs_data_with_suite<S>(
        crypto_suite: CryptoSuite,
        data_doc: &S,
        context: Option<Vec<String>>,
        signer: &dyn Signer,
        created: Option<String>,
    ) -> Result<DataIntegrityProof, DataIntegrityError>
    where
        S: Serialize,
    {
        if crypto_suite.is_rdfc() {
            return Err(DataIntegrityError::MalformedProof(format!(
                "Cryptosuite {} uses RDFC canonicalization; call sign_rdfc_data_with_suite instead",
                String::try_from(crypto_suite).unwrap_or_default()
            )));
        }
        let options = SignOptions {
            context,
            created: parse_created_opt(created)?,
            cryptosuite: Some(crypto_suite),
            proof_purpose: None,
        };
        DataIntegrityProof::sign(data_doc, signer, options).await
    }

    /// Creates an RDFC signature for the given JSON-LD data.
    ///
    /// **Deprecated** — prefer [`DataIntegrityProof::sign`] with
    /// `SignOptions::new().with_cryptosuite(CryptoSuite::EddsaRdfc2022)`.
    #[deprecated(
        since = "0.6.0",
        note = "use DataIntegrityProof::sign with SignOptions"
    )]
    pub async fn sign_rdfc_data(
        data_doc: &serde_json::Value,
        context: Option<Vec<String>>,
        signer: &dyn Signer,
        created: Option<String>,
    ) -> Result<DataIntegrityProof, DataIntegrityError> {
        DataIntegrityProof::sign_rdfc_data_with_suite(
            CryptoSuite::EddsaRdfc2022,
            data_doc,
            context,
            signer,
            created,
        )
        .await
    }

    /// Creates an RDFC signature with an explicit cryptosuite.
    ///
    /// **Deprecated** — prefer [`DataIntegrityProof::sign`] with
    /// `SignOptions::new().with_cryptosuite(...)`.
    #[deprecated(
        since = "0.6.0",
        note = "use DataIntegrityProof::sign with SignOptions"
    )]
    pub async fn sign_rdfc_data_with_suite(
        crypto_suite: CryptoSuite,
        data_doc: &serde_json::Value,
        context: Option<Vec<String>>,
        signer: &dyn Signer,
        created: Option<String>,
    ) -> Result<DataIntegrityProof, DataIntegrityError> {
        if !crypto_suite.is_rdfc() {
            return Err(DataIntegrityError::MalformedProof(format!(
                "Cryptosuite {} uses JCS canonicalization; call sign_jcs_data_with_suite instead",
                String::try_from(crypto_suite).unwrap_or_default()
            )));
        }
        let options = SignOptions {
            context,
            created: parse_created_opt(created)?,
            cryptosuite: Some(crypto_suite),
            proof_purpose: None,
        };
        DataIntegrityProof::sign(data_doc, signer, options).await
    }
}

// -----------------------------------------------------------------------
// Internal signing helpers
// -----------------------------------------------------------------------

async fn sign_jcs<S>(
    data_doc: &S,
    crypto_suite: CryptoSuite,
    context: Option<Vec<String>>,
    signer: &dyn Signer,
    created: String,
    proof_purpose: String,
) -> Result<DataIntegrityProof, DataIntegrityError>
where
    S: Serialize,
{
    let jcs = to_string(data_doc)
        .map_err(|e| DataIntegrityError::Canonicalization(format!("document: {e}")))?;
    debug!("Document (JCS): {}", jcs);

    let mut proof_options = DataIntegrityProof {
        type_: "DataIntegrityProof".to_string(),
        cryptosuite: crypto_suite,
        created: Some(created),
        verification_method: signer.verification_method().to_string(),
        proof_purpose,
        proof_value: None,
        context,
    };

    let proof_jcs = to_string(&proof_options)
        .map_err(|e| DataIntegrityError::Canonicalization(format!("proof config: {e}")))?;
    debug!("Proof options (JCS): {}", proof_jcs);

    let hash_data = hashing_eddsa_jcs(&jcs, &proof_jcs);
    let signed = signer.sign(&hash_data).await?;
    proof_options.proof_value = Some(multibase::encode(Base::Base58Btc, &signed));

    Ok(proof_options)
}

async fn sign_rdfc<S>(
    data_doc: &S,
    crypto_suite: CryptoSuite,
    context: Option<Vec<String>>,
    signer: &dyn Signer,
    created: String,
    proof_purpose: String,
) -> Result<DataIntegrityProof, DataIntegrityError>
where
    S: Serialize,
{
    let doc_value = serde_json::to_value(data_doc)
        .map_err(|e| DataIntegrityError::Canonicalization(format!("document serialize: {e}")))?;

    // Proof context: caller override, else pulled from document @context.
    let proof_context = if let Some(ctx) = context {
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

    let mut proof_options = DataIntegrityProof {
        type_: "DataIntegrityProof".to_string(),
        cryptosuite: crypto_suite,
        created: Some(created),
        verification_method: signer.verification_method().to_string(),
        proof_purpose,
        proof_value: None,
        context: proof_context,
    };

    let proof_value = serde_json::to_value(&proof_options).map_err(|e| {
        DataIntegrityError::Canonicalization(format!("proof config serialize: {e}"))
    })?;

    let hash_data = hashing_eddsa_rdfc(&doc_value, &proof_value)?;
    let signed = signer.sign(&hash_data).await?;
    proof_options.proof_value = Some(multibase::encode(Base::Base58Btc, &signed));

    Ok(proof_options)
}

// -----------------------------------------------------------------------
// Internal verify helper (shared between the DataIntegrityProof method
// and the deprecated top-level verify_data_with_public_key).
// -----------------------------------------------------------------------

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
    if let Some(expected) = &options.expected_context {
        if proof.context.as_ref() != Some(expected) {
            return Err(DataIntegrityError::Conformance(
                "Document context does not match proof context".to_string(),
            ));
        }
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

    if let Some(created) = &proof_config.created {
        let now = Utc::now();
        let created = created
            .parse::<DateTime<Utc>>()
            .map_err(|e| DataIntegrityError::Conformance(format!("Invalid created date: {e}")))?;
        if created > now {
            return Err(DataIntegrityError::Conformance(
                "Created date is in the future".to_string(),
            ));
        }
    }

    // Canonicalize & hash (JCS or RDFC depending on suite).
    let hash_data = if proof_config.cryptosuite.is_rdfc() {
        let doc_value = serde_json::to_value(signed_doc).map_err(|e| {
            DataIntegrityError::Canonicalization(format!("document serialize: {e}"))
        })?;
        let proof_value_json = serde_json::to_value(&proof_config).map_err(|e| {
            DataIntegrityError::Canonicalization(format!("proof config serialize: {e}"))
        })?;
        hashing_eddsa_rdfc(&doc_value, &proof_value_json)?
    } else {
        #[cfg(feature = "bbs-2023")]
        if matches!(proof_config.cryptosuite, CryptoSuite::Bbs2023) {
            return Err(DataIntegrityError::UnsupportedCryptoSuite {
                name: "bbs-2023 proofs must be verified via bbs_2023::verify_proof".to_string(),
            });
        }
        let jcs_doc = to_string(&signed_doc)
            .map_err(|e| DataIntegrityError::Canonicalization(format!("document: {e}")))?;
        let jcs_proof_config = to_string(&proof_config)
            .map_err(|e| DataIntegrityError::Canonicalization(format!("proof config: {e}")))?;
        hashing_eddsa_jcs(&jcs_doc, &jcs_proof_config)
    };

    proof_config
        .cryptosuite
        .verify(public_key_bytes, &hash_data, &proof_value)
}

// -----------------------------------------------------------------------
// Hashing pipelines (shared by all cryptosuites in this family)
// -----------------------------------------------------------------------

/// Hashing Algorithm for EDDSA JCS
fn hashing_eddsa_jcs(transformed_document: &str, canonical_proof_config: &str) -> Vec<u8> {
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
fn hashing_eddsa_rdfc(
    document: &serde_json::Value,
    proof_config: &serde_json::Value,
) -> Result<Vec<u8>, DataIntegrityError> {
    let doc_hash = affinidi_rdf_encoding::expand_canonicalize_and_hash(document)
        .map_err(|e| DataIntegrityError::Canonicalization(format!("RDFC document hash: {e}")))?;

    let proof_hash =
        affinidi_rdf_encoding::expand_canonicalize_and_hash(proof_config).map_err(|e| {
            DataIntegrityError::Canonicalization(format!("RDFC proof config hash: {e}"))
        })?;

    Ok([proof_hash.as_slice(), doc_hash.as_slice()].concat())
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
        hashing_eddsa_rdfc(&doc_value, &proof_value)
    } else {
        let jcs_doc = to_string(data_doc)
            .map_err(|e| DataIntegrityError::Canonicalization(format!("document: {e}")))?;
        let jcs_proof = to_string(proof_config)
            .map_err(|e| DataIntegrityError::Canonicalization(format!("proof config: {e}")))?;
        Ok(hashing_eddsa_jcs(&jcs_doc, &jcs_proof))
    }
}

// -----------------------------------------------------------------------
// Internal date helpers
// -----------------------------------------------------------------------

fn format_created(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn parse_created_opt(s: Option<String>) -> Result<Option<DateTime<Utc>>, DataIntegrityError> {
    match s {
        None => Ok(None),
        Some(s) => s
            .parse::<DateTime<Utc>>()
            .map(Some)
            .map_err(|e| DataIntegrityError::MalformedProof(format!("Invalid created date: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use affinidi_secrets_resolver::secrets::Secret;
    use serde_json::json;

    use crate::{DataIntegrityProof, SignOptions, VerifyOptions, hashing_eddsa_jcs};

    #[test]
    fn hashing_working() {
        let hash = hashing_eddsa_jcs("test1", "test2");
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

    // Legacy-shim sanity checks — still need to work for downstream
    // consumers during the deprecation window.

    #[tokio::test]
    async fn test_sign_jcs_data_bad_key() {
        let generic_doc = json!({"test": "test_data"});
        let pub_key = "zruqgFba156mDWfMUjJUSAKUvgCgF5NfgSYwSuEZuXpixts8tw3ot5BasjeyM65f8dzk5k6zgXf7pkbaaBnPrjCUmcJ";
        let pri_key = "z42tmXtqqQBLmEEwn8tfi1bA2ghBx9cBo6wo8a44kVJEiqyA";
        let secret = Secret::from_multibase(pri_key, Some(&format!("did:key:{pub_key}#{pub_key}")))
            .expect("Couldn't create test key data");
        assert!(
            DataIntegrityProof::sign_jcs_data(&generic_doc, None, &secret, None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_sign_jcs_data_good() {
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
            DataIntegrityProof::sign_jcs_data(&generic_doc, Some(context), &secret, None)
                .await
                .is_ok(),
            "Signing failed"
        );
    }

    #[cfg(feature = "ml-dsa")]
    #[tokio::test]
    async fn sign_verify_jcs_ml_dsa_44() {
        use crate::{crypto_suites::CryptoSuite, verification_proof::verify_data_with_public_key};

        let secret = Secret::generate_ml_dsa_44(Some("k-did#k-did"), Some(&[5u8; 32]));
        let doc = json!({"hello": "pqc"});

        let proof = DataIntegrityProof::sign_jcs_data_with_suite(
            CryptoSuite::MlDsa44Jcs2024,
            &doc,
            None,
            &secret,
            None,
        )
        .await
        .expect("sign ml-dsa");

        assert_eq!(proof.cryptosuite, CryptoSuite::MlDsa44Jcs2024);

        let result = verify_data_with_public_key(&doc, None, &proof, secret.get_public_bytes())
            .expect("verify ml-dsa");
        assert!(result.verified);
    }

    #[cfg(feature = "ml-dsa")]
    #[tokio::test]
    async fn sign_wrong_suite_for_key_fails() {
        use crate::crypto_suites::CryptoSuite;

        let secret = Secret::generate_ml_dsa_44(Some("k"), Some(&[1u8; 32]));
        let doc = json!({"x": 1});
        let err = DataIntegrityProof::sign_jcs_data_with_suite(
            CryptoSuite::EddsaJcs2022,
            &doc,
            None,
            &secret,
            None,
        )
        .await;
        assert!(err.is_err());
    }

    #[cfg(feature = "slh-dsa")]
    #[tokio::test]
    async fn sign_verify_jcs_slh_dsa_128s() {
        use crate::{crypto_suites::CryptoSuite, verification_proof::verify_data_with_public_key};

        let secret = Secret::generate_slh_dsa_sha2_128s(Some("k#k"));
        let doc = json!({"hello": "slh"});

        let proof = DataIntegrityProof::sign_jcs_data_with_suite(
            CryptoSuite::SlhDsa128Jcs2024,
            &doc,
            None,
            &secret,
            None,
        )
        .await
        .expect("sign slh-dsa");

        let result = verify_data_with_public_key(&doc, None, &proof, secret.get_public_bytes())
            .expect("verify slh-dsa");
        assert!(result.verified);
    }
}

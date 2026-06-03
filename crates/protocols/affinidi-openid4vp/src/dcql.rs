/*!
 * Digital Credentials Query Language (DCQL).
 *
 * DCQL is the JSON-encoded query language of [OpenID4VP 1.0][oid4vp]: a verifier
 * describes the credential(s) and claims it wants, and a wallet matches its held
 * credentials against the query. DCQL is the 1.0 successor to the older
 * [Presentation Exchange][pe] `presentation_definition` ([`crate::types`]); a
 * verifier uses one *or* the other, never both, in a single request.
 *
 * This module is the **query type model** — the serde-(de)serializable shapes
 * plus structural [validation](DcqlQuery::validate). It is transport-agnostic:
 * the same [`DcqlQuery`] travels on the wire in an authorization request and can
 * be persisted (e.g. as a community's required-evidence criteria). Matching a
 * query against a concrete credential store is a separate concern, layered on
 * top of these types by the holder.
 *
 * # Shape
 *
 * ```text
 * DcqlQuery
 * ├── credentials: [CredentialQuery]        (required, non-empty)
 * │   ├── id: String                        (unique within the query)
 * │   ├── format: String                    ("dc+sd-jwt", "mso_mdoc", …)
 * │   ├── meta: {…}                          (format-specific, e.g. vct_values)
 * │   ├── claims: [ClaimsQuery]             (optional, non-empty if present)
 * │   │   ├── id: String                     (required iff claim_sets is used)
 * │   │   ├── path: [ClaimPathSegment]       (name | index | wildcard; non-empty)
 * │   │   └── values: [Json]                 (optional; claim must equal one)
 * │   ├── claim_sets: [[claim id]]           (optional; alternative claim combos)
 * │   └── trusted_authorities: [TrustedAuthoritiesQuery]
 * └── credential_sets: [CredentialSetQuery]  (optional)
 *     └── options: [[credential id]]         (alternative satisfying combos)
 * ```
 *
 * [oid4vp]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
 * [pe]: https://identity.foundation/presentation-exchange/spec/v2.0.0/
 */

use std::collections::HashSet;

use serde::de::{self, Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_json::Value as Json;

use crate::error::Oid4vpError;

/// The id charset DCQL mandates for credential-query and claim ids: a non-empty
/// string of ASCII alphanumerics, `_`, or `-`.
fn is_valid_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A top-level DCQL query: the set of credentials a verifier requests, plus an
/// optional set of *options* describing which combinations satisfy the request.
///
/// Construct from JSON with [`DcqlQuery::from_json`] (which validates), or build
/// programmatically and call [`DcqlQuery::validate`] before use.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DcqlQuery {
    /// The requested credentials. MUST be non-empty; each [`CredentialQuery::id`]
    /// MUST be unique across this list.
    pub credentials: Vec<CredentialQuery>,

    /// Optional credential-set queries. When present, they describe which
    /// *combinations* of the above credentials satisfy the request (e.g. "an ID
    /// **and** either a membership or an endorsement"). When absent, every
    /// credential in `credentials` is required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_sets: Option<Vec<CredentialSetQuery>>,
}

impl DcqlQuery {
    /// Parse and **validate** a DCQL query from JSON. Returns
    /// [`Oid4vpError::InvalidDcqlQuery`] if the structure violates a DCQL
    /// constraint (empty `credentials`, duplicate / malformed ids, dangling
    /// `claim_sets` / `credential_sets` references, an empty `path`, …).
    pub fn from_json(value: &Json) -> Result<Self, Oid4vpError> {
        let query: DcqlQuery = serde_json::from_value(value.clone())?;
        query.validate()?;
        Ok(query)
    }

    /// Serialize this query to a JSON value. (Infallible for well-formed
    /// structures; surfaces a [`serde_json`] error only on a pathological
    /// non-serializable value inside `meta` / claim `values`.)
    pub fn to_json(&self) -> Result<Json, Oid4vpError> {
        Ok(serde_json::to_value(self)?)
    }

    /// Enforce the DCQL structural invariants that serde alone cannot:
    ///
    /// - `credentials` is non-empty and every `id` is unique and well-formed;
    /// - within each credential query, `claims` (if present) is non-empty, each
    ///   claim `path` is non-empty, and claim `id`s are unique + well-formed;
    /// - if a credential query carries `claim_sets`, every referenced claim id
    ///   exists in that query's `claims` (and so every claim there has an id);
    /// - every `credential_sets` option references a credential id that exists,
    ///   and no `options` / option is empty.
    pub fn validate(&self) -> Result<(), Oid4vpError> {
        if self.credentials.is_empty() {
            return Err(Oid4vpError::InvalidDcqlQuery(
                "`credentials` must contain at least one credential query".into(),
            ));
        }

        let mut credential_ids = HashSet::new();
        for cq in &self.credentials {
            if !is_valid_id(&cq.id) {
                return Err(Oid4vpError::InvalidDcqlQuery(format!(
                    "credential query id `{}` is not a non-empty [A-Za-z0-9_-] string",
                    cq.id
                )));
            }
            if !credential_ids.insert(cq.id.as_str()) {
                return Err(Oid4vpError::InvalidDcqlQuery(format!(
                    "duplicate credential query id `{}`",
                    cq.id
                )));
            }
            cq.validate()?;
        }

        if let Some(sets) = &self.credential_sets {
            for set in sets {
                set.validate(&credential_ids)?;
            }
        }

        Ok(())
    }
}

/// A request for a single credential of a given `format`, optionally narrowed by
/// format-specific `meta` (e.g. `vct_values`) and the specific `claims` wanted.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CredentialQuery {
    /// Identifies this query within the [`DcqlQuery`]; referenced by
    /// `claim_sets` and `credential_sets`. Non-empty `[A-Za-z0-9_-]`.
    pub id: String,

    /// The credential format requested, e.g. `dc+sd-jwt`, `vc+sd-jwt`,
    /// `mso_mdoc`, `jwt_vc_json`, `ldp_vc`. Kept open (a `String`) so new
    /// formats need no change here.
    pub format: String,

    /// Format-specific metadata constraining *which* credential of `format`
    /// matches — e.g. `{"vct_values": ["https://…/MembershipCredential"]}` for
    /// SD-JWT-VC, or `{"doctype_value": "org.iso.18013.5.1.mDL"}` for mdoc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Map<String, Json>>,

    /// The specific claims requested from the matching credential. When absent,
    /// no particular claim is required (the credential as a whole is requested).
    /// When present, MUST be non-empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<ClaimsQuery>>,

    /// Alternative claim combinations: each inner list is a set of claim
    /// [`ClaimsQuery::id`]s that together satisfy the request. The first option
    /// whose claims are all present is used. Requires every referenced claim to
    /// carry an `id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_sets: Option<Vec<Vec<String>>>,

    /// Trusted issuer/authority constraints for the matching credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_authorities: Option<Vec<TrustedAuthoritiesQuery>>,

    /// Whether the matching credential must prove cryptographic holder binding.
    /// Absent means the DCQL default, **`true`** — see
    /// [`require_cryptographic_holder_binding`](Self::require_cryptographic_holder_binding).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_cryptographic_holder_binding: Option<bool>,

    /// Whether multiple credentials may match this single query. Absent means
    /// the DCQL default, **`false`** — see [`multiple`](Self::multiple).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multiple: Option<bool>,
}

impl CredentialQuery {
    /// The resolved cryptographic-holder-binding requirement (default `true`).
    pub fn require_cryptographic_holder_binding(&self) -> bool {
        self.require_cryptographic_holder_binding.unwrap_or(true)
    }

    /// The resolved "may match multiple credentials" flag (default `false`).
    pub fn multiple(&self) -> bool {
        self.multiple.unwrap_or(false)
    }

    fn validate(&self) -> Result<(), Oid4vpError> {
        if self.format.is_empty() {
            return Err(Oid4vpError::InvalidDcqlQuery(format!(
                "credential query `{}` has an empty `format`",
                self.id
            )));
        }

        // Collect claim ids (validating uniqueness + charset) so claim_sets can
        // be checked against them.
        let mut claim_ids = HashSet::new();
        if let Some(claims) = &self.claims {
            if claims.is_empty() {
                return Err(Oid4vpError::InvalidDcqlQuery(format!(
                    "credential query `{}` has an empty `claims` (omit it instead)",
                    self.id
                )));
            }
            for claim in claims {
                claim.validate(&self.id)?;
                if let Some(cid) = &claim.id
                    && !claim_ids.insert(cid.as_str())
                {
                    return Err(Oid4vpError::InvalidDcqlQuery(format!(
                        "credential query `{}` has a duplicate claim id `{cid}`",
                        self.id
                    )));
                }
            }
        }

        if let Some(claim_sets) = &self.claim_sets {
            if claim_sets.is_empty() {
                return Err(Oid4vpError::InvalidDcqlQuery(format!(
                    "credential query `{}` has an empty `claim_sets` (omit it instead)",
                    self.id
                )));
            }
            for (i, option) in claim_sets.iter().enumerate() {
                if option.is_empty() {
                    return Err(Oid4vpError::InvalidDcqlQuery(format!(
                        "credential query `{}` claim_sets[{i}] is empty",
                        self.id
                    )));
                }
                for cid in option {
                    if !claim_ids.contains(cid.as_str()) {
                        return Err(Oid4vpError::InvalidDcqlQuery(format!(
                            "credential query `{}` claim_sets references unknown claim id `{cid}` \
                             (every claim referenced by claim_sets must carry that id)",
                            self.id
                        )));
                    }
                }
            }
        }

        Ok(())
    }
}

/// A request for a particular claim within a credential, addressed by a
/// [`ClaimPathSegment`] path and optionally constrained to specific `values`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClaimsQuery {
    /// Identifies this claim within its credential query. REQUIRED when the
    /// credential query uses `claim_sets` (which reference claims by id);
    /// optional otherwise. Non-empty `[A-Za-z0-9_-]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// The claim path: a non-empty sequence of [`ClaimPathSegment`]s walking
    /// into the credential's claims (object key, array index, or wildcard).
    pub path: Vec<ClaimPathSegment>,

    /// When present, the claim's value MUST equal one of these for the
    /// credential to match (e.g. `country == "US"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<Json>>,

    /// mdoc-specific hint: whether the verifier intends to retain the claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_to_retain: Option<bool>,
}

impl ClaimsQuery {
    fn validate(&self, credential_id: &str) -> Result<(), Oid4vpError> {
        if let Some(id) = &self.id
            && !is_valid_id(id)
        {
            return Err(Oid4vpError::InvalidDcqlQuery(format!(
                "credential query `{credential_id}` has a claim id `{id}` that is not a \
                 non-empty [A-Za-z0-9_-] string"
            )));
        }
        if self.path.is_empty() {
            return Err(Oid4vpError::InvalidDcqlQuery(format!(
                "credential query `{credential_id}` has a claim with an empty `path`"
            )));
        }
        Ok(())
    }
}

/// One segment of a DCQL claim `path`.
///
/// Per the DCQL claim-path encoding, a JSON **string** selects an object member,
/// a non-negative **integer** selects an array element, and **null** selects
/// *all* elements of an array (a wildcard).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimPathSegment {
    /// Select the value of this object member.
    Name(String),
    /// Select this (zero-based) array element.
    Index(u64),
    /// Select all elements of the array at this position (`null` on the wire).
    Wildcard,
}

impl Serialize for ClaimPathSegment {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            ClaimPathSegment::Name(name) => serializer.serialize_str(name),
            ClaimPathSegment::Index(index) => serializer.serialize_u64(*index),
            ClaimPathSegment::Wildcard => serializer.serialize_none(),
        }
    }
}

impl<'de> Deserialize<'de> for ClaimPathSegment {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Json::deserialize(deserializer)? {
            Json::String(name) => Ok(ClaimPathSegment::Name(name)),
            Json::Null => Ok(ClaimPathSegment::Wildcard),
            Json::Number(n) => n.as_u64().map(ClaimPathSegment::Index).ok_or_else(|| {
                de::Error::custom("DCQL claim path index must be a non-negative integer")
            }),
            other => Err(de::Error::custom(format!(
                "DCQL claim path segment must be a string, non-negative integer, or null; got {other}"
            ))),
        }
    }
}

/// A credential-set query: a set of *options*, each a combination of credential
/// query ids that together satisfy the request. The verifier accepts the first
/// option the wallet can fully satisfy.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CredentialSetQuery {
    /// Alternative satisfying combinations; each inner list is a set of
    /// [`CredentialQuery::id`]s. MUST be non-empty, and each option MUST be
    /// non-empty and reference existing credential ids.
    pub options: Vec<Vec<String>>,

    /// Whether this set must be satisfied. Absent means the DCQL default,
    /// **`true`** — see [`is_required`](Self::is_required).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

impl CredentialSetQuery {
    /// The resolved "this set is required" flag (default `true`).
    pub fn is_required(&self) -> bool {
        self.required.unwrap_or(true)
    }

    fn validate(&self, credential_ids: &HashSet<&str>) -> Result<(), Oid4vpError> {
        if self.options.is_empty() {
            return Err(Oid4vpError::InvalidDcqlQuery(
                "a credential set query has an empty `options`".into(),
            ));
        }
        for (i, option) in self.options.iter().enumerate() {
            if option.is_empty() {
                return Err(Oid4vpError::InvalidDcqlQuery(format!(
                    "credential set query options[{i}] is empty"
                )));
            }
            for cid in option {
                if !credential_ids.contains(cid.as_str()) {
                    return Err(Oid4vpError::InvalidDcqlQuery(format!(
                        "credential set query references unknown credential id `{cid}`"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// A trusted-authority constraint on the issuer of a matching credential.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrustedAuthoritiesQuery {
    /// The kind of authority key in `values`.
    #[serde(rename = "type")]
    pub authority_type: TrustedAuthorityType,
    /// The accepted authority values (interpreted per `authority_type`).
    pub values: Vec<String>,
}

/// The kind of trusted-authority key carried by a [`TrustedAuthoritiesQuery`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedAuthorityType {
    /// Authority Key Identifier (`aki`).
    Aki,
    /// ETSI Trusted List (`etsi_tl`).
    EtsiTl,
    /// OpenID Federation entity id (`openid_federation`).
    OpenidFederation,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A realistic single-credential SD-JWT-VC query round-trips and validates.
    #[test]
    fn parses_a_membership_query() {
        let value = json!({
            "credentials": [{
                "id": "membership",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://openvtc.org/credentials/MembershipCredential"] },
                "claims": [
                    { "path": ["givenName"] },
                    { "path": ["memberSince"] }
                ]
            }]
        });

        let query = DcqlQuery::from_json(&value).expect("valid DCQL");
        assert_eq!(query.credentials.len(), 1);
        let cq = &query.credentials[0];
        assert_eq!(cq.id, "membership");
        assert_eq!(cq.format, "dc+sd-jwt");
        // Defaults resolve.
        assert!(cq.require_cryptographic_holder_binding());
        assert!(!cq.multiple());
        let claims = cq.claims.as_ref().unwrap();
        assert_eq!(claims.len(), 2);
        assert_eq!(
            claims[0].path,
            vec![ClaimPathSegment::Name("givenName".into())]
        );

        // Round-trips losslessly.
        assert_eq!(
            DcqlQuery::from_json(&query.to_json().unwrap()).unwrap(),
            query
        );
    }

    /// Path segments cover name / index / wildcard and survive a round-trip.
    #[test]
    fn claim_path_segments_round_trip() {
        let value = json!({
            "credentials": [{
                "id": "c1",
                "format": "dc+sd-jwt",
                "claims": [{ "path": ["address", 0, null] }]
            }]
        });
        let query = DcqlQuery::from_json(&value).expect("valid");
        let path = &query.credentials[0].claims.as_ref().unwrap()[0].path;
        assert_eq!(
            path,
            &vec![
                ClaimPathSegment::Name("address".into()),
                ClaimPathSegment::Index(0),
                ClaimPathSegment::Wildcard,
            ]
        );
        // null serializes back to null, 0 to a number, "address" to a string.
        let back = query.to_json().unwrap();
        assert_eq!(
            back["credentials"][0]["claims"][0]["path"],
            json!(["address", 0, null])
        );
    }

    /// claim_sets + values: an "id required for claim_sets" query validates, and
    /// a values constraint is preserved.
    #[test]
    fn parses_claim_sets_and_values() {
        let value = json!({
            "credentials": [{
                "id": "id_card",
                "format": "dc+sd-jwt",
                "claims": [
                    { "id": "given", "path": ["givenName"] },
                    { "id": "country", "path": ["address", "country"], "values": ["US", "CA"] }
                ],
                "claim_sets": [["given", "country"], ["given"]]
            }]
        });
        let query = DcqlQuery::from_json(&value).expect("valid");
        let cq = &query.credentials[0];
        assert_eq!(cq.claim_sets.as_ref().unwrap().len(), 2);
        let country = &cq.claims.as_ref().unwrap()[1];
        assert_eq!(
            country.values.as_ref().unwrap(),
            &vec![json!("US"), json!("CA")]
        );
    }

    /// credential_sets with options referencing existing credential ids.
    #[test]
    fn parses_credential_sets() {
        let value = json!({
            "credentials": [
                { "id": "pid", "format": "dc+sd-jwt" },
                { "id": "membership", "format": "dc+sd-jwt" },
                { "id": "endorsement", "format": "dc+sd-jwt" }
            ],
            "credential_sets": [
                { "options": [["pid"]] },
                { "options": [["membership"], ["endorsement"]], "required": false }
            ]
        });
        let query = DcqlQuery::from_json(&value).expect("valid");
        let sets = query.credential_sets.as_ref().unwrap();
        assert!(sets[0].is_required());
        assert!(!sets[1].is_required());
    }

    // ---- validation failures (default-deny) ------------------------------

    #[test]
    fn rejects_empty_credentials() {
        let err = DcqlQuery::from_json(&json!({ "credentials": [] })).unwrap_err();
        assert!(matches!(err, Oid4vpError::InvalidDcqlQuery(_)), "{err:?}");
    }

    #[test]
    fn rejects_duplicate_credential_ids() {
        let value = json!({
            "credentials": [
                { "id": "dup", "format": "dc+sd-jwt" },
                { "id": "dup", "format": "mso_mdoc" }
            ]
        });
        let err = DcqlQuery::from_json(&value).unwrap_err();
        assert!(matches!(err, Oid4vpError::InvalidDcqlQuery(m) if m.contains("duplicate")));
    }

    #[test]
    fn rejects_malformed_credential_id() {
        let value = json!({ "credentials": [{ "id": "has space", "format": "dc+sd-jwt" }] });
        let err = DcqlQuery::from_json(&value).unwrap_err();
        assert!(matches!(err, Oid4vpError::InvalidDcqlQuery(_)), "{err:?}");
    }

    #[test]
    fn rejects_claim_sets_referencing_unknown_claim() {
        let value = json!({
            "credentials": [{
                "id": "c1",
                "format": "dc+sd-jwt",
                "claims": [{ "id": "a", "path": ["a"] }],
                "claim_sets": [["a", "ghost"]]
            }]
        });
        let err = DcqlQuery::from_json(&value).unwrap_err();
        assert!(matches!(err, Oid4vpError::InvalidDcqlQuery(m) if m.contains("ghost")));
    }

    #[test]
    fn rejects_credential_sets_referencing_unknown_credential() {
        let value = json!({
            "credentials": [{ "id": "pid", "format": "dc+sd-jwt" }],
            "credential_sets": [{ "options": [["pid"], ["nope"]] }]
        });
        let err = DcqlQuery::from_json(&value).unwrap_err();
        assert!(matches!(err, Oid4vpError::InvalidDcqlQuery(m) if m.contains("nope")));
    }

    #[test]
    fn rejects_empty_claim_path() {
        let value = json!({
            "credentials": [{ "id": "c1", "format": "dc+sd-jwt", "claims": [{ "path": [] }] }]
        });
        let err = DcqlQuery::from_json(&value).unwrap_err();
        assert!(matches!(err, Oid4vpError::InvalidDcqlQuery(m) if m.contains("path")));
    }

    #[test]
    fn rejects_negative_path_index() {
        // A negative number is not a valid path segment.
        let value = json!({
            "credentials": [{ "id": "c1", "format": "dc+sd-jwt", "claims": [{ "path": [-1] }] }]
        });
        let err = DcqlQuery::from_json(&value).unwrap_err();
        // serde rejects the segment before structural validation: still an error.
        assert!(
            matches!(err, Oid4vpError::Json(_) | Oid4vpError::InvalidDcqlQuery(_)),
            "{err:?}"
        );
    }

    #[test]
    fn trusted_authority_type_serde() {
        let value = json!({
            "credentials": [{
                "id": "c1",
                "format": "dc+sd-jwt",
                "trusted_authorities": [{ "type": "etsi_tl", "values": ["https://tl.example"] }]
            }]
        });
        let query = DcqlQuery::from_json(&value).expect("valid");
        let ta = &query.credentials[0].trusted_authorities.as_ref().unwrap()[0];
        assert_eq!(ta.authority_type, TrustedAuthorityType::EtsiTl);
        // Round-trips back to "etsi_tl".
        assert_eq!(
            query.to_json().unwrap()["credentials"][0]["trusted_authorities"][0]["type"],
            "etsi_tl"
        );
    }
}

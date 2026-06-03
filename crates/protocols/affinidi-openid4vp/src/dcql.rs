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

use std::collections::{HashMap, HashSet};

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

// ===========================================================================
// Matching: evaluate a DcqlQuery against the holder's held credentials.
// ===========================================================================

/// A held credential projected into the shape [`DcqlQuery::match_credentials`]
/// evaluates.
///
/// The holder builds one per credential it holds — for an SD-JWT-VC,
/// `format = "dc+sd-jwt"`, `vct = Some(<vct>)`, and `claims` the JSON object of
/// (disclosable) claims. The matcher reads only these fields and never parses a
/// wire credential itself, so format-specific decoding (SD-JWT disclosure, mdoc
/// CBOR, …) stays on the holder's side.
#[derive(Debug, Clone, PartialEq)]
pub struct CandidateCredential {
    /// Caller-chosen identifier, echoed back in [`CredentialMatch::candidate_id`].
    pub id: String,
    /// The credential format, compared against [`CredentialQuery::format`].
    pub format: String,
    /// The credential's claims as a JSON object — the tree a claim `path` walks.
    pub claims: Json,
    /// SD-JWT-VC type, matched against the query's `meta.vct_values` (if present).
    pub vct: Option<String>,
    /// mdoc doctype, matched against the query's `meta.doctype_value` (if present).
    pub doctype: Option<String>,
    /// Whether this credential can prove cryptographic holder binding. A query
    /// that requires holder binding (the DCQL default) will not match a
    /// candidate that cannot.
    pub supports_holder_binding: bool,
}

/// A satisfying selection produced by [`DcqlQuery::match_credentials`].
#[derive(Debug, Clone, PartialEq)]
pub struct DcqlMatch {
    /// One entry per (credential query → candidate) pairing that contributes to
    /// the satisfied request, in credential-query order.
    pub matches: Vec<CredentialMatch>,
}

/// One matched (credential query → candidate) pairing.
#[derive(Debug, Clone, PartialEq)]
pub struct CredentialMatch {
    /// The [`CredentialQuery::id`] that matched.
    pub credential_query_id: String,
    /// The [`CandidateCredential::id`] that satisfied it.
    pub candidate_id: String,
    /// The claim paths to disclose. **Empty** means "no per-claim constraint" —
    /// the query named no `claims`, so the holder discloses per its own policy.
    pub disclosed_paths: Vec<Vec<ClaimPathSegment>>,
}

/// Walk a DCQL claim `path` over a JSON value, returning every selected node.
///
/// A [`Name`](ClaimPathSegment::Name) selects an object member, an
/// [`Index`](ClaimPathSegment::Index) an array element, and a
/// [`Wildcard`](ClaimPathSegment::Wildcard) every element of an array. Returns
/// empty as soon as a segment selects nothing (the path does not resolve).
fn select_path<'a>(root: &'a Json, path: &[ClaimPathSegment]) -> Vec<&'a Json> {
    let mut current = vec![root];
    for segment in path {
        let mut next = Vec::new();
        for value in current {
            match segment {
                ClaimPathSegment::Name(name) => {
                    if let Some(child) = value.as_object().and_then(|o| o.get(name)) {
                        next.push(child);
                    }
                }
                ClaimPathSegment::Index(index) => {
                    if let Some(child) = value.as_array().and_then(|a| a.get(*index as usize)) {
                        next.push(child);
                    }
                }
                ClaimPathSegment::Wildcard => {
                    if let Some(array) = value.as_array() {
                        next.extend(array.iter());
                    }
                }
            }
        }
        if next.is_empty() {
            return Vec::new();
        }
        current = next;
    }
    current
}

impl ClaimsQuery {
    /// Whether this claim resolves against a candidate's `claims`: the `path`
    /// selects at least one value, and — when `values` is set — some selected
    /// value equals one of them.
    fn is_satisfied_by(&self, claims: &Json) -> bool {
        let selected = select_path(claims, &self.path);
        if selected.is_empty() {
            return false;
        }
        match &self.values {
            None => true,
            Some(allowed) => selected
                .iter()
                .any(|value| allowed.iter().any(|a| a == *value)),
        }
    }
}

impl CredentialQuery {
    /// Whether `candidate` satisfies this query's `format` and `meta`
    /// (`vct_values` / `doctype_value`) constraints.
    fn format_and_meta_match(&self, candidate: &CandidateCredential) -> bool {
        if self.format != candidate.format {
            return false;
        }
        let Some(meta) = &self.meta else {
            return true;
        };
        if let Some(vct_values) = meta.get("vct_values").and_then(|v| v.as_array()) {
            let ok = candidate
                .vct
                .as_deref()
                .is_some_and(|vct| vct_values.iter().any(|v| v.as_str() == Some(vct)));
            if !ok {
                return false;
            }
        }
        if let Some(doctype_value) = meta.get("doctype_value").and_then(|v| v.as_str())
            && candidate.doctype.as_deref() != Some(doctype_value)
        {
            return false;
        }
        true
    }

    /// Evaluate this query against one candidate: returns the claim paths to
    /// disclose when it matches (possibly empty — no `claims` constraint), or
    /// `None` when it does not.
    fn evaluate(&self, candidate: &CandidateCredential) -> Option<Vec<Vec<ClaimPathSegment>>> {
        if !self.format_and_meta_match(candidate) {
            return None;
        }
        if self.require_cryptographic_holder_binding() && !candidate.supports_holder_binding {
            return None;
        }
        let Some(claims) = &self.claims else {
            // No per-claim constraint: the credential as a whole matches.
            return Some(Vec::new());
        };
        match &self.claim_sets {
            // claim_sets: the first option whose every referenced claim resolves.
            Some(claim_sets) => claim_sets.iter().find_map(|option| {
                let mut paths = Vec::with_capacity(option.len());
                for claim_id in option {
                    let claim = claims.iter().find(|c| c.id.as_deref() == Some(claim_id))?;
                    if !claim.is_satisfied_by(&candidate.claims) {
                        return None;
                    }
                    paths.push(claim.path.clone());
                }
                Some(paths)
            }),
            // No claim_sets: every claim must resolve.
            None => {
                let mut paths = Vec::with_capacity(claims.len());
                for claim in claims {
                    if !claim.is_satisfied_by(&candidate.claims) {
                        return None;
                    }
                    paths.push(claim.path.clone());
                }
                Some(paths)
            }
        }
    }
}

impl DcqlQuery {
    /// Match this query against the holder's `candidates`, returning a satisfying
    /// [`DcqlMatch`] or [`Oid4vpError::NoMatchingCredentials`] when the request
    /// cannot be met.
    ///
    /// A credential query matches a candidate when `format`, `meta`
    /// (`vct_values` / `doctype_value`), cryptographic holder binding, and the
    /// `claims` / `claim_sets` all hold. When `multiple` is false (the default)
    /// the first matching candidate is taken; when true, all matching candidates
    /// are returned.
    ///
    /// Request satisfaction:
    /// - **With `credential_sets`:** every *required* set must have an `options`
    ///   entry whose credential queries all matched; an optional set contributes
    ///   its matches when satisfiable but never fails the request. Credential
    ///   queries not referenced by any satisfied set are omitted from the result.
    /// - **Without `credential_sets`:** *every* credential query must match.
    ///
    /// `self` is assumed [valid](DcqlQuery::validate); call `validate` first when
    /// the query came off the wire.
    pub fn match_credentials(
        &self,
        candidates: &[CandidateCredential],
    ) -> Result<DcqlMatch, Oid4vpError> {
        // Per credential query, the candidate matches (respecting `multiple`).
        let mut per_query: HashMap<&str, Vec<CredentialMatch>> = HashMap::new();
        for cq in &self.credentials {
            let mut matches = Vec::new();
            for candidate in candidates {
                if let Some(disclosed_paths) = cq.evaluate(candidate) {
                    matches.push(CredentialMatch {
                        credential_query_id: cq.id.clone(),
                        candidate_id: candidate.id.clone(),
                        disclosed_paths,
                    });
                    if !cq.multiple() {
                        break;
                    }
                }
            }
            per_query.insert(cq.id.as_str(), matches);
        }

        let query_matched = |id: &str| per_query.get(id).is_some_and(|m| !m.is_empty());

        // Which credential queries are selected by the (set-driven) request.
        let mut selected: Vec<&str> = Vec::new();
        match &self.credential_sets {
            Some(sets) => {
                for set in sets {
                    match set
                        .options
                        .iter()
                        .find(|option| option.iter().all(|id| query_matched(id)))
                    {
                        Some(option) => {
                            for id in option {
                                if !selected.contains(&id.as_str()) {
                                    selected.push(id.as_str());
                                }
                            }
                        }
                        None if set.is_required() => {
                            return Err(Oid4vpError::NoMatchingCredentials(
                                "no option of a required credential set could be satisfied".into(),
                            ));
                        }
                        None => {} // optional set, unsatisfied — skip.
                    }
                }
            }
            None => {
                for cq in &self.credentials {
                    if !query_matched(&cq.id) {
                        return Err(Oid4vpError::NoMatchingCredentials(format!(
                            "credential query `{}` matched no held credential",
                            cq.id
                        )));
                    }
                    selected.push(cq.id.as_str());
                }
            }
        }

        // Emit the matches for the selected queries, in credential-query order.
        let mut matches = Vec::new();
        for cq in &self.credentials {
            if selected.contains(&cq.id.as_str())
                && let Some(found) = per_query.get(cq.id.as_str())
            {
                matches.extend(found.iter().cloned());
            }
        }
        Ok(DcqlMatch { matches })
    }
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

#[cfg(test)]
mod match_tests {
    use super::*;
    use serde_json::json;

    /// An SD-JWT-VC candidate with the given vct + claims (holder-binding on).
    fn sd_jwt(id: &str, vct: &str, claims: Json) -> CandidateCredential {
        CandidateCredential {
            id: id.into(),
            format: "dc+sd-jwt".into(),
            claims,
            vct: Some(vct.into()),
            doctype: None,
            supports_holder_binding: true,
        }
    }

    const MEMBERSHIP_VCT: &str = "https://openvtc.org/credentials/MembershipCredential";

    #[test]
    fn matches_membership_and_selects_consented_paths() {
        let query = DcqlQuery::from_json(&json!({
            "credentials": [{
                "id": "membership",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": [MEMBERSHIP_VCT] },
                "claims": [{ "path": ["givenName"] }, { "path": ["memberSince"] }]
            }]
        }))
        .unwrap();

        let held = vec![sd_jwt(
            "cred-1",
            MEMBERSHIP_VCT,
            json!({ "givenName": "Alice", "memberSince": "2020", "dateOfBirth": "1990-01-01" }),
        )];

        let m = query.match_credentials(&held).expect("should match");
        assert_eq!(m.matches.len(), 1);
        assert_eq!(m.matches[0].credential_query_id, "membership");
        assert_eq!(m.matches[0].candidate_id, "cred-1");
        // Only the two requested claim paths — never dateOfBirth.
        assert_eq!(
            m.matches[0].disclosed_paths,
            vec![
                vec![ClaimPathSegment::Name("givenName".into())],
                vec![ClaimPathSegment::Name("memberSince".into())],
            ]
        );
    }

    #[test]
    fn wrong_vct_does_not_match() {
        let query = DcqlQuery::from_json(&json!({
            "credentials": [{
                "id": "m",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": [MEMBERSHIP_VCT] }
            }]
        }))
        .unwrap();
        let held = vec![sd_jwt("c", "https://example/SomethingElse", json!({}))];
        let err = query.match_credentials(&held).unwrap_err();
        assert!(
            matches!(err, Oid4vpError::NoMatchingCredentials(_)),
            "{err:?}"
        );
    }

    #[test]
    fn missing_required_claim_does_not_match() {
        let query = DcqlQuery::from_json(&json!({
            "credentials": [{
                "id": "m", "format": "dc+sd-jwt",
                "claims": [{ "path": ["givenName"] }, { "path": ["memberSince"] }]
            }]
        }))
        .unwrap();
        // Candidate lacks memberSince.
        let held = vec![sd_jwt("c", MEMBERSHIP_VCT, json!({ "givenName": "Alice" }))];
        assert!(query.match_credentials(&held).is_err());
    }

    #[test]
    fn value_constraint_is_enforced() {
        let query = DcqlQuery::from_json(&json!({
            "credentials": [{
                "id": "m", "format": "dc+sd-jwt",
                "claims": [{ "path": ["address", "country"], "values": ["US", "CA"] }]
            }]
        }))
        .unwrap();
        let us = vec![sd_jwt(
            "us",
            MEMBERSHIP_VCT,
            json!({ "address": { "country": "US" } }),
        )];
        let fr = vec![sd_jwt(
            "fr",
            MEMBERSHIP_VCT,
            json!({ "address": { "country": "FR" } }),
        )];
        assert_eq!(query.match_credentials(&us).unwrap().matches.len(), 1);
        assert!(query.match_credentials(&fr).is_err());
    }

    #[test]
    fn claim_sets_pick_first_satisfiable_option() {
        // Prefer {given, country}; fall back to {given}.
        let query = DcqlQuery::from_json(&json!({
            "credentials": [{
                "id": "id_card", "format": "dc+sd-jwt",
                "claims": [
                    { "id": "given", "path": ["givenName"] },
                    { "id": "country", "path": ["address", "country"] }
                ],
                "claim_sets": [["given", "country"], ["given"]]
            }]
        }))
        .unwrap();

        // Has both → first option; discloses two paths.
        let both = vec![sd_jwt(
            "c",
            MEMBERSHIP_VCT,
            json!({ "givenName": "Alice", "address": { "country": "US" } }),
        )];
        let m = query.match_credentials(&both).unwrap();
        assert_eq!(m.matches[0].disclosed_paths.len(), 2);

        // Only givenName → falls back to second option; discloses one path.
        let only_given = vec![sd_jwt("c", MEMBERSHIP_VCT, json!({ "givenName": "Alice" }))];
        let m = query.match_credentials(&only_given).unwrap();
        assert_eq!(
            m.matches[0].disclosed_paths,
            vec![vec![ClaimPathSegment::Name("givenName".into())]]
        );
    }

    #[test]
    fn holder_binding_requirement_excludes_unbound_candidate() {
        let query = DcqlQuery::from_json(&json!({
            "credentials": [{ "id": "m", "format": "dc+sd-jwt" }]  // require_* defaults true
        }))
        .unwrap();
        let mut cand = sd_jwt("c", MEMBERSHIP_VCT, json!({}));
        cand.supports_holder_binding = false;
        assert!(query.match_credentials(&[cand]).is_err());
    }

    #[test]
    fn credential_set_options_are_alternatives() {
        const PID_VCT: &str = "https://openvtc.org/credentials/PID";
        const ENDORSEMENT_VCT: &str = "https://openvtc.org/credentials/Endorsement";

        // Require a PID, AND (membership OR endorsement). Each query is pinned to
        // a distinct vct so a candidate satisfies exactly one query.
        let query = DcqlQuery::from_json(&json!({
            "credentials": [
                { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": [PID_VCT] } },
                { "id": "membership", "format": "dc+sd-jwt", "meta": { "vct_values": [MEMBERSHIP_VCT] } },
                { "id": "endorsement", "format": "dc+sd-jwt", "meta": { "vct_values": [ENDORSEMENT_VCT] } }
            ],
            "credential_sets": [
                { "options": [["pid"]] },
                { "options": [["membership"], ["endorsement"]] }
            ]
        }))
        .unwrap();

        // Holder has a PID + an endorsement (no membership) → satisfied via the
        // second option of the second set.
        let held = vec![
            sd_jwt("p", PID_VCT, json!({})),
            sd_jwt("e", ENDORSEMENT_VCT, json!({})),
        ];
        let m = query
            .match_credentials(&held)
            .expect("pid + endorsement satisfies");
        let ids: Vec<&str> = m
            .matches
            .iter()
            .map(|x| x.credential_query_id.as_str())
            .collect();
        assert!(ids.contains(&"pid") && ids.contains(&"endorsement"));
        assert!(
            !ids.contains(&"membership"),
            "membership query had no candidate"
        );

        // Missing the PID entirely → the required first set fails.
        let only_endorsement = vec![sd_jwt("e", ENDORSEMENT_VCT, json!({}))];
        assert!(query.match_credentials(&only_endorsement).is_err());
    }

    #[test]
    fn multiple_returns_all_matching_candidates() {
        let query = DcqlQuery::from_json(&json!({
            "credentials": [{
                "id": "m", "format": "dc+sd-jwt",
                "meta": { "vct_values": [MEMBERSHIP_VCT] },
                "multiple": true
            }]
        }))
        .unwrap();
        let held = vec![
            sd_jwt("a", MEMBERSHIP_VCT, json!({})),
            sd_jwt("b", MEMBERSHIP_VCT, json!({})),
        ];
        let m = query.match_credentials(&held).unwrap();
        assert_eq!(m.matches.len(), 2);
    }

    #[test]
    fn wildcard_path_matches_an_array_element_value() {
        let query = DcqlQuery::from_json(&json!({
            "credentials": [{
                "id": "m", "format": "dc+sd-jwt",
                "claims": [{ "path": ["nationalities", null], "values": ["US"] }]
            }]
        }))
        .unwrap();
        let us = vec![sd_jwt(
            "c",
            MEMBERSHIP_VCT,
            json!({ "nationalities": ["CA", "US"] }),
        )];
        let de = vec![sd_jwt(
            "c",
            MEMBERSHIP_VCT,
            json!({ "nationalities": ["DE"] }),
        )];
        assert_eq!(query.match_credentials(&us).unwrap().matches.len(), 1);
        assert!(query.match_credentials(&de).is_err());
    }
}

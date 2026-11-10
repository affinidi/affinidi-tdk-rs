//! Designated aliases: the verified source of `alsoKnownAs` (§ Designated
//! Aliases).
//!
//! `did:webs` does not let a DID document simply assert its own aliases. An
//! alias is only real if the AID **issued a credential saying so**, anchored in
//! its own key event log — a designation, verified as the designation
//! module describes, whose `a.ids` are the aliases.
//!
//! The designated aliases are every identifier in every attestation that
//! verifies and has not been revoked, as the reference implementation reads
//! them.

use crate::designation::designations;
use crate::errors::DidWebsError;
use crate::kel::Kels;

/// The aliases an AID has designated, and how far verification got.
#[derive(Debug, Clone, Default)]
pub struct DesignatedAliases {
    /// Aliases whose full chain verified.
    pub aliases: Vec<String>,
    /// Why an attestation the stream carried produced no aliases, when one did
    /// not verify.
    ///
    /// A stream with no attestation at all is not a failure — most `did:webs`
    /// identifiers designate nothing — so this stays `None` in that case.
    pub rejected: Option<String>,
}

/// The ACDC schema SAID for the designated-aliases attestation.
///
/// Fixed by the `did:webs` specification. Checking it is what stops an
/// unrelated credential the AID happens to have issued from being read as an
/// alias designation.
pub const DESIGNATED_ALIASES_SCHEMA: &str = "EN6Oh5XSD5_q2Hgu-aqpdfbVepdpYpFlgz6zvJL5b_r5";

/// The ACDC 2.x designated-aliases schema SAID: the v1 schema with `ri` as
/// `rd`, `t` added, and its version `2.0.0`, as proposed in
/// kswg-did-method-webs-specification#216.
pub const DESIGNATED_ALIASES_SCHEMA_V2: &str = "EF9Iy-vwD8GRKghnzHHGwAA6sC0VEWNtZ2Sf4tfd4IAA";

/// The ACDC 2.x designated-aliases schema.
pub const DESIGNATED_ALIASES_SCHEMA_V2_JSON: &str =
    include_str!("../schemas/designated-aliases-v2.json");

/// Collect the aliases `aid` has designated, verifying the whole chain.
///
/// Returns an empty list when the stream carries no designated-aliases
/// attestation.
///
/// # Errors
/// Returns [`DidWebsError::Kel`] only if `aid`'s own key event log does not
/// verify. An attestation that fails to verify is reported through
/// [`DesignatedAliases::rejected`], not as an error.
pub fn designated_aliases(kels: &Kels, aid: &str) -> Result<DesignatedAliases, DidWebsError> {
    let mut designated = DesignatedAliases::default();
    for attestation in designations(
        kels,
        aid,
        &[DESIGNATED_ALIASES_SCHEMA, DESIGNATED_ALIASES_SCHEMA_V2],
        &mut designated.rejected,
    )? {
        let Some(ids) = attestation.attributes.get("ids").and_then(|v| v.as_array()) else {
            designated
                .rejected
                .get_or_insert_with(|| "attestation carries no `a.ids` list".to_string());
            continue;
        };
        for alias in ids.iter().filter_map(|v| v.as_str()) {
            if !designated.aliases.iter().any(|a| a == alias) {
                designated.aliases.push(alias.to_string());
            }
        }
    }
    Ok(designated)
}

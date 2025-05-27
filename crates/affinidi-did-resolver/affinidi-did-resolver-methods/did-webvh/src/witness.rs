/*!
*   Handling of witnessing changes to the log entries
*/

use ahash::AHashSet;
use serde::{Deserialize, Serialize};
/// Witness nodes
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Witnesses {
    /// Number of witnesses required to witness a change
    /// Must be 1 or greater
    pub threshold: u32,

    /// Set of witness nodes
    pub witnesses: AHashSet<Witness>,
}

/// Single Witness Node
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Witness {
    pub id: String,
}

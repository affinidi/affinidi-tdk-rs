/*!
 * mDL (mobile Driving Licence) support per ISO 18013-5.
 *
 * This module is behind the `mdl` feature flag and provides:
 * - Typed `DrivingPrivileges` structure (Table 7)
 * - mDL schema validation with mandatory field checking (Table 5)
 * - mDL attribute name constants
 */

mod driving_privileges;
mod schema;

pub use driving_privileges::*;
pub use schema::*;

//! Schema-version marker and migration runner for the Fjall backend.
//!
//! The Redis backend tracks applied schema migrations in a `SCHEMA_MIGRATIONS`
//! set (`store::redis::database::migrations`) so a record-shape change is
//! applied exactly once. Fjall previously had no equivalent: a future change to
//! an on-disk record shape would silently deserialise old bytes as defaults
//! (`serde(default)`), corrupting state with no signal. This module gives the
//! embedded backend the same guard — a single version marker in the `globals`
//! partition plus a minimal, append-only migration registry.
//!
//! ## Adding a migration
//!
//! 1. Bump [`CURRENT_SCHEMA_VERSION`].
//! 2. Append a [`FjallMigration`] whose `version` equals the new value.
//! 3. Implement its `up` to rewrite the affected partition(s).
//!
//! On startup [`run_migrations`] reads the marker and compares it to
//! [`CURRENT_SCHEMA_VERSION`]:
//! - **no marker** → a fresh data dir, or one created before schema versioning
//!   existed. Both are at the baseline shape, so the current version is stamped
//!   and nothing is migrated.
//! - **marker == current** → up to date, no-op.
//! - **marker < current** → each pending migration runs in ascending order and
//!   the marker is advanced as each one lands.
//! - **marker > current** → the data dir was written by a *newer* mediator.
//!   Startup aborts with a clear error rather than risk misreading records the
//!   running binary doesn't understand.

use affinidi_messaging_mediator_common::errors::MediatorError;
use tracing::info;

use super::FjallStore;
use crate::common::error_codes;

/// `globals`-partition key holding the applied schema version, stored as
/// little-endian `u32`. Namespaced with leading/trailing underscores like the
/// circuit-breaker probe key so it can never collide with a counter name.
pub(super) const SCHEMA_VERSION_KEY: &[u8] = b"__schema_version__";

/// Schema version this binary understands. The current on-disk record shapes
/// are the baseline, version `1`. Bump this (and append a [`FjallMigration`])
/// whenever a stored record shape changes.
pub(super) const CURRENT_SCHEMA_VERSION: u32 = 1;

/// A single, idempotent forward migration that brings the data dir from
/// `version - 1` to `version`. The registry is append-only: a migration's
/// `version` must never change once released.
pub(super) struct FjallMigration {
    /// Target version this migration produces. Must equal the
    /// [`CURRENT_SCHEMA_VERSION`] it was introduced with.
    pub version: u32,
    /// Short name for logging.
    pub name: &'static str,
    /// Human-readable description of what the migration rewrites.
    pub description: &'static str,
    /// Rewrites the affected partition(s). Runs under no lock — a migration
    /// must be safe to re-run if the process dies mid-way (the marker is only
    /// advanced after `up` returns `Ok`).
    pub up: fn(&FjallStore) -> Result<(), MediatorError>,
}

/// All known migrations in ascending `version` order. New migrations are
/// appended here; the list is empty until the first record-shape change.
///
/// **Invariants** (enforced by tests): versions are unique, ascending, and
/// each is `> 0` and `<= CURRENT_SCHEMA_VERSION`; names are unique and
/// non-empty.
pub(super) fn all_migrations() -> Vec<FjallMigration> {
    vec![]
}

/// What [`run_migrations`] should do given the on-disk marker. Extracted as a
/// pure function so every branch is unit-testable without a real data dir.
#[derive(Debug, PartialEq, Eq)]
enum SchemaAction {
    /// No marker — stamp the current version, migrate nothing.
    Initialise,
    /// Marker equals current — no-op.
    UpToDate,
    /// Marker behind current — run these migration versions in order.
    Migrate(Vec<u32>),
    /// Marker ahead of current — abort; data dir is from a newer binary.
    TooNew { found: u32 },
}

/// Decide what to do for a stored marker against `current`, given the set of
/// `available` migration versions. Pending = available versions strictly above
/// the marker and at or below `current`, ascending.
fn plan_schema(stored: Option<u32>, current: u32, available: &[u32]) -> SchemaAction {
    match stored {
        None => SchemaAction::Initialise,
        Some(v) if v == current => SchemaAction::UpToDate,
        Some(v) if v < current => {
            let mut pending: Vec<u32> = available
                .iter()
                .copied()
                .filter(|&av| av > v && av <= current)
                .collect();
            pending.sort_unstable();
            SchemaAction::Migrate(pending)
        }
        Some(found) => SchemaAction::TooNew { found },
    }
}

/// Bring the store's data dir up to [`CURRENT_SCHEMA_VERSION`], running any
/// pending migrations. Called once from [`FjallStore::initialize`].
pub(super) fn run_migrations(store: &FjallStore) -> Result<(), MediatorError> {
    let stored = store.read_schema_version()?;
    let available: Vec<u32> = all_migrations().iter().map(|m| m.version).collect();

    match plan_schema(stored, CURRENT_SCHEMA_VERSION, &available) {
        SchemaAction::Initialise => {
            store.write_schema_version(CURRENT_SCHEMA_VERSION)?;
            info!("Fjall schema initialised at version {CURRENT_SCHEMA_VERSION}");
        }
        SchemaAction::UpToDate => {
            info!("Fjall schema up to date (version {CURRENT_SCHEMA_VERSION})");
        }
        SchemaAction::Migrate(versions) => {
            let from = stored.unwrap_or(0);
            info!(
                "Fjall schema behind (found {from}, want {CURRENT_SCHEMA_VERSION}); applying {} migration(s)",
                versions.len()
            );
            let registry = all_migrations();
            for v in versions {
                let migration = registry
                    .iter()
                    .find(|m| m.version == v)
                    .expect("planned migration version is present in the registry");
                info!(
                    "Running Fjall migration {} ({}) — {}",
                    migration.version, migration.name, migration.description
                );
                (migration.up)(store)?;
                // Advance the marker only after `up` succeeds, so a crash
                // mid-migration re-runs from the same point next boot.
                store.write_schema_version(migration.version)?;
                info!(
                    "Fjall migration {} ({}) applied",
                    migration.version, migration.name
                );
            }
            // Land the marker on the current version even when the latest
            // migration's version is below it (a pure marker bump with no data
            // change — normally they are equal).
            store.write_schema_version(CURRENT_SCHEMA_VERSION)?;
            info!("Fjall schema now at version {CURRENT_SCHEMA_VERSION}");
        }
        SchemaAction::TooNew { found } => {
            return Err(MediatorError::DatabaseError(
                error_codes::DB_SCHEMA_VERSION_ERROR,
                "fjall".into(),
                format!(
                    "Fjall data directory schema version {found} is newer than this \
                     mediator supports (max {CURRENT_SCHEMA_VERSION}). Upgrade the \
                     mediator binary, or point it at a data directory written by a \
                     compatible version."
                ),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // ─── Registry invariants (mirror the Redis migration suite) ──────────────

    #[test]
    fn migration_versions_are_unique() {
        let mut seen = HashSet::new();
        for m in all_migrations() {
            assert!(
                seen.insert(m.version),
                "duplicate migration version {}",
                m.version
            );
        }
    }

    #[test]
    fn migration_versions_are_ascending() {
        let migrations = all_migrations();
        for w in migrations.windows(2) {
            assert!(
                w[0].version < w[1].version,
                "migration versions not ascending: {} before {}",
                w[0].version,
                w[1].version
            );
        }
    }

    #[test]
    fn migration_versions_are_in_supported_range() {
        for m in all_migrations() {
            assert!(m.version > 0, "migration {} has version 0", m.name);
            assert!(
                m.version <= CURRENT_SCHEMA_VERSION,
                "migration {} ({}) targets version above CURRENT_SCHEMA_VERSION {}",
                m.version,
                m.name,
                CURRENT_SCHEMA_VERSION
            );
        }
    }

    #[test]
    fn migration_names_are_unique_and_non_empty() {
        let mut names = HashSet::new();
        for m in all_migrations() {
            assert!(
                !m.name.is_empty(),
                "migration {} has an empty name",
                m.version
            );
            assert!(
                !m.description.is_empty(),
                "migration {} has an empty description",
                m.version
            );
            assert!(names.insert(m.name), "duplicate migration name {}", m.name);
        }
    }

    // ─── plan_schema decision logic ──────────────────────────────────────────

    #[test]
    fn no_marker_initialises() {
        assert_eq!(plan_schema(None, 1, &[]), SchemaAction::Initialise);
    }

    #[test]
    fn marker_equal_to_current_is_up_to_date() {
        assert_eq!(plan_schema(Some(3), 3, &[1, 2, 3]), SchemaAction::UpToDate);
    }

    #[test]
    fn marker_ahead_of_current_is_too_new() {
        assert_eq!(
            plan_schema(Some(9), 3, &[1, 2, 3]),
            SchemaAction::TooNew { found: 9 }
        );
    }

    #[test]
    fn marker_behind_collects_pending_in_order() {
        // Out-of-order registry input is normalised to ascending pending.
        assert_eq!(
            plan_schema(Some(1), 4, &[4, 2, 3]),
            SchemaAction::Migrate(vec![2, 3, 4])
        );
    }

    #[test]
    fn marker_behind_with_no_registered_migrations_is_a_bare_bump() {
        // A version bump that needs no data rewrite: pending is empty, but the
        // runner still advances the marker to current.
        assert_eq!(plan_schema(Some(1), 2, &[]), SchemaAction::Migrate(vec![]));
    }

    #[test]
    fn pending_excludes_versions_above_current() {
        // A registry that knows about a future version must not run it when the
        // binary's current is lower.
        assert_eq!(
            plan_schema(Some(1), 2, &[2, 3]),
            SchemaAction::Migrate(vec![2])
        );
    }
}

/*!
 * Database schema migration system.
 *
 * Migrations are sequential, numbered operations that modify the Redis database
 * schema. Each migration runs exactly once. Applied migrations are tracked in a
 * Redis set (`SCHEMA_MIGRATIONS`) so the mediator knows which have already run.
 *
 * ## Adding a new migration
 *
 * 1. Create a new file: `m003_description.rs` with a `pub(crate) async fn up(...)`
 * 2. Add a variant to [`MigrationId`] and an entry in [`all_migrations()`]
 * 3. Implement the `up` function
 *
 * ## Redis keys used by the migration system
 *
 * - `SCHEMA_MIGRATIONS` (Set): IDs of all applied migrations (e.g. "1", "2")
 * - `SCHEMA_MIGRATION:{id}` (Hash): metadata for each applied migration
 *   - `name`: migration name
 *   - `applied_at`: unix timestamp (seconds) when it was applied
 */

pub(crate) mod m001_acl_queue_limit_flags;
pub(crate) mod m002_lua_perf_optimizations;
pub(crate) mod m003_backfill_role_type;
mod runner;

pub(crate) use runner::run_pending_migrations;

use crate::errors::MediatorError;
use crate::store::redis::database::Database;
use crate::store::redis::init::RedisInitConfig;

/// Descriptor for a database migration.
pub(crate) struct MigrationDef {
    /// Unique sequential ID. Must never change once deployed.
    pub id: u32,
    /// Short name for logging and audit trail.
    pub name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// The legacy SCHEMA_VERSION this migration was originally part of (if any).
    /// Used during bootstrap to seed the applied set from old-style version tracking.
    pub legacy_version: Option<&'static str>,
}

impl MigrationDef {
    /// Run this migration's up function.
    pub async fn run(&self, db: &Database, config: &RedisInitConfig) -> Result<(), MediatorError> {
        match self.id {
            1 => m001_acl_queue_limit_flags::up(db, config).await,
            2 => m002_lua_perf_optimizations::up(db, config).await,
            3 => m003_backfill_role_type::up(db, config).await,
            _ => Err(MediatorError::InternalError(
                17,
                "migrations".into(),
                format!("Unknown migration ID: {}", self.id),
            )),
        }
    }
}

/// Returns all migrations in sequential order. New migrations are appended here.
///
/// **Invariants** (enforced by tests):
/// - IDs must be unique
/// - IDs must be in ascending order
/// - Names must be unique
/// - Legacy versions (if any) must be valid semver
pub(crate) fn all_migrations() -> Vec<MigrationDef> {
    vec![
        MigrationDef {
            id: 1,
            name: "acl_queue_limit_flags",
            description: "Add self-manage queue limit ACL flags to existing accounts",
            legacy_version: Some("0.10.0"),
        },
        MigrationDef {
            id: 2,
            name: "lua_perf_optimizations",
            description: "Lua script performance and security optimizations (no data changes)",
            legacy_version: Some("0.14.0"),
        },
        MigrationDef {
            id: 3,
            name: "backfill_role_type",
            description: "Backfill ROLE_TYPE = Standard on legacy DID records that pre-date the role-type schema",
            legacy_version: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_migration_ids_are_unique() {
        let migrations = all_migrations();
        let mut ids = HashSet::new();
        for m in &migrations {
            assert!(
                ids.insert(m.id),
                "Duplicate migration ID: {} ({})",
                m.id,
                m.name
            );
        }
    }

    #[test]
    fn test_migration_ids_are_ascending() {
        let migrations = all_migrations();
        for window in migrations.windows(2) {
            assert!(
                window[0].id < window[1].id,
                "Migration IDs not in ascending order: {} ({}) should be before {} ({})",
                window[0].id,
                window[0].name,
                window[1].id,
                window[1].name
            );
        }
    }

    #[test]
    fn test_migration_names_are_unique() {
        let migrations = all_migrations();
        let mut names = HashSet::new();
        for m in &migrations {
            assert!(
                names.insert(m.name),
                "Duplicate migration name: {} (id: {})",
                m.name,
                m.id
            );
        }
    }

    #[test]
    fn test_legacy_versions_are_valid_semver() {
        let migrations = all_migrations();
        for m in &migrations {
            if let Some(lv) = m.legacy_version {
                assert!(
                    semver::Version::parse(lv).is_ok(),
                    "Migration {} ({}) has invalid legacy_version: {}",
                    m.id,
                    m.name,
                    lv
                );
            }
        }
    }

    #[test]
    fn test_migration_names_not_empty() {
        let migrations = all_migrations();
        for m in &migrations {
            assert!(!m.name.is_empty(), "Migration {} has empty name", m.id);
            assert!(
                !m.description.is_empty(),
                "Migration {} ({}) has empty description",
                m.id,
                m.name
            );
        }
    }

    #[test]
    fn test_at_least_one_migration_exists() {
        assert!(
            !all_migrations().is_empty(),
            "Migration registry should not be empty"
        );
    }
}

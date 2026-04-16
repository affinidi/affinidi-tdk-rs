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
mod runner;

pub(crate) use runner::run_pending_migrations;

use crate::common::config::Config;
use crate::database::Database;
use affinidi_messaging_mediator_common::errors::MediatorError;

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
    pub async fn run(&self, db: &Database, config: &Config) -> Result<(), MediatorError> {
        match self.id {
            1 => m001_acl_queue_limit_flags::up(db, config).await,
            2 => m002_lua_perf_optimizations::up(db, config).await,
            _ => Err(MediatorError::InternalError(
                17,
                "migrations".into(),
                format!("Unknown migration ID: {}", self.id),
            )),
        }
    }
}

/// Returns all migrations in order. New migrations are appended here.
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
    ]
}

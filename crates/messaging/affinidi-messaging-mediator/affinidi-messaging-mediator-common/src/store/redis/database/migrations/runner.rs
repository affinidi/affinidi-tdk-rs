/*!
 * Migration runner — checks which migrations have been applied and runs pending ones.
 *
 * Handles bootstrapping from the legacy GLOBAL:SCHEMA_VERSION system:
 * - If SCHEMA_MIGRATIONS set doesn't exist but GLOBAL:SCHEMA_VERSION does,
 *   seeds the migration set based on the legacy version.
 * - After bootstrap, removes the legacy SCHEMA_VERSION field.
 */

use super::{MigrationDef, all_migrations};
use crate::errors::MediatorError;
use crate::store::redis::database::Database;
use crate::store::redis::init::RedisInitConfig;
use semver::Version;
use std::collections::HashSet;
use tracing::{info, warn};

const MIGRATIONS_SET_KEY: &str = "SCHEMA_MIGRATIONS";

/// Run all pending migrations in order.
/// Called during mediator startup from database initialization.
pub(crate) async fn run_pending_migrations(
    db: &Database,
    config: &RedisInitConfig,
) -> Result<(), MediatorError> {
    let migrations = all_migrations();

    // Bootstrap: detect legacy schema version system and seed applied set
    let applied = bootstrap_if_needed(db, &migrations).await?;

    let pending: Vec<&MigrationDef> = migrations
        .iter()
        .filter(|m| !applied.contains(&m.id))
        .collect();

    if pending.is_empty() {
        info!(
            "Database schema is up to date ({} migrations applied)",
            applied.len()
        );
        return Ok(());
    }

    info!("{} pending migration(s) to apply", pending.len());

    for migration in pending {
        info!(
            "Running migration {}: {} — {}",
            migration.id, migration.name, migration.description
        );

        migration.run(db, config).await?;

        // Record the migration as applied
        record_migration(db, migration.id, migration.name).await?;

        info!(
            "Migration {} ({}) applied successfully",
            migration.id, migration.name
        );
    }

    info!(
        "All migrations complete. {} total applied.",
        get_applied_ids(db).await?.len()
    );

    Ok(())
}

/// Get the set of applied migration IDs from Redis.
async fn get_applied_ids(db: &Database) -> Result<HashSet<u32>, MediatorError> {
    let mut conn = db.get_connection().await?;

    let members: Vec<String> = redis::cmd("SMEMBERS")
        .arg(MIGRATIONS_SET_KEY)
        .query_async(&mut conn)
        .await
        .map_err(|e| {
            MediatorError::DatabaseError(
                14,
                "migrations".into(),
                format!("Failed to read {MIGRATIONS_SET_KEY}: {e}"),
            )
        })?;

    Ok(members.iter().filter_map(|s| s.parse().ok()).collect())
}

/// Record a migration as applied.
async fn record_migration(db: &Database, id: u32, name: &str) -> Result<(), MediatorError> {
    let mut conn = db.get_connection().await?;
    let now = crate::time::unix_timestamp_secs();

    redis::pipe()
        .cmd("SADD")
        .arg(MIGRATIONS_SET_KEY)
        .arg(id)
        .cmd("HSET")
        .arg(format!("SCHEMA_MIGRATION:{id}"))
        .arg("name")
        .arg(name)
        .arg("applied_at")
        .arg(now)
        .exec_async(&mut conn)
        .await
        .map_err(|e| {
            MediatorError::DatabaseError(
                14,
                "migrations".into(),
                format!("Failed to record migration {id}: {e}"),
            )
        })
}

/// Bootstrap from the legacy GLOBAL:SCHEMA_VERSION system.
///
/// If SCHEMA_MIGRATIONS doesn't exist yet but GLOBAL:SCHEMA_VERSION does,
/// we seed the applied set based on the legacy version. This ensures existing
/// databases don't re-run migrations that were already applied under the old system.
async fn bootstrap_if_needed(
    db: &Database,
    migrations: &[MigrationDef],
) -> Result<HashSet<u32>, MediatorError> {
    let mut conn = db.get_connection().await?;

    // Check if the new migration system is already in use
    let set_exists: bool = redis::cmd("EXISTS")
        .arg(MIGRATIONS_SET_KEY)
        .query_async(&mut conn)
        .await
        .map_err(|e| {
            MediatorError::DatabaseError(
                14,
                "migrations".into(),
                format!("Failed to check {MIGRATIONS_SET_KEY}: {e}"),
            )
        })?;

    if set_exists {
        // New system already active — just return the applied set
        return get_applied_ids(db).await;
    }

    // Check for legacy schema version
    let legacy_version: Option<String> = redis::cmd("HGET")
        .arg("GLOBAL")
        .arg("SCHEMA_VERSION")
        .query_async(&mut conn)
        .await
        .map_err(|e| {
            MediatorError::DatabaseError(
                14,
                "migrations".into(),
                format!("Failed to read legacy SCHEMA_VERSION: {e}"),
            )
        })?;

    if let Some(legacy_str) = legacy_version {
        // Existing database with legacy versioning — seed the migration set
        let legacy_ver = Version::parse(&legacy_str).unwrap_or_else(|_| {
            warn!(
                "Could not parse legacy SCHEMA_VERSION '{}', treating as 0.0.0",
                legacy_str
            );
            Version::new(0, 0, 0)
        });

        info!(
            "Bootstrapping migration system from legacy SCHEMA_VERSION {}",
            legacy_ver
        );

        // Mark all migrations that would have already been applied at this version
        let mut seeded = HashSet::new();
        for migration in migrations {
            if let Some(lv) = migration.legacy_version
                && let Ok(migration_ver) = Version::parse(lv)
                && legacy_ver >= migration_ver
            {
                info!(
                    "  Seeding migration {} ({}) — already applied at legacy version {}",
                    migration.id, migration.name, lv
                );
                record_migration(db, migration.id, migration.name).await?;
                seeded.insert(migration.id);
            }
        }

        // Remove legacy version field — migration system is now authoritative
        redis::cmd("HDEL")
            .arg("GLOBAL")
            .arg("SCHEMA_VERSION")
            .exec_async(&mut conn)
            .await
            .map_err(|e| {
                MediatorError::DatabaseError(
                    14,
                    "migrations".into(),
                    format!("Failed to remove legacy SCHEMA_VERSION: {e}"),
                )
            })?;

        info!(
            "Bootstrap complete: {} migrations seeded, legacy SCHEMA_VERSION removed",
            seeded.len()
        );

        Ok(seeded)
    } else {
        // Fresh database — no legacy version, no migrations applied yet
        info!("Fresh database detected — no migrations applied yet");
        Ok(HashSet::new())
    }
}

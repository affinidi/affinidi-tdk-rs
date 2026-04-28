/*!
 * Migration 2: Lua script performance and security optimizations
 *
 * No data migration required — Lua functions are auto-replaced via
 * FUNCTION LOAD REPLACE at startup. This migration records that the
 * database is compatible with the new Lua function signatures.
 *
 * Changes:
 * - store_message: optional queue_maxlen arg for MAXLEN on per-DID streams
 * - delete_message: explicit admin_did_hash instead of "ADMIN" magic string
 * - fetch_messages: batch MGET instead of per-message GET
 * - clean_start_streaming: SPOP batch limit (500)
 */

use crate::common::config::Config;
use crate::database::Database;
use affinidi_messaging_mediator_common::errors::MediatorError;
use tracing::info;

pub(crate) async fn up(_db: &Database, _config: &Config) -> Result<(), MediatorError> {
    info!("  Lua scripts will be updated via FUNCTION LOAD REPLACE at startup");
    info!("  - store_message: per-DID stream MAXLEN support");
    info!("  - delete_message: admin permission via DID hash (not magic string)");
    info!("  - fetch_messages: batch MGET optimization");
    info!("  - clean_start_streaming: SPOP batch limit");
    Ok(())
}

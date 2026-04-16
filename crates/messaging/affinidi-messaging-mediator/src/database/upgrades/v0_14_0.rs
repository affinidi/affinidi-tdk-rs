/*!
 * Upgrade to 0.14.0 — Redis performance and security improvements.
 *
 * Changes in this version:
 * - Lua `store_message`: accepts optional `queue_maxlen` arg (6th) for
 *   MAXLEN trimming on RECEIVE_Q/SEND_Q streams. Backward compatible —
 *   existing callers without the arg still work (unlimited streams).
 * - Lua `delete_message`: replaces hardcoded "ADMIN" string check with
 *   explicit `admin_did_hash` parameter (2nd arg). Mediator and processors
 *   now pass the admin DID hash for permission checks.
 * - Lua `fetch_messages`: uses batch MGET instead of per-message GET for
 *   message body retrieval. Same data, better performance.
 * - Lua `clean_start_streaming`: adds batch limit (500) to SPOP loop.
 * - Circuit breaker thresholds now configurable via database config.
 * - Redis auth/TLS warnings logged at startup.
 *
 * Data migration: None required. All Redis data structures are unchanged.
 * Lua functions are automatically replaced via FUNCTION LOAD REPLACE at
 * startup. The new Lua function signatures are backward compatible with
 * existing data.
 */
use crate::database::Database;
use affinidi_messaging_mediator_common::errors::MediatorError;
use tracing::info;

impl Database {
    pub(crate) async fn upgrade_0_14_0(&self) -> Result<(), MediatorError> {
        info!("Upgrading database schema to 0.14.0");
        info!("  - Lua scripts updated (FUNCTION LOAD REPLACE at startup)");
        info!("  - store_message: per-DID stream MAXLEN support added");
        info!(
            "  - delete_message: admin permission check now uses DID hash instead of magic string"
        );
        info!("  - fetch_messages: batch MGET optimization");
        info!("  - clean_start_streaming: SPOP batch limit added");

        self.upgrade_change_schema_version("0.14.0").await
    }
}

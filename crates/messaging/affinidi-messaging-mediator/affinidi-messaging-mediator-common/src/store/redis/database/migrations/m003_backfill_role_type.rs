/*!
 * Migration 3: Backfill `ROLE_TYPE` on legacy DID records.
 *
 * Mediators built before the role-type schema landed (the
 * `account_add` path that writes `ROLE_TYPE = "Standard"`) left
 * existing user DID records without that field. The post-fold
 * `get_session` flow reads `ROLE_TYPE` from the joined `DID:<hash>`
 * record and warns + errors if it's missing — which manifested in
 * production as `Error parsing role_type!` log spam right after an
 * upgrade.
 *
 * This migration scans every `DID:<hash>` record (via the existing
 * `account_list` cursor pagination) and writes `ROLE_TYPE = "Standard"`
 * on any record where the field is missing. Admin records are
 * skipped — `setup_admin_account` always writes `ROLE_TYPE` itself
 * and `account_list` returns the merged view already, so an admin
 * record that's missing `ROLE_TYPE` would be a separate bug.
 *
 * Idempotent: running twice writes the same value. Safe to apply
 * during a rolling restart.
 */

use crate::errors::MediatorError;
use crate::store::redis::database::Database;
use crate::store::redis::init::RedisInitConfig;
use affinidi_messaging_sdk::protocols::mediator::accounts::AccountType;
use tracing::info;

pub(crate) async fn up(db: &Database, _config: &RedisInitConfig) -> Result<(), MediatorError> {
    let mut conn = db.get_connection().await?;
    let mut cursor: u32 = 0;
    let mut backfilled: u32 = 0;
    let mut already_set: u32 = 0;

    loop {
        let page = db.account_list(cursor, 100).await?;
        for account in page.accounts {
            // `Account::_type` defaults to `Standard` when the
            // backend can't read `ROLE_TYPE` from Redis (see
            // `_to_account` in `database/accounts.rs`). That means
            // `account.role` alone can't distinguish "field missing"
            // from "field set to Standard". Probe Redis directly.
            let key = format!("DID:{}", account.did_hash);
            let role: Option<String> = redis::cmd("HGET")
                .arg(&key)
                .arg("ROLE_TYPE")
                .query_async(&mut conn)
                .await
                .map_err(|err| {
                    MediatorError::DatabaseError(
                        14,
                        account.did_hash.clone(),
                        format!("HGET ROLE_TYPE failed: {err}"),
                    )
                })?;

            if role.is_some() {
                already_set += 1;
                continue;
            }

            // Field genuinely missing — backfill with Standard.
            // Admin accounts are unaffected because their setup path
            // (`setup_admin_account`) writes `ROLE_TYPE` explicitly.
            redis::cmd("HSET")
                .arg(&key)
                .arg("ROLE_TYPE")
                .arg::<String>(AccountType::Standard.into())
                .exec_async(&mut conn)
                .await
                .map_err(|err| {
                    MediatorError::DatabaseError(
                        14,
                        account.did_hash.clone(),
                        format!("HSET ROLE_TYPE failed: {err}"),
                    )
                })?;
            backfilled += 1;
        }

        if page.cursor == 0 {
            break;
        }
        cursor = page.cursor;
    }

    info!(
        "  Backfilled ROLE_TYPE on {} legacy account record(s); {} already had the field",
        backfilled, already_set
    );
    Ok(())
}

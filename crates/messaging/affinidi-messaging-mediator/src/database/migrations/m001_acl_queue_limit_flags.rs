/*!
 * Migration 1: ACL queue limit flags
 *
 * Originally part of the v0.10.0 upgrade. Adds self-manage queue limit
 * ACL flags to all existing accounts based on the mediator's default ACL config.
 */

use crate::common::config::Config;
use crate::database::Database;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::protocols::mediator::acls::MediatorACLSet;
use tracing::info;

pub(crate) async fn up(db: &Database, config: &Config) -> Result<(), MediatorError> {
    let default_acl = &config.security.global_acl_default;
    let send_limit_flag = default_acl.get_self_manage_send_queue_limit();
    let receive_limit_flag = default_acl.get_self_manage_receive_queue_limit();

    if !send_limit_flag && !receive_limit_flag {
        info!("  No queue limit flags to update (not enabled in config)");
        return Ok(());
    }

    let mut cursor: u32 = 0;
    let mut counter = 0;
    loop {
        let dids = db.account_list(cursor, 100).await?;

        for account in dids.accounts {
            counter += 1;
            let mut acls = MediatorACLSet::from_u64(account.acls);
            if send_limit_flag {
                acls.set_self_manage_send_queue_limit(true);
            }
            if receive_limit_flag {
                acls.set_self_manage_receive_queue_limit(true);
            }
            db.set_did_acl(&account.did_hash, &acls).await?;
        }

        if dids.cursor == 0 {
            break;
        } else {
            cursor = dids.cursor;
        }
    }

    info!("  Updated {} accounts with queue limit ACL flags", counter);
    Ok(())
}

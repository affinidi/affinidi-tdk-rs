/*!
 * Upgrades to version 0.10.0
 *
 * Adds ACL Flag to set queue limits. Sets this flag based on the mediator configuration
 */
use crate::database::Database;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::protocols::mediator::acls::MediatorACLSet;
use tracing::info;

impl Database {
    /// No schema changes, simply update version number
    pub(crate) async fn upgrade_0_10_0(
        &self,
        default_acl: &MediatorACLSet,
    ) -> Result<(), MediatorError> {
        let send_limit_flag = default_acl.get_self_manage_send_queue_limit();
        let receive_limit_flag = default_acl.get_self_manage_receive_queue_limit();

        if send_limit_flag || receive_limit_flag {
            self.update_acl_flag_queue_limits(send_limit_flag, receive_limit_flag)
                .await?;
        }

        self.upgrade_change_schema_version("0.10.0").await
    }

    async fn update_acl_flag_queue_limits(
        &self,
        send: bool,
        receive: bool,
    ) -> Result<(), MediatorError> {
        // Update all accounts to have the self_change_queue_limit flag set to true
        let mut cursor: u32 = 0;
        let mut counter = 0;
        loop {
            let dids = self.account_list(cursor, 100).await?;

            for account in dids.accounts {
                counter += 1;

                let mut acls = MediatorACLSet::from_u64(account.acls);
                if send {
                    acls.set_self_manage_send_queue_limit(true);
                }
                if receive {
                    acls.set_self_manage_receive_queue_limit(true);
                }
                self.set_did_acl(&account.did_hash, &acls).await?;
            }

            if dids.cursor == 0 {
                break;
            } else {
                cursor = dids.cursor;
            }
        }
        info!(
            "Updated {} accounts with self_change_queue_limit flag",
            counter
        );
        Ok(())
    }

    pub(crate) async fn upgrade_0_10_9(&self) -> Result<(), MediatorError> {
        self.upgrade_change_schema_version("0.10.9").await
    }
}

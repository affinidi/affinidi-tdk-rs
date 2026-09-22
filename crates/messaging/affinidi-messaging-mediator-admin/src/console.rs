//! A connected console session.

use std::sync::Arc;

use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_sdk::{
    ATM, config::ATMConfig, messages::compat::UnpackMetadata, profiles::ATMProfile,
};
use affinidi_secrets_resolver::SecretsResolver;
use affinidi_tdk_common::{TDKSharedState, config::TDKConfig};
use serde_json::Value;
use trust_tasks_rs::specs::messaging::{account, message, queue, stats};
use trust_tasks_rs::specs::{audit, config};

use crate::error::{ConsoleError, Result};
use crate::identity::Identity;
use crate::live::{LiveStream, MonitorFeed, MonitorFilter};
use crate::purge::{PurgePlan, PurgeRequest};

/// Which account a call acts on: `None` is the console's own.
pub type Target = Option<String>;

/// What the connected account is at the mediator — decided by the mediator's
/// own record of it, never claimed by the console.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// An administrator: sees and manages every account. `root` adds the
    /// rootAdmin-only operations (reading another account's message bodies,
    /// acting on privileged accounts' queues, assigning rootAdmin).
    Admin { root: bool },
    /// Any other account: its own queues, messages, settings and traffic.
    SelfService,
}

/// What this session may do, so a console can grey out what the mediator
/// would refuse. The mediator still enforces every rule; this only saves a
/// round trip and an error.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Capabilities {
    /// Mediator-wide views: stats, the queue ranking, any account's queues and
    /// message metadata, the audit log, configuration, monitoring everyone.
    pub mediator_wide: bool,
    /// Read another account's message body; act on a privileged account's queue.
    pub root: bool,
    /// The account is served locally (has queues here). Needed for self-service
    /// message operations.
    pub local: bool,
    /// May edit its own access list.
    pub self_manage_list: bool,
    /// May change its own send-queue limit.
    pub self_manage_send_limit: bool,
    /// May change its own receive-queue limit.
    pub self_manage_receive_limit: bool,
}

/// A stored message fetched raw, and opened when this session can.
#[derive(Debug)]
pub struct InspectedMessage {
    pub meta: message::get::v0_1::MessageMeta,
    /// The envelope exactly as the mediator stores it.
    pub envelope: String,
    /// The decrypted message, when this session holds the recipient's
    /// key-agreement secret — its own messages, typically. `None` is the normal
    /// answer for someone else's message.
    pub opened: Option<(Message, UnpackMetadata)>,
}

/// A live console session with one mediator, as one identity.
pub struct MediatorConsole {
    atm: ATM,
    profile: Arc<ATMProfile>,
    did: String,
    did_hash: String,
    mediator_did: String,
    account: account::get::v0_1::Account,
    mode: Mode,
    capabilities: Capabilities,
    live: LiveStream,
    /// The mediator's release, from its `readyz` probe; `None` when it could
    /// not be read.
    mediator_version: Option<String>,
}

/// The first mediator release that serves the operations tasks the console is
/// built on: `messaging/stats`, `queue`, `message` and `monitor`.
pub const OPERATIONS_SINCE: (u64, u64, u64) = (0, 28, 20);

impl MediatorConsole {
    /// Connect as `identity`, with a private SDK instance.
    pub async fn connect(identity: Identity) -> Result<Self> {
        let config = TDKConfig::headless().map_err(|e| ConsoleError::Connect(e.to_string()))?;
        let tdk = TDKSharedState::new(config)
            .await
            .map_err(|e| ConsoleError::Connect(e.to_string()))?;
        let atm_config = ATMConfig::builder()
            .build()
            .map_err(|e| ConsoleError::Connect(e.to_string()))?;
        let atm = ATM::new(atm_config, Arc::new(tdk))
            .await
            .map_err(|e| ConsoleError::Connect(e.to_string()))?;
        Self::connect_with(atm, identity).await
    }

    /// Connect as `identity` through an existing SDK instance — for an
    /// application that embeds the console alongside its own messaging.
    /// `identity`'s secrets are added to that instance's resolver.
    pub async fn connect_with(atm: ATM, identity: Identity) -> Result<Self> {
        if identity.secrets.is_empty() {
            return Err(ConsoleError::Identity(format!(
                "{} has no secrets to connect with",
                identity.did
            )));
        }
        atm.get_tdk()
            .secrets_resolver()
            .insert_vec(&identity.secrets)
            .await;

        let mediator_did = match identity.mediator_did.clone() {
            Some(m) => m,
            None => discover_mediator(&atm, &identity.did).await?,
        };

        let profile = ATMProfile::new(
            &atm,
            Some(identity.alias.clone()),
            identity.did.clone(),
            Some(mediator_did.clone()),
        )
        .await
        .map_err(|e| ConsoleError::Connect(e.to_string()))?;
        // `ATMProfile::new` drops a mediator it could not set up rather than
        // failing; a profile without one would fail every call later, so say
        // so now.
        profile.dids().map_err(|_| {
            ConsoleError::Connect(format!(
                "could not reach mediator {mediator_did} for {}",
                identity.did
            ))
        })?;
        let profile = atm
            .profile_add(&profile, true)
            .await
            .map_err(|e| ConsoleError::Connect(e.to_string()))?;

        let account = atm
            .trust_tasks()
            .account_get(&profile, None)
            .await
            .map_err(ConsoleError::from_call)?;
        let (mode, capabilities) = classify(&account);
        let mediator_version = probe_version(&atm, &profile).await;
        let live = LiveStream::start(atm.clone(), profile.clone());

        Ok(Self {
            did_hash: sha256::digest(&identity.did),
            did: identity.did,
            mediator_did,
            atm,
            profile,
            account,
            mode,
            capabilities,
            live,
            mediator_version,
        })
    }

    /// The mediator's release, when it could be read at connect time.
    pub fn mediator_version(&self) -> Option<&str> {
        self.mediator_version.as_deref()
    }

    /// Whether the mediator serves the operations tasks: statistics, the queue
    /// ranking and queue status, message listing, reading, deleting and
    /// purging, and live traffic. Assumed to when its version is unknown;
    /// the mediator then answers for itself.
    pub fn serves_operations(&self) -> bool {
        self.mediator_version
            .as_deref()
            .and_then(parse_version)
            .is_none_or(|v| v >= OPERATIONS_SINCE)
    }

    /// Refuse locally, with the reason, a task this mediator is too old to
    /// serve. An older mediator doesn't answer such a request at all, so
    /// sending it would only wait out the reply timeout.
    fn require_operations(&self, task: &'static str) -> Result<()> {
        if self.serves_operations() {
            return Ok(());
        }
        let (major, minor, patch) = OPERATIONS_SINCE;
        Err(ConsoleError::Refused {
            code: "protocol.trust_task.unsupported".into(),
            comment: format!(
                "this mediator ({}) does not serve {task}: it needs \
                 affinidi-messaging-mediator {major}.{minor}.{patch} or later",
                self.mediator_version
                    .as_deref()
                    .unwrap_or("unknown version")
            ),
        })
    }

    pub fn did(&self) -> &str {
        &self.did
    }
    /// The console's own account identifier at the mediator.
    pub fn did_hash(&self) -> &str {
        &self.did_hash
    }
    pub fn mediator_did(&self) -> &str {
        &self.mediator_did
    }
    pub fn mode(&self) -> Mode {
        self.mode
    }
    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
    /// The account as the mediator reported it at connect time.
    pub fn account(&self) -> &account::get::v0_1::Account {
        &self.account
    }

    /// Re-read the console's own account and recompute mode and capabilities
    /// — after an administrator changed its role or ACL, for example.
    pub async fn refresh(&mut self) -> Result<()> {
        self.account = self
            .atm
            .trust_tasks()
            .account_get(&self.profile, None)
            .await
            .map_err(ConsoleError::from_call)?;
        (self.mode, self.capabilities) = classify(&self.account);
        Ok(())
    }

    fn require_admin(&self, what: &'static str) -> Result<()> {
        if self.capabilities.mediator_wide {
            Ok(())
        } else {
            Err(ConsoleError::NotPermitted(what))
        }
    }

    /// A target other than the console's own account needs admin standing.
    fn require_target(&self, target: &Target, what: &'static str) -> Result<()> {
        match target {
            Some(t) if *t != self.did_hash => self.require_admin(what),
            _ => Ok(()),
        }
    }

    // ─── Mediator-wide (administrators) ─────────────────────────────────

    pub async fn stats(&self) -> Result<stats::show::v0_1::Response> {
        self.require_admin("mediator statistics")?;
        self.require_operations("messaging/stats/show")?;
        self.atm
            .trust_tasks()
            .stats_show(&self.profile)
            .await
            .map_err(ConsoleError::from_call)
    }

    /// One page of accounts ranked by the given queue and key.
    pub async fn queues(
        &self,
        queue: Option<queue::list::v0_1::Queue>,
        sort: Option<queue::list::v0_1::PayloadSort>,
        cursor: Option<String>,
        limit: Option<u32>,
    ) -> Result<queue::list::v0_1::Response> {
        self.require_admin("the queue ranking")?;
        self.require_operations("messaging/queue/list")?;
        self.atm
            .trust_tasks()
            .queue_list(&self.profile, queue, sort, None, cursor, limit)
            .await
            .map_err(ConsoleError::from_call)
    }

    pub async fn accounts(
        &self,
        cursor: Option<String>,
        limit: Option<u32>,
    ) -> Result<account::list::v0_1::Response> {
        self.require_admin("the account list")?;
        self.atm
            .trust_tasks()
            .account_list(&self.profile, cursor, limit, None)
            .await
            .map_err(ConsoleError::from_call)
    }

    pub async fn audit(
        &self,
        cursor: Option<String>,
        page_size: Option<u32>,
    ) -> Result<audit::list::v0_1::Response> {
        self.require_admin("the audit log")?;
        self.atm
            .trust_tasks()
            .audit_list(&self.profile, cursor, page_size)
            .await
            .map_err(ConsoleError::from_call)
    }

    pub async fn config(&self) -> Result<config::show::v0_1::Response> {
        self.require_admin("the mediator configuration")?;
        self.atm
            .trust_tasks()
            .config_show(&self.profile, None)
            .await
            .map_err(ConsoleError::from_call)
    }

    // ─── One account (self, or any for an administrator) ────────────────

    pub async fn account_of(&self, target: Target) -> Result<account::get::v0_1::Account> {
        self.require_target(&target, "another account")?;
        self.atm
            .trust_tasks()
            .account_get(&self.profile, target)
            .await
            .map_err(ConsoleError::from_call)
    }

    /// Both queues of an account, live; `peers` adds the top counterparties.
    pub async fn queue_status(
        &self,
        target: Target,
        peers: Option<u32>,
    ) -> Result<queue::status::v0_1::Response> {
        self.require_target(&target, "another account's queues")?;
        self.require_operations("messaging/queue/status")?;
        self.atm
            .trust_tasks()
            .queue_status(&self.profile, target, peers)
            .await
            .map_err(ConsoleError::from_call)
    }

    /// One page of an account's queue: metadata only, oldest first.
    pub async fn messages(
        &self,
        target: Target,
        queue: message::list::v0_1::Queue,
        peer: Option<String>,
        cursor: Option<String>,
        limit: Option<u32>,
    ) -> Result<message::list::v0_1::Response> {
        self.require_target(&target, "another account's messages")?;
        self.require_operations("messaging/message/list")?;
        self.atm
            .trust_tasks()
            .message_list(&self.profile, target, queue, peer, cursor, limit)
            .await
            .map_err(ConsoleError::from_call)
    }

    /// Fetch one stored message and, if this session can decrypt it, open it.
    /// Opening happens here, locally; the plaintext never goes back to the
    /// mediator.
    pub async fn inspect(&self, target: Target, msg_id: &str) -> Result<InspectedMessage> {
        if target.as_ref().is_some_and(|t| *t != self.did_hash) && !self.capabilities.root {
            return Err(ConsoleError::NotPermitted(
                "reading another account's message body needs a rootAdmin",
            ));
        }
        self.require_operations("messaging/message/get")?;
        let got = self
            .atm
            .trust_tasks()
            .message_get(&self.profile, target, msg_id)
            .await
            .map_err(ConsoleError::from_call)?;
        let envelope = got.message.to_string();
        let opened = self.atm.unpack(&envelope).await.ok();
        Ok(InspectedMessage {
            meta: got.meta,
            envelope,
            opened,
        })
    }

    pub async fn delete(
        &self,
        target: Target,
        msg_ids: &[String],
    ) -> Result<message::delete::v0_1::Response> {
        self.require_target(&target, "another account's messages")?;
        self.require_operations("messaging/message/delete")?;
        self.atm
            .trust_tasks()
            .message_delete(&self.profile, target, msg_ids)
            .await
            .map_err(ConsoleError::from_call)
    }

    /// Count what a purge would remove, and return a plan to confirm.
    pub async fn purge_preview(&self, request: PurgeRequest) -> Result<PurgePlan> {
        self.require_target(&request.target, "another account's queue")?;
        let preview = self.run_purge(&request, true).await?;
        Ok(PurgePlan {
            matched: preview.matched,
            matched_bytes: preview.matched_bytes.unwrap_or(0),
            previewed_at: chrono::Utc::now(),
            request,
        })
    }

    /// Carry out a previewed purge — refusing, with nothing removed, when the
    /// queue no longer matches what was previewed, so a user never confirms
    /// one count and loses another.
    pub async fn purge(&self, plan: PurgePlan) -> Result<queue::purge::v0_1::Response> {
        let now = self.run_purge(&plan.request, true).await?;
        if now.matched != plan.matched {
            return Err(ConsoleError::PlanStale {
                previewed: plan.matched,
                now: now.matched,
            });
        }
        self.run_purge(&plan.request, false).await
    }

    async fn run_purge(
        &self,
        request: &PurgeRequest,
        dry_run: bool,
    ) -> Result<queue::purge::v0_1::Response> {
        self.require_operations("messaging/queue/purge")?;
        self.atm
            .trust_tasks()
            .queue_purge(
                &self.profile,
                request.target.clone(),
                request.queue,
                request.peer.clone(),
                request.older_than_seconds,
                dry_run,
            )
            .await
            .map_err(ConsoleError::from_call)
    }

    /// Apply a partial account update: role, capability flags, queue limits.
    /// Omitted members are unchanged.
    pub async fn update_account(
        &self,
        target: Target,
        role: Option<account::update::v0_1::AccountType>,
        acl: Option<account::update::v0_1::MediatorAcl>,
        limits: Option<account::update::v0_1::QueueLimits>,
    ) -> Result<account::update::v0_1::Account> {
        self.require_target(&target, "another account")?;
        if role.is_some() {
            self.require_admin("changing a role")?;
        }
        self.atm
            .trust_tasks()
            .account_update(&self.profile, target, role, acl, limits)
            .await
            .map_err(ConsoleError::from_call)
    }

    // ─── Live traffic ────────────────────────────────────────────────────

    /// Open a live traffic monitor. Administrators may watch anything; any
    /// other account only its own traffic. The feed renews its lease itself
    /// and unsubscribes when dropped.
    pub async fn monitor(&self, filter: MonitorFilter) -> Result<MonitorFeed> {
        self.require_operations("messaging/monitor/subscribe")?;
        self.live.open_feed(&self.atm, &self.profile, filter).await
    }

    /// The SDK instance, for an embedding application.
    pub fn atm(&self) -> &ATM {
        &self.atm
    }
    /// The console's SDK profile.
    pub fn profile(&self) -> &Arc<ATMProfile> {
        &self.profile
    }
}

impl Drop for MediatorConsole {
    fn drop(&mut self) {
        self.live.stop();
    }
}

/// Mode and capabilities from the mediator's record of the account.
fn classify(account: &account::get::v0_1::Account) -> (Mode, Capabilities) {
    let role = serde_json::to_value(account.account_type).unwrap_or(Value::Null);
    let role = role.as_str().unwrap_or("standard");
    let admin = matches!(role, "admin" | "rootAdmin");
    let root = role == "rootAdmin";
    let acl = serde_json::to_value(&account.acl).unwrap_or(Value::Null);
    let flag = |k: &str| acl.get(k).and_then(Value::as_bool).unwrap_or(false);
    let mode = if admin {
        Mode::Admin { root }
    } else {
        Mode::SelfService
    };
    (
        mode,
        Capabilities {
            mediator_wide: admin,
            root,
            local: flag("local"),
            self_manage_list: flag("selfManageList"),
            self_manage_send_limit: flag("selfManageSendQueueLimit"),
            self_manage_receive_limit: flag("selfManageReceiveQueueLimit"),
        },
    )
}

/// The mediator a DID names in its `DIDCommMessaging` service.
async fn discover_mediator(atm: &ATM, did: &str) -> Result<String> {
    let doc = atm
        .get_tdk()
        .did_resolver()
        .resolve(did)
        .await
        .map_err(|e| ConsoleError::Identity(format!("resolving {did}: {e}")))?
        .doc;
    doc.service
        .iter()
        .filter(|s| s.type_.iter().any(|t| t == "DIDCommMessaging"))
        .flat_map(|s| s.service_endpoint.get_uris())
        .find_map(|uri| mediator_did_in(&uri))
        .ok_or_else(|| ConsoleError::NoMediator(did.to_string()))
}

/// The mediator DID a `DIDCommMessaging` endpoint URI names, if it names one
/// (rather than a URL). `affinidi-did-common` before 0.4.3 returns a map-form
/// endpoint's `uri` JSON-quoted, so the quotes are stripped first.
fn mediator_did_in(uri: &str) -> Option<String> {
    let uri = uri.trim_matches('"');
    uri.starts_with("did:").then(|| uri.to_string())
}

/// The mediator's release from its public `readyz` endpoint, best effort: any
/// failure (no REST endpoint, unreachable, an older mediator without a
/// `version` member) is `None`.
async fn probe_version(atm: &ATM, profile: &ATMProfile) -> Option<String> {
    let base = profile.get_mediator_rest_endpoint()?;
    let url = format!("{}/readyz", base.trim_end_matches('/'));
    let response = atm
        .get_tdk()
        .client()
        .get(&url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .ok()?;
    let body: Value = response.json().await.ok()?;
    body["version"].as_str().map(str::to_string)
}

/// `major.minor.patch`, ignoring any pre-release or build suffix.
fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.split(['-', '+']).next()?;
    let mut parts = core.split('.').map(|p| p.parse::<u64>().ok());
    Some((parts.next()??, parts.next()??, parts.next()??))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(role: &str, acl: Value) -> account::get::v0_1::Account {
        serde_json::from_value(serde_json::json!({
            "did": "abc",
            "accountType": role,
            "acl": acl,
        }))
        .unwrap()
    }

    #[test]
    fn versions_parse_and_compare_against_the_operations_floor() {
        assert_eq!(parse_version("0.26.3"), Some((0, 26, 3)));
        assert_eq!(parse_version("0.28.20-rc.1"), Some((0, 28, 20)));
        assert_eq!(parse_version("nonsense"), None);
        assert!(parse_version("0.26.3").unwrap() < OPERATIONS_SINCE);
        assert!(parse_version("0.28.20").unwrap() >= OPERATIONS_SINCE);
        assert!(parse_version("0.29.0").unwrap() >= OPERATIONS_SINCE);
    }

    #[test]
    fn a_mediator_did_is_found_quoted_or_not_and_a_url_is_not_one() {
        let did = "did:webvh:Qm:example.com:mediator";
        assert_eq!(mediator_did_in(did).as_deref(), Some(did));
        assert_eq!(mediator_did_in(&format!("\"{did}\"")).as_deref(), Some(did));
        assert_eq!(mediator_did_in("https://mediator.example.com/"), None);
    }

    #[test]
    fn a_standard_account_is_self_service_with_its_flags() {
        let (mode, caps) = classify(&account(
            "standard",
            serde_json::json!({ "local": true, "selfManageList": true }),
        ));
        assert_eq!(mode, Mode::SelfService);
        assert!(!caps.mediator_wide && !caps.root);
        assert!(caps.local && caps.self_manage_list && !caps.self_manage_send_limit);
    }

    #[test]
    fn admins_and_root_admins_are_told_apart() {
        assert_eq!(
            classify(&account("admin", serde_json::json!({}))).0,
            Mode::Admin { root: false }
        );
        let (mode, caps) = classify(&account("rootAdmin", serde_json::json!({})));
        assert_eq!(mode, Mode::Admin { root: true });
        assert!(caps.mediator_wide && caps.root);
    }
}

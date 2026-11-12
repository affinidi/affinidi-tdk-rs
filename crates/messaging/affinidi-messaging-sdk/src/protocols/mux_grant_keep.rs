//! Keep stored mux grants alive: per-grant `auto_renew` and `auto_recreate`
//! (design §5.4, §5.3, §5.8 and §8), on either wire.
//!
//! A stored grant lasts until it expires, and it dies early when the
//! unknown-key rule suspends it, its signing key leaves the member DID's
//! document, or someone revokes it. The SDK does nothing about any of that
//! unless asked: both flags are off by default (§5.8). [`MuxGrantKeeper`] is
//! the opt-in, for grants whose member DIDs' keys this `ATM` holds:
//!
//! - **`auto_renew`**: sign a fresh grant (same member, same principal, never
//!   a wider scope) at 75 % of the grant's lifetime, or at once on a
//!   `grantsExpiring` notice for it. The new grant replaces the old one.
//! - **`auto_recreate`**: when the grant is `suspended` (a `grantsSuspended`
//!   notice, or `mux/list` says so), `staleKey` or `expired`, sign it again
//!   with the member DID's current key under its current epoch and grant it.
//!
//! **Never recreated:** a grant someone ended on purpose. A `grantsRevoked`
//! notice (`revokedByMember`, `epochBumped`, `admin`, `accountRemoved`, or
//! any reason this SDK does not know), a grant `mux/list` shows as
//! `epochRevoked`, a grant refused with `epochMismatch` on renewal (the member
//! ran revoke-all since), and a grant that disappeared from `mux/list` (a
//! `mux/revoke` deletes it). These end in [`MuxGrantStatus::Revoked`] and the
//! keeper leaves them alone. Re-granting such a member is the app's call; the
//! keeper picks up any new active grant it finds.
//!
//! The keeper never creates a grant the mediator does not already hold: a
//! member with no stored grant is [`MuxGrantStatus::NotStored`]. Create the
//! first grant with [`sign_grant`] and `mux_grant` / `TspMuxSender::grant`,
//! then [`MuxGrantKeeper::refresh`].
//!
//! # Notices
//!
//! The keeper does not read notices itself. On DIDComm they come from
//! `ATMProfile::mux_notices()`, and a subscriber there takes them out of the
//! ordinary message stream; on `tsp-mux` they come from the socket's single
//! receiver. Either way the app owns them and acknowledges them. So the app
//! hands each one to [`MuxGrantKeeper::handle_notice`], which returns once
//! the keeper has acted on it, and then acknowledges it as before (R1.6: one
//! acknowledger, after handling). A notice that concerns no kept member is
//! the app's to handle.
//!
//! # Bounds
//!
//! A failed grant is retried after 10 s, doubling to 5 min, at most 8 times
//! (R1.4); then the member waits for the next connection or
//! [`MuxGrantKeeper::refresh`]. A member is recreated at most 3 times an
//! hour: two devices that both hold the member DID's (different) keys and
//! both auto-recreate would otherwise suspend each other's grants for ever.
//!
//! [`sign_grant`]: super::mux::sign_grant

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;
use tracing::{debug, warn};

use super::mux::{MuxCapability, MuxNotice, MuxReady, sign_grant};
use crate::profiles::ATMProfile;
use crate::tasks::messaging::mux::{grant::v0_1 as grant_task, list::v0_1 as list_task};
use crate::{ATM, errors::ATMError};

/// One stored grant to keep: the member DID that signs it, the scope it
/// should have, how long each grant lasts, and what to do about it. Both
/// flags are off by default (§5.8); with both off the keeper only reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MuxGrantKeep {
    pub member_did: String,
    /// The most the grant may cover. A renewal or recreation signs the
    /// grant's current scope as the mediator reports it, within this; it
    /// never widens a narrowed grant.
    pub scope: Vec<MuxCapability>,
    /// Lifetime of each new grant, in seconds. Capped by the connection's
    /// `maxGrantLifetimeSeconds`.
    pub lifetime_secs: u64,
    /// Re-sign the grant before it expires.
    pub auto_renew: bool,
    /// Re-sign a suspended, stale-key or expired grant.
    pub auto_recreate: bool,
}

impl MuxGrantKeep {
    /// A grant to keep, with renewal and recreation off.
    pub fn new(member_did: impl Into<String>, scope: &[MuxCapability], lifetime_secs: u64) -> Self {
        Self {
            member_did: member_did.into(),
            scope: scope.to_vec(),
            lifetime_secs,
            auto_renew: false,
            auto_recreate: false,
        }
    }

    /// Turn `auto_renew` on or off.
    pub fn auto_renew(mut self, on: bool) -> Self {
        self.auto_renew = on;
        self
    }

    /// Turn `auto_recreate` on or off.
    pub fn auto_recreate(mut self, on: bool) -> Self {
        self.auto_recreate = on;
        self
    }
}

/// Why a stored grant is dead but could be signed again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MuxGrantLapse {
    /// The unknown-key rule suspended it (§5.3).
    Suspended,
    /// Its signing key left the member DID's authentication keys (§5.1).
    StaleKey,
    /// It reached its expiry.
    Expired,
}

/// Why a grant ended on purpose. The keeper never recreates these.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MuxGrantRevokeReason {
    /// The member revoked it (`mux/revoke` as member).
    RevokedByMember,
    /// The member ran revoke-all (its epoch moved on).
    EpochBumped,
    /// An operator acted.
    Admin,
    /// The member's or the principal's account was removed.
    AccountRemoved,
    /// It was in `mux/list` and is not any more: something deleted it
    /// (a `mux/revoke`) and no notice said why.
    Removed,
    /// A reason this SDK does not know (as the mediator wrote it).
    Other(String),
}

impl MuxGrantRevokeReason {
    fn from_wire(reason: &str) -> Self {
        match reason {
            "revokedByMember" => Self::RevokedByMember,
            "epochBumped" => Self::EpochBumped,
            "admin" => Self::Admin,
            "accountRemoved" => Self::AccountRemoved,
            other => Self::Other(other.to_string()),
        }
    }
}

/// Where one kept grant stands (R6.2). Times are seconds since the epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MuxGrantStatus {
    /// Not looked at yet (no connection has been up).
    Waiting,
    /// The mediator holds no grant from this member to this principal. The
    /// keeper never creates one.
    NotStored,
    /// The grant is active.
    Active { grant_id: String, expires_at: u64 },
    /// A renewal of this grant is being signed and sent.
    Renewing { grant_id: String },
    /// A dead grant is being signed again.
    Recreating { lapse: MuxGrantLapse },
    /// The grant was dead (`lapse`) and a new one is active.
    Recreated {
        grant_id: String,
        expires_at: u64,
        lapse: MuxGrantLapse,
    },
    /// Past 75 % of its lifetime, and `auto_renew` is off: it lapses at
    /// `expires_at` unless the app renews it.
    Expiring { grant_id: String, expires_at: u64 },
    /// Dead, and `auto_recreate` is off: the app must get a fresh grant
    /// signed (for `Suspended`, the notice said so).
    NeedsRecreate {
        grant_id: Option<String>,
        lapse: MuxGrantLapse,
    },
    /// The last renewal or recreation failed. `retrying` says whether the
    /// keeper tries again by itself; if not, it tries on the next connection
    /// or [`MuxGrantKeeper::refresh`].
    Failed { error: String, retrying: bool },
    /// Ended on purpose: never recreated.
    Revoked { reason: MuxGrantRevokeReason },
    /// The connection is gone for good: the keeper has stopped.
    Ended,
}

/// The wire a keeper grants and lists on. Shared by both wires.
pub(crate) trait GrantWire: Send + Sync + 'static {
    fn grant(
        &self,
        statements: Vec<Value>,
    ) -> impl Future<Output = Result<grant_task::Response, ATMError>> + Send;
    fn list(
        &self,
        cursor: Option<String>,
    ) -> impl Future<Output = Result<list_task::Response, ATMError>> + Send;
}

struct DidcommWire {
    atm: ATM,
    profile: Arc<ATMProfile>,
}

impl GrantWire for DidcommWire {
    async fn grant(&self, statements: Vec<Value>) -> Result<grant_task::Response, ATMError> {
        self.atm
            .trust_tasks()
            .mux_grant(&self.profile, statements)
            .await
    }
    async fn list(&self, cursor: Option<String>) -> Result<list_task::Response, ATMError> {
        self.atm
            .trust_tasks()
            .mux_list(&self.profile, false, cursor, None)
            .await
    }
}

/// Keep `members`' stored grants to `profile`'s DID, on its `didcomm-mux`
/// connection (opened with `ATM::profile_enable_mux_websocket`). Fails when
/// the profile has no mux connection, or a member is listed twice, has an
/// empty scope or a zero lifetime.
pub async fn keep_grants(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    members: Vec<MuxGrantKeep>,
) -> Result<MuxGrantKeeper, ATMError> {
    let ready = profile.mux_ready().await.ok_or_else(|| {
        ATMError::ConfigError(format!(
            "profile ({}) has no mux connection to keep grants on",
            profile.inner.alias
        ))
    })?;
    let (principal, mediator) = {
        let (p, m) = profile.dids()?;
        (p.to_string(), m.to_string())
    };
    spawn_grant_keep(
        atm.clone(),
        principal,
        mediator,
        members,
        ready,
        DidcommWire {
            atm: atm.clone(),
            profile: profile.clone(),
        },
    )
}

enum Cmd {
    Notice(Box<MuxNotice>, oneshot::Sender<Vec<String>>),
    Refresh(oneshot::Sender<()>),
}

/// Keeps a set of stored grants renewed and recreated, as each one opted
/// into. Dropping it stops it; the grants stay stored.
#[derive(Debug)]
pub struct MuxGrantKeeper {
    statuses: BTreeMap<String, watch::Receiver<MuxGrantStatus>>,
    cmd: mpsc::Sender<Cmd>,
    task: tokio::task::JoinHandle<()>,
}

impl MuxGrantKeeper {
    /// Where `member_did`'s grant stands, as a watch. `None` for a DID this
    /// keeper does not keep.
    pub fn status(&self, member_did: &str) -> Option<watch::Receiver<MuxGrantStatus>> {
        self.statuses.get(member_did).cloned()
    }

    /// Every kept member's current status.
    pub fn statuses(&self) -> BTreeMap<String, MuxGrantStatus> {
        self.statuses
            .iter()
            .map(|(did, rx)| (did.clone(), rx.borrow().clone()))
            .collect()
    }

    /// Act on a verified `messaging/mux/notice` (from
    /// `ATMProfile::mux_notices()`, or a `tsp-mux` socket's
    /// `TspMuxFrame::Notice`): renew on `grantsExpiring`, recreate on
    /// `grantsSuspended`, stop on `grantsRevoked`, each as the member opted
    /// into. Returns once the keeper has acted, with the kept members the
    /// notice concerned; then acknowledge the notice. The keeper never
    /// acknowledges it. A notice about an older grant than the one the
    /// keeper holds (one delivered twice) changes nothing.
    pub async fn handle_notice(&self, notice: &MuxNotice) -> Result<Vec<String>, ATMError> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(Cmd::Notice(Box::new(notice.clone()), tx))
            .await
            .map_err(|_| stopped())?;
        rx.await.map_err(|_| stopped())
    }

    /// Read the principal's grants again (`mux/list`) and act on what they
    /// say: after the app stored a grant itself, say. Returns once done.
    pub async fn refresh(&self) -> Result<(), ATMError> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(Cmd::Refresh(tx))
            .await
            .map_err(|_| stopped())?;
        rx.await.map_err(|_| stopped())
    }

    /// Stop keeping the grants.
    pub fn stop(self) {}
}

fn stopped() -> ATMError {
    ATMError::Disconnected("the mux grant keeper has stopped".into())
}

impl Drop for MuxGrantKeeper {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Renew at this fraction of a grant's lifetime.
const RENEW_AT: f64 = 0.75;
/// First retry delay after a failure; doubles up to [`RETRY_MAX`].
const RETRY_FIRST: Duration = Duration::from_secs(10);
const RETRY_MAX: Duration = Duration::from_secs(300);
/// Attempts before a member waits for the next connection or refresh.
const MAX_ATTEMPTS: u32 = 8;
/// Shortest wait before renewing a grant the keeper just stored.
const MIN_ROUND: Duration = Duration::from_secs(5);
/// At most this many recreations of one member per [`RECREATE_WINDOW`].
const RECREATE_BURST: usize = 3;
const RECREATE_WINDOW: Duration = Duration::from_secs(3600);
/// Pages of `mux/list` read per look.
const MAX_LIST_PAGES: usize = 100;
/// Statements per `mux/grant`.
const GRANT_BATCH: usize = 100;

/// Start a keeper for one connection's `ready` watch and wire. Shared by
/// both wires.
pub(crate) fn spawn_grant_keep<W: GrantWire>(
    atm: ATM,
    principal: String,
    mediator: String,
    members: Vec<MuxGrantKeep>,
    ready: watch::Receiver<Option<MuxReady>>,
    wire: W,
) -> Result<MuxGrantKeeper, ATMError> {
    if members.is_empty() {
        return Err(ATMError::ConfigError(
            "keep_grants needs at least one member".into(),
        ));
    }
    let mut kept: BTreeMap<String, Member> = BTreeMap::new();
    let mut statuses = BTreeMap::new();
    for cfg in members {
        if cfg.scope.is_empty() {
            // Empty means nothing, never everything (R5.1).
            return Err(ATMError::ConfigError(format!(
                "keep_grants: member {} has an empty scope",
                cfg.member_did
            )));
        }
        if cfg.lifetime_secs == 0 {
            return Err(ATMError::ConfigError(format!(
                "keep_grants: member {} has a zero lifetime",
                cfg.member_did
            )));
        }
        let (tx, rx) = watch::channel(MuxGrantStatus::Waiting);
        statuses.insert(cfg.member_did.clone(), rx);
        let did = cfg.member_did.clone();
        if kept.insert(did.clone(), Member::new(cfg, tx)).is_some() {
            return Err(ATMError::ConfigError(format!(
                "keep_grants: member {did} is listed twice"
            )));
        }
    }
    let (cmd_tx, cmd_rx) = mpsc::channel(16);
    let keeper = Keeper {
        atm,
        principal,
        mediator,
        wire,
        members: kept,
        max_lifetime: None,
        list_failures: 0,
    };
    let task = tokio::spawn(keeper.run(ready, cmd_rx));
    Ok(MuxGrantKeeper {
        statuses,
        cmd: cmd_tx,
        task,
    })
}

/// The grant the keeper last saw or stored for a member.
#[derive(Clone, Debug)]
struct Tracked {
    grant_id: String,
    iat: u64,
    /// Effective expiry.
    exp: u64,
    /// Effective scope.
    scope: Vec<MuxCapability>,
    epoch: u64,
    /// `None` while active.
    lapse: Option<MuxGrantLapse>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Due {
    Renew,
    /// Report `Expiring` (auto_renew off).
    Expiring,
    /// Look at the list again (the grant has expired).
    Check,
    Recreate(MuxGrantLapse),
}

struct Member {
    cfg: MuxGrantKeep,
    status: watch::Sender<MuxGrantStatus>,
    grant: Option<Tracked>,
    /// Ended on purpose: never recreate until an active grant shows up.
    revoked: bool,
    due: Option<(Instant, Due)>,
    /// Consecutive failed attempts.
    failures: u32,
    recreated: VecDeque<Instant>,
}

impl Member {
    fn new(cfg: MuxGrantKeep, status: watch::Sender<MuxGrantStatus>) -> Self {
        Self {
            cfg,
            status,
            grant: None,
            revoked: false,
            due: None,
            failures: 0,
            recreated: VecDeque::new(),
        }
    }

    fn set(&self, s: MuxGrantStatus) {
        self.status.send_replace(s);
    }

    fn end(&mut self, reason: MuxGrantRevokeReason) {
        self.revoked = true;
        self.due = None;
        self.failures = 0;
        self.set(MuxGrantStatus::Revoked { reason });
    }

    /// Schedule what a newly known active grant needs: renewal, or (renewal
    /// off) an `Expiring` report and a look at its expiry.
    fn schedule_active(&mut self, now_unix: u64) {
        let Some(g) = &self.grant else { return };
        let delay = renew_delay(g.iat, g.exp, now_unix);
        self.due = Some((
            Instant::now() + delay,
            if self.cfg.auto_renew {
                Due::Renew
            } else {
                Due::Expiring
            },
        ));
    }

    /// A dead grant: recreate it if opted into, else say it needs it.
    fn lapsed(&mut self, lapse: MuxGrantLapse) {
        if self.revoked {
            return;
        }
        if let Some(g) = &mut self.grant {
            g.lapse = Some(lapse);
        }
        let recreate = match lapse {
            MuxGrantLapse::Expired => self.cfg.auto_renew || self.cfg.auto_recreate,
            MuxGrantLapse::Suspended | MuxGrantLapse::StaleKey => self.cfg.auto_recreate,
        };
        if recreate {
            self.due = Some((Instant::now(), Due::Recreate(lapse)));
        } else {
            self.due = None;
            self.set(MuxGrantStatus::NeedsRecreate {
                grant_id: self.grant.as_ref().map(|g| g.grant_id.clone()),
                lapse,
            });
        }
    }

    /// Whether a notice naming `grant_ids` is about the grant held now (or
    /// none is known yet). A redelivered notice about a replaced grant is not.
    fn concerns(&self, grant_ids: &[String]) -> bool {
        match &self.grant {
            None => true,
            Some(g) => grant_ids.contains(&g.grant_id),
        }
    }

    /// The scope a new grant signs: the current grant's effective scope
    /// within the configured one, so it never widens.
    fn signing_scope(&self) -> Vec<MuxCapability> {
        match &self.grant {
            Some(g) => self
                .cfg
                .scope
                .iter()
                .copied()
                .filter(|c| g.scope.contains(c))
                .collect(),
            None => self.cfg.scope.clone(),
        }
    }

    /// Record a failure; retry with backoff until [`MAX_ATTEMPTS`].
    fn failed(&mut self, error: String, retryable: bool, due: Due) {
        self.failures += 1;
        let retrying = retryable && self.failures < MAX_ATTEMPTS;
        self.due = retrying.then(|| (Instant::now() + backoff(self.failures), due));
        self.set(MuxGrantStatus::Failed { error, retrying });
    }
}

/// When to renew a grant signed at `iat` with effective expiry `exp`, from
/// `now` (all seconds since the epoch): at [`RENEW_AT`] of its lifetime, at
/// once if that has passed.
pub(crate) fn renew_delay(iat: u64, exp: u64, now: u64) -> Duration {
    let life = exp.saturating_sub(iat) as f64;
    let at = iat as f64 + life * RENEW_AT;
    Duration::from_secs_f64((at - now as f64).max(0.0))
}

fn backoff(failures: u32) -> Duration {
    let d = RETRY_FIRST.saturating_mul(1u32 << failures.saturating_sub(1).min(16));
    d.min(RETRY_MAX)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn cap_from_wire(v: &impl serde::Serialize) -> Option<MuxCapability> {
    match serde_json::to_value(v).ok()?.as_str()? {
        "receive" => Some(MuxCapability::Receive),
        "pickup" => Some(MuxCapability::Pickup),
        "delete" => Some(MuxCapability::Delete),
        "send" => Some(MuxCapability::Send),
        _ => None,
    }
}

fn wire_str(v: &impl serde::Serialize) -> String {
    match serde_json::to_value(v) {
        Ok(Value::String(s)) => s,
        Ok(other) => other.to_string(),
        Err(_) => String::new(),
    }
}

/// Grant refusals worth trying again by themselves.
fn retryable_code(code: &str) -> bool {
    matches!(
        code,
        "messaging/mux:didUnresolvable"
            | "messaging/mux:notYetValid"
            | "messaging/mux/grant:replayed"
            | "messaging/mux/grant:contended"
    )
}

struct Keeper<W> {
    atm: ATM,
    principal: String,
    mediator: String,
    wire: W,
    members: BTreeMap<String, Member>,
    /// The connection's `maxGrantLifetimeSeconds`.
    max_lifetime: Option<u64>,
    /// Consecutive failed `mux/list` reads.
    list_failures: u32,
}

impl<W: GrantWire> Keeper<W> {
    async fn run(
        mut self,
        mut ready: watch::Receiver<Option<MuxReady>>,
        mut cmds: mpsc::Receiver<Cmd>,
    ) {
        let mut nonce: Option<String> = None;
        loop {
            let up = ready.borrow_and_update().clone();
            if let Some(r) = &up {
                self.max_lifetime = r.max_grant_lifetime_seconds;
                if nonce.as_deref() != Some(r.mux_nonce.as_str()) {
                    // A new connection: give every member its attempts back
                    // and look again.
                    nonce = Some(r.mux_nonce.clone());
                    self.list_failures = 0;
                    for m in self.members.values_mut() {
                        m.failures = 0;
                    }
                    self.look().await;
                }
                self.act_on_due().await;
            }
            // While no connection is up nothing is attempted, so nothing
            // wakes the loop but the connection or a command.
            let wake = up
                .is_some()
                .then(|| {
                    self.members
                        .values()
                        .filter_map(|m| m.due)
                        .map(|d| d.0)
                        .min()
                })
                .flatten();
            tokio::select! {
                changed = ready.changed() => {
                    if changed.is_err() {
                        for m in self.members.values() {
                            m.set(MuxGrantStatus::Ended);
                        }
                        return;
                    }
                }
                cmd = cmds.recv() => match cmd {
                    None => return,
                    Some(Cmd::Notice(notice, reply)) => {
                        let concerned = self.notice(&notice);
                        if ready.borrow().is_some() {
                            self.act_on_due().await;
                        }
                        let _ = reply.send(concerned);
                    }
                    Some(Cmd::Refresh(reply)) => {
                        if ready.borrow().is_some() {
                            self.list_failures = 0;
                            for m in self.members.values_mut() {
                                m.failures = 0;
                            }
                            self.look().await;
                            self.act_on_due().await;
                        }
                        let _ = reply.send(());
                    }
                },
                _ = sleep_until(wake) => {}
            }
        }
    }

    /// Apply a notice to the members it names. Returns them.
    fn notice(&mut self, notice: &MuxNotice) -> Vec<String> {
        let mut concerned = Vec::new();
        for s in &notice.suspensions {
            let ids: Vec<String> = s.grant_ids.iter().map(|g| g.as_str().to_string()).collect();
            if let Some(m) = self.members.get_mut(s.did.as_str())
                && m.concerns(&ids)
            {
                debug!(member = %s.did.as_str(), "mux grant suspended");
                m.failures = 0;
                if m.grant.is_none() {
                    // Not looked at yet: read the grant (and its epoch)
                    // before signing anything.
                    if !m.revoked {
                        m.due = Some((Instant::now(), Due::Check));
                    }
                } else {
                    m.lapsed(MuxGrantLapse::Suspended);
                }
                concerned.push(m.cfg.member_did.clone());
            }
        }
        for r in &notice.revocations {
            let ids: Vec<String> = r.grant_ids.iter().map(|g| g.as_str().to_string()).collect();
            if let Some(m) = self.members.get_mut(r.did.as_str())
                && m.concerns(&ids)
            {
                let reason = MuxGrantRevokeReason::from_wire(&wire_str(&r.reason));
                debug!(member = %r.did.as_str(), ?reason, "mux grant revoked; not recreating it");
                m.end(reason);
                concerned.push(m.cfg.member_did.clone());
            }
        }
        for e in &notice.expiring {
            let id = e.grant_id.as_str().to_string();
            if let Some(m) = self.members.get_mut(e.did.as_str())
                && !m.revoked
                && m.grant.as_ref().is_some_and(|g| g.grant_id == id)
            {
                if m.cfg.auto_renew {
                    m.failures = 0;
                    m.due = Some((Instant::now(), Due::Renew));
                } else {
                    m.set(MuxGrantStatus::Expiring {
                        grant_id: id,
                        expires_at: e.expires_at.timestamp().max(0) as u64,
                    });
                }
                concerned.push(m.cfg.member_did.clone());
            }
        }
        concerned
    }

    /// Read every grant the principal holds and bring each member up to date.
    async fn look(&mut self) {
        let mut found: HashMap<String, list_task::GrantView> = HashMap::new();
        let mut cursor = None;
        for _ in 0..MAX_LIST_PAGES {
            match self.wire.list(cursor.take()).await {
                Ok(page) => {
                    for g in page.grants {
                        let did = g.statement.issuer.as_str().to_string();
                        if self.members.contains_key(&did) {
                            found.insert(did, g);
                        }
                    }
                    match page.next_cursor {
                        Some(c) => cursor = Some(wire_str(&c)),
                        None => break,
                    }
                }
                Err(e) => {
                    warn!(principal = %self.principal, "mux/list failed: {e}");
                    // Leave every member as it was; look again with backoff,
                    // up to MAX_ATTEMPTS times on this connection.
                    self.list_failures += 1;
                    if self.list_failures < MAX_ATTEMPTS {
                        let at = Instant::now() + backoff(self.list_failures);
                        for m in self.members.values_mut() {
                            if m.due.is_none() && !m.revoked {
                                m.due = Some((at, Due::Check));
                            }
                        }
                    }
                    return;
                }
            }
        }
        self.list_failures = 0;
        let now = now_unix();
        for (did, m) in self.members.iter_mut() {
            apply_listed(m, found.remove(did), now);
        }
    }

    /// Run every action that is due, and what a look it makes brings due.
    async fn act_on_due(&mut self) {
        for _ in 0..3 {
            if !self.act_once().await {
                break;
            }
        }
    }

    /// One pass over due actions, with one `mux/grant` for all grants.
    /// Returns whether it looked at the list (which may bring more due).
    async fn act_once(&mut self) -> bool {
        let now = Instant::now();
        let mut look = false;
        let mut signing: Vec<(String, Due)> = Vec::new();
        for (did, m) in self.members.iter_mut() {
            let Some((at, due)) = m.due else { continue };
            if at > now || m.revoked {
                continue;
            }
            m.due = None;
            match due {
                Due::Check => look = true,
                Due::Expiring => {
                    if let Some(g) = &m.grant {
                        m.set(MuxGrantStatus::Expiring {
                            grant_id: g.grant_id.clone(),
                            expires_at: g.exp,
                        });
                        let left = g.exp.saturating_sub(now_unix());
                        m.due = Some((now + Duration::from_secs(left + 1), Due::Check));
                    }
                }
                Due::Renew => {
                    if let Some(g) = &m.grant {
                        m.set(MuxGrantStatus::Renewing {
                            grant_id: g.grant_id.clone(),
                        });
                    }
                    signing.push((did.clone(), due));
                }
                Due::Recreate(lapse) => {
                    while m
                        .recreated
                        .front()
                        .is_some_and(|t| now.duration_since(*t) >= RECREATE_WINDOW)
                    {
                        m.recreated.pop_front();
                    }
                    if m.recreated.len() >= RECREATE_BURST {
                        let next = m.recreated[0] + RECREATE_WINDOW;
                        m.due = Some((next, due));
                        m.set(MuxGrantStatus::Failed {
                            error: format!(
                                "recreated {RECREATE_BURST} times within an hour: another key \
                                 of this DID keeps suspending its grants; waiting"
                            ),
                            retrying: true,
                        });
                        continue;
                    }
                    m.set(MuxGrantStatus::Recreating { lapse });
                    signing.push((did.clone(), due));
                }
            }
        }
        if !signing.is_empty() {
            self.grant(signing).await;
        }
        if look {
            self.look().await;
        }
        look
    }

    /// Sign and send a grant for each `(member, why)`.
    async fn grant(&mut self, todo: Vec<(String, Due)>) {
        let mut sent: Vec<(String, Due, String, Value)> = Vec::new();
        for (did, due) in todo {
            let Some(m) = self.members.get_mut(&did) else {
                continue;
            };
            let scope = m.signing_scope();
            if scope.is_empty() {
                m.failed(
                    "the grant was narrowed to nothing in the kept scope".into(),
                    false,
                    due,
                );
                continue;
            }
            let lifetime = m
                .cfg
                .lifetime_secs
                .min(self.max_lifetime.unwrap_or(u64::MAX));
            let epoch = m.grant.as_ref().map(|g| g.epoch).unwrap_or(0);
            match sign_grant(
                &self.atm,
                &did,
                &self.principal,
                &self.mediator,
                &scope,
                epoch,
                lifetime,
            )
            .await
            {
                Ok((statement, grant_id)) => sent.push((did, due, grant_id, statement)),
                // No key for the member here: nothing will change that by
                // itself.
                Err(e) => m.failed(format!("couldn't sign the grant: {e}"), false, due),
            }
        }
        for chunk in sent.chunks(GRANT_BATCH) {
            let statements = chunk.iter().map(|s| s.3.clone()).collect();
            let answer = self.wire.grant(statements).await;
            for (did, due, grant_id, statement) in chunk {
                let Some(m) = self.members.get_mut(did) else {
                    continue;
                };
                let outcome = match &answer {
                    Ok(r) => r.results.iter().find(|o| o.grant_id.as_str() == grant_id),
                    Err(e) => {
                        m.failed(e.to_string(), true, *due);
                        continue;
                    }
                };
                apply_grant_outcome(m, *due, grant_id, statement, outcome);
            }
        }
    }
}

async fn sleep_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Bring a member up to date with what `mux/list` says about its grant.
fn apply_listed(m: &mut Member, view: Option<list_task::GrantView>, now: u64) {
    let Some(v) = view else {
        // A grant that was active and is gone was deleted (`mux/revoke`).
        let was_active = m.grant.as_ref().is_some_and(|g| g.lapse.is_none());
        if was_active && !m.revoked {
            m.grant = None;
            m.end(MuxGrantRevokeReason::Removed);
        } else if m.grant.is_none() && !m.revoked {
            m.due = None;
            m.set(MuxGrantStatus::NotStored);
        }
        return;
    };
    let state = wire_str(&v.state);
    let tracked = Tracked {
        grant_id: v.statement.grant_id.as_str().to_string(),
        iat: v.statement.iat,
        exp: v.expires_at.timestamp().max(0) as u64,
        scope: v.scope.0.iter().filter_map(cap_from_wire).collect(),
        epoch: v.statement.epoch,
        lapse: None,
    };
    let same = m
        .grant
        .as_ref()
        .is_some_and(|g| g.grant_id == tracked.grant_id);
    match state.as_str() {
        "active" => {
            if m.revoked && same {
                // The grant a revocation named, read before the revocation
                // reached the list: still ended.
                return;
            }
            // An active grant, even for a member whose earlier grant ended
            // and that the app granted again: keep it.
            m.revoked = false;
            let recreated = match m.status.borrow().clone() {
                MuxGrantStatus::Recreated {
                    grant_id, lapse, ..
                } if grant_id == tracked.grant_id => Some(lapse),
                _ => None,
            };
            let keep_due = same && m.due.is_some();
            let expiring = same && matches!(*m.status.borrow(), MuxGrantStatus::Expiring { .. });
            m.grant = Some(tracked);
            let g = m.grant.as_ref().expect("just set");
            if recreated.is_none() && !expiring {
                m.set(MuxGrantStatus::Active {
                    grant_id: g.grant_id.clone(),
                    expires_at: g.exp,
                });
            }
            if !keep_due {
                m.schedule_active(now);
            }
        }
        "epochRevoked" => {
            m.grant = Some(tracked);
            if !m.revoked {
                m.end(MuxGrantRevokeReason::EpochBumped);
            }
        }
        dead => {
            let lapse = match dead {
                "suspended" => MuxGrantLapse::Suspended,
                "staleKey" => MuxGrantLapse::StaleKey,
                _ => MuxGrantLapse::Expired,
            };
            // Already being recreated for this grant: leave the schedule.
            let pending = same && matches!(m.due, Some((_, Due::Recreate(_))));
            m.grant = Some(tracked);
            if !pending {
                m.lapsed(lapse);
            }
        }
    }
}

/// Apply the mediator's answer to one grant the keeper sent.
fn apply_grant_outcome(
    m: &mut Member,
    due: Due,
    grant_id: &str,
    statement: &Value,
    outcome: Option<&grant_task::GrantOutcome>,
) {
    let Some(o) = outcome else {
        m.failed(
            "the mediator did not answer for this grant".into(),
            true,
            due,
        );
        return;
    };
    if wire_str(&o.status) == "stored" {
        let u = |k: &str| statement.get(k).and_then(Value::as_u64).unwrap_or(0);
        let (iat, exp) = (u("iat"), u("exp"));
        let scope = statement
            .get("scope")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(cap_from_wire).collect())
            .unwrap_or_default();
        m.grant = Some(Tracked {
            grant_id: grant_id.to_string(),
            iat,
            exp,
            scope,
            epoch: u("epoch"),
            lapse: None,
        });
        m.failures = 0;
        if matches!(due, Due::Recreate(_)) {
            m.recreated.push_back(Instant::now());
        }
        m.set(match due {
            Due::Recreate(lapse) => MuxGrantStatus::Recreated {
                grant_id: grant_id.to_string(),
                expires_at: exp,
                lapse,
            },
            _ => MuxGrantStatus::Active {
                grant_id: grant_id.to_string(),
                expires_at: exp,
            },
        });
        let life = Duration::from_secs(exp.saturating_sub(iat));
        let next = life.mul_f64(RENEW_AT).max(MIN_ROUND);
        m.due = Some((
            Instant::now() + next,
            if m.cfg.auto_renew {
                Due::Renew
            } else {
                Due::Expiring
            },
        ));
        return;
    }
    let code = o.code.as_ref().map(wire_str).unwrap_or_default();
    if code == "messaging/mux/grant:epochMismatch" {
        // The member ran revoke-all since this grant's epoch: deliberate.
        // Never re-sign under the new epoch by ourselves.
        m.end(MuxGrantRevokeReason::EpochBumped);
        return;
    }
    m.failed(format!("grant refused: {code}"), retryable_code(&code), due);
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_secrets_resolver::SecretsResolver;
    use affinidi_secrets_resolver::secrets::Secret;
    use serde_json::json;
    use std::sync::Mutex;
    use tokio::time::timeout;

    const PRINCIPAL: &str = "did:example:phone";
    const MEDIATOR: &str = "did:example:mediator";

    fn ready(nonce: &str) -> MuxReady {
        MuxReady {
            session_id: "sess".into(),
            mux_nonce: nonce.into(),
            max_dids_per_connection: None,
            max_attach_lifetime_seconds: None,
            max_grant_lifetime_seconds: Some(86_400),
            pending_notices: None,
        }
    }

    /// An `ATM` holding an offline-resolvable `did:key` member's key.
    async fn atm_with_member() -> (ATM, String) {
        use affinidi_tdk_common::{TDKSharedState, config::TDKConfig};
        let tdk = Arc::new(
            TDKSharedState::new(TDKConfig::headless().unwrap())
                .await
                .unwrap(),
        );
        let seed = [11u8; 32];
        let mb = Secret::generate_ed25519(None, Some(&seed))
            .get_public_keymultibase()
            .unwrap();
        let did = format!("did:key:{mb}");
        tdk.secrets_resolver()
            .insert(Secret::generate_ed25519(
                Some(&format!("{did}#{mb}")),
                Some(&seed),
            ))
            .await;
        let atm = ATM::new(crate::config::ATMConfig::builder().build().unwrap(), tdk)
            .await
            .unwrap();
        (atm, did)
    }

    /// A mediator's grant store, in memory: what `mux/list` shows and what
    /// `mux/grant` stores, with a refusal to give on the next grant.
    #[derive(Clone, Default)]
    struct FakeWire {
        inner: Arc<Mutex<FakeState>>,
    }

    #[derive(Default)]
    struct FakeState {
        /// By member DID: (statement, state, effective scope).
        grants: BTreeMap<String, (Value, String)>,
        sent: Vec<Value>,
        refuse_next: Option<(String, Option<u64>)>,
        lists: usize,
    }

    impl FakeWire {
        fn store(&self, did: &str, grant_id: &str, iat: u64, exp: u64, state: &str) {
            let statement = json!({
                "type": "muxGrant", "issuer": did, "audience": MEDIATOR,
                "grantId": grant_id, "principal": PRINCIPAL,
                "scope": ["receive", "pickup"], "epoch": 0, "iat": iat, "exp": exp,
                "proof": {
                    "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022",
                    "proofPurpose": "authentication",
                    "verificationMethod": format!("{did}#k"),
                    "proofValue": "z5555"
                }
            });
            self.inner
                .lock()
                .unwrap()
                .grants
                .insert(did.to_string(), (statement, state.to_string()));
        }
        fn set_state(&self, did: &str, state: &str) {
            self.inner.lock().unwrap().grants.get_mut(did).unwrap().1 = state.into();
        }
        fn remove(&self, did: &str) {
            self.inner.lock().unwrap().grants.remove(did);
        }
        fn sent(&self) -> Vec<Value> {
            self.inner.lock().unwrap().sent.clone()
        }
        fn lists(&self) -> usize {
            self.inner.lock().unwrap().lists
        }
    }

    impl GrantWire for FakeWire {
        async fn grant(&self, statements: Vec<Value>) -> Result<grant_task::Response, ATMError> {
            let mut s = self.inner.lock().unwrap();
            let mut results = Vec::new();
            for st in statements {
                s.sent.push(st.clone());
                let did = st["issuer"].as_str().unwrap().to_string();
                let gid = st["grantId"].as_str().unwrap().to_string();
                if let Some((code, epoch)) = s.refuse_next.take() {
                    let mut r = json!({ "status": "refused", "code": code, "grantId": gid,
                                        "did": did, "principal": PRINCIPAL });
                    if let Some(e) = epoch {
                        r["currentEpoch"] = json!(e);
                    }
                    results.push(r);
                    continue;
                }
                s.grants.insert(did.clone(), (st, "active".into()));
                results.push(json!({ "status": "stored", "grantId": gid, "did": did,
                                     "principal": PRINCIPAL, "attachedNow": true }));
            }
            Ok(serde_json::from_value(json!({ "results": results })).unwrap())
        }

        async fn list(&self, _cursor: Option<String>) -> Result<list_task::Response, ATMError> {
            let mut s = self.inner.lock().unwrap();
            s.lists += 1;
            let grants: Vec<Value> = s
                .grants
                .values()
                .map(|(st, state)| {
                    let exp = st["exp"].as_i64().unwrap();
                    let at = chrono::DateTime::from_timestamp(exp, 0).unwrap();
                    json!({ "statement": st, "state": state, "scope": st["scope"],
                            "expiresAt": at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true) })
                })
                .collect();
            Ok(serde_json::from_value(
                json!({ "as": "principal", "grants": grants, "attachments": [] }),
            )
            .unwrap())
        }
    }

    fn spawn(
        atm: ATM,
        members: Vec<MuxGrantKeep>,
        wire: FakeWire,
    ) -> (MuxGrantKeeper, watch::Sender<Option<MuxReady>>) {
        let (tx, rx) = watch::channel(Some(ready("n1")));
        let k =
            spawn_grant_keep(atm, PRINCIPAL.into(), MEDIATOR.into(), members, rx, wire).unwrap();
        (k, tx)
    }

    async fn becomes(
        k: &MuxGrantKeeper,
        did: &str,
        f: impl Fn(&MuxGrantStatus) -> bool,
    ) -> MuxGrantStatus {
        let mut rx = k.status(did).unwrap();
        timeout(Duration::from_secs(5), rx.wait_for(|s| f(s)))
            .await
            .unwrap_or_else(|_| {
                panic!("status within 5s; is {:?}", k.status(did).unwrap().borrow())
            })
            .expect("status")
            .clone()
    }

    fn notice(v: Value) -> MuxNotice {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn renews_at_three_quarters_of_the_lifetime() {
        assert_eq!(renew_delay(1000, 1400, 1000), Duration::from_secs(300));
        assert_eq!(renew_delay(1000, 1400, 1250), Duration::from_secs(50));
        // Past the point: at once.
        assert_eq!(renew_delay(1000, 1400, 1390), Duration::ZERO);
        assert_eq!(renew_delay(1000, 900, 1000), Duration::ZERO);
    }

    #[test]
    fn retries_back_off_and_stop() {
        assert_eq!(backoff(1), Duration::from_secs(10));
        assert_eq!(backoff(2), Duration::from_secs(20));
        assert_eq!(backoff(4), Duration::from_secs(80));
        assert_eq!(backoff(30), RETRY_MAX);
    }

    #[test]
    fn revoke_reasons_are_read_from_the_wire() {
        assert_eq!(
            MuxGrantRevokeReason::from_wire("revokedByMember"),
            MuxGrantRevokeReason::RevokedByMember
        );
        assert_eq!(
            MuxGrantRevokeReason::from_wire("epochBumped"),
            MuxGrantRevokeReason::EpochBumped
        );
        assert_eq!(
            MuxGrantRevokeReason::from_wire("somethingNew"),
            MuxGrantRevokeReason::Other("somethingNew".into())
        );
    }

    #[tokio::test]
    async fn refuses_bad_member_lists() {
        let (atm, did) = atm_with_member().await;
        let (_tx, rx) = watch::channel(None);
        let go = |m: Vec<MuxGrantKeep>| {
            spawn_grant_keep(
                atm.clone(),
                "p".into(),
                "m".into(),
                m,
                rx.clone(),
                FakeWire::default(),
            )
            .is_err()
        };
        assert!(go(vec![]));
        assert!(go(vec![MuxGrantKeep::new(did.clone(), &[], 60)]));
        assert!(go(vec![MuxGrantKeep::new(
            did.clone(),
            &[MuxCapability::Receive],
            0
        )]));
        let one = MuxGrantKeep::new(did, &[MuxCapability::Receive], 60);
        assert!(go(vec![one.clone(), one]));
    }

    /// The keeper never creates a grant: with none stored it says so.
    #[tokio::test]
    async fn a_member_with_no_grant_is_reported_not_created() {
        let (atm, did) = atm_with_member().await;
        let wire = FakeWire::default();
        let keep = MuxGrantKeep::new(did.clone(), &[MuxCapability::Receive], 600)
            .auto_renew(true)
            .auto_recreate(true);
        let (k, _tx) = spawn(atm, vec![keep], wire.clone());
        becomes(&k, &did, |s| *s == MuxGrantStatus::NotStored).await;
        assert!(wire.sent().is_empty());
    }

    /// An active grant is renewed at 75 % of its lifetime with a fresh
    /// signature, the same scope and a new grant id; then renewed again.
    #[tokio::test(start_paused = true)]
    async fn renews_before_the_grant_expires() {
        let (atm, did) = atm_with_member().await;
        let wire = FakeWire::default();
        let now = now_unix();
        wire.store(&did, "g0", now, now + 400, "active");
        let keep = MuxGrantKeep::new(did.clone(), &[MuxCapability::Receive], 400).auto_renew(true);
        let (k, _tx) = spawn(atm, vec![keep], wire.clone());
        becomes(
            &k,
            &did,
            |s| matches!(s, MuxGrantStatus::Active { grant_id, .. } if grant_id == "g0"),
        )
        .await;
        // Not before 75 %.
        tokio::time::sleep(Duration::from_secs(290)).await;
        assert!(wire.sent().is_empty(), "renewed too early");
        tokio::time::sleep(Duration::from_secs(20)).await;
        let s = becomes(
            &k,
            &did,
            |s| matches!(s, MuxGrantStatus::Active { grant_id, .. } if grant_id != "g0"),
        )
        .await;
        let sent = wire.sent();
        assert_eq!(sent.len(), 1);
        let st = &sent[0];
        assert_eq!(st["type"], "muxGrant");
        assert_eq!(st["issuer"], did);
        assert_eq!(st["principal"], PRINCIPAL);
        assert_eq!(st["audience"], MEDIATOR);
        // The listed grant had receive+pickup, the kept scope is receive:
        // never wider than either.
        assert_eq!(st["scope"], json!(["receive"]));
        assert!(st.get("proof").is_some());
        let MuxGrantStatus::Active { grant_id, .. } = s else {
            unreachable!()
        };
        assert_eq!(st["grantId"], grant_id);
        // And again at 75 % of the new grant's lifetime.
        tokio::time::sleep(Duration::from_secs(310)).await;
        becomes(
            &k,
            &did,
            |s| matches!(s, MuxGrantStatus::Active { grant_id: g, .. } if *g != grant_id),
        )
        .await;
        assert_eq!(wire.sent().len(), 2);
    }

    /// With auto_renew off nothing is signed: the grant is reported expiring.
    #[tokio::test(start_paused = true)]
    async fn without_auto_renew_an_expiring_grant_is_only_reported() {
        let (atm, did) = atm_with_member().await;
        let wire = FakeWire::default();
        let now = now_unix();
        wire.store(&did, "g0", now, now + 400, "active");
        let keep = MuxGrantKeep::new(did.clone(), &[MuxCapability::Receive], 400);
        let (k, _tx) = spawn(atm, vec![keep], wire.clone());
        becomes(&k, &did, |s| matches!(s, MuxGrantStatus::Active { .. })).await;
        tokio::time::sleep(Duration::from_secs(310)).await;
        becomes(
            &k,
            &did,
            |s| matches!(s, MuxGrantStatus::Expiring { grant_id, .. } if grant_id == "g0"),
        )
        .await;
        assert!(wire.sent().is_empty());
    }

    /// A `grantsExpiring` notice renews at once (auto_renew on).
    #[tokio::test]
    async fn an_expiring_notice_renews_now() {
        let (atm, did) = atm_with_member().await;
        let wire = FakeWire::default();
        let now = now_unix();
        wire.store(&did, "g0", now, now + 4000, "active");
        let keep = MuxGrantKeep::new(did.clone(), &[MuxCapability::Receive], 4000).auto_renew(true);
        let (k, _tx) = spawn(atm, vec![keep], wire.clone());
        becomes(&k, &did, |s| matches!(s, MuxGrantStatus::Active { .. })).await;
        let n = notice(json!({ "notice": "grantsExpiring", "expiring": [
            { "grantId": "g0", "did": did, "expiresAt": "2030-01-01T00:00:00Z" } ] }));
        assert_eq!(k.handle_notice(&n).await.unwrap(), vec![did.clone()]);
        assert_eq!(
            wire.sent().len(),
            1,
            "renewed before handle_notice returned"
        );
        becomes(
            &k,
            &did,
            |s| matches!(s, MuxGrantStatus::Active { grant_id, .. } if grant_id != "g0"),
        )
        .await;
    }

    /// `grantsSuspended` with auto_recreate: re-signed and granted again,
    /// and the status goes Active → Recreated. The same notice delivered
    /// again (about the replaced grant) changes nothing.
    #[tokio::test]
    async fn a_suspended_grant_is_recreated() {
        let (atm, did) = atm_with_member().await;
        let wire = FakeWire::default();
        let now = now_unix();
        wire.store(&did, "g0", now, now + 4000, "active");
        let keep = MuxGrantKeep::new(
            did.clone(),
            &[MuxCapability::Receive, MuxCapability::Pickup],
            4000,
        )
        .auto_recreate(true);
        let (k, _tx) = spawn(atm, vec![keep], wire.clone());
        becomes(&k, &did, |s| matches!(s, MuxGrantStatus::Active { .. })).await;
        wire.set_state(&did, "suspended");
        let n = notice(json!({ "notice": "grantsSuspended", "suspensions": [
            { "did": did, "grantIds": ["g0"], "reason": "suspendedUnknownKey",
              "suspendedAt": "2026-11-13T00:00:00Z" } ] }));
        assert_eq!(k.handle_notice(&n).await.unwrap(), vec![did.clone()]);
        let s = becomes(&k, &did, |s| matches!(s, MuxGrantStatus::Recreated { .. })).await;
        assert!(
            matches!(&s, MuxGrantStatus::Recreated { lapse: MuxGrantLapse::Suspended, grant_id, .. } if grant_id != "g0"),
            "{s:?}"
        );
        let sent = wire.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0]["scope"], json!(["receive", "pickup"]));
        assert_eq!(sent[0]["epoch"], 0);
        // Redelivered: about g0, which is no longer the grant held.
        assert!(k.handle_notice(&n).await.unwrap().is_empty());
        assert_eq!(wire.sent().len(), 1);
    }

    /// Without auto_recreate a suspension is reported, not acted on.
    #[tokio::test]
    async fn without_auto_recreate_a_suspension_is_reported() {
        let (atm, did) = atm_with_member().await;
        let wire = FakeWire::default();
        let now = now_unix();
        wire.store(&did, "g0", now, now + 4000, "suspended");
        let keep = MuxGrantKeep::new(did.clone(), &[MuxCapability::Receive], 4000).auto_renew(true);
        let (k, _tx) = spawn(atm, vec![keep], wire.clone());
        let s = becomes(&k, &did, |s| {
            matches!(s, MuxGrantStatus::NeedsRecreate { .. })
        })
        .await;
        assert_eq!(
            s,
            MuxGrantStatus::NeedsRecreate {
                grant_id: Some("g0".into()),
                lapse: MuxGrantLapse::Suspended
            }
        );
        assert!(wire.sent().is_empty());
    }

    /// A stale-key or expired grant seen in `mux/list` is recreated.
    #[tokio::test]
    async fn stale_key_and_expired_grants_in_the_list_are_recreated() {
        for (state, lapse) in [
            ("staleKey", MuxGrantLapse::StaleKey),
            ("expired", MuxGrantLapse::Expired),
        ] {
            let (atm, did) = atm_with_member().await;
            let wire = FakeWire::default();
            let now = now_unix();
            wire.store(&did, "g0", now - 100, now + 4000, state);
            let keep =
                MuxGrantKeep::new(did.clone(), &[MuxCapability::Receive], 4000).auto_recreate(true);
            let (k, _tx) = spawn(atm, vec![keep], wire.clone());
            let s = becomes(&k, &did, |s| matches!(s, MuxGrantStatus::Recreated { .. })).await;
            assert!(
                matches!(s, MuxGrantStatus::Recreated { lapse: l, .. } if l == lapse),
                "{s:?}"
            );
            assert_eq!(wire.sent().len(), 1);
        }
    }

    /// A member's own revoke, a revoke-all, an admin or a removed account
    /// is never undone, however the keeper learns of it.
    #[tokio::test]
    async fn a_deliberate_revoke_is_never_recreated() {
        for reason in ["revokedByMember", "epochBumped", "admin", "accountRemoved"] {
            let (atm, did) = atm_with_member().await;
            let wire = FakeWire::default();
            let now = now_unix();
            wire.store(&did, "g0", now, now + 4000, "active");
            let keep = MuxGrantKeep::new(did.clone(), &[MuxCapability::Receive], 4000)
                .auto_renew(true)
                .auto_recreate(true);
            let (k, _tx) = spawn(atm, vec![keep], wire.clone());
            becomes(&k, &did, |s| matches!(s, MuxGrantStatus::Active { .. })).await;
            // The list still shows the grant active (read before the revoke
            // reached it): it stays ended.
            let n = notice(json!({ "notice": "grantsRevoked", "revocations": [
                { "did": did, "grantIds": ["g0"], "reason": reason,
                  "revokedAt": "2026-11-13T00:00:00Z" } ] }));
            assert_eq!(k.handle_notice(&n).await.unwrap(), vec![did.clone()]);
            let s = k.status(&did).unwrap().borrow().clone();
            assert_eq!(
                s,
                MuxGrantStatus::Revoked {
                    reason: MuxGrantRevokeReason::from_wire(reason)
                }
            );
            // A later suspension notice or a fresh look does not bring it back.
            let n = notice(json!({ "notice": "grantsSuspended", "suspensions": [
                { "did": did, "grantIds": ["g0"], "reason": "suspendedUnknownKey",
                  "suspendedAt": "2026-11-13T00:00:00Z" } ] }));
            k.handle_notice(&n).await.unwrap();
            k.refresh().await.unwrap();
            assert!(wire.sent().is_empty(), "{reason}: recreated");
            assert!(matches!(
                *k.status(&did).unwrap().borrow(),
                MuxGrantStatus::Revoked { .. }
            ));
        }
    }

    /// `epochRevoked` in the list, an `epochMismatch` on renewal, and a grant
    /// that disappears from the list all end the grant for good.
    #[tokio::test]
    async fn an_epoch_bump_or_a_deleted_grant_ends_it() {
        let (atm, did) = atm_with_member().await;
        let keep = MuxGrantKeep::new(did.clone(), &[MuxCapability::Receive], 4000)
            .auto_renew(true)
            .auto_recreate(true);
        let now = now_unix();

        let wire = FakeWire::default();
        wire.store(&did, "g0", now, now + 4000, "epochRevoked");
        let (k, _tx) = spawn(atm.clone(), vec![keep.clone()], wire.clone());
        let s = becomes(&k, &did, |s| matches!(s, MuxGrantStatus::Revoked { .. })).await;
        assert_eq!(
            s,
            MuxGrantStatus::Revoked {
                reason: MuxGrantRevokeReason::EpochBumped
            }
        );
        assert!(wire.sent().is_empty());

        let wire = FakeWire::default();
        wire.store(&did, "g0", now, now + 4000, "active");
        wire.inner.lock().unwrap().refuse_next =
            Some(("messaging/mux/grant:epochMismatch".into(), Some(1)));
        let (k, _tx) = spawn(atm.clone(), vec![keep.clone()], wire.clone());
        becomes(&k, &did, |s| matches!(s, MuxGrantStatus::Active { .. })).await;
        let n = notice(json!({ "notice": "grantsExpiring", "expiring": [
            { "grantId": "g0", "did": did, "expiresAt": "2030-01-01T00:00:00Z" } ] }));
        k.handle_notice(&n).await.unwrap();
        let s = k.status(&did).unwrap().borrow().clone();
        assert_eq!(
            s,
            MuxGrantStatus::Revoked {
                reason: MuxGrantRevokeReason::EpochBumped
            }
        );
        assert_eq!(
            wire.sent().len(),
            1,
            "the one refused renewal, not re-signed at epoch 1"
        );

        let wire = FakeWire::default();
        wire.store(&did, "g0", now, now + 4000, "active");
        let (k, _tx) = spawn(atm, vec![keep], wire.clone());
        becomes(&k, &did, |s| matches!(s, MuxGrantStatus::Active { .. })).await;
        wire.remove(&did);
        k.refresh().await.unwrap();
        let s = k.status(&did).unwrap().borrow().clone();
        assert_eq!(
            s,
            MuxGrantStatus::Revoked {
                reason: MuxGrantRevokeReason::Removed
            }
        );
        assert!(wire.sent().is_empty());
    }

    /// Status runs Active → Renewing → Active on renewal; a failed renewal is
    /// Failed{retrying} and is retried with backoff; a new connection looks
    /// at the list again; the end of the connection is Ended.
    #[tokio::test(start_paused = true)]
    async fn status_transitions() {
        let (atm, did) = atm_with_member().await;
        let wire = FakeWire::default();
        let now = now_unix();
        wire.store(&did, "g0", now, now + 4000, "active");
        wire.inner.lock().unwrap().refuse_next =
            Some(("messaging/mux:didUnresolvable".into(), None));
        let keep = MuxGrantKeep::new(did.clone(), &[MuxCapability::Receive], 4000).auto_renew(true);
        let (k, tx) = spawn(atm, vec![keep], wire.clone());
        let mut rx = k.status(&did).unwrap();
        assert_eq!(*rx.borrow(), MuxGrantStatus::Waiting);
        becomes(&k, &did, |s| matches!(s, MuxGrantStatus::Active { .. })).await;
        rx.mark_unchanged();
        let n = notice(json!({ "notice": "grantsExpiring", "expiring": [
            { "grantId": "g0", "did": did, "expiresAt": "2030-01-01T00:00:00Z" } ] }));
        k.handle_notice(&n).await.unwrap();
        let s = k.status(&did).unwrap().borrow().clone();
        assert!(
            matches!(&s, MuxGrantStatus::Failed { error, retrying: true } if error.contains("didUnresolvable")),
            "{s:?}"
        );
        // Retried after 10 s, and stored.
        tokio::time::sleep(Duration::from_secs(11)).await;
        becomes(
            &k,
            &did,
            |s| matches!(s, MuxGrantStatus::Active { grant_id, .. } if grant_id != "g0"),
        )
        .await;
        assert_eq!(wire.sent().len(), 2);

        let lists = wire.lists();
        tx.send_replace(None);
        tx.send_replace(Some(ready("n2")));
        k.refresh().await.unwrap();
        assert!(wire.lists() > lists, "looked again on the new connection");
        drop(tx);
        becomes(&k, &did, |s| *s == MuxGrantStatus::Ended).await;
    }

    /// Two devices with different keys for one DID, both auto-recreating,
    /// would suspend each other for ever: recreation stops after three an
    /// hour.
    #[tokio::test]
    async fn recreation_is_bounded() {
        let (atm, did) = atm_with_member().await;
        let wire = FakeWire::default();
        let now = now_unix();
        wire.store(&did, "g0", now, now + 4000, "active");
        let keep =
            MuxGrantKeep::new(did.clone(), &[MuxCapability::Receive], 4000).auto_recreate(true);
        let (k, _tx) = spawn(atm, vec![keep], wire.clone());
        becomes(&k, &did, |s| matches!(s, MuxGrantStatus::Active { .. })).await;
        for round in 0..4 {
            let current = match k.status(&did).unwrap().borrow().clone() {
                MuxGrantStatus::Active { grant_id, .. }
                | MuxGrantStatus::Recreated { grant_id, .. } => grant_id,
                other => panic!("round {round}: {other:?}"),
            };
            wire.set_state(&did, "suspended");
            let n = notice(json!({ "notice": "grantsSuspended", "suspensions": [
                { "did": did, "grantIds": [current], "reason": "suspendedUnknownKey",
                  "suspendedAt": "2026-11-13T00:00:00Z" } ] }));
            k.handle_notice(&n).await.unwrap();
        }
        assert_eq!(wire.sent().len(), RECREATE_BURST);
        let s = k.status(&did).unwrap().borrow().clone();
        assert!(
            matches!(s, MuxGrantStatus::Failed { retrying: true, .. }),
            "{s:?}"
        );
    }

    /// A notice for a DID the keeper does not keep is left to the app.
    #[tokio::test]
    async fn a_notice_for_another_did_concerns_nobody() {
        let (atm, did) = atm_with_member().await;
        let wire = FakeWire::default();
        let now = now_unix();
        wire.store(&did, "g0", now, now + 4000, "active");
        let keep =
            MuxGrantKeep::new(did.clone(), &[MuxCapability::Receive], 4000).auto_recreate(true);
        let (k, _tx) = spawn(atm, vec![keep], wire.clone());
        becomes(&k, &did, |s| matches!(s, MuxGrantStatus::Active { .. })).await;
        let n = notice(json!({ "notice": "grantsSuspended", "suspensions": [
            { "did": "did:example:other", "grantIds": ["gx"], "reason": "suspendedUnknownKey",
              "suspendedAt": "2026-11-13T00:00:00Z" } ] }));
        assert!(k.handle_notice(&n).await.unwrap().is_empty());
        let n = notice(
            json!({ "notice": "grantsPresent", "did": "did:example:other",
                               "count": 1, "suspended": 0, "epoch": 0 }),
        );
        assert!(k.handle_notice(&n).await.unwrap().is_empty());
        assert!(wire.sent().is_empty());
    }
}

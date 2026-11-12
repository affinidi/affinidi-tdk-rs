//! Keep session attaches across reconnects (`reattach_on_reconnect`, design
//! §5.8 and §8), on either wire.
//!
//! A session attach is bound to one connection: its statement names the
//! connection's `sessionId` and `muxNonce`, and it ends with the connection.
//! Stored grants come back by themselves on every connect; session attaches
//! do not, and the SDK does not re-attach anything unless asked (§5.8:
//! everything is opted into). [`MuxKeepAttached`] is that opt-in. Given the
//! members to keep and the keys to sign for them (this `ATM`'s secrets), it
//! signs fresh attach statements for every new connection, attaches them, and
//! attaches again before they expire. It stops when dropped.
//!
//! - DIDComm (`didcomm-mux`): [`keep_attached`].
//! - Raw TSP (`tsp-mux`):
//!   [`TspMuxSender::keep_attached`](super::tsp_mux::TspMuxSender::keep_attached).
//!
//! Each round's outcome is published on [`MuxKeepAttached::status`] (R6.2):
//! the app sees whether the members are attached on the current connection,
//! and why not when they are not.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::watch;
use tracing::{debug, warn};

use super::mux::{MuxCapability, MuxReady, sign_attach};
use crate::profiles::ATMProfile;
use crate::{ATM, errors::ATMError};

/// One member DID to keep attached: its scope and how long each attach
/// lasts. The `ATM` that keeps it must hold the member's signing key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MuxKeepAttach {
    pub member_did: String,
    pub scope: Vec<MuxCapability>,
    /// Lifetime of each attach statement, in seconds. Capped by the
    /// connection's `maxAttachLifetimeSeconds`.
    pub lifetime_secs: u64,
}

impl MuxKeepAttach {
    pub fn new(member_did: impl Into<String>, scope: &[MuxCapability], lifetime_secs: u64) -> Self {
        Self {
            member_did: member_did.into(),
            scope: scope.to_vec(),
            lifetime_secs,
        }
    }
}

/// Where keeping the members attached stands.
#[derive(Clone, Debug, PartialEq)]
pub enum MuxKeepStatus {
    /// No connection is up (or none has said `ready` yet).
    Waiting,
    /// The attach went in on the connection with this nonce. `response` is
    /// the mediator's `messaging/mux/attach` answer, with each member's own
    /// outcome (a member can be refused while others are attached).
    Attached { mux_nonce: String, response: Value },
    /// The attach failed on the connection with this nonce; it is tried
    /// again shortly, and on the next connection.
    Failed { mux_nonce: String, error: String },
    /// The connection is gone for good (closed, or replaced by a new mux
    /// handle): nothing more will be attached.
    Ended,
}

/// Keeps a set of members attached to a mux connection across reconnects.
/// Dropping it stops it; members already attached stay attached until their
/// statements expire or the connection ends.
#[derive(Debug)]
pub struct MuxKeepAttached {
    status: watch::Receiver<MuxKeepStatus>,
    task: tokio::task::JoinHandle<()>,
}

impl MuxKeepAttached {
    /// The latest outcome, as a watch.
    pub fn status(&self) -> watch::Receiver<MuxKeepStatus> {
        self.status.clone()
    }

    /// Stop keeping the members attached.
    pub fn stop(self) {}
}

impl Drop for MuxKeepAttached {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Attach again when this much of the shortest lifetime is left.
const RENEW_AT: f64 = 0.75;
/// Wait before trying a failed attach again on the same connection.
const RETRY_AFTER: Duration = Duration::from_secs(10);
/// Shortest wait between rounds, whatever the lifetimes.
const MIN_ROUND: Duration = Duration::from_secs(5);

/// Keep `members` attached to `profile`'s `didcomm-mux` connection (opened
/// with `ATM::profile_enable_mux_websocket`). Fails when the profile has no
/// mux connection, or `members` is empty or has an empty scope.
pub async fn keep_attached(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    members: Vec<MuxKeepAttach>,
) -> Result<MuxKeepAttached, ATMError> {
    let ready = profile.mux_ready().await.ok_or_else(|| {
        ATMError::ConfigError(format!(
            "profile ({}) has no mux connection to keep members attached to",
            profile.inner.alias
        ))
    })?;
    let (principal, mediator) = {
        let (p, m) = profile.dids()?;
        (p.to_string(), m.to_string())
    };
    let atm2 = atm.clone();
    let profile = profile.clone();
    spawn_keep(
        atm.clone(),
        principal,
        mediator,
        members,
        ready,
        move |statements| {
            let atm = atm2.clone();
            let profile = profile.clone();
            async move {
                let r = atm.trust_tasks().mux_attach(&profile, statements).await?;
                serde_json::to_value(&r)
                    .map_err(|e| ATMError::MsgReceiveError(format!("attach answer: {e}")))
            }
        },
    )
}

/// Start the keeping task for one connection's `ready` watch and attach
/// function. Shared by both wires.
pub(crate) fn spawn_keep<F, Fut>(
    atm: ATM,
    principal: String,
    mediator: String,
    members: Vec<MuxKeepAttach>,
    ready: watch::Receiver<Option<MuxReady>>,
    attach: F,
) -> Result<MuxKeepAttached, ATMError>
where
    F: Fn(Vec<Value>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Value, ATMError>> + Send + 'static,
{
    if members.is_empty() {
        return Err(ATMError::ConfigError(
            "keep_attached needs at least one member".into(),
        ));
    }
    if let Some(m) = members.iter().find(|m| m.scope.is_empty()) {
        // Empty means nothing, never everything (R5.1).
        return Err(ATMError::ConfigError(format!(
            "keep_attached: member {} has an empty scope",
            m.member_did
        )));
    }
    if let Some(m) = members.iter().find(|m| m.lifetime_secs == 0) {
        return Err(ATMError::ConfigError(format!(
            "keep_attached: member {} has a zero lifetime",
            m.member_did
        )));
    }
    let (status_tx, status) = watch::channel(MuxKeepStatus::Waiting);
    let task = tokio::spawn(keep(
        atm, principal, mediator, members, ready, attach, status_tx,
    ));
    Ok(MuxKeepAttached { status, task })
}

async fn keep<F, Fut>(
    atm: ATM,
    principal: String,
    mediator: String,
    members: Vec<MuxKeepAttach>,
    mut ready: watch::Receiver<Option<MuxReady>>,
    attach: F,
    status: watch::Sender<MuxKeepStatus>,
) where
    F: Fn(Vec<Value>) -> Fut,
    Fut: Future<Output = Result<Value, ATMError>>,
{
    loop {
        // The current connection, once it has said `ready`.
        let current = loop {
            if let Some(r) = ready.borrow_and_update().clone() {
                break r;
            }
            status.send_replace(MuxKeepStatus::Waiting);
            if ready.changed().await.is_err() {
                status.send_replace(MuxKeepStatus::Ended);
                return;
            }
        };
        let cap = current.max_attach_lifetime_seconds.unwrap_or(u64::MAX);
        let shortest = members
            .iter()
            .map(|m| m.lifetime_secs.min(cap))
            .min()
            .unwrap_or(cap)
            .max(1);

        let next = match round(
            &atm, &principal, &mediator, &members, &current, cap, &attach,
        )
        .await
        {
            Ok(response) => {
                debug!(%principal, nonce = %current.mux_nonce, "mux members attached");
                status.send_replace(MuxKeepStatus::Attached {
                    mux_nonce: current.mux_nonce.clone(),
                    response,
                });
                Duration::from_secs_f64(shortest as f64 * RENEW_AT).max(MIN_ROUND)
            }
            Err(e) => {
                warn!(%principal, nonce = %current.mux_nonce, "mux members not attached: {e}");
                status.send_replace(MuxKeepStatus::Failed {
                    mux_nonce: current.mux_nonce.clone(),
                    error: e.to_string(),
                });
                RETRY_AFTER
            }
        };
        // Until it is time to renew (or retry), or the connection changes.
        tokio::select! {
            changed = ready.changed() => {
                if changed.is_err() {
                    status.send_replace(MuxKeepStatus::Ended);
                    return;
                }
            }
            _ = tokio::time::sleep(next) => {}
        }
    }
}

/// Sign an attach for every member on `ready`'s connection and send them.
async fn round<F, Fut>(
    atm: &ATM,
    principal: &str,
    mediator: &str,
    members: &[MuxKeepAttach],
    ready: &MuxReady,
    cap: u64,
    attach: &F,
) -> Result<Value, ATMError>
where
    F: Fn(Vec<Value>) -> Fut,
    Fut: Future<Output = Result<Value, ATMError>>,
{
    let mut statements = Vec::with_capacity(members.len());
    for m in members {
        statements.push(
            sign_attach(
                atm,
                &m.member_did,
                principal,
                mediator,
                &ready.session_id,
                &ready.mux_nonce,
                &m.scope,
                m.lifetime_secs.min(cap),
            )
            .await?,
        );
    }
    attach(statements).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_secrets_resolver::SecretsResolver;
    use affinidi_secrets_resolver::secrets::Secret;
    use std::sync::Mutex;
    use tokio::time::timeout;

    fn ready(nonce: &str) -> MuxReady {
        MuxReady {
            session_id: "sess".into(),
            mux_nonce: nonce.into(),
            max_dids_per_connection: None,
            max_attach_lifetime_seconds: Some(600),
            max_grant_lifetime_seconds: None,
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
        let seed = [9u8; 32];
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

    async fn status_becomes(
        rx: &mut watch::Receiver<MuxKeepStatus>,
        f: impl Fn(&MuxKeepStatus) -> bool,
    ) -> MuxKeepStatus {
        timeout(Duration::from_secs(5), rx.wait_for(|s| f(s)))
            .await
            .expect("status within 5s")
            .expect("status")
            .clone()
    }

    #[tokio::test]
    async fn refuses_an_empty_or_unscoped_member_list() {
        let (atm, did) = atm_with_member().await;
        let (_tx, rx) = watch::channel(None);
        let attach = |_s: Vec<Value>| async { Ok(Value::Null) };
        assert!(
            spawn_keep(
                atm.clone(),
                "p".into(),
                "m".into(),
                vec![],
                rx.clone(),
                attach
            )
            .is_err()
        );
        let unscoped = vec![MuxKeepAttach::new(did.clone(), &[], 60)];
        assert!(
            spawn_keep(
                atm.clone(),
                "p".into(),
                "m".into(),
                unscoped,
                rx.clone(),
                attach
            )
            .is_err()
        );
        let forever = vec![MuxKeepAttach::new(did, &[MuxCapability::Receive], 0)];
        assert!(spawn_keep(atm, "p".into(), "m".into(), forever, rx, attach).is_err());
    }

    /// Each new connection gets fresh statements bound to its nonce; while
    /// none is up the status says so; and it ends with the connection.
    #[tokio::test]
    async fn attaches_again_on_every_new_connection() {
        let (atm, did) = atm_with_member().await;
        let (tx, rx) = watch::channel(Some(ready("n1")));
        let sent: Arc<Mutex<Vec<Vec<Value>>>> = Arc::default();
        let log = sent.clone();
        let keep = spawn_keep(
            atm,
            "did:example:phone".into(),
            "did:example:mediator".into(),
            vec![MuxKeepAttach::new(
                did.clone(),
                &[MuxCapability::Receive],
                300,
            )],
            rx,
            move |statements| {
                log.lock().unwrap().push(statements);
                async { Ok(serde_json::json!({ "results": [] })) }
            },
        )
        .unwrap();
        let mut status = keep.status();
        status_becomes(
            &mut status,
            |s| matches!(s, MuxKeepStatus::Attached { mux_nonce, .. } if mux_nonce == "n1"),
        )
        .await;

        tx.send_replace(None);
        status_becomes(&mut status, |s| *s == MuxKeepStatus::Waiting).await;
        tx.send_replace(Some(ready("n2")));
        status_becomes(
            &mut status,
            |s| matches!(s, MuxKeepStatus::Attached { mux_nonce, .. } if mux_nonce == "n2"),
        )
        .await;
        {
            let sent = sent.lock().unwrap();
            assert_eq!(sent.len(), 2);
            for (round, nonce) in sent.iter().zip(["n1", "n2"]) {
                assert_eq!(round.len(), 1);
                let st = &round[0];
                assert_eq!(st["type"], "muxAttach");
                assert_eq!(st["issuer"], did);
                assert_eq!(st["principal"], "did:example:phone");
                assert_eq!(st["audience"], "did:example:mediator");
                assert_eq!(st["sessionId"], "sess");
                assert_eq!(st["muxNonce"], nonce);
                assert!(st.get("proof").is_some(), "signed: {st}");
                let life = st["exp"].as_u64().unwrap() - st["iat"].as_u64().unwrap();
                assert_eq!(life, 300);
            }
        }
        drop(tx);
        status_becomes(&mut status, |s| *s == MuxKeepStatus::Ended).await;
    }

    /// A failed attach is reported with its error, and the lifetime is capped
    /// by the connection's limit.
    #[tokio::test]
    async fn a_failed_attach_is_reported_and_lifetimes_are_capped() {
        let (atm, did) = atm_with_member().await;
        let mut r = ready("n1");
        r.max_attach_lifetime_seconds = Some(60);
        let (_tx, rx) = watch::channel(Some(r));
        let sent: Arc<Mutex<Vec<Vec<Value>>>> = Arc::default();
        let log = sent.clone();
        let keep = spawn_keep(
            atm,
            "p".into(),
            "m".into(),
            vec![MuxKeepAttach::new(did, &[MuxCapability::Receive], 3600)],
            rx,
            move |statements| {
                log.lock().unwrap().push(statements);
                async { Err(ATMError::Disconnected("socket down".into())) }
            },
        )
        .unwrap();
        let mut status = keep.status();
        let failed =
            status_becomes(&mut status, |s| matches!(s, MuxKeepStatus::Failed { .. })).await;
        assert!(
            matches!(&failed, MuxKeepStatus::Failed { mux_nonce, error } if mux_nonce == "n1" && error.contains("socket down")),
            "{failed:?}"
        );
        let st = &sent.lock().unwrap()[0][0];
        assert_eq!(
            st["exp"].as_u64().unwrap() - st["iat"].as_u64().unwrap(),
            60
        );
    }

    /// An attach is renewed before its statement runs out.
    #[tokio::test(start_paused = true)]
    async fn renews_before_the_attach_expires() {
        let (atm, did) = atm_with_member().await;
        let (_tx, rx) = watch::channel(Some(ready("n1")));
        let rounds = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let n = rounds.clone();
        let _keep = spawn_keep(
            atm,
            "p".into(),
            "m".into(),
            vec![MuxKeepAttach::new(did, &[MuxCapability::Receive], 100)],
            rx,
            move |_statements| {
                n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async { Ok(Value::Null) }
            },
        )
        .unwrap();
        // Renewed at 75 % of 100 s: by 80 s there has been a second round.
        tokio::time::sleep(Duration::from_secs(80)).await;
        assert!(rounds.load(std::sync::atomic::Ordering::SeqCst) >= 2);
    }
}

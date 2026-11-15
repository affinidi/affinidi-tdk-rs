//! The one TSP receive path: addressing, the relationship lookup, key-state
//! freshness (Rev 3 §7.4.2) and verification, shared by [`TspAgent`] and the
//! messaging SDK (#1141).
//!
//! It is async so an endpoint that resolves VIDs over the network (the SDK)
//! can await the resolution, and generic over two small traits so an
//! endpoint with synchronous parts ([`TspAgent`], with an in-memory store and
//! a [`VidResolver`]) runs the same code: [`SyncVidResolver`] adapts a
//! synchronous resolver, every future it produces is ready at once, and
//! [`TspAgent::receive`] completes the whole receive in a single poll.
//!
//! What it does not do is apply a control message to relationship state: the
//! two endpoints keep that state in different stores with different
//! persistence (an in-memory [`TspStore`](crate::store::TspStore), and the
//! SDK's durable `RelationshipStore`), so each applies the
//! [`ControlMessage`](crate::message::control::ControlMessage) it gets back
//! here to its own store. Nor does it apply the §7.2.2 relationship gate,
//! because which messages the gate covers depends on what the caller does with
//! control and padding messages; [`Verified::admits_application_message`]
//! answers it.
//!
//! [`TspAgent`]: crate::TspAgent
//! [`TspAgent::receive`]: crate::TspAgent::receive

use std::future::Future;

use crate::error::TspError;
use crate::keystate::{KeyStatePolicy, KeyStateTracker, RefreshStatus};
use crate::message::direct::{self, UnpackedMessage};
use crate::message::envelope::Envelope;
use crate::relationship::RelationshipState;
use crate::vid::ResolvedVid;
use crate::vid::resolver::VidResolver;

/// Resolves a VID to its current key state, possibly over the network.
///
/// The async counterpart of [`VidResolver`]; [`SyncVidResolver`] adapts one.
pub trait AsyncVidResolver: Send + Sync {
    /// Resolve `vid`, from a cache where the resolver keeps one.
    fn resolve(&self, vid: &str) -> impl Future<Output = Result<ResolvedVid, TspError>> + Send;

    /// Resolve `vid` again from its provenance chain, bypassing any cache
    /// (§7.4.2: the cached value is precisely what may have gone stale).
    fn refresh(&self, vid: &str) -> impl Future<Output = Result<ResolvedVid, TspError>> + Send;

    /// Key state for `vid` that the resolver re-resolved from its provenance
    /// chain on its own since a refresh failed, if it has any. See
    /// [`VidResolver::completed_refresh`]. The default has none.
    fn completed_refresh(&self, _vid: &str) -> impl Future<Output = Option<ResolvedVid>> + Send {
        std::future::ready(None)
    }
}

/// The relationship state the receive path needs to read.
pub trait RelationshipLookup: Send + Sync {
    /// The state of the relationship between `our_vid` and `their_vid`.
    fn relationship_state(
        &self,
        our_vid: &str,
        their_vid: &str,
    ) -> impl Future<Output = Result<RelationshipState, TspError>> + Send;
}

/// A synchronous [`VidResolver`] as an [`AsyncVidResolver`]: every future is
/// ready immediately.
pub struct SyncVidResolver<'a, R: VidResolver + ?Sized>(pub &'a R);

impl<R: VidResolver + ?Sized> AsyncVidResolver for SyncVidResolver<'_, R> {
    fn resolve(&self, vid: &str) -> impl Future<Output = Result<ResolvedVid, TspError>> + Send {
        std::future::ready(self.0.resolve(vid))
    }

    fn refresh(&self, vid: &str) -> impl Future<Output = Result<ResolvedVid, TspError>> + Send {
        std::future::ready(self.0.refresh(vid))
    }

    fn completed_refresh(&self, vid: &str) -> impl Future<Output = Option<ResolvedVid>> + Send {
        std::future::ready(self.0.completed_refresh(vid))
    }
}

impl RelationshipLookup for crate::store::TspStore {
    fn relationship_state(
        &self,
        our_vid: &str,
        their_vid: &str,
    ) -> impl Future<Output = Result<RelationshipState, TspError>> + Send {
        std::future::ready(Ok(crate::store::TspStore::relationship_state(
            self, our_vid, their_vid,
        )))
    }
}

/// The two ids a TSP message has, computed from the same wire bytes.
///
/// A mediator stores and deletes a TSP message by the SHA-256 of its stored
/// form, and the SDK reports the SHA-256 of the wire bytes as the message's
/// hop id ([`MetaEnvelope::sha256`](crate::MetaEnvelope::sha256)). The
/// `messaging-core` adapter's `ReceivedMessage::id` is the BLAKE2s-256 of the
/// same bytes ([`direct::message_digest_bytes`]). Neither changes; this names
/// both so one can be found from the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct MessageIds {
    /// SHA-256 of the wire bytes: the hop id.
    pub hop_id: [u8; 32],
    /// BLAKE2s-256 of the wire bytes: the adapter's `ReceivedMessage::id`
    /// (hex-encoded there).
    pub message_id: [u8; 32],
}

/// Both ids of the TSP message `wire`.
pub fn message_ids(wire: &[u8]) -> MessageIds {
    MessageIds {
        hop_id: direct::sha256(wire),
        message_id: direct::message_digest_bytes(wire),
    }
}

/// What the receive path needs besides the message: where to resolve keys,
/// where to read relationships, the freshness bookkeeping and policy, and the
/// time.
pub struct ReceiveContext<'a, R: ?Sized, S: ?Sized> {
    /// Resolves the sender's key state.
    pub resolver: &'a R,
    /// Reads the relationship with the sender.
    pub relationships: &'a S,
    /// Per-peer freshness bookkeeping. One tracker must always be fed from
    /// one clock.
    pub key_state: &'a KeyStateTracker,
    /// How key state is kept fresh.
    pub policy: &'a KeyStatePolicy,
    /// The current time, in the tracker's milliseconds.
    pub now_ms: u64,
}

/// A message that verified as its sender's.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Verified {
    /// The opened message.
    pub unpacked: UnpackedMessage,
    /// The relationship with the sender when the message arrived, before any
    /// control message in it was applied.
    pub relationship: RelationshipState,
    /// The message's ids.
    pub ids: MessageIds,
}

impl Verified {
    /// Does the relationship held when the message arrived admit an
    /// application message (§7.2.2)?
    pub fn admits_application_message(&self) -> bool {
        self.relationship.admits_application_message()
    }
}

/// Open `wire`, addressed to `our_vid`, with `our_decryption_key`, verifying it
/// against its sender's key state kept fresh per Rev 3 §7.4.2.
///
/// Two occasions refresh the sender's key state, both only where this
/// endpoint resolves key state for itself ([`KeyStatePolicy::self_resolving`])
/// and holds a relationship with the sender:
///
/// * a message arriving after a silence longer than the re-verification
///   threshold is not acted on until the key state is confirmed — the case
///   that matters under compromise, since stale key state is internally
///   consistent, so a message signed with a compromised key verifies and gives
///   no warning. Confirmed means a refresh succeeded (now or, inside the rate
///   limit, the latest one), or the resolver re-resolved the VID itself since
///   one failed; otherwise the receive fails with
///   [`TspError::KeyStateUnconfirmed`], which may clear: leave the message
///   queued and receive it again later;
/// * a verification failure is retried once after a refresh, since the failure
///   may be a rotation not yet observed. A failure against freshly resolved
///   (or recently and successfully refreshed) key state is definitive and is
///   returned as is; one where the refresh failed, or the last one failed or
///   has not finished, is [`TspError::KeyStateUnconfirmed`], carrying the
///   verification failure.
///
/// Outside a relationship neither applies and a failure is returned at once,
/// or anyone could make this endpoint resolve by sending it noise. A sender
/// inside a relationship is recorded as seen once its message verifies; one
/// outside is not, so the tracker grows with relationships rather than with
/// senders. A caller whose control handling forms a relationship records the
/// sender itself ([`KeyStateTracker::record_seen`]).
pub async fn receive<R, S>(
    ctx: &ReceiveContext<'_, R, S>,
    our_vid: &str,
    our_decryption_key: &[u8; 32],
    wire: &[u8],
) -> Result<Verified, TspError>
where
    R: AsyncVidResolver + ?Sized,
    S: RelationshipLookup + ?Sized,
{
    let (envelope, _) = Envelope::decode(wire)?;
    if envelope.receiver != our_vid {
        return Err(TspError::InvalidMessage(format!(
            "message addressed to {}, not {our_vid}",
            envelope.receiver
        )));
    }
    let sender = envelope.sender;

    let relationship = ctx
        .relationships
        .relationship_state(our_vid, &sender)
        .await?;
    let established = relationship.admits_application_message();
    let watching = ctx.policy.self_resolving && established;

    let mut sender_resolved = ctx.resolver.resolve(&sender).await?;
    if watching
        && ctx.key_state.silent_longer_than(
            &sender,
            ctx.policy.reverification_threshold,
            ctx.now_ms,
        )
    {
        sender_resolved = confirm_key_state_after_silence(ctx, &sender).await?;
    }

    let unpacked = match direct::unpack(wire, our_decryption_key, &sender_resolved.signing_key) {
        Ok(unpacked) => unpacked,
        Err(first_error) => {
            if !watching {
                return Err(first_error);
            }
            match refresh_key_state(ctx, &sender).await {
                // Verified against freshly resolved key state, so a failure now
                // is definitive.
                Ok(KeyStateRefresh::Fresh(fresh)) => {
                    direct::unpack(wire, our_decryption_key, &fresh.signing_key)?
                }
                Ok(KeyStateRefresh::RateLimited) => match ctx.key_state.refresh_status(&sender) {
                    // The latest refresh succeeded: the key state we verified
                    // against is current, so the failure stands.
                    RefreshStatus::Succeeded | RefreshStatus::NeverAttempted => {
                        return Err(first_error);
                    }
                    // The latest refresh failed or has not finished: the key
                    // state is not known to be current, so the message may yet
                    // verify.
                    RefreshStatus::InFlight | RefreshStatus::Failed { .. } => {
                        return Err(TspError::KeyStateUnconfirmed {
                            reason: format!(
                                "message from {sender} did not verify and its key state could \
                                 not be refreshed (the last refresh failed or is in progress)"
                            ),
                            verification: Some(Box::new(first_error)),
                        });
                    }
                },
                // A refresh that failed shows nothing about the key: the
                // message may verify against the state it would have returned.
                Err(e) => {
                    return Err(TspError::KeyStateUnconfirmed {
                        reason: format!(
                            "message from {sender} did not verify and refreshing its key state \
                             failed: {e}"
                        ),
                        verification: Some(Box::new(first_error)),
                    });
                }
            }
        }
    };

    if established {
        ctx.key_state.record_seen(&sender, ctx.now_ms);
    }

    Ok(Verified {
        unpacked,
        relationship,
        ids: message_ids(wire),
    })
}

fn unconfirmed(reason: String) -> TspError {
    TspError::KeyStateUnconfirmed {
        reason,
        verification: None,
    }
}

/// What [`refresh_key_state`] did.
enum KeyStateRefresh {
    /// The VID was resolved again and this is its current key state.
    Fresh(ResolvedVid),
    /// The rate limit is in force, so nothing was resolved.
    RateLimited,
}

/// The key state to verify a message from `vid` against, after a silence
/// longer than the re-verification threshold, or a `KeyStateUnconfirmed` error when it
/// cannot be confirmed.
///
/// Inside the rate limit: after a refresh that succeeded, the state the
/// resolver holds is that refresh's, so it is used; while a refresh is in
/// flight elsewhere, or after one that failed, the message is discarded (the
/// sender's retry finds the outcome), and the next attempt comes later after
/// each failure in a row ([`KeyStateTracker::next_resolution_at_ms`]).
async fn confirm_key_state_after_silence<R, S>(
    ctx: &ReceiveContext<'_, R, S>,
    vid: &str,
) -> Result<ResolvedVid, TspError>
where
    R: AsyncVidResolver + ?Sized,
    S: RelationshipLookup + ?Sized,
{
    if matches!(
        ctx.key_state.refresh_status(vid),
        RefreshStatus::Failed { .. }
    ) && let Some(resolved) = ctx.resolver.completed_refresh(vid).await
    {
        ctx.key_state.record_confirmed_after_failed_refresh(vid);
        return Ok(resolved);
    }

    match refresh_key_state(ctx, vid).await {
        Ok(KeyStateRefresh::Fresh(fresh)) => Ok(fresh),
        Ok(KeyStateRefresh::RateLimited) => {
            let next_in_ms = ctx
                .key_state
                .next_resolution_at_ms(vid, ctx.policy.resolution_rate_limit)
                .saturating_sub(ctx.now_ms);
            match ctx.key_state.refresh_status(vid) {
                RefreshStatus::Succeeded => ctx.resolver.resolve(vid).await,
                RefreshStatus::InFlight => Err(unconfirmed(format!(
                    "key state for {vid} is not confirmed after a silence: a refresh is in \
                     progress; send again once it completes"
                ))),
                RefreshStatus::Failed { consecutive } => Err(unconfirmed(format!(
                    "key state for {vid} is not confirmed after a silence: the last refresh \
                     failed ({consecutive} in a row); next refresh allowed in {next_in_ms} ms"
                ))),
                RefreshStatus::NeverAttempted => Err(unconfirmed(format!(
                    "key state for {vid} is not confirmed after a silence"
                ))),
            }
        }
        Err(e) => Err(unconfirmed(format!(
            "key state for {vid} could not be confirmed after a silence: the refresh failed: {e}"
        ))),
    }
}

/// Re-resolve `vid`, subject to the per-peer rate limit.
///
/// `RateLimited` means no resolution was attempted. §7.4.2 bounds resolution
/// because it can be provoked by an unauthenticated message, and resolution is
/// more expensive than the message provoking it. Checking the limit and
/// stamping the attempt is one step, and the outcome is recorded against this
/// attempt only, so a slow older refresh cannot overwrite a newer one's
/// result.
async fn refresh_key_state<R, S>(
    ctx: &ReceiveContext<'_, R, S>,
    vid: &str,
) -> Result<KeyStateRefresh, TspError>
where
    R: AsyncVidResolver + ?Sized,
    S: RelationshipLookup + ?Sized,
{
    let Some(token) =
        ctx.key_state
            .try_begin_refresh(vid, ctx.policy.resolution_rate_limit, ctx.now_ms)
    else {
        return Ok(KeyStateRefresh::RateLimited);
    };
    match ctx.resolver.refresh(vid).await {
        Ok(fresh) => {
            ctx.key_state.record_refresh_succeeded(&token);
            Ok(KeyStateRefresh::Fresh(fresh))
        }
        Err(e) => {
            ctx.key_state.record_refresh_failed(&token);
            Err(e)
        }
    }
}

/// Run `future` to completion if it completes in one poll, as every future
/// built from [`SyncVidResolver`] and [`TspStore`](crate::store::TspStore)
/// does. `None` if it would have to wait.
pub(crate) fn complete_now<F: Future>(future: F) -> Option<F::Output> {
    let future = std::pin::pin!(future);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match future.poll(&mut cx) {
        std::task::Poll::Ready(output) => Some(output),
        std::task::Poll::Pending => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TspAgent;
    use crate::keystate::{Clock, SystemClock};
    use crate::message::MessageType;
    use crate::store::TspStore;
    use crate::vid::PrivateVid;

    /// A resolver that really waits before answering, as one going over the
    /// network does.
    struct Yielding(ResolvedVid);

    impl AsyncVidResolver for Yielding {
        async fn resolve(&self, _vid: &str) -> Result<ResolvedVid, TspError> {
            tokio::task::yield_now().await;
            Ok(self.0.clone())
        }
        async fn refresh(&self, vid: &str) -> Result<ResolvedVid, TspError> {
            self.resolve(vid).await
        }
    }

    fn invite() -> (Vec<u8>, PrivateVid, ResolvedVid) {
        let alice = TspAgent::new();
        let alice_vid = PrivateVid::generate("did:example:alice");
        let alice_public = alice_vid.to_resolved();
        let bob_vid = PrivateVid::generate("did:example:bob");
        alice.add_private_vid(alice_vid);
        alice.add_verified_vid(bob_vid.to_resolved());
        let packed = alice
            .send_relationship_invite("did:example:alice", "did:example:bob")
            .unwrap();
        (packed.bytes, bob_vid, alice_public)
    }

    #[tokio::test]
    async fn the_receive_path_runs_over_an_async_resolver() {
        let (wire, bob, alice) = invite();
        let resolver = Yielding(alice);
        let store = TspStore::new();
        let key_state = KeyStateTracker::new();
        let policy = KeyStatePolicy::default();
        let ctx = ReceiveContext {
            resolver: &resolver,
            relationships: &store,
            key_state: &key_state,
            policy: &policy,
            now_ms: SystemClock.now_ms(),
        };
        let verified = receive(&ctx, "did:example:bob", &bob.decryption_key, &wire)
            .await
            .unwrap();
        assert_eq!(verified.unpacked.sender, "did:example:alice");
        assert_eq!(verified.unpacked.message_type, MessageType::Control);
        assert_eq!(verified.relationship, RelationshipState::None);
        assert!(!verified.admits_application_message());
        assert_eq!(verified.ids, message_ids(&wire));

        let wrong = receive(&ctx, "did:example:carol", &bob.decryption_key, &wire).await;
        assert!(matches!(wrong, Err(TspError::InvalidMessage(_))));
    }

    #[test]
    fn a_synchronous_resolver_completes_in_one_poll() {
        let (wire, bob, alice) = invite();
        let memory = crate::vid::resolver::MemoryVidResolver::new();
        memory.insert(alice);
        let resolver = SyncVidResolver(&memory);
        let store = TspStore::new();
        let key_state = KeyStateTracker::new();
        let policy = KeyStatePolicy::default();
        let ctx = ReceiveContext {
            resolver: &resolver,
            relationships: &store,
            key_state: &key_state,
            policy: &policy,
            now_ms: 0,
        };
        let verified = complete_now(receive(&ctx, "did:example:bob", &bob.decryption_key, &wire))
            .expect("ready in one poll")
            .unwrap();
        assert_eq!(verified.unpacked.sender, "did:example:alice");
    }

    /// A resolver whose refresh fails while `down` is set, as one does during
    /// an outage.
    struct Flaky {
        vid: ResolvedVid,
        down: std::sync::atomic::AtomicBool,
    }

    impl AsyncVidResolver for Flaky {
        async fn resolve(&self, _vid: &str) -> Result<ResolvedVid, TspError> {
            Ok(self.vid.clone())
        }
        async fn refresh(&self, _vid: &str) -> Result<ResolvedVid, TspError> {
            if self.down.load(std::sync::atomic::Ordering::SeqCst) {
                Err(TspError::DidResolution("resolver unreachable".into()))
            } else {
                Ok(self.vid.clone())
            }
        }
    }

    /// After a silence, a refresh that fails transiently leaves the message
    /// unconfirmed — a failure that may clear, not a verdict on the message —
    /// and the same bytes are accepted once a later refresh succeeds.
    #[tokio::test]
    async fn a_transient_refresh_failure_after_a_silence_is_retryable() {
        let alice = TspAgent::new();
        let alice_vid = PrivateVid::generate("did:example:alice");
        let alice_public = alice_vid.to_resolved();
        let bob = PrivateVid::generate("did:example:bob");
        alice.add_private_vid(alice_vid);
        alice.add_verified_vid(bob.to_resolved());
        alice.store.set_relationship_state(
            "did:example:alice",
            "did:example:bob",
            RelationshipState::Bidirectional,
        );
        let wire = alice
            .send("did:example:alice", "did:example:bob", b"hello")
            .unwrap()
            .bytes;

        let store = TspStore::new();
        store.set_relationship_state(
            "did:example:bob",
            "did:example:alice",
            RelationshipState::Bidirectional,
        );
        let key_state = KeyStateTracker::new();
        key_state.record_seen("did:example:alice", 0);
        let policy = KeyStatePolicy::default();
        let resolver = Flaky {
            vid: alice_public,
            down: std::sync::atomic::AtomicBool::new(true),
        };
        let after_silence = policy.reverification_threshold.as_millis() as u64 + 1;

        let ctx = ReceiveContext {
            resolver: &resolver,
            relationships: &store,
            key_state: &key_state,
            policy: &policy,
            now_ms: after_silence,
        };
        let err = receive(&ctx, "did:example:bob", &bob.decryption_key, &wire)
            .await
            .unwrap_err();
        assert!(err.is_transient(), "{err}");
        assert!(matches!(
            err,
            TspError::KeyStateUnconfirmed {
                verification: None,
                ..
            }
        ));

        // Inside the backed-off rate limit it stays retryable.
        let ctx = ReceiveContext {
            now_ms: after_silence + 1_000,
            ..ctx
        };
        let err = receive(&ctx, "did:example:bob", &bob.decryption_key, &wire)
            .await
            .unwrap_err();
        assert!(err.is_transient(), "{err}");

        // The resolver recovers; a later attempt refreshes and accepts.
        resolver
            .down
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let ctx = ReceiveContext {
            now_ms: after_silence + 60 * 60 * 1_000,
            ..ctx
        };
        let verified = receive(&ctx, "did:example:bob", &bob.decryption_key, &wire)
            .await
            .unwrap();
        assert_eq!(verified.unpacked.payload, b"hello");
    }

    /// A message that does not verify against freshly refreshed key state is
    /// refused for good: the refresh shows the key it was signed with is not
    /// the sender's.
    #[tokio::test]
    async fn a_failure_against_fresh_key_state_is_permanent() {
        let (wire, bob, _alice) = invite();
        // The resolver hands out someone else's key for Alice: a rotation.
        let rotated = PrivateVid::generate("did:example:alice").to_resolved();
        let resolver = Flaky {
            vid: rotated,
            down: std::sync::atomic::AtomicBool::new(false),
        };
        let store = TspStore::new();
        store.set_relationship_state(
            "did:example:bob",
            "did:example:alice",
            RelationshipState::Bidirectional,
        );
        let key_state = KeyStateTracker::new();
        let policy = KeyStatePolicy::default();
        let ctx = ReceiveContext {
            resolver: &resolver,
            relationships: &store,
            key_state: &key_state,
            policy: &policy,
            now_ms: 0,
        };
        let err = receive(&ctx, "did:example:bob", &bob.decryption_key, &wire)
            .await
            .unwrap_err();
        assert!(!err.is_transient(), "{err}");
    }

    #[test]
    fn message_ids_name_the_hop_id_and_the_adapter_id_of_the_same_bytes() {
        let (wire, _, _) = invite();
        let ids = message_ids(&wire);
        assert_eq!(
            ids.hop_id,
            crate::MetaEnvelope::parse(&wire).unwrap().sha256
        );
        assert_eq!(ids.message_id, direct::message_digest_bytes(&wire));
        assert_ne!(ids.hop_id, ids.message_id);
    }
}

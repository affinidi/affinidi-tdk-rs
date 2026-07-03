/*!
 * Multi-mediator topology fixture.
 *
 * [`TestTopology`] spawns N in-process [`TestMediator`]s — each relay-enabled
 * and wired to its own SDK [`TestEnvironment`] — so a cross-mediator scenario
 * is a plain `#[tokio::test]` with no Redis and no external network. Every
 * mediator and user identity is `did:peer:2.*`, which carries its own service
 * endpoint, so all DIDs resolve locally: the mediators form a fully-connected,
 * trust-any relay mesh without a shared resolver registry. The only real socket
 * traffic is the loopback HTTP hop a relaying mediator makes to the next hop's
 * `/inbound`.
 *
 * This generalises the routing-2.0 double-forward that
 * `tests/cross_mediator_forwarding.rs` previously hand-rolled per test: spawn a
 * mesh, add users on whichever mediators, and [`forward`](TestTopology::forward)
 * a message hop-to-hop.
 *
 * ```no_run
 * # use affinidi_messaging_test_mediator::TestTopology;
 * # use std::time::Duration;
 * # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
 * let topology = TestTopology::builder().mediators(2).spawn().await?;
 * let alice = topology.add_user(0, "Alice").await?; // homed on mediator 0
 * let bob = topology.add_user(1, "Bob").await?;      // homed on mediator 1
 *
 * let got = topology
 *     .forward(0, &alice, 1, &bob, "Hello Bob", Duration::from_secs(15))
 *     .await?;
 * assert_eq!(got.as_deref(), Some("Hello Bob"));
 *
 * topology.shutdown().await?;
 * # Ok(()) }
 * ```
 */

use std::time::Duration;

use affinidi_messaging_didcomm::Message;
use serde_json::json;
use uuid::Uuid;

use crate::{
    RelayMode, TestEnvironment, TestEnvironmentError, TestMediator, TestMediatorBuilder, TestUser,
    acl,
};

/// Errors from constructing or driving a [`TestTopology`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TestTopologyError {
    /// `mediators(0)` — a topology needs at least one mediator.
    #[error("a topology needs at least one mediator")]
    NoMediators,

    /// A node index passed to [`TestTopology::node`] / `forward` / `add_user`
    /// was out of range.
    #[error("mediator node index {index} out of range (topology has {count} mediators)")]
    NodeOutOfRange {
        /// The offending index.
        index: usize,
        /// How many mediators the topology actually has.
        count: usize,
    },

    /// Wiring the SDK environment to a spawned mediator failed.
    #[error(transparent)]
    Environment(#[from] TestEnvironmentError),

    /// Spawning a mediator failed.
    #[error("spawn mediator: {0}")]
    Mediator(String),

    /// An SDK operation (pack / forward / send / receive) failed.
    #[error("sdk: {0}")]
    Sdk(String),
}

/// Builder for a [`TestTopology`]. Create with [`TestTopology::builder`].
///
/// Every mediator is spawned relay-enabled (`enable_forwarding`,
/// `enable_external_forwarding`, an allow-all global default ACL so
/// cross-mediator forward senders auto-register, and the chosen
/// [`RelayMode`]). The trusted-peer allowlist is left empty, i.e. **trust any
/// relaying peer** — which is what makes the mesh fully connected without
/// needing each peer's DID ahead of spawn. Tests that need an explicit
/// trusted-peer allowlist (or a non-relay mediator) should drop to
/// [`TestMediator::builder`] directly.
pub struct TestTopologyBuilder {
    mediators: usize,
    relay_mode: RelayMode,
    customize: Option<Box<dyn Fn(TestMediatorBuilder) -> TestMediatorBuilder + Send + Sync>>,
    #[cfg(feature = "tsp")]
    tsp_policy: Option<affinidi_messaging_sdk::TspPolicy>,
}

impl Default for TestTopologyBuilder {
    fn default() -> Self {
        Self {
            mediators: 2,
            relay_mode: RelayMode::Blind,
            customize: None,
            #[cfg(feature = "tsp")]
            tsp_policy: None,
        }
    }
}

impl TestTopologyBuilder {
    /// Number of mediators to spawn (default 2).
    pub fn mediators(mut self, count: usize) -> Self {
        self.mediators = count;
        self
    }

    /// Relay posture for every mediator (default [`RelayMode::Blind`]).
    pub fn relay_mode(mut self, mode: RelayMode) -> Self {
        self.relay_mode = mode;
        self
    }

    /// Set a [`TspPolicy`](affinidi_messaging_sdk::TspPolicy) on every node's SDK
    /// so `atm.send_to` protocol selection (and cross-mediator TSP routing) can be
    /// exercised. Defaults to unset (each node uses `TspPolicy::Off`).
    #[cfg(feature = "tsp")]
    pub fn tsp_policy(mut self, policy: affinidi_messaging_sdk::TspPolicy) -> Self {
        self.tsp_policy = Some(policy);
        self
    }

    /// Shorthand for [`relay_mode`](Self::relay_mode)`(RelayMode::Rewrap)` —
    /// each mediator re-encrypts the inner forward from itself to the next hop.
    pub fn rewrap(self) -> Self {
        self.relay_mode(RelayMode::Rewrap)
    }

    /// Apply extra configuration to every mediator's builder after the relay
    /// defaults are set — e.g. swap in a Redis/Fjall store for multi-process
    /// coordination tests, or tune ACLs. The closure runs once per node.
    ///
    /// ```no_run
    /// # use affinidi_messaging_test_mediator::TestTopology;
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// let topology = TestTopology::builder()
    ///     .mediators(3)
    ///     .configure_each(|b| b.enable_message_expiry(true))
    ///     .spawn()
    ///     .await?;
    /// # let _ = topology; Ok(()) }
    /// ```
    pub fn configure_each<F>(mut self, f: F) -> Self
    where
        F: Fn(TestMediatorBuilder) -> TestMediatorBuilder + Send + Sync + 'static,
    {
        self.customize = Some(Box::new(f));
        self
    }

    /// Spawn the mediators and wire each to its own SDK environment.
    pub async fn spawn(self) -> Result<TestTopology, TestTopologyError> {
        if self.mediators == 0 {
            return Err(TestTopologyError::NoMediators);
        }

        let mut nodes = Vec::with_capacity(self.mediators);
        for _ in 0..self.mediators {
            let mut builder = TestMediator::builder()
                .enable_forwarding(true)
                .enable_external_forwarding(true)
                .global_acl_default(acl::allow_all())
                .relay_mode(self.relay_mode);
            if let Some(customize) = &self.customize {
                builder = customize(builder);
            }
            let handle = builder
                .spawn()
                .await
                .map_err(|e| TestTopologyError::Mediator(e.to_string()))?;
            #[cfg(feature = "tsp")]
            let node = match self.tsp_policy {
                Some(policy) => TestEnvironment::new_with_tsp_policy(handle, policy).await?,
                None => TestEnvironment::new(handle).await?,
            };
            #[cfg(not(feature = "tsp"))]
            let node = TestEnvironment::new(handle).await?;
            nodes.push(node);
        }

        Ok(TestTopology { nodes })
    }
}

/// A spawned multi-mediator mesh. Each node is a [`TestEnvironment`] (mediator +
/// SDK). Users are homed on a node by index; [`forward`](Self::forward) routes a
/// message from a user on one node to a user on another via the routing-2.0
/// double forward.
pub struct TestTopology {
    nodes: Vec<TestEnvironment>,
}

impl TestTopology {
    /// Start building a topology.
    pub fn builder() -> TestTopologyBuilder {
        TestTopologyBuilder::default()
    }

    /// Number of mediators in the topology.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Always `false` — a spawned topology has at least one mediator. Present
    /// for the `len`/`is_empty` lint pairing.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Borrow the [`TestEnvironment`] (mediator + SDK) for node `index`.
    pub fn node(&self, index: usize) -> Result<&TestEnvironment, TestTopologyError> {
        self.nodes
            .get(index)
            .ok_or(TestTopologyError::NodeOutOfRange {
                index,
                count: self.nodes.len(),
            })
    }

    /// The `did:peer` of node `index`'s mediator.
    pub fn mediator_did(&self, index: usize) -> Result<&str, TestTopologyError> {
        Ok(self.node(index)?.mediator.did())
    }

    /// Add a user homed on node `index`, with its WebSocket live stream brought
    /// up so cross-mediator forwards delivered to it surface in real time
    /// (delivery over plain HTTP isn't unwrapped by the SDK's delivery-request
    /// path, so the stream must be live before the forward arrives).
    pub async fn add_user(&self, index: usize, alias: &str) -> Result<TestUser, TestTopologyError> {
        let env = self.node(index)?;
        let user = env.add_user(alias).await?;
        env.atm
            .profile_enable_websocket(&user.profile)
            .await
            .map_err(|e| TestTopologyError::Sdk(e.to_string()))?;
        Ok(user)
    }

    /// Route a basic message from `sender` (on `from_node`) to `recipient` (on
    /// `to_node`) as the routing-2.0 double forward, then wait up to `wait` for
    /// the recipient's live stream to surface the decrypted body.
    ///
    /// Returns the recipient's view of the message's `content` field, or `None`
    /// if nothing arrived within `wait` (use a short `wait` for negative cases
    /// that expect no delivery). The construction is: authcrypt for the
    /// recipient, an INNER forward addressed to the recipient's mediator, an
    /// OUTER forward addressed to the sender's own mediator (so it relays the
    /// inner forward over the wire to the next hop), then send the outer forward
    /// to the sender's mediator.
    pub async fn forward(
        &self,
        from_node: usize,
        sender: &TestUser,
        to_node: usize,
        recipient: &TestUser,
        text: &str,
        wait: Duration,
    ) -> Result<Option<String>, TestTopologyError> {
        let sender_env = self.node(from_node)?;
        let recipient_env = self.node(to_node)?;
        let sender_mediator_did = sender_env.mediator.did().to_string();
        let recipient_mediator_did = recipient_env.mediator.did().to_string();

        let now = unix_secs();
        let msg = Message::build(
            Uuid::new_v4().to_string(),
            "https://didcomm.org/basicmessage/2.0/message".to_string(),
            json!({ "content": text }),
        )
        .to(recipient.did.clone())
        .from(sender.did.clone())
        .created_time(now)
        .expires_time(now + 60)
        .finalize();
        let msg_id = msg.id.clone();

        let (packed, _) = sender_env
            .atm
            .pack_encrypted(&msg, &recipient.did, Some(&sender.did), Some(&sender.did))
            .await
            .map_err(|e| TestTopologyError::Sdk(e.to_string()))?;

        // INNER forward: encrypted for the recipient's mediator, next = recipient.
        let (_inner_id, inner_fwd) = sender_env
            .atm
            .routing()
            .forward_message(
                &sender.profile,
                false,
                &packed,
                &recipient_mediator_did,
                &recipient.did,
                None,
                None,
            )
            .await
            .map_err(|e| TestTopologyError::Sdk(e.to_string()))?;

        // OUTER forward: encrypted for the sender's own mediator, next =
        // recipient's mediator (so the sender's mediator relays the inner
        // forward over the wire to the recipient's mediator).
        let (_outer_id, outer_fwd) = sender_env
            .atm
            .routing()
            .forward_message(
                &sender.profile,
                false,
                &inner_fwd,
                &sender_mediator_did,
                &recipient_mediator_did,
                None,
                None,
            )
            .await
            .map_err(|e| TestTopologyError::Sdk(e.to_string()))?;

        sender_env
            .atm
            .send_message(&sender.profile, &outer_fwd, &msg_id, false, false)
            .await
            .map_err(|e| TestTopologyError::Sdk(e.to_string()))?;

        match recipient_env
            .atm
            .message_pickup()
            .live_stream_get(&recipient.profile, &msg_id, wait, true)
            .await
        {
            Ok(Some((received, _meta))) => Ok(received
                .body
                .get("content")
                .and_then(|c| c.as_str())
                .map(str::to_string)),
            _ => Ok(None),
        }
    }

    /// Shut every mediator down, consuming the topology.
    pub async fn shutdown(self) -> Result<(), TestTopologyError> {
        for node in self.nodes {
            node.shutdown()
                .await
                .map_err(|e| TestTopologyError::Mediator(e.to_string()))?;
        }
        Ok(())
    }
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

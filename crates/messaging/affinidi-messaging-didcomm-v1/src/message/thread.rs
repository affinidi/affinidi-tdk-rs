//! The `~thread` decorator (Aries RFC 0008).
//!
//! # Where v1 puts threading
//!
//! v2.1 carries `thid` and `pthid` as top-level message headers. v1 carries
//! them inside a `~thread` **decorator** — a reserved member of the message
//! object:
//!
//! ```json
//! {
//!   "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/basicmessage/1.0/message",
//!   "@id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
//!   "~thread": { "thid": "1e513ad4-48c9-444e-9e7e-5b8b45c5e325" },
//!   "content": "hello"
//! }
//! ```
//!
//! # The defaulting trap
//!
//! RFC 0008 says a message with no `~thread.thid` **is** the head of its own
//! thread, and its effective thread id is its `@id`. That makes three states
//! that are easy to collapse into two:
//!
//! | On the wire | [`ThreadDecorator`] | [`effective_thid`] |
//! |---|---|---|
//! | no `~thread` at all | `None` | the message `@id` |
//! | `~thread` present, no `thid` | `Some` with `thid: None` | the message `@id` |
//! | `~thread.thid` present | `Some` with `thid: Some(..)` | that value |
//!
//! This crate preserves all three. It does not synthesise a `~thread` on
//! serialization, and it does not fill in a defaulted `thid` — because
//! "absent" and "present and equal to `@id`" are different facts, and a caller
//! is entitled to tell them apart.
//!
//! That matters more here than it looks. A Trust Task document's `id` is **not**
//! the transport `@id`; they are independent identifiers that happen to sit in
//! the same envelope. A consumer that normalises an absent `thid` into `@id`
//! before comparing has manufactured a transport thread value out of nothing
//! and may then "cross-check" it against the document's `threadId` and reject a
//! perfectly valid message. Use [`explicit_thid`] when comparing against
//! in-band values, and [`effective_thid`] only when actually routing a reply.
//!
//! [`effective_thid`]: super::MessageV1::effective_thid
//! [`explicit_thid`]: super::MessageV1::explicit_thid

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The `~thread` decorator.
///
/// `sender_order` and `received_orders` are carried through faithfully but not
/// interpreted — this crate is a transport, and message ordering is an
/// application concern.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadDecorator {
    /// The thread this message belongs to. Absent means the message starts its
    /// own thread — see the [module docs](self) before defaulting it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thid: Option<String>,
    /// The parent thread, when this thread was spawned from another.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pthid: Option<String>,
    /// The sender's index for this message within the thread.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_order: Option<u32>,
    /// Highest `sender_order` seen from each other participant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_orders: Option<BTreeMap<String, u32>>,
}

impl ThreadDecorator {
    /// An empty decorator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the thread id.
    pub fn thid(mut self, thid: impl Into<String>) -> Self {
        self.thid = Some(thid.into());
        self
    }

    /// Set the parent thread id.
    pub fn pthid(mut self, pthid: impl Into<String>) -> Self {
        self.pthid = Some(pthid.into());
        self
    }

    /// Set this message's position in the thread.
    pub fn sender_order(mut self, order: u32) -> Self {
        self.sender_order = Some(order);
        self
    }

    /// Record the highest `sender_order` seen from each other participant.
    pub fn received_orders(mut self, orders: BTreeMap<String, u32>) -> Self {
        self.received_orders = Some(orders);
        self
    }

    /// Whether every member is absent.
    ///
    /// An empty `~thread` is legal but carries no information; a caller
    /// building one programmatically can use this to decide whether to attach
    /// it at all.
    pub fn is_empty(&self) -> bool {
        self.thid.is_none()
            && self.pthid.is_none()
            && self.sender_order.is_none()
            && self.received_orders.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_only_present_members() {
        let decorator = ThreadDecorator::new().thid("t-1");
        let json = serde_json::to_value(&decorator).unwrap();
        assert_eq!(json, serde_json::json!({ "thid": "t-1" }));
    }

    #[test]
    fn empty_decorator_serializes_to_an_empty_object() {
        let json = serde_json::to_value(ThreadDecorator::new()).unwrap();
        assert_eq!(json, serde_json::json!({}));
        assert!(ThreadDecorator::new().is_empty());
        assert!(!ThreadDecorator::new().thid("t").is_empty());
    }

    #[test]
    fn roundtrips_all_members() {
        let decorator = ThreadDecorator::new()
            .thid("t-1")
            .pthid("p-1")
            .sender_order(3)
            .received_orders(BTreeMap::from([("did:example:bob".to_string(), 2)]));

        let json = serde_json::to_string(&decorator).unwrap();
        let parsed: ThreadDecorator = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, decorator);
    }

    /// A decorator that is present but carries no `thid` must deserialize as
    /// `Some(..)` with `thid: None`, not collapse to an absent decorator.
    #[test]
    fn present_but_empty_is_distinct_from_absent() {
        let parsed: ThreadDecorator = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed.thid, None);
        assert!(parsed.is_empty());
    }

    #[test]
    fn ignores_unknown_members() {
        let parsed: ThreadDecorator =
            serde_json::from_str(r#"{"thid":"t-1","goal_code":"unknown"}"#).unwrap();
        assert_eq!(parsed.thid.as_deref(), Some("t-1"));
    }
}

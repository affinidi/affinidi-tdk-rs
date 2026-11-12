/*!
 * Message cache for WebSocket transport
 */
use super::WebSocketResponses;
use crate::messages::compat::UnpackMetadata;
use affinidi_messaging_didcomm::message::Message;
use ahash::AHashMap as HashMap;
use std::{collections::VecDeque, mem::size_of_val};
use tokio::sync::oneshot;
use tracing::debug;

/// Message cache struct
/// Holds live-stream messages in a cache so we can get the first available or by a specific message ID
///
/// Entries are keyed by the mediator's message id (`UnpackMetadata::sha256_hash`),
/// which is unique per stored message. The DIDComm `id` is chosen by the sender
/// and is not unique, so `id`, `thid` and `pthid` are secondary indexes that
/// each map to every cached entry carrying that value, oldest first.
#[derive(Default)]
pub(crate) struct MessageCache {
    messages: HashMap<String, (Message, UnpackMetadata)>, // Cached message data, keyed by entry key
    id_lookup: HashMap<String, VecDeque<String>>,         // DIDComm message ID to entry keys
    thid_lookup: HashMap<String, VecDeque<String>>,       // Thread ID (or pthid) to entry keys
    pub(crate) wanted_list: HashMap<String, oneshot::Sender<WebSocketResponses>>, // Message ID's (match by id/thid/pthid) that are wanted by the SDK
    ordered_list: VecDeque<String>, // Entry keys in the order they were received
    total_bytes: u64, // Total size of messages in cache (approx as based on object size)
    cache_full: bool, // Flag to state that the cache is full
    fetch_cache_limit_count: u32, // Cache limit on # of messages
    fetch_cache_limit_bytes: u64, // Cache limit on total size of messages
}

fn entry_key(message: &Message, meta: &UnpackMetadata) -> String {
    if meta.sha256_hash.is_empty() {
        format!("id:{}", message.id)
    } else {
        meta.sha256_hash.clone()
    }
}

fn thread_of(message: &Message) -> Option<&String> {
    // DIDComm problem reports use pthid only
    message.thid.as_ref().or(message.pthid.as_ref())
}

fn index_remove(index: &mut HashMap<String, VecDeque<String>>, value: &str, key: &str) {
    if let Some(keys) = index.get_mut(value) {
        keys.retain(|existing| existing != key);
        if keys.is_empty() {
            index.remove(value);
        }
    }
}

impl MessageCache {
    pub(crate) fn new(fetch_cache_limit_count: u32, fetch_cache_limit_bytes: u64) -> Self {
        MessageCache {
            fetch_cache_limit_count,
            fetch_cache_limit_bytes,
            ..Default::default()
        }
    }

    /// Number of messages held in the cache.
    pub(crate) fn len(&self) -> usize {
        self.messages.len()
    }

    /// Cache a message.
    ///
    /// The same stored message delivered again (same mediator id, as happens
    /// when the mediator re-pushes the undelivered inbox after a reconnect)
    /// is already held, so the repeat is ignored. Distinct messages that share
    /// a DIDComm `id` are each kept.
    pub(crate) fn insert(&mut self, message: Message, meta: UnpackMetadata) {
        let key = entry_key(&message, &meta);
        if self.messages.contains_key(&key) {
            debug!(
                "Message already cached, ignoring repeat delivery: id({}) cached_count({})",
                message.id,
                self.len()
            );
            return;
        }

        self.total_bytes += size_of_val(&message) as u64;
        self.id_lookup
            .entry(message.id.clone())
            .or_default()
            .push_back(key.clone());
        if let Some(thread) = thread_of(&message) {
            self.thid_lookup
                .entry(thread.clone())
                .or_default()
                .push_back(key.clone());
        }
        self.ordered_list.push_back(key.clone());
        debug!(
            "Message inserted into cache: id({}) cached_count({})",
            message.id,
            self.len() + 1
        );
        self.messages.insert(key, (message, meta));
        self.update_full();
    }

    /// Get the next message from the cache
    pub(crate) fn next(&mut self) -> Option<(Message, UnpackMetadata)> {
        let key = self.ordered_list.front().cloned()?;
        self.remove_entry(&key)
    }

    /// Is the inbound message wanted?
    /// If it exists, will remove from the cache
    ///
    /// Logic:
    /// Try and find if their is an existing search for the message id/thid/pthid
    pub(crate) fn message_wanted(
        &mut self,
        message: &Message,
    ) -> Option<oneshot::Sender<WebSocketResponses>> {
        // Can we find a match on thid?
        if let Some(thid) = &message.thid
            && let Some(sender) = self.wanted_list.remove(thid)
        {
            return Some(sender);
        }

        if let Some(pthid) = &message.pthid
            && let Some(sender) = self.wanted_list.remove(pthid)
        {
            return Some(sender);
        }

        self.wanted_list.remove(&message.id)
    }

    /// Take the oldest cached message whose `id`, or failing that whose
    /// `thid`/`pthid`, matches `msg_id`, removing it from the cache.
    pub(crate) fn get(&mut self, msg_id: &str) -> Option<(Message, UnpackMetadata)> {
        let key = self
            .id_lookup
            .get(msg_id)
            .or_else(|| self.thid_lookup.get(msg_id))
            .and_then(|keys| keys.front())
            .cloned()?;

        self.remove_entry(&key)
    }

    /// Does this message exist in the cache?
    /// If not, then we add it to the wanted list to look up later as messages come in (within the duration of the original get request)
    pub(crate) fn get_or_add_wanted(
        &mut self,
        msg_id: &str,
        sender: oneshot::Sender<WebSocketResponses>,
    ) -> Option<(oneshot::Sender<WebSocketResponses>, Message, UnpackMetadata)> {
        if let Some((message, metadata)) = self.get(msg_id) {
            return Some((sender, message, metadata));
        }

        debug!(
            "Message ID ({}) not found in cache, adding to wanted list",
            msg_id
        );
        self.wanted_list.insert(msg_id.to_string(), sender);
        None
    }

    fn remove_entry(&mut self, key: &str) -> Option<(Message, UnpackMetadata)> {
        let (message, meta) = self.messages.remove(key)?;

        if let Some(pos) = self.ordered_list.iter().position(|r| r == key) {
            self.ordered_list.remove(pos);
        }
        index_remove(&mut self.id_lookup, &message.id, key);
        if let Some(thread) = thread_of(&message) {
            index_remove(&mut self.thid_lookup, thread, key);
        }

        // Remove from search list
        self.wanted_list.remove(&message.id);

        self.total_bytes = self
            .total_bytes
            .saturating_sub(size_of_val(&message) as u64);
        self.update_full();

        Some((message, meta))
    }

    fn update_full(&mut self) {
        self.cache_full = self.len() > self.fetch_cache_limit_count as usize
            || self.total_bytes > self.fetch_cache_limit_bytes;
    }

    /// Is the cache full based on limits?
    pub(crate) fn is_full(&self) -> bool {
        self.cache_full
    }

    /// Remove and return every pending "wanted" sender.
    ///
    /// Used when the websocket connection drops: each in-flight `GetMessage`
    /// waiter is handed back so the caller can be told the request was lost
    /// (rather than leaving it to time out). Cached messages are left intact.
    pub(crate) fn drain_wanted(&mut self) -> Vec<oneshot::Sender<WebSocketResponses>> {
        self.wanted_list.drain().map(|(_, sender)| sender).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn drain_wanted_returns_and_clears_pending_senders() {
        let mut cache = MessageCache::default();

        let (tx_a, rx_a) = oneshot::channel();
        let (tx_b, rx_b) = oneshot::channel();
        cache.wanted_list.insert("msg-a".to_string(), tx_a);
        cache.wanted_list.insert("msg-b".to_string(), tx_b);

        let drained = cache.drain_wanted();

        // Both waiters are handed back and the wanted list is now empty.
        assert_eq!(drained.len(), 2);
        assert!(cache.wanted_list.is_empty());
        assert!(cache.drain_wanted().is_empty());

        // Each drained sender can still notify its waiter that the
        // connection was lost (the senders are live, not dropped).
        for sender in drained {
            assert!(sender.send(WebSocketResponses::Disconnected).is_ok());
        }
        assert!(matches!(rx_a.await, Ok(WebSocketResponses::Disconnected)));
        assert!(matches!(rx_b.await, Ok(WebSocketResponses::Disconnected)));
    }

    fn message(id: &str, thid: Option<&str>) -> Message {
        let mut builder = Message::build(
            id.to_string(),
            "example/v1".to_string(),
            serde_json::json!({}),
        );
        if let Some(thid) = thid {
            builder = builder.thid(thid.to_string());
        }
        builder.finalize()
    }

    fn meta(mediator_id: &str) -> UnpackMetadata {
        UnpackMetadata {
            sha256_hash: mediator_id.to_string(),
            ..Default::default()
        }
    }

    fn limited_cache(count: u32) -> MessageCache {
        MessageCache::new(count, u64::MAX)
    }

    fn assert_empty(cache: &MessageCache) {
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.total_bytes, 0);
        assert!(cache.ordered_list.is_empty());
        assert!(cache.id_lookup.is_empty());
        assert!(cache.thid_lookup.is_empty());
        assert!(!cache.is_full());
    }

    #[test]
    fn repeat_delivery_of_a_cached_message_is_held_once() {
        let mut cache = limited_cache(10);
        cache.insert(message("m1", None), meta("hash-1"));
        cache.insert(message("m1", None), meta("hash-1"));
        assert_eq!(cache.len(), 1);

        let (taken, taken_meta) = cache.next().expect("the message is cached");
        assert_eq!(taken.id, "m1");
        assert_eq!(taken_meta.sha256_hash, "hash-1");
        assert!(cache.next().is_none());
        assert_empty(&cache);
    }

    #[test]
    fn distinct_messages_sharing_an_id_are_both_kept() {
        let mut cache = limited_cache(10);
        cache.insert(message("same", None), meta("hash-1"));
        cache.insert(message("same", None), meta("hash-2"));
        assert_eq!(cache.len(), 2);

        assert_eq!(cache.get("same").unwrap().1.sha256_hash, "hash-1");
        assert_eq!(cache.next().unwrap().1.sha256_hash, "hash-2");
        assert!(cache.next().is_none());
        assert_empty(&cache);
    }

    #[test]
    fn repeated_ids_do_not_leave_the_cache_full() {
        let mut cache = limited_cache(2);
        for round in 0..5 {
            cache.insert(message("m1", None), meta("hash-1"));
            cache.insert(message("m1", None), meta("hash-1"));
            cache.insert(message("m2", None), meta(&format!("hash-2-{round}")));
            cache.insert(message("m2", None), meta(&format!("hash-3-{round}")));
            assert!(cache.is_full(), "three messages exceed a limit of two");
            while cache.next().is_some() {}
            assert_empty(&cache);
        }
    }

    #[test]
    fn thread_lookup_finds_every_message_on_a_thread() {
        let mut cache = limited_cache(10);
        cache.insert(message("a", Some("thread")), meta("hash-a"));
        cache.insert(message("b", Some("thread")), meta("hash-b"));

        assert_eq!(cache.get("thread").unwrap().0.id, "a");
        assert_eq!(cache.get("thread").unwrap().0.id, "b");
        assert!(cache.get("thread").is_none());
        assert_empty(&cache);
    }

    #[test]
    fn taking_one_message_by_thread_leaves_the_other_findable() {
        let mut cache = limited_cache(10);
        cache.insert(message("a", Some("thread")), meta("hash-a"));
        cache.insert(message("b", Some("thread")), meta("hash-b"));

        assert_eq!(cache.get("a").unwrap().0.id, "a");
        assert_eq!(cache.get("thread").unwrap().0.id, "b");
        assert_empty(&cache);
    }

    #[test]
    fn get_or_add_wanted_takes_only_one_of_two_messages_sharing_an_id() {
        let mut cache = limited_cache(10);
        cache.insert(message("same", None), meta("hash-1"));
        cache.insert(message("same", None), meta("hash-2"));

        let (tx, _rx) = oneshot::channel();
        let (_, _, taken) = cache.get_or_add_wanted("same", tx).unwrap();
        assert_eq!(taken.sha256_hash, "hash-1");
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.next().unwrap().1.sha256_hash, "hash-2");
        assert_empty(&cache);
    }

    #[test]
    fn drain_wanted_on_empty_cache_is_noop() {
        let mut cache = MessageCache::default();
        assert!(cache.drain_wanted().is_empty());
    }
}

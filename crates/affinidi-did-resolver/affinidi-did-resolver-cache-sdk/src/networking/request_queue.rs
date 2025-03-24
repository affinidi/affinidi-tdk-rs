//! When messages are sent via websocket, the response may be out of order
//! [RequestList] helps manage the buffer and returns the right response

use super::network::Responder;
use crate::config::DIDCacheConfig;
use ahash::AHashMap as HashMap;
use tracing::debug;

/// List of lookups that are in progress.Note the list is not in any order.
/// NOTE: SHA256 Hash of the DID is used as the key for the list
/// - list: The list of requests waiting for a response from the server (key: DID Hash, value: Vec[(Unique ID, Responder Channel)]
/// - list_full: Is the list full based on limits?
/// - limit_count: The maximum number of items to store in the request list
/// - total_count: The total number of items in the list
///
/// NOTE: Handles duplicate DID resolver requests, by matching them in the list by the DID hash, adds elements using
///       the unique ID as an identifier.
pub(crate) struct RequestList {
    list: HashMap<[u64; 2], Vec<(String, Responder)>>,
    list_full: bool,
    limit_count: u32,
    total_count: u32,
}

impl RequestList {
    /// Create a new request list
    pub fn new(config: &DIDCacheConfig) -> Self {
        debug!(
            "created request list limit_count({})",
            config.network_cache_limit_count
        );
        Self {
            list: HashMap::new(),
            list_full: false,
            limit_count: config.network_cache_limit_count,
            total_count: 0,
        }
    }

    /// Insert a new request into the list
    /// Returns: true if the request is new, false if it is a duplicate (no need to send to server)
    pub fn insert(&mut self, key: [u64; 2], uid: &str, channel: Responder) -> bool {
        // If the key exists, append the value to the list
        if let Some(element) = self.list.get_mut(&key) {
            element.push((uid.to_string(), channel));
            debug!(
                "Duplicate resolver request, adding to queue to await response. id ({:#?})",
                key
            );
            false
        } else {
            // Otherwise, create a new list with the value
            self.list.insert(key, vec![(uid.to_string(), channel)]);

            self.total_count += 1;

            if self.total_count > self.limit_count {
                self.list_full = true;
            }

            debug!(
                "Request inserted: id({:#?}) list_count({})",
                key, self.total_count
            );
            true
        }
    }

    /// Remove a response from the list returning the value
    /// ^^ This is why we don't need a get() function...
    /// If uid isn't provided, then all channels for given key are removed
    /// If uid is provided, then we just remove that channel for that key (which if empty will delete the key)
    pub(crate) fn remove(&mut self, key: &[u64; 2], uid: Option<String>) -> Option<Vec<Responder>> {
        // Get the Responder Channels from the list
        // Request must be in the list itself!

        if let Some(uid) = uid {
            let response = if let Some(channels) = self.list.get_mut(key) {
                // Find the index of the element to remove
                let index = channels.iter().position(|(id, _)| *id == uid);

                if let Some(index) = index {
                    // Remove the element from the list
                    let (_, channel) = channels.remove(index);

                    debug!(
                        "Request removed: id({:#?}) channels_waiting({}) list_count({})",
                        key,
                        channels.len(),
                        self.total_count
                    );
                    Some(vec![channel])
                } else {
                    debug!("Request not found: id({:#?}) unique_id({})", key, uid);
                    None
                }
            } else {
                debug!("Request not found: id({:#?})", key);
                None
            };

            // If the list is empty, remove the key
            if let Some(channels) = self.list.get(key) {
                if channels.is_empty() {
                    self.list.remove(key);
                    self.total_count -= 1;
                    self.list_full = false;
                }
            }

            response
        } else {
            // Remove all channels for the key
            if let Some(channels) = self.list.remove(key) {
                self.total_count -= 1;
                self.list_full = false;

                debug!(
                    "Request removed: hash({:#?}) channels_waiting({}) remaining_list_count({})",
                    key,
                    channels.len(),
                    self.total_count
                );

                Some(channels.into_iter().map(|(_, channel)| channel).collect())
            } else {
                debug!("Request not found: hash({:#?})", key);
                None
            }
        }
    }

    /// Is the list full based on limits?
    pub(crate) fn is_full(&self) -> bool {
        self.list_full
    }
}
#[cfg(test)]
mod tests {
    use crate::{
        DIDCacheClient, config,
        networking::{network::WSCommands, request_queue::RequestList},
    };
    use ahash::AHashMap as HashMap;
    use rand::{Rng, distr::Alphanumeric};
    use tokio::sync::oneshot::{self, Sender};

    const DID_KEY: &str = "did:key:z6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv";
    const DID_KEY_2: &str = "did:key:z6Mkp89diy1PZkbUBDTpiqZBotddb1VV7JnY8qiZMGErUbFe";

    #[tokio::test]
    async fn new_works() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let request_list = RequestList::new(&config);

        assert!(!request_list.list_full);
        assert_eq!(request_list.total_count, 0);
    }

    #[tokio::test]
    async fn insert_works_returns_true() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let mut request_list = RequestList::new(&config);

        let (tx, _) = oneshot::channel::<WSCommands>();

        let unique_id: String = _unique_id();
        let did_hash = DIDCacheClient::hash_did(DID_KEY);

        let insert_result = request_list.insert(did_hash, &unique_id, tx);

        assert!(insert_result);
    }

    #[tokio::test]
    async fn insert_works_returns_false_duplicates() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let mut request_list = RequestList::new(&config);

        let (tx, _) = oneshot::channel::<WSCommands>();
        let (tx2, _) = oneshot::channel::<WSCommands>();

        let unique_id: String = _unique_id();
        let did_hash = DIDCacheClient::hash_did(DID_KEY);

        let insert_result = request_list.insert(did_hash, &unique_id, tx);
        let insert_result2 = request_list.insert(did_hash, &unique_id, tx2);

        assert!(insert_result);
        assert!(!insert_result2);
    }

    #[tokio::test]
    async fn insert_list_becomes_full() {
        let config = config::DIDCacheConfigBuilder::default()
            .with_network_cache_limit_count(1)
            .build();
        let mut request_list = RequestList::new(&config);

        let (tx, _) = oneshot::channel::<WSCommands>();
        let (tx2, _) = oneshot::channel::<WSCommands>();

        let unique_id: String = _unique_id();
        let unique_id_2: String = _unique_id();

        let did_hash = DIDCacheClient::hash_did(DID_KEY);
        let did_hash_2 = DIDCacheClient::hash_did(DID_KEY_2);

        let insert_result = request_list.insert(did_hash, &unique_id, tx);
        let insert_result2 = request_list.insert(did_hash_2, &unique_id_2, tx2);

        assert!(insert_result);
        assert!(insert_result2);
        assert!(request_list.list_full);

        assert_eq!(request_list.total_count, 2);
    }

    #[tokio::test]
    async fn remove_key_not_found() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let mut request_list = RequestList::new(&config);

        let result = request_list.remove(&DIDCacheClient::hash_did(DID_KEY), None);
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn remove_key_not_found_passing_uuid() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let mut request_list = RequestList::new(&config);

        let result = request_list.remove(&DIDCacheClient::hash_did(DID_KEY), Some("".to_string()));
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn remove_key_not_found_passing_uuid_wrong_did() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let mut request_list = RequestList::new(&config);

        let result =
            request_list.remove(&DIDCacheClient::hash_did("wrongdid"), Some("".to_string()));
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn remove_passing_uuid_works() {
        let (mut request_list, did_to_uuid) = _fill_request_list([DID_KEY].to_vec(), true, Some(1));

        let num_of_channels_before_remove = request_list
            .list
            .get(&DIDCacheClient::hash_did(DID_KEY))
            .unwrap()
            .len();
        let total_count_before_remove = request_list.total_count;
        let ids = did_to_uuid.get(DID_KEY).unwrap();

        request_list
            .remove(&DIDCacheClient::hash_did(DID_KEY), ids.first().cloned())
            .unwrap();

        assert_eq!(
            num_of_channels_before_remove - 1,
            request_list
                .list
                .get(&DIDCacheClient::hash_did(DID_KEY))
                .unwrap()
                .len()
        );
        assert_eq!(total_count_before_remove, request_list.total_count);
    }

    #[tokio::test]
    async fn remove_without_passing_uuid_to_remove_all_works() {
        let (mut request_list, _) = _fill_request_list([DID_KEY].to_vec(), true, Some(4));

        request_list
            .remove(&DIDCacheClient::hash_did(DID_KEY), None)
            .unwrap();

        assert_eq!(request_list.total_count, 0);
    }

    #[tokio::test]
    async fn remove_works() {
        let (mut request_list, _) = _fill_request_list([DID_KEY].to_vec(), false, None);

        request_list
            .remove(&DIDCacheClient::hash_did(DID_KEY), None)
            .unwrap();
    }

    fn _unique_id() -> String {
        rand::rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect()
    }

    fn _fill_request_list(
        dids: Vec<&str>,
        fill_channels_for_key: bool,
        fill_channels_for_key_number: Option<u8>,
    ) -> (RequestList, HashMap<String, Vec<String>>) {
        fn get_hash_and_id(did: &str) -> (String, [u64; 2], Sender<WSCommands>) {
            (
                _unique_id(),
                DIDCacheClient::hash_did(did),
                oneshot::channel::<WSCommands>().0,
            )
        }

        let nested_channels_num = fill_channels_for_key_number.unwrap_or(0);

        let mut did_to_uuid_map: HashMap<String, Vec<String>> = HashMap::new();

        let config = config::DIDCacheConfigBuilder::default().build();
        let mut request_list = RequestList::new(&config);

        for did in dids {
            let (unique_id, did_hash, tx) = get_hash_and_id(did);
            let mut uuids_arr: Vec<String> = [unique_id.clone()].to_vec();
            let insert_result = request_list.insert(did_hash, &unique_id, tx);
            if insert_result && fill_channels_for_key {
                for _i in 0..nested_channels_num {
                    let (unique_id, did_hash, tx) = get_hash_and_id(did);
                    uuids_arr.push(unique_id.clone());
                    request_list.insert(did_hash, &unique_id, tx);
                }
            }
            did_to_uuid_map.insert(did.to_string(), uuids_arr);
        }

        (request_list, did_to_uuid_map)
    }
}

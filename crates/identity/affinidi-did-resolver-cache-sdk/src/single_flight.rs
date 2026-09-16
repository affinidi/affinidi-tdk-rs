//! Leadership of the single-flight maps that collapse concurrent cache misses
//! into one underlying resolution.
//!
//! The first caller to miss on a key becomes the leader and does the work; the
//! rest follow a `watch` channel and wake when the leader is done. Two
//! properties matter, and both are enforced here rather than at each call site:
//!
//! - **Followers receive the leader's failure.** Otherwise every follower
//!   becomes the next leader in turn, so N concurrent resolutions of a DID
//!   whose host is refusing us (HTTP 429, say) make N sequential fetches — the
//!   single-flight amplifying the very load that caused the refusal. The
//!   failure is shared only with callers already waiting: it is not cached, and
//!   the next resolution after the leader finishes fetches again.
//! - **Leadership is released when the leader's future is dropped**, not only
//!   when it returns. A caller that wraps `resolve` in a timeout cancels the
//!   leader mid-fetch; if the map entry outlived it, every later caller would
//!   find a closed channel, wake immediately, find nothing cached and loop —
//!   a busy spin that never yields.

use std::collections::HashMap;
use std::sync::{Mutex as StdMutex, PoisonError};

use tokio::sync::watch;

use crate::errors::DIDCacheError;

/// The value a follower reads: `Some` once the leader has failed.
type Outcome = Option<DIDCacheError>;

pub(crate) type InflightMap = StdMutex<HashMap<[u64; 2], watch::Receiver<Outcome>>>;

pub(crate) enum Role<'a> {
    Leader(Leadership<'a>),
    Follower(watch::Receiver<Outcome>),
}

/// Become the leader for `key`, or follow the leader already working on it.
pub(crate) fn claim(map: &InflightMap, key: [u64; 2]) -> Role<'_> {
    let mut entries = map.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(receiver) = entries.get(&key) {
        Role::Follower(receiver.clone())
    } else {
        let (sender, receiver) = watch::channel(None);
        entries.insert(key, receiver);
        Role::Leader(Leadership { map, key, sender })
    }
}

/// Wait for the leader to finish. Returns the leader's failure, or `None` when
/// it succeeded or was cancelled — the caller re-reads its cache to tell which.
pub(crate) async fn follow(mut receiver: watch::Receiver<Outcome>) -> Outcome {
    // Resolves when the leader publishes a failure, or with an error once the
    // leader's sender is dropped; the value is read the same way in both cases.
    let _ = receiver.changed().await;
    receiver.borrow().clone()
}

/// Held by the leader for the duration of its resolution. Dropping it — by
/// returning or by being cancelled — removes the map entry and wakes followers.
pub(crate) struct Leadership<'a> {
    map: &'a InflightMap,
    key: [u64; 2],
    sender: watch::Sender<Outcome>,
}

impl Leadership<'_> {
    /// Hand `error` to every waiting follower, then release leadership.
    pub(crate) fn fail(self, error: &DIDCacheError) {
        self.sender.send_replace(Some(error.clone()));
    }
}

impl Drop for Leadership<'_> {
    fn drop(&mut self) {
        // Not `expect`: this runs during unwinding too, and a second panic
        // there aborts the process.
        self.map
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn follower_receives_the_leaders_failure() {
        let map = InflightMap::default();
        let Role::Leader(leadership) = claim(&map, [1, 2]) else {
            panic!("the first claim leads");
        };
        let Role::Follower(receiver) = claim(&map, [1, 2]) else {
            panic!("the second claim follows");
        };

        leadership.fail(&DIDCacheError::NetworkTimeout);

        assert!(matches!(
            follow(receiver).await,
            Some(DIDCacheError::NetworkTimeout)
        ));
        assert!(map.lock().unwrap().is_empty(), "failure is not retained");
    }

    #[tokio::test]
    async fn dropped_leadership_releases_the_key() {
        let map = InflightMap::default();
        let Role::Leader(leadership) = claim(&map, [3, 4]) else {
            panic!("the first claim leads");
        };
        let Role::Follower(receiver) = claim(&map, [3, 4]) else {
            panic!("the second claim follows");
        };

        drop(leadership);

        assert!(follow(receiver).await.is_none());
        assert!(matches!(claim(&map, [3, 4]), Role::Leader(_)));
    }
}

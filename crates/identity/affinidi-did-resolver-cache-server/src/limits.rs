//! Limits on WebSocket connections: how many may be open, in all and per
//! client address, and the timeouts and message size each one runs under.

use crate::config::Config;
use std::{
    collections::HashMap,
    fmt,
    net::IpAddr,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Why a new WebSocket connection was not admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionRefused {
    /// The server-wide connection limit is reached.
    ServerFull,
    /// This client address has as many connections open as it may.
    ClientFull,
}

impl fmt::Display for ConnectionRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionRefused::ServerFull => {
                f.write_str("too many open WebSocket connections; retry shortly")
            }
            ConnectionRefused::ClientFull => {
                f.write_str("too many open WebSocket connections from this address")
            }
        }
    }
}

struct Connections {
    total: Arc<Semaphore>,
    per_client: Mutex<HashMap<IpAddr, usize>>,
    max_per_client: usize,
}

/// WebSocket limits shared by every connection.
pub struct WsLimits {
    /// A connection that receives nothing for this long is closed.
    pub idle_timeout: Duration,
    /// A send that takes longer than this closes the connection.
    pub send_timeout: Duration,
    /// Largest message (and frame) accepted, in bytes.
    pub max_message_size: usize,
    max_connections: usize,
    connections: Arc<Connections>,
}

impl fmt::Debug for WsLimits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WsLimits")
            .field("idle_timeout", &self.idle_timeout)
            .field("send_timeout", &self.send_timeout)
            .field("max_message_size", &self.max_message_size)
            .field("max_connections", &self.max_connections)
            .field(
                "max_connections_per_client",
                &self.connections.max_per_client,
            )
            .field("open_connections", &self.open_connections())
            .finish()
    }
}

impl WsLimits {
    /// `max_connections` and `max_connections_per_client` are raised to 1 if
    /// given as 0.
    pub fn new(
        max_connections: usize,
        max_connections_per_client: usize,
        idle_timeout: Duration,
        send_timeout: Duration,
        max_message_size: usize,
    ) -> Self {
        let max_connections = max_connections.clamp(1, Semaphore::MAX_PERMITS);
        WsLimits {
            idle_timeout,
            send_timeout,
            max_message_size,
            max_connections,
            connections: Arc::new(Connections {
                total: Arc::new(Semaphore::new(max_connections)),
                per_client: Mutex::new(HashMap::new()),
                max_per_client: max_connections_per_client.max(1),
            }),
        }
    }

    pub fn from_config(config: &Config) -> Self {
        WsLimits::new(
            config.ws_max_connections,
            config.ws_max_connections_per_ip,
            config.ws_idle_timeout,
            config.ws_send_timeout,
            config.ws_max_message_size,
        )
    }

    /// Admit a connection from `client`, or refuse it if either limit is
    /// reached. The connection counts until the returned slot is dropped.
    pub fn try_open(&self, client: IpAddr) -> Result<ConnectionSlot, ConnectionRefused> {
        // Taken first: if the client limit then refuses, dropping the permit
        // gives the place back.
        let total = self
            .connections
            .total
            .clone()
            .try_acquire_owned()
            .map_err(|_| ConnectionRefused::ServerFull)?;

        let mut per_client = self
            .connections
            .per_client
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let open = per_client.get(&client).copied().unwrap_or(0);
        if open >= self.connections.max_per_client {
            return Err(ConnectionRefused::ClientFull);
        }
        per_client.insert(client, open + 1);

        Ok(ConnectionSlot {
            _total: total,
            client,
            connections: self.connections.clone(),
        })
    }

    /// Connections open now, across all clients.
    pub fn open_connections(&self) -> usize {
        self.max_connections - self.connections.total.available_permits()
    }

    /// Connections open now from `client`.
    pub fn open_connections_from(&self, client: IpAddr) -> usize {
        self.connections
            .per_client
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&client)
            .copied()
            .unwrap_or(0)
    }
}

/// One admitted connection. Dropping it frees its place in both limits.
pub struct ConnectionSlot {
    _total: OwnedSemaphorePermit,
    client: IpAddr,
    connections: Arc<Connections>,
}

impl fmt::Debug for ConnectionSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionSlot")
            .field("client", &self.client)
            .finish()
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        let mut per_client = self
            .connections
            .per_client
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(open) = per_client.get_mut(&self.client) {
            *open = open.saturating_sub(1);
            if *open == 0 {
                // No entry is kept for an address with nothing open, so the
                // map never holds more entries than there are connections.
                per_client.remove(&self.client);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn limits(total: usize, per_client: usize) -> WsLimits {
        WsLimits::new(
            total,
            per_client,
            Duration::from_secs(1),
            Duration::from_secs(1),
            1024,
        )
    }

    #[test]
    fn a_client_is_held_to_its_limit() {
        let limits = limits(10, 2);
        let a = limits.try_open(ip("203.0.113.1")).unwrap();
        let _b = limits.try_open(ip("203.0.113.1")).unwrap();
        assert_eq!(
            limits.try_open(ip("203.0.113.1")).unwrap_err(),
            ConnectionRefused::ClientFull
        );
        // A refused client does not use up a server-wide place.
        assert_eq!(limits.open_connections(), 2);
        // Another client is unaffected.
        let _c = limits.try_open(ip("198.51.100.1")).unwrap();

        drop(a);
        assert_eq!(limits.open_connections_from(ip("203.0.113.1")), 1);
        let _d = limits.try_open(ip("203.0.113.1")).unwrap();
    }

    #[test]
    fn the_server_is_held_to_its_limit() {
        let limits = limits(2, 10);
        let a = limits.try_open(ip("203.0.113.1")).unwrap();
        let _b = limits.try_open(ip("198.51.100.1")).unwrap();
        assert_eq!(
            limits.try_open(ip("192.0.2.1")).unwrap_err(),
            ConnectionRefused::ServerFull
        );
        assert_eq!(limits.open_connections_from(ip("192.0.2.1")), 0);
        drop(a);
        let _c = limits.try_open(ip("192.0.2.1")).unwrap();
        assert_eq!(limits.open_connections(), 2);
    }

    #[test]
    fn closed_connections_leave_no_entry() {
        let limits = limits(10, 10);
        let slots: Vec<_> = (1..=5)
            .map(|n| limits.try_open(ip(&format!("203.0.113.{n}"))).unwrap())
            .collect();
        assert_eq!(limits.connections.per_client.lock().unwrap().len(), 5);
        drop(slots);
        assert!(limits.connections.per_client.lock().unwrap().is_empty());
        assert_eq!(limits.open_connections(), 0);
    }

    #[test]
    fn zero_limits_are_raised_to_one() {
        let limits = limits(0, 0);
        let _a = limits.try_open(ip("203.0.113.1")).unwrap();
        assert_eq!(
            limits.try_open(ip("198.51.100.1")).unwrap_err(),
            ConnectionRefused::ServerFull
        );
    }
}

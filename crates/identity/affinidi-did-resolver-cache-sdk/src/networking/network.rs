//! NetworkTask handles the communication with the network.
//! This runs as a separate task in the background.
//! Allows for multiplexing of multiple requests/responses to the network.
//!
//! The SDK communicates via a MPSC channel to this task.
//! The remote server communicates via a websocket connection.
//!
//! # How the task stays responsive
//!
//! The task never blocks on the network while there are commands to answer:
//!
//! - **Reading** runs in its own task per connection, which owns the read half
//!   of the socket and forwards whole messages (fragmented messages are
//!   reassembled there). The main loop reads that channel, which is
//!   cancel-safe, so no frame is ever half-read and lost when another branch
//!   wins the `select!`.
//! - **Reconnecting** is a state of the loop, not a loop of its own: while the
//!   connection is down, a `Send` is answered at once with a transport error,
//!   and the reconnect (with backoff) runs as one more branch of the `select!`.
//! - **Commands** are always read. A `Send` that would grow the request list
//!   past its limit is answered with an error instead of the loop ceasing to
//!   read commands (which would also stop it reading the `TimeOut`s that free
//!   the list).
//!
//! Every request in flight when the connection is lost is answered with a
//! transport error, and the connection state is published on every change (see
//! [`ConnectionState`]).

use affinidi_task_utils::CancellationToken;

use super::{ConnectionState, WSResponse, WSResponseType, request_queue::RequestList};
use crate::{
    DIDCacheClient, WSRequest, config::DIDCacheConfig, errors::DIDCacheError,
    networking::utils::connect,
};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, BufReader, ReadHalf, WriteHalf},
    select,
    sync::{
        mpsc::{self, Receiver},
        oneshot, watch,
    },
    task::JoinHandle,
    time::{interval_at, sleep, timeout},
};
use tracing::{Instrument, Level, debug, info, span, warn};
use web_socket::{CloseCode, DataType, Event, Stream, WebSocket};

/// WSCommands are the commands that can be sent between the SDK and the network task
/// Send: Sends the response string to the websocket (Channel, ID, WSRequest)
/// ResponseReceived: the full response frame from the websocket. Carrying the
///   whole `WSResponse` rather than picked-apart fields means the agent name
///   path can read the *resolved* DID and the echoed name, and future fields
///   need no further change here.
/// ErrorReceived: Error received from the remote server
/// TransportFailed: the request was not answered by the server: the client is
///   not connected, the connection was lost while it was in flight, it could
///   not be written, or too many requests are already in flight.
/// TimeOut: SDK request timed out, contains ID and did_hash we were looking for
#[derive(Debug)]
pub(crate) enum WSCommands {
    Send(Responder, String, WSRequest),
    ResponseReceived(Box<WSResponse>),
    ErrorReceived(String),
    TransportFailed(String),
    TimeOut(String, [u64; 2]),
}

pub(crate) type Responder = oneshot::Sender<WSCommands>;

/// The following is to help with handling either TCP or TLS connections
pub(crate) trait ReadWrite: AsyncRead + AsyncWrite + Send {}
impl<T> ReadWrite for T where T: AsyncRead + AsyncWrite + Send {}

pub(crate) type WsStream = BufReader<Pin<Box<dyn ReadWrite>>>;
type WsReader = WebSocket<ReadHalf<WsStream>>;
type WsWriter = WebSocket<WriteHalf<WsStream>>;

/// Largest message accepted from the server, after reassembling fragments.
/// The same as the per-frame limit of the WebSocket library.
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Interval between keep-alive pings; three unanswered in a row drop the
/// connection.
const PING_INTERVAL: Duration = Duration::from_secs(20);

/// Delay before reconnecting after an established connection is lost. Small,
/// but not zero, so a server that accepts and immediately closes connections
/// is not hammered in a tight loop.
const RECONNECT_DELAY: Duration = Duration::from_millis(100);

/// Longest wait between failed connection attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// The connection state shared between the network task (which publishes it)
/// and the client (which hands out receivers).
///
/// Lives outside the task so it survives a supervisor restart: the epoch keeps
/// counting, and receivers stay subscribed.
pub(crate) struct ConnectionSignal {
    state: watch::Sender<ConnectionState>,
    epoch: AtomicU64,
}

impl ConnectionSignal {
    pub(crate) fn new() -> Self {
        ConnectionSignal {
            state: watch::Sender::new(ConnectionState::Connecting),
            epoch: AtomicU64::new(0),
        }
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<ConnectionState> {
        self.state.subscribe()
    }

    pub(crate) fn set(&self, state: ConnectionState) {
        self.state.send_replace(state);
    }

    fn connected(&self) {
        let epoch = self.epoch.fetch_add(1, Ordering::SeqCst) + 1;
        self.set(ConnectionState::Connected { epoch });
    }
}

/// What the reader task forwards to the main loop.
#[derive(Debug)]
enum Inbound {
    Message(String),
    Ping(Box<[u8]>),
    Pong,
    /// The connection can no longer be read; the reason why.
    Closed(String),
}

/// An established connection: the write half, and the reader task that owns
/// the read half. Dropping it stops the reader.
struct Connection {
    writer: WsWriter,
    inbound: Receiver<Inbound>,
    _reader: AbortOnDrop,
}

/// Aborts the reader task when the connection is dropped.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Connection {
    fn new(socket: WebSocket<WsStream>) -> Self {
        let (read, write) = tokio::io::split(socket.stream);
        let (tx, inbound) = mpsc::channel(32);
        let reader = tokio::spawn(read_loop(WebSocket::client(read), tx));
        Connection {
            writer: WebSocket::client(write),
            inbound,
            _reader: AbortOnDrop(reader),
        }
    }
}

/// Reads the socket and forwards whole messages, pings, pongs and the reason
/// the connection ended. Reassembles fragmented messages.
async fn read_loop(mut socket: WsReader, tx: mpsc::Sender<Inbound>) {
    let mut partial: Option<Vec<u8>> = None;
    loop {
        let event = match socket.recv().await {
            Ok(event) => event,
            Err(err) => {
                let _ = tx
                    .send(Inbound::Closed(format!("receive error: {err}")))
                    .await;
                return;
            }
        };
        let inbound = match event {
            Event::Data { ty, data } => match assemble(&mut partial, ty, data) {
                Ok(Some(message)) => Inbound::Message(message),
                Ok(None) => continue,
                Err(reason) => Inbound::Closed(reason),
            },
            Event::Ping(data) => Inbound::Ping(data),
            Event::Pong(_) => Inbound::Pong,
            Event::Error(err) => Inbound::Closed(format!("protocol error: {err}")),
            Event::Close { code, reason } => {
                Inbound::Closed(format!("closed by the server ({code}: {reason})"))
            }
        };
        let closed = matches!(inbound, Inbound::Closed(_));
        if tx.send(inbound).await.is_err() || closed {
            return;
        }
    }
}

/// Add a data frame to the message being assembled. Returns the message once
/// it is complete, `None` while more fragments are expected, or why the
/// connection must be dropped.
fn assemble(
    partial: &mut Option<Vec<u8>>,
    ty: DataType,
    data: Box<[u8]>,
) -> Result<Option<String>, String> {
    let complete = match ty {
        DataType::Complete(_) => {
            if partial.is_some() {
                return Err(
                    "protocol error: a whole message arrived inside a fragmented one".into(),
                );
            }
            data.into_vec()
        }
        DataType::Stream(Stream::Start(_)) => {
            *partial = Some(data.into_vec());
            return Ok(None);
        }
        DataType::Stream(Stream::Next(_)) | DataType::Stream(Stream::End(_)) => {
            let Some(buffer) = partial.as_mut() else {
                return Err("protocol error: a continuation frame without a first fragment".into());
            };
            if buffer.len() + data.len() > MAX_MESSAGE_SIZE {
                return Err(format!(
                    "message larger than {MAX_MESSAGE_SIZE} bytes in fragments"
                ));
            }
            buffer.extend_from_slice(&data);
            if matches!(ty, DataType::Stream(Stream::Next(_))) {
                return Ok(None);
            }
            partial.take().unwrap_or_default()
        }
    };
    Ok(Some(String::from_utf8_lossy(&complete).into_owned()))
}

type ConnectFuture = Pin<Box<dyn Future<Output = Result<WebSocket<WsStream>, String>> + Send>>;

/// NetworkTask handles the communication with the network.
/// This runs as a separate task in the background.
pub(crate) struct NetworkTask {
    config: DIDCacheConfig,
    service_address: String,
    cache: RequestList,
    signal: Arc<ConnectionSignal>,
    connection: Option<Connection>,
    connecting: Option<ConnectFuture>,
    /// Consecutive failed connection attempts, for the backoff.
    failures: u32,
    missed_pings: u32,
    /// Messages from the server that did not parse, for rate-limiting the
    /// warning.
    unparseable_messages: u64,
}

impl NetworkTask {
    pub async fn run(
        config: DIDCacheConfig,
        sdk_rx: &mut Receiver<WSCommands>,
        signal: Arc<ConnectionSignal>,
        shutdown: CancellationToken,
    ) -> Result<(), DIDCacheError> {
        let _span = span!(Level::INFO, "network_task");
        async move {
            debug!("Starting...");

            let service_address = if let Some(service_address) = &config.service_address {
                service_address.to_string()
            } else {
                return Err(DIDCacheError::ConfigError(
                    "Running in local mode, yet network service called!".to_string(),
                ));
            };

            let cache = RequestList::new(&config);

            let mut task = NetworkTask {
                config,
                service_address,
                cache,
                signal,
                connection: None,
                connecting: None,
                failures: 0,
                missed_pings: 0,
                unparseable_messages: 0,
            };
            // A restart after a panic must not report the previous run's
            // connection as still up.
            if task.signal.state.borrow().is_connected() {
                task.signal.set(ConnectionState::Disconnected {
                    reason: "network task restarted".into(),
                });
            }
            task.start_connecting(Duration::ZERO);

            let mut watchdog =
                interval_at(tokio::time::Instant::now() + PING_INTERVAL, PING_INTERVAL);

            loop {
                select! {
                    _ = shutdown.cancelled() => {
                        debug!("Shutdown signalled; closing network task");
                        task.close().await;
                        return Ok(());
                    }
                    command = sdk_rx.recv() => {
                        let Some(command) = command else {
                            // MPSC channel closed: every SDK handle has been
                            // dropped, so there is nothing left to serve.
                            // Cancel so the supervisor records `Stopped`
                            // rather than restarting a task with no clients.
                            info!("SDK channel closed");
                            task.close().await;
                            shutdown.cancel();
                            return Ok(());
                        };
                        task.handle_command(command).await;
                    }
                    inbound = next_inbound(&mut task.connection) => {
                        task.handle_inbound(inbound).await;
                    }
                    result = next_connect(&mut task.connecting) => {
                        task.connecting = None;
                        task.connect_finished(result);
                    }
                    _ = watchdog.tick() => {
                        task.keep_alive().await;
                    }
                }
            }
        }
        .instrument(_span)
        .await
    }

    /// Answer one command from the SDK.
    async fn handle_command(&mut self, command: WSCommands) {
        match command {
            WSCommands::Send(responder, uid, request) => {
                if self.connection.is_none() {
                    let _ = responder.send(WSCommands::TransportFailed(format!(
                        "not connected to the DID cache server ({}); reconnecting",
                        self.service_address
                    )));
                    return;
                }
                let hash = DIDCacheClient::hash_did(&request.did);
                if !self.cache.contains(&hash) && self.cache.is_full() {
                    // Requests whose callers have given up still count until
                    // their `TimeOut` arrives; drop them before refusing.
                    self.cache.prune_closed();
                    if self.cache.is_full() {
                        let _ = responder.send(WSCommands::TransportFailed(
                            "too many requests in flight to the DID cache server".into(),
                        ));
                        return;
                    }
                }
                if self.cache.insert(hash, &uid, responder)
                    && let Err(err) = self.ws_send(&request).await
                {
                    warn!("Couldn't send request to the DID cache server: {err}");
                    self.connection_lost(format!("send failed: {err}"));
                }
            }
            WSCommands::TimeOut(uid, did_hash) => {
                let _ = self.cache.remove(&did_hash, Some(uid));
            }
            other => {
                debug!("Invalid command received: {:?}", other);
            }
        }
    }

    /// Handle what the reader task forwarded.
    async fn handle_inbound(&mut self, inbound: Inbound) {
        match inbound {
            Inbound::Message(message) => {
                debug!("Received DID Lookup response ({})", message);
                self.ws_recv(&message);
            }
            Inbound::Ping(data) => {
                if let Some(connection) = self.connection.as_mut() {
                    let sent = timeout(
                        self.config.network_timeout,
                        connection.writer.send_pong(data),
                    )
                    .await;
                    if !matches!(sent, Ok(Ok(()))) {
                        self.connection_lost("could not answer a ping".into());
                    }
                }
            }
            Inbound::Pong => {
                self.missed_pings = self.missed_pings.saturating_sub(1);
            }
            Inbound::Closed(reason) => {
                warn!("WebSocket connection lost: {reason}");
                self.connection_lost(reason);
            }
        }
    }

    /// Ping the server, and drop a connection that has stopped answering.
    async fn keep_alive(&mut self) {
        // Callers that timed out while their `TimeOut` was lost (the command
        // channel was full) are cleared here at the latest.
        self.cache.prune_closed();

        let Some(connection) = self.connection.as_mut() else {
            return;
        };
        if self.missed_pings > 2 {
            warn!("Missed 3 pings, restarting connection");
            self.connection_lost("no answer to 3 pings".into());
            return;
        }
        let sent = timeout(
            self.config.network_timeout,
            connection.writer.send_ping(vec![]),
        )
        .await;
        if !matches!(sent, Ok(Ok(()))) {
            self.connection_lost("could not send a ping".into());
            return;
        }
        self.missed_pings += 1;
    }

    /// The outcome of a connection attempt.
    fn connect_finished(&mut self, result: Result<WebSocket<WsStream>, String>) {
        match result {
            Ok(socket) => {
                debug!("Websocket connected");
                self.connection = Some(Connection::new(socket));
                self.failures = 0;
                self.missed_pings = 0;
                self.signal.connected();
            }
            Err(reason) => {
                warn!("Couldn't connect to the DID cache server: {reason}");
                self.failures = self.failures.saturating_add(1);
                self.signal.set(ConnectionState::Disconnected { reason });
                self.start_connecting(backoff(self.failures));
            }
        }
    }

    /// Drop the connection: answer every request in flight with an error,
    /// publish the state, and start reconnecting.
    fn connection_lost(&mut self, reason: String) {
        if self.connection.take().is_none() {
            return;
        }
        let pending = self.cache.drain();
        if !pending.is_empty() {
            debug!(
                "Failing {} request(s) in flight on the lost connection",
                pending.len()
            );
        }
        for responder in pending {
            let _ = responder.send(WSCommands::TransportFailed(format!(
                "connection to the DID cache server lost: {reason}"
            )));
        }
        self.signal.set(ConnectionState::Disconnected { reason });
        self.start_connecting(RECONNECT_DELAY);
    }

    fn start_connecting(&mut self, delay: Duration) {
        let address = self.service_address.clone();
        let connect_timeout = self.config.network_timeout;
        if !delay.is_zero() {
            debug!("connect backoff: {:?}", delay);
        }
        self.connecting = Some(Box::pin(async move {
            sleep(delay).await;
            debug!("Starting websocket connection");
            match timeout(connect_timeout, create_socket(&address)).await {
                Ok(result) => result.map_err(|e| e.to_string()),
                Err(_) => Err(format!(
                    "connecting to {address} timed out after {connect_timeout:?}"
                )),
            }
        }));
    }

    /// Close the connection on shutdown and publish `Stopped`.
    async fn close(&mut self) {
        self.connecting = None;
        if let Some(connection) = self.connection.take() {
            let _ = timeout(
                self.config.network_timeout,
                connection.writer.close(CloseCode::Normal),
            )
            .await;
        }
        for responder in self.cache.drain() {
            let _ = responder.send(WSCommands::TransportFailed(
                "the DID cache client is stopping".into(),
            ));
        }
        self.signal.set(ConnectionState::Stopped);
    }

    /// Sends the request to the remote server via the websocket
    async fn ws_send(&mut self, request: &WSRequest) -> Result<(), DIDCacheError> {
        let Some(connection) = self.connection.as_mut() else {
            return Err(DIDCacheError::TransportError("not connected".into()));
        };
        let request_str = serde_json::to_string(request).map_err(|e| {
            DIDCacheError::TransportError(format!("Failed to serialize request: {e}"))
        })?;
        match timeout(
            self.config.network_timeout,
            connection.writer.send(request_str.as_str()),
        )
        .await
        {
            Ok(Ok(())) => {
                debug!("Request sent: {:?}", request);
                Ok(())
            }
            Ok(Err(e)) => Err(DIDCacheError::TransportError(format!(
                "Couldn't write request to the websocket: {e}",
            ))),
            Err(_) => Err(DIDCacheError::TransportError(format!(
                "Writing the request did not finish within {:?}",
                self.config.network_timeout
            ))),
        }
    }

    /// Processes inbound websocket messages from the remote server.
    ///
    /// A message this client cannot parse is not a connection fault: the
    /// server and the SDK are deployed independently, and a newer server may
    /// answer in a shape this client does not know. Dropping the connection
    /// would fail every other request in flight, and reconnect on every such
    /// answer. Instead, the one waiter the message names (by its `hash`) gets
    /// an error, and a message naming none is ignored.
    fn ws_recv(&mut self, message: &str) {
        let response: WSResponseType = match serde_json::from_str(message) {
            Ok(response) => response,
            Err(e) => {
                self.unparseable(message, &e);
                return;
            }
        };
        match response {
            WSResponseType::Response(response) => {
                debug!("Received response: {:?}", response.hash);
                if let Some(channels) = self.cache.remove(&response.hash, None) {
                    // Loop through and notify each registered channel
                    for channel in channels {
                        let _ = channel.send(WSCommands::ResponseReceived(Box::new(
                            WSResponse::new(
                                response.did.clone(),
                                response.hash,
                                response.document.clone(),
                            )
                            .with_logs(response.did_log.clone(), response.did_witness_log.clone())
                            .with_agent_name(response.agent_name.clone()),
                        )));
                    }
                } else {
                    debug!("Response not found in request list: {:#?}", response.hash);
                }
            }
            WSResponseType::Error(response) => {
                warn!(
                    "Received error: did hash({:#?}) Error: {:?}",
                    response.hash, response.error
                );
                if let Some(channels) = self.cache.remove(&response.hash, None) {
                    for channel in channels {
                        let _ = channel.send(WSCommands::ErrorReceived(response.error.clone()));
                    }
                } else {
                    debug!("Response not found in request list: {:#?}", response.hash);
                }
            }
        }
    }

    /// Handle a message that did not parse: fail the waiter it names, if any.
    fn unparseable(&mut self, message: &str, error: &serde_json::Error) {
        self.unparseable_messages = self.unparseable_messages.saturating_add(1);
        let hash = request_hash(message);
        // Warn for the first few, then every hundredth, so a server that
        // answers everything in a new shape does not flood the log.
        let count = self.unparseable_messages;
        if count <= 3 || count.is_multiple_of(100) {
            warn!(
                "Unparseable message from the DID cache server ({count} so far; \
                 the server may be newer than this client): {error}"
            );
        } else {
            debug!("Unparseable message from the DID cache server: {error}");
        }
        let Some(hash) = hash else {
            return;
        };
        if let Some(channels) = self.cache.remove(&hash, None) {
            for channel in channels {
                let _ = channel.send(WSCommands::TransportFailed(format!(
                    "the DID cache server's answer could not be parsed \
                     (is the server newer than this client?): {error}"
                )));
            }
        }
    }
}

/// The request hash an unparseable message carries, if it has one where every
/// response type keeps it: a `hash` of two integers, at the top level or one
/// level down (inside the externally tagged variant).
fn request_hash(message: &str) -> Option<[u64; 2]> {
    let value: serde_json::Value = serde_json::from_str(message).ok()?;
    let as_hash = |v: &serde_json::Value| -> Option<[u64; 2]> {
        let array = v.get("hash")?.as_array()?;
        match array.as_slice() {
            [a, b] => Some([a.as_u64()?, b.as_u64()?]),
            _ => None,
        }
    };
    as_hash(&value).or_else(|| value.as_object()?.values().find_map(as_hash))
}

/// Wait between connection attempts after `failures` consecutive failures:
/// 1, 2, 4, … seconds, at most [`MAX_BACKOFF`].
fn backoff(failures: u32) -> Duration {
    let exponent = failures.saturating_sub(1).min(6);
    Duration::from_secs(1u64 << exponent).min(MAX_BACKOFF)
}

/// The next message from the connection, or never when there is none.
async fn next_inbound(connection: &mut Option<Connection>) -> Inbound {
    match connection {
        Some(connection) => connection
            .inbound
            .recv()
            .await
            .unwrap_or_else(|| Inbound::Closed("the reader stopped".into())),
        None => std::future::pending().await,
    }
}

/// The outcome of the connection attempt in progress, or never when there is
/// none.
async fn next_connect(
    connecting: &mut Option<ConnectFuture>,
) -> Result<WebSocket<WsStream>, String> {
    match connecting {
        Some(attempt) => attempt.await,
        None => std::future::pending().await,
    }
}

/// Open a websocket connection to the DID cache server.
async fn create_socket(service_address: &str) -> Result<WebSocket<WsStream>, DIDCacheError> {
    let url = url::Url::parse(service_address).map_err(|err| {
        DIDCacheError::TransportError(format!(
            "Invalid ServiceEndpoint address {service_address}: {err}"
        ))
    })?;
    connect(&url)
        .await
        .map_err(|err| DIDCacheError::TransportError(format!("Websocket connection failed: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_up_to_the_cap() {
        assert_eq!(backoff(1), Duration::from_secs(1));
        assert_eq!(backoff(2), Duration::from_secs(2));
        assert_eq!(backoff(4), Duration::from_secs(8));
        assert_eq!(backoff(7), MAX_BACKOFF);
        assert_eq!(backoff(u32::MAX), MAX_BACKOFF);
    }

    #[test]
    fn fragments_are_reassembled() {
        use web_socket::MessageType::Text;
        let mut partial = None;
        let frame = |s: &str| s.as_bytes().to_vec().into_boxed_slice();
        assert_eq!(
            assemble(
                &mut partial,
                DataType::Stream(Stream::Start(Text)),
                frame("{\"a\":")
            ),
            Ok(None)
        );
        assert_eq!(
            assemble(
                &mut partial,
                DataType::Stream(Stream::Next(Text)),
                frame(" 1")
            ),
            Ok(None)
        );
        assert_eq!(
            assemble(
                &mut partial,
                DataType::Stream(Stream::End(Text)),
                frame("}")
            ),
            Ok(Some("{\"a\": 1}".to_string()))
        );
        assert!(partial.is_none());
        assert_eq!(
            assemble(&mut partial, DataType::Complete(Text), frame("whole")),
            Ok(Some("whole".to_string()))
        );
    }

    #[test]
    fn the_hash_of_an_unknown_answer_is_found() {
        assert_eq!(
            request_hash(r#"{"NewVariant":{"did":"did:web:a","hash":[1,2],"x":true}}"#),
            Some([1, 2])
        );
        assert_eq!(request_hash(r#"{"hash":[3,4]}"#), Some([3, 4]));
        assert_eq!(request_hash(r#"{"NewVariant":{"did":"did:web:a"}}"#), None);
        assert_eq!(request_hash("not json"), None);
        assert_eq!(request_hash(r#"{"hash":[1]}"#), None);
    }

    #[test]
    fn a_continuation_without_a_start_is_a_protocol_error() {
        use web_socket::MessageType::Text;
        let mut partial = None;
        assert!(
            assemble(
                &mut partial,
                DataType::Stream(Stream::End(Text)),
                Box::new([])
            )
            .is_err()
        );
    }
}

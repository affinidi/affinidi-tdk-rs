//! A hermetic network for the live conformance sections: TLS listeners that
//! play public addresses, a sink that plays an internal service, a stub DNS
//! zone, and a post-vetting map from public addresses to those listeners.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::is_globally_routable;

pub(crate) struct Tls {
    pub(crate) server: Arc<rustls::ServerConfig>,
    pub(crate) client: rustls::ClientConfig,
}

/// A self-signed certificate for `names`, with a server config presenting it
/// and a client config trusting only it.
pub(crate) fn tls_for(names: &[String]) -> Tls {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let certified = rcgen::generate_simple_self_signed(names.to_vec()).expect("self-signed cert");
    let cert = certified.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .expect("server cert");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).expect("root");
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    Tls {
        server: Arc::new(server),
        client,
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Route {
    pub(crate) status: u16,
    pub(crate) location: Option<String>,
}

/// Counts accepted TCP connections.
#[derive(Debug, Clone, Default)]
pub(crate) struct Counter(Arc<AtomicUsize>);

impl Counter {
    fn hit(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    pub(crate) fn get(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

/// An HTTPS listener on `127.0.0.1` that serves `routes`, one request per
/// connection, and counts connections.
pub(crate) async fn spawn_tls_listener(
    tls: Arc<rustls::ServerConfig>,
    routes: Arc<HashMap<String, Route>>,
) -> (u16, Counter) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local addr").port();
    let counter = Counter::default();
    let accepted = counter.clone();
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            accepted.hit();
            let acceptor = acceptor.clone();
            let routes = routes.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let Some(path) = read_request_path(&mut stream).await else {
                    return;
                };
                let route = routes.get(&path).cloned().unwrap_or(Route {
                    status: 404,
                    location: None,
                });
                let location = route
                    .location
                    .map(|location| format!("Location: {location}\r\n"))
                    .unwrap_or_default();
                let response = format!(
                    "HTTP/1.1 {} Test\r\n{location}Content-Length: 2\r\nConnection: close\r\n\r\nok",
                    route.status
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (port, counter)
}

async fn read_request_path<S: AsyncRead + Unpin>(stream: &mut S) -> Option<String> {
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 || head.len() > 16 * 1024 {
            return None;
        }
        head.extend_from_slice(&chunk[..read]);
    }
    let head = String::from_utf8_lossy(&head);
    head.lines()
        .next()?
        .split_whitespace()
        .nth(1)
        .map(str::to_owned)
}

/// A plain TCP listener standing in for an internal service. It listens on
/// `127.0.0.1` and, where the host has it, on `::1` at the same port.
pub(crate) async fn spawn_sink() -> (u16, Counter) {
    let v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let port = v4.local_addr().expect("local addr").port();
    let counter = Counter::default();
    spawn_counting(v4, counter.clone());
    if let Ok(v6) = TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await {
        spawn_counting(v6, counter.clone());
    }
    (port, counter)
}

fn spawn_counting(listener: TcpListener, counter: Counter) {
    tokio::spawn(async move {
        while let Ok((_stream, _)) = listener.accept().await {
            counter.hit();
        }
    });
}

/// A fixed DNS zone. The nth lookup of a name returns its nth answer set (the
/// last one repeats). A non-routable answer carries the sink's port, so a
/// guard that let it through would be caught connecting there.
#[derive(Debug)]
pub(crate) struct StubResolver {
    zone: HashMap<String, Vec<Vec<IpAddr>>>,
    sink_port: u16,
    lookups: Mutex<HashMap<String, usize>>,
}

impl StubResolver {
    pub(crate) fn new(zone: HashMap<String, Vec<Vec<IpAddr>>>, sink_port: u16) -> Arc<Self> {
        Arc::new(Self {
            zone,
            sink_port,
            lookups: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) fn lookups(&self, name: &str) -> usize {
        self.lookups
            .lock()
            .expect("lookups lock")
            .get(name)
            .copied()
            .unwrap_or(0)
    }
}

impl Resolve for StubResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let answers = {
            let mut lookups = self.lookups.lock().expect("lookups lock");
            let count = lookups.entry(host.clone()).or_default();
            let answers = self
                .zone
                .get(&host)
                .and_then(|sets| sets.get(*count).or_else(|| sets.last()))
                .cloned();
            *count += 1;
            answers
        };
        let sink_port = self.sink_port;
        Box::pin(async move {
            let answers = answers.ok_or_else(|| format!("stub zone has no entry for {host}"))?;
            let addrs: Vec<SocketAddr> = answers
                .into_iter()
                .map(|ip| {
                    let port = if is_globally_routable(ip) {
                        0
                    } else {
                        sink_port
                    };
                    SocketAddr::new(ip, port)
                })
                .collect();
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// Stands in for the internet: sends each public address the guard vetted to
/// the local listener playing that address, and records what it was handed.
#[derive(Debug, Clone)]
pub(crate) struct Network {
    listeners: Arc<HashMap<IpAddr, u16>>,
    vetted: Arc<Mutex<Vec<IpAddr>>>,
}

impl Network {
    pub(crate) fn new(listeners: HashMap<IpAddr, u16>) -> Self {
        Self {
            listeners: Arc::new(listeners),
            vetted: Arc::default(),
        }
    }

    /// Every address the guarded resolver returned, in order.
    pub(crate) fn vetted(&self) -> Vec<IpAddr> {
        self.vetted.lock().expect("vetted lock").clone()
    }

    pub(crate) fn around(self, guarded: Arc<dyn Resolve>) -> Arc<dyn Resolve> {
        Arc::new(Routed {
            guarded,
            network: self,
        })
    }
}

struct Routed {
    guarded: Arc<dyn Resolve>,
    network: Network,
}

impl Resolve for Routed {
    fn resolve(&self, name: Name) -> Resolving {
        let resolving = self.guarded.resolve(name);
        let network = self.network.clone();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = resolving
                .await?
                .map(|addr| {
                    network.vetted.lock().expect("vetted lock").push(addr.ip());
                    match network.listeners.get(&addr.ip()) {
                        Some(port) => SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), *port),
                        None => addr,
                    }
                })
                .collect();
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/*!
 * WebSocket proxy tunneling support via HTTPS_PROXY / ALL_PROXY environment variables.
 *
 * When running in restricted network environments (corporate firewalls, containers),
 * this module enables WebSocket connections through an HTTP CONNECT proxy.
 */

use base64::Engine;

use crate::errors::ATMError;
use std::env;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, client_async_tls_with_config, connect_async,
    tungstenite::{
        client::IntoClientRequest,
        http::{Response, Uri},
    },
};
use tracing::debug;

type WebSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Determines the proxy URL for a given target host by checking environment variables.
///
/// Checks in order: `HTTPS_PROXY` / `https_proxy` → `ALL_PROXY` / `all_proxy`.
/// Returns `None` if the target host matches a `NO_PROXY` / `no_proxy` exclusion pattern.
fn get_proxy_url(target_host: &str) -> Option<String> {
    if is_no_proxy(target_host) {
        return None;
    }

    env_var_nonempty("HTTPS_PROXY")
        .or_else(|| env_var_nonempty("https_proxy"))
        .or_else(|| env_var_nonempty("ALL_PROXY"))
        .or_else(|| env_var_nonempty("all_proxy"))
}

fn env_var_nonempty(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.is_empty())
}

/// Checks whether the target host should bypass the proxy based on `NO_PROXY` / `no_proxy`.
///
/// Supports:
/// - Exact host match: `example.com`
/// - Domain suffix match: `.example.com` (matches `foo.example.com`)
/// - Wildcard `*` (bypasses all)
fn is_no_proxy(target_host: &str) -> bool {
    let no_proxy = env_var_nonempty("NO_PROXY").or_else(|| env_var_nonempty("no_proxy"));

    let Some(no_proxy) = no_proxy else {
        return false;
    };

    let host_lower = target_host.to_lowercase();

    for entry in no_proxy.split(',') {
        let entry = entry.trim().to_lowercase();
        if entry.is_empty() {
            continue;
        }
        if entry == "*" {
            return true;
        }
        if host_lower == entry {
            return true;
        }
        // ".example.com" matches "foo.example.com"
        if entry.starts_with('.') && host_lower.ends_with(&entry) {
            return true;
        }
        // "example.com" also matches "sub.example.com"
        if host_lower.ends_with(&format!(".{entry}")) {
            return true;
        }
    }

    false
}

/// Establishes a TCP connection through an HTTP CONNECT proxy tunnel.
async fn connect_via_proxy(
    proxy_url: &str,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, ATMError> {
    let proxy_uri: Uri = proxy_url
        .parse()
        .map_err(|e| ATMError::TransportError(format!("Invalid proxy URL '{proxy_url}': {e}")))?;

    let proxy_host = proxy_uri.host().ok_or_else(|| {
        ATMError::TransportError(format!("Proxy URL '{proxy_url}' has no host"))
    })?;
    let proxy_port = proxy_uri.port_u16().unwrap_or(match proxy_uri.scheme_str() {
        Some("https") => 443,
        _ => 8080,
    });

    debug!(
        "Connecting to proxy {}:{} for tunnel to {}:{}",
        proxy_host, proxy_port, target_host, target_port
    );

    let mut stream =
        TcpStream::connect((proxy_host, proxy_port))
            .await
            .map_err(|e| {
                ATMError::TransportError(format!(
                    "Failed to connect to proxy {proxy_host}:{proxy_port}: {e}"
                ))
            })?;

    // Build CONNECT request
    let target = format!("{target_host}:{target_port}");
    let mut connect_req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");

    // Add proxy authentication if credentials are in the URL
    if let Some(authority) = proxy_uri.authority() {
        let authority_str = authority.as_str();
        if let Some(at_pos) = authority_str.rfind('@') {
            let userinfo = &authority_str[..at_pos];
            let encoded = base64::engine::general_purpose::STANDARD.encode(userinfo);
            connect_req.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
        }
    }

    connect_req.push_str("\r\n");

    stream
        .write_all(connect_req.as_bytes())
        .await
        .map_err(|e| ATMError::TransportError(format!("Failed to send CONNECT to proxy: {e}")))?;

    // Read proxy response — we only need the status line
    let mut buf = vec![0u8; 4096];
    let mut total = 0;

    loop {
        let n = stream.read(&mut buf[total..]).await.map_err(|e| {
            ATMError::TransportError(format!("Failed to read proxy CONNECT response: {e}"))
        })?;

        if n == 0 {
            return Err(ATMError::TransportError(
                "Proxy closed connection before completing CONNECT handshake".into(),
            ));
        }

        total += n;

        // Check if we've received the full header (ends with \r\n\r\n)
        if let Some(header_end) = find_header_end(&buf[..total]) {
            let response = String::from_utf8_lossy(&buf[..header_end]);
            let status_line = response.lines().next().unwrap_or("");

            // Parse status code from "HTTP/1.1 200 ..."
            let status_ok = status_line
                .split_whitespace()
                .nth(1)
                .and_then(|code| code.parse::<u16>().ok())
                .is_some_and(|code| code == 200);

            if !status_ok {
                return Err(ATMError::TransportError(format!(
                    "Proxy CONNECT failed: {status_line}"
                )));
            }

            debug!("Proxy CONNECT tunnel established to {target}");
            return Ok(stream);
        }

        if total >= buf.len() {
            return Err(ATMError::TransportError(
                "Proxy CONNECT response too large".into(),
            ));
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

/// Connects a WebSocket, tunneling through a proxy if `HTTPS_PROXY` / `ALL_PROXY` is set.
///
/// When no proxy is configured, falls back to a direct `connect_async`.
pub(crate) async fn connect_websocket<R>(
    request: R,
    target_host: &str,
    target_port: u16,
) -> Result<(WebSocket, Response<Option<Vec<u8>>>), ATMError>
where
    R: IntoClientRequest + Unpin,
{
    if let Some(proxy_url) = get_proxy_url(target_host) {
        debug!("Using proxy for WebSocket connection to {target_host}:{target_port}");

        let stream = connect_via_proxy(&proxy_url, target_host, target_port).await?;

        // Pass None as connector — tokio-tungstenite will use its default rustls config
        // (from the `rustls-tls-native-roots` feature) to handle TLS for wss:// URIs.
        let (ws, response) = client_async_tls_with_config(request, stream, None, None)
            .await
            .map_err(|e| {
                ATMError::TransportError(format!("WebSocket connection via proxy failed: {e}"))
            })?;

        Ok((ws, response))
    } else {
        let (ws, response) = connect_async(request).await.map_err(|e| {
            ATMError::TransportError(format!("WebSocket connection failed: {e}"))
        })?;

        Ok((ws, response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;

    // Mutex to serialize tests that modify process-global env vars
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    // SAFETY: env::set_var/remove_var are unsafe in Rust 2024 because env vars are
    // process-global shared state. We serialize access via ENV_MUTEX so no concurrent
    // reads can race with our modifications.
    fn clear_proxy_env() {
        for var in [
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
        ] {
            unsafe {
                env::remove_var(var);
            }
        }
    }

    fn set_env(key: &str, val: &str) {
        unsafe {
            env::set_var(key, val);
        }
    }

    #[test]
    fn test_no_proxy_set() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_proxy_env();
        assert_eq!(get_proxy_url("example.com"), None);
    }

    #[test]
    fn test_https_proxy() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_proxy_env();
        set_env("HTTPS_PROXY", "http://proxy:8080");
        assert_eq!(
            get_proxy_url("example.com"),
            Some("http://proxy:8080".into())
        );
        clear_proxy_env();
    }

    #[test]
    fn test_all_proxy_fallback() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_proxy_env();
        set_env("ALL_PROXY", "http://allproxy:3128");
        assert_eq!(
            get_proxy_url("example.com"),
            Some("http://allproxy:3128".into())
        );
        clear_proxy_env();
    }

    #[test]
    fn test_https_proxy_takes_precedence() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_proxy_env();
        set_env("HTTPS_PROXY", "http://preferred:8080");
        set_env("ALL_PROXY", "http://fallback:3128");
        assert_eq!(
            get_proxy_url("example.com"),
            Some("http://preferred:8080".into())
        );
        clear_proxy_env();
    }

    #[test]
    fn test_no_proxy_exact_match() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_proxy_env();
        set_env("HTTPS_PROXY", "http://proxy:8080");
        set_env("NO_PROXY", "example.com,other.com");
        assert_eq!(get_proxy_url("example.com"), None);
        assert_eq!(
            get_proxy_url("notexcluded.com"),
            Some("http://proxy:8080".into())
        );
        clear_proxy_env();
    }

    #[test]
    fn test_no_proxy_domain_suffix() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_proxy_env();
        set_env("HTTPS_PROXY", "http://proxy:8080");
        set_env("NO_PROXY", ".example.com");
        assert_eq!(get_proxy_url("sub.example.com"), None);
        assert_eq!(
            get_proxy_url("example.com"),
            Some("http://proxy:8080".into())
        );
        clear_proxy_env();
    }

    #[test]
    fn test_no_proxy_subdomain_match() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_proxy_env();
        set_env("HTTPS_PROXY", "http://proxy:8080");
        set_env("NO_PROXY", "example.com");
        assert_eq!(get_proxy_url("sub.example.com"), None);
        clear_proxy_env();
    }

    #[test]
    fn test_no_proxy_wildcard() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_proxy_env();
        set_env("HTTPS_PROXY", "http://proxy:8080");
        set_env("NO_PROXY", "*");
        assert_eq!(get_proxy_url("anything.com"), None);
        clear_proxy_env();
    }

    #[test]
    fn test_empty_proxy_ignored() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_proxy_env();
        set_env("HTTPS_PROXY", "");
        assert_eq!(get_proxy_url("example.com"), None);
        clear_proxy_env();
    }

    #[test]
    fn test_find_header_end() {
        // "HTTP/1.1 200 OK\r\n\r\n" = 19 bytes, \r\n\r\n starts at 15 → 15+4=19
        assert_eq!(find_header_end(b"HTTP/1.1 200 OK\r\n\r\n"), Some(19));
        assert_eq!(find_header_end(b"HTTP/1.1 200 OK\r\n"), None);
        // "HTTP/1.1 200 OK\r\nProxy-Agent: test\r\n\r\n" = 38 bytes
        assert_eq!(
            find_header_end(b"HTTP/1.1 200 OK\r\nProxy-Agent: test\r\n\r\n"),
            Some(38)
        );
    }
}

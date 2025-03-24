//! # Client handshake request
//!
//! A client sends a handshake request to the server. It includes the following information:
//!
//! ```yml
//! GET /chat HTTP/1.1
//! Host: example.com:8000
//! Upgrade: websocket
//! Connection: Upgrade
//! Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
//! Sec-WebSocket-Version: 13
//! ```
//!
//! The server must be careful to understand everything the client asks for, otherwise security issues can occur.
//! If any header is not understood or has an incorrect value, the server should send a 400 ("Bad Request")} response and immediately close the socket.
//!
//! ### Tips
//!
//! All browsers send an Origin header.
//! You can use this header for security (checking for same origin, automatically allowing or denying, etc.) and send a 403 Forbidden if you don't like what you see.
//! However, be warned that non-browser agents can send a faked Origin. Most applications reject requests without this header.
//!
//! Any http headers is allowed. (Do whatever you want with them)
//!
//! ### Note
//!
//! -  HTTP version must be `1.1` or greater, and method must be `GET`
//! - `Host` header field containing the server's authority.
//! - `Upgrade` header field containing the value `"websocket"`
//! - `Connection` header field that includes the token `"Upgrade"`
//! - `Sec-WebSocket-Version` header field containing the value `13`
//! - `Sec-WebSocket-Key` header field with a base64-encoded value that, when decoded, is 16 bytes in length.
//! -  Request may include any other header fields, for example, cookies and/or authentication-related header fields.
//! -  Optionally, `Origin` header field.  This header field is sent by all browser clients.

use sha1::{Digest, Sha1};
use std::fmt;

/// WebSocket magic string used during the WebSocket handshake
pub const MAGIC_STRING: &[u8; 36] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Create `Sec-WebSocket-Accept` key from `Sec-WebSocket-Key` http header value.
///
/// ### Example
///
/// ```no_compile
/// use crate::utils::handshake::accept_key_from;
/// assert_eq!(accept_key_from("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
/// ```
#[inline]
pub fn accept_key_from(sec_ws_key: impl AsRef<[u8]>) -> String {
    let mut sha1 = Sha1::new();
    sha1.update(sec_ws_key.as_ref());
    sha1.update(MAGIC_STRING);
    base64_encode(sha1.finalize())
}

/// Create websocket handshake request
///
/// ### Example
///
/// ```no_compile
/// use crate::utils::handshake::request;
/// let _ = request("example.com", "/path", [("key", "value")]);
/// ```
///
/// ### Output
///
/// ```yaml
/// GET /path HTTP/1.1
/// Host: example.com
/// Upgrade: websocket
/// Connection: Upgrade
/// Sec-WebSocket-Version: 13
/// Sec-WebSocket-Key: D3E1sFZlZfeZgNXtVHfhKg== # randomly generated
/// key: value
/// ...
/// ```
pub fn request(
    host: impl AsRef<str>,
    path: impl AsRef<str>,
    headers: impl IntoIterator<Item = impl Header>,
) -> (String, String) {
    let host = host.as_ref();
    let path = path.as_ref().trim_start_matches('/');
    let sec_key = base64_encode(42_u128.to_ne_bytes());
    let headers: String = headers.into_iter().map(|f| Header::fmt(&f)).collect();
    (
        format!(
            "GET /{path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {sec_key}\r\n{headers}\r\n"
        ),
        sec_key,
    )
}

/// Provides a interface for formatting HTTP headers
///
/// # Example
///
/// ```no_compile
///
/// assert_eq!(Header::fmt(&("val", 2)), "val: 2\r\n");
/// assert_eq!(Header::fmt(&["key", "value"]), "key: value\r\n");
/// ```
pub trait Header {
    /// Format a single http header field
    fn fmt(_: &Self) -> String;
}

impl<T: Header> Header for &T {
    fn fmt(this: &Self) -> String {
        T::fmt(this)
    }
}
impl<T: fmt::Display> Header for [T; 2] {
    fn fmt([key, value]: &Self) -> String {
        format!("{key}: {value}\r\n")
    }
}
impl<K: fmt::Display, V: fmt::Display> Header for (K, V) {
    fn fmt((key, value): &Self) -> String {
        format!("{key}: {value}\r\n")
    }
}

fn base64_encode(string: impl AsRef<[u8]>) -> String {
    base64::Engine::encode(&base64::prelude::BASE64_STANDARD, string)
}

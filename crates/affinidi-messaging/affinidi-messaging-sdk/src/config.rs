use crate::errors::ATMError;
use affinidi_messaging_didcomm::{Message as DidcommMessage, UnpackMetadata};
use rustls::pki_types::CertificateDer;
use std::{fs::File, io::BufReader};
use tokio::sync::broadcast::Sender;
use tracing::error;

/// Configuration for the Affinidi Trusted Messaging (ATM) Service
/// You need to use the `builder()` method to create a new instance of `ATMConfig`
/// Example:
/// ```
/// use affinidi_messaging_sdk::config::ATMConfig;
///
/// let config = ATMConfig::builder().build();
/// ```
#[derive(Clone)]
pub struct ATMConfig {
    pub(crate) ssl_certificates: Vec<CertificateDer<'static>>,
    pub(crate) fetch_cache_limit_count: u32,
    pub(crate) fetch_cache_limit_bytes: u64,

    /// If you want to aggregate inbound messages from the SDK to a channel to be used by the client
    pub(crate) inbound_message_channel: Option<Sender<(DidcommMessage, UnpackMetadata)>>,
}

impl ATMConfig {
    /// Returns a builder for `ATMConfig`
    /// Example:
    /// ```
    /// use affinidi_messaging_sdk::config::ATMConfig;
    ///
    /// let config = ATMConfig::builder().build();
    /// ```
    pub fn builder() -> ATMConfigBuilder {
        ATMConfigBuilder::default()
    }

    pub fn get_ssl_certificates(&self) -> &Vec<CertificateDer> {
        &self.ssl_certificates
    }
}

/// Builder for `ATMConfig`.
/// Example:
/// ```
/// use affinidi_messaging_sdk::config::ATMConfig;
///
/// // Create a new `ATMConfig` with defaults
/// let config = ATMConfig::builder().build();
/// ```
pub struct ATMConfigBuilder {
    ssl_certificates: Vec<String>,
    fetch_cache_limit_count: u32,
    fetch_cache_limit_bytes: u64,
    inbound_message_channel: Option<Sender<(DidcommMessage, UnpackMetadata)>>,
}

impl Default for ATMConfigBuilder {
    fn default() -> Self {
        ATMConfigBuilder {
            ssl_certificates: vec![],
            fetch_cache_limit_count: 100,
            fetch_cache_limit_bytes: 1024 * 1024 * 10, // Defaults to 10MB Cache
            inbound_message_channel: None,
        }
    }
}

impl ATMConfigBuilder {
    /// Default starting constructor for `ATMConfigBuilder`
    pub fn new() -> ATMConfigBuilder {
        ATMConfigBuilder::default()
    }

    /// Add a list of SSL certificates to the configuration
    /// Each certificate should be a file path to a PEM encoded certificate
    pub fn with_ssl_certificates(mut self, ssl_certificates: &mut Vec<String>) -> Self {
        self.ssl_certificates.append(ssl_certificates);
        self
    }

    /// Set the maximum number of messages to cache in the fetch task
    /// This is per profile
    /// Default: 100
    pub fn with_fetch_cache_limit_count(mut self, count: u32) -> Self {
        self.fetch_cache_limit_count = count;
        self
    }

    /// Set the maximum total size of messages to cache in the fetch task in bytes
    /// This is per profile
    /// Default: 10MB (1024*1024*10)
    pub fn with_fetch_cache_limit_bytes(mut self, count: u64) -> Self {
        self.fetch_cache_limit_bytes = count;
        self
    }

    /// Set an optional MPSC channel to send inbound messages to
    /// This is useful if you want to aggregate inbound messages from the SDK to a channel to be used by the client
    pub fn with_inbound_message_channel(
        mut self,
        inbound_message_channel: Sender<(DidcommMessage, UnpackMetadata)>,
    ) -> Self {
        self.inbound_message_channel = Some(inbound_message_channel);
        self
    }

    pub fn build(self) -> Result<ATMConfig, ATMError> {
        // Process any custom SSL certificates
        let mut certs = vec![];
        let mut failed_certs = false;
        for cert in &self.ssl_certificates {
            let file = File::open(cert).map_err(|e| {
                ATMError::SSLError(format!(
                    "Couldn't open SSL certificate file ({})! Reason: {}",
                    cert, e
                ))
            })?;
            let mut reader = BufReader::new(file);

            for cert in rustls_pemfile::certs(&mut reader) {
                match cert {
                    Ok(cert) => certs.push(cert.into_owned()),
                    Err(e) => {
                        failed_certs = true;
                        error!("Couldn't parse SSL certificate! Reason: {}", e)
                    }
                }
            }
        }
        if failed_certs {
            return Err(ATMError::SSLError(
                "Couldn't parse all SSL certificates!".to_owned(),
            ));
        }

        Ok(ATMConfig {
            ssl_certificates: certs,
            fetch_cache_limit_count: self.fetch_cache_limit_count,
            fetch_cache_limit_bytes: self.fetch_cache_limit_bytes,
            inbound_message_channel: self.inbound_message_channel,
        })
    }
}

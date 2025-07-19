//! Resolving WebVH DID's logic is handled here

use std::time::Duration;

use crate::{
    DIDWebVHError, DIDWebVHState,
    log_entry::{LogEntry, MetaData},
    log_entry_state::{LogEntryState, LogEntryValidationStatus},
    parameters::Parameters,
    url::{URLType, WebVHURL},
    witness::proofs::WitnessProofCollection,
};
use chrono::{DateTime, Utc};
use reqwest::Client;
use tracing::{Instrument, Level, span, warn};
use url::Url;

/// Integration with the Spruice ID SSI Library
pub mod ssi_resolve;

pub struct DIDWebVH;

impl DIDWebVH {
    // Handles the fetching of the file from a given URL
    async fn download_file(client: Client, url: Url) -> Result<String, DIDWebVHError> {
        client
            .get(url.clone())
            .send()
            .await
            .map_err(|e| DIDWebVHError::NetworkError(format!("url ({url}): {e}")))?
            .text()
            .await
            .map_err(|e| {
                DIDWebVHError::NetworkError(format!("url ({url}): Failed to read response: {e}"))
            })
    }

    /// Handles all processing and fetching for LogEntry file
    async fn get_log_entries(
        url: WebVHURL,
        client: Client,
    ) -> Result<Vec<LogEntryState>, DIDWebVHError> {
        let log_entries_url = match url.get_http_url(Some("did.jsonl")) {
            Ok(url) => url,
            Err(e) => {
                warn!("Invalid URL for DID: {e}");
                return Err(DIDWebVHError::InvalidMethodIdentifier(format!(
                    "Couldn't generate a valid URL from the DID: {e}"
                )));
            }
        };

        let log_entries_text = Self::download_file(client, log_entries_url).await?;

        let mut log_entries = Vec::new();
        for line in log_entries_text.lines() {
            let log_entry: LogEntry = serde_json::from_str(line).map_err(|e| {
                DIDWebVHError::LogEntryError(format!(
                    "Failed to parse log entry from line: {line}. Error: {e}"
                ))
            })?;

            log_entries.push(LogEntryState {
                log_entry: log_entry.clone(),
                metadata: MetaData::default(),
                version_number: log_entry.get_version_id_fields()?.0,
                validation_status: LogEntryValidationStatus::NotValidated,
                validated_parameters: Parameters::default(),
            });
        }

        Ok(log_entries)
    }

    /// Handles all processing and fetching for witness proofs
    async fn get_witness_proofs(
        url: WebVHURL,
        client: Client,
    ) -> Result<WitnessProofCollection, DIDWebVHError> {
        let witness_url = match url.get_http_url(Some("did-witness.json")) {
            Ok(url) => url,
            Err(e) => {
                warn!("Invalid URL for DID: {e}");
                return Err(DIDWebVHError::InvalidMethodIdentifier(format!(
                    "Couldn't generate a valid URL from the DID: {e}"
                )));
            }
        };

        let proofs_raw = Self::download_file(client, witness_url).await?;

        Ok(WitnessProofCollection {
            proofs: serde_json::from_str(&proofs_raw).map_err(|e| {
                DIDWebVHError::WitnessProofError(format!(
                    "Couldn't deserialize Witness Proofs Data: {e}",
                ))
            })?,
            ..Default::default()
        })
    }
}

impl DIDWebVHState {
    /// Resolves a webvh DID
    ///
    /// Inputs:
    /// did: DID to resolve
    /// timeout: how many seconds (Default: 10) before timing out on network operations
    pub async fn resolve(
        &mut self,
        did: &str,
        timeout: Option<Duration>,
    ) -> Result<&LogEntryState, DIDWebVHError> {
        let _span = span!(Level::DEBUG, "resolve", DID = did);
        async move {
            let parsed_did_url = WebVHURL::parse_did_url(did)?;

            if parsed_did_url.type_ == URLType::WhoIs {
                // TODO: whois is not implemented yet
                return Err(DIDWebVHError::NotImplemented(
                    "/whois isn't implemented yet".to_string(),
                ));
            }

            if !self.validated || self.expires < Utc::now() {
                // Set network timeout values. Will default to 10 seconds for any reasons
                let network_timeout = if let Some(timeout) = timeout {
                    timeout
                } else {
                    Duration::from_secs(10)
                };

                // Async download did.jsonl and did-witness.json
                let client = reqwest::Client::new();
                let r1 = tokio::time::timeout(
                    network_timeout,
                    tokio::spawn(DIDWebVH::get_log_entries(
                        parsed_did_url.clone(),
                        client.clone(),
                    )),
                );

                let r2 = tokio::time::timeout(
                    network_timeout,
                    tokio::spawn(DIDWebVH::get_witness_proofs(
                        parsed_did_url.clone(),
                        client.clone(),
                    )),
                );

                let (r1, r2) = (r1.await, r2.await);

                // LogEntry
                let log_entries = if let Ok(log_entries) = r1 {
                    match log_entries {
                        Ok(entries) => match entries {
                            Ok(entries) => entries,
                            Err(e) => {
                                warn!("Error downloading LogEntries: {e}");
                                return Err(e);
                            }
                        },
                        Err(e) => {
                            warn!("tokio join error: {e}");
                            return Err(DIDWebVHError::NetworkError(format!(
                                "Error downloading LogEntries for DID: {e}"
                            )));
                        }
                    }
                } else {
                    warn!("timeout error on LogEntry download");
                    return Err(DIDWebVHError::NetworkError(
                        "Network timeout on downloaded LogEntries for DID".to_string(),
                    ));
                };

                // If there is any error with witness proofs then set witness proofs to an empty proof
                // WitnessProofCollection
                // If a webvh DID is NOT using witnesses then it will still successfully validate
                let witness_proofs = if let Ok(proofs) = r2 {
                    match proofs {
                        Ok(proofs) => match proofs {
                            Ok(proofs) => proofs,
                            Err(e) => {
                                warn!("Error downloading witness proofs: {e}");
                                WitnessProofCollection::default()
                            }
                        },
                        Err(e) => {
                            warn!("tokio join error: {e}");
                            WitnessProofCollection::default()
                        }
                    }
                } else {
                    warn!("Downloading witness proofs timedout. Defaulting to no witness proofs");
                    WitnessProofCollection::default()
                };

                // Have LogEntries and Witness Proofs, now can validate the DID
                self.log_entries = log_entries;
                self.witness_proofs = witness_proofs;
                self.validated = false;
                self.expires = DateTime::default();

                self.validate()?;
            }

            // DID is fully validated
            if parsed_did_url.query_version_id.is_some()
                || parsed_did_url.query_version_time.is_some()
            {
                self.get_specific_log_entry(
                    parsed_did_url.query_version_id.as_deref(),
                    parsed_did_url.query_version_time,
                )
                .map_err(|_| DIDWebVHError::NotFound)
            } else {
                self.log_entries.last().ok_or(DIDWebVHError::NotFound)
            }
        }
        .instrument(_span)
        .await
    }
}

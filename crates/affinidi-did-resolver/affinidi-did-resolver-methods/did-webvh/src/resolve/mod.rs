//! Resolving WebVH DID's logic is handled here

use crate::{
    DIDWebVHError,
    log_entry::{LogEntry, MetaData},
    log_entry_state::{LogEntryState, LogEntryValidationStatus},
    parameters::Parameters,
    url::WebVHURL,
    witness::proofs::WitnessProofCollection,
};
use reqwest::Client;
use tracing::warn;
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

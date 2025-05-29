/*!
*  Reads a JSON Log file, all functions related to reading and verifying Log Entries are here
*/

use super::LogEntry;
use crate::{DIDWebVHError, parameters::Parameters};
use std::{
    fs::File,
    io::{self, BufRead},
    path::Path,
};

impl LogEntry {
    /// Reads a JSON Log file and returns an iterator over the lines in the file.
    fn read_from_json_file<P>(file_path: P) -> io::Result<io::Lines<io::BufReader<File>>>
    where
        P: AsRef<Path>,
    {
        let file = File::open(file_path)?;
        Ok(io::BufReader::new(file).lines())
    }

    /// Get either latest LogEntry or the specific version if specified.
    pub fn get_log_entry_from_file<P>(
        file_path: P,
        version: Option<u32>,
    ) -> Result<LogEntry, DIDWebVHError>
    where
        P: AsRef<Path>,
    {
        if let Ok(lines) = LogEntry::read_from_json_file(file_path) {
            for line in lines.map_while(Result::ok) {
                let log_entry = serde_json::to_value(&line).map_err(|e| {
                    DIDWebVHError::LogEntryError(format!("Failed to deserialize log entry: {}", e))
                })?;
            }
        }

        Err(DIDWebVHError::LogEntryError(
            "Failed to read log entry from file".to_string(),
        ))
    }

    pub fn verify_log_entry(
        &self,
        parameters: Option<&Parameters>,
    ) -> Result<Parameters, DIDWebVHError> {
        //

        Ok(Parameters::default())
    }
}

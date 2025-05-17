use serde::Serialize;
use serde_json_canonicalizer::to_string;

/// Creates a signature for the given data using the specified key.
pub fn sign_data<D>(data_doc: &D) -> String
where
    D: Serialize,
{
    to_string(data_doc).unwrap()
}

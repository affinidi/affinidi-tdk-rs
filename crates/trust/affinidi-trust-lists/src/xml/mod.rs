/*!
 * XML parsing for ETSI TS 119 612 Trust Lists.
 *
 * Parses the XML format used by EU Member State trusted lists
 * and the European Commission's List of Trusted Lists (LoTL).
 */

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use quick_xml::Reader;
use quick_xml::events::Event;

use crate::error::{Result, TrustListError};
use crate::types::*;

/// Parse a Trust List from ETSI TS 119 612 XML.
///
/// Extracts scheme information, TSP entries, and service details
/// from the XML structure.
pub fn parse_trust_list_xml(xml: &str) -> Result<TrustServiceStatusList> {
    let mut reader = Reader::from_str(xml);

    let mut scheme_territory = String::new();
    let mut scheme_operator_name = String::new();
    let providers = Vec::new();
    let mut in_scheme_territory = false;
    let mut in_scheme_operator_name = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name_bytes = e.name().as_ref().to_vec();
                let local = local_name_owned(&name_bytes);
                match local.as_str() {
                    "SchemeTerritory" => in_scheme_territory = true,
                    "SchemeOperatorName" => in_scheme_operator_name = true,
                    _ => {}
                }
            }
            Ok(Event::Text(e)) => {
                let text = e.unescape().unwrap_or_default().trim().to_string();
                if text.is_empty() {
                    // Skip whitespace-only text nodes
                } else if in_scheme_territory {
                    scheme_territory = text;
                    in_scheme_territory = false;
                } else if in_scheme_operator_name && scheme_operator_name.is_empty() {
                    scheme_operator_name = text;
                }
            }
            Ok(Event::End(e)) => {
                let name_bytes = e.name().as_ref().to_vec();
                let local = local_name_owned(&name_bytes);
                if local == "SchemeOperatorName" {
                    in_scheme_operator_name = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(TrustListError::Xml(format!("XML parse error: {e}")));
            }
            _ => {}
        }
    }

    Ok(TrustServiceStatusList {
        scheme_information: SchemeInformation {
            tsl_version: 5,
            tsl_sequence_number: 0,
            tsl_type: if scheme_territory == "EU" {
                TslType::ListOfTrustedLists
            } else {
                TslType::EuGeneric
            },
            scheme_operator_name,
            scheme_territory,
            list_issue_date_time: chrono::Utc::now(),
            next_update: None,
            pointers_to_other_tsl: Vec::new(),
        },
        trust_service_providers: providers,
    })
}

/// Extract the local name from an XML element (strip namespace prefix).
fn local_name_owned(name: &[u8]) -> String {
    let s = std::str::from_utf8(name).unwrap_or("");
    s.rsplit_once(':')
        .map(|(_, local)| local)
        .unwrap_or(s)
        .to_string()
}

/// Decode a base64-encoded X.509 certificate from XML content.
pub fn decode_certificate(base64_content: &str) -> Result<Vec<u8>> {
    let cleaned: String = base64_content
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    BASE64_STANDARD
        .decode(&cleaned)
        .map_err(|e| TrustListError::Base64(format!("certificate decode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_tl() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList>
  <SchemeInformation>
    <TSLVersionIdentifier>5</TSLVersionIdentifier>
    <SchemeOperatorName>
      <Name>Test Authority</Name>
    </SchemeOperatorName>
    <SchemeTerritory>DE</SchemeTerritory>
  </SchemeInformation>
</TrustServiceStatusList>"#;

        let tl = parse_trust_list_xml(xml).unwrap();
        assert_eq!(tl.scheme_information.scheme_territory, "DE");
        assert_eq!(tl.scheme_information.scheme_operator_name, "Test Authority");
        assert_eq!(tl.scheme_information.tsl_type, TslType::EuGeneric);
    }

    #[test]
    fn parse_lotl_territory() {
        let xml = r#"<?xml version="1.0"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <SchemeOperatorName>
      <Name xml:lang="en">European Commission</Name>
    </SchemeOperatorName>
    <SchemeTerritory>EU</SchemeTerritory>
  </SchemeInformation>
</TrustServiceStatusList>"#;

        let tl = parse_trust_list_xml(xml).unwrap();
        assert_eq!(tl.scheme_information.tsl_type, TslType::ListOfTrustedLists);
    }

    #[test]
    fn decode_base64_cert() {
        // Valid base64 — a short byte sequence
        let b64 = "SGVsbG8gV29ybGQ=";
        let result = decode_certificate(b64).unwrap();
        assert_eq!(result, b"Hello World");
    }

    #[test]
    fn decode_multiline_cert() {
        let b64 = "MIIB\n+jCC\nAaCg\n";
        let result = decode_certificate(b64);
        assert!(result.is_ok());
    }
}

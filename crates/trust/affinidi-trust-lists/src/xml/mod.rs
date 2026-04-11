/*!
 * XML parsing for ETSI TS 119 612 Trust Lists.
 *
 * Parses the XML format used by EU Member State trusted lists
 * and the European Commission's List of Trusted Lists (LoTL).
 *
 * # ETSI TS 119 612 XML Structure
 *
 * ```text
 * TrustServiceStatusList
 * ├── SchemeInformation
 * │   ├── TSLVersionIdentifier
 * │   ├── TSLSequenceNumber
 * │   ├── TSLType
 * │   ├── SchemeOperatorName / Name
 * │   ├── SchemeTerritory
 * │   ├── ListIssueDateTime
 * │   └── PointersToOtherTSL / OtherTSLPointer
 * │       ├── TSLLocation
 * │       ├── SchemeTerritory
 * │       └── ServiceDigitalIdentity / X509Certificate
 * └── TrustServiceProviderList
 *     └── TrustServiceProvider
 *         ├── TSPName / Name
 *         ├── TSPTradeName / Name
 *         └── TSPServices / TSPService
 *             └── ServiceInformation
 *                 ├── ServiceTypeIdentifier
 *                 ├── ServiceName / Name
 *                 ├── ServiceDigitalIdentity / X509Certificate
 *                 ├── ServiceStatus
 *                 └── StatusStartingTime
 * ```
 */

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use quick_xml::Reader;
use quick_xml::events::Event;

use crate::error::{Result, TrustListError};
use crate::service_status::ServiceStatus;
use crate::service_type::ServiceType;
use crate::types::*;

/// Parse a Trust List from ETSI TS 119 612 XML.
///
/// Extracts scheme information, TSP entries, services, and digital identities
/// from the XML structure.
pub fn parse_trust_list_xml(xml: &str) -> Result<TrustServiceStatusList> {
    let mut reader = Reader::from_str(xml);

    let mut scheme_territory = String::new();
    let mut scheme_operator_name = String::new();
    let mut tsl_type_uri = String::new();
    let mut tsl_version = 5u32;
    let mut tsl_sequence_number = 0u32;
    let mut providers: Vec<TrustServiceProvider> = Vec::new();
    let mut pointers: Vec<OtherTslPointer> = Vec::new();

    // Parser state — track depth with a stack of element names
    let mut path: Vec<String> = Vec::new();

    // Current parsing context
    let mut current_tsp_name = String::new();
    let mut current_tsp_trade_name: Option<String> = None;
    let mut current_tsp_uris: Vec<String> = Vec::new();
    let mut current_services: Vec<ServiceInformation> = Vec::new();

    // Service parsing context
    let mut current_service_type = String::new();
    let mut current_service_name = String::new();
    let mut current_service_cert: Option<Vec<u8>> = None;
    let mut current_service_status = String::new();
    let mut current_status_time = String::new();

    // LoTL pointer context
    let mut current_pointer_location = String::new();
    let mut current_pointer_territory = String::new();
    let mut current_pointer_certs: Vec<Vec<u8>> = Vec::new();
    let mut current_pointer_operator: Option<String> = None;

    // Certificate accumulation (multiline base64)
    let mut in_x509_cert = false;
    let mut cert_base64 = String::new();

    let mut text_buf = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name_bytes = e.name().as_ref().to_vec();
                let local = local_name_owned(&name_bytes);
                path.push(local.clone());
                text_buf.clear();

                if local == "X509Certificate" {
                    in_x509_cert = true;
                    cert_base64.clear();
                }
            }
            Ok(Event::Text(e)) => {
                let text = e.unescape().unwrap_or_default().to_string();
                if in_x509_cert {
                    cert_base64.push_str(text.trim());
                } else {
                    let trimmed = text.trim();
                    if !trimmed.is_empty() {
                        text_buf = trimmed.to_string();
                    }
                }
            }
            Ok(Event::End(e)) => {
                let name_bytes = e.name().as_ref().to_vec();
                let local = local_name_owned(&name_bytes);

                // Build path string for context matching
                let path_str = path.join("/");

                match local.as_str() {
                    "TSLVersionIdentifier" => {
                        if let Ok(v) = text_buf.parse::<u32>() {
                            tsl_version = v;
                        }
                    }
                    "TSLSequenceNumber" => {
                        if let Ok(v) = text_buf.parse::<u32>() {
                            tsl_sequence_number = v;
                        }
                    }
                    "TSLType" => {
                        tsl_type_uri = text_buf.clone();
                    }
                    "SchemeTerritory" => {
                        if path_str.contains("OtherTSLPointer") {
                            current_pointer_territory = text_buf.clone();
                        } else if scheme_territory.is_empty() {
                            scheme_territory = text_buf.clone();
                        }
                    }
                    "Name" => {
                        if path_str.contains("SchemeOperatorName")
                            && !path_str.contains("TrustServiceProvider")
                            && !path_str.contains("OtherTSLPointer")
                        {
                            if scheme_operator_name.is_empty() {
                                scheme_operator_name = text_buf.clone();
                            }
                        } else if path_str.contains("OtherTSLPointer")
                            && path_str.contains("SchemeOperatorName")
                        {
                            current_pointer_operator = Some(text_buf.clone());
                        } else if path_str.contains("TSPName") {
                            if current_tsp_name.is_empty() {
                                current_tsp_name = text_buf.clone();
                            }
                        } else if path_str.contains("TSPTradeName") {
                            current_tsp_trade_name = Some(text_buf.clone());
                        } else if path_str.contains("ServiceName")
                            && current_service_name.is_empty()
                        {
                            current_service_name = text_buf.clone();
                        }
                    }
                    "ServiceTypeIdentifier" => {
                        current_service_type = text_buf.clone();
                    }
                    "ServiceStatus" => {
                        current_service_status = text_buf.clone();
                    }
                    "StatusStartingTime" => {
                        current_status_time = text_buf.clone();
                    }
                    "TSLLocation" => {
                        current_pointer_location = text_buf.clone();
                    }
                    "URI" => {
                        if path_str.contains("TSPInformationURI") {
                            current_tsp_uris.push(text_buf.clone());
                        }
                    }
                    "X509Certificate" => {
                        in_x509_cert = false;
                        if let Ok(der) = decode_certificate(&cert_base64) {
                            if path_str.contains("OtherTSLPointer") {
                                current_pointer_certs.push(der);
                            } else {
                                current_service_cert = Some(der);
                            }
                        }
                    }
                    "OtherTSLPointer" => {
                        if !current_pointer_location.is_empty() {
                            pointers.push(OtherTslPointer {
                                tsl_location: current_pointer_location.clone(),
                                scheme_territory: current_pointer_territory.clone(),
                                signing_certificates: current_pointer_certs.clone(),
                                scheme_operator_name: current_pointer_operator.take(),
                            });
                        }
                        current_pointer_location.clear();
                        current_pointer_territory.clear();
                        current_pointer_certs.clear();
                    }
                    "ServiceInformation" => {
                        // Finalize current service
                        let status_time =
                            chrono::DateTime::parse_from_rfc3339(&current_status_time)
                                .map(|dt| dt.with_timezone(&chrono::Utc))
                                .unwrap_or_else(|_| chrono::Utc::now());

                        let identity = match current_service_cert.take() {
                            Some(cert) => ServiceDigitalIdentity::X509Certificate(cert),
                            None => ServiceDigitalIdentity::PublicKey(vec![]),
                        };

                        current_services.push(ServiceInformation {
                            service_type: ServiceType::from_uri(&current_service_type),
                            service_name: current_service_name.clone(),
                            digital_identity: identity,
                            service_status: ServiceStatus::from_uri(&current_service_status),
                            status_starting_time: status_time,
                            history: Vec::new(),
                        });

                        current_service_type.clear();
                        current_service_name.clear();
                        current_service_status.clear();
                        current_status_time.clear();
                    }
                    "TrustServiceProvider" => {
                        // Finalize current TSP
                        if !current_tsp_name.is_empty() {
                            providers.push(TrustServiceProvider {
                                name: current_tsp_name.clone(),
                                trade_name: current_tsp_trade_name.take(),
                                territory: scheme_territory.clone(),
                                information_uris: current_tsp_uris.clone(),
                                services: current_services.clone(),
                            });
                        }
                        current_tsp_name.clear();
                        current_tsp_uris.clear();
                        current_services.clear();
                    }
                    _ => {}
                }

                path.pop();
                text_buf.clear();
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(TrustListError::Xml(format!("XML parse error: {e}")));
            }
            _ => {}
        }
    }

    let tsl_type = if !tsl_type_uri.is_empty() {
        TslType::from_uri(&tsl_type_uri)
    } else if scheme_territory == "EU" {
        TslType::ListOfTrustedLists
    } else {
        TslType::EuGeneric
    };

    Ok(TrustServiceStatusList {
        scheme_information: SchemeInformation {
            tsl_version,
            tsl_sequence_number,
            tsl_type,
            scheme_operator_name,
            scheme_territory,
            list_issue_date_time: chrono::Utc::now(),
            next_update: None,
            pointers_to_other_tsl: pointers,
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

    #[test]
    fn parse_tl_with_tsp_and_services() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<tsl:TrustServiceStatusList xmlns:tsl="http://uri.etsi.org/02231/v2#">
  <tsl:SchemeInformation>
    <tsl:TSLVersionIdentifier>5</tsl:TSLVersionIdentifier>
    <tsl:TSLSequenceNumber>42</tsl:TSLSequenceNumber>
    <tsl:SchemeOperatorName>
      <tsl:Name xml:lang="en">Bundesnetzagentur</tsl:Name>
    </tsl:SchemeOperatorName>
    <tsl:SchemeTerritory>DE</tsl:SchemeTerritory>
  </tsl:SchemeInformation>
  <tsl:TrustServiceProviderList>
    <tsl:TrustServiceProvider>
      <tsl:TSPInformation>
        <tsl:TSPName>
          <tsl:Name xml:lang="en">Bundesdruckerei GmbH</tsl:Name>
        </tsl:TSPName>
      </tsl:TSPInformation>
      <tsl:TSPServices>
        <tsl:TSPService>
          <tsl:ServiceInformation>
            <tsl:ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/IdV/nothQC</tsl:ServiceTypeIdentifier>
            <tsl:ServiceName>
              <tsl:Name xml:lang="en">PID Issuance Service</tsl:Name>
            </tsl:ServiceName>
            <tsl:ServiceDigitalIdentity>
              <tsl:DigitalId>
                <tsl:X509Certificate>SGVsbG8=</tsl:X509Certificate>
              </tsl:DigitalId>
            </tsl:ServiceDigitalIdentity>
            <tsl:ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</tsl:ServiceStatus>
            <tsl:StatusStartingTime>2024-01-15T00:00:00Z</tsl:StatusStartingTime>
          </tsl:ServiceInformation>
        </tsl:TSPService>
      </tsl:TSPServices>
    </tsl:TrustServiceProvider>
  </tsl:TrustServiceProviderList>
</tsl:TrustServiceStatusList>"#;

        let tl = parse_trust_list_xml(xml).unwrap();
        assert_eq!(tl.scheme_information.scheme_territory, "DE");
        assert_eq!(tl.scheme_information.tsl_version, 5);
        assert_eq!(tl.scheme_information.tsl_sequence_number, 42);

        // TSP parsed
        assert_eq!(tl.trust_service_providers.len(), 1);
        let tsp = &tl.trust_service_providers[0];
        assert_eq!(tsp.name, "Bundesdruckerei GmbH");
        assert_eq!(tsp.territory, "DE");

        // Service parsed
        assert_eq!(tsp.services.len(), 1);
        let svc = &tsp.services[0];
        assert_eq!(svc.service_name, "PID Issuance Service");
        assert!(svc.service_status.is_active());

        // Certificate parsed
        match &svc.digital_identity {
            ServiceDigitalIdentity::X509Certificate(cert) => {
                assert_eq!(cert, b"Hello");
            }
            _ => panic!("expected X509Certificate"),
        }
    }

    #[test]
    fn parse_multiple_tsps() {
        let xml = r#"<?xml version="1.0"?>
<TrustServiceStatusList>
  <SchemeInformation>
    <SchemeOperatorName><Name>Authority</Name></SchemeOperatorName>
    <SchemeTerritory>AT</SchemeTerritory>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPInformation>
        <TSPName><Name>Provider A</Name></TSPName>
      </TSPInformation>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/IdV/nothQC</ServiceTypeIdentifier>
            <ServiceName><Name>Service 1</Name></ServiceName>
            <ServiceDigitalIdentity>
              <DigitalId><X509Certificate>AQID</X509Certificate></DigitalId>
            </ServiceDigitalIdentity>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
            <StatusStartingTime>2024-01-01T00:00:00Z</StatusStartingTime>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
    <TrustServiceProvider>
      <TSPInformation>
        <TSPName><Name>Provider B</Name></TSPName>
      </TSPInformation>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceName><Name>Service 2</Name></ServiceName>
            <ServiceDigitalIdentity>
              <DigitalId><X509Certificate>BAUG</X509Certificate></DigitalId>
            </ServiceDigitalIdentity>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</ServiceStatus>
            <StatusStartingTime>2023-06-15T00:00:00Z</StatusStartingTime>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>"#;

        let tl = parse_trust_list_xml(xml).unwrap();
        assert_eq!(tl.trust_service_providers.len(), 2);

        let a = &tl.trust_service_providers[0];
        assert_eq!(a.name, "Provider A");
        assert_eq!(a.services.len(), 1);
        assert!(a.services[0].service_status.is_active());

        let b = &tl.trust_service_providers[1];
        assert_eq!(b.name, "Provider B");
        assert_eq!(b.services[0].service_type, ServiceType::CaQc);
        assert!(b.services[0].service_status.is_terminated());
    }

    #[test]
    fn parse_and_load_into_registry() {
        let xml = r#"<?xml version="1.0"?>
<TrustServiceStatusList>
  <SchemeInformation>
    <SchemeOperatorName><Name>Test</Name></SchemeOperatorName>
    <SchemeTerritory>FR</SchemeTerritory>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPInformation>
        <TSPName><Name>French PID Provider</Name></TSPName>
      </TSPInformation>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/IdV/nothQC</ServiceTypeIdentifier>
            <ServiceName><Name>PID Service</Name></ServiceName>
            <ServiceDigitalIdentity>
              <DigitalId><X509Certificate>dGVzdC1jZXJ0</X509Certificate></DigitalId>
            </ServiceDigitalIdentity>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
            <StatusStartingTime>2024-01-01T00:00:00Z</StatusStartingTime>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>"#;

        let tl = parse_trust_list_xml(xml).unwrap();

        let mut registry = crate::TrustListRegistry::new();
        registry.load_trust_list(&tl);

        assert_eq!(registry.entry_count(), 1);
        // Lookup by the decoded cert bytes
        let result = registry.lookup_by_certificate(b"test-cert");
        assert!(result.is_trusted());
    }
}

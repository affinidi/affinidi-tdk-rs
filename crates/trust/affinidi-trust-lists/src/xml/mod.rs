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
use chrono::{DateTime, Utc};
use quick_xml::Reader;
use quick_xml::events::Event;

use crate::error::{Result, TrustListError};
use crate::service_status::ServiceStatus;
use crate::service_type::ServiceType;
use crate::types::*;

/// A trust list parsed from XML whose signature has not been verified.
///
/// ETSI TS 119 612 lists carry an enveloped XAdES signature by the scheme
/// operator. This crate does not verify it: that needs XML canonicalisation
/// and XMLDSig processing, which it does not implement. Whoever can alter the
/// bytes of an unauthenticated list decides its trust anchors, so the parsed
/// list is held in this wrapper and only reaches a
/// [`TrustListRegistry`](crate::TrustListRegistry) through
/// [`assume_authenticated`](Self::assume_authenticated), a step the caller
/// takes after authenticating the bytes by other means (verifying the XAdES
/// signature against the signing certificates the LoTL publishes for the
/// territory, or obtaining the list from a source the caller already trusts).
#[derive(Debug, Clone)]
pub struct UnverifiedTrustList {
    list: TrustServiceStatusList,
    signature_present: bool,
}

impl UnverifiedTrustList {
    /// The parsed content, for inspection. Nothing in it is authenticated.
    pub fn list(&self) -> &TrustServiceStatusList {
        &self.list
    }

    /// Whether the document has a top-level `Signature` element. Its presence
    /// says nothing about its validity: it has not been verified.
    pub fn has_signature_element(&self) -> bool {
        self.signature_present
    }

    /// Release the list for loading into a registry. Call this only after the
    /// caller has authenticated the XML this was parsed from; this crate has
    /// not verified its signature.
    pub fn assume_authenticated(self) -> TrustServiceStatusList {
        self.list
    }
}

#[derive(Default)]
struct ServiceState {
    service_type: String,
    name: String,
    identities: Vec<ServiceDigitalIdentity>,
    status: String,
    status_time: String,
}

#[derive(Default)]
struct HistoryState {
    service_type: String,
    status: String,
    status_time: String,
}

#[derive(Default)]
struct PointerState {
    location: String,
    territory: String,
    certificates: Vec<Vec<u8>>,
    operator: Option<String>,
}

/// Parse a Trust List from ETSI TS 119 612 XML.
///
/// Extracts scheme information (including `ListIssueDateTime` and
/// `NextUpdate`), TSP entries, services with all their digital identities,
/// service history, and LoTL pointers. The `Signature` element is detected but
/// not verified; see [`UnverifiedTrustList`].
///
/// Returns an error rather than substituting a value when `ListIssueDateTime`
/// is missing, or a date, certificate or SKI cannot be decoded.
pub fn parse_trust_list_xml(xml: &str) -> Result<UnverifiedTrustList> {
    let mut reader = Reader::from_str(xml);

    let mut scheme_territory = String::new();
    let mut scheme_operator_name = String::new();
    let mut tsl_type_uri = String::new();
    let mut tsl_version = 5u32;
    let mut tsl_sequence_number = 0u32;
    let mut list_issue_date_time: Option<DateTime<Utc>> = None;
    let mut next_update: Option<DateTime<Utc>> = None;
    let mut signature_present = false;
    let mut providers: Vec<TrustServiceProvider> = Vec::new();
    let mut pointers: Vec<OtherTslPointer> = Vec::new();

    let mut path: Vec<String> = Vec::new();

    let mut current_tsp_name = String::new();
    let mut current_tsp_trade_name: Option<String> = None;
    let mut current_tsp_uris: Vec<String> = Vec::new();
    let mut current_services: Vec<ServiceInformation> = Vec::new();

    let mut service = ServiceState::default();
    let mut history = HistoryState::default();
    let mut pointer = PointerState::default();

    let mut text_buf = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let qname = e.name();
                let local = local_name_owned(qname.as_ref());
                if path.len() == 1 && local == "Signature" {
                    signature_present = true;
                }
                path.push(local);
                text_buf.clear();
            }
            Ok(Event::Text(e)) => {
                // quick-xml emits raw text between entity references; the
                // references themselves arrive as separate `GeneralRef` events
                // (see below), so accumulate rather than replace. Since 0.42 the
                // content is already `&str` — `decode()` is gone.
                let text: &str = &e;
                text_buf.push_str(text);
            }
            Ok(Event::GeneralRef(e)) => {
                // An entity reference inside element text (e.g. `&amp;` in an org
                // name or URI). quick-xml surfaces these as their own event since
                // 0.41; resolve predefined/numeric references and append so the
                // value is reassembled exactly as 0.37's inline `unescape()`
                // produced it. `BytesRef` derefs to `str` since 0.42.
                let name: &str = &e;
                let resolved = quick_xml::escape::unescape(&format!("&{name};"))
                    .map(|c| c.into_owned())
                    .unwrap_or_else(|_| name.to_string());
                text_buf.push_str(&resolved);
            }
            Ok(Event::End(e)) => {
                let qname = e.name();
                let local = local_name_owned(qname.as_ref());
                let text = text_buf.trim().to_string();
                let within = |name: &str| path.iter().any(|element| element == name);

                if within("Signature") {
                    // The enveloped signature's KeyInfo carries certificates of
                    // its own; none of them identify a service.
                } else if within("OtherTSLPointer") {
                    match local.as_str() {
                        "TSLLocation" => pointer.location = text,
                        "SchemeTerritory" => pointer.territory = text,
                        "Name" if within("SchemeOperatorName") => {
                            pointer.operator.get_or_insert(text);
                        }
                        "X509Certificate" => {
                            pointer.certificates.push(decode_certificate(&text)?);
                        }
                        "OtherTSLPointer" => {
                            let finished = std::mem::take(&mut pointer);
                            if !finished.location.is_empty() {
                                pointers.push(OtherTslPointer {
                                    tsl_location: finished.location,
                                    scheme_territory: finished.territory,
                                    signing_certificates: finished.certificates,
                                    scheme_operator_name: finished.operator,
                                });
                            }
                        }
                        _ => {}
                    }
                } else if within("ServiceHistory") {
                    match local.as_str() {
                        "ServiceTypeIdentifier" => history.service_type = text,
                        "ServiceStatus" => history.status = text,
                        "StatusStartingTime" => history.status_time = text,
                        "ServiceHistoryInstance" => {
                            let finished = std::mem::take(&mut history);
                            let entry = ServiceHistoryEntry {
                                service_type: ServiceType::from_uri(&finished.service_type),
                                service_status: ServiceStatus::from_uri(&finished.status),
                                status_starting_time: parse_date_time(
                                    "StatusStartingTime",
                                    &finished.status_time,
                                )?,
                            };
                            current_services
                                .last_mut()
                                .ok_or_else(|| {
                                    TrustListError::Parse(
                                        "ServiceHistory without a preceding ServiceInformation"
                                            .into(),
                                    )
                                })?
                                .history
                                .push(entry);
                        }
                        _ => {}
                    }
                } else if within("ServiceInformation") {
                    let in_identity = within("ServiceDigitalIdentity");
                    match local.as_str() {
                        "ServiceTypeIdentifier" => service.service_type = text,
                        "Name" if within("ServiceName") && service.name.is_empty() => {
                            service.name = text;
                        }
                        "ServiceStatus" => service.status = text,
                        "StatusStartingTime" => service.status_time = text,
                        "X509Certificate" if in_identity => {
                            service
                                .identities
                                .push(ServiceDigitalIdentity::X509Certificate(decode_certificate(
                                    &text,
                                )?));
                        }
                        "X509SKI" if in_identity => {
                            service.identities.push(ServiceDigitalIdentity::X509Ski(
                                decode_base64("X509SKI", &text)?,
                            ));
                        }
                        "X509SubjectName" if in_identity => {
                            service
                                .identities
                                .push(ServiceDigitalIdentity::X509SubjectName(text));
                        }
                        "ServiceInformation" => {
                            let finished = std::mem::take(&mut service);
                            current_services.push(ServiceInformation {
                                service_type: ServiceType::from_uri(&finished.service_type),
                                service_name: finished.name,
                                digital_identities: finished.identities,
                                service_status: ServiceStatus::from_uri(&finished.status),
                                status_starting_time: parse_date_time(
                                    "StatusStartingTime",
                                    &finished.status_time,
                                )?,
                                history: Vec::new(),
                            });
                        }
                        _ => {}
                    }
                } else if within("TrustServiceProvider") {
                    match local.as_str() {
                        "Name" if within("TSPName") && current_tsp_name.is_empty() => {
                            current_tsp_name = text;
                        }
                        "Name" if within("TSPTradeName") => {
                            current_tsp_trade_name.get_or_insert(text);
                        }
                        "URI" if within("TSPInformationURI") => current_tsp_uris.push(text),
                        "TrustServiceProvider" => {
                            if !current_tsp_name.is_empty() {
                                providers.push(TrustServiceProvider {
                                    name: std::mem::take(&mut current_tsp_name),
                                    trade_name: current_tsp_trade_name.take(),
                                    territory: scheme_territory.clone(),
                                    information_uris: std::mem::take(&mut current_tsp_uris),
                                    services: std::mem::take(&mut current_services),
                                });
                            }
                            current_tsp_name.clear();
                            current_tsp_trade_name = None;
                            current_tsp_uris.clear();
                            current_services.clear();
                        }
                        _ => {}
                    }
                } else if within("SchemeInformation") {
                    match local.as_str() {
                        "TSLVersionIdentifier" => {
                            tsl_version = parse_number("TSLVersionIdentifier", &text)?;
                        }
                        "TSLSequenceNumber" => {
                            tsl_sequence_number = parse_number("TSLSequenceNumber", &text)?;
                        }
                        "TSLType" => tsl_type_uri = text,
                        "SchemeTerritory" if scheme_territory.is_empty() => {
                            scheme_territory = text;
                        }
                        "Name"
                            if within("SchemeOperatorName") && scheme_operator_name.is_empty() =>
                        {
                            scheme_operator_name = text;
                        }
                        "ListIssueDateTime" => {
                            list_issue_date_time =
                                Some(parse_date_time("ListIssueDateTime", &text)?);
                        }
                        "dateTime" if within("NextUpdate") => {
                            next_update = Some(parse_date_time("NextUpdate", &text)?);
                        }
                        _ => {}
                    }
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

    let list_issue_date_time = list_issue_date_time
        .ok_or_else(|| TrustListError::MissingField("ListIssueDateTime".into()))?;

    let tsl_type = if !tsl_type_uri.is_empty() {
        TslType::from_uri(&tsl_type_uri)
    } else if scheme_territory == "EU" {
        TslType::ListOfTrustedLists
    } else {
        TslType::EuGeneric
    };

    Ok(UnverifiedTrustList {
        list: TrustServiceStatusList {
            scheme_information: SchemeInformation {
                tsl_version,
                tsl_sequence_number,
                tsl_type,
                scheme_operator_name,
                scheme_territory,
                list_issue_date_time,
                next_update,
                pointers_to_other_tsl: pointers,
            },
            trust_service_providers: providers,
        },
        signature_present,
    })
}

fn parse_date_time(field: &str, value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|date_time| date_time.with_timezone(&Utc))
        .map_err(|e| TrustListError::Parse(format!("{field} '{value}': {e}")))
}

fn parse_number(field: &str, value: &str) -> Result<u32> {
    value
        .parse()
        .map_err(|e| TrustListError::Parse(format!("{field} '{value}': {e}")))
}

fn decode_base64(field: &str, value: &str) -> Result<Vec<u8>> {
    let cleaned: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    BASE64_STANDARD
        .decode(&cleaned)
        .map_err(|e| TrustListError::Base64(format!("{field} decode: {e}")))
}

/// Extract the local name from an XML element (strip namespace prefix).
fn local_name_owned(name: &str) -> String {
    name.rsplit_once(':')
        .map(|(_, local)| local)
        .unwrap_or(name)
        .to_string()
}

/// Decode a base64-encoded X.509 certificate from XML content.
pub fn decode_certificate(base64_content: &str) -> Result<Vec<u8>> {
    decode_base64("certificate", base64_content)
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
    <ListIssueDateTime>2026-01-01T00:00:00Z</ListIssueDateTime>
  </SchemeInformation>
</TrustServiceStatusList>"#;

        let tl = parse_trust_list_xml(xml).unwrap().assume_authenticated();
        assert_eq!(tl.scheme_information.scheme_territory, "DE");
        assert_eq!(tl.scheme_information.scheme_operator_name, "Test Authority");
        assert_eq!(tl.scheme_information.tsl_type, TslType::EuGeneric);
    }

    /// Element text containing XML entity references must be reassembled with the
    /// entities resolved. Under quick-xml 0.41 the reader emits the surrounding
    /// text and each `&…;` reference as separate events, so this exercises the
    /// `Event::Text` + `Event::GeneralRef` accumulation path (predefined `&amp;`
    /// and numeric `&#38;` both resolve to `&`).
    #[test]
    fn parse_resolves_entity_references_in_text() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList>
  <SchemeInformation>
    <SchemeOperatorName>
      <Name>Foo &amp; Bar &#38; Baz &lt;Ltd&gt;</Name>
    </SchemeOperatorName>
    <SchemeTerritory>DE</SchemeTerritory>
    <ListIssueDateTime>2026-01-01T00:00:00Z</ListIssueDateTime>
  </SchemeInformation>
</TrustServiceStatusList>"#;

        let tl = parse_trust_list_xml(xml).unwrap().assume_authenticated();
        assert_eq!(
            tl.scheme_information.scheme_operator_name, "Foo & Bar & Baz <Ltd>",
            "predefined and numeric entity references are resolved and the text \
             around them reassembled"
        );
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
    <ListIssueDateTime>2026-01-01T00:00:00Z</ListIssueDateTime>
  </SchemeInformation>
</TrustServiceStatusList>"#;

        let tl = parse_trust_list_xml(xml).unwrap().assume_authenticated();
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
    <tsl:ListIssueDateTime>2026-01-01T00:00:00Z</tsl:ListIssueDateTime>
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

        let tl = parse_trust_list_xml(xml).unwrap().assume_authenticated();
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
        match svc.digital_identities.as_slice() {
            [ServiceDigitalIdentity::X509Certificate(cert)] => {
                assert_eq!(cert, b"Hello");
            }
            other => panic!("expected one X509Certificate, got {other:?}"),
        }
    }

    #[test]
    fn parse_multiple_tsps() {
        let xml = r#"<?xml version="1.0"?>
<TrustServiceStatusList>
  <SchemeInformation>
    <SchemeOperatorName><Name>Authority</Name></SchemeOperatorName>
    <SchemeTerritory>AT</SchemeTerritory>
    <ListIssueDateTime>2026-01-01T00:00:00Z</ListIssueDateTime>
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

        let tl = parse_trust_list_xml(xml).unwrap().assume_authenticated();
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
    <ListIssueDateTime>2026-01-01T00:00:00Z</ListIssueDateTime>
    <NextUpdate><dateTime>2026-07-01T00:00:00Z</dateTime></NextUpdate>
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

        let tl = parse_trust_list_xml(xml).unwrap().assume_authenticated();

        let mut registry = crate::TrustListRegistry::new();
        let now = chrono::DateTime::parse_from_rfc3339("2026-02-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        registry.load_trust_list(&tl, now).unwrap();

        assert_eq!(registry.entry_count(), 1);
        // Lookup by the decoded cert bytes
        let result = registry.lookup_by_certificate(b"test-cert");
        assert!(result.is_trusted());
    }

    const HISTORY_XML: &str = r#"<?xml version="1.0"?>
<TrustServiceStatusList>
  <SchemeInformation>
    <SchemeOperatorName><Name>Authority</Name></SchemeOperatorName>
    <SchemeTerritory>DE</SchemeTerritory>
    <ListIssueDateTime>2026-01-01T00:00:00Z</ListIssueDateTime>
    <NextUpdate><dateTime>2026-07-01T00:00:00Z</dateTime></NextUpdate>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPInformation><TSPName><Name>Provider</Name></TSPName></TSPInformation>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceName><Name>Current CA</Name></ServiceName>
            <ServiceDigitalIdentity>
              <DigitalId><X509Certificate>AQID</X509Certificate></DigitalId>
              <DigitalId><X509Certificate>BAUG</X509Certificate></DigitalId>
              <DigitalId><X509SKI>BwgJ</X509SKI></DigitalId>
            </ServiceDigitalIdentity>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
            <StatusStartingTime>2025-01-01T00:00:00Z</StatusStartingTime>
          </ServiceInformation>
          <ServiceHistory>
            <ServiceHistoryInstance>
              <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
              <ServiceName><Name>Former CA name</Name></ServiceName>
              <ServiceDigitalIdentity>
                <DigitalId><X509Certificate>CgsM</X509Certificate></DigitalId>
              </ServiceDigitalIdentity>
              <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</ServiceStatus>
              <StatusStartingTime>2020-01-01T00:00:00Z</StatusStartingTime>
            </ServiceHistoryInstance>
          </ServiceHistory>
        </TSPService>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/IdV/nothQC</ServiceTypeIdentifier>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
            <StatusStartingTime>2025-02-01T00:00:00Z</StatusStartingTime>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:KeyInfo><ds:X509Data><ds:X509Certificate>DQ4P</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
  </ds:Signature>
</TrustServiceStatusList>"#;

    #[test]
    fn service_history_stays_with_its_service() {
        let parsed = parse_trust_list_xml(HISTORY_XML).unwrap();
        assert!(parsed.has_signature_element());
        let tl = parsed.assume_authenticated();
        let services = &tl.trust_service_providers[0].services;
        assert_eq!(services.len(), 2);

        assert_eq!(services[0].service_name, "Current CA");
        assert_eq!(services[0].history.len(), 1);
        assert!(services[0].history[0].service_status.is_terminated());

        assert_eq!(services[1].service_name, "");
        assert!(
            services[1].digital_identities.is_empty(),
            "a service without identities takes none from history or the signature"
        );
    }

    #[test]
    fn every_digital_identity_is_kept_and_indexed() {
        let tl = parse_trust_list_xml(HISTORY_XML)
            .unwrap()
            .assume_authenticated();
        assert_eq!(
            tl.trust_service_providers[0].services[0]
                .digital_identities
                .len(),
            3
        );

        let mut registry = crate::TrustListRegistry::new();
        let now = chrono::DateTime::parse_from_rfc3339("2026-02-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        registry.load_trust_list(&tl, now).unwrap();
        assert!(registry.lookup_by_certificate(&[1, 2, 3]).is_trusted());
        assert!(registry.lookup_by_certificate(&[4, 5, 6]).is_trusted());
        assert!(registry.lookup_by_ski(&[7, 8, 9]).is_trusted());
        assert!(!registry.lookup_by_certificate(&[10, 11, 12]).is_trusted());
        assert!(!registry.lookup_by_certificate(&[13, 14, 15]).is_trusted());
    }

    #[test]
    fn issue_and_next_update_are_parsed() {
        let tl = parse_trust_list_xml(HISTORY_XML)
            .unwrap()
            .assume_authenticated();
        let info = &tl.scheme_information;
        assert_eq!(
            info.list_issue_date_time.to_rfc3339(),
            "2026-01-01T00:00:00+00:00"
        );
        assert_eq!(
            info.next_update.map(|next| next.to_rfc3339()),
            Some("2026-07-01T00:00:00+00:00".to_string())
        );

        let after = chrono::DateTime::parse_from_rfc3339("2026-08-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(!tl.is_current_at(after));
        assert!(
            crate::TrustListRegistry::new()
                .load_trust_list(&tl, after)
                .is_err()
        );
    }

    #[test]
    fn closed_list_has_no_next_update() {
        let xml = HISTORY_XML.replace(
            "<NextUpdate><dateTime>2026-07-01T00:00:00Z</dateTime></NextUpdate>",
            "<NextUpdate/>",
        );
        let tl = parse_trust_list_xml(&xml).unwrap().assume_authenticated();
        assert!(tl.scheme_information.next_update.is_none());
    }

    #[test]
    fn missing_issue_date_is_an_error() {
        let xml = HISTORY_XML.replace(
            "<ListIssueDateTime>2026-01-01T00:00:00Z</ListIssueDateTime>",
            "",
        );
        assert!(parse_trust_list_xml(&xml).is_err());
    }

    #[test]
    fn unparseable_status_time_is_an_error() {
        let xml = HISTORY_XML.replace("2025-02-01T00:00:00Z", "yesterday");
        assert!(parse_trust_list_xml(&xml).is_err());
    }

    #[test]
    fn undecodable_certificate_is_an_error() {
        let xml = HISTORY_XML.replace("<X509Certificate>AQID", "<X509Certificate>A!ID");
        assert!(parse_trust_list_xml(&xml).is_err());
    }
}

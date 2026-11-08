//! Services, designated by the AID.
//!
//! § Service Endpoints: "`did:webs` DIDs MUST support service endpoints,
//! including types declared in the DID Specification Registries, such as
//! DIDCommMessaging." KERI's own endpoint data cannot carry them: an
//! `/end/role` reply names one of KERI's roles (`agent`, `mailbox`, `witness`,
//! …), and a `/loc/scheme` reply a `tcp`, `http` or `https` URL — keripy refuses
//! anything else. A `DIDCommMessaging` service whose endpoint is a mediator's
//! DID, or a `TSPTransport` service, fits neither.
//!
//! So a service of any type is a designation of schema
//! [`SERVICE_SCHEMA`], whose `a.services` are DID document service entries —
//! `id` (a relative DID URL), `type`, `serviceEndpoint`, and any other members
//! the type defines — published as written. KERI's role endpoints are still
//! derived from KERI's replies ([`crate::services`]); a designation adds to
//! them, and a designated service whose `id` is already taken is dropped.

use affinidi_keri_core::SadValue;
use affinidi_keri_core::sad::SadMap;
use serde_json::{Map, Value, json};

use crate::designation::designations;
use crate::errors::DidWebsError;
use crate::kel::Kels;

/// The ACDC schema SAID of a service designation.
///
/// The schema is `schemas/service-designation.json` in this crate; a test
/// recomputes its SAID.
pub const SERVICE_SCHEMA: &str = "ELj0Sdf2Boi7BMiIFAEJ9_MSFJU8t-LavLN-gMb8oXM8";

/// The service designation schema document.
pub const SERVICE_SCHEMA_JSON: &str = include_str!("../schemas/service-designation.json");

/// A service to designate: one DID document service entry.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct DesignatedService {
    /// The entry's id, a fragment such as `#didcomm`. Written relative, as
    /// every id in a `did:webs` document is.
    pub id: String,
    /// The service type: a string, or an array of strings.
    pub type_: Value,
    /// The `serviceEndpoint`: a URI, a map or a set, as the type defines.
    pub service_endpoint: Value,
    /// Any other members the service type defines.
    pub properties: Map<String, Value>,
}

impl DesignatedService {
    /// A service of one type at `service_endpoint`.
    pub fn new(id: impl Into<String>, type_: impl Into<String>, service_endpoint: Value) -> Self {
        Self {
            id: id.into(),
            type_: json!(type_.into()),
            service_endpoint,
            properties: Map::new(),
        }
    }

    /// Add a member the service type defines.
    pub fn with_property(mut self, name: impl Into<String>, value: Value) -> Self {
        self.properties.insert(name.into(), value);
        self
    }

    /// The service entry as it is designated and published.
    pub fn to_service(&self) -> Value {
        self.to_sad().to_json_value()
    }

    /// The entry as it goes into the designation: `id`, `type`,
    /// `serviceEndpoint`, then the other members, in that order. The
    /// designation's SAID covers these bytes, so the order is fixed here
    /// rather than left to how `serde_json` was built.
    pub(crate) fn to_sad(&self) -> SadValue {
        let mut entry = SadMap::new();
        entry.insert("id".into(), SadValue::from(self.id.as_str()));
        entry.insert("type".into(), SadValue::from_json_value(&self.type_));
        entry.insert(
            "serviceEndpoint".into(),
            SadValue::from_json_value(&self.service_endpoint),
        );
        for (k, v) in &self.properties {
            entry
                .entry(k.clone())
                .or_insert_with(|| SadValue::from_json_value(v));
        }
        SadValue::Object(entry)
    }
}

/// The services an AID has designated, and how far verification got.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct DesignatedServices {
    /// The designated service entries, from every designation that verified
    /// and stands unrevoked. Where two share an `id`, the first stands.
    pub services: Vec<Value>,
    /// Why a designation the stream carried produced nothing, when one did not
    /// verify or carried a malformed entry.
    pub rejected: Option<String>,
}

/// Collect the services `aid` has designated.
///
/// A designation with a malformed entry yields nothing: it is not the
/// credential the schema describes, and publishing the rest of it would be
/// reading part of a statement as the whole.
///
/// # Errors
/// Returns [`DidWebsError::Kel`] only if `aid`'s own key event log does not
/// verify.
pub fn designated_services(kels: &Kels, aid: &str) -> Result<DesignatedServices, DidWebsError> {
    let mut out = DesignatedServices::default();
    for designation in designations(kels, aid, SERVICE_SCHEMA, &mut out.rejected)? {
        match read_services(&designation.attributes) {
            Ok(services) => {
                for service in services {
                    if out.services.iter().any(|s| s["id"] == service["id"]) {
                        continue;
                    }
                    out.services.push(service);
                }
            }
            Err(e) => {
                out.rejected.get_or_insert(e);
            }
        }
    }
    Ok(out)
}

fn read_services(attributes: &SadValue) -> Result<Vec<Value>, String> {
    let services = attributes
        .get("services")
        .and_then(|v| v.as_array())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "service designation carries no `a.services`".to_string())?;
    services
        .iter()
        .map(|s| check_service(s).map(|()| s.to_json_value()))
        .collect()
}

/// Whether an entry is a service a DID document can carry.
pub(crate) fn check_service(service: &SadValue) -> Result<(), String> {
    let id = service
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "a designated service has no `id`".to_string())?;
    if !id.starts_with('#') || id.len() < 2 || id[1..].contains('#') {
        return Err(format!(
            "designated service id {id:?} is not a relative DID URL fragment"
        ));
    }
    let type_ok = match service.get("type") {
        Some(SadValue::String(t)) => !t.is_empty(),
        Some(SadValue::Array(ts)) => {
            !ts.is_empty() && ts.iter().all(|t| t.as_str().is_some_and(|t| !t.is_empty()))
        }
        _ => false,
    };
    if !type_ok {
        return Err(format!("designated service {id} has no usable `type`"));
    }
    if !matches!(
        service.get("serviceEndpoint"),
        Some(SadValue::String(_) | SadValue::Object(_) | SadValue::Array(_))
    ) {
        return Err(format!("designated service {id} has no `serviceEndpoint`"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_didcomm_service_with_a_mediator_did_is_a_valid_entry() {
        let service = DesignatedService::new(
            "#didcomm",
            "DIDCommMessaging",
            json!({"uri": "did:webvh:QmMediator:mediator.example", "accept": ["didcomm/v2"]}),
        );
        assert!(check_service(&service.to_sad()).is_ok());
    }

    #[test]
    fn an_absolute_or_empty_id_is_refused() {
        for id in ["did:webs:example.com:E1#x", "#", "x", "#a#b"] {
            let service = DesignatedService::new(id, "LinkedDomains", json!("https://x"));
            assert!(check_service(&service.to_sad()).is_err(), "{id}");
        }
    }

    #[test]
    fn a_service_needs_a_type_and_an_endpoint() {
        assert!(
            check_service(&affinidi_keri_core::sad!({"id": "#x", "serviceEndpoint": "https://x"}))
                .is_err()
        );
        assert!(
            check_service(
                &affinidi_keri_core::sad!({"id": "#x", "type": [], "serviceEndpoint": "https://x"})
            )
            .is_err()
        );
        assert!(check_service(&affinidi_keri_core::sad!({"id": "#x", "type": "T"})).is_err());
        assert!(
            check_service(
                &affinidi_keri_core::sad!({"id": "#x", "type": "T", "serviceEndpoint": 3})
            )
            .is_err()
        );
    }
}

/*!
 * Driving Privileges per ISO 18013-5 Table 7.
 *
 * ```text
 * driving_privileges = [* DrivingPrivilege]
 *
 * DrivingPrivilege = {
 *   "vehicle_category_code": tstr,
 *   ? "issue_date": full-date,
 *   ? "expiry_date": full-date,
 *   ? "codes": [* Code]
 * }
 *
 * Code = {
 *   "code": tstr,
 *   ? "sign": tstr,
 *   ? "value": tstr
 * }
 * ```
 */

use crate::error::{MdocError, Result};

/// Driving privileges — an array of vehicle category entries.
///
/// Per ISO 18013-5 Table 7, this is the `driving_privileges` data element.
#[derive(Debug, Clone)]
pub struct DrivingPrivileges(pub Vec<DrivingPrivilege>);

/// A single driving privilege (vehicle category).
#[derive(Debug, Clone)]
pub struct DrivingPrivilege {
    /// Vehicle category code (e.g., "A", "B", "C", "D", "BE").
    pub vehicle_category_code: String,
    /// Date of issue for this category (full-date tstr, e.g., "2020-01-15").
    pub issue_date: Option<String>,
    /// Expiry date for this category (full-date tstr).
    pub expiry_date: Option<String>,
    /// Condition/restriction codes.
    pub codes: Option<Vec<DrivingPrivilegeCode>>,
}

/// Condition/restriction code per ISO 18013-5 Table 8.
#[derive(Debug, Clone)]
pub struct DrivingPrivilegeCode {
    /// The code identifier.
    pub code: String,
    /// Optional sign (e.g., "=", "<", ">").
    pub sign: Option<String>,
    /// Optional value.
    pub value: Option<String>,
}

/// Builder for constructing DrivingPrivileges.
pub struct DrivingPrivilegesBuilder {
    privileges: Vec<DrivingPrivilege>,
    current: Option<DrivingPrivilegeBuilderState>,
}

struct DrivingPrivilegeBuilderState {
    vehicle_category_code: String,
    issue_date: Option<String>,
    expiry_date: Option<String>,
    codes: Vec<DrivingPrivilegeCode>,
}

impl DrivingPrivilegesBuilder {
    /// Start building a new set of driving privileges.
    pub fn new() -> Self {
        Self {
            privileges: Vec::new(),
            current: None,
        }
    }

    /// Add a new vehicle category. Finishes any in-progress category.
    pub fn add_category(mut self, code: impl Into<String>) -> Self {
        self.finish_current();
        self.current = Some(DrivingPrivilegeBuilderState {
            vehicle_category_code: code.into(),
            issue_date: None,
            expiry_date: None,
            codes: Vec::new(),
        });
        self
    }

    /// Set issue date for the current category.
    pub fn issue_date(mut self, date: impl Into<String>) -> Self {
        if let Some(ref mut state) = self.current {
            state.issue_date = Some(date.into());
        }
        self
    }

    /// Set expiry date for the current category.
    pub fn expiry_date(mut self, date: impl Into<String>) -> Self {
        if let Some(ref mut state) = self.current {
            state.expiry_date = Some(date.into());
        }
        self
    }

    /// Add a condition/restriction code to the current category.
    pub fn add_code(
        mut self,
        code: impl Into<String>,
        sign: Option<String>,
        value: Option<String>,
    ) -> Self {
        if let Some(ref mut state) = self.current {
            state.codes.push(DrivingPrivilegeCode {
                code: code.into(),
                sign,
                value,
            });
        }
        self
    }

    /// Build the DrivingPrivileges.
    pub fn build(mut self) -> DrivingPrivileges {
        self.finish_current();
        DrivingPrivileges(self.privileges)
    }

    fn finish_current(&mut self) {
        if let Some(state) = self.current.take() {
            self.privileges.push(DrivingPrivilege {
                vehicle_category_code: state.vehicle_category_code,
                issue_date: state.issue_date,
                expiry_date: state.expiry_date,
                codes: if state.codes.is_empty() {
                    None
                } else {
                    Some(state.codes)
                },
            });
        }
    }
}

impl Default for DrivingPrivilegesBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DrivingPrivileges {
    /// Start building a new set of driving privileges.
    pub fn builder() -> DrivingPrivilegesBuilder {
        DrivingPrivilegesBuilder::new()
    }

    /// Convert to a CBOR Value for embedding as an `elementValue` in IssuerSignedItem.
    pub fn to_cbor_value(&self) -> ciborium::Value {
        ciborium::Value::Array(self.0.iter().map(|p| p.to_cbor_value()).collect())
    }

    /// Parse from a CBOR Value (e.g., from a disclosed attribute).
    pub fn from_cbor_value(value: &ciborium::Value) -> Result<Self> {
        let arr = match value {
            ciborium::Value::Array(a) => a,
            _ => {
                return Err(MdocError::Cbor(
                    "driving_privileges must be a CBOR array".into(),
                ));
            }
        };

        let privileges: Result<Vec<DrivingPrivilege>> =
            arr.iter().map(DrivingPrivilege::from_cbor_value).collect();
        Ok(DrivingPrivileges(privileges?))
    }
}

impl DrivingPrivilege {
    /// Convert to a CBOR Value (map).
    pub fn to_cbor_value(&self) -> ciborium::Value {
        let mut entries = vec![(
            ciborium::Value::Text("vehicle_category_code".to_string()),
            ciborium::Value::Text(self.vehicle_category_code.clone()),
        )];

        if let Some(ref date) = self.issue_date {
            entries.push((
                ciborium::Value::Text("issue_date".to_string()),
                ciborium::Value::Text(date.clone()),
            ));
        }
        if let Some(ref date) = self.expiry_date {
            entries.push((
                ciborium::Value::Text("expiry_date".to_string()),
                ciborium::Value::Text(date.clone()),
            ));
        }
        if let Some(ref codes) = self.codes {
            let codes_arr: Vec<ciborium::Value> = codes.iter().map(|c| c.to_cbor_value()).collect();
            entries.push((
                ciborium::Value::Text("codes".to_string()),
                ciborium::Value::Array(codes_arr),
            ));
        }

        ciborium::Value::Map(entries)
    }

    /// Parse from a CBOR Value (map).
    pub fn from_cbor_value(value: &ciborium::Value) -> Result<Self> {
        let entries = match value {
            ciborium::Value::Map(m) => m,
            _ => {
                return Err(MdocError::Cbor(
                    "DrivingPrivilege must be a CBOR map".into(),
                ));
            }
        };

        let get_text = |key: &str| -> Option<String> {
            entries.iter().find_map(|(k, v)| {
                if let (ciborium::Value::Text(k_str), ciborium::Value::Text(v_str)) = (k, v)
                    && k_str == key
                {
                    return Some(v_str.clone());
                }
                None
            })
        };

        let vehicle_category_code = get_text("vehicle_category_code")
            .ok_or_else(|| MdocError::MissingField("vehicle_category_code".into()))?;

        let codes = entries.iter().find_map(|(k, v)| {
            if let ciborium::Value::Text(k_str) = k
                && k_str == "codes"
                && let ciborium::Value::Array(arr) = v
            {
                let parsed: Result<Vec<DrivingPrivilegeCode>> = arr
                    .iter()
                    .map(DrivingPrivilegeCode::from_cbor_value)
                    .collect();
                return Some(parsed);
            }
            None
        });

        let codes = match codes {
            Some(Ok(c)) => Some(c),
            Some(Err(e)) => return Err(e),
            None => None,
        };

        Ok(DrivingPrivilege {
            vehicle_category_code,
            issue_date: get_text("issue_date"),
            expiry_date: get_text("expiry_date"),
            codes,
        })
    }
}

impl DrivingPrivilegeCode {
    /// Convert to a CBOR Value (map).
    pub fn to_cbor_value(&self) -> ciborium::Value {
        let mut entries = vec![(
            ciborium::Value::Text("code".to_string()),
            ciborium::Value::Text(self.code.clone()),
        )];

        if let Some(ref sign) = self.sign {
            entries.push((
                ciborium::Value::Text("sign".to_string()),
                ciborium::Value::Text(sign.clone()),
            ));
        }
        if let Some(ref value) = self.value {
            entries.push((
                ciborium::Value::Text("value".to_string()),
                ciborium::Value::Text(value.clone()),
            ));
        }

        ciborium::Value::Map(entries)
    }

    /// Parse from a CBOR Value (map).
    pub fn from_cbor_value(value: &ciborium::Value) -> Result<Self> {
        let entries = match value {
            ciborium::Value::Map(m) => m,
            _ => return Err(MdocError::Cbor("Code must be a CBOR map".into())),
        };

        let get_text = |key: &str| -> Option<String> {
            entries.iter().find_map(|(k, v)| {
                if let (ciborium::Value::Text(k_str), ciborium::Value::Text(v_str)) = (k, v)
                    && k_str == key
                {
                    return Some(v_str.clone());
                }
                None
            })
        };

        let code = get_text("code").ok_or_else(|| MdocError::MissingField("code".into()))?;

        Ok(DrivingPrivilegeCode {
            code,
            sign: get_text("sign"),
            value: get_text("value"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_single_category() {
        let dp = DrivingPrivileges::builder()
            .add_category("B")
            .issue_date("2020-01-15")
            .expiry_date("2030-01-15")
            .build();

        assert_eq!(dp.0.len(), 1);
        assert_eq!(dp.0[0].vehicle_category_code, "B");
        assert_eq!(dp.0[0].issue_date.as_deref(), Some("2020-01-15"));
        assert_eq!(dp.0[0].expiry_date.as_deref(), Some("2030-01-15"));
        assert!(dp.0[0].codes.is_none());
    }

    #[test]
    fn builder_multiple_categories() {
        let dp = DrivingPrivileges::builder()
            .add_category("A")
            .issue_date("2018-06-01")
            .add_category("B")
            .issue_date("2020-01-15")
            .expiry_date("2030-01-15")
            .add_category("BE")
            .build();

        assert_eq!(dp.0.len(), 3);
        assert_eq!(dp.0[0].vehicle_category_code, "A");
        assert_eq!(dp.0[1].vehicle_category_code, "B");
        assert_eq!(dp.0[2].vehicle_category_code, "BE");
    }

    #[test]
    fn builder_with_codes() {
        let dp = DrivingPrivileges::builder()
            .add_category("B")
            .add_code("01", Some("=".to_string()), Some("glasses".to_string()))
            .add_code("05", None, None)
            .build();

        assert_eq!(dp.0.len(), 1);
        let codes = dp.0[0].codes.as_ref().unwrap();
        assert_eq!(codes.len(), 2);
        assert_eq!(codes[0].code, "01");
        assert_eq!(codes[0].sign.as_deref(), Some("="));
        assert_eq!(codes[0].value.as_deref(), Some("glasses"));
        assert_eq!(codes[1].code, "05");
        assert!(codes[1].sign.is_none());
    }

    #[test]
    fn cbor_roundtrip() {
        let dp = DrivingPrivileges::builder()
            .add_category("B")
            .issue_date("2020-01-15")
            .expiry_date("2030-01-15")
            .add_code("01", Some("=".to_string()), Some("glasses".to_string()))
            .add_category("A")
            .issue_date("2018-06-01")
            .build();

        let cbor_val = dp.to_cbor_value();
        let parsed = DrivingPrivileges::from_cbor_value(&cbor_val).unwrap();

        assert_eq!(parsed.0.len(), 2);
        assert_eq!(parsed.0[0].vehicle_category_code, "B");
        assert_eq!(parsed.0[0].issue_date.as_deref(), Some("2020-01-15"));
        assert_eq!(parsed.0[0].expiry_date.as_deref(), Some("2030-01-15"));
        let codes = parsed.0[0].codes.as_ref().unwrap();
        assert_eq!(codes[0].code, "01");
        assert_eq!(parsed.0[1].vehicle_category_code, "A");
    }

    #[test]
    fn cbor_bytes_roundtrip() {
        let dp = DrivingPrivileges::builder().add_category("C").build();

        let cbor_val = dp.to_cbor_value();
        let mut buf = Vec::new();
        ciborium::into_writer(&cbor_val, &mut buf).unwrap();

        let decoded: ciborium::Value = ciborium::from_reader(&buf[..]).unwrap();
        let parsed = DrivingPrivileges::from_cbor_value(&decoded).unwrap();
        assert_eq!(parsed.0[0].vehicle_category_code, "C");
    }

    #[test]
    fn empty_privileges() {
        let dp = DrivingPrivileges::builder().build();
        assert!(dp.0.is_empty());

        let cbor_val = dp.to_cbor_value();
        let parsed = DrivingPrivileges::from_cbor_value(&cbor_val).unwrap();
        assert!(parsed.0.is_empty());
    }

    #[test]
    fn invalid_cbor_type_fails() {
        let result = DrivingPrivileges::from_cbor_value(&ciborium::Value::Text("bad".into()));
        assert!(result.is_err());
    }
}

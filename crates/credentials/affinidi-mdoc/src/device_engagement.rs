/*!
 * Device Engagement structure per ISO 18013-5 §9.1.1.4.
 *
 * ```text
 * DeviceEngagement = [
 *   version: tstr,                          ; "1.0"
 *   security: Security,                     ; [cipher_suite, EDeviceKeyBytes]
 *   ? deviceRetrievalMethods: [+ DeviceRetrievalMethod],
 *   ? serverRetrievalMethods: ServerRetrievalMethods,
 *   ? protocolInfo: any
 * ]
 *
 * Security = [
 *   cipherSuiteIdentifier: int,             ; 1 = P-256 + HKDF-SHA-256 + AES-256-GCM
 *   eDeviceKeyBytes: Tag24<COSE_Key>
 * ]
 *
 * DeviceRetrievalMethod = [
 *   transportType: uint,                    ; 1=NFC, 2=BLE, 3=WiFiAware
 *   version: uint,
 *   retrievalOptions: any
 * ]
 * ```
 *
 * ISO 18013-5 encodes DeviceEngagement as a CBOR **array** (positional fields),
 * not a map. We use manual `ciborium::Value` construction.
 */

use crate::error::{MdocError, Result};
use crate::tag24::Tag24;

/// Cipher suite 1: P-256, HKDF-SHA-256, AES-256-GCM (the only one in ISO 18013-5).
pub const CIPHER_SUITE_P256: u32 = 1;

/// Transport type: NFC.
pub const TRANSPORT_NFC: u32 = 1;
/// Transport type: BLE.
pub const TRANSPORT_BLE: u32 = 2;
/// Transport type: WiFi Aware.
pub const TRANSPORT_WIFI_AWARE: u32 = 3;

/// Device Engagement per ISO 18013-5 §9.1.1.4.
///
/// Contains the device's ephemeral public key and optional retrieval methods.
/// Encoded as a CBOR array for session establishment.
#[derive(Debug, Clone)]
pub struct DeviceEngagement {
    /// Protocol version (always "1.0").
    pub version: String,
    /// Security parameters: cipher suite + ephemeral device key.
    pub security: Security,
    /// Optional device retrieval methods (BLE, NFC, WiFi Aware).
    pub device_retrieval_methods: Option<Vec<DeviceRetrievalMethod>>,
    /// Optional server retrieval methods.
    pub server_retrieval_methods: Option<ciborium::Value>,
    /// Optional protocol info.
    pub protocol_info: Option<ciborium::Value>,
}

/// Security parameters for device engagement.
#[derive(Debug, Clone)]
pub struct Security {
    /// Cipher suite identifier (1 = P-256 + HKDF-SHA-256 + AES-256-GCM).
    pub cipher_suite: u32,
    /// Ephemeral device public key as Tag24-wrapped COSE_Key.
    pub e_device_key_bytes: Tag24<ciborium::Value>,
}

/// A device retrieval method (transport configuration).
#[derive(Debug, Clone)]
pub struct DeviceRetrievalMethod {
    /// Transport type (1=NFC, 2=BLE, 3=WiFiAware).
    pub transport_type: u32,
    /// Protocol version.
    pub version: u32,
    /// Transport-specific options.
    pub retrieval_options: Option<ciborium::Value>,
}

impl DeviceEngagement {
    /// Create a new DeviceEngagement with the given ephemeral device key (COSE_Key).
    ///
    /// Uses cipher suite 1 (P-256 + HKDF-SHA-256 + AES-256-GCM).
    pub fn new(e_device_key: ciborium::Value) -> Result<Self> {
        Ok(Self {
            version: "1.0".to_string(),
            security: Security {
                cipher_suite: CIPHER_SUITE_P256,
                e_device_key_bytes: Tag24::new(e_device_key)?,
            },
            device_retrieval_methods: None,
            server_retrieval_methods: None,
            protocol_info: None,
        })
    }

    /// Create with a specific cipher suite.
    pub fn with_cipher_suite(cipher_suite: u32, e_device_key: ciborium::Value) -> Result<Self> {
        Ok(Self {
            version: "1.0".to_string(),
            security: Security {
                cipher_suite,
                e_device_key_bytes: Tag24::new(e_device_key)?,
            },
            device_retrieval_methods: None,
            server_retrieval_methods: None,
            protocol_info: None,
        })
    }

    /// Add a BLE retrieval method.
    pub fn add_ble_retrieval(mut self, options: Option<ciborium::Value>) -> Self {
        let method = DeviceRetrievalMethod {
            transport_type: TRANSPORT_BLE,
            version: 1,
            retrieval_options: options,
        };
        self.device_retrieval_methods
            .get_or_insert_with(Vec::new)
            .push(method);
        self
    }

    /// Add an NFC retrieval method.
    pub fn add_nfc_retrieval(mut self, options: Option<ciborium::Value>) -> Self {
        let method = DeviceRetrievalMethod {
            transport_type: TRANSPORT_NFC,
            version: 1,
            retrieval_options: options,
        };
        self.device_retrieval_methods
            .get_or_insert_with(Vec::new)
            .push(method);
        self
    }

    /// Encode as a CBOR Value (array per ISO 18013-5).
    pub fn to_cbor_value(&self) -> Result<ciborium::Value> {
        // Security = [cipherSuiteIdentifier, eDeviceKeyBytes]
        let security = ciborium::Value::Array(vec![
            ciborium::Value::Integer(self.security.cipher_suite.into()),
            ciborium::Value::Tag(
                24,
                Box::new(ciborium::Value::Bytes(
                    self.security.e_device_key_bytes.inner_bytes.clone(),
                )),
            ),
        ]);

        // DeviceEngagement = [version, security, ?deviceRetrievalMethods, ...]
        let mut arr = vec![ciborium::Value::Text(self.version.clone()), security];

        // Optional fields use positional encoding — must include nulls for gaps
        match &self.device_retrieval_methods {
            Some(methods) => {
                let methods_arr: Vec<ciborium::Value> = methods
                    .iter()
                    .map(|m| {
                        let mut method_arr = vec![
                            ciborium::Value::Integer(m.transport_type.into()),
                            ciborium::Value::Integer(m.version.into()),
                        ];
                        if let Some(opts) = &m.retrieval_options {
                            method_arr.push(opts.clone());
                        }
                        ciborium::Value::Array(method_arr)
                    })
                    .collect();
                arr.push(ciborium::Value::Array(methods_arr));
            }
            None => {
                // Only add null if there are later fields
                if self.server_retrieval_methods.is_some() || self.protocol_info.is_some() {
                    arr.push(ciborium::Value::Null);
                }
            }
        }

        if let Some(server) = &self.server_retrieval_methods {
            arr.push(server.clone());
        } else if self.protocol_info.is_some() {
            arr.push(ciborium::Value::Null);
        }

        if let Some(proto) = &self.protocol_info {
            arr.push(proto.clone());
        }

        Ok(ciborium::Value::Array(arr))
    }

    /// Encode to CBOR bytes.
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>> {
        let value = self.to_cbor_value()?;
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf)
            .map_err(|e| MdocError::Cbor(format!("DeviceEngagement encoding: {e}")))?;
        Ok(buf)
    }

    /// Decode from a CBOR Value.
    pub fn from_cbor_value(value: &ciborium::Value) -> Result<Self> {
        let arr = match value {
            ciborium::Value::Array(a) => a,
            _ => {
                return Err(MdocError::Cbor(
                    "DeviceEngagement must be a CBOR array".into(),
                ));
            }
        };

        if arr.len() < 2 {
            return Err(MdocError::Cbor(
                "DeviceEngagement requires at least 2 elements".into(),
            ));
        }

        let version = match &arr[0] {
            ciborium::Value::Text(s) => s.clone(),
            _ => {
                return Err(MdocError::Cbor(
                    "DeviceEngagement version must be tstr".into(),
                ));
            }
        };

        // Parse Security = [cipherSuiteIdentifier, eDeviceKeyBytes]
        let security_arr = match &arr[1] {
            ciborium::Value::Array(a) if a.len() >= 2 => a,
            _ => return Err(MdocError::Cbor("Security must be a 2-element array".into())),
        };

        let cipher_suite = match &security_arr[0] {
            ciborium::Value::Integer(i) => {
                let n: i128 = (*i).into();
                n as u32
            }
            _ => return Err(MdocError::Cbor("cipher suite must be int".into())),
        };

        let e_device_key_bytes = match &security_arr[1] {
            ciborium::Value::Tag(24, inner) => {
                let inner_bytes = match inner.as_ref() {
                    ciborium::Value::Bytes(b) => b.clone(),
                    _ => {
                        return Err(MdocError::Cbor(
                            "eDeviceKeyBytes Tag24 inner must be bytes".into(),
                        ));
                    }
                };
                let inner_value: ciborium::Value = ciborium::from_reader(&inner_bytes[..])
                    .map_err(|e| MdocError::Cbor(format!("eDeviceKeyBytes decode: {e}")))?;
                Tag24 {
                    inner: inner_value,
                    inner_bytes,
                }
            }
            ciborium::Value::Bytes(b) => {
                let inner_value: ciborium::Value = ciborium::from_reader(&b[..])
                    .map_err(|e| MdocError::Cbor(format!("eDeviceKeyBytes decode: {e}")))?;
                Tag24 {
                    inner: inner_value,
                    inner_bytes: b.clone(),
                }
            }
            _ => {
                return Err(MdocError::Cbor(
                    "eDeviceKeyBytes must be Tag24 or bytes".into(),
                ));
            }
        };

        // Parse optional device retrieval methods
        let device_retrieval_methods = if arr.len() > 2 {
            match &arr[2] {
                ciborium::Value::Array(methods) => {
                    let mut parsed = Vec::new();
                    for m in methods {
                        if let ciborium::Value::Array(ma) = m {
                            if ma.len() >= 2 {
                                let transport_type = match &ma[0] {
                                    ciborium::Value::Integer(i) => {
                                        let n: i128 = (*i).into();
                                        n as u32
                                    }
                                    _ => continue,
                                };
                                let ver = match &ma[1] {
                                    ciborium::Value::Integer(i) => {
                                        let n: i128 = (*i).into();
                                        n as u32
                                    }
                                    _ => continue,
                                };
                                let retrieval_options = ma.get(2).cloned();
                                parsed.push(DeviceRetrievalMethod {
                                    transport_type,
                                    version: ver,
                                    retrieval_options,
                                });
                            }
                        }
                    }
                    Some(parsed)
                }
                ciborium::Value::Null => None,
                _ => None,
            }
        } else {
            None
        };

        let server_retrieval_methods = arr.get(3).and_then(|v| {
            if matches!(v, ciborium::Value::Null) {
                None
            } else {
                Some(v.clone())
            }
        });

        let protocol_info = arr.get(4).and_then(|v| {
            if matches!(v, ciborium::Value::Null) {
                None
            } else {
                Some(v.clone())
            }
        });

        Ok(DeviceEngagement {
            version,
            security: Security {
                cipher_suite,
                e_device_key_bytes,
            },
            device_retrieval_methods,
            server_retrieval_methods,
            protocol_info,
        })
    }

    /// Decode from CBOR bytes.
    pub fn from_cbor_bytes(bytes: &[u8]) -> Result<Self> {
        let value: ciborium::Value = ciborium::from_reader(bytes)
            .map_err(|e| MdocError::Cbor(format!("DeviceEngagement decode: {e}")))?;
        Self::from_cbor_value(&value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cose_key() -> ciborium::Value {
        // Minimal P-256 COSE_Key
        ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()), // kty
                ciborium::Value::Integer(2.into()), // EC2
            ),
            (
                ciborium::Value::Integer((-1).into()), // crv
                ciborium::Value::Integer(1.into()),    // P-256
            ),
            (
                ciborium::Value::Integer((-2).into()), // x
                ciborium::Value::Bytes(vec![0xaa; 32]),
            ),
            (
                ciborium::Value::Integer((-3).into()), // y
                ciborium::Value::Bytes(vec![0xbb; 32]),
            ),
        ])
    }

    #[test]
    fn create_device_engagement() {
        let de = DeviceEngagement::new(test_cose_key()).unwrap();
        assert_eq!(de.version, "1.0");
        assert_eq!(de.security.cipher_suite, CIPHER_SUITE_P256);
        assert!(de.device_retrieval_methods.is_none());
    }

    #[test]
    fn cbor_roundtrip() {
        let de = DeviceEngagement::new(test_cose_key())
            .unwrap()
            .add_ble_retrieval(None);

        let bytes = de.to_cbor_bytes().unwrap();
        let parsed = DeviceEngagement::from_cbor_bytes(&bytes).unwrap();

        assert_eq!(parsed.version, "1.0");
        assert_eq!(parsed.security.cipher_suite, CIPHER_SUITE_P256);
        assert!(parsed.device_retrieval_methods.is_some());
        let methods = parsed.device_retrieval_methods.unwrap();
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0].transport_type, TRANSPORT_BLE);
    }

    #[test]
    fn minimal_engagement_roundtrip() {
        let de = DeviceEngagement::new(test_cose_key()).unwrap();
        let bytes = de.to_cbor_bytes().unwrap();
        let parsed = DeviceEngagement::from_cbor_bytes(&bytes).unwrap();
        assert_eq!(parsed.version, "1.0");
        assert!(parsed.device_retrieval_methods.is_none());
    }

    #[test]
    fn with_nfc_retrieval() {
        let de = DeviceEngagement::new(test_cose_key())
            .unwrap()
            .add_nfc_retrieval(None)
            .add_ble_retrieval(None);

        let methods = de.device_retrieval_methods.as_ref().unwrap();
        assert_eq!(methods.len(), 2);
        assert_eq!(methods[0].transport_type, TRANSPORT_NFC);
        assert_eq!(methods[1].transport_type, TRANSPORT_BLE);
    }

    #[test]
    fn to_cbor_value_is_array() {
        let de = DeviceEngagement::new(test_cose_key()).unwrap();
        let value = de.to_cbor_value().unwrap();
        assert!(matches!(value, ciborium::Value::Array(_)));
    }
}

// Non-normative examples copied from the OpenID4VCI 1.0 Final spec text
// (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html). Values the spec wraps
// "for display purposes only" are joined onto one line; nothing else is changed.

/// OpenID4VCI 1.0 §4.1.1.
pub(super) const OFFER_PRE_AUTH: &str = r##"{
  "credential_issuer": "https://credential-issuer.example.com",
  "credential_configuration_ids": [
    "UniversityDegreeCredential",
    "org.iso.18013.5.1.mDL"
  ],
  "grants": {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "oaKazRN8I0IbtZ0C7JuMn5",
      "tx_code": {
        "length": 4,
        "input_mode": "numeric",
        "description": "Please provide the one-time code that was sent via e-mail"
      }
    }
  }
}"##;

/// OpenID4VCI 1.0 §4.1.3.
pub(super) const OFFER_AUTH_CODE: &str = r##"{
  "credential_issuer": "https://credential-issuer.example.com",
  "credential_configuration_ids": [
    "UniversityDegreeCredential"
  ],
  "grants": {
    "authorization_code": {
      "issuer_state": "eyJhbGciOiJSU0Et...FYUaBy"
    }
  }
}"##;

/// OpenID4VCI 1.0 §4.1.3.
pub(super) const OFFER_PRE_AUTH_EMPTY_TX_CODE: &str = r##"{
  "credential_issuer": "https://credential-issuer.example.com",
  "credential_configuration_ids": [
    "UniversityDegree_LDP_VC"
  ],
  "grants": {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "adhjhdjajkdkhjhdj",
      "tx_code": {}
    }
  }
}"##;

/// OpenID4VCI 1.0 §5.1.1.
pub(super) const AUTH_DETAILS: &str = r##"[
  {
    "type": "openid_credential",
    "credential_configuration_id": "UniversityDegreeCredential"
  }
]"##;

/// OpenID4VCI 1.0 §5.1.1.
pub(super) const AUTH_DETAILS_LOCATIONS: &str = r##"[
  {
    "type": "openid_credential",
    "locations": [
      "https://credential-issuer.example.com"
    ],
    "credential_configuration_id": "UniversityDegreeCredential"
  }
]"##;

/// OpenID4VCI 1.0 §5.1.1.
pub(super) const AUTH_DETAILS_TWO: &str = r##"[
  {
    "type": "openid_credential",
    "credential_configuration_id": "UniversityDegreeCredential"
  },
  {
    "type": "openid_credential",
    "credential_configuration_id": "org.iso.18013.5.1.mDL"
  }
]"##;

/// OpenID4VCI 1.0 A.1.1.3.
pub(super) const AUTH_DETAILS_JWT_VC_CLAIMS: &str = r##"[
  {
    "type": "openid_credential",
    "credential_configuration_id": "UniversityDegreeCredential",
    "claims": [
      {"path": ["credentialSubject", "given_name"]},
      {"path": ["credentialSubject", "family_name"]},
      {"path": ["credentialSubject", "degree"]}
    ]
  }
]"##;

/// OpenID4VCI 1.0 A.2.3.
pub(super) const AUTH_DETAILS_MDOC_CLAIMS: &str = r##"[
  {
    "type": "openid_credential",
    "credential_configuration_id": "org.iso.18013.5.1.mDL",
    "claims": [
      {"path": ["org.iso.18013.5.1","given_name"]},
      {"path": ["org.iso.18013.5.1","family_name"]},
      {"path": ["org.iso.18013.5.1","birth_date"]},
      {"path": ["org.iso.18013.5.1.aamva","organ_donor"]}
    ]
  }
]"##;

/// OpenID4VCI 1.0 A.3.3.
pub(super) const AUTH_DETAILS_SD_JWT_CLAIMS: &str = r##"[
  {
    "type": "openid_credential",
    "credential_configuration_id": "PID_SD_JWT_VC",
    "claims": [
      {"path": ["given_name"]},
      {"path": ["family_name"]}
    ]
  }
]"##;

/// OpenID4VCI 1.0 §6.2.
pub(super) const TOKEN_RESPONSE: &str = r##"{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ",
  "token_type": "Bearer",
  "expires_in": 86400,
  "authorization_details": [
    {
      "type": "openid_credential",
      "credential_configuration_id": "UniversityDegreeCredential",
      "credential_identifiers": [
        "CivilEngineeringDegree-2023",
        "ElectricalEngineeringDegree-2023"
      ]
    }
  ]
}"##;

/// OpenID4VCI 1.0 §6.3.
pub(super) const TOKEN_ERROR: &str = r##"{
  "error": "invalid_request"
}"##;

/// OpenID4VCI 1.0 §7.2.
pub(super) const NONCE_RESPONSE: &str = r##"{
  "c_nonce": "wKI4LT17ac15ES9bw8ac4"
}"##;

/// OpenID4VCI 1.0 §8.2.
pub(super) const CREDENTIAL_REQUEST_MDOC: &str = r##"{
  "credential_configuration_id": "org.iso.18013.5.1.mDL",
  "proofs": {
    "jwt": [
      "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ"
    ]
  }
}"##;

/// OpenID4VCI 1.0 §8.2.
pub(super) const CREDENTIAL_REQUEST_SD_JWT: &str = r##"{
  "credential_identifier": "CivilEngineeringDegree-2023",
  "proofs": {
    "jwt": [
      "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiblVXQW9BdjNYWml0aDhFN2kxOU9kYXhPTFlGT3dNLVoyRXVNMDJUaXJUNCIsInkiOiJIc2tIVThCalVpMVU5WHFpN1N3bWo4Z3dBS18weGtjRGpFV183MVNvc0VZIn19",
      "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ"
    ]
  }
}"##;

/// OpenID4VCI 1.0 §8.2.
pub(super) const CREDENTIAL_REQUEST_DI_VP: &str = r##"{
  "credential_identifier": "CivilEngineeringDegree-2023",
  "proofs": {
    "di_vp": [
      {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "type": [
          "VerifiablePresentation"
        ],
        "holder": "did:key:z6MkvrFpBNCoYewiaeBLgjUDvLxUtnK5R6mqh5XPvLsrPsro",
        "proof": [
          {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-2022",
            "proofPurpose": "authentication",
            "verificationMethod": "did:key:z6MkvrFpBNCoYewiaeBLgjUDvLxUtnK5R6mqh5XPvLsrPsro#z6MkvrFpBNCoYewiaeBLgjUDvLxUtnK5R6mqh5XPvLsrPsro",
            "created": "2023-03-01T14:56:29.280619Z",
            "challenge": "82d4cb36-11f6-4273-b9c6-df1ac0ff17e9",
            "domain": "did:web:audience.company.com",
            "proofValue": "z5hrbHzZiqXHNpLq6i7zePEUcUzEbZKmWfNQzXcUXUrqF7bykQ7ACiWFyZdT2HcptF1zd1t7NhfQSdqrbPEjZceg7"
          }
        ]
      }
    ]
  }
}"##;

/// OpenID4VCI 1.0 §8.3.
pub(super) const CREDENTIAL_RESPONSE_ONE: &str = r##"{
  "credentials": [
    {
      "credential": "LUpixVCWJk0eOt4CXQe1NXK....WZwmhmn9OQp6YxX0a2L"
    }
  ]
}"##;

/// OpenID4VCI 1.0 §8.3.
pub(super) const CREDENTIAL_RESPONSE_MULTI: &str = r##"{
  "credentials": [
    {
      "credential": "LUpixVCWJk0eOt4CXQe1NXK....WZwmhmn9OQp6YxX0a2L"
    },
    {
      "credential": "YXNkZnNhZGZkamZqZGFza23....29tZTIzMjMyMzIzMjMy"
    }
  ],
  "notification_id": "3fwe98js"
}"##;

/// OpenID4VCI 1.0 §8.3.
pub(super) const CREDENTIAL_RESPONSE_DEFERRED: &str = r##"{
  "transaction_id": "8xLOxBtZp8",
  "interval" : 3600
}"##;

/// OpenID4VCI 1.0 §8.3.1.2.
pub(super) const CREDENTIAL_ERROR: &str = r##"{
  "error": "unknown_credential_configuration"
}"##;

/// OpenID4VCI 1.0 §9.1.
pub(super) const DEFERRED_REQUEST: &str = r##"{
  "transaction_id": "8xLOxBtZp8"
}"##;

/// OpenID4VCI 1.0 §9.2.
pub(super) const DEFERRED_RESPONSE: &str = r##"{
  "credentials": [
    {
      "credential": "LUpixVCWJk0eOt4CXQe1NXK....WZwmhmn9OQp6YxX0a2L"
    },
    {
      "credential": "YXNkZnNhZGZkamZqZGFza23....29tZTIzMjMyMzIzMjMy"
    }
  ],
  "notification_id": "3fwe98js"
}"##;

/// OpenID4VCI 1.0 §9.2.
pub(super) const DEFERRED_RESPONSE_PENDING: &str = r##"{
  "transaction_id": "8xLOxBtZp8",
  "interval": 86400
}"##;

/// OpenID4VCI 1.0 §9.3.
pub(super) const DEFERRED_ERROR: &str = r##"{
  "error": "invalid_transaction_id"
}"##;

/// OpenID4VCI 1.0 §11.1.
pub(super) const NOTIFICATION_ACCEPTED: &str = r##"{
  "notification_id": "3fwe98js",
  "event": "credential_accepted"
}"##;

/// OpenID4VCI 1.0 §11.1.
pub(super) const NOTIFICATION_FAILURE: &str = r##"{
  "notification_id": "3fwe98js",
  "event": "credential_failure",
  "event_description": "Could not store the Credential. Out of storage."
}"##;

/// OpenID4VCI 1.0 §11.3.
pub(super) const NOTIFICATION_ERROR: &str = r##"{
  "error": "invalid_notification_id"
}"##;

/// OpenID4VCI 1.0 §12.2.4.
pub(super) const CONFIGS_SD_JWT: &str = r##"{
  "credential_configurations_supported": {
    "SD_JWT_VC_example_in_OpenID4VCI": {
      "format": "dc+sd-jwt",
      "scope": "SD_JWT_VC_example_in_OpenID4VCI",
      "cryptographic_binding_methods_supported": [
        "jwk"
      ],
      "credential_signing_alg_values_supported": [
        "ES256"
      ],
      "proof_types_supported": {
        "jwt": {
          "proof_signing_alg_values_supported": [
            "ES256"
          ],
          "key_attestations_required": {
            "key_storage": [ "iso_18045_moderate" ],
            "user_authentication": [ "iso_18045_moderate" ]
          }
        }
      },
      "vct": "SD_JWT_VC_example_in_OpenID4VCI",
      "credential_metadata": {
        "display": [
          {
            "name": "IdentityCredential",
            "logo": {
              "uri": "https://university.example.edu/public/logo.png",
              "alt_text": "a square logo of a university"
            },
            "locale": "en-US",
            "background_color": "#12107c",
            "text_color": "#FFFFFF"
          }
        ],
        "claims": [
          {
            "path": ["given_name"],
            "display": [
              {
                "name": "Given Name",
                "locale": "en-US"
              },
              {
                "name": "Vorname",
                "locale": "de-DE"
              }
            ]
          },
          {
            "path": ["family_name"],
            "display": [
              {
                "name": "Surname",
                "locale": "en-US"
              },
              {
                "name": "Nachname",
                "locale": "de-DE"
              }
            ]
          },
          {"path": ["email"]},
          {"path": ["phone_number"]},
          {
            "path": ["address"],
            "display": [
              {
                "name": "Place of residence",
                "locale": "en-US"
              },
              {
                "name": "Wohnsitz",
                "locale": "de-DE"
              }
            ]
          },
          {"path": ["address", "street_address"]},
          {"path": ["address", "locality"]},
          {"path": ["address", "region"]},
          {"path": ["address", "country"]},
          {"path": ["birthdate"]},
          {"path": ["is_over_18"]},
          {"path": ["is_over_21"]},
          {"path": ["is_over_65"]}
        ]
      }
    }
  }
}"##;

/// OpenID4VCI 1.0 A.1.1.2.
pub(super) const CONFIGS_JWT_VC_JSON: &str = r##"{
  "credential_configurations_supported": {
    "UniversityDegreeCredential": {
      "format": "jwt_vc_json",
      "scope": "UniversityDegree",
      "cryptographic_binding_methods_supported": [
        "did:example"
      ],
      "credential_signing_alg_values_supported": [
        "ES256"
      ],
      "credential_definition": {
        "type": [
          "VerifiableCredential",
          "UniversityDegreeCredential"
        ]
      },
      "proof_types_supported": {
        "jwt": {
          "proof_signing_alg_values_supported": [
            "ES256"
          ]
        }
      },
      "credential_metadata": {
        "claims": [
          {
            "path": ["credentialSubject", "given_name"],
            "display": [
              {
                "name": "Given Name",
                "locale": "en-US"
              }
            ]
          },
          {
            "path": ["credentialSubject", "family_name"],
            "display": [
              {
                "name": "Surname",
                "locale": "en-US"
              }
            ]
          },
          {"path": ["credentialSubject", "degree"]},
          {
            "path": ["credentialSubject", "gpa"],
            "mandatory": true,
            "display": [
              {
                "name": "GPA"
              }
            ]
          }
        ],
        "display": [
          {
            "name": "University Credential",
            "locale": "en-US",
            "logo": {
              "uri": "https://university.example.edu/public/logo.png",
              "alt_text": "a square logo of a university"
            },
            "background_color": "#12107c",
            "text_color": "#FFFFFF"
          }
        ]
      }
    }
  }
}"##;

/// OpenID4VCI 1.0 A.1.1.4.
pub(super) const CREDENTIAL_RESPONSE_JWT_VC_JSON: &str = r##"{
  "credentials": [
    {
      "credential": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6InVybjppZXRmOnBhcmFtczpvYXV0aDpqd2stdGh1bWJwcmludDpzaGEtMjU2Om1sVXBvZzd2RWV3RkJlbTZVbDA5YzJkdFR3YzhkRnpWcElEWDNzcUdXVzAifQ.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sImlkIjoiaHR0cHM6Ly9jcmVkZW50aWFsLWlzc3Vlci5leGFtcGxlLmNvbS9jcmVkZW50aWFscy8zNzMyIiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlVuaXZlcnNpdHlEZWdyZWVDcmVkZW50aWFsIl0sImlzc3VlciI6Imh0dHBzOi8vY3JlZGVudGlhbC1pc3N1ZXIuZXhhbXBsZS5jb20iLCJpc3N1YW5jZURhdGUiOiIyMDI1LTAxLTAxVDAwOjAwOjAwWiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmp3azpleUpyYVdRaU9pSjFjbTQ2YVdWMFpqcHdZWEpoYlhNNmIyRjFkR2c2YW5kckxYUm9kVzFpY0hKcGJuUTZjMmhoTFRJMU5qcFdZa3BQVTNacWVGVTJURGhETjBkVlR6UmtjMmhKV1ZZemVtSjJSbmRyV1VJME0xbEtOVXQwZERoRklpd2lhM1I1SWpvaVJVTWlMQ0pqY25ZaU9pSlFMVEkxTmlJc0ltRnNaeUk2SWtWVE1qVTJJaXdpZUNJNklrMWtReTFQUzNFMFFWRktabFpEV0RWNmNGRnZURGhxTkZaRlpuWlFXRGs0ZEZVNWFIaGpUbGhIY204aUxDSjVJam9pYm5OWGJtWmlOazVYYzBzek9VSklMV2hCWVZOclExTmxORUo1YldWT2MyTktSVjl6WVVRelJETmlUU0o5IiwiZGVncmVlIjp7InR5cGUiOiJCYWNoZWxvckRlZ3JlZSIsIm5hbWUiOiJCYWNoZWxvciBvZiBTY2llbmNlIGFuZCBBcnRzIn19fSwiaXNzIjoiaHR0cHM6Ly9jcmVkZW50aWFsLWlzc3Vlci5leGFtcGxlLmNvbSIsIm5iZiI6MTczNTY4OTYwMCwianRpIjoiaHR0cHM6Ly9jcmVkZW50aWFsLWlzc3Vlci5leGFtcGxlLmNvbS9jcmVkZW50aWFscy8zNzMyIiwic3ViIjoiZGlkOmp3azpleUpyYVdRaU9pSjFjbTQ2YVdWMFpqcHdZWEpoYlhNNmIyRjFkR2c2YW5kckxYUm9kVzFpY0hKcGJuUTZjMmhoTFRJMU5qcFdZa3BQVTNacWVGVTJURGhETjBkVlR6UmtjMmhKV1ZZemVtSjJSbmRyV1VJME0xbEtOVXQwZERoRklpd2lhM1I1SWpvaVJVTWlMQ0pqY25ZaU9pSlFMVEkxTmlJc0ltRnNaeUk2SWtWVE1qVTJJaXdpZUNJNklrMWtReTFQUzNFMFFWRktabFpEV0RWNmNGRnZURGhxTkZaRlpuWlFXRGs0ZEZVNWFIaGpUbGhIY204aUxDSjVJam9pYm5OWGJtWmlOazVYYzBzek9VSklMV2hCWVZOclExTmxORUo1YldWT2MyTktSVjl6WVVRelJETmlUU0o5In0.k13xQCnQIKAIuwQIbg37dwlNr8D6_2YUQtDTVQCq-ZsjcXxHagGC_VIZtd7RpR8OvBzTBHVwrBRD-_RzoV2Ofg"
    }
  ]
}"##;

/// OpenID4VCI 1.0 A.1.2.2.
pub(super) const CONFIGS_LDP_VC: &str = r##"{
  "credential_configurations_supported": {
    "UniversityDegree_LDP_VC": {
      "format": "ldp_vc",
      "cryptographic_binding_methods_supported": [
        "did:example"
      ],
      "credential_signing_alg_values_supported": [
        "Ed25519Signature2018"
      ],
      "credential_definition": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "type": [
          "VerifiableCredential",
          "UniversityDegreeCredential"
        ]
      },
      "credential_metadata": {
        "claims": [
          {
            "path": ["credentialSubject", "given_name"],
            "display": [
              {
                "name": "Given Name",
                "locale": "en-US"
              }
            ]
          },
          {
            "path": ["credentialSubject", "family_name"],
            "display": [
              {
                "name": "Surname",
                "locale": "en-US"
              }
            ]
          },
          {
            "path": ["credentialSubject", "degree"]
          },
          {
            "path": ["credentialSubject", "gpa"],
            "mandatory": true,
            "display": [
              {
                "name": "GPA"
              }
            ]
          }
        ],
        "display": [
          {
            "name": "University Credential",
            "locale": "en-US",
            "logo": {
              "uri": "https://university.example.edu/public/logo.png",
              "alt_text": "a square logo of a university"
            },
            "background_color": "#12107c",
            "text_color": "#FFFFFF"
          }
        ]
      }
    }
  }
}"##;

/// OpenID4VCI 1.0 A.1.2.4.
pub(super) const CREDENTIAL_RESPONSE_LDP_VC: &str = r##"{
  "credentials": [
    {
      "credential": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": "http://example.edu/credentials/3732",
        "type": [
          "VerifiableCredential",
          "UniversityDegreeCredential"
        ],
        "issuer": "https://example.edu/issuers/565049",
        "issuanceDate": "2010-01-01T00:00:00Z",
        "credentialSubject": {
          "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
          "degree": {
            "type": "BachelorDegree",
            "name": "Bachelor of Science and Arts"
          }
        },
        "proof": {
          "type": "Ed25519Signature2020",
          "created": "2022-02-25T14:58:43Z",
          "verificationMethod": "https://example.edu/issuers/565049#key-1",
          "proofPurpose": "assertionMethod",
          "proofValue": "zeEdUoM7m9cY8ZyTpey83yBKeBcmcvbyrEQzJ19rD2UXArU2U1jPGoEtrRvGYppdiK37GU4NBeoPakxpWhAvsVSt"
        }
      }
    }
  ]
}"##;

/// OpenID4VCI 1.0 A.2.2.
pub(super) const CONFIGS_MSO_MDOC: &str = r##"{
  "credential_configurations_supported": {
    "org.iso.18013.5.1.mDL": {
      "format": "mso_mdoc",
      "doctype": "org.iso.18013.5.1.mDL",
      "cryptographic_binding_methods_supported": [
        "cose_key"
      ],
      "credential_signing_alg_values_supported": [
        -7, -9
      ],
      "credential_metadata": {
        "display": [
          {
            "name": "Mobile Driving License",
            "locale": "en-US",
            "logo": {
              "uri": "https://state.example.org/public/mdl.png",
              "alt_text": "state mobile driving license"
            },
            "background_color": "#12107c",
            "text_color": "#FFFFFF"
          },
          {
            "name": "モバイル運転免許証",
            "locale": "ja-JP",
            "logo": {
              "uri": "https://state.example.org/public/mdl.png",
              "alt_text": "米国州発行のモバイル運転免許証"
            },
            "background_color": "#12107c",
            "text_color": "#FFFFFF"
          }
        ],
        "claims": [
          {
            "path": ["org.iso.18013.5.1", "given_name"],
            "display": [
              {
                "name": "Given Name",
                "locale": "en-US"
              },
              {
                "name": "名前",
                "locale": "ja-JP"
              }
            ]
          },
          {
            "path": ["org.iso.18013.5.1", "family_name"],
            "display": [
              {
                "name": "Surname",
                "locale": "en-US"
              }
            ]
          },
          {
            "path": ["org.iso.18013.5.1", "birth_date"],
            "mandatory": true
          },
          {"path": ["org.iso.18013.5.1.aamva", "organ_donor"]}
        ]
      }
    }
  }
}"##;

/// OpenID4VCI 1.0 A.2.4.
pub(super) const CREDENTIAL_RESPONSE_MSO_MDOC: &str = r##"{
  "credentials": [
    {
      "credential": "omppc3N1ZXJBdXRohEOhASahG...ArQwggKwMIICVqADAgEC"
    }
  ]
}"##;

/// OpenID4VCI 1.0 A.3.2.
pub(super) const CONFIGS_DC_SD_JWT: &str = r##"{
  "credential_configurations_supported": {
    "SD_JWT_VC_example_in_OpenID4VCI": {
      "format": "dc+sd-jwt",
      "scope": "SD_JWT_VC_example_in_OpenID4VCI",
      "cryptographic_binding_methods_supported": [
        "jwk"
      ],
      "credential_signing_alg_values_supported": [
        "ES256"
      ],
      "proof_types_supported": {
        "jwt": {
          "proof_signing_alg_values_supported": [
            "ES256"
          ],
          "key_attestations_required": {
            "key_storage": [ "iso_18045_moderate" ],
            "user_authentication": [ "iso_18045_moderate" ]
          }
        }
      },
      "vct": "SD_JWT_VC_example_in_OpenID4VCI",
      "credential_metadata": {
        "display": [
          {
            "name": "IdentityCredential",
            "logo": {
              "uri": "https://university.example.edu/public/logo.png",
              "alt_text": "a square logo of a university"
            },
            "locale": "en-US",
            "background_color": "#12107c",
            "text_color": "#FFFFFF"
          }
        ],
        "claims": [
          {
            "path": ["given_name"],
            "display": [
              {
                "name": "Given Name",
                "locale": "en-US"
              },
              {
                "name": "Vorname",
                "locale": "de-DE"
              }
            ]
          },
          {
            "path": ["family_name"],
            "display": [
              {
                "name": "Surname",
                "locale": "en-US"
              },
              {
                "name": "Nachname",
                "locale": "de-DE"
              }
            ]
          },
          {"path": ["email"]},
          {"path": ["phone_number"]},
          {
            "path": ["address"],
            "display": [
              {
                "name": "Place of residence",
                "locale": "en-US"
              },
              {
                "name": "Wohnsitz",
                "locale": "de-DE"
              }
            ]
          },
          {"path": ["address", "street_address"]},
          {"path": ["address", "locality"]},
          {"path": ["address", "region"]},
          {"path": ["address", "country"]},
          {"path": ["birthdate"]},
          {"path": ["is_over_18"]},
          {"path": ["is_over_21"]},
          {"path": ["is_over_65"]}
        ]
      }
    }
  }
}"##;

/// OpenID4VCI 1.0 A.3.4.
pub(super) const CREDENTIAL_RESPONSE_DC_SD_JWT: &str = r##"{
  "credentials": [
    {
      "credential": "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRjK3NkLWp3dCIsICJraWQiOiAiZG9jLXNpZ25lci0wNS0yNS0yMDIyIn0.eyJfc2QiOiBbIjA5dktySk1PbHlUV00wc2pwdV9wZE9CVkJRMk0xeTNLaHBINTE1blhrcFkiLCAiMnJzakdiYUMwa3k4bVQwcEpyUGlvV1RxMF9kYXcxc1g3NnBvVWxnQ3diSSIsICJFa084ZGhXMGRIRUpidlVIbEVfVkNldUM5dVJFTE9pZUxaaGg3WGJVVHRBIiwgIklsRHpJS2VpWmREd3BxcEs2WmZieXBoRnZ6NUZnbldhLXNONndxUVhDaXciLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiamRyVEU4WWNiWTRFaWZ1Z2loaUFlX0JQZWt4SlFaSUNlaVVRd1k5UXF4SSIsICJqc3U5eVZ1bHdRUWxoRmxNXzNKbHpNYVNGemdsaFFHMERwZmF5UXdMVUs0Il0sICJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiaWF0IjogMTY4MzAwMDAwMCwgImV4cCI6IDE4ODMwMDAwMDAsICJ2Y3QiOiAiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIiwgIl9zZF9hbGciOiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIlRDQUVSMTladnUzT0hGNGo0VzR2ZlNWb0hJUDFJTGlsRGxzN3ZDZUdlbWMiLCAieSI6ICJaeGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1ZWNDRTZ0NGpUOUYySFpRIn19fQ.dVjA0sh4xGD32uPqc9h4WHiEL3A08kiKNE08IIrtn3PJvljLU7n19LBTtuzPFZoc_GoPuS97SIDbz96K8pkZew~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImlzX292ZXJfMTgiLCB0cnVlXQ~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgImlzX292ZXJfMjEiLCB0cnVlXQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImlzX292ZXJfNjUiLCB0cnVlXQ~"
    }
  ]
}"##;

/// OpenID4VCI 1.0 F.1.
pub(super) const PROOFS_JWT: &str = r##"{
  "jwt": [
    "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiblVXQW9BdjNYWml0aDhFN2kxOU9kYXhPTFlGT3dNLVoyRXVNMDJUaXJUNCIsInkiOiJIc2tIVThCalVpMVU5WHFpN1N3bWo4Z3dBS18weGtjRGpFV183MVNvc0VZIn19.eyJhdWQiOiJodHRwczovL2NyZWRlbnRpYWwtaXNzdWVyLmV4YW1wbGUuY29tIiwiaWF0IjoxNzAxOTYwNDQ0LCJub25jZSI6IkxhclJHU2JtVVBZdFJZTzZCUTR5bjgifQ.-a3EDsxClUB4O3LeDD5DVGEnNMT01FCQW4P6-2-BNBqc_Zxf0Qw4CWayLEpqkAomlkLb9zioZoipdP-jvh1WlA"
  ]
}"##;

/// OpenID4VCI 1.0 F.2.
pub(super) const PROOFS_DI_VP: &str = r##"{
  "di_vp": [
    {
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://www.w3.org/ns/credentials/examples/v2"
      ],
      "type": [
        "VerifiablePresentation"
      ],
      "holder": "did:key:z6MkvrFpBNCoYewiaeBLgjUDvLxUtnK5R6mqh5XPvLsrPsro",
      "proof": [
        {
          "type": "DataIntegrityProof",
          "cryptosuite": "eddsa-2022",
          "proofPurpose": "authentication",
          "verificationMethod": "did:key:z6MkvrFpBNCoYewiaeBLgjUDvLxUtnK5R6mqh5XPvLsrPsro#z6MkvrFpBNCoYewiaeBLgjUDvLxUtnK5R6mqh5XPvLsrPsro",
          "created": "2023-03-01T14:56:29.280619Z",
          "challenge": "82d4cb36-11f6-4273-b9c6-df1ac0ff17e9",
          "domain": "did:web:audience.company.com",
          "proofValue": "z5hrbHzZiqXHNpLq6i7zePEUcUzEbZKmWfNQzXcUXUrqF7bykQ7ACiWFyZdT2HcptF1zd1t7NhfQSdqrbPEjZceg7"
        }
      ]
    }
  ]
}"##;

/// OpenID4VCI 1.0 F.3.
pub(super) const PROOFS_ATTESTATION: &str = r##"{
  "attestation": [
    "<key attestation in JWT format>"
  ]
}"##;

/// OpenID4VCI 1.0 Appendix I.1.
pub(super) const ISSUER_METADATA: &str = r##"{
  "credential_issuer": "https://credential-issuer.example.com",
  "authorization_servers": [
    "https://server.example.com"
  ],
  "credential_endpoint": "https://credential-issuer.example.com/credential",
  "nonce_endpoint": "https://credential-issuer.example.com/nonce",
  "deferred_credential_endpoint": "https://credential-issuer.example.com/deferred_credential",
  "notification_endpoint": "https://credential-issuer.example.com/notification",
  "credential_request_encryption": {
    "jwks": [
      {
        "kty":"EC", "kid":"ac", "use":"enc", "crv":"P-256", "alg":"ECDH-ES",
        "x":"YO4epjifD-KWeq1sL2tNmm36BhXnkJ0He-WqMYrp9Fk",
        "y":"Hekpm0zfK7C-YccH5iBjcIXgf6YdUvNUac_0At55Okk"
      }
    ],
    "enc_values_supported": ["A128GCM"],
    "zip_values_supported": ["DEF"],
    "encryption_required": true
  },
  "credential_response_encryption": {
    "alg_values_supported": ["ECDH-ES"],
    "enc_values_supported": ["A128GCM"],
    "zip_values_supported": ["DEF"],
    "encryption_required": true
  },
  "batch_credential_issuance": {
    "batch_size": 10
  },
  "display": [
    {
      "name": "Example University",
      "locale": "en-US",
      "logo": {
        "uri": "https://university.example.edu/public/logo.png",
        "alt_text":"a square logo of a university"
      }
    },
    {
      "name": "Example Université",
      "locale": "fr-FR",
      "logo": {
        "uri": "https://university.example.edu/public/logo.png",
        "alt_text":"Un logo universitaire carré"
      }
    }
  ],
  "credential_configurations_supported": {
    "SD_JWT_VC_example_in_OpenID4VCI": {
      "format": "dc+sd-jwt",
      "scope": "SD_JWT_VC_example_in_OpenID4VCI",
      "credential_signing_alg_values_supported": ["ES256"],
      "cryptographic_binding_methods_supported": ["jwk"],
      "proof_types_supported": {
        "jwt": {
          "proof_signing_alg_values_supported": ["ES256"],
          "key_attestations_required": {
            "key_storage": ["iso_18045_moderate"],
            "user_authentication": ["iso_18045_moderate"]
          }
        }
      },
      "vct": "SD_JWT_VC_example_in_OpenID4VCI",
      "credential_metadata": {
        "display": [
          {
            "name": "IdentityCredential",
            "locale": "en-US",
            "logo": {
              "uri": "https://university.example.edu/public/logo_credential.png",
              "alt_text": "a square logo of a university credential"
            },
            "description": "A credential that signals the membership of a university",
            "background_color": "#12107c",
            "text_color": "#FFFFFF"
          }
        ],
        "claims": [
          {
            "path": ["given_name"],
            "display": [
              {
                "name": "Given Name",
                "locale": "en-US"
              },
              {
                "name": "Vorname",
                "locale": "de-DE"
              }
            ]
          },
          {
            "path": ["family_name"],
            "display": [
              {
                "name": "Surname",
                "locale": "en-US"
              },
              {
                "name": "Nachname",
                "locale": "de-DE"
              }
            ]
          },
          {"path": ["email"]},
          {"path": ["phone_number"]},
          {
            "path": ["address"],
            "display": [
              {
                "name": "Place of residence",
                "locale": "en-US"
              },
              {
                "name": "Wohnsitz",
                "locale": "de-DE"
              }
            ]
          },
          {"path": ["address", "street_address"]},
          {"path": ["address", "locality"]},
          {"path": ["address", "region"]},
          {"path": ["address", "country"]},
          {"path": ["birthdate"]},
          {"path": ["is_over_18"]},
          {"path": ["is_over_21"]},
          {"path": ["is_over_65"]}
        ]
      }
    }
  }
}"##;

/// OpenID4VCI 1.0 Appendix I.1 (signed Credential Issuer Metadata).
pub(super) const SIGNED_ISSUER_METADATA: &str = "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9wZW5pZHZjaS1pc3N1ZXItbWV0YWRhdGErand0IiwieDVjIjpbIk1JSUI5RENDQVpxZ0F3SUJBZ0lVRkFIcFd2VjdOR1J4T05JSFQvQ0N3RUU5QmE0d0NnWUlLb1pJemowRUF3SXdLREVtTUNRR0ExVUVBd3dkWTNKbFpHVnVkR2xoYkMxcGMzTjFaWEl1WlhoaGJYQnNaUzVqYjIwd0lCY05NalV3TnpJeU1EZ3lPREEyV2hnUE1qQTFOVEEzTVRVd09ESTRNRFphTUNneEpqQWtCZ05WQkFNTUhXTnlaV1JsYm5ScFlXd3RhWE56ZFdWeUxtVjRZVzF3YkdVdVkyOXRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVsSG50aWhHdTV2Q3RrWituMllhQ28rdW5ubndrd2xVUHBUc25PMk9TdnpvVHNYdGQxazE4WWhBUGhPTjYvbERXei9mN0FNcmRWN0xNZ0JZU3BwMndKS09CbnpDQm5EQWRCZ05WSFE0RUZnUVVhTWo0bmEvUWpjdHA3V2dyR2xxam0zUFQxU2t3SHdZRFZSMGpCQmd3Rm9BVWFNajRuYS9RamN0cDdXZ3JHbHFqbTNQVDFTa3dEd1lEVlIwVEFRSC9CQVV3QXdFQi96QkpCZ05WSFJFRVFqQkFnaDFqY21Wa1pXNTBhV0ZzTFdsemMzVmxjaTVsZUdGdGNHeGxMbU52YllJZktpNWpjbVZrWlc1MGFXRnNMV2x6YzNWbGNpNWxlR0Z0Y0d4bExtTnZiVEFLQmdncWhrak9QUVFEQWdOSUFEQkZBaUJMWjNuTGhMT1diR2hBTGNSUHhQTGlIdFV1bGRqRFQ0MUZrOTBUand5MEpRSWhBT3NtWXpTcHNGenBqTjBPV1R2UEV5dURrL05nUnVmSjNkRGFnOHNaSjZkTSJdfQ.eyJzdWIiOiJodHRwczovL2NyZWRlbnRpYWwtaXNzdWVyLmV4YW1wbGUuY29tIiwiaWF0IjoxNTE2MjM5MDIyLCJjcmVkZW50aWFsX2lzc3VlciI6Imh0dHBzOi8vY3JlZGVudGlhbC1pc3N1ZXIuZXhhbXBsZS5jb20iLCJhdXRob3JpemF0aW9uX3NlcnZlcnMiOlsiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iXSwiY3JlZGVudGlhbF9lbmRwb2ludCI6Imh0dHBzOi8vY3JlZGVudGlhbC1pc3N1ZXIuZXhhbXBsZS5jb20vY3JlZGVudGlhbCIsImRlZmVycmVkX2NyZWRlbnRpYWxfZW5kcG9pbnQiOiJodHRwczovL2NyZWRlbnRpYWwtaXNzdWVyLmV4YW1wbGUuY29tL2RlZmVycmVkX2NyZWRlbnRpYWwiLCJjcmVkZW50aWFsX3Jlc3BvbnNlX2VuY3J5cHRpb24iOnsiYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRUNESC1FUyJdLCJlbmNfdmFsdWVzX3N1cHBvcnRlZCI6WyJBMTI4R0NNIl0sImVuY3J5cHRpb25fcmVxdWlyZWQiOmZhbHNlfSwiZGlzcGxheSI6W3sibmFtZSI6IkV4YW1wbGUgVW5pdmVyc2l0eSIsImxvY2FsZSI6ImVuLVVTIn0seyJuYW1lIjoiRXhhbXBsZSBVbml2ZXJzaXTDqSIsImxvY2FsZSI6ImZyLUZSIn1dLCJjcmVkZW50aWFsX2NvbmZpZ3VyYXRpb25zX3N1cHBvcnRlZCI6eyJTRF9KV1RfVkNfZXhhbXBsZV9pbl9PcGVuSUQ0VkNJIjp7ImZvcm1hdCI6ImRjK3NkLWp3dCIsInNjb3BlIjoiU0RfSldUX1ZDX2V4YW1wbGVfaW5fT3BlbklENFZDSSIsImNyeXB0b2dyYXBoaWNfYmluZGluZ19tZXRob2RzX3N1cHBvcnRlZCI6WyJqd2siXSwiY3JlZGVudGlhbF9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIkVTMjU2Il0sInByb29mX3R5cGVzX3N1cHBvcnRlZCI6eyJqd3QiOnsicHJvb2Zfc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJFUzI1NiJdLCJrZXlfYXR0ZXN0YXRpb25zX3JlcXVpcmVkIjp7ImtleV9zdG9yYWdlIjpbImlzb18xODA0NV9tb2RlcmF0ZSJdLCJ1c2VyX2F1dGhlbnRpY2F0aW9uIjpbImlzb18xODA0NV9tb2RlcmF0ZSJdfX19LCJ2Y3QiOiJTRF9KV1RfVkNfZXhhbXBsZV9pbl9PcGVuSUQ0VkNJIiwiY3JlZGVudGlhbF9tZXRhZGF0YSI6eyJkaXNwbGF5IjpbeyJuYW1lIjoiSWRlbnRpdHlDcmVkZW50aWFsIiwibG9nbyI6eyJ1cmkiOiJodHRwczovL3VuaXZlcnNpdHkuZXhhbXBsZS5lZHUvcHVibGljL2xvZ28ucG5nIiwiYWx0X3RleHQiOiJhIHNxdWFyZSBsb2dvIG9mIGEgdW5pdmVyc2l0eSJ9LCJsb2NhbGUiOiJlbi1VUyIsImJhY2tncm91bmRfY29sb3IiOiIjMTIxMDdjIiwidGV4dF9jb2xvciI6IiNGRkZGRkYifV0sImNsYWltcyI6W3sicGF0aCI6WyJnaXZlbl9uYW1lIl0sImRpc3BsYXkiOlt7Im5hbWUiOiJHaXZlbiBOYW1lIiwibG9jYWxlIjoiZW4tVVMifSx7Im5hbWUiOiJWb3JuYW1lIiwibG9jYWxlIjoiZGUtREUifV19LHsicGF0aCI6WyJmYW1pbHlfbmFtZSJdLCJkaXNwbGF5IjpbeyJuYW1lIjoiU3VybmFtZSIsImxvY2FsZSI6ImVuLVVTIn0seyJuYW1lIjoiTmFjaG5hbWUiLCJsb2NhbGUiOiJkZS1ERSJ9XX0seyJwYXRoIjpbImVtYWlsIl19LHsicGF0aCI6WyJwaG9uZV9udW1iZXIiXX0seyJwYXRoIjpbImFkZHJlc3MiXSwiZGlzcGxheSI6W3sibmFtZSI6IlBsYWNlIG9mIHJlc2lkZW5jZSIsImxvY2FsZSI6ImVuLVVTIn0seyJuYW1lIjoiV29obnNpdHoiLCJsb2NhbGUiOiJkZS1ERSJ9XX0seyJwYXRoIjpbImFkZHJlc3MiLCJzdHJlZXRfYWRkcmVzcyJdfSx7InBhdGgiOlsiYWRkcmVzcyIsImxvY2FsaXR5Il19LHsicGF0aCI6WyJhZGRyZXNzIiwicmVnaW9uIl19LHsicGF0aCI6WyJhZGRyZXNzIiwiY291bnRyeSJdfSx7InBhdGgiOlsiYmlydGhkYXRlIl19LHsicGF0aCI6WyJpc19vdmVyXzE4Il19LHsicGF0aCI6WyJpc19vdmVyXzIxIl19LHsicGF0aCI6WyJpc19vdmVyXzY1Il19XX19fX0.KkM97TGKU9yTAPnbTfSPVFT3RywX9_5QPEtNwMhiu8V_UPBGMYA2mkVc-VxGTm9vdeV482-TWnVfbub_kzS9Eg";

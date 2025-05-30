# Affinidi DID Authentication

## 29th May 2025 (0.1.10)

* **MAINTENANCE:** Updated crate dependencies (SSI Crate 0.10 --> 0.11)

## 3rd May 2025 (0.1.9)

* **FIX:** building the refresh HTTP request was incorrectly using the DID and
not the REST API URL
* **FIX:** Refresh was using wrong DIDComm message type
* **FIX:** Debug log message could cause a panic in the authentication task due
to a negative `u64` value

## 2nd May 2025 (0.1.8)

* **FEATURE:** Adding improved debug messaging for troubleshooting of refreshing
auth credentials
* **FEATURE:** Splitting refresh logic to be more granular so that `tdk-common`
authentication task
has improved handling of refresh logic
* **FEATURE:** Added unit tests for token expiry

## 22nd April 2025 (0.1.7)

* Improved logging of error when no auth service is found

## 24th March 2025 Release 0.1.6

* Implemented caching expiry for AuthenticationRecords

## Release 0.1.0

* Initial release of crate

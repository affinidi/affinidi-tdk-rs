# Meeting Place Changelog

## 18th December 2025 (0.2.2)

- **CHORE:** Updating dependencies

## 3rd November 2025 (0.2.1)

- **CHORE:** Updating dependencies

## 30th September 2025 (0.2.0)

- **BREAKING:** Removed SSI Library dependencies

## 29th May 2025 (0.1.10)

- **MAINTENANCE:** Updating dependencies (mainly SSI crate)
- **UPDATE:** Meeting Place API changed, requiring mediator DID to be specified

## 3rd May 2025 (0.1.9)

- **MAINTENANCE:** Updating dependencies, especially due to changes with DID
  authentication

## 16th April 2025 (0.1.8)

- Removed hardcoded API endpoint for MPX
  - Will derive the API endpoint from the DID (#api), otherwise will fail back to
    the default MPX API

## 29th March 2025 (0.1.7)

- **FEATURE:** MeetingPlace API's added
  - query-offer
  - check-offer
  - register-offer
  - deregister-offer

## Release 0.1.0

- Initial release of crate

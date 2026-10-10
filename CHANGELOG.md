# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/structured-world/structured-passkeys/releases/tag/v0.1.0) - 2026-10-10

### Added

- *(ctap)* CTAP1/U2F over USB ([#35](https://github.com/structured-world/structured-passkeys/pull/35))
- *(ctap)* credential management and settings ([#23](https://github.com/structured-world/structured-passkeys/pull/23))
- *(ctap)* FIDO_2_0 with the conformance suite ([#22](https://github.com/structured-world/structured-passkeys/pull/22))
- *(ctap)* makeCredential, getAssertion and getNextAssertion ([#21](https://github.com/structured-world/structured-passkeys/pull/21))
- *(nfc)* CTAP over NFC on Stax, Flex and Nano Gen5 ([#20](https://github.com/structured-world/structured-passkeys/pull/20))
- *(ctap)* authenticatorReset and the reset ID ([#16](https://github.com/structured-world/structured-passkeys/pull/16))
- *(app)* the device unlock is built-in UV
- *(ctap)* PIN/UV auth protocols and pinUvAuthToken
- *(ctap)* NVM store for config, index and device keys
- *(app)* say why the selection screen names no website
- *(app)* authenticatorSelection waiting for the user
- *(app)* FIDO HID interface on the device
- *(app)* run the IO stack in the application
- add workspace, device app skeleton and gate

### Fixed

- *(ctap)* hash secrets into caller storage, keep decrypt errors
- *(app)* wipe CBC ciphertext copies, assert PIN rules
- *(ctap)* rp ID for mc/ga, UV status, MAC first
- *(ctap)* consent before built-in UV, wipe requests
- *(app)* settle index entries after every write

### Other

- *(app)* mark a superseded request instead of counting
- *(app)* keepalive cadence follows the OS ticker
- *(deps)* update ledger_device_sdk to 1.38.0
- rename project to Structured Passkeys

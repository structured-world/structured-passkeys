//! FIDO2 / CTAP authenticator logic for Ledger devices.
//!
//! The crate is `no_std` with `alloc` so the device application links it as is; the `std`
//! feature (on by default) is for host users such as tests and tools.
//!
//! - [`ctaphid`]: the USB HID transport (framing, reassembly, channels).
//! - [`nfc`]: the NFC transport (ISO/IEC 7816-4 applet, chaining, status updates).
//! - [`cbor`]: the CTAP2 canonical CBOR encoding.
//! - [`ctap1`]: CTAP1/U2F messages over `CTAPHID_MSG`.
//! - [`ctap2`]: CTAP2 command dispatch, status codes and authenticatorGetInfo.
//! - [`crypto`]: the cryptographic platform the device implements, and HKDF on top of it.
//! - [`pin`]: the PIN/UV auth protocols and the pinUvAuthToken state.
//! - [`storage`]: the NVM regions the device implements, and the consistent state on top of them.
//! - [`ui`]: the screens and the clock a ceremony waits on.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod attestation;
pub mod cbor;
pub mod credential_id;
pub mod crypto;
pub mod ctap1;
pub mod ctap2;
pub mod ctaphid;
pub mod keys;
pub mod nfc;
pub mod pin;
#[cfg(feature = "soft")]
pub mod soft;
pub mod storage;
pub mod ui;

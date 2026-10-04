//! Fuzz target: the NFC applet from arbitrary command APDUs and device actions.

#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../tests/support/nfc_harness.rs"]
mod harness;

fuzz_target!(|data: &[u8]| harness::run(data));

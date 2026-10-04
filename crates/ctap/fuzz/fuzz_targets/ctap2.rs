//! Fuzz target: CTAP2 requests from arbitrary bytes through the authenticator.

#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../tests/support/ctap2_harness.rs"]
mod harness;

fuzz_target!(|data: &[u8]| harness::run(data));

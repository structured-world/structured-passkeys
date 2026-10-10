//! Fuzz target: CTAP1/U2F messages from arbitrary bytes through the authenticator.

#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/ctap1.rs"]
mod harness;

fuzz_target!(|data: &[u8]| harness::run(data));

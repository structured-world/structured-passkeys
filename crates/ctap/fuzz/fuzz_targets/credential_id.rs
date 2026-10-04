//! Fuzz target: opening credential IDs and parsing their authenticated plaintext.

#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/credential_id.rs"]
mod harness;

fuzz_target!(|data: &[u8]| harness::run(data));

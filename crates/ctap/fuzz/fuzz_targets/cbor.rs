//! Fuzz target: CTAP2 canonical CBOR decoding of arbitrary bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/cbor.rs"]
mod harness;

fuzz_target!(|data: &[u8]| harness::run(data));

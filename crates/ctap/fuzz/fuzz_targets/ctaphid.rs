//! Fuzz target: CTAPHID reassembly and framing from arbitrary report sequences.

#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/ctaphid.rs"]
mod harness;

fuzz_target!(|data: &[u8]| harness::run(data));

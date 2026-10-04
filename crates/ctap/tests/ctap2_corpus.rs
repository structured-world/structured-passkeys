//! Regression corpus of the CTAP2 request fuzz target, replayed on the stable toolchain so every
//! input that once mattered (seeds and past findings) keeps passing the harness properties.

#[path = "support/ctap2_harness.rs"]
mod harness;

use std::fs;
use std::path::Path;

/// Every file of `fuzz/corpus/ctap2` passes the harness; an empty corpus is a mistake, not a
/// pass.
#[test]
fn ctap2_corpus_passes_the_harness() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/ctap2");
    let mut count = 0;
    for entry in fs::read_dir(&dir).expect("corpus directory exists") {
        let path = entry.expect("readable corpus entry").path();
        let data = fs::read(&path).expect("readable corpus file");
        harness::run(&data);
        count += 1;
    }
    assert!(count > 0, "no corpus in {}", dir.display());
}

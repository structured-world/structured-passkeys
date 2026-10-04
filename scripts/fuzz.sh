#!/usr/bin/env bash
# Runs every fuzz target of crates/ctap for FUZZ_SECONDS seconds each (default 30), with nightly
# and cargo-fuzz. The corpus of each target is generated here, in crates/ctap/fuzz/corpus/<target>:
# git ignores it, and it carries over between runs on the same machine (CI keeps it in its cache),
# so every run starts where the last one stopped. An input that breaks a harness rule stops the run
# and is left in crates/ctap/fuzz/artifacts/<target>; the defect it shows gets a regression test of
# its own.
set -euo pipefail
cd "$(dirname "$0")/../crates/ctap"

seconds="${FUZZ_SECONDS:-30}"
if [[ ! "$seconds" =~ ^[1-9][0-9]*$ ]]; then
    echo "FUZZ_SECONDS must be a positive number of seconds: '$seconds'" >&2
    exit 1
fi

targets=$(cargo +nightly fuzz list)
if [[ -z "$targets" ]]; then
    echo "no fuzz targets in crates/ctap/fuzz" >&2
    exit 1
fi
for target in $targets; do
    echo "== fuzz $target, ${seconds}s"
    cargo +nightly fuzz run "$target" -- -max_total_time="$seconds"
done

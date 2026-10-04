#!/usr/bin/env bash
# Runs every fuzz target of crates/ctap for FUZZ_SECONDS seconds each (default 30), with the dated
# nightly below and cargo-fuzz (its version is pinned in scripts/check.sh and CI). The corpus of
# each target is generated here, in crates/ctap/fuzz/corpus/<target>:
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

# A dated nightly, so a rerun of the same revision fuzzes with the same compiler and
# instrumentation; installed here when missing, the same way locally and in CI.
toolchain=nightly-2026-09-07
rustup toolchain install "$toolchain" --profile minimal

# cargo-fuzz has no --locked: the fuzz workspace's lockfile is checked first, so cargo-fuzz finds it
# in sync and builds exactly what is committed.
cargo "+$toolchain" metadata --locked --format-version 1 --manifest-path fuzz/Cargo.toml >/dev/null

# cargo-fuzz builds for the target it was itself built for unless told otherwise, and a prebuilt
# cargo-fuzz is a static musl binary on Linux; the targets are built for the toolchain's host.
host=$(rustc "+$toolchain" -vV | awk '/^host:/ { print $2 }')

targets=$(cargo "+$toolchain" fuzz list)
if [[ -z "$targets" ]]; then
    echo "no fuzz targets in crates/ctap/fuzz" >&2
    exit 1
fi
for target in $targets; do
    echo "== fuzz $target, ${seconds}s"
    cargo "+$toolchain" fuzz run --target "$host" "$target" -- -max_total_time="$seconds"
done

#!/usr/bin/env bash
# Mechanical gate run by CI and local checks. Every check that a change must pass
# before review is listed here and nowhere else; a new crate, device target or test
# suite is added to this script in the change that introduces it.
#
# Device builds and their Speculos runs need Ledger's Linux dev-tools image: on Linux they run here, on
# macOS on the Linux check host named by STRUCTURED_PASSKEYS_LINUX
# (scripts/linux/check.sh). Without that host the gate fails instead of
# skipping them.
set -euo pipefail
cd "$(dirname "$0")/.."

# The device crate builds only for Ledger targets, so host checks leave it out.
# --locked: a manifest change without its Cargo.lock update fails here instead of
# being resolved silently in the working tree.
host=(--locked --workspace --exclude structured-passkeys-app --all-features)

run() {
    echo "== $*"
    "$@"
}

# Linters whose verdicts change between releases run at the versions CI installs
# (.github/workflows/check.yml), so a local pass means a CI pass. `pinned LINE CMD...`
# fails unless CMD prints LINE as one of its lines.
pinned() {
    local want=$1
    shift
    if ! "$@" 2>&1 | grep -qxF -- "${want}"; then
        echo "$1: need the version CI uses ('${want}' from '$*')" >&2
        exit 1
    fi
}
pinned "version: 0.11.0" shellcheck --version
pinned "1.7.12" actionlint -version
pinned "cargo-fuzz 0.13.2" cargo fuzz --version

run scripts/check-links.sh
run shellcheck scripts/*.sh scripts/linux/*.sh
# Workflow syntax and expressions, and shellcheck on their `run:` blocks.
run actionlint
run cargo fmt --all --check
run cargo clippy "${host[@]}" --all-targets -- -D warnings
run cargo nextest run "${host[@]}"
run cargo test --doc "${host[@]}"
run cargo build --locked -p structured-passkeys-ctap --target thumbv7em-none-eabihf --no-default-features
# Fuzz targets are their own workspace: they lint on stable, then each runs for a while on
# nightly, growing a corpus that is generated, never committed (scripts/fuzz.sh).
fuzz=(--manifest-path crates/ctap/fuzz/Cargo.toml)
run cargo fmt "${fuzz[@]}" --check
run cargo clippy --locked "${fuzz[@]}" --all-targets -- -D warnings
run scripts/fuzz.sh

# Every device build then runs in Speculos (scripts/speculos-check.sh).
case "$(uname -s)" in
    Linux)
        # The check host script (scripts/linux/check.sh) against a fake host here; on macOS
        # the check host runs it.
        run scripts/linux/check-test.sh
        run scripts/device-build.sh
        run scripts/speculos-check.sh
        ;;
    *)
        if [[ -z "${STRUCTURED_PASSKEYS_LINUX:-}" ]]; then
            echo "device builds need the Linux check host: set STRUCTURED_PASSKEYS_LINUX" >&2
            exit 1
        fi
        run scripts/linux/check.sh speculos
        ;;
esac

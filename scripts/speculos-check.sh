#!/usr/bin/env bash
# Runs every device build of the application in Speculos, inside Ledger's
# dev-tools image, and checks both of its USB interfaces and, on the models
# with NFC, the FIDO applet.
#
# The Ledger APDU channel and the home screen, with Speculos on its HID transport:
#   - BOLOS GET_APP_NAME_AND_VERSION (B0 01) answers the app name and 9000,
#   - an instruction the app does not implement (E0 01) answers exactly 6D00,
#   - the current screen shows the app name.
# The FIDO HID interface, with Speculos on its U2F transport: scripts/fido_check.py
# (INIT, PING up to the 1024-byte message size, getInfo, authenticatorReset in and
# after its window, authenticatorSelection waiting for the user: keepalives, cancel,
# timeout, confirm and refuse, and authenticatorClientPIN; the reset, selection and
# token screens are compared with tests/snapshots/<model>/; SPECULOS_GOLDEN=1 writes
# the snapshots instead).
# The conformance suite, with Speculos on its U2F transport: SoloKeys fido2-tests at a pinned
# commit, patched where CTAP 2.2 differs from the CTAP 2.0 it was written for
# (tests/conformance/fido2-tests.patch, each change with its section), in its own environment
# with the python-fido2 it needs (tests/conformance/requirements.txt), driven by the pytest
# plugin tests/conformance/ledger_speculos.py, which answers the screens. Its CTAP 2.0 tests run
# with the credProtect tests of its CTAP 2.1 part, an extension getInfo lists.
# The FIDO applet over NFC on Stax, Flex and Nano Gen5, with Speculos on its NFC
# transport: scripts/nfc_check.py (selection and deselection of the applet,
# short and extended APDUs, reset, selection by the tap, the consent screen with
# and without status updates, cancel).
#
# Expects the artifacts of scripts/device-build.sh in app/target/<target>/release/.
# Linux only: the image is a Linux container.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
image=$("$root/scripts/dev-tools-image.sh")

# A run of scripts/linux/check.sh names its containers, so stopping it removes them.
name=()
if [[ -n "${CHECK_CONTAINER_PREFIX:-}" ]]; then
    name=(--name "$CHECK_CONTAINER_PREFIX-speculos")
fi

docker pull --quiet "$image" >/dev/null
# The expansion stays nounset-safe for an empty array on Bash before 4.4.
docker run --rm ${name[@]+"${name[@]}"} \
    --volume "$root:/app" \
    --workdir /app \
    --env SPECULOS_GOLDEN="${SPECULOS_GOLDEN:-0}" \
    "$image" bash -c '
        name="Structured Passkeys"
        name_hex=$(printf "%s" "$name" | od -An -tx1 | tr -d " \n")
        # Sends one APDU (hex) and prints the response with its status word; every
        # request has a deadline so an app that never answers fails the check.
        apdu() {
            curl -sf --max-time 10 -X POST -H "Content-Type: application/json" \
                -d "{\"data\":\"$1\"}" http://127.0.0.1:5000/apdu | jq -r ".data // \"\""
        }
        # Starts Speculos for model $1 on transport $2 with ELF $3 and waits for its API;
        # sets pid, and returns non-zero when it did not come up.
        start() {
            speculos --model "$1" --transport "$2" --display headless --api-port 5000 \
                --apdu-port 9999 "$3" >"/tmp/speculos.log" 2>&1 &
            pid=$!
            for _ in $(seq 1 60); do
                if curl -sf --max-time 5 http://127.0.0.1:5000/events >/dev/null; then
                    return 0
                fi
                # Speculos exited during startup: no point waiting out the loop.
                if ! kill -0 "$pid" 2>/dev/null; then
                    break
                fi
                sleep 1
            done
            echo "speculos did not start"
            cat /tmp/speculos.log
            return 1
        }
        stop() {
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        }
        # python-fido2 at the version scripts/fido_check.py declares, in a virtual
        # environment of this container.
        fido2=$(grep -oE "fido2==[0-9.]+" scripts/fido_check.py)
        python3 -m venv /tmp/fido
        /tmp/fido/bin/pip install --quiet "$fido2"
        # The conformance suite at its pinned commit, with its own python-fido2.
        suite=/tmp/fido2-tests
        git clone --quiet https://github.com/solokeys/fido2-tests "$suite"
        git -C "$suite" checkout --quiet 591d3d2279949e08de0766897f24bcfd39af1339
        git -C "$suite" apply --recount /app/tests/conformance/fido2-tests.patch
        python3 -m venv /tmp/conformance
        /tmp/conformance/bin/pip install --quiet -r tests/conformance/requirements.txt
        status=0
        for target in nanosplus nanox stax flex apex_p; do
            case "$target" in
                nanosplus) model=nanosp ;;
                *) model="$target" ;;
            esac
            elf="app/target/$target/release/structured-passkeys-app"
            echo "== speculos $target"
            if [[ ! -f "$elf" ]]; then
                echo "missing $elf"
                status=1
                continue
            fi
            if start "$model" HID "$elf"; then
                data=$(apdu b001000000)
                if [[ "$data" == *"$name_hex"* && "$data" == *9000 ]]; then
                    echo "B0 01: $data"
                else
                    echo "B0 01 failed: \"$data\""
                    status=1
                fi
                # An instruction the app does not implement: ISO/IEC 7816-4 5.6, SW 6D00.
                data=$(apdu e001000000)
                if [[ "$data" == 6d00 ]]; then
                    echo "E0 01: $data"
                else
                    echo "E0 01 failed, expected 6d00: \"$data\""
                    status=1
                fi
                screen=$(curl -sf --max-time 10 "http://127.0.0.1:5000/events?currentscreenonly=true" || true)
                # Nano screens split the name over lines, keeping a trailing space.
                if printf "%s" "$screen" | jq -e --arg n "$name" "[.events[].text] | join(\" \") | gsub(\"\\\\s+\"; \" \") | contains(\$n)" >/dev/null; then
                    echo "home screen shows \"$name\""
                else
                    echo "home screen check failed: $screen"
                    status=1
                fi
            else
                status=1
            fi
            stop
            echo "== speculos $target, FIDO HID"
            if start "$model" U2F "$elf"; then
                golden=()
                if [[ "$SPECULOS_GOLDEN" == 1 ]]; then
                    golden=(--golden)
                fi
                if ! /tmp/fido/bin/python scripts/fido_check.py --speculos --model "$model" \
                    --snapshots tests/snapshots "${golden[@]}"; then
                    cat /tmp/speculos.log
                    status=1
                fi
            else
                status=1
            fi
            stop
            # The plugin starts and restarts Speculos itself: a reboot of the suite is a restart.
            echo "== speculos $target, fido2-tests"
            if ! (cd "$suite" && SPECULOS_MODEL="$model" SPECULOS_ELF="/app/$elf" \
                PYTHONPATH="/app/tests/conformance:$suite" /tmp/conformance/bin/python -m pytest \
                -p ledger_speculos --vendor ledger --timeout 120 -q -rfEs \
                tests/standard/fido2 tests/standard/fido2v1/extensions tests/standard/transport); then
                tail -50 /tmp/speculos-conformance.log
                status=1
            fi
            case "$target" in
                nanosplus | nanox) continue ;;
            esac
            echo "== speculos $target, FIDO over NFC"
            if start "$model" NFC "$elf"; then
                if ! /tmp/fido/bin/python scripts/nfc_check.py --model "$model"; then
                    cat /tmp/speculos.log
                    status=1
                fi
            else
                status=1
            fi
            stop
        done
        exit "$status"
    '

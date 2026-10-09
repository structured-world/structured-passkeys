#!/usr/bin/env bash
# Builds and lints the device application for every Ledger target in Ledger's
# dev-tools image, the image and toolchain Ledger deploys with. Linux only: the
# image is a Linux container.
#
# Each ELF is checked for the C SDK's FIDO HID class and its CTAPHID
# (lib_u2f): the application defines that class itself, so any of those
# symbols means an SDK change brought the C transport back.
#
# Artifacts (ELF, .hex, .apdu, .sha256) land in app/target/<target>/release/.
# The container runs as root, as the image expects; its output is handed back
# to the calling user afterwards, whatever the result.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
image=$("$root/scripts/dev-tools-image.sh")

# A run of scripts/linux/check.sh names its containers, so stopping it removes them.
name=()
if [[ -n "${CHECK_CONTAINER_PREFIX:-}" ]]; then
    name=(--name "$CHECK_CONTAINER_PREFIX-build")
fi

docker pull --quiet "$image" >/dev/null
# The expansion stays nounset-safe for an empty array on Bash before 4.4.
# Without an SELinux label on the container, the mount is usable on a host with
# SELinux enforcing (Podman labels containers there) and the host files keep their labels.
docker run --rm ${name[@]+"${name[@]}"} \
    --security-opt label=disable \
    --volume "$root:/app" \
    --workdir /app/app \
    --env OWNER="$(id -u):$(id -g)" \
    "$image" bash -c '
        status=0
        for target in nanosplus nanox stax flex apex_p; do
            echo "== cargo ledger build $target"
            cargo ledger build "$target" -- --locked || status=1
            echo "== cargo clippy $target"
            cargo clippy --release --locked --target "$target" -- -D warnings || status=1
            echo "== no C FIDO transport in $target"
            elf="target/$target/release/structured-passkeys-app"
            # The class functions and data of usbd_ledger_hid_u2f.c and the lib_u2f transport;
            # USBD_LEDGER_HID_U2F_class_info is the application'"'"'s own.
            c_transport="USBD_LEDGER_HID_U2F_(init|de_init|setup|ep0_rx_ready|data_in|data_out|send_message|is_busy|data_ready|setting)$|LEDGER_HID_U2F_|ledger_hid_u2f_|u2f_transport_|U2F_TRANSPORT_"
            if [[ ! -f "$elf" ]]; then
                echo "missing $elf"
                status=1
            elif ! symbols=$(arm-none-eabi-nm "$elf"); then
                echo "cannot read the symbols of $elf"
                status=1
            elif found=$(grep -E " ($c_transport)" <<<"$symbols"); then
                echo "C FIDO transport linked into $target:"
                echo "$found"
                status=1
            fi
        done
        if [[ -d target ]]; then
            chown -R "$OWNER" target || status=1
        fi
        exit "$status"
    '

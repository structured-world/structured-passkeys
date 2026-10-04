# Structured Passkeys

A FIDO2 / passkey authenticator application for Ledger devices, written in Rust.

- Discoverable credentials (passkeys) that are not silently lost on application updates.
- A key origin chosen on the device for every credential: **device-only** (random, never leaves the
  secure element, reported as single-device) or **seed-recoverable** (reproducible from the recovery
  phrase, reported as backed up).
- CTAP 2.1 with the CTAP 2.2 extensions current relying parties request (`hmac-secret-mc` for the
  WebAuthn PRF extension), credential management, client PIN.
- Encrypted backup and restore of the discoverable index through a host tool.
- Targets: Nano S Plus, Nano X, Stax, Flex, Nano Gen5.

**Status:** implementation in progress.

## FIDO2 on a Ledger device

CTAP describes a dedicated security key that owns its power, its PIN and its storage. A Ledger
device is a wallet running applications, so this application follows CTAP to the letter wherever
the platform sees the result (messages, status codes, getInfo, the order of the steps) and maps the
security key's own mechanics onto the device:

- **User verification is the device unlock.** The person entered the device PIN to unlock the
  device, and a locked device runs no request, so the application never asks for a PIN again;
  built-in user verification succeeds while the operating system holds the PIN validated. The
  application needs no PIN permission and can never spend one of the device's PIN tries.
- **Opening the application is the power cycle.** State that CTAP resets at power-up (PIN/UV key
  agreement keys, tokens, the three-mismatch block of the client PIN) starts over when the
  application opens.
- **Consent on the screen.** Every token the platform asks for is shown first with what it allows
  and for which site; the person allows or refuses it on the device.

## Layout

| Path | Crate | Role |
|---|---|---|
| `crates/ctap` | `structured-passkeys-ctap` | Protocol logic, `no_std` with `alloc`, tested on the host |
| `app` | `structured-passkeys-app` | Device application on the Ledger Rust SDK |
| `cli` | `structured-passkeys` | Host companion tool |

## Building

Host crates build with the repository toolchain (`rust-toolchain.toml`). The device application
builds in Ledger's `ledger-app-dev-tools` image, a Linux container, with the toolchain that image
pins:

```sh
scripts/device-build.sh                                                   # Linux with Docker
STRUCTURED_PASSKEYS_LINUX=<ssh destination> scripts/linux/check.sh device   # elsewhere, through a Linux host
```

The single check that every change must pass:

```sh
scripts/check.sh
```

## Releases

Every release on GitHub carries, per device, the ELF, the `.hex`, the `.apdu` to load and a
`.sha256` with the application hash the device shows at installation, plus `SHA256SUMS` for the
downloads. Versions, tags and `CHANGELOG.md` come from conventional commits through a release
pull request.

## Loading onto a device

Nano S Plus, Stax, Flex and Nano Gen5 accept the application after an on-device warning; the Nano X
accepts only applications signed by Ledger. With the device unlocked and on its dashboard, from a
release (`structured-passkeys-<tag>-<device>.apdu` and `.elf`) or a local build:

```sh
uvx --from ledgerblue python -m ledgerblue.runScript --scp \
  --fileName target/device/apex_p/release/structured-passkeys-app.apdu \
  --elfFile target/device/apex_p/release/structured-passkeys-app
uvx --from ledgerwallet ledgerctl list
```

The paths are those `scripts/linux/check.sh device` copies back; after `scripts/device-build.sh`
they are under `app/target/` instead. Builds follow the newest Ledger SDK, so the device needs the
current Ledger OS: status `0x511F` on loading means its OS is older, update it in Ledger Wallet.

## License

Apache-2.0, see [LICENSE](LICENSE).

Ledger, Ledger Nano, Ledger Stax and Ledger Flex are trademarks of Ledger SAS. This project is
independent and not affiliated with or endorsed by Ledger.

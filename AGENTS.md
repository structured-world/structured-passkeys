# Contributor and reviewer guide

Rules a change in this repository must meet. Reviewers check them; the gate script
(`scripts/check.sh`) checks the mechanical ones.

## Specifications

- Every behavior decided by a specification (CTAP 2.1/2.2, WebAuthn L3, CBOR) carries a code
  comment naming the specification and section.
- Where the specification leaves a choice open (a timeout value, an optional command), the comment
  states the choice and why.
- A MUST or MUST NOT holds on every path, error paths included: a message the specification says is
  never answered gets no reply even when it is malformed or arrives in an unexpected state.
- Input is validated in the order the specification layers it (channel before command, length
  before buffering), so a message that fails an outer check never reaches an inner one.
- The pull request description states the scope and acceptance checks of the change; a behavior
  change without them is incomplete.

## CTAP on a Ledger device

CTAP describes a dedicated security key that owns its power, its PIN and its storage; this
application runs inside a Ledger wallet, where the operating system owns all three.

- Behavior the platform sees (requests and responses, status codes, getInfo members, the order of
  the checks) follows the specification literally: browsers and operating systems implement it
  and adapt to nothing else.
- Mechanics inside the device follow the Ledger platform, and a review does not ask to put the
  dedicated-key model back. The accepted mappings:
  - Built-in user verification is the device unlock: the person entered the device PIN to unlock
    the device, so performBuiltInUv succeeds while `os_global_pin_is_validated()` holds. The
    application never asks for the device PIN, holds no PIN permission, and spends none of the
    device's own tries (three wrong entries wipe the device).
  - The power cycle of CTAP is opening the application.
  - authenticatorReset keeps the 10-second window after the application opens, which CTAP 2.2
    §6.6 requires only without a display, so a reset never reaches a device sitting open.
  - A reset revokes the credentials the recovery phrase derives through a random reset ID kept in
    the application's storage, since their keys cannot be erased. That storage is the application's
    data, so wiping it or reinstalling the application without restoring its backup brings those
    credentials back; the reset screen says so.
  - getInfo reports the options of a feature (`clientPin`, `pinUvAuthToken`, `uv`, `rk`) together
    with the commands that use it, so a platform never starts a flow that ends in a command the
    application does not have yet.
  - The NFC tap is user presence although the device has a screen (CTAP 2.2 grants it to
    authenticators without another gesture): a prompt answered while the device rests on a phone
    makes NFC unusable. The tap is the selection of the FIDO applet with the application open, as
    no field event reaches the application, and counts for 120 seconds or until NFCCTAP_CONTROL
    ends CTAP. Consent screens and the reset confirmation still show over NFC.
  - Every transport takes the same 1024-byte messages, the CTAP minimum, so getInfo reports one
    `maxMsgSize` whichever transport carries it; the HID buffer is no larger than the NFC one.
- A new mapping is a decision about the product, not a review fix: it comes with its reason in
  the code and is added to this list.

## Code

- Protocol logic lives in `crates/ctap`, which is `#![no_std]` with `alloc`; `std` only behind the
  `std` feature for host users. The device crate `app` only adapts the Ledger SDK to the platform
  traits.
- Untrusted input (CTAPHID packets, CBOR, credential IDs, backup blobs) is bounded by the received
  length; no allocation sized by a field the attacker controls beyond that.
- Secrets (derived keys, private keys, CredRandom, PIN material) live in RAM only for the command
  that needs them and are zeroised on every exit path, including errors and drop. Buffers that
  receive host requests count: a request can carry PIN/UV material. Zeroise with the `zeroize`
  crate, never with a plain fill the compiler may remove.
- No `unwrap` outside tests; `expect` only for internal invariants with the invariant stated.
- Arithmetic: `checked_*` with explicit handling; `saturating_*` only where clamping is the specified
  behavior, with a comment saying so. On values derived from host input a failed check drops the
  message with a protocol error, never a panic; on values the device produced itself, `expect`
  names the invariant that rules the failure out.
- Typed errors in libraries, `TryFrom` conversions included (no primitive error types); every CTAP
  failure maps to a specified status code.
- Comments explain the code under them in one or two sentences; no plans, history or issue numbers
  (a specification reference is the exception).

## Tests

- Test bodies live in sibling files (`foo/tests.rs`, declared with `#[cfg(test)] mod tests;`), never
  inline in production files.
- Each test states what it checks. Expected values come from specification vectors or an independent
  computation, never from the code under test.
- A bug fix starts with a test that fails without the fix.
- A fuzz harness asserts the protocol's MUST and MUST NOT rules, not only the absence of panics. Its
  minimized corpus is committed and replayed by the test suite on stable.
- `cargo nextest run` for Rust tests; `cargo test --doc` for doc tests.

## Scripts and CI

- Scripts run on a clean machine: no git identity, no global configuration, nothing outside the
  repository assumed. Cargo commands in the gate use `--locked`.
- Tools whose verdicts change between versions (shellcheck, linters) are pinned in CI to the version
  the gate uses locally; GitHub Actions are pinned by commit SHA. The exception is Ledger's
  dev-tools image (`scripts/dev-tools-image.sh`), which follows `latest` on purpose: Ledger builds
  catalog releases with the latest image and its checks require the newest SDK, so a pinned image
  would test a build Ledger never ships.

## Commits and pull requests

- Conventional commits: `type(scope): summary` in English, imperative, at most 50 characters, no
  phase or step markers in titles.
- A pull request lists the acceptance checks it ran.
- Breaking changes carry `!` in the pull request title.

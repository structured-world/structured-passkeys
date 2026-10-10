#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["fido2==2.2.1"]
# ///
"""Checks the FIDO HID interface of the application through python-fido2.

    fido_check.py             the Ledger FIDO HID device connected to this host
    fido_check.py --speculos  the application in Speculos started with `--transport U2F
                              --apdu-port 9999`, whose APDU port then carries the FIDO HID
                              reports

Checks: INIT allocates a channel and reports CTAPHID protocol 2 with CBOR and MSG; PING
echoes 1-byte and 1024-byte payloads, and a 1025-byte one is ERR_INVALID_LEN (the message size of
every transport); getInfo parses with strict CBOR checks and reports the application AAGUID, a
1024-byte maxMsgSize and the transports of the model (nfc and usb on Stax, Flex and Nano Gen5).

authenticatorSelection (CTAP 2.2 §6.9), a request waiting for the user: while it waits, keepalives
with status UPNEEDED arrive about every 100 ms (§11.2.9.1.7); CTAPHID_CANCEL ends it with
CTAP2_ERR_KEEPALIVE_CANCEL; no answer ends it with CTAP2_ERR_USER_ACTION_TIMEOUT after 30 seconds
without input, and in Speculos an input that answers nothing restarts those 30 seconds;
confirming answers CTAP2_OK and refusing CTAP2_ERR_OPERATION_DENIED. In Speculos the script
answers the screen itself through the Speculos API and compares the selection screen with the
snapshot of the model in `--snapshots` (`--golden` writes it instead); on a device it asks the
person at the device to answer.

authenticatorClientPIN (§6.5), in Speculos, whose NVM starts empty: getInfo lists PIN/UV auth
protocols 2 and 1; setPIN; getPinToken with both protocols after consent on the device, the token
decrypting to 32 bytes; a wrong PIN spends a try (CTAP2_ERR_PIN_INVALID) and a correct one
restores the tries; a refused consent spends none (CTAP2_ERR_OPERATION_DENIED); changePIN, after
which the old PIN is wrong. The consent screen is compared with its snapshot like the selection
screen.

authenticatorReset (§6.6), in Speculos, run first because it is accepted only in the 10 seconds
after the application opens: with a PIN set, refusing answers CTAP2_ERR_OPERATION_DENIED and keeps
the PIN; confirming answers CTAP2_OK and erases it (getPinToken then answers CTAP2_ERR_PIN_NOT_SET).
The confirmation screen is compared with its snapshot. Once the other checks have outlasted the
window, a reset answers CTAP2_ERR_NOT_ALLOWED without a screen.

Built-in user verification (§6.5.5.7.3), which is the device unlock, in Speculos and on a device:
getUVRetries offers one attempt; getPinUvAuthTokenUsingUvWithPermissions gives a token after the
consent choice alone, no PIN asked, and in Speculos a refused consent gives none
(CTAP2_ERR_OPERATION_DENIED). Its consent screen, which names the RP, is compared with its snapshot.

Credentials (§6.1 to §6.3), in Speculos and on a device, with built-in UV: getInfo reports the
options rk, up, uv and pinUvAuthToken; a discoverable registration starts on the device-only key
origin (UP, UV and AT, no BE or BS, packed self attestation) and a second one switches to the
recovery phrase key on the key type screen (BE and BS); a getAssertion without allowList lists both
accounts, newest first, and the one picked signs with its user and userSelected; one with an
allowList shows the sign-in screen and signs with UP and UV; one without presence answers the count
with no screen, getNextAssertion the other, and then CTAP2_ERR_NOT_ALLOWED; a registration whose
excludeList names a credential of the device ends with CTAP2_ERR_CREDENTIAL_EXCLUDED after the
screen; a registration for a 253-character domain, the longest, shows it whole. Every signature is
verified with the key its registration returned. The registration, key type, account picker,
sign-in and long RP ID screens are compared with their snapshots.

Credential management (§6.8) and authenticatorConfig (§6.11), in Speculos and on a device, with
tokens from built-in UV: getInfo reports credMgmt and authnrCfg; the metadata counts the
credentials above, the RPs enumerate with their hashes, the credentials of the RP with their users
and the public keys their registrations returned; updateUserInformation renames one;
deleteCredential of the device-only and of the recovery phrase key, with no screen (§6.8.5 asks for
nothing beyond the token), leaves IDs that no longer sign; toggleAlwaysUv turns getInfo's alwaysUv
on and off again. The consent for the credential management token is compared with its snapshot.

Extensions (§12), in Speculos and on a device, on non-discoverable credentials with built-in UV:
getInfo lists credProtect, hmac-secret and hmac-secret-mc; a registration with all three answers
the credProtect level, `"hmac-secret": true` and the hmac-secret-mc output, which a sign-in with UV
returns again for the same salt, while one without UV returns another; a credential of credProtect
3 is not found without UV.

CTAP1/U2F messages (U2F raw messages v1.2), in Speculos and on a device: getInfo lists U2F_V2;
U2F_VERSION; a registration refused, then confirmed, whose signature verifies with its
certificate; check-only for this application and another; sign-ins confirmed with the enforce and
the don't-enforce control byte, verified with the registration's key, and one refused; the key
handle signing over CTAP2 for the appid URL; with alwaysUv on, SW_COMMAND_NOT_ALLOWED and no
U2F_V2. The registration and sign-in screens are compared with their snapshots.

The passkey list of the device's settings, in Speculos: a new passkey is listed first; deleting it
from the list through its deletion screen leaves an ID that no longer signs, and the list, empty
then, says so. The list and the deletion screen are compared with their snapshots.

The screens to answer come first and those to leave alone last, so at a device the person
answers: selection "Don't allow", selection "Allow", token consent "Allow", the credential and
credential management screens as printed, then nothing while a selection is cancelled and the
next one times out.
"""

import argparse
import hashlib
import json
import os
import re
import socket
import struct
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fido2.cose import ES256
from fido2.ctap import CtapError
from fido2.ctap1 import APDU, ApduError, Ctap1
from fido2.ctap2 import Config, CredentialManagement, Ctap2
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2
from fido2.hid import CAPABILITY, CtapHidDevice, list_descriptors, open_connection
from fido2.hid.base import CtapHidConnection, HidDescriptor

LEDGER_VENDOR_ID = 0x2C97
# The APDU and API ports scripts/speculos-check.sh gives Speculos.
SPECULOS_APDU_PORT = 9999
SPECULOS_API = "http://127.0.0.1:5000"
AAGUID = bytes.fromhex("8f920f839da2486194d77f3c9945d532")
MAX_MESSAGE = 1024
REPORT = 64
# The Speculos models without NFC.
NANO_MODELS = ("nanosp", "nanox")
# CTAPHID_KEEPALIVE (§11.2.9.2.1) and its status "user presence needed".
KEEPALIVE = 0x80 | 0x3B
STATUS_UPNEEDED = 2
# §11.2.9.1.7: keepalives SHOULD go at least every 100 ms. The device sends one per OS tick,
# which runs a few milliseconds slow on hardware; the margin covers that and scheduling on the
# host.
KEEPALIVE_GAP_MS = 100
KEEPALIVE_SLACK_MS = 50
# The user action timeout of the application, and how much later the error may arrive.
USER_ACTION_TIMEOUT_S = 30
TIMEOUT_SLACK_S = 5
# The texts of the selection screen.
SELECTION_TITLE = "Allow security key access?"
SELECTION_CONFIRM = "Allow"
SELECTION_REJECT = "Don't allow"
# The title of the consent screen for a pinUvAuthToken, with the client PIN or built-in UV.
TOKEN_TITLE = "Allow security key use?"
# The texts of the reset confirmation, and how long after the application opens a reset is
# accepted.
RESET_TITLE = "Reset the security key?"
RESET_CONFIRM = "Reset"
RESET_REJECT = "Cancel"
RESET_WINDOW_S = 10
# authenticatorClientPIN subcommands and response members (§6.5.5).
GET_PIN_RETRIES = 0x01
GET_KEY_AGREEMENT = 0x02
SET_PIN = 0x03
CHANGE_PIN = 0x04
GET_PIN_TOKEN = 0x05
GET_TOKEN_USING_UV = 0x06
GET_UV_RETRIES = 0x07
KEY_AGREEMENT = 0x01
PIN_UV_AUTH_TOKEN = 0x02
PIN_RETRIES = 0x03
UV_RETRIES = 0x05
# The getAssertion, credential management and authenticatorConfig permissions (§6.5.5.7).
PERMISSION_GA = 0x02
PERMISSION_CM = 0x04
PERMISSION_ACFG = 0x20
# Authenticator data flags (WebAuthn L3 §6.1): UP, UV, BE, BS, AT.
FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08
FLAG_BS = 0x10
FLAG_AT = 0x40
# The relying party of the credential checks, and the screens' labels.
RP_ID = "example.com"
REGISTER_TITLE = f"Create a passkey for {RP_ID}?"
REGISTER_CONFIRM = "Create passkey"
KEY_TYPE = "Key type"
USE_KEY_TYPE = "Use this key type"
SIGN_IN_TITLE = f"Sign in to {RP_ID}?"
SIGN_IN = "Sign in"
OTHER_ACCOUNT = "Other account"
EXCLUDED_TITLE = "Already registered"
EXCLUDED_CONFIRM = "OK"
DELETE_CONFIRM = "Delete"
# The extensions getInfo lists (§6.4).
EXTENSIONS = ["credProtect", "hmac-secret", "hmac-secret-mc"]
# The longest domain, 253 characters (RFC 1035 §2.3.4), which a screen shows whole.
LONG_RP_ID = "a." * 121 + "example.com"
# The start of a registration screen: a Nano heads a long one with the short question.
REGISTER_START = "Create a passkey"
# CTAP1/U2F: the application of the checks, as a platform sends the appid extension's URL, and
# the screens, which name it by the first 8 bytes of its SHA-256.
U2F_APP_ID = "https://u2f.example"
U2F_LABEL = "U2F site #" + hashlib.sha256(U2F_APP_ID.encode()).digest()[:8].hex().upper()
U2F_REGISTER_START = "Register a security key"
U2F_REGISTER = "Register"
U2F_REGISTER_REJECT = "Don't register"
U2F_SIGN_IN_START = "Sign in"
SIGN_IN_REJECT = "Don't sign in"
# U2F_AUTHENTICATE's "don't-enforce-user-presence-and-sign" control byte (U2F raw messages §5.1).
U2F_DONT_ENFORCE = 0x08


class KeepaliveLog:
    """Arrival times of the keepalive packets a connection reads, with their status."""

    def __init__(self):
        self.lock = threading.Lock()
        self.arrivals: list[tuple[float, int]] = []

    def note(self, packet: bytes) -> None:
        if len(packet) > 7 and packet[4] == KEEPALIVE:
            with self.lock:
                self.arrivals.append((time.monotonic(), packet[7]))

    def clear(self) -> None:
        with self.lock:
            self.arrivals.clear()

    def gaps_ms(self) -> list[float]:
        with self.lock:
            times = [at for at, _ in self.arrivals]
        return [(later - earlier) * 1000 for earlier, later in zip(times, times[1:])]

    def statuses(self) -> set[int]:
        with self.lock:
            return {status for _, status in self.arrivals}


class SpeculosConnection(CtapHidConnection):
    """FIDO HID reports through the Speculos APDU socket: each report travels with a 4-byte
    big-endian length; Speculos announces 2 bytes less than it sends."""

    def __init__(self, keepalives: KeepaliveLog):
        self.keepalives = keepalives
        self.sock = socket.create_connection(("127.0.0.1", SPECULOS_APDU_PORT))
        # Longer than the user action timeout, so the timeout error itself can arrive.
        self.sock.settimeout(USER_ACTION_TIMEOUT_S + 2 * TIMEOUT_SLACK_S)

    def _read(self, size: int) -> bytes:
        data = b""
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise ConnectionError("Speculos closed the connection")
            data += chunk
        return data

    def write_packet(self, data: bytes) -> None:
        self.sock.sendall(struct.pack(">I", len(data)) + bytes(data))

    def read_packet(self) -> bytes:
        size = struct.unpack(">I", self._read(4))[0] + 2
        packet = self._read(size)
        if len(packet) != REPORT:
            raise ConnectionError(f"a {len(packet)}-byte report instead of {REPORT}")
        self.keepalives.note(packet)
        return packet

    def close(self) -> None:
        self.sock.close()


class LoggedConnection(CtapHidConnection):
    """A device connection that notes the keepalives it reads."""

    def __init__(self, inner: CtapHidConnection, keepalives: KeepaliveLog):
        self.inner = inner
        self.keepalives = keepalives

    def write_packet(self, data: bytes) -> None:
        self.inner.write_packet(data)

    def read_packet(self) -> bytes:
        packet = self.inner.read_packet()
        self.keepalives.note(packet)
        return packet

    def close(self) -> None:
        self.inner.close()


def connect(speculos: bool, keepalives: KeepaliveLog) -> CtapHidDevice:
    if speculos:
        descriptor = HidDescriptor("speculos", 0, 0, REPORT, REPORT, "Speculos", None)
        return CtapHidDevice(descriptor, SpeculosConnection(keepalives))
    ledgers = [d for d in list_descriptors() if d.vid == LEDGER_VENDOR_ID]
    if len(ledgers) != 1:
        raise SystemExit(f"expected one Ledger FIDO HID device, found {len(ledgers)}")
    descriptor = ledgers[0]
    print(f"enumerated {descriptor.product_name} ({descriptor.vid:04x}:{descriptor.pid:04x})")
    return CtapHidDevice(descriptor, LoggedConnection(open_connection(descriptor), keepalives))


def api(path: str, body: dict | None = None) -> bytes:
    """A request to the Speculos API: GET without a body, POST with one."""
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        SPECULOS_API + path, data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.read()


def screen_texts() -> list[dict]:
    return json.loads(api("/events?currentscreenonly=true"))["events"]


def screen_shows(text: str) -> bool:
    joined = " ".join(event["text"] for event in screen_texts())
    return text in " ".join(joined.split())


def button(text: str) -> dict | None:
    """The text element of the current screen where the label `text` starts, read exactly: a
    button label, not a title that happens to contain the same word. A label NBGL wraps arrives
    as one text element per line, as the reject text of a review's footer."""
    texts = screen_texts()
    for start, event in enumerate(texts):
        words = []
        for following in texts[start:]:
            words.append(following["text"].strip())
            shown = " ".join(words)
            if shown == text:
                return event
            if not text.startswith(shown + " "):
                break
    return None


def wait_for_screen(text: str) -> None:
    for _ in range(100):
        if screen_shows(text):
            return
        time.sleep(0.1)
    raise SystemExit(f"FAILED: the screen never showed {text!r}: {screen_texts()}")


# The next-page arrow at the right of a review's footer (NBGL `FOOTER_TEXT_AND_NAV`, its
# `SIMPLE_FOOTER_HEIGHT` of 92, 96 and 60 pixels at the foot of the screen).
NEXT_PAGE = {"stax": (376, 626), "flex": (456, 552), "apex_p": (284, 370)}

SELECTION_LABELS = (SELECTION_CONFIRM, SELECTION_REJECT)
RESET_LABELS = (RESET_CONFIRM, RESET_REJECT)


class SpeculosUser:
    """Answers a screen through the Speculos API, as the person would; `labels` are its confirm
    and reject choices."""

    def __init__(self, model: str):
        self.model = model
        self.nano = model in NANO_MODELS

    def read_until(self, wanted: str) -> str:
        """Pages through the shown screen until a page offers `wanted`, which stays shown, and
        returns the text of every page on the way, whitespace removed: a long question is paged by
        a Nano and by the review a touch model asks it in."""
        seen = []
        for _ in range(50):
            texts = screen_texts()
            seen.extend(event["text"] for event in texts)
            if button(wanted) is not None:
                return "".join("".join(seen).split())
            if self.nano:
                api("/button/right", {"action": "press-and-release"})
            else:
                x, y = NEXT_PAGE[self.model]
                api("/finger", {"action": "press-and-release", "x": x, "y": y})
            for _ in range(50):
                if screen_texts() != texts:
                    break
                time.sleep(0.1)
            else:
                raise SystemExit(f"FAILED: no page offers {wanted!r}: {texts}")
        raise SystemExit(f"FAILED: no page offers {wanted!r} after 50 pages")

    def answer(self, confirm: bool, labels: tuple[str, str] = SELECTION_LABELS) -> None:
        self.press(labels[0] if confirm else labels[1])

    def press(self, wanted: str) -> None:
        """Chooses the option labelled `wanted` on the shown screen, then waits until the screen
        changes, so the next press meets the next screen."""
        before = screen_texts()
        self._press(wanted)
        for _ in range(50):
            if screen_texts() != before:
                return
            time.sleep(0.1)

    def _press(self, wanted: str) -> None:
        if self.nano:
            # The choice steps through its pages with the right button and takes the shown
            # one with both buttons; the last page stays put when pressed again.
            shown = None
            while (texts := screen_texts()) != shown:
                if button(wanted) is not None:
                    api("/button/both", {"action": "press-and-release"})
                    return
                shown = texts
                api("/button/right", {"action": "press-and-release"})
                time.sleep(0.2)
            raise SystemExit(f"FAILED: no page offers {wanted!r}: {shown}")
        event = button(wanted)
        if event is None:
            raise SystemExit(f"FAILED: no button reads {wanted!r}: {screen_texts()}")
        api("/finger", {"action": "press-and-release", "x": event["x"], "y": event["y"]})


class PersonAtDevice:
    """Asks the person at the device to answer a screen."""

    def answer(self, confirm: bool, labels: tuple[str, str] = SELECTION_LABELS) -> None:
        self.press(labels[0] if confirm else labels[1])

    def press(self, wanted: str) -> None:
        print(f"   on the device, choose {wanted!r}", flush=True)

    def follow(self, steps: list[tuple[str, str]]) -> None:
        """Names every screen of one ceremony with its option at once, in order, since the person
        answers screens this script cannot see."""
        if len(steps) == 1:
            title, label = steps[0]
            print(f"   on the device, on {title!r} choose {label!r}", flush=True)
            return
        print("   on the device, one screen after another:", flush=True)
        for number, (title, label) in enumerate(steps, start=1):
            print(f"     {number}. on {title!r} choose {label!r}", flush=True)


def selection(ctap: Ctap2, cancel: threading.Event | None = None) -> int:
    """Runs authenticatorSelection and returns its CTAP status."""
    try:
        ctap.selection(event=cancel)
        return CtapError.ERR.SUCCESS
    except CtapError as error:
        return error.code


def check_selection_answers(device: CtapHidDevice, user, snapshot) -> None:
    """authenticatorSelection refused, then confirmed; the screen is compared with its snapshot
    while it waits for the confirmation."""
    ctap = Ctap2(device)
    for confirm, expected in ((False, CtapError.ERR.OPERATION_DENIED), (True, CtapError.ERR.SUCCESS)):

        def answer(confirm: bool = confirm) -> None:
            if snapshot is not None and confirm:
                snapshot()
            user.answer(confirm)

        status = while_answering(1.0, answer, lambda: selection(ctap))
        check(status == expected, f"selection: {'confirm' if confirm else 'refuse'} answers {status!r}")


def check_selection_unanswered(device: CtapHidDevice, keepalives: KeepaliveLog) -> None:
    """authenticatorSelection left unanswered: the host cancels it after a second of keepalives,
    and the next one times out."""
    ctap = Ctap2(device)

    keepalives.clear()
    cancel = threading.Event()
    threading.Timer(1.0, cancel.set).start()
    status = selection(ctap, cancel)
    check(status == CtapError.ERR.KEEPALIVE_CANCEL, f"selection: CANCEL ends it ({status!r})")
    gaps = keepalives.gaps_ms()
    check(
        len(gaps) >= 5 and max(gaps) <= KEEPALIVE_GAP_MS + KEEPALIVE_SLACK_MS,
        f"selection: keepalives every {max(gaps, default=0):.0f} ms at most over {len(gaps)} gaps",
    )
    check(
        keepalives.statuses() == {STATUS_UPNEEDED},
        f"selection: keepalive status {sorted(keepalives.statuses())} is UPNEEDED",
    )

    started = time.monotonic()
    status = selection(ctap)
    waited = time.monotonic() - started
    check(
        status == CtapError.ERR.USER_ACTION_TIMEOUT
        and USER_ACTION_TIMEOUT_S <= waited <= USER_ACTION_TIMEOUT_S + TIMEOUT_SLACK_S,
        f"selection: no answer times out after {waited:.1f} s ({status!r})",
    )


def check_input_restarts_timeout(device: CtapHidDevice, user: SpeculosUser) -> None:
    """authenticatorSelection with an input that answers nothing two thirds into the timeout (a
    page turn on a Nano, a touch outside the buttons elsewhere): the timeout runs again from the
    input, so the request ends a full timeout after it, not after the first."""
    ctap = Ctap2(device)
    input_at = USER_ACTION_TIMEOUT_S * 2 / 3

    def touch() -> None:
        if user.nano:
            api("/button/right", {"action": "press-and-release"})
        else:
            api("/finger", {"action": "press-and-release", "x": 4, "y": 4})

    # The origin is taken before the timer starts, so the input never lands earlier than
    # `input_at` after it and the lower bound below holds.
    started = time.monotonic()
    threading.Timer(input_at, touch).start()
    status = selection(ctap)
    waited = time.monotonic() - started
    expected = input_at + USER_ACTION_TIMEOUT_S
    check(
        status == CtapError.ERR.USER_ACTION_TIMEOUT
        and expected <= waited <= expected + TIMEOUT_SLACK_S,
        f"selection: an input at {input_at:.0f} s restarts the timeout, which ends it after "
        f"{waited:.1f} s ({status!r})",
    )


def check(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAILED: {message}")
    print(f"ok: {message}")


def ctap_result(call) -> tuple[int, object]:
    """Runs `call` and returns its CTAP status with what it returned, None after an error."""
    try:
        return CtapError.ERR.SUCCESS, call()
    except CtapError as error:
        return error.code, None


def ctap_status(call) -> int:
    """Runs `call` and returns its CTAP status: success, or the error it raised."""
    return ctap_result(call)[0]


def while_answering(delay_s: float, answer, call):
    """Runs `call` while `answer` runs `delay_s` later in another thread, and returns what `call`
    returned. An exception in `answer` (a failed check raises SystemExit) is kept by its future and
    raised here once both are done, instead of ending only the other thread."""

    def delayed() -> None:
        time.sleep(delay_s)
        answer()

    with ThreadPoolExecutor(max_workers=1) as pool:
        answering = pool.submit(delayed)
        returned = call()
        answering.result()
    return returned


def padded_pin(pin: str) -> bytes:
    """The PIN padded with zeros to 64 bytes (§6.5.5.5)."""
    encoded = pin.encode()
    return encoded + b"\0" * (64 - len(encoded))


def pin_hash(pin: str) -> bytes:
    """LEFT(SHA-256(PIN), 16) (§6.5.5.6)."""
    return hashlib.sha256(pin.encode()).digest()[:16]


class PinSession:
    """The platform side of one key agreement with `protocol` (§6.5.5.4)."""

    def __init__(self, ctap: Ctap2, protocol):
        self.ctap = ctap
        self.protocol = protocol
        response = ctap.client_pin(protocol.VERSION, GET_KEY_AGREEMENT)
        self.key_agreement, self.secret = protocol.encapsulate(response[KEY_AGREEMENT])

    def client_pin(self, sub_command: int, **members):
        return self.ctap.client_pin(
            self.protocol.VERSION, sub_command, key_agreement=self.key_agreement, **members
        )


def set_pin(ctap: Ctap2, protocol, pin: str) -> None:
    session = PinSession(ctap, protocol)
    new_pin_enc = protocol.encrypt(session.secret, padded_pin(pin))
    session.client_pin(
        SET_PIN,
        new_pin_enc=new_pin_enc,
        pin_uv_param=protocol.authenticate(session.secret, new_pin_enc),
    )


def change_pin(ctap: Ctap2, protocol, old: str, new: str) -> None:
    session = PinSession(ctap, protocol)
    pin_hash_enc = protocol.encrypt(session.secret, pin_hash(old))
    new_pin_enc = protocol.encrypt(session.secret, padded_pin(new))
    session.client_pin(
        CHANGE_PIN,
        new_pin_enc=new_pin_enc,
        pin_hash_enc=pin_hash_enc,
        pin_uv_param=protocol.authenticate(session.secret, new_pin_enc + pin_hash_enc),
    )


def pin_token(ctap: Ctap2, protocol, pin: str) -> bytes:
    """getPinToken (§6.5.5.7.1): the decrypted pinUvAuthToken."""
    session = PinSession(ctap, protocol)
    response = session.client_pin(
        GET_PIN_TOKEN, pin_hash_enc=protocol.encrypt(session.secret, pin_hash(pin))
    )
    return protocol.decrypt(session.secret, response[PIN_UV_AUTH_TOKEN])


def pin_retries(ctap: Ctap2) -> int:
    return ctap.client_pin(2, GET_PIN_RETRIES)[PIN_RETRIES]


def answered(
    user,
    confirm: bool,
    title: str,
    call,
    snapshot=None,
    labels: tuple[str, str] = SELECTION_LABELS,
    delay_s: float = 1.0,
) -> int:
    """Runs `call` while the user answers the screen titled `title` with one of `labels`, `delay_s`
    after the call starts; returns its CTAP status."""

    def answer() -> None:
        if isinstance(user, SpeculosUser):
            wait_for_screen(title)
        if snapshot is not None:
            snapshot()
        user.answer(confirm, labels)

    return while_answering(delay_s, answer, lambda: ctap_status(call))


def check_client_pin(device: CtapHidDevice, user, snapshot) -> None:
    ctap = Ctap2(device)
    check(
        ctap.info.pin_uv_protocols == [2, 1],
        f"getInfo: pinUvAuthProtocols {ctap.info.pin_uv_protocols}",
    )
    check(pin_retries(ctap) == 8, "clientPIN: eight tries on fresh NVM")
    check(
        ctap_status(lambda: set_pin(ctap, PinProtocolV2(), "1234")) == CtapError.ERR.SUCCESS,
        "clientPIN: setPIN",
    )
    for protocol, shot in ((PinProtocolV2(), snapshot), (PinProtocolV1(), None)):
        name = f"protocol {protocol.VERSION}"
        token: list[bytes] = []
        status = answered(
            user, True, TOKEN_TITLE, lambda p=protocol: token.append(pin_token(ctap, p, "1234")), shot
        )
        check(
            status == CtapError.ERR.SUCCESS and [len(t) for t in token] == [32],
            f"clientPIN {name}: getPinToken after consent gives a 32-byte token",
        )
        status = answered(user, True, TOKEN_TITLE, lambda p=protocol: pin_token(ctap, p, "0000"))
        check(
            status == CtapError.ERR.PIN_INVALID and pin_retries(ctap) == 7,
            f"clientPIN {name}: a wrong PIN spends a try ({status!r})",
        )
        status = answered(user, True, TOKEN_TITLE, lambda p=protocol: pin_token(ctap, p, "1234"))
        check(
            status == CtapError.ERR.SUCCESS and pin_retries(ctap) == 8,
            f"clientPIN {name}: the right PIN restores the tries",
        )
    status = answered(user, False, TOKEN_TITLE, lambda: pin_token(ctap, PinProtocolV2(), "0000"))
    check(
        status == CtapError.ERR.OPERATION_DENIED and pin_retries(ctap) == 8,
        f"clientPIN: a refused consent spends no try ({status!r})",
    )
    check(
        ctap_status(lambda: change_pin(ctap, PinProtocolV2(), "1234", "98765"))
        == CtapError.ERR.SUCCESS,
        "clientPIN: changePIN",
    )
    status = answered(user, True, TOKEN_TITLE, lambda: pin_token(ctap, PinProtocolV2(), "1234"))
    check(status == CtapError.ERR.PIN_INVALID, f"clientPIN: the old PIN is wrong now ({status!r})")


def check_reset(device: CtapHidDevice, user, snapshot) -> None:
    """authenticatorReset inside its window, which the checks before it must leave room for."""
    ctap = Ctap2(device)
    check(
        ctap_status(lambda: set_pin(ctap, PinProtocolV2(), "1234")) == CtapError.ERR.SUCCESS,
        "reset: a PIN is set first",
    )
    # The answers come as soon as the screen shows: the window is short.
    status = answered(user, False, RESET_TITLE, ctap.reset, labels=RESET_LABELS, delay_s=0.1)
    check(status == CtapError.ERR.OPERATION_DENIED, f"reset: refusing answers {status!r}")
    # setPIN with a PIN already set fails its check (§6.5.5.5), so it shows the PIN is kept.
    status = ctap_status(lambda: set_pin(ctap, PinProtocolV2(), "1234"))
    check(status == CtapError.ERR.PIN_AUTH_INVALID, f"reset: a refused reset keeps the PIN ({status!r})")
    status = answered(
        user, True, RESET_TITLE, ctap.reset, snapshot, labels=RESET_LABELS, delay_s=0.1
    )
    check(status == CtapError.ERR.SUCCESS, f"reset: confirming answers {status!r}")
    status = ctap_status(lambda: pin_token(ctap, PinProtocolV2(), "1234"))
    check(status == CtapError.ERR.PIN_NOT_SET, f"reset: the PIN is erased ({status!r})")


def check_reset_window_closed(device: CtapHidDevice) -> None:
    """authenticatorReset after its window: refused at once, with no screen to answer."""
    status = ctap_status(Ctap2(device).reset)
    check(
        status == CtapError.ERR.NOT_ALLOWED,
        f"reset: after {RESET_WINDOW_S} s it is not allowed ({status!r})",
    )


def check_built_in_uv(device: CtapHidDevice, user, snapshot) -> None:
    """Built-in user verification, which is the device unlock: the consent choice alone gives a
    token, and refusing it gives none."""
    ctap = Ctap2(device)
    protocol = PinProtocolV2()

    def uv_token() -> bytes:
        session = PinSession(ctap, protocol)
        response = session.client_pin(
            GET_TOKEN_USING_UV, permissions=PERMISSION_GA, permissions_rpid="example.com"
        )
        return protocol.decrypt(session.secret, response[PIN_UV_AUTH_TOKEN])

    uv_retries = ctap.client_pin(2, GET_UV_RETRIES)[UV_RETRIES]
    check(uv_retries == 1, f"built-in UV: offered on the unlocked device ({uv_retries})")
    token: list[bytes] = []
    status = answered(user, True, TOKEN_TITLE, lambda: token.append(uv_token()), snapshot)
    check(
        status == CtapError.ERR.SUCCESS and [len(t) for t in token] == [32],
        f"built-in UV: consent gives a 32-byte token, no PIN asked ({status!r})",
    )
    # Refusing is the same consent screen as for the client PIN, which a device run does not
    # repeat; Speculos answers it itself.
    if isinstance(user, SpeculosUser):
        status = answered(user, False, TOKEN_TITLE, uv_token)
        check(
            status == CtapError.ERR.OPERATION_DENIED,
            f"built-in UV: a refused consent gives no token ({status!r})",
        )


def pressed(user, steps: list[tuple[str, str, object]], call) -> tuple[int, object]:
    """Runs `call` while the user goes through `steps`, each a screen title, the option to choose
    on it and a snapshot check or None; returns its CTAP status and result."""

    def answer() -> None:
        if not isinstance(user, SpeculosUser):
            user.follow([(title, label) for title, label, _ in steps])
            return
        for title, label, snapshot in steps:
            wait_for_screen(title)
            if snapshot is not None:
                snapshot()
            user.press(label)

    return while_answering(1.0, answer, lambda: ctap_result(call))


def check_credentials(device: CtapHidDevice, user, snapshot) -> dict[str, object]:
    """makeCredential, getAssertion and getNextAssertion (CTAP 2.2 §6.1 to §6.3) with built-in user
    verification (the uv option, the device unlock), for both key origins. Returns the attested
    credential data of the device-only and the recovery phrase registration for RP_ID."""
    ctap = Ctap2(device)
    info_options = ctap.info.options
    check(
        all(info_options.get(name) for name in ("rk", "up", "uv", "pinUvAuthToken")),
        f"getInfo: options {info_options}",
    )
    client_data_hash = hashlib.sha256(b"client data").digest()
    rp = {"id": RP_ID, "name": "Example"}
    params = [{"type": "public-key", "alg": -7}]

    def register(user_id: bytes, name: str):
        return lambda: ctap.make_credential(
            client_data_hash,
            rp,
            {"id": user_id, "name": name, "displayName": name.title()},
            params,
            options={"rk": True, "uv": True},
        )

    # A discoverable credential with UV starts on the device-only origin.
    status, device_only = pressed(
        user,
        [(REGISTER_TITLE, REGISTER_CONFIRM, snapshot("registration", REGISTER_TITLE))],
        register(b"user-device", "device user"),
    )
    flags = device_only.auth_data.flags if device_only else 0
    check(
        status == CtapError.ERR.SUCCESS
        and flags & (FLAG_UP | FLAG_UV | FLAG_AT) == FLAG_UP | FLAG_UV | FLAG_AT
        and flags & (FLAG_BE | FLAG_BS) == 0,
        f"makeCredential: a device-only key, UP and UV, no BE or BS (flags {flags:#04x})",
    )
    check(device_only.fmt == "packed", "makeCredential: packed self attestation")
    # The other origin through the key type screen.
    status, seed = pressed(
        user,
        [
            (REGISTER_TITLE, KEY_TYPE, None),
            ("Use Recovery phrase key?", USE_KEY_TYPE, snapshot("key_type", "Use Recovery phrase key?")),
            (REGISTER_TITLE, REGISTER_CONFIRM, None),
        ],
        register(b"user-seed", "seed user"),
    )
    flags = seed.auth_data.flags if seed else 0
    check(
        status == CtapError.ERR.SUCCESS
        and flags & (FLAG_BE | FLAG_BS) == FLAG_BE | FLAG_BS,
        f"makeCredential: a recovery phrase key reports BE and BS (flags {flags:#04x})",
    )
    keys = {
        device_only.auth_data.credential_data.credential_id: device_only.auth_data.credential_data.public_key,
        seed.auth_data.credential_data.credential_id: seed.auth_data.credential_data.public_key,
    }

    def verify(assertion) -> bool:
        key = keys.get(assertion.credential["id"])
        if key is None:
            return False
        try:
            assertion.verify(client_data_hash, key)
            return True
        except Exception:
            return False

    # Two accounts for the RP: the device lists them, newest first; the second is picked.
    status, picked = pressed(
        user,
        [
            (SIGN_IN_TITLE, OTHER_ACCOUNT, snapshot("account_picker", SIGN_IN_TITLE)),
            (SIGN_IN_TITLE, SIGN_IN, None),
        ],
        lambda: ctap.get_assertion(RP_ID, client_data_hash, options={"uv": True}),
    )
    check(
        status == CtapError.ERR.SUCCESS
        and verify(picked)
        and picked.credential["id"] == device_only.auth_data.credential_data.credential_id
        and picked.user_selected
        and picked.user.get("name") == "device user",
        f"getAssertion: the picked account signs, with its user ({status!r})",
    )
    # One credential named in the allowList: the sign-in screen, then UP and UV.
    allow = [{"type": "public-key", "id": seed.auth_data.credential_data.credential_id}]
    status, single = pressed(
        user,
        [(SIGN_IN_TITLE, SIGN_IN, snapshot("assertion", SIGN_IN_TITLE))],
        lambda: ctap.get_assertion(RP_ID, client_data_hash, allow, options={"uv": True}),
    )
    flags = single.auth_data.flags if single else 0
    check(
        status == CtapError.ERR.SUCCESS
        and verify(single)
        and flags & (FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS) == FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS,
        f"getAssertion: the allowList credential signs with UP and UV (flags {flags:#04x})",
    )
    # No presence asked for: the count, and getNextAssertion for the rest, with no screen.
    first = ctap.get_assertion(RP_ID, client_data_hash, options={"up": False})
    second = ctap.get_next_assertion()
    check(
        first.number_of_credentials == 2
        and verify(first)
        and verify(second)
        and {first.credential["id"], second.credential["id"]} == set(keys)
        and first.auth_data.flags & FLAG_UP == 0,
        "getNextAssertion: both credentials, no UP, no screen",
    )
    status = ctap_status(ctap.get_next_assertion)
    check(status == CtapError.ERR.NOT_ALLOWED, f"getNextAssertion: past the last ({status!r})")
    # A registration whose excludeList names a credential of this device.
    status, _ = pressed(
        user,
        [(EXCLUDED_TITLE, EXCLUDED_CONFIRM, None)],
        lambda: ctap.make_credential(
            client_data_hash,
            rp,
            {"id": b"user-new", "name": "new"},
            params,
            exclude_list=allow,
            options={"uv": True},
        ),
    )
    check(
        status == CtapError.ERR.CREDENTIAL_EXCLUDED,
        f"makeCredential: an excluded credential after presence ({status!r})",
    )
    # The longest domain is shown whole: a Nano pages the choice, a touch model asks it as a
    # review whose pages hold all of it. The first page is compared with its snapshot.
    long_snapshot = snapshot("long_rp_id", REGISTER_START)

    def long_rp_id_shown() -> None:
        wait_for_screen(REGISTER_START)
        if long_snapshot is not None:
            long_snapshot()
        shown = user.read_until(REGISTER_CONFIRM)
        # A Nano heads every page of the details with the short question, shortened, and the
        # page count, as in "Create...y?(2/7)"; between them the details run on.
        shown = re.sub(r"Create\.\.\.y\?\(\d+/\d+\)", "", shown)
        if f"Createapasskeyfor{LONG_RP_ID}?" not in shown:
            print(f"   the pages read: {shown!r}", flush=True)
        check(
            f"Createapasskeyfor{LONG_RP_ID}?" in shown,
            "makeCredential: a 253-character RP ID is shown whole",
        )

    status, _ = pressed(
        user,
        [(REGISTER_START, REGISTER_CONFIRM, long_rp_id_shown)],
        lambda: ctap.make_credential(
            client_data_hash,
            {"id": LONG_RP_ID, "name": "Long"},
            {"id": b"user-long", "name": "long"},
            params,
            options={"uv": True},
        ),
    )
    check(
        status == CtapError.ERR.SUCCESS,
        f"makeCredential: a 253-character RP ID registers ({status!r})",
    )
    return {
        "device": device_only.auth_data.credential_data,
        "seed": seed.auth_data.credential_data,
    }


def check_extensions(device: CtapHidDevice, user) -> None:
    """credProtect, hmac-secret and hmac-secret-mc (CTAP 2.2 §12.1, §12.7, §12.8), the PRF of
    WebAuthn, with built-in UV on non-discoverable credentials, which no list or count of the other
    checks sees."""
    ctap = Ctap2(device)
    check(
        ctap.info.extensions == EXTENSIONS,
        f"getInfo: extensions {ctap.info.extensions}",
    )
    client_data_hash = hashlib.sha256(b"client data").digest()
    rp = {"id": RP_ID, "name": "Example"}
    params = [{"type": "public-key", "alg": -7}]
    protocol = PinProtocolV2()
    salt = hashlib.sha256(b"prf salt").digest()

    def hmac_input(session: PinSession) -> dict:
        salt_enc = protocol.encrypt(session.secret, salt)
        return {
            1: session.key_agreement,
            2: salt_enc,
            3: protocol.authenticate(session.secret, salt_enc),
            4: protocol.VERSION,
        }

    # The PRF at registration: hmac-secret-mc under CredRandomWithUV, with credProtect 2.
    session = PinSession(ctap, protocol)
    status, made = pressed(
        user,
        [(REGISTER_TITLE, REGISTER_CONFIRM, None)],
        lambda: ctap.make_credential(
            client_data_hash,
            rp,
            {"id": b"user-prf", "name": "prf user"},
            params,
            extensions={
                "credProtect": 2,
                "hmac-secret": True,
                "hmac-secret-mc": hmac_input(session),
            },
            options={"uv": True},
        ),
    )
    outputs = made.auth_data.extensions if made else {}
    at_registration = (
        protocol.decrypt(session.secret, outputs["hmac-secret-mc"])
        if "hmac-secret-mc" in outputs
        else b""
    )
    check(
        status == CtapError.ERR.SUCCESS
        and outputs.get("credProtect") == 2
        and outputs.get("hmac-secret") is True
        and len(at_registration) == 32,
        f"makeCredential: credProtect, hmac-secret and the hmac-secret-mc output ({status!r})",
    )
    allow = [{"type": "public-key", "id": made.auth_data.credential_data.credential_id}]

    def sign_in(uv: bool) -> bytes:
        session = PinSession(ctap, protocol)
        status, assertion = pressed(
            user,
            [(SIGN_IN_TITLE, SIGN_IN, None)],
            lambda: ctap.get_assertion(
                RP_ID,
                client_data_hash,
                allow,
                extensions={"hmac-secret": hmac_input(session)},
                options={"uv": uv},
            ),
        )
        output = assertion.auth_data.extensions.get("hmac-secret") if assertion else None
        check(
            status == CtapError.ERR.SUCCESS and output is not None,
            f"getAssertion with uv {uv}: an hmac-secret output ({status!r})",
        )
        return protocol.decrypt(session.secret, output)

    with_uv = sign_in(True)
    check(with_uv == at_registration, "hmac-secret: the sign-in with UV gives the registration's PRF")
    without_uv = sign_in(False)
    check(
        len(without_uv) == 32 and without_uv != with_uv,
        "hmac-secret: without UV the PRF differs",
    )
    # credProtect 3: never used without UV, refused before any screen.
    status, protected = pressed(
        user,
        [(REGISTER_TITLE, REGISTER_CONFIRM, None)],
        lambda: ctap.make_credential(
            client_data_hash,
            rp,
            {"id": b"user-protected", "name": "protected user"},
            params,
            extensions={"credProtect": 3},
            options={"uv": True},
        ),
    )
    check(
        status == CtapError.ERR.SUCCESS and protected.auth_data.extensions == {"credProtect": 3},
        f"makeCredential: credProtect 3 ({status!r})",
    )
    protected_allow = [
        {"type": "public-key", "id": protected.auth_data.credential_data.credential_id}
    ]
    status = ctap_status(lambda: ctap.get_assertion(RP_ID, client_data_hash, protected_allow))
    check(
        status == CtapError.ERR.NO_CREDENTIALS,
        f"getAssertion: credProtect 3 without UV finds no credential ({status!r})",
    )


def uv_token(ctap: Ctap2, user, permissions: int, snapshot=None) -> bytes:
    """A pinUvAuthToken with `permissions` and no RP ID from built-in user verification, after the
    consent on the device."""
    protocol = PinProtocolV2()
    token: list[bytes] = []

    def get() -> None:
        session = PinSession(ctap, protocol)
        response = session.client_pin(GET_TOKEN_USING_UV, permissions=permissions)
        token.append(protocol.decrypt(session.secret, response[PIN_UV_AUTH_TOKEN]))

    status = answered(user, True, TOKEN_TITLE, get, snapshot)
    check(
        status == CtapError.ERR.SUCCESS and len(token) == 1,
        f"built-in UV: a token with permissions {permissions:#04x} ({status!r})",
    )
    return token[0]


def check_credential_management(
    device: CtapHidDevice, user, snapshot, registered: dict[str, object]
) -> None:
    """authenticatorCredentialManagement (CTAP 2.2 §6.8) with a cm token from built-in UV, on the
    credentials check_credentials registered: the metadata counts them, the RPs and the RP's
    credentials enumerate with their users and public keys, updateUserInformation renames one,
    and deleteCredential of either key origin, confirmed on the device, leaves an ID that no
    longer signs."""
    ctap = Ctap2(device)
    info_options = ctap.info.options
    check(
        info_options.get("credMgmt") is True and info_options.get("authnrCfg") is True,
        f"getInfo: credMgmt and authnrCfg ({info_options})",
    )
    token = uv_token(ctap, user, PERMISSION_CM, snapshot("cm_token", TOKEN_TITLE))
    credman = CredentialManagement(ctap, PinProtocolV2(), token)
    result = CredentialManagement.RESULT
    metadata = credman.get_metadata()
    check(
        metadata[result.EXISTING_CRED_COUNT] >= len(registered),
        f"credMgmt: {metadata[result.EXISTING_CRED_COUNT]} discoverable credentials, "
        f"{metadata[result.MAX_REMAINING_COUNT]} more fit",
    )
    rps = {rp[result.RP]["id"]: rp[result.RP_ID_HASH] for rp in credman.enumerate_rps()}
    check(
        rps.get(RP_ID) == hashlib.sha256(RP_ID.encode()).digest(),
        f"credMgmt: the RPs enumerate with their hashes ({len(rps)} RPs)",
    )
    rp_hash = hashlib.sha256(RP_ID.encode()).digest()
    listed = credman.enumerate_creds(rp_hash)
    by_id = {entry[result.CREDENTIAL_ID]["id"]: entry for entry in listed}
    expected = {data.credential_id: data for data in registered.values()}
    check(
        set(by_id) >= set(expected)
        and all(by_id[cid][result.PUBLIC_KEY] == data.public_key for cid, data in expected.items())
        and by_id[registered["seed"].credential_id][result.USER]["name"] == "seed user",
        f"credMgmt: the credentials of {RP_ID} enumerate with their users and public keys",
    )
    seed_id = {"type": "public-key", "id": registered["seed"].credential_id}
    credman.update_user_info(
        seed_id, {"id": b"user-seed", "name": "renamed user", "displayName": "Renamed"}
    )
    renamed = {
        entry[result.CREDENTIAL_ID]["id"]: entry[result.USER] for entry in credman.enumerate_creds(rp_hash)
    }[registered["seed"].credential_id]
    check(
        renamed.get("name") == "renamed user" and renamed.get("displayName") == "Renamed",
        "credMgmt: updateUserInformation renames a credential",
    )
    client_data_hash = hashlib.sha256(b"client data").digest()
    for origin in ("device", "seed"):
        descriptor = {"type": "public-key", "id": registered[origin].credential_id}
        # §6.8.5 asks for no gesture beyond the token: no screen.
        status = ctap_status(lambda d=descriptor: credman.delete_cred(d))
        check(status == CtapError.ERR.SUCCESS, f"credMgmt: the {origin} credential is deleted ({status!r})")
        status = ctap_status(
            lambda d=descriptor: ctap.get_assertion(
                RP_ID, client_data_hash, [d], options={"up": False}
            )
        )
        check(
            status == CtapError.ERR.NO_CREDENTIALS,
            f"credMgmt: the deleted {origin} credential no longer signs ({status!r})",
        )


def u2f_answered(user, start: str, labels: tuple[str, str], confirm: bool, call, snapshot=None):
    """Runs the U2F `call` while the user answers the screen that starts with `start`, checking in
    Speculos that it names the application by its label; returns the status word, 0x9000 with the
    result, or the error status with None."""

    def answer() -> None:
        if isinstance(user, SpeculosUser):
            wait_for_screen(start)
            if snapshot is not None:
                snapshot()
            shown = user.read_until(labels[0] if confirm else labels[1])
            check(
                "".join(U2F_LABEL.split()) in shown,
                f"U2F: the screen names the application {U2F_LABEL}",
            )
        user.answer(confirm, labels)

    def run():
        try:
            return APDU.OK, call()
        except ApduError as error:
            return error.code, None

    return while_answering(1.0, answer, run)


def check_u2f(device: CtapHidDevice, user, snapshot) -> None:
    """CTAP1/U2F messages over CTAPHID_MSG (U2F raw messages v1.2): getInfo lists U2F_V2 and
    INIT reports MSG; U2F_VERSION answers U2F_V2; a registration confirmed on the device returns a
    key handle, a certificate of the credential key and a signature that python-fido2 verifies
    with that certificate; a refused one is SW_CONDITIONS_NOT_SATISFIED; check-only tells the key
    handle of this application (SW_CONDITIONS_NOT_SATISFIED) from another's (SW_WRONG_DATA); a
    sign-in confirmed on the device signs with user presence and a counter of 0, with the
    enforce and the don't-enforce control byte alike, and a refused one gives no signature; the
    same key handle signs over CTAP2 for the appid URL as RP ID; with alwaysUv on, U2F is
    SW_COMMAND_NOT_ALLOWED and getInfo leaves U2F_V2 out."""
    ctap = Ctap2(device)
    ctap1 = Ctap1(device)
    check("U2F_V2" in ctap.info.versions, f"getInfo: versions {ctap.info.versions}")
    check(ctap1.get_version() == "U2F_V2", "U2F_VERSION answers U2F_V2")
    app_param = hashlib.sha256(U2F_APP_ID.encode()).digest()
    client_param = hashlib.sha256(b"u2f client data").digest()
    register_labels = (U2F_REGISTER, U2F_REGISTER_REJECT)
    sign_in_labels = (SIGN_IN, SIGN_IN_REJECT)

    status, _ = u2f_answered(
        user, U2F_REGISTER_START, register_labels, False,
        lambda: ctap1.register(client_param, app_param),
    )
    check(status == APDU.USE_NOT_SATISFIED, f"U2F: a refused registration is {status:#06x}")
    status, registration = u2f_answered(
        user, U2F_REGISTER_START, register_labels, True,
        lambda: ctap1.register(client_param, app_param),
        snapshot("u2f_register", U2F_REGISTER_START),
    )
    check(status == APDU.OK, f"U2F: a confirmed registration ({status:#06x})")
    # python-fido2 checks the signature with the certificate's key, which is the credential's.
    registration.verify(app_param, client_param)
    check(
        registration.certificate and len(registration.key_handle) <= 255,
        f"U2F: the registration verifies with its {len(registration.certificate)}-byte certificate",
    )
    key_handle = registration.key_handle

    for app, expected in ((app_param, APDU.USE_NOT_SATISFIED), (bytes(32), APDU.WRONG_DATA)):
        try:
            ctap1.authenticate(client_param, app, key_handle, check_only=True)
            status = APDU.OK
        except ApduError as error:
            status = error.code
        check(status == expected, f"U2F: check-only answers {status:#06x}")

    status, signed = u2f_answered(
        user, U2F_SIGN_IN_START, sign_in_labels, True,
        lambda: ctap1.authenticate(client_param, app_param, key_handle),
        snapshot("u2f_sign_in", U2F_SIGN_IN_START),
    )
    check(
        status == APDU.OK and signed.user_presence == 1 and signed.counter == 0,
        f"U2F: a confirmed sign-in signs with presence and counter 0 ({status:#06x})",
    )
    signed.verify(app_param, client_param, registration.public_key)
    data = client_param + app_param + bytes([len(key_handle)]) + key_handle
    status, response = u2f_answered(
        user, U2F_SIGN_IN_START, sign_in_labels, True,
        lambda: ctap1.send_apdu(ins=Ctap1.INS.AUTHENTICATE, p1=U2F_DONT_ENFORCE, data=data),
    )
    check(
        status == APDU.OK and response[0] == 1,
        f"U2F: don't-enforce still asks on the device and signs ({status:#06x})",
    )
    status, _ = u2f_answered(
        user, U2F_SIGN_IN_START, sign_in_labels, False,
        lambda: ctap1.authenticate(client_param, app_param, key_handle),
    )
    check(status == APDU.USE_NOT_SATISFIED, f"U2F: a refused sign-in is {status:#06x}")

    # The appid extension: the platform asks CTAP2 with the appid URL as the RP ID.
    client_data_hash = hashlib.sha256(b"client data").digest()
    status, assertion = pressed(
        user,
        # A Nano opens the question on its short title, "Sign in?".
        [(U2F_SIGN_IN_START, SIGN_IN, None)],
        lambda: ctap.get_assertion(
            U2F_APP_ID, client_data_hash, [{"type": "public-key", "id": key_handle}]
        ),
    )
    check(status == CtapError.ERR.SUCCESS, f"getAssertion: the U2F key handle as appid ({status!r})")
    assertion.verify(client_data_hash, ES256.from_ctap1(registration.public_key))

    token = uv_token(ctap, user, PERMISSION_ACFG)
    config = Config(ctap, PinProtocolV2(), token)
    config.toggle_always_uv()
    try:
        ctap1.get_version()
        status = APDU.OK
    except ApduError as error:
        status = error.code
    versions = ctap.get_info().versions
    config.toggle_always_uv()
    check(
        status == 0x6986 and "U2F_V2" not in versions,
        f"U2F: with alwaysUv, SW_COMMAND_NOT_ALLOWED ({status:#06x}) and versions {versions}",
    )
    check(ctap1.get_version() == "U2F_V2", "U2F: back with alwaysUv off")


def check_config(device: CtapHidDevice, user) -> None:
    """authenticatorConfig toggleAlwaysUv (CTAP 2.2 §6.11.2) with an acfg token from built-in UV:
    getInfo reports alwaysUv on, then off again."""
    ctap = Ctap2(device)
    token = uv_token(ctap, user, PERMISSION_ACFG)
    config = Config(ctap, PinProtocolV2(), token)
    states = []
    for _ in range(2):
        config.toggle_always_uv()
        states.append(ctap.get_info().options.get("alwaysUv"))
    check(states == [True, False], f"authenticatorConfig: toggleAlwaysUv turns alwaysUv {states}")


# The settings button at the top right of a touch model's home screen (NBGL
# `nbgl_layoutAddTopRightButton`: `BUTTON_WIDTH` by `BUTTON_DIAMETER`, `BORDER_MARGIN` from the
# corner).
SETTINGS_BUTTON = {"stax": (336, 64), "flex": (404, 76), "apex_p": (257, 44)}
SETTINGS_RP_ID = "settings.example"
PASSKEY_TITLE = f"Passkey for {SETTINGS_RP_ID}"


def open_passkey_list(user: SpeculosUser) -> None:
    """From the home screen to the passkey list of the settings, as the person would."""
    if user.nano:
        for _ in range(10):
            if button("App settings") is not None:
                break
            api("/button/right", {"action": "press-and-release"})
            time.sleep(0.2)
        api("/button/both", {"action": "press-and-release"})
        time.sleep(0.5)
        user.press("Passkeys")
        return
    # The home screen, after the status page of the last ceremony, which a touch would only end.
    wait_for_screen("Quit app")
    x, y = SETTINGS_BUTTON[user.model]
    api("/finger", {"action": "press-and-release", "x": x, "y": y})
    # The first settings page holds the passkey list entry; the header, the application's name,
    # reads "Passkeys" too, so the entry is the one below it.
    for _ in range(100):
        entries = [e for e in screen_texts() if e["text"].strip() == "Passkeys"]
        if len(entries) > 1:
            entry = max(entries, key=lambda e: e["y"])
            api("/finger", {"action": "press-and-release", "x": entry["x"], "y": entry["y"]})
            return
        time.sleep(0.1)
    raise SystemExit(f"FAILED: no passkey list entry in the settings: {screen_texts()}")


def check_settings_list(device: CtapHidDevice, user: SpeculosUser, snapshot) -> None:
    """The passkey list of the device's settings, in Speculos: a new credential is listed first,
    deleting it there through its deletion screen leaves an ID that no longer signs, and the
    list, empty then, says so. The list and the deletion screen are compared with their
    snapshots."""
    ctap = Ctap2(device)
    client_data_hash = hashlib.sha256(b"client data").digest()
    status, made = pressed(
        user,
        # A Nano heads this registration with the short question.
        [(REGISTER_START, REGISTER_CONFIRM, None)],
        lambda: ctap.make_credential(
            client_data_hash,
            {"id": SETTINGS_RP_ID, "name": "Settings"},
            {"id": b"user-settings", "name": "settings user"},
            [{"type": "public-key", "alg": -7}],
            options={"rk": True, "uv": True},
        ),
    )
    check(status == CtapError.ERR.SUCCESS, f"settings: a passkey to list ({status!r})")
    open_passkey_list(user)
    wait_for_screen(PASSKEY_TITLE)
    list_snapshot = snapshot("passkey_list", PASSKEY_TITLE)
    if list_snapshot is not None:
        list_snapshot()
    user.press(DELETE_CONFIRM)
    # "Delete the passkey for <RP>?", or on a Nano, which shortens it, "Delete this passkey?".
    wait_for_screen("Delete th")
    delete_snapshot = snapshot("delete", "Delete th")
    if delete_snapshot is not None:
        delete_snapshot()
    user.press(DELETE_CONFIRM)
    # The list again, without it: credential management deleted the others, so it is empty.
    wait_for_screen("No passkeys")
    check(not screen_shows(SETTINGS_RP_ID), "settings: the deleted passkey left the list")
    user.press("OK")
    descriptor = {"type": "public-key", "id": made.auth_data.credential_data.credential_id}
    status = ctap_status(
        lambda: ctap.get_assertion(SETTINGS_RP_ID, client_data_hash, [descriptor], options={"up": False})
    )
    check(
        status == CtapError.ERR.NO_CREDENTIALS,
        f"settings: the passkey deleted in the list no longer signs ({status!r})",
    )


def snapshot_check(model: str, directory: Path, golden: bool, name: str, title: str):
    """Compares the shown screen titled `title` with the model's snapshot `name`, or writes it
    with `golden`."""
    path = directory / model / f"{name}.png"

    def compare() -> None:
        wait_for_screen(title)
        shot = api("/screenshot")
        if golden:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(shot)
            print(f"ok: {name} screen written to {path}")
            return
        check(path.is_file() and path.read_bytes() == shot, f"{name} screen matches {path}")

    return compare


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--speculos", action="store_true")
    parser.add_argument("--model", help="Speculos model, for the screen and the snapshot")
    parser.add_argument("--snapshots", type=Path, help="directory of the screen snapshots")
    parser.add_argument("--golden", action="store_true", help="write the snapshots instead")
    args = parser.parse_args()

    keepalives = KeepaliveLog()
    device = connect(args.speculos, keepalives)
    check(device.version == 2, f"INIT: channel {device._channel_id:#x}, CTAPHID protocol 2")
    capabilities = CAPABILITY(device.capabilities)
    check(
        CAPABILITY.CBOR in capabilities and CAPABILITY.NMSG not in capabilities,
        f"INIT: capabilities {capabilities!r} (CBOR and MSG)",
    )

    if args.speculos:
        if args.model is None:
            raise SystemExit("--speculos needs --model for the screen")
        user = SpeculosUser(args.model)
        snapshots = args.snapshots

        def snapshot(name: str, title: str):
            if snapshots is None:
                return None
            return snapshot_check(args.model, snapshots, args.golden, name, title)

        # First, while the reset window is open. A device keeps its credentials, so it is not
        # reset here.
        check_reset(device, user, snapshot("reset", RESET_TITLE))

    else:
        user = PersonAtDevice()

        def snapshot(name: str, title: str):
            return None

    for length in (1, MAX_MESSAGE):
        payload = os.urandom(length)
        check(device.ping(payload) == payload, f"PING echoes {length} bytes")
    status = ctap_status(lambda: device.ping(os.urandom(MAX_MESSAGE + 1)))
    check(
        status == CtapError.ERR.INVALID_LENGTH,
        f"PING of {MAX_MESSAGE + 1} bytes is ERR_INVALID_LEN ({status!r})",
    )

    info = Ctap2(device).info
    check(bytes(info.aaguid) == AAGUID, f"getInfo: AAGUID {bytes(info.aaguid).hex()}")
    check(info.max_msg_size == MAX_MESSAGE, f"getInfo: maxMsgSize {info.max_msg_size}")
    if args.model is not None:
        transports = ["usb"] if args.model in NANO_MODELS else ["nfc", "usb"]
        check(sorted(info.transports) == transports, f"getInfo: transports {info.transports}")

    # The screens the person answers come first, in the order refuse, allow, allow; the ones
    # left unanswered (cancel, timeout) last, so no answer is given to the wrong screen.
    check_selection_answers(device, user, snapshot("selection", SELECTION_TITLE))
    check_built_in_uv(device, user, snapshot("uv_token", TOKEN_TITLE))
    registered = check_credentials(device, user, snapshot)
    check_credential_management(device, user, snapshot, registered)
    check_config(device, user)
    check_extensions(device, user)
    check_u2f(device, user, snapshot)
    if args.speculos:
        check_settings_list(device, user, snapshot)
        # The reset left the PIN unset, so it can be set; a device keeps its PIN.
        check_client_pin(device, user, snapshot("token", TOKEN_TITLE))
    check_selection_unanswered(device, keepalives)
    if args.speculos:
        check_input_restarts_timeout(device, user)
        # The selection timeout alone outlasts the reset window.
        check_reset_window_closed(device)
    device.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"FAILED: {error!r}", file=sys.stderr)
        sys.exit(1)

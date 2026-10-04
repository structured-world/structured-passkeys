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

Checks: INIT allocates a channel and reports CTAPHID protocol 2 with CBOR and without MSG; PING
echoes 1-byte and 1024-byte payloads, and a 1025-byte one is ERR_INVALID_LEN (the message size of
every transport); getInfo parses with strict CBOR checks and reports the application AAGUID, a
1024-byte maxMsgSize and the transports of the model (nfc and usb on Stax, Flex and Nano Gen5).

authenticatorSelection (CTAP 2.2 §6.9), a request waiting for the user: while it waits, keepalives
with status UPNEEDED arrive about every 100 ms (§11.2.9.1.7); CTAPHID_CANCEL ends it with
CTAP2_ERR_KEEPALIVE_CANCEL; no answer ends it with CTAP2_ERR_USER_ACTION_TIMEOUT after 30 seconds;
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

The screens to answer come first and those to leave alone last, so at a device the person
answers: selection "Don't allow", selection "Allow", token consent "Allow", then nothing while
a selection is cancelled and the next one times out.
"""

import argparse
import hashlib
import json
import os
import socket
import struct
import sys
import threading
import time
import urllib.request
from pathlib import Path

from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
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
# getAssertion permission (§6.5.5.7).
PERMISSION_GA = 0x02


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
    """The text element of the current screen that reads exactly `text`: a button label, not a
    title that happens to contain the same word."""
    for event in screen_texts():
        if event["text"].strip() == text:
            return event
    return None


def wait_for_screen(text: str) -> None:
    for _ in range(100):
        if screen_shows(text):
            return
        time.sleep(0.1)
    raise SystemExit(f"FAILED: the screen never showed {text!r}: {screen_texts()}")


SELECTION_LABELS = (SELECTION_CONFIRM, SELECTION_REJECT)
RESET_LABELS = (RESET_CONFIRM, RESET_REJECT)


class SpeculosUser:
    """Answers a screen through the Speculos API, as the person would; `labels` are its confirm
    and reject choices."""

    def __init__(self, model: str):
        self.nano = model in NANO_MODELS

    def answer(self, confirm: bool, labels: tuple[str, str] = SELECTION_LABELS) -> None:
        wanted = labels[0] if confirm else labels[1]
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
        wanted = labels[0] if confirm else labels[1]
        print(f"   on the device, choose {wanted!r}", flush=True)


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

        # The answer runs in the timer's thread, where an exception (a failed snapshot check
        # raises SystemExit) would end only that thread: it is kept and raised here instead.
        failure: list[BaseException] = []

        def answer(confirm: bool = confirm) -> None:
            try:
                if snapshot is not None and confirm:
                    snapshot()
                user.answer(confirm)
            except BaseException as error:
                failure.append(error)

        timer = threading.Timer(1.0, answer)
        timer.start()
        status = selection(ctap)
        timer.join()
        if failure:
            raise failure[0]
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


def check(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAILED: {message}")
    print(f"ok: {message}")


def ctap_status(call) -> int:
    """Runs `call` and returns its CTAP status: success, or the error it raised."""
    try:
        call()
        return CtapError.ERR.SUCCESS
    except CtapError as error:
        return error.code


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
    after the call starts; returns its CTAP status. The answer runs in a timer's thread; an
    exception there is kept and raised here."""
    failure: list[BaseException] = []

    def answer() -> None:
        try:
            if isinstance(user, SpeculosUser):
                wait_for_screen(title)
            if snapshot is not None:
                snapshot()
            user.answer(confirm, labels)
        except BaseException as error:
            failure.append(error)

    timer = threading.Timer(delay_s, answer)
    timer.start()
    status = ctap_status(call)
    timer.join()
    if failure:
        raise failure[0]
    return status


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
        CAPABILITY.CBOR in capabilities and CAPABILITY.NMSG in capabilities,
        f"INIT: capabilities {capabilities!r} (CBOR, no MSG)",
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
    if args.speculos:
        # The reset left the PIN unset, so it can be set; a device keeps its PIN.
        check_client_pin(device, user, snapshot("token", TOKEN_TITLE))
    check_selection_unanswered(device, keepalives)
    if args.speculos:
        # The selection timeout alone outlasts the reset window.
        check_reset_window_closed(device)
    device.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"FAILED: {error!r}", file=sys.stderr)
        sys.exit(1)

#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["fido2==2.2.1"]
# ///
"""Checks the FIDO applet over NFC (CTAP 2.2 §11.3) in Speculos.

    nfc_check.py --model stax   the application in Speculos started with `--transport NFC
                                --apdu-port 9999`, whose APDU port then carries NFC APDUs

Applet: SELECT of another AID answers 6A82 and selects nothing, so a CTAP command is still refused
(6985); SELECT of the FIDO AID answers "FIDO_2_0"; NFCCTAP_CONTROL END deselects (§11.3.4).

CTAP over APDUs, with the client of python-fido2 framing requests in short APDUs (chained with CLA
90, responses read with GET RESPONSE) and in extended ones: getInfo reports maxMsgSize 1024 and
the transports nfc and usb; a request longer than 1024 bytes is CTAP2_ERR_REQUEST_TOO_LARGE.

Ceremonies, the screens answered through the Speculos API: authenticatorReset in its window with
the confirmation on the device; authenticatorSelection answers at once, the tap being the user
presence; two discoverable registrations on taps and a sign-in with hmac-secret, which answers
the count and the first account, getNextAssertion the second, each with its own PRF output and
the same ones on a second sign-in; getPinToken waits for the consent on the device while the platform polls with
NFCCTAP_GETRESPONSE and gets status updates with "user presence needed", or, from a client
without them, answers its NFCCTAP_MSG directly; a poll with P1 0x11 cancels a waiting request
(CTAP2_ERR_KEEPALIVE_CANCEL).
"""

import argparse
import hashlib
import socket
import struct
import sys
import threading
import time
from collections.abc import Callable

from fido2.ctap import STATUS, CtapDevice, CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import PinProtocolV2
from fido2.hid import CAPABILITY, CTAPHID

from fido_check import (
    GET_PIN_TOKEN,
    RESET_LABELS,
    RESET_TITLE,
    SELECTION_TITLE,
    SPECULOS_APDU_PORT,
    TIMEOUT_SLACK_S,
    TOKEN_TITLE,
    USER_ACTION_TIMEOUT_S,
    PinSession,
    SpeculosUser,
    answered,
    check,
    ctap_status,
    pin_hash,
    pin_token,
    screen_shows,
    set_pin,
)

AID = bytes.fromhex("A0000006472F0001")
SW_OK = 0x9000
SW_UPDATE = 0x9100
MAX_MESSAGE = 1024
STATUS_UPNEEDED = 2


class SpeculosApdu:
    """Command APDUs through the Speculos APDU socket: each travels with a 4-byte big-endian
    length; Speculos announces the response 2 bytes shorter than it sends, the status word."""

    def __init__(self):
        self.sock = socket.create_connection(("127.0.0.1", SPECULOS_APDU_PORT))
        self.sock.settimeout(USER_ACTION_TIMEOUT_S + 2 * TIMEOUT_SLACK_S)

    def _read(self, size: int) -> bytes:
        data = b""
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise ConnectionError("Speculos closed the connection")
            data += chunk
        return data

    def transmit(self, apdu: bytes) -> tuple[bytes, int]:
        self.sock.sendall(struct.pack(">I", len(apdu)) + apdu)
        size = struct.unpack(">I", self._read(4))[0] + 2
        response = self._read(size)
        return response[:-2], int.from_bytes(response[-2:], "big")

    def close(self) -> None:
        self.sock.close()


class NfcCtap(CtapDevice):
    """CTAP over the APDUs of §11.3, framed as python-fido2's NFC client frames them: short
    APDUs with command chaining and GET RESPONSE, or extended ones; NFCCTAP_GETRESPONSE polls
    while the request waits, unless `updates` is off."""

    def __init__(self, link: SpeculosApdu, extended: bool = False, updates: bool = True):
        self.link = link
        self.extended = extended
        self.updates = updates

    @property
    def capabilities(self) -> int:
        return CAPABILITY.CBOR

    def exchange(self, cla: int, ins: int, p1: int, p2: int, data: bytes = b"") -> tuple[bytes, int]:
        if self.extended:
            return self.link.transmit(struct.pack(">BBBBBH", cla, ins, p1, p2, 0, len(data)) + data)
        while len(data) > 250:
            part, data = data[:250], data[250:]
            response, sw = self.link.transmit(struct.pack(">BBBBB", 0x10 | cla, ins, p1, p2, len(part)) + part)
            if sw != SW_OK:
                return response, sw
        apdu = struct.pack(">BBBB", cla, ins, p1, p2)
        if data:
            apdu += struct.pack(">B", len(data)) + data
        response, sw = self.link.transmit(apdu + b"\x00")
        while sw >> 8 == 0x61:
            part, sw = self.link.transmit(b"\x00\xC0\x00\x00" + bytes([sw & 0xFF]))
            response += part
        return response, sw

    def call(
        self,
        cmd: int,
        data: bytes = b"",
        event: threading.Event | None = None,
        on_keepalive: Callable[[STATUS], None] | None = None,
    ) -> bytes:
        if cmd != CTAPHID.CBOR:
            raise CtapError(CtapError.ERR.INVALID_COMMAND)
        event = event or threading.Event()
        response, sw = self.exchange(0x80, 0x10, 0x80 if self.updates else 0x00, 0x00, data)
        while sw == SW_UPDATE:
            if on_keepalive:
                on_keepalive(STATUS(response[0]))
            p1 = 0x11 if event.wait(0.1) else 0x00
            response, sw = self.exchange(0x80, 0x11, p1, 0x00)
        if sw != SW_OK:
            raise CtapError(CtapError.ERR.OTHER)
        return response

    @classmethod
    def list_devices(cls):
        return iter(())


def check_applet(link: SpeculosApdu) -> None:
    ndef = bytes.fromhex("D2760000850101")
    _, sw = link.transmit(b"\x00\xA4\x04\x00" + bytes([len(ndef)]) + ndef + b"\x00")
    check(sw == 0x6A82, f"SELECT of another AID is not found ({sw:04x})")
    _, sw = link.transmit(b"\x80\x10\x00\x00\x01\x04\x00")
    check(sw == 0x6985, f"no CTAP before the FIDO applet is selected ({sw:04x})")
    select(link)


def select(link: SpeculosApdu) -> None:
    version, sw = link.transmit(b"\x00\xA4\x04\x00" + bytes([len(AID)]) + AID + b"\x00")
    check((version, sw) == (b"FIDO_2_0", SW_OK), f"SELECT answers {version!r} {sw:04x}")


def check_get_info(link: SpeculosApdu) -> None:
    for extended in (False, True):
        info = Ctap2(NfcCtap(link, extended=extended)).info
        form = "extended" if extended else "short"
        check(info.max_msg_size == MAX_MESSAGE, f"getInfo in {form} APDUs: maxMsgSize {info.max_msg_size}")
        check(
            sorted(info.transports) == ["nfc", "usb"],
            f"getInfo in {form} APDUs: transports {info.transports}",
        )
    # A getInfo with 1100 bytes of padding goes in five chained parts and is too large to hold.
    response = NfcCtap(link).call(CTAPHID.CBOR, b"\x04" + b"\x00" * 1100)
    check(response == b"\x39", f"a request beyond 1024 bytes is REQUEST_TOO_LARGE ({response.hex()})")


def check_reset(link: SpeculosApdu, user: SpeculosUser) -> None:
    ctap = Ctap2(NfcCtap(link))
    status = answered(user, True, RESET_TITLE, ctap.reset, labels=RESET_LABELS, delay_s=0.1)
    check(status == CtapError.ERR.SUCCESS, f"reset over NFC, confirmed on the device ({status!r})")


def check_selection(link: SpeculosApdu) -> None:
    started = time.monotonic()
    status = ctap_status(Ctap2(NfcCtap(link)).selection)
    waited = time.monotonic() - started
    check(
        status == CtapError.ERR.SUCCESS and waited < 2 and not screen_shows(SELECTION_TITLE),
        f"selection over NFC: the tap is presence, no screen ({status!r}, {waited:.1f} s)",
    )


def check_hmac_secret(link: SpeculosApdu) -> None:
    """hmac-secret over the tap (CTAP 2.2 §12.7): with no account list over NFC, a sign-in of two
    discoverable accounts answers the count and the first, and getNextAssertion the second, each
    with its own PRF output for the same salt; a second sign-in gives the same outputs."""
    ctap = Ctap2(NfcCtap(link))
    protocol = PinProtocolV2()
    client_data_hash = hashlib.sha256(b"client data").digest()
    rp = {"id": "prf.example.com", "name": "PRF"}
    params = [{"type": "public-key", "alg": -7}]
    for user_id in (b"prf-1", b"prf-2"):
        # Each registration takes a tap of its own: the selection of the applet.
        select(link)
        status = ctap_status(
            lambda user_id=user_id: ctap.make_credential(
                client_data_hash,
                rp,
                {"id": user_id, "name": user_id.decode()},
                params,
                extensions={"hmac-secret": True},
                options={"rk": True, "uv": True},
            )
        )
        check(status == CtapError.ERR.SUCCESS, f"registration {user_id!r} over the tap ({status!r})")
    salt = hashlib.sha256(b"prf salt").digest()

    def sign_in() -> dict[bytes, bytes]:
        select(link)
        session = PinSession(ctap, protocol)
        salt_enc = protocol.encrypt(session.secret, salt)
        extensions = {
            "hmac-secret": {
                1: session.key_agreement,
                2: salt_enc,
                3: protocol.authenticate(session.secret, salt_enc),
                4: protocol.VERSION,
            }
        }
        first = ctap.get_assertion(rp["id"], client_data_hash, extensions=extensions)
        check(first.number_of_credentials == 2, f"sign-in over the tap counts {first.number_of_credentials}")
        second = ctap.get_next_assertion()
        outputs = {}
        for assertion in (first, second):
            output = assertion.auth_data.extensions.get("hmac-secret") if assertion.auth_data.extensions else None
            check(output is not None, "getAssertion and getNextAssertion each answer hmac-secret")
            outputs[bytes(assertion.credential["id"])] = protocol.decrypt(session.secret, output)
        return outputs

    once = sign_in()
    check(
        len(once) == 2 and all(len(v) == 32 for v in once.values()) and len(set(once.values())) == 2,
        "hmac-secret: one 32-byte output per account, different accounts differ",
    )
    check(sign_in() == once, "hmac-secret: a second sign-in gives the same outputs")


def check_token(link: SpeculosApdu, user: SpeculosUser) -> None:
    check(
        ctap_status(lambda: set_pin(Ctap2(NfcCtap(link)), PinProtocolV2(), "1234")) == CtapError.ERR.SUCCESS,
        "clientPIN over NFC: setPIN",
    )
    for updates in (True, False):
        updates_seen: list[STATUS] = []
        device = NfcCtap(link, updates=updates)
        ctap = Ctap2(device)
        original = device.call

        def call(cmd, data=b"", event=None, on_keepalive=None, original=original):
            return original(cmd, data, event, lambda status: updates_seen.append(status))

        device.call = call
        token: list[bytes] = []
        status = answered(
            user, True, TOKEN_TITLE, lambda: token.append(pin_token(ctap, PinProtocolV2(), "1234"))
        )
        form = "with status updates" if updates else "without status updates"
        check(
            status == CtapError.ERR.SUCCESS and [len(t) for t in token] == [32],
            f"getPinToken over NFC {form}: consent on the device gives a token ({status!r})",
        )
        expected = [STATUS.UPNEEDED] if updates else []
        check(
            sorted(set(updates_seen)) == expected,
            f"getPinToken over NFC {form}: status updates {sorted(set(updates_seen))}",
        )


def check_cancel(link: SpeculosApdu) -> None:
    """getPinToken whose consent is left unanswered: the platform cancels it a second later with
    a poll."""
    ctap = Ctap2(NfcCtap(link))
    protocol = PinProtocolV2()
    session = PinSession(ctap, protocol)
    cancel = threading.Event()
    threading.Timer(1.0, cancel.set).start()
    status = ctap_status(
        lambda: ctap.client_pin(
            protocol.VERSION,
            GET_PIN_TOKEN,
            key_agreement=session.key_agreement,
            pin_hash_enc=protocol.encrypt(session.secret, pin_hash("1234")),
            event=cancel,
        )
    )
    check(status == CtapError.ERR.KEEPALIVE_CANCEL, f"a poll with P1 0x11 cancels the request ({status!r})")


def check_deselect(link: SpeculosApdu) -> None:
    _, sw = link.transmit(b"\x80\x12\x01\x00")
    check(sw == SW_OK, f"NFCCTAP_CONTROL END deselects ({sw:04x})")
    _, sw = link.transmit(b"\x80\x10\x00\x00\x01\x04\x00")
    check(sw == 0x6985, f"no CTAP after deselection ({sw:04x})")
    select(link)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--model", required=True, help="Speculos model, for the screen")
    args = parser.parse_args()

    user = SpeculosUser(args.model)
    link = SpeculosApdu()
    check_applet(link)
    # While the reset window is open.
    check_reset(link, user)
    check_get_info(link)
    check_selection(link)
    check_hmac_secret(link)
    check_token(link, user)
    check_cancel(link)
    check_deselect(link)
    link.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"FAILED: {error!r}", file=sys.stderr)
        sys.exit(1)

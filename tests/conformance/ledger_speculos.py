"""Runs SoloKeys fido2-tests against the application in Speculos.

Loaded with `-p ledger_speculos`. It starts Speculos for SPECULOS_MODEL with SPECULOS_ELF on its
U2F transport and connects the suite's device to it; answers the confirmation screens as the user
at the device would, picking the account a test asks for; makes the suite's reboot a restart of
Speculos; and skips what the application does not report or Speculos cannot emulate, each with
its reason.
"""

import json
import os
import re
import socket
import struct
import subprocess
import threading
import time
import urllib.request

import fido2
import fido2._pyu2f.base
import fido2._pyu2f.hidtransport
import fido2.cbor
import fido2.client
import fido2.ctap1
import fido2.ctap2
import pytest
from fido2.hid import CAPABILITY, CtapHidDevice

API = "http://127.0.0.1:5000"
MODEL = os.environ["SPECULOS_MODEL"]
ELF = os.environ["SPECULOS_ELF"]
NANO = MODEL in ("nanosp", "nanox")
# Prints every screen the presser acts on.
DEBUG = os.environ.get("PRESSER_DEBUG") == "1"
# The questions the application asks, and the answer that confirms each.
QUESTIONS = (
    "Allow security key",
    "Create a passkey",
    "Sign in",
    "Reset the security key",
    "Already registered",
    "Register a security key",
    "Not registered",
)
CONFIRM = ("Allow", "Create passkey", "Sign in", "Reset", "OK", "Register")
# The application's name on its home screen.
HOME = "Structured Passkeys"
OTHER_ACCOUNT = "Other account"
# The next-page arrow at the right of a review's footer (NBGL FOOTER_TEXT_AND_NAV).
NEXT_PAGE = {"stax": (376, 626), "flex": (456, 552), "apex_p": (284, 370)}

# Tests that need the application's storage to outlive a restart, which Speculos does not keep
# for Rust applications ("NVRAM data save and load functionality is not yet implemented for Rust
# apps", speculos/main.py). The application's own unit tests cover the same behaviour.
NEEDS_NVRAM = {
    "test_lockout": "a PIN blocked across power cycles",
    "test_pin_attempts": "PIN retries restored by a power cycle",
    "test_user_info_returned_when_using_allowlist[-True]": "a credential kept across a power cycle",
    "test_user_info_returned_when_using_allowlist[123456-True]": "a credential kept across a power cycle",
}
# Tests whose premise CTAP 2.2 rules out for this authenticator, with the rule. The application's
# own tests cover the behaviour CTAP 2.2 gives instead; hmac-secret over getNextAssertion is
# checked on the device in scripts/nfc_check.py, over the NFC tap, where no account list is shown.
CTAP_2_2 = {
    "test_get_next_assertion_has_extension": "an authenticator with a display lists the accounts "
    "of a request with presence and returns the one picked, without numberOfCredentials (CTAP 2.2 "
    "section 6.2.2 step 15.2.3), and hmac-secret needs presence (section 12.7)",
    "test_credprotect_required_not_excluded_with_no_uv": "every registration verifies the user, as "
    "getInfo reports uv without makeCredUvNotRqd (CTAP 2.2 section 6.1.2 step 8), so a "
    "userVerificationRequired credential in the excludeList is found (step 16)",
}
# The channels the suite's transport tests name themselves.
SUITE_CHANNELS = (b"\x11\x22\x33\x44", b"\x01\x22\x33\x44", b"\x05\x04\x03\x02")
# Tests that leave a screen unanswered, with the number of confirmations they want first.
PRESS_BUDGET = {
    "test_no_user_presence": 0,
    "test_user_presence_permits_only_one_request": 1,
}


def api(path, body=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        API + path, data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.read()


def screen_texts():
    try:
        return json.loads(api("/events?currentscreenonly=true"))["events"]
    except Exception:
        return []


def find_answer(texts, wanted):
    """The event where one of the `wanted` answers starts, or None: an answer may be drawn over
    several lines, each a text event of its own, as the reject text of a review's footer."""
    for start, event in enumerate(texts):
        words = []
        for following in texts[start:]:
            words.append(following["text"].strip())
            shown = " ".join(words)
            if shown in wanted:
                return event
            if not any(answer.startswith(shown + " ") for answer in wanted):
                break
    return None


class Speculos:
    """The emulator process; a restart is the device's power cycle."""

    def __init__(self):
        self.process = None
        self.log = open("/tmp/speculos-conformance.log", "ab")

    def start(self):
        self.process = subprocess.Popen(
            [
                "speculos",
                "--model",
                MODEL,
                "--transport",
                "U2F",
                "--display",
                "headless",
                "--api-port",
                "5000",
                "--apdu-port",
                "9999",
                ELF,
            ],
            stdout=self.log,
            stderr=subprocess.STDOUT,
        )
        for _ in range(120):
            try:
                api("/events")
                return
            except Exception:
                time.sleep(0.5)
        raise RuntimeError("speculos did not start")

    def stop(self):
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(10)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None


SPECULOS = Speculos()


class SpeculosHid(fido2._pyu2f.base.HidDevice):
    """Speculos' U2F transport: 64-byte HID reports, each behind a 4-byte length."""

    def __init__(self):
        # A read that waits 30 seconds for nothing means Speculos stalled: while a request waits
        # for the user the application sends a keepalive every 100 ms. The bound also covers
        # the reads at collection time, where the per-test timeout does not run.
        self.sock = socket.create_connection(("127.0.0.1", 9999), timeout=30)

    def GetInReportDataLength(self):
        return 64

    def GetOutReportDataLength(self):
        return 64

    def Write(self, packet):
        packet = bytes(packet)
        self.sock.sendall(struct.pack(">I", len(packet)) + packet)

    def _read(self, length):
        data = b""
        while len(data) < length:
            chunk = self.sock.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Speculos closed the connection")
            data += chunk
        return data

    def Read(self):
        # The length Speculos sends leaves out the two status bytes it keeps for APDUs.
        size = (int.from_bytes(self._read(4), "big") + 2) & 0xFFFFFFFF
        return list(self._read(size))


def connect():
    transport = fido2._pyu2f.hidtransport.UsbHidTransport(SpeculosHid())
    return CtapHidDevice({"path": "speculos"}, transport)


class Presser(threading.Thread):
    """Answers every question on the screen with its confirming option; on the account picker it
    moves on to the account `pick` (1 is the most recent). `budget` limits the confirmations, for
    the tests that leave a screen unanswered."""

    def __init__(self):
        super().__init__(daemon=True)
        self.running = True
        self.pick = 1
        self.budget = None
        self.since = 0.0
        self.position = None
        self.flow = False

    def run(self):
        while self.running:
            try:
                self.step()
            except Exception:
                pass
            time.sleep(0.1)

    def press(self, event):
        if NANO:
            api("/button/both", {"action": "press-and-release"})
        else:
            api("/finger", {"action": "press-and-release", "x": event["x"], "y": event["y"]})

    def step(self):
        texts = screen_texts()
        joined = " ".join(" ".join(event["text"] for event in texts).split())
        # A long question is paged, by a Nano always and by a touch model as a review, and its
        # middle pages carry only details: once a question appears its pages are followed until
        # the home screen is back.
        if any(question in joined for question in QUESTIONS):
            if not self.flow:
                self.flow = True
                self.since = time.monotonic()
        elif HOME in joined:
            self.flow = False
        if not self.flow:
            return
        if DEBUG:
            print(f"presser {time.monotonic():.2f}: {joined!r}", flush=True)
        # The first screen of a question waits a moment: the keepalive that carries a test's
        # account choice arrives right after the screen is drawn.
        if time.monotonic() - self.since < 0.5:
            return
        if self.budget == 0:
            return
        # A long account screen is a review whose position line is on a later page: the
        # position seen on any page holds until the account is answered.
        position = re.search(r"Account (\d+) of (\d+)", joined)
        if position:
            self.position = int(position.group(1))
        wanted = CONFIRM
        if self.position is not None and self.position < self.pick:
            wanted = (OTHER_ACCOUNT,)
        event = find_answer(texts, wanted)
        if event is not None:
            # The state moves on before the press: the answer can reach the test, and the test
            # its next request or test (with its own pick and budget), before the press returns.
            self.position = None
            if wanted is CONFIRM:
                # The question is answered: the next one starts with its own wait.
                self.flow = False
                self.pick = 1
                if self.budget is not None:
                    self.budget -= 1
            self.press(event)
            self.wait_for_change(texts)
            return
        if NANO:
            api("/button/right", {"action": "press-and-release"})
        else:
            x, y = NEXT_PAGE[MODEL]
            api("/finger", {"action": "press-and-release", "x": x, "y": y})
        self.wait_for_change(texts)

    @staticmethod
    def wait_for_change(texts):
        """Waits, up to two seconds, for the screen to leave `texts`."""
        for _ in range(40):
            if screen_texts() != texts:
                return
            time.sleep(0.05)


PRESSER = Presser()


class SelectCredential:
    """The suite's account choice for a display authenticator: the presser takes account `n`."""

    def __init__(self, n):
        self.n = n

    def __call__(self, status):
        PRESSER.pick = self.n


def pytest_configure(config):
    import tests.conftest as conftest
    import tests.utils as utils

    def find_device(self, nfcInterfaceOnly=False):
        self.nfc_interface_only = nfcInterfaceOnly
        self.dev = connect()
        self.client = fido2.client.Fido2Client(self.dev, self.origin)
        self.ctap2 = self.client.ctap2
        self.ctap1 = fido2.ctap1.CTAP1(self.dev)
        # The device allocates every channel (CTAP 2.2 section 11.2.3) and refuses any other with
        # ERR_INVALID_CHANNEL, while the suite names its extra channels itself. Each name gets a
        # channel the device allocated, so the tests run on real channels; 0 and the broadcast
        # channel stay as they are, since their tests check exactly that refusal.
        transport = self.dev._dev
        own = transport.cid
        self.channels = {}
        for name in SUITE_CHANNELS:
            transport.InternalInit()
            self.channels[name] = bytes(transport.cid)
        transport.cid = own

    def set_cid(self, cid):
        if not isinstance(cid, (bytes, bytearray)):
            cid = struct.pack("%dB" % len(cid), *[ord(x) for x in cid])
        self.dev._dev.cid = self.channels.get(bytes(cid), cid)

    def reboot(self):
        SPECULOS.stop()
        SPECULOS.start()
        self.find_device(self.nfc_interface_only)

    send_mc = conftest.TestDevice.sendMC

    def sendMC(self, *args, **kwargs):
        # getInfo reports built-in user verification (`uv` true) without makeCredUvNotRqd, so a
        # platform asks for it in a registration that brings neither a PIN token nor the option
        # (CTAP 2.2 section 6.1.2 steps 8 to 11). The suite predates that rule: without a PIN set
        # it registers with no user verification at all. With a PIN set it brings the token, or
        # leaves it out on purpose to see CTAP2_ERR_PUAT_REQUIRED, so the request stays as it is.
        # Options of another type stay too: those tests check the type itself.
        args = list(args)
        options, pin_auth = args[6], args[7]
        pin_set = self.ctap2.get_info().options.get("clientPin", False)
        if pin_auth is None and not pin_set and (options is None or isinstance(options, dict)):
            options = dict(options or {})
            options.setdefault("uv", True)
            args[6] = options
        return send_mc(self, *args, **kwargs)

    conftest.TestDevice.find_device = find_device
    conftest.TestDevice.set_cid = set_cid
    conftest.TestDevice.reboot = reboot
    conftest.TestDevice.sendMC = sendMC
    utils.DeviceSelectCredential = SelectCredential

    # python-fido2 0.8.1 knows the response members of CTAP 2.0 only and fails on userSelected
    # (0x06), which CTAP 2.2 section 6.2.2 step 15.2.3 sets after the account picker. Members it
    # does not know are left out of its view; the CBOR is still decoded, key order checks
    # included.
    response = fido2.ctap2.AssertionResponse
    known = {key.value for key in response.KEY}

    def assertion_init(self, _):
        decoded = fido2.cbor.decode(self)
        data = {response.KEY(k): v for k, v in decoded.items() if k in known}
        self.credential = data.get(response.KEY.CREDENTIAL)
        self.auth_data = fido2.ctap2.AuthenticatorData(data[response.KEY.AUTH_DATA])
        self.signature = data[response.KEY.SIGNATURE]
        self.user = data.get(response.KEY.USER)
        self.number_of_credentials = data.get(response.KEY.N_CREDS)
        self.data = data

    response.__init__ = assertion_init
    SPECULOS.start()
    PRESSER.start()


def pytest_collection_modifyitems(config, items):
    hid = SpeculosHid()
    device = CtapHidDevice({"path": "speculos"}, fido2._pyu2f.hidtransport.UsbHidTransport(hid))
    hid.sock.close()
    for item in items:
        path = item.nodeid
        reason = CTAP_2_2.get(item.originalname)
        if reason:
            item.add_marker(pytest.mark.skip(reason=reason))
        if item.originalname == "test_wink" and not device.capabilities & CAPABILITY.WINK:
            item.add_marker(
                pytest.mark.skip(
                    reason="the device does not report WINK, an optional command (CTAP 2.2 "
                    "section 11.2.9.2.1)"
                )
            )
        if "test_ctap1_interop.py" in path and device.capabilities & CAPABILITY.NMSG:
            item.add_marker(
                pytest.mark.skip(
                    reason="the device reports NMSG: no CTAPHID_MSG, so no CTAP1/U2F to interoperate with"
                )
            )
        # The device has a display: it lists the accounts of a request with presence and returns
        # the one picked, without numberOfCredentials (CTAP 2.2 section 6.2.2 step 15.2.3). The
        # suite's display variants apply, the others do not.
        if "test_resident_key.py" in path:
            if item.originalname.endswith("_nodisplay"):
                item.add_marker(
                    pytest.mark.skip(
                        reason="an authenticator with a display lists the accounts instead of "
                        "counting them (CTAP 2.2 section 6.2.2 step 15.2.3)"
                    )
                )
            elif item.originalname.endswith("_display"):
                item.own_markers = [m for m in item.own_markers if m.name != "skipif"]
            # Filling the 64 discoverable slots with the longest names takes minutes of
            # screens, more than the suite's per-test limit.
            if item.originalname == "test_rk_maximum_list_capacity_per_rp_display":
                item.add_marker(pytest.mark.timeout(1800))
        reason = NEEDS_NVRAM.get(item.name) or NEEDS_NVRAM.get(item.originalname)
        if reason:
            item.add_marker(
                pytest.mark.skip(
                    reason=f"{reason}: Speculos does not keep the NVRAM of a Rust application across a restart"
                )
            )


def pytest_runtest_setup(item):
    PRESSER.pick = 1
    PRESSER.position = None
    PRESSER.budget = PRESS_BUDGET.get(item.originalname)


def pytest_unconfigure(config):
    PRESSER.running = False
    SPECULOS.stop()

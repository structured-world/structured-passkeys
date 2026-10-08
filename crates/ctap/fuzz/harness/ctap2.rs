//! CTAP2 requests from arbitrary bytes through the authenticator: the checks of the fuzz target.
//!
//! The first byte picks the user's answers, the rest is the request. The authenticator has a
//! client PIN set, so the PIN subcommands reach their checks. Every response must be a known
//! status and, on success, canonical CBOR; a request must never panic. Beyond the shape, the
//! clientPIN rules that hold for any input: a pinUvAuthToken only after the consent was approved
//! (CTAP 2.2 §6.5.5.7), the NFC tap included, built-in UV only on an unlocked device, a PIN try
//! spent only by a PIN check that fails, one at a time (§6.5.5.6, §6.5.5.7), and a selection only
//! with user presence (§6.9). For the credential commands, authenticator data reports user
//! presence only when the user answered on the device or the tap counted, and a new credential
//! always comes with both UP and UV (§6.1.2 steps 11 and 18).

use structured_passkeys_ctap::cbor::{Decoder, Key, validate};
use structured_passkeys_ctap::credential_id::Origin;
use structured_passkeys_ctap::crypto::{Crypto, KEY_LEN};
use structured_passkeys_ctap::ctap2::{
    Authenticator, Link, MaxMsgSize, NfcTap, Settings, Transports,
};
use structured_passkeys_ctap::soft::SoftCrypto;
use structured_passkeys_ctap::storage::{MemoryStorage, PinVerifier, Store};
use structured_passkeys_ctap::ui::{Accounts, Answer, Choice, Passkeys, Prompt, Registration, Ui};

/// Authenticator data flags UP and UV (WebAuthn L3 §6.1).
const UP: u8 = 0x01;
const UV: u8 = 0x04;

/// The status codes of CTAP 2.2 §8.2 the authenticator may answer with.
const STATUS_CODES: [u8; 46] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0A, 0x0B, 0x11, 0x12, 0x14, 0x15, 0x17, 0x18, 0x19,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
    0x33, 0x34, 0x35, 0x36, 0x37, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x7F,
];

/// A user whose answers come from one byte: bits 0-1 the confirmation, bit 2 the key origin
/// chosen at registration, bits 3-4 the account picked, bit 5 whether the device is locked.
struct Fuzzed(u8);

impl Fuzzed {
    fn answer(&self) -> Answer {
        match self.0 & 0x03 {
            0 => Answer::Confirmed,
            1 => Answer::Rejected,
            2 => Answer::Cancelled,
            _ => Answer::TimedOut,
        }
    }

    fn choice<T>(&self, chosen: T) -> Choice<T> {
        match self.answer() {
            Answer::Confirmed => Choice::Chose(chosen),
            Answer::Rejected => Choice::Rejected,
            Answer::Cancelled => Choice::Cancelled,
            Answer::TimedOut => Choice::TimedOut,
        }
    }
}

impl Ui for Fuzzed {
    fn confirm(&mut self, _prompt: Prompt<'_>, _timeout_ms: u32) -> Answer {
        self.answer()
    }

    fn register(&mut self, _registration: Registration<'_>, _timeout_ms: u32) -> Choice<Origin> {
        self.choice(if self.0 & 0x04 == 0 {
            Origin::SeedRecoverable
        } else {
            Origin::DeviceOnly
        })
    }

    fn pick<A: Accounts>(
        &mut self,
        _rp_id: &str,
        accounts: &mut A,
        _timeout_ms: u32,
    ) -> Choice<usize> {
        // Every account the picker offers reads, as the screen reads each one it shows.
        for index in 0..accounts.count() {
            assert!(
                accounts.read(index, |_| ()).is_some(),
                "account {index} unreadable"
            );
        }
        let wanted = usize::from((self.0 >> 3) & 0x03);
        self.choice(wanted % accounts.count().max(1))
    }

    fn browse<P: Passkeys>(
        &mut self,
        _passkeys: &mut P,
        _start: usize,
        _timeout_ms: u32,
    ) -> Choice<usize> {
        // The settings list belongs to the device, never to a request.
        unreachable!("no request opens the settings list")
    }

    fn device_unlocked(&mut self) -> bool {
        self.0 & 0x20 == 0
    }

    fn now_ms(&self) -> u64 {
        0
    }
}

/// The subCommand of an authenticatorClientPIN request, if the request is one and carries it.
fn client_pin_sub_command(request: &[u8]) -> Option<u64> {
    let (&0x06, parameters) = request.split_first()? else {
        return None;
    };
    Decoder::new(parameters)
        .map(|entries| {
            let mut found = None;
            while let Some(key) = entries.next_key()? {
                let value = entries.value();
                if key == Key::Int(0x02) {
                    found = value.unsigned().ok();
                } else {
                    value.skip()?;
                }
            }
            Ok(found)
        })
        .ok()
        .flatten()
}

/// The flags byte of the authenticator data in a makeCredential or getAssertion response body.
fn auth_data_flags(body: &[u8]) -> Option<u8> {
    Decoder::new(body)
        .map(|entries| {
            let mut flags = None;
            while let Some(key) = entries.next_key()? {
                let value = entries.value();
                if key == Key::Int(0x02) {
                    flags = value.bytes()?.get(KEY_LEN).copied();
                } else {
                    value.skip()?;
                }
            }
            Ok(flags)
        })
        .ok()
        .flatten()
}

/// Runs one input; panics on any broken property.
pub fn run(data: &[u8]) {
    let Some((&answers, request)) = data.split_first() else {
        return;
    };
    let crypto = SoftCrypto::new([0x11; KEY_LEN], [0x22; KEY_LEN]);
    let mut store = Store::open(MemoryStorage::new(4, 4));
    // The client PIN "1234": LEFT(SHA-256("1234"), 16).
    let hash = crypto.sha256(&[b"1234"]);
    let mut verifier = [0u8; 16];
    verifier.copy_from_slice(&hash[..16]);
    let mut config = store.config();
    config.pin = Some(PinVerifier::new(verifier));
    store.write_config(&config);
    let settings = Settings {
        max_msg_size: MaxMsgSize::try_from(1024).expect("at least 1024"),
        transports: Transports::UsbAndNfc,
    };
    let mut authenticator = Authenticator::new(settings, crypto, store);
    // Bit 6 sends the request over NFC, bit 7 with the device tapped first.
    let link = if answers & 0x40 == 0 {
        Link::Usb
    } else {
        Link::Nfc
    };
    if answers & 0x80 != 0 {
        authenticator.nfc_tap(NfcTap {
            at_ms: 0,
            selection: 0,
        });
    }
    let mut response = [0u8; 1024];
    let length = authenticator.process(request, link, &mut Fuzzed(answers), &mut response);
    assert!(length >= 1, "every request is answered");
    assert!(
        STATUS_CODES.contains(&response[0]),
        "unknown status {:#04x}",
        response[0]
    );
    if response[0] == 0x00 && length > 1 {
        assert_eq!(validate(&response[1..length]), Ok(()), "canonical response");
    } else {
        assert_eq!(length, 1, "an error carries no body");
    }

    let sub_command = client_pin_sub_command(request);
    let succeeded = response[0] == 0x00;
    let tapped = link == Link::Nfc && answers & 0x80 != 0;
    // makeCredential and getAssertion report user presence only after the user answered on the
    // device or the tap counted; a new credential always has UP and UV.
    if succeeded && matches!(request.first(), Some(0x01 | 0x02)) {
        let flags = auth_data_flags(&response[1..length]).expect("authenticator data");
        if flags & UP != 0 {
            assert!(
                tapped || answers & 0x03 == 0,
                "user presence only when proved"
            );
        }
        if request[0] == 0x01 {
            assert_eq!(flags & (UP | UV), UP | UV, "a credential with UP and UV");
            assert_eq!(answers & 0x20, 0, "a credential only on an unlocked device");
        }
    }
    // authenticatorSelection answers OK only with user presence: a confirmation on the device, or
    // over NFC the tap (§6.9).
    if succeeded && request == [0x0B] {
        assert!(
            tapped || answers & 0x03 == 0,
            "selection only with user presence"
        );
    }
    // getPinToken, getPinUvAuthTokenUsingUvWithPermissions, getPinUvAuthTokenUsingPinWithPermissions.
    if succeeded && matches!(sub_command, Some(0x05 | 0x06 | 0x09)) {
        assert_eq!(
            answers & 0x03,
            0,
            "a token only after the consent was approved"
        );
    }
    if succeeded && sub_command == Some(0x06) {
        assert_eq!(answers & 0x20, 0, "built-in UV only on an unlocked device");
    }
    let retries = authenticator.store().config().pin_retries;
    if retries != 8 {
        assert_eq!(retries, 7, "one try per request");
        assert_eq!(response[0], 0x31, "a spent try answers PIN_INVALID");
        assert!(
            matches!(sub_command, Some(0x04 | 0x05 | 0x09)),
            "only a PIN check spends a try"
        );
    }
}

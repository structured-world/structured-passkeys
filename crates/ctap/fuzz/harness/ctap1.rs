//! CTAP1/U2F messages from arbitrary bytes through the authenticator: the checks of the fuzz
//! target.
//!
//! The first byte picks the user's answer and the state, the rest is the message; with bit 2 set,
//! the rest instead fills an authentication with the key handle and application of a credential
//! registered beforehand, so signing paths are reached. A message must never panic, and for any
//! input: the response ends with a status word of U2F raw messages §3.3; while alwaysUv is on it
//! is SW_COMMAND_NOT_ALLOWED alone (CTAP 2.2 §7.2.2); a signature comes back only after the user
//! confirmed on the device; a check-only authentication never succeeds (§5.1); and a successful
//! registration has the layout of §4.3.

use structured_passkeys_ctap::credential_id::Origin;
use structured_passkeys_ctap::crypto::KEY_LEN;
use structured_passkeys_ctap::ctap1::{self, Control, Request};
use structured_passkeys_ctap::ctap2::{Authenticator, MaxMsgSize, Settings, Transports};
use structured_passkeys_ctap::soft::SoftCrypto;
use structured_passkeys_ctap::storage::{MemoryStorage, Store};
use structured_passkeys_ctap::ui::{Accounts, Answer, Choice, Passkeys, Prompt, Registration, Ui};

/// The status words U2F messages are answered with.
const STATUS_WORDS: [[u8; 2]; 8] = [
    [0x90, 0x00],
    [0x69, 0x85],
    [0x69, 0x86],
    [0x6A, 0x80],
    [0x67, 0x00],
    [0x6E, 0x00],
    [0x6D, 0x00],
    [0x6F, 0x00],
];
const NO_ERROR: [u8; 2] = [0x90, 0x00];
const COMMAND_NOT_ALLOWED: [u8; 2] = [0x69, 0x86];
/// The application of the credential registered before the message.
const APPLICATION: [u8; 32] = [0xA9; 32];

/// A user whose answer comes from two bits; a U2F message has no other screen than a
/// confirmation.
struct Fuzzed(Answer);

impl Ui for Fuzzed {
    fn confirm(&mut self, _prompt: Prompt<'_>, _timeout_ms: u32) -> Answer {
        self.0
    }

    fn register(&mut self, _registration: Registration<'_>, _timeout_ms: u32) -> Choice<Origin> {
        unreachable!("a U2F registration offers no key origin")
    }

    fn pick<A: Accounts>(
        &mut self,
        _rp_id: &str,
        _accounts: &mut A,
        _timeout_ms: u32,
    ) -> Choice<usize> {
        unreachable!("a U2F authentication names its key handle")
    }

    fn browse<P: Passkeys>(
        &mut self,
        _passkeys: &mut P,
        _start: usize,
        _timeout_ms: u32,
    ) -> Choice<usize> {
        unreachable!("no request opens the settings list")
    }

    fn device_unlocked(&mut self) -> bool {
        true
    }

    fn now_ms(&self) -> u64 {
        0
    }
}

/// Bytes of the DER value at the start of `bytes`, header included, if it is one.
fn der_len(bytes: &[u8]) -> Option<usize> {
    match *bytes.get(1)? {
        0x81 => Some(3 + usize::from(*bytes.get(2)?)),
        0x82 => Some(4 + usize::from(u16::from_be_bytes([*bytes.get(2)?, *bytes.get(3)?]))),
        short if short < 0x80 => Some(2 + usize::from(short)),
        _ => None,
    }
}

pub fn run(data: &[u8]) {
    let Some((&control, rest)) = data.split_first() else {
        return;
    };
    let answer = match control & 0x03 {
        0 => Answer::Confirmed,
        1 => Answer::Rejected,
        2 => Answer::Cancelled,
        _ => Answer::TimedOut,
    };
    let always_uv = control & 0x08 != 0;
    let settings = Settings {
        max_msg_size: MaxMsgSize::try_from(1024).expect("at least 1024"),
        transports: Transports::Usb,
    };
    let mut authenticator = Authenticator::new(
        settings,
        SoftCrypto::new([0x11; KEY_LEN], [0x22; KEY_LEN]),
        Store::open(MemoryStorage::new(4, 4)),
    );
    // A credential registered over U2F, whose key handle the authentications below can name.
    let mut response = [0u8; 1024];
    let length = authenticator.execute_ctap1(
        Ok(Request::Register {
            challenge: [0xC1; 32],
            application: APPLICATION,
        }),
        &mut Fuzzed(Answer::Confirmed),
        &mut response,
    );
    assert_eq!(
        response[length - 2..length],
        NO_ERROR,
        "the registration succeeds"
    );
    let key_handle_len = usize::from(response[66]);
    let key_handle = response[67..67 + key_handle_len].to_vec();
    if always_uv {
        authenticator.toggle_always_uv();
    }

    let (request, check_only) = if control & 0x04 != 0 {
        let Some((&byte, challenge)) = rest.split_first() else {
            return;
        };
        let Ok(control) = Control::try_from(byte) else {
            return;
        };
        let mut filled = [0u8; 32];
        let taken = challenge.len().min(32);
        filled[..taken].copy_from_slice(&challenge[..taken]);
        (
            Ok(Request::Authenticate {
                control,
                challenge: filled,
                application: APPLICATION,
                key_handle,
            }),
            control == Control::CheckOnly,
        )
    } else {
        let parsed = ctap1::parse(rest);
        let check_only = matches!(
            parsed,
            Ok(Request::Authenticate {
                control: Control::CheckOnly,
                ..
            })
        );
        (parsed, check_only)
    };
    let registration = matches!(request, Ok(Request::Register { .. }));
    let signing = matches!(
        request,
        Ok(Request::Register { .. } | Request::Authenticate { .. })
    );
    let length = authenticator.execute_ctap1(request, &mut Fuzzed(answer), &mut response);
    assert!(length >= 2, "every message is answered");
    let status: [u8; 2] = response[length - 2..length].try_into().expect("two bytes");
    assert!(
        STATUS_WORDS.contains(&status),
        "unknown status {status:02x?}"
    );
    if always_uv {
        assert_eq!(
            &response[..length],
            COMMAND_NOT_ALLOWED,
            "U2F off under alwaysUv"
        );
    }
    if status != NO_ERROR {
        assert_eq!(length, 2, "a refusal carries no data");
        return;
    }
    assert!(!check_only, "a check-only authentication never succeeds");
    if signing {
        assert_eq!(
            answer,
            Answer::Confirmed,
            "a signature only after confirmation"
        );
    }
    if registration {
        let body = &response[..length - 2];
        assert_eq!(body[0], 0x05, "reserved byte");
        assert_eq!(body[1], 0x04, "uncompressed point");
        let key_handle_end = 67 + usize::from(body[66]);
        let certificate = &body[key_handle_end..];
        assert_eq!(certificate[0], 0x30, "a certificate SEQUENCE");
        let certificate_len = der_len(certificate).expect("a DER length");
        let signature = &certificate[certificate_len..];
        assert_eq!(signature[0], 0x30, "a DER signature SEQUENCE");
        assert_eq!(
            der_len(signature),
            Some(signature.len()),
            "the signature ends the body"
        );
    }
}

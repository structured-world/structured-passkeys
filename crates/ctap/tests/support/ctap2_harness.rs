//! CTAP2 requests from arbitrary bytes through the authenticator, shared by the fuzz target and
//! the regression test of its corpus.
//!
//! The first byte picks the user's answers, the rest is the request. The authenticator has a
//! client PIN set, so the PIN subcommands reach their checks. Every response must be a known
//! status and, on success, canonical CBOR; a request must never panic.

use structured_passkeys_ctap::cbor::validate;
use structured_passkeys_ctap::crypto::{Crypto, KEY_LEN};
use structured_passkeys_ctap::ctap2::{Authenticator, MaxMsgSize, Settings};
use structured_passkeys_ctap::soft::SoftCrypto;
use structured_passkeys_ctap::storage::{MemoryStorage, PinVerifier, Store};
use structured_passkeys_ctap::ui::{Answer, Prompt, Ui, Verification};

/// The status codes of CTAP 2.2 §8.2 the authenticator may answer with.
const STATUS_CODES: [u8; 46] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0A, 0x0B, 0x11, 0x12, 0x14, 0x15, 0x17, 0x18, 0x19,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
    0x33, 0x34, 0x35, 0x36, 0x37, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x7F,
];

/// A user whose answers come from one byte: bits 0-1 the confirmation, bits 2-4 the keypad,
/// bit 5 whether built-in verification is offered.
struct Fuzzed(u8);

impl Ui for Fuzzed {
    fn confirm(&mut self, _prompt: Prompt<'_>, _timeout_ms: u32) -> Answer {
        match self.0 & 0x03 {
            0 => Answer::Confirmed,
            1 => Answer::Rejected,
            2 => Answer::Cancelled,
            _ => Answer::TimedOut,
        }
    }

    fn verify_user(&mut self, _timeout_ms: u32) -> Verification {
        match (self.0 >> 2) & 0x07 {
            0 => Verification::Verified,
            1 => Verification::Invalid,
            2 => Verification::Blocked,
            3 => Verification::Rejected,
            4 => Verification::Cancelled,
            _ => Verification::TimedOut,
        }
    }

    fn uv_retries(&mut self) -> u8 {
        u8::from(self.0 & 0x20 == 0)
    }

    fn now_ms(&self) -> u64 {
        0
    }
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
    };
    let mut authenticator = Authenticator::new(settings, crypto, store);
    let mut response = [0u8; 1024];
    let length = authenticator.process(request, &mut Fuzzed(answers), &mut response);
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
}

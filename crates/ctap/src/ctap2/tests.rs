//! CTAP2 dispatch and authenticatorGetInfo against CTAP 2.2 §6.4 and §8. Expected responses are
//! written out byte by byte, never produced by the code under test.

use super::{
    AAGUID, Authenticator, Command, CommandCode, Link, MaxMsgSize, NFC_PRESENCE_MS, NfcTap,
    RESET_WINDOW_MS, Settings, StatusCode, TooSmall, Transports, UnknownCommand,
};
use crate::cbor::{self, validate};
use crate::credential_id::Origin;
use crate::crypto::KEY_LEN;
use crate::pin::Protocol;
use crate::soft::SoftCrypto;
use crate::storage::{MemoryStorage, PIN_RETRIES, PinVerifier, Store};
use crate::ui::{
    Account, Accounts, Answer, Choice, Passkeys, Prompt, Registration, USER_ACTION_TIMEOUT_MS, Ui,
};

pub(super) type TestAuthenticator = Authenticator<SoftCrypto, MemoryStorage>;

pub(super) fn settings(transports: Transports) -> Settings {
    Settings {
        max_msg_size: MaxMsgSize::try_from(1024).expect("at least 1024"),
        transports,
    }
}

/// An authenticator on fresh NVM with the software platform, offering USB.
pub(super) fn authenticator() -> TestAuthenticator {
    authenticator_with(Transports::Usb)
}

/// An authenticator on fresh NVM with the software platform, offering `transports`.
pub(super) fn authenticator_with(transports: Transports) -> TestAuthenticator {
    Authenticator::new(
        settings(transports),
        SoftCrypto::new([0x11; KEY_LEN], [0x22; KEY_LEN]),
        Store::open(MemoryStorage::new(4, 4)),
    )
}

impl TestAuthenticator {
    /// The application closed and opened again: NVM stays, everything in RAM starts over, as
    /// after a power cycle.
    pub(super) fn reopen(self) -> Self {
        Authenticator::new(
            self.settings,
            self.crypto,
            Store::open(self.store.into_storage()),
        )
    }
}

/// An account as a screen showed it, copied out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Shown {
    pub(super) name: Option<String>,
    pub(super) display_name: Option<String>,
    pub(super) origin: Option<Origin>,
}

impl Shown {
    fn from_account(account: &Account<'_>) -> Self {
        Self {
            name: account.name.map(String::from),
            display_name: account.display_name.map(String::from),
            origin: account.origin,
        }
    }
}

/// A screen the scripted user was shown, with the RP ID copied out of the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Asked {
    /// authenticatorSelection.
    Selection,
    /// authenticatorReset.
    Reset,
    /// Consent to a token with these permission bits and permissions RP ID.
    Token {
        permissions: u8,
        rp_id: Option<String>,
    },
    /// A sign-in with this account.
    Assertion { rp_id: String, account: Shown },
    /// A registration found in the excludeList.
    Excluded { rp_id: String },
    /// The deletion of this account's credential.
    Delete { rp_id: String, account: Shown },
    /// A CTAP1/U2F registration for the application this label stands for.
    U2fRegistration { rp_id: String },
    /// A registration for this account, the origin selector starting on `default_origin`.
    Registration {
        rp_id: String,
        account: Shown,
        default_origin: Origin,
    },
    /// The account picker with these accounts.
    Pick { rp_id: String, accounts: Vec<Shown> },
    /// The settings list with these passkeys as (RP ID, account), from the one at `start`.
    Browse {
        passkeys: Vec<(String, Shown)>,
        start: usize,
    },
}

impl Asked {
    fn from_prompt(prompt: Prompt<'_>) -> Self {
        match prompt {
            Prompt::Selection => Asked::Selection,
            Prompt::Reset => Asked::Reset,
            Prompt::Token { permissions, rp_id } => Asked::Token {
                permissions: permissions.bits(),
                rp_id: rp_id.map(String::from),
            },
            Prompt::Assertion { rp_id, account } => Asked::Assertion {
                rp_id: String::from(rp_id),
                account: Shown::from_account(&account),
            },
            Prompt::Excluded { rp_id } => Asked::Excluded {
                rp_id: String::from(rp_id),
            },
            Prompt::Delete { rp_id, account } => Asked::Delete {
                rp_id: String::from(rp_id),
                account: Shown::from_account(&account),
            },
            Prompt::U2fRegistration { rp_id } => Asked::U2fRegistration {
                rp_id: String::from(rp_id),
            },
        }
    }
}

/// A user who gives `answer` to every confirmation, recording what was shown with its timeout,
/// on a device whose PIN the operating system holds validated while `unlocked`; the clock is
/// `now_ms`. A confirmed registration takes `origin`, or the default when it is `None`; a
/// confirmed account picker takes the account at `pick`. The settings list answers with the
/// choices of `browsed` in turn, then leaves.
pub(super) struct Scripted {
    pub(super) answer: Answer,
    pub(super) unlocked: bool,
    pub(super) now_ms: u64,
    pub(super) origin: Option<Origin>,
    pub(super) pick: usize,
    pub(super) browsed: Vec<Choice<usize>>,
    pub(super) asked: Vec<(Asked, u32)>,
}

impl Scripted {
    pub(super) fn new(answer: Answer) -> Self {
        Self {
            answer,
            unlocked: true,
            now_ms: 0,
            origin: None,
            pick: 0,
            browsed: Vec::new(),
            asked: Vec::new(),
        }
    }

    fn choice<T>(&self, chosen: T) -> Choice<T> {
        match self.answer {
            Answer::Confirmed => Choice::Chose(chosen),
            Answer::Rejected => Choice::Rejected,
            Answer::Cancelled => Choice::Cancelled,
            Answer::TimedOut => Choice::TimedOut,
        }
    }
}

impl Ui for Scripted {
    fn confirm(&mut self, prompt: Prompt<'_>, timeout_ms: u32) -> Answer {
        self.asked.push((Asked::from_prompt(prompt), timeout_ms));
        self.answer
    }

    fn register(&mut self, registration: Registration<'_>, timeout_ms: u32) -> Choice<Origin> {
        self.asked.push((
            Asked::Registration {
                rp_id: String::from(registration.rp_id),
                account: Shown::from_account(&registration.account),
                default_origin: registration.default_origin,
            },
            timeout_ms,
        ));
        self.choice(self.origin.unwrap_or(registration.default_origin))
    }

    fn pick<A: Accounts>(
        &mut self,
        rp_id: &str,
        accounts: &mut A,
        timeout_ms: u32,
    ) -> Choice<usize> {
        let shown = (0..accounts.count())
            .map(|index| {
                accounts
                    .read(index, |account| Shown::from_account(&account))
                    .expect("every offered account reads")
            })
            .collect();
        self.asked.push((
            Asked::Pick {
                rp_id: String::from(rp_id),
                accounts: shown,
            },
            timeout_ms,
        ));
        self.choice(self.pick)
    }

    fn browse<P: Passkeys>(
        &mut self,
        passkeys: &mut P,
        start: usize,
        timeout_ms: u32,
    ) -> Choice<usize> {
        let shown = (0..passkeys.count())
            .map(|index| {
                passkeys
                    .read(index, |passkey| {
                        (
                            String::from(passkey.rp_id),
                            Shown::from_account(&passkey.account),
                        )
                    })
                    .expect("every listed passkey reads")
            })
            .collect();
        self.asked.push((
            Asked::Browse {
                passkeys: shown,
                start,
            },
            timeout_ms,
        ));
        if self.browsed.is_empty() {
            Choice::Rejected
        } else {
            self.browsed.remove(0)
        }
    }

    fn device_unlocked(&mut self) -> bool {
        self.unlocked
    }

    fn now_ms(&self) -> u64 {
        self.now_ms
    }
}

fn process_with(request: &[u8], ui: &mut Scripted) -> Vec<u8> {
    let mut authenticator = authenticator();
    let mut response = [0u8; 256];
    let length = authenticator.process(request, Link::Usb, ui, &mut response);
    response[..length].to_vec()
}

/// Processes `request` for a user who would confirm, checking that no screen was shown.
fn process(request: &[u8]) -> Vec<u8> {
    let mut ui = Scripted::new(Answer::Confirmed);
    let response = process_with(request, &mut ui);
    assert_eq!(ui.asked, [], "no screen for {request:02x?}");
    response
}

/// authenticatorSelection asks for user presence once, with the 30-second user action timeout,
/// and answers as §6.9 says: presence CTAP2_OK with no body, refusal OPERATION_DENIED, no answer
/// USER_ACTION_TIMEOUT; a request cancelled while it waited is KEEPALIVE_CANCEL (§11.2.9.1.5).
#[test]
fn selection_answers_with_the_users_answer() {
    for (answer, status) in [
        (Answer::Confirmed, 0x00),
        (Answer::Rejected, 0x27),
        (Answer::TimedOut, 0x2F),
        (Answer::Cancelled, 0x2D),
    ] {
        let mut ui = Scripted::new(answer);
        assert_eq!(process_with(&[0x0B], &mut ui), [status], "{answer:?}");
        assert_eq!(
            ui.asked,
            [(Asked::Selection, USER_ACTION_TIMEOUT_MS)],
            "{answer:?}"
        );
    }
    assert_eq!(USER_ACTION_TIMEOUT_MS, 30_000);
}

/// Over NFC the tap is user presence (CTAP 2.2 Terminology, "Evidence of user interaction"): an
/// authenticatorSelection within two minutes of it answers CTAP2_OK with no screen, and does not
/// use the tap up. Without a tap, past the limit or after the platform ended CTAP, the device asks
/// on its screen as over USB; over USB a tap never counts.
#[test]
fn selection_over_nfc_takes_the_tap() {
    let mut authenticator = authenticator_with(Transports::UsbAndNfc);
    let mut ui = Scripted::new(Answer::Rejected);
    let mut response = [0u8; 8];
    let mut select = |authenticator: &mut TestAuthenticator, link, ui: &mut Scripted| {
        let length = authenticator.process(&[0x0B], link, ui, &mut response);
        response[..length].to_vec()
    };
    assert_eq!(
        select(&mut authenticator, Link::Nfc, &mut ui),
        [0x27],
        "no tap yet"
    );
    assert_eq!(ui.asked.len(), 1);

    ui.asked.clear();
    ui.now_ms = 5_000;
    authenticator.nfc_tap(NfcTap {
        at_ms: ui.now_ms,
        selection: 0,
    });
    assert_eq!(select(&mut authenticator, Link::Nfc, &mut ui), [0x00]);
    ui.now_ms += NFC_PRESENCE_MS;
    assert_eq!(
        select(&mut authenticator, Link::Nfc, &mut ui),
        [0x00],
        "not used up"
    );
    assert_eq!(ui.asked, [], "no screen while the tap counts");
    assert_eq!(
        select(&mut authenticator, Link::Usb, &mut ui),
        [0x27],
        "not over USB"
    );
    assert_eq!(ui.asked.len(), 1);

    ui.asked.clear();
    ui.now_ms += 1;
    assert_eq!(
        select(&mut authenticator, Link::Nfc, &mut ui),
        [0x27],
        "past two minutes"
    );
    authenticator.nfc_tap(NfcTap {
        at_ms: ui.now_ms,
        selection: 1,
    });
    authenticator.nfc_ended();
    assert_eq!(
        select(&mut authenticator, Link::Nfc, &mut ui),
        [0x27],
        "deselected"
    );
    assert_eq!(ui.asked.len(), 2);
}

/// authenticatorSelection has no parameters: bytes after the command are an invalid length, and
/// no screen is shown for it.
#[test]
fn selection_with_parameters_is_invalid_length() {
    assert_eq!(process(&[0x0B, 0xA0]), [StatusCode::InvalidLength as u8]);
}

/// Parsing names the command without running it, so a request can be parsed while the transport
/// holds it and run once the transport is free again.
#[test]
fn parsing_names_the_command() {
    let authenticator = authenticator();
    assert_eq!(authenticator.parse(&[0x04]), Ok(Command::GetInfo));
    assert_eq!(authenticator.parse(&[0x0B]), Ok(Command::Selection));
    assert_eq!(authenticator.parse(&[0x07]), Ok(Command::Reset));
    assert_eq!(authenticator.parse(&[0x08]), Ok(Command::GetNextAssertion));
    assert_eq!(authenticator.parse(&[]), Err(StatusCode::InvalidLength));
    assert_eq!(
        authenticator.parse(&[0x09]),
        Err(StatusCode::InvalidCommand)
    );
}

/// The options map of getInfo (§6.4) in canonical order: `rk`, `up`, `uv`, `uvAcfg` true,
/// `alwaysUv` false until toggled, `credMgmt` and `authnrCfg` true, `clientPin` false while no
/// client PIN is set, `pinUvAuthToken` true.
pub(super) const OPTIONS_WITHOUT_PIN: [u8; 80] = [
    0x04, 0xA9, // key 4, a map of nine
    0x62, b'r', b'k', 0xF5, // "rk": true
    0x62, b'u', b'p', 0xF5, // "up": true
    0x62, b'u', b'v', 0xF5, // "uv": true
    0x66, b'u', b'v', b'A', b'c', b'f', b'g', 0xF5, // "uvAcfg": true
    0x68, b'a', b'l', b'w', b'a', b'y', b's', b'U', b'v', 0xF4, // "alwaysUv": false
    0x68, b'c', b'r', b'e', b'd', b'M', b'g', b'm', b't', 0xF5, // "credMgmt": true
    0x69, b'a', b'u', b't', b'h', b'n', b'r', b'C', b'f', b'g', 0xF5, // "authnrCfg": true
    0x69, b'c', b'l', b'i', b'e', b'n', b't', b'P', b'i', b'n', 0xF4, // "clientPin": false
    0x6E, b'p', b'i', b'n', b'U', b'v', b'A', b'u', b't', b'h', b'T', b'o', b'k', b'e', b'n',
    0xF5, // "pinUvAuthToken": true
];

/// getInfo answers CTAP2_OK and the map {1: ["U2F_V2", "FIDO_2_0"], 2: ["credProtect",
/// "hmac-secret", "hmac-secret-mc"], 3: AAGUID, 4: options, 5: 1024, 6: [2, 1], 9: ["usb"], 13: 4}
/// in canonical order: the required versions, U2F_V2 for the CTAP1/U2F messages and FIDO_2_0 for
/// the CTAP 2.0 command set the conformance suite covers, the implemented extensions, among them
/// hmac-secret-mc, which platforms take as the offer of the PRF at registration, and aaguid, the
/// options, maxMsgSize, the PIN/UV auth protocols, two first, the transports, and minPINLength,
/// which "MUST be present if the authenticator supports authenticatorClientPIN" (§6.4), at the 4
/// code points of §6.5.1.
#[test]
fn get_info_reports_the_implemented_members() {
    let response = process(&[0x04]);
    let mut expected = vec![0x00, 0xA8, 0x01, 0x82, 0x66];
    expected.extend_from_slice(b"U2F_V2");
    expected.push(0x68);
    expected.extend_from_slice(b"FIDO_2_0");
    expected.extend_from_slice(&[0x02, 0x83, 0x6B]);
    expected.extend_from_slice(b"credProtect");
    expected.push(0x6B);
    expected.extend_from_slice(b"hmac-secret");
    expected.push(0x6E);
    expected.extend_from_slice(b"hmac-secret-mc");
    expected.extend_from_slice(&[0x03, 0x50]);
    expected.extend_from_slice(&AAGUID);
    expected.extend_from_slice(&OPTIONS_WITHOUT_PIN);
    expected.extend_from_slice(&[0x05, 0x19, 0x04, 0x00, 0x06, 0x82, 0x02, 0x01]);
    expected.extend_from_slice(&[0x09, 0x81, 0x63, b'u', b's', b'b']);
    expected.extend_from_slice(&[0x0D, 0x04]);
    assert_eq!(response, expected);
    assert_eq!(validate(&response[1..]), Ok(()), "canonical CBOR");
}

/// With alwaysUv on, U2F is disabled (§7.2.2) and versions is ["FIDO_2_0"] alone; turned off,
/// U2F_V2 is back.
#[test]
fn always_uv_leaves_u2f_out_of_versions() {
    let mut authenticator = authenticator();
    let mut ui = Scripted::new(Answer::Confirmed);
    let mut response = [0u8; 256];
    authenticator.toggle_always_uv();
    let length = authenticator.process(&[0x04], Link::Usb, &mut ui, &mut response);
    let mut versions = vec![0x00, 0xA8, 0x01, 0x81, 0x68];
    versions.extend_from_slice(b"FIDO_2_0");
    versions.push(0x02);
    assert!(response[..length].starts_with(&versions));
    authenticator.toggle_always_uv();
    let length = authenticator.process(&[0x04], Link::Usb, &mut ui, &mut response);
    let mut versions = vec![0x00, 0xA8, 0x01, 0x82, 0x66];
    versions.extend_from_slice(b"U2F_V2");
    assert!(response[..length].starts_with(&versions));
}

/// A device with NFC lists both transports, ["nfc", "usb"], whichever one getInfo arrives on:
/// the AuthenticatorTransport names of WebAuthn L3 §5.8.4.
#[test]
fn get_info_lists_nfc_on_a_device_that_has_it() {
    let mut authenticator = authenticator_with(Transports::UsbAndNfc);
    let mut ui = Scripted::new(Answer::Confirmed);
    for link in [Link::Usb, Link::Nfc] {
        let mut response = [0u8; 256];
        let length = authenticator.process(&[0x04], link, &mut ui, &mut response);
        let tail = [
            0x09, 0x82, 0x63, b'n', b'f', b'c', 0x63, b'u', b's', b'b', 0x0D, 0x04,
        ];
        assert_eq!(response[1], 0xA8, "{link:?}");
        assert!(response[..length].ends_with(&tail), "{link:?}");
        assert_eq!(validate(&response[1..length]), Ok(()), "{link:?}");
    }
}

/// The AAGUID is the fixed UUID 8f920f83-9da2-4861-94d7-7f3c9945d532 in network order.
#[test]
fn aaguid_is_the_application_uuid() {
    assert_eq!(
        AAGUID,
        [
            0x8f, 0x92, 0x0f, 0x83, 0x9d, 0xa2, 0x48, 0x61, 0x94, 0xd7, 0x7f, 0x3c, 0x99, 0x45,
            0xd5, 0x32
        ]
    );
}

/// getInfo has no parameters; bytes after the command are an invalid length.
#[test]
fn get_info_with_parameters_is_invalid_length() {
    assert_eq!(process(&[0x04, 0xA0]), [StatusCode::InvalidLength as u8]);
}

/// An empty request has no command byte: CTAP1_ERR_INVALID_LENGTH.
#[test]
fn an_empty_request_is_invalid_length() {
    assert_eq!(process(&[]), [0x03]);
}

/// §8.1: a command the authenticator does not implement, defined or not, is
/// CTAP1_ERR_INVALID_COMMAND with no body.
#[test]
fn unimplemented_commands_are_invalid_command() {
    for code in [0x03, 0x05, 0x09, 0x0C, 0x40, 0x41, 0xFF] {
        assert_eq!(process(&[code, 0xA0]), [0x01], "command {code:#04x}");
    }
}

/// authenticatorReset (§6.6) within the window after the application opens: the user confirms
/// on the device, and the store forgets the PIN and every credential and draws a new reset ID,
/// which stays across a reopening. Refusal, timeout and cancel leave everything as it was.
#[test]
fn reset_asks_the_user_and_erases_everything() {
    for (answer, status) in [
        (Answer::Rejected, 0x27),
        (Answer::TimedOut, 0x2F),
        (Answer::Cancelled, 0x2D),
    ] {
        let mut authenticator = with_pin();
        let mut ui = Scripted::new(answer);
        let mut response = [0u8; 8];
        let length = authenticator.process(&[0x07], Link::Usb, &mut ui, &mut response);
        assert_eq!(response[..length], [status], "{answer:?}");
        assert!(authenticator.store.config().pin.is_some(), "{answer:?}");
        assert_eq!(authenticator.store.config().reset_id, 0, "{answer:?}");
    }

    let mut authenticator = with_pin();
    let mut ui = Scripted::new(Answer::Confirmed);
    ui.now_ms = RESET_WINDOW_MS;
    let token = *authenticator.client_pin.token(Protocol::Two);
    let mut response = [0u8; 8];
    let length = authenticator.process(&[0x07], Link::Usb, &mut ui, &mut response);
    assert_eq!(response[..length], [0x00]);
    assert_eq!(ui.asked, [(Asked::Reset, USER_ACTION_TIMEOUT_MS)]);
    let config = authenticator.store.config();
    assert!(config.pin.is_none());
    assert_eq!(config.pin_retries, PIN_RETRIES);
    assert_ne!(config.reset_id, 0);
    assert_ne!(
        *authenticator.client_pin.token(Protocol::Two),
        token,
        "tokens issued before no longer verify"
    );
    let reopened = authenticator.reopen();
    assert_eq!(
        reopened.store.config().reset_id,
        config.reset_id,
        "the reset ID survives a reopening"
    );
}

/// After the window a reset is CTAP2_ERR_NOT_ALLOWED (§6.6) and shows no screen.
#[test]
fn reset_after_the_window_is_not_allowed() {
    let mut authenticator = with_pin();
    let mut ui = Scripted::new(Answer::Confirmed);
    ui.now_ms = RESET_WINDOW_MS + 1;
    let mut response = [0u8; 8];
    let length = authenticator.process(&[0x07], Link::Usb, &mut ui, &mut response);
    assert_eq!(response[..length], [0x30]);
    assert_eq!(ui.asked, []);
    assert!(authenticator.store.config().pin.is_some());
}

/// authenticatorReset takes no parameters.
#[test]
fn reset_with_parameters_is_invalid_length() {
    assert_eq!(process(&[0x07, 0xA0]), [StatusCode::InvalidLength as u8]);
}

/// An authenticator whose store holds a client PIN.
fn with_pin() -> TestAuthenticator {
    let mut authenticator = authenticator();
    let mut config = authenticator.store.config();
    config.pin = Some(PinVerifier::new([0x5A; 16]));
    authenticator.store.write_config(&config);
    authenticator
}

/// A response that does not fit is CTAP1_ERR_OTHER, and an empty buffer gets nothing.
#[test]
fn a_response_that_does_not_fit_is_other() {
    let mut authenticator = authenticator();
    let mut ui = Scripted::new(Answer::Confirmed);
    let mut small = [0u8; 8];
    assert_eq!(
        authenticator.process(&[0x04], Link::Usb, &mut ui, &mut small),
        1
    );
    assert_eq!(small[0], 0x7F);
    assert_eq!(
        authenticator.process(&[0x04], Link::Usb, &mut ui, &mut []),
        0
    );
}

/// §8: an authenticator accepts messages of at least 1024 bytes, so no smaller maxMsgSize can
/// be reported.
#[test]
fn max_msg_size_is_at_least_1024() {
    assert_eq!(MaxMsgSize::try_from(1023), Err(TooSmall(1023)));
    assert_eq!(MaxMsgSize::try_from(0), Err(TooSmall(0)));
    assert_eq!(MaxMsgSize::try_from(1024).map(MaxMsgSize::get), Ok(1024));
    assert_eq!(MaxMsgSize::try_from(7609).map(MaxMsgSize::get), Ok(7609));
}

/// Command codes are the ones of §6; unknown codes come back as the error value.
#[test]
fn command_codes_follow_the_specification() {
    let table = [
        (0x01, CommandCode::MakeCredential),
        (0x02, CommandCode::GetAssertion),
        (0x04, CommandCode::GetInfo),
        (0x06, CommandCode::ClientPin),
        (0x07, CommandCode::Reset),
        (0x08, CommandCode::GetNextAssertion),
        (0x09, CommandCode::BioEnrollment),
        (0x0A, CommandCode::CredentialManagement),
        (0x0B, CommandCode::Selection),
        (0x0C, CommandCode::LargeBlobs),
        (0x0D, CommandCode::Config),
    ];
    for (code, command) in table {
        assert_eq!(CommandCode::try_from(code), Ok(command));
        assert_eq!(command as u8, code);
    }
    assert_eq!(CommandCode::try_from(0x03), Err(UnknownCommand(0x03)));
}

/// §8: canonical-form violations are CTAP2_ERR_INVALID_CBOR (0x12), wrong member types
/// CTAP2_ERR_CBOR_UNEXPECTED_TYPE (0x11).
#[test]
fn cbor_errors_map_to_their_status_codes() {
    assert_eq!(StatusCode::from(cbor::Error::Malformed) as u8, 0x12);
    assert_eq!(StatusCode::from(cbor::Error::NotCanonical) as u8, 0x12);
    assert_eq!(StatusCode::from(cbor::Error::TooDeep) as u8, 0x12);
    assert_eq!(StatusCode::from(cbor::Error::UnexpectedType) as u8, 0x11);
}

/// Status codes carry the values of the §8.2 table.
#[test]
fn status_codes_follow_the_specification() {
    let table = [
        (StatusCode::Ok, 0x00),
        (StatusCode::InvalidCommand, 0x01),
        (StatusCode::InvalidParameter, 0x02),
        (StatusCode::InvalidLength, 0x03),
        (StatusCode::InvalidSeq, 0x04),
        (StatusCode::Timeout, 0x05),
        (StatusCode::ChannelBusy, 0x06),
        (StatusCode::LockRequired, 0x0A),
        (StatusCode::InvalidChannel, 0x0B),
        (StatusCode::CborUnexpectedType, 0x11),
        (StatusCode::InvalidCbor, 0x12),
        (StatusCode::MissingParameter, 0x14),
        (StatusCode::LimitExceeded, 0x15),
        (StatusCode::FpDatabaseFull, 0x17),
        (StatusCode::LargeBlobStorageFull, 0x18),
        (StatusCode::CredentialExcluded, 0x19),
        (StatusCode::Processing, 0x21),
        (StatusCode::InvalidCredential, 0x22),
        (StatusCode::UserActionPending, 0x23),
        (StatusCode::OperationPending, 0x24),
        (StatusCode::NoOperations, 0x25),
        (StatusCode::UnsupportedAlgorithm, 0x26),
        (StatusCode::OperationDenied, 0x27),
        (StatusCode::KeyStoreFull, 0x28),
        (StatusCode::UnsupportedOption, 0x2B),
        (StatusCode::InvalidOption, 0x2C),
        (StatusCode::KeepaliveCancel, 0x2D),
        (StatusCode::NoCredentials, 0x2E),
        (StatusCode::UserActionTimeout, 0x2F),
        (StatusCode::NotAllowed, 0x30),
        (StatusCode::PinInvalid, 0x31),
        (StatusCode::PinBlocked, 0x32),
        (StatusCode::PinAuthInvalid, 0x33),
        (StatusCode::PinAuthBlocked, 0x34),
        (StatusCode::PinNotSet, 0x35),
        (StatusCode::PuatRequired, 0x36),
        (StatusCode::PinPolicyViolation, 0x37),
        (StatusCode::RequestTooLarge, 0x39),
        (StatusCode::ActionTimeout, 0x3A),
        (StatusCode::UpRequired, 0x3B),
        (StatusCode::UvBlocked, 0x3C),
        (StatusCode::IntegrityFailure, 0x3D),
        (StatusCode::InvalidSubcommand, 0x3E),
        (StatusCode::UvInvalid, 0x3F),
        (StatusCode::UnauthorizedPermission, 0x40),
        (StatusCode::Other, 0x7F),
    ];
    for (status, value) in table {
        assert_eq!(status as u8, value, "{status:?}");
    }
}

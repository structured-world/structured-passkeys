//! CTAP1/U2F registration and authentication against FIDO U2F Raw Message Formats v1.2, end to
//! end through the authenticator. Responses are read by their byte layout (§4.3, §5.4) and every
//! signature is checked with the independent `p256` verifier over the data the specification
//! names.

use sha2::{Digest, Sha256};

use super::super::client_pin::tests::{Value, command, run};
use super::super::get_assertion::tests::asserted;
use super::super::make_credential::tests::{
    CLIENT_DATA_HASH, OK, RP_ID, descriptors, options, register, verifies,
};
use super::super::tests::{Asked, Scripted, Shown, TestAuthenticator, authenticator};
use super::u2f_label;
use crate::credential_id::{self, CredProtect, Credential, KeySource, Origin};
use crate::ctap1::{Control, Request, StatusWord};
use crate::keys::KeyRing;
use crate::ui::{Answer, USER_ACTION_TIMEOUT_MS};

const CHALLENGE: [u8; 32] = [0xC1; 32];
const NO_ERROR: [u8; 2] = [0x90, 0x00];
const CONDITIONS_NOT_SATISFIED: [u8; 2] = [0x69, 0x85];
const COMMAND_NOT_ALLOWED: [u8; 2] = [0x69, 0x86];
const WRONG_DATA: [u8; 2] = [0x6A, 0x80];

/// The application parameter of `app_id`, its SHA-256 (§4.1).
fn application(app_id: &str) -> [u8; 32] {
    Sha256::digest(app_id).into()
}

/// Runs `request` for a user who answers `answer`, with room for any response.
fn u2f(authenticator: &mut TestAuthenticator, ui: &mut Scripted, request: Request) -> Vec<u8> {
    let mut response = [0u8; 1024];
    let length = authenticator.execute_ctap1(Ok(request), ui, &mut response);
    response[..length].to_vec()
}

/// What a registration response holds (§4.3).
struct Registered {
    public_key: Vec<u8>,
    key_handle: Vec<u8>,
    certificate: Vec<u8>,
    signature: Vec<u8>,
}

/// Reads a registration response by its layout: 0x05, the 65-byte public key, the key handle
/// length and the key handle, the DER certificate (its length read from its own header), the
/// signature, then 90 00.
fn registered(response: &[u8]) -> Registered {
    let (body, status) = response.split_at(response.len() - 2);
    assert_eq!(status, NO_ERROR);
    assert_eq!(body[0], 0x05, "reserved byte");
    let public_key = body[1..66].to_vec();
    assert_eq!(public_key[0], 0x04, "uncompressed point");
    let key_handle_len = usize::from(body[66]);
    let key_handle = body[67..67 + key_handle_len].to_vec();
    let rest = &body[67 + key_handle_len..];
    assert_eq!(rest[0], 0x30, "a certificate is a SEQUENCE");
    let certificate_len = match rest[1] {
        0x81 => 3 + usize::from(rest[2]),
        0x82 => 4 + usize::from(u16::from_be_bytes([rest[2], rest[3]])),
        short => 2 + usize::from(short),
    };
    Registered {
        public_key,
        key_handle,
        certificate: rest[..certificate_len].to_vec(),
        signature: rest[certificate_len..].to_vec(),
    }
}

/// Registers at `app_id` for a user who confirms.
fn register_u2f(authenticator: &mut TestAuthenticator, app_id: &str) -> Registered {
    let mut ui = Scripted::new(Answer::Confirmed);
    registered(&u2f(
        authenticator,
        &mut ui,
        Request::Register {
            challenge: CHALLENGE,
            application: application(app_id),
        },
    ))
}

fn authenticate(control: Control, app_id: &str, key_handle: &[u8]) -> Request {
    Request::Authenticate {
        control,
        challenge: CHALLENGE,
        application: application(app_id),
        key_handle: key_handle.to_vec(),
    }
}

/// U2F_VERSION answers "U2F_V2" (§6.1) with no screen.
#[test]
fn version_answers_u2f_v2() {
    let mut authenticator = authenticator();
    let mut ui = Scripted::new(Answer::Confirmed);
    let response = u2f(&mut authenticator, &mut ui, Request::Version);
    assert_eq!(response, [&b"U2F_V2"[..], &NO_ERROR].concat());
    assert_eq!(ui.asked, []);
}

/// A confirmed registration answers §4.3's layout: the public key, a key handle, a certificate
/// of that public key, and the signature of the new key over 0x00 || application || challenge ||
/// key handle || public key, nothing else. The screen names the application by its label and
/// waits the user action timeout.
#[test]
fn registration_signs_the_registration_data() {
    let mut authenticator = authenticator();
    let mut ui = Scripted::new(Answer::Confirmed);
    let response = u2f(
        &mut authenticator,
        &mut ui,
        Request::Register {
            challenge: CHALLENGE,
            application: application("https://example.com"),
        },
    );
    let made = registered(&response);
    let signed = [
        &[0x00][..],
        &application("https://example.com"),
        &CHALLENGE,
        &made.key_handle,
        &made.public_key,
    ]
    .concat();
    assert!(verifies(&made.public_key, &signed, &made.signature));
    assert!(!verifies(&made.public_key, &signed[1..], &made.signature));
    // The certificate is of the credential key: its SubjectPublicKeyInfo carries the point.
    assert!(
        made.certificate
            .windows(made.public_key.len())
            .any(|window| window == made.public_key)
    );
    assert_eq!(
        ui.asked,
        [(
            Asked::U2fRegistration {
                rp_id: u2f_label(&application("https://example.com")),
            },
            USER_ACTION_TIMEOUT_MS,
        )]
    );
}

/// The label names the application by "U2F site #" and the first 8 bytes of its hash.
#[test]
fn the_label_is_the_application_fingerprint() {
    let mut application = [0u8; 32];
    application[..8].copy_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
    application[8..].fill(0xFF);
    assert_eq!(u2f_label(&application), "U2F site #0123456789ABCDEF");
}

/// Without the user's presence a registration is SW_CONDITIONS_NOT_SATISFIED (§4.3), whatever
/// ended the screen: a refusal, the timeout or a cancelled request. No key handle comes back.
#[test]
fn registration_without_presence_is_conditions_not_satisfied() {
    for answer in [Answer::Rejected, Answer::TimedOut, Answer::Cancelled] {
        let mut authenticator = authenticator();
        let mut ui = Scripted::new(answer);
        let response = u2f(
            &mut authenticator,
            &mut ui,
            Request::Register {
                challenge: CHALLENGE,
                application: application("https://example.com"),
            },
        );
        assert_eq!(response, CONDITIONS_NOT_SATISFIED, "{answer:?}");
        assert_eq!(ui.asked.len(), 1, "{answer:?}");
    }
}

/// The probe registration (application 0x41..., challenge 0x42...) asks on the "not registered"
/// screen, and either answer completes it with a registration of §4.3's layout, signed over the
/// probe's parameters: Chromium retries SW_CONDITIONS_NOT_SATISFIED until its timeout and
/// reports the device as not registered only after a successful response. A registration that
/// differs in one byte is a real one and asks on the registration screen.
#[test]
fn the_probe_registration_completes_after_the_not_registered_screen() {
    for answer in [Answer::Confirmed, Answer::Rejected] {
        let mut authenticator = authenticator();
        let mut ui = Scripted::new(answer);
        let probe = Request::Register {
            challenge: [0x42; 32],
            application: [0x41; 32],
        };
        let made = registered(&u2f(&mut authenticator, &mut ui, probe));
        let signed = [
            &[0x00][..],
            &[0x41; 32],
            &[0x42; 32],
            &made.key_handle,
            &made.public_key,
        ]
        .concat();
        assert!(
            verifies(&made.public_key, &signed, &made.signature),
            "{answer:?}"
        );
        assert_eq!(
            ui.asked,
            [(Asked::U2fNotRegistered, USER_ACTION_TIMEOUT_MS)],
            "{answer:?}"
        );
    }
    let mut ui = Scripted::new(Answer::Confirmed);
    let mut challenge = [0x42; 32];
    challenge[31] = 0x43;
    let real = Request::Register {
        challenge,
        application: [0x41; 32],
    };
    registered(&u2f(&mut authenticator(), &mut ui, real));
    assert_eq!(
        ui.asked,
        [(
            Asked::U2fRegistration {
                rp_id: u2f_label(&[0x41; 32]),
            },
            USER_ACTION_TIMEOUT_MS,
        )]
    );
}

/// A probe the user leaves unanswered or the platform cancels stays SW_CONDITIONS_NOT_SATISFIED,
/// test-of-user-presence not met (§4.3), with no key handle.
#[test]
fn an_unanswered_probe_is_conditions_not_satisfied() {
    for answer in [Answer::TimedOut, Answer::Cancelled] {
        let mut ui = Scripted::new(answer);
        let probe = Request::Register {
            challenge: [0x42; 32],
            application: [0x41; 32],
        };
        assert_eq!(
            u2f(&mut authenticator(), &mut ui, probe),
            CONDITIONS_NOT_SATISFIED,
            "{answer:?}"
        );
        assert_eq!(
            ui.asked,
            [(Asked::U2fNotRegistered, USER_ACTION_TIMEOUT_MS)]
        );
    }
}

/// An authentication with a key handle of this application signs application || 0x01 || counter
/// 0 || challenge after the user confirms the sign-in, which names the application and the
/// seed-recoverable key, and answers 0x01, the counter and the signature (§5.4).
#[test]
fn authentication_signs_after_confirmation() {
    let mut authenticator = authenticator();
    let made = register_u2f(&mut authenticator, "https://example.com");
    let mut ui = Scripted::new(Answer::Confirmed);
    let response = u2f(
        &mut authenticator,
        &mut ui,
        authenticate(
            Control::EnforcePresence,
            "https://example.com",
            &made.key_handle,
        ),
    );
    let (body, status) = response.split_at(response.len() - 2);
    assert_eq!(status, NO_ERROR);
    assert_eq!(body[..5], [0x01, 0, 0, 0, 0], "user present, counter 0");
    let signed = [
        &application("https://example.com")[..],
        &[0x01, 0, 0, 0, 0],
        &CHALLENGE,
    ]
    .concat();
    assert!(verifies(&made.public_key, &signed, &body[5..]));
    assert_eq!(
        ui.asked,
        [(
            Asked::Assertion {
                rp_id: u2f_label(&application("https://example.com")),
                account: Shown {
                    name: None,
                    display_name: None,
                    origin: Some(Origin::SeedRecoverable),
                },
            },
            USER_ACTION_TIMEOUT_MS,
        )]
    );
}

/// "Don't-enforce" still asks on the device: no signature leaves it unconfirmed. A refusal is
/// SW_CONDITIONS_NOT_SATISFIED with no signature.
#[test]
fn dont_enforce_still_asks() {
    let mut authenticator = authenticator();
    let made = register_u2f(&mut authenticator, "https://example.com");
    let mut ui = Scripted::new(Answer::Confirmed);
    let request = authenticate(
        Control::DontEnforcePresence,
        "https://example.com",
        &made.key_handle,
    );
    let response = u2f(&mut authenticator, &mut ui, request.clone());
    assert_eq!(response[response.len() - 2..], NO_ERROR);
    assert_eq!(ui.asked.len(), 1);
    let mut refusing = Scripted::new(Answer::Rejected);
    assert_eq!(
        u2f(&mut authenticator, &mut refusing, request),
        CONDITIONS_NOT_SATISFIED
    );
    assert_eq!(refusing.asked.len(), 1);
}

/// Check-only (§5.1) tells a key handle of this application (SW_CONDITIONS_NOT_SATISFIED) from
/// one that is not (SW_WRONG_DATA), with no screen and no signature: another application's key
/// handle and bytes that are no key handle at all are both not this authenticator's.
#[test]
fn check_only_tells_valid_key_handles() {
    let mut authenticator = authenticator();
    let made = register_u2f(&mut authenticator, "https://example.com");
    let mut ui = Scripted::new(Answer::Confirmed);
    let cases = [
        (
            "https://example.com",
            made.key_handle.clone(),
            CONDITIONS_NOT_SATISFIED,
        ),
        ("https://other.example", made.key_handle.clone(), WRONG_DATA),
        ("https://example.com", vec![0x01; 40], WRONG_DATA),
        ("https://example.com", Vec::new(), WRONG_DATA),
    ];
    for (app_id, key_handle, expected) in cases {
        let response = u2f(
            &mut authenticator,
            &mut ui,
            authenticate(Control::CheckOnly, app_id, &key_handle),
        );
        assert_eq!(response, expected, "{app_id} {key_handle:02x?}");
    }
    assert_eq!(ui.asked, []);
}

/// A signing request with a key handle that is not this authenticator's is SW_WRONG_DATA before
/// any screen (§5.1).
#[test]
fn foreign_key_handles_are_wrong_data_without_a_screen() {
    let mut authenticator = authenticator();
    let made = register_u2f(&mut authenticator, "https://example.com");
    let mut ui = Scripted::new(Answer::Confirmed);
    let response = u2f(
        &mut authenticator,
        &mut ui,
        authenticate(
            Control::EnforcePresence,
            "https://other.example",
            &made.key_handle,
        ),
    );
    assert_eq!(response, WRONG_DATA);
    assert_eq!(ui.asked, []);
}

/// A credential of credProtect level 3 is never used without user verification (CTAP 2.2
/// §12.1), which U2F cannot give: its key handle counts as not this authenticator's, also in a
/// check. Level 2 is used, as the key handle is the credential list it asks for.
#[test]
fn cred_protect_required_credentials_are_not_used() {
    let mut authenticator = authenticator();
    for (level, expected) in [
        (CredProtect::Required, WRONG_DATA),
        (
            CredProtect::OptionalWithCredentialIdList,
            CONDITIONS_NOT_SATISFIED,
        ),
    ] {
        let keys = KeyRing::new(&mut authenticator.crypto);
        let credential = Credential {
            key: KeySource::Seed([0x5E; 32]),
            alg: -7,
            cred_protect: level,
            user: None,
            reset_id: 0,
            store: None,
        };
        let key_handle = credential_id::seal_for_hash(
            &mut authenticator.crypto,
            &keys,
            &application("https://example.com"),
            &credential,
        )
        .expect("seals");
        let mut ui = Scripted::new(Answer::Confirmed);
        let response = u2f(
            &mut authenticator,
            &mut ui,
            authenticate(Control::CheckOnly, "https://example.com", &key_handle),
        );
        assert_eq!(response, expected, "{level:?}");
    }
}

/// A key handle from a U2F registration is a credential ID of the same format: CTAP2 getAssertion
/// for the RP ID whose hash is the application parameter, as a platform sends it for the `appid`
/// extension, signs with it.
#[test]
fn u2f_credentials_answer_ctap2_for_their_application() {
    let mut authenticator = authenticator();
    let made = register_u2f(&mut authenticator, RP_ID);
    let mut ui = Scripted::new(Answer::Confirmed);
    let response = run(
        &mut authenticator,
        &mut ui,
        &command(
            0x02,
            &[
                (0x01, Value::Text(RP_ID)),
                (0x02, Value::Bytes(CLIENT_DATA_HASH.to_vec())),
                (0x03, descriptors(&[&made.key_handle])),
                (0x05, options(&[("up", true)])),
            ],
        ),
    );
    assert_eq!(response[0], OK);
    let asserted = asserted(&response[1..]);
    assert_eq!(asserted.id, made.key_handle);
    let signed = [&asserted.auth_data[..], &CLIENT_DATA_HASH].concat();
    assert!(verifies(&made.public_key, &signed, &asserted.signature));
}

/// A non-discoverable CTAP2 credential answers U2F for the application that is its RP ID hash.
#[test]
fn ctap2_credentials_answer_u2f() {
    let mut authenticator = authenticator();
    let made = register(&mut authenticator, RP_ID, b"user-1", false, None);
    let mut ui = Scripted::new(Answer::Confirmed);
    let response = u2f(
        &mut authenticator,
        &mut ui,
        authenticate(Control::EnforcePresence, RP_ID, &made.id),
    );
    let (body, status) = response.split_at(response.len() - 2);
    assert_eq!(status, NO_ERROR);
    let signed = [&application(RP_ID)[..], &body[..5], &CHALLENGE].concat();
    assert!(verifies(&made.public_key, &signed, &body[5..]));
}

/// authenticatorReset revokes U2F credentials as it does CTAP2 ones: the key handle no longer
/// opens.
#[test]
fn reset_revokes_u2f_credentials() {
    let mut authenticator = authenticator();
    let made = register_u2f(&mut authenticator, "https://example.com");
    let mut ui = Scripted::new(Answer::Confirmed);
    assert_eq!(run(&mut authenticator, &mut ui, &[0x07]), [OK]);
    let response = u2f(
        &mut authenticator,
        &mut ui,
        authenticate(Control::CheckOnly, "https://example.com", &made.key_handle),
    );
    assert_eq!(response, WRONG_DATA);
}

/// With alwaysUv every U2F command is SW_COMMAND_NOT_ALLOWED (CTAP 2.2 §7.2.2), with no screen;
/// turning it off brings U2F back.
#[test]
fn always_uv_disables_u2f() {
    let mut authenticator = authenticator();
    let made = register_u2f(&mut authenticator, "https://example.com");
    authenticator.toggle_always_uv();
    let mut ui = Scripted::new(Answer::Confirmed);
    let requests = [
        Request::Version,
        Request::Register {
            challenge: CHALLENGE,
            application: application("https://example.com"),
        },
        authenticate(
            Control::EnforcePresence,
            "https://example.com",
            &made.key_handle,
        ),
    ];
    for request in requests {
        assert_eq!(
            u2f(&mut authenticator, &mut ui, request.clone()),
            COMMAND_NOT_ALLOWED,
            "{request:?}"
        );
    }
    assert_eq!(ui.asked, []);
    authenticator.toggle_always_uv();
    assert_eq!(
        u2f(&mut authenticator, &mut ui, Request::Version),
        [&b"U2F_V2"[..], &NO_ERROR].concat()
    );
}

/// While U2F is disabled by alwaysUv, every message is SW_COMMAND_NOT_ALLOWED, one that did not
/// parse as well: the protocol is off, so nothing about the message is reported.
#[test]
fn always_uv_refuses_malformed_messages_too() {
    let mut authenticator = authenticator();
    authenticator.toggle_always_uv();
    let mut ui = Scripted::new(Answer::Confirmed);
    let mut response = [0u8; 16];
    let length = authenticator.execute_ctap1(Err(StatusWord::WrongLength), &mut ui, &mut response);
    assert_eq!(response[..length], COMMAND_NOT_ALLOWED);
}

/// A request that failed to parse is answered with its status word alone.
#[test]
fn a_refused_request_answers_its_status_word() {
    let mut authenticator = authenticator();
    let mut ui = Scripted::new(Answer::Confirmed);
    let mut response = [0u8; 16];
    let length = authenticator.execute_ctap1(Err(StatusWord::WrongLength), &mut ui, &mut response);
    assert_eq!(response[..length], [0x67, 0x00]);
}

/// A response with no room for its data is the "no precise diagnosis" status alone; no room even
/// for a status word gets nothing.
#[test]
fn a_response_without_room_is_unknown() {
    let mut authenticator = authenticator();
    let mut ui = Scripted::new(Answer::Confirmed);
    let mut response = [0u8; 4];
    let length = authenticator.execute_ctap1(Ok(Request::Version), &mut ui, &mut response);
    assert_eq!(response[..length], [0x6F, 0x00]);
    let mut none = [0u8; 1];
    assert_eq!(
        authenticator.execute_ctap1(Ok(Request::Version), &mut ui, &mut none),
        0
    );
}

/// A U2F message between getAssertion and getNextAssertion ends the continuation (§6.3: it
/// continues only the command right before it).
#[test]
fn a_u2f_message_ends_the_next_assertion() {
    let mut authenticator = authenticator();
    register(&mut authenticator, RP_ID, b"user-1", true, None);
    register(&mut authenticator, RP_ID, b"user-2", true, None);
    // Two accounts and no account picker over the scripted user: the platform picks, so the
    // response carries numberOfCredentials and getNextAssertion would continue.
    let mut ui = Scripted::new(Answer::Confirmed);
    let response = run(
        &mut authenticator,
        &mut ui,
        &command(
            0x02,
            &[
                (0x01, Value::Text(RP_ID)),
                (0x02, Value::Bytes(CLIENT_DATA_HASH.to_vec())),
                (0x05, options(&[("up", false)])),
            ],
        ),
    );
    assert_eq!(response[0], OK);
    assert_eq!(asserted(&response[1..]).number_of_credentials, Some(2));
    u2f(&mut authenticator, &mut ui, Request::Version);
    const NOT_ALLOWED: u8 = 0x30;
    assert_eq!(run(&mut authenticator, &mut ui, &[0x08]), [NOT_ALLOWED]);
}
